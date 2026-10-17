import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
from sqlalchemy.orm import Session

from backend.app.connectors.cloudtrail_connector import CloudTrailConnector
from backend.app.connectors.config_connector import AWSConfigConnector
from backend.app.connectors.security_hub_connector import SecurityHubConnector
from backend.app.core.config import settings
from backend.app.investigation.diff import ConfigurationDiffEngine
from backend.app.investigation.domain import (
    CandidateRanking,
    NormalizedCloudEvent,
)
from backend.app.investigation.ranking import CandidateRankingEngine
from backend.app.models.models import (
    AssessmentRun,
    Asset,
    AuditLog,
    CandidateChangeExplanation,
    Finding,
    InvestigationSession,
    TimelineEvent,
)

logger = logging.getLogger("vyra.investigation.engine")


class InvestigationEngine:
    """
    Core orchestrator for investigating cloud security regressions.
    Correlates observed findings with CloudTrail events, Config history,
    and Security Hub findings using deterministic attribution rules.
    """

    @staticmethod
    def run_investigation(
        db: Session,
        session: boto3.Session,
        resource_id: str,
        finding_id: str | None = None,
        time_window_hours: int = 24,
        region: str | None = None
    ) -> InvestigationSession:
        target_region = region or settings.AWS_DEFAULT_REGION
        now = datetime.now(UTC)
        start_time = now - timedelta(hours=time_window_hours)

        # 1. Load Finding, Run & Asset
        finding = None
        if finding_id:
            finding = db.query(Finding).filter(Finding.id == finding_id).first()
            if finding:
                resource_id = finding.resource_id

        run = None
        if finding and finding.run_id:
            run = db.query(AssessmentRun).filter(AssessmentRun.id == finding.run_id).first()

        is_demo_mode = (run and run.mode == "DEMO_FIXTURE") or (finding and "legacy-analytics" in finding.resource_id)

        asset = None
        if finding:
            asset = db.query(Asset).filter(
                Asset.run_id == finding.run_id,
                (Asset.name == resource_id) | (Asset.id == resource_id),
            ).first()
        if not asset:
            asset = db.query(Asset).filter(Asset.name == resource_id).first()
        if not asset:
            asset = db.query(Asset).filter(Asset.id == resource_id).first()

        control_id = finding.control_id if finding else "VYRA-S3-001"
        target_account = "112233445566" if is_demo_mode else (asset.account_id if asset and asset.account_id != "unknown" else (settings.VYRA_EXPECTED_AWS_ACCOUNT_ID or "unknown"))
        resource_arn = asset.arn if asset else f"arn:aws:s3:::{resource_id}"
        resource_type = asset.asset_type if asset else "s3:bucket"

        # 2. Configurations & Semantic Diff
        current_cfg = asset.configuration_data if asset else {}
        baseline_cfg = {
            "public_access_block": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            },
            "public_access_block_status": "FULL_BLOCK",
            "encryption_status": "CONFIGURED",
            "versioning_status": "Enabled"
        }
        config_diffs = ConfigurationDiffEngine.compute_diff(baseline_cfg, current_cfg, resource_type)

        blindspots: list[str] = []
        raw_events_data: list[dict[str, Any]] = []

        if is_demo_mode:
            # DEMO MODE: load deterministic demo benchmark change events without calling AWS
            raw_events_data = InvestigationEngine._get_demo_events(resource_id, target_region, "112233445566", now)
        else:
            # LIVE MODE: Strictly query live AWS services using validated read-only session
            # 3. Retrieve CloudTrail Management Events
            try:
                ct_connector = CloudTrailConnector(session=session, region_name=target_region)
                ct_result = ct_connector.lookup_management_events(
                    resource_name=resource_id,
                    start_time=start_time,
                    end_time=now,
                    max_results=50
                )
                if ct_result.get("status") == "PERMISSION_DENIED":
                    blindspots.append(f"CloudTrail lookup failed: {ct_result.get('error')}. User lacks cloudtrail:LookupEvents permission.")
                    raw_events_data = []
                elif ct_result.get("status") == "SUCCESS":
                    raw_events_data = ct_result.get("events", [])
                    if not raw_events_data:
                        blindspots.append(f"No CloudTrail management events found for resource '{resource_id}' within the last {time_window_hours} hour(s).")
                else:
                    blindspots.append(f"CloudTrail lookup returned error: {ct_result.get('error')}")
                    raw_events_data = []
            except Exception as e:
                logger.error(f"Error querying live CloudTrail: {e}")
                blindspots.append(f"CloudTrail inquiry error: {e!s}")
                raw_events_data = []

            # 4. Check AWS Config History
            try:
                cfg_connector = AWSConfigConnector(session=session, region_name=target_region)
                cfg_avail = cfg_connector.check_availability()
                if cfg_avail.status == "AVAILABLE":
                    cfg_history = cfg_connector.get_resource_config_history(
                        resource_type="AWS::S3::Bucket" if "s3" in resource_type.lower() else resource_type,
                        resource_id=resource_id,
                        earlier_time=start_time,
                        later_time=now,
                        limit=10
                    )
                    cfg_items = cfg_history.get("items", [])
                    if not cfg_items:
                        blindspots.append("AWS Config returned 0 historical configuration snapshots in the selected time window.")
                else:
                    blindspots.append(f"AWS Config historical snapshot comparison unavailable: {cfg_avail.status_details}")
            except Exception as e:
                logger.debug(f"AWS Config lookup failed: {e}")
                blindspots.append(f"AWS Config lookup error: {e!s}")

            # 5. Check Security Hub Findings
            try:
                sh_connector = SecurityHubConnector(session=session, region_name=target_region)
                sh_avail = sh_connector.check_availability()
                if sh_avail.status == "AVAILABLE":
                    sh_res = sh_connector.get_related_findings(resource_id=resource_id)
                    sh_findings = sh_res.get("findings", [])
                    if sh_findings:
                        blindspots.append(f"Correlated with {len(sh_findings)} active Security Hub finding(s).")
                else:
                    blindspots.append(f"Consolidated Security Hub finding correlation unavailable: {sh_avail.status_details}")
            except Exception as e:
                logger.debug(f"Security Hub lookup failed: {e}")
                blindspots.append(f"Security Hub correlation error: {e!s}")

        # Convert raw event dicts to domain models
        normalized_events: list[NormalizedCloudEvent] = [
            NormalizedCloudEvent(**e) for e in raw_events_data
        ]

        # 6. Rank Candidate Changes Deterministically
        first_observed = finding.first_seen if finding else (now - timedelta(hours=2))
        ranked_explanations = CandidateRankingEngine.rank_events_for_finding(
            events=normalized_events,
            control_id=control_id,
            resource_id=resource_id,
            first_observed_time=first_observed,
            config_diffs=config_diffs
        )

        # Determine overall investigation status & summary
        top_candidate = next((x for x in ranked_explanations if x.ranking == CandidateRanking.SUPPORTED_CANDIDATE), None)
        if top_candidate:
            inv_status = "COMPLETED"
            summary = (
                f"Identified high-confidence candidate change: '{top_candidate.event_name}' executed at "
                f"{top_candidate.event_time} by actor '{top_candidate.actor_identity}'. "
                f"{top_candidate.rationale}"
            )
        elif any(x.ranking == CandidateRanking.POSSIBLE for x in ranked_explanations):
            inv_status = "COMPLETED"
            summary = "Identified possible candidate changes, but causal evidence is incomplete. Further pipeline corroboration required."
        else:
            inv_status = "INSUFFICIENT_EVIDENCE"
            summary = f"No causal API operations observed within the {time_window_hours}h window. Review blindspots and broader event history."

        # 7. Persist Investigation Session
        inv_session = InvestigationSession(
            id=f"INV-{now.strftime('%Y%m%d%H%M')}-{str(uuid.uuid4())[:6]}",
            created_at=now,
            title=f"Investigation: {finding.title if finding else resource_id}",
            finding_id=finding_id,
            resource_id=resource_id,
            resource_arn=resource_arn,
            target_account=target_account,
            target_region=target_region,
            time_window_start=start_time,
            time_window_end=now,
            status=inv_status,
            summary=summary,
            baseline_config=baseline_cfg,
            current_config=current_cfg,
            config_diff=config_diffs,
            blindspots=blindspots,
            limitations=(
                "Analysis reflects CloudTrail management events and observed bucket configuration. "
                "Data-plane operations and external DNS queries are not observable via management Event History."
            ),
            next_steps=top_candidate.next_steps if top_candidate else [
                "Inspect CI/CD deployment logs",
                "Review IAM permissions for user/role that created the resource",
                "Apply dry-run remediation plan to restore compliant posture"
            ]
        )
        db.add(inv_session)
        db.flush()

        # 8. Persist Timeline Events
        # Add baseline event
        db.add(TimelineEvent(
            investigation_id=inv_session.id,
            timestamp=start_time,
            event_type="CONFIG_BASELINE",
            event_name="SecureBaselineRecorded",
            actor="vyra-system",
            source="VYRA Baseline Model",
            details=f"Secure configuration baseline established for {resource_id}.",
            payload=baseline_cfg
        ))

        # Add candidate events
        for ev in normalized_events:
            ev_dt = datetime.fromisoformat(ev.event_time.replace("Z", "+00:00")) if isinstance(ev.event_time, str) else ev.event_time
            db.add(TimelineEvent(
                investigation_id=inv_session.id,
                timestamp=ev_dt,
                event_type="API_CALL",
                event_name=ev.event_name,
                actor=ev.actor_arn or ev.actor_name or "Unknown",
                source="AWS CloudTrail",
                details=f"{ev.event_name} called by {ev.actor_name} from IP {ev.source_ip or 'unknown'}",
                payload=ev.request_parameters
            ))

        # Add finding observation event
        if finding:
            db.add(TimelineEvent(
                investigation_id=inv_session.id,
                timestamp=finding.first_seen,
                event_type="FINDING_OBSERVED",
                event_name="SecurityRegressionDetected",
                actor="vyra-assessment-engine",
                source="VYRA Controls Engine",
                details=f"Finding {finding.id} triggered: {finding.title}",
                payload={"control_id": finding.control_id, "severity": finding.severity}
            ))

        # 9. Persist Candidate Explanations
        for exp in ranked_explanations:
            exp_dt = datetime.fromisoformat(exp.event_time.replace("Z", "+00:00")) if isinstance(exp.event_time, str) else exp.event_time
            db.add(CandidateChangeExplanation(
                investigation_id=inv_session.id,
                event_id=exp.event_id,
                event_time=exp_dt,
                event_name=exp.event_name,
                actor=exp.actor_identity,
                ranking=exp.ranking.value,
                confidence_score=exp.confidence_score,
                matched_resource=exp.matched_resource,
                operation_relevance=exp.operation_relevance,
                property_changes=exp.property_changes,
                temporal_relationship=exp.temporal_relationship,
                rationale=exp.rationale,
                supporting_evidence=exp.supporting_evidence_ids,
                contradictory_evidence=exp.contradictory_evidence,
                missing_evidence=exp.missing_evidence,
                next_steps=exp.next_steps
            ))

        # Audit Log
        db.add(AuditLog(
            actor="vyra-investigator",
            action="INVESTIGATION_COMPLETED",
            resource=inv_session.id,
            status="SUCCESS",
            details=f"Completed regression investigation for {resource_id}. Status: {inv_status}"
        ))

        db.commit()
        db.refresh(inv_session)
        return inv_session

    @staticmethod
    def _get_demo_events(resource_id: str, region: str, account_id: str, now: datetime) -> list[dict[str, Any]]:
        """
        Deterministic event timeline for offline benchmark demonstration.
        Attributed strictly to demo fixture user ci-deployer-svc on demo account 112233445566.
        """
        t1 = (now - timedelta(hours=3, minutes=15)).isoformat()
        t2 = (now - timedelta(hours=1, minutes=45)).isoformat()
        demo_resource = resource_id if resource_id and "legacy-analytics" in resource_id else "legacy-analytics-logs-public"
        demo_account = "112233445566"
        demo_region = "us-east-1"

        return [
            {
                "event_id": f"evt-demo-{uuid.uuid4().hex[:8]}",
                "event_time": t1,
                "event_name": "PutBucketPublicAccessBlock",
                "event_source": "s3.amazonaws.com",
                "aws_region": demo_region,
                "actor_arn": f"arn:aws:iam::{demo_account}:user/ci-deployer-svc",
                "actor_type": "IAMUser",
                "actor_name": "ci-deployer-svc",
                "source_ip": "198.51.100.24",
                "user_agent": "aws-cli/2.15.15 Python/3.11 Linux/5.15",
                "resource_type": "AWS::S3::Bucket",
                "resource_name": demo_resource,
                "resource_arn": f"arn:aws:s3:::{demo_resource}",
                "read_only": False,
                "error_code": None,
                "request_parameters": {
                    "bucketName": demo_resource,
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False
                    }
                },
                "response_elements": {},
                "raw_event": {}
            },
            {
                "event_id": f"evt-demo-{uuid.uuid4().hex[:8]}",
                "event_time": t2,
                "event_name": "PutBucketPolicy",
                "event_source": "s3.amazonaws.com",
                "aws_region": demo_region,
                "actor_arn": f"arn:aws:iam::{demo_account}:user/ci-deployer-svc",
                "actor_type": "IAMUser",
                "actor_name": "ci-deployer-svc",
                "source_ip": "198.51.100.24",
                "user_agent": "aws-cli/2.15.15 Python/3.11 Linux/5.15",
                "resource_type": "AWS::S3::Bucket",
                "resource_name": demo_resource,
                "resource_arn": f"arn:aws:s3:::{demo_resource}",
                "read_only": False,
                "error_code": None,
                "request_parameters": {
                    "bucketName": demo_resource,
                    "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::" + demo_resource + "/*\"}]}"
                },
                "response_elements": {},
                "raw_event": {}
            }
        ]
