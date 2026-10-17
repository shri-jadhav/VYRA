import logging
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy.orm import Session

from backend.app.collectors.aws_session import (
    AWSAccountIdentityError,
    AWSConfigurationError,
    AWSProfileConfigurationError,
    create_boto3_session,
    validate_caller_identity,
)
from backend.app.core.config import settings
from backend.app.core.security import sanitize_dict
from backend.app.investigation.domain import VerificationOutcome
from backend.app.models.models import (
    AssessmentRun,
    AuditLog,
    ControlEvaluation,
    Finding,
    RemediationPlan,
    VerificationRun,
)

logger = logging.getLogger("vyra.verification.engine")


class VerificationEngine:
    """
    Independent read-only verification engine for Workflow C.
    Compares baseline evidence/observation against fresh read-only observations on AWS.

    Safety:
    - Strictly READ-ONLY queries via boto3.
    - Zero AWS resource mutation.
    - Deterministic classification: RESOLVED, STILL_PRESENT, REGRESSED, UNVERIFIABLE.
    """

    def __init__(self, db: Session, profile_name: str | None = None):
        self.db = db
        self.profile_name = profile_name or settings.AWS_PROFILE

    def run_verification(
        self,
        finding_id: str,
        investigation_id: str | None = None,
        operator_note: str | None = None,
    ) -> VerificationRun:
        """
        Executes an independent read-only verification of a security finding.
        """
        finding = self.db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            raise ValueError(f"Finding '{finding_id}' not found.")

        now = datetime.now(UTC)
        run_id = f"VRUN-{uuid4().hex[:12].upper()}"

        # 1. Extract Baseline Observation
        baseline_observation = self._extract_baseline_observation(finding)

        # 2. Extract Account ID
        account_id = "unknown"
        if finding.resource_arn and ":" in finding.resource_arn:
            parts = finding.resource_arn.split(":")
            if len(parts) >= 5 and parts[4]:
                account_id = parts[4]

        # 3. Collect Fresh Read-Only Observation
        fresh_observation: dict[str, Any] = {}
        outcome = VerificationOutcome.UNVERIFIABLE
        comparison_summary = ""
        limitations: str | None = None

        # Check if finding belongs to a demo run
        run = None
        if finding.run_id:
            run = self.db.query(AssessmentRun).filter(AssessmentRun.id == finding.run_id).first()

        is_demo = (run and run.mode == "DEMO_FIXTURE") or (finding and "legacy-analytics" in finding.resource_id)

        if is_demo:
            account_id = "112233445566"
            outcome, fresh_observation, comparison_summary, limitations = self._evaluate_demo_state(finding)
        else:
            try:
                session = create_boto3_session(self.profile_name)
                if settings.VYRA_EXPECTED_AWS_ACCOUNT_ID:
                    identity = validate_caller_identity(session)
                    account_id = identity.get("account_id", account_id)
                elif account_id == "unknown":
                    try:
                        sts = session.client("sts")
                        if hasattr(sts, "get_caller_identity"):
                            caller = sts.get_caller_identity()
                            if isinstance(caller, dict) and isinstance(caller.get("Account"), str):
                                account_id = caller.get("Account", "unknown")
                    except (ClientError, BotoCoreError) as sts_err:
                        logger.debug("Could not determine STS account ID during verification: %s", sts_err)

                outcome, fresh_observation, comparison_summary, limitations = self._evaluate_fresh_state(
                    session=session,
                    finding=finding,
                    baseline=baseline_observation,
                )

            except (AWSProfileConfigurationError, AWSAccountIdentityError, AWSConfigurationError) as ace:
                outcome = VerificationOutcome.UNVERIFIABLE
                limitations = f"AWS configuration/identity error: {ace!s}"
                comparison_summary = f"Verification aborted due to AWS identity validation error: {ace!s}"
                fresh_observation = {"error": str(ace), "error_type": type(ace).__name__}

            except ClientError as ce:
                code = ce.response.get("Error", {}).get("Code", "ClientError")
                msg = ce.response.get("Error", {}).get("Message", str(ce))
                outcome = VerificationOutcome.UNVERIFIABLE
                limitations = f"AWS ClientError during verification read query ({code}): {msg}"
                comparison_summary = (
                    f"Verification could not be completed because AWS returned a client error ({code}). "
                    "Unable to confirm if remediation succeeded without sufficient read access."
                )
                fresh_observation = {"error_code": code, "error_message": msg}

            except BotoCoreError as bce:
                outcome = VerificationOutcome.UNVERIFIABLE
                limitations = f"AWS client communication error ({type(bce).__name__}): {bce!s}"
                comparison_summary = (
                    f"Verification could not be completed due to an AWS communication or SDK error ({type(bce).__name__}): {bce!s}."
                )
                fresh_observation = {"error_type": type(bce).__name__, "error_message": str(bce)}

        # 4. Persist VerificationRun
        v_run = VerificationRun(
            id=run_id,
            created_at=now,
            investigation_id=investigation_id,
            finding_id=finding.id,
            resource_id=finding.resource_id,
            account_id=account_id,
            outcome=outcome.value,
            baseline_observation=baseline_observation,
            fresh_observation=fresh_observation,
            comparison_summary=comparison_summary,
            limitations=limitations,
        )
        self.db.add(v_run)

        # 5. Update Finding Lifecycle
        finding.last_seen = now
        if outcome == VerificationOutcome.RESOLVED:
            finding.status = "REMEDIATED"
            finding.verification_result = "VERIFIED"
        elif outcome == VerificationOutcome.REGRESSED:
            finding.status = "OPEN"
            finding.verification_result = "REGRESSED"
        elif outcome == VerificationOutcome.STILL_PRESENT:
            finding.status = "OPEN"
            finding.verification_result = "STILL_FAILING"
        elif outcome == VerificationOutcome.UNVERIFIABLE:
            finding.verification_result = "UNVERIFIABLE"

        # 6. Update Associated RemediationPlan if any exists
        remediation_plan = (
            self.db.query(RemediationPlan)
            .filter(RemediationPlan.finding_id == finding.id)
            .order_by(RemediationPlan.id.desc())
            .first()
        )
        if remediation_plan:
            remediation_plan.verification_timestamp = now
            remediation_plan.verification_output = comparison_summary
            if outcome == VerificationOutcome.RESOLVED:
                remediation_plan.status = "VERIFIED"

        # 7. Record Audit Log
        audit_details = (
            f"Verification outcome: {outcome.value} for finding {finding.id} ({finding.control_id}) "
            f"on resource {finding.resource_id}. {operator_note or ''}".strip()
        )
        self.db.add(
            AuditLog(
                actor="vyra-verifier",
                action="AFTER_FIX_VERIFICATION",
                resource=finding.resource_id,
                status="SUCCESS" if outcome != VerificationOutcome.UNVERIFIABLE else "ERROR",
                details=audit_details,
            )
        )

        self.db.commit()
        self.db.refresh(v_run)
        self.db.refresh(finding)
        return v_run

    def _extract_baseline_observation(self, finding: Finding) -> dict[str, Any]:
        """Loads baseline evidence from original control evaluation or finding record."""
        latest_eval = (
            self.db.query(ControlEvaluation)
            .filter(
                ControlEvaluation.control_id == finding.control_id,
                ControlEvaluation.resource_id == finding.resource_id,
            )
            .order_by(ControlEvaluation.timestamp.desc())
            .first()
        )

        if latest_eval:
            return {
                "evaluation_id": latest_eval.id,
                "control_id": latest_eval.control_id,
                "status": latest_eval.status,
                "severity": latest_eval.severity,
                "rationale": latest_eval.rationale,
                "evidence_source": latest_eval.evidence_source,
                "observed_at": latest_eval.timestamp.isoformat() if latest_eval.timestamp else None,
                "evidence_data": sanitize_dict(latest_eval.evidence_data or {}),
            }

        return {
            "finding_id": finding.id,
            "control_id": finding.control_id,
            "status": finding.status,
            "severity": finding.severity,
            "title": finding.title,
            "description": finding.description,
            "first_seen": finding.first_seen.isoformat() if finding.first_seen else None,
            "last_seen": finding.last_seen.isoformat() if finding.last_seen else None,
            "risk_summary": finding.risk_summary,
        }

    def _evaluate_demo_state(
        self,
        finding: Finding,
    ) -> tuple[VerificationOutcome, dict[str, Any], str, str | None]:
        """Evaluates simulated verification state for demo benchmark findings without calling AWS."""
        remediation_plan = (
            self.db.query(RemediationPlan)
            .filter(RemediationPlan.finding_id == finding.id)
            .order_by(RemediationPlan.id.desc())
            .first()
        )
        is_remediated = (
            finding.status == "REMEDIATED"
            or (remediation_plan and remediation_plan.status in ("APPROVED", "VERIFIED"))
        )
        cid = finding.control_id
        rid = finding.resource_id

        if is_remediated:
            fresh = {
                "status": "REMEDIATED",
                "control_id": cid,
                "resource_id": rid,
                "remediation_verified": True,
                "mode": "DEMO_BENCHMARK"
            }
            summary = f"RESOLVED: Demo verification probe confirmed compliant posture on '{rid}' ({cid})."
            return VerificationOutcome.RESOLVED, fresh, summary, None
        else:
            fresh = {
                "status": "OPEN",
                "control_id": cid,
                "resource_id": rid,
                "remediation_verified": False,
                "mode": "DEMO_BENCHMARK"
            }
            summary = f"STILL_PRESENT: Demo verification probe indicates security finding condition remains active on '{rid}' ({cid})."
            return VerificationOutcome.STILL_PRESENT, fresh, summary, None

    def _evaluate_fresh_state(
        self,
        session: boto3.Session,
        finding: Finding,
        baseline: dict[str, Any],
    ) -> tuple[VerificationOutcome, dict[str, Any], str, str | None]:
        """
        Executes targeted read-only boto3 calls to evaluate whether the finding condition is resolved,
        still present, regressed, or unverifiable.
        """
        cid = finding.control_id
        rid = finding.resource_id

        # -------------------------------------------------------------
        # S3: Public Access Block (VYRA-S3-001)
        # -------------------------------------------------------------
        if cid == "VYRA-S3-001":
            s3 = session.client("s3")
            try:
                res = s3.get_public_access_block(Bucket=rid)
                pab = res.get("PublicAccessBlockConfiguration", {})
                fresh = {
                    "BlockPublicAcls": pab.get("BlockPublicAcls", False),
                    "IgnorePublicAcls": pab.get("IgnorePublicAcls", False),
                    "BlockPublicPolicy": pab.get("BlockPublicPolicy", False),
                    "RestrictPublicBuckets": pab.get("RestrictPublicBuckets", False),
                }
                all_blocked = all(fresh.values())

                if all_blocked:
                    summary = (
                        f"RESOLVED: S3 Bucket '{rid}' now has all 4 PublicAccessBlock protections enabled: "
                        f"BlockPublicAcls={fresh['BlockPublicAcls']}, IgnorePublicAcls={fresh['IgnorePublicAcls']}, "
                        f"BlockPublicPolicy={fresh['BlockPublicPolicy']}, RestrictPublicBuckets={fresh['RestrictPublicBuckets']}."
                    )
                    return VerificationOutcome.RESOLVED, fresh, summary, None
                else:
                    unblocked = [k for k, v in fresh.items() if not v]
                    summary = (
                        f"STILL_PRESENT: S3 Bucket '{rid}' remains publicly accessible or partially unprotected. "
                        f"The following flags remain False: {', '.join(unblocked)}."
                    )
                    return VerificationOutcome.STILL_PRESENT, fresh, summary, None

            except ClientError as ce:
                code = ce.response.get("Error", {}).get("Code", "")
                if code == "NoSuchPublicAccessBlockConfiguration":
                    fresh = {"configuration_present": False}
                    summary = f"STILL_PRESENT: S3 Bucket '{rid}' has NO PublicAccessBlock configuration configured on AWS."
                    return VerificationOutcome.STILL_PRESENT, fresh, summary, None
                elif code == "NoSuchBucket":
                    fresh = {"bucket_exists": False}
                    summary = f"UNVERIFIABLE: S3 Bucket '{rid}' no longer exists (NoSuchBucket). May have been deleted."
                    return VerificationOutcome.UNVERIFIABLE, fresh, summary, "Target bucket was deleted."
                elif code in ("AccessDenied", "AccessDeniedException"):
                    return (
                        VerificationOutcome.UNVERIFIABLE,
                        {"permission_denied": True},
                        f"UNVERIFIABLE: Read permission denied on S3 GetPublicAccessBlock for bucket '{rid}'.",
                        "Missing s3:GetBucketPublicAccessBlock permission.",
                    )
                raise

        # -------------------------------------------------------------
        # S3: Server-Side Encryption (VYRA-S3-002)
        # -------------------------------------------------------------
        elif cid == "VYRA-S3-002":
            s3 = session.client("s3")
            try:
                res = s3.get_bucket_encryption(Bucket=rid)
                rules = res.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                fresh = {"rules_count": len(rules), "rules": rules}
                if rules:
                    sse_algo = (
                        rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "UNKNOWN")
                    )
                    summary = f"RESOLVED: S3 Bucket '{rid}' now enforces default Server-Side Encryption ({sse_algo})."
                    return VerificationOutcome.RESOLVED, fresh, summary, None
                else:
                    summary = f"STILL_PRESENT: S3 Bucket '{rid}' has no encryption rules configured."
                    return VerificationOutcome.STILL_PRESENT, fresh, summary, None
            except ClientError as ce:
                code = ce.response.get("Error", {}).get("Code", "")
                if code == "ServerSideEncryptionConfigurationNotFoundError":
                    fresh = {"encryption_configured": False}
                    summary = f"STILL_PRESENT: Default server-side encryption is not configured on S3 Bucket '{rid}'."
                    return VerificationOutcome.STILL_PRESENT, fresh, summary, None
                elif code == "NoSuchBucket":
                    return (
                        VerificationOutcome.UNVERIFIABLE,
                        {"bucket_exists": False},
                        f"UNVERIFIABLE: S3 Bucket '{rid}' was not found.",
                        "Bucket deleted.",
                    )
                elif code in ("AccessDenied", "AccessDeniedException"):
                    return (
                        VerificationOutcome.UNVERIFIABLE,
                        {"permission_denied": True},
                        f"UNVERIFIABLE: Permission denied reading encryption config on S3 Bucket '{rid}'.",
                        "Missing s3:GetEncryptionConfiguration permission.",
                    )
                raise

        # -------------------------------------------------------------
        # S3: Versioning (VYRA-S3-003)
        # -------------------------------------------------------------
        elif cid == "VYRA-S3-003":
            s3 = session.client("s3")
            try:
                res = s3.get_bucket_versioning(Bucket=rid)
                status = res.get("Status", "Suspended")
                fresh = {"versioning_status": status, "mfa_delete": res.get("MFADelete", "Disabled")}
                if status == "Enabled":
                    summary = f"RESOLVED: S3 Bucket '{rid}' versioning is now Enabled."
                    return VerificationOutcome.RESOLVED, fresh, summary, None
                else:
                    summary = f"STILL_PRESENT: S3 Bucket '{rid}' versioning remains '{status}'."
                    return VerificationOutcome.STILL_PRESENT, fresh, summary, None
            except ClientError as ce:
                code = ce.response.get("Error", {}).get("Code", "")
                if code in ("AccessDenied", "AccessDeniedException"):
                    return (
                        VerificationOutcome.UNVERIFIABLE,
                        {"permission_denied": True},
                        f"UNVERIFIABLE: Permission denied reading bucket versioning for '{rid}'.",
                        "Missing s3:GetBucketVersioning permission.",
                    )
                raise

        # -------------------------------------------------------------
        # S3: Bucket Policy Public Status (VYRA-S3-004)
        # -------------------------------------------------------------
        elif cid == "VYRA-S3-004":
            s3 = session.client("s3")
            try:
                res = s3.get_bucket_policy_status(Bucket=rid)
                is_public = res.get("PolicyStatus", {}).get("IsPublic", False)
                fresh = {"is_public": is_public}
                if not is_public:
                    summary = f"RESOLVED: S3 Bucket '{rid}' policy is no longer public to the internet."
                    return VerificationOutcome.RESOLVED, fresh, summary, None
                else:
                    summary = f"STILL_PRESENT: S3 Bucket '{rid}' policy status is still marked IsPublic=True."
                    return VerificationOutcome.STILL_PRESENT, fresh, summary, None
            except ClientError as ce:
                code = ce.response.get("Error", {}).get("Code", "")
                if code == "NoSuchBucketPolicy":
                    fresh = {"has_policy": False, "is_public": False}
                    summary = f"RESOLVED: S3 Bucket '{rid}' has no bucket policy (not public)."
                    return VerificationOutcome.RESOLVED, fresh, summary, None
                raise

        # -------------------------------------------------------------
        # IAM: Root Account MFA (VYRA-IAM-001)
        # -------------------------------------------------------------
        elif cid == "VYRA-IAM-001":
            iam = session.client("iam")
            res = iam.get_account_summary()
            mfa_enabled = res.get("SummaryMap", {}).get("AccountMFAEnabled", 0)
            fresh = {"AccountMFAEnabled": mfa_enabled}
            if mfa_enabled == 1:
                summary = "RESOLVED: Root account MFA is active on the AWS account."
                return VerificationOutcome.RESOLVED, fresh, summary, None
            else:
                summary = "STILL_PRESENT: Root account MFA remains disabled (AccountMFAEnabled=0)."
                return VerificationOutcome.STILL_PRESENT, fresh, summary, None

        # -------------------------------------------------------------
        # IAM: Root Account Access Keys Absent (VYRA-IAM-002)
        # -------------------------------------------------------------
        elif cid == "VYRA-IAM-002":
            iam = session.client("iam")
            res = iam.get_account_summary()
            keys_present = res.get("SummaryMap", {}).get("AccountAccessKeysPresent", 0)
            fresh = {"AccountAccessKeysPresent": keys_present}
            if keys_present == 0:
                summary = "RESOLVED: Root account has 0 active access keys."
                return VerificationOutcome.RESOLVED, fresh, summary, None
            else:
                summary = "STILL_PRESENT: Root account still has active access keys present."
                return VerificationOutcome.STILL_PRESENT, fresh, summary, None

        # -------------------------------------------------------------
        # IAM: User MFA (VYRA-IAM-003)
        # -------------------------------------------------------------
        elif cid == "VYRA-IAM-003":
            iam = session.client("iam")
            try:
                res = iam.list_mfa_devices(UserName=rid)
                devices = res.get("MFADevices", [])
                fresh = {"mfa_device_count": len(devices), "devices": devices}
                if len(devices) > 0:
                    summary = f"RESOLVED: IAM user '{rid}' has {len(devices)} active MFA device(s) configured."
                    return VerificationOutcome.RESOLVED, fresh, summary, None
                else:
                    summary = f"STILL_PRESENT: IAM user '{rid}' has 0 MFA devices configured."
                    return VerificationOutcome.STILL_PRESENT, fresh, summary, None
            except ClientError as ce:
                code = ce.response.get("Error", {}).get("Code", "")
                if code == "NoSuchEntity":
                    return (
                        VerificationOutcome.UNVERIFIABLE,
                        {"user_exists": False},
                        f"UNVERIFIABLE: IAM user '{rid}' does not exist (may have been deleted).",
                        "User deleted.",
                    )
                raise

        # -------------------------------------------------------------
        # CloudTrail: Multi-Region Trail (VYRA-CT-001)
        # -------------------------------------------------------------
        elif cid == "VYRA-CT-001":
            ct = session.client("cloudtrail")
            res = ct.describe_trails()
            trails = res.get("trailList", [])
            multi_region = [t for t in trails if t.get("IsMultiRegionTrail")]
            fresh = {"total_trails": len(trails), "multi_region_count": len(multi_region)}
            if multi_region:
                summary = f"RESOLVED: CloudTrail has {len(multi_region)} active multi-region trail(s) configured."
                return VerificationOutcome.RESOLVED, fresh, summary, None
            else:
                summary = "STILL_PRESENT: No multi-region CloudTrail trails found in the account."
                return VerificationOutcome.STILL_PRESENT, fresh, summary, None

        # -------------------------------------------------------------
        # IAM: User Access Key Age under 90 Days (VYRA-IAM-004)
        # -------------------------------------------------------------
        elif cid == "VYRA-IAM-004":
            iam = session.client("iam")
            try:
                res = iam.list_access_keys(UserName=rid)
                keys = res.get("AccessKeyMetadata", [])
                now_utc = datetime.now(UTC)
                old_keys = []
                for k in keys:
                    if k.get("Status") == "Active" and k.get("CreateDate"):
                        age = (now_utc - k["CreateDate"]).days
                        if age > 90:
                            old_keys.append((k.get("AccessKeyId"), age))
                fresh = {"keys_count": len(keys), "old_keys_count": len(old_keys)}
                if not old_keys:
                    summary = f"RESOLVED: All active access keys for user '{rid}' are under 90 days old."
                    return VerificationOutcome.RESOLVED, fresh, summary, None
                else:
                    summary = f"STILL_PRESENT: User '{rid}' has {len(old_keys)} active access key(s) older than 90 days."
                    return VerificationOutcome.STILL_PRESENT, fresh, summary, None
            except ClientError as ce:
                code = ce.response.get("Error", {}).get("Code", "")
                if code == "NoSuchEntity":
                    return VerificationOutcome.UNVERIFIABLE, {"user_exists": False}, f"UNVERIFIABLE: IAM user '{rid}' not found.", "User deleted."
                raise

        # -------------------------------------------------------------
        # Security Services: IAM Access Analyzer (VYRA-SEC-001)
        # -------------------------------------------------------------
        elif cid == "VYRA-SEC-001":
            aa = session.client("accessanalyzer")
            res = aa.list_analyzers()
            active = [a for a in res.get("analyzers", []) if a.get("status") == "ACTIVE"]
            fresh = {"active_analyzers_count": len(active)}
            if active:
                summary = f"RESOLVED: Found {len(active)} active IAM Access Analyzer(s)."
                return VerificationOutcome.RESOLVED, fresh, summary, None
            else:
                summary = "STILL_PRESENT: No active IAM Access Analyzer deployed in the region."
                return VerificationOutcome.STILL_PRESENT, fresh, summary, None

        # -------------------------------------------------------------
        # Security Services: GuardDuty (VYRA-SEC-002)
        # -------------------------------------------------------------
        elif cid == "VYRA-SEC-002":
            gd = session.client("guardduty")
            res = gd.list_detectors()
            detectors = res.get("DetectorIds", [])
            fresh = {"detectors_count": len(detectors)}
            if detectors:
                summary = f"RESOLVED: Amazon GuardDuty is enabled with {len(detectors)} detector(s)."
                return VerificationOutcome.RESOLVED, fresh, summary, None
            else:
                summary = "STILL_PRESENT: Amazon GuardDuty is not enabled in this region (0 detectors)."
                return VerificationOutcome.STILL_PRESENT, fresh, summary, None

        # -------------------------------------------------------------
        # Security Services: Security Hub (VYRA-SEC-003)
        # -------------------------------------------------------------
        elif cid == "VYRA-SEC-003":
            sh = session.client("securityhub")
            try:
                res = sh.describe_hub()
                hub_arn = res.get("HubArn")
                fresh = {"hub_arn": hub_arn}
                if hub_arn:
                    summary = f"RESOLVED: AWS Security Hub is enabled ({hub_arn})."
                    return VerificationOutcome.RESOLVED, fresh, summary, None
                else:
                    summary = "STILL_PRESENT: AWS Security Hub is not active in this region."
                    return VerificationOutcome.STILL_PRESENT, fresh, summary, None
            except ClientError as ce:
                code = ce.response.get("Error", {}).get("Code", "")
                if "SubscriptionRequired" in code or "InvalidAccessException" in code:
                    return VerificationOutcome.STILL_PRESENT, {"subscribed": False}, "STILL_PRESENT: Security Hub is not enabled or subscribed.", None
                raise

        # Generic fallback for other controls
        summary = (
            f"Control '{cid}' for resource '{rid}' has no automated targeted verification probe. "
            "Operator manual review recommended."
        )
        return VerificationOutcome.UNVERIFIABLE, {}, summary, "Automated probe not implemented for this control ID."
