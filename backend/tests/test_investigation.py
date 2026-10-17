from datetime import UTC, datetime, timedelta

from backend.app.investigation.diff import ConfigurationDiffEngine
from backend.app.investigation.domain import CandidateRanking, NormalizedCloudEvent
from backend.app.investigation.ranking import CandidateRankingEngine
from backend.app.investigation.reports import InvestigationReportGenerator
from backend.app.models.models import CandidateChangeExplanation, InvestigationSession, TimelineEvent


def test_diff_engine_s3():
    baseline = {
        "public_access_block": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
        "encryption_status": "CONFIGURED",
        "versioning_status": "Enabled",
    }
    current = {
        "public_access_block": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
        "encryption_status": "NOT_CONFIGURED",
        "versioning_status": "Suspended",
    }

    diffs = ConfigurationDiffEngine.compute_diff(baseline, current, "s3:bucket")
    diff_keys = [d["property"] for d in diffs]

    assert "public_access_block.BlockPublicAcls" in diff_keys
    assert "encryption_status" in diff_keys
    assert "versioning_status" in diff_keys
    assert all(d["security_impact"] == "REGRESSION" for d in diffs)


def test_candidate_ranking_supported_candidate():
    now = datetime.now(UTC)
    event_time = now - timedelta(hours=2)

    event = NormalizedCloudEvent(
        event_id="EVT-101",
        event_time=event_time.isoformat(),
        event_name="DeleteBucketPublicAccessBlock",
        event_source="s3.amazonaws.com",
        aws_region="ap-south-1",
        actor_name="deploy-service-role",
        actor_arn="arn:aws:iam::112233445566:role/deploy-service-role",
        actor_type="AssumedRole",
        resource_type="s3:bucket",
        resource_name="prod-frontend-bucket",
        read_only=False,
    )

    diffs = [{"property": "public_access_block.BlockPublicAcls", "security_impact": "REGRESSION"}]

    explanations = CandidateRankingEngine.rank_events_for_finding(
        events=[event],
        control_id="VYRA-S3-001",
        resource_id="prod-frontend-bucket",
        first_observed_time=now,
        config_diffs=diffs,
    )

    assert len(explanations) == 1
    explanation = explanations[0]
    assert explanation.ranking == CandidateRanking.SUPPORTED_CANDIDATE
    assert explanation.confidence_score >= 80
    assert "DeleteBucketPublicAccessBlock" in explanation.event_name


def test_candidate_ranking_unrelated_event():
    now = datetime.now(UTC)
    event_time = now - timedelta(hours=1)

    event = NormalizedCloudEvent(
        event_id="EVT-999",
        event_time=event_time.isoformat(),
        event_name="DescribeTrails",
        event_source="cloudtrail.amazonaws.com",
        aws_region="ap-south-1",
        actor_name="auditor",
        actor_arn="arn:aws:iam::112233445566:user/auditor",
        actor_type="IAMUser",
        resource_type="cloudtrail",
        resource_name="trail-1",
        read_only=True,
    )

    diffs = [{"property": "public_access_block.BlockPublicAcls", "security_impact": "REGRESSION"}]

    explanations = CandidateRankingEngine.rank_events_for_finding(
        events=[event],
        control_id="VYRA-S3-001",
        resource_id="prod-frontend-bucket",
        first_observed_time=now,
        config_diffs=diffs,
    )

    assert len(explanations) == 1
    explanation = explanations[0]
    assert explanation.ranking in (CandidateRanking.NOT_OBSERVED, CandidateRanking.INSUFFICIENT_EVIDENCE)
    assert explanation.confidence_score <= 30


def test_investigation_report_generator():
    now = datetime.now(UTC)
    session = InvestigationSession(
        id="INV-TEST-001",
        created_at=now,
        title="Investigation: prod-frontend-bucket S3 Regression",
        resource_id="prod-frontend-bucket",
        resource_arn="arn:aws:s3:::prod-frontend-bucket",
        target_account="112233445566",
        target_region="ap-south-1",
        time_window_start=now - timedelta(days=1),
        time_window_end=now,
        status="COMPLETED",
        summary="S3 PublicAccessBlock was removed by Terraform deployment script.",
        blindspots=["cloudtrail:LookupEvents was denied for current IAM user."],
        limitations="Lookback restricted to 24 hours.",
        next_steps=["Re-enable Public Access Block via CLI or Terraform."],
    )

    session.candidate_explanations.append(
        CandidateChangeExplanation(
            id="EXP-1",
            investigation_id="INV-TEST-001",
            event_id="EVT-101",
            event_time=now - timedelta(hours=2),
            event_name="DeletePublicAccessBlock",
            actor="arn:aws:iam::112233445566:role/deploy-role",
            ranking="SUPPORTED_CANDIDATE",
            confidence_score=92,
            matched_resource="prod-frontend-bucket",
            operation_relevance="Directly removes PublicAccessBlock",
            rationale="Exact API operation matching regression",
        )
    )

    session.timeline_events.append(
        TimelineEvent(
            id="TL-1",
            investigation_id="INV-TEST-001",
            timestamp=now - timedelta(hours=2),
            event_type="API_CALL",
            event_name="DeletePublicAccessBlock",
            actor="deploy-role",
            source="CloudTrail",
            details="Bucket public access block was deleted",
        )
    )

    html = InvestigationReportGenerator.generate_html(session)
    assert "INV-TEST-001" in html
    assert "prod-frontend-bucket" in html
    assert "DeletePublicAccessBlock" in html

    md = InvestigationReportGenerator.generate_markdown(session)
    assert "Incident Investigation Report" in md
    assert "prod-frontend-bucket" in md

    json_data = InvestigationReportGenerator.generate_json(session)
    assert json_data["investigation_id"] == "INV-TEST-001"
    assert len(json_data["candidate_explanations"]) == 1
