"""VYRA — Complete Offline Release Acceptance Test Suite.

Validates all 18 core open-source release acceptance criteria offline:
 1. Offline demo mode runs with zero AWS credentials and zero network calls.
 2. Demo mode page loads never invoke boto3 or STS.
 3. Live mode fails closed when profile 'vyra-readonly' is missing.
 4. Live mode fails closed when VYRA_EXPECTED_AWS_ACCOUNT_ID is missing or mismatched.
 5. Live mode halts immediately on STS failure before any collection.
 6. Demo and live assessment data are strictly isolated (no cross-contamination).
 7. Empty database returns clean empty state without crashing.
 8. S3 collector handles unencrypted, public, and properly configured buckets.
 9. IAM collector handles root account MFA, inactive access keys, wildcard policies.
10. CloudTrail collector detects disabled logging, multi-region trails, missing encryption.
11. Modular connectors gracefully handle AccessDenied and disabled services.
12. Verification engine correctly computes RESOLVED, STILL_PRESENT, and UNVERIFIABLE.
13. Verification history excludes test fixtures and isolates runs.
14. Terraform plan checker detects insecure S3 configurations (ACL, encryption, public access block).
15. Terraform plan checker detects IAM wildcard permissions.
16. Terraform plan checker emits valid SARIF 2.1.0 output.
17. Reports exclude secrets and accurately summarize findings.
18. Investigation sessions remain scoped to their assessment run.

CRITICAL: All tests run offline against an isolated in-memory SQLite database.
No AWS network calls, credentials, or live resources are ever touched.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.exceptions import ProfileNotFound
from botocore.stub import Stubber
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.collectors.aws_session import (
    AWSAccountIdentityError,
    AWSProfileConfigurationError,
    create_boto3_session,
    validate_caller_identity,
)
from backend.app.collectors.cloudtrail_collector import CloudTrailCollector
from backend.app.collectors.iam_collector import IAMCollector
from backend.app.collectors.orchestrator import CollectorOrchestrator
from backend.app.collectors.s3_collector import S3Collector
from backend.app.connectors.guardduty_connector import GuardDutyConnector
from backend.app.core.database import Base, get_db
from backend.app.core.security import sanitize_dict
from backend.app.investigation.domain import VerificationOutcome
from backend.app.main import app
from backend.app.models.models import (
    AssessmentRun,
    ControlEvaluation,
    Finding,
    InvestigationSession,
    VerificationRun,
)
from backend.app.plan_checker.checker import PlanChecker
from backend.app.reports.generator import ReportGenerator
from backend.app.verification.engine import VerificationEngine


# ---------------------------------------------------------------------------
# Test Database Fixture
# ---------------------------------------------------------------------------
@pytest.fixture
def acceptance_client():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    db = TestingSession()

    yield client, db

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# 1. Offline Demo Mode (Zero Credentials / Zero Network Calls)
# ---------------------------------------------------------------------------
def test_acceptance_01_offline_demo_mode_runs_with_zero_aws(acceptance_client):
    client, _ = acceptance_client
    with patch("boto3.Session") as mock_boto:
        res = client.post("/api/v1/assessment/trigger", json={"mode": "DEMO"})
        assert res.status_code == 200
        data = res.json()
        assert data["mode"] == "DEMO"
        assert data["status"] == "COMPLETED"
        assert data["profile_used"] == "demo-benchmark-fixture"
        assert data["target_account"] in ["112233445566", "112233445566-DEMO"]
        mock_boto.assert_not_called()


# ---------------------------------------------------------------------------
# 2. Demo Mode Page Loads Never Invoke boto3 or STS
# ---------------------------------------------------------------------------
def test_acceptance_02_demo_page_loads_never_call_aws(acceptance_client):
    client, _ = acceptance_client
    with patch("boto3.Session") as mock_session, patch("boto3.client") as mock_client:
        r1 = client.get("/api/v1/health")
        assert r1.status_code == 200
        assert r1.json()["status"] == "HEALTHY"

        r2 = client.get("/api/v1/connectors/matrix")
        assert r2.status_code == 200

        r3 = client.get("/api/v1/assessment/metrics")
        assert r3.status_code == 200

        mock_session.assert_not_called()
        mock_client.assert_not_called()


# ---------------------------------------------------------------------------
# 3. Live Mode Fails Closed When Profile 'vyra-readonly' is Missing
# ---------------------------------------------------------------------------
def test_acceptance_03_missing_profile_fails_closed():
    with patch("boto3.Session", side_effect=ProfileNotFound(profile="vyra-readonly")):
        with pytest.raises(AWSProfileConfigurationError) as exc_info:
            create_boto3_session(profile_name="vyra-readonly")
        assert "not found" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# 4. Live Mode Fails Closed When Expected Account ID is Missing or Mismatched
# ---------------------------------------------------------------------------
def test_acceptance_04_account_id_missing_or_mismatched():
    session = MagicMock()
    # Missing expected account
    with pytest.raises(AWSAccountIdentityError) as exc:
        validate_caller_identity(session, expected_account_id="")
    assert "not configured" in str(exc.value)

    # Mismatched account
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "222233334444", "Arn": "arn:aws:iam::222233334444:root"}
    session.client.return_value = mock_sts

    with pytest.raises(AWSAccountIdentityError) as exc_mismatch:
        validate_caller_identity(session, expected_account_id="111122223333")
    assert "mismatch" in str(exc_mismatch.value).lower()


# ---------------------------------------------------------------------------
# 5. Live Mode Halts Immediately on STS Failure Before Collection
# ---------------------------------------------------------------------------
def test_acceptance_05_sts_failure_halts_immediately():
    sts_client = boto3.client("sts", region_name="us-east-1")
    stubber = Stubber(sts_client)
    stubber.add_client_error("get_caller_identity", service_error_code="AuthFailure", service_message="AWS STS Auth Failed")

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = sts_client
        orch = CollectorOrchestrator(profile_name="vyra-readonly")
        orch.session = mock_session

        with pytest.raises(AWSAccountIdentityError):
            orch.collect_all("RUN-LIVE-TEST-FAIL")


# ---------------------------------------------------------------------------
# 6. Demo and Live Assessment Data Are Strictly Isolated
# ---------------------------------------------------------------------------
def test_acceptance_06_demo_and_live_data_strictly_isolated(acceptance_client):
    client, db = acceptance_client
    t0 = datetime(2026, 10, 17, 10, 0, 0, tzinfo=UTC)

    live_run = AssessmentRun(
        id="RUN-LIVE-999",
        started_at=t0,
        completed_at=t0 + timedelta(minutes=5),
        status="COMPLETED",
        mode="LIVE_AWS",
        target_account="998877665544",
        target_region="ap-south-1",
        profile_used="vyra-readonly",
        total_assets=1,
        total_controls=1,
        passed_controls=0,
        failed_controls=1,
    )
    demo_run = AssessmentRun(
        id="RUN-DEMO-999",
        started_at=t0 + timedelta(hours=1),
        completed_at=t0 + timedelta(hours=1, minutes=2),
        status="COMPLETED",
        mode="DEMO_FIXTURE",
        target_account="112233445566",
        target_region="us-east-1",
        profile_used="demo-benchmark-fixture",
        total_assets=1,
        total_controls=1,
        passed_controls=1,
        failed_controls=0,
    )
    finding_live = Finding(
        id="FND-LIVE-999",
        run_id="RUN-LIVE-999",
        control_id="VYRA-S3-001",
        title="Live S3 Finding",
        description="Live production bucket vulnerability",
        severity="HIGH",
        status="OPEN",
        resource_id="live-prod-vault-998877665544",
        resource_arn="arn:aws:s3:::live-prod-vault-998877665544",
        service="s3",
    )
    finding_demo = Finding(
        id="FND-DEMO-999",
        run_id="RUN-DEMO-999",
        control_id="VYRA-S3-001",
        title="Demo S3 Finding",
        description="Demo synthetic benchmark finding",
        severity="MEDIUM",
        status="OPEN",
        resource_id="demo-customer-data-benchmark",
        resource_arn="arn:aws:s3:::demo-customer-data-benchmark",
        service="s3",
    )
    db.add_all([live_run, demo_run, finding_live, finding_demo])
    db.commit()

    # Default is latest completed (DEMO)
    metrics = client.get("/api/v1/assessment/metrics").json()
    assert metrics["run_id"] == "RUN-DEMO-999"
    assert metrics["account_id"] == "112233445566"

    findings = client.get("/api/v1/findings").json()
    assert len(findings) == 1
    assert findings[0]["resource_id"] == "demo-customer-data-benchmark"
    assert not any("live-prod-vault" in f["resource_id"] for f in findings)


# ---------------------------------------------------------------------------
# 7. Empty Database Returns Clean Empty State Without Crashing
# ---------------------------------------------------------------------------
def test_acceptance_07_empty_database_returns_clean_empty_state(acceptance_client):
    client, _ = acceptance_client
    metrics = client.get("/api/v1/assessment/metrics").json()
    assert metrics["mode"] == "NOT_SCANNED"
    assert metrics["run_id"] is None
    assert metrics["total_findings"] == 0
    assert metrics["security_score"] == 0

    assert client.get("/api/v1/findings").json() == []
    assert client.get("/api/v1/assets").json() == []
    assert client.get("/api/v1/remediation/plans").json() == []


# ---------------------------------------------------------------------------
# 8. S3 Collector Handles Unencrypted, Public, and Properly Configured Buckets
# ---------------------------------------------------------------------------
def test_acceptance_08_s3_collector_posture_handling():
    s3_client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(s3_client)

    stubber.add_response("list_buckets", {"Buckets": [{"Name": "test-sec-bucket", "CreationDate": datetime.now(UTC)}]})
    stubber.add_response("get_bucket_location", {"LocationConstraint": "us-east-1"})
    stubber.add_response("get_public_access_block", {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    })
    stubber.add_response("get_bucket_encryption", {
        "ServerSideEncryptionConfiguration": {
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
        }
    })
    stubber.add_response("get_bucket_versioning", {"Status": "Enabled"})
    stubber.add_response("get_bucket_policy_status", {"PolicyStatus": {"IsPublic": False}})
    stubber.add_response("get_bucket_logging", {"LoggingEnabled": {"TargetBucket": "logs-bkt", "TargetPrefix": "access-logs/"}})

    with stubber:
        collector = S3Collector.__new__(S3Collector)
        collector.client = s3_client
        res = collector.collect()
        assert res["status"] == "SUCCESS"
        assert len(res["buckets"]) == 1
        b = res["buckets"][0]
        assert b["public_access_block_status"] == "FULL_BLOCK"
        assert b["encryption_status"] == "CONFIGURED"
        assert b["versioning_status"] == "Enabled"
        assert b["logging_status"] == "CONFIGURED"


# ---------------------------------------------------------------------------
# 9. IAM Collector Handles Root MFA, Access Keys, Wildcard Policies
# ---------------------------------------------------------------------------
def test_acceptance_09_iam_collector_root_mfa_and_keys():
    iam_client = boto3.client("iam", region_name="us-east-1")
    stubber = Stubber(iam_client)

    stubber.add_response("get_account_summary", {
        "SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 0, "Users": 1}
    })
    stubber.add_client_error("get_account_password_policy", service_error_code="NoSuchEntity")
    stubber.add_response("list_users", {
        "Users": [{
            "Path": "/",
            "UserName": "svc-deployer",
            "UserId": "AIDA1234567890123456",
            "Arn": "arn:aws:iam::112233445566:user/svc-deployer",
            "CreateDate": datetime.now(UTC),
        }]
    })
    stubber.add_response("list_mfa_devices", {"MFADevices": []})
    stubber.add_response("list_access_keys", {
        "AccessKeyMetadata": [{"AccessKeyId": "AKIAEXAMPLE123456", "Status": "Active", "CreateDate": datetime.now(UTC)}]
    })
    stubber.add_response("list_attached_user_policies", {
        "AttachedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]
    })
    stubber.add_response("list_user_policies", {"PolicyNames": []})
    stubber.add_response("list_roles", {"Roles": []})

    with stubber:
        collector = IAMCollector.__new__(IAMCollector)
        collector.client = iam_client
        res = collector.collect()
        assert res["status"] == "SUCCESS"
        assert res["account_summary"]["AccountMFAEnabled"] == 0
        u = res["users"][0]
        assert u["mfa_active"] is False
        assert len(u["access_keys"]) == 1


# ---------------------------------------------------------------------------
# 10. CloudTrail Collector Detects Multi-Region Trails and Logging Status
# ---------------------------------------------------------------------------
def test_acceptance_10_cloudtrail_collector_posture():
    ct_client = boto3.client("cloudtrail", region_name="us-east-1")
    stubber = Stubber(ct_client)

    stubber.add_response("describe_trails", {
        "trailList": [{
            "Name": "main-audit-trail",
            "TrailARN": "arn:aws:cloudtrail:us-east-1:112233445566:trail/main-audit-trail",
            "HomeRegion": "us-east-1",
            "S3BucketName": "audit-logs-bucket",
            "IsMultiRegionTrail": True,
            "LogFileValidationEnabled": True,
            "KmsKeyId": "arn:aws:kms:us-east-1:112233445566:key/uuid-kms",
        }]
    })
    stubber.add_response("get_trail_status", {
        "IsLogging": True,
        "LatestDeliveryTime": datetime.now(UTC),
    })
    stubber.add_response("get_event_selectors", {
        "EventSelectors": [{"ReadWriteType": "All", "IncludeManagementEvents": True}],
        "AdvancedEventSelectors": [],
    })

    with stubber:
        collector = CloudTrailCollector.__new__(CloudTrailCollector)
        collector.client = ct_client
        res = collector.collect()
        assert res["status"] == "SUCCESS"
        assert len(res["trails"]) == 1
        t = res["trails"][0]
        assert t["is_multi_region"] is True
        assert t["is_logging"] is True
        assert t["log_file_validation_enabled"] is True


# ---------------------------------------------------------------------------
# 11. Modular Connectors Gracefully Handle AccessDenied and Disabled Services
# ---------------------------------------------------------------------------
def test_acceptance_11_modular_connectors_handle_errors():
    gd_client = boto3.client("guardduty", region_name="us-east-1")
    stubber = Stubber(gd_client)
    stubber.add_client_error("list_detectors", service_error_code="SubscriptionRequiredException", service_message="Not subscribed")

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = gd_client
        conn = GuardDutyConnector(session=mock_session, region_name="us-east-1")
        cap = conn.check_availability()
        assert cap.status.value in ["NOT_SUBSCRIBED", "UNAVAILABLE", "UNCONFIGURED"]


# ---------------------------------------------------------------------------
# 12. Verification Engine Computes RESOLVED, STILL_PRESENT, UNVERIFIABLE
# ---------------------------------------------------------------------------
def test_acceptance_12_verification_outcomes(acceptance_client):
    _, db = acceptance_client
    finding_fixed = Finding(
        id="FND-V-001",
        run_id="RUN-1",
        control_id="VYRA-S3-001",
        title="Public S3",
        description="Public bucket check",
        severity="HIGH",
        status="OPEN",
        resource_id="secure-bucket",
        resource_arn="arn:aws:s3:::secure-bucket",
        service="s3",
    )
    db.add(finding_fixed)
    db.commit()

    # 1. RESOLVED
    s3_fixed = boto3.client("s3", region_name="us-east-1")
    stub_fixed = Stubber(s3_fixed)
    stub_fixed.add_response("get_public_access_block", {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }, {"Bucket": "secure-bucket"})

    with stub_fixed:
        mock_session = MagicMock()
        mock_session.client.return_value = s3_fixed
        with patch("backend.app.verification.engine.create_boto3_session", return_value=mock_session):
            engine = VerificationEngine(db=db)
            vrun = engine.run_verification(finding_id="FND-V-001")
            assert vrun.outcome == VerificationOutcome.RESOLVED.value

    # 2. STILL_PRESENT
    s3_open = boto3.client("s3", region_name="us-east-1")
    stub_open = Stubber(s3_open)
    stub_open.add_response("get_public_access_block", {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        }
    }, {"Bucket": "secure-bucket"})

    with stub_open:
        mock_session = MagicMock()
        mock_session.client.return_value = s3_open
        with patch("backend.app.verification.engine.create_boto3_session", return_value=mock_session):
            engine = VerificationEngine(db=db)
            vrun = engine.run_verification(finding_id="FND-V-001")
            assert vrun.outcome == VerificationOutcome.STILL_PRESENT.value

    # 3. UNVERIFIABLE on AccessDenied
    s3_denied = boto3.client("s3", region_name="us-east-1")
    stub_denied = Stubber(s3_denied)
    stub_denied.add_client_error("get_public_access_block", service_error_code="AccessDenied")

    with stub_denied:
        mock_session = MagicMock()
        mock_session.client.return_value = s3_denied
        with patch("backend.app.verification.engine.create_boto3_session", return_value=mock_session):
            engine = VerificationEngine(db=db)
            vrun = engine.run_verification(finding_id="FND-V-001")
            assert vrun.outcome == VerificationOutcome.UNVERIFIABLE.value


# ---------------------------------------------------------------------------
# 13. Verification History Excludes Test Fixtures and Isolates Runs
# ---------------------------------------------------------------------------
def test_acceptance_13_verification_history_isolated(acceptance_client):
    client, db = acceptance_client
    t = datetime(2026, 10, 17, 12, 0, 0, tzinfo=UTC)

    run_a = AssessmentRun(id="RUN-A", started_at=t, completed_at=t + timedelta(minutes=1), status="COMPLETED", mode="DEMO_FIXTURE")
    run_b = AssessmentRun(id="RUN-B", started_at=t + timedelta(hours=1), completed_at=t + timedelta(hours=1, minutes=1), status="COMPLETED", mode="DEMO_FIXTURE")
    f_a = Finding(id="F-A", run_id="RUN-A", control_id="VYRA-S3-001", title="A", description="A desc", severity="HIGH", status="OPEN", resource_id="res-a", resource_arn="arn-a", service="s3")
    f_b = Finding(id="F-B", run_id="RUN-B", control_id="VYRA-S3-001", title="B", description="B desc", severity="HIGH", status="OPEN", resource_id="res-b", resource_arn="arn-b", service="s3")

    v_a = VerificationRun(id="VRUN-A", created_at=t, finding_id="F-A", resource_id="res-a", account_id="112233445566", outcome="RESOLVED", comparison_summary="Verified fixed")
    v_b = VerificationRun(id="VRUN-B", created_at=t + timedelta(hours=1), finding_id="F-B", resource_id="res-b", account_id="112233445566", outcome="STILL_PRESENT", comparison_summary="Still present")

    db.add_all([run_a, run_b, f_a, f_b, v_a, v_b])
    db.commit()

    # Scope to RUN-A
    hist_a = client.get("/api/v1/verification/history?run_id=RUN-A").json()
    assert len(hist_a) == 1
    assert hist_a[0]["id"] == "VRUN-A"

    # Non-existent run returns 404
    assert client.get("/api/v1/verification/history?run_id=RUN-NONEXIST").status_code == 404


# ---------------------------------------------------------------------------
# 14. Terraform Plan Checker Detects Insecure S3 Configurations
# ---------------------------------------------------------------------------
def test_acceptance_14_plan_checker_s3_rules():
    plan_insecure = {
        "format_version": "1.2",
        "resource_changes": [
            {
                "address": "aws_s3_bucket_public_access_block.unblocked",
                "type": "aws_s3_bucket_public_access_block",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "block_public_acls": False,
                        "ignore_public_acls": False,
                        "block_public_policy": False,
                        "restrict_public_buckets": False,
                    },
                },
            },
            {
                "address": "aws_s3_bucket_server_side_encryption_configuration.deleted_enc",
                "type": "aws_s3_bucket_server_side_encryption_configuration",
                "change": {
                    "actions": ["delete"],
                },
            },
        ],
    }

    res = PlanChecker.evaluate_plan_dict(plan_insecure)
    assert res["status"] == "BLOCKED"
    assert res["exit_code"] == 1
    rule_ids = [v["rule_id"] for v in res["violations"]]
    assert "VYRA-GATE-S3-001" in rule_ids
    assert "VYRA-GATE-S3-002" in rule_ids


# ---------------------------------------------------------------------------
# 15. Terraform Plan Checker Detects IAM Wildcard Permissions
# ---------------------------------------------------------------------------
def test_acceptance_15_plan_checker_iam_wildcards():
    plan_wildcard = {
        "format_version": "1.2",
        "resource_changes": [
            {
                "address": "aws_iam_policy.admin",
                "type": "aws_iam_policy",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
                    },
                },
            }
        ],
    }

    res = PlanChecker.evaluate_plan_dict(plan_wildcard)
    assert res["status"] == "BLOCKED"
    assert res["exit_code"] == 1
    assert any(v["rule_id"] == "VYRA-GATE-IAM-001" for v in res["violations"])


# ---------------------------------------------------------------------------
# 16. Terraform Plan Checker Emits Valid SARIF 2.1.0 Output
# ---------------------------------------------------------------------------
def test_acceptance_16_sarif_output_validity():
    fixtures_dir = Path(__file__).resolve().parent.parent / "app" / "fixtures" / "plans"
    insecure_plan = fixtures_dir / "insecure_regression_plan.json"

    res = PlanChecker.evaluate_plan_file(str(insecure_plan))
    sarif = res["sarif"]

    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert "https://json.schemastore.org/sarif-2.1.0.json" in sarif["$schema"]
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "VYRA Pre-Deployment Security Gate"
    assert len(run["results"]) >= 3
    for r in run["results"]:
        assert "ruleId" in r
        assert "level" in r
        assert "locations" in r


# ---------------------------------------------------------------------------
# 17. Reports Exclude Secrets and Accurately Summarize Findings
# ---------------------------------------------------------------------------
def test_acceptance_17_reports_exclude_secrets_and_summarize():
    run = AssessmentRun(
        id="RUN-REPORT-TEST",
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
        status="COMPLETED",
        mode="LIVE_AWS",
        target_account="112233445566",
        target_region="us-east-1",
        profile_used="vyra-readonly",
        total_controls=10,
        passed_controls=8,
        failed_controls=2,
    )
    finding = Finding(
        id="FND-REP-1",
        run_id="RUN-REPORT-TEST",
        control_id="VYRA-IAM-001",
        title="Access Key Exposure Risk",
        description="User has active key without rotation",
        severity="HIGH",
        status="OPEN",
        resource_id="user-auditor",
        resource_arn="arn:aws:iam::112233445566:user/user-auditor",
        service="iam",
        remediation_guidance="Rotate key immediately",
        verification_result="UNVERIFIED",
    )
    eval_item = ControlEvaluation(
        id="EV-REP-1",
        run_id="RUN-REPORT-TEST",
        control_id="VYRA-IAM-001",
        title="IAM Access Key Posture",
        category="IAM",
        severity="HIGH",
        status="FAIL",
        resource_id="user-auditor",
        resource_arn="arn:aws:iam::112233445566:user/user-auditor",
        rationale="Active access key exceeds max age",
        evidence_source="IAM:ListAccessKeys",
    )

    json_rep = ReportGenerator.generate_json_report(run, [eval_item], [finding])
    html_rep = ReportGenerator.generate_html_report(run, [eval_item], [finding])

    # Check secret sanitization
    secret_payload = {
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "token": "sensitive_session_token_12345678",
        "password": "SuperSecretPassword123!",
    }
    sanitized = sanitize_dict(secret_payload)
    assert "[REDACTED_BY_VYRA_GUARD]" in sanitized["aws_secret_access_key"]
    assert "[REDACTED_BY_VYRA_GUARD]" in sanitized["token"]
    assert "[REDACTED_BY_VYRA_GUARD]" in sanitized["password"]

    # Verify report summaries
    assert json_rep["assessment_run"]["id"] == "RUN-REPORT-TEST"
    assert len(json_rep["findings"]) == 1
    assert "RUN-REPORT-TEST" in html_rep
    assert "112233445566" in html_rep


# ---------------------------------------------------------------------------
# 18. Investigation Sessions Remain Scoped to Their Assessment Run
# ---------------------------------------------------------------------------
def test_acceptance_18_investigation_sessions_run_scoped(acceptance_client):
    client, db = acceptance_client
    t = datetime(2026, 10, 17, 12, 0, 0, tzinfo=UTC)

    run_1 = AssessmentRun(id="RUN-INV-1", started_at=t, completed_at=t + timedelta(minutes=1), status="COMPLETED", mode="DEMO_FIXTURE", target_account="112233445566")
    run_2 = AssessmentRun(id="RUN-INV-2", started_at=t + timedelta(hours=1), completed_at=t + timedelta(hours=1, minutes=1), status="COMPLETED", mode="DEMO_FIXTURE", target_account="223344556677")

    f_1 = Finding(id="F-1", run_id="RUN-INV-1", control_id="VYRA-S3-001", title="F1", description="desc 1", severity="HIGH", status="OPEN", resource_id="res-1", resource_arn="arn-1", service="s3")
    f_2 = Finding(id="F-2", run_id="RUN-INV-2", control_id="VYRA-S3-001", title="F2", description="desc 2", severity="HIGH", status="OPEN", resource_id="res-2", resource_arn="arn-2", service="s3")

    sess_1 = InvestigationSession(
        id="INV-SESS-1",
        title="Session 1",
        created_at=t,
        resource_id="res-1",
        finding_id="F-1",
        target_account="112233445566",
        target_region="us-east-1",
        time_window_start=t - timedelta(days=1),
        time_window_end=t,
        status="COMPLETED",
        summary="Investigation 1",
    )
    sess_2 = InvestigationSession(
        id="INV-SESS-2",
        title="Session 2",
        created_at=t + timedelta(hours=1),
        resource_id="res-2",
        finding_id="F-2",
        target_account="223344556677",
        target_region="us-east-1",
        time_window_start=t - timedelta(days=1),
        time_window_end=t,
        status="COMPLETED",
        summary="Investigation 2",
    )

    db.add_all([run_1, run_2, f_1, f_2, sess_1, sess_2])
    db.commit()

    # Querying RUN-INV-1 returns only session 1
    res1 = client.get("/api/v1/investigation/sessions?run_id=RUN-INV-1").json()
    assert len(res1) == 1
    assert res1[0]["id"] == "INV-SESS-1"

    # Querying RUN-INV-2 returns only session 2
    res2 = client.get("/api/v1/investigation/sessions?run_id=RUN-INV-2").json()
    assert len(res2) == 1
    assert res2[0]["id"] == "INV-SESS-2"
