"""Tests for DEMO vs LIVE data isolation and run-scoping in VYRA.

Verifies:
1. Default overview context selects the latest completed run.
2. Findings returned in default context belong strictly to the latest completed run.
3. Discovered assets returned in default context belong strictly to the latest completed run.
4. Control evaluations returned in default context belong strictly to the latest completed run.
5. Remediation plans returned in default context belong strictly to the latest completed run.
6. Demo run excludes live bucket ('live-production-vault-998877665544-ap-south-1') and account ('998877665544').
7. Live run query excludes demo fixtures.
8. Explicit valid run_id returns data strictly belonging to that requested run.
9. Explicit invalid or non-existent run_id returns 404 across all scoped endpoints.
10. Empty database returns appropriate empty state, never crashing or querying unrelated data.
11. Only COMPLETED runs are chosen as default (FAILED or RUNNING runs ignored for default context).
12. Detail endpoints (/findings/{id}, /assets/{id}, /controls/evaluations/{id}, /remediation/plans/{id})
    do not leak across runs if run_id is scoped.
13. Reports (JSON and HTML) respect the run scope and do not leak across runs.
14. Mode switch / refresh behaves predictably without cross-run contamination.

CRITICAL: All tests run against an isolated in-memory SQLite database.
The production/local database 'vyra.db' is never touched, altered, or deleted.
"""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.database import Base, get_db
from backend.app.main import app
from backend.app.models.models import (
    AssessmentRun,
    Asset,
    ControlEvaluation,
    Finding,
    InvestigationSession,
    RemediationPlan,
    VerificationRun,
)


@pytest.fixture
def isolated_db():
    """Create an isolated, temporary in-memory database fixture for each test."""
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=test_engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    session = TestingSessionLocal()
    try:
        yield session, TestingSessionLocal
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def client(isolated_db):
    """FastAPI TestClient with isolated test database session override."""
    session, TestingSessionLocal = isolated_db

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client, session
    app.dependency_overrides.clear()


def seed_multi_run_dataset(db):
    """Seeds two distinct completed runs: an older LIVE run and a newer DEMO run, plus an incomplete run."""
    t0 = datetime(2026, 10, 16, 10, 0, 0, tzinfo=UTC)
    t1 = datetime(2026, 10, 17, 10, 0, 0, tzinfo=UTC)
    t2 = datetime(2026, 10, 17, 12, 0, 0, tzinfo=UTC)

    # 1. Historical LIVE Run (Run 1)
    run_live = AssessmentRun(
        id="RUN-LIVE-001",
        started_at=t0,
        completed_at=t0 + timedelta(minutes=5),
        status="COMPLETED",
        mode="LIVE_AWS",
        target_account="998877665544",
        target_region="ap-south-1",
        profile_used="vyra-readonly",
        total_assets=1,
        total_controls=10,
        passed_controls=8,
        failed_controls=2,
        error_controls=0,
        unknown_controls=0,
        not_configured_controls=0,
        summary_metadata={"collector": "live"},
    )

    asset_live = Asset(
        id="asset-live-s3-1",
        run_id="RUN-LIVE-001",
        account_id="998877665544",
        region="ap-south-1",
        service="s3",
        asset_type="s3:bucket",
        name="live-production-vault-998877665544-ap-south-1",
        arn="arn:aws:s3:::live-production-vault-998877665544-ap-south-1",
        first_seen=t0,
        last_seen=t0,
        configuration_data={"public_access": False},
    )

    finding_live = Finding(
        id="finding-live-001",
        run_id="RUN-LIVE-001",
        control_id="VYRA-S3-001",
        title="Live S3 Public Access Disabled",
        description="Live production bucket check",
        severity="HIGH",
        status="OPEN",
        resource_id="live-production-vault-998877665544-ap-south-1",
        resource_arn="arn:aws:s3:::live-production-vault-998877665544-ap-south-1",
        service="s3",
        first_seen=t0,
        last_seen=t0,
        verification_result="UNVERIFIED",
    )

    plan_live = RemediationPlan(
        id="plan-live-001",
        finding_id="finding-live-001",
        title="Remediate live vault bucket",
        risk_explanation="Exposure risk for production bucket",
        dry_run_action="aws s3api put-public-access-block",
        cli_command="aws s3api put-public-access-block --bucket live-production-vault-998877665544-ap-south-1",
        terraform_snippet='resource "aws_s3_bucket_public_access_block" "live" {}',
        status="PROPOSED",
    )

    eval_live = ControlEvaluation(
        id="eval-live-001",
        run_id="RUN-LIVE-001",
        control_id="VYRA-S3-001",
        title="S3 Public Access Block",
        category="Storage",
        severity="HIGH",
        status="FAIL",
        resource_id="live-production-vault-998877665544-ap-south-1",
        resource_arn="arn:aws:s3:::live-production-vault-998877665544-ap-south-1",
        rationale="Live vault bucket missing restrictive public access block",
        evidence_source="AWS:S3:GetPublicAccessBlock",
        timestamp=t0,
        evidence_data={},
    )

    # 2. Latest DEMO Run (Run 2)
    run_demo = AssessmentRun(
        id="RUN-DEMO-002",
        started_at=t1,
        completed_at=t1 + timedelta(minutes=2),
        status="COMPLETED",
        mode="DEMO_FIXTURE",
        target_account="112233445566",
        target_region="us-east-1",
        profile_used="demo-benchmark-fixture",
        total_assets=1,
        total_controls=10,
        passed_controls=7,
        failed_controls=3,
        error_controls=0,
        unknown_controls=0,
        not_configured_controls=0,
        summary_metadata={"fixture": "enterprise-benchmark"},
    )

    asset_demo = Asset(
        id="asset-demo-s3-1",
        run_id="RUN-DEMO-002",
        account_id="112233445566",
        region="us-east-1",
        service="s3",
        asset_type="s3:bucket",
        name="demo-customer-data-benchmark-us-east-1",
        arn="arn:aws:s3:::demo-customer-data-benchmark-us-east-1",
        first_seen=t1,
        last_seen=t1,
        configuration_data={"public_access": True},
    )

    finding_demo = Finding(
        id="finding-demo-002",
        run_id="RUN-DEMO-002",
        control_id="VYRA-S3-001",
        title="Demo Fixture S3 Public Access Allowed",
        description="Simulated customer benchmark fixture bucket",
        severity="CRITICAL",
        status="OPEN",
        resource_id="demo-customer-data-benchmark-us-east-1",
        resource_arn="arn:aws:s3:::demo-customer-data-benchmark-us-east-1",
        service="s3",
        first_seen=t1,
        last_seen=t1,
        verification_result="UNVERIFIED",
    )

    plan_demo = RemediationPlan(
        id="plan-demo-002",
        finding_id="finding-demo-002",
        title="Apply demo S3 restrictive policy",
        risk_explanation="Demo exposure risk",
        dry_run_action="aws s3api put-public-access-block",
        cli_command="aws s3api put-public-access-block --bucket demo-customer-data-benchmark-us-east-1",
        terraform_snippet='resource "aws_s3_bucket_public_access_block" "demo" {}',
        status="PROPOSED",
    )

    eval_demo = ControlEvaluation(
        id="eval-demo-002",
        run_id="RUN-DEMO-002",
        control_id="VYRA-S3-001",
        title="S3 Public Access Block",
        category="Storage",
        severity="CRITICAL",
        status="FAIL",
        resource_id="demo-customer-data-benchmark-us-east-1",
        resource_arn="arn:aws:s3:::demo-customer-data-benchmark-us-east-1",
        rationale="Demo benchmark bucket allows public access",
        evidence_source="DemoFixture",
        timestamp=t1,
        evidence_data={},
    )

    # 3. In-flight RUNNING Run (Run 3 - should NOT be chosen as default completed context)
    run_running = AssessmentRun(
        id="RUN-INFLIGHT-003",
        started_at=t2,
        completed_at=None,
        status="RUNNING",
        mode="LIVE_AWS",
        target_account="999888777666",
        target_region="eu-west-1",
        profile_used="vyra-readonly",
        total_assets=0,
        total_controls=0,
        passed_controls=0,
        failed_controls=0,
        error_controls=0,
        unknown_controls=0,
        not_configured_controls=0,
    )

    db.add_all([
        run_live, asset_live, finding_live, plan_live, eval_live,
        run_demo, asset_demo, finding_demo, plan_demo, eval_demo,
        run_running,
    ])
    db.commit()


def test_1_default_overview_context_selects_latest_completed_run(client):
    test_client, db = client
    seed_multi_run_dataset(db)

    res = test_client.get("/api/v1/assessment/metrics")
    assert res.status_code == 200
    metrics = res.json()

    # Must select latest COMPLETED run (RUN-DEMO-002), ignoring RUN-INFLIGHT-003 and older RUN-LIVE-001
    assert metrics["run_id"] == "RUN-DEMO-002"
    assert metrics["mode"] == "DEMO_FIXTURE"
    assert metrics["account_id"] == "112233445566"
    assert metrics["region"] == "us-east-1"
    assert metrics["profile"] == "demo-benchmark-fixture"


def test_2_findings_in_default_context_belong_strictly_to_latest_run(client):
    test_client, db = client
    seed_multi_run_dataset(db)

    res = test_client.get("/api/v1/findings")
    assert res.status_code == 200
    findings = res.json()

    assert len(findings) == 1
    assert findings[0]["id"] == "finding-demo-002"
    assert findings[0]["run_id"] == "RUN-DEMO-002"
    assert findings[0]["resource_id"] == "demo-customer-data-benchmark-us-east-1"


def test_3_discovered_assets_in_default_context_belong_strictly_to_latest_run(client):
    test_client, db = client
    seed_multi_run_dataset(db)

    res = test_client.get("/api/v1/assets")
    assert res.status_code == 200
    assets = res.json()

    assert len(assets) == 1
    assert assets[0]["id"] == "asset-demo-s3-1"
    assert assets[0]["run_id"] == "RUN-DEMO-002"
    assert assets[0]["name"] == "demo-customer-data-benchmark-us-east-1"


def test_4_control_evaluations_in_default_context_belong_strictly_to_latest_run(client):
    test_client, db = client
    seed_multi_run_dataset(db)

    res = test_client.get("/api/v1/controls/evaluations")
    assert res.status_code == 200
    evals = res.json()

    assert len(evals) == 1
    assert evals[0]["id"] == "eval-demo-002"
    assert evals[0]["run_id"] == "RUN-DEMO-002"
    assert evals[0]["resource_id"] == "demo-customer-data-benchmark-us-east-1"


def test_5_remediation_plans_in_default_context_belong_strictly_to_latest_run(client):
    test_client, db = client
    seed_multi_run_dataset(db)

    res = test_client.get("/api/v1/remediation/plans")
    assert res.status_code == 200
    plans = res.json()

    assert len(plans) == 1
    assert plans[0]["id"] == "plan-demo-002"
    assert plans[0]["finding_id"] == "finding-demo-002"


def test_6_demo_run_excludes_live_bucket_and_account(client):
    test_client, db = client
    seed_multi_run_dataset(db)

    # 1. Check overview metrics
    metrics_res = test_client.get("/api/v1/assessment/metrics")
    metrics = metrics_res.json()
    assert metrics["account_id"] != "998877665544"
    assert metrics["account_id"] == "112233445566"

    # 2. Check findings
    findings = test_client.get("/api/v1/findings").json()
    assert not any("live-production-vault" in f["resource_id"] for f in findings)
    assert not any(f["run_id"] == "RUN-LIVE-001" for f in findings)

    # 3. Check assets
    assets = test_client.get("/api/v1/assets").json()
    assert not any("live-production-vault" in a["name"] for a in assets)
    assert not any(a["account_id"] == "998877665544" for a in assets)

    # 4. Check remediation plans
    plans = test_client.get("/api/v1/remediation/plans").json()
    assert not any("live-production-vault" in p["cli_command"] for p in plans)


def test_7_live_run_query_excludes_demo_fixtures(client):
    test_client, db = client
    seed_multi_run_dataset(db)

    # Explicitly scope to the live run
    live_run_id = "RUN-LIVE-001"
    metrics = test_client.get(f"/api/v1/assessment/metrics?run_id={live_run_id}").json()
    assert metrics["run_id"] == live_run_id
    assert metrics["mode"] == "LIVE_AWS"
    assert metrics["account_id"] == "998877665544"

    findings = test_client.get(f"/api/v1/findings?run_id={live_run_id}").json()
    assert len(findings) == 1
    assert findings[0]["resource_id"] == "live-production-vault-998877665544-ap-south-1"
    assert not any("demo" in f["resource_id"].lower() for f in findings)

    assets = test_client.get(f"/api/v1/assets?run_id={live_run_id}").json()
    assert len(assets) == 1
    assert assets[0]["name"] == "live-production-vault-998877665544-ap-south-1"
    assert not any("demo" in a["name"].lower() for a in assets)


def test_8_explicit_valid_run_id_returns_strictly_requested_run_data(client):
    test_client, db = client
    seed_multi_run_dataset(db)

    # Check metrics, findings, assets, evaluations, plans for LIVE run
    live_id = "RUN-LIVE-001"
    assert test_client.get(f"/api/v1/assessment/metrics?run_id={live_id}").json()["run_id"] == live_id
    assert len(test_client.get(f"/api/v1/findings?run_id={live_id}").json()) == 1
    assert len(test_client.get(f"/api/v1/assets?run_id={live_id}").json()) == 1
    assert len(test_client.get(f"/api/v1/controls/evaluations?run_id={live_id}").json()) == 1
    assert len(test_client.get(f"/api/v1/remediation/plans?run_id={live_id}").json()) == 1

    # Check metrics, findings, assets, evaluations, plans for DEMO run
    demo_id = "RUN-DEMO-002"
    assert test_client.get(f"/api/v1/assessment/metrics?run_id={demo_id}").json()["run_id"] == demo_id
    assert len(test_client.get(f"/api/v1/findings?run_id={demo_id}").json()) == 1
    assert len(test_client.get(f"/api/v1/assets?run_id={demo_id}").json()) == 1
    assert len(test_client.get(f"/api/v1/controls/evaluations?run_id={demo_id}").json()) == 1
    assert len(test_client.get(f"/api/v1/remediation/plans?run_id={demo_id}").json()) == 1


def test_9_explicit_invalid_run_id_returns_404_on_all_scoped_endpoints(client):
    test_client, db = client
    seed_multi_run_dataset(db)

    bad_id = "RUN-DOES-NOT-EXIST-404"

    assert test_client.get(f"/api/v1/assessment/metrics?run_id={bad_id}").status_code == 404
    assert test_client.get(f"/api/v1/findings?run_id={bad_id}").status_code == 404
    assert test_client.get(f"/api/v1/assets?run_id={bad_id}").status_code == 404
    assert test_client.get(f"/api/v1/controls/evaluations?run_id={bad_id}").status_code == 404
    assert test_client.get(f"/api/v1/remediation/plans?run_id={bad_id}").status_code == 404
    assert test_client.get(f"/api/v1/reports/json?run_id={bad_id}").status_code == 404
    assert test_client.get(f"/api/v1/reports/html?run_id={bad_id}").status_code == 404


def test_10_empty_database_returns_empty_state_without_crashing(client):
    test_client, db = client
    # Database is completely empty

    metrics_res = test_client.get("/api/v1/assessment/metrics")
    assert metrics_res.status_code == 200
    metrics = metrics_res.json()
    assert metrics["mode"] == "NOT_SCANNED"
    assert metrics["run_id"] is None
    assert metrics["total_assets"] == 0
    assert metrics["total_findings"] == 0

    assert test_client.get("/api/v1/findings").json() == []
    assert test_client.get("/api/v1/assets").json() == []
    assert test_client.get("/api/v1/controls/evaluations").json() == []
    assert test_client.get("/api/v1/remediation/plans").json() == []

    # Reports should return 404 when no runs exist
    assert test_client.get("/api/v1/reports/json").status_code == 404
    assert test_client.get("/api/v1/reports/html").status_code == 404


def test_11_only_completed_runs_are_chosen_as_default(client):
    test_client, db = client
    t = datetime(2026, 10, 17, 14, 0, 0, tzinfo=UTC)

    # 1. Insert a failed run
    failed_run = AssessmentRun(
        id="RUN-FAILED-001",
        started_at=t,
        completed_at=t + timedelta(minutes=1),
        status="FAILED",
        mode="LIVE_AWS",
        target_account="998877665544",
        target_region="ap-south-1",
        profile_used="vyra-readonly",
        total_assets=0,
        total_controls=0,
        passed_controls=0,
        failed_controls=0,
        error_controls=0,
        unknown_controls=0,
        not_configured_controls=0,
    )
    db.add(failed_run)
    db.commit()

    # Metrics should still return empty state because no COMPLETED run exists
    res = test_client.get("/api/v1/assessment/metrics")
    assert res.status_code == 200
    assert res.json()["mode"] == "NOT_SCANNED"

    # 2. Insert an older completed run
    completed_run = AssessmentRun(
        id="RUN-COMPLETED-001",
        started_at=t - timedelta(hours=1),
        completed_at=t - timedelta(minutes=50),
        status="COMPLETED",
        mode="DEMO_FIXTURE",
        target_account="112233445566",
        target_region="us-east-1",
        profile_used="demo-benchmark-fixture",
        total_assets=0,
        total_controls=5,
        passed_controls=5,
        failed_controls=0,
        error_controls=0,
        unknown_controls=0,
        not_configured_controls=0,
    )
    db.add(completed_run)
    db.commit()

    # Now the completed run MUST be chosen, even though the failed run has a newer timestamp
    metrics = test_client.get("/api/v1/assessment/metrics").json()
    assert metrics["run_id"] == "RUN-COMPLETED-001"
    assert metrics["mode"] == "DEMO_FIXTURE"


def test_12_detail_endpoints_scoped_to_run_id_prevent_cross_run_leakage(client):
    test_client, db = client
    seed_multi_run_dataset(db)

    # Looking for a live finding with demo run_id must return 404
    res = test_client.get("/api/v1/findings/finding-live-001?run_id=RUN-DEMO-002")
    assert res.status_code == 404

    # Looking for a live finding with matching live run_id must succeed
    res = test_client.get("/api/v1/findings/finding-live-001?run_id=RUN-LIVE-001")
    assert res.status_code == 200
    assert res.json()["id"] == "finding-live-001"

    # Looking for a live asset with demo run_id must return 404
    res = test_client.get("/api/v1/assets/asset-live-s3-1?run_id=RUN-DEMO-002")
    assert res.status_code == 404

    # Looking for a live asset with matching live run_id must succeed
    res = test_client.get("/api/v1/assets/asset-live-s3-1?run_id=RUN-LIVE-001")
    assert res.status_code == 200

    # Looking for a live remediation plan with demo run_id must return 404
    res = test_client.get("/api/v1/remediation/plans/plan-live-001?run_id=RUN-DEMO-002")
    assert res.status_code == 404

    # Looking for a live remediation plan with matching live run_id must succeed
    res = test_client.get("/api/v1/remediation/plans/plan-live-001?run_id=RUN-LIVE-001")
    assert res.status_code == 200

    # Looking for a live evaluation with demo run_id must return 404
    res = test_client.get("/api/v1/controls/evaluations/eval-live-001?run_id=RUN-DEMO-002")
    assert res.status_code == 404

    # Looking for a live evaluation with matching live run_id must succeed
    res = test_client.get("/api/v1/controls/evaluations/eval-live-001?run_id=RUN-LIVE-001")
    assert res.status_code == 200


def test_13_reports_respect_run_scope_without_cross_run_leakage(client):
    test_client, db = client
    seed_multi_run_dataset(db)

    # 1. JSON report for demo run
    demo_rep = test_client.get("/api/v1/reports/json?run_id=RUN-DEMO-002").json()
    assert demo_rep["assessment_run"]["id"] == "RUN-DEMO-002"
    assert demo_rep["assessment_run"]["target_account"] == "112233445566"
    assert len(demo_rep["findings"]) == 1
    assert demo_rep["findings"][0]["id"] == "finding-demo-002"
    assert "live-production-vault" not in str(demo_rep)

    # 2. JSON report for live run
    live_rep = test_client.get("/api/v1/reports/json?run_id=RUN-LIVE-001").json()
    assert live_rep["assessment_run"]["id"] == "RUN-LIVE-001"
    assert live_rep["assessment_run"]["target_account"] == "998877665544"
    assert len(live_rep["findings"]) == 1
    assert live_rep["findings"][0]["id"] == "finding-live-001"
    assert "live-production-vault" in str(live_rep)

    # 3. HTML report for demo run
    html_demo = test_client.get("/api/v1/reports/html?run_id=RUN-DEMO-002").text
    assert "RUN-DEMO-002" in html_demo
    assert "112233445566" in html_demo
    assert "live-production-vault" not in html_demo

    # 4. HTML report for live run
    html_live = test_client.get("/api/v1/reports/html?run_id=RUN-LIVE-001").text
    assert "RUN-LIVE-001" in html_live
    assert "998877665544" in html_live
    assert "live-production-vault" in html_live


def test_14_mode_switch_and_run_filtering_consistency(client):
    test_client, db = client
    seed_multi_run_dataset(db)

    # Default is latest completed (DEMO)
    def_metrics = test_client.get("/api/v1/assessment/metrics").json()
    assert def_metrics["mode"] == "DEMO_FIXTURE"
    assert def_metrics["run_id"] == "RUN-DEMO-002"

    # Switching inspection scope to LIVE run
    live_metrics = test_client.get("/api/v1/assessment/metrics?run_id=RUN-LIVE-001").json()
    assert live_metrics["mode"] == "LIVE_AWS"
    assert live_metrics["run_id"] == "RUN-LIVE-001"

    # Switching back to DEMO run
    demo_metrics = test_client.get("/api/v1/assessment/metrics?run_id=RUN-DEMO-002").json()
    assert demo_metrics["mode"] == "DEMO_FIXTURE"
    assert demo_metrics["run_id"] == "RUN-DEMO-002"

    # Verifying findings filter works on scoped run
    s3_findings = test_client.get("/api/v1/findings?run_id=RUN-LIVE-001&service=s3").json()
    assert len(s3_findings) == 1
    assert s3_findings[0]["resource_id"] == "live-production-vault-998877665544-ap-south-1"

    iam_findings = test_client.get("/api/v1/findings?run_id=RUN-LIVE-001&service=iam").json()
    assert len(iam_findings) == 0


def test_15_verification_history_isolated_and_excludes_test_fixtures(client):
    test_client, db = client
    seed_multi_run_dataset(db)
    t = datetime(2026, 10, 17, 12, 0, 0, tzinfo=UTC)

    # 1. Verification run for LIVE finding
    vrun_live = VerificationRun(
        id="VRUN-LIVE-001",
        created_at=t - timedelta(hours=2),
        finding_id="finding-live-001",
        resource_id="live-production-vault-998877665544-ap-south-1",
        account_id="998877665544",
        outcome="RESOLVED",
        comparison_summary="Live bucket verified remediated",
    )

    # 2. Verification run for DEMO finding
    vrun_demo = VerificationRun(
        id="VRUN-DEMO-001",
        created_at=t - timedelta(hours=1),
        finding_id="finding-demo-002",
        resource_id="demo-customer-data-benchmark-us-east-1",
        account_id="112233445566",
        outcome="STILL_PRESENT",
        comparison_summary="Demo bucket still allows public access",
    )

    # 3. Test fixture verification run (from test runner with EndpointConnectionError)
    test_finding = Finding(
        id="FND-TEST-VERIFY-BCE-001",
        run_id="RUN-TEST",
        control_id="VYRA-S3-001",
        title="Test BCE Bucket",
        description="Test fixture finding",
        severity="HIGH",
        status="OPEN",
        resource_id="test-bce-bucket",
        resource_arn="arn:aws:s3:::test-bce-bucket",
        service="s3",
        verification_result="UNVERIFIABLE",
    )
    vrun_test = VerificationRun(
        id="VRUN-TEST-BCE-001",
        created_at=t,
        finding_id="FND-TEST-VERIFY-BCE-001",
        resource_id="test-bce-bucket",
        account_id="unknown",
        outcome="UNVERIFIABLE",
        limitations='AWS client communication error (EndpointConnectionError): Could not connect to the endpoint URL: "https://s3.ap-south-1.amazonaws.com"',
        comparison_summary="Verification could not be completed due to EndpointConnectionError",
    )

    db.add_all([vrun_live, vrun_demo, test_finding, vrun_test])
    db.commit()

    # In default context (latest completed is DEMO), verification history must ONLY show demo run
    default_history = test_client.get("/api/v1/verification/history").json()
    assert len(default_history) == 1
    assert default_history[0]["id"] == "VRUN-DEMO-001"
    assert default_history[0]["finding_id"] == "finding-demo-002"
    # The test fixture EndpointConnectionError must NOT be present
    assert not any("EndpointConnectionError" in (r.get("limitations") or "") for r in default_history)
    assert not any(r["id"] == "VRUN-TEST-BCE-001" for r in default_history)
    assert not any(r["id"] == "VRUN-LIVE-001" for r in default_history)

    # When querying LIVE run verification history, must only show live run
    live_history = test_client.get("/api/v1/verification/history?run_id=RUN-LIVE-001").json()
    assert len(live_history) == 1
    assert live_history[0]["id"] == "VRUN-LIVE-001"
    assert live_history[0]["resource_id"] == "live-production-vault-998877665544-ap-south-1"

    # Invalid run_id must return 404
    assert test_client.get("/api/v1/verification/history?run_id=RUN-INVALID-404").status_code == 404


def test_16_investigation_sessions_isolated_by_run(client):
    test_client, db = client
    seed_multi_run_dataset(db)
    t = datetime(2026, 10, 17, 12, 0, 0, tzinfo=UTC)

    session_live = InvestigationSession(
        id="INV-LIVE-001",
        title="Live S3 Exposure Investigation",
        created_at=t - timedelta(hours=2),
        resource_id="live-production-vault-998877665544-ap-south-1",
        finding_id="finding-live-001",
        target_account="998877665544",
        target_region="ap-south-1",
        time_window_start=t - timedelta(days=7),
        time_window_end=t,
        status="COMPLETED",
        summary="Live investigation",
    )

    session_demo = InvestigationSession(
        id="INV-DEMO-001",
        title="Demo Benchmark Investigation",
        created_at=t - timedelta(hours=1),
        resource_id="demo-customer-data-benchmark-us-east-1",
        finding_id="finding-demo-002",
        target_account="112233445566",
        target_region="us-east-1",
        time_window_start=t - timedelta(days=7),
        time_window_end=t,
        status="COMPLETED",
        summary="Demo investigation",
    )

    db.add_all([session_live, session_demo])
    db.commit()

    # Querying DEMO run returns only demo session
    demo_sessions = test_client.get("/api/v1/investigation/sessions?run_id=RUN-DEMO-002").json()
    assert len(demo_sessions) == 1
    assert demo_sessions[0]["id"] == "INV-DEMO-001"
    assert demo_sessions[0]["target_account"] == "112233445566"

    # Querying LIVE run returns only live session
    live_sessions = test_client.get("/api/v1/investigation/sessions?run_id=RUN-LIVE-001").json()
    assert len(live_sessions) == 1
    assert live_sessions[0]["id"] == "INV-LIVE-001"
    assert live_sessions[0]["target_account"] == "998877665544"
