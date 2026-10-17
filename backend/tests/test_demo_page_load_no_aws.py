from unittest.mock import patch

import pytest

from backend.app.core.config import settings
from backend.app.main import app, lifespan


@pytest.mark.asyncio
async def test_app_startup_lifespan_invokes_no_aws():
    """Proves that FastAPI application startup hooks make zero boto3/AWS calls."""
    with patch("backend.app.collectors.aws_session.create_boto3_session") as mock_create_session, \
         patch("boto3.Session") as mock_boto_session, \
         patch("boto3.client") as mock_boto_client:

        async with lifespan(app):
            pass

        assert mock_create_session.call_count == 0, "Startup must not create a boto3 session"
        assert mock_boto_session.call_count == 0, "Startup must not instantiate boto3.Session"
        assert mock_boto_client.call_count == 0, "Startup must not instantiate any boto3 client"


def test_health_endpoint_page_load_invokes_no_aws(client):
    """Proves that GET /api/v1/health makes zero boto3/AWS calls on standard page load."""
    with patch("backend.app.collectors.aws_session.create_boto3_session") as mock_create_session, \
         patch("boto3.Session") as mock_boto_session, \
         patch("boto3.client") as mock_boto_client:

        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "HEALTHY"

        assert mock_create_session.call_count == 0, "Default health check must not call create_boto3_session"
        assert mock_boto_session.call_count == 0, "Default health check must not instantiate boto3.Session"
        assert mock_boto_client.call_count == 0, "Default health check must not instantiate boto3.client"


def test_connectors_page_load_invokes_no_aws(client):
    """Proves that GET /api/v1/connectors makes zero boto3/AWS calls on default page load."""
    with patch("backend.app.collectors.aws_session.create_boto3_session") as mock_create_session, \
         patch("boto3.Session") as mock_boto_session, \
         patch("boto3.client") as mock_boto_client:

        # Default query (as invoked by ConnectorsView.tsx)
        res1 = client.get("/api/v1/connectors")
        assert res1.status_code == 200
        assert len(res1.json()) == 12

        # Explicit region query
        res2 = client.get("/api/v1/connectors?region=ap-south-1")
        assert res2.status_code == 200
        assert len(res2.json()) == 12

        # Explicit AUTO mode
        res3 = client.get("/api/v1/connectors?mode=AUTO")
        assert res3.status_code == 200
        assert len(res3.json()) == 12

        # Explicit DEMO_FIXTURE mode
        res4 = client.get("/api/v1/connectors?mode=DEMO_FIXTURE")
        assert res4.status_code == 200
        assert len(res4.json()) == 12

        # Specific connector query
        res5 = client.get("/api/v1/connectors/s3")
        assert res5.status_code == 200

        res6 = client.get("/api/v1/connectors/sts?mode=AUTO")
        assert res6.status_code == 200

        assert mock_create_session.call_count == 0, "Connector routes in non-LIVE mode must not create boto3 session"
        assert mock_boto_session.call_count == 0, "Connector routes must not instantiate boto3.Session"
        assert mock_boto_client.call_count == 0, "Connector routes must not instantiate boto3.client"


def test_full_dashboard_page_load_sequence_invokes_no_aws(client):
    """Proves that the full sequence of API requests triggered by frontend page load makes zero AWS calls."""
    # First seed a demo assessment so scoped entities exist
    client.post("/api/v1/assessment/trigger", json={"mode": "DEMO_FIXTURE"})

    page_load_endpoints = [
        "/api/v1/health",
        "/api/v1/assessment/metrics",
        "/api/v1/assessment/runs",
        "/api/v1/assets",
        "/api/v1/findings",
        "/api/v1/controls/evaluations",
        "/api/v1/remediation/plans",
        "/api/v1/audit",
        "/api/v1/connectors?region=ap-south-1",
        "/api/v1/verification/history",
        "/api/v1/investigation/sessions",
        "/api/v1/plan-check/runs",
        "/api/v1/reports/json",
        "/api/v1/reports/html",
    ]

    with patch("backend.app.collectors.aws_session.create_boto3_session") as mock_create_session, \
         patch("boto3.Session") as mock_boto_session, \
         patch("boto3.client") as mock_boto_client:

        for endpoint in page_load_endpoints:
            res = client.get(endpoint)
            assert res.status_code == 200, f"Expected 200 from {endpoint}, got {res.status_code}"

        assert mock_create_session.call_count == 0, "Dashboard page load sequence must never call create_boto3_session"
        assert mock_boto_session.call_count == 0, "Dashboard page load sequence must never instantiate boto3.Session"
        assert mock_boto_client.call_count == 0, "Dashboard page load sequence must never instantiate boto3.client"


def test_demo_assessment_trigger_invokes_no_aws(client):
    """Proves that triggering a DEMO_FIXTURE assessment makes zero AWS calls."""
    with patch("backend.app.collectors.aws_session.create_boto3_session") as mock_create_session, \
         patch("boto3.Session") as mock_boto_session, \
         patch("boto3.client") as mock_boto_client:

        res = client.post("/api/v1/assessment/trigger", json={"mode": "DEMO_FIXTURE"})
        assert res.status_code == 200
        assert res.json()["mode"] == "DEMO_FIXTURE"
        assert res.json()["status"] == "COMPLETED"

        assert mock_create_session.call_count == 0, "Demo assessment must never call create_boto3_session"
        assert mock_boto_session.call_count == 0, "Demo assessment must never instantiate boto3.Session"
        assert mock_boto_client.call_count == 0, "Demo assessment must never instantiate boto3.client"


def test_live_assessment_trigger_still_enforces_guards_and_attempts_session(client):
    """Proves that explicitly requested LIVE assessments preserve the vyra-readonly and account guards."""
    # 1. Missing expected account ID halts immediately before AWS calls
    with patch.object(settings, "VYRA_EXPECTED_AWS_ACCOUNT_ID", None):
        res = client.post(
            "/api/v1/assessment/trigger",
            json={"mode": "LIVE_AWS", "profile": "vyra-readonly"}
        )
        assert res.status_code == 400
        assert "Expected AWS Account ID is not configured" in res.json()["detail"]

    # 2. Arbitrary profile injection rejected
    res_bad_profile = client.post(
        "/api/v1/assessment/trigger",
        json={"mode": "LIVE_AWS", "profile": "malicious-admin-profile"}
    )
    assert res_bad_profile.status_code == 400
    assert "Unauthorized profile" in res_bad_profile.json()["detail"]

    # 3. Explicit LIVE connectors route verifies expected account ID
    with patch.object(settings, "VYRA_EXPECTED_AWS_ACCOUNT_ID", None):
        res_live_connectors = client.get("/api/v1/connectors?mode=LIVE_AWS")
        assert res_live_connectors.status_code == 400
        assert "Expected AWS Account ID is not configured" in res_live_connectors.json()["detail"]
