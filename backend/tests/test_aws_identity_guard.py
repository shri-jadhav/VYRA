from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.exceptions import ProfileNotFound
from botocore.stub import Stubber
from fastapi.testclient import TestClient

from backend.app.collectors.aws_session import (
    AWSAccountIdentityError,
    AWSProfileConfigurationError,
    create_boto3_session,
    validate_caller_identity,
)
from backend.app.collectors.orchestrator import CollectorOrchestrator
from backend.app.core.config import settings
from backend.app.main import app

client = TestClient(app)


def test_1_required_named_profile_loads():
    """Test 1: Required named profile 'vyra-readonly' loads without error."""
    with patch("boto3.Session") as mock_session_cls:
        mock_instance = MagicMock()
        mock_session_cls.return_value = mock_instance

        session = create_boto3_session("vyra-readonly")
        assert session == mock_instance
        mock_session_cls.assert_called_once_with(
            profile_name="vyra-readonly",
            region_name=settings.AWS_DEFAULT_REGION,
        )


def test_2_missing_profile_raises_profile_error():
    """Test 2: Missing profile (ProfileNotFound) raises AWSProfileConfigurationError."""
    with patch("boto3.Session", side_effect=ProfileNotFound(profile="vyra-readonly")):
        with pytest.raises(AWSProfileConfigurationError) as exc_info:
            create_boto3_session("vyra-readonly")
        assert "Required AWS profile 'vyra-readonly' was not found" in str(exc_info.value)


def test_3_no_fallback_session_created_when_profile_missing():
    """Test 3: No fallback ambient session is created when profile is missing; fails closed."""
    with patch("boto3.Session", side_effect=ProfileNotFound(profile="vyra-readonly")) as mock_session_cls:
        with pytest.raises(AWSProfileConfigurationError):
            create_boto3_session("vyra-readonly")

        # Must NOT call boto3.Session() a second time with empty/default args
        assert mock_session_cls.call_count == 1
        call_kwargs = mock_session_cls.call_args[1]
        assert call_kwargs.get("profile_name") == "vyra-readonly"


def test_4_missing_expected_account_id_blocks_live_assessment():
    """Test 4: Missing VYRA_EXPECTED_AWS_ACCOUNT_ID blocks LIVE assessment."""
    with patch.object(settings, "VYRA_EXPECTED_AWS_ACCOUNT_ID", ""):
        with patch.object(settings, "ALLOW_LIVE_COLLECTION", True):
            response = client.post(
                "/api/v1/assessment/trigger",
                json={"mode": "LIVE_AWS", "profile": "vyra-readonly"},
            )
            assert response.status_code == 400
            assert "Expected AWS Account ID is not configured" in response.json()["detail"]


def test_5_matching_sts_account_permits_authorized_flow():
    """Test 5: Matching STS account permits authorized collector flow."""
    sts_client = boto3.client("sts", region_name="us-east-1")
    stubber = Stubber(sts_client)
    stubber.add_response(
        "get_caller_identity",
        {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/vyra-auditor",
            "UserId": "AIDAEXAMPLEUSERID",
        },
    )

    mock_session = MagicMock()
    mock_session.client.return_value = sts_client

    with stubber:
        identity = validate_caller_identity(mock_session, expected_account_id="123456789012")
        assert identity["account_id"] == "123456789012"
        assert identity["arn"] == "arn:aws:iam::123456789012:user/vyra-auditor"


def test_6_mismatched_account_raises_account_identity_error_and_halts():
    """Test 6: Mismatched account raises AWSAccountIdentityError and halts collection."""
    sts_client = boto3.client("sts", region_name="us-east-1")
    stubber = Stubber(sts_client)
    stubber.add_response(
        "get_caller_identity",
        {
            "Account": "999999999999",  # Different from expected
            "Arn": "arn:aws:iam::999999999999:user/rogue-auditor",
            "UserId": "AIDAROGUEUSERID",
        },
    )

    mock_session = MagicMock()
    mock_session.client.return_value = sts_client

    with stubber:
        with pytest.raises(AWSAccountIdentityError) as exc_info:
            validate_caller_identity(mock_session, expected_account_id="123456789012")
        assert "AWS Account identity mismatch" in str(exc_info.value)
        assert "999999999999" in str(exc_info.value)
        assert "123456789012" in str(exc_info.value)


def test_7_sts_failure_stops_assessment_immediately():
    """Test 7: STS ClientError / failure stops assessment immediately."""
    sts_client = boto3.client("sts", region_name="us-east-1")
    stubber = Stubber(sts_client)
    stubber.add_client_error(
        "get_caller_identity",
        service_error_code="InvalidClientTokenId",
        service_message="The security token included in the request is invalid.",
    )

    mock_session = MagicMock()
    mock_session.client.return_value = sts_client

    with stubber:
        with pytest.raises(AWSAccountIdentityError) as exc_info:
            validate_caller_identity(mock_session, expected_account_id="123456789012")
        assert "InvalidClientTokenId" in str(exc_info.value)


def test_8_arbitrary_profile_injection_rejected():
    """Test 8: Arbitrary profile injection in API request and session factory is rejected."""
    # Direct session creation rejection
    with pytest.raises(AWSProfileConfigurationError) as exc_info:
        create_boto3_session("injected-admin-profile")
    assert "Unauthorized profile 'injected-admin-profile'" in str(exc_info.value)

    # API rejection
    response = client.post(
        "/api/v1/assessment/trigger",
        json={"mode": "LIVE_AWS", "profile": "unauthorized-profile-attack"},
    )
    assert response.status_code == 400
    assert "Unauthorized profile 'unauthorized-profile-attack'" in response.json()["detail"]


def test_9_demo_mode_works_offline_without_aws_credentials():
    """Test 9: DEMO mode works fully offline without AWS credentials or network calls."""
    response = client.post(
        "/api/v1/assessment/trigger",
        json={"mode": "DEMO"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["mode"] == "DEMO"
    assert data["status"] == "COMPLETED"
    assert data["profile_used"] == "demo-benchmark-fixture"
    assert data["target_account"] in ["112233445566", "112233445566-DEMO"]
    assert data["total_controls"] > 0


def test_10_orchestrator_halts_before_collecting_resources_on_mismatch():
    """Test 10: Orchestrator halts collection before S3/IAM when account mismatches (botocore Stubber)."""
    sts_client = boto3.client("sts", region_name="us-east-1")
    stubber = Stubber(sts_client)
    # Return wrong account
    stubber.add_response(
        "get_caller_identity",
        {
            "Account": "999999999999",
            "Arn": "arn:aws:iam::999999999999:user/wrong-account",
            "UserId": "AIDAWROOOOOONG",
        },
    )

    mock_session = MagicMock()
    mock_session.client.return_value = sts_client

    orchestrator = CollectorOrchestrator(profile_name="vyra-readonly")
    orchestrator.session = mock_session

    with patch.object(settings, "VYRA_EXPECTED_AWS_ACCOUNT_ID", "123456789012"):
        with patch("backend.app.collectors.orchestrator.S3Collector") as mock_s3_col:
            with patch("backend.app.collectors.orchestrator.IAMCollector") as mock_iam_col:
                with stubber:
                    with pytest.raises(AWSAccountIdentityError):
                        orchestrator.collect_all("RUN-TEST-HALT")

                # Verify S3 and IAM collectors were NEVER instantiated or executed
                mock_s3_col.assert_not_called()
                mock_iam_col.assert_not_called()
