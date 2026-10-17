from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.exceptions import EndpointConnectionError
from botocore.stub import Stubber

from backend.app.investigation.domain import VerificationOutcome
from backend.app.models.models import Finding
from backend.app.verification.engine import VerificationEngine


def test_verification_outcome_resolved(db_session):
    # Setup test finding
    finding_id = "FND-TEST-VERIFY-001"
    existing = db_session.query(Finding).filter(Finding.id == finding_id).first()
    if not existing:
        finding = Finding(
            id=finding_id,
            run_id="RUN-TEST",
            control_id="VYRA-S3-001",
            title="S3 Public Access Block Disabled",
            description="Testing S3 public access",
            severity="HIGH",
            status="OPEN",
            resource_id="test-remediated-bucket",
            resource_arn="arn:aws:s3:::test-remediated-bucket",
            service="s3",
            verification_result="PENDING_VERIFICATION",
        )
        db_session.add(finding)
        db_session.commit()

    s3_client = boto3.client("s3", region_name="ap-south-1")
    stubber = Stubber(s3_client)

    # Mock get_public_access_block with all 4 true
    stubber.add_response(
        "get_public_access_block",
        {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        },
        {"Bucket": "test-remediated-bucket"},
    )

    mock_session = MagicMock()
    mock_session.client.return_value = s3_client

    with stubber:
        with patch("backend.app.verification.engine.create_boto3_session", return_value=mock_session):
            engine = VerificationEngine(db=db_session)
            vrun = engine.run_verification(finding_id=finding_id)

            assert vrun.outcome == VerificationOutcome.RESOLVED.value
            assert "RESOLVED" in vrun.comparison_summary

            # Check finding was updated
            updated_finding = db_session.query(Finding).filter(Finding.id == finding_id).first()
            assert updated_finding.status == "REMEDIATED"
            assert updated_finding.verification_result == "VERIFIED"


def test_verification_outcome_still_present(db_session):
    finding_id = "FND-TEST-VERIFY-002"
    existing = db_session.query(Finding).filter(Finding.id == finding_id).first()
    if not existing:
        finding = Finding(
            id=finding_id,
            run_id="RUN-TEST",
            control_id="VYRA-S3-001",
            title="S3 Public Access Block Disabled",
            description="Testing S3 public access still failing",
            severity="HIGH",
            status="OPEN",
            resource_id="test-unremediated-bucket",
            resource_arn="arn:aws:s3:::test-unremediated-bucket",
            service="s3",
            verification_result="PENDING_VERIFICATION",
        )
        db_session.add(finding)
        db_session.commit()

    s3_client = boto3.client("s3", region_name="ap-south-1")
    stubber = Stubber(s3_client)

    # Mock get_public_access_block with partial/false
    stubber.add_response(
        "get_public_access_block",
        {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            }
        },
        {"Bucket": "test-unremediated-bucket"},
    )

    mock_session = MagicMock()
    mock_session.client.return_value = s3_client

    with stubber:
        with patch("backend.app.verification.engine.create_boto3_session", return_value=mock_session):
            engine = VerificationEngine(db=db_session)
            vrun = engine.run_verification(finding_id=finding_id)

            assert vrun.outcome == VerificationOutcome.STILL_PRESENT.value
            assert "STILL_PRESENT" in vrun.comparison_summary

            updated_finding = db_session.query(Finding).filter(Finding.id == finding_id).first()
            assert updated_finding.status == "OPEN"
            assert updated_finding.verification_result == "STILL_FAILING"


def test_verification_outcome_unverifiable_on_access_denied(db_session):
    finding_id = "FND-TEST-VERIFY-003"
    existing = db_session.query(Finding).filter(Finding.id == finding_id).first()
    if not existing:
        finding = Finding(
            id=finding_id,
            run_id="RUN-TEST",
            control_id="VYRA-S3-001",
            title="S3 Public Access Block Disabled",
            description="Testing S3 access denied",
            severity="HIGH",
            status="OPEN",
            resource_id="test-denied-bucket",
            resource_arn="arn:aws:s3:::test-denied-bucket",
            service="s3",
            verification_result="PENDING_VERIFICATION",
        )
        db_session.add(finding)
        db_session.commit()

    s3_client = boto3.client("s3", region_name="ap-south-1")
    stubber = Stubber(s3_client)

    stubber.add_client_error(
        "get_public_access_block",
        service_error_code="AccessDenied",
        service_message="User is not authorized to perform: s3:GetBucketPublicAccessBlock",
        expected_params={"Bucket": "test-denied-bucket"},
    )

    mock_session = MagicMock()
    mock_session.client.return_value = s3_client

    with stubber:
        with patch("backend.app.verification.engine.create_boto3_session", return_value=mock_session):
            engine = VerificationEngine(db=db_session)
            vrun = engine.run_verification(finding_id=finding_id)

            assert vrun.outcome == VerificationOutcome.UNVERIFIABLE.value
            assert "UNVERIFIABLE" in vrun.comparison_summary
            assert vrun.limitations is not None

            updated_finding = db_session.query(Finding).filter(Finding.id == finding_id).first()
            assert updated_finding.verification_result == "UNVERIFIABLE"


def test_verification_outcome_unverifiable_on_botocore_error(db_session):
    """Verifies that BotoCoreError (communication / SDK failure) safely produces UNVERIFIABLE outcome."""
    finding_id = "FND-TEST-VERIFY-BCE-001"
    existing = db_session.query(Finding).filter(Finding.id == finding_id).first()
    if not existing:
        finding = Finding(
            id=finding_id,
            run_id="RUN-TEST",
            control_id="VYRA-S3-001",
            title="S3 Public Access Block Disabled",
            description="Testing botocore communication error",
            severity="HIGH",
            status="OPEN",
            resource_id="test-bce-bucket",
            resource_arn="arn:aws:s3:::test-bce-bucket",
            service="s3",
            verification_result="PENDING_VERIFICATION",
        )
        db_session.add(finding)
        db_session.commit()

    mock_client = MagicMock()
    mock_client.get_public_access_block.side_effect = EndpointConnectionError(
        endpoint_url="https://s3.ap-south-1.amazonaws.com"
    )

    mock_session = MagicMock()
    mock_session.client.return_value = mock_client

    with patch("backend.app.verification.engine.create_boto3_session", return_value=mock_session):
        engine = VerificationEngine(db=db_session)
        vrun = engine.run_verification(finding_id=finding_id)

        assert vrun.outcome == VerificationOutcome.UNVERIFIABLE.value
        assert "AWS client communication error" in (vrun.limitations or "")
        assert "EndpointConnectionError" in (vrun.limitations or "")


def test_verification_unexpected_programming_error_raises(db_session):
    """Verifies that unexpected programming errors (e.g. AttributeError) are NOT swallowed as UNVERIFIABLE."""
    finding_id = "FND-TEST-VERIFY-BUG-001"
    existing = db_session.query(Finding).filter(Finding.id == finding_id).first()
    if not existing:
        finding = Finding(
            id=finding_id,
            run_id="RUN-TEST",
            control_id="VYRA-S3-001",
            title="S3 Public Access Block Disabled",
            description="Testing programming bug propagation",
            severity="HIGH",
            status="OPEN",
            resource_id="test-bug-bucket",
            resource_arn="arn:aws:s3:::test-bug-bucket",
            service="s3",
            verification_result="PENDING_VERIFICATION",
        )
        db_session.add(finding)
        db_session.commit()

    # Simulate an unexpected programming defect in _evaluate_fresh_state
    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_client.get_public_access_block.side_effect = AttributeError("Simulated internal code defect")
    mock_session.client.return_value = mock_client

    with patch("backend.app.verification.engine.create_boto3_session", return_value=mock_session):
        engine = VerificationEngine(db=db_session)
        with pytest.raises(AttributeError) as exc_info:
            engine.run_verification(finding_id=finding_id)
        assert "Simulated internal code defect" in str(exc_info.value)
