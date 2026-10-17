import boto3
from botocore.stub import Stubber

from backend.app.collectors.sts_collector import STSCollector


def test_sts_collector_success():
    sts_client = boto3.client("sts", region_name="us-east-1")
    stubber = Stubber(sts_client)

    response = {
        "UserId": "AIDA34NSGHCQA26NJR2LY",
        "Account": "112233445566",
        "Arn": "arn:aws:iam::112233445566:user/vyra-auditor"
    }

    stubber.add_response("get_caller_identity", response)
    with stubber:
        collector = STSCollector.__new__(STSCollector)
        collector.client = sts_client
        result = collector.collect()

        assert result["status"] == "SUCCESS"
        assert result["account_id"] == "112233445566"
        assert result["arn"] == "arn:aws:iam::112233445566:user/vyra-auditor"


def test_sts_collector_access_denied():
    sts_client = boto3.client("sts", region_name="us-east-1")
    stubber = Stubber(sts_client)

    stubber.add_client_error(
        "get_caller_identity",
        service_error_code="AccessDenied",
        service_message="User is not authorized to perform sts:GetCallerIdentity"
    )

    with stubber:
        collector = STSCollector.__new__(STSCollector)
        collector.client = sts_client
        result = collector.collect()

        assert result["status"] == "DENIED"
        assert "AccessDenied" in result["error"]
