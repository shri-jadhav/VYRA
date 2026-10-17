import boto3
from botocore.stub import Stubber

from backend.app.collectors.cloudtrail_collector import CloudTrailCollector
from backend.app.collectors.security_services_collector import SecurityServicesCollector


def test_cloudtrail_empty_trails():
    ct_client = boto3.client("cloudtrail", region_name="us-east-1")
    stubber = Stubber(ct_client)

    stubber.add_response("describe_trails", {"trailList": []})

    with stubber:
        collector = CloudTrailCollector.__new__(CloudTrailCollector)
        collector.client = ct_client
        res = collector.collect()

        assert res["status"] == "SUCCESS"
        assert res["trails"] == []


def test_guardduty_subscription_required():
    gd_client = boto3.client("guardduty", region_name="ap-south-1")
    stubber = Stubber(gd_client)

    stubber.add_client_error(
        "list_detectors",
        service_error_code="SubscriptionRequiredException",
        service_message="The AWS Access Key Id needs a subscription for the service"
    )

    with stubber:
        collector = SecurityServicesCollector.__new__(SecurityServicesCollector)
        collector.session = None
        collector.region = "ap-south-1"

        # Mock the session.client to return gd_client
        class MockSession:
            def client(self, name, region_name=None):
                return gd_client

        collector.session = MockSession()
        res = collector._check_guardduty()

        assert res["status"] == "SUBSCRIPTION_REQUIRED"
        assert "subscrib" in res["details"].lower()
