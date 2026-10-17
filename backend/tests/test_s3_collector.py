from datetime import UTC, datetime

import boto3
from botocore.stub import Stubber

from backend.app.collectors.s3_collector import S3Collector


def test_s3_collector_bucket_evaluation():
    s3_client = boto3.client("s3", region_name="ap-south-1")
    stubber = Stubber(s3_client)

    now = datetime.now(UTC)

    # 1. list_buckets
    stubber.add_response("list_buckets", {
        "Buckets": [{"Name": "test-secure-bucket", "CreationDate": now}]
    })

    # 2. get_bucket_location
    stubber.add_response("get_bucket_location", {
        "LocationConstraint": "ap-south-1"
    }, {"Bucket": "test-secure-bucket"})

    # 3. get_public_access_block
    stubber.add_response("get_public_access_block", {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True
        }
    }, {"Bucket": "test-secure-bucket"})

    # 4. get_bucket_encryption
    stubber.add_response("get_bucket_encryption", {
        "ServerSideEncryptionConfiguration": {
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        }
    }, {"Bucket": "test-secure-bucket"})

    # 5. get_bucket_versioning
    stubber.add_response("get_bucket_versioning", {
        "Status": "Enabled"
    }, {"Bucket": "test-secure-bucket"})

    # 6. get_bucket_policy_status
    stubber.add_response("get_bucket_policy_status", {
        "PolicyStatus": {"IsPublic": False}
    }, {"Bucket": "test-secure-bucket"})

    # 7. get_bucket_logging
    stubber.add_response("get_bucket_logging", {
        "LoggingEnabled": {
            "TargetBucket": "test-log-bucket",
            "TargetPrefix": "logs/"
        }
    }, {"Bucket": "test-secure-bucket"})

    with stubber:
        collector = S3Collector.__new__(S3Collector)
        collector.client = s3_client
        res = collector.collect()

        assert res["status"] == "SUCCESS"
        assert len(res["buckets"]) == 1
        b = res["buckets"][0]
        assert b["name"] == "test-secure-bucket"
        assert b["public_access_block_status"] == "FULL_BLOCK"
        assert b["encryption_status"] == "CONFIGURED"
        assert b["versioning_status"] == "Enabled"
        assert b["policy_status"]["IsPublic"] is False
        assert b["logging_status"] == "CONFIGURED"
        assert b["logging"]["TargetBucket"] == "test-log-bucket"


def test_s3_collector_public_bucket_and_unencrypted():
    s3_client = boto3.client("s3", region_name="ap-south-1")
    stubber = Stubber(s3_client)
    now = datetime.now(UTC)

    stubber.add_response("list_buckets", {
        "Buckets": [{"Name": "test-leaky-bucket", "CreationDate": now}]
    })
    stubber.add_response("get_bucket_location", {"LocationConstraint": "ap-south-1"}, {"Bucket": "test-leaky-bucket"})

    # Partial / unblocked
    stubber.add_response("get_public_access_block", {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False
        }
    }, {"Bucket": "test-leaky-bucket"})

    # Missing encryption
    stubber.add_client_error(
        "get_bucket_encryption",
        service_error_code="ServerSideEncryptionConfigurationNotFoundError",
        expected_params={"Bucket": "test-leaky-bucket"}
    )

    # Missing versioning
    stubber.add_response("get_bucket_versioning", {}, {"Bucket": "test-leaky-bucket"})

    # Public policy
    stubber.add_response("get_bucket_policy_status", {
        "PolicyStatus": {"IsPublic": True}
    }, {"Bucket": "test-leaky-bucket"})

    # Missing logging
    stubber.add_response("get_bucket_logging", {}, {"Bucket": "test-leaky-bucket"})

    with stubber:
        collector = S3Collector.__new__(S3Collector)
        collector.client = s3_client
        res = collector.collect()

        assert res["status"] == "SUCCESS"
        b = res["buckets"][0]
        assert b["public_access_block_status"] == "PARTIAL_OR_UNBLOCKED"
        assert b["encryption_status"] == "NOT_CONFIGURED"
        assert b["versioning_status"] == "NOT_CONFIGURED"
        assert b["policy_status"]["IsPublic"] is True
        assert b["logging_status"] == "NOT_CONFIGURED"
        assert b["logging"] is None
