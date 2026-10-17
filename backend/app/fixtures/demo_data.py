from datetime import UTC, datetime
from typing import Any


def get_demo_evidence_fixture(run_id: str) -> dict[str, Any]:
    """
    Returns a clearly labeled benchmark demo fixture.
    STRICT COMPLIANCE: Clearly tagged as DEMO_FIXTURE so it is never confused with live AWS findings.
    """
    now = datetime.now(UTC).isoformat()
    return {
        "run_id": run_id,
        "profile_used": "demo-benchmark-fixture",
        "region": "us-east-1",
        "collection_timestamp": now,
        "collector_version": "1.0.0-demo",
        "provenance": {
            "source": "DEMO_FIXTURE",
            "collector_agent": "VYRA Fixture Simulator",
            "auth_chain": "simulated_benchmark",
            "profile": "demo-benchmark-fixture",
        },
        "sts": {
            "service": "sts",
            "status": "SUCCESS",
            "account_id": "112233445566",
            "user_id": "AIDABENCHMARKDEMO123",
            "arn": "arn:aws:iam::112233445566:user/demo-security-auditor",
        },
        "s3": {
            "service": "s3",
            "status": "SUCCESS",
            "permissions_summary": {
                "ListAllMyBuckets": "ALLOWED",
                "GetBucketPublicAccessBlock": "ALLOWED",
                "GetEncryptionConfiguration": "ALLOWED",
                "GetBucketVersioning": "ALLOWED",
                "GetBucketPolicyStatus": "ALLOWED",
                "GetBucketLogging": "ALLOWED",
            },
            "buckets": [
                {
                    "name": "prod-customer-pii-vault",
                    "arn": "arn:aws:s3:::prod-customer-pii-vault",
                    "creation_date": "2025-01-15T08:00:00+00:00",
                    "region": "us-east-1",
                    "public_access_block": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True
                    },
                    "public_access_block_status": "FULL_BLOCK",
                    "encryption": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}],
                    "encryption_status": "CONFIGURED",
                    "versioning": {"Status": "Enabled"},
                    "versioning_status": "Enabled",
                    "policy_status": {"IsPublic": False},
                    "logging": {"TargetBucket": "prod-customer-pii-access-logs", "TargetPrefix": "pii-vault/"},
                    "logging_status": "CONFIGURED",
                    "errors": {}
                },
                {
                    "name": "legacy-analytics-logs-public",
                    "arn": "arn:aws:s3:::legacy-analytics-logs-public",
                    "creation_date": "2024-06-20T14:30:00+00:00",
                    "region": "us-east-1",
                    "public_access_block": {
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False
                    },
                    "public_access_block_status": "PARTIAL_OR_UNBLOCKED",
                    "encryption": [],
                    "encryption_status": "NOT_CONFIGURED",
                    "versioning": {},
                    "versioning_status": "NOT_CONFIGURED",
                    "policy_status": {"IsPublic": True},
                    "logging": None,
                    "logging_status": "NOT_CONFIGURED",
                    "errors": {}
                },
                {
                    "name": "staging-app-assets-unencrypted",
                    "arn": "arn:aws:s3:::staging-app-assets-unencrypted",
                    "creation_date": "2025-03-01T10:15:00+00:00",
                    "region": "us-east-1",
                    "public_access_block": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True
                    },
                    "public_access_block_status": "FULL_BLOCK",
                    "encryption": [],
                    "encryption_status": "NOT_CONFIGURED",
                    "versioning": {"Status": "Suspended"},
                    "versioning_status": "Suspended",
                    "policy_status": {"IsPublic": False},
                    "logging": None,
                    "logging_status": "NOT_CONFIGURED",
                    "errors": {}
                }
            ]
        },
        "iam": {
            "service": "iam",
            "status": "SUCCESS",
            "permissions_summary": {
                "GetAccountSummary": "ALLOWED",
                "GetAccountPasswordPolicy": "ALLOWED",
                "ListUsers": "ALLOWED",
                "ListMFADevices": "ALLOWED",
                "ListAccessKeys": "ALLOWED",
                "ListAttachedUserPolicies": "ALLOWED",
                "ListRoles": "ALLOWED",
            },
            "account_summary": {
                "AccountMFAEnabled": 0,
                "AccountAccessKeysPresent": 0,
                "AccountPasswordPresent": 1,
                "Users": 3,
                "Roles": 8
            },
            "password_policy": {
                "MinimumPasswordLength": 14,
                "RequireSymbols": True,
                "RequireNumbers": True,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True
            },
            "password_policy_status": "CONFIGURED",  # nosec B105
            "users": [
                {
                    "user_name": "ci-deployer-svc",
                    "arn": "arn:aws:iam::112233445566:user/ci-deployer-svc",
                    "user_id": "AIDACI1234567890",
                    "create_date": "2024-02-10T12:00:00+00:00",
                    "mfa_active": False,
                    "mfa_devices": [],
                    "access_keys": [
                        {
                            "access_key_id": "AKIAVBMEXAMPLE11111",
                            "status": "Active",
                            "create_date": "2024-02-10T12:00:00+00:00",
                            "age_days": 615
                        }
                    ],
                    "attached_policies": [
                        {"PolicyName": "AmazonS3FullAccess", "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3FullAccess"}
                    ],
                    "errors": {}
                },
                {
                    "user_name": "lead-architect",
                    "arn": "arn:aws:iam::112233445566:user/lead-architect",
                    "user_id": "AIDALEAD123456789",
                    "create_date": "2024-08-01T09:00:00+00:00",
                    "mfa_active": True,
                    "mfa_devices": [{"SerialNumber": "arn:aws:iam::112233445566:mfa/lead-architect-yubikey"}],
                    "access_keys": [],
                    "attached_policies": [
                        {"PolicyName": "ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
                    ],
                    "errors": {}
                }
            ],
            "roles": [
                {
                    "role_name": "OrganizationAccountAccessRole",
                    "arn": "arn:aws:iam::112233445566:role/OrganizationAccountAccessRole",
                    "create_date": "2024-01-01T00:00:00+00:00",
                    "assume_role_policy": {},
                    "attached_policies": [
                        {"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
                    ]
                }
            ]
        },
        "cloudtrail": {
            "service": "cloudtrail",
            "status": "SUCCESS",
            "permissions_summary": {
                "DescribeTrails": "ALLOWED",
                "GetTrailStatus": "ALLOWED",
                "GetEventSelectors": "ALLOWED",
            },
            "trails": []
        },
        "security_services": {
            "service": "security_services",
            "region": "us-east-1",
            "services": {
                "access_analyzer": {
                    "name": "IAM Access Analyzer",
                    "status": "DISABLED",
                    "count": 0,
                    "active_count": 0,
                    "details": "0 active analyzer(s) found"
                },
                "guardduty": {
                    "name": "Amazon GuardDuty",
                    "status": "SUBSCRIPTION_REQUIRED",
                    "details": "Service not subscribed/enabled on AWS account"
                },
                "security_hub": {
                    "name": "AWS Security Hub",
                    "status": "SUBSCRIPTION_REQUIRED",
                    "details": "Service not subscribed/enabled on AWS account"
                },
                "aws_config": {
                    "name": "AWS Config",
                    "status": "DISABLED",
                    "count": 0,
                    "details": "0 configuration recorder(s) found"
                },
                "ssm": {
                    "name": "AWS Systems Manager",
                    "status": "DISABLED",
                    "count": 0,
                    "details": "0 managed instance(s) detected"
                },
                "cloudwatch": {
                    "name": "Amazon CloudWatch",
                    "status": "ENABLED",
                    "count": 2,
                    "details": "2 security alarm(s) active"
                }
            }
        }
    }
