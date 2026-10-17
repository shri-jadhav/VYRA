from datetime import UTC, datetime
from unittest.mock import MagicMock

import boto3
from botocore.stub import Stubber

from backend.app.connectors.access_analyzer_connector import AccessAnalyzerConnector
from backend.app.connectors.cloudtrail_connector import CloudTrailConnector
from backend.app.connectors.cloudwatch_connector import CloudWatchConnector
from backend.app.connectors.config_connector import AWSConfigConnector
from backend.app.connectors.guardduty_connector import GuardDutyConnector
from backend.app.connectors.inspector_connector import InspectorConnector
from backend.app.connectors.macie_connector import MacieConnector
from backend.app.connectors.registry import ConnectorRegistry
from backend.app.connectors.security_hub_connector import SecurityHubConnector
from backend.app.connectors.ssm_connector import SSMConnector
from backend.app.core.iam_permissions import (
    CANONICAL_ACTIONS,
    CANONICAL_OPERATIONS,
    PROHIBITED_ACTIONS,
    generate_least_privilege_policy,
)


def test_guardduty_connector_enabled_with_stubber():
    client = boto3.client("guardduty", region_name="us-east-1")
    stubber = Stubber(client)
    now = datetime.now(UTC)

    stubber.add_response("list_detectors", {"DetectorIds": ["det-12345"]})
    stubber.add_response("get_detector", {
        "CreatedAt": now.isoformat(),
        "FindingPublishingFrequency": "FIFTEEN_MINUTES",
        "ServiceRole": "arn:aws:iam::123456789012:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty",
        "Status": "ENABLED"
    }, {"DetectorId": "det-12345"})

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = client

        conn = GuardDutyConnector(mock_session, region_name="us-east-1")
        cap = conn.check_availability()

        assert cap.status.value == "AVAILABLE"
        assert cap.coverage["detectors_count"] == 1
        assert cap.coverage["active_detectors"] == 1
        assert "Detector is active" in cap.status_details


def test_guardduty_connector_access_denied():
    client = boto3.client("guardduty", region_name="us-east-1")
    stubber = Stubber(client)

    stubber.add_client_error("list_detectors", service_error_code="AccessDeniedException", service_message="User not authorized")

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = client

        conn = GuardDutyConnector(mock_session, region_name="us-east-1")
        cap = conn.check_availability()

        assert cap.status.value == "PERMISSION_DENIED"
        assert "guardduty:ListDetectors" in cap.missing_permissions


def test_access_analyzer_connector_active():
    client = boto3.client("accessanalyzer", region_name="us-east-1")
    stubber = Stubber(client)
    now = datetime.now(UTC)

    stubber.add_response("list_analyzers", {
        "analyzers": [{
            "arn": "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/ConsoleAnalyzer",
            "name": "ConsoleAnalyzer",
            "status": "ACTIVE",
            "type": "ACCOUNT",
            "createdAt": now
        }]
    })

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = client

        conn = AccessAnalyzerConnector(mock_session, region_name="us-east-1")
        cap = conn.check_availability()

        assert cap.status.value == "AVAILABLE"
        assert cap.coverage["total_analyzers"] == 1
        assert cap.coverage["active_analyzers_count"] == 1


def test_inspector_connector_available():
    client = boto3.client("inspector2", region_name="us-east-1")
    stubber = Stubber(client)

    stubber.add_response("list_coverage", {
        "coveredResources": []
    })

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = client

        conn = InspectorConnector(mock_session, region_name="us-east-1")
        cap = conn.check_availability()

        assert cap.status.value == "AVAILABLE"
        assert cap.coverage["covered_resources_count"] == 0


def test_macie_connector_not_enabled():
    client = boto3.client("macie2", region_name="us-east-1")
    stubber = Stubber(client)

    stubber.add_client_error(
        "describe_buckets",
        service_error_code="AccessDeniedException",
        service_message="Macie is not enabled"
    )

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = client

        conn = MacieConnector(mock_session, region_name="us-east-1")
        cap = conn.check_availability()

        assert cap.status.value in ["NOT_SUBSCRIBED", "PERMISSION_DENIED"]


def test_ssm_connector_managed_instances():
    client = boto3.client("ssm", region_name="us-east-1")
    stubber = Stubber(client)

    stubber.add_response("describe_instance_information", {
        "InstanceInformationList": [
            {"InstanceId": "i-0123456789abcdef0", "PingStatus": "Online", "PlatformType": "Linux"}
        ]
    })

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = client

        conn = SSMConnector(mock_session, region_name="us-east-1")
        cap = conn.check_availability()

        assert cap.status.value == "AVAILABLE"
        assert cap.coverage["managed_instances_count"] == 1


def test_cloudwatch_connector_alarms():
    client = boto3.client("cloudwatch", region_name="us-east-1")
    logs_client = boto3.client("logs", region_name="us-east-1")
    cw_stubber = Stubber(client)
    logs_stubber = Stubber(logs_client)

    cw_stubber.add_response("describe_alarms", {
        "MetricAlarms": [{"AlarmName": "HighCPU", "StateValue": "OK"}]
    })

    logs_stubber.add_response("describe_log_groups", {
        "logGroups": [{"logGroupName": "/aws/lambda/test", "retentionInDays": 30}]
    })

    with cw_stubber, logs_stubber:
        mock_session = MagicMock()
        def mock_client(name, **kwargs):
            if name == "cloudwatch":
                return client
            if name == "logs":
                return logs_client
            raise ValueError(f"Unexpected client {name}")

        mock_session.client.side_effect = mock_client

        conn = CloudWatchConnector(mock_session, region_name="us-east-1")
        cap = conn.check_availability()

        assert cap.status.value == "AVAILABLE"
        assert cap.coverage["metric_alarms_count"] == 1
        assert cap.coverage["security_log_groups_count"] == 1


def test_connector_registry_offline_matrix():
    capabilities = ConnectorRegistry.get_all_capabilities(session=None, region="us-east-1")

    assert len(capabilities) == 12
    services = {c.service_id: c for c in capabilities}
    assert services["sts"].status.value == "AVAILABLE"
    assert services["s3"].status.value == "AVAILABLE"
    assert services["iam"].status.value == "AVAILABLE"
    assert services["cloudtrail"].status.value == "AVAILABLE"
    assert services["config"].status.value == "DISABLED"
    assert services["securityhub"].status.value == "NOT_SUBSCRIBED"
    assert services["guardduty"].status.value == "NOT_SUBSCRIBED"
    assert services["accessanalyzer"].status.value == "DISABLED"
    assert services["inspector"].status.value == "DISABLED"
    assert services["macie"].status.value == "DISABLED"
    assert services["ssm"].status.value == "DISABLED"
    assert services["cloudwatch"].status.value == "AVAILABLE"

    for c in capabilities:
        m = c.model_dump()
        assert "coverage" in m
        assert "required_permissions" in m
        assert "limitations" in m
        assert "telemetry_type" in m
        assert m["telemetry_type"] in [
            "STATUS_ONLY",
            "POSTURE_EVALUATION",
            "EVENTS_LOOKUP",
            "CONFIGURATION_HISTORY",
            "FINDINGS_RETRIEVED",
            "WORKLOAD_INVENTORY",
            "METRICS_ALARMS"
        ]


def test_guardduty_list_findings_summary():
    client = boto3.client("guardduty", region_name="us-east-1")
    stubber = Stubber(client)
    stubber.add_response("list_detectors", {"DetectorIds": ["det-12345"]})
    stubber.add_response("list_findings", {"FindingIds": ["f-111"]}, {"DetectorId": "det-12345", "MaxResults": 25})
    stubber.add_response("get_findings", {
        "Findings": [{
            "Id": "f-111",
            "AccountId": "123456789012",
            "Arn": "arn:aws:guardduty:us-east-1:123456789012:detector/det-12345/finding/f-111",
            "CreatedAt": "2026-01-01T00:00:00Z",
            "Region": "us-east-1",
            "Resource": {},
            "SchemaVersion": "2.0",
            "UpdatedAt": "2026-01-01T00:00:00Z",
            "Type": "Recon:IAMUser/TorIPCaller",
            "Severity": 8.0,
            "Title": "API called from Tor exit node"
        }]
    }, {"DetectorId": "det-12345", "FindingIds": ["f-111"]})

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = client
        conn = GuardDutyConnector(mock_session, region_name="us-east-1")
        res = conn.list_findings_summary(limit=25)

        assert res["status"] == "SUCCESS"
        assert res["count"] == 1
        assert res["findings"][0]["Id"] == "f-111"


def test_access_analyzer_list_findings():
    client = boto3.client("accessanalyzer", region_name="us-east-1")
    stubber = Stubber(client)
    now = datetime.now(UTC)

    stubber.add_response("list_analyzers", {
        "analyzers": [{
            "arn": "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/main",
            "name": "main",
            "type": "ACCOUNT",
            "createdAt": now,
            "status": "ACTIVE"
        }]
    })
    stubber.add_response("list_findings", {
        "findings": [{
            "id": "finding-001",
            "principal": {"AWS": "111122223333"},
            "action": ["s3:GetObject"],
            "resource": "arn:aws:s3:::sensitive-bucket",
            "resourceType": "AWS::S3::Bucket",
            "condition": {},
            "isPublic": True,
            "status": "ACTIVE",
            "createdAt": now,
            "analyzedAt": now,
            "updatedAt": now,
            "resourceOwnerAccount": "123456789012"
        }]
    }, {"analyzerArn": "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/main", "maxResults": 25})

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = client
        conn = AccessAnalyzerConnector(mock_session, region_name="us-east-1")
        res = conn.list_findings(limit=25)

        assert res["status"] == "SUCCESS"
        assert res["count"] == 1
        assert res["findings"][0]["id"] == "finding-001"


def test_inspector_batch_status_and_findings():
    client = boto3.client("inspector2", region_name="us-east-1")
    stubber = Stubber(client)
    now = datetime.now(UTC)
    stubber.add_response("batch_get_account_status", {
        "accounts": [{
            "accountId": "123456789012",
            "state": {"status": "ENABLED", "errorCode": "ALREADY_ENABLED", "errorMessage": "none"},
            "resourceState": {
                "ec2": {"status": "ENABLED", "errorCode": "ALREADY_ENABLED", "errorMessage": "none"},
                "ecr": {"status": "ENABLED", "errorCode": "ALREADY_ENABLED", "errorMessage": "none"}
            }
        }]
    })
    stubber.add_response("list_findings", {
        "findings": [{
            "findingArn": "arn:aws:inspector2:us-east-1:123456789012:finding/cve-2024-1234",
            "awsAccountId": "123456789012",
            "severity": "HIGH",
            "title": "CVE-2024-1234 in libssl",
            "type": "PACKAGE_VULNERABILITY",
            "description": "Buffer overflow vulnerability in libssl",
            "remediation": {},
            "firstObservedAt": now,
            "lastObservedAt": now,
            "status": "ACTIVE",
            "resources": [{
                "type": "AWS_EC2_INSTANCE",
                "id": "i-0123456789abcdef0"
            }]
        }]
    }, {"maxResults": 25})

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = client
        conn = InspectorConnector(mock_session, region_name="us-east-1")

        status_res = conn.batch_get_account_status()
        assert status_res["status"] == "SUCCESS"
        assert status_res["accounts"][0]["state"]["status"] == "ENABLED"

        findings_res = conn.list_findings(limit=25)
        assert findings_res["status"] == "SUCCESS"
        assert findings_res["count"] == 1
        assert findings_res["findings"][0]["severity"] == "HIGH"


def test_macie_session_and_findings():
    client = boto3.client("macie2", region_name="us-east-1")
    stubber = Stubber(client)
    stubber.add_response("get_macie_session", {
        "status": "ENABLED",
        "findingPublishingFrequency": "FIFTEEN_MINUTES",
        "serviceRole": "arn:aws:iam::123456789012:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie"
    })
    stubber.add_response("list_findings", {
        "findingIds": ["macie-find-1", "macie-find-2"]
    }, {"maxResults": 25})

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = client
        conn = MacieConnector(mock_session, region_name="us-east-1")

        session_res = conn.get_macie_session()
        assert session_res["status"] == "SUCCESS"
        assert session_res["session"]["status"] == "ENABLED"

        findings_res = conn.list_findings(limit=25)
        assert findings_res["status"] == "SUCCESS"
        assert findings_res["count"] == 2
        assert "macie-find-1" in findings_res["finding_ids"]


def test_ssm_describe_instance_patches():
    client = boto3.client("ssm", region_name="us-east-1")
    stubber = Stubber(client)
    now = datetime.now(UTC)
    stubber.add_response("describe_instance_patches", {
        "Patches": [{
            "Title": "KB123456",
            "KBId": "123456",
            "Classification": "SecurityUpdates",
            "Severity": "Critical",
            "State": "Installed",
            "InstalledTime": now
        }]
    }, {"InstanceId": "i-0123456789abcdef0", "MaxResults": 25})

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = client
        conn = SSMConnector(mock_session, region_name="us-east-1")

        patches_res = conn.describe_instance_patches(instance_id="i-0123456789abcdef0", limit=25)
        assert patches_res["status"] == "SUCCESS"
        assert patches_res["count"] == 1
        assert patches_res["patches"][0]["KBId"] == "123456"


def test_config_get_resource_config_history():
    client = boto3.client("config", region_name="us-east-1")
    stubber = Stubber(client)
    now = datetime.now(UTC)
    stubber.add_response("get_resource_config_history", {
        "configurationItems": [{
            "version": "1.3",
            "configurationItemCaptureTime": now,
            "configurationStateId": "12345",
            "resourceType": "AWS::S3::Bucket",
            "resourceId": "prod-bucket",
            "arn": "arn:aws:s3:::prod-bucket",
            "configuration": "{}"
        }]
    }, {"resourceType": "AWS::S3::Bucket", "resourceId": "prod-bucket", "limit": 10})

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = client
        conn = AWSConfigConnector(mock_session, region_name="us-east-1")

        res = conn.get_resource_config_history(resource_type="AWS::S3::Bucket", resource_id="prod-bucket", limit=10)
        assert res["status"] == "SUCCESS"
        assert res["count"] == 1
        assert res["items"][0]["resourceId"] == "prod-bucket"


def test_security_hub_get_related_findings():
    client = boto3.client("securityhub", region_name="us-east-1")
    stubber = Stubber(client)
    stubber.add_response("get_findings", {
        "Findings": [{
            "SchemaVersion": "2018-10-08",
            "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/sh-1",
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
            "GeneratorId": "aws-securityhub",
            "AwsAccountId": "123456789012",
            "CreatedAt": "2026-01-01T00:00:00Z",
            "UpdatedAt": "2026-01-01T00:00:00Z",
            "Title": "S3 bucket public read access",
            "Description": "Bucket policy allows public reads",
            "Severity": {"Label": "HIGH"},
            "Resources": [{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::target-bucket"}]
        }]
    }, {
        "Filters": {
            "ResourceId": [{"Value": "arn:aws:s3:::target-bucket", "Comparison": "EQUALS"}],
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
        },
        "MaxResults": 25
    })

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = client
        conn = SecurityHubConnector(mock_session, region_name="us-east-1")

        res = conn.get_related_findings(resource_id="arn:aws:s3:::target-bucket", limit=25)
        assert res["status"] == "SUCCESS"
        assert len(res["findings"]) == 1
        assert res["findings"][0]["title"] == "S3 bucket public read access"


def test_cloudtrail_lookup_management_events():
    client = boto3.client("cloudtrail", region_name="us-east-1")
    stubber = Stubber(client)
    now = datetime.now(UTC)
    stubber.add_response("lookup_events", {
        "Events": [{
            "EventId": "evt-001",
            "EventName": "PutBucketAcl",
            "ReadOnly": "false",
            "EventTime": now,
            "EventSource": "s3.amazonaws.com",
            "Username": "security-operator",
            "CloudTrailEvent": '{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/sec-op"},"eventSource":"s3.amazonaws.com","eventName":"PutBucketAcl","awsRegion":"us-east-1","sourceIPAddress":"1.2.3.4"}'
        }],
        "NextToken": "tok-123"
    }, {
        "MaxResults": 25,
        "LookupAttributes": [{"AttributeKey": "ResourceName", "AttributeValue": "my-bucket"}]
    })

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = client
        conn = CloudTrailConnector(mock_session, region_name="us-east-1")

        res = conn.lookup_management_events(resource_name="my-bucket", max_results=25)
        assert res["status"] == "SUCCESS"
        assert res["total_events_returned"] == 1
        assert res["events"][0]["event_name"] == "PutBucketAcl"
        assert res["next_token"] == "tok-123"


def test_all_connectors_permissions_match_policy():
    """Validates that all connector permissions in registry match the canonical policy without unregistered actions."""
    capabilities = ConnectorRegistry.get_all_capabilities(session=None, region="us-east-1")

    all_connector_permissions = set()
    for cap in capabilities:
        for perm in cap.required_permissions:
            all_connector_permissions.add(perm)

    # Verify that every connector required permission is accounted for in canonical policy
    unaccounted = all_connector_permissions - CANONICAL_ACTIONS
    assert not unaccounted, f"Found connector permissions not in canonical policy: {unaccounted}"

    # Verify that every canonical policy action is represented in at least one connector
    unused_policy_actions = CANONICAL_ACTIONS - all_connector_permissions
    assert not unused_policy_actions, f"Found canonical policy actions not mapped to any connector: {unused_policy_actions}"

    assert all_connector_permissions == CANONICAL_ACTIONS


def test_access_analyzer_prefix_validation():
    """Explicitly assert correct IAM action prefix 'access-analyzer:' and reject 'accessanalyzer:'."""
    conn = AccessAnalyzerConnector(MagicMock(), region_name="us-east-1")
    assert conn.service_id == "accessanalyzer"
    assert "access-analyzer:ListAnalyzers" in conn.required_permissions
    assert "access-analyzer:ListFindings" in conn.required_permissions

    # Must NOT contain the unhyphenated prefix anywhere in canonical actions or connector permissions
    for perm in conn.required_permissions:
        assert not perm.startswith("accessanalyzer:"), f"Found incorrect prefix in connector permission: {perm}"

    for action in CANONICAL_ACTIONS:
        assert not action.startswith("accessanalyzer:"), f"Found incorrect prefix in CANONICAL_ACTIONS: {action}"


def test_canonical_permissions_inventory_integrity():
    """Validates that the canonical permission inventory is intact, exactly 44 actions, and excludes prohibited actions."""
    assert len(CANONICAL_OPERATIONS) == 44
    assert len(CANONICAL_ACTIONS) == 44

    for prohibited in PROHIBITED_ACTIONS:
        assert prohibited not in CANONICAL_ACTIONS, f"Prohibited action '{prohibited}' leaked into CANONICAL_ACTIONS!"

    # S3 GetBucketEncryption must use canonical IAM action s3:GetEncryptionConfiguration
    assert "s3:GetEncryptionConfiguration" in CANONICAL_ACTIONS
    assert "s3:GetBucketEncryption" not in CANONICAL_ACTIONS


def test_least_privilege_policy_template_scoping():
    """Validates that the generated IAM policy properly narrows resources where supported."""
    policy = generate_least_privilege_policy(narrow_resources=True)
    assert policy["Version"] == "2012-10-17"
    statements = {s["Sid"]: s for s in policy["Statement"]}

    assert "VyraInventoryAndGlobalReadOnly" in statements
    assert "VyraS3BucketPostureReadOnly" in statements
    assert "VyraIAMUserPostureReadOnly" in statements
    assert "VyraIAMRolePostureReadOnly" in statements
    assert "VyraCloudTrailTrailPostureReadOnly" in statements
    assert "VyraSecurityHubPostureReadOnly" in statements
    assert "VyraGuardDutyDetectorPostureReadOnly" in statements
    assert "VyraAccessAnalyzerPostureReadOnly" in statements
    assert "VyraCloudWatchLogsRetentionReadOnly" in statements

    # Statement 1: Only unscopeable wildcard actions
    assert statements["VyraInventoryAndGlobalReadOnly"]["Resource"] == "*"
    assert "sts:GetCallerIdentity" in statements["VyraInventoryAndGlobalReadOnly"]["Action"]
    assert "s3:ListAllMyBuckets" in statements["VyraInventoryAndGlobalReadOnly"]["Action"]
    assert "access-analyzer:ListAnalyzers" in statements["VyraInventoryAndGlobalReadOnly"]["Action"]

    # Statement 2: S3 bucket actions scoped to arn:aws:s3:::*
    assert statements["VyraS3BucketPostureReadOnly"]["Resource"] == "arn:aws:s3:::*"
    assert "s3:GetBucketLocation" in statements["VyraS3BucketPostureReadOnly"]["Action"]
    assert "s3:GetEncryptionConfiguration" in statements["VyraS3BucketPostureReadOnly"]["Action"]
    assert "s3:GetBucketPublicAccessBlock" in statements["VyraS3BucketPostureReadOnly"]["Action"]

    # Statement 3 & 4: IAM user and role actions scoped
    assert statements["VyraIAMUserPostureReadOnly"]["Resource"] == "arn:aws:iam::*:user/*"
    assert "iam:ListMFADevices" in statements["VyraIAMUserPostureReadOnly"]["Action"]
    assert statements["VyraIAMRolePostureReadOnly"]["Resource"] == "arn:aws:iam::*:role/*"
    assert "iam:ListAttachedRolePolicies" in statements["VyraIAMRolePostureReadOnly"]["Action"]

    # Statement 7 & 8: GuardDuty and Access Analyzer scoped to specific ARNs
    assert statements["VyraGuardDutyDetectorPostureReadOnly"]["Resource"] == "arn:aws:guardduty:*:*:detector/*"
    assert "guardduty:GetDetector" in statements["VyraGuardDutyDetectorPostureReadOnly"]["Action"]
    assert "guardduty:GetFindings" in statements["VyraGuardDutyDetectorPostureReadOnly"]["Action"]
    assert "guardduty:ListDetectors" in statements["VyraInventoryAndGlobalReadOnly"]["Action"]
    assert "guardduty:ListFindings" in statements["VyraInventoryAndGlobalReadOnly"]["Action"]
    assert statements["VyraAccessAnalyzerPostureReadOnly"]["Resource"] == "arn:aws:access-analyzer:*:*:analyzer/*"
    assert "access-analyzer:ListFindings" in statements["VyraAccessAnalyzerPostureReadOnly"]["Action"]

    # Check total actions across all statements equals CANONICAL_ACTIONS
    all_policy_actions = set()
    for s in policy["Statement"]:
        for a in s["Action"]:
            all_policy_actions.add(a)

    assert all_policy_actions == CANONICAL_ACTIONS
