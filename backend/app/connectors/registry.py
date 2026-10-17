import logging
from datetime import UTC, datetime

import boto3
from botocore.exceptions import ClientError

from backend.app.connectors.access_analyzer_connector import AccessAnalyzerConnector
from backend.app.connectors.cloudtrail_connector import CloudTrailConnector
from backend.app.connectors.cloudwatch_connector import CloudWatchConnector
from backend.app.connectors.config_connector import AWSConfigConnector
from backend.app.connectors.guardduty_connector import GuardDutyConnector
from backend.app.connectors.inspector_connector import InspectorConnector
from backend.app.connectors.macie_connector import MacieConnector
from backend.app.connectors.security_hub_connector import SecurityHubConnector
from backend.app.connectors.ssm_connector import SSMConnector
from backend.app.investigation.domain import ConnectorCapability, ConnectorStatus

logger = logging.getLogger("vyra.connectors.registry")


class ConnectorRegistry:
    """Central registry and health monitor for all modular AWS connectors."""

    @staticmethod
    def get_all_capabilities(session: boto3.Session | None, region: str) -> list[ConnectorCapability]:
        if session is None:
            return ConnectorRegistry._get_offline_capabilities(region)

        capabilities: list[ConnectorCapability] = []

        # 1. AWS STS
        capabilities.append(ConnectorRegistry._probe_sts(session, region))

        # 2. Amazon S3
        capabilities.append(ConnectorRegistry._probe_s3(session, region))

        # 3. AWS IAM
        capabilities.append(ConnectorRegistry._probe_iam(session, region))

        # 4. AWS CloudTrail
        ct_conn = CloudTrailConnector(session=session, region_name=region)
        capabilities.append(ct_conn.check_availability())

        # 5. AWS Config
        cfg_conn = AWSConfigConnector(session=session, region_name=region)
        capabilities.append(cfg_conn.check_availability())

        # 6. AWS Security Hub
        sh_conn = SecurityHubConnector(session=session, region_name=region)
        capabilities.append(sh_conn.check_availability())

        # 7. Amazon GuardDuty
        gd_conn = GuardDutyConnector(session=session, region_name=region)
        capabilities.append(gd_conn.check_availability())

        # 8. IAM Access Analyzer
        aa_conn = AccessAnalyzerConnector(session=session, region_name=region)
        capabilities.append(aa_conn.check_availability())

        # 9. Amazon Inspector
        ins_conn = InspectorConnector(session=session, region_name=region)
        capabilities.append(ins_conn.check_availability())

        # 10. Amazon Macie
        mac_conn = MacieConnector(session=session, region_name=region)
        capabilities.append(mac_conn.check_availability())

        # 11. AWS Systems Manager
        ssm_conn = SSMConnector(session=session, region_name=region)
        capabilities.append(ssm_conn.check_availability())

        # 12. Amazon CloudWatch
        cw_conn = CloudWatchConnector(session=session, region_name=region)
        capabilities.append(cw_conn.check_availability())

        return capabilities

    @staticmethod
    def _probe_sts(session: boto3.Session, region: str) -> ConnectorCapability:
        client = session.client("sts", region_name=region)
        status = ConnectorStatus.AVAILABLE
        details = "STS is operational."
        missing_perms = []

        try:
            res = client.get_caller_identity()
            details = f"Authenticated: {res.get('Arn')}"
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            if "AccessDenied" in code:
                status = ConnectorStatus.PERMISSION_DENIED
                missing_perms.append("sts:GetCallerIdentity")
                details = f"Permission denied: {code}"
            else:
                status = ConnectorStatus.ERROR
                details = f"{code}: {e}"
        except Exception as e:
            status = ConnectorStatus.ERROR
            details = str(e)

        return ConnectorCapability(
            service_id="sts",
            display_name="AWS Security Token Service (STS)",
            category="Core Identity",
            status=status,
            status_details=details,
            required_permissions=["sts:GetCallerIdentity"],
            missing_permissions=missing_perms,
            supported_operations=["GetCallerIdentity"],
            telemetry_type="STATUS_ONLY",
            data_retention_window="Live",
            cost_notes="Free tier zero-cost API call.",
            limitations="Returns caller identity metadata only.",
            coverage={"service": "sts"},
            last_checked_at=datetime.now(UTC).isoformat()
        )

    @staticmethod
    def _probe_s3(session: boto3.Session, region: str) -> ConnectorCapability:
        client = session.client("s3", region_name=region)
        status = ConnectorStatus.AVAILABLE
        details = "S3 bucket inventory and metadata accessible."
        missing_perms = []
        coverage = {"buckets_count": 0}

        try:
            buckets_res = client.list_buckets()
            b_list = buckets_res.get("Buckets", [])
            coverage["buckets_count"] = len(b_list)
            details = f"S3 accessible ({len(b_list)} bucket(s) discovered)."
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            if "AccessDenied" in code:
                status = ConnectorStatus.PERMISSION_DENIED
                missing_perms.append("s3:ListAllMyBuckets")
                details = f"Permission denied: {code}"
            else:
                status = ConnectorStatus.ERROR
                details = f"{code}: {e}"
        except Exception as e:
            status = ConnectorStatus.ERROR
            details = str(e)

        return ConnectorCapability(
            service_id="s3",
            display_name="Amazon S3 Security Posture",
            category="Storage Infrastructure",
            status=status,
            status_details=details,
            required_permissions=[
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetEncryptionConfiguration",
                "s3:GetBucketVersioning",
                "s3:GetBucketPolicyStatus",
                "s3:GetBucketLogging"
            ],
            missing_permissions=missing_perms,
            supported_operations=[
                "ListBuckets",
                "GetBucketLocation",
                "GetBucketPublicAccessBlock",
                "GetEncryptionConfiguration",
                "GetBucketVersioning",
                "GetBucketPolicyStatus",
                "GetBucketLogging"
            ],
            telemetry_type="POSTURE_EVALUATION",
            data_retention_window="Live",
            cost_notes="Standard S3 management API queries.",
            limitations="Strictly read-only; never accesses or downloads S3 object contents.",
            coverage=coverage,
            last_checked_at=datetime.now(UTC).isoformat()
        )

    @staticmethod
    def _probe_iam(session: boto3.Session, region: str) -> ConnectorCapability:
        client = session.client("iam", region_name=region)
        status = ConnectorStatus.AVAILABLE
        details = "IAM posture inspection accessible."
        missing_perms = []
        coverage = {}

        try:
            summary = client.get_account_summary()
            coverage["users_count"] = summary.get("SummaryMap", {}).get("Users", 0)
            coverage["roles_count"] = summary.get("SummaryMap", {}).get("Roles", 0)
            details = f"IAM accessible ({coverage['users_count']} user(s), {coverage['roles_count']} role(s))."
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            if "AccessDenied" in code:
                status = ConnectorStatus.PERMISSION_DENIED
                missing_perms.append("iam:GetAccountSummary")
                details = f"Permission denied: {code}"
            else:
                status = ConnectorStatus.ERROR
                details = f"{code}: {e}"
        except Exception as e:
            status = ConnectorStatus.ERROR
            details = str(e)

        return ConnectorCapability(
            service_id="iam",
            display_name="AWS Identity & Access Management (IAM)",
            category="Access Governance",
            status=status,
            status_details=details,
            required_permissions=[
                "iam:GetAccountSummary",
                "iam:GetAccountPasswordPolicy",
                "iam:ListUsers",
                "iam:ListMFADevices",
                "iam:ListAccessKeys",
                "iam:ListAttachedUserPolicies",
                "iam:ListUserPolicies",
                "iam:ListRoles",
                "iam:ListAttachedRolePolicies"
            ],
            missing_permissions=missing_perms,
            supported_operations=[
                "GetAccountSummary",
                "GetAccountPasswordPolicy",
                "ListUsers",
                "ListMFADevices",
                "ListAccessKeys",
                "ListAttachedUserPolicies",
                "ListUserPolicies",
                "ListRoles",
                "ListAttachedRolePolicies"
            ],
            telemetry_type="POSTURE_EVALUATION",
            data_retention_window="Live",
            cost_notes="Free tier zero-cost IAM APIs.",
            limitations="Assesses declared identities and policies; does not simulate cross-account IAM evaluation.",
            coverage=coverage,
            last_checked_at=datetime.now(UTC).isoformat()
        )

    @staticmethod
    def _get_offline_capabilities(region: str) -> list[ConnectorCapability]:
        """Returns baseline capability declarations for offline/demo operation without contacting AWS."""
        now = datetime.now(UTC).isoformat()
        return [
            ConnectorCapability(
                service_id="sts",
                display_name="AWS Security Token Service (STS)",
                category="Core Identity",
                status=ConnectorStatus.AVAILABLE,
                status_details="Authenticated (Demo Fixture: 112233445566)",
                required_permissions=["sts:GetCallerIdentity"],
                missing_permissions=[],
                supported_operations=["GetCallerIdentity"],
                telemetry_type="STATUS_ONLY",
                data_retention_window="Live",
                cost_notes="Free tier zero-cost API call.",
                limitations="Returns caller identity metadata only.",
                last_checked_at=now
            ),
            ConnectorCapability(
                service_id="s3",
                display_name="Amazon S3 Security Posture",
                category="Storage Infrastructure",
                status=ConnectorStatus.AVAILABLE,
                status_details="S3 accessible (Demo Benchmark: 3 buckets loaded)",
                required_permissions=[
                    "s3:ListAllMyBuckets",
                    "s3:GetBucketLocation",
                    "s3:GetBucketPublicAccessBlock",
                    "s3:GetEncryptionConfiguration",
                    "s3:GetBucketVersioning",
                    "s3:GetBucketPolicyStatus",
                    "s3:GetBucketLogging"
                ],
                missing_permissions=[],
                supported_operations=[
                    "ListBuckets",
                    "GetBucketLocation",
                    "GetBucketPublicAccessBlock",
                    "GetEncryptionConfiguration",
                    "GetBucketVersioning",
                    "GetBucketPolicyStatus",
                    "GetBucketLogging"
                ],
                telemetry_type="POSTURE_EVALUATION",
                data_retention_window="Live",
                cost_notes="Standard S3 management API queries.",
                limitations="Strictly read-only; never accesses or downloads S3 object contents.",
                last_checked_at=now
            ),
            ConnectorCapability(
                service_id="iam",
                display_name="AWS Identity & Access Management (IAM)",
                category="Access Governance",
                status=ConnectorStatus.AVAILABLE,
                status_details="IAM accessible (Demo Benchmark: 2 users, 8 roles)",
                required_permissions=[
                    "iam:GetAccountSummary",
                    "iam:GetAccountPasswordPolicy",
                    "iam:ListUsers",
                    "iam:ListMFADevices",
                    "iam:ListAccessKeys",
                    "iam:ListAttachedUserPolicies",
                    "iam:ListUserPolicies",
                    "iam:ListRoles",
                    "iam:ListAttachedRolePolicies"
                ],
                missing_permissions=[],
                supported_operations=[
                    "GetAccountSummary",
                    "GetAccountPasswordPolicy",
                    "ListUsers",
                    "ListMFADevices",
                    "ListAccessKeys",
                    "ListAttachedUserPolicies",
                    "ListUserPolicies",
                    "ListRoles",
                    "ListAttachedRolePolicies"
                ],
                telemetry_type="POSTURE_EVALUATION",
                data_retention_window="Live",
                cost_notes="Free tier zero-cost IAM APIs.",
                limitations="Assesses declared identities and policies; does not extract secret keys.",
                last_checked_at=now
            ),
            ConnectorCapability(
                service_id="cloudtrail",
                display_name="AWS CloudTrail Management Events",
                category="Auditing & Event History",
                status=ConnectorStatus.AVAILABLE,
                status_details="CloudTrail service operational (Demo Benchmark: 0 active trails)",
                required_permissions=[
                    "cloudtrail:DescribeTrails",
                    "cloudtrail:GetTrailStatus",
                    "cloudtrail:GetEventSelectors",
                    "cloudtrail:LookupEvents"
                ],
                missing_permissions=[],
                supported_operations=[
                    "DescribeTrails",
                    "GetTrailStatus",
                    "GetEventSelectors",
                    "LookupEvents (Management events, 90-day retention)"
                ],
                telemetry_type="EVENTS_LOOKUP",
                data_retention_window="90 days",
                cost_notes="CloudTrail Event History lookup is free of charge for management events.",
                limitations="Event History retains management events up to 90 days.",
                last_checked_at=now
            ),
            ConnectorCapability(
                service_id="config",
                display_name="AWS Config Historical Configuration",
                category="Configuration History & Compliance",
                status=ConnectorStatus.DISABLED,
                status_details="AWS Config is not configured or recording in this region (0 recorders found).",
                required_permissions=[
                    "config:DescribeConfigurationRecorders",
                    "config:DescribeConfigurationRecorderStatus",
                    "config:DescribeDeliveryChannels",
                    "config:GetResourceConfigHistory"
                ],
                missing_permissions=[],
                supported_operations=[
                    "DescribeConfigurationRecorders",
                    "DescribeConfigurationRecorderStatus",
                    "DescribeDeliveryChannels",
                    "GetResourceConfigHistory"
                ],
                telemetry_type="CONFIGURATION_HISTORY",
                data_retention_window="Variable",
                cost_notes="Charges per configuration item recorded when enabled.",
                limitations="Configuration history is only available if a recorder was actively running.",
                last_checked_at=now
            ),
            ConnectorCapability(
                service_id="securityhub",
                display_name="AWS Security Hub CSPM",
                category="Consolidated Findings",
                status=ConnectorStatus.NOT_SUBSCRIBED,
                status_details="Security Hub is not enabled on this account (Demo mode).",
                required_permissions=[
                    "securityhub:DescribeHub",
                    "securityhub:GetEnabledStandards",
                    "securityhub:GetFindings"
                ],
                missing_permissions=[],
                supported_operations=[
                    "DescribeHub",
                    "GetEnabledStandards",
                    "GetFindings (Filtered by Resource ID)"
                ],
                telemetry_type="FINDINGS_RETRIEVED",
                data_retention_window="90 days",
                cost_notes="Paid service billed per check/finding. VYRA strictly queries existing findings.",
                limitations="Only available if Security Hub is enabled in the account and region.",
                last_checked_at=now
            ),
            ConnectorCapability(
                service_id="guardduty",
                display_name="Amazon GuardDuty Threat Findings",
                category="Threat Detection",
                status=ConnectorStatus.NOT_SUBSCRIBED,
                status_details="Service not subscribed/enabled on AWS account (Demo mode).",
                required_permissions=[
                    "guardduty:ListDetectors",
                    "guardduty:GetDetector",
                    "guardduty:ListFindings",
                    "guardduty:GetFindings"
                ],
                missing_permissions=[],
                supported_operations=[
                    "ListDetectors",
                    "GetDetector",
                    "ListFindings",
                    "GetFindings"
                ],
                telemetry_type="FINDINGS_RETRIEVED",
                data_retention_window="90 days",
                cost_notes="Paid service based on log volume. VYRA will not enable detectors.",
                limitations="Only captures threats if GuardDuty was already running.",
                last_checked_at=now
            ),
            ConnectorCapability(
                service_id="accessanalyzer",
                display_name="AWS IAM Access Analyzer",
                category="Resource Sharing & Policy Analysis",
                status=ConnectorStatus.DISABLED,
                status_details="0 active analyzers found in this region (Demo mode).",
                required_permissions=[
                    "access-analyzer:ListAnalyzers",
                    "access-analyzer:ListFindings"
                ],
                missing_permissions=[],
                supported_operations=[
                    "ListAnalyzers",
                    "ListFindings"
                ],
                telemetry_type="FINDINGS_RETRIEVED",
                data_retention_window="Live",
                cost_notes="Free tier service for account-level analyzers.",
                limitations="Analyzes resource policies; does not analyze real-time VPC traffic.",
                last_checked_at=now
            ),
            ConnectorCapability(
                service_id="inspector",
                display_name="Amazon Inspector Vulnerability Scanner",
                category="Vulnerability Management",
                status=ConnectorStatus.DISABLED,
                status_details="Inspector is not enabled in this region (Demo mode).",
                required_permissions=[
                    "inspector2:BatchGetAccountStatus",
                    "inspector2:ListCoverage",
                    "inspector2:ListFindings"
                ],
                missing_permissions=[],
                supported_operations=[
                    "BatchGetAccountStatus",
                    "ListCoverage",
                    "ListFindings"
                ],
                telemetry_type="FINDINGS_RETRIEVED",
                data_retention_window="Active scan life",
                cost_notes="Paid vulnerability scanner billed per resource.",
                limitations="Only captures CVEs for workloads with Inspector enabled.",
                last_checked_at=now
            ),
            ConnectorCapability(
                service_id="macie",
                display_name="Amazon Macie Sensitive Data Security",
                category="Data Security",
                status=ConnectorStatus.DISABLED,
                status_details="Macie is not enabled on this account (Demo mode).",
                required_permissions=[
                    "macie2:GetMacieSession",
                    "macie2:DescribeBuckets",
                    "macie2:ListFindings"
                ],
                missing_permissions=[],
                supported_operations=[
                    "GetMacieSession",
                    "DescribeBuckets",
                    "ListFindings"
                ],
                telemetry_type="FINDINGS_RETRIEVED",
                data_retention_window="Active findings",
                cost_notes="Paid data classification service.",
                limitations="Does not read S3 object contents.",
                last_checked_at=now
            ),
            ConnectorCapability(
                service_id="ssm",
                display_name="AWS Systems Manager (SSM) Inventory",
                category="Workload Inventory & Compliance",
                status=ConnectorStatus.DISABLED,
                status_details="0 managed instance(s) detected (Demo mode).",
                required_permissions=[
                    "ssm:DescribeInstanceInformation",
                    "ssm:DescribeInstancePatches"
                ],
                missing_permissions=[],
                supported_operations=[
                    "DescribeInstanceInformation",
                    "DescribeInstancePatches (Patch Compliance)"
                ],
                telemetry_type="WORKLOAD_INVENTORY",
                data_retention_window="Live",
                cost_notes="Core inventory features are free.",
                limitations="Only captures instances with active SSM agents.",
                last_checked_at=now
            ),
            ConnectorCapability(
                service_id="cloudwatch",
                display_name="Amazon CloudWatch Security Alarms & Logs",
                category="Monitoring & Log Telemetry",
                status=ConnectorStatus.AVAILABLE,
                status_details="CloudWatch metrics and logs operational (Demo mode).",
                required_permissions=[
                    "cloudwatch:DescribeAlarms",
                    "logs:DescribeLogGroups"
                ],
                missing_permissions=[],
                supported_operations=[
                    "DescribeAlarms",
                    "DescribeLogGroups"
                ],
                telemetry_type="METRICS_ALARMS",
                data_retention_window="Live",
                cost_notes="Standard request fees apply.",
                limitations="Evaluates security-relevant metric alarms.",
                last_checked_at=now
            ),
        ]
