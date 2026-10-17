"""
Canonical AWS IAM Permission Inventory for VYRA.

Single authoritative source of truth for:
- Required IAM actions per AWS service (grounded in AWS Service Authorization Reference)
- Exact boto3 client methods
- Resource-level ARN scoping capabilities vs wildcard requirements
- Least-privilege IAM policy document generation
- Prohibited actions and security boundary guarantees
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class IAMOperation:
    service_id: str
    action: str
    boto3_method: str
    resource_scope: str | list[str]
    supports_resource_scoping: bool
    scope_description: str
    wildcard_justification: str | None = None


# Canonical inventory of all 44 AWS operations implemented across VYRA collectors,
# connectors, investigation workflows, and verification routines.
CANONICAL_OPERATIONS: tuple[IAMOperation, ...] = (
    # -------------------------------------------------------------------------
    # 1. AWS STS (Identity & Pre-Flight Validation)
    # -------------------------------------------------------------------------
    IAMOperation(
        service_id="sts",
        action="sts:GetCallerIdentity",
        boto3_method="get_caller_identity",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="Global caller identity validation",
        wildcard_justification="AWS STS GetCallerIdentity is a global identity verification API and does not support resource ARN constraints in IAM policies.",
    ),

    # -------------------------------------------------------------------------
    # 2. Amazon S3 (Bucket Security Posture Evaluation)
    # NOTE ON AUDIT TARGETS:
    # - s3:GetBucketPolicyStatus is used (NOT s3:GetBucketPolicy) because VYRA
    #   directly evaluates whether public access is enabled without downloading
    #   arbitrary customer policy document JSON payloads.
    # - s3:GetBucketAcl is excluded; public access is audited via PublicAccessBlock.
    # - s3:GetBucketTagging is excluded; tag auditing is not implemented.
    # -------------------------------------------------------------------------
    IAMOperation(
        service_id="s3",
        action="s3:ListAllMyBuckets",
        boto3_method="list_buckets",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="Account-level bucket inventory enumeration",
        wildcard_justification="AWS S3 ListAllMyBuckets enumerates all buckets owned by the authenticated sender and requires Resource: * per AWS IAM engine specification.",
    ),
    IAMOperation(
        service_id="s3",
        action="s3:GetBucketLocation",
        boto3_method="get_bucket_location",
        resource_scope="arn:aws:s3:::*",
        supports_resource_scoping=True,
        scope_description="S3 bucket region determination",
    ),
    IAMOperation(
        service_id="s3",
        action="s3:GetBucketPublicAccessBlock",
        boto3_method="get_public_access_block",
        resource_scope="arn:aws:s3:::*",
        supports_resource_scoping=True,
        scope_description="S3 Block Public Access (BPA) configuration",
    ),
    IAMOperation(
        service_id="s3",
        action="s3:GetBucketPolicyStatus",
        boto3_method="get_bucket_policy_status",
        resource_scope="arn:aws:s3:::*",
        supports_resource_scoping=True,
        scope_description="S3 public policy evaluator status",
    ),
    IAMOperation(
        service_id="s3",
        action="s3:GetEncryptionConfiguration",
        boto3_method="get_bucket_encryption",
        resource_scope="arn:aws:s3:::*",
        supports_resource_scoping=True,
        scope_description="S3 default server-side encryption configuration",
    ),
    IAMOperation(
        service_id="s3",
        action="s3:GetBucketVersioning",
        boto3_method="get_bucket_versioning",
        resource_scope="arn:aws:s3:::*",
        supports_resource_scoping=True,
        scope_description="S3 bucket object versioning status",
    ),
    IAMOperation(
        service_id="s3",
        action="s3:GetBucketLogging",
        boto3_method="get_bucket_logging",
        resource_scope="arn:aws:s3:::*",
        supports_resource_scoping=True,
        scope_description="S3 bucket server access logging configuration",
    ),

    # -------------------------------------------------------------------------
    # 3. AWS IAM (Identity & Access Hygiene)
    # NOTE ON AUDIT TARGETS:
    # - iam:GetPolicy & iam:GetPolicyVersion are excluded; managed policy attachments
    #   are discovered via ListAttachedUserPolicies & ListAttachedRolePolicies
    #   without downloading raw version policy documents.
    # - iam:ListRolePolicies is excluded; roles are evaluated via managed policy
    #   attachments (iam:ListAttachedRolePolicies).
    # -------------------------------------------------------------------------
    IAMOperation(
        service_id="iam",
        action="iam:GetAccountSummary",
        boto3_method="get_account_summary",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="Account-level IAM entity and root MFA summary",
        wildcard_justification="AWS IAM GetAccountSummary is an account-level entity and does not accept resource ARN restrictions.",
    ),
    IAMOperation(
        service_id="iam",
        action="iam:GetAccountPasswordPolicy",
        boto3_method="get_account_password_policy",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="Account-level password complexity policy",
        wildcard_justification="AWS IAM GetAccountPasswordPolicy is account-scoped and requires Resource: *.",
    ),
    IAMOperation(
        service_id="iam",
        action="iam:ListUsers",
        boto3_method="list_users",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="Account user identity enumeration",
        wildcard_justification="AWS IAM ListUsers enumerates all IAM user identities and does not support resource ARN restrictions.",
    ),
    IAMOperation(
        service_id="iam",
        action="iam:ListRoles",
        boto3_method="list_roles",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="Account role enumeration",
        wildcard_justification="AWS IAM ListRoles enumerates IAM roles across the account and requires Resource: *.",
    ),
    IAMOperation(
        service_id="iam",
        action="iam:ListMFADevices",
        boto3_method="list_mfa_devices",
        resource_scope="arn:aws:iam::*:user/*",
        supports_resource_scoping=True,
        scope_description="User MFA hardware/virtual device posture",
    ),
    IAMOperation(
        service_id="iam",
        action="iam:ListAccessKeys",
        boto3_method="list_access_keys",
        resource_scope="arn:aws:iam::*:user/*",
        supports_resource_scoping=True,
        scope_description="User access key age and rotation audit",
    ),
    IAMOperation(
        service_id="iam",
        action="iam:ListAttachedUserPolicies",
        boto3_method="list_attached_user_policies",
        resource_scope="arn:aws:iam::*:user/*",
        supports_resource_scoping=True,
        scope_description="Managed policies attached to users",
    ),
    IAMOperation(
        service_id="iam",
        action="iam:ListUserPolicies",
        boto3_method="list_user_policies",
        resource_scope="arn:aws:iam::*:user/*",
        supports_resource_scoping=True,
        scope_description="Inline policy names attached to users",
    ),
    IAMOperation(
        service_id="iam",
        action="iam:ListAttachedRolePolicies",
        boto3_method="list_attached_role_policies",
        resource_scope="arn:aws:iam::*:role/*",
        supports_resource_scoping=True,
        scope_description="Managed policies attached to roles",
    ),

    # -------------------------------------------------------------------------
    # 4. AWS CloudTrail (Audit Trail Status & Change Investigation)
    # -------------------------------------------------------------------------
    IAMOperation(
        service_id="cloudtrail",
        action="cloudtrail:DescribeTrails",
        boto3_method="describe_trails",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="Regional audit trail inventory",
        wildcard_justification="AWS CloudTrail DescribeTrails lists trails across regions and requires Resource: * per AWS specification.",
    ),
    IAMOperation(
        service_id="cloudtrail",
        action="cloudtrail:GetTrailStatus",
        boto3_method="get_trail_status",
        resource_scope="arn:aws:cloudtrail:*:*:trail/*",
        supports_resource_scoping=True,
        scope_description="Trail active logging status",
    ),
    IAMOperation(
        service_id="cloudtrail",
        action="cloudtrail:GetEventSelectors",
        boto3_method="get_event_selectors",
        resource_scope="arn:aws:cloudtrail:*:*:trail/*",
        supports_resource_scoping=True,
        scope_description="Trail management & data event selectors",
    ),
    IAMOperation(
        service_id="cloudtrail",
        action="cloudtrail:LookupEvents",
        boto3_method="lookup_events",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="90-day management event history lookup for root-cause diffing",
        wildcard_justification="AWS CloudTrail LookupEvents queries the account-wide event history and does not support resource ARN constraints.",
    ),

    # -------------------------------------------------------------------------
    # 5. AWS Config (Configuration Recorders & Resource Timeline Diffing)
    # -------------------------------------------------------------------------
    IAMOperation(
        service_id="config",
        action="config:DescribeConfigurationRecorders",
        boto3_method="describe_configuration_recorders",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="AWS Config recorder inventory",
        wildcard_justification="AWS Config DescribeConfigurationRecorders operates at the regional service level and requires Resource: *.",
    ),
    IAMOperation(
        service_id="config",
        action="config:DescribeConfigurationRecorderStatus",
        boto3_method="describe_configuration_recorder_status",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="Active recording state verification",
        wildcard_justification="AWS Config DescribeConfigurationRecorderStatus requires Resource: *.",
    ),
    IAMOperation(
        service_id="config",
        action="config:DescribeDeliveryChannels",
        boto3_method="describe_delivery_channels",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="Delivery channel configuration inspection",
        wildcard_justification="AWS Config DescribeDeliveryChannels requires Resource: *.",
    ),
    IAMOperation(
        service_id="config",
        action="config:GetResourceConfigHistory",
        boto3_method="get_resource_config_history",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="Historical configuration timeline queries for investigation diffs",
        wildcard_justification="AWS Config GetResourceConfigHistory queries historical configuration timelines and does not support resource ARN restrictions.",
    ),

    # -------------------------------------------------------------------------
    # 6. AWS Security Hub (Hub Posture & CIS Standards)
    # -------------------------------------------------------------------------
    IAMOperation(
        service_id="securityhub",
        action="securityhub:DescribeHub",
        boto3_method="describe_hub",
        resource_scope="arn:aws:securityhub:*:*:hub/default",
        supports_resource_scoping=True,
        scope_description="Security Hub subscription and enrollment status",
    ),
    IAMOperation(
        service_id="securityhub",
        action="securityhub:GetEnabledStandards",
        boto3_method="get_enabled_standards",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="Active CIS and FSBP compliance standards subscriptions",
        wildcard_justification="AWS Security Hub GetEnabledStandards queries account-wide standards subscriptions and requires Resource: *.",
    ),
    IAMOperation(
        service_id="securityhub",
        action="securityhub:GetFindings",
        boto3_method="get_findings",
        resource_scope="arn:aws:securityhub:*:*:hub/default",
        supports_resource_scoping=True,
        scope_description="Active external security findings retrieval",
    ),

    # -------------------------------------------------------------------------
    # 7. Amazon GuardDuty (Threat Detection Posture & Findings)
    # NOTE ON AUDIT TARGET:
    # - guardduty:ListFindings IS implemented and invoked by GuardDutyConnector
    #   (list_findings_summary) to retrieve threat finding IDs for an active detector.
    # -------------------------------------------------------------------------
    IAMOperation(
        service_id="guardduty",
        action="guardduty:ListDetectors",
        boto3_method="list_detectors",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="GuardDuty detector discovery",
        wildcard_justification="AWS GuardDuty ListDetectors discovers detector IDs in the region and requires Resource: *.",
    ),
    IAMOperation(
        service_id="guardduty",
        action="guardduty:GetDetector",
        boto3_method="get_detector",
        resource_scope="arn:aws:guardduty:*:*:detector/*",
        supports_resource_scoping=True,
        scope_description="GuardDuty detector active status inspection",
    ),
    IAMOperation(
        service_id="guardduty",
        action="guardduty:ListFindings",
        boto3_method="list_findings",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="Active threat finding IDs retrieval",
        wildcard_justification="AWS GuardDuty ListFindings queries finding IDs for a detector and requires Resource: * per AWS IAM engine evaluation specifications.",
    ),
    IAMOperation(
        service_id="guardduty",
        action="guardduty:GetFindings",
        boto3_method="get_findings",
        resource_scope="arn:aws:guardduty:*:*:detector/*",
        supports_resource_scoping=True,
        scope_description="Threat finding detail summaries",
    ),

    # -------------------------------------------------------------------------
    # 8. AWS IAM Access Analyzer (External Exposure & Policy Analysis)
    # NOTE: AWS IAM Action prefix is 'access-analyzer:' (with hyphen),
    # while the boto3 client service name is 'accessanalyzer'.
    # -------------------------------------------------------------------------
    IAMOperation(
        service_id="accessanalyzer",
        action="access-analyzer:ListAnalyzers",
        boto3_method="list_analyzers",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="IAM Access Analyzer discovery in the target region",
        wildcard_justification="AWS IAM Access Analyzer ListAnalyzers enumerates analyzers in a region and requires Resource: *.",
    ),
    IAMOperation(
        service_id="accessanalyzer",
        action="access-analyzer:ListFindings",
        boto3_method="list_findings",
        resource_scope="arn:aws:access-analyzer:*:*:analyzer/*",
        supports_resource_scoping=True,
        scope_description="External cross-account access findings retrieval",
    ),

    # -------------------------------------------------------------------------
    # 9. Amazon Inspector v2 (Vulnerability CVE Posture)
    # -------------------------------------------------------------------------
    IAMOperation(
        service_id="inspector",
        action="inspector2:BatchGetAccountStatus",
        boto3_method="batch_get_account_status",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="Inspector v2 account scanning status check",
        wildcard_justification="AWS Inspector v2 BatchGetAccountStatus evaluates account-level scanning state and requires Resource: *.",
    ),
    IAMOperation(
        service_id="inspector",
        action="inspector2:ListCoverage",
        boto3_method="list_coverage",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="Inspector v2 scanned workload coverage",
        wildcard_justification="AWS Inspector v2 ListCoverage evaluates fleet coverage across the account and requires Resource: *.",
    ),
    IAMOperation(
        service_id="inspector",
        action="inspector2:ListFindings",
        boto3_method="list_findings",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="Inspector v2 CVE vulnerability findings retrieval",
        wildcard_justification="AWS Inspector v2 ListFindings filters findings across account resources and requires Resource: * per AWS IAM authorization specification.",
    ),

    # -------------------------------------------------------------------------
    # 10. Amazon Macie (Sensitive Data Discovery Posture)
    # -------------------------------------------------------------------------
    IAMOperation(
        service_id="macie",
        action="macie2:GetMacieSession",
        boto3_method="get_macie_session",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="Macie session status & publishing frequency check",
        wildcard_justification="AWS Macie GetMacieSession checks account-level session status and requires Resource: *.",
    ),
    IAMOperation(
        service_id="macie",
        action="macie2:DescribeBuckets",
        boto3_method="describe_buckets",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="S3 buckets evaluated by Macie discovery",
        wildcard_justification="AWS Macie DescribeBuckets queries all buckets evaluated by Macie in the region and requires Resource: *.",
    ),
    IAMOperation(
        service_id="macie",
        action="macie2:ListFindings",
        boto3_method="list_findings",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="Sensitive data discovery finding IDs retrieval",
        wildcard_justification="AWS Macie ListFindings lists findings across the account session and requires Resource: * per AWS specification.",
    ),

    # -------------------------------------------------------------------------
    # 11. AWS Systems Manager (Compute Fleet & Patch Compliance)
    # -------------------------------------------------------------------------
    IAMOperation(
        service_id="ssm",
        action="ssm:DescribeInstanceInformation",
        boto3_method="describe_instance_information",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="SSM managed instance fleet inventory",
        wildcard_justification="AWS Systems Manager DescribeInstanceInformation lists managed EC2 instances and requires Resource: * per AWS authorization reference.",
    ),
    IAMOperation(
        service_id="ssm",
        action="ssm:DescribeInstancePatches",
        boto3_method="describe_instance_patches",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="Instance patch compliance status queries",
        wildcard_justification="AWS Systems Manager DescribeInstancePatches queries patch state for instances and does not support resource ARN restrictions in IAM policies.",
    ),

    # -------------------------------------------------------------------------
    # 12. Amazon CloudWatch & Logs (Alarms & Audit Log Retention)
    # -------------------------------------------------------------------------
    IAMOperation(
        service_id="cloudwatch",
        action="cloudwatch:DescribeAlarms",
        boto3_method="describe_alarms",
        resource_scope="*",
        supports_resource_scoping=False,
        scope_description="Security-relevant metric alarms inspection",
        wildcard_justification="AWS CloudWatch DescribeAlarms queries alarm states across the region and requires Resource: * per AWS authorization reference.",
    ),
    IAMOperation(
        service_id="cloudwatch",
        action="logs:DescribeLogGroups",
        boto3_method="describe_log_groups",
        resource_scope="arn:aws:logs:*:*:log-group:*",
        supports_resource_scoping=True,
        scope_description="CloudWatch log group presence and retention period audit",
    ),
)

# Set of all 44 verified canonical actions
CANONICAL_ACTIONS: frozenset[str] = frozenset(op.action for op in CANONICAL_OPERATIONS)

# Mapping of service_id to required IAM actions
SERVICE_ACTIONS_MAP: dict[str, list[str]] = {}
for op in CANONICAL_OPERATIONS:
    SERVICE_ACTIONS_MAP.setdefault(op.service_id, []).append(op.action)

# Explicit prohibited actions that VYRA will NEVER request or call
PROHIBITED_ACTIONS: dict[str, str] = {
    "s3:GetObject": "Prevents any extraction, reading, or download of sensitive data stored in S3 objects.",
    "iam:GetUserPolicy": "Prevents extraction of inline user policy documents that may contain sensitive credentials.",
    "iam:GetRolePolicy": "Prevents extraction of inline role policy documents.",
    "secretsmanager:GetSecretValue": "Strict boundary: VYRA never reads plaintext application or infrastructure secrets.",
    "ssm:GetParameter": "Zero parameter payload access: prevents retrieval of SSM Parameter Store plaintext values.",
    "ssm:GetParameters": "Zero parameter payload access.",
    "ssm:SendCommand": "No remote command execution on EC2 instances or compute workloads.",
    "ssm:StartSession": "No interactive terminal or shell sessions.",
    "cloudwatch:GetMetricData": "Prevents unneeded billable high-cardinality metric batch queries.",
    "logs:FilterLogEvents": "Prevents bulk scanning or streaming of application log stream records.",
}

# Audit target justifications explaining why each was investigated and its exact status
AUDIT_TARGET_STATUS: dict[str, dict[str, Any]] = {
    "s3:GetBucketPolicy": {
        "implemented": False,
        "reason": "VYRA calls s3:GetBucketPolicyStatus (IsPublic: true/false) rather than downloading customer bucket policy JSON.",
    },
    "s3:GetBucketAcl": {
        "implemented": False,
        "reason": "Public access posture is evaluated via s3:GetBucketPublicAccessBlock and policy status rather than bucket ACLs.",
    },
    "s3:GetBucketTagging": {
        "implemented": False,
        "reason": "Tag-based security posture evaluation is not implemented.",
    },
    "iam:GetPolicy": {
        "implemented": False,
        "reason": "Policy ARNs are enumerated via ListAttachedUserPolicies / ListAttachedRolePolicies; live policy entities are not retrieved.",
    },
    "iam:GetPolicyVersion": {
        "implemented": False,
        "reason": "Live managed policy version JSON documents are not fetched via AWS APIs.",
    },
    "iam:ListRolePolicies": {
        "implemented": False,
        "reason": "Role posture audits evaluate managed attached policies (iam:ListAttachedRolePolicies); inline role policies are not queried.",
    },
    "guardduty:ListFindings": {
        "implemented": True,
        "reason": "Active operation invoked by GuardDutyConnector.list_findings_summary; requires Resource: * per AWS IAM engine evaluation rules.",
    },
}


def get_canonical_permissions_for_service(service_id: str) -> list[str]:
    """Returns the immutable list of canonical IAM actions for a given service."""
    if service_id not in SERVICE_ACTIONS_MAP:
        raise KeyError(f"Unknown service '{service_id}'. Must be one of {list(SERVICE_ACTIONS_MAP.keys())}")
    return list(SERVICE_ACTIONS_MAP[service_id])


def generate_least_privilege_policy(narrow_resources: bool = True) -> dict[str, Any]:
    """
    Generates a production-grade AWS IAM Policy document.

    If narrow_resources is True (default), actions supporting resource-level permissions
    are strictly partitioned into discrete statements bound to their respective exact ARN patterns
    per the AWS Service Authorization Reference. No action is ever paired with an incompatible
    resource ARN type.

    Actions where the AWS IAM engine mandates Resource: * are segregated in an inventory statement
    with explicit technical justifications.

    Enforces zero duplicate actions across all statements.
    """
    if not narrow_resources:
        # Standard two-statement format
        core_actions = (
            SERVICE_ACTIONS_MAP["sts"]
            + SERVICE_ACTIONS_MAP["s3"]
            + SERVICE_ACTIONS_MAP["iam"]
        )
        investigation_actions = (
            SERVICE_ACTIONS_MAP["cloudtrail"]
            + SERVICE_ACTIONS_MAP["config"]
            + SERVICE_ACTIONS_MAP["securityhub"]
            + SERVICE_ACTIONS_MAP["guardduty"]
            + SERVICE_ACTIONS_MAP["accessanalyzer"]
            + SERVICE_ACTIONS_MAP["inspector"]
            + SERVICE_ACTIONS_MAP["macie"]
            + SERVICE_ACTIONS_MAP["ssm"]
            + SERVICE_ACTIONS_MAP["cloudwatch"]
        )
        statements = [
            {
                "Sid": "VyraCorePostureReadOnly",
                "Effect": "Allow",
                "Action": sorted(list(set(core_actions))),
                "Resource": "*",
            },
            {
                "Sid": "VyraInvestigationAndVerification",
                "Effect": "Allow",
                "Action": sorted(list(set(investigation_actions))),
                "Resource": "*",
            },
        ]
        # Validate zero redundant action entries across statements
        seen_wide: set[str] = set()
        for stmt in statements:
            for act in stmt["Action"]:
                if act in seen_wide:
                    raise ValueError(f"Duplicate action in standard policy: {act}")
                seen_wide.add(act)

        return {
            "Version": "2012-10-17",
            "Statement": statements,
        }

    # Strict resource-level segregation (no mismatched action-ARN pairs)
    wildcard_actions: list[str] = []
    s3_actions: list[str] = []
    iam_user_actions: list[str] = []
    iam_role_actions: list[str] = []
    cloudtrail_actions: list[str] = []
    securityhub_actions: list[str] = []
    guardduty_actions: list[str] = []
    accessanalyzer_actions: list[str] = []
    logs_actions: list[str] = []

    for op in CANONICAL_OPERATIONS:
        if not op.supports_resource_scoping:
            wildcard_actions.append(op.action)
        elif op.service_id == "s3":
            s3_actions.append(op.action)
        elif op.service_id == "iam" and ":user/" in str(op.resource_scope):
            iam_user_actions.append(op.action)
        elif op.service_id == "iam" and ":role/" in str(op.resource_scope):
            iam_role_actions.append(op.action)
        elif op.service_id == "cloudtrail":
            cloudtrail_actions.append(op.action)
        elif op.service_id == "securityhub":
            securityhub_actions.append(op.action)
        elif op.service_id == "guardduty":
            guardduty_actions.append(op.action)
        elif op.service_id == "accessanalyzer":
            accessanalyzer_actions.append(op.action)
        elif op.service_id == "cloudwatch" and "logs:" in op.action:
            logs_actions.append(op.action)

    statements = [
        {
            "Sid": "VyraInventoryAndGlobalReadOnly",
            "Effect": "Allow",
            "Action": sorted(list(set(wildcard_actions))),
            "Resource": "*",
        },
        {
            "Sid": "VyraS3BucketPostureReadOnly",
            "Effect": "Allow",
            "Action": sorted(list(set(s3_actions))),
            "Resource": "arn:aws:s3:::*",
        },
        {
            "Sid": "VyraIAMUserPostureReadOnly",
            "Effect": "Allow",
            "Action": sorted(list(set(iam_user_actions))),
            "Resource": "arn:aws:iam::*:user/*",
        },
        {
            "Sid": "VyraIAMRolePostureReadOnly",
            "Effect": "Allow",
            "Action": sorted(list(set(iam_role_actions))),
            "Resource": "arn:aws:iam::*:role/*",
        },
        {
            "Sid": "VyraCloudTrailTrailPostureReadOnly",
            "Effect": "Allow",
            "Action": sorted(list(set(cloudtrail_actions))),
            "Resource": "arn:aws:cloudtrail:*:*:trail/*",
        },
        {
            "Sid": "VyraSecurityHubPostureReadOnly",
            "Effect": "Allow",
            "Action": sorted(list(set(securityhub_actions))),
            "Resource": "arn:aws:securityhub:*:*:hub/default",
        },
        {
            "Sid": "VyraGuardDutyDetectorPostureReadOnly",
            "Effect": "Allow",
            "Action": sorted(list(set(guardduty_actions))),
            "Resource": "arn:aws:guardduty:*:*:detector/*",
        },
        {
            "Sid": "VyraAccessAnalyzerPostureReadOnly",
            "Effect": "Allow",
            "Action": sorted(list(set(accessanalyzer_actions))),
            "Resource": "arn:aws:access-analyzer:*:*:analyzer/*",
        },
        {
            "Sid": "VyraCloudWatchLogsRetentionReadOnly",
            "Effect": "Allow",
            "Action": sorted(list(set(logs_actions))),
            "Resource": "arn:aws:logs:*:*:log-group:*",
        },
    ]

    # Validate zero redundant action entries across all statements
    seen_narrowed: set[str] = set()
    for stmt in statements:
        for act in stmt["Action"]:
            if act in seen_narrowed:
                raise ValueError(f"Duplicate action detected in policy generator: {act}")
            seen_narrowed.add(act)

    return {
        "Version": "2012-10-17",
        "Statement": statements,
    }


def render_policy_json(narrow_resources: bool = True) -> str:
    """Returns the formatted, indented JSON string for the IAM policy."""
    policy = generate_least_privilege_policy(narrow_resources=narrow_resources)
    return json.dumps(policy, indent=2)


def sync_documentation_policies(repo_root: Path | None = None) -> dict[str, bool]:
    """
    Safely regenerates the JSON policy blocks in README.md and SECURITY.md
    directly from generate_least_privilege_policy(narrow_resources=True).
    Ensures docs never drift from the canonical Python inventory.
    """
    if repo_root is None:
        # Defaults to repository root relative to this file: backend/app/core -> repo root
        repo_root = Path(__file__).resolve().parent.parent.parent.parent

    policy_json = render_policy_json(narrow_resources=True)
    results = {}

    # Target files
    doc_files = [repo_root / "README.md", repo_root / "SECURITY.md"]

    for doc_path in doc_files:
        if not doc_path.exists():
            results[doc_path.name] = False
            continue

        content = doc_path.read_text(encoding="utf-8")

        # Pattern matches the ```json { ... } ``` block following the Least-Privilege IAM policy header
        pattern = re.compile(
            r"(###?\s+(?:Minimal\s+)?Least-Privilege\s+IAM\s+Policy.*?\n+```json\n)(.*?)(\n```)",
            re.DOTALL | re.IGNORECASE,
        )

        if not pattern.search(content):
            # Fallback pattern for general policy blocks
            pattern = re.compile(
                r"(##\s+Least-Privilege\s+IAM\s+Policy\s+Specification.*?\n+```json\n)(.*?)(\n```)",
                re.DOTALL | re.IGNORECASE,
            )

        if pattern.search(content):
            new_content = pattern.sub(rf"\g<1>{policy_json}\g<3>", content)
            doc_path.write_text(new_content, encoding="utf-8")
            results[doc_path.name] = True
        else:
            results[doc_path.name] = False

    return results
