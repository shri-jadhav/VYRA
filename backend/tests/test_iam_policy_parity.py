"""
Strict Automated IAM Policy Parity and Audit Verification Suite.

Guarantees that:
1. Every implemented AWS SDK collector/connector operation is present in CANONICAL_OPERATIONS.
2. Every action in CANONICAL_OPERATIONS is present in both narrowed and standard generated policies.
3. Resource ARN scoping strictly aligns with AWS Service Authorization Reference.
4. Audit targets (s3:GetBucketPolicy, s3:GetBucketAcl, s3:GetBucketTagging, iam:GetPolicy,
   iam:GetPolicyVersion, iam:ListRolePolicies, guardduty:ListFindings) are explicitly verified.
5. README.md and SECURITY.md match the canonical generator action-by-action with zero drift.
"""

import json
import re
from pathlib import Path
from unittest.mock import MagicMock

from backend.app.connectors.access_analyzer_connector import AccessAnalyzerConnector
from backend.app.connectors.cloudtrail_connector import CloudTrailConnector
from backend.app.connectors.cloudwatch_connector import CloudWatchConnector
from backend.app.connectors.config_connector import AWSConfigConnector
from backend.app.connectors.guardduty_connector import GuardDutyConnector
from backend.app.connectors.inspector_connector import InspectorConnector
from backend.app.connectors.macie_connector import MacieConnector
from backend.app.connectors.security_hub_connector import SecurityHubConnector
from backend.app.connectors.ssm_connector import SSMConnector
from backend.app.core.iam_permissions import (
    AUDIT_TARGET_STATUS,
    CANONICAL_ACTIONS,
    CANONICAL_OPERATIONS,
    PROHIBITED_ACTIONS,
    SERVICE_ACTIONS_MAP,
    generate_least_privilege_policy,
)


def test_complete_canonical_inventory_action_by_action_in_policy():
    """
    Validates that every single implemented action in CANONICAL_OPERATIONS
    appears action-by-action in the generated policy.
    Fails if any implemented operation is omitted.
    """
    assert len(CANONICAL_OPERATIONS) == 44, f"Expected 44 canonical operations, found {len(CANONICAL_OPERATIONS)}"
    assert len(CANONICAL_ACTIONS) == 44, f"Expected 44 unique canonical actions, found {len(CANONICAL_ACTIONS)}"

    # Test Narrowed Policy
    narrowed_policy = generate_least_privilege_policy(narrow_resources=True)
    narrowed_actions = set()
    for statement in narrowed_policy["Statement"]:
        for action in statement["Action"]:
            narrowed_actions.add(action)

    omitted_from_narrowed = CANONICAL_ACTIONS - narrowed_actions
    assert not omitted_from_narrowed, f"Actions omitted from narrowed policy: {omitted_from_narrowed}"
    extra_in_narrowed = narrowed_actions - CANONICAL_ACTIONS
    assert not extra_in_narrowed, f"Unregistered actions in narrowed policy: {extra_in_narrowed}"
    assert narrowed_actions == CANONICAL_ACTIONS

    # Test Standard Two-Statement Policy
    standard_policy = generate_least_privilege_policy(narrow_resources=False)
    standard_actions = set()
    for statement in standard_policy["Statement"]:
        for action in statement["Action"]:
            standard_actions.add(action)

    omitted_from_standard = CANONICAL_ACTIONS - standard_actions
    assert not omitted_from_standard, f"Actions omitted from standard policy: {omitted_from_standard}"
    extra_in_standard = standard_actions - CANONICAL_ACTIONS
    assert not extra_in_standard, f"Unregistered actions in standard policy: {extra_in_standard}"
    assert standard_actions == CANONICAL_ACTIONS


def test_collectors_and_connectors_map_to_canonical_inventory():
    """
    Discovers all required permissions from active collectors and connector classes
    and asserts action-by-action correspondence with CANONICAL_ACTIONS.
    """
    session_mock = MagicMock()

    connectors = [
        CloudTrailConnector(session_mock, region_name="us-east-1"),
        AWSConfigConnector(session_mock, region_name="us-east-1"),
        SecurityHubConnector(session_mock, region_name="us-east-1"),
        GuardDutyConnector(session_mock, region_name="us-east-1"),
        AccessAnalyzerConnector(session_mock, region_name="us-east-1"),
        InspectorConnector(session_mock, region_name="us-east-1"),
        MacieConnector(session_mock, region_name="us-east-1"),
        SSMConnector(session_mock, region_name="us-east-1"),
        CloudWatchConnector(session_mock, region_name="us-east-1"),
    ]

    all_connector_actions = set()
    for conn in connectors:
        for perm in conn.required_permissions:
            all_connector_actions.add(perm)

    # Core service actions (STS, S3, IAM) from collectors
    core_actions = set(SERVICE_ACTIONS_MAP["sts"] + SERVICE_ACTIONS_MAP["s3"] + SERVICE_ACTIONS_MAP["iam"])

    total_implemented_actions = all_connector_actions | core_actions
    assert total_implemented_actions == CANONICAL_ACTIONS, (
        f"Difference between collector/connector actions and canonical actions: "
        f"Missing: {CANONICAL_ACTIONS - total_implemented_actions}, "
        f"Extra: {total_implemented_actions - CANONICAL_ACTIONS}"
    )


def test_explicit_audit_targets_usage_and_omissions():
    """
    Explicitly tests and verifies the 7 audit targets specified in requirements:
    1. s3:GetBucketPolicy
    2. s3:GetBucketAcl
    3. s3:GetBucketTagging
    4. iam:GetPolicy
    5. iam:GetPolicyVersion
    6. iam:ListRolePolicies
    7. guardduty:ListFindings
    """
    # 1. s3:GetBucketPolicy: NOT in policy; s3:GetBucketPolicyStatus is used instead
    assert "s3:GetBucketPolicy" not in CANONICAL_ACTIONS
    assert "s3:GetBucketPolicyStatus" in CANONICAL_ACTIONS
    assert AUDIT_TARGET_STATUS["s3:GetBucketPolicy"]["implemented"] is False

    # 2. s3:GetBucketAcl: NOT in policy; PublicAccessBlock is used instead
    assert "s3:GetBucketAcl" not in CANONICAL_ACTIONS
    assert "s3:GetBucketPublicAccessBlock" in CANONICAL_ACTIONS
    assert AUDIT_TARGET_STATUS["s3:GetBucketAcl"]["implemented"] is False

    # 3. s3:GetBucketTagging: NOT in policy; tagging audit is not implemented
    assert "s3:GetBucketTagging" not in CANONICAL_ACTIONS
    assert AUDIT_TARGET_STATUS["s3:GetBucketTagging"]["implemented"] is False

    # 4. iam:GetPolicy: NOT in policy; managed policy bodies are not retrieved
    assert "iam:GetPolicy" not in CANONICAL_ACTIONS
    assert AUDIT_TARGET_STATUS["iam:GetPolicy"]["implemented"] is False

    # 5. iam:GetPolicyVersion: NOT in policy; version bodies are not retrieved
    assert "iam:GetPolicyVersion" not in CANONICAL_ACTIONS
    assert AUDIT_TARGET_STATUS["iam:GetPolicyVersion"]["implemented"] is False

    # 6. iam:ListRolePolicies: NOT in policy; managed attachments are used via iam:ListAttachedRolePolicies
    assert "iam:ListRolePolicies" not in CANONICAL_ACTIONS
    assert "iam:ListAttachedRolePolicies" in CANONICAL_ACTIONS
    assert AUDIT_TARGET_STATUS["iam:ListRolePolicies"]["implemented"] is False

    # 7. guardduty:ListFindings: IS IMPLEMENTED and MUST be in policy (with Resource: *)
    assert "guardduty:ListFindings" in CANONICAL_ACTIONS
    assert AUDIT_TARGET_STATUS["guardduty:ListFindings"]["implemented"] is True

    # Check guardduty:ListFindings appears in GuardDutyConnector
    gd_conn = GuardDutyConnector(MagicMock(), region_name="us-east-1")
    assert "guardduty:ListFindings" in gd_conn.required_permissions

    # Check guardduty:ListFindings appears in narrowed policy under Resource: *
    policy = generate_least_privilege_policy(narrow_resources=True)
    inv_statement = next(s for s in policy["Statement"] if s["Sid"] == "VyraInventoryAndGlobalReadOnly")
    assert "guardduty:ListFindings" in inv_statement["Action"]
    assert "guardduty:ListDetectors" in inv_statement["Action"]
    assert inv_statement["Resource"] == "*"


def test_resource_scoping_strict_type_alignment():
    """
    Validates that every statement in the narrowed policy contains ONLY resource ARNs
    compatible with the actions in that statement, preventing cross-service ARN leakage.
    """
    policy = generate_least_privilege_policy(narrow_resources=True)
    statements_by_sid = {s["Sid"]: s for s in policy["Statement"]}

    # Statement 1: VyraInventoryAndGlobalReadOnly
    stmt1 = statements_by_sid["VyraInventoryAndGlobalReadOnly"]
    assert stmt1["Resource"] == "*"
    assert len(stmt1["Action"]) == 25
    assert "sts:GetCallerIdentity" in stmt1["Action"]
    assert "s3:ListAllMyBuckets" in stmt1["Action"]
    assert "iam:ListUsers" in stmt1["Action"]
    assert "iam:ListRoles" in stmt1["Action"]
    assert "cloudtrail:DescribeTrails" in stmt1["Action"]
    assert "cloudtrail:LookupEvents" in stmt1["Action"]
    assert "access-analyzer:ListAnalyzers" in stmt1["Action"]
    assert "guardduty:ListDetectors" in stmt1["Action"]
    assert "guardduty:ListFindings" in stmt1["Action"]

    # Statement 2: S3 Buckets
    stmt2 = statements_by_sid["VyraS3BucketPostureReadOnly"]
    assert stmt2["Resource"] == "arn:aws:s3:::*"
    assert all(a.startswith("s3:") for a in stmt2["Action"])
    assert "s3:ListAllMyBuckets" not in stmt2["Action"]  # ListAllMyBuckets must be in wildcard

    # Statement 3: IAM Users
    stmt3 = statements_by_sid["VyraIAMUserPostureReadOnly"]
    assert stmt3["Resource"] == "arn:aws:iam::*:user/*"
    assert all(a.startswith("iam:") for a in stmt3["Action"])

    # Statement 4: IAM Roles
    stmt4 = statements_by_sid["VyraIAMRolePostureReadOnly"]
    assert stmt4["Resource"] == "arn:aws:iam::*:role/*"
    assert stmt4["Action"] == ["iam:ListAttachedRolePolicies"]

    # Statement 5: CloudTrail Trails
    stmt5 = statements_by_sid["VyraCloudTrailTrailPostureReadOnly"]
    assert stmt5["Resource"] == "arn:aws:cloudtrail:*:*:trail/*"
    assert all(a.startswith("cloudtrail:") for a in stmt5["Action"])

    # Statement 6: Security Hub
    stmt6 = statements_by_sid["VyraSecurityHubPostureReadOnly"]
    assert stmt6["Resource"] == "arn:aws:securityhub:*:*:hub/default"
    assert all(a.startswith("securityhub:") for a in stmt6["Action"])

    # Statement 7: GuardDuty Detectors
    stmt7 = statements_by_sid["VyraGuardDutyDetectorPostureReadOnly"]
    assert stmt7["Resource"] == "arn:aws:guardduty:*:*:detector/*"
    assert all(a.startswith("guardduty:") for a in stmt7["Action"])
    assert "guardduty:GetDetector" in stmt7["Action"]
    assert "guardduty:GetFindings" in stmt7["Action"]
    assert "guardduty:ListFindings" not in stmt7["Action"]
    assert "guardduty:ListDetectors" not in stmt7["Action"]

    # Statement 8: Access Analyzer
    stmt8 = statements_by_sid["VyraAccessAnalyzerPostureReadOnly"]
    assert stmt8["Resource"] == "arn:aws:access-analyzer:*:*:analyzer/*"
    assert stmt8["Action"] == ["access-analyzer:ListFindings"]

    # Statement 9: CloudWatch Logs
    stmt9 = statements_by_sid["VyraCloudWatchLogsRetentionReadOnly"]
    assert stmt9["Resource"] == "arn:aws:logs:*:*:log-group:*"
    assert stmt9["Action"] == ["logs:DescribeLogGroups"]


def test_documentation_exact_policy_synchronization():
    """
    Extracts the policy JSON directly from README.md and SECURITY.md
    and asserts action-by-action and statement-by-statement identity
    with render_policy_json(narrow_resources=True).
    """
    repo_root = Path(__file__).resolve().parent.parent.parent
    expected_policy = generate_least_privilege_policy(narrow_resources=True)

    for doc_name in ["README.md", "SECURITY.md"]:
        doc_path = repo_root / doc_name
        assert doc_path.exists(), f"Documentation file {doc_name} does not exist"
        content = doc_path.read_text(encoding="utf-8")

        # Match json code block in Least-Privilege IAM policy section
        match = re.search(r"```json\s*\n({[\s\S]*?})\n```", content)
        assert match is not None, f"Could not find JSON policy block in {doc_name}"

        doc_policy = json.loads(match.group(1))
        assert doc_policy == expected_policy, f"{doc_name} policy does not match canonical generated policy!"


def test_prohibited_actions_are_never_in_canonical_policy():
    """Validates that dangerous/mutating/secret-reading actions are strictly forbidden."""
    for prohibited in PROHIBITED_ACTIONS:
        assert prohibited not in CANONICAL_ACTIONS, f"Forbidden action {prohibited} found in CANONICAL_ACTIONS"


def test_guardduty_action_scoping_and_zero_redundancy():
    """
    Explicitly tests that GuardDuty action scoping matches AWS Service Authorization Reference
    and that no redundant action entries exist in generated policies:
    - guardduty:GetDetector is scoped to detector ARN (arn:aws:guardduty:*:*:detector/*)
    - guardduty:GetFindings is scoped to detector ARN (arn:aws:guardduty:*:*:detector/*)
    - guardduty:ListDetectors requires Resource: *
    - guardduty:ListFindings requires Resource: *
    - All actions across statements in both narrow and standard policies have zero duplicates.
    """
    narrowed = generate_least_privilege_policy(narrow_resources=True)
    stmt_map = {s["Sid"]: s for s in narrowed["Statement"]}

    inv = stmt_map["VyraInventoryAndGlobalReadOnly"]
    assert inv["Resource"] == "*"
    assert "guardduty:ListDetectors" in inv["Action"]
    assert "guardduty:ListFindings" in inv["Action"]
    assert "guardduty:GetDetector" not in inv["Action"]
    assert "guardduty:GetFindings" not in inv["Action"]

    gd_detector = stmt_map["VyraGuardDutyDetectorPostureReadOnly"]
    assert gd_detector["Resource"] == "arn:aws:guardduty:*:*:detector/*"
    assert "guardduty:GetDetector" in gd_detector["Action"]
    assert "guardduty:GetFindings" in gd_detector["Action"]
    assert "guardduty:ListDetectors" not in gd_detector["Action"]
    assert "guardduty:ListFindings" not in gd_detector["Action"]

    # Verify zero duplicates across statements in narrowed policy
    all_narrowed_actions = []
    for s in narrowed["Statement"]:
        # Verify no duplicate within statement
        assert len(s["Action"]) == len(set(s["Action"])), f"Duplicate action in statement {s['Sid']}"
        all_narrowed_actions.extend(s["Action"])
    assert len(all_narrowed_actions) == len(set(all_narrowed_actions)), "Redundant action entries found across statements in narrowed policy"
    assert set(all_narrowed_actions) == CANONICAL_ACTIONS

    # Verify zero duplicates in standard wide policy
    wide = generate_least_privilege_policy(narrow_resources=False)
    all_wide_actions = []
    for s in wide["Statement"]:
        assert len(s["Action"]) == len(set(s["Action"])), f"Duplicate action in wide statement {s['Sid']}"
        all_wide_actions.extend(s["Action"])
    assert len(all_wide_actions) == len(set(all_wide_actions)), "Redundant action entries found across statements in wide policy"
    assert set(all_wide_actions) == CANONICAL_ACTIONS
