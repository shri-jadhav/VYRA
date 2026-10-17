import json
import logging
from typing import Any

from pydantic import BaseModel

logger = logging.getLogger("vyra.plan_checker.rules")


class GateRuleResult(BaseModel):
    rule_id: str
    rule_name: str
    severity: str        # CRITICAL, HIGH, MEDIUM, LOW
    status: str          # VIOLATION, PASSED, UNKNOWN
    resource_type: str
    resource_address: str
    message: str
    remediation_guidance: str
    confidence: str      # HIGH, MEDIUM, UNKNOWN
    is_blocking: bool


class PlanCheckRule:
    def __init__(self, rule_id: str, name: str, severity: str, is_blocking: bool):
        self.rule_id = rule_id
        self.name = name
        self.severity = severity
        self.is_blocking = is_blocking

    def evaluate(self, resource_change: dict[str, Any]) -> GateRuleResult | None:
        raise NotImplementedError


class S3PublicAccessBlockRule(PlanCheckRule):
    def __init__(self):
        super().__init__(
            rule_id="VYRA-GATE-S3-001",
            name="S3 Public Access Block Removal or Disabling",
            severity="CRITICAL",
            is_blocking=True
        )

    def evaluate(self, rc: dict[str, Any]) -> GateRuleResult | None:
        res_type = rc.get("type", "")
        address = rc.get("address", "")
        if res_type != "aws_s3_bucket_public_access_block":
            return None

        change = rc.get("change", {})
        actions = change.get("actions", [])
        if "delete" in actions:
            return GateRuleResult(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                status="VIOLATION",
                resource_type=res_type,
                resource_address=address,
                message=f"Plan proposes DELETING public access block for '{address}', exposing bucket to public access.",
                remediation_guidance="Retain aws_s3_bucket_public_access_block configuration.",
                confidence="HIGH",
                is_blocking=self.is_blocking
            )

        after = change.get("after") or {}
        after_unknown = change.get("after_unknown") or {}

        # Check unknown
        flags = ["block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets"]
        any_unknown = any(after_unknown.get(f) is True for f in flags)
        if any_unknown:
            return GateRuleResult(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                status="UNKNOWN",
                resource_type=res_type,
                resource_address=address,
                message=f"Public access block settings for '{address}' contain computed values known only after apply.",
                remediation_guidance="Specify explicit boolean values (true) for all 4 public access flags in Terraform.",
                confidence="UNKNOWN",
                is_blocking=False
            )

        disabled_flags = [f for f in flags if after.get(f) is False]
        if disabled_flags:
            return GateRuleResult(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                status="VIOLATION",
                resource_type=res_type,
                resource_address=address,
                message=f"Public access block for '{address}' has disabled protective flags: {', '.join(disabled_flags)}.",
                remediation_guidance="Set all 4 flags to true: block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets.",
                confidence="HIGH",
                is_blocking=self.is_blocking
            )

        return GateRuleResult(
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            status="PASSED",
            resource_type=res_type,
            resource_address=address,
            message=f"All 4 public access block settings for '{address}' are set to true.",
            remediation_guidance="No action required.",
            confidence="HIGH",
            is_blocking=False
        )


class S3BucketEncryptionRule(PlanCheckRule):
    def __init__(self):
        super().__init__(
            rule_id="VYRA-GATE-S3-002",
            name="S3 Bucket Default Encryption Configuration",
            severity="HIGH",
            is_blocking=True
        )

    def evaluate(self, rc: dict[str, Any]) -> GateRuleResult | None:
        res_type = rc.get("type", "")
        address = rc.get("address", "")
        if res_type != "aws_s3_bucket_server_side_encryption_configuration":
            return None

        change = rc.get("change", {})
        actions = change.get("actions", [])
        if "delete" in actions:
            return GateRuleResult(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                status="VIOLATION",
                resource_type=res_type,
                resource_address=address,
                message=f"Plan proposes DELETING server-side encryption configuration for '{address}'.",
                remediation_guidance="Maintain default encryption with AES256 or aws:kms.",
                confidence="HIGH",
                is_blocking=self.is_blocking
            )

        after = change.get("after") or {}
        rules = after.get("rule", [])
        if not rules:
            return GateRuleResult(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                status="VIOLATION",
                resource_type=res_type,
                resource_address=address,
                message=f"Encryption configuration for '{address}' does not specify any encryption rules.",
                remediation_guidance="Add an apply_server_side_encryption_by_default block.",
                confidence="HIGH",
                is_blocking=self.is_blocking
            )

        return GateRuleResult(
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            status="PASSED",
            resource_type=res_type,
            resource_address=address,
            message=f"Server-side encryption is properly configured for '{address}'.",
            remediation_guidance="No action required.",
            confidence="HIGH",
            is_blocking=False
        )


class IAMWildcardPolicyRule(PlanCheckRule):
    def __init__(self):
        super().__init__(
            rule_id="VYRA-GATE-IAM-001",
            name="Dangerous Wildcard IAM Action/Resource Permissions",
            severity="CRITICAL",
            is_blocking=True
        )

    def evaluate(self, rc: dict[str, Any]) -> GateRuleResult | None:
        res_type = rc.get("type", "")
        address = rc.get("address", "")
        if res_type not in ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"]:
            return None

        change = rc.get("change", {})
        after = change.get("after") or {}
        policy_str = after.get("policy")
        if not policy_str or not isinstance(policy_str, str):
            return None

        try:
            policy_doc = json.loads(policy_str)
            statements = policy_doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]

            for stmt in statements:
                if stmt.get("Effect") == "Allow":
                    act = stmt.get("Action", [])
                    res = stmt.get("Resource", [])
                    if isinstance(act, str):
                        act = [act]
                    if isinstance(res, str):
                        res = [res]

                    has_wild_act = "*" in act or "*:*" in act
                    has_wild_res = "*" in res
                    if has_wild_act and has_wild_res:
                        return GateRuleResult(
                            rule_id=self.rule_id,
                            rule_name=self.name,
                            severity=self.severity,
                            status="VIOLATION",
                            resource_type=res_type,
                            resource_address=address,
                            message=f"IAM Policy '{address}' grants administrative full wildcard Action: '*' on Resource: '*'.",
                            remediation_guidance="Scope actions down to the least-privilege specific service APIs and resource ARNs.",
                            confidence="HIGH",
                            is_blocking=self.is_blocking
                        )
        except (json.JSONDecodeError, TypeError, KeyError) as parse_err:
            logger.debug(
                "Failed to parse IAM policy document in %s: %s", address, parse_err
            )

        return GateRuleResult(
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            status="PASSED",
            resource_type=res_type,
            resource_address=address,
            message=f"IAM Policy '{address}' does not contain full wildcard admin grants.",
            remediation_guidance="No action required.",
            confidence="HIGH",
            is_blocking=False
        )


class SecurityGroupOpenPortRule(PlanCheckRule):
    def __init__(self):
        super().__init__(
            rule_id="VYRA-GATE-SEC-001",
            name="Security Group Open Ingress to Sensitive Ports",
            severity="HIGH",
            is_blocking=True
        )

    def evaluate(self, rc: dict[str, Any]) -> GateRuleResult | None:
        res_type = rc.get("type", "")
        address = rc.get("address", "")
        if res_type not in ["aws_security_group", "aws_security_group_rule"]:
            return None

        change = rc.get("change", {})
        after = change.get("after") or {}
        ingress_rules = []
        if res_type == "aws_security_group":
            ingress_rules = after.get("ingress", [])
        else:
            if after.get("type") == "ingress":
                ingress_rules = [after]

        sensitive_ports = [22, 3389, 5432, 3306, 27017, 6379]

        for rule in ingress_rules:
            cidr_blocks = rule.get("cidr_blocks", [])
            from_port = rule.get("from_port", 0)
            to_port = rule.get("to_port", 0)

            if "0.0.0.0/0" in cidr_blocks:
                for p in sensitive_ports:
                    if from_port <= p <= to_port:
                        return GateRuleResult(
                            rule_id=self.rule_id,
                            rule_name=self.name,
                            severity=self.severity,
                            status="VIOLATION",
                            resource_type=res_type,
                            resource_address=address,
                            message=f"Security group '{address}' exposes sensitive management port {p} to public internet (0.0.0.0/0).",
                            remediation_guidance="Restrict ingress CIDR to internal corporate VPN or authorized bastion hosts.",
                            confidence="HIGH",
                            is_blocking=self.is_blocking
                        )

        return None


ALL_PLAN_RULES = [
    S3PublicAccessBlockRule(),
    S3BucketEncryptionRule(),
    IAMWildcardPolicyRule(),
    SecurityGroupOpenPortRule(),
]
