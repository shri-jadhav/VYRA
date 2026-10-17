from datetime import UTC, datetime
from typing import Any

from backend.app.engine.controls_registry import CONTROLS_REGISTRY
from backend.app.models.models import Asset, ControlEvaluation


class ControlEvaluator:
    """
    Evaluates evidence against versioned security controls.
    Enforces status taxonomy: PASS, FAIL, UNKNOWN, NOT_CONFIGURED, ERROR, EXEMPT.
    CRITICAL RULE: Missing permissions or missing evidence is NEVER treated as a pass.
    """

    def __init__(self, run_id: str, evidence: dict[str, Any]):
        self.run_id = run_id
        self.evidence = evidence
        self.timestamp = datetime.now(UTC)

    def evaluate_all(self) -> list[ControlEvaluation]:
        evaluations: list[ControlEvaluation] = []

        # 1. Evaluate S3 Controls
        evaluations.extend(self._evaluate_s3())

        # 2. Evaluate IAM Controls
        evaluations.extend(self._evaluate_iam())

        # 3. Evaluate CloudTrail Controls
        evaluations.extend(self._evaluate_cloudtrail())

        # 4. Evaluate Security Services Controls
        evaluations.extend(self._evaluate_security_services())

        # 5. Evaluate Integration & Governance Control
        evaluations.append(self._evaluate_integration_health())

        return evaluations

    def extract_assets(self) -> list[Asset]:
        """Extracts normalized Asset entities from the gathered evidence."""
        assets: list[Asset] = []
        account_id = self.evidence.get("sts", {}).get("account_id") or "unknown"
        region = self.evidence.get("region") or "ap-south-1"

        # S3 Buckets
        for b in self.evidence.get("s3", {}).get("buckets", []):
            name = b.get("name")
            arn = b.get("arn") or f"arn:aws:s3:::{name}"
            assets.append(Asset(
                id=arn,
                run_id=self.run_id,
                account_id=account_id,
                region=b.get("region") or region,
                service="s3",
                asset_type="s3:bucket",
                name=name,
                arn=arn,
                configuration_data=b
            ))

        # IAM Users
        for u in self.evidence.get("iam", {}).get("users", []):
            arn = u.get("arn") or f"arn:aws:iam::{account_id}:user/{u.get('user_name')}"
            assets.append(Asset(
                id=arn,
                run_id=self.run_id,
                account_id=account_id,
                region="global",
                service="iam",
                asset_type="iam:user",
                name=u.get("user_name"),
                arn=arn,
                configuration_data=u
            ))

        # IAM Roles
        for r in self.evidence.get("iam", {}).get("roles", []):
            arn = r.get("arn")
            if arn:
                assets.append(Asset(
                    id=arn,
                    run_id=self.run_id,
                    account_id=account_id,
                    region="global",
                    service="iam",
                    asset_type="iam:role",
                    name=r.get("role_name"),
                    arn=arn,
                    configuration_data=r
                ))

        # CloudTrail Trails
        for t in self.evidence.get("cloudtrail", {}).get("trails", []):
            arn = t.get("arn") or f"arn:aws:cloudtrail:{region}:{account_id}:trail/{t.get('name')}"
            assets.append(Asset(
                id=arn,
                run_id=self.run_id,
                account_id=account_id,
                region=t.get("home_region") or region,
                service="cloudtrail",
                asset_type="cloudtrail:trail",
                name=t.get("name"),
                arn=arn,
                configuration_data=t
            ))

        return assets

    def _evaluate_s3(self) -> list[ControlEvaluation]:
        evals: list[ControlEvaluation] = []
        s3_data = self.evidence.get("s3", {})
        buckets = s3_data.get("buckets", [])
        s3_status = s3_data.get("status")

        if s3_status == "DENIED":
            # Report permission error control evaluation
            for cid in ["VYRA-S3-001", "VYRA-S3-002", "VYRA-S3-003", "VYRA-S3-004"]:
                ctrl = CONTROLS_REGISTRY[cid]
                evals.append(ControlEvaluation(
                    run_id=self.run_id,
                    control_id=ctrl.control_id,
                    title=ctrl.title,
                    category=ctrl.category,
                    severity=ctrl.severity,
                    status="ERROR",
                    resource_id="s3:all-buckets",
                    resource_arn="arn:aws:s3:::*",
                    rationale=f"S3 access denied: {s3_data.get('error', 'ListAllMyBuckets denied')}",
                    evidence_source="s3.list_buckets",
                    remediation_guidance=ctrl.remediation_guidance,
                    limitations=ctrl.limitations,
                    evidence_data={"error": s3_data.get("error")}
                ))
            return evals

        if not buckets and s3_status == "SUCCESS":
            # No buckets in account
            for cid in ["VYRA-S3-001", "VYRA-S3-002", "VYRA-S3-003", "VYRA-S3-004"]:
                ctrl = CONTROLS_REGISTRY[cid]
                evals.append(ControlEvaluation(
                    run_id=self.run_id,
                    control_id=ctrl.control_id,
                    title=ctrl.title,
                    category=ctrl.category,
                    severity=ctrl.severity,
                    status="NOT_CONFIGURED",
                    resource_id="s3:inventory",
                    resource_arn="arn:aws:s3:::*",
                    rationale="No S3 buckets discovered in this AWS account.",
                    evidence_source="s3.list_buckets",
                    remediation_guidance=ctrl.remediation_guidance,
                    limitations=ctrl.limitations,
                    evidence_data={}
                ))
            return evals

        for b in buckets:
            b_name = b.get("name")
            b_arn = b.get("arn")

            # 1. VYRA-S3-001 (Public Access Block)
            c1 = CONTROLS_REGISTRY["VYRA-S3-001"]
            pab_status = b.get("public_access_block_status")
            if pab_status == "FULL_BLOCK":
                st1, rat1 = "PASS", f"All 4 S3 Public Access Block settings are enabled on bucket '{b_name}'."
            elif pab_status == "PARTIAL_OR_UNBLOCKED":
                st1, rat1 = "FAIL", f"Bucket '{b_name}' has one or more S3 Public Access Block flags disabled, exposing potential public vectors."
            elif pab_status == "NOT_CONFIGURED":
                st1, rat1 = "NOT_CONFIGURED", f"Bucket '{b_name}' does not have any Public Access Block configuration attached."
            elif pab_status == "PERMISSION_DENIED":
                st1, rat1 = "ERROR", f"Permission denied when checking Public Access Block on '{b_name}'."
            else:
                st1, rat1 = "ERROR", f"Error checking Public Access Block on '{b_name}': {b.get('errors', {}).get('get_public_access_block')}"

            evals.append(ControlEvaluation(
                run_id=self.run_id,
                control_id=c1.control_id,
                title=c1.title,
                category=c1.category,
                severity=c1.severity,
                status=st1,
                resource_id=b_name,
                resource_arn=b_arn,
                rationale=rat1,
                evidence_source="s3.get_public_access_block",
                remediation_guidance=c1.remediation_guidance,
                limitations=c1.limitations,
                evidence_data={"public_access_block": b.get("public_access_block")}
            ))

            # 2. VYRA-S3-002 (Default Encryption)
            c2 = CONTROLS_REGISTRY["VYRA-S3-002"]
            enc_status = b.get("encryption_status")
            if enc_status == "CONFIGURED":
                st2, rat2 = "PASS", f"Server-Side Encryption is enabled by default on bucket '{b_name}'."
            elif enc_status == "NOT_CONFIGURED":
                st2, rat2 = "FAIL", f"Default Server-Side Encryption is not configured on bucket '{b_name}'."
            elif enc_status == "PERMISSION_DENIED":
                st2, rat2 = "ERROR", f"Permission denied when checking encryption configuration on '{b_name}'."
            else:
                st2, rat2 = "ERROR", f"Error checking encryption configuration on '{b_name}'."

            evals.append(ControlEvaluation(
                run_id=self.run_id,
                control_id=c2.control_id,
                title=c2.title,
                category=c2.category,
                severity=c2.severity,
                status=st2,
                resource_id=b_name,
                resource_arn=b_arn,
                rationale=rat2,
                evidence_source="s3.get_bucket_encryption",
                remediation_guidance=c2.remediation_guidance,
                limitations=c2.limitations,
                evidence_data={"encryption_rules": b.get("encryption")}
            ))

            # 3. VYRA-S3-003 (Versioning)
            c3 = CONTROLS_REGISTRY["VYRA-S3-003"]
            ver_status = b.get("versioning_status")
            if ver_status == "Enabled":
                st3, rat3 = "PASS", f"Versioning is active on bucket '{b_name}'."
            elif ver_status in ["Suspended", "NOT_CONFIGURED"]:
                st3, rat3 = "FAIL", f"Versioning is not enabled on bucket '{b_name}' (Status: {ver_status})."
            elif ver_status == "PERMISSION_DENIED":
                st3, rat3 = "ERROR", f"Permission denied when checking versioning on '{b_name}'."
            else:
                st3, rat3 = "ERROR", f"Error querying bucket versioning on '{b_name}'."

            evals.append(ControlEvaluation(
                run_id=self.run_id,
                control_id=c3.control_id,
                title=c3.title,
                category=c3.category,
                severity=c3.severity,
                status=st3,
                resource_id=b_name,
                resource_arn=b_arn,
                rationale=rat3,
                evidence_source="s3.get_bucket_versioning",
                remediation_guidance=c3.remediation_guidance,
                limitations=c3.limitations,
                evidence_data={"versioning": b.get("versioning")}
            ))

            # 4. VYRA-S3-004 (Bucket Policy Public Status)
            c4 = CONTROLS_REGISTRY["VYRA-S3-004"]
            pol_status = b.get("policy_status", {})
            if pol_status.get("IsPublic") is True:
                st4, rat4 = "FAIL", f"Bucket policy status marks '{b_name}' as PUBLIC to the internet."
            elif pol_status.get("IsPublic") is False or pol_status.get("Notice") == "NoBucketPolicy":
                st4, rat4 = "PASS", f"Bucket '{b_name}' does not allow unrestricted public access via policy."
            elif pol_status.get("Status") == "PERMISSION_DENIED":
                st4, rat4 = "ERROR", f"Permission denied inspecting bucket policy on '{b_name}'."
            else:
                st4, rat4 = "UNKNOWN", f"Could not determine policy status for bucket '{b_name}'."

            evals.append(ControlEvaluation(
                run_id=self.run_id,
                control_id=c4.control_id,
                title=c4.title,
                category=c4.category,
                severity=c4.severity,
                status=st4,
                resource_id=b_name,
                resource_arn=b_arn,
                rationale=rat4,
                evidence_source="s3.get_bucket_policy_status",
                remediation_guidance=c4.remediation_guidance,
                limitations=c4.limitations,
                evidence_data={"policy_status": pol_status}
            ))

        return evals

    def _evaluate_iam(self) -> list[ControlEvaluation]:
        evals: list[ControlEvaluation] = []
        iam_data = self.evidence.get("iam", {})
        account_summary = iam_data.get("account_summary", {})
        users = iam_data.get("users", [])
        account_id = self.evidence.get("sts", {}).get("account_id") or "unknown"

        # 1. VYRA-IAM-001 (Root MFA)
        c1 = CONTROLS_REGISTRY["VYRA-IAM-001"]
        if "AccountMFAEnabled" in account_summary:
            mfa_enabled = account_summary["AccountMFAEnabled"] == 1
            st1 = "PASS" if mfa_enabled else "FAIL"
            rat1 = "Root account has hardware or virtual MFA enabled." if mfa_enabled else "Root account does NOT have MFA protection enabled (AccountMFAEnabled=0)."
        elif iam_data.get("permissions_summary", {}).get("GetAccountSummary") == "DENIED":
            st1, rat1 = "ERROR", "Permission denied for iam:GetAccountSummary. Root MFA status cannot be verified."
        else:
            st1, rat1 = "UNKNOWN", "Account summary data unavailable to assess Root MFA."

        evals.append(ControlEvaluation(
            run_id=self.run_id,
            control_id=c1.control_id,
            title=c1.title,
            category=c1.category,
            severity=c1.severity,
            status=st1,
            resource_id="root-account",
            resource_arn=f"arn:aws:iam::{account_id}:root",
            rationale=rat1,
            evidence_source="iam.get_account_summary",
            remediation_guidance=c1.remediation_guidance,
            limitations=c1.limitations,
            evidence_data={"AccountMFAEnabled": account_summary.get("AccountMFAEnabled")}
        ))

        # 2. VYRA-IAM-002 (Root Access Keys)
        c2 = CONTROLS_REGISTRY["VYRA-IAM-002"]
        if "AccountAccessKeysPresent" in account_summary:
            keys_present = account_summary["AccountAccessKeysPresent"] > 0
            st2 = "FAIL" if keys_present else "PASS"
            rat2 = "Active programmatic access keys detected on the root account." if keys_present else "No programmatic access keys exist on the root account (AccountAccessKeysPresent=0)."
        elif iam_data.get("permissions_summary", {}).get("GetAccountSummary") == "DENIED":
            st2, rat2 = "ERROR", "Permission denied for iam:GetAccountSummary."
        else:
            st2, rat2 = "UNKNOWN", "Root access key posture could not be verified."

        evals.append(ControlEvaluation(
            run_id=self.run_id,
            control_id=c2.control_id,
            title=c2.title,
            category=c2.category,
            severity=c2.severity,
            status=st2,
            resource_id="root-account-keys",
            resource_arn=f"arn:aws:iam::{account_id}:root",
            rationale=rat2,
            evidence_source="iam.get_account_summary",
            remediation_guidance=c2.remediation_guidance,
            limitations=c2.limitations,
            evidence_data={"AccountAccessKeysPresent": account_summary.get("AccountAccessKeysPresent")}
        ))

        # 3. User-Level Controls (VYRA-IAM-003 MFA & VYRA-IAM-004 Key Age)
        c3 = CONTROLS_REGISTRY["VYRA-IAM-003"]
        c4 = CONTROLS_REGISTRY["VYRA-IAM-004"]

        if not users:
            # Report placeholder if no users or list_users failed
            list_users_perm = iam_data.get("permissions_summary", {}).get("ListUsers")
            st_user = "ERROR" if list_users_perm == "DENIED" else "NOT_CONFIGURED"
            rat_user = "Permission denied for iam:ListUsers." if list_users_perm == "DENIED" else "No IAM users found."

            evals.append(ControlEvaluation(
                run_id=self.run_id,
                control_id=c3.control_id,
                title=c3.title,
                category=c3.category,
                severity=c3.severity,
                status=st_user,
                resource_id="iam:users-mfa",
                resource_arn=f"arn:aws:iam::{account_id}:user/*",
                rationale=rat_user,
                evidence_source="iam.list_users",
                remediation_guidance=c3.remediation_guidance,
                limitations=c3.limitations,
                evidence_data={}
            ))
        else:
            for u in users:
                user_name = u.get("user_name")
                user_arn = u.get("arn")
                mfa_active = u.get("mfa_active", False)
                access_keys = u.get("access_keys", [])

                # VYRA-IAM-003 User MFA
                if u.get("errors", {}).get("list_mfa_devices"):
                    st_u_mfa = "ERROR"
                    rat_u_mfa = f"Permission denied checking MFA devices for user '{user_name}'."
                elif mfa_active:
                    st_u_mfa = "PASS"
                    rat_u_mfa = f"User '{user_name}' has active MFA devices configured."
                else:
                    st_u_mfa = "FAIL"
                    rat_u_mfa = f"User '{user_name}' does not have MFA configured."

                evals.append(ControlEvaluation(
                    run_id=self.run_id,
                    control_id=c3.control_id,
                    title=c3.title,
                    category=c3.category,
                    severity=c3.severity,
                    status=st_u_mfa,
                    resource_id=user_name,
                    resource_arn=user_arn,
                    rationale=rat_u_mfa,
                    evidence_source="iam.list_mfa_devices",
                    remediation_guidance=c3.remediation_guidance,
                    limitations=c3.limitations,
                    evidence_data={"mfa_devices": u.get("mfa_devices")}
                ))

                # VYRA-IAM-004 Key Age
                if not access_keys:
                    st_key = "NOT_CONFIGURED"
                    rat_key = f"User '{user_name}' has no active programmatic access keys."
                else:
                    oldest_key = max(access_keys, key=lambda k: k.get("age_days", 0))
                    age = oldest_key.get("age_days", 0)
                    if age > 90:
                        st_key = "FAIL"
                        rat_key = f"User '{user_name}' has active access key {oldest_key.get('access_key_id')} aged {age} days (>90 days rotation threshold)."
                    else:
                        st_key = "PASS"
                        rat_key = f"User '{user_name}' access keys are within safe 90-day rotation age ({age} days old)."

                evals.append(ControlEvaluation(
                    run_id=self.run_id,
                    control_id=c4.control_id,
                    title=c4.title,
                    category=c4.category,
                    severity=c4.severity,
                    status=st_key,
                    resource_id=user_name,
                    resource_arn=user_arn,
                    rationale=rat_key,
                    evidence_source="iam.list_access_keys",
                    remediation_guidance=c4.remediation_guidance,
                    limitations=c4.limitations,
                    evidence_data={"access_keys": access_keys}
                ))

        return evals

    def _evaluate_cloudtrail(self) -> list[ControlEvaluation]:
        c = CONTROLS_REGISTRY["VYRA-CT-001"]
        ct_data = self.evidence.get("cloudtrail", {})
        trails = ct_data.get("trails", [])
        status = ct_data.get("status")
        account_id = self.evidence.get("sts", {}).get("account_id") or "unknown"

        if status == "DENIED":
            return [ControlEvaluation(
                run_id=self.run_id,
                control_id=c.control_id,
                title=c.title,
                category=c.category,
                severity=c.severity,
                status="ERROR",
                resource_id="cloudtrail:all",
                resource_arn=f"arn:aws:cloudtrail:*:{account_id}:trail/*",
                rationale=f"Permission denied for cloudtrail:DescribeTrails: {ct_data.get('error')}",
                evidence_source="cloudtrail.describe_trails",
                remediation_guidance=c.remediation_guidance,
                limitations=c.limitations,
                evidence_data={}
            )]

        if not trails:
            return [ControlEvaluation(
                run_id=self.run_id,
                control_id=c.control_id,
                title=c.title,
                category=c.category,
                severity=c.severity,
                status="NOT_CONFIGURED",
                resource_id="cloudtrail:none",
                resource_arn=f"arn:aws:cloudtrail:*:{account_id}:trail/*",
                rationale="No CloudTrail trails exist in this AWS account. Account activity is unmonitored.",
                evidence_source="cloudtrail.describe_trails",
                remediation_guidance=c.remediation_guidance,
                limitations=c.limitations,
                evidence_data={}
            )]

        active_multi_region = [t for t in trails if t.get("is_multi_region") and t.get("is_logging")]
        if active_multi_region:
            trail_names = ", ".join(t.get("name") for t in active_multi_region)
            st, rat = "PASS", f"Active multi-region logging trail(s) detected: {trail_names}."
        else:
            st, rat = "FAIL", "CloudTrail trails exist, but none are both multi-region and actively logging."

        return [ControlEvaluation(
            run_id=self.run_id,
            control_id=c.control_id,
            title=c.title,
            category=c.category,
            severity=c.severity,
            status=st,
            resource_id="cloudtrail:trails",
            resource_arn=f"arn:aws:cloudtrail:*:{account_id}:trail/*",
            rationale=rat,
            evidence_source="cloudtrail.get_trail_status",
            remediation_guidance=c.remediation_guidance,
            limitations=c.limitations,
            evidence_data={"trails": trails}
        )]

    def _evaluate_security_services(self) -> list[ControlEvaluation]:
        evals: list[ControlEvaluation] = []
        sec_services = self.evidence.get("security_services", {}).get("services", {})
        account_id = self.evidence.get("sts", {}).get("account_id") or "unknown"
        region = self.evidence.get("region") or "ap-south-1"

        # 1. Access Analyzer (VYRA-SEC-001)
        c1 = CONTROLS_REGISTRY["VYRA-SEC-001"]
        aa_info = sec_services.get("access_analyzer", {})
        aa_status = aa_info.get("status")
        if aa_status == "ENABLED":
            st1, rat1 = "PASS", f"IAM Access Analyzer is active ({aa_info.get('details')})."
        elif aa_status == "DISABLED":
            st1, rat1 = "NOT_CONFIGURED", "IAM Access Analyzer is not enabled in this region."
        elif aa_status == "PERMISSION_DENIED":
            st1, rat1 = "ERROR", f"Permission denied for access-analyzer:ListAnalyzers: {aa_info.get('details')}"
        else:
            st1, rat1 = "ERROR", f"Access Analyzer probe error: {aa_info.get('details')}"

        evals.append(ControlEvaluation(
            run_id=self.run_id,
            control_id=c1.control_id,
            title=c1.title,
            category=c1.category,
            severity=c1.severity,
            status=st1,
            resource_id="access-analyzer",
            resource_arn=f"arn:aws:access-analyzer:{region}:{account_id}:analyzer/*",
            rationale=rat1,
            evidence_source="accessanalyzer.list_analyzers",
            remediation_guidance=c1.remediation_guidance,
            limitations=c1.limitations,
            evidence_data=aa_info
        ))

        # 2. GuardDuty (VYRA-SEC-002)
        c2 = CONTROLS_REGISTRY["VYRA-SEC-002"]
        gd_info = sec_services.get("guardduty", {})
        gd_status = gd_info.get("status")
        if gd_status == "ENABLED":
            st2, rat2 = "PASS", f"Amazon GuardDuty is active ({gd_info.get('details')})."
        elif gd_status in ["DISABLED", "SUBSCRIPTION_REQUIRED"]:
            st2, rat2 = "NOT_CONFIGURED", f"Amazon GuardDuty is not enabled ({gd_info.get('details')})."
        elif gd_status == "PERMISSION_DENIED":
            st2, rat2 = "ERROR", f"Permission denied probing GuardDuty: {gd_info.get('details')}"
        else:
            st2, rat2 = "ERROR", f"GuardDuty probe error: {gd_info.get('details')}"

        evals.append(ControlEvaluation(
            run_id=self.run_id,
            control_id=c2.control_id,
            title=c2.title,
            category=c2.category,
            severity=c2.severity,
            status=st2,
            resource_id="guardduty",
            resource_arn=f"arn:aws:guardduty:{region}:{account_id}:detector/*",
            rationale=rat2,
            evidence_source="guardduty.list_detectors",
            remediation_guidance=c2.remediation_guidance,
            limitations=c2.limitations,
            evidence_data=gd_info
        ))

        # 3. Security Hub (VYRA-SEC-003)
        c3 = CONTROLS_REGISTRY["VYRA-SEC-003"]
        sh_info = sec_services.get("security_hub", {})
        sh_status = sh_info.get("status")
        if sh_status == "ENABLED":
            st3, rat3 = "PASS", f"AWS Security Hub is active ({sh_info.get('details')})."
        elif sh_status in ["DISABLED", "SUBSCRIPTION_REQUIRED"]:
            st3, rat3 = "NOT_CONFIGURED", f"AWS Security Hub is not enabled ({sh_info.get('details')})."
        elif sh_status == "PERMISSION_DENIED":
            st3, rat3 = "ERROR", f"Permission denied probing Security Hub: {sh_info.get('details')}"
        else:
            st3, rat3 = "ERROR", f"Security Hub probe error: {sh_info.get('details')}"

        evals.append(ControlEvaluation(
            run_id=self.run_id,
            control_id=c3.control_id,
            title=c3.title,
            category=c3.category,
            severity=c3.severity,
            status=st3,
            resource_id="securityhub",
            resource_arn=f"arn:aws:securityhub:{region}:{account_id}:hub/*",
            rationale=rat3,
            evidence_source="securityhub.describe_hub",
            remediation_guidance=c3.remediation_guidance,
            limitations=c3.limitations,
            evidence_data=sh_info
        ))

        return evals

    def _evaluate_integration_health(self) -> ControlEvaluation:
        c = CONTROLS_REGISTRY["VYRA-INT-001"]
        denied_collectors = []

        # Check collector statuses
        for s_key in ["sts", "s3", "iam", "cloudtrail"]:
            s_data = self.evidence.get(s_key, {})
            if s_data.get("status") == "DENIED":
                denied_collectors.append(s_key)

        if denied_collectors:
            st = "FAIL"
            rat = f"One or more core collectors encountered permission denial: {', '.join(denied_collectors)}."
        else:
            st = "PASS"
            rat = "All core collectors authenticated and gathered telemetry without IAM permission denial."

        return ControlEvaluation(
            run_id=self.run_id,
            control_id=c.control_id,
            title=c.title,
            category=c.category,
            severity=c.severity,
            status=st,
            resource_id="vyra-collector-health",
            resource_arn="vyra://platform/collectors/health",
            rationale=rat,
            evidence_source="collector.provenance",
            remediation_guidance=c.remediation_guidance,
            limitations=c.limitations,
            evidence_data=self.evidence.get("provenance", {})
        )
