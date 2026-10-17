from typing import Any


class ConfigurationDiffEngine:
    """Computes semantic configuration differences between baseline and observed states."""

    @staticmethod
    def compute_diff(baseline: dict[str, Any], current: dict[str, Any], resource_type: str) -> list[dict[str, Any]]:
        diffs: list[dict[str, Any]] = []

        if "s3" in resource_type.lower() or "bucket" in resource_type.lower():
            diffs.extend(ConfigurationDiffEngine._diff_s3(baseline, current))
        elif "iam" in resource_type.lower() or "user" in resource_type.lower():
            diffs.extend(ConfigurationDiffEngine._diff_iam(baseline, current))
        elif "cloudtrail" in resource_type.lower():
            diffs.extend(ConfigurationDiffEngine._diff_cloudtrail(baseline, current))
        else:
            diffs.extend(ConfigurationDiffEngine._generic_diff(baseline, current))

        return diffs

    @staticmethod
    def _diff_s3(b: dict[str, Any], c: dict[str, Any]) -> list[dict[str, Any]]:
        diffs = []

        # 1. Public Access Block
        b_pab = b.get("public_access_block") or {}
        c_pab = c.get("public_access_block") or {}
        for key in ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]:
            b_val = b_pab.get(key)
            c_val = c_pab.get(key)
            if b_val != c_val and (b_val is not None or c_val is not None):
                diffs.append({
                    "property": f"public_access_block.{key}",
                    "baseline_value": b_val,
                    "current_value": c_val,
                    "security_impact": "REGRESSION" if (b_val is True and c_val is False) else "IMPROVEMENT" if (b_val is False and c_val is True) else "MODIFIED",
                    "description": f"Public access block flag '{key}' changed from {b_val} to {c_val}."
                })

        # 2. Server-Side Encryption
        b_enc = b.get("encryption_status")
        c_enc = c.get("encryption_status")
        if b_enc != c_enc:
            diffs.append({
                "property": "encryption_status",
                "baseline_value": b_enc,
                "current_value": c_enc,
                "security_impact": "REGRESSION" if (b_enc == "CONFIGURED" and c_enc != "CONFIGURED") else "IMPROVEMENT",
                "description": f"Default Server-Side Encryption posture changed from '{b_enc}' to '{c_enc}'."
            })

        # 3. Versioning
        b_ver = b.get("versioning_status")
        c_ver = c.get("versioning_status")
        if b_ver != c_ver:
            diffs.append({
                "property": "versioning_status",
                "baseline_value": b_ver,
                "current_value": c_ver,
                "security_impact": "REGRESSION" if (b_ver == "Enabled" and c_ver != "Enabled") else "IMPROVEMENT",
                "description": f"Object versioning status changed from '{b_ver}' to '{c_ver}'."
            })

        return diffs

    @staticmethod
    def _diff_iam(b: dict[str, Any], c: dict[str, Any]) -> list[dict[str, Any]]:
        diffs = []

        # MFA Status
        b_mfa = b.get("mfa_active")
        c_mfa = c.get("mfa_active")
        if b_mfa != c_mfa:
            diffs.append({
                "property": "mfa_active",
                "baseline_value": b_mfa,
                "current_value": c_mfa,
                "security_impact": "REGRESSION" if (b_mfa is True and c_mfa is False) else "IMPROVEMENT",
                "description": f"MFA posture changed from {b_mfa} to {c_mfa}."
            })

        # Access Keys
        b_keys = {k.get("access_key_id"): k for k in b.get("access_keys", [])}
        c_keys = {k.get("access_key_id"): k for k in c.get("access_keys", [])}

        for kid, kdata in c_keys.items():
            if kid not in b_keys:
                diffs.append({
                    "property": "access_keys.created",
                    "baseline_value": None,
                    "current_value": kid,
                    "security_impact": "NEUTRAL",
                    "description": f"New access key '{kid}' created on user (Status: {kdata.get('status')})."
                })

        return diffs

    @staticmethod
    def _diff_cloudtrail(b: dict[str, Any], c: dict[str, Any]) -> list[dict[str, Any]]:
        diffs = []
        b_log = b.get("is_logging")
        c_log = c.get("is_logging")
        if b_log != c_log:
            diffs.append({
                "property": "is_logging",
                "baseline_value": b_log,
                "current_value": c_log,
                "security_impact": "REGRESSION" if (b_log is True and c_log is False) else "IMPROVEMENT",
                "description": f"CloudTrail audit logging state changed from {b_log} to {c_log}."
            })
        return diffs

    @staticmethod
    def _generic_diff(b: dict[str, Any], c: dict[str, Any]) -> list[dict[str, Any]]:
        diffs = []
        all_keys = set(b.keys()).union(set(c.keys()))
        for k in all_keys:
            if b.get(k) != c.get(k):
                diffs.append({
                    "property": k,
                    "baseline_value": b.get(k),
                    "current_value": c.get(k),
                    "security_impact": "MODIFIED",
                    "description": f"Property '{k}' modified from '{b.get(k)}' to '{c.get(k)}'."
                })
        return diffs
