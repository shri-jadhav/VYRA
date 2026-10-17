from typing import Any

from backend.app.plan_checker.rules import GateRuleResult


class SarifExporter:
    """Converts VYRA pre-deployment plan findings to OASIS SARIF v2.1.0 format."""

    @staticmethod
    def generate_sarif(results: list[GateRuleResult], target_file: str = "terraform.plan.json") -> dict[str, Any]:
        rules_map: dict[str, dict[str, Any]] = {}
        sarif_results: list[dict[str, Any]] = []

        for r in results:
            if r.status != "VIOLATION":
                continue

            # Level mapping
            level = "error" if r.severity in ["CRITICAL", "HIGH"] else "warning"

            if r.rule_id not in rules_map:
                rules_map[r.rule_id] = {
                    "id": r.rule_id,
                    "name": r.rule_name,
                    "shortDescription": {"text": r.rule_name},
                    "defaultConfiguration": {"level": level},
                    "properties": {
                        "severity": r.severity,
                        "isBlocking": r.is_blocking
                    }
                }

            sarif_results.append({
                "ruleId": r.rule_id,
                "level": level,
                "message": {"text": r.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": target_file,
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": {
                                "startLine": 1,
                                "message": {"text": f"Terraform resource address: {r.resource_address}"}
                            }
                        }
                    }
                ],
                "properties": {
                    "resourceAddress": r.resource_address,
                    "remediationGuidance": r.remediation_guidance,
                    "confidence": r.confidence
                }
            })

        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "VYRA Pre-Deployment Security Gate",
                            "semanticVersion": "1.0.0",
                            "informationUri": "https://github.com/vyra-security/platform",
                            "rules": list(rules_map.values())
                        }
                    },
                    "results": sarif_results
                }
            ]
        }
