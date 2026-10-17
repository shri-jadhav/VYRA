import logging
from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import ClientError

from backend.app.connectors.base import BaseConnector
from backend.app.core.security import sanitize_dict
from backend.app.investigation.domain import ConnectorCapability, ConnectorStatus

logger = logging.getLogger("vyra.connectors.access_analyzer")


class AccessAnalyzerConnector(BaseConnector):
    @property
    def service_id(self) -> str:
        return "accessanalyzer"

    @property
    def display_name(self) -> str:
        return "AWS IAM Access Analyzer"

    @property
    def category(self) -> str:
        return "Resource Sharing & Policy Analysis"

    @property
    def required_permissions(self) -> list[str]:
        return [
            "access-analyzer:ListAnalyzers",
            "access-analyzer:ListFindings"
        ]

    @property
    def supported_operations(self) -> list[str]:
        return [
            "ListAnalyzers",
            "ListFindings"
        ]

    @property
    def telemetry_type(self) -> str:
        return "FINDINGS_RETRIEVED"

    @property
    def cost_notes(self) -> str:
        return "Free tier service for account-level analyzers."

    @property
    def limitations(self) -> str:
        return "Analyzes resource policies; does not analyze real-time VPC traffic."

    def check_availability(self) -> ConnectorCapability:
        client = self.session.client("accessanalyzer", region_name=self.region_name)
        status = ConnectorStatus.AVAILABLE
        details = "IAM Access Analyzer accessible."
        missing_perms = []
        coverage = {
            "total_analyzers": 0,
            "active_analyzers_count": 0,
            "analyzers": []
        }

        try:
            res = client.list_analyzers()
            analyzers = res.get("analyzers", [])
            coverage["total_analyzers"] = len(analyzers)
            coverage["analyzers"] = [a.get("arn") for a in analyzers if a.get("arn")]
            active = [a for a in analyzers if a.get("status") == "ACTIVE"]
            coverage["active_analyzers_count"] = len(active)

            if not active:
                status = ConnectorStatus.DISABLED
                details = "0 active analyzers found in this region."
            else:
                details = f"{len(active)} active analyzer(s) found."
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            if "AccessDenied" in code:
                status = ConnectorStatus.PERMISSION_DENIED
                missing_perms.append("access-analyzer:ListAnalyzers")
                details = f"Permission denied: {code}"
            else:
                status = ConnectorStatus.ERROR
                details = f"{code}: {e}"
        except Exception as e:
            status = ConnectorStatus.ERROR
            details = str(e)

        return ConnectorCapability(
            service_id=self.service_id,
            display_name=self.display_name,
            category=self.category,
            status=status,
            status_details=details,
            required_permissions=self.required_permissions,
            missing_permissions=missing_perms,
            supported_operations=self.supported_operations,
            telemetry_type=self.telemetry_type,
            data_retention_window="Live",
            cost_notes=self.cost_notes,
            limitations=self.limitations,
            coverage=coverage,
            last_checked_at=datetime.now(UTC).isoformat()
        )


    def list_findings(self, analyzer_arn: str | None = None, limit: int = 25) -> dict[str, Any]:
        """Queries external access findings for an analyzer."""
        client = self.session.client("accessanalyzer", region_name=self.region_name)
        try:
            target_arn = analyzer_arn
            if not target_arn:
                res = client.list_analyzers()
                analyzers = res.get("analyzers", [])
                active = [a for a in analyzers if a.get("status") == "ACTIVE"]
                if not active:
                    return {"status": "DISABLED", "findings": [], "count": 0}
                target_arn = active[0].get("arn")

            findings_res = client.list_findings(analyzerArn=target_arn, maxResults=min(limit, 25))
            findings = findings_res.get("findings", [])
            return {"status": "SUCCESS", "findings": sanitize_dict(findings), "count": len(findings)}
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            return {"status": "PERMISSION_DENIED" if "AccessDenied" in code else "ERROR", "error": code, "findings": []}
        except Exception as e:
            return {"status": "ERROR", "error": str(e), "findings": []}
