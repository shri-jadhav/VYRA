import logging
from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import ClientError

from backend.app.connectors.base import BaseConnector
from backend.app.core.security import sanitize_dict
from backend.app.investigation.domain import ConnectorCapability, ConnectorStatus

logger = logging.getLogger("vyra.connectors.inspector")


class InspectorConnector(BaseConnector):
    @property
    def service_id(self) -> str:
        return "inspector"

    @property
    def display_name(self) -> str:
        return "Amazon Inspector Vulnerability Scanner"

    @property
    def category(self) -> str:
        return "Vulnerability Management"

    @property
    def required_permissions(self) -> list[str]:
        return [
            "inspector2:BatchGetAccountStatus",
            "inspector2:ListCoverage",
            "inspector2:ListFindings"
        ]

    @property
    def supported_operations(self) -> list[str]:
        return [
            "BatchGetAccountStatus",
            "ListCoverage",
            "ListFindings"
        ]

    @property
    def telemetry_type(self) -> str:
        return "FINDINGS_RETRIEVED"

    @property
    def cost_notes(self) -> str:
        return "Inspector is a paid vulnerability scanner billed per scanned resource. VYRA will not initiate scans."

    @property
    def limitations(self) -> str:
        return "Only captures CVEs for workloads where Amazon Inspector v2 was actively enabled."

    def check_availability(self) -> ConnectorCapability:
        client = self.session.client("inspector2", region_name=self.region_name)
        status = ConnectorStatus.AVAILABLE
        details = "Amazon Inspector v2 accessible."
        missing_perms = []
        coverage = {
            "covered_resources_count": 0,
        }

        try:
            cov_res = client.list_coverage(maxResults=10)
            covered = cov_res.get("coveredResources", [])
            coverage["covered_resources_count"] = len(covered)
            details = f"Inspector v2 operational with {len(covered)} covered resource(s)."
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            if "AccessDenied" in code:
                status = ConnectorStatus.PERMISSION_DENIED
                missing_perms.append("inspector2:ListCoverage")
                details = f"Permission denied: {code}"
            elif "ValidationException" in code or "DisabledException" in code or "not enabled" in str(e).lower():
                status = ConnectorStatus.DISABLED
                details = "Inspector is not enabled in this region."
            else:
                status = ConnectorStatus.DISABLED
                details = f"Inspector inactive: {code}"
        except Exception as e:
            status = ConnectorStatus.DISABLED
            details = f"Inspector inactive: {e}"

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
            data_retention_window="Active scan life",
            cost_notes=self.cost_notes,
            limitations=self.limitations,
            coverage=coverage,
            last_checked_at=datetime.now(UTC).isoformat()
        )

    def batch_get_account_status(self) -> dict[str, Any]:
        """Queries account-level onboarding status in Inspector v2."""
        client = self.session.client("inspector2", region_name=self.region_name)
        try:
            res = client.batch_get_account_status()
            accounts = res.get("accounts", [])
            return {"status": "SUCCESS", "accounts": sanitize_dict(accounts), "count": len(accounts)}
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            return {"status": "PERMISSION_DENIED" if "AccessDenied" in code else "ERROR", "error": code, "accounts": []}
        except Exception as e:
            return {"status": "ERROR", "error": str(e), "accounts": []}

    def list_findings(self, limit: int = 25) -> dict[str, Any]:
        """Lists active vulnerability findings from Inspector."""
        client = self.session.client("inspector2", region_name=self.region_name)
        try:
            res = client.list_findings(maxResults=min(limit, 25))
            findings = res.get("findings", [])
            return {"status": "SUCCESS", "findings": sanitize_dict(findings), "count": len(findings)}
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            return {"status": "PERMISSION_DENIED" if "AccessDenied" in code else "ERROR", "error": code, "findings": []}
        except Exception as e:
            return {"status": "ERROR", "error": str(e), "findings": []}
