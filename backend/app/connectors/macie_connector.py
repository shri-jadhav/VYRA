import logging
from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import ClientError

from backend.app.connectors.base import BaseConnector
from backend.app.core.security import sanitize_dict
from backend.app.investigation.domain import ConnectorCapability, ConnectorStatus

logger = logging.getLogger("vyra.connectors.macie")


class MacieConnector(BaseConnector):
    @property
    def service_id(self) -> str:
        return "macie"

    @property
    def display_name(self) -> str:
        return "Amazon Macie Sensitive Data Security"

    @property
    def category(self) -> str:
        return "Data Security"

    @property
    def required_permissions(self) -> list[str]:
        return [
            "macie2:GetMacieSession",
            "macie2:DescribeBuckets",
            "macie2:ListFindings"
        ]

    @property
    def supported_operations(self) -> list[str]:
        return [
            "GetMacieSession",
            "DescribeBuckets",
            "ListFindings"
        ]

    @property
    def telemetry_type(self) -> str:
        return "FINDINGS_RETRIEVED"

    @property
    def cost_notes(self) -> str:
        return "Macie is a paid data classification service. VYRA will not launch discovery jobs or download contents."

    @property
    def limitations(self) -> str:
        return "Does not read S3 object contents or execute sensitive data discovery jobs."

    def check_availability(self) -> ConnectorCapability:
        client = self.session.client("macie2", region_name=self.region_name)
        status = ConnectorStatus.AVAILABLE
        details = "Amazon Macie accessible."
        missing_perms = []
        coverage = {
            "monitored_buckets_count": 0,
        }

        try:
            b_res = client.describe_buckets(maxResults=10)
            buckets = b_res.get("buckets", [])
            coverage["monitored_buckets_count"] = len(buckets)
            details = f"Macie operational monitoring {len(buckets)} bucket metadata records."
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            if "AccessDenied" in code:
                status = ConnectorStatus.PERMISSION_DENIED
                missing_perms.append("macie2:DescribeBuckets")
                details = f"Permission denied: {code}"
            elif "AccessDeniedException" in code and "not enabled" in str(e).lower():
                status = ConnectorStatus.DISABLED
                details = "Macie is not enabled on this account."
            else:
                status = ConnectorStatus.DISABLED
                details = f"Macie inactive: {code}"
        except Exception as e:
            status = ConnectorStatus.DISABLED
            details = f"Macie inactive: {e}"

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
            data_retention_window="Active findings",
            cost_notes=self.cost_notes,
            limitations=self.limitations,
            coverage=coverage,
            last_checked_at=datetime.now(UTC).isoformat()
        )

    def get_macie_session(self) -> dict[str, Any]:
        """Queries Macie session configuration and enablement status."""
        client = self.session.client("macie2", region_name=self.region_name)
        try:
            res = client.get_macie_session()
            return {"status": "SUCCESS", "session": sanitize_dict(res)}
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            return {"status": "PERMISSION_DENIED" if "AccessDenied" in code else "ERROR", "error": code, "session": {}}
        except Exception as e:
            return {"status": "ERROR", "error": str(e), "session": {}}

    def list_findings(self, limit: int = 25) -> dict[str, Any]:
        """Lists active sensitive data findings from Macie."""
        client = self.session.client("macie2", region_name=self.region_name)
        try:
            res = client.list_findings(maxResults=min(limit, 25))
            findings = res.get("findingIds", [])
            return {"status": "SUCCESS", "finding_ids": sanitize_dict(findings), "count": len(findings)}
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            return {"status": "PERMISSION_DENIED" if "AccessDenied" in code else "ERROR", "error": code, "finding_ids": []}
        except Exception as e:
            return {"status": "ERROR", "error": str(e), "finding_ids": []}
