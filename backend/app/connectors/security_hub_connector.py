import logging
from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import ClientError

from backend.app.connectors.base import BaseConnector
from backend.app.core.security import sanitize_dict
from backend.app.investigation.domain import ConnectorCapability, ConnectorStatus

logger = logging.getLogger("vyra.connectors.security_hub")


class SecurityHubConnector(BaseConnector):
    @property
    def service_id(self) -> str:
        return "securityhub"

    @property
    def display_name(self) -> str:
        return "AWS Security Hub CSPM"

    @property
    def category(self) -> str:
        return "Consolidated Findings"

    @property
    def required_permissions(self) -> list[str]:
        return [
            "securityhub:DescribeHub",
            "securityhub:GetEnabledStandards",
            "securityhub:GetFindings"
        ]

    @property
    def supported_operations(self) -> list[str]:
        return [
            "DescribeHub",
            "GetEnabledStandards",
            "GetFindings (Filtered by Resource ID)"
        ]

    @property
    def telemetry_type(self) -> str:
        return "FINDINGS_RETRIEVED"

    @property
    def cost_notes(self) -> str:
        return "Security Hub is a paid service billed per check/finding. VYRA strictly queries existing findings."

    @property
    def limitations(self) -> str:
        return (
            "Only available if Security Hub is enabled in the account and region. "
            "VYRA will not activate subscriptions."
        )

    def check_availability(self) -> ConnectorCapability:
        client = self.session.client("securityhub", region_name=self.region_name)
        status = ConnectorStatus.AVAILABLE
        details = "Security Hub API reachable."
        missing_perms = []
        coverage = {
            "hub_arn": None,
            "standards_count": 0,
            "enabled_standards": []
        }

        hub_arn = None
        try:
            res = client.describe_hub()
            hub_arn = res.get("HubArn")
            coverage["hub_arn"] = hub_arn
            if not hub_arn:
                status = ConnectorStatus.DISABLED
                details = "Security Hub is not enabled in this region."
            else:
                details = f"Security Hub is active ({hub_arn})."
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            msg = e.response.get("Error", {}).get("Message", str(e))
            if "SubscriptionRequired" in code:
                status = ConnectorStatus.NOT_SUBSCRIBED
                details = "AWS Access Key Id requires a subscription for Security Hub."
            elif "AccessDenied" in code:
                status = ConnectorStatus.PERMISSION_DENIED
                missing_perms.append("securityhub:DescribeHub")
                details = f"Permission denied: {code}"
            elif "InvalidAccessException" in code and "not subscribed" in msg.lower():
                status = ConnectorStatus.DISABLED
                details = "Security Hub is not subscribed in this region."
            else:
                status = ConnectorStatus.ERROR
                details = f"{code}: {msg}"

        # Probe enabled standards if active
        if hub_arn and status == ConnectorStatus.AVAILABLE:
            try:
                std_res = client.get_enabled_standards()
                stds = std_res.get("StandardsSubscriptions", [])
                coverage["standards_count"] = len(stds)
                coverage["enabled_standards"] = [s.get("StandardsArn") for s in stds if s.get("StandardsArn")]
                details += f" {len(stds)} standard(s) enabled."
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "Unknown")
                if "AccessDenied" in code:
                    missing_perms.append("securityhub:GetEnabledStandards")

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
            data_retention_window="90 days",
            cost_notes=self.cost_notes,
            limitations=self.limitations,
            coverage=coverage,
            last_checked_at=datetime.now(UTC).isoformat()
        )


    def get_enabled_standards(self) -> dict[str, Any]:
        """Queries currently enabled compliance standards."""
        client = self.session.client("securityhub", region_name=self.region_name)
        try:
            res = client.get_enabled_standards()
            return {"status": "SUCCESS", "standards": sanitize_dict(res.get("StandardsSubscriptions", []))}
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            return {"status": "PERMISSION_DENIED" if "AccessDenied" in code else "ERROR", "error": code, "standards": []}

    def get_related_findings(self, resource_id: str, limit: int = 25) -> dict[str, Any]:
        """Queries Security Hub findings for a specific resource ID."""
        client = self.session.client("securityhub", region_name=self.region_name)
        try:
            filters = {
                "ResourceId": [{"Value": resource_id, "Comparison": "EQUALS"}],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
            }
            res = client.get_findings(Filters=filters, MaxResults=min(limit, 25))
            findings = res.get("Findings", [])
            normalized = []
            for f in findings:
                normalized.append({
                    "finding_id": f.get("Id"),
                    "title": f.get("Title"),
                    "description": f.get("Description"),
                    "severity": f.get("Severity", {}).get("Label", "MEDIUM"),
                    "product_arn": f.get("ProductArn"),
                    "company_name": f.get("CompanyName"),
                    "updated_at": f.get("UpdatedAt"),
                    "compliance_status": f.get("Compliance", {}).get("Status")
                })
            return {"status": "SUCCESS", "findings": sanitize_dict(normalized)}
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            return {
                "status": "NOT_SUBSCRIBED" if "SubscriptionRequired" in code else "ERROR",
                "error": code,
                "findings": []
            }
        except Exception as e:
            return {"status": "ERROR", "error": str(e), "findings": []}
