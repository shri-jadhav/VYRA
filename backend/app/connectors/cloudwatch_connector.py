import logging
from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import ClientError

from backend.app.connectors.base import BaseConnector
from backend.app.core.security import sanitize_dict
from backend.app.investigation.domain import ConnectorCapability, ConnectorStatus

logger = logging.getLogger("vyra.connectors.cloudwatch")


class CloudWatchConnector(BaseConnector):
    @property
    def service_id(self) -> str:
        return "cloudwatch"

    @property
    def display_name(self) -> str:
        return "Amazon CloudWatch Security Alarms & Logs"

    @property
    def category(self) -> str:
        return "Monitoring & Log Telemetry"

    @property
    def required_permissions(self) -> list[str]:
        return [
            "cloudwatch:DescribeAlarms",
            "logs:DescribeLogGroups"
        ]

    @property
    def supported_operations(self) -> list[str]:
        return [
            "DescribeAlarms",
            "DescribeLogGroups"
        ]

    @property
    def telemetry_type(self) -> str:
        return "METRICS_ALARMS"

    @property
    def cost_notes(self) -> str:
        return "Standard CloudWatch read-only API calls incur minimal standard AWS request fees. VYRA will not create alarms or metrics."

    @property
    def limitations(self) -> str:
        return "Evaluates security-relevant metric alarms and CloudTrail delivery log groups."

    def check_availability(self) -> ConnectorCapability:
        cw_client = self.session.client("cloudwatch", region_name=self.region_name)
        logs_client = self.session.client("logs", region_name=self.region_name)

        status = ConnectorStatus.AVAILABLE
        details = "CloudWatch and Logs APIs reachable."
        missing_perms = []
        coverage = {
            "metric_alarms_count": 0,
            "security_log_groups_count": 0,
            "log_groups": []
        }

        # 1. Probe DescribeAlarms
        try:
            cw_res = cw_client.describe_alarms(MaxRecords=10)
            alarms = cw_res.get("MetricAlarms", [])
            coverage["metric_alarms_count"] = len(alarms)
            details = f"Found {len(alarms)} metric alarm(s)."
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            if "AccessDenied" in code:
                status = ConnectorStatus.PERMISSION_DENIED
                missing_perms.append("cloudwatch:DescribeAlarms")
                details = f"Permission denied on DescribeAlarms: {code}"
            else:
                status = ConnectorStatus.ERROR
                details = f"{code}: {e}"

        # 2. Probe DescribeLogGroups
        try:
            logs_res = logs_client.describe_log_groups(limit=10)
            log_groups = logs_res.get("logGroups", [])
            coverage["security_log_groups_count"] = len(log_groups)
            coverage["log_groups"] = [lg.get("logGroupName") for lg in log_groups if lg.get("logGroupName")]
            details += f" {len(log_groups)} log group(s) accessible."
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            if "AccessDenied" in code:
                if status == ConnectorStatus.AVAILABLE:
                    status = ConnectorStatus.PERMISSION_DENIED
                missing_perms.append("logs:DescribeLogGroups")

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


    def describe_alarms(self, limit: int = 25) -> dict[str, Any]:
        """Queries metric alarms."""
        client = self.session.client("cloudwatch", region_name=self.region_name)
        try:
            res = client.describe_alarms(MaxRecords=min(limit, 25))
            alarms = res.get("MetricAlarms", [])
            return {"status": "SUCCESS", "alarms": sanitize_dict(alarms), "count": len(alarms)}
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            return {"status": "PERMISSION_DENIED" if "AccessDenied" in code else "ERROR", "error": code, "alarms": []}
        except Exception as e:
            return {"status": "ERROR", "error": str(e), "alarms": []}

    def describe_log_groups(self, prefix: str | None = None, limit: int = 25) -> dict[str, Any]:
        """Queries CloudWatch log groups."""
        client = self.session.client("logs", region_name=self.region_name)
        kwargs: dict[str, Any] = {"limit": min(limit, 25)}
        if prefix:
            kwargs["logGroupNamePrefix"] = prefix
        try:
            res = client.describe_log_groups(**kwargs)
            groups = res.get("logGroups", [])
            return {"status": "SUCCESS", "log_groups": sanitize_dict(groups), "count": len(groups)}
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            return {"status": "PERMISSION_DENIED" if "AccessDenied" in code else "ERROR", "error": code, "log_groups": []}
        except Exception as e:
            return {"status": "ERROR", "error": str(e), "log_groups": []}
