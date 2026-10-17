import logging
from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import ClientError

from backend.app.connectors.base import BaseConnector
from backend.app.core.security import sanitize_dict
from backend.app.investigation.domain import ConnectorCapability, ConnectorStatus

logger = logging.getLogger("vyra.connectors.config")


class AWSConfigConnector(BaseConnector):
    @property
    def service_id(self) -> str:
        return "config"

    @property
    def display_name(self) -> str:
        return "AWS Config Historical Configuration"

    @property
    def category(self) -> str:
        return "Configuration History & Compliance"

    @property
    def required_permissions(self) -> list[str]:
        return [
            "config:DescribeConfigurationRecorders",
            "config:DescribeConfigurationRecorderStatus",
            "config:DescribeDeliveryChannels",
            "config:GetResourceConfigHistory"
        ]

    @property
    def supported_operations(self) -> list[str]:
        return [
            "DescribeConfigurationRecorders",
            "DescribeConfigurationRecorderStatus",
            "DescribeDeliveryChannels",
            "GetResourceConfigHistory"
        ]

    @property
    def telemetry_type(self) -> str:
        return "CONFIGURATION_HISTORY"

    @property
    def cost_notes(self) -> str:
        return "AWS Config incurs charges per configuration item recorded when enabled. VYRA only queries existing history."

    @property
    def limitations(self) -> str:
        return (
            "Configuration history is only available if an AWS Config recorder was actively running in the target region. "
            "VYRA will not create or enable a recorder."
        )

    def check_availability(self) -> ConnectorCapability:
        client = self.session.client("config", region_name=self.region_name)
        status = ConnectorStatus.AVAILABLE
        details = "AWS Config API reachable."
        missing_perms = []
        coverage = {
            "recorders_count": 0,
            "recording_active": False,
            "delivery_channels_count": 0,
            "delivery_channels": []
        }

        recorders = []
        try:
            res = client.describe_configuration_recorders()
            recorders = res.get("ConfigurationRecorders", [])
            coverage["recorders_count"] = len(recorders)
            if not recorders:
                status = ConnectorStatus.DISABLED
                details = "AWS Config is not configured or recording in this region (0 recorders found)."
            else:
                status = ConnectorStatus.AVAILABLE
                details = f"Found {len(recorders)} configuration recorder(s)."
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            if "AccessDenied" in code:
                status = ConnectorStatus.PERMISSION_DENIED
                missing_perms.append("config:DescribeConfigurationRecorders")
                details = f"Permission denied: {code}"
            else:
                status = ConnectorStatus.ERROR
                details = f"{code}: {e}"

        # Probe recorder status
        if recorders:
            try:
                st_res = client.describe_configuration_recorder_status()
                statuses = st_res.get("ConfigurationRecordersStatus", [])
                is_recording = any(s.get("recording", False) for s in statuses)
                coverage["recording_active"] = is_recording
                if is_recording:
                    details += " Active recording in progress."
                else:
                    details += " Recorder is stopped."
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "Unknown")
                if "AccessDenied" in code:
                    missing_perms.append("config:DescribeConfigurationRecorderStatus")

        # Probe delivery channels
        try:
            dc_res = client.describe_delivery_channels()
            channels = dc_res.get("DeliveryChannels", [])
            coverage["delivery_channels_count"] = len(channels)
            coverage["delivery_channels"] = [c.get("name") for c in channels if c.get("name")]
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            if "AccessDenied" in code:
                missing_perms.append("config:DescribeDeliveryChannels")

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
            data_retention_window="Variable (per bucket delivery retention)",
            cost_notes=self.cost_notes,
            limitations=self.limitations,
            coverage=coverage,
            last_checked_at=datetime.now(UTC).isoformat()
        )


    def get_recorder_status(self) -> dict[str, Any]:
        """Retrieves recorder execution status."""
        client = self.session.client("config", region_name=self.region_name)
        try:
            res = client.describe_configuration_recorder_status()
            return {"status": "SUCCESS", "recorder_statuses": sanitize_dict(res.get("ConfigurationRecordersStatus", []))}
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            return {"status": "PERMISSION_DENIED" if "AccessDenied" in code else "ERROR", "error": code, "recorder_statuses": []}

    def get_delivery_channels(self) -> dict[str, Any]:
        """Retrieves configured delivery channels."""
        client = self.session.client("config", region_name=self.region_name)
        try:
            res = client.describe_delivery_channels()
            return {"status": "SUCCESS", "delivery_channels": sanitize_dict(res.get("DeliveryChannels", []))}
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            return {"status": "PERMISSION_DENIED" if "AccessDenied" in code else "ERROR", "error": code, "delivery_channels": []}

    def get_resource_config_history(
        self,
        resource_type: str,
        resource_id: str,
        earlier_time: datetime | None = None,
        later_time: datetime | None = None,
        limit: int = 20
    ) -> dict[str, Any]:
        """Queries historical configuration snapshots for a specific resource if Config is active."""
        client = self.session.client("config", region_name=self.region_name)
        kwargs: dict[str, Any] = {
            "resourceType": resource_type,
            "resourceId": resource_id,
            "limit": min(limit, 20)
        }
        if earlier_time:
            kwargs["earlierTime"] = earlier_time
        if later_time:
            kwargs["laterTime"] = later_time

        try:
            res = client.get_resource_config_history(**kwargs)
            items = res.get("configurationItems", [])
            return {
                "status": "SUCCESS",
                "items": sanitize_dict(items),
                "count": len(items)
            }
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            msg = e.response.get("Error", {}).get("Message", str(e))
            return {
                "status": "PERMISSION_DENIED" if "AccessDenied" in code else "ERROR",
                "error": f"{code}: {msg}",
                "items": []
            }
        except Exception as e:
            return {"status": "ERROR", "error": str(e), "items": []}
