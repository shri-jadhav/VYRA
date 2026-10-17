import logging
from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import ClientError

from backend.app.connectors.base import BaseConnector
from backend.app.core.security import sanitize_dict
from backend.app.investigation.domain import ConnectorCapability, ConnectorStatus

logger = logging.getLogger("vyra.connectors.ssm")


class SSMConnector(BaseConnector):
    @property
    def service_id(self) -> str:
        return "ssm"

    @property
    def display_name(self) -> str:
        return "AWS Systems Manager (SSM) Inventory"

    @property
    def category(self) -> str:
        return "Workload Inventory & Compliance"

    @property
    def required_permissions(self) -> list[str]:
        return [
            "ssm:DescribeInstanceInformation",
            "ssm:DescribeInstancePatches"
        ]

    @property
    def supported_operations(self) -> list[str]:
        return [
            "DescribeInstanceInformation",
            "DescribeInstancePatches (Patch Compliance)"
        ]

    @property
    def telemetry_type(self) -> str:
        return "WORKLOAD_INVENTORY"

    @property
    def cost_notes(self) -> str:
        return "Core inventory and patch inspection features are free of charge."

    @property
    def limitations(self) -> str:
        return "Only captures EC2 instances with active SSM agents; never executes mutating commands or installs patches."

    def check_availability(self) -> ConnectorCapability:
        client = self.session.client("ssm", region_name=self.region_name)
        status = ConnectorStatus.AVAILABLE
        details = "AWS Systems Manager accessible."
        missing_perms = []
        coverage = {
            "managed_instances_count": 0,
            "instances": []
        }

        try:
            res = client.describe_instance_information(MaxResults=10)
            instances = res.get("InstanceInformationList", [])
            coverage["managed_instances_count"] = len(instances)
            coverage["instances"] = [i.get("InstanceId") for i in instances if i.get("InstanceId")]
            details = f"{len(instances)} managed instance(s) detected."
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            if "AccessDenied" in code:
                status = ConnectorStatus.PERMISSION_DENIED
                missing_perms.append("ssm:DescribeInstanceInformation")
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


    def describe_instance_patches(self, instance_id: str, limit: int = 25) -> dict[str, Any]:
        """Queries patch compliance states for a managed instance."""
        client = self.session.client("ssm", region_name=self.region_name)
        try:
            res = client.describe_instance_patches(InstanceId=instance_id, MaxResults=min(limit, 25))
            patches = res.get("Patches", [])
            return {"status": "SUCCESS", "patches": sanitize_dict(patches), "count": len(patches)}
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            return {"status": "PERMISSION_DENIED" if "AccessDenied" in code else "ERROR", "error": code, "patches": []}
        except Exception as e:
            return {"status": "ERROR", "error": str(e), "patches": []}
