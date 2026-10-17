import logging
from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import ClientError

from backend.app.connectors.base import BaseConnector
from backend.app.core.security import sanitize_dict
from backend.app.investigation.domain import ConnectorCapability, ConnectorStatus

logger = logging.getLogger("vyra.connectors.guardduty")


class GuardDutyConnector(BaseConnector):
    @property
    def service_id(self) -> str:
        return "guardduty"

    @property
    def display_name(self) -> str:
        return "Amazon GuardDuty Threat Findings"

    @property
    def category(self) -> str:
        return "Threat Detection"

    @property
    def required_permissions(self) -> list[str]:
        return [
            "guardduty:ListDetectors",
            "guardduty:GetDetector",
            "guardduty:ListFindings",
            "guardduty:GetFindings"
        ]

    @property
    def supported_operations(self) -> list[str]:
        return [
            "ListDetectors",
            "GetDetector",
            "ListFindings",
            "GetFindings"
        ]

    @property
    def telemetry_type(self) -> str:
        return "FINDINGS_RETRIEVED"

    @property
    def cost_notes(self) -> str:
        return "GuardDuty is a paid service based on DNS, VPC Flow, and S3 event volume. VYRA will not enable detectors."

    @property
    def limitations(self) -> str:
        return "Only captures threats if GuardDuty was already running during the incident window."

    def check_availability(self) -> ConnectorCapability:
        client = self.session.client("guardduty", region_name=self.region_name)
        status = ConnectorStatus.AVAILABLE
        details = "GuardDuty accessible."
        missing_perms = []
        coverage = {
            "detectors_count": 0,
            "detector_ids": [],
            "active_detectors": 0,
        }

        try:
            res = client.list_detectors()
            detectors = res.get("DetectorIds", [])
            coverage["detectors_count"] = len(detectors)
            coverage["detector_ids"] = detectors

            if not detectors:
                status = ConnectorStatus.DISABLED
                details = "Amazon GuardDuty is not enabled in this region (0 detectors found)."
            else:
                details = f"Found {len(detectors)} detector(s)."
                # Probe first detector status
                try:
                    det_res = client.get_detector(DetectorId=detectors[0])
                    det_status = det_res.get("Status", "DISABLED")
                    if det_status == "ENABLED":
                        coverage["active_detectors"] += 1
                        details += " Detector is active."
                    else:
                        details += " Detector is suspended or disabled."
                except ClientError as ce:
                    code = ce.response.get("Error", {}).get("Code", "Unknown")
                    if "AccessDenied" in code:
                        missing_perms.append("guardduty:GetDetector")
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            if "SubscriptionRequired" in code:
                status = ConnectorStatus.NOT_SUBSCRIBED
                details = "AWS Access Key requires a subscription for GuardDuty."
            elif "AccessDenied" in code:
                status = ConnectorStatus.PERMISSION_DENIED
                missing_perms.append("guardduty:ListDetectors")
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
            data_retention_window="90 days",
            cost_notes=self.cost_notes,
            limitations=self.limitations,
            coverage=coverage,
            last_checked_at=datetime.now(UTC).isoformat()
        )


    def list_findings_summary(self, limit: int = 25) -> dict[str, Any]:
        """Queries GuardDuty finding summaries for the first active detector."""
        client = self.session.client("guardduty", region_name=self.region_name)
        try:
            det_res = client.list_detectors()
            detectors = det_res.get("DetectorIds", [])
            if not detectors:
                return {"status": "DISABLED", "findings": [], "count": 0}

            detector_id = detectors[0]
            findings_res = client.list_findings(
                DetectorId=detector_id,
                MaxResults=min(limit, 25)
            )
            finding_ids = findings_res.get("FindingIds", [])
            if not finding_ids:
                return {"status": "SUCCESS", "findings": [], "count": 0}

            details_res = client.get_findings(DetectorId=detector_id, FindingIds=finding_ids)
            findings = details_res.get("Findings", [])
            return {"status": "SUCCESS", "findings": sanitize_dict(findings), "count": len(findings)}
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            return {"status": "PERMISSION_DENIED" if "AccessDenied" in code else "ERROR", "error": code, "findings": []}
        except Exception as e:
            return {"status": "ERROR", "error": str(e), "findings": []}
