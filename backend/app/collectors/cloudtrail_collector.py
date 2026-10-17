import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from backend.app.core.security import sanitize_dict

logger = logging.getLogger("vyra.collectors.cloudtrail")


class CloudTrailCollector:
    """Read-only collector for AWS CloudTrail trails and logging posture."""

    def __init__(self, session: boto3.Session):
        self.client = session.client("cloudtrail")

    def collect(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "service": "cloudtrail",
            "status": "ERROR",
            "trails": [],
            "error": None,
            "permissions_summary": {
                "DescribeTrails": "UNKNOWN",
                "GetTrailStatus": "UNKNOWN",
                "GetEventSelectors": "UNKNOWN",
            }
        }

        try:
            trails_res = self.client.describe_trails()
            trails_list = trails_res.get("trailList", [])
            result["permissions_summary"]["DescribeTrails"] = "ALLOWED"
            logger.info(f"CloudTrail describe_trails returned {len(trails_list)} trails.")
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            msg = e.response.get("Error", {}).get("Message", str(e))
            result["status"] = "DENIED" if "AccessDenied" in code else "ERROR"
            result["error"] = f"{code}: {msg}"
            result["permissions_summary"]["DescribeTrails"] = "DENIED"
            return result
        except Exception as e:
            result["error"] = str(e)
            return result

        if not trails_list:
            result["status"] = "SUCCESS"
            result["trails"] = []
            return result

        for t in trails_list:
            name = t.get("Name")
            arn = t.get("TrailARN")

            trail_info: dict[str, Any] = {
                "name": name,
                "arn": arn,
                "home_region": t.get("HomeRegion"),
                "s3_bucket_name": t.get("S3BucketName"),
                "is_multi_region": t.get("IsMultiRegionTrail", False),
                "is_organization_trail": t.get("IsOrganizationTrail", False),
                "log_file_validation_enabled": t.get("LogFileValidationEnabled", False),
                "kms_key_id": t.get("KmsKeyId"),
                "is_logging": False,
                "latest_delivery_time": None,
                "event_selectors": [],
                "advanced_event_selectors": [],
                "status_error": None,
                "event_selectors_error": None,
            }

            try:
                status_res = self.client.get_trail_status(Name=name)
                trail_info["is_logging"] = status_res.get("IsLogging", False)
                latest_delivery = status_res.get("LatestDeliveryTime")
                trail_info["latest_delivery_time"] = latest_delivery.isoformat() if latest_delivery else None
                result["permissions_summary"]["GetTrailStatus"] = "ALLOWED"
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "Unknown")
                trail_info["status_error"] = code
                result["permissions_summary"]["GetTrailStatus"] = "DENIED" if "AccessDenied" in code else "ERROR"

            try:
                sel_res = self.client.get_event_selectors(TrailName=name)
                trail_info["event_selectors"] = sel_res.get("EventSelectors", [])
                trail_info["advanced_event_selectors"] = sel_res.get("AdvancedEventSelectors", [])
                result["permissions_summary"]["GetEventSelectors"] = "ALLOWED"
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "Unknown")
                trail_info["event_selectors_error"] = code
                result["permissions_summary"]["GetEventSelectors"] = "DENIED" if "AccessDenied" in code else "ERROR"

            result["trails"].append(trail_info)

        result["status"] = "SUCCESS"
        return sanitize_dict(result)
