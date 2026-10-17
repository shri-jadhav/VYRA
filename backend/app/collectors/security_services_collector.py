import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from backend.app.core.security import sanitize_dict

logger = logging.getLogger("vyra.collectors.security_services")


class SecurityServicesCollector:
    """
    Read-only probes for optional AWS security services:
    IAM Access Analyzer, Amazon GuardDuty, AWS Security Hub, AWS Config, Systems Manager.
    CRITICAL: Never enables services or runs mutating actions. Accurately reports posture.
    """

    def __init__(self, session: boto3.Session, region: str = None):
        self.session = session
        self.region = region

    def collect(self) -> dict[str, Any]:
        results: dict[str, Any] = {
            "service": "security_services",
            "region": self.region,
            "services": {}
        }

        # 1. Access Analyzer
        results["services"]["access_analyzer"] = self._check_access_analyzer()

        # 2. GuardDuty
        results["services"]["guardduty"] = self._check_guardduty()

        # 3. Security Hub
        results["services"]["security_hub"] = self._check_security_hub()

        # 4. AWS Config
        results["services"]["aws_config"] = self._check_aws_config()

        # 5. Systems Manager (SSM)
        results["services"]["ssm"] = self._check_ssm()

        return sanitize_dict(results)

    def _check_access_analyzer(self) -> dict[str, Any]:
        try:
            client = self.session.client("accessanalyzer", region_name=self.region)
            res = client.list_analyzers()
            analyzers = res.get("analyzers", [])
            active = [a for a in analyzers if a.get("status") == "ACTIVE"]
            return {
                "name": "IAM Access Analyzer",
                "status": "ENABLED" if active else "DISABLED",
                "count": len(analyzers),
                "active_count": len(active),
                "details": f"{len(active)} active analyzer(s) found",
                "analyzers": analyzers
            }
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            msg = e.response.get("Error", {}).get("Message", str(e))
            if "AccessDenied" in code:
                return {"name": "IAM Access Analyzer", "status": "PERMISSION_DENIED", "details": f"Denied: {code}"}
            return {"name": "IAM Access Analyzer", "status": "ERROR", "details": f"{code}: {msg}"}
        except Exception as e:
            return {"name": "IAM Access Analyzer", "status": "ERROR", "details": str(e)}

    def _check_guardduty(self) -> dict[str, Any]:
        try:
            client = self.session.client("guardduty", region_name=self.region)
            res = client.list_detectors()
            detectors = res.get("DetectorIds", [])
            return {
                "name": "Amazon GuardDuty",
                "status": "ENABLED" if detectors else "DISABLED",
                "count": len(detectors),
                "details": f"{len(detectors)} detector(s) found",
                "detector_ids": detectors
            }
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            msg = e.response.get("Error", {}).get("Message", str(e))
            if "SubscriptionRequired" in code:
                return {"name": "Amazon GuardDuty", "status": "SUBSCRIPTION_REQUIRED", "details": "Service not subscribed/enabled on AWS account"}
            elif "AccessDenied" in code:
                return {"name": "Amazon GuardDuty", "status": "PERMISSION_DENIED", "details": f"Denied: {code}"}
            return {"name": "Amazon GuardDuty", "status": "ERROR", "details": f"{code}: {msg}"}
        except Exception as e:
            return {"name": "Amazon GuardDuty", "status": "ERROR", "details": str(e)}

    def _check_security_hub(self) -> dict[str, Any]:
        try:
            client = self.session.client("securityhub", region_name=self.region)
            res = client.describe_hub()
            hub_arn = res.get("HubArn")
            return {
                "name": "AWS Security Hub",
                "status": "ENABLED" if hub_arn else "DISABLED",
                "details": f"Hub ARN: {hub_arn}",
                "hub_arn": hub_arn
            }
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            msg = e.response.get("Error", {}).get("Message", str(e))
            if "SubscriptionRequired" in code:
                return {"name": "AWS Security Hub", "status": "SUBSCRIPTION_REQUIRED", "details": "Service not subscribed/enabled on AWS account"}
            elif "InvalidAccessException" in code or "AccessDenied" in code:
                if "not subscribed" in msg.lower():
                    return {"name": "AWS Security Hub", "status": "DISABLED", "details": "Security Hub is not enabled in this region"}
                return {"name": "AWS Security Hub", "status": "PERMISSION_DENIED", "details": f"Denied: {code}"}
            return {"name": "AWS Security Hub", "status": "ERROR", "details": f"{code}: {msg}"}
        except Exception as e:
            return {"name": "AWS Security Hub", "status": "ERROR", "details": str(e)}

    def _check_aws_config(self) -> dict[str, Any]:
        try:
            client = self.session.client("config", region_name=self.region)
            res = client.describe_configuration_recorders()
            recorders = res.get("ConfigurationRecorders", [])
            return {
                "name": "AWS Config",
                "status": "ENABLED" if recorders else "DISABLED",
                "count": len(recorders),
                "details": f"{len(recorders)} configuration recorder(s) found"
            }
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            msg = e.response.get("Error", {}).get("Message", str(e))
            if "AccessDenied" in code:
                return {"name": "AWS Config", "status": "PERMISSION_DENIED", "details": f"Denied: {code}"}
            return {"name": "AWS Config", "status": "ERROR", "details": f"{code}: {msg}"}
        except Exception as e:
            return {"name": "AWS Config", "status": "ERROR", "details": str(e)}

    def _check_ssm(self) -> dict[str, Any]:
        try:
            client = self.session.client("ssm", region_name=self.region)
            res = client.describe_instance_information(MaxResults=5)
            instances = res.get("InstanceInformationList", [])
            return {
                "name": "AWS Systems Manager",
                "status": "ENABLED" if instances else "DISABLED",
                "count": len(instances),
                "details": f"{len(instances)} managed instance(s) detected"
            }
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            if "AccessDenied" in code:
                return {"name": "AWS Systems Manager", "status": "PERMISSION_DENIED", "details": f"Denied: {code}"}
            return {"name": "AWS Systems Manager", "status": "ERROR", "details": code}
        except Exception as e:
            return {"name": "AWS Systems Manager", "status": "ERROR", "details": str(e)}
