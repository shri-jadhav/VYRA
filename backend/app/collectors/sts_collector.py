import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from backend.app.core.security import sanitize_dict

logger = logging.getLogger("vyra.collectors.sts")


class STSCollector:
    """Read-only collector for AWS STS caller identity."""

    def __init__(self, session: boto3.Session):
        self.client = session.client("sts")

    def collect(self) -> dict[str, Any]:
        result = {
            "service": "sts",
            "status": "ERROR",
            "account_id": None,
            "user_id": None,
            "arn": None,
            "error": None,
        }
        try:
            response = self.client.get_caller_identity()
            result.update({
                "status": "SUCCESS",
                "account_id": response.get("Account"),
                "user_id": response.get("UserId"),
                "arn": response.get("Arn"),
                "raw": sanitize_dict(response)
            })
            logger.info(f"STS verified successfully. Account: {result['account_id']}, ARN: {result['arn']}")
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            msg = e.response.get("Error", {}).get("Message", str(e))
            logger.error(f"STS get_caller_identity failed: {code} - {msg}")
            result["status"] = "DENIED" if "AccessDenied" in code else "ERROR"
            result["error"] = f"{code}: {msg}"
        except Exception as e:
            logger.error(f"Unexpected STS collection error: {e}")
            result["error"] = str(e)

        return result
