import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

import boto3

from backend.app.collectors.aws_session import (
    AWSAccountIdentityError,
    create_boto3_session,
    validate_caller_identity,
)
from backend.app.collectors.cloudtrail_collector import CloudTrailCollector
from backend.app.collectors.iam_collector import IAMCollector
from backend.app.collectors.s3_collector import S3Collector
from backend.app.collectors.security_services_collector import SecurityServicesCollector
from backend.app.collectors.sts_collector import STSCollector
from backend.app.core.config import settings
from backend.app.core.security import sanitize_dict

logger = logging.getLogger("vyra.collectors.orchestrator")


class CollectorOrchestrator:
    """
    Orchestrates all read-only AWS collectors, tracks execution latency,
    records provenance, and writes sanitized evidence to local storage.
    """

    def __init__(self, profile_name: str | None = None, region_name: str | None = None):
        self.profile_name = profile_name or settings.AWS_PROFILE
        self.region_name = region_name or settings.AWS_DEFAULT_REGION
        self.session: boto3.Session | None = None

    def initialize_session(self) -> boto3.Session:
        self.session = create_boto3_session(self.profile_name, self.region_name)
        return self.session

    def collect_all(self, run_id: str) -> dict[str, Any]:
        """Runs all authorized read-only collectors safely and returns structured evidence."""
        if not self.session:
            self.initialize_session()

        started_at = datetime.now(UTC)
        logger.info(f"Starting collector orchestration for run {run_id} using profile {self.profile_name}")

        evidence_payload: dict[str, Any] = {
            "run_id": run_id,
            "profile_used": self.profile_name,
            "region": self.region_name,
            "collection_timestamp": started_at.isoformat(),
            "collector_version": settings.APP_VERSION,
            "sts": {},
            "s3": {},
            "iam": {},
            "cloudtrail": {},
            "security_services": {},
            "provenance": {
                "source": "AWS_API_LIVE_READONLY",
                "collector_agent": "VYRA Cloud Assessment Engine",
                "auth_chain": "boto3_standard_profile",
                "profile": self.profile_name,
            }
        }

        # 1. STS Collector & Mandatory Identity Validation
        try:
            sts_col = STSCollector(self.session)
            sts_data = sts_col.collect()
            evidence_payload["sts"] = sts_data
            if sts_data.get("status") != "SUCCESS":
                error_msg = sts_data.get("error", "STS authentication failed.")
                logger.error(f"STS caller identity failed: {error_msg}. Halting all subsequent collection.")
                raise AWSAccountIdentityError(f"STS verification failed: {error_msg}")

            # Enforce expected account identity guard
            validated_id = validate_caller_identity(self.session)
            account_id = validated_id.get("account_id", sts_data.get("account_id"))
            evidence_payload["account_id"] = account_id
            evidence_payload["provenance"]["account_id"] = account_id
        except AWSAccountIdentityError:
            raise
        except Exception as e:
            logger.error(f"Identity verification failed: {e}")
            raise AWSAccountIdentityError(f"Identity verification failed: {str(e)}") from e

        # 2. S3 Collector
        try:
            s3_col = S3Collector(self.session)
            evidence_payload["s3"] = s3_col.collect()
        except Exception as e:
            logger.error(f"S3 collection failed: {e}")
            evidence_payload["s3"] = {"status": "ERROR", "error": str(e), "buckets": []}

        # 3. IAM Collector
        try:
            iam_col = IAMCollector(self.session)
            evidence_payload["iam"] = iam_col.collect()
        except Exception as e:
            logger.error(f"IAM collection failed: {e}")
            evidence_payload["iam"] = {"status": "ERROR", "error": str(e), "users": [], "account_summary": {}}

        # 4. CloudTrail Collector
        try:
            ct_col = CloudTrailCollector(self.session)
            evidence_payload["cloudtrail"] = ct_col.collect()
        except Exception as e:
            logger.error(f"CloudTrail collection failed: {e}")
            evidence_payload["cloudtrail"] = {"status": "ERROR", "error": str(e), "trails": []}

        # 5. Security Services Collector
        try:
            sec_col = SecurityServicesCollector(self.session, region=self.region_name)
            evidence_payload["security_services"] = sec_col.collect()
        except Exception as e:
            logger.error(f"Security services collection failed: {e}")
            evidence_payload["security_services"] = {"status": "ERROR", "error": str(e), "services": {}}

        # Sanitize and write evidence artifact
        sanitized_payload = sanitize_dict(evidence_payload)
        evidence_file_path = os.path.join(settings.EVIDENCE_DIR, f"{run_id}.json")
        try:
            with open(evidence_file_path, "w", encoding="utf-8") as f:
                json.dump(sanitized_payload, f, indent=2, default=str)
            logger.info(f"Evidence artifact saved safely to {evidence_file_path}")
        except Exception as e:
            logger.error(f"Failed to write evidence artifact: {e}")

        return sanitized_payload
