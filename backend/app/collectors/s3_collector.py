import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from backend.app.core.security import sanitize_dict

logger = logging.getLogger("vyra.collectors.s3")


class S3Collector:
    """
    Read-only collector for Amazon S3 bucket configurations.
    CRITICAL SAFETY GUARANTEE: Never accesses or reads S3 object contents.
    Only queries bucket-level security configuration metadata.
    """

    def __init__(self, session: boto3.Session):
        self.client = session.client("s3")

    def collect(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "service": "s3",
            "status": "ERROR",
            "buckets": [],
            "error": None,
            "permissions_summary": {
                "ListAllMyBuckets": "UNKNOWN",
                "GetBucketPublicAccessBlock": "UNKNOWN",
                "GetEncryptionConfiguration": "UNKNOWN",
                "GetBucketVersioning": "UNKNOWN",
                "GetBucketPolicyStatus": "UNKNOWN",
                "GetBucketLogging": "UNKNOWN",
            }
        }

        try:
            buckets_list = []
            # Use paginator if supported by boto3 client, else call list_buckets directly
            try:
                paginator = self.client.get_paginator("list_buckets")
                for page in paginator.paginate():
                    buckets_list.extend(page.get("Buckets", []))
            except Exception:
                buckets_response = self.client.list_buckets()
                buckets_list = buckets_response.get("Buckets", [])

            result["permissions_summary"]["ListAllMyBuckets"] = "ALLOWED"
            logger.info(f"S3 list_buckets returned {len(buckets_list)} buckets.")
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            msg = e.response.get("Error", {}).get("Message", str(e))
            logger.error(f"S3 list_buckets failed: {code} - {msg}")
            result["status"] = "DENIED" if "AccessDenied" in code else "ERROR"
            result["error"] = f"{code}: {msg}"
            result["permissions_summary"]["ListAllMyBuckets"] = "DENIED"
            return result
        except Exception as e:
            logger.error(f"Unexpected error in S3 collection: {e}")
            result["error"] = str(e)
            return result

        for b in buckets_list:
            name = b.get("Name")
            created_at = b.get("CreationDate")
            bucket_arn = b.get("BucketArn") or f"arn:aws:s3:::{name}"

            bucket_info: dict[str, Any] = {
                "name": name,
                "arn": bucket_arn,
                "creation_date": created_at.isoformat() if created_at else None,
                "region": "unknown",
                "public_access_block": None,
                "public_access_block_status": "NOT_CONFIGURED",
                "encryption": None,
                "encryption_status": "NOT_CONFIGURED",
                "versioning": None,
                "versioning_status": "NOT_CONFIGURED",
                "policy_status": None,
                "logging": None,
                "logging_status": "NOT_CONFIGURED",
                "errors": {}
            }

            # 1. Bucket Location (Region)
            try:
                loc_res = self.client.get_bucket_location(Bucket=name)
                loc = loc_res.get("LocationConstraint")
                # AWS returns None for us-east-1
                bucket_info["region"] = loc if loc else "us-east-1"
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "Unknown")
                bucket_info["errors"]["get_bucket_location"] = code

            # 2. Public Access Block
            try:
                pab_res = self.client.get_public_access_block(Bucket=name)
                pab_cfg = pab_res.get("PublicAccessBlockConfiguration", {})
                bucket_info["public_access_block"] = pab_cfg
                result["permissions_summary"]["GetBucketPublicAccessBlock"] = "ALLOWED"

                all_blocked = (
                    pab_cfg.get("BlockPublicAcls", False) and
                    pab_cfg.get("IgnorePublicAcls", False) and
                    pab_cfg.get("BlockPublicPolicy", False) and
                    pab_cfg.get("RestrictPublicBuckets", False)
                )
                bucket_info["public_access_block_status"] = "FULL_BLOCK" if all_blocked else "PARTIAL_OR_UNBLOCKED"
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "Unknown")
                if code in ["NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlock"]:
                    bucket_info["public_access_block_status"] = "NOT_CONFIGURED"
                    result["permissions_summary"]["GetBucketPublicAccessBlock"] = "ALLOWED"
                elif "AccessDenied" in code:
                    bucket_info["public_access_block_status"] = "PERMISSION_DENIED"
                    result["permissions_summary"]["GetBucketPublicAccessBlock"] = "DENIED"
                    bucket_info["errors"]["get_public_access_block"] = code
                else:
                    bucket_info["public_access_block_status"] = "ERROR"
                    bucket_info["errors"]["get_public_access_block"] = code

            # 3. Server-Side Encryption
            try:
                enc_res = self.client.get_bucket_encryption(Bucket=name)
                rules = enc_res.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                bucket_info["encryption"] = rules
                bucket_info["encryption_status"] = "CONFIGURED" if rules else "NOT_CONFIGURED"
                result["permissions_summary"]["GetEncryptionConfiguration"] = "ALLOWED"
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "Unknown")
                if code in ["ServerSideEncryptionConfigurationNotFoundError", "NoSuchServerSideEncryptionConfiguration"]:
                    bucket_info["encryption_status"] = "NOT_CONFIGURED"
                    result["permissions_summary"]["GetEncryptionConfiguration"] = "ALLOWED"
                elif "AccessDenied" in code:
                    bucket_info["encryption_status"] = "PERMISSION_DENIED"
                    result["permissions_summary"]["GetEncryptionConfiguration"] = "DENIED"
                    bucket_info["errors"]["get_bucket_encryption"] = code
                else:
                    bucket_info["encryption_status"] = "ERROR"
                    bucket_info["errors"]["get_bucket_encryption"] = code

            # 4. Bucket Versioning
            try:
                ver_res = self.client.get_bucket_versioning(Bucket=name)
                status = ver_res.get("Status")
                bucket_info["versioning"] = ver_res
                bucket_info["versioning_status"] = status if status else "NOT_CONFIGURED"
                result["permissions_summary"]["GetBucketVersioning"] = "ALLOWED"
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "Unknown")
                if "AccessDenied" in code:
                    bucket_info["versioning_status"] = "PERMISSION_DENIED"
                    result["permissions_summary"]["GetBucketVersioning"] = "DENIED"
                    bucket_info["errors"]["get_bucket_versioning"] = code
                else:
                    bucket_info["versioning_status"] = "ERROR"
                    bucket_info["errors"]["get_bucket_versioning"] = code

            # 5. Bucket Policy Status (Public Policy detector)
            try:
                pol_status = self.client.get_bucket_policy_status(Bucket=name)
                bucket_info["policy_status"] = pol_status.get("PolicyStatus", {})
                result["permissions_summary"]["GetBucketPolicyStatus"] = "ALLOWED"
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "Unknown")
                if code in ["NoSuchBucketPolicy"]:
                    bucket_info["policy_status"] = {"IsPublic": False, "Notice": "NoBucketPolicy"}
                    result["permissions_summary"]["GetBucketPolicyStatus"] = "ALLOWED"
                elif "AccessDenied" in code:
                    bucket_info["policy_status"] = {"Status": "PERMISSION_DENIED"}
                    result["permissions_summary"]["GetBucketPolicyStatus"] = "DENIED"
                    bucket_info["errors"]["get_bucket_policy_status"] = code
                else:
                    bucket_info["policy_status"] = {"Status": "ERROR", "Code": code}
                    bucket_info["errors"]["get_bucket_policy_status"] = code

            # 6. Bucket Access Logging
            try:
                log_res = self.client.get_bucket_logging(Bucket=name)
                logging_cfg = log_res.get("LoggingEnabled")
                bucket_info["logging"] = logging_cfg
                bucket_info["logging_status"] = "CONFIGURED" if logging_cfg else "NOT_CONFIGURED"
                result["permissions_summary"]["GetBucketLogging"] = "ALLOWED"
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "Unknown")
                if "AccessDenied" in code:
                    bucket_info["logging_status"] = "PERMISSION_DENIED"
                    result["permissions_summary"]["GetBucketLogging"] = "DENIED"
                    bucket_info["errors"]["get_bucket_logging"] = code
                else:
                    bucket_info["logging_status"] = "ERROR"
                    bucket_info["errors"]["get_bucket_logging"] = code

            result["buckets"].append(bucket_info)

        result["status"] = "SUCCESS"
        return sanitize_dict(result)
