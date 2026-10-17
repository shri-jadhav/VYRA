import logging
from datetime import UTC, datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError

from backend.app.core.security import sanitize_dict

logger = logging.getLogger("vyra.collectors.iam")


class IAMCollector:
    """Read-only collector for AWS IAM users, roles, MFA posture, and account summary."""

    def __init__(self, session: boto3.Session):
        self.client = session.client("iam")

    def collect(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "service": "iam",
            "status": "ERROR",
            "account_summary": {},
            "users": [],
            "roles": [],
            "errors": {},
            "password_policy": None,
            "password_policy_status": "NOT_CONFIGURED",  # nosec B105
            "permissions_summary": {
                "GetAccountSummary": "UNKNOWN",
                "GetAccountPasswordPolicy": "UNKNOWN",
                "ListUsers": "UNKNOWN",
                "ListMFADevices": "UNKNOWN",
                "ListAccessKeys": "UNKNOWN",
                "ListAttachedUserPolicies": "UNKNOWN",
                "ListRoles": "UNKNOWN",
            }
        }

        # 1. Account Summary (Root posture)
        try:
            summary_res = self.client.get_account_summary()
            result["account_summary"] = summary_res.get("SummaryMap", {})
            result["permissions_summary"]["GetAccountSummary"] = "ALLOWED"
            logger.info("IAM get_account_summary collected successfully.")
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            result["permissions_summary"]["GetAccountSummary"] = "DENIED" if "AccessDenied" in code else "ERROR"
            result["errors"]["get_account_summary"] = code

        # 2. Account Password Policy
        try:
            pw_res = self.client.get_account_password_policy()
            result["password_policy"] = pw_res.get("PasswordPolicy", {})
            result["password_policy_status"] = "CONFIGURED"  # nosec B105
            result["permissions_summary"]["GetAccountPasswordPolicy"] = "ALLOWED"
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            if code in ["NoSuchEntity", "NoSuchEntityException"]:
                result["password_policy"] = None
                result["password_policy_status"] = "NOT_CONFIGURED"  # nosec B105
                result["permissions_summary"]["GetAccountPasswordPolicy"] = "ALLOWED"
            elif "AccessDenied" in code:
                result["password_policy_status"] = "PERMISSION_DENIED"  # nosec B105
                result["permissions_summary"]["GetAccountPasswordPolicy"] = "DENIED"
                result["errors"]["get_account_password_policy"] = code
            else:
                result["password_policy_status"] = "ERROR"  # nosec B105
                result["errors"]["get_account_password_policy"] = code

        # 3. List Users & Posture (with pagination)
        try:
            users_list = []
            try:
                paginator = self.client.get_paginator("list_users")
                for page in paginator.paginate():
                    users_list.extend(page.get("Users", []))
                    if len(users_list) >= 100:
                        break
            except Exception:
                users_res = self.client.list_users(MaxItems=100)
                users_list = users_res.get("Users", [])

            result["permissions_summary"]["ListUsers"] = "ALLOWED"

            for u in users_list:
                user_name = u.get("UserName")
                user_arn = u.get("Arn")
                created_date = u.get("CreateDate")

                user_info: dict[str, Any] = {
                    "user_name": user_name,
                    "arn": user_arn,
                    "user_id": u.get("UserId"),
                    "create_date": created_date.isoformat() if created_date else None,
                    "mfa_active": False,
                    "mfa_devices": [],
                    "access_keys": [],
                    "attached_policies": [],
                    "inline_policies": [],
                    "errors": {}
                }

                # Check MFA devices
                try:
                    mfa_res = self.client.list_mfa_devices(UserName=user_name)
                    devices = mfa_res.get("MFADevices", [])
                    user_info["mfa_devices"] = devices
                    user_info["mfa_active"] = len(devices) > 0
                    result["permissions_summary"]["ListMFADevices"] = "ALLOWED"
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "Unknown")
                    user_info["errors"]["list_mfa_devices"] = code
                    result["permissions_summary"]["ListMFADevices"] = "DENIED" if "AccessDenied" in code else "ERROR"

                # Check Access Keys
                try:
                    keys_res = self.client.list_access_keys(UserName=user_name)
                    keys = keys_res.get("AccessKeyMetadata", [])
                    processed_keys = []
                    now = datetime.now(UTC)

                    for k in keys:
                        create_dt = k.get("CreateDate")
                        age_days = (now - create_dt).days if create_dt else 0
                        processed_keys.append({
                            "access_key_id": k.get("AccessKeyId"),
                            "status": k.get("Status"),  # Active / Inactive
                            "create_date": create_dt.isoformat() if create_dt else None,
                            "age_days": age_days,
                        })

                    user_info["access_keys"] = processed_keys
                    result["permissions_summary"]["ListAccessKeys"] = "ALLOWED"
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "Unknown")
                    user_info["errors"]["list_access_keys"] = code
                    result["permissions_summary"]["ListAccessKeys"] = "DENIED" if "AccessDenied" in code else "ERROR"

                # Check Attached Policies
                try:
                    pols_res = self.client.list_attached_user_policies(UserName=user_name)
                    user_info["attached_policies"] = pols_res.get("AttachedPolicies", [])
                    result["permissions_summary"]["ListAttachedUserPolicies"] = "ALLOWED"
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "Unknown")
                    user_info["errors"]["list_attached_user_policies"] = code
                    result["permissions_summary"]["ListAttachedUserPolicies"] = "DENIED" if "AccessDenied" in code else "ERROR"

                # Check Inline Policies
                try:
                    inline_res = self.client.list_user_policies(UserName=user_name)
                    user_info["inline_policies"] = inline_res.get("PolicyNames", [])
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "Unknown")
                    user_info["errors"]["list_user_policies"] = code

                result["users"].append(user_info)

        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            result["permissions_summary"]["ListUsers"] = "DENIED" if "AccessDenied" in code else "ERROR"
            result["errors"]["list_users"] = code

        # 4. List Roles (with pagination and attached policies)
        try:
            roles_list = []
            try:
                paginator = self.client.get_paginator("list_roles")
                for page in paginator.paginate():
                    roles_list.extend(page.get("Roles", []))
                    if len(roles_list) >= 50:
                        break
            except Exception:
                roles_res = self.client.list_roles(MaxItems=50)
                roles_list = roles_res.get("Roles", [])

            result["permissions_summary"]["ListRoles"] = "ALLOWED"
            for r in roles_list:
                role_name = r.get("RoleName")
                role_info = {
                    "role_name": role_name,
                    "arn": r.get("Arn"),
                    "create_date": r.get("CreateDate").isoformat() if r.get("CreateDate") else None,
                    "assume_role_policy": r.get("AssumeRolePolicyDocument"),
                    "attached_policies": [],
                    "errors": {}
                }
                try:
                    r_pols = self.client.list_attached_role_policies(RoleName=role_name)
                    role_info["attached_policies"] = r_pols.get("AttachedPolicies", [])
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "Unknown")
                    role_info["errors"]["list_attached_role_policies"] = code

                result["roles"].append(role_info)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            result["permissions_summary"]["ListRoles"] = "DENIED" if "AccessDenied" in code else "ERROR"
            result["errors"]["list_roles"] = code

        result["status"] = "SUCCESS" if (result["users"] or result["account_summary"]) else "PARTIAL_OR_ERROR"
        return sanitize_dict(result)
