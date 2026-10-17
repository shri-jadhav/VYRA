from datetime import UTC, datetime, timedelta

import boto3
from botocore.stub import Stubber

from backend.app.collectors.iam_collector import IAMCollector


def test_iam_collector_root_and_user_posture():
    iam_client = boto3.client("iam", region_name="us-east-1")
    stubber = Stubber(iam_client)

    now = datetime.now(UTC)
    old_key_date = now - timedelta(days=120)

    # 1. get_account_summary: Root MFA disabled, Root keys 0
    stubber.add_response("get_account_summary", {
        "SummaryMap": {
            "AccountMFAEnabled": 0,
            "AccountAccessKeysPresent": 0,
            "Users": 1,
            "Roles": 2
        }
    })

    # 2. get_account_password_policy
    stubber.add_response("get_account_password_policy", {
        "PasswordPolicy": {
            "MinimumPasswordLength": 14,
            "RequireSymbols": True,
            "RequireNumbers": True,
            "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True,
            "AllowUsersToChangePassword": True,
            "ExpirePasswords": True,
            "MaxPasswordAge": 90,
            "PasswordReusePrevention": 24,
            "HardExpiry": False
        }
    })

    # 3. list_users with required Path and valid UserId length (>=16)
    stubber.add_response("list_users", {
        "Users": [{
            "Path": "/",
            "UserName": "dev-user",
            "Arn": "arn:aws:iam::123456789012:user/dev-user",
            "UserId": "AIDA1234567890123456",
            "CreateDate": now
        }]
    })

    # 4. list_mfa_devices: no devices
    stubber.add_response("list_mfa_devices", {
        "MFADevices": []
    }, {"UserName": "dev-user"})

    # 5. list_access_keys: 120-day old active key
    stubber.add_response("list_access_keys", {
        "AccessKeyMetadata": [{
            "UserName": "dev-user",
            "AccessKeyId": "AKIAEXAMPLEKEY123",
            "Status": "Active",
            "CreateDate": old_key_date
        }]
    }, {"UserName": "dev-user"})

    # 6. list_attached_user_policies
    stubber.add_response("list_attached_user_policies", {
        "AttachedPolicies": [{"PolicyName": "ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}]
    }, {"UserName": "dev-user"})

    # 7. list_user_policies
    stubber.add_response("list_user_policies", {
        "PolicyNames": []
    }, {"UserName": "dev-user"})

    # 8. list_roles
    stubber.add_response("list_roles", {
        "Roles": []
    })

    with stubber:
        collector = IAMCollector.__new__(IAMCollector)
        collector.client = iam_client
        res = collector.collect()

        assert res["status"] == "SUCCESS"
        assert res["account_summary"]["AccountMFAEnabled"] == 0
        assert res["account_summary"]["AccountAccessKeysPresent"] == 0
        assert res["password_policy_status"] == "CONFIGURED"
        assert res["password_policy"]["MinimumPasswordLength"] == 14
        assert len(res["users"]) == 1
        user = res["users"][0]
        assert user["mfa_active"] is False
        assert len(user["access_keys"]) == 1
        assert user["access_keys"][0]["age_days"] >= 119
        assert len(user["attached_policies"]) == 1
        assert user["attached_policies"][0]["PolicyName"] == "ReadOnlyAccess"
