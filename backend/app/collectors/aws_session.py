import logging

import boto3
from botocore.exceptions import ClientError, ProfileNotFound

from backend.app.core.config import settings

logger = logging.getLogger("vyra.collectors.session")


class AWSConfigurationError(Exception):
    """Base exception for AWS configuration and identity errors."""
    pass


class AWSProfileConfigurationError(AWSConfigurationError):
    """Raised when the mandatory named AWS profile cannot be loaded or is invalid."""
    pass


class AWSAccountIdentityError(AWSConfigurationError):
    """Raised when AWS account identity validation fails or caller account mismatches."""
    pass


def create_boto3_session(
    profile_name: str | None = None,
    region_name: str | None = None,
) -> boto3.Session:
    """
    Initializes a boto3 Session strictly tied to the configured read-only profile.

    SAFETY REQUIREMENTS:
    - Never falls back to default credentials, environment variables, or instance profiles.
    - Fails closed immediately if the profile cannot be loaded.
    - Prevents arbitrary profile name injection by callers.
    """
    target_profile = profile_name or settings.AWS_PROFILE
    target_region = region_name or settings.AWS_DEFAULT_REGION

    # Guard: Callers cannot inject arbitrary profile names. Must match settings.AWS_PROFILE.
    if profile_name and profile_name != settings.AWS_PROFILE:
        logger.error(
            f"Attempted to initialize AWS session with unauthorized profile '{profile_name}'."
        )
        raise AWSProfileConfigurationError(
            f"Unauthorized profile '{profile_name}'. Only the configured profile '{settings.AWS_PROFILE}' is permitted."
        )

    try:
        session = boto3.Session(profile_name=target_profile, region_name=target_region)
        return session
    except ProfileNotFound as e:
        logger.error(
            f"Mandatory AWS profile '{target_profile}' was not found in credentials/config files: {e}"
        )
        # FAIL CLOSED: Never fall back to ambient/default credentials
        raise AWSProfileConfigurationError(
            f"Required AWS profile '{target_profile}' was not found. Configure this profile before running live assessments."
        ) from e
    except Exception as e:
        logger.error(
            f"Failed to initialize boto3 session with profile '{target_profile}': {type(e).__name__}"
        )
        raise AWSProfileConfigurationError(
            f"Failed to load AWS profile '{target_profile}': {type(e).__name__}"
        ) from e


def validate_caller_identity(
    session: boto3.Session,
    expected_account_id: str | None = None,
) -> dict[str, str]:
    """
    Validates caller identity using sts:GetCallerIdentity against the expected AWS Account ID.

    SAFETY REQUIREMENTS:
    - In LIVE mode, requires VYRA_EXPECTED_AWS_ACCOUNT_ID to be configured.
    - Halts immediately if caller identity does not match the configured expected account.
    - Never leaks secret tokens or credentials in logs or exceptions.
    """
    expected = (
        expected_account_id
        if expected_account_id is not None
        else settings.VYRA_EXPECTED_AWS_ACCOUNT_ID
    )
    if not expected or not expected.strip():
        raise AWSAccountIdentityError(
            "Expected AWS Account ID is not configured. Set VYRA_EXPECTED_AWS_ACCOUNT_ID in environment or .env before running live assessments."
        )

    expected = expected.strip()

    try:
        sts = session.client("sts")
        caller = sts.get_caller_identity()
    except ClientError as ce:
        code = ce.response.get("Error", {}).get("Code", "Unknown")
        msg = ce.response.get("Error", {}).get("Message", str(ce))
        logger.error(f"STS GetCallerIdentity failed with {code}: {msg}")
        raise AWSAccountIdentityError(f"STS GetCallerIdentity failed ({code}): {msg}") from ce
    except Exception as e:
        logger.error(f"Unexpected error validating STS caller identity: {type(e).__name__}")
        raise AWSAccountIdentityError(f"Failed to verify STS caller identity: {type(e).__name__}") from e

    caller_account = caller.get("Account")
    if not caller_account:
        raise AWSAccountIdentityError("STS response did not contain an Account identifier.")

    if caller_account != expected:
        logger.error(
            f"AWS Account identity mismatch! Configured expected account is '{expected}', "
            f"but authenticated caller identity returned '{caller_account}'. Aborting all AWS collection."
        )
        raise AWSAccountIdentityError(
            f"AWS Account identity mismatch: authenticated caller account '{caller_account}' "
            f"does not match expected account '{expected}'. All operations aborted."
        )

    logger.info(f"Verified caller identity for AWS account: {caller_account}")
    return {
        "account_id": caller_account,
        "arn": caller.get("Arn", ""),
        "user_id": caller.get("UserId", ""),
    }


def create_validated_aws_session(
    profile_name: str | None = None,
    region_name: str | None = None,
    expected_account_id: str | None = None,
) -> tuple[boto3.Session, dict[str, str]]:
    """
    Creates a boto3 session with the mandatory profile and validates caller identity
    against the expected account ID in a single, safe operation.
    """
    session = create_boto3_session(profile_name=profile_name, region_name=region_name)
    identity = validate_caller_identity(session=session, expected_account_id=expected_account_id)
    return session, identity
