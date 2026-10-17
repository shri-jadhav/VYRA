import logging

from fastapi import APIRouter, HTTPException, Query

from backend.app.collectors.aws_session import (
    AWSAccountIdentityError,
    AWSConfigurationError,
    AWSProfileConfigurationError,
    create_boto3_session,
    validate_caller_identity,
)
from backend.app.connectors.registry import ConnectorRegistry
from backend.app.core.config import settings
from backend.app.schemas.schemas import ConnectorCapabilityRead

logger = logging.getLogger("vyra.api.connectors")

router = APIRouter(prefix="/connectors", tags=["Connectors Matrix"])


@router.get("", response_model=list[ConnectorCapabilityRead])
@router.get("/matrix", response_model=list[ConnectorCapabilityRead])
def list_connectors(
    region: str | None = Query(None, description="AWS Region to inspect"),
    mode: str = Query("AUTO", description="Mode: LIVE_AWS, DEMO_FIXTURE, or AUTO"),
):
    """
    Returns the capability status, required vs missing IAM permissions,
    supported operations, cost notes, and limitations for all modular AWS connectors.
    Strictly read-only discovery.
    """
    target_region = region or settings.AWS_DEFAULT_REGION
    if mode != "LIVE_AWS":
        return ConnectorRegistry.get_all_capabilities(session=None, region=target_region)

    if not settings.ALLOW_LIVE_COLLECTION:
        raise HTTPException(status_code=403, detail="Live AWS collection is disabled by environment configuration.")
    if not settings.VYRA_EXPECTED_AWS_ACCOUNT_ID:
        raise HTTPException(
            status_code=400,
            detail="Expected AWS Account ID is not configured. Set VYRA_EXPECTED_AWS_ACCOUNT_ID before querying live connectors.",
        )

    session = None
    try:
        session = create_boto3_session(settings.AWS_PROFILE)
        validate_caller_identity(session)
    except (AWSProfileConfigurationError, AWSAccountIdentityError, AWSConfigurationError) as ce:
        logger.error(f"AWS configuration error for live connectors: {ce}")
        raise HTTPException(status_code=400, detail=f"AWS configuration error: {ce!s}")

    try:
        capabilities = ConnectorRegistry.get_all_capabilities(session=session, region=target_region)
        return capabilities
    except Exception as e:
        logger.exception(f"Failed to query connector capabilities: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to query connector matrix: {str(e)}")


@router.get("/{service_id}", response_model=ConnectorCapabilityRead)
def get_connector(
    service_id: str,
    region: str | None = Query(None, description="AWS Region to inspect"),
    mode: str = Query("AUTO", description="Mode: LIVE_AWS, DEMO_FIXTURE, or AUTO"),
):
    """Returns capabilities and status of a specific AWS connector."""
    target_region = region or settings.AWS_DEFAULT_REGION
    if mode != "LIVE_AWS":
        capabilities = ConnectorRegistry.get_all_capabilities(session=None, region=target_region)
    else:
        if not settings.ALLOW_LIVE_COLLECTION:
            raise HTTPException(status_code=403, detail="Live AWS collection is disabled by environment configuration.")
        if not settings.VYRA_EXPECTED_AWS_ACCOUNT_ID:
            raise HTTPException(
                status_code=400,
                detail="Expected AWS Account ID is not configured. Set VYRA_EXPECTED_AWS_ACCOUNT_ID before querying live connectors.",
            )
        try:
            session = create_boto3_session(settings.AWS_PROFILE)
            validate_caller_identity(session)
            capabilities = ConnectorRegistry.get_all_capabilities(session=session, region=target_region)
        except (AWSProfileConfigurationError, AWSAccountIdentityError, AWSConfigurationError) as ce:
            raise HTTPException(status_code=400, detail=f"AWS configuration error: {ce!s}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to query connector: {str(e)}")

    match = next((c for c in capabilities if c.service_id.lower() == service_id.lower()), None)
    if not match:
        raise HTTPException(status_code=404, detail=f"Connector '{service_id}' not found.")
    return match
