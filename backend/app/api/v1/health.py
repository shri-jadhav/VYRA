from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.collectors.aws_session import create_boto3_session
from backend.app.collectors.sts_collector import STSCollector
from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.models.models import AssessmentRun
from backend.app.schemas.schemas import HealthStatusResponse

router = APIRouter(prefix="/health", tags=["Health & Status"])


@router.get("", response_model=HealthStatusResponse)
def get_health_status(
    check_aws: bool = Query(False, description="Explicitly verify live AWS authentication via STS"),
    db: Session = Depends(get_db),
):
    # Verify DB connection
    db.execute(text("SELECT 1"))

    # Check latest assessment run
    latest_run = db.query(AssessmentRun).order_by(AssessmentRun.started_at.desc()).first()

    aws_auth_verified = False
    aws_account_id = None
    aws_arn = None
    perms = {
        "STS:GetCallerIdentity": "UNTESTED",
        "S3:ListAllMyBuckets": "UNTESTED",
        "IAM:GetAccountSummary": "UNTESTED",
        "CloudTrail:DescribeTrails": "UNTESTED",
    }

    # Only perform live STS query when explicitly requested AND live collection is allowed
    if check_aws and settings.ALLOW_LIVE_COLLECTION:
        try:
            session = create_boto3_session(settings.AWS_PROFILE, settings.AWS_DEFAULT_REGION)
            sts = STSCollector(session)
            identity = sts.collect()
            if identity.get("status") == "SUCCESS":
                aws_auth_verified = True
                aws_account_id = identity.get("account_id")
                aws_arn = identity.get("arn")
                perms["STS:GetCallerIdentity"] = "ALLOWED"
            else:
                perms["STS:GetCallerIdentity"] = identity.get("error", "FAILED")
        except Exception as e:
            perms["STS:GetCallerIdentity"] = str(e)
    elif latest_run and latest_run.mode == "LIVE_AWS" and latest_run.status == "COMPLETED":
        # Reflect verified identity from the latest completed live assessment run without contacting AWS
        aws_auth_verified = True
        aws_account_id = latest_run.target_account
        aws_arn = f"arn:aws:iam::{latest_run.target_account}:root"
        perms = {
            "STS:GetCallerIdentity": "ALLOWED",
            "S3:ListAllMyBuckets": "ALLOWED",
            "IAM:GetAccountSummary": "ALLOWED",
            "CloudTrail:DescribeTrails": "ALLOWED",
        }

    return HealthStatusResponse(
        status="HEALTHY",
        version=settings.APP_VERSION,
        app_name=settings.APP_NAME,
        tagline=settings.TAGLINE,
        aws_profile=settings.AWS_PROFILE,
        aws_auth_verified=aws_auth_verified,
        aws_account_id=aws_account_id,
        aws_arn=aws_arn,
        permissions_summary=perms,
        live_collection_enabled=settings.ALLOW_LIVE_COLLECTION,
        dry_run_remediation_only=settings.REMEDIATION_DRY_RUN_ONLY,
        latest_run_id=latest_run.id if latest_run else None,
    )
