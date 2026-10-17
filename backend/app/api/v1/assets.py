
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.scope import resolve_assessment_run
from backend.app.models.models import Asset
from backend.app.schemas.schemas import AssetRead

router = APIRouter(prefix="/assets", tags=["Cloud Assets"])


@router.get("", response_model=list[AssetRead])
def list_assets(
    run_id: str | None = Query(None, description="Assessment run ID to scope assets"),
    service: str | None = Query(None, description="Filter by service, e.g. s3, iam, cloudtrail"),
    asset_type: str | None = Query(None, description="Filter by asset type, e.g. s3:bucket"),
    search: str | None = Query(None, description="Search term in name or arn"),
    limit: int = 100,
    db: Session = Depends(get_db)
):
    target_run = resolve_assessment_run(db, run_id=run_id)
    if not target_run:
        return []

    query = db.query(Asset).filter(Asset.run_id == target_run.id)
    if service:
        query = query.filter(Asset.service == service.lower())
    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    if search:
        term = f"%{search}%"
        query = query.filter((Asset.name.ilike(term)) | (Asset.arn.ilike(term)))

    return query.order_by(Asset.last_seen.desc()).limit(limit).all()


@router.get("/{asset_id}", response_model=AssetRead)
def get_asset(
    asset_id: str,
    run_id: str | None = Query(None, description="Optional assessment run ID to scope asset lookup"),
    db: Session = Depends(get_db),
):
    query = db.query(Asset).filter(Asset.id == asset_id)
    if run_id:
        target_run = resolve_assessment_run(db, run_id=run_id)
        query = query.filter(Asset.run_id == target_run.id)
    asset = query.first()
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")
    return asset
