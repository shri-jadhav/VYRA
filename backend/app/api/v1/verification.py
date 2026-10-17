import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.core.scope import resolve_assessment_run
from backend.app.models.models import Finding, VerificationRun
from backend.app.schemas.schemas import VerificationRunRead, VerificationRunRequest
from backend.app.verification.engine import VerificationEngine

logger = logging.getLogger("vyra.api.verification")

router = APIRouter(prefix="/verification", tags=["After-Fix Verification"])


@router.post("/run", response_model=VerificationRunRead)
def run_verification(
    req: VerificationRunRequest,
    db: Session = Depends(get_db),
):
    """
    Executes an independent read-only verification comparing baseline evidence against
    fresh read-only observations on AWS.
    Determines outcome: RESOLVED, STILL_PRESENT, REGRESSED, or UNVERIFIABLE.
    Strictly read-only; zero mutation.
    """
    engine = VerificationEngine(db=db, profile_name=settings.AWS_PROFILE)
    try:
        v_run = engine.run_verification(
            finding_id=req.finding_id,
            investigation_id=req.investigation_id,
            operator_note=req.operator_note,
        )
        return v_run
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        logger.exception(f"Verification execution error: {e}")
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")


@router.get("/history", response_model=list[VerificationRunRead])
def list_verification_history(
    run_id: str | None = Query(None, description="Assessment run ID to scope verification history"),
    finding_id: str | None = Query(None, description="Filter by finding ID"),
    resource_id: str | None = Query(None, description="Filter by resource ID"),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """Lists history of independent verification runs strictly scoped to the active run context."""
    target_run = resolve_assessment_run(db, run_id=run_id)
    if not target_run:
        return []

    query = (
        db.query(VerificationRun)
        .join(Finding, VerificationRun.finding_id == Finding.id)
        .filter(Finding.run_id == target_run.id)
    )
    if finding_id:
        query = query.filter(VerificationRun.finding_id == finding_id)
    if resource_id:
        query = query.filter(VerificationRun.resource_id == resource_id)

    return query.order_by(VerificationRun.created_at.desc()).limit(limit).all()


@router.get("/{run_id}", response_model=VerificationRunRead)
def get_verification_run(
    run_id: str,
    assessment_run_id: str | None = Query(None, description="Optional assessment run ID to scope verification run lookup"),
    db: Session = Depends(get_db),
):
    """Retrieves full details of a specific verification run."""
    query = db.query(VerificationRun).filter(VerificationRun.id == run_id)
    if assessment_run_id:
        target_run = resolve_assessment_run(db, run_id=assessment_run_id)
        query = query.join(Finding, VerificationRun.finding_id == Finding.id).filter(Finding.run_id == target_run.id)
    run = query.first()
    if not run:
        raise HTTPException(status_code=404, detail=f"Verification run '{run_id}' not found.")
    return run
