from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.scope import resolve_assessment_run
from backend.app.engine.controls_registry import CONTROLS_REGISTRY
from backend.app.models.models import ControlEvaluation
from backend.app.schemas.schemas import ControlEvaluationRead

router = APIRouter(prefix="/controls", tags=["Security Controls"])


@router.get("/definitions")
def list_control_definitions():
    """Returns the registry of all versioned controls in VYRA."""
    return [
        {
            "control_id": c.control_id,
            "title": c.title,
            "category": c.category,
            "severity": c.severity,
            "description": c.description,
            "remediation_guidance": c.remediation_guidance,
            "limitations": c.limitations,
        }
        for c in CONTROLS_REGISTRY.values()
    ]


@router.get("/evaluations", response_model=list[ControlEvaluationRead])
def list_evaluations(
    run_id: str | None = Query(None, description="Assessment run ID"),
    status: str | None = Query(None, description="Filter by status: PASS, FAIL, UNKNOWN, NOT_CONFIGURED, ERROR, EXEMPT"),
    category: str | None = Query(None, description="Filter by category"),
    search: str | None = Query(None, description="Search term in title, resource or rationale"),
    db: Session = Depends(get_db)
):
    target_run = resolve_assessment_run(db, run_id=run_id)
    if not target_run:
        return []

    query = db.query(ControlEvaluation).filter(ControlEvaluation.run_id == target_run.id)

    if status:
        query = query.filter(ControlEvaluation.status == status.upper())
    if category:
        query = query.filter(ControlEvaluation.category == category)
    if search:
        term = f"%{search}%"
        query = query.filter(
            (ControlEvaluation.title.ilike(term)) |
            (ControlEvaluation.resource_id.ilike(term)) |
            (ControlEvaluation.rationale.ilike(term))
        )

    return query.order_by(ControlEvaluation.severity.asc(), ControlEvaluation.status.asc()).all()


@router.get("/evaluations/{evaluation_id}", response_model=ControlEvaluationRead)
def get_evaluation(
    evaluation_id: str,
    run_id: str | None = Query(None, description="Optional assessment run ID to scope evaluation lookup"),
    db: Session = Depends(get_db),
):
    query = db.query(ControlEvaluation).filter(ControlEvaluation.id == evaluation_id)
    if run_id:
        target_run = resolve_assessment_run(db, run_id=run_id)
        query = query.filter(ControlEvaluation.run_id == target_run.id)
    ev = query.first()
    if not ev:
        raise HTTPException(status_code=404, detail=f"Control evaluation '{evaluation_id}' not found.")
    return ev
