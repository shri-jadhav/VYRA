from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.scope import resolve_assessment_run
from backend.app.models.models import Finding, RemediationPlan
from backend.app.remediation.dry_run_service import DryRunRemediationService
from backend.app.schemas.schemas import RemediationApprovalRequest, RemediationPlanRead

router = APIRouter(prefix="/remediation", tags=["Remediation Workflow"])


@router.get("/plans", response_model=list[RemediationPlanRead])
def list_remediation_plans(
    run_id: str | None = Query(None, description="Assessment run ID to scope remediation plans"),
    status: str | None = Query(None, description="PROPOSED, APPROVED, REJECTED, VERIFIED"),
    db: Session = Depends(get_db)
):
    target_run = resolve_assessment_run(db, run_id=run_id)
    if not target_run:
        return []

    query = (
        db.query(RemediationPlan)
        .join(RemediationPlan.finding)
        .filter(Finding.run_id == target_run.id)
    )
    if status:
        query = query.filter(RemediationPlan.status == status.upper())
    return query.order_by(RemediationPlan.id.desc()).all()


@router.get("/plans/{plan_id}", response_model=RemediationPlanRead)
def get_remediation_plan(
    plan_id: str,
    run_id: str | None = Query(None, description="Optional assessment run ID to scope plan lookup"),
    db: Session = Depends(get_db),
):
    query = db.query(RemediationPlan).filter(RemediationPlan.id == plan_id)
    if run_id:
        target_run = resolve_assessment_run(db, run_id=run_id)
        query = query.join(RemediationPlan.finding).filter(Finding.run_id == target_run.id)
    plan = query.first()
    if not plan:
        raise HTTPException(status_code=404, detail=f"Remediation plan '{plan_id}' not found.")
    return plan


@router.post("/plans/{plan_id}/approve", response_model=RemediationPlanRead)
def approve_plan(plan_id: str, payload: RemediationApprovalRequest, db: Session = Depends(get_db)):
    try:
        updated = DryRunRemediationService.approve_plan(
            db=db,
            plan_id=plan_id,
            approver_name=payload.approver_name,
            action=payload.action,
            notes=payload.notes
        )
        return updated
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/plans/{plan_id}/reverify")
def reverify_plan(plan_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        result = DryRunRemediationService.reverify_finding(db=db, plan_id=plan_id)
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
