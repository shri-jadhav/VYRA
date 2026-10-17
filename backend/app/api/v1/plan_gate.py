import json
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.models import AuditLog, PlanCheckRun
from backend.app.plan_checker.checker import PlanChecker
from backend.app.schemas.schemas import PlanCheckRunRead

logger = logging.getLogger("vyra.api.plan_gate")

router = APIRouter(prefix="/plan-check", tags=["Pre-Deployment Plan Gate"])


@router.post("/evaluate", response_model=PlanCheckRunRead)
async def evaluate_plan_payload(
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Evaluates a Terraform plan JSON against security regression gate rules.
    Accepts either:
    1. A PlanCheckRequest wrapping plan_content or plan_filepath
    2. A direct Terraform plan JSON object with 'resource_changes'
    """
    try:
        body = await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON request body: {e}")

    filename = "terraform_plan.json"
    plan_dict: dict[str, Any] = {}

    if "plan_content" in body and isinstance(body["plan_content"], dict):
        plan_dict = body["plan_content"]
        filename = body.get("source_filename", "terraform_plan.json")
    elif "plan_filepath" in body and body["plan_filepath"]:
        filepath = body["plan_filepath"]
        try:
            with open(filepath, encoding="utf-8") as f:
                plan_dict = json.load(f)
            filename = filepath
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to read plan file '{filepath}': {e}")
    elif "resource_changes" in body or "format_version" in body:
        # Direct raw Terraform plan JSON
        plan_dict = body
        filename = body.get("source_filename", "terraform_plan.json")
    else:
        raise HTTPException(
            status_code=400,
            detail="Expected either a Terraform plan JSON (with 'resource_changes') or an object with 'plan_content'/'plan_filepath'."
        )

    try:
        eval_result = PlanChecker.evaluate_plan_dict(plan_dict, filename=filename)
    except Exception as e:
        logger.exception(f"Plan evaluation error: {e}")
        raise HTTPException(status_code=500, detail=f"Error evaluating plan: {e}")

    run_id = f"PLAN-{uuid4().hex[:12].upper()}"
    run = PlanCheckRun(
        id=run_id,
        created_at=datetime.now(UTC),
        source_filename=filename,
        status=eval_result["status"],
        blocking_count=eval_result["blocking_count"],
        warning_count=eval_result["warning_count"],
        unknown_count=eval_result["unknown_count"],
        passed_count=eval_result["passed_count"],
        summary=eval_result["summary"],
        findings_data=eval_result["results"],
        sarif_data=eval_result["sarif"],
    )
    db.add(run)

    db.add(
        AuditLog(
            actor="vyra-ci-gate",
            action="PRE_DEPLOYMENT_PLAN_CHECK",
            resource=filename,
            status=eval_result["status"],
            details=eval_result["summary"],
        )
    )
    db.commit()
    db.refresh(run)
    return run



@router.get("/runs", response_model=list[PlanCheckRunRead])
def list_plan_runs(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """Lists recent pre-deployment plan check runs."""
    return (
        db.query(PlanCheckRun)
        .order_by(PlanCheckRun.created_at.desc())
        .limit(limit)
        .all()
    )


@router.get("/runs/{run_id}", response_model=PlanCheckRunRead)
def get_plan_run(
    run_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves details of a specific plan check run."""
    run = db.query(PlanCheckRun).filter(PlanCheckRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail=f"Plan check run '{run_id}' not found.")
    return run


@router.get("/runs/{run_id}/sarif")
def get_run_sarif(
    run_id: str,
    db: Session = Depends(get_db),
):
    """Downloads the OASIS SARIF v2.1.0 output for GitHub Security tab integration."""
    run = db.query(PlanCheckRun).filter(PlanCheckRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail=f"Plan check run '{run_id}' not found.")
    return JSONResponse(
        content=run.sarif_data,
        headers={"Content-Disposition": f'attachment; filename="vyra-{run_id}.sarif"'},
    )
