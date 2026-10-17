
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.scope import resolve_assessment_run
from backend.app.models.models import (
    AuditLog,
    ControlEvaluation,
    Finding,
)
from backend.app.reports.generator import ReportGenerator

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/json")
def get_json_report(run_id: str | None = Query(None), db: Session = Depends(get_db)):
    run = resolve_assessment_run(db, run_id=run_id)
    if not run:
        raise HTTPException(status_code=404, detail="No completed assessment run found to generate report.")

    evaluations = db.query(ControlEvaluation).filter(ControlEvaluation.run_id == run.id).all()
    findings = db.query(Finding).filter(Finding.run_id == run.id).all()

    # Log audit event
    db.add(AuditLog(
        actor="vyra-user",
        action="REPORT_EXPORT_JSON",
        resource=run.id,
        status="SUCCESS",
        details="Exported JSON assessment report"
    ))
    db.commit()

    return ReportGenerator.generate_json_report(run, evaluations, findings)


@router.get("/html")
def get_html_report(run_id: str | None = Query(None), db: Session = Depends(get_db)):
    run = resolve_assessment_run(db, run_id=run_id)
    if not run:
        raise HTTPException(status_code=404, detail="No completed assessment run found to generate report.")

    evaluations = db.query(ControlEvaluation).filter(ControlEvaluation.run_id == run.id).all()
    findings = db.query(Finding).filter(Finding.run_id == run.id).all()

    # Log audit event
    db.add(AuditLog(
        actor="vyra-user",
        action="REPORT_EXPORT_HTML",
        resource=run.id,
        status="SUCCESS",
        details="Generated HTML assessment report"
    ))
    db.commit()

    html_content = ReportGenerator.generate_html_report(run, evaluations, findings)
    return Response(content=html_content, media_type="text/html")
