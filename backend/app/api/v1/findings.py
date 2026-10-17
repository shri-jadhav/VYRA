from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.scope import resolve_assessment_run
from backend.app.models.models import AuditLog, Finding
from backend.app.schemas.schemas import FindingRead, FindingStatusUpdate

router = APIRouter(prefix="/findings", tags=["Security Findings"])


@router.get("", response_model=list[FindingRead])
def list_findings(
    run_id: str | None = Query(None, description="Assessment run ID to scope findings"),
    severity: str | None = Query(None, description="CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL"),
    status: str | None = Query(None, description="OPEN, IN_REVIEW, ACCEPTED_RISK, REMEDIATED"),
    service: str | None = Query(None, description="Service, e.g. s3, iam, cloudtrail"),
    search: str | None = Query(None, description="Search term in title, resource or description"),
    db: Session = Depends(get_db)
):
    target_run = resolve_assessment_run(db, run_id=run_id)
    if not target_run:
        return []

    query = db.query(Finding).filter(Finding.run_id == target_run.id)

    if severity:
        query = query.filter(Finding.severity == severity.upper())
    if status:
        query = query.filter(Finding.status == status.upper())
    if service:
        query = query.filter(Finding.service == service.lower())
    if search:
        term = f"%{search}%"
        query = query.filter(
            (Finding.title.ilike(term)) |
            (Finding.resource_id.ilike(term)) |
            (Finding.description.ilike(term))
        )

    # Sort critical first, then high, medium, low
    severity_order = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFORMATIONAL": 5}
    findings = query.all()
    return sorted(findings, key=lambda f: (severity_order.get(f.severity, 99), f.last_seen), reverse=False)


@router.get("/{finding_id}", response_model=FindingRead)
def get_finding(
    finding_id: str,
    run_id: str | None = Query(None, description="Optional run ID to scope finding lookup"),
    db: Session = Depends(get_db)
):
    query = db.query(Finding).filter(Finding.id == finding_id)
    if run_id:
        target_run = resolve_assessment_run(db, run_id=run_id)
        query = query.filter(Finding.run_id == target_run.id)
    finding = query.first()
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")
    return finding


@router.patch("/{finding_id}/status", response_model=FindingRead)
def update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdate,
    run_id: str | None = Query(None, description="Optional run ID to scope finding lookup"),
    db: Session = Depends(get_db)
):
    query = db.query(Finding).filter(Finding.id == finding_id)
    if run_id:
        target_run = resolve_assessment_run(db, run_id=run_id)
        query = query.filter(Finding.run_id == target_run.id)
    finding = query.first()
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")

    old_status = finding.status
    new_status = payload.status.upper()
    valid_statuses = ["OPEN", "IN_REVIEW", "ACCEPTED_RISK", "REMEDIATED"]
    if new_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of {valid_statuses}")

    finding.status = new_status
    finding.last_seen = datetime.now(UTC)

    # Audit log
    db.add(AuditLog(
        actor="vyra-analyst",
        action="FINDING_STATUS_UPDATE",
        resource=finding_id,
        status="SUCCESS",
        details=f"Status changed from {old_status} to {new_status}. Justification: {payload.justification or 'None provided'}"
    ))

    db.commit()
    db.refresh(finding)
    return finding
