
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.scope import resolve_assessment_run
from backend.app.models.models import AuditLog, Finding
from backend.app.schemas.schemas import AuditLogRead

router = APIRouter(prefix="/audit", tags=["Audit Trail"])


@router.get("", response_model=list[AuditLogRead])
def list_audit_logs(
    run_id: str | None = Query(None, description="Optional assessment run ID to scope audit logs"),
    actor: str | None = Query(None, description="Filter by actor"),
    action: str | None = Query(None, description="Filter by action name"),
    limit: int = 100,
    db: Session = Depends(get_db)
):
    query = db.query(AuditLog)
    if run_id:
        target_run = resolve_assessment_run(db, run_id=run_id)
        if not target_run:
            return []
        finding_ids = db.query(Finding.id).filter(Finding.run_id == target_run.id).scalar_subquery()
        query = query.filter((AuditLog.resource == target_run.id) | (AuditLog.resource.in_(finding_ids)))
    if actor:
        query = query.filter(AuditLog.actor == actor)
    if action:
        query = query.filter(AuditLog.action == action)

    return query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
