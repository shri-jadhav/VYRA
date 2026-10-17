import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy.orm import Session

from backend.app.collectors.aws_session import (
    AWSAccountIdentityError,
    AWSConfigurationError,
    AWSProfileConfigurationError,
    create_boto3_session,
    validate_caller_identity,
)
from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.core.scope import resolve_assessment_run
from backend.app.investigation.engine import InvestigationEngine
from backend.app.investigation.reports import InvestigationReportGenerator
from backend.app.models.models import Finding, InvestigationSession
from backend.app.schemas.schemas import (
    InvestigationSessionRead,
    InvestigationStartRequest,
)

logger = logging.getLogger("vyra.api.investigation")

router = APIRouter(prefix="/investigation", tags=["Investigation Workbench"])


@router.post("/start", response_model=InvestigationSessionRead)
def start_investigation(
    req: InvestigationStartRequest,
    db: Session = Depends(get_db),
):
    """
    Initiates a security regression investigation for an AWS resource or finding.
    Correlates observed findings with CloudTrail events, Config history,
    and Security Hub findings using deterministic attribution rules.
    """
    try:
        session = create_boto3_session(settings.AWS_PROFILE)
        if settings.VYRA_EXPECTED_AWS_ACCOUNT_ID:
            validate_caller_identity(session)
    except AWSProfileConfigurationError as pe:
        logger.error(f"AWS profile configuration error for investigation: {pe}")
        raise HTTPException(status_code=400, detail=f"AWS profile configuration error: {pe!s}")
    except AWSAccountIdentityError as aie:
        logger.error(f"AWS account identity error for investigation: {aie}")
        raise HTTPException(status_code=400, detail=f"AWS account identity error: {aie!s}")
    except AWSConfigurationError as ce:
        logger.error(f"AWS configuration error for investigation: {ce}")
        raise HTTPException(status_code=400, detail=f"AWS configuration error: {ce!s}")

    time_window_hours = min(max(req.lookback_days * 24, 1), 2160)  # up to 90 days

    try:
        investigation_session = InvestigationEngine.run_investigation(
            db=db,
            session=session,
            resource_id=req.resource_id,
            finding_id=req.finding_id,
            time_window_hours=time_window_hours,
            region=req.region or settings.AWS_DEFAULT_REGION,
        )
        return investigation_session
    except Exception as e:
        logger.exception(f"Failed to execute investigation: {e}")
        raise HTTPException(status_code=500, detail=f"Investigation failed: {str(e)}")


@router.get("/sessions", response_model=list[InvestigationSessionRead])
def list_investigation_sessions(
    run_id: str | None = Query(None, description="Assessment run ID to scope investigation sessions"),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """Lists past investigation sessions ordered by timestamp."""
    query = db.query(InvestigationSession)
    if run_id:
        target_run = resolve_assessment_run(db, run_id=run_id)
        if not target_run:
            return []
        finding_ids = db.query(Finding.id).filter(Finding.run_id == target_run.id).scalar_subquery()
        query = query.filter(
            (InvestigationSession.target_account == target_run.target_account) |
            (InvestigationSession.finding_id.in_(finding_ids))
        )
    return query.order_by(InvestigationSession.created_at.desc()).limit(limit).all()


@router.get("/{session_id}", response_model=InvestigationSessionRead)
def get_investigation_session(
    session_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves full details of an investigation session including timeline events and candidate causes."""
    session_obj = (
        db.query(InvestigationSession)
        .filter(InvestigationSession.id == session_id)
        .first()
    )
    if not session_obj:
        raise HTTPException(status_code=404, detail=f"Investigation session '{session_id}' not found.")
    return session_obj


@router.get("/{session_id}/report")
def export_investigation_report(
    session_id: str,
    format: str = Query("html", pattern="^(html|json|markdown)$"),
    db: Session = Depends(get_db),
):
    """Generates an exportable incident investigation report in HTML, Markdown, or JSON."""
    session_obj = (
        db.query(InvestigationSession)
        .filter(InvestigationSession.id == session_id)
        .first()
    )
    if not session_obj:
        raise HTTPException(status_code=404, detail=f"Investigation session '{session_id}' not found.")

    if format == "html":
        html_content = InvestigationReportGenerator.generate_html(session_obj)
        return HTMLResponse(
            content=html_content,
            headers={"Content-Disposition": f'inline; filename="vyra-incident-{session_id}.html"'},
        )
    elif format == "markdown":
        md_content = InvestigationReportGenerator.generate_markdown(session_obj)
        return PlainTextResponse(
            content=md_content,
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="vyra-incident-{session_id}.md"'},
        )
    else:  # json
        json_data = InvestigationReportGenerator.generate_json(session_obj)
        return json_data
