"""Assessment run scope resolver for VYRA.

Enforces strict run-level data isolation:
- If run_id is explicitly provided, it must refer to an existing assessment run.
  If not found, raises HTTPException(404, f"Assessment run '{run_id}' not found.").
- If run_id is None, resolves to the latest successfully completed assessment run
  (status == "COMPLETED", ordered by started_at DESC).
- If no completed run exists in the database, returns None (empty state).
"""

from fastapi import HTTPException
from sqlalchemy.orm import Session

from backend.app.models.models import AssessmentRun


def resolve_assessment_run(db: Session, run_id: str | None = None) -> AssessmentRun | None:
    """Resolve the assessment run context for scoping queries.

    Args:
        db: SQLAlchemy database session.
        run_id: Optional explicit run identifier.

    Returns:
        The matching AssessmentRun if resolved, or None if no completed run exists.

    Raises:
        HTTPException(404): If an explicit run_id was provided but not found in the DB.
    """
    if run_id:
        run = db.query(AssessmentRun).filter(AssessmentRun.id == run_id).first()
        if not run:
            raise HTTPException(
                status_code=404,
                detail=f"Assessment run '{run_id}' not found.",
            )
        return run

    # Default context: latest successfully completed run
    return (
        db.query(AssessmentRun)
        .filter(AssessmentRun.status == "COMPLETED")
        .order_by(AssessmentRun.started_at.desc())
        .first()
    )
