import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.collectors.orchestrator import CollectorOrchestrator
from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.core.scope import resolve_assessment_run
from backend.app.engine.evaluator import ControlEvaluator
from backend.app.engine.finding_generator import FindingGenerator
from backend.app.fixtures.demo_data import get_demo_evidence_fixture
from backend.app.models.models import (
    AssessmentRun,
    Asset,
    AuditLog,
    Finding,
    RemediationPlan,
)
from backend.app.schemas.schemas import (
    AssessmentRunRead,
    AssessmentTriggerRequest,
    OverviewMetrics,
)

router = APIRouter(prefix="/assessment", tags=["Assessment Runs"])


@router.post("/trigger", response_model=AssessmentRunRead)
def trigger_assessment(req: AssessmentTriggerRequest, db: Session = Depends(get_db)):
    run_id = f"RUN-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:6]}"
    started_at = datetime.now(UTC)

    # Profile restriction: prevent callers from injecting arbitrary profile names
    target_profile = req.profile or settings.AWS_PROFILE
    if req.profile and req.profile != settings.AWS_PROFILE:
        raise HTTPException(
            status_code=400,
            detail=f"Unauthorized profile '{req.profile}'. Only the configured profile '{settings.AWS_PROFILE}' is permitted.",
        )

    # Safety check on live collection
    if req.mode == "LIVE_AWS":
        if not settings.ALLOW_LIVE_COLLECTION:
            raise HTTPException(status_code=403, detail="Live AWS collection is disabled by environment configuration.")
        if not settings.VYRA_EXPECTED_AWS_ACCOUNT_ID:
            raise HTTPException(
                status_code=400,
                detail="Expected AWS Account ID is not configured. Set VYRA_EXPECTED_AWS_ACCOUNT_ID in environment or .env before running live assessments.",
            )

    # Record Audit Event for start
    db.add(AuditLog(
        actor="vyra-operator",
        action="ASSESSMENT_STARTED",
        resource=run_id,
        status="SUCCESS",
        details=f"Triggered assessment in mode {req.mode} using profile {target_profile}"
    ))
    db.commit()

    run = AssessmentRun(
        id=run_id,
        started_at=started_at,
        status="RUNNING",
        mode=req.mode,
        profile_used=target_profile if req.mode == "LIVE_AWS" else "demo-benchmark-fixture",
        target_region=req.region or settings.AWS_DEFAULT_REGION
    )
    db.add(run)
    db.commit()

    try:
        if req.mode == "LIVE_AWS":
            orchestrator = CollectorOrchestrator(profile_name=target_profile, region_name=req.region)
            evidence = orchestrator.collect_all(run_id=run_id)
            run.target_account = evidence.get("sts", {}).get("account_id") or "unknown"
            run.target_region = req.region or settings.AWS_DEFAULT_REGION
        else:
            evidence = get_demo_evidence_fixture(run_id=run_id)
            run.target_account = evidence.get("sts", {}).get("account_id") or "112233445566-DEMO"
            run.target_region = evidence.get("region") or "us-east-1"

        # Evaluate Controls & Discover Assets
        evaluator = ControlEvaluator(run_id=run_id, evidence=evidence)
        evaluations = evaluator.evaluate_all()
        assets = evaluator.extract_assets()

        # Persist Assets
        for asset in assets:
            existing_asset = db.query(Asset).filter(Asset.id == asset.id).first()
            if existing_asset:
                existing_asset.run_id = run_id
                existing_asset.last_seen = datetime.now(UTC)
                existing_asset.configuration_data = asset.configuration_data
            else:
                db.add(asset)

        # Persist Evaluations
        for ev in evaluations:
            db.add(ev)
        db.flush()

        # Generate / Update Findings
        FindingGenerator.process_evaluations(db, evaluations, run_id=run_id)

        # Update Run Metrics
        run.completed_at = datetime.now(UTC)
        run.status = "COMPLETED"
        run.total_assets = len(assets)
        run.total_controls = len(evaluations)
        run.passed_controls = sum(1 for e in evaluations if e.status == "PASS")
        run.failed_controls = sum(1 for e in evaluations if e.status == "FAIL")
        run.error_controls = sum(1 for e in evaluations if e.status == "ERROR")
        run.unknown_controls = sum(1 for e in evaluations if e.status == "UNKNOWN")
        run.not_configured_controls = sum(1 for e in evaluations if e.status == "NOT_CONFIGURED")
        run.summary_metadata = {
            "s3_buckets_analyzed": len(evidence.get("s3", {}).get("buckets", [])),
            "iam_users_analyzed": len(evidence.get("iam", {}).get("users", [])),
            "cloudtrail_trails_analyzed": len(evidence.get("cloudtrail", {}).get("trails", [])),
        }

        db.add(AuditLog(
            actor="vyra-system",
            action="ASSESSMENT_COMPLETED",
            resource=run_id,
            status="SUCCESS",
            details=f"Completed assessment. Controls: {run.total_controls}, Failed: {run.failed_controls}, Passed: {run.passed_controls}"
        ))
        db.commit()
        db.refresh(run)
        return run

    except Exception as e:
        db.rollback()
        run.status = "FAILED"
        run.completed_at = datetime.now(UTC)
        db.add(run)
        db.add(AuditLog(
            actor="vyra-system",
            action="ASSESSMENT_FAILED",
            resource=run_id,
            status="ERROR",
            details=f"Assessment failed with exception: {e!s}"
        ))
        db.commit()
        raise HTTPException(status_code=500, detail=f"Assessment execution failed: {e!s}")


@router.get("/runs", response_model=list[AssessmentRunRead])
def list_runs(limit: int = 20, db: Session = Depends(get_db)):
    return db.query(AssessmentRun).order_by(AssessmentRun.started_at.desc()).limit(limit).all()


@router.get("/runs/{run_id}", response_model=AssessmentRunRead)
def get_run(run_id: str, db: Session = Depends(get_db)):
    run = db.query(AssessmentRun).filter(AssessmentRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail=f"Assessment run '{run_id}' not found.")
    return run


@router.get("/metrics", response_model=OverviewMetrics)
def get_overview_metrics(
    run_id: str | None = Query(None, description="Optional assessment run ID to scope metrics"),
    db: Session = Depends(get_db),
):
    target_run = resolve_assessment_run(db, run_id=run_id)

    if not target_run:
        return OverviewMetrics(
            run_id=None,
            mode="NOT_SCANNED",
            last_scan_time=None,
            account_id="N/A",
            region=settings.AWS_DEFAULT_REGION,
            profile=settings.AWS_PROFILE,
            security_score=0,
            total_assets=0,
            total_findings=0,
            critical_findings=0,
            high_findings=0,
            medium_findings=0,
            low_findings=0,
            controls_passed=0,
            controls_failed=0,
            controls_error=0,
            controls_not_configured=0,
            active_integrations=0,
            total_integrations=5,
            remediations_proposed=0,
            remediations_approved=0,
        )

    # Tally findings strictly scoped to this run
    findings = (
        db.query(Finding)
        .filter(Finding.run_id == target_run.id)
        .filter(Finding.status.in_(["OPEN", "IN_REVIEW"]))
        .all()
    )
    crit = sum(1 for f in findings if f.severity == "CRITICAL")
    high = sum(1 for f in findings if f.severity == "HIGH")
    med = sum(1 for f in findings if f.severity == "MEDIUM")
    low = sum(1 for f in findings if f.severity == "LOW")

    total_ctrl = target_run.total_controls or 1
    score = int((target_run.passed_controls / total_ctrl) * 100) if total_ctrl > 0 else 0

    # Tally remediation plans strictly scoped to this run via Finding
    plans = (
        db.query(RemediationPlan)
        .join(RemediationPlan.finding)
        .filter(Finding.run_id == target_run.id)
        .all()
    )
    proposed = sum(1 for p in plans if p.status == "PROPOSED")
    approved = sum(1 for p in plans if p.status == "APPROVED")

    return OverviewMetrics(
        run_id=target_run.id,
        mode=target_run.mode,
        last_scan_time=target_run.completed_at,
        account_id=target_run.target_account,
        region=target_run.target_region,
        profile=target_run.profile_used,
        security_score=score,
        total_assets=target_run.total_assets,
        total_findings=len(findings),
        critical_findings=crit,
        high_findings=high,
        medium_findings=med,
        low_findings=low,
        controls_passed=target_run.passed_controls,
        controls_failed=target_run.failed_controls,
        controls_error=target_run.error_controls,
        controls_not_configured=target_run.not_configured_controls,
        active_integrations=3,  # Core active collectors
        total_integrations=5,
        remediations_proposed=proposed,
        remediations_approved=approved,
    )
