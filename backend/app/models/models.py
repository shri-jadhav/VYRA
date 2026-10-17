import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from backend.app.core.database import Base


def gen_uuid() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(UTC)


class AssessmentRun(Base):
    __tablename__ = "assessment_runs"

    id = Column(String(64), primary_key=True, default=gen_uuid)
    started_at = Column(DateTime, default=utc_now, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(32), default="RUNNING")  # RUNNING, COMPLETED, FAILED
    mode = Column(String(32), default="LIVE_AWS")   # LIVE_AWS, DEMO_FIXTURE
    target_account = Column(String(64), default="unknown")
    target_region = Column(String(64), default="unknown")
    profile_used = Column(String(64), default="vyra-readonly")
    total_assets = Column(Integer, default=0)
    total_controls = Column(Integer, default=0)
    passed_controls = Column(Integer, default=0)
    failed_controls = Column(Integer, default=0)
    error_controls = Column(Integer, default=0)
    unknown_controls = Column(Integer, default=0)
    not_configured_controls = Column(Integer, default=0)
    summary_metadata = Column(JSON, default=dict)

    evaluations = relationship("ControlEvaluation", back_populates="assessment_run", cascade="all, delete-orphan")
    assets = relationship("Asset", back_populates="assessment_run", cascade="all, delete-orphan")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(String(128), primary_key=True)
    run_id = Column(String(64), ForeignKey("assessment_runs.id"), nullable=False)
    account_id = Column(String(64), default="unknown")
    region = Column(String(64), default="unknown")
    service = Column(String(32), nullable=False)  # s3, iam, cloudtrail, security_services
    asset_type = Column(String(64), nullable=False)  # s3:bucket, iam:user, iam:role, cloudtrail:trail
    name = Column(String(256), nullable=False)
    arn = Column(String(512), nullable=False)
    first_seen = Column(DateTime, default=utc_now)
    last_seen = Column(DateTime, default=utc_now)
    configuration_data = Column(JSON, default=dict)

    assessment_run = relationship("AssessmentRun", back_populates="assets")


class ControlEvaluation(Base):
    __tablename__ = "control_evaluations"

    id = Column(String(64), primary_key=True, default=gen_uuid)
    run_id = Column(String(64), ForeignKey("assessment_runs.id"), nullable=False)
    control_id = Column(String(64), nullable=False)  # e.g., VYRA-S3-001
    title = Column(String(256), nullable=False)
    category = Column(String(64), nullable=False)
    severity = Column(String(32), nullable=False)    # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    status = Column(String(32), nullable=False)      # PASS, FAIL, UNKNOWN, NOT_CONFIGURED, ERROR, EXEMPT
    resource_id = Column(String(256), nullable=False)
    resource_arn = Column(String(512), nullable=False)
    rationale = Column(Text, nullable=False)
    evidence_source = Column(String(256), nullable=False)
    timestamp = Column(DateTime, default=utc_now)
    remediation_guidance = Column(Text, nullable=True)
    limitations = Column(Text, nullable=True)
    evidence_data = Column(JSON, default=dict)

    assessment_run = relationship("AssessmentRun", back_populates="evaluations")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(64), primary_key=True)  # e.g., FND-VYRA-S3-001-drainsentinel-web
    run_id = Column(String(64), nullable=False)
    control_id = Column(String(64), nullable=False)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(32), nullable=False)    # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    status = Column(String(32), default="OPEN")      # OPEN, IN_REVIEW, ACCEPTED_RISK, REMEDIATED
    resource_id = Column(String(256), nullable=False)
    resource_arn = Column(String(512), nullable=False)
    service = Column(String(32), nullable=False)
    first_seen = Column(DateTime, default=utc_now)
    last_seen = Column(DateTime, default=utc_now)
    risk_summary = Column(Text, nullable=True)
    remediation_guidance = Column(Text, nullable=True)
    evidence_reference = Column(String(256), nullable=True)
    verification_result = Column(String(64), default="PENDING_VERIFICATION")

    remediations = relationship("RemediationPlan", back_populates="finding", cascade="all, delete-orphan")


class RemediationPlan(Base):
    __tablename__ = "remediation_plans"

    id = Column(String(64), primary_key=True, default=gen_uuid)
    finding_id = Column(String(64), ForeignKey("findings.id"), nullable=False)
    title = Column(String(256), nullable=False)
    risk_explanation = Column(Text, nullable=False)
    dry_run_action = Column(Text, nullable=False)
    cli_command = Column(Text, nullable=False)
    terraform_snippet = Column(Text, nullable=False)
    status = Column(String(32), default="PROPOSED")  # PROPOSED, APPROVED, REJECTED, VERIFIED
    approver = Column(String(128), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    verification_timestamp = Column(DateTime, nullable=True)
    verification_output = Column(Text, nullable=True)

    finding = relationship("Finding", back_populates="remediations")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(64), primary_key=True, default=gen_uuid)
    timestamp = Column(DateTime, default=utc_now)
    actor = Column(String(128), default="vyra-system")
    action = Column(String(128), nullable=False)
    resource = Column(String(256), nullable=True)
    status = Column(String(32), default="SUCCESS")  # SUCCESS, DENIED, ERROR
    details = Column(Text, nullable=True)


# ============================================================================
# CLOUD CHANGE INVESTIGATOR & REGRESSION ENGINE MODELS
# ============================================================================

class InvestigationSession(Base):
    __tablename__ = "investigation_sessions"

    id = Column(String(64), primary_key=True, default=gen_uuid)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    title = Column(String(256), nullable=False)
    finding_id = Column(String(64), nullable=True)
    resource_id = Column(String(256), nullable=False)
    resource_arn = Column(String(512), nullable=True)
    target_account = Column(String(64), nullable=False)
    target_region = Column(String(64), nullable=False)
    time_window_start = Column(DateTime, nullable=False)
    time_window_end = Column(DateTime, nullable=False)
    status = Column(String(32), default="COMPLETED")  # IN_PROGRESS, COMPLETED, INSUFFICIENT_EVIDENCE, ERROR
    summary = Column(Text, nullable=True)
    baseline_config = Column(JSON, default=dict)
    current_config = Column(JSON, default=dict)
    config_diff = Column(JSON, default=list)
    blindspots = Column(JSON, default=list)
    limitations = Column(Text, nullable=True)
    next_steps = Column(JSON, default=list)

    timeline_events = relationship("TimelineEvent", back_populates="investigation", cascade="all, delete-orphan")
    candidate_explanations = relationship("CandidateChangeExplanation", back_populates="investigation", cascade="all, delete-orphan")


class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id = Column(String(64), primary_key=True, default=gen_uuid)
    investigation_id = Column(String(64), ForeignKey("investigation_sessions.id"), nullable=False)
    timestamp = Column(DateTime, nullable=False)
    event_type = Column(String(32), nullable=False)  # API_CALL, CONFIG_CHANGE, FINDING_OBSERVED, VERIFICATION
    event_name = Column(String(128), nullable=False)
    actor = Column(String(256), nullable=False)
    source = Column(String(64), nullable=False)      # CloudTrail, AWS Config, Security Hub, VYRA Collector
    details = Column(Text, nullable=False)
    payload = Column(JSON, default=dict)

    investigation = relationship("InvestigationSession", back_populates="timeline_events")


class CandidateChangeExplanation(Base):
    __tablename__ = "candidate_change_explanations"

    id = Column(String(64), primary_key=True, default=gen_uuid)
    investigation_id = Column(String(64), ForeignKey("investigation_sessions.id"), nullable=False)
    event_id = Column(String(128), nullable=False)
    event_time = Column(DateTime, nullable=False)
    event_name = Column(String(128), nullable=False)
    actor = Column(String(256), nullable=False)
    ranking = Column(String(32), nullable=False)      # SUPPORTED_CANDIDATE, POSSIBLE, INSUFFICIENT_EVIDENCE, NOT_OBSERVED
    confidence_score = Column(Integer, default=0)     # 0 to 100
    matched_resource = Column(String(256), nullable=False)
    operation_relevance = Column(String(256), nullable=False)
    property_changes = Column(JSON, default=list)
    temporal_relationship = Column(String(256), nullable=False)
    rationale = Column(Text, nullable=False)
    supporting_evidence = Column(JSON, default=list)
    contradictory_evidence = Column(JSON, default=list)
    missing_evidence = Column(JSON, default=list)
    next_steps = Column(JSON, default=list)

    investigation = relationship("InvestigationSession", back_populates="candidate_explanations")


class PlanCheckRun(Base):
    __tablename__ = "plan_check_runs"

    id = Column(String(64), primary_key=True, default=gen_uuid)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    source_filename = Column(String(256), nullable=False)
    status = Column(String(32), nullable=False)       # PASSED, BLOCKED, ERROR
    blocking_count = Column(Integer, default=0)
    warning_count = Column(Integer, default=0)
    unknown_count = Column(Integer, default=0)
    passed_count = Column(Integer, default=0)
    summary = Column(Text, nullable=False)
    findings_data = Column(JSON, default=list)
    sarif_data = Column(JSON, default=dict)


class VerificationRun(Base):
    __tablename__ = "verification_runs"

    id = Column(String(64), primary_key=True, default=gen_uuid)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    investigation_id = Column(String(64), nullable=True)
    finding_id = Column(String(64), nullable=False)
    resource_id = Column(String(256), nullable=False)
    account_id = Column(String(64), nullable=False)
    outcome = Column(String(32), nullable=False)      # RESOLVED, STILL_PRESENT, REGRESSED, UNVERIFIABLE
    baseline_observation = Column(JSON, default=dict)
    fresh_observation = Column(JSON, default=dict)
    comparison_summary = Column(Text, nullable=False)
    limitations = Column(Text, nullable=True)
