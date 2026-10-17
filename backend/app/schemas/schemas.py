from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AssessmentTriggerRequest(BaseModel):
    mode: str = Field(default="LIVE_AWS", description="LIVE_AWS or DEMO_FIXTURE")
    profile: str | None = Field(default="vyra-readonly", description="AWS profile name")
    region: str | None = Field(default="ap-south-1", description="AWS region")


class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    run_id: str
    account_id: str
    region: str
    service: str
    asset_type: str
    name: str
    arn: str
    first_seen: datetime
    last_seen: datetime
    configuration_data: dict[str, Any]


class ControlEvaluationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    run_id: str
    control_id: str
    title: str
    category: str
    severity: str
    status: str
    resource_id: str
    resource_arn: str
    rationale: str
    evidence_source: str
    timestamp: datetime
    remediation_guidance: str | None = None
    limitations: str | None = None
    evidence_data: dict[str, Any] = {}


class RemediationPlanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str
    title: str
    risk_explanation: str
    dry_run_action: str
    cli_command: str
    terraform_snippet: str
    status: str
    approver: str | None = None
    approved_at: datetime | None = None
    verification_timestamp: datetime | None = None
    verification_output: str | None = None


class RemediationApprovalRequest(BaseModel):
    approver_name: str
    action: str = Field(default="APPROVE", description="APPROVE or REJECT")
    notes: str | None = None


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    run_id: str
    control_id: str
    title: str
    description: str
    severity: str
    status: str
    resource_id: str
    resource_arn: str
    service: str
    first_seen: datetime
    last_seen: datetime
    risk_summary: str | None = None
    remediation_guidance: str | None = None
    evidence_reference: str | None = None
    verification_result: str
    remediations: list[RemediationPlanRead] = []


class FindingStatusUpdate(BaseModel):
    status: str = Field(..., description="OPEN, IN_REVIEW, ACCEPTED_RISK, REMEDIATED")
    justification: str | None = None


class AssessmentRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str
    mode: str
    target_account: str
    target_region: str
    profile_used: str
    total_assets: int
    total_controls: int
    passed_controls: int
    failed_controls: int
    error_controls: int
    unknown_controls: int
    not_configured_controls: int
    summary_metadata: dict[str, Any] = {}


class AuditLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    timestamp: datetime
    actor: str
    action: str
    resource: str | None = None
    status: str
    details: str | None = None


class HealthStatusResponse(BaseModel):
    status: str
    version: str
    app_name: str
    tagline: str
    aws_profile: str
    aws_auth_verified: bool
    aws_account_id: str | None = None
    aws_arn: str | None = None
    permissions_summary: dict[str, str]
    live_collection_enabled: bool
    dry_run_remediation_only: bool
    latest_run_id: str | None = None


class OverviewMetrics(BaseModel):
    run_id: str | None = None
    mode: str
    last_scan_time: datetime | None = None
    account_id: str
    region: str
    profile: str
    security_score: int
    total_assets: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    controls_passed: int
    controls_failed: int
    controls_error: int
    controls_not_configured: int
    active_integrations: int
    total_integrations: int
    remediations_proposed: int
    remediations_approved: int


# ============================================================================
# INVESTIGATION SCHEMAS
# ============================================================================

class InvestigationStartRequest(BaseModel):
    resource_id: str = Field(..., description="Resource ID, Name, or ARN to investigate")
    finding_id: str | None = Field(default=None, description="Optional finding ID to anchor investigation")
    region: str | None = Field(default="ap-south-1", description="AWS region")
    lookback_days: int = Field(default=90, description="CloudTrail lookback window in days (max 90)")
    environment_mode: str = Field(default="AUTO", description="LIVE_AWS, DEMO_FIXTURE, or AUTO")


class TimelineEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    timestamp: datetime
    event_type: str
    event_name: str
    actor: str
    source: str
    details: str
    payload: dict[str, Any] = {}


class CandidateExplanationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    event_id: str
    event_time: datetime
    event_name: str
    actor: str
    ranking: str
    confidence_score: int
    matched_resource: str
    operation_relevance: str
    property_changes: list[str] = []
    temporal_relationship: str
    rationale: str
    supporting_evidence: list[str] = []
    contradictory_evidence: list[str] = []
    missing_evidence: list[str] = []
    next_steps: list[str] = []


class InvestigationSessionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    created_at: datetime
    title: str
    status: str
    resource_id: str
    resource_arn: str | None = None
    finding_id: str | None = None
    target_account: str
    target_region: str
    time_window_start: datetime
    time_window_end: datetime
    summary: str | None = None
    baseline_config: dict[str, Any] = {}
    current_config: dict[str, Any] = {}
    config_diff: list[dict[str, Any]] = []
    blindspots: list[str] = []
    limitations: str | None = None
    next_steps: list[str] = []
    timeline_events: list[TimelineEventRead] = []
    candidate_explanations: list[CandidateExplanationRead] = []



# ============================================================================
# CONNECTOR SCHEMAS
# ============================================================================

class ConnectorCapabilityRead(BaseModel):
    service_id: str
    display_name: str
    category: str
    status: str
    status_details: str
    required_permissions: list[str]
    missing_permissions: list[str] = []
    supported_operations: list[str]
    telemetry_type: str = "STATUS_ONLY"
    data_retention_window: str | None = None
    cost_notes: str
    limitations: str
    coverage: dict[str, Any] = Field(default_factory=dict)
    last_checked_at: str | None = None



# ============================================================================
# PLAN GATE SCHEMAS
# ============================================================================

class PlanCheckRequest(BaseModel):
    source_filename: str = "terraform_plan.json"
    plan_content: dict[str, Any] | None = None
    plan_filepath: str | None = None


class PlanCheckRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    created_at: datetime
    source_filename: str
    status: str
    blocking_count: int
    warning_count: int
    unknown_count: int
    passed_count: int
    summary: str
    findings_data: list[dict[str, Any]] = []
    sarif_data: dict[str, Any] = {}


# ============================================================================
# VERIFICATION SCHEMAS
# ============================================================================

class VerificationRunRequest(BaseModel):
    finding_id: str = Field(..., description="Finding ID to verify")
    investigation_id: str | None = Field(default=None, description="Associated investigation ID")
    operator_note: str | None = Field(default=None, description="Operator note or ticket reference")


class VerificationRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    created_at: datetime
    investigation_id: str | None = None
    finding_id: str
    resource_id: str
    account_id: str
    outcome: str
    baseline_observation: dict[str, Any] = {}
    fresh_observation: dict[str, Any] = {}
    comparison_summary: str
    limitations: str | None = None
