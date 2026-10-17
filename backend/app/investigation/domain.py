from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ConnectorStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    ENABLED = "AVAILABLE"
    DISABLED = "DISABLED"
    NOT_SUBSCRIBED = "NOT_SUBSCRIBED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    ACCESS_DENIED = "PERMISSION_DENIED"
    UNSUPPORTED_REGION = "UNSUPPORTED_REGION"
    ERROR = "ERROR"


class ConnectorCapability(BaseModel):
    service_id: str
    display_name: str
    category: str
    status: ConnectorStatus
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



class NormalizedCloudEvent(BaseModel):
    event_id: str
    event_time: str
    event_name: str
    event_source: str
    aws_region: str
    actor_arn: str | None = None
    actor_type: str | None = None
    actor_name: str | None = None
    source_ip: str | None = None
    user_agent: str | None = None
    resource_type: str
    resource_name: str
    resource_arn: str | None = None
    read_only: bool = False
    error_code: str | None = None
    request_parameters: dict[str, Any] = Field(default_factory=dict)
    response_elements: dict[str, Any] = Field(default_factory=dict)
    raw_event: dict[str, Any] = Field(default_factory=dict)


class CandidateRanking(StrEnum):
    SUPPORTED_CANDIDATE = "SUPPORTED_CANDIDATE"
    POSSIBLE = "POSSIBLE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    NOT_OBSERVED = "NOT_OBSERVED"


class CandidateExplanation(BaseModel):
    event_id: str
    event_time: str
    event_name: str
    actor_identity: str
    ranking: CandidateRanking
    confidence_score: int  # 0 to 100
    matched_resource: str
    operation_relevance: str
    property_changes: list[str] = Field(default_factory=list)
    temporal_relationship: str
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradictory_evidence: list[str] = Field(default_factory=list)
    rationale: str
    missing_evidence: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)


class VerificationOutcome(StrEnum):
    RESOLVED = "RESOLVED"
    STILL_PRESENT = "STILL_PRESENT"
    REGRESSED = "REGRESSED"
    UNVERIFIABLE = "UNVERIFIABLE"
