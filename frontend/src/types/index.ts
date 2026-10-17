export type ControlStatus = 'PASS' | 'FAIL' | 'UNKNOWN' | 'NOT_CONFIGURED' | 'ERROR' | 'EXEMPT';
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
export type FindingStatus = 'OPEN' | 'IN_REVIEW' | 'ACCEPTED_RISK' | 'REMEDIATED';
export type RemediationStatus = 'PROPOSED' | 'APPROVED' | 'REJECTED' | 'VERIFIED';

export interface HealthStatus {
  status: string;
  version: string;
  app_name: string;
  tagline: string;
  aws_profile: string;
  aws_auth_verified: boolean;
  aws_account_id: string | null;
  aws_arn: string | null;
  permissions_summary: Record<string, string>;
  live_collection_enabled: boolean;
  dry_run_remediation_only: boolean;
  latest_run_id: string | null;
}

export interface OverviewMetrics {
  run_id?: string | null;
  mode: string;
  last_scan_time: string | null;
  account_id: string;
  region: string;
  profile: string;
  security_score: number;
  total_assets: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  controls_passed: number;
  controls_failed: number;
  controls_error: number;
  controls_not_configured: number;
  active_integrations: number;
  total_integrations: number;
  remediations_proposed: number;
  remediations_approved: number;
}

export interface Asset {
  id: string;
  run_id: string;
  account_id: string;
  region: string;
  service: string;
  asset_type: string;
  name: string;
  arn: string;
  first_seen: string;
  last_seen: string;
  configuration_data: Record<string, any>;
}

export interface ControlEvaluation {
  id: string;
  run_id: string;
  control_id: string;
  title: string;
  category: string;
  severity: Severity;
  status: ControlStatus;
  resource_id: string;
  resource_arn: string;
  rationale: string;
  evidence_source: string;
  timestamp: string;
  remediation_guidance?: string;
  limitations?: string;
  evidence_data: Record<string, any>;
}

export interface RemediationPlan {
  id: string;
  finding_id: string;
  title: string;
  risk_explanation: string;
  dry_run_action: string;
  cli_command: string;
  terraform_snippet: string;
  status: RemediationStatus;
  approver?: string;
  approved_at?: string;
  verification_timestamp?: string;
  verification_output?: string;
}

export interface Finding {
  id: string;
  run_id: string;
  control_id: string;
  title: string;
  description: string;
  severity: Severity;
  status: FindingStatus;
  resource_id: string;
  resource_arn: string;
  service: string;
  first_seen: string;
  last_seen: string;
  risk_summary?: string;
  remediation_guidance?: string;
  evidence_reference?: string;
  verification_result: string;
  remediations: RemediationPlan[];
}

export interface AssessmentRun {
  id: string;
  started_at: string;
  completed_at?: string;
  status: string;
  mode: string;
  target_account: string;
  target_region: string;
  profile_used: string;
  total_assets: number;
  total_controls: number;
  passed_controls: number;
  failed_controls: number;
  error_controls: number;
  unknown_controls: number;
  not_configured_controls: number;
  summary_metadata: Record<string, any>;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  resource?: string;
  status: string;
  details?: string;
}

export type CandidateRanking =
  | 'SUPPORTED_CANDIDATE'
  | 'POSSIBLE'
  | 'INSUFFICIENT_EVIDENCE'
  | 'NOT_OBSERVED';

export interface CandidateExplanation {
  id: string;
  event_id: string;
  event_time: string;
  event_name: string;
  actor: string;
  ranking: CandidateRanking;
  confidence_score: number;
  matched_resource: string;
  operation_relevance: string;
  property_changes: string[];
  temporal_relationship: string;
  rationale: string;
  supporting_evidence: string[];
  contradictory_evidence: string[];
  missing_evidence: string[];
  next_steps: string[];
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  event_type: string;
  event_name: string;
  actor: string;
  source: string;
  details: string;
  payload: Record<string, any>;
}

export interface ConfigDiffItem {
  property: string;
  baseline_value: any;
  current_value: any;
  security_impact: 'REGRESSION' | 'IMPROVEMENT' | 'MODIFIED';
  description: string;
}

export interface InvestigationSession {
  id: string;
  created_at: string;
  title: string;
  status: string;
  resource_id: string;
  resource_arn?: string;
  finding_id?: string;
  target_account: string;
  target_region: string;
  time_window_start: string;
  time_window_end: string;
  summary?: string;
  baseline_config: Record<string, any>;
  current_config: Record<string, any>;
  config_diff: ConfigDiffItem[];
  blindspots: string[];
  limitations?: string;
  next_steps: string[];
  timeline_events: TimelineEvent[];
  candidate_explanations: CandidateExplanation[];
}

export interface ConnectorCapability {
  service_id: string;
  display_name: string;
  category: string;
  status: string;
  status_details: string;
  required_permissions: string[];
  missing_permissions: string[];
  supported_operations: string[];
  telemetry_type?: string;
  data_retention_window?: string;
  cost_notes: string;
  limitations: string;
  coverage?: Record<string, any>;
  last_checked_at?: string;
}


export interface GateRuleResult {
  rule_id: string;
  rule_title: string;
  severity: Severity;
  status: 'PASSED' | 'VIOLATION' | 'UNKNOWN';
  is_blocking: boolean;
  resource_address: string;
  resource_type: string;
  message: string;
  remediation_advice: string;
  property_path?: string;
}

export interface PlanCheckRun {
  id: string;
  created_at: string;
  source_filename: string;
  status: 'PASSED' | 'BLOCKED' | 'ERROR';
  blocking_count: number;
  warning_count: number;
  unknown_count: number;
  passed_count: number;
  summary: string;
  findings_data: GateRuleResult[];
  sarif_data: Record<string, any>;
}

export type VerificationOutcome =
  | 'RESOLVED'
  | 'STILL_PRESENT'
  | 'REGRESSED'
  | 'UNVERIFIABLE';

export interface VerificationRun {
  id: string;
  created_at: string;
  investigation_id?: string;
  finding_id: string;
  resource_id: string;
  account_id: string;
  outcome: VerificationOutcome;
  baseline_observation: Record<string, any>;
  fresh_observation: Record<string, any>;
  comparison_summary: string;
  limitations?: string;
}
