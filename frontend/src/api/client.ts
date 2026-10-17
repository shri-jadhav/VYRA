import {
  HealthStatus,
  OverviewMetrics,
  Asset,
  ControlEvaluation,
  Finding,
  RemediationPlan,
  AssessmentRun,
  AuditLog,
  InvestigationSession,
  ConnectorCapability,
  PlanCheckRun,
  VerificationRun,
} from '../types';

const BASE_URL = '/api/v1';

async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${BASE_URL}${url}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    let errorDetail = errorText;
    try {
      const parsed = JSON.parse(errorText);
      errorDetail = parsed.detail || errorText;
    } catch {
      // Keep raw text
    }
    throw new Error(errorDetail || `HTTP error ${response.status}`);
  }

  return response.json();
}

export const api = {
  // Health
  getHealth: () => fetchJson<HealthStatus>('/health'),

  // Assessment & Metrics
  getMetrics: (runId?: string) => {
    const params = new URLSearchParams();
    if (runId) params.set('run_id', runId);
    const q = params.toString() ? `?${params.toString()}` : '';
    return fetchJson<OverviewMetrics>(`/assessment/metrics${q}`);
  },
  listRuns: () => fetchJson<AssessmentRun[]>('/assessment/runs'),
  triggerAssessment: (mode: 'LIVE_AWS' | 'DEMO_FIXTURE', profile = 'vyra-readonly', region = 'ap-south-1') =>
    fetchJson<AssessmentRun>('/assessment/trigger', {
      method: 'POST',
      body: JSON.stringify({ mode, profile, region }),
    }),

  // Assets
  listAssets: (service?: string, search?: string, runId?: string) => {
    const params = new URLSearchParams();
    if (service) params.set('service', service);
    if (search) params.set('search', search);
    if (runId) params.set('run_id', runId);
    const q = params.toString() ? `?${params.toString()}` : '';
    return fetchJson<Asset[]>(`/assets${q}`);
  },

  // Controls
  listControlDefinitions: () => fetchJson<any[]>('/controls/definitions'),
  listEvaluations: (status?: string, category?: string, search?: string, runId?: string) => {
    const params = new URLSearchParams();
    if (status) params.set('status', status);
    if (category) params.set('category', category);
    if (search) params.set('search', search);
    if (runId) params.set('run_id', runId);
    const q = params.toString() ? `?${params.toString()}` : '';
    return fetchJson<ControlEvaluation[]>(`/controls/evaluations${q}`);
  },

  // Findings
  listFindings: (severity?: string, status?: string, service?: string, search?: string, runId?: string) => {
    const params = new URLSearchParams();
    if (severity) params.set('severity', severity);
    if (status) params.set('status', status);
    if (service) params.set('service', service);
    if (search) params.set('search', search);
    if (runId) params.set('run_id', runId);
    const q = params.toString() ? `?${params.toString()}` : '';
    return fetchJson<Finding[]>(`/findings${q}`);
  },
  getFinding: (id: string, runId?: string) => {
    const params = new URLSearchParams();
    if (runId) params.set('run_id', runId);
    const q = params.toString() ? `?${params.toString()}` : '';
    return fetchJson<Finding>(`/findings/${id}${q}`);
  },
  updateFindingStatus: (id: string, status: string, justification?: string, runId?: string) => {
    const params = new URLSearchParams();
    if (runId) params.set('run_id', runId);
    const q = params.toString() ? `?${params.toString()}` : '';
    return fetchJson<Finding>(`/findings/${id}/status${q}`, {
      method: 'PATCH',
      body: JSON.stringify({ status, justification }),
    });
  },

  // Remediation
  listRemediations: (status?: string, runId?: string) => {
    const params = new URLSearchParams();
    if (status) params.set('status', status);
    if (runId) params.set('run_id', runId);
    const q = params.toString() ? `?${params.toString()}` : '';
    return fetchJson<RemediationPlan[]>(`/remediation/plans${q}`);
  },
  approveRemediation: (planId: string, approverName: string, action: 'APPROVE' | 'REJECT', notes?: string) =>
    fetchJson<RemediationPlan>(`/remediation/plans/${planId}/approve`, {
      method: 'POST',
      body: JSON.stringify({ approver_name: approverName, action, notes }),
    }),
  reverifyRemediation: (planId: string) =>
    fetchJson<any>(`/remediation/plans/${planId}/reverify`, {
      method: 'POST',
    }),

  // Investigation Workbench (Workflow A)
  startInvestigation: (resourceId: string, findingId?: string, region = 'ap-south-1', lookbackDays = 90) =>
    fetchJson<InvestigationSession>('/investigation/start', {
      method: 'POST',
      body: JSON.stringify({
        resource_id: resourceId,
        finding_id: findingId || null,
        region,
        lookback_days: lookbackDays,
      }),
    }),
  listInvestigationSessions: (limit = 20, runId?: string) => {
    const params = new URLSearchParams();
    params.set('limit', String(limit));
    if (runId) params.set('run_id', runId);
    return fetchJson<InvestigationSession[]>(`/investigation/sessions?${params.toString()}`);
  },
  getInvestigationSession: (sessionId: string) =>
    fetchJson<InvestigationSession>(`/investigation/${sessionId}`),
  getInvestigationReportUrl: (sessionId: string, format: 'html' | 'markdown' | 'json') =>
    `${BASE_URL}/investigation/${sessionId}/report?format=${format}`,

  // Connectors Matrix
  listConnectors: (region?: string) => {
    const params = new URLSearchParams();
    if (region) params.set('region', region);
    return fetchJson<ConnectorCapability[]>(`/connectors?${params.toString()}`);
  },
  getConnector: (serviceId: string, region?: string) => {
    const params = new URLSearchParams();
    if (region) params.set('region', region);
    return fetchJson<ConnectorCapability>(`/connectors/${serviceId}?${params.toString()}`);
  },

  // Pre-Deployment Plan Gate (Workflow B)
  evaluatePlan: (planPayload: { source_filename?: string; plan_content?: any; plan_filepath?: string }) =>
    fetchJson<PlanCheckRun>('/plan-check/evaluate', {
      method: 'POST',
      body: JSON.stringify(planPayload),
    }),
  listPlanRuns: (limit = 20) =>
    fetchJson<PlanCheckRun[]>(`/plan-check/runs?limit=${limit}`),
  getPlanRun: (runId: string) =>
    fetchJson<PlanCheckRun>(`/plan-check/runs/${runId}`),
  getPlanSarifUrl: (runId: string) =>
    `${BASE_URL}/plan-check/runs/${runId}/sarif`,

  // After-Fix Verification (Workflow C)
  runVerification: (findingId: string, investigationId?: string, operatorNote?: string) =>
    fetchJson<VerificationRun>('/verification/run', {
      method: 'POST',
      body: JSON.stringify({
        finding_id: findingId,
        investigation_id: investigationId || null,
        operator_note: operatorNote || null,
      }),
    }),
  listVerificationHistory: (findingId?: string, resourceId?: string, limit = 50, runId?: string) => {
    const params = new URLSearchParams();
    if (findingId) params.set('finding_id', findingId);
    if (resourceId) params.set('resource_id', resourceId);
    if (runId) params.set('run_id', runId);
    params.set('limit', String(limit));
    return fetchJson<VerificationRun[]>(`/verification/history?${params.toString()}`);
  },
  getVerificationRun: (runId: string) =>
    fetchJson<VerificationRun>(`/verification/${runId}`),

  // Reports
  getJsonReportUrl: (runId?: string) =>
    runId ? `${BASE_URL}/reports/json?run_id=${encodeURIComponent(runId)}` : `${BASE_URL}/reports/json`,
  getHtmlReportUrl: (runId?: string) =>
    runId ? `${BASE_URL}/reports/html?run_id=${encodeURIComponent(runId)}` : `${BASE_URL}/reports/html`,

  // Audit
  listAuditLogs: (actor?: string, action?: string, runId?: string) => {
    const params = new URLSearchParams();
    if (actor) params.set('actor', actor);
    if (action) params.set('action', action);
    if (runId) params.set('run_id', runId);
    return fetchJson<AuditLog[]>(`/audit?${params.toString()}`);
  },
};
