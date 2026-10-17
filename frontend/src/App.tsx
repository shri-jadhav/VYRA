import React, { useState, useEffect, useCallback } from 'react';
import { api } from './api/client';
import {
  HealthStatus,
  OverviewMetrics,
  Asset,
  Finding,
  ControlEvaluation,
  RemediationPlan,
  AssessmentRun,
  AuditLog,
  FindingStatus,
} from './types';
import { Sidebar, NavTab } from './components/Sidebar';
import { Header } from './components/Header';
import { OverviewView } from './views/OverviewView';
import { AssetsView } from './views/AssetsView';
import { FindingsView } from './views/FindingsView';
import { ControlsView } from './views/ControlsView';
import { IntegrationsView } from './views/IntegrationsView';
import { VulnerabilitiesView } from './views/VulnerabilitiesView';
import { RemediationView } from './views/RemediationView';
import { ReportsView } from './views/ReportsView';
import { AuditTrailView } from './views/AuditTrailView';
import { SettingsView } from './views/SettingsView';
import { InvestigationsView } from './views/InvestigationsView';
import { PlanGateView } from './views/PlanGateView';
import { VerificationView } from './views/VerificationView';
import { ConnectorsView } from './views/ConnectorsView';
import { AlertCircle } from 'lucide-react';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<NavTab>('overview');
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [metrics, setMetrics] = useState<OverviewMetrics | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [evaluations, setEvaluations] = useState<ControlEvaluation[]>([]);
  const [remediations, setRemediations] = useState<RemediationPlan[]>([]);
  const [runs, setRuns] = useState<AssessmentRun[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const loadData = useCallback(async (explicitRunId?: string | null) => {
    setIsLoading(true);
    setError(null);
    try {
      const targetRunId = explicitRunId !== undefined ? explicitRunId : selectedRunId;
      const [h, m, r] = await Promise.all([
        api.getHealth(),
        api.getMetrics(targetRunId || undefined),
        api.listRuns(),
      ]);
      setHealth(h);
      setMetrics(m);
      setRuns(r);

      const activeRunId = targetRunId || m?.run_id || undefined;

      // Load collections scoped strictly to active run
      const [ast, fnd, evl, rem, aud] = await Promise.all([
        api.listAssets(undefined, undefined, activeRunId),
        api.listFindings(undefined, undefined, undefined, undefined, activeRunId),
        api.listEvaluations(undefined, undefined, undefined, activeRunId),
        api.listRemediations(undefined, activeRunId),
        api.listAuditLogs(undefined, undefined, activeRunId),
      ]);
      setAssets(ast);
      setFindings(fnd);
      setEvaluations(evl);
      setRemediations(rem);
      setAuditLogs(aud);
    } catch (err: any) {
      console.error('Failed to load VYRA platform data:', err);
      setError(err.message || 'Could not connect to VYRA backend service.');
    } finally {
      setIsLoading(false);
    }
  }, [selectedRunId]);

  useEffect(() => {
    let ignore = false;
    (async () => {
      if (!ignore) {
        await loadData();
      }
    })();
    return () => {
      ignore = true;
    };
  }, [loadData]);

  const handleSelectRun = async (runId: string) => {
    setSelectedRunId(runId);
    await loadData(runId);
  };

  const handleRunLiveAssessment = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const newRun = await api.triggerAssessment('LIVE_AWS', 'vyra-readonly');
      setSelectedRunId(newRun.id);
      await loadData(newRun.id);
    } catch (err: any) {
      setError(`Live assessment failed: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRunDemoAssessment = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const newRun = await api.triggerAssessment('DEMO_FIXTURE');
      setSelectedRunId(newRun.id);
      await loadData(newRun.id);
    } catch (err: any) {
      setError(`Demo fixture failed: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleUpdateFindingStatus = async (
    findingId: string,
    status: FindingStatus,
    justification?: string
  ) => {
    try {
      await api.updateFindingStatus(
        findingId,
        status,
        justification,
        selectedRunId || metrics?.run_id || undefined
      );
      await loadData();
    } catch (err: any) {
      setError(`Failed to update finding status: ${err.message}`);
    }
  };

  const handleApproveRemediation = async (
    planId: string,
    approverName: string,
    action: 'APPROVE' | 'REJECT',
    notes?: string
  ) => {
    try {
      await api.approveRemediation(planId, approverName, action, notes);
      await loadData();
    } catch (err: any) {
      setError(`Remediation action failed: ${err.message}`);
    }
  };

  const handleReverifyRemediation = async (planId: string) => {
    try {
      const res = await api.reverifyRemediation(planId);
      await loadData();
      return res;
    } catch (err: any) {
      setError(`Re-verification query failed: ${err.message}`);
      throw err;
    }
  };

  const getTabTitle = () => {
    switch (currentTab) {
      case 'overview':
        return 'Security Posture Overview';
      case 'assets':
        return 'Discovered Cloud Assets';
      case 'findings':
        return 'Security Findings & Evidence';
      case 'controls':
        return 'Controls Evaluation Baseline';
      case 'integrations':
        return 'Telemetry & Integrations';
      case 'vulnerabilities':
        return 'Threat Vectors & MITRE Matrix';
      case 'investigations':
        return 'Cloud Change Investigator';
      case 'plangate':
        return 'Pre-Deployment Security Gate';
      case 'verification':
        return 'After-Fix Verification Workbench';
      case 'connectors':
        return 'Modular AWS Connectors Matrix';
      case 'remediation':
        return 'Dry-Run Remediation Workspace';
      case 'reports':
        return 'Compliance & Audit Reports';
      case 'audit':
        return 'Application Audit Trail';
      case 'settings':
        return 'Platform Settings & Guardrails';
      default:
        return 'VYRA Security Workbench';
    }
  };

  return (
    <div className="flex h-screen bg-[#000000] text-[#F5F5F7] overflow-hidden font-sans antialiased select-none">
      {/* Sidebar Navigation */}
      <Sidebar
        currentTab={currentTab}
        onTabChange={setCurrentTab}
        metrics={metrics}
        health={health}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden bg-[#000000]">
        {/* Top Header */}
        <Header
          title={getTabTitle()}
          metrics={metrics}
          health={health}
          isLoading={isLoading}
          onRunLiveAssessment={handleRunLiveAssessment}
          onRunDemoAssessment={handleRunDemoAssessment}
          onRefresh={loadData}
        />

        {/* Global Error Banner */}
        {error && (
          <div className="bg-[#181818] border-b border-[#3A3A3A] px-4 py-2 flex items-center justify-between text-xs text-[#F5F5F7] shrink-0">
            <div className="flex items-center space-x-2">
              <AlertCircle className="w-3.5 h-3.5 text-white shrink-0" />
              <span className="font-mono text-[11px]">{error}</span>
            </div>
            <button
              onClick={() => setError(null)}
              className="text-xs font-mono text-[#A1A1A6] hover:text-white ml-4"
            >
              [Dismiss]
            </button>
          </div>
        )}

        {/* Tab View Content */}
        <main className="flex-1 overflow-y-auto bg-[#000000]">
          {currentTab === 'overview' && (
            <OverviewView
              metrics={metrics}
              findings={findings}
              evaluations={evaluations}
              onNavigate={setCurrentTab}
              onRunLiveAssessment={handleRunLiveAssessment}
              onRunDemoAssessment={handleRunDemoAssessment}
            />
          )}

          {currentTab === 'investigations' && (
            <InvestigationsView findings={findings} runId={selectedRunId || metrics?.run_id} />
          )}

          {currentTab === 'plangate' && <PlanGateView />}

          {currentTab === 'verification' && (
            <VerificationView
              findings={findings}
              runId={selectedRunId || metrics?.run_id}
              onRefresh={loadData}
            />
          )}

          {currentTab === 'connectors' && <ConnectorsView />}

          {currentTab === 'assets' && <AssetsView assets={assets} isLoading={isLoading} />}

          {currentTab === 'findings' && (
            <FindingsView
              findings={findings}
              isLoading={isLoading}
              onUpdateStatus={handleUpdateFindingStatus}
              onNavigate={setCurrentTab}
            />
          )}

          {currentTab === 'controls' && (
            <ControlsView evaluations={evaluations} isLoading={isLoading} />
          )}

          {currentTab === 'integrations' && (
            <IntegrationsView health={health} metrics={metrics} />
          )}

          {currentTab === 'vulnerabilities' && (
            <VulnerabilitiesView findings={findings} metrics={metrics} />
          )}

          {currentTab === 'remediation' && (
            <RemediationView
              remediations={remediations}
              isLoading={isLoading}
              onApprove={handleApproveRemediation}
              onReverify={handleReverifyRemediation}
            />
          )}

          {currentTab === 'reports' && (
            <ReportsView
              metrics={metrics}
              runs={runs}
              selectedRunId={selectedRunId}
              onSelectRun={handleSelectRun}
            />
          )}

          {currentTab === 'audit' && <AuditTrailView logs={auditLogs} isLoading={isLoading} />}

          {currentTab === 'settings' && <SettingsView health={health} />}
        </main>
      </div>
    </div>
  );
};

export default App;
