import React, { useState } from 'react';
import {
  ChevronRight,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  HelpCircle,
  XCircle,
  Play,
  Database,
} from 'lucide-react';
import { OverviewMetrics, Finding, ControlEvaluation } from '../types';
import { NavTab } from '../components/Sidebar';
import { SeverityBadge, ModeBadge } from '../components/ui/Badge';
import { VyraLogo } from '../components/VyraLogo';

interface OverviewViewProps {
  metrics: OverviewMetrics | null;
  findings: Finding[];
  evaluations?: ControlEvaluation[];
  onNavigate: (tab: NavTab) => void;
  onRunLiveAssessment: () => void;
  onRunDemoAssessment: () => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  metrics,
  findings,
  onNavigate,
  onRunLiveAssessment,
  onRunDemoAssessment,
}) => {
  const [activeTab, setActiveTab] = useState<'all' | 'critical'>('all');

  // Empty state when no assessment has been run yet
  if (!metrics || metrics.mode === 'NOT_SCANNED') {
    return (
      <div className="p-8 max-w-4xl mx-auto space-y-6 animate-fade-in font-sans">
        <div className="rounded-2xl bg-[#101010] border border-[#2A2A2A] p-8 text-center space-y-5">
          <div className="flex justify-center">
            <VyraLogo size={48} />
          </div>

          <div className="space-y-1">
            <h1 className="text-xl font-semibold text-[#F5F5F7] tracking-tight">
              Welcome to VYRA Security Workbench
            </h1>
            <p className="text-xs text-[#A1A1A6] font-mono">
              Find the change. Prevent the regression. Verify the fix.
            </p>
          </div>

          <p className="text-xs text-[#737378] max-w-lg mx-auto leading-relaxed">
            Continuous cloud security inspection engine. Observe AWS configurations, audit security baselines,
            attribute configuration drift from CloudTrail, and verify remediations with independent read-only checks.
          </p>

          <div className="flex items-center justify-center space-x-3 pt-2">
            <button
              onClick={onRunLiveAssessment}
              className="px-4 py-2 rounded-xl text-xs font-semibold bg-[#FFFFFF] hover:bg-[#D6D6D6] text-black transition-colors shadow-sm flex items-center space-x-1.5"
            >
              <Play className="w-3.5 h-3.5 fill-current text-black" />
              <span>Run Live AWS Assessment</span>
            </button>
            <button
              onClick={onRunDemoAssessment}
              className="px-4 py-2 rounded-xl text-xs font-medium bg-[#181818] border border-[#2A2A2A] text-[#F5F5F7] hover:bg-[#202020] transition-colors flex items-center space-x-1.5"
            >
              <Database className="w-3.5 h-3.5 text-[#A1A1A6]" />
              <span>Load Demo Benchmark Dataset</span>
            </button>
          </div>
        </div>
      </div>
    );
  }

  const criticalAndHigh = findings.filter(
    (f) => f.severity === 'CRITICAL' || f.severity === 'HIGH'
  );

  const displayedFindings = activeTab === 'critical' ? criticalAndHigh : findings;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans animate-fade-in text-[#F5F5F7]">
      {/* Assessment Provenance Header Bar */}
      <div className="rounded-2xl bg-[#101010] border border-[#2A2A2A] p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center space-x-3.5">
          <VyraLogo size={32} />
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-sm font-semibold text-[#F5F5F7] tracking-tight">
                Assessment Provenance
              </h2>
              <ModeBadge mode={metrics.mode} />
            </div>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-[#A1A1A6] mt-1 font-mono">
              <span>Account: <strong className="text-white">{metrics.account_id}</strong></span>
              <span className="text-[#3A3A3A]">&middot;</span>
              <span>Region: <strong className="text-white">{metrics.region}</strong></span>
              <span className="text-[#3A3A3A]">&middot;</span>
              <span>Evaluated: {metrics.last_scan_time ? new Date(metrics.last_scan_time).toUTCString() : 'N/A'}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-2 text-xs font-mono text-[#A1A1A6] shrink-0">
          <ShieldCheck className="w-3.5 h-3.5 text-[#F5F5F7]" />
          <span>Read-Only Guardrails Active</span>
        </div>
      </div>

      {/* Grouped Key Metrics Horizontal Summary */}
      <div className="rounded-2xl bg-[#101010] border border-[#2A2A2A] divide-y md:divide-y-0 md:divide-x divide-[#2A2A2A] grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5">
        {/* Compliance Score */}
        <div className="p-4 space-y-1">
          <span className="text-[11px] font-medium text-[#737378] uppercase tracking-wider block">
            Compliance Score
          </span>
          <div className="text-2xl font-bold font-mono text-[#F5F5F7]">
            {metrics.security_score}%
          </div>
          <div className="w-full bg-[#181818] h-1.5 rounded-full overflow-hidden mt-2">
            <div
              className="h-full bg-white rounded-full"
              style={{ width: `${Math.min(100, Math.max(0, metrics.security_score))}%` }}
            />
          </div>
          <span className="text-[10px] text-[#A1A1A6] block mt-1">Verified benchmark</span>
        </div>

        {/* Discovered Assets */}
        <div className="p-4 space-y-1">
          <span className="text-[11px] font-medium text-[#737378] uppercase tracking-wider block">
            Discovered Assets
          </span>
          <div className="text-2xl font-bold font-mono text-[#F5F5F7]">
            {metrics.total_assets}
          </div>
          <div className="flex items-center justify-between text-[11px] text-[#A1A1A6] pt-1">
            <span>S3, IAM, CloudTrail</span>
            <button
              onClick={() => onNavigate('assets')}
              className="text-[#F5F5F7] hover:underline"
            >
              View
            </button>
          </div>
        </div>

        {/* Active Security Findings */}
        <div className="p-4 space-y-1">
          <span className="text-[11px] font-medium text-[#737378] uppercase tracking-wider block">
            Active Findings
          </span>
          <div className="flex items-baseline space-x-2 font-mono">
            <span className="text-2xl font-bold text-white">{metrics.total_findings}</span>
            <span className="text-xs text-white font-semibold">
              ({metrics.critical_findings} Crit, {metrics.high_findings} High)
            </span>
          </div>
          <div className="flex items-center justify-between text-[11px] text-[#A1A1A6] pt-1">
            <span>Action Required</span>
            <button
              onClick={() => onNavigate('findings')}
              className="text-[#F5F5F7] hover:underline"
            >
              Triage
            </button>
          </div>
        </div>

        {/* Security Controls Posture */}
        <div className="p-4 space-y-1">
          <span className="text-[11px] font-medium text-[#737378] uppercase tracking-wider block">
            Controls Posture
          </span>
          <div className="flex items-baseline space-x-1.5 font-mono">
            <span className="text-2xl font-bold text-white">{metrics.controls_passed}</span>
            <span className="text-xs text-[#737378]">/</span>
            <span className="text-xs text-[#A1A1A6]">
              {metrics.controls_passed + metrics.controls_failed + metrics.controls_not_configured + metrics.controls_error}
            </span>
          </div>
          <div className="flex items-center justify-between text-[11px] text-[#A1A1A6] pt-1">
            <span>{metrics.controls_failed} failing</span>
            <button
              onClick={() => onNavigate('controls')}
              className="text-[#F5F5F7] hover:underline"
            >
              Inspect
            </button>
          </div>
        </div>

        {/* Remediation Workflows */}
        <div className="p-4 space-y-1">
          <span className="text-[11px] font-medium text-[#737378] uppercase tracking-wider block">
            Remediations
          </span>
          <div className="flex items-baseline space-x-2 font-mono">
            <span className="text-2xl font-bold text-white">{metrics.remediations_proposed}</span>
            <span className="text-xs text-[#A1A1A6]">({metrics.remediations_approved} approved)</span>
          </div>
          <div className="flex items-center justify-between text-[11px] text-[#A1A1A6] pt-1">
            <span>Terraform / CLI</span>
            <button
              onClick={() => onNavigate('remediation')}
              className="text-[#F5F5F7] hover:underline"
            >
              Review
            </button>
          </div>
        </div>
      </div>

      {/* Control Evaluation Counts Group */}
      <div className="rounded-2xl bg-[#101010] border border-[#2A2A2A] p-4 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-[#F5F5F7] uppercase tracking-wider">
            Controls Evaluation Baseline Breakdown
          </span>
          <button
            onClick={() => onNavigate('controls')}
            className="text-xs text-[#A1A1A6] hover:text-[#F5F5F7] hover:underline flex items-center space-x-1"
          >
            <span>All Controls</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
          <div className="p-3 rounded-xl bg-[#141414] border border-[#2A2A2A] flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <CheckCircle2 className="w-4 h-4 text-white" />
              <span className="text-[#F5F5F7]">PASS</span>
            </div>
            <span className="text-base font-bold text-white">{metrics.controls_passed}</span>
          </div>

          <div className="p-3 rounded-xl bg-[#141414] border border-[#2A2A2A] flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <XCircle className="w-4 h-4 text-white" />
              <span className="text-white font-semibold">FAIL</span>
            </div>
            <span className="text-base font-bold text-white">{metrics.controls_failed}</span>
          </div>

          <div className="p-3 rounded-xl bg-[#141414] border border-[#2A2A2A] flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 text-[#A1A1A6]" />
              <span className="text-[#A1A1A6]">UNCONFIGURED</span>
            </div>
            <span className="text-base font-medium text-[#A1A1A6]">{metrics.controls_not_configured}</span>
          </div>

          <div className="p-3 rounded-xl bg-[#141414] border border-[#2A2A2A] flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <HelpCircle className="w-4 h-4 text-[#737378]" />
              <span className="text-[#737378]">ERROR / DENIED</span>
            </div>
            <span className="text-base font-medium text-[#737378]">{metrics.controls_error}</span>
          </div>
        </div>
      </div>

      {/* Prioritized Security Findings Grouped Table */}
      <div className="space-y-3">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-semibold text-[#F5F5F7] tracking-tight">
              Security Findings & Prioritized Risks
            </h3>
            <span className="text-xs text-[#737378]">
              Showing {displayedFindings.length} findings
            </span>
          </div>

          {/* iOS Segmented Control */}
          <div className="bg-[#141414] p-1 rounded-xl border border-[#2A2A2A] flex space-x-1 text-xs">
            <button
              onClick={() => setActiveTab('all')}
              className={`px-3 py-1 rounded-lg transition-colors ${
                activeTab === 'all'
                  ? 'bg-[#222222] text-[#FFFFFF] font-medium shadow-sm'
                  : 'text-[#A1A1A6] hover:text-[#F5F5F7]'
              }`}
            >
              All ({findings.length})
            </button>
            <button
              onClick={() => setActiveTab('critical')}
              className={`px-3 py-1 rounded-lg transition-colors ${
                activeTab === 'critical'
                  ? 'bg-[#222222] text-[#FFFFFF] font-medium shadow-sm'
                  : 'text-[#A1A1A6] hover:text-[#F5F5F7]'
              }`}
            >
              Critical & High ({criticalAndHigh.length})
            </button>
          </div>
        </div>

        {/* Grouped Table */}
        <div className="bg-[#101010] border border-[#2A2A2A] rounded-2xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#141414] border-b border-[#2A2A2A] text-[#737378] text-[11px] font-semibold uppercase tracking-wider">
                <tr>
                  <th className="py-2.5 px-4">Severity</th>
                  <th className="py-2.5 px-4">Finding Name</th>
                  <th className="py-2.5 px-4">Control ID</th>
                  <th className="py-2.5 px-4">Resource Identifier</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#2A2A2A]">
                {displayedFindings.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-xs text-[#737378] font-mono">
                      No security findings in this filter.
                    </td>
                  </tr>
                ) : (
                  displayedFindings.map((f) => (
                    <tr
                      key={f.id}
                      onClick={() => onNavigate('findings')}
                      className="hover:bg-[#181818] cursor-pointer transition-colors"
                    >
                      <td className="py-3 px-4">
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="py-3 px-4 font-medium text-[#F5F5F7] max-w-sm">
                        <span className="hover:underline">{f.title}</span>
                        <div className="text-[11px] text-[#A1A1A6] line-clamp-1 mt-0.5 font-normal">
                          {f.description}
                        </div>
                      </td>
                      <td className="py-3 px-4 font-mono text-[#A1A1A6] text-[11px]">{f.control_id}</td>
                      <td className="py-3 px-4 font-mono text-[#F5F5F7] font-medium text-[11px] truncate max-w-[200px]" title={f.resource_id}>
                        {f.resource_id}
                      </td>
                      <td className="py-3 px-4">
                        <span className="text-[#A1A1A6] font-mono text-xs">{f.status}</span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onNavigate('remediation');
                          }}
                          className="text-[#F5F5F7] hover:underline font-medium text-xs inline-flex items-center space-x-1"
                        >
                          <span>Remediate</span>
                          <ChevronRight className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
