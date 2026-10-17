import React, { useState } from 'react';
import { FileText, Download, ExternalLink, Code2 } from 'lucide-react';
import { api } from '../api/client';
import { AssessmentRun, OverviewMetrics } from '../types';
import { ModeBadge } from '../components/ui/Badge';

interface ReportsViewProps {
  metrics?: OverviewMetrics | null;
  runs: AssessmentRun[];
  selectedRunId?: string | null;
  onSelectRun?: (runId: string) => void;
}

export const ReportsView: React.FC<ReportsViewProps> = ({
  metrics,
  runs,
  selectedRunId,
  onSelectRun,
}) => {
  const [downloading, setDownloading] = useState<string | null>(null);

  const handleDownloadJson = async (runId?: string) => {
    const targetRunId = runId || selectedRunId || metrics?.run_id || undefined;
    setDownloading(targetRunId || 'json');
    try {
      const url = api.getJsonReportUrl(targetRunId);
      const res = await fetch(url);
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const downloadUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = `vyra-assessment-report-${targetRunId || Date.now()}.json`;
      a.click();
    } finally {
      setDownloading(null);
    }
  };

  const handleOpenHtml = (runId?: string) => {
    const targetRunId = runId || selectedRunId || metrics?.run_id || undefined;
    window.open(api.getHtmlReportUrl(targetRunId), '_blank');
  };

  return (
    <div className="p-6 space-y-5 max-w-7xl mx-auto font-sans animate-fade-in text-[#F5F5F7]">
      <div className="pb-3 border-b border-[#2A2A2A]">
        <div className="flex items-center space-x-2">
          <h1 className="text-lg font-semibold text-[#F5F5F7] tracking-tight">
            Compliance & Assessment Reports
          </h1>
          <span className="text-xs text-[#737378] font-mono">
            Audit Artifacts
          </span>
        </div>
        <p className="text-xs text-[#737378] mt-0.5">
          Export full assessment reports including control results, findings, evidence provenance, and limitations.
        </p>
      </div>

      {/* Export Options Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* HTML Executive Report Card */}
        <div className="p-5 rounded-2xl bg-[#101010] border border-[#2A2A2A] space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center space-x-3">
              <div className="p-2.5 rounded-xl bg-[#141414] border border-[#2A2A2A] text-[#F5F5F7]">
                <FileText className="w-5 h-5 text-white" />
              </div>
              <div>
                <h3 className="font-semibold text-sm text-[#F5F5F7]">HTML Executive Audit Report</h3>
                <p className="text-xs text-[#737378]">Formatted for executive briefings, external auditors, and SOC2 evidence.</p>
              </div>
            </div>

            <div className="text-xs font-mono text-[#737378] space-y-1.5 p-3.5 rounded-xl bg-[#141414] border border-[#2A2A2A]">
              <div className="flex justify-between">
                <span>Theme:</span>
                <span className="text-[#F5F5F7]">Apple Native Monochrome</span>
              </div>
              <div className="flex justify-between">
                <span>Contents:</span>
                <span className="text-[#D6D6D6]">Provenance, Controls, Findings, Verification</span>
              </div>
              <div className="flex justify-between">
                <span>Render:</span>
                <span className="text-[#F5F5F7]">Jinja2 Template Engine</span>
              </div>
            </div>
          </div>

          <button
            onClick={() => handleOpenHtml()}
            className="w-full flex items-center justify-center space-x-2 py-2 rounded-xl text-xs font-semibold bg-[#FFFFFF] hover:bg-[#D6D6D6] text-black transition-colors shadow-sm"
          >
            <ExternalLink className="w-3.5 h-3.5" />
            <span>Open & Print HTML Report</span>
          </button>
        </div>

        {/* JSON Machine-Readable Report Card */}
        <div className="p-5 rounded-2xl bg-[#101010] border border-[#2A2A2A] space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center space-x-3">
              <div className="p-2.5 rounded-xl bg-[#141414] border border-[#2A2A2A] text-[#F5F5F7]">
                <Code2 className="w-5 h-5 text-[#A1A1A6]" />
              </div>
              <div>
                <h3 className="font-semibold text-sm text-[#F5F5F7]">Raw JSON Assessment Artifact</h3>
                <p className="text-xs text-[#737378]">Machine-readable data for SIEM ingestion, CI pipelines, and automated reporting.</p>
              </div>
            </div>

            <div className="text-xs font-mono text-[#737378] space-y-1.5 p-3.5 rounded-xl bg-[#141414] border border-[#2A2A2A]">
              <div className="flex justify-between">
                <span>Format:</span>
                <span className="text-[#F5F5F7]">RFC 8259 Standard JSON</span>
              </div>
              <div className="flex justify-between">
                <span>Sanitization:</span>
                <span className="text-white font-medium">Strict Secret Redaction Active</span>
              </div>
              <div className="flex justify-between">
                <span>Timestamp:</span>
                <span className="text-[#F5F5F7]">ISO 8601 UTC</span>
              </div>
            </div>
          </div>

          <button
            onClick={() => handleDownloadJson()}
            disabled={downloading === 'json'}
            className="w-full flex items-center justify-center space-x-2 py-2 rounded-xl text-xs font-medium bg-[#141414] hover:bg-[#202020] border border-[#2A2A2A] text-[#F5F5F7] transition-colors disabled:opacity-40"
          >
            <Download className="w-3.5 h-3.5 text-[#A1A1A6]" />
            <span>{downloading === 'json' ? 'Generating...' : 'Download JSON Artifact'}</span>
          </button>
        </div>
      </div>

      {/* Historical Assessment Runs */}
      <div className="rounded-2xl bg-[#101010] border border-[#2A2A2A] p-4 space-y-3">
        <div className="flex justify-between items-center">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F7]">
            Historical Assessment Runs
          </h3>
          <span className="text-[11px] font-mono text-[#737378]">
            {runs.length} recorded runs
          </span>
        </div>

        <div className="border border-[#2A2A2A] rounded-xl overflow-hidden">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#141414] border-b border-[#2A2A2A] text-[#737378] text-[10px] uppercase tracking-wider">
              <tr>
                <th className="p-3">Run ID</th>
                <th className="p-3">Mode</th>
                <th className="p-3">Target Account</th>
                <th className="p-3">Region</th>
                <th className="p-3">Controls (Pass / Fail)</th>
                <th className="p-3">Started At</th>
                <th className="p-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2A2A2A]">
              {runs.map((r) => {
                const isActive = selectedRunId === r.id;
                return (
                  <tr
                    key={r.id}
                    className={`hover:bg-[#181818] transition-colors ${isActive ? 'bg-[#181818]' : ''}`}
                  >
                    <td className="p-3 font-semibold text-[#F5F5F7]">
                      <div className="flex items-center space-x-2">
                        <span>{r.id}</span>
                        {isActive && (
                          <span className="text-[9px] px-2 py-0.5 rounded-full bg-[#252525] border border-[#3A3A3A] text-white">
                            Active
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="p-3">
                      <ModeBadge mode={r.mode} />
                    </td>
                    <td className="p-3 text-[#A1A1A6]">{r.target_account}</td>
                    <td className="p-3 text-[#737378]">{r.target_region}</td>
                    <td className="p-3">
                      <span className="text-white font-bold">{r.passed_controls}</span>
                      <span className="text-[#737378]"> / </span>
                      <span className="text-[#A1A1A6] font-semibold">{r.failed_controls}</span>
                    </td>
                    <td className="p-3 text-[#737378] text-[10px]">
                      {new Date(r.started_at).toUTCString()}
                    </td>
                    <td className="p-3 text-right space-x-1.5">
                      {onSelectRun && (
                        <button
                          onClick={() => onSelectRun(r.id)}
                          className="px-2.5 py-1 rounded-lg bg-[#141414] hover:bg-[#202020] border border-[#2A2A2A] text-xs text-[#F5F5F7] transition-colors"
                          title="View dashboard for this run"
                        >
                          Select
                        </button>
                      )}
                      <button
                        onClick={() => handleOpenHtml(r.id)}
                        className="px-2.5 py-1 rounded-lg bg-[#141414] hover:bg-[#202020] border border-[#2A2A2A] text-xs text-[#A1A1A6] hover:text-white transition-colors"
                        title="Open HTML report for this run"
                      >
                        HTML
                      </button>
                      <button
                        onClick={() => handleDownloadJson(r.id)}
                        className="px-2.5 py-1 rounded-lg bg-[#141414] hover:bg-[#202020] border border-[#2A2A2A] text-xs text-[#A1A1A6] hover:text-white transition-colors"
                        title="Download JSON artifact for this run"
                      >
                        JSON
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
