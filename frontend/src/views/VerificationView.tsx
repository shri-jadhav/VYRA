import React, { useState, useEffect, useCallback } from 'react';
import {
  CheckCircle,
  AlertTriangle,
  RotateCcw,
  ShieldCheck,
} from 'lucide-react';
import { api } from '../api/client';
import { Finding, VerificationRun } from '../types';
import { SeverityBadge, StatusBadge } from '../components/ui/Badge';

interface VerificationViewProps {
  findings: Finding[];
  runId?: string | null;
  onRefresh: () => void;
}

export const VerificationView: React.FC<VerificationViewProps> = ({ findings, runId, onRefresh }) => {
  const [history, setHistory] = useState<VerificationRun[]>([]);
  const [selectedRun, setSelectedRun] = useState<VerificationRun | null>(null);
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [operatorNote] = useState<string>('');
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const loadHistory = useCallback(async () => {
    try {
      const runs = await api.listVerificationHistory(undefined, undefined, 50, runId || undefined);
      setHistory(runs);
      if (runs.length > 0) {
        setSelectedRun((prev) => (prev ? (runs.find((r) => r.id === prev.id) || runs[0]) : runs[0]));
      } else {
        setSelectedRun(null);
      }
    } catch (err: any) {
      console.error('Failed to load verification history:', err);
    }
  }, [runId]);

  useEffect(() => {
    let ignore = false;
    (async () => {
      try {
        const runs = await api.listVerificationHistory(undefined, undefined, 50, runId || undefined);
        if (!ignore) {
          setHistory(runs);
          setSelectedRun(runs.length > 0 ? runs[0] : null);
        }
      } catch (err: any) {
        if (!ignore) {
          console.error('Failed to load verification history:', err);
        }
      }
    })();
    return () => {
      ignore = true;
    };
  }, [runId]);

  const handleVerify = async (findingId: string) => {
    setVerifyingId(findingId);
    setError(null);
    setSuccessMsg(null);
    try {
      const vrun = await api.runVerification(findingId, undefined, operatorNote || undefined);
      setHistory((prev) => [vrun, ...prev]);
      setSelectedRun(vrun);
      setSuccessMsg(`Verification complete: outcome is ${vrun.outcome}.`);
      onRefresh();
    } catch (err: any) {
      setError(`Verification probe failed: ${err.message}`);
    } finally {
      setVerifyingId(null);
    }
  };

  return (
    <div className="p-6 space-y-5 max-w-7xl mx-auto font-sans animate-fade-in text-[#F5F5F7]">
      {/* Title & Refresh */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center pb-3 border-b border-[#2A2A2A] gap-3">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-lg font-semibold text-[#F5F5F7] tracking-tight">
              After-Fix Verification
            </h1>
            <span className="text-xs text-[#A1A1A6] font-mono">
              Independent Probe
            </span>
          </div>
          <p className="text-xs text-[#737378] mt-0.5">
            Independent read-only verification comparing baseline evidence against fresh observations on AWS.
          </p>
        </div>

        <button
          onClick={() => {
            loadHistory();
            onRefresh();
          }}
          className="px-3 py-1.5 text-xs text-[#F5F5F7] hover:text-white bg-[#141414] hover:bg-[#202020] border border-[#2A2A2A] rounded-xl flex items-center space-x-1.5 transition-colors"
        >
          <RotateCcw className="w-3.5 h-3.5 text-[#A1A1A6]" />
          <span>Refresh Records</span>
        </button>
      </div>

      {/* Safety Guarantee Notice */}
      <div className="p-4 bg-[#101010] border border-[#2A2A2A] rounded-2xl text-xs flex items-start space-x-3">
        <ShieldCheck className="w-4 h-4 text-white shrink-0 mt-0.5" />
        <div className="text-[#A1A1A6] leading-relaxed">
          <strong className="text-white">Strict Read-Only Verification Guarantee: </strong>
          VYRA never relies on an operator merely checking a "Mark as Fixed" box, and{' '}
          <strong className="text-white">never mutates AWS resources</strong>. Verification executes targeted
          read-only queries via boto3 to confirm whether external remediation satisfies the control criteria.
        </div>
      </div>

      {error && (
        <div className="p-3 bg-[#141414] border border-[#3A3A3A] rounded-xl text-xs text-[#F5F5F7] flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 text-white shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {successMsg && (
        <div className="p-3 bg-[#141414] border border-[#2A2A2A] rounded-xl text-xs text-[#F5F5F7] flex items-center space-x-2">
          <CheckCircle className="w-4 h-4 text-white shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Findings Awaiting Verification */}
      <div className="bg-[#101010] border border-[#2A2A2A] rounded-2xl p-4 space-y-3">
        <div className="flex justify-between items-center">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F7]">
            Security Findings Target List
          </h3>
          <span className="text-[11px] font-mono text-[#737378]">
            {findings.length} registered finding(s)
          </span>
        </div>

        <div className="border border-[#2A2A2A] rounded-xl overflow-hidden">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#141414] border-b border-[#2A2A2A] text-[#737378] text-[10px] uppercase tracking-wider">
              <tr>
                <th className="p-2.5">Finding ID</th>
                <th className="p-2.5">Control</th>
                <th className="p-2.5">Severity</th>
                <th className="p-2.5">Resource ID</th>
                <th className="p-2.5">Status</th>
                <th className="p-2.5">Verification Posture</th>
                <th className="p-2.5 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2A2A2A]">
              {findings.map((f) => {
                const isRunning = verifyingId === f.id;
                return (
                  <tr key={f.id} className="hover:bg-[#141414]">
                    <td className="p-2.5 font-bold text-[#F5F5F7]">{f.id}</td>
                    <td className="p-2.5 text-[#737378]">{f.control_id}</td>
                    <td className="p-2.5">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="p-2.5 text-[#F5F5F7] font-semibold truncate max-w-[180px]">
                      {f.resource_id}
                    </td>
                    <td className="p-2.5">
                      <StatusBadge status={f.status} showIcon={false} />
                    </td>
                    <td className="p-2.5">
                      <StatusBadge status={f.verification_result} />
                    </td>
                    <td className="p-2.5 text-right">
                      <button
                        onClick={() => handleVerify(f.id)}
                        disabled={isRunning}
                        className="px-3 py-1 bg-[#FFFFFF] hover:bg-[#D6D6D6] text-black font-semibold text-xs rounded-xl transition-colors disabled:opacity-40 shadow-sm"
                      >
                        {isRunning ? 'Probing AWS...' : 'Verify Fix'}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Verification History & Evidence Diff Viewer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Past Verification Runs List (4 cols) */}
        <div className="lg:col-span-4 space-y-2">
          <div className="text-xs font-semibold text-[#737378] px-1 flex justify-between items-center">
            <span>Verification Audit Log</span>
            <span className="text-[#A1A1A6] font-mono text-[11px]">{history.length} runs</span>
          </div>

          <div className="space-y-1.5 max-h-[500px] overflow-y-auto pr-1">
            {history.map((r) => {
              const isSelected = selectedRun?.id === r.id;
              return (
                <div
                  key={r.id}
                  onClick={() => setSelectedRun(r)}
                  className={`p-3 rounded-xl border text-left cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-[#202020] border-white text-white shadow-sm'
                      : 'bg-[#101010] border-[#2A2A2A] text-[#A1A1A6] hover:bg-[#141414]'
                  }`}
                >
                  <div className="flex items-center justify-between text-[11px] font-mono mb-1">
                    <span className="truncate max-w-[130px] text-[#737378]">{r.id}</span>
                    <StatusBadge status={r.outcome} showIcon={false} />
                  </div>
                  <div className="text-xs font-mono font-semibold text-[#F5F5F7] truncate">
                    {r.resource_id}
                  </div>
                  <div className="text-[10px] text-[#737378] mt-0.5 font-mono">
                    Finding: {r.finding_id} &middot; {new Date(r.created_at).toLocaleTimeString()}
                  </div>
                </div>
              );
            })}

            {history.length === 0 && (
              <div className="p-4 bg-[#101010] border border-dashed border-[#2A2A2A] rounded-xl text-center text-xs text-[#737378]">
                No verification probes run yet. Click "Verify Fix" on any finding above.
              </div>
            )}
          </div>
        </div>

        {/* Selected Verification Record Evidence (8 cols) */}
        <div className="lg:col-span-8">
          {selectedRun ? (
            <div className="bg-[#101010] border border-[#2A2A2A] rounded-2xl p-4 space-y-3">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 pb-3 border-b border-[#2A2A2A]">
                <div>
                  <div className="text-[10px] uppercase font-semibold text-[#737378]">
                    Verification Outcome
                  </div>
                  <div className="flex items-center space-x-2 mt-0.5">
                    <StatusBadge status={selectedRun.outcome} />
                    <span className="font-mono text-xs text-[#F5F5F7] font-bold">
                      {selectedRun.resource_id}
                    </span>
                  </div>
                </div>

                <div className="text-xs font-mono text-[#737378] text-right">
                  <div>Run: {selectedRun.id}</div>
                  <div className="text-[10px]">{new Date(selectedRun.created_at).toUTCString()}</div>
                </div>
              </div>

              {/* Comparison Summary */}
              <div className="space-y-1">
                <span className="text-[10px] uppercase font-semibold text-[#737378] block">
                  Comparison Summary & Observations
                </span>
                <p className="text-xs bg-[#141414] p-3 rounded-xl border border-[#2A2A2A] text-[#F5F5F7] leading-relaxed">
                  {selectedRun.comparison_summary}
                </p>
              </div>

              {/* Baseline vs Fresh Observation JSON Split */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                <div>
                  <span className="text-[10px] uppercase font-semibold text-[#737378] block mb-1">
                    Baseline Observation Snapshot
                  </span>
                  <pre className="p-3 bg-[#0A0A0A] border border-[#2A2A2A] rounded-xl font-mono text-[10px] text-[#A1A1A6] max-h-[220px] overflow-auto">
                    {JSON.stringify(selectedRun.baseline_observation, null, 2)}
                  </pre>
                </div>

                <div>
                  <span className="text-[10px] uppercase font-semibold text-[#737378] block mb-1">
                    Fresh Read-Only Observation
                  </span>
                  <pre className="p-3 bg-[#0A0A0A] border border-[#2A2A2A] rounded-xl font-mono text-[10px] text-[#A1A1A6] max-h-[220px] overflow-auto">
                    {JSON.stringify(selectedRun.fresh_observation, null, 2)}
                  </pre>
                </div>
              </div>

              {selectedRun.limitations && (
                <div className="p-3 bg-[#141414] border border-[#2A2A2A] rounded-xl text-xs text-[#737378]">
                  <span className="text-[#A1A1A6] font-semibold text-[10px] block mb-0.5">
                    Operational Limitations
                  </span>
                  {selectedRun.limitations}
                </div>
              )}
            </div>
          ) : (
            <div className="p-10 bg-[#101010] border border-dashed border-[#2A2A2A] rounded-2xl text-center text-xs text-[#737378]">
              Select a verification run from the audit log on the left to inspect baseline vs fresh observation snapshots.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
