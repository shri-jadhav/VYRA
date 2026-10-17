import React, { useState, useEffect, useCallback } from 'react';
import {
  Search,
  AlertTriangle,
  FileText,
  Download,
  User,
  Info,
  RotateCcw,
  CheckCircle2,
} from 'lucide-react';
import { api } from '../api/client';
import {
  InvestigationSession,
  Finding,
} from '../types';

interface InvestigationsViewProps {
  findings: Finding[];
  runId?: string | null;
}

export const InvestigationsView: React.FC<InvestigationsViewProps> = ({ findings, runId }) => {
  const [sessions, setSessions] = useState<InvestigationSession[]>([]);
  const [activeSession, setActiveSession] = useState<InvestigationSession | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isStarting, setIsStarting] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // New investigation form state
  const [targetResource, setTargetResource] = useState<string>(
    findings.length > 0 ? findings[0].resource_id : ''
  );
  const [selectedFindingId, setSelectedFindingId] = useState<string>(
    findings.length > 0 ? findings[0].id : ''
  );
  const [targetRegion, setTargetRegion] = useState<string>('ap-south-1');
  const [lookbackDays, setLookbackDays] = useState<number>(30);
  const [rankingFilter, setRankingFilter] = useState<string>('ALL');

  const loadSessions = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.listInvestigationSessions(20, runId || undefined);
      setSessions(data);
      if (data.length > 0) {
        setActiveSession((prev) => (prev ? (data.find((s) => s.id === prev.id) || data[0]) : data[0]));
      } else {
        setActiveSession(null);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load past investigation sessions.');
    } finally {
      setIsLoading(false);
    }
  }, [runId]);

  useEffect(() => {
    let ignore = false;
    (async () => {
      setIsLoading(true);
      setError(null);
      try {
        const data = await api.listInvestigationSessions(20, runId || undefined);
        if (!ignore) {
          setSessions(data);
          setActiveSession(data.length > 0 ? data[0] : null);
        }
      } catch (err: any) {
        if (!ignore) {
          setError(err.message || 'Failed to load past investigation sessions.');
        }
      } finally {
        if (!ignore) {
          setIsLoading(false);
        }
      }
    })();
    return () => {
      ignore = true;
    };
  }, [runId]);

  const handleStartInvestigation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetResource.trim()) return;

    setIsStarting(true);
    setError(null);
    try {
      const session = await api.startInvestigation(
        targetResource.trim(),
        selectedFindingId || undefined,
        targetRegion,
        lookbackDays
      );
      setSessions((prev) => [session, ...prev]);
      setActiveSession(session);
    } catch (err: any) {
      setError(`Investigation failed: ${err.message}`);
    } finally {
      setIsStarting(false);
    }
  };

  const handleSelectFinding = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const fId = e.target.value;
    setSelectedFindingId(fId);
    if (fId) {
      const match = findings.find((f) => f.id === fId);
      if (match) {
        setTargetResource(match.resource_id);
      }
    }
  };

  const filteredCandidates = activeSession?.candidate_explanations.filter((c) => {
    if (rankingFilter === 'ALL') return true;
    return c.ranking === rankingFilter;
  });

  return (
    <div className="p-6 space-y-5 max-w-7xl mx-auto font-sans animate-fade-in text-[#F5F5F7]">
      {/* Title & Actions */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center pb-3 border-b border-[#2A2A2A] gap-3">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-lg font-semibold text-[#F5F5F7] tracking-tight">
              Cloud Change Investigator
            </h1>
            <span className="text-xs text-[#A1A1A6] font-mono">
              Root Cause Attribution
            </span>
          </div>
          <p className="text-xs text-[#737378] mt-0.5">
            Deterministic event attribution, CloudTrail timelines, configuration diffs, and evidence audits.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          {activeSession && (
            <>
              <a
                href={api.getInvestigationReportUrl(activeSession.id, 'html')}
                target="_blank"
                rel="noreferrer"
                className="px-3 py-1.5 text-xs text-[#F5F5F7] hover:text-white bg-[#141414] hover:bg-[#202020] border border-[#2A2A2A] rounded-xl flex items-center space-x-1.5 transition-colors"
              >
                <FileText className="w-3.5 h-3.5 text-[#F5F5F7]" />
                <span>HTML Report</span>
              </a>
              <a
                href={api.getInvestigationReportUrl(activeSession.id, 'markdown')}
                download
                className="px-3 py-1.5 text-xs text-[#A1A1A6] hover:text-white bg-[#141414] hover:bg-[#202020] border border-[#2A2A2A] rounded-xl flex items-center space-x-1.5 transition-colors"
              >
                <Download className="w-3.5 h-3.5 text-[#A1A1A6]" />
                <span>Markdown</span>
              </a>
            </>
          )}
          <button
            onClick={loadSessions}
            disabled={isLoading}
            className="p-1.5 text-xs bg-[#141414] hover:bg-[#202020] text-[#A1A1A6] hover:text-white border border-[#2A2A2A] rounded-xl transition-colors disabled:opacity-40"
            title="Refresh history"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 bg-[#141414] border border-[#3A3A3A] rounded-xl text-xs text-[#F5F5F7] flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 shrink-0 text-white" />
          <span>{error}</span>
        </div>
      )}

      {/* Investigation Launcher Bar */}
      <div className="bg-[#101010] border border-[#2A2A2A] rounded-2xl p-4">
        <form onSubmit={handleStartInvestigation} className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
          <div className="md:col-span-3">
            <label className="block text-[11px] font-medium text-[#737378] mb-1">
              Select Observed Finding
            </label>
            <select
              value={selectedFindingId}
              onChange={handleSelectFinding}
              className="w-full bg-[#141414] border border-[#2A2A2A] text-[#F5F5F7] text-xs rounded-xl px-3 py-2 focus:outline-none focus:border-[#3A3A3A] truncate"
            >
              <option value="">Choose active finding (optional)</option>
              {findings.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.severity}: {f.title} ({f.resource_id})
                </option>
              ))}
            </select>
          </div>

          <div className="md:col-span-4">
            <label className="block text-[11px] font-medium text-[#737378] mb-1">
              Target Resource Identifier
            </label>
            <input
              type="text"
              value={targetResource}
              onChange={(e) => setTargetResource(e.target.value)}
              placeholder="e.g. drainsentinel-web, root, user_name"
              className="w-full bg-[#141414] border border-[#2A2A2A] text-[#F5F5F7] text-xs rounded-xl px-3 py-2 focus:outline-none focus:border-[#3A3A3A] font-mono"
              required
            />
          </div>

          <div className="md:col-span-2">
            <label className="block text-[11px] font-medium text-[#737378] mb-1">
              AWS Region
            </label>
            <select
              value={targetRegion}
              onChange={(e) => setTargetRegion(e.target.value)}
              className="w-full bg-[#141414] border border-[#2A2A2A] text-[#F5F5F7] text-xs rounded-xl px-3 py-2 focus:outline-none focus:border-[#3A3A3A]"
            >
              <option value="ap-south-1">ap-south-1 (Mumbai)</option>
              <option value="us-east-1">us-east-1 (N. Virginia)</option>
              <option value="us-west-2">us-west-2 (Oregon)</option>
              <option value="eu-west-1">eu-west-1 (Ireland)</option>
            </select>
          </div>

          <div className="md:col-span-1">
            <label className="block text-[11px] font-medium text-[#737378] mb-1">
              Window
            </label>
            <select
              value={lookbackDays}
              onChange={(e) => setLookbackDays(Number(e.target.value))}
              className="w-full bg-[#141414] border border-[#2A2A2A] text-[#F5F5F7] text-xs rounded-xl px-2.5 py-2 focus:outline-none focus:border-[#3A3A3A]"
            >
              <option value={1}>24h</option>
              <option value={7}>7d</option>
              <option value={30}>30d</option>
              <option value={90}>90d</option>
            </select>
          </div>

          <div className="md:col-span-2">
            <button
              type="submit"
              disabled={isStarting}
              className="w-full py-2 px-3 bg-[#FFFFFF] hover:bg-[#D6D6D6] text-black font-semibold text-xs rounded-xl flex items-center justify-center space-x-1.5 transition-colors disabled:opacity-40 shadow-sm"
            >
              <Search className="w-3.5 h-3.5 text-black" />
              <span>{isStarting ? 'Investigating...' : 'Investigate'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Main Investigation Split Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Past Sessions List (3 cols) */}
        <div className="lg:col-span-3 space-y-2">
          <div className="text-xs font-semibold text-[#737378] px-1 flex justify-between items-center">
            <span>Investigation History</span>
            <span className="text-[#A1A1A6] font-mono text-[11px]">{sessions.length} runs</span>
          </div>

          <div className="space-y-1.5 max-h-[640px] overflow-y-auto pr-1">
            {sessions.map((s) => {
              const isSelected = activeSession?.id === s.id;
              return (
                <div
                  key={s.id}
                  onClick={() => setActiveSession(s)}
                  className={`p-3 rounded-xl text-left cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-[#202020] border-l-2 border-white text-white shadow-sm'
                      : 'bg-[#101010] hover:bg-[#141414] text-[#A1A1A6]'
                  }`}
                >
                  <div className="flex items-center justify-between text-[11px] mb-1 font-mono">
                    <span className="truncate max-w-[140px] text-[#737378]">{s.id}</span>
                    <span className={s.status === 'COMPLETED' ? 'text-white' : 'text-[#737378]'}>
                      {s.status}
                    </span>
                  </div>
                  <div className="text-xs font-semibold text-[#F5F5F7] truncate font-mono">
                    {s.resource_id}
                  </div>
                  <div className="text-[10px] text-[#737378] mt-1">
                    {new Date(s.created_at).toUTCString()}
                  </div>
                </div>
              );
            })}

            {sessions.length === 0 && !isLoading && (
              <div className="p-4 bg-[#101010] rounded-xl text-center text-xs text-[#737378]">
                No past sessions. Launch an investigation above.
              </div>
            )}
          </div>
        </div>

        {/* Active Session Details (9 cols) */}
        <div className="lg:col-span-9 space-y-4">
          {activeSession ? (
            <>
              {/* Target Metadata Bar */}
              <div className="bg-[#101010] border border-[#2A2A2A] rounded-2xl p-4 space-y-3">
                <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-2 pb-3 border-b border-[#2A2A2A]">
                  <div>
                    <span className="text-[10px] text-[#737378] uppercase font-semibold">Target Cloud Resource</span>
                    <div className="text-base font-bold text-white font-mono mt-0.5">
                      {activeSession.resource_id}
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-4 text-xs font-mono text-[#A1A1A6]">
                    <div>
                      <span className="text-[#737378] block text-[10px]">Account:</span>
                      <span className="text-[#F5F5F7]">{activeSession.target_account}</span>
                    </div>
                    <div>
                      <span className="text-[#737378] block text-[10px]">Region:</span>
                      <span className="text-[#F5F5F7]">{activeSession.target_region}</span>
                    </div>
                    <div>
                      <span className="text-[#737378] block text-[10px]">Window:</span>
                      <span className="text-[#F5F5F7]">{new Date(activeSession.time_window_start).toLocaleDateString()} to {new Date(activeSession.time_window_end).toLocaleDateString()}</span>
                    </div>
                  </div>
                </div>

                {/* Executive Summary */}
                <div>
                  <span className="text-xs font-semibold text-[#F5F5F7] flex items-center space-x-1.5 mb-1.5">
                    <Info className="w-3.5 h-3.5 text-[#A1A1A6]" />
                    <span>Executive Summary & Attribution Rationale</span>
                  </span>
                  <p className="text-xs text-[#D6D6D6] leading-relaxed bg-[#141414] p-3.5 rounded-xl border border-[#2A2A2A]">
                    {activeSession.summary || 'Investigation completed with deterministic event analysis.'}
                  </p>
                </div>
              </div>

              {/* Semantic Configuration Diff */}
              {activeSession.config_diff && activeSession.config_diff.length > 0 && (
                <div className="bg-[#101010] border border-[#2A2A2A] rounded-2xl p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-semibold text-[#F5F5F7] uppercase tracking-wider">
                      Configuration Difference ({activeSession.config_diff.length} properties)
                    </h3>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-[#141414] border-b border-[#2A2A2A] text-[#737378] text-[10px] uppercase">
                        <tr>
                          <th className="p-2">Property</th>
                          <th className="p-2">Baseline</th>
                          <th className="p-2">Observed</th>
                          <th className="p-2">Impact</th>
                          <th className="p-2 font-sans">Explanation</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#2A2A2A]">
                        {activeSession.config_diff.map((d, i) => (
                          <tr key={i} className="hover:bg-[#141414]">
                            <td className="p-2 font-semibold text-[#F5F5F7]">{d.property}</td>
                            <td className="p-2 text-[#737378]">
                              {typeof d.baseline_value === 'object' ? JSON.stringify(d.baseline_value) : String(d.baseline_value)}
                            </td>
                            <td className="p-2 text-white font-bold">
                              {typeof d.current_value === 'object' ? JSON.stringify(d.current_value) : String(d.current_value)}
                            </td>
                            <td className="p-2">
                              {d.security_impact === 'REGRESSION' ? (
                                <span className="inline-flex items-center space-x-1 text-white font-bold">
                                  <AlertTriangle className="w-3 h-3 text-white" />
                                  <span>REGRESSION</span>
                                </span>
                              ) : (
                                <span className="inline-flex items-center space-x-1 text-[#D6D6D6] font-medium">
                                  <CheckCircle2 className="w-3 h-3 text-white" />
                                  <span>IMPROVEMENT</span>
                                </span>
                              )}
                            </td>
                            <td className="p-2 text-[#A1A1A6] font-sans text-xs">{d.description}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Candidate Explanations */}
              <div className="bg-[#101010] border border-[#2A2A2A] rounded-2xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold text-[#F5F5F7] uppercase tracking-wider">
                    Candidate Change Explanations
                  </h3>
                  <div className="bg-[#141414] p-1 rounded-xl border border-[#2A2A2A] flex space-x-1 text-xs">
                    {['ALL', 'SUPPORTED_CANDIDATE', 'POSSIBLE'].map((f) => (
                      <button
                        key={f}
                        onClick={() => setRankingFilter(f)}
                        className={`px-2.5 py-0.5 rounded-lg text-xs transition-colors ${
                          rankingFilter === f
                            ? 'bg-[#252525] text-white font-medium shadow-sm'
                            : 'text-[#737378] hover:text-[#A1A1A6]'
                        }`}
                      >
                        {f.replace('_', ' ')}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="space-y-3">
                  {filteredCandidates && filteredCandidates.length > 0 ? (
                    filteredCandidates.map((c) => (
                      <div key={c.id} className="p-3.5 bg-[#141414] rounded-xl space-y-2 border-l-2 border-white">
                        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-1">
                          <div className="flex items-center space-x-2">
                            <span className={c.ranking === 'SUPPORTED_CANDIDATE' ? 'text-white font-semibold text-xs' : 'text-[#A1A1A6] font-medium text-xs'}>
                              {c.ranking.replace(/_/g, ' ')}
                            </span>
                            <span className="text-[#3A3A3A]">&middot;</span>
                            <span className="font-mono text-xs font-bold text-white">{c.event_name}</span>
                            <span className="text-xs text-[#737378]">({c.confidence_score}% confidence)</span>
                          </div>
                          <div className="text-xs text-[#A1A1A6] font-mono flex items-center space-x-1">
                            <User className="w-3 h-3 text-[#737378]" />
                            <span>{c.actor}</span>
                          </div>
                        </div>

                        <p className="text-xs text-[#D6D6D6] leading-relaxed font-sans">{c.rationale}</p>

                        <div className="grid grid-cols-2 gap-2 text-xs text-[#737378] pt-1 font-mono">
                          <div>Operation: <span className="text-[#F5F5F7]">{c.operation_relevance}</span></div>
                          <div>Timestamp: <span className="text-[#F5F5F7]">{new Date(c.event_time).toUTCString()}</span></div>
                        </div>

                        {c.next_steps && c.next_steps.length > 0 && (
                          <div className="pt-2 border-t border-[#2A2A2A] text-xs">
                            <span className="text-[#737378] font-semibold block text-[11px]">Recommended Next Steps:</span>
                            <ul className="list-disc list-inside text-[#D6D6D6] space-y-0.5 mt-0.5 font-mono text-[11px]">
                              {c.next_steps.map((s, idx) => (
                                <li key={idx}>{s}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    ))
                  ) : (
                    <div className="p-4 text-center text-xs text-[#737378]">
                      No candidate explanations match this filter.
                    </div>
                  )}
                </div>
              </div>

              {/* CloudTrail Chronological Timeline */}
              <div className="bg-[#101010] border border-[#2A2A2A] rounded-2xl p-4 space-y-3">
                <h3 className="text-xs font-semibold text-[#F5F5F7] uppercase tracking-wider">
                  CloudTrail Chronological Timeline
                </h3>

                <div className="relative pl-4 space-y-3 border-l border-[#2A2A2A]">
                  {activeSession.timeline_events.map((t) => (
                    <div key={t.id} className="relative">
                      <div className="absolute -left-[21px] top-1.5 w-2 h-2 rounded-full bg-white" />
                      <div className="bg-[#141414] p-3 rounded-xl space-y-1 text-xs border border-[#2A2A2A]">
                        <div className="flex justify-between text-[#737378] font-mono text-[10px]">
                          <span className="text-white font-semibold">{new Date(t.timestamp).toUTCString()}</span>
                          <span className="text-[#A1A1A6]">{t.source}</span>
                        </div>
                        <div className="font-bold text-white font-mono">{t.event_name}</div>
                        <div className="text-[#D6D6D6] font-sans">{t.details}</div>
                        {t.actor && <div className="text-[#737378] font-mono text-[10px]">Actor: {t.actor}</div>}
                      </div>
                    </div>
                  ))}

                  {activeSession.timeline_events.length === 0 && (
                    <div className="text-xs text-[#737378]">No events observed in lookback window.</div>
                  )}
                </div>
              </div>
            </>
          ) : (
            <div className="p-12 bg-[#101010] border border-[#2A2A2A] rounded-2xl text-center space-y-2 text-[#737378] text-xs">
              Select an investigation session from the history on the left or launch a new investigation.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
