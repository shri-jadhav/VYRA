import React, { useState } from 'react';
import {
  Search,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';
import { Finding, FindingStatus } from '../types';
import { NavTab } from '../components/Sidebar';
import { SeverityBadge, StatusBadge } from '../components/ui/Badge';

interface FindingsViewProps {
  findings: Finding[];
  isLoading: boolean;
  onUpdateStatus: (findingId: string, status: FindingStatus, justification?: string) => Promise<void>;
  onNavigate: (tab: NavTab) => void;
}

export const FindingsView: React.FC<FindingsViewProps> = ({
  findings,
  isLoading,
  onUpdateStatus,
  onNavigate,
}) => {
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [search, setSearch] = useState('');
  const [updatingId, setUpdatingId] = useState<string | null>(null);
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);

  const filtered = findings.filter((f) => {
    const matchesSev = severityFilter === 'ALL' || f.severity === severityFilter;
    const matchesStatus = statusFilter === 'ALL' || f.status === statusFilter;
    const matchesSearch =
      !search ||
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.resource_id.toLowerCase().includes(search.toLowerCase()) ||
      f.description.toLowerCase().includes(search.toLowerCase()) ||
      f.control_id.toLowerCase().includes(search.toLowerCase());
    return matchesSev && matchesStatus && matchesSearch;
  });

  const handleStatusChange = async (findingId: string, newStatus: FindingStatus) => {
    setUpdatingId(findingId);
    try {
      await onUpdateStatus(findingId, newStatus, 'Triaged via VYRA Security Console');
    } finally {
      setUpdatingId(null);
    }
  };

  const toggleExpand = (id: string) => {
    setExpandedFindingId((prev) => (prev === id ? null : id));
  };

  return (
    <div className="p-6 space-y-5 max-w-7xl mx-auto font-sans animate-fade-in text-[#F5F5F7]">
      {/* Title & Filters */}
      <div className="space-y-4">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-lg font-semibold text-[#F5F5F7] tracking-tight">
              Security Findings ({findings.length})
            </h1>
          </div>
          <p className="text-xs text-[#A1A1A6] mt-0.5">
            Normalized cloud security findings with evidence provenance and dry-run remediation guidance.
          </p>
        </div>

        {/* Apple Segmented Filter Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-[#2A2A2A] pb-3 gap-3 text-xs">
          {/* Severity Segments */}
          <div className="bg-[#141414] p-1 rounded-xl border border-[#2A2A2A] flex space-x-1">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-3 py-1 rounded-lg text-xs transition-colors ${
                  severityFilter === sev
                    ? 'bg-[#252525] text-white font-medium shadow-sm'
                    : 'text-[#A1A1A6] hover:text-white'
                }`}
              >
                {sev === 'ALL' ? `All (${findings.length})` : sev}
              </button>
            ))}
          </div>

          <div className="flex items-center space-x-3">
            {/* Status Filter */}
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-[#101010] border border-[#2A2A2A] text-xs text-[#F5F5F7] rounded-xl px-3 py-1.5 focus:outline-none focus:border-[#3A3A3A]"
            >
              <option value="ALL">All Statuses</option>
              <option value="OPEN">Open</option>
              <option value="IN_REVIEW">In Review</option>
              <option value="ACCEPTED_RISK">Accepted Risk</option>
              <option value="REMEDIATED">Remediated</option>
            </select>

            {/* Search Input */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-[#737378]" />
              <input
                type="text"
                placeholder="Filter findings..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="bg-[#101010] border border-[#2A2A2A] text-xs text-[#F5F5F7] placeholder-[#737378] pl-8 pr-3 py-1.5 rounded-xl focus:outline-none focus:border-[#3A3A3A] w-48 transition-colors"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Grouped Table */}
      <div className="bg-[#101010] border border-[#2A2A2A] rounded-2xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#141414] border-b border-[#2A2A2A] text-[#737378] text-[11px] font-semibold uppercase tracking-wider">
              <tr>
                <th className="py-2.5 px-3 w-8"></th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Finding Title</th>
                <th className="py-2.5 px-3">Control ID</th>
                <th className="py-2.5 px-3">Target Resource</th>
                <th className="py-2.5 px-3">Lifecycle Status</th>
                <th className="py-2.5 px-3">Verification</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2A2A2A]">
              {isLoading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-xs text-[#737378] font-mono">
                    Loading findings...
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-xs text-[#737378] font-mono">
                    No findings matching query.
                  </td>
                </tr>
              ) : (
                filtered.map((f) => {
                  const isExpanded = expandedFindingId === f.id;
                  return (
                    <React.Fragment key={f.id}>
                      <tr
                        onClick={() => toggleExpand(f.id)}
                        className="hover:bg-[#181818] cursor-pointer transition-colors"
                      >
                        <td className="py-3 px-3 text-center text-[#737378]">
                          {isExpanded ? (
                            <ChevronDown className="w-3.5 h-3.5 text-[#F5F5F7]" />
                          ) : (
                            <ChevronRight className="w-3.5 h-3.5 text-[#737378]" />
                          )}
                        </td>
                        <td className="py-3 px-3">
                          <SeverityBadge severity={f.severity} />
                        </td>
                        <td className="py-3 px-3 font-medium text-[#F5F5F7] max-w-sm">
                          <span className="hover:underline">{f.title}</span>
                          <div className="text-[11px] text-[#A1A1A6] line-clamp-1 mt-0.5 font-normal">
                            {f.description}
                          </div>
                        </td>
                        <td className="py-3 px-3 font-mono text-[#A1A1A6] text-[11px]">{f.control_id}</td>
                        <td className="py-3 px-3 font-mono text-[#F5F5F7] font-medium text-[11px] truncate max-w-[200px]" title={f.resource_id}>
                          {f.resource_id}
                        </td>
                        <td className="py-3 px-3" onClick={(e) => e.stopPropagation()}>
                          <select
                            disabled={updatingId === f.id}
                            value={f.status}
                            onChange={(e) => handleStatusChange(f.id, e.target.value as FindingStatus)}
                            className="bg-[#181818] border border-[#2A2A2A] text-xs text-[#F5F5F7] rounded-lg px-2.5 py-1 focus:outline-none focus:border-[#3A3A3A]"
                          >
                            <option value="OPEN">OPEN</option>
                            <option value="IN_REVIEW">IN REVIEW</option>
                            <option value="ACCEPTED_RISK">ACCEPTED RISK</option>
                            <option value="REMEDIATED">REMEDIATED</option>
                          </select>
                        </td>
                        <td className="py-3 px-3">
                          <StatusBadge status={f.verification_result} />
                        </td>
                        <td className="py-3 px-3 text-right" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => onNavigate('remediation')}
                            className="text-[#F5F5F7] hover:underline font-medium text-xs inline-flex items-center space-x-1"
                          >
                            <span>Remediate</span>
                            <ChevronRight className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>

                      {/* Apple-style Grouped Detail Drawer */}
                      {isExpanded && (
                        <tr className="bg-[#0A0A0A]">
                          <td colSpan={8} className="p-4 border-t border-b border-[#2A2A2A]">
                            <div className="grid grid-cols-1 md:grid-cols-12 gap-4 text-xs">
                              <div className="md:col-span-8 space-y-3">
                                <div>
                                  <span className="text-[10px] uppercase font-semibold text-[#737378] tracking-wider block mb-1">
                                    Technical Explanation & Security Impact
                                  </span>
                                  <p className="text-[#F5F5F7] leading-relaxed bg-[#101010] p-3.5 rounded-xl border border-[#2A2A2A]">
                                    {f.description}
                                  </p>
                                </div>
                                {f.remediation_guidance && (
                                  <div>
                                    <span className="text-[10px] uppercase font-semibold text-[#737378] tracking-wider block mb-1">
                                      Remediation Recommendation
                                    </span>
                                    <p className="text-[#D6D6D6] bg-[#101010] p-3.5 rounded-xl border border-[#2A2A2A]">
                                      {f.remediation_guidance}
                                    </p>
                                  </div>
                                )}
                              </div>

                              <div className="md:col-span-4 space-y-2.5 text-xs bg-[#101010] p-4 rounded-xl border border-[#2A2A2A]">
                                <div className="text-[#737378] font-semibold uppercase text-[10px] tracking-wider pb-1.5 border-b border-[#2A2A2A]">
                                  Evidence Metadata
                                </div>
                                <div>
                                  <span className="text-[#737378] block text-[10px]">Resource Identifier:</span>
                                  <span className="text-[#F5F5F7] font-mono text-[11px] break-all">{f.resource_arn || f.resource_id}</span>
                                </div>
                                <div>
                                  <span className="text-[#737378] block text-[10px]">Collector Source:</span>
                                  <span className="text-[#D6D6D6] text-[11px] font-mono">{f.evidence_reference || 'Read-Only API Probe'}</span>
                                </div>
                                <div>
                                  <span className="text-[#737378] block text-[10px]">First Observed:</span>
                                  <span className="text-[#D6D6D6] text-[11px]">{new Date(f.first_seen).toUTCString()}</span>
                                </div>
                                <div>
                                  <span className="text-[#737378] block text-[10px]">Last Evaluated:</span>
                                  <span className="text-[#D6D6D6] text-[11px]">{new Date(f.last_seen).toUTCString()}</span>
                                </div>

                                <div className="pt-2 border-t border-[#2A2A2A]">
                                  <button
                                    onClick={() => onNavigate('remediation')}
                                    className="w-full py-1.5 text-center bg-[#FFFFFF] hover:bg-[#D6D6D6] text-black font-semibold text-xs rounded-xl transition-colors shadow-sm"
                                  >
                                    View Remediation Plan
                                  </button>
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
