import React, { useState } from 'react';
import {
  Search,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';
import { ControlEvaluation } from '../types';
import { StatusBadge, SeverityBadge } from '../components/ui/Badge';

interface ControlsViewProps {
  evaluations: ControlEvaluation[];
  isLoading: boolean;
}

export const ControlsView: React.FC<ControlsViewProps> = ({ evaluations, isLoading }) => {
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [search, setSearch] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const categories = [
    'ALL',
    'Storage Security',
    'Identity & Access Management',
    'Auditing & Logging',
    'Threat Detection & Posture',
    'Platform Governance',
  ];

  const filtered = evaluations.filter((ev) => {
    const matchesStatus = statusFilter === 'ALL' || ev.status === statusFilter;
    const matchesCat = categoryFilter === 'ALL' || ev.category === categoryFilter;
    const matchesSearch =
      !search ||
      ev.control_id.toLowerCase().includes(search.toLowerCase()) ||
      ev.title.toLowerCase().includes(search.toLowerCase()) ||
      ev.resource_id.toLowerCase().includes(search.toLowerCase()) ||
      ev.rationale.toLowerCase().includes(search.toLowerCase());
    return matchesStatus && matchesCat && matchesSearch;
  });

  const toggleExpand = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  return (
    <div className="p-6 space-y-5 max-w-7xl mx-auto font-sans animate-fade-in text-[#F5F5F7]">
      {/* Header & Filters */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-3 border-b border-[#2A2A2A] gap-3">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-lg font-semibold text-[#F5F5F7] tracking-tight">
              Controls Evaluation Baseline ({filtered.length})
            </h1>
            <span className="text-xs text-[#737378] font-mono">
              of {evaluations.length} total
            </span>
          </div>
          <p className="text-xs text-[#737378] mt-0.5">
            Deterministic security controls evaluated against point-in-time cloud configuration telemetry.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-1.5 rounded-xl bg-[#101010] border border-[#2A2A2A] text-xs text-[#F5F5F7] focus:outline-none focus:border-[#3A3A3A]"
          >
            <option value="ALL">All Statuses</option>
            <option value="PASS">PASS</option>
            <option value="FAIL">FAIL</option>
            <option value="NOT_CONFIGURED">NOT CONFIGURED</option>
            <option value="ERROR">ERROR / DENIED</option>
            <option value="UNKNOWN">UNKNOWN</option>
          </select>

          {/* Category Filter */}
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="px-3 py-1.5 rounded-xl bg-[#101010] border border-[#2A2A2A] text-xs text-[#F5F5F7] focus:outline-none focus:border-[#3A3A3A]"
          >
            {categories.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>

          {/* Search */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-[#737378]" />
            <input
              type="text"
              placeholder="Search controls..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-8 pr-3 py-1.5 rounded-xl bg-[#101010] border border-[#2A2A2A] text-xs text-[#F5F5F7] placeholder-[#737378] focus:outline-none focus:border-[#3A3A3A] w-48 transition-colors"
            />
          </div>
        </div>
      </div>

      {/* Grouped Controls Table */}
      <div className="bg-[#101010] border border-[#2A2A2A] rounded-2xl overflow-hidden">
        <div className="overflow-x-auto max-h-[680px]">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#141414] sticky top-0 z-10 border-b border-[#2A2A2A] text-[#737378] text-[10px] uppercase tracking-wider">
              <tr>
                <th className="p-3 w-8"></th>
                <th className="p-3">Control ID</th>
                <th className="p-3">Control Title & Category</th>
                <th className="p-3">Target Resource</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Evaluation Status</th>
                <th className="p-3">Evidence Source</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2A2A2A]">
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-[#737378] font-mono">
                    Evaluating security controls...
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-[#737378] font-mono">
                    No control evaluations matching criteria found.
                  </td>
                </tr>
              ) : (
                filtered.map((ev) => {
                  const isExpanded = expandedId === ev.id;
                  return (
                    <React.Fragment key={ev.id}>
                      <tr
                        onClick={() => toggleExpand(ev.id)}
                        className="hover:bg-[#181818] cursor-pointer transition-colors"
                      >
                        <td className="p-3 text-center text-[#737378]">
                          {isExpanded ? (
                            <ChevronDown className="w-3.5 h-3.5 text-[#F5F5F7]" />
                          ) : (
                            <ChevronRight className="w-3.5 h-3.5 text-[#737378]" />
                          )}
                        </td>
                        <td className="p-3 font-bold text-[#F5F5F7]">{ev.control_id}</td>
                        <td className="p-3 max-w-[300px]">
                          <div className="font-medium text-[#F5F5F7] truncate font-sans text-xs" title={ev.title}>
                            {ev.title}
                          </div>
                          <div className="text-[10px] text-[#737378] font-sans truncate">
                            {ev.category}
                          </div>
                        </td>
                        <td className="p-3 text-[#F5F5F7] font-semibold truncate max-w-[180px]" title={ev.resource_id}>
                          {ev.resource_id}
                        </td>
                        <td className="p-3">
                          <SeverityBadge severity={ev.severity} />
                        </td>
                        <td className="p-3">
                          <StatusBadge status={ev.status} />
                        </td>
                        <td className="p-3 text-[#737378] text-[11px] truncate max-w-[160px]" title={ev.evidence_source}>
                          {ev.evidence_source}
                        </td>
                      </tr>

                      {/* Detail Drawer */}
                      {isExpanded && (
                        <tr className="bg-[#0A0A0A]">
                          <td colSpan={7} className="p-4 border-t border-b border-[#2A2A2A] space-y-3 font-mono">
                            <div className="space-y-2 text-xs">
                              <div>
                                <span className="text-[10px] uppercase font-semibold tracking-wider text-[#737378] block">
                                  Evaluation Rationale & Evidence Audit
                                </span>
                                <p className="text-xs font-sans text-[#F5F5F7] bg-[#101010] p-3.5 rounded-xl border border-[#2A2A2A] mt-1 leading-relaxed">
                                  {ev.rationale}
                                </p>
                              </div>

                              <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 pt-1 text-[11px] font-mono text-[#737378]">
                                <div>
                                  <span className="block text-[10px] uppercase text-[#737378]">Resource Target:</span>
                                  <span className="text-[#F5F5F7] break-all">{ev.resource_arn || ev.resource_id}</span>
                                </div>
                                <div>
                                  <span className="block text-[10px] uppercase text-[#737378]">Evidence Collector:</span>
                                  <span className="text-[#D6D6D6]">{ev.evidence_source}</span>
                                </div>
                                <div>
                                  <span className="block text-[10px] uppercase text-[#737378]">Evaluation Timestamp:</span>
                                  <span className="text-[#D6D6D6]">{new Date(ev.timestamp).toUTCString()}</span>
                                </div>
                              </div>

                              {ev.limitations && (
                                <div className="p-3 bg-[#101010] border border-[#2A2A2A] rounded-xl text-xs text-[#737378] font-sans">
                                  <span className="text-[#A1A1A6] font-semibold text-[10px] uppercase font-mono block mb-0.5">
                                    Operational Limitations / Scope Boundary:
                                  </span>
                                  {ev.limitations}
                                </div>
                              )}
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
