import React, { useState } from 'react';
import { Search, ShieldCheck } from 'lucide-react';
import { AuditLog } from '../types';
import { StatusBadge } from '../components/ui/Badge';

interface AuditTrailViewProps {
  logs: AuditLog[];
  isLoading: boolean;
}

export const AuditTrailView: React.FC<AuditTrailViewProps> = ({ logs, isLoading }) => {
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');

  const actions = [
    'ALL',
    'ASSESSMENT_STARTED',
    'ASSESSMENT_COMPLETED',
    'REMEDIATION_APPROVAL',
    'REMEDIATION_REVERIFY',
    'FINDING_STATUS_UPDATE',
    'REPORT_EXPORT_JSON',
    'REPORT_EXPORT_HTML',
  ];

  const filtered = logs.filter((log) => {
    const matchesAction = actionFilter === 'ALL' || log.action === actionFilter;
    const matchesSearch =
      !search ||
      log.actor.toLowerCase().includes(search.toLowerCase()) ||
      log.action.toLowerCase().includes(search.toLowerCase()) ||
      (log.resource && log.resource.toLowerCase().includes(search.toLowerCase())) ||
      (log.details && log.details.toLowerCase().includes(search.toLowerCase()));
    return matchesAction && matchesSearch;
  });

  return (
    <div className="p-6 space-y-5 max-w-7xl mx-auto font-sans animate-fade-in text-[#F5F5F7]">
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-3 border-b border-[#2A2A2A] gap-3">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-lg font-semibold text-[#F5F5F7] tracking-tight">
              Operational Audit Trail ({filtered.length})
            </h1>
            <span className="text-xs text-[#737378] font-mono">
              of {logs.length} events
            </span>
          </div>
          <p className="text-xs text-[#737378] mt-0.5">
            Continuous chronological recording of assessment executions, dry-run approvals, and re-verification queries.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="px-3 py-1.5 rounded-xl bg-[#101010] border border-[#2A2A2A] text-xs text-[#F5F5F7] focus:outline-none focus:border-[#3A3A3A]"
          >
            {actions.map((act) => (
              <option key={act} value={act}>
                {act}
              </option>
            ))}
          </select>

          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-[#737378]" />
            <input
              type="text"
              placeholder="Search audit trail..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-8 pr-3 py-1.5 rounded-xl bg-[#101010] border border-[#2A2A2A] text-xs text-[#F5F5F7] placeholder-[#737378] focus:outline-none focus:border-[#3A3A3A] w-48 transition-colors"
            />
          </div>
        </div>
      </div>

      {/* Audit Notice */}
      <div className="p-3.5 rounded-2xl bg-[#101010] border border-[#2A2A2A] flex items-center justify-between text-xs text-[#A1A1A6]">
        <span className="flex items-center space-x-2">
          <ShieldCheck className="w-4 h-4 text-white" />
          <span>
            Platform audit log &middot; Operational traceability for all control reviews and dry-run actions.
          </span>
        </span>
        <span className="text-[11px] text-[#737378] font-mono">{filtered.length} events logged</span>
      </div>

      {/* Grouped Audit Log Table */}
      <div className="rounded-2xl bg-[#101010] border border-[#2A2A2A] overflow-hidden">
        <div className="overflow-x-auto max-h-[680px]">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#141414] sticky top-0 z-10 border-b border-[#2A2A2A] text-[#737378] text-[10px] uppercase tracking-wider">
              <tr>
                <th className="p-3">Timestamp (UTC)</th>
                <th className="p-3">Actor</th>
                <th className="p-3">Action</th>
                <th className="p-3">Target Resource</th>
                <th className="p-3">Status</th>
                <th className="p-3">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2A2A2A]">
              {isLoading ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-[#737378] font-mono">
                    Loading audit trail...
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-[#737378] font-mono">
                    No audit records matching query.
                  </td>
                </tr>
              ) : (
                filtered.map((log) => (
                  <tr key={log.id} className="hover:bg-[#181818] transition-colors">
                    <td className="p-3 text-[#737378] text-[11px]">
                      {new Date(log.timestamp).toUTCString()}
                    </td>
                    <td className="p-3 font-semibold text-[#F5F5F7]">{log.actor}</td>
                    <td className="p-3">
                      <span className="text-[10px] px-2 py-0.5 rounded-full bg-[#181818] border border-[#2A2A2A] text-[#F5F5F7]">
                        {log.action}
                      </span>
                    </td>
                    <td className="p-3 text-[#A1A1A6] text-[11px] truncate max-w-[160px]" title={log.resource || '-'}>
                      {log.resource || '-'}
                    </td>
                    <td className="p-3">
                      <StatusBadge status={log.status} />
                    </td>
                    <td className="p-3 text-[#A1A1A6] text-[11px] font-sans max-w-md truncate" title={log.details || '-'}>
                      {log.details || '-'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
