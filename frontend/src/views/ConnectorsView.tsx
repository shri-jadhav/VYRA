import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  RotateCcw,
  DollarSign,
  Lock,
  ChevronDown,
  ChevronRight,
  Check,
  X,
} from 'lucide-react';
import { api } from '../api/client';
import { ConnectorCapability } from '../types';
import { StatusBadge } from '../components/ui/Badge';

export const ConnectorsView: React.FC = () => {
  const [connectors, setConnectors] = useState<ConnectorCapability[]>([]);
  const [region, setRegion] = useState<string>('ap-south-1');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const loadConnectors = async (targetRegion: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.listConnectors(targetRegion);
      setConnectors(data);
    } catch (err: any) {
      setError(`Failed to inspect connector matrix: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    let ignore = false;
    (async () => {
      setIsLoading(true);
      setError(null);
      try {
        const data = await api.listConnectors(region);
        if (!ignore) {
          setConnectors(data);
        }
      } catch (err: any) {
        if (!ignore) {
          setError(`Failed to inspect connector matrix: ${err.message}`);
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
  }, [region]);

  const toggleExpand = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  return (
    <div className="p-6 space-y-5 max-w-7xl mx-auto font-sans animate-fade-in text-[#F5F5F7]">
      {/* Title & Controls */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center pb-3 border-b border-[#2A2A2A] gap-3">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-lg font-semibold text-[#F5F5F7] tracking-tight">
              Connectors Matrix
            </h1>
            <span className="text-xs text-[#A1A1A6] font-mono">
              {connectors.length > 0 ? `${connectors.length} AWS Services` : '12 AWS Services'}
            </span>
          </div>
          <p className="text-xs text-[#737378] mt-0.5">
            Granular read-only telemetry, permission boundaries, data retention, cost models, and operational limitations.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <select
            value={region}
            onChange={(e) => setRegion(e.target.value)}
            className="bg-[#101010] border border-[#2A2A2A] text-[#F5F5F7] text-xs rounded-xl px-3 py-1.5 focus:outline-none focus:border-[#3A3A3A]"
          >
            <option value="ap-south-1">ap-south-1 (Mumbai)</option>
            <option value="us-east-1">us-east-1 (N. Virginia)</option>
            <option value="us-west-2">us-west-2 (Oregon)</option>
            <option value="eu-west-1">eu-west-1 (Ireland)</option>
          </select>

          <button
            onClick={() => loadConnectors(region)}
            disabled={isLoading}
            className="px-3 py-1.5 text-xs font-medium bg-[#141414] hover:bg-[#202020] text-[#F5F5F7] border border-[#2A2A2A] rounded-xl flex items-center space-x-1.5 transition-colors disabled:opacity-40"
          >
            <RotateCcw className={`w-3.5 h-3.5 text-[#A1A1A6] ${isLoading ? 'animate-spin' : ''}`} />
            <span>{isLoading ? 'Probing...' : 'Re-probe'}</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 bg-[#141414] border border-[#3A3A3A] rounded-xl text-xs text-[#F5F5F7] flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 text-white shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Grouped Technical Table */}
      <div className="bg-[#101010] border border-[#2A2A2A] rounded-2xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#141414] border-b border-[#2A2A2A] text-[#737378] text-[10px] uppercase tracking-wider">
              <tr>
                <th className="p-3 w-8"></th>
                <th className="p-3">Service & Domain</th>
                <th className="p-3">Category</th>
                <th className="p-3">Connector Status</th>
                <th className="p-3">Telemetry Depth</th>
                <th className="p-3">Permissions Status</th>
                <th className="p-3">Retention Window</th>
                <th className="p-3">Operations</th>
                <th className="p-3">Cost Model</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2A2A2A]">
              {isLoading && connectors.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-[#737378] font-mono">
                    Probing AWS connector matrix...
                  </td>
                </tr>
              ) : (
                connectors.map((c) => {
                  const isExpanded = expandedId === c.service_id;
                  const hasMissingPerms = c.missing_permissions && c.missing_permissions.length > 0;
                  const depthLabel =
                    c.telemetry_type === 'POSTURE_EVALUATION'
                      ? 'Posture Evaluation'
                      : c.telemetry_type === 'FINDINGS_RETRIEVED'
                      ? 'Findings Retrieved'
                      : c.telemetry_type === 'EVENTS_LOOKUP'
                      ? 'Events Looked Up'
                      : c.telemetry_type === 'CONFIGURATION_HISTORY'
                      ? 'Config History'
                      : c.telemetry_type === 'WORKLOAD_INVENTORY'
                      ? 'Workload Inventory'
                      : c.telemetry_type === 'METRICS_ALARMS'
                      ? 'Metrics & Alarms'
                      : 'Status Only';

                  return (
                    <React.Fragment key={c.service_id}>
                      <tr
                        onClick={() => toggleExpand(c.service_id)}
                        className="hover:bg-[#181818] cursor-pointer transition-colors"
                      >
                        <td className="p-3 text-center text-[#737378]">
                          {isExpanded ? (
                            <ChevronDown className="w-3.5 h-3.5 text-[#F5F5F7]" />
                          ) : (
                            <ChevronRight className="w-3.5 h-3.5 text-[#737378]" />
                          )}
                        </td>
                        <td className="p-3">
                          <div className="font-semibold text-[#F5F5F7]">{c.display_name}</div>
                          <div className="text-[10px] text-[#737378]">{c.service_id}</div>
                        </td>
                        <td className="p-3 text-[#A1A1A6] text-[11px] font-sans">
                          {c.category}
                        </td>
                        <td className="p-3">
                          <StatusBadge status={c.status} />
                        </td>
                        <td className="p-3">
                          <span className="text-[10px] text-[#A1A1A6] bg-[#141414] border border-[#2A2A2A] px-2 py-0.5 rounded-full font-mono">
                            {depthLabel}
                          </span>
                        </td>
                        <td className="p-3">
                          {hasMissingPerms ? (
                            <span className="text-[10px] text-white font-semibold bg-[#222222] border border-[#3A3A3A] px-2 py-0.5 rounded-full">
                              {c.missing_permissions.length} Missing
                            </span>
                          ) : (
                            <span className="text-[10px] text-[#D6D6D6] bg-[#141414] border border-[#2A2A2A] px-2 py-0.5 rounded-full">
                              {c.required_permissions.length} Granted
                            </span>
                          )}
                        </td>
                        <td className="p-3 text-[#A1A1A6] text-[11px]">
                          {c.data_retention_window || 'N/A'}
                        </td>
                        <td className="p-3 text-[#737378] text-[11px]">
                          {c.supported_operations.length} APIs
                        </td>
                        <td className="p-3 text-[#A1A1A6] text-[11px] max-w-[200px] truncate" title={c.cost_notes}>
                          {c.cost_notes}
                        </td>
                      </tr>

                      {/* Expanded Drawer / Detail Row */}
                      {isExpanded && (
                        <tr className="bg-[#0A0A0A]">
                          <td colSpan={9} className="p-4 border-t border-b border-[#2A2A2A] space-y-3">

                            <div className="text-xs text-[#F5F5F7] font-sans leading-relaxed">
                              {c.status_details}
                            </div>

                            {/* Required Permissions Chips */}
                            <div>
                              <div className="text-[10px] uppercase font-semibold text-[#737378] mb-1.5 tracking-wider">
                                Required IAM Permissions (Read-Only)
                              </div>
                              <div className="flex flex-wrap gap-1.5">
                                {c.required_permissions.map((p) => {
                                  const isMissing = c.missing_permissions?.includes(p);
                                  return (
                                    <span
                                      key={p}
                                      className={`px-2 py-0.5 rounded-lg text-[10px] font-mono flex items-center space-x-1 ${
                                        isMissing
                                          ? 'bg-[#252525] text-white border border-[#3A3A3A] font-semibold'
                                          : 'bg-[#141414] text-[#D6D6D6] border border-[#2A2A2A]'
                                      }`}
                                    >
                                      {isMissing ? (
                                        <X className="w-2.5 h-2.5 text-white" />
                                      ) : (
                                        <Check className="w-2.5 h-2.5 text-[#D6D6D6]" />
                                      )}
                                      <span>{p}</span>
                                    </span>
                                  );
                                })}
                              </div>
                            </div>

                            {/* Supported Operations */}
                            <div>
                              <div className="text-[10px] uppercase font-semibold text-[#737378] mb-1 tracking-wider">
                                Supported Operations & Telemetry Handlers
                              </div>
                              <div className="flex flex-wrap gap-1">
                                {c.supported_operations.map((op) => (
                                  <span
                                    key={op}
                                    className="px-2 py-0.5 bg-[#141414] border border-[#2A2A2A] text-[#A1A1A6] rounded-md text-[10px] font-mono"
                                  >
                                    {op}
                                  </span>
                                ))}
                              </div>
                            </div>

                            {/* Limitations & Cost notes */}
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 text-xs font-sans text-[#A1A1A6] border-t border-[#2A2A2A]">
                              <div className="flex items-start space-x-2">
                                <DollarSign className="w-3.5 h-3.5 text-[#737378] shrink-0 mt-0.5" />
                                <div>
                                  <strong className="text-[#F5F5F7] font-mono text-[10px] uppercase block">
                                    Cost & Ingestion Model
                                  </strong>
                                  <span className="text-[11px]">{c.cost_notes}</span>
                                </div>
                              </div>
                              <div className="flex items-start space-x-2">
                                <Lock className="w-3.5 h-3.5 text-[#737378] shrink-0 mt-0.5" />
                                <div>
                                  <strong className="text-[#F5F5F7] font-mono text-[10px] uppercase block">
                                    Operational Limitations
                                  </strong>
                                  <span className="text-[11px]">{c.limitations}</span>
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
