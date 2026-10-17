import React from 'react';
import {
  Shield,
  Server,
  AlertTriangle,
  CheckSquare,
  Layers,
  Crosshair,
  Wrench,
  FileText,
  Clock,
  Settings,
  Search,
  FileCode,
  ShieldCheck,
  Cpu,
  Lock,
} from 'lucide-react';
import { OverviewMetrics, HealthStatus } from '../types';

export type NavTab =
  | 'overview'
  | 'investigations'
  | 'plangate'
  | 'verification'
  | 'connectors'
  | 'assets'
  | 'findings'
  | 'controls'
  | 'integrations'
  | 'vulnerabilities'
  | 'remediation'
  | 'reports'
  | 'audit'
  | 'settings';

interface SidebarProps {
  currentTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  metrics: OverviewMetrics | null;
  health: HealthStatus | null;
}

interface NavSection {
  title: string;
  items: {
    id: NavTab;
    label: string;
    icon: React.ElementType;
    counter?: string | number | null;
  }[];
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onTabChange,
  metrics,
  health,
}) => {
  const sections: NavSection[] = [
    {
      title: 'Core Workflows',
      items: [
        { id: 'overview', label: 'Overview', icon: Shield },
        { id: 'investigations', label: 'Change Investigator', icon: Search },
        { id: 'plangate', label: 'Pre-Deployment Gate', icon: FileCode },
        { id: 'verification', label: 'After-Fix Verification', icon: ShieldCheck },
      ],
    },
    {
      title: 'Posture & Triage',
      items: [
        {
          id: 'findings',
          label: 'Findings',
          icon: AlertTriangle,
          counter: metrics?.total_findings ? String(metrics.total_findings) : null,
        },
        {
          id: 'controls',
          label: 'Controls Baseline',
          icon: CheckSquare,
          counter: metrics ? `${metrics.controls_passed}/${metrics.controls_passed + metrics.controls_failed + metrics.controls_not_configured + metrics.controls_error}` : null,
        },
        { id: 'vulnerabilities', label: 'Threat Vectors', icon: Crosshair },
        {
          id: 'remediation',
          label: 'Remediation Plans',
          icon: Wrench,
          counter: metrics?.remediations_proposed ? String(metrics.remediations_proposed) : null,
        },
      ],
    },
    {
      title: 'Cloud Inventory',
      items: [
        { id: 'connectors', label: 'Connectors Matrix', icon: Cpu, counter: '12' },
        { id: 'assets', label: 'Assets', icon: Server, counter: metrics?.total_assets ? String(metrics.total_assets) : null },
        { id: 'integrations', label: 'Telemetry & Integrations', icon: Layers },
      ],
    },
    {
      title: 'Compliance & Governance',
      items: [
        { id: 'reports', label: 'Reports', icon: FileText },
        { id: 'audit', label: 'Audit Trail', icon: Clock },
        { id: 'settings', label: 'Settings & Guardrails', icon: Settings },
      ],
    },
  ];

  return (
    <aside className="w-[240px] min-w-[240px] h-screen bg-[#000000] border-r border-[#2A2A2A] flex flex-col justify-between select-none shrink-0 font-sans">
      <div className="flex-1 flex flex-col min-h-0">
        {/* Apple Utility App Header */}
        <div className="px-4 py-3.5 border-b border-[#2A2A2A] flex items-center justify-between">
          <div>
            <div className="text-xs font-semibold text-[#F5F5F7] tracking-tight">
              Security Engineering
            </div>
            <div className="text-[10px] text-[#737378] font-mono">
              Cloud Console
            </div>
          </div>
        </div>

        {/* Grouped Sidebar Navigation */}
        <nav className="p-2 space-y-4 overflow-y-auto flex-1">
          {sections.map((sec) => (
            <div key={sec.title} className="space-y-0.5">
              <div className="px-2.5 pb-1 text-[10px] uppercase font-semibold tracking-wider text-[#737378]">
                {sec.title}
              </div>
              {sec.items.map((item) => {
                const Icon = item.icon;
                const isActive = currentTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => onTabChange(item.id)}
                    className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded-xl text-xs transition-colors text-left ${
                      isActive
                        ? 'bg-[#202020] text-[#FFFFFF] font-medium shadow-sm'
                        : 'text-[#A1A1A6] hover:text-[#F5F5F7] hover:bg-[#121212]'
                    }`}
                  >
                    <div className="flex items-center space-x-2.5 min-w-0">
                      <Icon
                        className={`w-3.5 h-3.5 shrink-0 ${
                          isActive ? 'text-[#FFFFFF]' : 'text-[#737378]'
                        }`}
                      />
                      <span className="truncate whitespace-nowrap text-xs">{item.label}</span>
                    </div>

                    {item.counter && (
                      <span className={`text-[10px] font-mono shrink-0 ml-1.5 ${isActive ? 'text-[#D6D6D6]' : 'text-[#737378]'}`}>
                        {item.counter}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>
      </div>

      {/* Safety & Environment Guardrail Footer */}
      <div className="p-3 border-t border-[#2A2A2A] bg-[#080808] text-[11px] space-y-1.5 shrink-0 font-mono">
        <div className="flex items-center justify-between text-[#A1A1A6]">
          <span className="flex items-center space-x-1">
            <Lock className="w-3 h-3 text-[#A1A1A6]" />
            <span>Profile:</span>
          </span>
          <span className="text-[#F5F5F7] text-[10px]">
            {health?.aws_profile || 'vyra-readonly'}
          </span>
        </div>

        <div className="flex items-center justify-between text-[#A1A1A6]">
          <span>Account:</span>
          <span className="text-[#F5F5F7] text-[10px]">
            {metrics?.account_id
              ? `${metrics.account_id.slice(0, 4)}...${metrics.account_id.slice(-4)}`
              : 'Disconnected'}
          </span>
        </div>

        <div className="pt-1.5 border-t border-[#2A2A2A] flex items-center justify-between text-[10px]">
          <div className="flex items-center space-x-1.5">
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                health?.aws_auth_verified ? 'bg-white' : 'bg-[#737378]'
              }`}
            />
            <span className="text-[#A1A1A6]">
              {health?.aws_auth_verified ? 'Verified Read-Only' : 'Offline / Ready'}
            </span>
          </div>
          <span className="text-[#737378] font-mono">v1.0</span>
        </div>
      </div>
    </aside>
  );
};
