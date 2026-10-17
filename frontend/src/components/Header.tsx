import React from 'react';
import { Play, Database, RefreshCw, ShieldCheck, Search, Globe, User } from 'lucide-react';
import { OverviewMetrics, HealthStatus } from '../types';
import { ModeBadge } from './ui/Badge';
import { VyraLogo } from './VyraLogo';

interface HeaderProps {
  title: string;
  subtitle?: string;
  metrics: OverviewMetrics | null;
  health: HealthStatus | null;
  isLoading: boolean;
  onRunLiveAssessment: () => void;
  onRunDemoAssessment: () => void;
  onRefresh: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  title,
  subtitle,
  metrics,
  health,
  isLoading,
  onRunLiveAssessment,
  onRunDemoAssessment,
  onRefresh,
}) => {
  return (
    <header className="bg-[#000000] border-b border-[#2A2A2A] select-none shrink-0 z-20">
      {/* Top Main Toolbar */}
      <div className="h-13 px-4 flex items-center justify-between gap-3">
        {/* Left: Vyra Emblem, Wordmark & Assessment Mode */}
        <div className="flex items-center space-x-3 shrink-0">
          <div className="flex items-center space-x-2.5">
            <VyraLogo size={24} />
            <span className="font-semibold text-sm tracking-widest text-[#F5F5F7]">VYRA</span>
          </div>

          <div className="h-4 w-px bg-[#2A2A2A] hidden sm:block" />

          {metrics && (
            <div className="hidden sm:flex items-center space-x-2">
              <ModeBadge mode={metrics.mode} />
              {metrics.run_id && (
                <span className="hidden xl:inline text-[11px] font-mono text-[#737378]" title={`Active Run: ${metrics.run_id}`}>
                  {metrics.run_id.slice(0, 8)}...
                </span>
              )}
            </div>
          )}
        </div>

        {/* Center: Apple-style Search Bar */}
        <div className="hidden md:flex items-center flex-1 max-w-md mx-4">
          <div className="relative w-full">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-[#737378]" />
            <input
              type="text"
              placeholder="Search findings, assets, cloud resources [Alt+S]"
              className="w-full bg-[#101010] hover:bg-[#141414] focus:bg-[#101010] text-xs text-[#F5F5F7] placeholder-[#737378] pl-9 pr-3 py-1.5 rounded-xl border border-[#2A2A2A] focus:border-[#3A3A3A] focus:outline-none transition-colors"
            />
          </div>
        </div>

        {/* Right: Actions & Hardware Context */}
        <div className="flex items-center space-x-2.5 shrink-0">
          {/* Read-Only Safety Assurance */}
          <div className="hidden xl:flex items-center space-x-1.5 text-xs text-[#A1A1A6] px-2 py-1 rounded-lg bg-[#080808]">
            <ShieldCheck className="w-3.5 h-3.5 text-[#F5F5F7]" />
            <span className="text-[11px] font-mono text-[#A1A1A6]">Read-Only Enforced</span>
          </div>

          {/* Refresh Action */}
          <button
            onClick={onRefresh}
            disabled={isLoading}
            className="p-1.5 rounded-lg text-[#A1A1A6] hover:text-[#F5F5F7] hover:bg-[#181818] transition-colors disabled:opacity-40"
            title="Refresh assessment telemetry"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-white' : ''}`} />
          </button>

          {/* Demo Benchmark Trigger */}
          <button
            onClick={onRunDemoAssessment}
            disabled={isLoading}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl text-xs font-medium text-[#F5F5F7] bg-[#141414] hover:bg-[#202020] border border-[#2A2A2A] transition-colors disabled:opacity-40"
            title="Switch to simulated enterprise benchmark fixture"
          >
            <Database className="w-3.5 h-3.5 text-[#A1A1A6]" />
            <span>Demo Benchmark</span>
          </button>

          {/* Run Live AWS Scan Button (Apple Native Primary: Pure White Fill) */}
          <button
            onClick={onRunLiveAssessment}
            disabled={isLoading || (health !== null && !health.live_collection_enabled)}
            className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-xl text-xs font-semibold text-black bg-[#FFFFFF] hover:bg-[#D6D6D6] transition-colors disabled:opacity-40 shadow-sm"
            title="Execute live read-only assessment using AWS CLI profile vyra-readonly"
          >
            <Play className="w-3 h-3 fill-current text-black" />
            <span>{isLoading ? 'Scanning...' : 'Live AWS Scan'}</span>
          </button>

          <div className="h-4 w-px bg-[#2A2A2A] hidden lg:block" />

          {/* Target Account & Region Context */}
          <div className="hidden lg:flex items-center space-x-2 text-xs font-mono text-[#A1A1A6] bg-[#080808] border border-[#2A2A2A] rounded-xl px-2.5 py-1">
            <div className="flex items-center space-x-1" title="Active AWS Region">
              <Globe className="w-3 h-3 text-[#737378]" />
              <span className="text-[11px]">{metrics?.region || 'ap-south-1'}</span>
            </div>
            <span className="text-[#3A3A3A]">&middot;</span>
            <div className="flex items-center space-x-1" title="Target AWS Account ID">
              <User className="w-3 h-3 text-[#A1A1A6]" />
              <span className="font-medium text-[#F5F5F7] text-[11px]">
                {metrics?.account_id ? `${metrics.account_id}` : 'Disconnected'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Sub-Header: Native Navigation Breadcrumb Bar */}
      <div className="h-7 px-4 bg-[#080808] border-t border-[#2A2A2A] flex items-center justify-between text-xs">
        <div className="flex items-center space-x-2 text-[11px]">
          <span className="text-[#A1A1A6] hover:text-[#F5F5F7] cursor-pointer transition-colors">VYRA</span>
          <span className="text-[#3A3A3A]">/</span>
          <span className="text-[#F5F5F7] font-medium">{title}</span>
        </div>
        {subtitle && (
          <span className="text-[11px] text-[#737378] hidden sm:inline">{subtitle}</span>
        )}
      </div>
    </header>
  );
};
