import React from 'react';
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  XCircle,
} from 'lucide-react';
import { Severity, FindingStatus, ControlStatus, VerificationOutcome } from '../../types';

export interface SeverityBadgeProps {
  severity: Severity | string;
  className?: string;
  compact?: boolean;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  className = '',
  compact = false,
}) => {
  const normalized = (severity || '').toUpperCase();
  const label = compact ? normalized.slice(0, 4) : normalized;

  if (normalized === 'CRITICAL') {
    return (
      <span className={`inline-flex items-center space-x-1.5 text-white font-semibold text-xs tracking-wide select-none ${className}`}>
        <AlertCircle className="w-3.5 h-3.5 text-white shrink-0" />
        <span className="font-mono text-[11px] font-bold">{label}</span>
      </span>
    );
  }

  if (normalized === 'HIGH') {
    return (
      <span className={`inline-flex items-center space-x-1.5 text-[#F5F5F7] font-medium text-xs tracking-wide select-none ${className}`}>
        <AlertTriangle className="w-3.5 h-3.5 text-[#D6D6D6] shrink-0" />
        <span className="font-mono text-[11px] font-medium">{label}</span>
      </span>
    );
  }

  if (normalized === 'MEDIUM') {
    return (
      <span className={`inline-flex items-center space-x-1.5 text-[#A1A1A6] font-normal text-xs select-none ${className}`}>
        <span className="w-1.5 h-1.5 rounded-full bg-[#A1A1A6] shrink-0" />
        <span className="font-mono text-[11px]">{label}</span>
      </span>
    );
  }

  if (normalized === 'LOW') {
    return (
      <span className={`inline-flex items-center space-x-1.5 text-[#737378] font-normal text-xs select-none ${className}`}>
        <span className="w-1.5 h-1.5 rounded-full bg-[#737378] shrink-0" />
        <span className="font-mono text-[11px]">{label}</span>
      </span>
    );
  }

  return (
    <span className={`inline-flex items-center space-x-1.5 text-[#737378] text-xs font-mono select-none ${className}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-[#3A3A3A] shrink-0" />
      <span className="text-[11px]">{label}</span>
    </span>
  );
};

export interface StatusBadgeProps {
  status:
    | FindingStatus
    | ControlStatus
    | VerificationOutcome
    | 'PASS'
    | 'FAIL'
    | 'ERROR'
    | 'NOT_CONFIGURED'
    | 'UNKNOWN'
    | 'AVAILABLE'
    | 'ENABLED'
    | 'DISABLED'
    | 'PERMISSION_DENIED'
    | 'ACCESS_DENIED'
    | 'SUBSCRIPTION_REQUIRED'
    | 'APPROVED'
    | 'REJECTED'
    | 'PROPOSED'
    | 'VERIFIED'
    | 'ACTIVE'
    | 'DISCONNECTED'
    | 'AUTHENTICATED'
    | 'BLOCKED'
    | 'PASSED'
    | 'VIOLATION'
    | string;
  className?: string;
  showIcon?: boolean;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  status,
  className = '',
  showIcon = true,
}) => {
  const norm = (status || '').toUpperCase();
  const label = norm.replace(/_/g, ' ');

  // Positive / Passing / Verified states: Apple near-white primary text + CheckCircle2
  if (
    norm === 'PASS' ||
    norm === 'PASSED' ||
    norm === 'VERIFIED' ||
    norm === 'RESOLVED' ||
    norm === 'APPROVED' ||
    norm === 'AUTHENTICATED' ||
    norm === 'AVAILABLE' ||
    norm === 'ENABLED' ||
    norm === 'ACTIVE'
  ) {
    return (
      <span className={`inline-flex items-center space-x-1.5 text-[#F5F5F7] font-mono text-xs select-none ${className}`}>
        {showIcon && <CheckCircle2 className="w-3.5 h-3.5 text-[#FFFFFF] shrink-0" />}
        <span className="font-medium text-[11px]">{label}</span>
      </span>
    );
  }

  // Failing / Errors / Regressions / Violations: Strong primary text + AlertTriangle or XCircle
  if (
    norm === 'FAIL' ||
    norm === 'ERROR' ||
    norm === 'STILL_PRESENT' ||
    norm === 'REGRESSED' ||
    norm === 'BLOCKED' ||
    norm === 'REJECTED' ||
    norm === 'PERMISSION_DENIED' ||
    norm === 'ACCESS_DENIED' ||
    norm === 'VIOLATION'
  ) {
    return (
      <span className={`inline-flex items-center space-x-1.5 text-[#FFFFFF] font-mono text-xs select-none ${className}`}>
        {showIcon && <XCircle className="w-3.5 h-3.5 text-[#FFFFFF] shrink-0" />}
        <span className="font-semibold text-[11px]">{label}</span>
      </span>
    );
  }

  // In Review / Open / Needs Attention / Disabled: Secondary grey + Warning icon
  if (
    norm === 'IN_REVIEW' ||
    norm === 'OPEN' ||
    norm === 'NOT_CONFIGURED' ||
    norm === 'DISABLED' ||
    norm === 'NOT_SUBSCRIBED'
  ) {
    return (
      <span className={`inline-flex items-center space-x-1.5 text-[#A1A1A6] font-mono text-xs select-none ${className}`}>
        {showIcon && <AlertTriangle className="w-3 h-3 text-[#A1A1A6] shrink-0" />}
        <span className="text-[11px]">{label}</span>
      </span>
    );
  }

  // Unverifiable / Unknown / Muted / Unsupported Region: Tertiary grey + Help icon
  if (norm === 'UNVERIFIABLE' || norm === 'UNKNOWN' || norm === 'UNSUPPORTED_REGION') {
    return (
      <span className={`inline-flex items-center space-x-1.5 text-[#737378] font-mono text-xs select-none ${className}`}>
        {showIcon && <HelpCircle className="w-3 h-3 text-[#737378] shrink-0" />}
        <span className="text-[11px]">{label}</span>
      </span>
    );
  }


  // Neutral fallback
  return (
    <span className={`inline-flex items-center space-x-1.5 text-[#A1A1A6] font-mono text-xs select-none ${className}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-[#3A3A3A] shrink-0" />
      <span className="text-[11px]">{label}</span>
    </span>
  );
};

export interface ModeBadgeProps {
  mode: string;
  className?: string;
}

export const ModeBadge: React.FC<ModeBadgeProps> = ({ mode, className = '' }) => {
  const norm = (mode || '').toUpperCase();
  if (norm === 'LIVE_AWS') {
    return (
      <span className={`inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full bg-[#181818] border border-[#3A3A3A] text-[#F5F5F7] font-mono text-[11px] select-none ${className}`}>
        <span className="w-1.5 h-1.5 rounded-full bg-white shrink-0 animate-pulse" />
        <span className="font-medium tracking-wide">LIVE AWS</span>
      </span>
    );
  }

  if (norm === 'DEMO_FIXTURE') {
    return (
      <span className={`inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full bg-[#141414] border border-[#2A2A2A] text-[#A1A1A6] font-mono text-[11px] select-none ${className}`}>
        <span className="w-1.5 h-1.5 rounded-full bg-[#737378] shrink-0" />
        <span className="tracking-wide">DEMO BENCHMARK</span>
      </span>
    );
  }

  return (
    <span className={`inline-flex items-center space-x-1.5 px-2 py-0.5 rounded-full bg-[#101010] text-[#737378] font-mono text-[11px] select-none ${className}`}>
      <span>{norm || 'IDLE'}</span>
    </span>
  );
};
