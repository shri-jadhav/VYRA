import React from 'react';
import { ShieldCheck, CheckCircle2, Terminal } from 'lucide-react';
import { HealthStatus } from '../types';
import { StatusBadge } from '../components/ui/Badge';

interface SettingsViewProps {
  health: HealthStatus | null;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ health }) => {
  return (
    <div className="p-6 space-y-5 max-w-5xl mx-auto font-sans animate-fade-in text-[#F5F5F7]">
      <div className="pb-3 border-b border-[#2A2A2A]">
        <div className="flex items-center space-x-2">
          <h1 className="text-lg font-semibold text-[#F5F5F7] tracking-tight">
            Settings & Guardrails
          </h1>
          <span className="text-xs text-[#737378] font-mono">
            Security Architecture
          </span>
        </div>
        <p className="text-xs text-[#737378] mt-0.5">
          Active security guardrails, credential safety policies, and local runtime configuration.
        </p>
      </div>

      {/* Safety Guardrails Grouped Section */}
      <div className="p-5 rounded-2xl bg-[#101010] border border-[#2A2A2A] space-y-4">
        <h3 className="font-semibold text-xs text-[#F5F5F7] uppercase tracking-wider flex items-center space-x-2">
          <ShieldCheck className="w-4 h-4 text-white" />
          <span>Enforced AWS Safety Architecture</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          <div className="p-3.5 rounded-xl bg-[#141414] border border-[#2A2A2A] space-y-1">
            <div className="font-semibold text-white flex items-center space-x-1.5 font-mono">
              <CheckCircle2 className="w-3.5 h-3.5 text-white" />
              <span>Explicit Read-Only Profile</span>
            </div>
            <p className="text-[#A1A1A6] font-sans text-xs leading-relaxed">
              AWS collectors exclusively target the configured profile: <code className="font-mono text-white bg-[#0A0A0A] px-1.5 py-0.5 rounded">{health?.aws_profile || 'vyra-readonly'}</code>.
              Standard boto3 credential resolution is used without hardcoding or token exposure.
            </p>
          </div>

          <div className="p-3.5 rounded-xl bg-[#141414] border border-[#2A2A2A] space-y-1">
            <div className="font-semibold text-white flex items-center space-x-1.5 font-mono">
              <CheckCircle2 className="w-3.5 h-3.5 text-white" />
              <span>Zero S3 Object Content Access</span>
            </div>
            <p className="text-[#A1A1A6] font-sans text-xs leading-relaxed">
              S3 collectors query bucket-level security configuration metadata (encryption, versioning, public access block).
              No <code className="font-mono text-white bg-[#0A0A0A] px-1.5 py-0.5 rounded">s3:GetObject</code> operations are ever performed.
            </p>
          </div>

          <div className="p-3.5 rounded-xl bg-[#141414] border border-[#2A2A2A] space-y-1">
            <div className="font-semibold text-white flex items-center space-x-1.5 font-mono">
              <CheckCircle2 className="w-3.5 h-3.5 text-white" />
              <span>No Resource Mutation or Provisioning</span>
            </div>
            <p className="text-[#A1A1A6] font-sans text-xs leading-relaxed">
              VYRA never creates, modifies, deletes, deploys, or reconfigures AWS resources.
              Remediation plans are strictly dry-run only. <code className="font-mono text-white bg-[#0A0A0A] px-1.5 py-0.5 rounded">terraform apply</code> is never run.
            </p>
          </div>

          <div className="p-3.5 rounded-xl bg-[#141414] border border-[#2A2A2A] space-y-1">
            <div className="font-semibold text-white flex items-center space-x-1.5 font-mono">
              <CheckCircle2 className="w-3.5 h-3.5 text-white" />
              <span>Paid Services Protection</span>
            </div>
            <p className="text-[#A1A1A6] font-sans text-xs leading-relaxed">
              Optional services (GuardDuty, Security Hub) report subscription requirements accurately and
              will never be auto-enabled or provisioned without explicit external configuration.
            </p>
          </div>
        </div>
      </div>

      {/* Verified Permissions & Identity Group */}
      <div className="p-5 rounded-2xl bg-[#101010] border border-[#2A2A2A] space-y-3">
        <h3 className="font-semibold text-xs text-[#F5F5F7] uppercase tracking-wider">
          Verified AWS Caller Identity
        </h3>
        <div className="p-3.5 rounded-xl bg-[#141414] border border-[#2A2A2A] space-y-2.5 text-xs font-mono">
          <div className="flex justify-between items-center">
            <span className="text-[#737378]">Verified Status:</span>
            <StatusBadge status={health?.aws_auth_verified ? 'AUTHENTICATED' : 'DISCONNECTED'} />
          </div>
          <div className="flex justify-between items-center">
            <span className="text-[#737378]">Target Account ID:</span>
            <span className="text-white font-semibold">{health?.aws_account_id || 'N/A'}</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-[#737378]">Caller ARN:</span>
            <span className="text-[#D6D6D6] truncate max-w-md">{health?.aws_arn || 'N/A'}</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-[#737378]">Profile Name:</span>
            <span className="text-white">{health?.aws_profile || 'vyra-readonly'}</span>
          </div>
        </div>
      </div>

      {/* Terminal CLI Assessment Command */}
      <div className="p-5 rounded-2xl bg-[#101010] border border-[#2A2A2A] space-y-3 font-mono">
        <div className="flex items-center space-x-2">
          <Terminal className="w-3.5 h-3.5 text-[#A1A1A6]" />
          <h3 className="font-semibold text-xs text-[#F5F5F7] uppercase tracking-wider">
            Terminal CLI Assessment Command
          </h3>
        </div>
        <p className="text-xs text-[#737378] font-sans">
          To run an assessment or test locally via terminal without UI:
        </p>
        <pre className="p-3 rounded-xl bg-[#0A0A0A] border border-[#2A2A2A] text-xs text-[#F5F5F7] overflow-x-auto leading-relaxed">
{`# Run assessment via backend API
curl -X POST http://127.0.0.1:8000/api/v1/assessment/trigger \\
  -H "Content-Type: application/json" \\
  -d '{"mode": "LIVE_AWS", "profile": "vyra-readonly"}'`}
        </pre>
      </div>
    </div>
  );
};
