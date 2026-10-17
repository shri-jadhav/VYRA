import React, { useState } from 'react';
import {
  Copy,
  Check,
  RefreshCw,
  AlertTriangle,
  Terminal,
  FileCode,
  ShieldCheck,
} from 'lucide-react';
import { RemediationPlan } from '../types';
import { StatusBadge } from '../components/ui/Badge';

interface RemediationViewProps {
  remediations: RemediationPlan[];
  isLoading: boolean;
  onApprove: (planId: string, approverName: string, action: 'APPROVE' | 'REJECT', notes?: string) => Promise<void>;
  onReverify: (planId: string) => Promise<any>;
}

export const RemediationView: React.FC<RemediationViewProps> = ({
  remediations,
  isLoading,
  onApprove,
  onReverify,
}) => {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [approvingId, setApprovingId] = useState<string | null>(null);
  const [reverifyingId, setReverifyingId] = useState<string | null>(null);
  const [verificationFeedback, setVerificationFeedback] = useState<Record<string, string>>({});

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleApprove = async (planId: string, action: 'APPROVE' | 'REJECT') => {
    setApprovingId(planId);
    try {
      await onApprove(planId, 'Cloud Security Engineer', action, 'Approved for dry-run verification');
    } finally {
      setApprovingId(null);
    }
  };

  const handleReverify = async (planId: string) => {
    setReverifyingId(planId);
    try {
      const res = await onReverify(planId);
      setVerificationFeedback((prev) => ({
        ...prev,
        [planId]: res.details || (res.remediated ? 'Re-verification PASSED: Fix verified on AWS' : 'Re-verification FAILED: Resource still failing'),
      }));
    } finally {
      setReverifyingId(null);
    }
  };

  return (
    <div className="p-6 space-y-5 max-w-7xl mx-auto font-sans animate-fade-in text-[#F5F5F7]">
      {/* View Header */}
      <div className="pb-3 border-b border-[#2A2A2A]">
        <div className="flex items-center space-x-2">
          <h1 className="text-lg font-semibold text-[#F5F5F7] tracking-tight">
            Remediation Plans ({remediations.length})
          </h1>
          <span className="text-xs text-[#737378] font-mono">
            Dry-Run Workspace
          </span>
        </div>
        <p className="text-xs text-[#737378] mt-0.5">
          Proposed cloud remediations, risk analysis, peer review approvals, and independent read-only re-verification.
        </p>
      </div>

      {/* Safety Notice */}
      <div className="p-4 rounded-2xl bg-[#101010] border border-[#2A2A2A] flex items-start space-x-3 text-xs text-[#A1A1A6]">
        <ShieldCheck className="w-4 h-4 text-white mt-0.5 shrink-0" />
        <div className="space-y-0.5 leading-relaxed">
          <div className="font-semibold text-white">Strict Dry-Run Only Guarantee</div>
          <div className="text-[11px] text-[#737378]">
            VYRA strictly will not mutate or reconfigure AWS resources. Generated CLI commands and Terraform
            snippets are provided for engineering review. The "Re-Verify" action executes an independent,
            read-only query to check whether an administrator or CI/CD pipeline has applied the fix.
          </div>
        </div>
      </div>

      {/* Remediation Plans List */}
      <div className="space-y-4">
        {isLoading ? (
          <div className="p-12 text-center text-xs text-[#737378] bg-[#101010] rounded-2xl border border-[#2A2A2A] font-mono">
            Loading remediation plans...
          </div>
        ) : remediations.length === 0 ? (
          <div className="p-12 text-center text-xs text-[#737378] bg-[#101010] rounded-2xl border border-[#2A2A2A] font-mono">
            No active remediation plans proposed.
          </div>
        ) : (
          remediations.map((plan) => (
            <div
              key={plan.id}
              className="p-5 rounded-2xl bg-[#101010] border border-[#2A2A2A] space-y-4"
            >
              {/* Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#2A2A2A] pb-3">
                <div>
                  <div className="text-[10px] font-mono text-[#737378]">
                    Plan ID: {plan.id} &middot; Finding: {plan.finding_id}
                  </div>
                  <h3 className="font-semibold text-sm text-[#F5F5F7] mt-0.5">{plan.title}</h3>
                </div>

                <div className="flex items-center space-x-2">
                  <StatusBadge status={plan.status} />

                  {/* Approval Actions */}
                  {plan.status === 'PROPOSED' && (
                    <div className="flex items-center space-x-1.5">
                      <button
                        onClick={() => handleApprove(plan.id, 'APPROVE')}
                        disabled={approvingId === plan.id}
                        className="px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-[#FFFFFF] hover:bg-[#D6D6D6] text-black transition-colors disabled:opacity-40 shadow-sm"
                      >
                        Approve Plan
                      </button>
                      <button
                        onClick={() => handleApprove(plan.id, 'REJECT')}
                        disabled={approvingId === plan.id}
                        className="px-3 py-1.5 rounded-xl text-xs font-medium bg-[#141414] hover:bg-[#202020] text-[#F5F5F7] border border-[#2A2A2A] transition-colors disabled:opacity-40"
                      >
                        Reject
                      </button>
                    </div>
                  )}

                  {/* Independent Re-Verify Button */}
                  <button
                    onClick={() => handleReverify(plan.id)}
                    disabled={reverifyingId === plan.id}
                    className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl text-xs font-medium bg-[#141414] hover:bg-[#202020] border border-[#2A2A2A] text-[#F5F5F7] transition-colors disabled:opacity-40"
                    title="Execute read-only query to independently check if resource was remediated externally"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 text-[#A1A1A6] ${reverifyingId === plan.id ? 'animate-spin' : ''}`} />
                    <span>Re-Verify</span>
                  </button>
                </div>
              </div>

              {/* Approval Audit Metadata */}
              {plan.approver && (
                <div className="text-[11px] font-mono text-[#737378] bg-[#141414] p-2.5 rounded-xl border border-[#2A2A2A] flex justify-between">
                  <span>Approved By: <strong className="text-[#F5F5F7]">{plan.approver}</strong></span>
                  <span>Timestamp: {plan.approved_at ? new Date(plan.approved_at).toUTCString() : 'N/A'}</span>
                </div>
              )}

              {/* Verification Feedback Banner */}
              {(verificationFeedback[plan.id] || plan.verification_output) && (
                <div className="p-3 rounded-xl bg-[#141414] border border-[#3A3A3A] text-xs font-mono text-[#F5F5F7]">
                  <div className="font-semibold text-white mb-0.5">Independent Verification Result:</div>
                  <div>{verificationFeedback[plan.id] || plan.verification_output}</div>
                </div>
              )}

              {/* Risk Rationale & Dry Run Simulation */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                <div className="p-3.5 rounded-xl bg-[#141414] border border-[#2A2A2A] space-y-1">
                  <div className="font-semibold text-white flex items-center space-x-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 text-[#A1A1A6]" />
                    <span className="text-[10px] uppercase font-mono tracking-wider">Operational Risk & Impact</span>
                  </div>
                  <p className="text-[#A1A1A6] text-xs leading-relaxed">{plan.risk_explanation}</p>
                </div>

                <div className="p-3.5 rounded-xl bg-[#141414] border border-[#2A2A2A] space-y-1">
                  <div className="font-semibold text-white flex items-center space-x-1.5">
                    <Terminal className="w-3.5 h-3.5 text-[#A1A1A6]" />
                    <span className="text-[10px] uppercase font-mono tracking-wider">Dry-Run Simulation Action</span>
                  </div>
                  <p className="text-[#A1A1A6] text-xs leading-relaxed">{plan.dry_run_action}</p>
                </div>
              </div>

              {/* Code Snippets: AWS CLI & Terraform */}
              <div className="space-y-3 font-mono">
                {/* CLI Command */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs text-[#737378]">
                    <span className="font-medium text-[#F5F5F7] flex items-center space-x-1.5 text-[11px]">
                      <Terminal className="w-3.5 h-3.5 text-[#A1A1A6]" />
                      <span>AWS CLI Remediation Command (Manual Execution)</span>
                    </span>
                    <button
                      onClick={() => copyToClipboard(plan.cli_command, `${plan.id}-cli`)}
                      className="flex items-center space-x-1 text-xs text-[#A1A1A6] hover:text-white transition-colors"
                    >
                      {copiedId === `${plan.id}-cli` ? <Check className="w-3 h-3 text-white" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedId === `${plan.id}-cli` ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="p-3 rounded-xl bg-[#0A0A0A] border border-[#2A2A2A] text-xs text-[#F5F5F7] overflow-x-auto whitespace-pre-wrap leading-relaxed">
                    {plan.cli_command}
                  </pre>
                </div>

                {/* Terraform Code */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs text-[#737378]">
                    <span className="font-medium text-[#F5F5F7] flex items-center space-x-1.5 text-[11px]">
                      <FileCode className="w-3.5 h-3.5 text-[#A1A1A6]" />
                      <span>Terraform Infrastructure-as-Code Module</span>
                    </span>
                    <button
                      onClick={() => copyToClipboard(plan.terraform_snippet, `${plan.id}-tf`)}
                      className="flex items-center space-x-1 text-xs text-[#A1A1A6] hover:text-white transition-colors"
                    >
                      {copiedId === `${plan.id}-tf` ? <Check className="w-3 h-3 text-white" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedId === `${plan.id}-tf` ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="p-3 rounded-xl bg-[#0A0A0A] border border-[#2A2A2A] text-xs text-[#D6D6D6] overflow-x-auto whitespace-pre-wrap leading-relaxed">
                    {plan.terraform_snippet}
                  </pre>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
