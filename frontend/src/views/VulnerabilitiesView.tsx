import React from 'react';
import { Finding, OverviewMetrics } from '../types';
import { SeverityBadge } from '../components/ui/Badge';

interface VulnerabilitiesViewProps {
  findings: Finding[];
  metrics?: OverviewMetrics | null;
}

export const VulnerabilitiesView: React.FC<VulnerabilitiesViewProps> = ({ findings }) => {
  const threatVectors = [
    {
      id: 'vector-s3-public',
      title: 'Public Cloud Storage Exposure Vector',
      cwe: 'CWE-200: Exposure of Sensitive Information',
      mitre: 'T1537 (Transfer Data to Cloud Account) / T1078.004 (Cloud Accounts)',
      severity: 'CRITICAL',
      impact: 'Allows unauthenticated adversaries to discover or exfiltrate sensitive cloud data assets over public internet.',
      affectedCount: findings.filter((f) => f.control_id === 'VYRA-S3-001' || f.control_id === 'VYRA-S3-004').length,
      sampleFinding: findings.find((f) => f.control_id === 'VYRA-S3-001' || f.control_id === 'VYRA-S3-004'),
    },
    {
      id: 'vector-root-mfa',
      title: 'Root Identity Hijack & Unprotected Break-Glass Vector',
      cwe: 'CWE-308: Use of Single-factor Authentication',
      mitre: 'T1078.004 (Cloud Accounts) / T1098 (Account Manipulation)',
      severity: 'CRITICAL',
      impact: 'Single-factor root account credentials vulnerable to credential stuffing, password spray, or phishing takeover.',
      affectedCount: findings.filter((f) => f.control_id === 'VYRA-IAM-001').length,
      sampleFinding: findings.find((f) => f.control_id === 'VYRA-IAM-001'),
    },
    {
      id: 'vector-stale-keys',
      title: 'Stale Long-Lived API Credential Vector',
      cwe: 'CWE-1004: Inadequate Key Lifetime',
      mitre: 'T1552 (Unsecured Credentials) / T1078 (Valid Accounts)',
      severity: 'MEDIUM',
      impact: 'Unrotated access keys aged beyond 90 days increase exposure window for leaked secrets in source code or CI logs.',
      affectedCount: findings.filter((f) => f.control_id === 'VYRA-IAM-004').length,
      sampleFinding: findings.find((f) => f.control_id === 'VYRA-IAM-004'),
    },
    {
      id: 'vector-unmonitored-audit',
      title: 'Blindspot & Audit Evasion Vector (Missing CloudTrail)',
      cwe: 'CWE-778: Insufficient Logging',
      mitre: 'T1562.008 (Disable or Bypass Cloud Logs)',
      severity: 'HIGH',
      impact: 'Absence of active multi-region audit trails prevents forensic investigation, incident response, and breach detection.',
      affectedCount: findings.filter((f) => f.control_id === 'VYRA-CT-001').length,
      sampleFinding: findings.find((f) => f.control_id === 'VYRA-CT-001'),
    },
  ];

  return (
    <div className="p-6 space-y-5 max-w-7xl mx-auto font-sans animate-fade-in text-[#F5F5F7]">
      <div className="pb-3 border-b border-[#2A2A2A]">
        <div className="flex items-center space-x-2">
          <h1 className="text-lg font-semibold text-[#F5F5F7] tracking-tight">
            Threat Vectors & MITRE Matrix
          </h1>
          <span className="text-xs text-[#737378] font-mono">
            MITRE ATT&CK &middot; CWE
          </span>
        </div>
        <p className="text-xs text-[#737378] mt-0.5">
          Correlating observed cloud security misconfigurations to MITRE ATT&CK tactics and vulnerability classifications.
        </p>
      </div>

      {/* Threat Vectors Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {threatVectors.map((v) => (
          <div
            key={v.id}
            className="p-5 rounded-2xl bg-[#101010] border border-[#2A2A2A] space-y-3 flex flex-col justify-between"
          >
            <div className="space-y-2">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[#141414] border border-[#2A2A2A] text-[#737378]">
                    {v.cwe}
                  </span>
                  <h3 className="font-semibold text-sm text-[#F5F5F7] mt-1.5">{v.title}</h3>
                </div>
                <SeverityBadge severity={v.severity} />
              </div>

              <div className="text-xs text-[#A1A1A6] font-sans leading-relaxed">
                <strong className="text-white text-[11px] block mb-0.5">Exploitation Impact: </strong>
                {v.impact}
              </div>
            </div>

            <div className="space-y-2 pt-2 border-t border-[#2A2A2A] font-mono text-xs">
              <div className="p-3 rounded-xl bg-[#141414] border border-[#2A2A2A] space-y-1">
                <div className="text-[#737378] text-[11px]">
                  <span>MITRE ATT&CK: </span>
                  <span className="text-[#F5F5F7]">{v.mitre}</span>
                </div>
                <div className="text-[#737378] text-[11px] flex items-center justify-between">
                  <span>Correlated Exposure:</span>
                  <span className={v.affectedCount > 0 ? 'text-white font-semibold' : 'text-[#A1A1A6]'}>
                    {v.affectedCount} asset(s) exposed
                  </span>
                </div>
              </div>

              {v.sampleFinding && (
                <div className="text-[11px] text-[#737378] flex justify-between items-center">
                  <span>Observed on: <strong className="text-[#F5F5F7]">{v.sampleFinding.resource_id}</strong></span>
                  <span className="text-[#D6D6D6]">Remediation mapped</span>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
