import React from 'react';
import { ShieldCheck } from 'lucide-react';
import { HealthStatus, OverviewMetrics } from '../types';
import { StatusBadge } from '../components/ui/Badge';

interface IntegrationsViewProps {
  health: HealthStatus | null;
  metrics: OverviewMetrics | null;
}

export const IntegrationsView: React.FC<IntegrationsViewProps> = ({ health, metrics }) => {
  const integrations = [
    {
      id: 'sts',
      name: 'AWS Security Token Service (STS)',
      category: 'Core Identity',
      status: health?.aws_auth_verified ? 'CONNECTED' : 'DISCONNECTED',
      permissions: ['sts:GetCallerIdentity'],
      description: 'Resolves caller identity, Account ID, and verified ARN. Strictly read-only zero-cost API.',
      statusNote: health?.aws_auth_verified ? 'Authenticated as vyra-auditor' : 'Not verified',
    },
    {
      id: 's3',
      name: 'Amazon S3 Security Posture',
      category: 'Storage Infrastructure',
      status: metrics?.total_assets ? 'ACTIVE' : 'READY',
      permissions: [
        's3:ListAllMyBuckets',
        's3:GetBucketLocation',
        's3:GetBucketPublicAccessBlock',
        's3:GetEncryptionConfiguration',
        's3:GetBucketVersioning',
        's3:GetBucketPolicyStatus',
      ],
      description: 'Inspects bucket security configurations. Strict safety guarantee: Never reads object contents.',
      statusNote: 'Bucket configuration metadata collected safely',
    },
    {
      id: 'iam',
      name: 'AWS Identity & Access Management (IAM)',
      category: 'Access Governance',
      status: metrics?.total_assets ? 'ACTIVE' : 'READY',
      permissions: [
        'iam:GetAccountSummary',
        'iam:ListUsers',
        'iam:ListMFADevices',
        'iam:ListAccessKeys',
        'iam:ListRoles',
      ],
      description: 'Assesses Root account MFA, programmatic access key age, and user MFA device posture.',
      statusNote: 'Least-privilege auditor scoping verified',
    },
    {
      id: 'cloudtrail',
      name: 'AWS CloudTrail Audit Logging',
      category: 'Governance & Auditing',
      status: 'ACTIVE',
      permissions: ['cloudtrail:DescribeTrails', 'cloudtrail:GetTrailStatus'],
      description: 'Verifies multi-region audit logging trails and log file validation integrity.',
      statusNote: 'Trail inventory assessed',
    },
    {
      id: 'accessanalyzer',
      name: 'IAM Access Analyzer',
      category: 'Threat & Resource Sharing',
      status: 'DISABLED',
      permissions: ['access-analyzer:ListAnalyzers'],
      description: 'Identifies unintended external resource sharing across accounts.',
      statusNote: '0 active analyzers in target region',
    },
    {
      id: 'guardduty',
      name: 'Amazon GuardDuty',
      category: 'Threat Detection',
      status: 'SUBSCRIPTION_REQUIRED',
      permissions: ['guardduty:ListDetectors'],
      description: 'Continuous intelligent threat detection and anomaly scanning.',
      statusNote: 'Account requires subscription (VYRA will not enable automatically)',
    },
    {
      id: 'securityhub',
      name: 'AWS Security Hub',
      category: 'Posture Aggregation',
      status: 'SUBSCRIPTION_REQUIRED',
      permissions: ['securityhub:DescribeHub'],
      description: 'Comprehensive view of security alerts and compliance posture.',
      statusNote: 'Account requires subscription (VYRA will not enable automatically)',
    },
    {
      id: 'config',
      name: 'AWS Config',
      category: 'Configuration History',
      status: 'DISABLED',
      permissions: ['config:DescribeConfigurationRecorders'],
      description: 'Monitors and records AWS resource configurations over time.',
      statusNote: '0 configuration recorders active in region',
    },
  ];

  return (
    <div className="p-6 space-y-5 max-w-7xl mx-auto font-sans animate-fade-in text-[#F5F5F7]">
      <div className="pb-3 border-b border-[#2A2A2A]">
        <div className="flex items-center space-x-2">
          <h1 className="text-lg font-semibold text-[#F5F5F7] tracking-tight">
            AWS Telemetry Integrations & Permissions
          </h1>
          <span className="text-xs text-[#737378] font-mono">
            Read-Only Collectors
          </span>
        </div>
        <p className="text-xs text-[#737378] mt-0.5">
          Explicitly invoked, read-only collectors using AWS CLI profile <code className="text-white bg-[#101010] px-1.5 py-0.5 rounded font-mono">vyra-readonly</code>.
        </p>
      </div>

      {/* Safety Notice */}
      <div className="p-4 rounded-2xl bg-[#101010] border border-[#2A2A2A] flex items-start space-x-3 text-xs text-[#A1A1A6]">
        <ShieldCheck className="w-4 h-4 text-white mt-0.5 shrink-0" />
        <div className="space-y-0.5 leading-relaxed">
          <div className="font-semibold text-white">Strict Read-Only Guardrails</div>
          <div className="text-[11px] text-[#737378]">
            VYRA operates exclusively via verified read-only API calls. Paid services (GuardDuty, Security Hub)
            are accurately reported when unsubscribed or disabled, and will never be enabled automatically.
            S3 object contents are never read.
          </div>
        </div>
      </div>

      {/* Integrations Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {integrations.map((item) => (
          <div
            key={item.id}
            className="p-4 rounded-2xl bg-[#101010] border border-[#2A2A2A] space-y-3 flex flex-col justify-between"
          >
            <div className="space-y-2">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="text-[10px] text-[#737378] uppercase tracking-wider font-semibold">
                    {item.category}
                  </div>
                  <h3 className="font-semibold text-sm text-[#F5F5F7] mt-0.5">{item.name}</h3>
                </div>
                <StatusBadge status={item.status} />
              </div>

              <p className="text-xs text-[#A1A1A6] font-sans leading-relaxed">{item.description}</p>
            </div>

            <div className="space-y-2 pt-2 border-t border-[#2A2A2A] font-mono">
              <div className="text-[11px] text-[#737378] bg-[#141414] p-2.5 rounded-xl border border-[#2A2A2A]">
                Status: <span className="text-[#F5F5F7]">{item.statusNote}</span>
              </div>

              <div>
                <div className="text-[10px] uppercase font-semibold text-[#737378] mb-1">
                  Required Read-Only Permissions:
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {item.permissions.map((p) => (
                    <span
                      key={p}
                      className="text-[10px] px-2 py-0.5 rounded-lg bg-[#141414] text-[#D6D6D6] border border-[#2A2A2A]"
                    >
                      {p}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
