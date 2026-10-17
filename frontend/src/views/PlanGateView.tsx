import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Download,
  Copy,
  Check,
  AlertTriangle,
  Play,
  FileCode,
  Terminal,
} from 'lucide-react';
import { api } from '../api/client';
import { PlanCheckRun } from '../types';
import { SeverityBadge, StatusBadge } from '../components/ui/Badge';

export const PlanGateView: React.FC = () => {
  const [planJsonInput, setPlanJsonInput] = useState<string>('');
  const [activeRun, setActiveRun] = useState<PlanCheckRun | null>(null);
  const [isEvaluating, setIsEvaluating] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedCi, setCopiedCi] = useState<boolean>(false);

  const sampleInsecurePlan = {
    format_version: '1.2',
    terraform_version: '1.9.0',
    resource_changes: [
      {
        address: 'aws_s3_bucket_public_access_block.drainsentinel_web',
        type: 'aws_s3_bucket_public_access_block',
        name: 'drainsentinel_web',
        change: {
          actions: ['update'],
          before: {
            block_public_acls: true,
            block_public_policy: true,
            ignore_public_acls: true,
            restrict_public_buckets: true,
          },
          after: {
            block_public_acls: false,
            block_public_policy: false,
            ignore_public_acls: false,
            restrict_public_buckets: false,
          },
        },
      },
      {
        address: 'aws_iam_role_policy.overpermissive_deploy_policy',
        type: 'aws_iam_role_policy',
        name: 'overpermissive_deploy_policy',
        change: {
          actions: ['create'],
          after: {
            policy: JSON.stringify({
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Action: '*',
                  Resource: '*',
                },
              ],
            }),
          },
        },
      },
      {
        address: 'aws_security_group_rule.open_ssh_rule',
        type: 'aws_security_group_rule',
        name: 'open_ssh_rule',
        change: {
          actions: ['create'],
          after: {
            type: 'ingress',
            from_port: 22,
            to_port: 22,
            protocol: 'tcp',
            cidr_blocks: ['0.0.0.0/0'],
          },
        },
      },
    ],
  };

  const sampleSecurePlan = {
    format_version: '1.2',
    terraform_version: '1.9.0',
    resource_changes: [
      {
        address: 'aws_s3_bucket_public_access_block.drainsentinel_web',
        type: 'aws_s3_bucket_public_access_block',
        name: 'drainsentinel_web',
        change: {
          actions: ['create'],
          after: {
            block_public_acls: true,
            block_public_policy: true,
            ignore_public_acls: true,
            restrict_public_buckets: true,
          },
        },
      },
      {
        address: 'aws_s3_bucket_server_side_encryption_configuration.secure_s3',
        type: 'aws_s3_bucket_server_side_encryption_configuration',
        name: 'secure_s3',
        change: {
          actions: ['create'],
          after: {
            rule: [{ apply_server_side_encryption_by_default: [{ sse_algorithm: 'AES256' }] }],
          },
        },
      },
      {
        address: 'aws_security_group_rule.secure_ingress',
        type: 'aws_security_group_rule',
        name: 'secure_ingress',
        change: {
          actions: ['create'],
          after: {
            type: 'ingress',
            from_port: 443,
            to_port: 443,
            protocol: 'tcp',
            cidr_blocks: ['10.0.0.0/16'],
          },
        },
      },
    ],
  };

  const handleEvaluate = async (contentObj?: any) => {
    setIsEvaluating(true);
    setError(null);
    try {
      let parsedPlan = contentObj;
      if (!parsedPlan) {
        if (!planJsonInput.trim()) {
          throw new Error('Please paste Terraform plan JSON or load a sample plan.');
        }
        parsedPlan = JSON.parse(planJsonInput);
      }

      const res = await api.evaluatePlan({
        source_filename: 'terraform.plan.json',
        plan_content: parsedPlan,
      });
      setActiveRun(res);
    } catch (err: any) {
      setError(`Plan evaluation failed: ${err.message}`);
    } finally {
      setIsEvaluating(false);
    }
  };

  const handleLoadSample = (sample: any) => {
    const formatted = JSON.stringify(sample, null, 2);
    setPlanJsonInput(formatted);
    handleEvaluate(sample);
  };

  const handleCopyCiYaml = () => {
    const yaml = `# .github/workflows/vyra-gate.yml
name: "VYRA Pre-Deployment Security Gate"
on:
  pull_request:
    branches: [main, master]

jobs:
  regression-gate:
    name: "Evaluate Security Regressions"
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Terraform Plan
        run: |
          terraform init
          terraform plan -out=tfplan.binary
          terraform show -json tfplan.binary > tfplan.json

      - name: Run VYRA Plan Gate
        run: |
          python -m backend.app.plan_checker.cli tfplan.json --format sarif --output vyra-gate.sarif

      - name: Upload SARIF to GitHub Security Tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: vyra-gate.sarif
`;
    navigator.clipboard.writeText(yaml);
    setCopiedCi(true);
    setTimeout(() => setCopiedCi(false), 2000);
  };

  return (
    <div className="p-6 space-y-5 max-w-7xl mx-auto font-sans animate-fade-in text-[#F5F5F7]">
      {/* Title & SARIF Download */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center pb-3 border-b border-[#2A2A2A] gap-3">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-lg font-semibold text-[#F5F5F7] tracking-tight">
              Pre-Deployment Security Gate
            </h1>
            <span className="text-xs text-[#A1A1A6] font-mono">
              CI / CD Regression Gate
            </span>
          </div>
          <p className="text-xs text-[#737378] mt-0.5">
            Static analysis for Terraform plans before apply. Halts deployment pipelines on detected S3, IAM, and Security Group regressions.
          </p>
        </div>

        {activeRun && (
          <a
            href={api.getPlanSarifUrl(activeRun.id)}
            download
            className="px-3 py-1.5 text-xs text-[#F5F5F7] hover:text-white bg-[#141414] hover:bg-[#202020] border border-[#2A2A2A] rounded-xl flex items-center space-x-1.5 transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-[#F5F5F7]" />
            <span>Download SARIF v2.1.0</span>
          </a>
        )}
      </div>

      {error && (
        <div className="p-3 bg-[#141414] border border-[#3A3A3A] rounded-xl text-xs text-[#F5F5F7] flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 text-white shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Plan Input Section */}
      <div className="bg-[#101010] border border-[#2A2A2A] rounded-2xl p-4 space-y-3">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
          <label className="text-[11px] font-medium text-[#737378] flex items-center space-x-1.5">
            <FileCode className="w-3.5 h-3.5 text-[#A1A1A6]" />
            <span>Terraform Plan JSON (from terraform show -json)</span>
          </label>

          <div className="flex items-center space-x-2 text-xs">
            <button
              onClick={() => handleLoadSample(sampleInsecurePlan)}
              className="px-2.5 py-1 bg-[#141414] hover:bg-[#202020] text-[#F5F5F7] border border-[#2A2A2A] rounded-lg transition-colors text-xs"
            >
              Load Insecure Plan
            </button>
            <button
              onClick={() => handleLoadSample(sampleSecurePlan)}
              className="px-2.5 py-1 bg-[#141414] hover:bg-[#202020] text-[#F5F5F7] border border-[#2A2A2A] rounded-lg transition-colors text-xs"
            >
              Load Secure Plan
            </button>
          </div>
        </div>

        <textarea
          rows={5}
          value={planJsonInput}
          onChange={(e) => setPlanJsonInput(e.target.value)}
          placeholder='Paste Terraform plan JSON here or click "Load Insecure Plan" above...'
          className="w-full bg-[#141414] border border-[#2A2A2A] text-[#F5F5F7] font-mono text-xs rounded-xl p-3 focus:outline-none focus:border-[#3A3A3A]"
        />

        <div className="flex justify-end">
          <button
            onClick={() => handleEvaluate()}
            disabled={isEvaluating}
            className="px-4 py-2 bg-[#FFFFFF] hover:bg-[#D6D6D6] text-black font-semibold text-xs rounded-xl flex items-center space-x-1.5 transition-colors disabled:opacity-40 shadow-sm"
          >
            <Play className="w-3.5 h-3.5 fill-current text-black" />
            <span>{isEvaluating ? 'Evaluating Plan...' : 'Evaluate Pre-Deployment Gate'}</span>
          </button>
        </div>
      </div>

      {/* Evaluation Results Banner & Metrics */}
      {activeRun && (
        <div className="space-y-4">
          {/* Status Banner */}
          <div
            className={`p-4 rounded-2xl border flex flex-col md:flex-row justify-between items-start md:items-center gap-3 bg-[#101010] ${
              activeRun.status === 'BLOCKED' ? 'border-[#3A3A3A]' : 'border-[#2A2A2A]'
            }`}
          >
            <div className="flex items-center space-x-3.5">
              {activeRun.status === 'BLOCKED' ? (
                <ShieldAlert className="w-6 h-6 text-white shrink-0" />
              ) : (
                <ShieldCheck className="w-6 h-6 text-white shrink-0" />
              )}
              <div>
                <div className="flex items-center space-x-2">
                  <span className="font-semibold text-xs uppercase tracking-wider text-white">
                    CI Gate {activeRun.status}
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[#141414] border border-[#2A2A2A] text-[#A1A1A6]">
                    Exit Code: {activeRun.status === 'BLOCKED' ? '1' : '0'}
                  </span>
                </div>
                <p className="text-xs text-[#A1A1A6] mt-0.5">
                  {activeRun.summary}
                </p>
              </div>
            </div>

            <div className="text-right text-xs font-mono text-[#737378]">
              <div>Run ID: {activeRun.id}</div>
              <div className="text-[10px]">{new Date(activeRun.created_at).toUTCString()}</div>
            </div>
          </div>

          {/* Metrics Counters */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="p-3.5 bg-[#101010] border border-[#2A2A2A] rounded-xl">
              <span className="text-[10px] uppercase font-semibold tracking-wider text-[#737378] block">
                Blocking Violations
              </span>
              <span className="text-xl font-bold font-mono text-white mt-0.5 block">
                {activeRun.blocking_count}
              </span>
            </div>
            <div className="p-3.5 bg-[#101010] border border-[#2A2A2A] rounded-xl">
              <span className="text-[10px] uppercase font-semibold tracking-wider text-[#737378] block">
                Warnings
              </span>
              <span className="text-xl font-bold font-mono text-[#A1A1A6] mt-0.5 block">
                {activeRun.warning_count}
              </span>
            </div>
            <div className="p-3.5 bg-[#101010] border border-[#2A2A2A] rounded-xl">
              <span className="text-[10px] uppercase font-semibold tracking-wider text-[#737378] block">
                Computed Unknowns
              </span>
              <span className="text-xl font-bold font-mono text-[#737378] mt-0.5 block">
                {activeRun.unknown_count}
              </span>
            </div>
            <div className="p-3.5 bg-[#101010] border border-[#2A2A2A] rounded-xl">
              <span className="text-[10px] uppercase font-semibold tracking-wider text-[#737378] block">
                Checks Passed
              </span>
              <span className="text-xl font-bold font-mono text-white mt-0.5 block">
                {activeRun.passed_count}
              </span>
            </div>
          </div>

          {/* Violations Table */}
          <div className="bg-[#101010] border border-[#2A2A2A] rounded-2xl p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F7]">
                Gate Rule Findings & Violations
              </h3>
              <span className="text-[11px] font-mono text-[#737378]">
                {activeRun.findings_data.length} evaluations
              </span>
            </div>

            <div className="border border-[#2A2A2A] rounded-xl overflow-hidden">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#141414] border-b border-[#2A2A2A] text-[#737378] text-[10px] uppercase tracking-wider">
                  <tr>
                    <th className="p-2.5">Rule ID</th>
                    <th className="p-2.5">Status</th>
                    <th className="p-2.5">Severity</th>
                    <th className="p-2.5">Resource Address</th>
                    <th className="p-2.5 font-sans">Violation Detail</th>
                    <th className="p-2.5">Remediation Snippet</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#2A2A2A]">
                  {activeRun.findings_data.map((f, i) => (
                    <tr key={i} className="hover:bg-[#141414]">
                      <td className="p-2.5 font-bold text-[#F5F5F7]">{f.rule_id}</td>
                      <td className="p-2.5">
                        <StatusBadge status={f.status} showIcon={false} />
                      </td>
                      <td className="p-2.5">
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="p-2.5 text-[#F5F5F7] truncate max-w-[200px]" title={f.resource_address}>
                        {f.resource_address}
                      </td>
                      <td className="p-2.5 text-[#A1A1A6] font-sans text-xs">{f.message}</td>
                      <td className="p-2.5 text-[#737378] text-[11px] font-mono max-w-[260px] truncate" title={f.remediation_advice}>
                        {f.remediation_advice}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* GitHub Actions Integration Guide */}
      <div className="bg-[#101010] border border-[#2A2A2A] rounded-2xl p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Terminal className="w-3.5 h-3.5 text-[#A1A1A6]" />
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[#F5F5F7]">
              CI / CD Pipeline Integration (GitHub Actions)
            </h3>
          </div>
          <button
            onClick={handleCopyCiYaml}
            className="px-2.5 py-1 text-xs bg-[#141414] hover:bg-[#202020] border border-[#2A2A2A] text-[#F5F5F7] rounded-xl flex items-center space-x-1 transition-colors"
          >
            {copiedCi ? <Check className="w-3 h-3 text-white" /> : <Copy className="w-3 h-3" />}
            <span>{copiedCi ? 'Copied' : 'Copy Workflow YAML'}</span>
          </button>
        </div>
        <p className="text-xs text-[#A1A1A6] leading-relaxed">
          Enforce pre-deployment security regression checks automatically on all Pull Requests. The gate
          evaluates the generated Terraform plan JSON and halts the pipeline with exit code 1 if blocking
          violations exist.
        </p>

        <pre className="p-3 bg-[#0A0A0A] border border-[#2A2A2A] rounded-xl font-mono text-[11px] text-[#A1A1A6] overflow-x-auto leading-relaxed">
{`# CLI Invocation:
vyra plan-check tfplan.json --format sarif --output vyra.sarif

# GitHub Actions Step (.github/workflows/vyra-gate.yml):
- name: Run VYRA Security Regression Gate
  run: vyra plan-check tfplan.json --format sarif --output vyra.sarif

- name: Upload SARIF to GitHub Security Tab
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: vyra.sarif`}
        </pre>
      </div>
    </div>
  );
};
