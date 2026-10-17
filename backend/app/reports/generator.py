from datetime import UTC, datetime
from typing import Any

from jinja2 import Template

from backend.app.models.models import AssessmentRun, ControlEvaluation, Finding

HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VYRA Security Assessment Report - {{ run.id }}</title>
  <style>
    :root {
      --bg: #080808;
      --surface-1: #111111;
      --surface-2: #171717;
      --border: #2A2A2A;
      --text-pri: #F5F5F5;
      --text-sec: #A3A3A3;
      --pass: #22c55e;
      --fail: #ef4444;
      --warn: #eab308;
      --info: #3b82f6;
    }
    body {
      background-color: var(--bg);
      color: var(--text-pri);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      margin: 0;
      padding: 40px;
      line-height: 1.5;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    .header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 24px;
      margin-bottom: 32px;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
    }
    .logo { font-size: 24px; font-weight: 800; letter-spacing: 2px; }
    .tagline { color: var(--text-sec); font-size: 13px; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
    .meta-box {
      background: var(--surface-1);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 32px;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
    }
    .meta-item .label { font-size: 11px; text-transform: uppercase; color: var(--text-sec); letter-spacing: 0.5px; }
    .meta-item .val { font-size: 16px; font-weight: 600; margin-top: 4px; }
    .badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
    }
    .badge-pass { background: rgba(34, 197, 94, 0.15); color: var(--pass); border: 1px solid rgba(34, 197, 94, 0.3); }
    .badge-fail { background: rgba(239, 68, 68, 0.15); color: var(--fail); border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-error { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
    .badge-not-configured { background: rgba(234, 179, 8, 0.15); color: var(--warn); border: 1px solid rgba(234, 179, 8, 0.3); }
    .badge-critical { background: #450a0a; color: #fca5a5; border: 1px solid #7f1d1d; }
    .badge-high { background: #3b0764; color: #d8b4fe; border: 1px solid #581c87; }
    .badge-medium { background: #1e1b4b; color: #93c5fd; border: 1px solid #312e81; }
    .badge-low { background: #14532d; color: #86efac; border: 1px solid #166534; }
    h2 { font-size: 18px; font-weight: 700; border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-top: 40px; }
    table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 13px; }
    th { text-align: left; background: var(--surface-2); padding: 10px 14px; border: 1px solid var(--border); color: var(--text-sec); font-weight: 600; }
    td { padding: 12px 14px; border: 1px solid var(--border); background: var(--surface-1); vertical-align: top; }
    .finding-card {
      background: var(--surface-1);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 16px;
      margin-bottom: 16px;
    }
    .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
    .finding-title { font-weight: 700; font-size: 15px; }
    .code-block {
      background: #000;
      border: 1px solid var(--border);
      padding: 10px;
      border-radius: 4px;
      font-family: monospace;
      font-size: 12px;
      color: #7dd3fc;
      overflow-x: auto;
      margin-top: 8px;
    }
    .footer { margin-top: 60px; font-size: 12px; color: var(--text-sec); text-align: center; border-top: 1px solid var(--border); padding-top: 24px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <div class="logo">VYRA</div>
        <div class="tagline">Observe. Validate. Remediate.</div>
      </div>
      <div style="text-align: right;">
        <span class="badge {{ 'badge-pass' if run.mode == 'LIVE_AWS' else 'badge-not-configured' }}">{{ run.mode }}</span>
        <div style="font-size: 12px; color: var(--text-sec); margin-top: 6px;">Report Generated: {{ generated_at }}</div>
      </div>
    </div>

    <div class="meta-box">
      <div class="meta-item">
        <div class="label">Target Account</div>
        <div class="val">{{ run.target_account }}</div>
      </div>
      <div class="meta-item">
        <div class="label">Target Region</div>
        <div class="val">{{ run.target_region }}</div>
      </div>
      <div class="meta-item">
        <div class="label">AWS Profile</div>
        <div class="val">{{ run.profile_used }}</div>
      </div>
      <div class="meta-item">
        <div class="label">Security Score</div>
        <div class="val">{{ security_score }}%</div>
      </div>
      <div class="meta-item">
        <div class="label">Controls (Pass / Fail / Gap)</div>
        <div class="val">{{ run.passed_controls }} / {{ run.failed_controls }} / {{ run.not_configured_controls }}</div>
      </div>
      <div class="meta-item">
        <div class="label">Active Findings</div>
        <div class="val">{{ findings|length }}</div>
      </div>
    </div>

    <h2>1. Executive Summary & Provenance</h2>
    <p style="color: var(--text-sec); font-size: 14px;">
      This assessment was conducted by the VYRA Cloud Security Engineering Platform using read-only AWS APIs under explicit guardrails.
      No mutations or resource modifications were performed. Findings represent point-in-time configuration validation against established
      security best practices and CIS benchmarks.
    </p>

    <h2>2. Normalized Security Findings ({{ findings|length }})</h2>
    {% if not findings %}
      <p style="color: var(--text-sec); font-size: 14px;">No security findings identified.</p>
    {% else %}
      {% for f in findings %}
        <div class="finding-card">
          <div class="finding-header">
            <span class="finding-title">{{ f.title }}</span>
            <span class="badge badge-{{ f.severity|lower }}">{{ f.severity }}</span>
          </div>
          <div style="font-size: 13px; color: var(--text-sec); margin-bottom: 8px;">
            <strong>Resource:</strong> <code>{{ f.resource_id }}</code> |
            <strong>Status:</strong> {{ f.status }} |
            <strong>Evidence:</strong> {{ f.evidence_reference }}
          </div>
          <div style="font-size: 13px; margin-bottom: 8px;">
            {{ f.description }}
          </div>
          {% if f.remediation_guidance %}
            <div style="font-size: 12px; color: #a3a3a3; margin-top: 8px;">
              <strong>Recommended Remediation:</strong> {{ f.remediation_guidance }}
            </div>
          {% endif %}
        </div>
      {% endfor %}
    {% endif %}

    <h2>3. Security Controls Evaluation Posture</h2>
    <table>
      <thead>
        <tr>
          <th>Control ID</th>
          <th>Control Title</th>
          <th>Category</th>
          <th>Status</th>
          <th>Resource</th>
          <th>Evaluation Rationale</th>
        </tr>
      </thead>
      <tbody>
        {% for ev in evaluations %}
          <tr>
            <td><code>{{ ev.control_id }}</code></td>
            <td>{{ ev.title }}</td>
            <td>{{ ev.category }}</td>
            <td>
              <span class="badge badge-{{ ev.status|lower|replace('_', '-') }}">{{ ev.status }}</span>
            </td>
            <td><code>{{ ev.resource_id }}</code></td>
            <td>{{ ev.rationale }}</td>
          </tr>
        {% endfor %}
      </tbody>
    </table>

    <div class="footer">
      VYRA Cloud & Endpoint Security Engineering Platform &bull; Automated Read-Only Audit &bull; Generated {{ generated_at }}
    </div>
  </div>
</body>
</html>
"""


class ReportGenerator:
    """Generates JSON and HTML assessment reports."""

    @staticmethod
    def generate_json_report(run: AssessmentRun, evaluations: list[ControlEvaluation], findings: list[Finding]) -> dict[str, Any]:
        return {
            "report_id": f"REP-{run.id}",
            "generated_at": datetime.now(UTC).isoformat(),
            "assessment_run": {
                "id": run.id,
                "started_at": run.started_at.isoformat() if run.started_at else None,
                "completed_at": run.completed_at.isoformat() if run.completed_at else None,
                "status": run.status,
                "mode": run.mode,
                "target_account": run.target_account,
                "target_region": run.target_region,
                "profile_used": run.profile_used,
                "total_controls": run.total_controls,
                "passed_controls": run.passed_controls,
                "failed_controls": run.failed_controls,
                "error_controls": run.error_controls,
                "not_configured_controls": run.not_configured_controls,
            },
            "findings": [
                {
                    "id": f.id,
                    "control_id": f.control_id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity,
                    "status": f.status,
                    "resource_id": f.resource_id,
                    "resource_arn": f.resource_arn,
                    "service": f.service,
                    "remediation_guidance": f.remediation_guidance,
                    "verification_result": f.verification_result
                }
                for f in findings
            ],
            "evaluations": [
                {
                    "control_id": ev.control_id,
                    "title": ev.title,
                    "category": ev.category,
                    "severity": ev.severity,
                    "status": ev.status,
                    "resource_id": ev.resource_id,
                    "resource_arn": ev.resource_arn,
                    "rationale": ev.rationale,
                    "evidence_source": ev.evidence_source,
                    "limitations": ev.limitations
                }
                for ev in evaluations
            ]
        }

    @staticmethod
    def generate_html_report(run: AssessmentRun, evaluations: list[ControlEvaluation], findings: list[Finding]) -> str:
        total = run.total_controls or 1
        score = int((run.passed_controls / total) * 100) if total > 0 else 0
        tmpl = Template(HTML_REPORT_TEMPLATE)
        return tmpl.render(
            run=run,
            evaluations=evaluations,
            findings=findings,
            security_score=score,
            generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        )
