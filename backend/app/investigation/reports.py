from datetime import UTC, datetime
from typing import Any

from jinja2 import Template

from backend.app.models.models import InvestigationSession

INVESTIGATION_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VYRA Incident Investigation Report - {{ session.id }}</title>
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
    }
    body {
      background-color: var(--bg);
      color: var(--text-pri);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      margin: 0;
      padding: 40px;
      line-height: 1.6;
    }
    .container { max-width: 1100px; margin: 0 auto; }
    .header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 20px;
      margin-bottom: 28px;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
    }
    .logo { font-size: 24px; font-weight: 800; letter-spacing: 2px; }
    .tagline { color: var(--text-sec); font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
    .meta-box {
      background: var(--surface-1);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 30px;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
    }
    .meta-item .label { font-size: 11px; text-transform: uppercase; color: var(--text-sec); letter-spacing: 0.5px; }
    .meta-item .val { font-size: 15px; font-weight: 600; margin-top: 4px; font-family: monospace; }
    .badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
    }
    .badge-supported { background: #450a0a; color: #fca5a5; border: 1px solid #7f1d1d; }
    .badge-possible { background: #3b0764; color: #d8b4fe; border: 1px solid #581c87; }
    .badge-evidence { background: #1e1b4b; color: #93c5fd; border: 1px solid #312e81; }
    h2 { font-size: 17px; font-weight: 700; border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-top: 36px; }
    .card { background: var(--surface-1); border: 1px solid var(--border); border-radius: 6px; padding: 18px; margin-bottom: 16px; }
    .timeline-item { border-left: 2px solid var(--border); padding-left: 16px; margin-left: 8px; margin-bottom: 20px; position: relative; }
    .timeline-dot { position: absolute; left: -7px; top: 4px; width: 12px; height: 12px; border-radius: 50%; background: #fff; border: 2px solid var(--bg); }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
    th { text-align: left; background: var(--surface-2); padding: 10px 14px; border: 1px solid var(--border); color: var(--text-sec); }
    td { padding: 10px 14px; border: 1px solid var(--border); background: var(--surface-1); vertical-align: top; }
    .code { font-family: monospace; color: #38bdf8; background: #000; padding: 2px 6px; border-radius: 4px; font-size: 12px; }
    .footer { margin-top: 60px; font-size: 12px; color: var(--text-sec); text-align: center; border-top: 1px solid var(--border); padding-top: 24px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <div class="logo">VYRA</div>
        <div class="tagline">Find the change. Prevent the regression. Verify the fix.</div>
      </div>
      <div style="text-align: right;">
        <span class="badge badge-supported">{{ session.status }}</span>
        <div style="font-size: 12px; color: var(--text-sec); margin-top: 6px;">Investigation ID: {{ session.id }}</div>
      </div>
    </div>

    <div class="meta-box">
      <div class="meta-item">
        <div class="label">Target Resource</div>
        <div class="val">{{ session.resource_id }}</div>
      </div>
      <div class="meta-item">
        <div class="label">Account ID</div>
        <div class="val">{{ session.target_account }}</div>
      </div>
      <div class="meta-item">
        <div class="label">Region</div>
        <div class="val">{{ session.target_region }}</div>
      </div>
      <div class="meta-item">
        <div class="label">Investigation Window</div>
        <div class="val">{{ session.time_window_start.strftime('%Y-%m-%d %H:%M') }} - {{ session.time_window_end.strftime('%H:%M UTC') }}</div>
      </div>
    </div>

    <h2>1. Executive Summary & Attribution Findings</h2>
    <div class="card">
      <p style="margin: 0; font-size: 14px; color: var(--text-pri);">{{ session.summary }}</p>
    </div>

    <h2>2. Candidate Change Explanations (Deterministic Ranking)</h2>
    {% for c in session.candidate_explanations %}
      <div class="card">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <div>
            <strong style="font-size: 15px;">{{ c.event_name }}</strong>
            <span style="color: var(--text-sec); font-size: 13px; margin-left: 10px;">by {{ c.actor }}</span>
          </div>
          <div>
            <span class="badge {{ 'badge-supported' if c.ranking == 'SUPPORTED_CANDIDATE' else 'badge-possible' }}">
              {{ c.ranking }} &bull; Confidence: {{ c.confidence_score }}%
            </span>
          </div>
        </div>
        <div style="font-size: 13px; color: var(--text-sec); margin-bottom: 8px;">
          <strong>Timestamp:</strong> {{ c.event_time.strftime('%Y-%m-%d %H:%M:%S UTC') }} |
          <strong>Resource:</strong> <span class="code">{{ c.matched_resource }}</span>
        </div>
        <div style="font-size: 13px; margin-bottom: 8px;">
          <strong>Analysis:</strong> {{ c.rationale }}
        </div>
        {% if c.property_changes %}
          <div style="font-size: 12px; color: #fca5a5; margin-top: 6px;">
            <strong>Detected Property Changes:</strong>
            <ul>
              {% for p in c.property_changes %}
                <li>{{ p }}</li>
              {% endfor %}
            </ul>
          </div>
        {% endif %}
      </div>
    {% endfor %}

    <h2>3. Observed Configuration Diffs</h2>
    {% if not session.config_diff %}
      <div class="card" style="font-size: 13px; color: var(--text-sec);">No property diff recorded.</div>
    {% else %}
      <table>
        <thead>
          <tr>
            <th>Property</th>
            <th>Baseline Value</th>
            <th>Current Observed Value</th>
            <th>Security Impact</th>
          </tr>
        </thead>
        <tbody>
          {% for d in session.config_diff %}
            <tr>
              <td><code>{{ d.property }}</code></td>
              <td style="color: #86efac;">{{ d.baseline_value }}</td>
              <td style="color: #fca5a5;">{{ d.current_value }}</td>
              <td><strong>{{ d.security_impact }}</strong></td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    {% endif %}

    <h2>4. Chronological Investigation Timeline</h2>
    <div style="margin-top: 20px;">
      {% for t in session.timeline_events %}
        <div class="timeline-item">
          <div class="timeline-dot"></div>
          <div style="font-size: 12px; color: var(--text-sec); font-family: monospace;">{{ t.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC') }} &bull; {{ t.source }}</div>
          <div style="font-size: 14px; font-weight: 600; margin-top: 2px;">{{ t.event_name }} ({{ t.event_type }})</div>
          <div style="font-size: 13px; color: var(--text-sec); margin-top: 2px;">{{ t.details }}</div>
        </div>
      {% endfor %}
    </div>

    <h2>5. Evidence Limitations & Blind Spots</h2>
    <div class="card" style="font-size: 13px; color: var(--text-sec);">
      <p><strong>Limitations:</strong> {{ session.limitations }}</p>
      {% if session.blindspots %}
        <p><strong>Observed Blind Spots:</strong></p>
        <ul>
          {% for b in session.blindspots %}
            <li>{{ b }}</li>
          {% endfor %}
        </ul>
      {% endif %}
    </div>

    <div class="footer">
      VYRA Cloud Change Investigator &bull; Generated {{ generated_at }} &bull; Strictly Read-Only Assessment
    </div>
  </div>
</body>
</html>
"""


class InvestigationReportGenerator:
    """Produces Markdown, JSON, and HTML incident investigation reports."""

    @staticmethod
    def generate_markdown(session: InvestigationSession) -> str:
        md = []
        md.append(f"# Incident Investigation Report: {session.title}")
        md.append(f"**Investigation ID:** `{session.id}`  ")
        md.append(f"**Target Resource:** `{session.resource_id}`  ")
        md.append(f"**Target Account:** `{session.target_account}` | **Region:** `{session.target_region}`  ")
        md.append(f"**Time Window:** {session.time_window_start} to {session.time_window_end}  ")
        md.append(f"**Investigation Status:** `{session.status}`\n")

        md.append("## 1. Executive Summary & Attribution")
        md.append(session.summary or "No summary recorded.")
        md.append("")

        md.append("## 2. Candidate Change Explanations (Deterministic Ranking)")
        for c in session.candidate_explanations:
            md.append(f"### {c.event_name} (Ranking: {c.ranking} — Confidence: {c.confidence_score}%)")
            md.append(f"- **Actor Identity:** `{c.actor}`")
            md.append(f"- **Timestamp:** {c.event_time}")
            md.append(f"- **Rationale:** {c.rationale}")
            if c.property_changes:
                md.append(f"- **Property Changes:** {', '.join(c.property_changes)}")
            md.append("")

        md.append("## 3. Configuration Differences")
        if session.config_diff:
            md.append("| Property | Baseline | Observed Current | Security Impact |")
            md.append("| :--- | :--- | :--- | :--- |")
            for d in session.config_diff:
                md.append(f"| `{d.get('property')}` | {d.get('baseline_value')} | {d.get('current_value')} | **{d.get('security_impact')}** |")
            md.append("")

        md.append("## 4. Chronological Timeline")
        for t in session.timeline_events:
            md.append(f"- **{t.timestamp}** `[{t.source}]` **{t.event_name}** ({t.event_type}): {t.details}")
        md.append("")

        md.append("## 5. Limitations & Next Steps")
        md.append(f"- **Limitations:** {session.limitations}")
        if session.next_steps:
            md.append("- **Recommended Next Steps:**")
            for step in session.next_steps:
                md.append(f"  - {step}")

        return "\n".join(md)

    @staticmethod
    def generate_html(session: InvestigationSession) -> str:
        tmpl = Template(INVESTIGATION_HTML_TEMPLATE)
        return tmpl.render(
            session=session,
            generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        )

    @staticmethod
    def generate_json(session: InvestigationSession) -> dict[str, Any]:
        return {
            "investigation_id": session.id,
            "title": session.title,
            "created_at": session.created_at.isoformat() if session.created_at else None,
            "resource_id": session.resource_id,
            "resource_arn": session.resource_arn,
            "target_account": session.target_account,
            "target_region": session.target_region,
            "status": session.status,
            "summary": session.summary,
            "candidate_explanations": [
                {
                    "event_id": c.event_id,
                    "event_time": c.event_time.isoformat() if c.event_time else None,
                    "event_name": c.event_name,
                    "actor": c.actor,
                    "ranking": c.ranking,
                    "confidence_score": c.confidence_score,
                    "matched_resource": c.matched_resource,
                    "rationale": c.rationale,
                    "property_changes": c.property_changes,
                    "supporting_evidence": c.supporting_evidence,
                    "next_steps": c.next_steps
                }
                for c in session.candidate_explanations
            ],
            "config_diff": session.config_diff,
            "timeline_events": [
                {
                    "timestamp": t.timestamp.isoformat() if t.timestamp else None,
                    "event_type": t.event_type,
                    "event_name": t.event_name,
                    "actor": t.actor,
                    "source": t.source,
                    "details": t.details
                }
                for t in session.timeline_events
            ],
            "blindspots": session.blindspots,
            "limitations": session.limitations,
            "next_steps": session.next_steps
        }
