def test_api_health(client):
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "HEALTHY"
    assert data["app_name"] == "VYRA Cloud Security Engineering Platform"


def test_api_assessment_and_metrics(client):
    # Trigger Demo Assessment
    res = client.post("/api/v1/assessment/trigger", json={"mode": "DEMO_FIXTURE"})
    assert res.status_code == 200
    run_data = res.json()
    assert run_data["status"] == "COMPLETED"
    assert run_data["mode"] == "DEMO_FIXTURE"

    # Get Metrics
    metrics_res = client.get("/api/v1/assessment/metrics")
    assert metrics_res.status_code == 200
    metrics = metrics_res.json()
    assert metrics["mode"] == "DEMO_FIXTURE"
    assert metrics["total_assets"] > 0
    assert metrics["total_findings"] > 0

    # List Assets
    assets_res = client.get("/api/v1/assets")
    assert assets_res.status_code == 200
    assert len(assets_res.json()) > 0

    # List Controls Evaluations
    ctrls_res = client.get("/api/v1/controls/evaluations")
    assert ctrls_res.status_code == 200
    assert len(ctrls_res.json()) > 0

    # List Findings
    findings_res = client.get("/api/v1/findings")
    assert findings_res.status_code == 200
    findings = findings_res.json()
    assert len(findings) > 0

    # Test Finding Status Update
    f_id = findings[0]["id"]
    patch_res = client.patch(f"/api/v1/findings/{f_id}/status", json={"status": "IN_REVIEW", "justification": "Under active triage"})
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "IN_REVIEW"

    # List Remediation Plans and Approve one
    plans_res = client.get("/api/v1/remediation/plans")
    assert plans_res.status_code == 200
    plans = plans_res.json()
    assert len(plans) > 0
    plan_id = plans[0]["id"]

    approve_res = client.post(f"/api/v1/remediation/plans/{plan_id}/approve", json={"approver_name": "SecOps Lead", "action": "APPROVE"})
    assert approve_res.status_code == 200
    assert approve_res.json()["status"] == "APPROVED"

    # Test Reports JSON & HTML
    rep_json = client.get("/api/v1/reports/json")
    assert rep_json.status_code == 200
    assert "findings" in rep_json.json()

    rep_html = client.get("/api/v1/reports/html")
    assert rep_html.status_code == 200
    assert "<!DOCTYPE html>" in rep_html.text

    # Test Audit Trail
    audit_res = client.get("/api/v1/audit")
    assert audit_res.status_code == 200
    assert len(audit_res.json()) > 0
