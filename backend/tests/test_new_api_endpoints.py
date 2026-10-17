import json
from pathlib import Path


def test_api_connectors_matrix(client):
    response = client.get("/api/v1/connectors")
    assert response.status_code == 200
    connectors = response.json()
    assert isinstance(connectors, list)
    assert len(connectors) == 12

    service_ids = [c["service_id"] for c in connectors]
    assert "sts" in service_ids
    assert "s3" in service_ids
    assert "iam" in service_ids
    assert "cloudtrail" in service_ids
    assert "config" in service_ids
    assert "securityhub" in service_ids
    assert "guardduty" in service_ids
    assert "accessanalyzer" in service_ids
    assert "inspector" in service_ids
    assert "macie" in service_ids
    assert "ssm" in service_ids
    assert "cloudwatch" in service_ids


def test_api_plan_check_evaluate(client):
    fixtures_dir = Path(__file__).resolve().parent.parent / "app" / "fixtures" / "plans"
    insecure_plan = fixtures_dir / "insecure_regression_plan.json"
    with open(insecure_plan, encoding="utf-8") as f:
        plan_content = json.load(f)

    payload = {
        "source_filename": "insecure_regression_plan.json",
        "plan_content": plan_content,
    }

    response = client.post("/api/v1/plan-check/evaluate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "BLOCKED"
    assert data["blocking_count"] >= 3
    assert "sarif_data" in data

    # Verify SARIF download endpoint
    run_id = data["id"]
    sarif_resp = client.get(f"/api/v1/plan-check/runs/{run_id}/sarif")
    assert sarif_resp.status_code == 200
    sarif = sarif_resp.json()
    assert sarif["version"] == "2.1.0"


def test_api_investigation_sessions(client):
    response = client.get("/api/v1/investigation/sessions")
    assert response.status_code == 200
    sessions = response.json()
    assert isinstance(sessions, list)


def test_api_verification_history(client):
    response = client.get("/api/v1/verification/history")
    assert response.status_code == 200
    history = response.json()
    assert isinstance(history, list)
