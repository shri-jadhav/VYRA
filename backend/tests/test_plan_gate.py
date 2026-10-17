from pathlib import Path

from backend.app.plan_checker.checker import PlanChecker


def test_plan_checker_insecure_regression():
    fixtures_dir = Path(__file__).resolve().parent.parent / "app" / "fixtures" / "plans"
    insecure_plan = fixtures_dir / "insecure_regression_plan.json"

    res = PlanChecker.evaluate_plan_file(str(insecure_plan))
    assert res["status"] == "BLOCKED"
    assert res["exit_code"] == 1
    assert res["blocking_count"] >= 3

    rule_ids = [r["rule_id"] for r in res["violations"]]
    assert "VYRA-GATE-S3-001" in rule_ids
    assert "VYRA-GATE-IAM-001" in rule_ids
    assert "VYRA-GATE-SEC-001" in rule_ids


def test_plan_checker_remediated_secure():
    fixtures_dir = Path(__file__).resolve().parent.parent / "app" / "fixtures" / "plans"
    secure_plan = fixtures_dir / "remediated_secure_plan.json"

    res = PlanChecker.evaluate_plan_file(str(secure_plan))
    assert res["status"] == "PASSED"
    assert res["exit_code"] == 0
    assert res["blocking_count"] == 0
    assert res["passed_count"] >= 3


def test_plan_checker_computed_unknown():
    # Construct a plan change where attributes are unknown at plan time
    plan_data = {
        "format_version": "1.2",
        "resource_changes": [
            {
                "address": "aws_s3_bucket_public_access_block.dynamic_bucket",
                "type": "aws_s3_bucket_public_access_block",
                "change": {
                    "actions": ["create"],
                    "after": {},
                    "after_unknown": {
                        "block_public_acls": True,
                        "block_public_policy": True,
                    },
                },
            }
        ],
    }

    res = PlanChecker.evaluate_plan_dict(plan_data, filename="computed_test.json")
    # Computed unknown attributes must be flagged as UNKNOWN, never false-pass
    assert res["unknown_count"] >= 1
    assert res["blocking_count"] == 0


def test_sarif_exporter_format():
    fixtures_dir = Path(__file__).resolve().parent.parent / "app" / "fixtures" / "plans"
    insecure_plan = fixtures_dir / "insecure_regression_plan.json"

    res = PlanChecker.evaluate_plan_file(str(insecure_plan))
    sarif = res["sarif"]

    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "VYRA Pre-Deployment Security Gate"
    assert len(run["results"]) >= 3
