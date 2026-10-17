import json
import logging
from typing import Any

from backend.app.plan_checker.rules import ALL_PLAN_RULES, GateRuleResult
from backend.app.plan_checker.sarif import SarifExporter

logger = logging.getLogger("vyra.plan_checker")


SEVERITY_LEVELS: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


class PlanChecker:
    """Evaluates Terraform plan JSON against security regression gate rules."""

    @staticmethod
    def evaluate_plan_dict(
        plan_data: dict[str, Any],
        filename: str = "terraform.plan.json",
        fail_on: str = "high",
    ) -> dict[str, Any]:
        resource_changes = plan_data.get("resource_changes", [])
        all_results: list[GateRuleResult] = []

        for rc in resource_changes:
            for rule in ALL_PLAN_RULES:
                res = rule.evaluate(rc)
                if res:
                    all_results.append(res)

        violations = [r for r in all_results if r.status == "VIOLATION"]
        unknowns = [r for r in all_results if r.status == "UNKNOWN"]
        passed = [r for r in all_results if r.status == "PASSED"]

        threshold = SEVERITY_LEVELS.get(fail_on.upper(), 3)
        blocking = [
            v for v in violations
            if v.is_blocking and SEVERITY_LEVELS.get(v.severity, 0) >= threshold
        ]
        warnings = [v for v in violations if v not in blocking]

        status = "BLOCKED" if blocking else "PASSED"
        exit_code = 1 if blocking else 0

        summary = (
            f"Pre-deployment check {status}. "
            f"{len(blocking)} blocking violation(s), {len(warnings)} warning(s), "
            f"{len(unknowns)} computed/unknown, {len(passed)} rule check(s) passed."
        )

        sarif = SarifExporter.generate_sarif(all_results, target_file=filename)

        return {
            "status": status,
            "exit_code": exit_code,
            "summary": summary,
            "fail_on": fail_on.lower(),
            "blocking_count": len(blocking),
            "warning_count": len(warnings),
            "unknown_count": len(unknowns),
            "passed_count": len(passed),
            "results": [r.model_dump() for r in all_results],
            "violations": [v.model_dump() for v in violations],
            "sarif": sarif
        }

    @staticmethod
    def evaluate_plan_file(filepath: str, fail_on: str = "high") -> dict[str, Any]:
        with open(filepath, encoding="utf-8") as f:
            plan_data = json.load(f)
        return PlanChecker.evaluate_plan_dict(plan_data, filename=filepath, fail_on=fail_on)
