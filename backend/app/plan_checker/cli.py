import argparse
import json
import sys

from backend.app.plan_checker.checker import PlanChecker


def main(argv: list[str] | None = None):
    # Normalize argv to strip leading 'check' or 'evaluate' subcommand if present
    raw_args = list(argv) if argv is not None else sys.argv[1:]
    if raw_args and raw_args[0] in ["check", "evaluate", "gate"]:
        raw_args = raw_args[1:]

    parser = argparse.ArgumentParser(
        prog="vyra plan-check",
        description="VYRA Pre-Deployment Security Regression Gate — Evaluates Terraform plan JSON before apply"
    )
    parser.add_argument(
        "plan_positional",
        nargs="?",
        default=None,
        help="Positional path to Terraform plan JSON file"
    )
    parser.add_argument(
        "--plan", "-p", "--input", "-i",
        dest="plan_named",
        default=None,
        help="Named path to Terraform plan JSON file (generated via: terraform show -json tfplan > plan.json)"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["table", "text", "json", "sarif"],
        default="table",
        help="Output format: table (default terminal summary), text, json, or sarif (OASIS SARIF v2.1.0)"
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default="high",
        help="Minimum violation severity threshold that triggers non-zero exit code (default: high)"
    )
    parser.add_argument(
        "--fail-on-violation",
        action="store_true",
        default=False,
        help="Alias to fail if any blocking violations are detected"
    )
    parser.add_argument(
        "--output", "-o",
        help="Optional path to write output file (e.g. results.sarif)"
    )

    args = parser.parse_args(raw_args)
    plan_path = args.plan_named or args.plan_positional
    if not plan_path:
        parser.error("A plan JSON file must be specified via positional argument or --plan / --input.")

    fail_on = args.fail_on
    if args.fail_on_violation and fail_on == "high":
        fail_on = "high"

    try:
        results = PlanChecker.evaluate_plan_file(plan_path, fail_on=fail_on)
    except Exception as e:
        sys.stderr.write(f"Error evaluating plan file '{plan_path}': {e}\n")
        sys.exit(2)

    # Format output
    if args.format == "sarif":
        content = json.dumps(results["sarif"], indent=2)
    elif args.format == "json":
        content = json.dumps(results, indent=2)
    else:
        lines = []
        lines.append("=" * 72)
        lines.append("VYRA PRE-DEPLOYMENT SECURITY REGRESSION GATE")
        lines.append(f"Plan file:  {plan_path}")
        lines.append(f"Status:     {results['status']}")
        lines.append(f"Threshold:  Fail on {args.fail_on.upper()} or higher")
        lines.append(f"Summary:    {results['summary']}")
        lines.append("-" * 72)

        if results["violations"]:
            lines.append("VIOLATIONS DETECTED:")
            for v in results["violations"]:
                blocking_tag = " [BLOCKING]" if v.get("is_blocking") else " [WARNING]"
                lines.append(f"  [{v['severity']}]{blocking_tag} [{v['rule_id']}] {v['rule_name']}")
                lines.append(f"    Resource: {v['resource_address']}")
                lines.append(f"    Issue:    {v['message']}")
                lines.append(f"    Fix:      {v['remediation_guidance']}")
                lines.append("")
        else:
            lines.append("No security regression violations detected. Plan passed.")

        lines.append("=" * 72)
        content = "\n".join(lines)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Report written to {args.output}")
    else:
        print(content)

    sys.exit(results["exit_code"])


if __name__ == "__main__":
    main()
