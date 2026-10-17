import argparse
import sys

from backend.app.core.config import settings


def run_plan_check(argv: list[str]):
    from backend.app.plan_checker.cli import main as plan_checker_main
    plan_checker_main(argv)


def run_server(host: str = "127.0.0.1", port: int = 8000, reload: bool = False):
    import uvicorn
    print(f"Starting {settings.APP_NAME} v{settings.APP_VERSION} on http://{host}:{port}")
    print(f"Tagline: {settings.TAGLINE}")
    print(f"Default Profile: {settings.AWS_PROFILE} | Region: {settings.AWS_DEFAULT_REGION}")
    uvicorn.run("backend.app.main:app", host=host, port=port, reload=reload)


def run_assessment(mode: str = "DEMO", profile: str | None = None, region: str | None = None):
    import uuid
    from datetime import UTC, datetime

    from backend.app.collectors.orchestrator import CollectorOrchestrator
    from backend.app.core.database import SessionLocal
    from backend.app.engine.evaluator import ControlEvaluator
    from backend.app.engine.finding_generator import FindingGenerator
    from backend.app.fixtures.demo_data import get_demo_evidence_fixture
    from backend.app.models.models import AssessmentRun, Asset

    run_id = f"RUN-CLI-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:6]}"
    started_at = datetime.now(UTC)

    target_profile = profile or settings.AWS_PROFILE
    target_region = region or settings.AWS_DEFAULT_REGION

    print(f"Executing VYRA {mode} Assessment [Run ID: {run_id}]...")

    if mode == "LIVE_AWS":
        if not settings.ALLOW_LIVE_COLLECTION:
            print("ERROR: Live AWS collection is disabled in configuration.")
            sys.exit(1)
        if not settings.VYRA_EXPECTED_AWS_ACCOUNT_ID:
            print("ERROR: VYRA_EXPECTED_AWS_ACCOUNT_ID must be set for live assessments.")
            sys.exit(1)
        orchestrator = CollectorOrchestrator(profile_name=target_profile, region_name=target_region)
        evidence = orchestrator.collect_all(run_id=run_id)
        account_id = evidence.get("sts", {}).get("account_id", "unknown")
    else:
        evidence = get_demo_evidence_fixture(run_id=run_id)
        account_id = evidence.get("sts", {}).get("account_id", "112233445566-DEMO")

    db = SessionLocal()
    try:
        run = AssessmentRun(
            id=run_id,
            started_at=started_at,
            status="RUNNING",
            mode=mode,
            profile_used=target_profile if mode == "LIVE_AWS" else "demo-benchmark-fixture",
            target_region=target_region,
            target_account=account_id,
        )
        db.add(run)
        db.commit()

        evaluator = ControlEvaluator(run_id=run_id, evidence=evidence)
        evaluations = evaluator.evaluate_all()
        assets = evaluator.extract_assets()

        for asset in assets:
            existing = db.query(Asset).filter(Asset.id == asset.id).first()
            if existing:
                existing.run_id = run_id
                existing.last_seen = datetime.now(UTC)
            else:
                db.add(asset)

        for ev in evaluations:
            db.add(ev)
        db.flush()

        FindingGenerator.process_evaluations(db, evaluations, run_id=run_id)

        run.completed_at = datetime.now(UTC)
        run.status = "COMPLETED"
        run.total_assets = len(assets)
        run.total_controls = len(evaluations)
        run.passed_controls = sum(1 for e in evaluations if e.status == "PASS")
        run.failed_controls = sum(1 for e in evaluations if e.status == "FAIL")
        run.error_controls = sum(1 for e in evaluations if e.status == "ERROR")
        run.unknown_controls = sum(1 for e in evaluations if e.status == "UNKNOWN")
        run.not_configured_controls = sum(1 for e in evaluations if e.status == "NOT_CONFIGURED")

        db.commit()

        print("-" * 60)
        print("Assessment completed successfully!")
        print(f"Status:   {run.status}")
        print(f"Mode:     {run.mode}")
        print(f"Account:  {run.target_account}")
        print(f"Assets:   {run.total_assets}")
        print(f"Controls: {run.total_controls} Total | {run.passed_controls} PASS | {run.failed_controls} FAIL")
        print("-" * 60)
    finally:
        db.close()


def print_version():
    print(f"{settings.APP_NAME} v{settings.APP_VERSION}")
    print(f"Tagline: {settings.TAGLINE}")
    print("Cloud Security Workbench | Find the change. Prevent the regression. Verify the fix.")


def main():
    if len(sys.argv) < 2:
        print("Usage: vyra <command> [options]")
        print("Commands:")
        print("  start         Start the VYRA API server")
        print("  plan-check    Evaluate Terraform plan JSON against security gates")
        print("  gate          Alias for plan-check")
        print("  assess        Run security assessment (default: offline DEMO)")
        print("  version       Print platform version and info")
        sys.exit(0)

    command = sys.argv[1].lower()
    sub_args = sys.argv[2:]

    if command in ["plan-check", "gate", "check"]:
        run_plan_check(sub_args)
    elif command == "start":
        parser = argparse.ArgumentParser(prog="vyra start", description="Start VYRA platform API server")
        parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
        parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
        parser.add_argument("--reload", action="store_true", help="Enable live auto-reload")
        args = parser.parse_args(sub_args)
        run_server(host=args.host, port=args.port, reload=args.reload)
    elif command == "assess":
        parser = argparse.ArgumentParser(prog="vyra assess", description="Run VYRA security assessment")
        parser.add_argument("--mode", choices=["DEMO", "LIVE_AWS"], default="DEMO", help="Assessment mode (default: DEMO)")
        parser.add_argument("--profile", default=None, help="AWS named profile (must match configured profile in LIVE mode)")
        parser.add_argument("--region", default=None, help="Target AWS region")
        args = parser.parse_args(sub_args)
        run_assessment(mode=args.mode, profile=args.profile, region=args.region)
    elif command in ["version", "--version", "-v"]:
        print_version()
    else:
        print(f"Unknown command: '{command}'. Use 'start', 'plan-check', 'assess', or 'version'.")
        sys.exit(1)


if __name__ == "__main__":
    main()
