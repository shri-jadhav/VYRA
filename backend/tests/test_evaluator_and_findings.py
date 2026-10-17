from backend.app.engine.evaluator import ControlEvaluator
from backend.app.engine.finding_generator import FindingGenerator
from backend.app.fixtures.demo_data import get_demo_evidence_fixture


def test_control_evaluator_taxonomy(db_session):
    evidence = get_demo_evidence_fixture("RUN-TEST-001")
    evaluator = ControlEvaluator("RUN-TEST-001", evidence)

    evaluations = evaluator.evaluate_all()
    assert len(evaluations) > 0

    statuses = {e.status for e in evaluations}
    # Should include PASS, FAIL, and NOT_CONFIGURED
    assert "PASS" in statuses
    assert "FAIL" in statuses
    assert "NOT_CONFIGURED" in statuses

    # Test asset extraction
    assets = evaluator.extract_assets()
    assert len(assets) >= 3

    # Test finding generator
    findings = FindingGenerator.process_evaluations(db_session, evaluations, "RUN-TEST-001")
    assert len(findings) > 0

    # Verify dry-run plan created
    first_f = findings[0]
    assert len(first_f.remediations) == 1
    plan = first_f.remediations[0]
    assert plan.status in ["PROPOSED", "APPROVED"]
    assert len(plan.cli_command) > 0
    assert len(plan.terraform_snippet) > 0
