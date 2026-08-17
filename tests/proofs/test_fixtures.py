import ast
from dataclasses import replace
from pathlib import Path

import pytest

from tidemark.proofs.catalogue import PROOF_CATALOGUE
from tidemark.proofs.fixtures import CORE_PROOF_FIXTURE_IDS, execute_proof_fixture
from tidemark.proofs.model import (
    ProofEvidenceStatus,
    ProofExternalResultStatus,
    ProofReferenceState,
    ProofRunOutcome,
    ProofStatus,
)
from tidemark.proofs import runner as proof_runner
from tidemark.proofs.runner import run_core_proof_properties
from tidemark.evidence.projection import EvidenceCompleteness, ExecutionReviewStatus
from tidemark.runtime.vocabulary import DecisionOutcome, PreparedCallState, RuleId


ROOT = Path(__file__).resolve().parents[2]
EXPECTED = {
    fixture.fixture_id: fixture.expected_observation
    for item in PROOF_CATALOGUE[:3]
    for fixture in item.fixtures
}


@pytest.mark.parametrize("fixture_id", tuple(EXPECTED))
def test_p01_p02_p03_fixed_fixture_matches_its_closed_observation(
    tmp_path, fixture_id
):
    observed = execute_proof_fixture(fixture_id, tmp_path / fixture_id)

    assert observed == EXPECTED[fixture_id]
    assert type(observed) is type(EXPECTED[fixture_id])


def test_p01_selection_executes_once_while_raw_supply_denies_before_preparation(
    tmp_path,
):
    selected = execute_proof_fixture(CORE_PROOF_FIXTURE_IDS[0], tmp_path / "selected")
    supplied = execute_proof_fixture(CORE_PROOF_FIXTURE_IDS[1], tmp_path / "supplied")

    assert selected.decision_outcome is DecisionOutcome.ALLOW
    assert selected.prepared_call_count == 1
    assert selected.execution_outcomes.completed == 1
    assert selected.adapter_entry_count == 1
    assert selected.authoritative_side_effect_count == 1
    assert selected.capability_state is PreparedCallState.CONSUMED
    assert selected.reference_states == (ProofReferenceState.ACTIVE_CONSUMED,)

    assert supplied.decision_outcome is DecisionOutcome.DENY
    assert supplied.decision_rule_id is RuleId.PROTECTED_RAW_VALUE_SUPPLIED
    assert supplied.prepared_call_count == 0
    assert supplied.execution_attempt_count == 0
    assert supplied.adapter_entry_count == 0
    assert supplied.authoritative_side_effect_count == 0


def test_p02_preserves_allow_but_refuses_after_reference_deactivation(tmp_path):
    observed = execute_proof_fixture(CORE_PROOF_FIXTURE_IDS[2], tmp_path)

    assert observed.decision_outcome is DecisionOutcome.ALLOW
    assert observed.decision_rule_id is RuleId.AUTHORIZATION_ALLOW
    assert observed.prepared_call_count == 1
    assert observed.execution_outcomes.refused == 1
    assert observed.adapter_entry_count == 0
    assert observed.authoritative_side_effect_count == 0
    assert observed.capability_state is PreparedCallState.UNUSED
    assert observed.reference_states == (ProofReferenceState.INACTIVE_UNCONSUMED,)


def test_p03_success_and_real_append_failure_have_opposite_effect_boundaries(
    tmp_path,
):
    ordered = execute_proof_fixture(CORE_PROOF_FIXTURE_IDS[3], tmp_path / "ordered")
    unavailable = execute_proof_fixture(CORE_PROOF_FIXTURE_IDS[4], tmp_path / "unavailable")

    assert ordered.pre_execution_record_count == 1
    assert ordered.execution_outcomes.completed == 1
    assert ordered.adapter_entry_count == 1
    assert ordered.authoritative_side_effect_count == 1
    assert ordered.capability_state is PreparedCallState.CONSUMED
    assert ordered.reference_states == (ProofReferenceState.ACTIVE_CONSUMED,)

    assert unavailable.decision_outcome is DecisionOutcome.ALLOW
    assert unavailable.pre_execution_record_count == 0
    assert unavailable.execution_outcomes.refused == 1
    assert unavailable.adapter_entry_count == 0
    assert unavailable.authoritative_side_effect_count == 0
    assert unavailable.capability_state is PreparedCallState.UNUSED
    assert unavailable.reference_states == (ProofReferenceState.ACTIVE_UNCONSUMED,)


def test_p04_sequential_replay_is_one_effect_and_one_rejection(tmp_path):
    fixture_id = "W2-P04-C01-sequential-replay"

    observed = execute_proof_fixture(fixture_id, tmp_path / fixture_id)

    assert observed == PROOF_CATALOGUE[3].fixtures[0].expected_observation
    assert observed.execution_attempt_count == 2
    assert observed.execution_outcomes.completed == 1
    assert observed.execution_outcomes.replay_rejected == 1
    assert observed.adapter_entry_count == 1
    assert observed.authoritative_side_effect_count == 1
    assert observed.capability_state is PreparedCallState.CONSUMED
    assert observed.reference_states == (ProofReferenceState.ACTIVE_CONSUMED,)


def test_p05_concurrent_replay_matches_exact_bounded_aggregate(tmp_path):
    fixture_id = "W2-P05-C01-concurrent-replay"

    observed = execute_proof_fixture(fixture_id, tmp_path / fixture_id)

    assert observed == PROOF_CATALOGUE[4].fixtures[0].expected_observation
    assert observed.execution_attempt_count == 12
    assert observed.execution_outcomes.completed == 1
    assert observed.execution_outcomes.replay_rejected == 11
    assert observed.execution_outcomes.refused == 0
    assert observed.execution_outcomes.failed == 0
    assert observed.adapter_entry_count == 1
    assert observed.authoritative_side_effect_count == 1


def test_p05_bounded_aggregate_is_repeatable_across_fresh_state(tmp_path):
    fixture_id = "W2-P05-C01-concurrent-replay"

    observations = tuple(
        execute_proof_fixture(fixture_id, tmp_path / f"repeat-{index}")
        for index in range(5)
    )

    assert all(observed == observations[0] for observed in observations[1:])


@pytest.mark.parametrize(
    "case",
    PROOF_CATALOGUE[5].fixtures,
    ids=lambda case: case.fixture_id,
)
def test_p06_each_prepared_call_tamper_case_fails_closed(tmp_path, case):
    observed = execute_proof_fixture(case.fixture_id, tmp_path / case.fixture_id)

    assert observed == case.expected_observation
    assert observed.decision_outcome is DecisionOutcome.ALLOW
    assert observed.decision_rule_id is RuleId.AUTHORIZATION_ALLOW
    assert observed.prepared_call_count == 1
    assert observed.execution_attempt_count == 1
    assert observed.execution_outcomes.refused == 1
    assert observed.adapter_entry_count == 0
    assert observed.authoritative_side_effect_count == 0
    assert observed.capability_state is PreparedCallState.UNUSED
    assert observed.reference_states == (ProofReferenceState.ACTIVE_UNCONSUMED,)


def test_p06_missing_binding_seam_is_restored_and_clean_control_still_executes(
    tmp_path,
):
    from tidemark.runtime import execution_gate as gate_module

    original = gate_module._validate_runtime_execution_binding
    missing = execute_proof_fixture(
        "W2-P06-C02-binding-missing",
        tmp_path / "binding-missing",
    )

    assert missing == PROOF_CATALOGUE[5].fixtures[1].expected_observation
    assert gate_module._validate_runtime_execution_binding is original

    control = execute_proof_fixture(
        CORE_PROOF_FIXTURE_IDS[0],
        tmp_path / "legitimate-control",
    )
    assert control == PROOF_CATALOGUE[0].fixtures[0].expected_observation


@pytest.mark.parametrize(
    "case",
    PROOF_CATALOGUE[6].fixtures,
    ids=lambda case: case.fixture_id,
)
def test_p07_each_reference_context_failure_denies_before_preparation(
    tmp_path, case
):
    observed = execute_proof_fixture(case.fixture_id, tmp_path / case.fixture_id)

    assert observed == case.expected_observation
    assert observed.decision_outcome is DecisionOutcome.DENY
    assert observed.decision_rule_id is case.expected_observation.decision_rule_id
    assert observed.prepared_call_count == 0
    assert observed.execution_attempt_count == 0
    assert observed.adapter_entry_count == 0
    assert observed.authoritative_side_effect_count == 0


def test_p07_observations_never_serialize_an_opaque_reference(tmp_path):
    public = repr(
        tuple(
            execute_proof_fixture(case.fixture_id, tmp_path / case.fixture_id)
            for case in PROOF_CATALOGUE[6].fixtures
        )
    )

    assert "ref_" not in public


@pytest.mark.parametrize(
    "case",
    PROOF_CATALOGUE[7].fixtures,
    ids=lambda case: case.fixture_id,
)
def test_p08_each_evidence_uncertainty_case_preserves_non_success(tmp_path, case):
    observed = execute_proof_fixture(case.fixture_id, tmp_path / case.fixture_id)

    assert observed == case.expected_observation
    assert observed.decision_outcome is DecisionOutcome.ALLOW
    assert observed.evidence_success_claimed is False
    assert observed.external_effect_absence_claimed is False
    assert observed.evidence_execution_status is not ExecutionReviewStatus.COMPLETED


def test_p08_ambiguous_external_result_never_claims_effect_absence(tmp_path):
    observed = execute_proof_fixture(
        "W2-P08-C03-ambiguous-external-result",
        tmp_path,
    )

    assert observed.external_result_status is ProofExternalResultStatus.UNCONFIRMED
    assert observed.authoritative_side_effect_count == 0
    assert observed.evidence_integrity_status is ProofEvidenceStatus.PASS
    assert observed.evidence_reconciliation_status is ProofEvidenceStatus.PASS
    assert observed.evidence_completeness is EvidenceCompleteness.COMPLETE
    assert observed.evidence_execution_status is ExecutionReviewStatus.FAILED_AMBIGUOUS
    assert observed.evidence_success_claimed is False
    assert observed.external_effect_absence_claimed is False


def test_all_eight_properties_and_23_fixed_cases_adjudicate_pass(tmp_path):
    run = proof_runner.run_mechanism_proof_properties(
        tmp_path,
        source_revision="c" * 40,
    )

    assert run.outcome is ProofRunOutcome.COMPLETED
    assert run.infrastructure_error is None
    assert run.suite_result.suite_status is ProofStatus.PASS
    assert run.suite_result.catalogue_property_count == 8
    assert run.suite_result.executed_property_count == 8
    assert sum(len(item.cases) for item in run.suite_result.properties) == 23
    assert all(
        item.proof_status is ProofStatus.PASS
        for item in run.suite_result.properties
    )

    p08 = run.suite_result.properties[-1]
    assert p08.property_id == "W2-P08"
    assert p08.proof_status is ProofStatus.PASS
    assert all(case.case_status is ProofStatus.PASS for case in p08.cases)
    assert all(
        case.observed.evidence_success_claimed is False
        for case in p08.cases
    )
    assert all(
        case.observed.external_effect_absence_claimed is False
        for case in p08.cases
    )


def test_complete_unexpected_runtime_observation_is_property_fail_not_error(
    tmp_path, monkeypatch
):
    original = proof_runner.execute_proof_fixture

    def mismatch(fixture_id, workspace_root):
        observed = original(fixture_id, workspace_root)
        if fixture_id == "W2-P04-C01-sequential-replay":
            return replace(observed, adapter_entry_count=2)
        return observed

    monkeypatch.setattr(proof_runner, "execute_proof_fixture", mismatch)

    run = proof_runner.run_mechanism_proof_properties(
        tmp_path,
        source_revision="d" * 40,
    )

    assert run.outcome is ProofRunOutcome.COMPLETED
    assert run.infrastructure_error is None
    assert run.suite_result.suite_status is ProofStatus.FAIL
    p04 = run.suite_result.properties[3]
    assert p04.property_id == "W2-P04"
    assert p04.proof_status is ProofStatus.FAIL


def test_fixture_or_seam_failure_is_infrastructure_error_without_statuses(
    tmp_path, monkeypatch
):
    def infrastructure_failure(fixture_id, workspace_root):
        raise RuntimeError("bounded fixture orchestration failed")

    monkeypatch.setattr(
        proof_runner,
        "execute_proof_fixture",
        infrastructure_failure,
    )

    run = proof_runner.run_mechanism_proof_properties(
        tmp_path,
        source_revision="e" * 40,
    )

    assert run.outcome is ProofRunOutcome.ERROR
    assert run.suite_result is None
    assert run.infrastructure_error is not None


def test_p01_p02_p03_are_deterministic_across_fresh_runtime_state(tmp_path):
    for fixture_id in CORE_PROOF_FIXTURE_IDS:
        first = execute_proof_fixture(fixture_id, tmp_path / "first" / fixture_id)
        second = execute_proof_fixture(fixture_id, tmp_path / "second" / fixture_id)
        assert first == second


def test_minimal_core_runner_adjudicates_only_p01_through_p03(tmp_path):
    run = run_core_proof_properties(tmp_path, source_revision="b" * 40)

    assert run.outcome is ProofRunOutcome.COMPLETED
    assert run.infrastructure_error is None
    assert run.suite_result.suite_status is ProofStatus.PASS
    assert run.suite_result.selection == ("W2-P01", "W2-P02", "W2-P03")
    assert run.suite_result.catalogue_property_count == 8
    assert run.suite_result.executed_property_count == 3
    assert tuple(item.property_id for item in run.suite_result.properties) == run.suite_result.selection
    assert all(item.proof_status is ProofStatus.PASS for item in run.suite_result.properties)


def test_production_fixture_and_runner_modules_have_no_pytest_or_test_imports():
    for relative in ("src/tidemark/proofs/fixtures.py", "src/tidemark/proofs/runner.py"):
        source = (ROOT / relative).read_text(encoding="utf-8")
        tree = ast.parse(source)
        modules = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        assert "pytest" not in modules
        assert not any(name == "tests" or name.startswith("tests.") for name in modules)


def test_safe_observations_do_not_expose_protected_reference_private_or_path_data(
    tmp_path,
):
    public = repr(
        tuple(
            execute_proof_fixture(fixture_id, tmp_path / fixture_id)
            for fixture_id in CORE_PROOF_FIXTURE_IDS
        )
    )
    forbidden = (
        "synthetic-routing://beneficiary/order-9/4242",
        "ref_",
        "_payload_authenticator",
        "private execution binding",
        str(tmp_path),
        tmp_path.name,
        "/Users/",
        "prompt text",
        "provider payload",
    )
    assert all(value not in public for value in forbidden)
