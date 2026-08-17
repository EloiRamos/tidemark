import os
import socket
import subprocess
import sys
from dataclasses import FrozenInstanceError, asdict, replace
from pathlib import Path

import pytest

from tidemark.demo import (
    DemoHarnessError,
    DemoHarnessFailureCode,
    DeterministicDemoHarness,
)
from tidemark.demo import harness as harness_module
from tidemark.evidence.projection import (
    ExecutionReviewStatus,
    ProjectionDisposition,
    ReplayReviewState,
)
from tidemark.evidence.mechanism_projection import PreparedCallMechanismProjection
from tidemark.evidence.publication import verify_evidence_publication
from tidemark.payment.fixtures import RAW_SYNTHETIC_DESTINATION
from tidemark.runtime.vocabulary import RuleId
from tidemark.ui.run_summary import (
    EvidenceMode,
    PublicationReviewStatus,
    REQUIRED_SCENARIO_ORDER,
    RunStatus,
    ScenarioEvidence,
    ScenarioId,
    ScenarioProvenance,
    build_demo_run_summary,
)


def _run(seed="order-18-test", order=REQUIRED_SCENARIO_ORDER):
    return DeterministicDemoHarness(
        run_seed=seed,
        scenario_execution_order=order,
    ).run()


def _by_id(run):
    return {scenario.scenario_id: scenario for scenario in run.scenarios}


def _scenario_evidence(run):
    return tuple(
        ScenarioEvidence(
            scenario_id=scenario.scenario_id,
            projection=scenario.projection,
            publication=scenario.publication_package,
            provenance=scenario.provenance,
        )
        for scenario in run.scenarios
    )


def _semantic_signature(run):
    return tuple(
        (
            scenario.scenario_id,
            scenario.projection.disposition,
            scenario.projection.primary_rule_id,
            scenario.projection.execution_status,
            scenario.projection.execution_start_count,
            scenario.projection.payment_count,
            scenario.projection.replay_state,
            scenario.projection.model_non_attempt,
            scenario.provenance.mode,
        )
        for scenario in run.scenarios
    )


def test_full_harness_run_generates_all_six_scenarios_in_canonical_order():
    run = _run()

    assert tuple(item.scenario_id for item in run.scenarios) == REQUIRED_SCENARIO_ORDER
    assert len(run.scenarios) == 6
    assert run.summary.required_scenario_count == 6
    assert run.summary.observed_scenario_count == 6
    assert run.summary.status is RunStatus.PASS
    assert run.summary.match_count == 6
    assert run.run_id.startswith("demo-run-")


def test_benign_allow_uses_real_execution_and_payment_path():
    scenario = _by_id(_run())[ScenarioId.BENIGN_ALLOW]
    projection = scenario.projection

    assert projection.disposition is ProjectionDisposition.ALLOW
    assert projection.primary_rule_id is RuleId.AUTHORIZATION_ALLOW
    assert projection.execution_status is ExecutionReviewStatus.COMPLETED
    assert projection.execution_start_count == 1
    assert projection.payment_count == 1


@pytest.mark.parametrize(
    ("scenario_id", "rule_id"),
    (
        (
            ScenarioId.RAW_PROTECTED_VALUE_DENY,
            RuleId.PROTECTED_RAW_VALUE_SUPPLIED,
        ),
        (
            ScenarioId.FORGED_OR_MISBOUND_REFERENCE_DENY,
            RuleId.REFERENCE_NOT_FOUND,
        ),
        (ScenarioId.BOUND_DENY, RuleId.VALUE_CONSTRAINT_FAILED),
    ),
)
def test_deny_scenarios_have_the_canonical_rule_and_zero_side_effects(
    scenario_id, rule_id
):
    projection = _by_id(_run())[scenario_id].projection

    assert projection.disposition is ProjectionDisposition.DENY
    assert projection.primary_rule_id is rule_id
    assert projection.execution_status is ExecutionReviewStatus.NOT_STARTED
    assert projection.execution_start_count == 0
    assert projection.payment_count == 0


def test_replay_rejection_preserves_one_execution_and_one_payment():
    projection = _by_id(_run())[ScenarioId.REPLAY_REJECTION].projection

    assert projection.disposition is ProjectionDisposition.ALLOW
    assert projection.execution_status is ExecutionReviewStatus.COMPLETED
    assert projection.execution_start_count == 1
    assert projection.payment_count == 1
    assert projection.replay_state is ReplayReviewState.REJECTED


def test_model_non_attempt_is_not_a_fabricated_decision_or_execution():
    scenario = _by_id(_run())[ScenarioId.MODEL_NON_ATTEMPT]
    projection = scenario.projection

    assert scenario.provenance.mode is EvidenceMode.MODEL_NON_ATTEMPT
    assert projection.disposition is ProjectionDisposition.MODEL_NON_ATTEMPT
    assert projection.authorization_outcome is None
    assert projection.primary_rule_id is None
    assert projection.execution_start_count == 0
    assert projection.payment_count == 0
    assert projection.model_non_attempt is True


def test_each_existing_scenario_carries_one_safe_mechanism_projection():
    run = _run("w1b-harness-propagation")
    scenarios = _by_id(run)

    assert tuple(
        item.mechanism_projection.schema_version for item in run.scenarios
    ) == (
        "tidemark.prepared-call-mechanism-projection.v1",
    ) * 6
    assert all(
        type(item.mechanism_projection) is PreparedCallMechanismProjection
        for item in run.scenarios
    )
    assert scenarios[ScenarioId.BENIGN_ALLOW].mechanism_projection.seal.prepared_call_present is True
    assert scenarios[ScenarioId.RAW_PROTECTED_VALUE_DENY].mechanism_projection.seal.prepared_call_present is False
    assert scenarios[ScenarioId.FORGED_OR_MISBOUND_REFERENCE_DENY].mechanism_projection.seal.prepared_call_present is False
    assert scenarios[ScenarioId.BOUND_DENY].mechanism_projection.seal.prepared_call_present is False
    assert scenarios[ScenarioId.REPLAY_REJECTION].mechanism_projection.seal.prepared_call_present is True
    assert scenarios[ScenarioId.MODEL_NON_ATTEMPT].mechanism_projection.seal.prepared_call_present is False
    assert "PreparedToolCall(" not in repr(run)


def test_every_scenario_has_an_independently_verified_publication_package():
    run = _run()

    for scenario in run.scenarios:
        verification = verify_evidence_publication(scenario.publication_package)
        assert verification.valid is True
        assert verification.package is not None
        assert verification.package.trace_id == scenario.projection.trace_id


def test_valid_cross_scenario_publication_substitution_is_rejected():
    run = _run()
    evidence = list(_scenario_evidence(run))
    allow = next(item for item in evidence if item.scenario_id is ScenarioId.BENIGN_ALLOW)
    raw_index = next(
        index
        for index, item in enumerate(evidence)
        if item.scenario_id is ScenarioId.RAW_PROTECTED_VALUE_DENY
    )
    evidence[raw_index] = replace(evidence[raw_index], publication=allow.publication)

    summary = build_demo_run_summary("order-18-cross-scenario", tuple(evidence))
    raw = next(
        item
        for item in summary.scenarios
        if item.scenario_id is ScenarioId.RAW_PROTECTED_VALUE_DENY
    )

    assert raw.publication_status is PublicationReviewStatus.INVALID
    assert summary.status is RunStatus.INCOMPLETE


def test_harness_feeds_read_only_order_16_and_order_17_artifacts():
    run = _run()

    assert 'id="scenario-matrix"' in run.run_summary_html
    assert "PASS" in run.run_summary_html
    assert run.integrated_ui_html.count('data-surface="') == 4
    assert "SELECTION, NOT SUPPLY" in run.integrated_ui_html
    assert "04</span><span class=\"rail__label\">Cloud Proof" in run.integrated_ui_html
    assert "Guided demo" in run.integrated_ui_html
    for scenario in run.scenarios:
        artifact = scenario.decision_review_artifact
        expected_slug = scenario.scenario_id.value.lower().replace("_", "-")
        assert artifact.reference == f"decision-review-{expected_slug}.html"
        assert "Read-only runtime evidence" in artifact.html
        assert "Execution &amp; side-effect proof" in artifact.html
        assert artifact.reference in run.run_summary_html
        for forbidden_tag in ("<button", "<form", "<input", "<script"):
            assert forbidden_tag not in artifact.html.lower()
    for forbidden_tag in ("<button", "<form", "<input", "<script"):
        assert forbidden_tag not in run.run_summary_html.lower()


def test_each_run_builds_new_state_without_unconsuming_prior_authority(monkeypatch):
    original = harness_module.build_synthetic_payment_fixture
    fixtures = []

    def capture(*args, **kwargs):
        fixture = original(*args, **kwargs)
        fixtures.append(fixture)
        return fixture

    monkeypatch.setattr(harness_module, "build_synthetic_payment_fixture", capture)

    first = _run("fresh-state")
    first_fixtures = tuple(fixtures)
    first_states = tuple(item.reference_metadata().consumed for item in first_fixtures)
    second = _run("fresh-state")
    second_fixtures = tuple(fixtures[len(first_fixtures) :])

    assert first.summary.status is RunStatus.PASS
    assert second.summary.status is RunStatus.PASS
    assert len(first_fixtures) == len(second_fixtures) == 5
    assert first_states == (True, False, False, False, True)
    assert tuple(item.reference_metadata().consumed for item in first_fixtures) == first_states
    assert all(
        first_item.reference_store is not second_item.reference_store
        and first_item.payment_store is not second_item.payment_store
        and first_item.evidence_store is not second_item.evidence_store
        for first_item, second_item in zip(first_fixtures, second_fixtures)
    )


def test_internal_execution_order_does_not_change_canonical_output_semantics():
    forward = _run("order-independent", REQUIRED_SCENARIO_ORDER)
    reverse = _run("order-independent", tuple(reversed(REQUIRED_SCENARIO_ORDER)))

    assert tuple(item.scenario_id for item in reverse.scenarios) == REQUIRED_SCENARIO_ORDER
    assert _semantic_signature(reverse) == _semantic_signature(forward)
    assert reverse.summary.status is RunStatus.PASS


def test_ten_fresh_runs_are_semantically_repeatable():
    expected = _semantic_signature(_run("repeatable"))

    for _ in range(9):
        run = _run("repeatable")
        assert _semantic_signature(run) == expected
        assert run.summary.status is RunStatus.PASS


def test_scenario_generation_failure_is_bounded_and_cannot_return_success(monkeypatch):
    def fail_publication(*args, **kwargs):
        raise RuntimeError("GEMINI_API_KEY=order-18-do-not-disclose")

    monkeypatch.setattr(harness_module, "build_evidence_publication", fail_publication)

    with pytest.raises(DemoHarnessError) as caught:
        _run("failure-injection")

    assert caught.value.scenario_id is ScenarioId.BENIGN_ALLOW
    assert caught.value.code is DemoHarnessFailureCode.PUBLICATION_FAILED
    assert "GEMINI_API_KEY" not in str(caught.value)


def test_public_results_and_artifacts_omit_protected_and_runtime_private_values(
    monkeypatch,
):
    original = harness_module.build_synthetic_payment_fixture
    reference_ids = []

    def capture(*args, **kwargs):
        fixture = original(*args, **kwargs)
        reference_ids.append(fixture.destination_reference.value)
        return fixture

    monkeypatch.setattr(harness_module, "build_synthetic_payment_fixture", capture)
    run = _run("hygiene")
    public = (
        repr(run)
        + repr(asdict(run))
        + "".join(repr(scenario) for scenario in run.scenarios)
    )

    assert RAW_SYNTHETIC_DESTINATION not in public
    assert all(reference_id not in public for reference_id in reference_ids)
    for forbidden in (
        "RuntimePrivateExecutionBinding",
        "private_authenticator",
        "TrustedReferenceStore(",
        "SyntheticPaymentStore(",
    ):
        assert forbidden not in public


def test_run_seed_is_hashed_and_never_enters_public_artifacts():
    seed = "GEMINI_API_KEY=order-18-seed-secret/../private"
    run = _run(seed)
    rendered = repr(run) + run.run_summary_html + "".join(
        scenario.decision_review_artifact.html
        + scenario.publication_package.canonical_bytes.decode("utf-8")
        for scenario in run.scenarios
    )

    assert seed not in rendered
    assert "order-18-seed-secret" not in rendered


def test_normal_harness_run_performs_no_provider_network_or_cloud_request(monkeypatch):
    def blocked_connect(*args, **kwargs):
        raise AssertionError("network access is forbidden in Order 18")

    monkeypatch.setattr(socket.socket, "connect", blocked_connect)
    monkeypatch.setenv("GEMINI_API_KEY", "order-18-must-not-be-read")

    run = _run("offline-only")

    assert run.summary.status is RunStatus.PASS
    assert all(
        scenario.provenance.mode
        in {EvidenceMode.EVIDENCE_FALLBACK, EvidenceMode.MODEL_NON_ATTEMPT}
        for scenario in run.scenarios
    )
    assert "gemini-3.6-flash" not in run.run_summary_html


def test_scenario_correlations_and_artifact_names_are_closed_and_distinct():
    run = _run("closed-identities")
    trace_ids = tuple(item.projection.trace_id for item in run.scenarios)
    export_ids = tuple(item.publication_package.export_id for item in run.scenarios)
    references = tuple(item.decision_review_artifact.reference for item in run.scenarios)

    assert len(set(trace_ids)) == len(set(export_ids)) == len(set(references)) == 6
    assert all(".." not in value and "/" not in value for value in export_ids + references)


def test_harness_contracts_are_immutable_and_execution_order_is_closed():
    run = _run("immutable")

    with pytest.raises(FrozenInstanceError):
        run.run_id = "changed"
    with pytest.raises(FrozenInstanceError):
        run.scenarios[0].scenario_id = ScenarioId.BOUND_DENY
    with pytest.raises(ValueError, match="complete scenario permutation"):
        DeterministicDemoHarness(
            run_seed="missing",
            scenario_execution_order=REQUIRED_SCENARIO_ORDER[:-1],
        )
    with pytest.raises(TypeError, match="ScenarioId"):
        DeterministicDemoHarness(
            run_seed="wrong-type",
            scenario_execution_order=REQUIRED_SCENARIO_ORDER[:-1] + ("UNKNOWN",),
        )


def test_complete_harness_is_repeatable_in_a_clean_python_process():
    command = (
        "from tidemark.demo import DeterministicDemoHarness; "
        "run=DeterministicDemoHarness(run_seed='clean-process').run(); "
        "print(run.summary.status.value, len(run.scenarios))"
    )

    first = subprocess.run(
        [sys.executable, "-c", command],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(Path.cwd() / "src")},
    )
    second = subprocess.run(
        [sys.executable, "-c", command],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(Path.cwd() / "src")},
    )

    assert first.stdout.strip() == second.stdout.strip() == "PASS 6"
