import inspect
import re
from dataclasses import FrozenInstanceError, replace
from html.parser import HTMLParser

import pytest

from tidemark.evidence.projection import (
    EvidenceProjector,
    ProjectionStatus,
)
from tidemark.evidence.publication import (
    PublicationRequest,
    PublicationResultCounts,
    build_evidence_publication,
)
from tidemark.evidence.model import EvidenceEventType
from tidemark.payment.fixtures import (
    RAW_SYNTHETIC_DESTINATION,
    build_synthetic_payment_fixture,
)
from tidemark.runtime.identifiers import ReferenceId
from tidemark.ui import run_summary
from tidemark.ui.run_summary import (
    ComparisonStatus,
    EvidenceMode,
    PublicationReviewStatus,
    REQUIRED_SCENARIO_ORDER,
    RunStatus,
    ScenarioEvidence,
    ScenarioId,
    ScenarioIntegrityStatus,
    ScenarioProvenance,
    build_demo_run_summary,
    render_demo_run_summary,
)


class _DocumentAudit(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.attributes = []
        self.links = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend(attrs)
        normalized = dict(attrs)
        if tag == "a":
            self.links.append((normalized.get("href"), normalized.get("aria-label")))

    def handle_startendtag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend(attrs)


def _counts(events):
    event_types = tuple(event.event_type for event in events)
    decisions = tuple(
        event
        for event in events
        if event.event_type is EvidenceEventType.DECISION_RECORDED
    )
    return PublicationResultCounts(
        authoritative_event_count=len(events),
        refusal_count=sum(
            event_type
            in {
                EvidenceEventType.POLICY_INSTALLATION_REFUSED,
                EvidenceEventType.CALL_PREPARATION_REFUSED,
            }
            for event_type in event_types
        ),
        deny_count=sum(event.payload.outcome.value == "DENY" for event in decisions),
        allow_count=sum(event.payload.outcome.value == "ALLOW" for event in decisions),
        model_non_attempt_count=event_types.count(
            EvidenceEventType.RUN_MODEL_NON_ATTEMPT
        ),
        execution_start_count=event_types.count(EvidenceEventType.EXECUTION_STARTED),
        execution_completion_count=event_types.count(
            EvidenceEventType.EXECUTION_COMPLETED
        ),
        execution_failure_count=event_types.count(EvidenceEventType.EXECUTION_FAILED),
        replay_rejection_count=event_types.count(
            EvidenceEventType.EXECUTION_REPLAY_REJECTED
        ),
        payment_count=event_types.count(EvidenceEventType.PAYMENT_RECORDED),
        reconciliation_count=event_types.count(EvidenceEventType.EVIDENCE_RECONCILED),
        prior_export_count=event_types.count(
            EvidenceEventType.EVIDENCE_EXPORT_FINALIZED
        ),
    )


def _scenario_projection(tmp_path, scenario_id):
    fixture = build_synthetic_payment_fixture(str(tmp_path / scenario_id.value.lower()))
    if scenario_id is ScenarioId.BENIGN_ALLOW:
        prepared = fixture.prepare(fixture.canonical_call())
        fixture.execution_gate.execute(prepared)
    elif scenario_id is ScenarioId.RAW_PROTECTED_VALUE_DENY:
        fixture.prepare(
            fixture.canonical_call(
                destination_reference=RAW_SYNTHETIC_DESTINATION
            )
        )
    elif scenario_id is ScenarioId.FORGED_OR_MISBOUND_REFERENCE_DENY:
        fixture.prepare(
            fixture.canonical_call(
                destination_reference=ReferenceId("ref_order_17_forged_unknown")
            )
        )
    elif scenario_id is ScenarioId.BOUND_DENY:
        fixture.prepare(
            fixture.canonical_call(
                amount_minor=fixture.purchase_order.maximum_amount_minor + 1
            )
        )
    elif scenario_id is ScenarioId.REPLAY_REJECTION:
        prepared = fixture.prepare(fixture.canonical_call())
        fixture.execution_gate.execute(prepared)
        fixture.execution_gate.execute(prepared)
    elif scenario_id is ScenarioId.MODEL_NON_ATTEMPT:
        fixture.evidence_recorder.record_model_non_attempt(
            invocation_id=fixture.invocation_id,
            reason_code="no-candidate-tool-call",
        )
    else:
        raise AssertionError("test fixture received an unknown scenario")
    events = fixture.evidence_store.ordered_events()
    return fixture, events, EvidenceProjector().project(events)


def _publication(events, scenario_id):
    trace_id = events[0].trace_id
    return build_evidence_publication(
        events,
        PublicationRequest(
            export_id="order-17-" + scenario_id.value.lower().replace("_", "-"),
            export_version=1,
            trace_id=trace_id,
            expected_counts=_counts(events),
        ),
    )


def _scenario_evidence(tmp_path, scenario_id):
    fixture, events, projection = _scenario_projection(tmp_path, scenario_id)
    provenance = ScenarioProvenance(
        EvidenceMode.MODEL_NON_ATTEMPT
        if scenario_id is ScenarioId.MODEL_NON_ATTEMPT
        else EvidenceMode.EVIDENCE_FALLBACK
    )
    return fixture, ScenarioEvidence(
        scenario_id=scenario_id,
        projection=projection,
        publication=_publication(events, scenario_id),
        provenance=provenance,
    )


def _complete_run(tmp_path):
    evidence = tuple(
        _scenario_evidence(tmp_path, scenario_id)[1]
        for scenario_id in REQUIRED_SCENARIO_ORDER
    )
    return build_demo_run_summary("order-17-complete-run", evidence)


def test_required_scenario_matrix_is_fixed_complete_and_in_semantic_order(tmp_path):
    summary = _complete_run(tmp_path)

    assert tuple(item.scenario_id for item in summary.scenarios) == (
        ScenarioId.BENIGN_ALLOW,
        ScenarioId.RAW_PROTECTED_VALUE_DENY,
        ScenarioId.FORGED_OR_MISBOUND_REFERENCE_DENY,
        ScenarioId.BOUND_DENY,
        ScenarioId.REPLAY_REJECTION,
        ScenarioId.MODEL_NON_ATTEMPT,
    )
    assert summary.required_scenario_count == 6
    assert summary.observed_scenario_count == 6
    assert summary.missing_scenario_count == 0
    assert summary.status is RunStatus.PASS


def test_expected_and_observed_fields_remain_independent_and_visible(tmp_path):
    summary = _complete_run(tmp_path)
    rendered = render_demo_run_summary(summary)

    assert "Expected" in rendered
    assert "Observed" in rendered
    assert rendered.count("authorization.allow.v1") >= 4
    assert "protected.raw_value_supplied.v1" in rendered
    assert "reference.not_found.v1" in rendered
    assert "value.constraint_failed.v1" in rendered
    assert all(item.comparison is ComparisonStatus.MATCH for item in summary.scenarios)


def test_valid_allow_and_all_three_deny_cases_have_exact_observed_proof(tmp_path):
    summary = _complete_run(tmp_path)
    by_id = {item.scenario_id: item for item in summary.scenarios}

    allow = by_id[ScenarioId.BENIGN_ALLOW]
    assert allow.observed_decision == "ALLOW"
    assert allow.observed_primary_rule == "authorization.allow.v1"
    assert allow.observed_execution == "COMPLETED"
    assert allow.observed_execution_start_count == 1
    assert allow.observed_payment_count == 1

    expected_denies = {
        ScenarioId.RAW_PROTECTED_VALUE_DENY: "protected.raw_value_supplied.v1",
        ScenarioId.FORGED_OR_MISBOUND_REFERENCE_DENY: "reference.not_found.v1",
        ScenarioId.BOUND_DENY: "value.constraint_failed.v1",
    }
    for scenario_id, rule_id in expected_denies.items():
        scenario = by_id[scenario_id]
        assert scenario.observed_decision == "DENY"
        assert scenario.observed_primary_rule == rule_id
        assert scenario.observed_execution == "NOT STARTED"
        assert scenario.observed_execution_start_count == 0
        assert scenario.observed_payment_count == 0


def test_replay_and_model_non_attempt_preserve_their_distinct_semantics(tmp_path):
    summary = _complete_run(tmp_path)
    by_id = {item.scenario_id: item for item in summary.scenarios}

    replay = by_id[ScenarioId.REPLAY_REJECTION]
    assert replay.observed_decision == "ALLOW"
    assert replay.observed_execution == "COMPLETED"
    assert replay.observed_replay == "REJECTED"
    assert replay.observed_execution_start_count == 1
    assert replay.observed_payment_count == 1

    non_attempt = by_id[ScenarioId.MODEL_NON_ATTEMPT]
    assert non_attempt.observed_decision == "MODEL NON-ATTEMPT"
    assert non_attempt.observed_primary_rule == "NOT APPLICABLE"
    assert non_attempt.observed_execution == "NOT STARTED"
    assert non_attempt.observed_model_attempt == "NOT ATTEMPTED"
    rendered = render_demo_run_summary(summary)
    assert "not DENY, not callback veto, and not enforcement success" in rendered


def test_incomplete_evidence_is_warning_and_never_match_or_pass(tmp_path):
    fixture, events, _ = _scenario_projection(
        tmp_path, ScenarioId.BENIGN_ALLOW
    )
    incomplete_projection = EvidenceProjector().project(events[:3])
    incomplete = ScenarioEvidence(
        scenario_id=ScenarioId.BENIGN_ALLOW,
        projection=incomplete_projection,
        publication=None,
        provenance=ScenarioProvenance(EvidenceMode.EVIDENCE_FALLBACK),
    )

    summary = build_demo_run_summary("incomplete-order-17", (incomplete,))
    scenario = summary.scenarios[0]
    rendered = render_demo_run_summary(summary)

    assert fixture.payment_store.count == 1
    assert scenario.comparison is ComparisonStatus.INCOMPLETE
    assert scenario.integrity is ScenarioIntegrityStatus.CONFLICTING
    assert scenario.publication_status is PublicationReviewStatus.NOT_FINALIZED
    assert summary.status is RunStatus.INCOMPLETE
    assert "WARNING — INCOMPLETE EVIDENCE" in rendered
    assert "UNKNOWN — EVIDENCE INCOMPLETE" in rendered


def test_complete_expected_observed_disagreement_is_visible_as_mismatch(tmp_path):
    _, events, allow_projection = _scenario_projection(
        tmp_path, ScenarioId.BENIGN_ALLOW
    )
    mismatched = ScenarioEvidence(
        scenario_id=ScenarioId.RAW_PROTECTED_VALUE_DENY,
        projection=allow_projection,
        publication=_publication(events, ScenarioId.BENIGN_ALLOW),
        provenance=ScenarioProvenance(EvidenceMode.EVIDENCE_FALLBACK),
    )

    summary = build_demo_run_summary("mismatch-order-17", (mismatched,))
    scenario = next(
        item
        for item in summary.scenarios
        if item.scenario_id is ScenarioId.RAW_PROTECTED_VALUE_DENY
    )
    rendered = render_demo_run_summary(summary)

    assert scenario.expected_decision == "DENY"
    assert scenario.observed_decision == "ALLOW"
    assert scenario.comparison is ComparisonStatus.MISMATCH
    assert summary.mismatch_count == 1
    assert "MISMATCH" in rendered
    assert "protected.raw_value_supplied.v1" in rendered
    assert "authorization.allow.v1" in rendered


def test_integrity_failure_cannot_render_as_success(tmp_path):
    _, evidence = _scenario_evidence(tmp_path, ScenarioId.BENIGN_ALLOW)
    invalid_projection = replace(
        evidence.projection,
        integrity_status=ProjectionStatus.FAILED,
    )
    invalid = replace(evidence, projection=invalid_projection)

    summary = build_demo_run_summary("invalid-integrity-order-17", (invalid,))
    scenario = summary.scenarios[0]

    assert scenario.integrity is ScenarioIntegrityStatus.INVALID
    assert scenario.publication_status is PublicationReviewStatus.INVALID
    assert scenario.comparison is ComparisonStatus.INCOMPLETE
    assert summary.status is RunStatus.INCOMPLETE


def test_mode_and_provenance_are_per_scenario_and_offline_is_not_live(tmp_path):
    summary = _complete_run(tmp_path)
    rendered = render_demo_run_summary(summary)

    assert "EVIDENCE FALLBACK / OFFLINE" in rendered
    assert "MODEL NON-ATTEMPT / NO ENFORCEMENT CLAIM" in rendered
    assert "gemini-3.6-flash" not in rendered
    assert "LIVE MODEL / PROVIDER-BACKED EVIDENCE" not in rendered
    assert "does not satisfy live Gemini or Google Cloud acceptance" in rendered

    with pytest.raises(ValueError, match="offline provenance"):
        ScenarioProvenance(
            EvidenceMode.EVIDENCE_FALLBACK,
            model_identifier="gemini-3.6-flash",
            access_path="Gemini Developer API",
            provider_evidence_digest="sha256:" + "a" * 64,
        )


def test_live_mode_contract_requires_exact_supporting_provenance_without_fabricating_a_run():
    provenance = ScenarioProvenance(
        EvidenceMode.LIVE_MODEL,
        model_identifier="gemini-3.6-flash",
        access_path="Gemini Developer API",
        provider_evidence_digest="sha256:" + "a" * 64,
    )

    assert provenance.mode is EvidenceMode.LIVE_MODEL
    assert provenance.model_identifier == "gemini-3.6-flash"
    assert provenance.access_path == "Gemini Developer API"
    assert provenance.provider_evidence_digest == "sha256:" + "a" * 64

    with pytest.raises(ValueError, match="live provenance"):
        ScenarioProvenance(EvidenceMode.LIVE_MODEL)


def test_every_observed_required_case_has_a_deterministic_decision_link(tmp_path):
    summary = _complete_run(tmp_path)
    rendered = render_demo_run_summary(summary)
    audit = _DocumentAudit()
    audit.feed(rendered)
    scenario_links = tuple(
        link for link in audit.links if link[0] and link[0].startswith("decision-review-")
    )

    assert len(scenario_links) == len(REQUIRED_SCENARIO_ORDER)
    assert tuple(link[0] for link in scenario_links) == tuple(
        "decision-review-" + scenario_id.value.lower().replace("_", "-") + ".html"
        for scenario_id in REQUIRED_SCENARIO_ORDER
    )
    assert all(label and "decision review" in label.lower() for _, label in scenario_links)


def test_missing_required_scenario_is_explicit_and_run_cannot_pass(tmp_path):
    evidence = tuple(
        _scenario_evidence(tmp_path, scenario_id)[1]
        for scenario_id in REQUIRED_SCENARIO_ORDER[:-1]
    )

    summary = build_demo_run_summary("missing-order-17", evidence)
    rendered = render_demo_run_summary(summary)

    assert summary.status is RunStatus.INCOMPLETE
    assert summary.missing_scenario_count == 1
    assert "MISSING REQUIRED SCENARIO" in rendered
    assert "MODEL_NON_ATTEMPT" in rendered
    assert "<strong>Model:</strong> NOT ATTEMPTED" in rendered


def test_duplicate_and_unknown_scenario_identity_are_refused(tmp_path):
    _, evidence = _scenario_evidence(tmp_path, ScenarioId.BENIGN_ALLOW)

    with pytest.raises(ValueError, match="duplicate scenario identity"):
        build_demo_run_summary("duplicate-order-17", (evidence, evidence))
    with pytest.raises(TypeError, match="ScenarioId"):
        ScenarioEvidence(
            scenario_id="UNKNOWN_SCENARIO",
            projection=evidence.projection,
            publication=evidence.publication,
            provenance=evidence.provenance,
        )


def test_rendering_is_byte_deterministic_and_inputs_remain_immutable(tmp_path):
    evidence = tuple(
        _scenario_evidence(tmp_path, scenario_id)[1]
        for scenario_id in REQUIRED_SCENARIO_ORDER
    )
    projections_before = tuple(item.projection for item in evidence)
    packages_before = tuple(item.publication.canonical_bytes for item in evidence)
    summary = build_demo_run_summary("deterministic-order-17", evidence)

    first = render_demo_run_summary(summary)
    second = render_demo_run_summary(summary)

    assert first.encode("utf-8") == second.encode("utf-8")
    assert tuple(item.projection for item in evidence) == projections_before
    assert tuple(item.publication.canonical_bytes for item in evidence) == packages_before
    with pytest.raises(FrozenInstanceError):
        summary.status = RunStatus.MISMATCH


def test_complete_html_masks_values_paths_credentials_prompts_and_provider_data(tmp_path):
    fixtures_and_evidence = tuple(
        _scenario_evidence(tmp_path, scenario_id)
        for scenario_id in REQUIRED_SCENARIO_ORDER
    )
    forbidden = (
        RAW_SYNTHETIC_DESTINATION,
        *(fixture.destination_reference.value for fixture, _ in fixtures_and_evidence),
        "GEMINI_API_KEY=order-17-secret",
        "raw-prompt-order-17-DO-NOT-RENDER",
        "raw-provider-output-order-17-DO-NOT-RENDER",
        "/Users/example-user/private/order-17.json",
    )
    rendered = render_demo_run_summary(
        build_demo_run_summary(
            "|".join(forbidden),
            tuple(evidence for _, evidence in fixtures_and_evidence),
        )
    )

    assert all(value not in rendered for value in forbidden)
    assert "protected-value-omitted" not in rendered
    assert "ref_order_17_forged_unknown" not in rendered


def test_summary_is_semantic_keyboard_visible_and_has_no_write_surface(tmp_path):
    rendered = render_demo_run_summary(_complete_run(tmp_path))
    audit = _DocumentAudit()
    audit.feed(rendered)

    assert {"title", "main", "header", "section", "table", "caption", "thead", "tbody", "a"} <= set(audit.tags)
    assert not ({"button", "form", "input", "select", "textarea", "script"} & set(audit.tags))
    assert ("tabindex", "0") in audit.attributes
    assert any(name == "scope" and value == "col" for name, value in audit.attributes)
    assert any(name == "aria-label" and "scenario matrix" in value.lower() for name, value in audit.attributes if value)
    assert all(not name.startswith("data-") for name, _ in audit.attributes)
    assert all(name != "title" for name, _ in audit.attributes)
    assert ":focus-visible" in rendered
    assert "@media (prefers-reduced-motion: reduce)" in rendered


def test_renderer_rejects_non_summary_and_ui_imports_no_runtime_authority():
    with pytest.raises(TypeError, match="DemoRunSummary"):
        render_demo_run_summary(object())

    source = inspect.getsource(run_summary)
    import_lines = "\n".join(
        line for line in source.splitlines() if line.startswith(("from ", "import "))
    )
    for forbidden in (
        "PolicyEngine",
        "PolicyInstaller",
        "TrustedReferenceStore",
        "ReferenceResolver",
        "PreparedCallPipeline",
        "ExecutionGate",
        "SyntheticPaymentStore",
        "google.adk",
        "google.genai",
        "google.cloud",
    ):
        assert forbidden not in import_lines
    assert "ReviewProjection" in source
    assert "EvidencePublicationPackage" in source


def test_summary_model_and_renderer_contain_no_execution_or_reset_api(tmp_path):
    summary = _complete_run(tmp_path)
    source = inspect.getsource(run_summary)
    public_names = set(run_summary.__all__)

    assert not public_names & {
        "run",
        "rerun",
        "retry",
        "execute",
        "reset",
        "mint",
        "consume",
        "resolve",
        "publish",
        "deploy",
    }
    assert not re.search(r"def (run|rerun|retry|execute|reset|mint|consume|resolve)_", source)
    assert "authorization_authority=False" in repr(summary)
    assert "scenario_execution=False" in repr(summary)
