from dataclasses import replace

import pytest

from tidemark.evidence.model import (
    AuditEvent,
    CallbackPayload,
    EvidenceEventType,
    ExecutionRefusedPayload,
    ExecutionTerminalPayload,
)
from tidemark.evidence.integrity import EvidenceIntegrityChecker
from tidemark.evidence.projection import (
    EvidenceCompleteness,
    EvidenceProjector,
    ExecutionReviewStatus,
    ProjectionStatus,
    ReplayReviewState,
)
from tidemark.evidence.reconciliation import (
    EvidenceReconciler,
    ReconciliationFindingCode,
)
from tidemark.payment.fixtures import (
    RAW_SYNTHETIC_DESTINATION,
    build_synthetic_payment_fixture,
)
from tidemark.runtime.identifiers import (
    AdapterId,
    AdapterVersion,
    DecisionId,
    ExecutionId,
    PreparedCallId,
)
from tidemark.runtime.vocabulary import DecisionOutcome, RuleId


def _codes(projection):
    return tuple(item.code for item in projection.findings)


def _normalize(events):
    return tuple(
        replace(event, sequence=index, previous_event_digest=None)
        for index, event in enumerate(events, 1)
    )


def _success(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    prepared = fixture.prepare(fixture.canonical_call())
    fixture.execution_gate.execute(prepared)
    return fixture.evidence_store.ordered_events()


def _deny(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    fixture.prepare(
        fixture.canonical_call(destination_reference=RAW_SYNTHETIC_DESTINATION)
    )
    return fixture, fixture.evidence_store.ordered_events()


def test_execution_terminal_without_start_is_orphaned(tmp_path):
    intake, decision, _, completed, _ = _success(tmp_path)

    projection = EvidenceProjector().project(
        _normalize((intake, decision, completed))
    )

    assert ReconciliationFindingCode.ORPHAN_EVENT in _codes(projection)
    assert ReconciliationFindingCode.MISSING_PREDECESSOR in _codes(projection)
    assert projection.evidence_completeness is EvidenceCompleteness.INCOMPLETE


def test_execution_start_without_allow_decision_lineage_is_orphaned(tmp_path):
    start = _success(tmp_path)[2]

    projection = EvidenceProjector().project(_normalize((start,)))

    assert ReconciliationFindingCode.ORPHAN_EVENT in _codes(projection)
    assert ReconciliationFindingCode.MISSING_PREDECESSOR in _codes(projection)


def test_payment_without_execution_is_orphaned(tmp_path):
    intake, decision, _, _, payment = _success(tmp_path)

    projection = EvidenceProjector().project(
        _normalize((intake, decision, payment))
    )

    assert ReconciliationFindingCode.ORPHAN_EVENT in _codes(projection)
    assert projection.payment_recorded is True
    assert projection.reconciliation_status is ProjectionStatus.FAILED


def test_deny_plus_execution_start_is_an_impossible_transition(tmp_path):
    _, deny_events = _deny(tmp_path / "deny")
    start = _success(tmp_path / "success")[2]
    deny_decision = deny_events[1]
    corrupted_start = replace(
        start,
        event_id="deny-execution-start",
        trace_id=deny_decision.trace_id,
        invocation_id=deny_decision.invocation_id,
        call_id=deny_decision.call_id,
        decision_id=deny_decision.decision_id,
    )

    projection = EvidenceProjector().project(
        _normalize(deny_events + (corrupted_start,))
    )

    assert projection.authorization_outcome is DecisionOutcome.DENY
    assert ReconciliationFindingCode.INVALID_TRANSITION in _codes(projection)


def test_deny_plus_payment_is_an_impossible_side_effect(tmp_path):
    _, deny_events = _deny(tmp_path / "deny")
    payment = _success(tmp_path / "success")[-1]
    deny_decision = deny_events[1]
    corrupted_payment = replace(
        payment,
        event_id="deny-payment",
        trace_id=deny_decision.trace_id,
        invocation_id=deny_decision.invocation_id,
        call_id=deny_decision.call_id,
        decision_id=deny_decision.decision_id,
    )

    projection = EvidenceProjector().project(
        _normalize(deny_events + (corrupted_payment,))
    )

    assert projection.authorization_outcome is DecisionOutcome.DENY
    assert ReconciliationFindingCode.IMPOSSIBLE_SIDE_EFFECT in _codes(projection)


def test_allow_lineage_with_different_prepared_correlation_is_incomplete(
    tmp_path,
):
    intake, decision, start, _, _ = _success(tmp_path)
    mismatched = replace(
        start,
        event_id="mismatched-prepared-start",
        prepared_call_id=PreparedCallId("prepared-other"),
    )

    projection = EvidenceProjector().project(
        _normalize((intake, decision, mismatched))
    )

    assert ReconciliationFindingCode.CORRELATION_MISMATCH in _codes(projection)
    assert ReconciliationFindingCode.MISSING_PREDECESSOR in _codes(projection)
    assert projection.evidence_completeness is EvidenceCompleteness.INCOMPLETE


def test_completed_and_failed_for_one_execution_conflict(tmp_path):
    intake, decision, start, completed, payment = _success(tmp_path)
    failed = replace(
        completed,
        event_id="conflicting-failed-terminal",
        event_type=EvidenceEventType.EXECUTION_FAILED,
        payload=ExecutionTerminalPayload(
            external_result_confirmed=True,
            masked_failure_fact="adapter-confirmed-failure",
        ),
    )

    projection = EvidenceProjector().project(
        _normalize((intake, decision, start, completed, failed, payment))
    )
    integrity = EvidenceIntegrityChecker().check(
        _normalize((intake, decision, start, completed, failed, payment))
    )

    assert ReconciliationFindingCode.CONFLICTING_TERMINAL in _codes(projection)
    assert ReconciliationFindingCode.CONFLICTING_TERMINAL in tuple(
        item.code for item in integrity.findings
    )
    assert projection.execution_status is ExecutionReviewStatus.CONFLICT


@pytest.mark.parametrize(
    ("terminal_type", "payload"),
    (
        (
            EvidenceEventType.EXECUTION_COMPLETED,
            ExecutionTerminalPayload(True, None),
        ),
        (
            EvidenceEventType.EXECUTION_FAILED,
            ExecutionTerminalPayload(True, "adapter-confirmed-failure"),
        ),
    ),
)
def test_duplicate_same_kind_execution_terminal_is_detected(
    tmp_path, terminal_type, payload
):
    intake, decision, start, completed, payment = _success(tmp_path)
    first = replace(
        completed,
        event_id="first-terminal",
        event_type=terminal_type,
        payload=payload,
    )
    second = replace(first, event_id="second-terminal")
    tail = (payment,) if terminal_type is EvidenceEventType.EXECUTION_COMPLETED else ()

    projection = EvidenceProjector().project(
        _normalize((intake, decision, start, first, second) + tail)
    )

    assert ReconciliationFindingCode.DUPLICATE_TERMINAL in _codes(projection)


def test_duplicate_payment_for_one_prepared_execution_is_detected(tmp_path):
    events = _success(tmp_path)
    duplicate = replace(events[-1], event_id="duplicate-payment")

    projection = EvidenceProjector().project(
        _normalize(events + (duplicate,))
    )

    assert ReconciliationFindingCode.DUPLICATE_SIDE_EFFECT in _codes(projection)
    assert projection.payment_count == 2


def test_replay_followed_by_second_execution_start_is_inconsistent(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    prepared = fixture.prepare(fixture.canonical_call())
    fixture.execution_gate.execute(prepared)
    fixture.execution_gate.execute(prepared)
    events = fixture.evidence_store.ordered_events()
    first_start = next(
        event
        for event in events
        if event.event_type is EvidenceEventType.EXECUTION_STARTED
    )
    second_start = replace(
        first_start,
        event_id="second-execution-start",
        execution_id=ExecutionId("execution-second"),
    )

    projection = EvidenceProjector().project(
        _normalize(events + (second_start,))
    )

    assert ReconciliationFindingCode.REPLAY_INCONSISTENCY in _codes(projection)
    assert projection.replay_state is ReplayReviewState.INCONSISTENT


def test_replay_without_prior_execution_context_is_orphaned(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    prepared = fixture.prepare(fixture.canonical_call())
    fixture.execution_gate.execute(prepared)
    fixture.execution_gate.execute(prepared)
    events = fixture.evidence_store.ordered_events()
    intake, decision = events[:2]
    replay = events[-1]

    projection = EvidenceProjector().project(
        _normalize((intake, decision, replay))
    )

    assert ReconciliationFindingCode.ORPHAN_EVENT in _codes(projection)


def test_callback_tool_entry_without_release_has_missing_predecessor(tmp_path):
    intake, decision, start, completed, payment = _success(tmp_path)
    callback = AuditEvent(
        schema_version=decision.schema_version,
        event_id="callback-tool-entered-without-release",
        event_type=EvidenceEventType.CALLBACK_TOOL_ENTERED,
        occurred_at=decision.occurred_at,
        sequence=3,
        trace_id=decision.trace_id,
        invocation_id=decision.invocation_id,
        call_id=decision.call_id,
        decision_id=decision.decision_id,
        prepared_call_id=decision.prepared_call_id,
        execution_id=None,
        policy_version=decision.policy_version,
        registry_version=decision.registry_version,
        adapter_id=AdapterId("tidemark.google-adk.callback"),
        adapter_version=AdapterVersion("tidemark.google-adk.callback.v1"),
        producer=decision.producer,
        payload=CallbackPayload(
            framework_name="google-adk",
            framework_version="1.18.0",
            callback_name="schedule_payment",
            framework_invocation_id="framework-invocation",
            framework_call_id="framework-call",
            tool_id=decision.payload.tool_id,
            argument_shapes=(),
        ),
        previous_event_digest=None,
    )

    projection = EvidenceProjector().project(
        _normalize((intake, decision, callback, start, completed, payment))
    )

    assert ReconciliationFindingCode.MISSING_PREDECESSOR in _codes(projection)


def test_execution_correlation_discontinuity_is_detected(tmp_path):
    intake, decision, start, completed, payment = _success(tmp_path)
    mismatched = replace(
        completed,
        event_id="mismatched-decision-terminal",
        decision_id=DecisionId("decision-other"),
    )

    projection = EvidenceProjector().project(
        _normalize((intake, decision, start, mismatched, payment))
    )

    assert ReconciliationFindingCode.CORRELATION_MISMATCH in _codes(projection)


def test_started_execution_missing_terminal_is_incomplete(tmp_path):
    intake, decision, start, _, _ = _success(tmp_path)

    projection = EvidenceProjector().project(
        _normalize((intake, decision, start))
    )

    assert ReconciliationFindingCode.MISSING_TERMINAL in _codes(projection)
    assert projection.execution_status is ExecutionReviewStatus.INCOMPLETE


def test_successful_payment_path_missing_payment_is_incomplete(tmp_path):
    intake, decision, start, completed, _ = _success(tmp_path)

    projection = EvidenceProjector().project(
        _normalize((intake, decision, start, completed))
    )

    assert ReconciliationFindingCode.MISSING_TERMINAL in _codes(projection)
    assert projection.payment_recorded is False


def test_execution_refusal_cannot_share_one_attempt_with_start(tmp_path):
    intake, decision, start, _, _ = _success(tmp_path)
    refused = replace(
        start,
        event_id="execution-refused",
        event_type=EvidenceEventType.EXECUTION_REFUSED,
        payload=ExecutionRefusedPayload(
            RuleId.EXECUTION_PREPARED_CALL_INVALID,
            "prepared-call-invalid",
        ),
    )

    projection = EvidenceProjector().project(
        _normalize((intake, decision, refused, start))
    )

    assert ReconciliationFindingCode.INVALID_TRANSITION in _codes(projection)


def test_model_non_attempt_cannot_coexist_as_enforcement_success(tmp_path):
    fixture, _ = _deny(tmp_path)
    fixture.evidence_recorder.record_model_non_attempt(
        invocation_id=fixture.invocation_id,
        reason_code="no-candidate-tool-call",
    )

    projection = EvidenceProjector().project(
        fixture.evidence_store.ordered_events()
    )

    assert projection.model_non_attempt is True
    assert ReconciliationFindingCode.MODEL_NON_ATTEMPT_MISUSE in _codes(projection)
    assert projection.reconciliation_status is ProjectionStatus.FAILED


def test_reconciler_has_no_repair_or_authority_surface():
    reconciler = EvidenceReconciler()

    assert "read_only=True" in repr(reconciler)
    assert "repairs=False" in repr(reconciler)
    for forbidden in (
        "repair_trace",
        "drop_duplicate",
        "choose_terminal",
        "authorize",
        "execute",
        "restore_authority",
    ):
        assert not hasattr(reconciler, forbidden)
