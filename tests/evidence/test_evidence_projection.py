import asyncio
import json
import socket
from dataclasses import FrozenInstanceError

import pytest

from tidemark.adapters.google_adk import AdkSchedulePaymentCallbackAdapter

from google.adk.agents.invocation_context import InvocationContext
from google.adk.agents.llm_agent import LlmAgent
from google.adk.flows.llm_flows.functions import handle_function_call_list_async
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.adk.sessions.session import Session
from google.genai import types
from tidemark.evidence.projection import (
    CallbackReviewAction,
    EvidenceCompleteness,
    EvidenceProjector,
    ExecutionReviewStatus,
    ProjectionDisposition,
    ProjectionStatus,
    REVIEW_MASKING_PROFILE_VERSION,
    ReplayReviewState,
    review_projection_to_primitive,
)
from tidemark.evidence.model import (
    AuditEvent,
    EvidenceEventType,
    EvidenceReconciledPayload,
)
from tidemark.payment.fixtures import (
    DEFAULT_INVOCATION_ID,
    RAW_SYNTHETIC_DESTINATION,
    build_synthetic_payment_fixture,
)
from tidemark.runtime.execution_gate import (
    AdapterInvocationResult,
    ExecutionGate,
    TrustedAdapterRegistry,
)
from tidemark.runtime.identifiers import ToolId
from tidemark.runtime.policy_engine import CanonicalCall
from tidemark.runtime.policy_snapshot import PolicyInstaller
from tidemark.runtime.prepared_call import PreparationRefusal
from tidemark.runtime.vocabulary import DecisionOutcome, RuleId


FUNCTION_CALL_ID = "order-14-function-call-001"


def _valid_args(fixture):
    return {
        "amount_minor": fixture.purchase_order.maximum_amount_minor,
        "currency": fixture.purchase_order.allowed_currencies[0],
        "destination_reference": fixture.destination_reference.value,
    }


def _dispatch(adapter, pending_args):
    tool = adapter.build_tool()
    agent = LlmAgent(
        name="tidemark_order_14_agent",
        tools=[tool],
        before_tool_callback=[adapter.before_tool_callback],
    )
    context = InvocationContext(
        invocation_id=DEFAULT_INVOCATION_ID.value,
        agent=agent,
        session=Session(
            id="tidemark-order-14-session",
            app_name="tidemark-order-14",
            user_id="synthetic-reviewer",
            state={},
        ),
        session_service=InMemorySessionService(),
    )
    function_call = types.FunctionCall(
        id=FUNCTION_CALL_ID,
        name=tool.name,
        args=pending_args,
    )
    original_connect = socket.socket.connect

    def forbid_network(self, address):
        raise AssertionError(f"Order 14 attempted network access: {address!r}")

    socket.socket.connect = forbid_network
    try:
        return asyncio.run(
            handle_function_call_list_async(
                context,
                [function_call],
                {tool.name: tool},
            )
        )
    finally:
        socket.socket.connect = original_connect


def _project(fixture):
    return EvidenceProjector().project(
        fixture.evidence_store.ordered_events()
    )


def test_valid_preparation_refusal_projects_without_false_side_effect_findings(
    tmp_path,
):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    valid = fixture.canonical_call()
    unknown = CanonicalCall(
        tool_id=ToolId("unknown_tool"),
        contract_version=valid.contract_version,
        signature=valid.signature,
        arguments=valid.arguments,
    )

    result = fixture.prepare(unknown)
    projection = _project(fixture)

    assert type(result) is PreparationRefusal
    assert projection.disposition is ProjectionDisposition.REFUSAL
    assert projection.authorization_outcome is DecisionOutcome.REFUSAL
    assert projection.execution_started is False
    assert projection.payment_recorded is False
    assert projection.findings == ()
    assert projection.integrity_status is ProjectionStatus.CLEAN
    assert projection.reconciliation_status is ProjectionStatus.CLEAN
    assert projection.evidence_completeness is EvidenceCompleteness.COMPLETE


def test_valid_policy_installation_refusal_projects_as_clean_refusal(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    PolicyInstaller(evidence_recorder=fixture.evidence_recorder).install(object())

    projection = _project(fixture)

    assert projection.disposition is ProjectionDisposition.REFUSAL
    assert projection.authorization_outcome is DecisionOutcome.REFUSAL
    assert projection.call_ids == ()
    assert projection.execution_started is False
    assert projection.payment_recorded is False
    assert projection.findings == ()


def test_valid_deny_projects_rule_and_callback_veto_as_clean(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    adapter = AdkSchedulePaymentCallbackAdapter(fixture)
    args = _valid_args(fixture)
    args["destination_reference"] = RAW_SYNTHETIC_DESTINATION

    _dispatch(adapter, args)
    projection = _project(fixture)

    assert projection.disposition is ProjectionDisposition.DENY
    assert projection.authorization_outcome is DecisionOutcome.DENY
    assert projection.primary_rule_id is RuleId.PROTECTED_RAW_VALUE_SUPPLIED
    assert projection.callback_action is CallbackReviewAction.VETOED
    assert projection.execution_started is False
    assert projection.payment_recorded is False
    assert projection.findings == ()
    assert projection.evidence_completeness is EvidenceCompleteness.COMPLETE


def test_valid_allow_success_projects_complete_callback_execution_and_payment(
    tmp_path,
):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    adapter = AdkSchedulePaymentCallbackAdapter(fixture)

    _dispatch(adapter, _valid_args(fixture))
    projection = _project(fixture)

    assert projection.disposition is ProjectionDisposition.ALLOW
    assert projection.authorization_outcome is DecisionOutcome.ALLOW
    assert projection.primary_rule_id is RuleId.AUTHORIZATION_ALLOW
    assert projection.callback_action is CallbackReviewAction.TOOL_ENTERED
    assert projection.execution_started is True
    assert projection.execution_status is ExecutionReviewStatus.COMPLETED
    assert projection.payment_recorded is True
    assert projection.payment_count == 1
    assert len(projection.prepared_call_ids) == 1
    assert len(projection.execution_ids) == 1
    assert len(projection.payment_record_ids) == 1
    assert projection.findings == ()
    assert projection.evidence_completeness is EvidenceCompleteness.COMPLETE


def test_execution_failure_preserves_allow_and_does_not_require_payment(tmp_path):
    fixture = build_synthetic_payment_fixture(
        str(tmp_path), adapter_fail_before_record=True
    )
    prepared = fixture.prepare(fixture.canonical_call())
    fixture.execution_gate.execute(prepared)

    projection = _project(fixture)

    assert projection.authorization_outcome is DecisionOutcome.ALLOW
    assert projection.execution_status is ExecutionReviewStatus.FAILED_CONFIRMED
    assert projection.payment_recorded is False
    assert projection.findings == ()
    assert projection.evidence_completeness is EvidenceCompleteness.COMPLETE


def test_ambiguous_external_failure_is_visible_without_absence_claim(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    prepared = fixture.prepare(fixture.canonical_call())
    gate = ExecutionGate(
        adapter_registry=TrustedAdapterRegistry(
            tool_id=prepared.tool_id,
            adapter_id=prepared.adapter_id,
            adapter_version=prepared.adapter_version,
            adapter=lambda invocation: AdapterInvocationResult.unconfirmed_failure(),
        ),
        evidence_sink=fixture.evidence_recorder,
    )
    gate.execute(prepared)

    projection = _project(fixture)
    primitive = review_projection_to_primitive(projection)

    assert projection.authorization_outcome is DecisionOutcome.ALLOW
    assert projection.execution_status is ExecutionReviewStatus.FAILED_AMBIGUOUS
    assert projection.external_result_confirmed is False
    assert projection.payment_recorded is False
    assert "no side effect" not in json.dumps(primitive).lower()
    assert projection.findings == ()


def test_valid_replay_is_rejected_without_second_start_or_payment(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    prepared = fixture.prepare(fixture.canonical_call())
    fixture.execution_gate.execute(prepared)
    fixture.execution_gate.execute(prepared)

    projection = _project(fixture)

    assert projection.authorization_outcome is DecisionOutcome.ALLOW
    assert projection.execution_status is ExecutionReviewStatus.COMPLETED
    assert projection.replay_state is ReplayReviewState.REJECTED
    assert projection.execution_start_count == 1
    assert projection.payment_count == 1
    assert projection.findings == ()


def test_valid_pre_start_execution_refusal_does_not_become_deny(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    prepared = fixture.prepare(fixture.canonical_call())
    object.__setattr__(prepared, "integrity_id", "sha256:" + "0" * 64)
    fixture.execution_gate.execute(prepared)

    projection = _project(fixture)

    assert projection.authorization_outcome is DecisionOutcome.ALLOW
    assert projection.execution_status is ExecutionReviewStatus.REFUSED
    assert projection.execution_started is False
    assert projection.payment_recorded is False
    assert projection.findings == ()


def test_valid_model_non_attempt_is_neither_deny_veto_nor_execution(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    fixture.evidence_recorder.record_model_non_attempt(
        invocation_id=fixture.invocation_id,
        reason_code="no-candidate-tool-call",
    )

    projection = _project(fixture)

    assert projection.disposition is ProjectionDisposition.MODEL_NON_ATTEMPT
    assert projection.authorization_outcome is None
    assert projection.primary_rule_id is None
    assert projection.callback_action is CallbackReviewAction.NOT_APPLICABLE
    assert projection.execution_started is False
    assert projection.model_non_attempt is True
    assert projection.findings == ()


def test_projection_is_frozen_read_only_and_has_no_repair_or_export_surface(
    tmp_path,
):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    fixture.prepare(
        fixture.canonical_call(destination_reference=RAW_SYNTHETIC_DESTINATION)
    )
    projector = EvidenceProjector()
    projection = _project(fixture)

    try:
        projection.payment_count = 99
    except FrozenInstanceError:
        pass
    else:
        raise AssertionError("ReviewProjection must be immutable")

    for forbidden in (
        "repair_trace",
        "fix_sequence",
        "drop_duplicate",
        "choose_terminal",
        "rewrite_digest",
        "mask_in_place",
        "delete_corrupt_event",
        "export",
        "finalize_export",
    ):
        assert not hasattr(projector, forbidden)
        assert not hasattr(projection, forbidden)


def test_projection_accepts_only_the_runtime_owned_masking_profile(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    fixture.prepare(
        fixture.canonical_call(destination_reference=RAW_SYNTHETIC_DESTINATION)
    )
    events = fixture.evidence_store.ordered_events()

    projection = EvidenceProjector().project(
        events, REVIEW_MASKING_PROFILE_VERSION
    )

    assert projection.masking_profile_version == REVIEW_MASKING_PROFILE_VERSION
    with pytest.raises(ValueError, match="unknown review masking profile"):
        EvidenceProjector().project(events, "caller-selected-mask.v999")


def test_projection_never_appends_or_generates_reconciliation_or_export_events(
    tmp_path,
):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    fixture.prepare(
        fixture.canonical_call(destination_reference=RAW_SYNTHETIC_DESTINATION)
    )
    before = fixture.evidence_store.ordered_events()

    EvidenceProjector().project(before)

    after = fixture.evidence_store.ordered_events()
    assert after == before
    assert all(
        event.event_type
        not in {
            EvidenceEventType.EVIDENCE_RECONCILED,
            EvidenceEventType.EVIDENCE_EXPORT_FINALIZED,
        }
        for event in after
    )


def test_prior_reconciliation_does_not_suppress_new_findings_or_leak_detail(
    tmp_path,
):
    protected_marker = "reconciliation-protected-marker-DO-NOT-DISCLOSE"
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    intake = fixture.evidence_store.ordered_events()
    assert intake == ()
    fixture.evidence_recorder.record_call_intake(
        fixture.canonical_call(), fixture.call_context
    )
    first = fixture.evidence_store.ordered_events()[0]
    prior = AuditEvent(
        schema_version=first.schema_version,
        event_id="prior-reconciliation",
        event_type=EvidenceEventType.EVIDENCE_RECONCILED,
        occurred_at=first.occurred_at,
        sequence=2,
        trace_id=first.trace_id,
        invocation_id=None,
        call_id=None,
        decision_id=None,
        prepared_call_id=None,
        execution_id=None,
        policy_version=None,
        registry_version=None,
        adapter_id=None,
        adapter_version=None,
        producer=first.producer,
        payload=EvidenceReconciledPayload(
            related_event_ids=(first.event_id, "prior-reconciliation"),
            masked_detail=protected_marker,
        ),
        previous_event_digest=None,
    )

    projection = EvidenceProjector().project((first, prior))
    public = repr(projection) + json.dumps(
        review_projection_to_primitive(projection), sort_keys=True
    )

    assert any(
        item.code.value == "evidence.missing_terminal.v1"
        for item in projection.findings
    )
    assert any(
        item.code.value == "evidence.invalid_transition.v1"
        for item in projection.findings
    )
    assert protected_marker not in public
