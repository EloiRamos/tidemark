import asyncio
from dataclasses import asdict
from pathlib import Path
import socket

import pytest

from tidemark.adapters.gemini_live import (
    GeminiAccessVerification,
    GeminiCredentialEnvironment,
    build_gemini_adk_run_plan,
)
from tidemark.adapters.google_adk import AdkSchedulePaymentCallbackAdapter

from google.adk.agents.invocation_context import InvocationContext
from google.adk.agents.llm_agent import LlmAgent
from google.adk.flows.llm_flows.functions import handle_function_call_list_async
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.adk.sessions.session import Session
from google.genai import types

from tidemark.evidence.model import EvidenceEventType
from tidemark.payment.fixtures import (
    DEFAULT_INVOCATION_ID,
    RAW_SYNTHETIC_DESTINATION,
    build_synthetic_payment_fixture,
)
from tidemark.runtime.identifiers import (
    CallId,
    DecisionId,
    InvocationId,
    ToolId,
)
from tidemark.runtime.execution_gate import (
    AdapterInvocationResult,
    ExecutionGate,
    TrustedAdapterRegistry,
)
from tidemark.runtime.minimal_evidence import (
    EvidenceAppendFailure,
    MinimalPreExecutionEvidenceSink,
)
from tidemark.runtime.policy_engine import CanonicalCall
from tidemark.runtime.policy_snapshot import InstallationRefusal, PolicyInstaller
from tidemark.runtime.prepared_call import PreparationRefusal, PreparedToolCall
from tidemark.runtime.vocabulary import (
    DecisionOutcome,
    ExecutionOutcome,
    PreparedCallState,
    RuleId,
)


FUNCTION_CALL_ID = "order-13-function-call-001"


def _types(fixture):
    return tuple(
        event.event_type for event in fixture.evidence_store.ordered_events()
    )


def _valid_args(fixture):
    return {
        "amount_minor": fixture.purchase_order.maximum_amount_minor,
        "currency": fixture.purchase_order.allowed_currencies[0],
        "destination_reference": fixture.destination_reference.value,
    }


def _dispatch(adapter, pending_args, *, function_call_id=FUNCTION_CALL_ID):
    tool = adapter.build_tool()
    agent = LlmAgent(
        name="tidemark_order_13_agent",
        tools=[tool],
        before_tool_callback=[adapter.before_tool_callback],
    )
    context = InvocationContext(
        invocation_id=DEFAULT_INVOCATION_ID.value,
        agent=agent,
        session=Session(
            id="tidemark-order-13-session",
            app_name="tidemark-order-13",
            user_id="synthetic-reviewer",
            state={},
        ),
        session_service=InMemorySessionService(),
    )
    function_call = types.FunctionCall(
        id=function_call_id,
        name=tool.name,
        args=pending_args,
    )
    original_connect = socket.socket.connect

    def forbid_network(self, address):
        raise AssertionError(f"Order 13 attempted network access: {address!r}")

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


def test_policy_installation_refusal_is_distinct_and_stops_the_trail(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    installer = PolicyInstaller(evidence_recorder=fixture.evidence_recorder)

    refusal = installer.install(object())

    assert type(refusal) is InstallationRefusal
    assert _types(fixture) == (
        EvidenceEventType.POLICY_INSTALLATION_REFUSED,
    )
    event = fixture.evidence_store.ordered_events()[0]
    assert event.call_id is None
    assert event.execution_id is None


def test_call_preparation_refusal_has_intake_but_no_decision_or_execution(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    valid = fixture.canonical_call()
    unknown = CanonicalCall(
        tool_id=ToolId("unknown_tool"),
        contract_version=valid.contract_version,
        signature=valid.signature,
        arguments=valid.arguments,
    )

    result = fixture.prepare(unknown)

    assert type(result) is PreparationRefusal
    assert result.decision.outcome is DecisionOutcome.REFUSAL
    assert _types(fixture) == (
        EvidenceEventType.CALL_INTAKE_RECORDED,
        EvidenceEventType.CALL_PREPARATION_REFUSED,
    )


def test_deny_records_decision_without_prepared_or_execution_lineage(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))

    result = fixture.prepare(
        fixture.canonical_call(
            destination_reference=RAW_SYNTHETIC_DESTINATION
        )
    )

    assert type(result) is PreparationRefusal
    assert result.decision.outcome is DecisionOutcome.DENY
    assert _types(fixture) == (
        EvidenceEventType.CALL_INTAKE_RECORDED,
        EvidenceEventType.DECISION_RECORDED,
    )
    decision_event = fixture.evidence_store.ordered_events()[-1]
    assert decision_event.payload.outcome is DecisionOutcome.DENY
    assert decision_event.prepared_call_id is None
    assert fixture.payment_store.count == 0


def test_allow_success_records_complete_local_trail_and_payment_last(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    prepared = fixture.prepare(fixture.canonical_call())

    outcome = fixture.execution_gate.execute(prepared)

    assert type(prepared) is PreparedToolCall
    assert outcome.status is ExecutionOutcome.COMPLETED
    assert _types(fixture) == (
        EvidenceEventType.CALL_INTAKE_RECORDED,
        EvidenceEventType.DECISION_RECORDED,
        EvidenceEventType.EXECUTION_STARTED,
        EvidenceEventType.EXECUTION_COMPLETED,
        EvidenceEventType.PAYMENT_RECORDED,
    )
    events = fixture.evidence_store.ordered_events()
    assert tuple(event.sequence for event in events) == (1, 2, 3, 4, 5)
    assert len({event.trace_id for event in events}) == 1
    assert events[-1].execution_id == outcome.execution_id
    assert RAW_SYNTHETIC_DESTINATION not in repr(events)
    assert fixture.destination_reference.value not in repr(events)


def test_pre_execution_transaction_append_failure_fails_closed(tmp_path, monkeypatch):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    prepared = fixture.prepare(fixture.canonical_call())
    assert type(prepared) is PreparedToolCall

    monkeypatch.setattr(
        MinimalPreExecutionEvidenceSink,
        "append_pre_execution",
        lambda self, record: EvidenceAppendFailure(
            record_id=record.record_id,
            failure_code="evidence.append_failed.v1",
        ),
    )
    outcome = fixture.execution_gate.execute(prepared)

    assert outcome.status is ExecutionOutcome.REFUSED
    assert prepared.execution_capability.state is PreparedCallState.UNUSED
    assert fixture.reference_metadata().consumed is False
    assert fixture.adapter.entry_count == 0
    assert fixture.payment_store.count == 0
    assert EvidenceEventType.EXECUTION_STARTED not in _types(fixture)
    assert EvidenceEventType.PAYMENT_RECORDED not in _types(fixture)


def test_pre_start_integrity_refusal_records_no_execution_marker(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    prepared = fixture.prepare(fixture.canonical_call())
    assert type(prepared) is PreparedToolCall
    object.__setattr__(prepared, "integrity_id", "sha256:" + "0" * 64)

    outcome = fixture.execution_gate.execute(prepared)

    assert outcome.status is ExecutionOutcome.REFUSED
    assert _types(fixture)[-1] is EvidenceEventType.EXECUTION_REFUSED
    assert EvidenceEventType.EXECUTION_STARTED not in _types(fixture)
    assert fixture.payment_store.count == 0


def test_replay_records_rejection_without_second_start_or_payment(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    prepared = fixture.prepare(fixture.canonical_call())

    first = fixture.execution_gate.execute(prepared)
    second = fixture.execution_gate.execute(prepared)

    assert first.status is ExecutionOutcome.COMPLETED
    assert second.status is ExecutionOutcome.REPLAY_REJECTED
    assert _types(fixture).count(EvidenceEventType.EXECUTION_STARTED) == 1
    assert _types(fixture).count(EvidenceEventType.PAYMENT_RECORDED) == 1
    assert _types(fixture)[-1] is EvidenceEventType.EXECUTION_REPLAY_REJECTED
    assert fixture.adapter.entry_count == 1
    assert fixture.payment_store.count == 1


def test_adapter_failure_records_failed_terminal_without_payment(tmp_path):
    fixture = build_synthetic_payment_fixture(
        str(tmp_path), adapter_fail_before_record=True
    )
    prepared = fixture.prepare(fixture.canonical_call())

    outcome = fixture.execution_gate.execute(prepared)

    assert outcome.status is ExecutionOutcome.FAILED
    assert _types(fixture)[-2:] == (
        EvidenceEventType.EXECUTION_STARTED,
        EvidenceEventType.EXECUTION_FAILED,
    )
    assert EvidenceEventType.PAYMENT_RECORDED not in _types(fixture)
    assert fixture.payment_store.count == 0


def test_ambiguous_external_result_is_failed_without_no_side_effect_claim(tmp_path):
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

    outcome = gate.execute(prepared)

    assert outcome.status is ExecutionOutcome.FAILED
    assert outcome.external_result_confirmed is False
    failed = fixture.evidence_store.ordered_events()[-1]
    assert failed.event_type is EvidenceEventType.EXECUTION_FAILED
    assert failed.payload.external_result_confirmed is False
    assert failed.payload.masked_failure_fact == "unconfirmed-external-result"
    assert "no-side-effect" not in repr(failed)


def test_adk_deny_callback_trail_is_received_intake_decision_veto(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    adapter = AdkSchedulePaymentCallbackAdapter(fixture)
    args = _valid_args(fixture)
    args["destination_reference"] = RAW_SYNTHETIC_DESTINATION

    _dispatch(adapter, args)

    assert _types(fixture) == (
        EvidenceEventType.CALLBACK_RECEIVED,
        EvidenceEventType.CALL_INTAKE_RECORDED,
        EvidenceEventType.DECISION_RECORDED,
        EvidenceEventType.CALLBACK_VETOED,
    )
    assert fixture.adapter.entry_count == 0
    assert fixture.payment_store.count == 0


def test_adk_allow_callback_trail_and_execution_are_complete(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    adapter = AdkSchedulePaymentCallbackAdapter(fixture)

    _dispatch(adapter, _valid_args(fixture))

    assert _types(fixture) == (
        EvidenceEventType.CALLBACK_RECEIVED,
        EvidenceEventType.CALL_INTAKE_RECORDED,
        EvidenceEventType.DECISION_RECORDED,
        EvidenceEventType.CALLBACK_RELEASED,
        EvidenceEventType.CALLBACK_TOOL_ENTERED,
        EvidenceEventType.EXECUTION_STARTED,
        EvidenceEventType.EXECUTION_COMPLETED,
        EvidenceEventType.PAYMENT_RECORDED,
    )


def test_model_non_attempt_is_not_a_decision_veto_or_execution(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    callback_adapter = AdkSchedulePaymentCallbackAdapter(fixture)
    plan = build_gemini_adk_run_plan(
        callback_adapter=callback_adapter,
        verification=GeminiAccessVerification(
            model_availability_verified=True,
            exact_model_identifier_verified=True,
            access_path_verified=True,
            pinned_adk_compatibility_verified=True,
            authentication_method_verified=True,
            quota_verified=True,
            billing_source_verified=True,
            funding_source_verified=True,
            sku_credit_coverage_verified=True,
            region_verified=True,
            zero_personal_spend_safe=True,
            approved_credentials_available=True,
            human_live_request_approved=True,
            billing_upgrade_required=False,
        ),
        credential_environment=GeminiCredentialEnvironment(
            gemini_api_key_present=True,
            google_api_key_present=False,
            vertex_path_enabled=False,
            enterprise_path_enabled=False,
        ),
        evidence_recorder=fixture.evidence_recorder,
    )

    receipt = plan.record_model_non_attempt(
        invocation_id=DEFAULT_INVOCATION_ID.value,
        reason_code="no-candidate-tool-call",
    )

    assert receipt.event_type == EvidenceEventType.RUN_MODEL_NON_ATTEMPT.value
    assert _types(fixture) == (EvidenceEventType.RUN_MODEL_NON_ATTEMPT,)
    event = fixture.evidence_store.ordered_events()[0]
    assert not hasattr(event.payload, "outcome")
    assert fixture.adapter.entry_count == 0
    assert fixture.payment_store.count == 0


def test_queries_reconstruct_complete_non_secret_lineage(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    prepared = fixture.prepare(fixture.canonical_call())
    outcome = fixture.execution_gate.execute(prepared)
    events = fixture.evidence_store.ordered_events()
    decision_id = DecisionId(prepared.decision_id.value)

    assert fixture.evidence_store.events_for_trace(events[0].trace_id) == events
    assert fixture.evidence_store.events_for_invocation(
        InvocationId(prepared.invocation_id.value)
    ) == events
    assert len(fixture.evidence_store.events_for_call(CallId(prepared.call_id.value))) == 5
    assert len(fixture.evidence_store.events_for_decision(decision_id)) == 4
    assert len(fixture.evidence_store.events_for_prepared_call(prepared.prepared_call_id)) == 4
    assert len(fixture.evidence_store.events_for_execution(outcome.execution_id)) == 3


def test_payment_evidence_is_exactly_the_masked_authoritative_record(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    prepared = fixture.prepare(fixture.canonical_call())
    outcome = fixture.execution_gate.execute(prepared)
    payment = fixture.payment_store.records()[0]
    event = fixture.evidence_store.events_for_execution(outcome.execution_id)[-1]

    assert event.event_type is EvidenceEventType.PAYMENT_RECORDED
    assert asdict(event.payload) == {
        "payment_record_id": payment.payment_record_id,
        "execution_id": {"value": payment.execution_id.value},
        "prepared_call_id": {"value": payment.prepared_call_id.value},
        "idempotency_key_fingerprint": payment.idempotency_key_fingerprint,
        "amount_minor": payment.amount_minor,
        "currency": payment.currency,
        "parent_id": {"value": payment.parent_id.value},
        "destination_kind": payment.destination_kind,
        "masked_destination_display": payment.masked_destination_display,
        "status": "RECORDED",
        "store_version": payment.store_version,
        "created_at": payment.created_at,
    }
    assert not hasattr(event.payload, "reference_id")
    assert not hasattr(event.payload, "raw_destination")


def test_persisted_files_and_public_evidence_exclude_forbidden_values(
    tmp_path, caplog
):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    adapter = AdkSchedulePaymentCallbackAdapter(fixture)
    _dispatch(adapter, _valid_args(fixture))

    persisted = "".join(
        path.read_text(encoding="utf-8")
        for path in Path(tmp_path).rglob("*.json")
    )
    events = fixture.evidence_store.ordered_events()
    public = (
        repr(events)
        + repr(tuple(asdict(event) for event in events))
        + persisted
        + caplog.text
    )
    forbidden = (
        RAW_SYNTHETIC_DESTINATION,
        fixture.destination_reference.value,
        "GEMINI" + "_API_KEY",
        "promotion" + "_code",
        "runtime-private-authenticator",
    )

    assert all(marker not in public for marker in forbidden)
    assert "prepared runtime payload" not in public
    assert "PolicySnapshot" not in public


def test_order_13_has_no_spike_provider_cloud_or_mutation_dependency():
    project_root = Path(__file__).parents[2]
    paths = tuple((project_root / "src" / "tidemark" / "evidence").glob("*.py"))
    source = "".join(path.read_text(encoding="utf-8") for path in paths).lower()

    assert "tidemark" + "_spike" not in source
    assert "all_things" + "_agentic_evaluation" not in source
    assert "google" + ".cloud" not in source
    assert "fire" + "store" not in source
    assert "gemini" + "_api_key" not in source
