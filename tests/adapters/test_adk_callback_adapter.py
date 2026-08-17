import ast
import asyncio
from dataclasses import asdict
import inspect
from pathlib import Path
import socket

from tidemark.adapters.google_adk import (
    ADK_CALLBACK_ADAPTER_VERSION,
    ADK_DISTRIBUTION_VERSION,
    AdkCallbackAction,
    AdkSchedulePaymentCallbackAdapter,
)

from google.adk.agents.invocation_context import InvocationContext
from google.adk.agents.llm_agent import LlmAgent
from google.adk.flows.llm_flows.functions import (
    handle_function_call_list_async,
)
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.adk.sessions.session import Session
from google.adk.tools.function_tool import FunctionTool
from google.adk.tools.tool_context import ToolContext
from google.genai import types

from tidemark.payment.domain import SyntheticSchedulePaymentAdapter
from tidemark.payment.fixtures import (
    DEFAULT_INVOCATION_ID,
    RAW_SYNTHETIC_DESTINATION,
    build_synthetic_payment_fixture,
)
from tidemark.runtime.execution_gate import AdapterInvocation
from tidemark.runtime.execution_binding import (
    _lookup_runtime_execution_binding,
)
from tidemark.runtime.policy_engine import Decision
from tidemark.runtime.prepared_call import PreparedToolCall
from tidemark.runtime.vocabulary import (
    DecisionOutcome,
    ExecutionOutcome,
    PreparedCallState,
    RuleId,
)


_FUNCTION_CALL_ID = "adk-function-call-order-11-001"


def _valid_args(fixture):
    return {
        "amount_minor": fixture.purchase_order.maximum_amount_minor,
        "currency": fixture.purchase_order.allowed_currencies[0],
        "destination_reference": fixture.destination_reference.value,
    }


def _dispatch(
    adapter,
    pending_args,
    *,
    tool=None,
    invocation_id=DEFAULT_INVOCATION_ID.value,
    function_call_id=_FUNCTION_CALL_ID,
    later_callbacks=(),
):
    adk_tool = tool or adapter.build_tool()
    callbacks = [adapter.before_tool_callback, *later_callbacks]
    agent = LlmAgent(
        name="tidemark_order_11_agent",
        tools=[adk_tool],
        before_tool_callback=callbacks,
    )
    invocation_context = InvocationContext(
        invocation_id=invocation_id,
        agent=agent,
        session=Session(
            id="tidemark-order-11-session",
            app_name="tidemark-order-11",
            user_id="synthetic-reviewer",
            state={},
        ),
        session_service=InMemorySessionService(),
    )
    function_call = types.FunctionCall(
        id=function_call_id,
        name=adk_tool.name,
        args=pending_args,
    )
    original_connect = socket.socket.connect

    def forbid_network(self, address):
        raise AssertionError(f"Order 11 attempted a network request: {address!r}")

    socket.socket.connect = forbid_network
    try:
        event = asyncio.run(
            handle_function_call_list_async(
                invocation_context,
                [function_call],
                {adk_tool.name: adk_tool},
            )
        )
    finally:
        socket.socket.connect = original_connect
    return event


def _response(event):
    responses = event.get_function_responses()
    assert len(responses) == 1
    return responses[0].response


def test_pinned_adk_callback_and_dispatch_surface_is_exact(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    adapter = AdkSchedulePaymentCallbackAdapter(fixture)

    assert ADK_DISTRIBUTION_VERSION == "1.18.0"
    assert ADK_CALLBACK_ADAPTER_VERSION == "tidemark.google-adk.callback.v1"
    assert tuple(inspect.signature(adapter.before_tool_callback).parameters) == (
        "tool",
        "args",
        "tool_context",
    )
    assert adapter.build_tool().name == "schedule_payment"


def test_real_adk_dispatch_deny_veto_skips_tool_gate_and_payment(
    tmp_path, monkeypatch
):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    adapter = AdkSchedulePaymentCallbackAdapter(fixture)
    pending_args = _valid_args(fixture)
    pending_args["destination_reference"] = RAW_SYNTHETIC_DESTINATION

    def forbidden_execution_gate(self, prepared_call):
        raise AssertionError("core DENY entered ExecutionGate")

    monkeypatch.setattr(
        "tidemark.runtime.execution_gate.ExecutionGate.execute",
        forbidden_execution_gate,
    )

    event = _dispatch(adapter, pending_args)
    result = adapter.last_callback_result

    assert result.action is AdkCallbackAction.VETO
    assert result.core_outcome is DecisionOutcome.DENY
    assert result.rule_id is RuleId.PROTECTED_RAW_VALUE_SUPPLIED
    assert _response(event)["callback_action"] == "VETO"
    assert adapter.prepared_call_count == 0
    assert adapter.tool_body_entry_count == 0
    assert fixture.adapter.entry_count == 0
    assert fixture.payment_store.count == 0
    assert fixture.reference_metadata().consumed is False


def test_real_adk_dispatch_allow_releases_one_sealed_call_and_executes_once(
    tmp_path,
):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    adapter = AdkSchedulePaymentCallbackAdapter(fixture)

    event = _dispatch(adapter, _valid_args(fixture))
    result = adapter.last_callback_result
    execution = adapter.last_execution_result

    assert result.action is AdkCallbackAction.RELEASE
    assert result.core_outcome is DecisionOutcome.ALLOW
    assert result.rule_id is RuleId.AUTHORIZATION_ALLOW
    assert result.prepared_call_id is not None
    assert adapter.prepared_call_count == 1
    assert adapter.tool_body_entry_count == 1
    assert adapter.released_call_count == 1
    assert execution.status is ExecutionOutcome.COMPLETED
    assert _response(event)["execution_status"] == "COMPLETED"
    assert fixture.adapter.entry_count == 1
    assert fixture.payment_store.count == 1
    assert fixture.reference_metadata().consumed is True
    binding = _lookup_runtime_execution_binding(result.prepared_call_id)
    assert binding._capability_state is PreparedCallState.CONSUMED


def test_pending_argument_substitution_cannot_replace_sealed_payload(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    adapter = AdkSchedulePaymentCallbackAdapter(fixture)
    approved = _valid_args(fixture)

    def substitute_after_preparation(tool, args, tool_context):
        args.clear()
        args.update(
            {
                "amount_minor": fixture.purchase_order.maximum_amount_minor + 1,
                "currency": "USD",
                "destination_reference": RAW_SYNTHETIC_DESTINATION,
            }
        )
        return None

    _dispatch(
        adapter,
        approved,
        later_callbacks=(substitute_after_preparation,),
    )
    record = fixture.payment_store.records()[0]

    assert adapter.last_callback_result.action is AdkCallbackAction.RELEASE
    assert adapter.tool_body_entry_count == 1
    assert fixture.adapter.entry_count == 1
    assert fixture.payment_store.count == 1
    assert record.amount_minor == approved["amount_minor"]
    assert record.currency == approved["currency"]
    assert RAW_SYNTHETIC_DESTINATION not in repr(record)


def test_unknown_framework_tool_vetoes_with_existing_core_refusal(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    adapter = AdkSchedulePaymentCallbackAdapter(fixture)
    probe_entries = []

    def unknown_transport_tool(
        amount_minor: int,
        currency: str,
        destination_reference: str,
        tool_context: ToolContext,
    ):
        probe_entries.append(tool_context.function_call_id)
        return {"unexpected": True}

    event = _dispatch(
        adapter,
        _valid_args(fixture),
        tool=FunctionTool(unknown_transport_tool),
    )
    result = adapter.last_callback_result

    assert result.action is AdkCallbackAction.VETO
    assert result.core_outcome is DecisionOutcome.REFUSAL
    assert result.rule_id is RuleId.CONTRACT_TOOL_UNKNOWN
    assert _response(event)["callback_action"] == "VETO"
    assert probe_entries == []
    assert adapter.tool_body_entry_count == 0
    assert fixture.adapter.entry_count == 0
    assert fixture.payment_store.count == 0


def test_invocation_and_function_call_correlation_are_captured_as_data(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    adapter = AdkSchedulePaymentCallbackAdapter(fixture)

    _dispatch(adapter, _valid_args(fixture))
    metadata = adapter.last_callback_result.transport

    assert metadata.framework_name == "google-adk"
    assert metadata.framework_version == ADK_DISTRIBUTION_VERSION
    assert metadata.callback_version == ADK_CALLBACK_ADAPTER_VERSION
    assert metadata.tool_name == "schedule_payment"
    assert metadata.invocation_correlation == DEFAULT_INVOCATION_ID.value
    assert metadata.function_call_correlation == _FUNCTION_CALL_ID
    assert metadata.pending_argument_names == (
        "amount_minor",
        "currency",
        "destination_reference",
    )
    assert metadata.pending_argument_types == ("int", "str", "str")
    assert all(
        not value.__class__.__module__.startswith("google.adk")
        for value in asdict(metadata).values()
    )


def test_framework_objects_never_enter_core_or_payment_adapter(
    tmp_path, monkeypatch
):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    adapter = AdkSchedulePaymentCallbackAdapter(fixture)
    captured = []
    original_call = SyntheticSchedulePaymentAdapter.__call__

    def capture_call(self, invocation):
        captured.append(invocation)
        return original_call(self, invocation)

    monkeypatch.setattr(SyntheticSchedulePaymentAdapter, "__call__", capture_call)
    _dispatch(adapter, _valid_args(fixture))

    runtime_root = Path(__file__).parents[2] / "src" / "tidemark" / "runtime"
    for path in runtime_root.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = (
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
        )
        assert all(
            not any(
                name.name.startswith("google.adk")
                for name in (
                    node.names
                    if isinstance(node, ast.Import)
                    else [ast.alias(name=node.module or "")]
                )
            )
            for node in imports
        )

    isolation_fixture = build_synthetic_payment_fixture(
        str(tmp_path / "core-isolation")
    )
    decision = isolation_fixture.evaluate(isolation_fixture.canonical_call())
    prepared = isolation_fixture.prepare(isolation_fixture.canonical_call())
    assert type(decision) is Decision
    assert type(prepared) is PreparedToolCall
    assert len(captured) == 1
    assert type(captured[0]) is AdapterInvocation
    public_values = (
        *asdict(decision).values(),
        *asdict(prepared).values(),
        *asdict(captured[0]).values(),
    )
    assert all(
        not value.__class__.__module__.startswith("google.adk")
        for value in public_values
    )


def test_order_11_public_surfaces_do_not_leak_protected_values(tmp_path, caplog):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    adapter = AdkSchedulePaymentCallbackAdapter(fixture)
    pending_args = _valid_args(fixture)
    pending_args["destination_reference"] = RAW_SYNTHETIC_DESTINATION

    event = _dispatch(adapter, pending_args)
    decision = fixture.evaluate(
        fixture.canonical_call(
            destination_reference=RAW_SYNTHETIC_DESTINATION
        )
    )
    allowed_prepared = fixture.prepare(fixture.canonical_call())
    public_views = (
        repr(adapter.last_callback_result),
        repr(asdict(adapter.last_callback_result)),
        repr(adapter),
        repr(event),
        repr(_response(event)),
        repr(decision),
        repr(asdict(decision)),
        repr(allowed_prepared),
        repr(asdict(allowed_prepared)),
        caplog.text,
    )

    assert all(RAW_SYNTHETIC_DESTINATION not in view for view in public_views)
    assert all(
        fixture.destination_reference.value not in view for view in public_views
    )


def test_adapter_and_tests_have_no_spike_source_fixture_or_evidence_dependency():
    project_root = Path(__file__).parents[2]
    paths = (
        project_root / "src" / "tidemark" / "adapters" / "google_adk.py",
        Path(__file__),
    )
    forbidden_parts = (
        ("tidemark", "spike"),
        ("all", "things", "agentic", "evaluation"),
    )

    for path in paths:
        source = path.read_text(encoding="utf-8")
        lowered = source.lower().replace("-", "_")
        tree = ast.parse(source)
        imported = tuple(
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        ) + tuple(
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
        assert all("_".join(parts) not in lowered for parts in forbidden_parts)
        assert all(
            not any("_".join(parts) in name for parts in forbidden_parts)
            for name in imported
        )
