from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, fields, replace
from pathlib import Path

import pytest

from tidemark.payment.domain import (
    PAYMENT_RECORDED_STATUS,
    PurchaseOrderRecord,
    SyntheticPaymentRecord,
    SyntheticPaymentStore,
    SyntheticSchedulePaymentAdapter,
)
from tidemark.payment.fixtures import (
    DESTINATION_ARGUMENT_NAME,
    RAW_SYNTHETIC_DESTINATION,
    SCHEDULE_PAYMENT_TOOL_ID,
    SYNTHETIC_DESTINATION_KIND,
    build_synthetic_payment_fixture,
)
from tidemark.runtime.execution_gate import (
    AdapterInvocation,
    ExecutionGate,
    TrustedAdapterRegistry,
)
from tidemark.runtime.identifiers import (
    InvocationId,
    ParentId,
    ReferenceId,
    ToolId,
)
from tidemark.runtime.minimal_evidence import (
    EvidenceAppendFailure,
    MinimalPreExecutionEvidenceSink,
)
from tidemark.runtime.policy_engine import Decision
from tidemark.runtime.prepared_call import PreparationRefusal, PreparedToolCall
from tidemark.runtime.reference_store import (
    ReferenceBinding,
    ReferenceConsumptionOutcome,
    ReferenceLifecycle,
    ReferenceMetadata,
    TrustedRecord,
)
from tidemark.runtime.vocabulary import (
    ArgumentRole,
    DecisionOutcome,
    ExecutionOutcome,
    PreparedCallState,
    RuleId,
)


def assert_deny_without_payment(fixture, call, rule_id):
    decision = fixture.evaluate(call)
    preparation = fixture.prepare(call)

    assert type(decision) is Decision
    assert decision.outcome is DecisionOutcome.DENY
    assert decision.primary_rule_id is rule_id
    assert type(preparation) is PreparationRefusal
    assert preparation.decision.primary_rule_id is rule_id
    assert fixture.adapter.entry_count == 0
    assert fixture.payment_store.count == 0
    return decision, preparation


def test_valid_end_to_end_payment_flow_creates_exactly_one_payment(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    call = fixture.canonical_call()

    decision = fixture.evaluate(call)
    prepared = fixture.prepare(call)
    assert decision.outcome is DecisionOutcome.ALLOW
    assert decision.primary_rule_id is RuleId.AUTHORIZATION_ALLOW
    assert type(prepared) is PreparedToolCall

    outcome = fixture.execution_gate.execute(prepared)
    records = fixture.payment_store.records()

    assert outcome.status is ExecutionOutcome.COMPLETED
    assert outcome.external_result_confirmed is True
    assert fixture.adapter.entry_count == 1
    assert len(records) == 1
    assert records[0].execution_id == outcome.execution_id
    assert records[0].prepared_call_id == prepared.prepared_call_id
    assert fixture.reference_metadata().consumed is True
    assert decision.outcome is DecisionOutcome.ALLOW


def test_raw_protected_destination_is_denied_before_preparation_or_adapter(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    call = fixture.canonical_call(
        destination_reference="caller-supplied-raw-destination"
    )

    decision, preparation = assert_deny_without_payment(
        fixture, call, RuleId.PROTECTED_RAW_VALUE_SUPPLIED
    )

    assert decision.evaluation_stage.value == "REPRESENTATION"
    assert not hasattr(preparation, "prepared_call")


def test_unknown_reference_is_denied_with_stable_rule_and_zero_payment(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    call = fixture.canonical_call(
        destination_reference=ReferenceId("ref_order_9_forged_unknown")
    )

    assert_deny_without_payment(fixture, call, RuleId.REFERENCE_NOT_FOUND)


def test_invocation_mismatch_is_denied_with_zero_payment(tmp_path):
    fixture = build_synthetic_payment_fixture(
        str(tmp_path),
        reference_invocation_id=InvocationId("invocation-order-9-misbound"),
    )

    assert_deny_without_payment(
        fixture,
        fixture.canonical_call(),
        RuleId.REFERENCE_INVOCATION_MISMATCH,
    )


def test_parent_mismatch_is_denied_with_zero_payment(tmp_path):
    fixture = build_synthetic_payment_fixture(
        str(tmp_path),
        reference_parent_id=ParentId("purchase-order-order-9-misbound"),
    )

    assert_deny_without_payment(
        fixture,
        fixture.canonical_call(),
        RuleId.REFERENCE_PARENT_MISMATCH,
    )


def test_inactive_reference_is_denied_with_zero_payment(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path), reference_active=False)

    assert_deny_without_payment(
        fixture,
        fixture.canonical_call(),
        RuleId.REFERENCE_INACTIVE,
    )


def test_consumed_reference_is_denied_with_zero_payment(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    assert fixture.reference_store.consume(fixture.destination_reference) is (
        ReferenceConsumptionOutcome.CONSUMED
    )

    assert_deny_without_payment(
        fixture,
        fixture.canonical_call(),
        RuleId.REFERENCE_ALREADY_CONSUMED,
    )


def test_purchase_order_amount_boundary_is_allowed(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    call = fixture.canonical_call(
        amount_minor=fixture.purchase_order.maximum_amount_minor
    )

    decision = fixture.evaluate(call)
    prepared = fixture.prepare(call)
    outcome = fixture.execution_gate.execute(prepared)

    assert decision.outcome is DecisionOutcome.ALLOW
    assert outcome.status is ExecutionOutcome.COMPLETED
    assert fixture.payment_store.records()[0].amount_minor == (
        fixture.purchase_order.maximum_amount_minor
    )


def test_amount_above_purchase_order_bound_is_denied_with_zero_payment(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    call = fixture.canonical_call(
        amount_minor=fixture.purchase_order.maximum_amount_minor + 1
    )

    assert_deny_without_payment(
        fixture, call, RuleId.VALUE_CONSTRAINT_FAILED
    )


def test_supported_purchase_order_currency_is_allowed(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))

    decision = fixture.evaluate(fixture.canonical_call(currency="EUR"))

    assert decision.outcome is DecisionOutcome.ALLOW


def test_unsupported_currency_is_denied_with_zero_payment(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))

    assert_deny_without_payment(
        fixture,
        fixture.canonical_call(currency="USD"),
        RuleId.VALUE_CONSTRAINT_FAILED,
    )


def test_refusal_creates_no_prepared_call_adapter_entry_or_payment(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    unknown_call = replace(
        fixture.canonical_call(), tool_id=ToolId("unknown.schedule_payment")
    )

    decision = fixture.evaluate(unknown_call)
    preparation = fixture.prepare(unknown_call)

    assert decision.outcome is DecisionOutcome.REFUSAL
    assert decision.primary_rule_id is RuleId.CONTRACT_TOOL_UNKNOWN
    assert type(preparation) is PreparationRefusal
    assert fixture.adapter.entry_count == 0
    assert fixture.payment_store.count == 0


def test_execution_replay_is_rejected_and_does_not_add_payment(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    prepared = fixture.prepare(fixture.canonical_call())
    assert type(prepared) is PreparedToolCall

    first = fixture.execution_gate.execute(prepared)
    second = fixture.execution_gate.execute(prepared)

    assert first.status is ExecutionOutcome.COMPLETED
    assert second.status is ExecutionOutcome.REPLAY_REJECTED
    assert second.rule_id is RuleId.EXECUTION_REPLAY_REJECTED
    assert fixture.adapter.entry_count == 1
    assert fixture.payment_store.count == 1


def test_concurrent_execution_creates_one_payment_and_rejects_all_losers(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    prepared = fixture.prepare(fixture.canonical_call())
    assert type(prepared) is PreparedToolCall

    with ThreadPoolExecutor(max_workers=12) as executor:
        outcomes = tuple(
            executor.map(fixture.execution_gate.execute, (prepared,) * 24)
        )

    assert sum(
        outcome.status is ExecutionOutcome.COMPLETED for outcome in outcomes
    ) == 1
    assert sum(
        outcome.status is ExecutionOutcome.REPLAY_REJECTED
        for outcome in outcomes
    ) == 23
    assert fixture.adapter.entry_count == 1
    assert fixture.payment_store.count == 1


def test_pre_execution_evidence_failure_preserves_authority_and_zero_payment(
    tmp_path, monkeypatch
):
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


def test_adapter_failure_before_authoritative_write_is_failed_consumed_no_retry(
    tmp_path,
):
    fixture = build_synthetic_payment_fixture(
        str(tmp_path), adapter_fail_before_record=True
    )
    call = fixture.canonical_call()
    decision = fixture.evaluate(call)
    prepared = fixture.prepare(call)
    assert type(prepared) is PreparedToolCall
    sealed_decision = asdict(decision)

    outcome = fixture.execution_gate.execute(prepared)
    replay = fixture.execution_gate.execute(prepared)

    assert outcome.status is ExecutionOutcome.FAILED
    assert outcome.external_result_confirmed is True
    assert replay.status is ExecutionOutcome.REPLAY_REJECTED
    assert fixture.reference_metadata().consumed is True
    assert fixture.adapter.entry_count == 1
    assert fixture.payment_store.count == 0
    assert asdict(decision) == sealed_decision
    assert decision.outcome is DecisionOutcome.ALLOW


def test_payment_record_is_exact_masked_bounded_authoritative_state(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    prepared = fixture.prepare(fixture.canonical_call())
    outcome = fixture.execution_gate.execute(prepared)
    record = fixture.payment_store.records()[0]

    assert type(record) is SyntheticPaymentRecord
    assert {field.name for field in fields(record)} == {
        "payment_record_id",
        "execution_id",
        "prepared_call_id",
        "idempotency_key_fingerprint",
        "amount_minor",
        "currency",
        "parent_id",
        "destination_kind",
        "masked_destination_display",
        "status",
        "store_version",
        "created_at",
    }
    assert record.execution_id == outcome.execution_id
    assert record.prepared_call_id == prepared.prepared_call_id
    assert record.parent_id == fixture.purchase_order.parent_id
    assert record.destination_kind == SYNTHETIC_DESTINATION_KIND
    assert record.masked_destination_display == "synthetic-beneficiary-****4242"
    assert record.status == PAYMENT_RECORDED_STATUS
    assert record.store_version == 1
    assert record.idempotency_key_fingerprint.startswith("sha256:")
    assert len(record.idempotency_key_fingerprint) == 71


def test_protected_destination_is_absent_from_all_public_and_stored_surfaces(
    tmp_path,
):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    call = fixture.canonical_call()
    decision = fixture.evaluate(call)
    prepared = fixture.prepare(call)
    outcome = fixture.execution_gate.execute(prepared)
    record = fixture.payment_store.records()[0]
    evidence = "".join(
        path.read_text(encoding="utf-8")
        for path in Path(tmp_path).glob("*.json")
    )

    public_views = (
        repr(decision),
        repr(asdict(decision)),
        repr(prepared),
        repr(asdict(prepared)),
        repr(outcome),
        repr(asdict(outcome)),
        repr(record),
        repr(asdict(record)),
        evidence,
        repr(fixture.payment_store),
        repr(fixture.adapter),
    )

    assert all(RAW_SYNTHETIC_DESTINATION not in view for view in public_views)
    assert fixture.destination_reference.value not in repr(record)
    assert not hasattr(record, "reference_id")
    assert not hasattr(record, "raw_destination")


def test_adapter_boundary_receives_detached_payload_and_only_allowed_correlations(
    tmp_path,
):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    prepared = fixture.prepare(fixture.canonical_call())
    assert type(prepared) is PreparedToolCall
    store = SyntheticPaymentStore()
    adapter = SyntheticSchedulePaymentAdapter(
        payment_store=store,
        purchase_order=fixture.purchase_order,
        destination_kind=SYNTHETIC_DESTINATION_KIND,
        masked_destination_display="synthetic-beneficiary-****4242",
    )
    captured = []

    def capture_then_schedule(invocation):
        captured.append(invocation)
        return adapter(invocation)

    registry = TrustedAdapterRegistry(
        tool_id=prepared.tool_id,
        adapter_id=prepared.adapter_id,
        adapter_version=prepared.adapter_version,
        adapter=capture_then_schedule,
    )
    gate = ExecutionGate(
        adapter_registry=registry,
        evidence_sink=MinimalPreExecutionEvidenceSink(str(tmp_path / "capture")),
    )

    outcome = gate.execute(prepared)

    assert outcome.status is ExecutionOutcome.COMPLETED
    assert len(captured) == 1
    invocation = captured[0]
    assert type(invocation) is AdapterInvocation
    assert {field.name for field in fields(invocation)} == {
        "tool_id",
        "execution_id",
        "prepared_call_id",
        "call_id",
        "decision_id",
        "invocation_id",
        "arguments",
    }
    assert tuple(argument.name for argument in invocation.arguments) == (
        "amount_minor",
        "currency",
        DESTINATION_ARGUMENT_NAME,
    )
    assert tuple(argument.value for argument in invocation.arguments) == (
        fixture.purchase_order.maximum_amount_minor,
        "EUR",
        RAW_SYNTHETIC_DESTINATION,
    )
    assert invocation.arguments[2].role is ArgumentRole.PROTECTED_REFERENCE
    forbidden_names = {
        "reference_id",
        "trusted_store",
        "resolver",
        "snapshot",
        "policy_engine",
        "evidence_sink",
        "raw_proposal",
    }
    assert forbidden_names.isdisjoint(
        {field.name for field in fields(invocation)}
    )
    assert store.count == 1


def test_purchase_order_is_the_source_of_installed_bound_and_currency(tmp_path):
    purchase_order = PurchaseOrderRecord(
        parent_id=ParentId("purchase-order-order-9-custom"),
        maximum_amount_minor=12_345,
        allowed_currencies=("EUR", "GBP"),
    )
    fixture = build_synthetic_payment_fixture(
        str(tmp_path), purchase_order=purchase_order
    )
    tool_policy = fixture.snapshot.tool_policies[0]
    amount_binding = tool_policy.arguments[0].constraint_bindings[0]
    currency_binding = tool_policy.arguments[1].constraint_bindings[0]

    assert amount_binding.parameters == (("maximum", 12_345),)
    assert currency_binding.parameters == (("members", ("EUR", "GBP")),)
    assert fixture.evaluate(
        fixture.canonical_call(amount_minor=12_345, currency="GBP")
    ).outcome is DecisionOutcome.ALLOW
    assert fixture.evaluate(
        fixture.canonical_call(amount_minor=12_346, currency="GBP")
    ).primary_rule_id is RuleId.VALUE_CONSTRAINT_FAILED


def test_payment_store_and_adapter_have_no_general_database_or_retry_surface(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))

    assert {"delete", "update", "retry", "connect", "execute_sql"}.isdisjoint(
        dir(fixture.payment_store)
    )
    assert {"retry", "resolve", "issue", "prepare", "execute"}.isdisjoint(
        dir(fixture.adapter)
    )
    assert SCHEDULE_PAYMENT_TOOL_ID == ToolId("schedule_payment")
