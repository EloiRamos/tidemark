from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, asdict, fields
from datetime import datetime, timezone
import inspect

import pytest

from tidemark.runtime.identifiers import (
    AdapterId,
    AdapterVersion,
    CallId,
    DecisionId,
    InvocationId,
    ParentId,
    PolicyVersion,
    ReferenceId,
    RegistryVersion,
    ToolContractVersion,
    ToolId,
    TypeId,
)
from tidemark.runtime.execution_gate import (
    AdapterInvocation,
    AdapterInvocationResult,
    ExecutionGate,
    ExecutionResult,
    TrustedAdapterRegistry,
)
from tidemark.runtime.minimal_evidence import (
    EvidenceAppendFailure,
    MinimalPreExecutionEvidenceSink,
)
from tidemark.runtime.policy_authoring import (
    ValidatedPolicyAuthoring,
    validate_policy_authoring,
)
from tidemark.runtime.policy_engine import (
    CallContext,
    CanonicalArgument,
    CanonicalCall,
    CanonicalSignatureArgument,
    Decision,
    PolicyEngine,
    ResolutionEntry,
    ResolutionSet,
    Resolved,
)
from tidemark.runtime.policy_snapshot import InstalledSnapshot, PolicyInstaller
from tidemark.runtime.prepared_call import (
    PreparationRefusal,
    PreparedCallPipeline,
    PreparedToolCall,
)
from tidemark.runtime.reference_resolver import ReferenceResolver, ResolutionRequest
from tidemark.runtime.reference_store import (
    ReferenceBinding,
    ReferenceLifecycle,
    ReferenceMetadata,
    TrustedRecord,
    TrustedReferenceStore,
)
from tidemark.runtime.vocabulary import (
    DecisionOutcome,
    ExecutionOutcome,
    PreparedCallState,
    RuleId,
)


EVALUATION_TIME = datetime(2026, 8, 7, 17, 0, tzinfo=timezone.utc)
INVOCATION_ID = InvocationId("invocation-order-8")
PARENT_ID = ParentId("parent-order-8")
PROTECTED_MARKER = "protected-runtime-payload-never-publish-order-8"


def authoring(protected_names=("destination_reference",)):
    signature = (
        {"name": "quantity", "required": True, "type_id": "integer"},
    ) + tuple(
        {"name": name, "required": True, "type_id": "destination_reference"}
        for name in protected_names
    )
    arguments = (
        {
            "name": "quantity",
            "position": 0,
            "type_id": "integer",
            "required": True,
            "role": "UNPROTECTED_INPUT",
            "constraint_bindings": (
                {
                    "constraint_id": "value.integer.maximum.v1",
                    "parameters": {"maximum": 100},
                },
            ),
        },
    ) + tuple(
        {
            "name": name,
            "position": index + 1,
            "type_id": "destination_reference",
            "required": True,
            "role": "PROTECTED_REFERENCE",
            "constraint_bindings": (
                {
                    "constraint_id": "protected.reference.required.v1",
                    "parameters": {},
                },
                {
                    "constraint_id": "reference.kind.equals.v1",
                    "parameters": {"kind": "destination"},
                },
                {
                    "constraint_id": "reference.invocation.equals.v1",
                    "parameters": {},
                },
                {
                    "constraint_id": "reference.parent.equals.v1",
                    "parameters": {},
                },
                {"constraint_id": "reference.active.v1", "parameters": {}},
                {
                    "constraint_id": "reference.single_use.v1",
                    "parameters": {},
                },
            ),
        }
        for index, name in enumerate(protected_names)
    )
    role_metadata = (
        {
            "name": "quantity",
            "role": "UNPROTECTED_INPUT",
            "required_provenance": "UNTRUSTED",
        },
    ) + tuple(
        {
            "name": name,
            "role": "PROTECTED_REFERENCE",
            "required_provenance": "RUNTIME_TRUSTED",
        }
        for name in protected_names
    )
    return {
        "policy_version": "policy-order-8-v1",
        "registry_version": "registry-order-8-v1",
        "executable_tools": ("dispatch.submit",),
        "tool_registrations": (
            {
                "tool_id": "dispatch.submit",
                "contract_version": "dispatch.submit.contract.v1",
                "policy_version": "policy-order-8-v1",
                "signature": signature,
                "arguments": arguments,
                "role_metadata": role_metadata,
                "effect_class": "SIDE_EFFECTING",
                "reversibility": "IRREVERSIBLE",
                "adapter_id": "dispatch.local.adapter",
                "adapter_version": "dispatch.local.adapter.v1",
                "masking_profile_id": "dispatch.masking.v1",
            },
        ),
    }


def build_runtime(
    *,
    protected_values=None,
    protected_names=("destination_reference",),
    reference_ids=None,
):
    values = protected_values or tuple(
        f"{PROTECTED_MARKER}-{index}" for index in range(len(protected_names))
    )
    validated = validate_policy_authoring(authoring(protected_names))
    assert type(validated) is ValidatedPolicyAuthoring
    installed = PolicyInstaller().install(validated)
    assert type(installed) is InstalledSnapshot
    snapshot = installed.snapshot
    store = TrustedReferenceStore()
    issued = tuple(
        store.issuer.issue(
            TrustedRecord(value, "destination"),
            ReferenceBinding(INVOCATION_ID, PARENT_ID),
            ReferenceLifecycle(active=True, single_use=True),
        )
        for value in values
    )
    selected_ids = issued if reference_ids is None else reference_ids(issued)
    signature = tuple(
        CanonicalSignatureArgument(
            item.name, item.required, TypeId(item.type_id.value)
        )
        for item in snapshot.tool_policies[0].signature
    )
    call = CanonicalCall(
        tool_id=ToolId("dispatch.submit"),
        contract_version=ToolContractVersion("dispatch.submit.contract.v1"),
        signature=signature,
        arguments=(CanonicalArgument("quantity", 50),)
        + tuple(
            CanonicalArgument(name, reference_id)
            for name, reference_id in zip(protected_names, selected_ids)
        ),
    )
    context = CallContext(
        call_id=CallId("call-order-8"),
        decision_id=DecisionId("decision-order-8"),
        invocation_id=INVOCATION_ID,
        parent_id=PARENT_ID,
        policy_version=PolicyVersion(snapshot.policy_version.value),
        registry_version=RegistryVersion(snapshot.registry_version.value),
    )
    resolutions = tuple(
        ResolutionEntry(
            name,
            ReferenceResolver().resolve(
                ResolutionRequest(
                    reference_id,
                    "destination",
                    INVOCATION_ID,
                    PARENT_ID,
                    name,
                    EVALUATION_TIME,
                ),
                store,
            ),
        )
        for name, reference_id in zip(protected_names, selected_ids)
    )
    decision = PolicyEngine().evaluate(
        snapshot, call, ResolutionSet(resolutions), context
    )
    prepared = PreparedCallPipeline().prepare(
        snapshot=snapshot,
        canonical_call=call,
        call_context=context,
        trusted_store=store,
        evaluation_time=EVALUATION_TIME,
    )
    return prepared, decision, snapshot, store, issued, call, resolutions[0].result


class AdapterSpy:
    def __init__(self, result=None, error=None):
        self.calls = []
        self.result = result or AdapterInvocationResult.confirmed_success()
        self.error = error

    def __call__(self, invocation):
        self.calls.append(invocation)
        if self.error is not None:
            raise self.error
        return self.result


def gate_for(prepared, tmp_path, adapter=None, **registry_changes):
    spy = adapter or AdapterSpy()
    fields = {
        "tool_id": prepared.tool_id,
        "adapter_id": prepared.adapter_id,
        "adapter_version": prepared.adapter_version,
        "adapter": spy,
    }
    fields.update(registry_changes)
    registry = TrustedAdapterRegistry(**fields)
    sink = MinimalPreExecutionEvidenceSink(str(tmp_path))
    return ExecutionGate(adapter_registry=registry, evidence_sink=sink), spy, sink


def assert_unused(store, reference_ids):
    views = tuple(store.lookup(reference_id) for reference_id in reference_ids)
    assert all(type(view) is ReferenceMetadata for view in views)
    assert all(view.consumed is False for view in views)


def assert_consumed(store, reference_ids):
    views = tuple(store.lookup(reference_id) for reference_id in reference_ids)
    assert all(type(view) is ReferenceMetadata for view in views)
    assert all(view.consumed is True for view in views)


def evidence_files(tmp_path):
    return tuple(tmp_path.glob("*.json"))


def test_exact_prepared_tool_call_executes_and_returns_immutable_completed_result(
    tmp_path,
):
    prepared, decision, _, store, reference_ids, *_ = build_runtime()
    assert type(prepared) is PreparedToolCall
    gate, spy, _ = gate_for(prepared, tmp_path)

    result = gate.execute(prepared)

    assert type(result) is ExecutionResult
    assert result.status is ExecutionOutcome.COMPLETED
    assert result.external_result_confirmed is True
    assert len(spy.calls) == 1
    assert_consumed(store, reference_ids)
    assert decision.outcome is DecisionOutcome.ALLOW
    with pytest.raises(FrozenInstanceError):
        result.status = ExecutionOutcome.FAILED


@pytest.mark.parametrize("input_kind", ("canonical", "decision", "resolution", "arbitrary"))
def test_non_prepared_runtime_values_are_refused_before_evidence_or_adapter(
    tmp_path, input_kind
):
    prepared, decision, _, store, reference_ids, call, resolution = build_runtime()
    gate, spy, _ = gate_for(prepared, tmp_path)
    values = {
        "canonical": call,
        "decision": decision,
        "resolution": resolution,
        "arbitrary": object(),
    }

    result = gate.execute(values[input_kind])

    assert result.status is ExecutionOutcome.REFUSED
    assert result.rule_id is RuleId.EXECUTION_PREPARED_CALL_INVALID
    assert spy.calls == []
    assert evidence_files(tmp_path) == ()
    assert_unused(store, reference_ids)


def test_public_integrity_mismatch_is_rejected_before_any_action(tmp_path):
    prepared, _, _, store, reference_ids, *_ = build_runtime()
    gate, spy, _ = gate_for(prepared, tmp_path)
    object.__setattr__(prepared, "integrity_id", "sha256:" + "0" * 64)

    result = gate.execute(prepared)

    assert result.status is ExecutionOutcome.REFUSED
    assert spy.calls == []
    assert evidence_files(tmp_path) == ()
    assert_unused(store, reference_ids)


def test_missing_private_binding_is_rejected_before_any_action(tmp_path, monkeypatch):
    from tidemark.runtime import execution_gate as gate_module

    prepared, _, _, store, reference_ids, *_ = build_runtime()
    gate, spy, _ = gate_for(prepared, tmp_path)
    monkeypatch.setattr(
        gate_module, "_validate_runtime_execution_binding", lambda value: None
    )

    result = gate.execute(prepared)

    assert result.status is ExecutionOutcome.REFUSED
    assert spy.calls == []
    assert evidence_files(tmp_path) == ()
    assert_unused(store, reference_ids)


def test_private_correlation_mismatch_is_rejected_before_any_action(tmp_path):
    from tidemark.runtime.execution_binding import _lookup_runtime_execution_binding

    prepared, _, _, store, reference_ids, *_ = build_runtime()
    binding = _lookup_runtime_execution_binding(prepared.prepared_call_id)
    assert binding is not None
    object.__setattr__(binding, "decision_id", DecisionId("substituted-decision"))
    gate, spy, _ = gate_for(prepared, tmp_path)

    result = gate.execute(prepared)

    assert result.status is ExecutionOutcome.REFUSED
    assert spy.calls == []
    assert evidence_files(tmp_path) == ()
    assert_unused(store, reference_ids)


def test_private_binding_carries_exact_authority_and_is_not_caller_constructible():
    from tidemark.runtime.execution_binding import (
        _RuntimePrivateExecutionBinding,
        _lookup_runtime_execution_binding,
    )

    prepared, _, _, store, reference_ids, *_ = build_runtime()
    binding = _lookup_runtime_execution_binding(prepared.prepared_call_id)
    assert binding is not None

    assert binding.prepared_call_id == prepared.prepared_call_id
    assert binding.decision_id == prepared.decision_id
    assert binding.call_id == prepared.call_id
    assert binding.invocation_id == prepared.invocation_id
    assert binding.parent_id == PARENT_ID
    assert binding.tool_id == prepared.tool_id
    assert binding.policy_version == prepared.policy_version
    assert binding.registry_version == prepared.registry_version
    assert binding.adapter_id == prepared.adapter_id
    assert binding.adapter_version == prepared.adapter_version
    assert binding.public_integrity_id == prepared.integrity_id
    assert binding._reference_targets == reference_ids
    assert binding._store is store
    assert binding._store_authority is store._execution_authority
    assert binding._capability_state is PreparedCallState.UNUSED
    assert type(binding._payload_authenticator) is bytes

    with pytest.raises(TypeError):
        _RuntimePrivateExecutionBinding(
            prepared_call_id=prepared.prepared_call_id,
            decision_id=prepared.decision_id,
            call_id=prepared.call_id,
            invocation_id=prepared.invocation_id,
            parent_id=PARENT_ID,
            tool_id=prepared.tool_id,
            policy_version=prepared.policy_version,
            registry_version=prepared.registry_version,
            adapter_id=prepared.adapter_id,
            adapter_version=prepared.adapter_version,
            public_integrity_id=prepared.integrity_id,
            payload_authenticator=b"caller-authenticator",
            prepared_object_identity=id(prepared),
            reference_targets=reference_ids,
            store=store,
            store_authority=store._execution_authority,
        )


def test_private_authenticator_mismatch_is_rejected_before_any_action(tmp_path):
    from tidemark.runtime.execution_binding import _lookup_runtime_execution_binding

    prepared, _, _, store, reference_ids, *_ = build_runtime()
    binding = _lookup_runtime_execution_binding(prepared.prepared_call_id)
    assert binding is not None
    object.__setattr__(binding, "_payload_authenticator", b"invalid")
    gate, spy, _ = gate_for(prepared, tmp_path)

    result = gate.execute(prepared)

    assert result.status is ExecutionOutcome.REFUSED
    assert spy.calls == []
    assert evidence_files(tmp_path) == ()
    assert_unused(store, reference_ids)


def test_protected_payload_substitution_fails_private_integrity_before_action(
    tmp_path,
):
    prepared, _, _, store, reference_ids, *_ = build_runtime()
    protected = prepared.arguments[1]
    object.__setattr__(
        protected,
        "_RuntimePreparedValueCarrier__runtime_value",
        "caller-substituted-protected-payload",
    )
    gate, spy, _ = gate_for(prepared, tmp_path)

    result = gate.execute(prepared)

    assert result.status is ExecutionOutcome.REFUSED
    assert spy.calls == []
    assert evidence_files(tmp_path) == ()
    assert_unused(store, reference_ids)


@pytest.mark.parametrize(
    "registry_changes",
    (
        {"tool_id": ToolId("wrong.tool")},
        {"adapter_id": AdapterId("wrong.adapter")},
        {"adapter_version": AdapterVersion("wrong.adapter.v9")},
    ),
)
def test_wrong_trusted_adapter_binding_refuses_before_evidence_or_state(
    tmp_path, registry_changes
):
    prepared, _, _, store, reference_ids, *_ = build_runtime()
    gate, spy, _ = gate_for(prepared, tmp_path, **registry_changes)

    result = gate.execute(prepared)

    assert result.status is ExecutionOutcome.REFUSED
    assert spy.calls == []
    assert evidence_files(tmp_path) == ()
    assert_unused(store, reference_ids)


def test_pre_execution_append_failure_causes_zero_mutation_and_zero_adapter_calls(
    tmp_path, monkeypatch
):
    prepared, decision, _, store, reference_ids, *_ = build_runtime()
    gate, spy, sink = gate_for(prepared, tmp_path)
    monkeypatch.setattr(
        MinimalPreExecutionEvidenceSink,
        "append_pre_execution",
        lambda self, record: EvidenceAppendFailure(
            record_id=record.record_id,
            failure_code="evidence.append_failed.v1",
        ),
    )

    result = gate.execute(prepared)

    assert result.status is ExecutionOutcome.REFUSED
    assert spy.calls == []
    assert_unused(store, reference_ids)
    assert decision.outcome is DecisionOutcome.ALLOW
    assert prepared.execution_capability.state is PreparedCallState.UNUSED


@pytest.mark.parametrize("failure_point", ("flush", "synchronize"))
def test_pre_execution_durability_failure_causes_zero_state_or_adapter_action(
    tmp_path, monkeypatch, failure_point
):
    prepared, decision, _, store, reference_ids, *_ = build_runtime()
    gate, spy, _ = gate_for(prepared, tmp_path)

    def fail(self, target):
        raise OSError("injected durability failure")

    method = "_flush" if failure_point == "flush" else "_synchronize"
    monkeypatch.setattr(MinimalPreExecutionEvidenceSink, method, fail)

    result = gate.execute(prepared)

    assert result.status is ExecutionOutcome.REFUSED
    assert spy.calls == []
    assert_unused(store, reference_ids)
    assert decision.outcome is DecisionOutcome.ALLOW


def test_durable_append_precedes_atomic_mutation_and_adapter_entry(
    tmp_path, monkeypatch
):
    from tidemark.runtime.execution_binding import _lookup_runtime_execution_binding

    prepared, _, _, store, reference_ids, *_ = build_runtime()
    binding = _lookup_runtime_execution_binding(prepared.prepared_call_id)
    assert binding is not None
    observations = []
    original_append = MinimalPreExecutionEvidenceSink.append_pre_execution

    def ordered_append(self, record):
        observations.append(
            (
                "append",
                binding._capability_state,
                store.lookup(reference_ids[0]).consumed,
            )
        )
        return original_append(self, record)

    class OrderingAdapter:
        def __init__(self):
            self.calls = []

        def __call__(self, invocation):
            self.calls.append(invocation)
            observations.append(
                (
                    "adapter",
                    binding._capability_state,
                    store.lookup(reference_ids[0]).consumed,
                )
            )
            return AdapterInvocationResult.confirmed_success()

    adapter = OrderingAdapter()
    monkeypatch.setattr(
        MinimalPreExecutionEvidenceSink,
        "append_pre_execution",
        ordered_append,
    )
    gate, _, _ = gate_for(prepared, tmp_path, adapter=adapter)

    result = gate.execute(prepared)

    assert result.status is ExecutionOutcome.COMPLETED
    assert observations == [
        ("append", PreparedCallState.UNUSED, False),
        ("adapter", PreparedCallState.CONSUMED, True),
    ]


def test_atomic_transaction_consumes_one_capability_and_one_reference(tmp_path):
    prepared, _, _, store, reference_ids, *_ = build_runtime()
    gate, spy, _ = gate_for(prepared, tmp_path)

    result = gate.execute(prepared)

    assert result.status is ExecutionOutcome.COMPLETED
    assert len(spy.calls) == 1
    assert_consumed(store, reference_ids)


def test_atomic_transaction_consumes_multiple_references_together(tmp_path):
    names = ("destination_reference", "backup_reference")
    prepared, _, _, store, reference_ids, *_ = build_runtime(
        protected_names=names
    )
    gate, spy, _ = gate_for(prepared, tmp_path)

    result = gate.execute(prepared)

    assert result.status is ExecutionOutcome.COMPLETED
    assert len(spy.calls) == 1
    assert_consumed(store, reference_ids)


def test_invalid_second_target_leaves_all_references_and_capability_unused(tmp_path):
    from tidemark.runtime.execution_binding import _lookup_runtime_execution_binding

    names = ("destination_reference", "backup_reference")
    prepared, _, _, store, reference_ids, *_ = build_runtime(
        protected_names=names
    )
    store.deactivate(reference_ids[1])
    gate, spy, _ = gate_for(prepared, tmp_path)

    result = gate.execute(prepared)

    assert result.status is ExecutionOutcome.REFUSED
    assert spy.calls == []
    assert_unused(store, reference_ids)
    binding = _lookup_runtime_execution_binding(prepared.prepared_call_id)
    assert binding is not None
    assert binding._capability_state is PreparedCallState.UNUSED


def test_injected_transaction_mutation_failure_leaves_all_state_unchanged(
    tmp_path, monkeypatch
):
    from tidemark.runtime.execution_binding import _lookup_runtime_execution_binding

    names = ("destination_reference", "backup_reference")
    prepared, _, _, store, reference_ids, *_ = build_runtime(
        protected_names=names
    )
    gate, spy, _ = gate_for(prepared, tmp_path)

    def fail_commit(self, plan):
        raise RuntimeError("injected transaction mutation failure")

    monkeypatch.setattr(
        TrustedReferenceStore, "_commit_execution_consumption", fail_commit
    )

    result = gate.execute(prepared)

    assert result.status is ExecutionOutcome.REFUSED
    assert spy.calls == []
    assert_unused(store, reference_ids)
    binding = _lookup_runtime_execution_binding(prepared.prepared_call_id)
    assert binding is not None
    assert binding._capability_state is PreparedCallState.UNUSED


def test_duplicate_single_use_target_fails_preparation_closed():
    names = ("destination_reference", "backup_reference")
    prepared, decision, _, store, reference_ids, *_ = build_runtime(
        protected_names=names,
        reference_ids=lambda issued: (issued[0], issued[0]),
    )

    assert type(prepared) is PreparationRefusal
    assert decision.outcome is DecisionOutcome.ALLOW
    assert_unused(store, reference_ids)


def test_cross_store_private_target_substitution_is_refused_before_action(tmp_path):
    from tidemark.runtime.execution_binding import _lookup_runtime_execution_binding

    prepared, _, _, store, reference_ids, *_ = build_runtime()
    binding = _lookup_runtime_execution_binding(prepared.prepared_call_id)
    assert binding is not None
    object.__setattr__(binding, "_store", TrustedReferenceStore())
    gate, spy, _ = gate_for(prepared, tmp_path)

    result = gate.execute(prepared)

    assert result.status is ExecutionOutcome.REFUSED
    assert spy.calls == []
    assert evidence_files(tmp_path) == ()
    assert_unused(store, reference_ids)


def test_replay_is_rejected_and_adapter_count_remains_exactly_one(tmp_path):
    prepared, _, _, store, reference_ids, *_ = build_runtime()
    gate, spy, _ = gate_for(prepared, tmp_path)

    first = gate.execute(prepared)
    second = gate.execute(prepared)

    assert first.status is ExecutionOutcome.COMPLETED
    assert second.status is ExecutionOutcome.REPLAY_REJECTED
    assert second.rule_id is RuleId.EXECUTION_REPLAY_REJECTED
    assert len(spy.calls) == 1
    assert_consumed(store, reference_ids)


def test_concurrent_attempts_have_one_winner_and_all_losers_replay_rejected(
    tmp_path,
):
    prepared, _, _, store, reference_ids, *_ = build_runtime()
    gate, spy, _ = gate_for(prepared, tmp_path)

    with ThreadPoolExecutor(max_workers=12) as executor:
        results = tuple(executor.map(gate.execute, (prepared,) * 24))

    assert sum(result.status is ExecutionOutcome.COMPLETED for result in results) == 1
    assert sum(
        result.status is ExecutionOutcome.REPLAY_REJECTED for result in results
    ) == 23
    assert len(spy.calls) == 1
    assert_consumed(store, reference_ids)


def test_adapter_exception_fails_without_retry_and_retains_consumed_state(tmp_path):
    prepared, decision, _, store, reference_ids, *_ = build_runtime()
    spy = AdapterSpy(error=RuntimeError("adapter failed"))
    gate, _, _ = gate_for(prepared, tmp_path, adapter=spy)

    result = gate.execute(prepared)

    assert result.status is ExecutionOutcome.FAILED
    assert len(spy.calls) == 1


def test_confirmed_adapter_failure_is_failed_consumed_and_not_retried(tmp_path):
    prepared, decision, _, store, reference_ids, *_ = build_runtime()
    spy = AdapterSpy(result=AdapterInvocationResult.confirmed_failure())
    gate, _, _ = gate_for(prepared, tmp_path, adapter=spy)

    result = gate.execute(prepared)

    assert result.status is ExecutionOutcome.FAILED
    assert result.external_result_confirmed is True
    assert result.failure_fact == "adapter-confirmed-failure"
    assert decision.outcome is DecisionOutcome.ALLOW
    assert_consumed(store, reference_ids)
    assert gate.execute(prepared).status is ExecutionOutcome.REPLAY_REJECTED
    assert len(spy.calls) == 1
    assert_consumed(store, reference_ids)
    assert decision.outcome is DecisionOutcome.ALLOW
    assert gate.execute(prepared).status is ExecutionOutcome.REPLAY_REJECTED
    assert len(spy.calls) == 1


def test_ambiguous_result_is_unconfirmed_failed_consumed_and_not_retried(tmp_path):
    prepared, _, _, store, reference_ids, *_ = build_runtime()
    spy = AdapterSpy(result=AdapterInvocationResult.unconfirmed_failure())
    gate, _, _ = gate_for(prepared, tmp_path, adapter=spy)

    result = gate.execute(prepared)

    assert result.status is ExecutionOutcome.FAILED
    assert result.external_result_confirmed is False
    assert result.failure_fact == "unconfirmed-external-result"
    assert_consumed(store, reference_ids)
    assert gate.execute(prepared).status is ExecutionOutcome.REPLAY_REJECTED
    assert len(spy.calls) == 1


def test_outcome_evidence_failure_returns_failed_without_retry_or_restore(
    tmp_path, monkeypatch
):
    prepared, _, _, store, reference_ids, *_ = build_runtime()
    gate, spy, sink = gate_for(prepared, tmp_path)
    monkeypatch.setattr(
        MinimalPreExecutionEvidenceSink,
        "append_execution_outcome",
        lambda self, record: EvidenceAppendFailure(
            record_id=record.record_id,
            failure_code="evidence.append_failed.v1",
        ),
    )

    result = gate.execute(prepared)

    assert result.status is ExecutionOutcome.FAILED
    assert result.failure_fact == "outcome-evidence-append-failed"
    assert len(spy.calls) == 1
    assert_consumed(store, reference_ids)
    assert gate.execute(prepared).status is ExecutionOutcome.REPLAY_REJECTED
    assert len(spy.calls) == 1


def test_adapter_receives_exact_detached_payload_and_no_runtime_authority(tmp_path):
    protected = {"account": [PROTECTED_MARKER]}
    prepared, _, snapshot, store, reference_ids, raw_call, *_ = build_runtime(
        protected_values=(protected,)
    )
    before = prepared.arguments[1]._copy_value_for_runtime()
    spy = AdapterSpy()
    gate, _, sink = gate_for(prepared, tmp_path, adapter=spy)

    result = gate.execute(prepared)

    assert result.status is ExecutionOutcome.COMPLETED
    assert len(spy.calls) == 1
    invocation = spy.calls[0]
    assert type(invocation) is AdapterInvocation
    assert invocation.tool_id == prepared.tool_id
    assert invocation.arguments[0].value == 50
    assert PROTECTED_MARKER in repr(invocation.arguments[1].value)
    assert {field.name for field in fields(invocation)} == {
        "tool_id",
        "execution_id",
        "prepared_call_id",
        "call_id",
        "decision_id",
        "invocation_id",
        "arguments",
    }
    forbidden_types = (
        ReferenceId,
        TrustedReferenceStore,
        ReferenceResolver,
        PolicyEngine,
        MinimalPreExecutionEvidenceSink,
        type(snapshot),
        type(raw_call),
    )
    assert not any(
        isinstance(value, forbidden_types)
        for value in vars(invocation).values()
    )
    with pytest.raises(FrozenInstanceError):
        invocation.arguments[0].value = 99
    assert prepared.arguments[1]._copy_value_for_runtime() == before
    assert_consumed(store, reference_ids)
    assert sink not in vars(invocation).values()


def test_public_and_evidence_hygiene_omit_private_and_protected_material(tmp_path):
    from tidemark.runtime.execution_binding import _lookup_runtime_execution_binding

    prepared, _, _, _, reference_ids, *_ = build_runtime(
        protected_values=({"account": [PROTECTED_MARKER]},)
    )
    binding = _lookup_runtime_execution_binding(prepared.prepared_call_id)
    assert binding is not None
    gate, _, _ = gate_for(prepared, tmp_path)
    result = gate.execute(prepared)
    evidence = "".join(path.read_text(encoding="utf-8") for path in evidence_files(tmp_path))
    public = repr(prepared) + repr(asdict(prepared)) + repr(result) + evidence

    assert PROTECTED_MARKER not in public
    assert all(reference_id.value not in public for reference_id in reference_ids)
    assert "payload_authenticator" not in public
    assert "integrity_secret" not in public
    assert "RuntimePrivateExecutionBinding" not in public
    assert PROTECTED_MARKER not in repr(binding)
    assert not hasattr(binding, "__dict__")
    assert not hasattr(prepared, "runtime_private_binding")


def test_execution_gate_scope_contains_no_order_9_or_later_integration(tmp_path):
    from tidemark.runtime import execution_gate, minimal_evidence

    prepared, *_ = build_runtime()
    gate, _, _ = gate_for(prepared, tmp_path)
    forbidden = {
        "schedule_payment",
        "Invoice",
        "PurchaseOrder",
        "PaymentRecord",
        "EvidenceRecorder",
        "EvidenceProjector",
        "GoogleCloud",
        "Gemini",
        "ADK",
        "Database",
    }

    assert forbidden.isdisjoint(vars(execution_gate))
    assert forbidden.isdisjoint(vars(minimal_evidence))
    assert {"register", "replace", "retry"}.isdisjoint(dir(gate))
    assert not any(
        name.startswith(("payment", "adk", "gemini", "google", "cloud", "ui"))
        for name, _ in inspect.getmembers(execution_gate)
    )
