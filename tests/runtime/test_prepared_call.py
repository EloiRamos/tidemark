from dataclasses import FrozenInstanceError, asdict, fields, replace
from datetime import datetime, timezone
import builtins
import inspect
import socket

import pytest

from tidemark.runtime.identifiers import (
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
from tidemark.runtime.policy_authoring import (
    ValidatedPolicyAuthoring,
    validate_policy_authoring,
)
from tidemark.runtime.policy_engine import (
    CallContext,
    CanonicalArgument,
    CanonicalCall,
    CanonicalSignatureArgument,
    PolicyEngine,
    Resolved,
    _resolved_with_runtime_protected_value,
)
from tidemark.runtime.policy_snapshot import (
    InstalledSnapshot,
    PolicyInstaller,
    PolicySnapshot,
)
from tidemark.runtime.prepared_call import (
    PreparationRefusal,
    PreparedArgument,
    PreparedCallPipeline,
    PreparedMappingValue,
    PreparedToolCall,
)
from tidemark.runtime.reference_resolver import ReferenceResolver
from tidemark.runtime.reference_store import (
    ReferenceBinding,
    ReferenceLifecycle,
    ReferenceMetadata,
    TrustedRecord,
    TrustedReferenceStore,
)
from tidemark.runtime.vocabulary import (
    DecisionOutcome,
    PreparedCallState,
    RuleId,
)


EVALUATION_TIME = datetime(2026, 8, 7, 14, 0, tzinfo=timezone.utc)
INVOCATION_ID = InvocationId("invocation-order-7")
PARENT_ID = ParentId("parent-order-7")
PROTECTED_MARKER = "runtime-resolved-destination-order-7"


def valid_authoring():
    return {
        "policy_version": "policy-order-7-v1",
        "registry_version": "registry-order-7-v1",
        "executable_tools": ("dispatch.submit",),
        "tool_registrations": (
            {
                "tool_id": "dispatch.submit",
                "contract_version": "dispatch.submit.contract.v1",
                "policy_version": "policy-order-7-v1",
                "signature": (
                    {
                        "name": "quantity",
                        "required": True,
                        "type_id": "integer",
                    },
                    {
                        "name": "mode",
                        "required": True,
                        "type_id": "mode",
                    },
                    {
                        "name": "destination_reference",
                        "required": True,
                        "type_id": "destination_reference",
                    },
                ),
                "arguments": (
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
                    {
                        "name": "mode",
                        "position": 1,
                        "type_id": "mode",
                        "required": True,
                        "role": "UNPROTECTED_INPUT",
                        "constraint_bindings": (
                            {
                                "constraint_id": "value.enum.member.v1",
                                "parameters": {"members": ("FAST", "SAFE")},
                            },
                        ),
                    },
                    {
                        "name": "destination_reference",
                        "position": 2,
                        "type_id": "destination_reference",
                        "required": True,
                        "role": "PROTECTED_REFERENCE",
                        "constraint_bindings": (
                            {
                                "constraint_id": (
                                    "protected.reference.required.v1"
                                ),
                                "parameters": {},
                            },
                            {
                                "constraint_id": "reference.kind.equals.v1",
                                "parameters": {"kind": "destination"},
                            },
                            {
                                "constraint_id": (
                                    "reference.invocation.equals.v1"
                                ),
                                "parameters": {},
                            },
                            {
                                "constraint_id": "reference.parent.equals.v1",
                                "parameters": {},
                            },
                            {
                                "constraint_id": "reference.active.v1",
                                "parameters": {},
                            },
                            {
                                "constraint_id": "reference.single_use.v1",
                                "parameters": {},
                            },
                        ),
                    },
                ),
                "role_metadata": (
                    {
                        "name": "quantity",
                        "role": "UNPROTECTED_INPUT",
                        "required_provenance": "UNTRUSTED",
                    },
                    {
                        "name": "mode",
                        "role": "UNPROTECTED_INPUT",
                        "required_provenance": "UNTRUSTED",
                    },
                    {
                        "name": "destination_reference",
                        "role": "PROTECTED_REFERENCE",
                        "required_provenance": "RUNTIME_TRUSTED",
                    },
                ),
                "effect_class": "SIDE_EFFECTING",
                "reversibility": "IRREVERSIBLE",
                "adapter_id": "dispatch.local.adapter",
                "adapter_version": "dispatch.local.adapter.v1",
                "masking_profile_id": "dispatch.masking.v1",
            },
        ),
    }


def installed_snapshot():
    validated = validate_policy_authoring(valid_authoring())
    assert type(validated) is ValidatedPolicyAuthoring
    installed = PolicyInstaller().install(validated)
    assert type(installed) is InstalledSnapshot
    return installed.snapshot


def issue_reference(store, protected_value=PROTECTED_MARKER):
    return store.issuer.issue(
        TrustedRecord(protected_value=protected_value, kind="destination"),
        ReferenceBinding(
            invocation_id=INVOCATION_ID,
            parent_id=PARENT_ID,
        ),
        ReferenceLifecycle(active=True, single_use=True),
    )


def pipeline_inputs(*, protected_value=PROTECTED_MARKER, quantity=50, mode="FAST"):
    snapshot = installed_snapshot()
    store = TrustedReferenceStore()
    reference_id = issue_reference(store, protected_value)
    signature = tuple(
        CanonicalSignatureArgument(
            name=item.name,
            required=item.required,
            type_id=TypeId(item.type_id.value),
        )
        for item in snapshot.tool_policies[0].signature
    )
    call = CanonicalCall(
        tool_id=ToolId("dispatch.submit"),
        contract_version=ToolContractVersion(
            "dispatch.submit.contract.v1"
        ),
        signature=signature,
        arguments=(
            CanonicalArgument("quantity", quantity),
            CanonicalArgument("mode", mode),
            CanonicalArgument("destination_reference", reference_id),
        ),
    )
    context = CallContext(
        call_id=CallId("call-order-7"),
        decision_id=DecisionId("decision-order-7"),
        invocation_id=INVOCATION_ID,
        parent_id=PARENT_ID,
        policy_version=PolicyVersion(snapshot.policy_version.value),
        registry_version=RegistryVersion(snapshot.registry_version.value),
    )
    return snapshot, store, reference_id, call, context


def prepare(*, protected_value=PROTECTED_MARKER, quantity=50, mode="FAST"):
    snapshot, store, reference_id, call, context = pipeline_inputs(
        protected_value=protected_value,
        quantity=quantity,
        mode=mode,
    )
    result = PreparedCallPipeline().prepare(
        snapshot=snapshot,
        canonical_call=call,
        call_context=context,
        trusted_store=store,
        evaluation_time=EVALUATION_TIME,
    )
    return result, snapshot, store, reference_id, call, context


def argument_value(prepared_call, name):
    return next(
        argument._copy_value_for_runtime()
        for argument in prepared_call.arguments
        if argument.name == name
    )


def test_allow_creates_one_prepared_tool_call(monkeypatch):
    from tidemark.runtime import prepared_call as prepared_call_module

    token_calls = []

    def fixed_token(byte_count):
        token_calls.append(byte_count)
        return "1" * (byte_count * 2)

    monkeypatch.setattr(prepared_call_module, "token_hex", fixed_token)

    result, *_ = prepare()

    assert type(result) is PreparedToolCall
    assert token_calls == [32]


def test_deny_returns_refusal_and_mints_no_prepared_call(monkeypatch):
    from tidemark.runtime import prepared_call as prepared_call_module

    token_calls = []
    monkeypatch.setattr(
        prepared_call_module,
        "token_hex",
        lambda byte_count: token_calls.append(byte_count),
    )

    result, *_ = prepare(quantity=101)

    assert type(result) is PreparationRefusal
    assert result.decision.outcome is DecisionOutcome.DENY
    assert result.decision.primary_rule_id is RuleId.VALUE_CONSTRAINT_FAILED
    assert token_calls == []
    assert not hasattr(result, "prepared_call")


def test_engine_refusal_returns_preparation_refusal_and_no_prepared_call(
    monkeypatch,
):
    from tidemark.runtime import prepared_call as prepared_call_module

    snapshot, store, _, call, context = pipeline_inputs()
    unknown_call = replace(call, tool_id=ToolId("unknown.tool"))
    token_calls = []
    monkeypatch.setattr(
        prepared_call_module,
        "token_hex",
        lambda byte_count: token_calls.append(byte_count),
    )

    result = PreparedCallPipeline().prepare(
        snapshot=snapshot,
        canonical_call=unknown_call,
        call_context=context,
        trusted_store=store,
        evaluation_time=EVALUATION_TIME,
    )

    assert type(result) is PreparationRefusal
    assert result.decision.outcome is DecisionOutcome.REFUSAL
    assert result.decision.primary_rule_id is RuleId.CONTRACT_TOOL_UNKNOWN
    assert token_calls == []


def test_prepared_tool_call_and_nested_arguments_are_immutable():
    result, *_ = prepare(protected_value={"account": [PROTECTED_MARKER]})
    assert type(result) is PreparedToolCall
    protected = argument_value(result, "destination_reference")
    assert type(protected) is PreparedMappingValue

    with pytest.raises(FrozenInstanceError):
        result.decision_id = DecisionId("replacement")
    with pytest.raises(FrozenInstanceError):
        result.arguments[0].value = 99
    with pytest.raises(TypeError):
        protected.entries[0] = protected.entries[0]


def test_prepared_arguments_are_detached_from_caller_and_store_objects():
    source = {"account": [PROTECTED_MARKER]}
    result, _, store, reference_id, *_ = prepare(protected_value=source)
    assert type(result) is PreparedToolCall
    before = repr(argument_value(result, "destination_reference"))
    runtime_record = store._lookup_for_runtime(reference_id)
    assert runtime_record is not None

    source["account"][0] = "caller-mutated"
    runtime_record.protected_value["account"][0] = "store-copy-mutated"

    assert repr(argument_value(result, "destination_reference")) == before
    assert PROTECTED_MARKER in before


def test_protected_argument_uses_only_the_runtime_resolved_value():
    result, _, _, reference_id, *_ = prepare()
    assert type(result) is PreparedToolCall

    assert argument_value(result, "destination_reference") == PROTECTED_MARKER
    assert reference_id.value not in repr(result.arguments)


def test_unprotected_arguments_preserve_only_canonical_validated_values():
    result, *_ = prepare(quantity=100, mode="SAFE")
    assert type(result) is PreparedToolCall

    assert tuple(
        (
            argument.name,
            argument._copy_value_for_runtime(),
        )
        for argument in result.arguments[:2]
    ) == (("quantity", 100), ("mode", "SAFE"))


def test_raw_protected_value_is_rejected_and_never_survives_preparation():
    snapshot, store, _, call, context = pipeline_inputs()
    raw_value = "caller-supplied-protected-value-order-7"
    raw_call = replace(
        call,
        arguments=call.arguments[:2]
        + (CanonicalArgument("destination_reference", raw_value),),
    )

    result = PreparedCallPipeline().prepare(
        snapshot=snapshot,
        canonical_call=raw_call,
        call_context=context,
        trusted_store=store,
        evaluation_time=EVALUATION_TIME,
    )

    assert type(result) is PreparationRefusal
    assert result.decision.outcome is DecisionOutcome.DENY
    assert result.decision.primary_rule_id is (
        RuleId.PROTECTED_RAW_VALUE_SUPPLIED
    )
    assert raw_value not in repr(result)


def test_captured_versions_decision_and_adapter_identity_are_exact():
    result, snapshot, _, _, _, context = prepare()
    assert type(result) is PreparedToolCall

    assert result.call_id == context.call_id
    assert result.decision_id == context.decision_id
    assert result.invocation_id == context.invocation_id
    assert result.tool_id == ToolId("dispatch.submit")
    assert result.policy_version == snapshot.policy_version
    assert result.registry_version == snapshot.registry_version
    assert result.adapter_id.value == "dispatch.local.adapter"
    assert result.adapter_version.value == "dispatch.local.adapter.v1"


def test_prepared_call_ids_are_unique_across_successful_preparations():
    first, *_ = prepare()
    second, *_ = prepare()

    assert type(first) is PreparedToolCall
    assert type(second) is PreparedToolCall
    assert first.prepared_call_id != second.prepared_call_id


def test_integrity_identifier_is_stable_for_equal_sealed_content(monkeypatch):
    from tidemark.runtime import prepared_call as prepared_call_module

    monkeypatch.setattr(
        prepared_call_module, "token_hex", lambda byte_count: "a" * 64
    )

    first, *_ = prepare()
    second, *_ = prepare()

    assert type(first) is PreparedToolCall
    assert type(second) is PreparedToolCall
    assert first == second
    assert first.integrity_id == second.integrity_id
    assert first.integrity_id.startswith("sha256:")
    assert len(first.integrity_id) == 71


def test_public_integrity_preimage_excludes_protected_payload_and_reference(
    monkeypatch,
):
    from tidemark.runtime import prepared_call as prepared_call_module

    original_sha256 = prepared_call_module.sha256
    preimages = []

    def recording_sha256(value):
        preimages.append(value)
        return original_sha256(value)

    monkeypatch.setattr(prepared_call_module, "sha256", recording_sha256)
    result, _, _, reference_id, *_ = prepare(
        protected_value={"account": [PROTECTED_MARKER]}
    )

    assert type(result) is PreparedToolCall
    assert len(preimages) == 1
    assert PROTECTED_MARKER.encode("utf-8") not in preimages[0]
    assert reference_id.value.encode("utf-8") not in preimages[0]


def test_protected_marker_is_absent_from_all_public_prepared_call_views():
    result, *_ = prepare(
        protected_value={"account": [PROTECTED_MARKER]}
    )
    assert type(result) is PreparedToolCall
    protected_argument = result.arguments[2]

    public_views = (
        repr(result),
        repr(vars(result)),
        repr(asdict(result)),
        repr(result.arguments),
        repr(protected_argument),
        repr(vars(protected_argument)),
        repr(asdict(protected_argument)),
        result.integrity_id,
    )

    assert all(PROTECTED_MARKER not in view for view in public_views)
    assert all("account" not in view for view in public_views)


def test_protected_payload_difference_has_no_public_integrity_fingerprint(
    monkeypatch,
):
    from tidemark.runtime import prepared_call as prepared_call_module

    monkeypatch.setattr(
        prepared_call_module, "token_hex", lambda byte_count: "b" * 64
    )

    first, *_ = prepare(protected_value="protected-domain-value-one")
    second, *_ = prepare(protected_value="protected-domain-value-two")

    assert type(first) is PreparedToolCall
    assert type(second) is PreparedToolCall
    assert first.integrity_id == second.integrity_id
    assert repr(first) == repr(second)
    assert asdict(first) == asdict(second)


def test_public_integrity_changes_when_non_sensitive_call_metadata_changes(
    monkeypatch,
):
    from tidemark.runtime import prepared_call as prepared_call_module

    monkeypatch.setattr(
        prepared_call_module, "token_hex", lambda byte_count: "c" * 64
    )
    snapshot, store, _, call, context = pipeline_inputs()
    pipeline = PreparedCallPipeline()
    first = pipeline.prepare(
        snapshot=snapshot,
        canonical_call=call,
        call_context=context,
        trusted_store=store,
        evaluation_time=EVALUATION_TIME,
    )
    second = pipeline.prepare(
        snapshot=snapshot,
        canonical_call=call,
        call_context=replace(
            context, call_id=CallId("call-order-7-metadata-change")
        ),
        trusted_store=store,
        evaluation_time=EVALUATION_TIME,
    )

    assert type(first) is PreparedToolCall
    assert type(second) is PreparedToolCall
    assert first.integrity_id != second.integrity_id


def test_caller_source_mutation_after_preparation_changes_nothing():
    source = {"account": [PROTECTED_MARKER]}
    result, *_ = prepare(protected_value=source)
    assert type(result) is PreparedToolCall
    identity = result.integrity_id
    arguments = argument_value(result, "destination_reference")

    source["account"].append("caller-added")
    source["new"] = "caller-added"

    assert result.integrity_id == identity
    assert argument_value(result, "destination_reference") == arguments
    assert "caller-added" not in repr(
        argument_value(result, "destination_reference")
    )


def test_mutating_resolver_output_after_preparation_changes_nothing(monkeypatch):
    resolved = _resolved_with_runtime_protected_value(
        protected_value={"account": [PROTECTED_MARKER]},
        kind="destination",
        invocation_id=INVOCATION_ID,
        parent_id=PARENT_ID,
        active=True,
        consumed=False,
    )

    def fixed_resolution(self, request, trusted_store):
        return resolved

    monkeypatch.setattr(ReferenceResolver, "resolve", fixed_resolution)
    result, *_ = prepare()
    assert type(result) is PreparedToolCall
    before = repr(argument_value(result, "destination_reference"))
    resolver_payload = getattr(
        resolved,
        "_RuntimeProtectedValueCarrier__protected_value",
    )

    resolver_payload["account"][0] = "resolver-mutated"

    assert repr(argument_value(result, "destination_reference")) == before
    assert result.integrity_id == result.integrity_id


def test_prepared_call_contains_only_the_allowed_execution_payload_fields():
    result, *_ = prepare()
    assert type(result) is PreparedToolCall

    assert {field.name for field in fields(result)} == {
        "prepared_call_id",
        "call_id",
        "decision_id",
        "invocation_id",
        "tool_id",
        "policy_version",
        "registry_version",
        "arguments",
        "adapter_id",
        "adapter_version",
        "execution_capability",
        "integrity_id",
    }


@pytest.mark.parametrize(
    "forbidden_type",
    (TrustedReferenceStore, PolicySnapshot, ReferenceResolver, PolicyEngine),
)
def test_prepared_call_retains_no_runtime_authority_object(forbidden_type):
    result, *_ = prepare()
    assert type(result) is PreparedToolCall

    assert not any(
        isinstance(value, forbidden_type) for value in vars(result).values()
    )
    assert forbidden_type.__name__ not in repr(result)


def test_decision_correlation_cannot_be_replaced_after_preparation():
    result, *_ = prepare()
    assert type(result) is PreparedToolCall

    with pytest.raises(FrozenInstanceError):
        result.decision_id = DecisionId("replacement-decision")
    with pytest.raises(TypeError):
        replace(result, decision_id=DecisionId("replacement-decision"))


def test_prepared_call_has_only_inert_single_use_capability_metadata():
    result, *_ = prepare()
    assert type(result) is PreparedToolCall

    assert result.execution_capability.state is PreparedCallState.UNUSED
    with pytest.raises(FrozenInstanceError):
        result.execution_capability.state = PreparedCallState.CONSUMED
    assert not hasattr(result.execution_capability, "consume")
    assert not hasattr(result.execution_capability, "execute")


def test_prepared_call_contains_no_executable_behavior():
    result, *_ = prepare()
    assert type(result) is PreparedToolCall

    assert not hasattr(result, "execute")
    assert not hasattr(result, "invoke")
    assert not hasattr(result, "consume")
    assert not any(
        callable(value)
        for field in fields(result)
        for value in (getattr(result, field.name),)
    )


def test_pipeline_invokes_exactly_one_resolver_and_one_policy_evaluation(
    monkeypatch,
):
    resolver_calls = []
    engine_calls = []
    original_resolve = ReferenceResolver.resolve
    original_evaluate = PolicyEngine.evaluate

    def counted_resolve(self, request, trusted_store):
        resolver_calls.append(request.argument_name)
        return original_resolve(self, request, trusted_store)

    def counted_evaluate(
        self, snapshot, canonical_call, resolution_set, call_context
    ):
        engine_calls.append(call_context.decision_id)
        return original_evaluate(
            self,
            snapshot,
            canonical_call,
            resolution_set,
            call_context,
        )

    monkeypatch.setattr(ReferenceResolver, "resolve", counted_resolve)
    monkeypatch.setattr(PolicyEngine, "evaluate", counted_evaluate)

    result, *_ = prepare()

    assert type(result) is PreparedToolCall
    assert resolver_calls == ["destination_reference"]
    assert engine_calls == [DecisionId("decision-order-7")]


def test_preparation_performs_no_execution_consumption_or_persistence(
    monkeypatch,
):
    snapshot, store, reference_id, call, context = pipeline_inputs()
    before = store.lookup(reference_id)
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("preparation crossed its read-only boundary")

    monkeypatch.setattr(TrustedReferenceStore, "consume", forbidden)
    monkeypatch.setattr(TrustedReferenceStore, "deactivate", forbidden)
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)

    result = PreparedCallPipeline().prepare(
        snapshot=snapshot,
        canonical_call=call,
        call_context=context,
        trusted_store=store,
        evaluation_time=EVALUATION_TIME,
    )

    assert type(result) is PreparedToolCall
    assert calls == []
    after = store.lookup(reference_id)
    assert type(after) is ReferenceMetadata
    assert after == before
    assert (after.active, after.consumed) == (True, False)


def test_unsupported_resolved_payload_fails_closed_without_minting(
    monkeypatch,
):
    from tidemark.runtime import prepared_call as prepared_call_module

    resolved = _resolved_with_runtime_protected_value(
        protected_value=object(),
        kind="destination",
        invocation_id=INVOCATION_ID,
        parent_id=PARENT_ID,
        active=True,
        consumed=False,
    )
    token_calls = []
    monkeypatch.setattr(
        ReferenceResolver,
        "resolve",
        lambda self, request, trusted_store: resolved,
    )
    monkeypatch.setattr(
        prepared_call_module,
        "token_hex",
        lambda byte_count: token_calls.append(byte_count),
    )

    result, *_ = prepare()

    assert type(result) is PreparationRefusal
    assert result.decision.outcome is DecisionOutcome.ALLOW
    assert result.masked_detail == "prepared payload construction refused"
    assert token_calls == []


def test_preparation_refusal_is_immutable_and_contains_no_prepared_call():
    result, *_ = prepare(quantity=101)
    assert type(result) is PreparationRefusal

    with pytest.raises(FrozenInstanceError):
        result.masked_detail = "changed"
    assert not hasattr(result, "prepared_call")
    assert "PreparedToolCall" not in repr(result)


def test_pipeline_module_has_no_framework_model_cloud_ui_or_persistence_surface():
    from tidemark.runtime import prepared_call as prepared_call_module

    forbidden_names = {
        "ExecutionGate",
        "EvidenceRecorder",
        "EvidenceSink",
        "Database",
        "FileStore",
    }
    forbidden_methods = {
        "execute",
        "invoke",
        "consume",
        "deactivate",
        "persist",
        "append",
    }

    assert forbidden_names.isdisjoint(vars(prepared_call_module))
    assert forbidden_methods.isdisjoint(dir(PreparedCallPipeline()))
    assert not any(
        name.startswith(
            (
                "adk",
                "gemini",
                "google",
                "cloud",
                "payment",
                "database",
                "firestore",
                "ui",
            )
        )
        for name, _ in inspect.getmembers(prepared_call_module)
    )


def test_order_7_surface_does_not_export_execution_or_evidence_behavior():
    from tidemark.runtime import prepared_call as prepared_call_module

    assert {
        "PreparationRefusal",
        "PreparedArgument",
        "PreparedCallPipeline",
        "PreparedToolCall",
    }.issubset(set(prepared_call_module.__all__))
    assert "ExecutionGate" not in prepared_call_module.__all__
    assert "EvidenceRecorder" not in prepared_call_module.__all__
