from dataclasses import asdict
from datetime import datetime, timedelta, timezone
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
    ResolutionEntry,
    ResolutionFailure,
    ResolutionSet,
    Resolved,
)
from tidemark.runtime.policy_snapshot import InstalledSnapshot, PolicyInstaller
from tidemark.runtime.reference_resolver import (
    ReferenceResolver,
    ResolutionRequest,
)
from tidemark.runtime.reference_store import (
    ReferenceBinding,
    ReferenceConsumptionOutcome,
    ReferenceDeactivationOutcome,
    ReferenceLifecycle,
    ReferenceMetadata,
    TrustedRecord,
    TrustedReferenceStore,
)
from tidemark.runtime.vocabulary import DecisionOutcome, RuleId


PROTECTED_MARKER = "protected-runtime-value-never-publish-order-6"
EXPECTED_KIND = "destination"
EXPECTED_INVOCATION = InvocationId("invocation-order-6")
EXPECTED_PARENT = ParentId("parent-order-6")
ARGUMENT_NAME = "destination_reference"
EVALUATION_TIME = datetime(2026, 8, 7, 12, 0, tzinfo=timezone.utc)


def issue_reference(
    store,
    *,
    protected_value=PROTECTED_MARKER,
    kind=EXPECTED_KIND,
    invocation_id=EXPECTED_INVOCATION,
    parent_id=EXPECTED_PARENT,
    active=True,
    single_use=True,
):
    return store.issuer.issue(
        TrustedRecord(protected_value=protected_value, kind=kind),
        ReferenceBinding(
            invocation_id=invocation_id,
            parent_id=parent_id,
        ),
        ReferenceLifecycle(active=active, single_use=single_use),
    )


def request(reference_id, **changes):
    fields = {
        "reference_id": reference_id,
        "expected_kind": EXPECTED_KIND,
        "invocation_id": EXPECTED_INVOCATION,
        "parent_id": EXPECTED_PARENT,
        "argument_name": ARGUMENT_NAME,
        "evaluation_time": EVALUATION_TIME,
    }
    fields.update(changes)
    return ResolutionRequest(**fields)


def resolve(store, reference_id, **changes):
    return ReferenceResolver().resolve(
        request(reference_id, **changes), store
    )


def test_valid_reference_resolves_to_detached_trusted_facts():
    store = TrustedReferenceStore()
    reference_id = issue_reference(store)
    metadata = store.lookup(reference_id)
    assert type(metadata) is ReferenceMetadata

    result = resolve(store, reference_id)

    assert type(result) is Resolved
    assert result.kind == metadata.kind
    assert result.invocation_id == metadata.invocation_id
    assert result.parent_id == metadata.parent_id
    assert result.active is metadata.active
    assert result.consumed is metadata.consumed
    assert result.invocation_id is not metadata.invocation_id
    assert result.parent_id is not metadata.parent_id
    assert set(asdict(result)) == {
        "kind",
        "invocation_id",
        "parent_id",
        "active",
        "consumed",
    }


def test_unknown_reference_maps_to_exact_not_found_rule():
    result = resolve(
        TrustedReferenceStore(), ReferenceId("ref_missing_order_6")
    )

    assert result == ResolutionFailure(RuleId.REFERENCE_NOT_FOUND)


def test_wrong_kind_maps_to_exact_kind_mismatch_rule():
    store = TrustedReferenceStore()
    reference_id = issue_reference(store, kind="wrong-kind")

    result = resolve(store, reference_id)

    assert result == ResolutionFailure(RuleId.REFERENCE_KIND_MISMATCH)


def test_wrong_invocation_maps_to_exact_invocation_mismatch_rule():
    store = TrustedReferenceStore()
    reference_id = issue_reference(
        store, invocation_id=InvocationId("wrong-invocation")
    )

    result = resolve(store, reference_id)

    assert result == ResolutionFailure(
        RuleId.REFERENCE_INVOCATION_MISMATCH
    )


def test_wrong_parent_maps_to_exact_parent_mismatch_rule():
    store = TrustedReferenceStore()
    reference_id = issue_reference(store, parent_id=ParentId("wrong-parent"))

    result = resolve(store, reference_id)

    assert result == ResolutionFailure(RuleId.REFERENCE_PARENT_MISMATCH)


def test_inactive_reference_maps_to_exact_inactive_rule():
    store = TrustedReferenceStore()
    reference_id = issue_reference(store, active=False)

    result = resolve(store, reference_id)

    assert result == ResolutionFailure(RuleId.REFERENCE_INACTIVE)


def test_active_consumed_reference_maps_to_exact_already_consumed_rule():
    store = TrustedReferenceStore()
    reference_id = issue_reference(store)
    assert store.consume(reference_id) is ReferenceConsumptionOutcome.CONSUMED

    result = resolve(store, reference_id)

    assert result == ResolutionFailure(RuleId.REFERENCE_ALREADY_CONSUMED)


@pytest.mark.parametrize(
    ("record_changes", "consume", "deactivate", "expected_rule"),
    (
        (
            {
                "kind": "wrong-kind",
                "invocation_id": InvocationId("wrong-invocation"),
                "parent_id": ParentId("wrong-parent"),
            },
            True,
            True,
            RuleId.REFERENCE_KIND_MISMATCH,
        ),
        (
            {
                "invocation_id": InvocationId("wrong-invocation"),
                "parent_id": ParentId("wrong-parent"),
            },
            True,
            True,
            RuleId.REFERENCE_INVOCATION_MISMATCH,
        ),
        (
            {"parent_id": ParentId("wrong-parent")},
            True,
            True,
            RuleId.REFERENCE_PARENT_MISMATCH,
        ),
        (
            {},
            True,
            True,
            RuleId.REFERENCE_INACTIVE,
        ),
    ),
)
def test_first_failure_order_is_stable_for_compound_store_state(
    record_changes, consume, deactivate, expected_rule
):
    store = TrustedReferenceStore()
    reference_id = issue_reference(store, **record_changes)
    if consume:
        assert store.consume(reference_id) is (
            ReferenceConsumptionOutcome.CONSUMED
        )
    if deactivate:
        assert store.deactivate(reference_id) is (
            ReferenceDeactivationOutcome.DEACTIVATED
        )

    result = resolve(store, reference_id)

    assert result == ResolutionFailure(expected_rule)


def test_resolution_is_read_only_and_repeated_results_are_equivalent():
    store = TrustedReferenceStore()
    reference_id = issue_reference(store)
    before = store.lookup(reference_id)

    first = resolve(store, reference_id)
    second = resolve(store, reference_id)
    after = store.lookup(reference_id)

    assert type(first) is Resolved
    assert first == second
    assert before == after
    assert type(after) is ReferenceMetadata
    assert (after.active, after.consumed) == (True, False)


def test_resolution_does_not_consume_or_deactivate_reference():
    store = TrustedReferenceStore()
    reference_id = issue_reference(store)

    resolve(store, reference_id)

    assert store.consume(reference_id) is ReferenceConsumptionOutcome.CONSUMED
    assert store.deactivate(reference_id) is (
        ReferenceDeactivationOutcome.DEACTIVATED
    )


def test_resolved_repr_vars_and_asdict_omit_protected_value():
    store = TrustedReferenceStore()
    reference_id = issue_reference(
        store, protected_value={"marker": [PROTECTED_MARKER]}
    )

    result = resolve(store, reference_id)
    assert type(result) is Resolved
    public_views = (repr(result), repr(vars(result)), repr(asdict(result)))

    assert all(PROTECTED_MARKER not in view for view in public_views)
    assert all("protected_value" not in view for view in public_views)
    assert not hasattr(result, "protected_value")


def test_resolution_entry_asdict_path_omits_runtime_protected_value():
    store = TrustedReferenceStore()
    reference_id = issue_reference(store)
    result = resolve(store, reference_id)
    assert type(result) is Resolved
    entry = ResolutionEntry(argument_name=ARGUMENT_NAME, result=result)

    serialized = asdict(entry)

    assert PROTECTED_MARKER not in repr(serialized)
    assert "protected_value" not in repr(serialized)


def test_resolution_failure_contains_no_protected_value_in_public_views():
    result = resolve(
        TrustedReferenceStore(), ReferenceId("ref_missing_order_6")
    )

    assert type(result) is ResolutionFailure
    assert PROTECTED_MARKER not in repr(result)
    assert PROTECTED_MARKER not in repr(asdict(result))
    assert not hasattr(result, "protected_value")


def test_mutating_returned_runtime_copy_cannot_change_result_or_store():
    store = TrustedReferenceStore()
    reference_id = issue_reference(
        store, protected_value={"marker": [PROTECTED_MARKER]}
    )
    first = resolve(store, reference_id)
    assert type(first) is Resolved

    returned_copy = first._copy_protected_value_for_runtime()
    returned_copy["marker"][0] = "runtime-copy-mutated"
    same_result_copy = first._copy_protected_value_for_runtime()
    second = resolve(store, reference_id)
    stored = store._lookup_for_runtime(reference_id)

    assert same_result_copy == {"marker": [PROTECTED_MARKER]}
    assert type(second) is Resolved
    assert second._copy_protected_value_for_runtime() == {
        "marker": [PROTECTED_MARKER]
    }
    assert stored is not None
    assert stored.protected_value == {"marker": [PROTECTED_MARKER]}


@pytest.mark.parametrize(
    ("field", "invalid"),
    (
        ("reference_id", InvocationId("wrong-identifier-kind")),
        ("invocation_id", ReferenceId("wrong-identifier-kind")),
        ("parent_id", InvocationId("wrong-identifier-kind")),
        ("expected_kind", [EXPECTED_KIND]),
        ("argument_name", {ARGUMENT_NAME}),
        ("evaluation_time", "2026-08-07T12:00:00Z"),
    ),
)
def test_request_rejects_wrong_identifier_types_and_unsupported_containers(
    field, invalid
):
    fields = {
        "reference_id": ReferenceId("ref_request_validation"),
        "expected_kind": EXPECTED_KIND,
        "invocation_id": EXPECTED_INVOCATION,
        "parent_id": EXPECTED_PARENT,
        "argument_name": ARGUMENT_NAME,
        "evaluation_time": EVALUATION_TIME,
    }
    fields[field] = invalid

    with pytest.raises((TypeError, ValueError)):
        ResolutionRequest(**fields)


def test_request_rejects_scalar_and_datetime_subclasses():
    class CallerString(str):
        pass

    class CallerDatetime(datetime):
        pass

    with pytest.raises(ValueError):
        request(
            ReferenceId("ref_string_subclass"),
            expected_kind=CallerString(EXPECTED_KIND),
        )
    with pytest.raises(TypeError):
        request(
            ReferenceId("ref_datetime_subclass"),
            evaluation_time=CallerDatetime(
                2026, 8, 7, 12, 0, tzinfo=timezone.utc
            ),
        )


def test_request_requires_exact_utc_datetime_without_timezone_coercion():
    with pytest.raises(ValueError):
        request(
            ReferenceId("ref_naive_time"),
            evaluation_time=datetime(2026, 8, 7, 12, 0),
        )
    with pytest.raises(ValueError):
        request(
            ReferenceId("ref_non_utc_time"),
            evaluation_time=datetime(
                2026,
                8,
                7,
                12,
                0,
                tzinfo=timezone(timedelta(hours=1)),
            ),
        )


class ConversionTrap:
    def __init__(self):
        self.methods_called = []

    def __call__(self):
        self.methods_called.append("call")
        return EXPECTED_KIND

    def __str__(self):
        self.methods_called.append("str")
        return EXPECTED_KIND

    def __int__(self):
        self.methods_called.append("int")
        return 1

    def __float__(self):
        self.methods_called.append("float")
        return 1.0

    def __bool__(self):
        self.methods_called.append("bool")
        return True


@pytest.mark.parametrize(
    "field",
    (
        "reference_id",
        "expected_kind",
        "invocation_id",
        "parent_id",
        "argument_name",
        "evaluation_time",
    ),
)
def test_request_validation_never_invokes_caller_conversion_or_callable(
    field,
):
    trap = ConversionTrap()
    fields = {
        "reference_id": ReferenceId("ref_conversion_trap"),
        "expected_kind": EXPECTED_KIND,
        "invocation_id": EXPECTED_INVOCATION,
        "parent_id": EXPECTED_PARENT,
        "argument_name": ARGUMENT_NAME,
        "evaluation_time": EVALUATION_TIME,
    }
    fields[field] = trap

    with pytest.raises((TypeError, ValueError)):
        ResolutionRequest(**fields)

    assert trap.methods_called == []


def test_resolve_revalidates_exact_request_without_touching_store(monkeypatch):
    store = TrustedReferenceStore()
    reference_id = issue_reference(store)
    untrusted_request = request(reference_id)
    trap = ConversionTrap()
    object.__setattr__(untrusted_request, "expected_kind", trap)
    store_calls = []

    def forbidden_lookup(self, reference_id):
        store_calls.append(reference_id)
        raise AssertionError("invalid request reached trusted store")

    monkeypatch.setattr(
        TrustedReferenceStore, "_lookup_for_runtime", forbidden_lookup
    )

    with pytest.raises(ValueError):
        ReferenceResolver().resolve(untrusted_request, store)

    assert trap.methods_called == []
    assert store_calls == []


def test_corrupted_exact_identifier_is_rejected_without_caller_behavior():
    reference_id = ReferenceId("ref_corrupted_exact_identifier")
    trap = ConversionTrap()
    object.__setattr__(reference_id, "value", trap)

    with pytest.raises(ValueError):
        request(reference_id)

    assert trap.methods_called == []


def test_resolver_rejects_request_and_store_subclasses():
    class RequestSubclass(ResolutionRequest):
        pass

    class StoreSubclass(TrustedReferenceStore):
        pass

    base_request = request(ReferenceId("ref_subclass"))
    subclass_request = RequestSubclass(**vars(base_request))
    subclass_store = object.__new__(StoreSubclass)

    with pytest.raises(TypeError):
        ReferenceResolver().resolve(
            subclass_request, TrustedReferenceStore()
        )
    with pytest.raises(TypeError):
        ReferenceResolver().resolve(base_request, subclass_store)


def test_resolver_rejects_behavior_bearing_store_without_invoking_it():
    class BehaviorStore:
        def __init__(self):
            self.called = False

        def _lookup_for_runtime(self, reference_id):
            self.called = True
            raise AssertionError("untrusted store method invoked")

    behavior_store = BehaviorStore()

    with pytest.raises(TypeError):
        ReferenceResolver().resolve(
            request(ReferenceId("ref_behavior_store")), behavior_store
        )

    assert behavior_store.called is False


def minimal_authoring():
    return {
        "policy_version": "policy-order-6-v1",
        "registry_version": "registry-order-6-v1",
        "executable_tools": ("transfers.submit",),
        "tool_registrations": (
            {
                "tool_id": "transfers.submit",
                "contract_version": "transfers.submit.contract.v1",
                "policy_version": "policy-order-6-v1",
                "signature": (
                    {
                        "name": ARGUMENT_NAME,
                        "required": True,
                        "type_id": "destination_reference",
                    },
                ),
                "arguments": (
                    {
                        "name": ARGUMENT_NAME,
                        "position": 0,
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
                                "parameters": {"kind": EXPECTED_KIND},
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
                        "name": ARGUMENT_NAME,
                        "role": "PROTECTED_REFERENCE",
                        "required_provenance": "RUNTIME_TRUSTED",
                    },
                ),
                "effect_class": "SIDE_EFFECTING",
                "reversibility": "IRREVERSIBLE",
                "adapter_id": "transfers.local.adapter",
                "adapter_version": "transfers.local.adapter.v1",
                "masking_profile_id": "transfers.masking.v1",
            },
        ),
    }


def engine_inputs(reference_id):
    validated = validate_policy_authoring(minimal_authoring())
    assert type(validated) is ValidatedPolicyAuthoring
    installed = PolicyInstaller().install(validated)
    assert type(installed) is InstalledSnapshot
    snapshot = installed.snapshot
    call = CanonicalCall(
        tool_id=ToolId("transfers.submit"),
        contract_version=ToolContractVersion(
            "transfers.submit.contract.v1"
        ),
        signature=(
            CanonicalSignatureArgument(
                name=ARGUMENT_NAME,
                required=True,
                type_id=TypeId("destination_reference"),
            ),
        ),
        arguments=(CanonicalArgument(ARGUMENT_NAME, reference_id),),
    )
    context = CallContext(
        call_id=CallId("call-order-6"),
        decision_id=DecisionId("decision-order-6"),
        invocation_id=EXPECTED_INVOCATION,
        parent_id=EXPECTED_PARENT,
        policy_version=PolicyVersion(snapshot.policy_version.value),
        registry_version=RegistryVersion(snapshot.registry_version.value),
    )
    return snapshot, call, context


def test_valid_resolver_result_contributes_to_allow_through_engine_values():
    store = TrustedReferenceStore()
    reference_id = issue_reference(store)
    result = resolve(store, reference_id)
    snapshot, call, context = engine_inputs(reference_id)

    decision = PolicyEngine().evaluate(
        snapshot,
        call,
        ResolutionSet(
            entries=(ResolutionEntry(ARGUMENT_NAME, result),)
        ),
        context,
    )

    assert type(result) is Resolved
    assert decision.outcome is DecisionOutcome.ALLOW
    assert decision.primary_rule_id is RuleId.AUTHORIZATION_ALLOW


def test_resolver_failure_contributes_to_matching_deny_through_engine_values():
    store = TrustedReferenceStore()
    reference_id = ReferenceId("ref_missing_engine_integration")
    result = resolve(store, reference_id)
    snapshot, call, context = engine_inputs(reference_id)

    decision = PolicyEngine().evaluate(
        snapshot,
        call,
        ResolutionSet(
            entries=(ResolutionEntry(ARGUMENT_NAME, result),)
        ),
        context,
    )

    assert result == ResolutionFailure(RuleId.REFERENCE_NOT_FOUND)
    assert decision.outcome is DecisionOutcome.DENY
    assert decision.primary_rule_id is RuleId.REFERENCE_NOT_FOUND


def test_resolver_performs_no_policy_evaluation_or_external_io(monkeypatch):
    store = TrustedReferenceStore()
    reference_id = issue_reference(store)
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("resolver crossed its read-only boundary")

    monkeypatch.setattr(PolicyEngine, "evaluate", forbidden)
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)

    result = resolve(store, reference_id)

    assert type(result) is Resolved
    assert calls == []


def test_order_6_surface_contains_no_order_7_or_later_mechanism():
    from tidemark.runtime import reference_resolver

    forbidden = {
        "PreparedToolCall",
        "ExecutionGate",
        "EvidenceRecorder",
        "EvidenceSink",
    }
    forbidden_methods = {
        "prepare",
        "execute",
        "consume",
        "deactivate",
        "issue",
        "persist",
        "evaluate",
    }

    assert forbidden.isdisjoint(vars(reference_resolver))
    assert forbidden_methods.isdisjoint(dir(ReferenceResolver()))
    assert not any(
        name.startswith(
            (
                "adk",
                "gemini",
                "google",
                "cloud",
                "payment",
                "firestore",
                "database",
                "ui",
            )
        )
        for name, _ in inspect.getmembers(reference_resolver)
    )


def test_order_6_public_runtime_surface_exports_resolver_contracts_only():
    import tidemark.runtime as runtime

    assert {"ReferenceResolver", "ResolutionRequest"}.issubset(
        runtime.__all__
    )
    assert not hasattr(runtime, "PreparedToolCall")
    assert not hasattr(runtime, "ExecutionGate")
