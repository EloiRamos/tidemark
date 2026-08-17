from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, asdict
import builtins
import inspect
import socket

import pytest

from tidemark.runtime.identifiers import InvocationId, ParentId, ReferenceId
from tidemark.runtime.reference_store import (
    ReferenceBinding,
    ReferenceConsumptionOutcome,
    ReferenceDeactivationOutcome,
    ReferenceIssuer,
    ReferenceLifecycle,
    ReferenceMetadata,
    ReferenceNotFound,
    TrustedRecord,
    TrustedReferenceStore,
)


PROTECTED_VALUE = "protected-runtime-value-never-publish-order-5"
INVOCATION_VALUE = "invocation-binding-never-encode-order-5"
PARENT_VALUE = "parent-binding-never-encode-order-5"


def binding():
    return ReferenceBinding(
        invocation_id=InvocationId(INVOCATION_VALUE),
        parent_id=ParentId(PARENT_VALUE),
    )


def lifecycle(active=True, single_use=True):
    return ReferenceLifecycle(active=active, single_use=single_use)


def issue(
    store,
    protected_value=PROTECTED_VALUE,
    kind="destination",
    active=True,
    single_use=True,
):
    return store.issuer.issue(
        TrustedRecord(protected_value=protected_value, kind=kind),
        binding(),
        lifecycle(active=active, single_use=single_use),
    )


def found(store, reference_id):
    result = store.lookup(reference_id)
    assert type(result) is ReferenceMetadata
    return result


def test_trusted_value_issuance_returns_an_opaque_reference_id():
    store = TrustedReferenceStore()

    reference_id = issue(store)

    assert type(reference_id) is ReferenceId
    assert type(found(store, reference_id)) is ReferenceMetadata


def test_distinct_issuances_return_distinct_ids_for_identical_values():
    store = TrustedReferenceStore()

    first = issue(store)
    second = issue(store)

    assert first != second
    assert first.value != second.value
    assert found(store, first).kind == found(store, second).kind


def test_reference_id_contains_no_protected_value_or_binding_identity():
    store = TrustedReferenceStore()

    reference_id = issue(store)

    assert PROTECTED_VALUE not in reference_id.value
    assert INVOCATION_VALUE not in reference_id.value
    assert PARENT_VALUE not in reference_id.value


def test_caller_mutation_after_issue_cannot_change_stored_protected_value():
    source = {"account": ["original"]}
    record = TrustedRecord(protected_value=source, kind="destination")
    store = TrustedReferenceStore()
    reference_id = store.issuer.issue(record, binding(), lifecycle())

    source["account"][0] = "caller-mutated"
    source["new"] = "caller-added"
    runtime_record = store._lookup_for_runtime(reference_id)

    assert runtime_record is not None
    assert runtime_record.protected_value == {"account": ["original"]}


def test_issuance_freshly_copies_binding_identifiers():
    source_binding = binding()
    store = TrustedReferenceStore()
    reference_id = store.issuer.issue(
        TrustedRecord(PROTECTED_VALUE, "destination"),
        source_binding,
        lifecycle(),
    )

    view = found(store, reference_id)

    assert view.invocation_id == source_binding.invocation_id
    assert view.parent_id == source_binding.parent_id
    assert view.invocation_id is not source_binding.invocation_id
    assert view.parent_id is not source_binding.parent_id


def test_lookup_returns_all_inert_trusted_facts_without_protected_value():
    store = TrustedReferenceStore()
    reference_id = issue(store)

    view = found(store, reference_id)

    assert view.reference_id == reference_id
    assert view.kind == "destination"
    assert view.invocation_id == InvocationId(INVOCATION_VALUE)
    assert view.parent_id == ParentId(PARENT_VALUE)
    assert view.active is True
    assert view.single_use is True
    assert view.consumed is False
    assert not hasattr(view, "protected_value")


def test_unknown_reference_has_an_explicit_not_found_result():
    store = TrustedReferenceStore()
    unknown = ReferenceId("ref_unknown_order_5")

    result = store.lookup(unknown)

    assert type(result) is ReferenceNotFound
    assert result.reference_id == unknown


def test_lookup_is_read_only_and_returns_detached_immutable_views():
    store = TrustedReferenceStore()
    reference_id = issue(store)

    first = found(store, reference_id)
    second = found(store, reference_id)

    assert first == second
    assert first is not second
    assert first.reference_id is not second.reference_id
    with pytest.raises(FrozenInstanceError):
        first.active = False
    with pytest.raises(FrozenInstanceError):
        first.parent_id.value = "caller-mutated"
    assert found(store, reference_id).active is True


def test_deactivation_changes_only_the_owned_lifecycle_state():
    store = TrustedReferenceStore()
    reference_id = issue(store)

    result = store.deactivate(reference_id)
    view = found(store, reference_id)

    assert result is ReferenceDeactivationOutcome.DEACTIVATED
    assert view.active is False
    assert view.consumed is False


def test_repeated_deactivation_is_deterministic():
    store = TrustedReferenceStore()
    reference_id = issue(store)

    first = store.deactivate(reference_id)
    second = store.deactivate(reference_id)
    third = store.deactivate(reference_id)

    assert first is ReferenceDeactivationOutcome.DEACTIVATED
    assert second is ReferenceDeactivationOutcome.ALREADY_INACTIVE
    assert third is ReferenceDeactivationOutcome.ALREADY_INACTIVE


def test_deactivation_of_unknown_reference_is_explicitly_not_found():
    store = TrustedReferenceStore()

    result = store.deactivate(ReferenceId("ref_missing_order_5"))

    assert result is ReferenceDeactivationOutcome.NOT_FOUND


def test_inactive_lookup_remains_distinct_from_not_found():
    store = TrustedReferenceStore()
    reference_id = issue(store)
    store.deactivate(reference_id)

    inactive = store.lookup(reference_id)
    missing = store.lookup(ReferenceId("ref_missing_order_5"))

    assert type(inactive) is ReferenceMetadata
    assert inactive.active is False
    assert type(missing) is ReferenceNotFound


def test_consuming_an_inactive_reference_is_rejected_without_consumption():
    store = TrustedReferenceStore()
    reference_id = issue(store)
    store.deactivate(reference_id)

    result = store.consume(reference_id)

    assert result is ReferenceConsumptionOutcome.INACTIVE
    assert found(store, reference_id).consumed is False


def test_single_use_reference_can_be_consumed_successfully_exactly_once():
    store = TrustedReferenceStore()
    reference_id = issue(store)

    first = store.consume(reference_id)
    second = store.consume(reference_id)

    assert first is ReferenceConsumptionOutcome.CONSUMED
    assert second is ReferenceConsumptionOutcome.ALREADY_CONSUMED
    assert found(store, reference_id).consumed is True


def test_consumed_state_remains_distinct_from_inactive_and_not_found():
    store = TrustedReferenceStore()
    consumed_id = issue(store)
    inactive_id = issue(store)
    store.consume(consumed_id)
    store.deactivate(inactive_id)

    consumed = found(store, consumed_id)
    inactive = found(store, inactive_id)
    missing = store.lookup(ReferenceId("ref_missing_order_5"))

    assert (consumed.active, consumed.consumed) == (True, True)
    assert (inactive.active, inactive.consumed) == (False, False)
    assert type(missing) is ReferenceNotFound


def test_consumed_result_wins_over_later_inactive_state():
    store = TrustedReferenceStore()
    reference_id = issue(store)
    store.consume(reference_id)
    store.deactivate(reference_id)

    result = store.consume(reference_id)

    assert result is ReferenceConsumptionOutcome.ALREADY_CONSUMED


def test_consuming_unknown_reference_is_explicitly_not_found():
    store = TrustedReferenceStore()

    result = store.consume(ReferenceId("ref_missing_order_5"))

    assert result is ReferenceConsumptionOutcome.NOT_FOUND


def test_non_single_use_reference_is_not_mutated_by_consume_operation():
    store = TrustedReferenceStore()
    reference_id = issue(store, single_use=False)

    result = store.consume(reference_id)

    assert result is ReferenceConsumptionOutcome.NOT_SINGLE_USE
    view = found(store, reference_id)
    assert view.single_use is False
    assert view.consumed is False


def test_concurrent_consumers_produce_exactly_one_success():
    store = TrustedReferenceStore()
    reference_id = issue(store)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = tuple(
            executor.map(store.consume, (reference_id,) * 32)
        )

    assert results.count(ReferenceConsumptionOutcome.CONSUMED) == 1
    assert results.count(
        ReferenceConsumptionOutcome.ALREADY_CONSUMED
    ) == 31
    assert found(store, reference_id).consumed is True


def test_different_store_instances_are_isolated_even_for_same_inputs():
    first_store = TrustedReferenceStore()
    second_store = TrustedReferenceStore()
    first_id = issue(first_store)

    assert type(first_store.lookup(first_id)) is ReferenceMetadata
    assert type(second_store.lookup(first_id)) is ReferenceNotFound

    second_id = issue(second_store)
    first_store.consume(first_id)
    assert found(second_store, second_id).consumed is False


def test_reference_and_public_lookup_repr_never_expose_protected_value():
    store = TrustedReferenceStore()
    trusted_record = TrustedRecord(PROTECTED_VALUE, "destination")
    reference_id = store.issuer.issue(
        trusted_record, binding(), lifecycle()
    )

    rendered = " ".join(
        (
            repr(trusted_record),
            repr(reference_id),
            repr(store),
            repr(store.issuer),
            repr(found(store, reference_id)),
        )
    )

    assert PROTECTED_VALUE not in rendered


def test_public_lookup_asdict_path_contains_no_protected_value():
    store = TrustedReferenceStore()
    reference_id = issue(store)

    serialized = asdict(found(store, reference_id))

    assert PROTECTED_VALUE not in repr(serialized)
    assert "protected_value" not in serialized


def test_only_private_runtime_lookup_can_access_a_detached_protected_value():
    store = TrustedReferenceStore()
    reference_id = issue(store, protected_value={"value": [PROTECTED_VALUE]})

    public = found(store, reference_id)
    runtime_record = store._lookup_for_runtime(reference_id)

    assert not hasattr(public, "protected_value")
    assert runtime_record is not None
    assert runtime_record.protected_value == {"value": [PROTECTED_VALUE]}
    runtime_record.protected_value["value"][0] = "runtime-copy-mutated"
    second_runtime_record = store._lookup_for_runtime(reference_id)
    assert second_runtime_record is not None
    assert second_runtime_record.protected_value == {
        "value": [PROTECTED_VALUE]
    }


def test_internal_runtime_record_repr_is_also_protected_value_safe():
    store = TrustedReferenceStore()
    reference_id = issue(store)

    runtime_record = store._lookup_for_runtime(reference_id)

    assert runtime_record is not None
    assert PROTECTED_VALUE not in repr(runtime_record)


def test_issuer_is_a_store_bound_runtime_capability_not_a_store_write_method():
    store = TrustedReferenceStore()

    assert type(store.issuer) is ReferenceIssuer
    assert not hasattr(store, "issue")
    with pytest.raises(TypeError):
        ReferenceIssuer(store)


@pytest.mark.parametrize(
    ("trusted_record", "reference_binding", "reference_lifecycle"),
    (
        (object(), binding(), lifecycle()),
        (TrustedRecord(PROTECTED_VALUE, "destination"), object(), lifecycle()),
        (TrustedRecord(PROTECTED_VALUE, "destination"), binding(), object()),
    ),
)
def test_issuance_rejects_non_runtime_contract_types_before_mutation(
    trusted_record, reference_binding, reference_lifecycle
):
    store = TrustedReferenceStore()

    with pytest.raises(TypeError):
        store.issuer.issue(
            trusted_record, reference_binding, reference_lifecycle
        )

    assert type(
        store.lookup(ReferenceId("ref_absent_after_refusal"))
    ) is ReferenceNotFound


def test_store_performs_no_policy_evaluation_or_external_io(monkeypatch):
    from tidemark.runtime.policy_engine import PolicyEngine

    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("store crossed its lifecycle boundary")

    monkeypatch.setattr(PolicyEngine, "evaluate", forbidden)
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    store = TrustedReferenceStore()

    reference_id = issue(store)
    store.lookup(reference_id)
    store.consume(reference_id)
    store.deactivate(reference_id)

    assert calls == []


def test_store_module_has_no_mutable_authoritative_global_state():
    from tidemark.runtime import reference_store

    mutable_globals = {
        name: value
        for name, value in vars(reference_store).items()
        if name != "__builtins__" and type(value) in (dict, list, set)
    }

    assert mutable_globals == {}


def test_order_5_surface_contains_no_order_6_or_later_mechanism():
    from tidemark.runtime import reference_store

    forbidden = {
        "PolicyEngine",
        "RuleId",
        "ReferenceResolver",
        "ResolutionResult",
        "ResolutionSet",
        "PreparedToolCall",
        "ExecutionGate",
    }
    forbidden_methods = {"evaluate", "resolve", "prepare", "execute", "persist"}

    assert forbidden.isdisjoint(vars(reference_store))
    assert forbidden_methods.isdisjoint(dir(TrustedReferenceStore()))
    assert not any(
        name.startswith(("adk", "gemini", "google", "cloud", "payment"))
        for name, _ in inspect.getmembers(reference_store)
    )
