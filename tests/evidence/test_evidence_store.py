from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from tidemark.evidence.local_store import (
    AppendReceipt,
    DuplicateEventError,
    EvidenceDurabilityError,
    EvidenceStoreCorruptionError,
    InvalidTraceSequenceError,
    LocalAuditStore,
)
from tidemark.evidence.model import (
    EVIDENCE_SCHEMA_VERSION,
    ArgumentShape,
    AuditEvent,
    CallIntakeRecordedPayload,
    EvidenceEventType,
    EvidenceProducer,
    audit_event_to_primitive,
)
from tidemark.runtime.identifiers import (
    CallId,
    DecisionId,
    ExecutionId,
    InvocationId,
    PolicyVersion,
    PreparedCallId,
    RegistryVersion,
    ToolContractVersion,
    ToolId,
)


NOW = datetime(2026, 8, 7, 20, 0, tzinfo=timezone.utc)


def _event(
    sequence=1,
    *,
    event_id="event-001",
    trace_id="trace-001",
    invocation_id="invocation-001",
    call_id="call-001",
    decision_id=None,
    prepared_call_id=None,
    execution_id=None,
):
    return AuditEvent(
        schema_version=EVIDENCE_SCHEMA_VERSION,
        event_id=event_id,
        event_type=EvidenceEventType.CALL_INTAKE_RECORDED,
        occurred_at=NOW,
        sequence=sequence,
        trace_id=trace_id,
        invocation_id=InvocationId(invocation_id),
        call_id=CallId(call_id),
        decision_id=(
            DecisionId(decision_id) if decision_id is not None else None
        ),
        prepared_call_id=(
            PreparedCallId(prepared_call_id)
            if prepared_call_id is not None
            else None
        ),
        execution_id=(
            ExecutionId(execution_id) if execution_id is not None else None
        ),
        policy_version=PolicyVersion("policy.v1"),
        registry_version=RegistryVersion("registry.v1"),
        adapter_id=None,
        adapter_version=None,
        producer=EvidenceProducer("tidemark.tests", "order-13"),
        payload=CallIntakeRecordedPayload(
            tool_id=ToolId("schedule_payment"),
            contract_version=ToolContractVersion("contract.v1"),
            argument_shapes=(ArgumentShape("amount_minor", "int"),),
        ),
        previous_event_digest=None,
    )


def test_append_is_durable_queryable_and_reloads_from_disk(tmp_path):
    root = tmp_path / "audit"
    store = LocalAuditStore(str(root))
    event = _event()

    receipt = store.append(event)
    reloaded = LocalAuditStore(str(root))

    assert type(receipt) is AppendReceipt
    assert receipt.event_id == event.event_id
    assert receipt.sequence == 1
    assert receipt.event_digest.startswith("sha256:")
    assert reloaded.event_by_id(event.event_id) == event
    assert reloaded.events_for_trace("trace-001") == (event,)
    assert list((root / "events").glob("*.json"))


def test_sequence_is_monotonic_per_trace_and_append_order_agrees(tmp_path):
    store = LocalAuditStore(str(tmp_path / "audit"))
    first = _event()
    second = _event(2, event_id="event-002")

    store.append(first)
    store.append(second)

    assert store.next_sequence("trace-001") == 3
    assert store.events_for_trace("trace-001") == (first, second)
    with pytest.raises(InvalidTraceSequenceError):
        store.append(_event(2, event_id="event-003"))
    with pytest.raises(InvalidTraceSequenceError):
        store.append(_event(4, event_id="event-004"))
    assert store.events_for_trace("trace-001") == (first, second)


def test_duplicate_event_identity_fails_without_overwrite(tmp_path):
    store = LocalAuditStore(str(tmp_path / "audit"))
    event = _event()
    store.append(event)

    with pytest.raises(DuplicateEventError):
        store.append(replace(event, sequence=2))

    assert store.event_by_id(event.event_id) == event
    assert store.next_sequence("trace-001") == 2


def test_all_correlation_queries_are_ordered_and_read_only(tmp_path):
    store = LocalAuditStore(str(tmp_path / "audit"))
    first = _event(
        decision_id="decision-001",
        prepared_call_id="prepared-001",
        execution_id="execution-001",
    )
    second = _event(
        2,
        event_id="event-002",
        decision_id="decision-001",
        prepared_call_id="prepared-001",
        execution_id="execution-001",
    )
    store.append(first)
    store.append(second)

    expected = (first, second)
    assert store.events_for_invocation(InvocationId("invocation-001")) == expected
    assert store.events_for_call(CallId("call-001")) == expected
    assert store.events_for_decision(DecisionId("decision-001")) == expected
    assert store.events_for_prepared_call(PreparedCallId("prepared-001")) == expected
    assert store.events_for_execution(ExecutionId("execution-001")) == expected
    assert store.ordered_events() == expected
    with pytest.raises(AttributeError):
        expected.append(first)


def test_stored_event_and_receipt_are_immutable_and_serialization_is_detached(
    tmp_path,
):
    store = LocalAuditStore(str(tmp_path / "audit"))
    event = _event()
    receipt = store.append(event)
    queried = store.event_by_id(event.event_id)
    primitive = audit_event_to_primitive(queried)
    primitive["payload"]["argument_shapes"][0]["name"] = "mutated"

    with pytest.raises(FrozenInstanceError):
        receipt.sequence = 9
    with pytest.raises(FrozenInstanceError):
        queried.sequence = 9
    object.__setattr__(queried, "sequence", 9)
    object.__setattr__(event, "sequence", 8)
    assert store.event_by_id(event.event_id).payload.argument_shapes[0].name == (
        "amount_minor"
    )
    assert store.event_by_id(event.event_id).sequence == 1


@pytest.mark.parametrize("missing_name", ("update", "delete", "replace", "upsert"))
def test_public_store_exposes_no_mutation_api(tmp_path, missing_name):
    store = LocalAuditStore(str(tmp_path / "audit"))

    assert not hasattr(store, missing_name)
    assert not hasattr(store, "events")
    assert not hasattr(store, "records")


class _OpenFailureStore(LocalAuditStore):
    def _open_temp(self, path):
        raise OSError("controlled open failure")


class _WriteFailureStore(LocalAuditStore):
    def _write(self, stream, encoded):
        raise OSError("controlled write failure")


class _PartialWriteStore(LocalAuditStore):
    def _write(self, stream, encoded):
        stream.write(encoded[: max(1, len(encoded) // 2)])
        return max(1, len(encoded) // 2)


class _FlushFailureStore(LocalAuditStore):
    def _flush(self, stream):
        raise OSError("controlled flush failure")


class _FsyncFailureStore(LocalAuditStore):
    def _synchronize(self, descriptor):
        raise OSError("controlled fsync failure")


class _DirectoryFsyncFailureStore(LocalAuditStore):
    def __init__(self, root_path):
        self._synchronization_count = 0
        super().__init__(root_path)

    def _synchronize(self, descriptor):
        self._synchronization_count += 1
        if self._synchronization_count == 2:
            raise OSError("controlled directory fsync failure")
        return super()._synchronize(descriptor)


@pytest.mark.parametrize(
    "store_type",
    (
        _OpenFailureStore,
        _WriteFailureStore,
        _PartialWriteStore,
        _FlushFailureStore,
        _FsyncFailureStore,
        _DirectoryFsyncFailureStore,
    ),
)
def test_controlled_durable_failure_never_partially_appends(tmp_path, store_type):
    root = tmp_path / store_type.__name__
    healthy = LocalAuditStore(str(root))
    first = _event()
    healthy.append(first)
    failing = store_type(str(root))

    with pytest.raises(EvidenceDurabilityError):
        failing.append(_event(2, event_id="failed-event"))

    assert failing.event_by_id(first.event_id) == first
    assert failing.event_by_id("failed-event") is None
    assert failing.next_sequence("trace-001") == 2
    assert not any(
        "failed-event" in path.name
        for path in (root / "events").iterdir()
        if not path.name.startswith(".")
    )


def test_malformed_persisted_record_fails_detectably_without_changing_open_store(
    tmp_path,
):
    root = tmp_path / "audit"
    store = LocalAuditStore(str(root))
    event = _event()
    store.append(event)
    (root / "events" / "malformed.json").write_text(
        '{"schema_version":"broken"}\n', encoding="utf-8"
    )

    with pytest.raises(EvidenceStoreCorruptionError):
        LocalAuditStore(str(root))

    assert store.event_by_id(event.event_id) == event


def test_invalid_append_does_not_change_prior_state(tmp_path):
    store = LocalAuditStore(str(tmp_path / "audit"))
    first = _event()
    store.append(first)

    with pytest.raises(TypeError):
        store.append(object())

    assert store.ordered_events() == (first,)
    assert store.next_sequence("trace-001") == 2


def test_store_root_is_bounded_and_repr_exposes_no_writable_path(tmp_path):
    store = LocalAuditStore(str(tmp_path / "bounded-audit"))

    rendered = repr(store)

    assert "append_only=True" in rendered
    assert str(tmp_path) not in rendered
    assert not hasattr(store, "open_file")
    assert not hasattr(store, "write_path")
