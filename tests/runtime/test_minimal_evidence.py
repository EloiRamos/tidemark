from dataclasses import FrozenInstanceError, asdict
from datetime import datetime, timezone
import json

import pytest

from tidemark.runtime.identifiers import (
    AdapterId,
    AdapterVersion,
    CallId,
    DecisionId,
    ExecutionId,
    InvocationId,
    PolicyVersion,
    PreparedCallId,
    RegistryVersion,
    ToolId,
)
from tidemark.runtime.minimal_evidence import (
    MINIMAL_EVIDENCE_PRODUCER_VERSION,
    MINIMAL_EVIDENCE_SCHEMA_VERSION,
    DurableAppendReceipt,
    EvidenceAppendFailure,
    ExecutionOutcomeRecord,
    MinimalPreExecutionEvidenceSink,
    PreExecutionCorrelationRecord,
)
from tidemark.runtime.vocabulary import (
    DecisionOutcome,
    ExecutionOutcome,
    RuleId,
)


OCCURRED_AT = datetime(2026, 8, 7, 16, 0, tzinfo=timezone.utc)
PROTECTED_MARKER = "protected-value-must-never-enter-order-8-evidence"


def pre_execution_record(record_id="pre-order-8-001"):
    return PreExecutionCorrelationRecord(
        schema_version=MINIMAL_EVIDENCE_SCHEMA_VERSION,
        record_id=record_id,
        execution_id=ExecutionId("execution-order-8-001"),
        prepared_call_id=PreparedCallId("prepared-order-8-001"),
        call_id=CallId("call-order-8-001"),
        decision_id=DecisionId("decision-order-8-001"),
        invocation_id=InvocationId("invocation-order-8-001"),
        tool_id=ToolId("dispatch.submit"),
        policy_version=PolicyVersion("policy-order-8-v1"),
        registry_version=RegistryVersion("registry-order-8-v1"),
        adapter_id=AdapterId("dispatch.local.adapter"),
        adapter_version=AdapterVersion("dispatch.local.adapter.v1"),
        public_integrity_id="sha256:" + "a" * 64,
        authorization_outcome=DecisionOutcome.ALLOW,
        authorization_rule_id=RuleId.AUTHORIZATION_ALLOW,
        occurred_at=OCCURRED_AT,
        producer_version=MINIMAL_EVIDENCE_PRODUCER_VERSION,
    )


def outcome_record(record_id="outcome-order-8-001"):
    pre = pre_execution_record()
    return ExecutionOutcomeRecord(
        schema_version=pre.schema_version,
        record_id=record_id,
        execution_id=pre.execution_id,
        prepared_call_id=pre.prepared_call_id,
        call_id=pre.call_id,
        decision_id=pre.decision_id,
        invocation_id=pre.invocation_id,
        tool_id=pre.tool_id,
        policy_version=pre.policy_version,
        registry_version=pre.registry_version,
        adapter_id=pre.adapter_id,
        adapter_version=pre.adapter_version,
        public_integrity_id=pre.public_integrity_id,
        authorization_outcome=DecisionOutcome.ALLOW,
        authorization_rule_id=RuleId.AUTHORIZATION_ALLOW,
        execution_status=ExecutionOutcome.COMPLETED,
        external_result_confirmed=True,
        masked_failure_fact=None,
        occurred_at=OCCURRED_AT,
        producer_version=MINIMAL_EVIDENCE_PRODUCER_VERSION,
    )


def stored_records(root):
    return tuple(
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(root.glob("*.json"))
    )


def test_successful_pre_execution_append_flushes_and_synchronizes_before_receipt(
    tmp_path, monkeypatch
):
    calls = []
    original_flush = MinimalPreExecutionEvidenceSink._flush
    original_sync = MinimalPreExecutionEvidenceSink._synchronize

    def tracked_flush(self, stream):
        calls.append("flush")
        return original_flush(self, stream)

    def tracked_sync(self, descriptor):
        calls.append("sync")
        return original_sync(self, descriptor)

    monkeypatch.setattr(MinimalPreExecutionEvidenceSink, "_flush", tracked_flush)
    monkeypatch.setattr(
        MinimalPreExecutionEvidenceSink, "_synchronize", tracked_sync
    )
    sink = MinimalPreExecutionEvidenceSink(str(tmp_path))

    result = sink.append_pre_execution(pre_execution_record())

    assert type(result) is DurableAppendReceipt
    assert result.record_id == "pre-order-8-001"
    assert calls[0:2] == ["flush", "sync"]
    assert calls.count("flush") == 1
    assert calls.count("sync") >= 2
    records = stored_records(tmp_path)
    assert len(records) == 1
    assert records[0]["record_kind"] == "pre_execution_correlation"


def test_successful_outcome_append_is_a_separate_append_only_record(tmp_path):
    sink = MinimalPreExecutionEvidenceSink(str(tmp_path))

    first = sink.append_pre_execution(pre_execution_record())
    second = sink.append_execution_outcome(outcome_record())

    assert type(first) is DurableAppendReceipt
    assert type(second) is DurableAppendReceipt
    records = stored_records(tmp_path)
    assert tuple(record["record_kind"] for record in records) == (
        "execution_outcome",
        "pre_execution_correlation",
    )
    assert records[0]["execution_status"] == "COMPLETED"


def test_explicit_write_failure_returns_failure_without_a_record(
    tmp_path, monkeypatch
):
    sink = MinimalPreExecutionEvidenceSink(str(tmp_path))

    def fail_write(self, stream, encoded):
        raise OSError("injected append failure")

    monkeypatch.setattr(MinimalPreExecutionEvidenceSink, "_write", fail_write)

    result = sink.append_pre_execution(pre_execution_record())

    assert type(result) is EvidenceAppendFailure
    assert result.failure_code == "evidence.append_failed.v1"
    assert stored_records(tmp_path) == ()


def test_flush_failure_returns_failure_without_a_committed_record(
    tmp_path, monkeypatch
):
    sink = MinimalPreExecutionEvidenceSink(str(tmp_path))

    def fail_flush(self, stream):
        raise OSError("injected flush failure")

    monkeypatch.setattr(MinimalPreExecutionEvidenceSink, "_flush", fail_flush)

    result = sink.append_pre_execution(pre_execution_record())

    assert type(result) is EvidenceAppendFailure
    assert result.failure_code == "evidence.append_failed.v1"
    assert stored_records(tmp_path) == ()


def test_os_synchronization_failure_returns_failure_without_success_receipt(
    tmp_path, monkeypatch
):
    sink = MinimalPreExecutionEvidenceSink(str(tmp_path))

    def fail_sync(self, descriptor):
        raise OSError("injected sync failure")

    monkeypatch.setattr(
        MinimalPreExecutionEvidenceSink, "_synchronize", fail_sync
    )

    result = sink.append_pre_execution(pre_execution_record())

    assert type(result) is EvidenceAppendFailure
    assert result.failure_code == "evidence.append_failed.v1"


def test_malformed_and_duplicate_records_fail_explicitly(tmp_path):
    sink = MinimalPreExecutionEvidenceSink(str(tmp_path))
    record = pre_execution_record()

    malformed = sink.append_pre_execution(object())
    first = sink.append_pre_execution(record)
    duplicate = sink.append_pre_execution(record)

    assert type(malformed) is EvidenceAppendFailure
    assert malformed.failure_code == "evidence.record_invalid.v1"
    assert type(first) is DurableAppendReceipt
    assert type(duplicate) is EvidenceAppendFailure
    assert duplicate.failure_code == "evidence.duplicate_record.v1"
    assert len(stored_records(tmp_path)) == 1


def test_records_and_receipts_are_immutable_and_protected_value_free(tmp_path):
    sink = MinimalPreExecutionEvidenceSink(str(tmp_path))
    record = pre_execution_record()
    receipt = sink.append_pre_execution(record)
    assert type(receipt) is DurableAppendReceipt

    with pytest.raises(FrozenInstanceError):
        record.record_id = PROTECTED_MARKER
    with pytest.raises(FrozenInstanceError):
        receipt.record_id = PROTECTED_MARKER

    rendered = repr(record) + repr(asdict(record)) + repr(stored_records(tmp_path))
    assert PROTECTED_MARKER not in rendered
    forbidden = {
        "reference_id",
        "runtime_payload",
        "private_authenticator",
        "integrity_secret",
        "store",
        "resolution_result",
        "policy_snapshot",
    }
    assert forbidden.isdisjoint(stored_records(tmp_path)[0])


def test_minimal_sink_has_no_query_projection_reconciliation_or_export_surface(
    tmp_path,
):
    sink = MinimalPreExecutionEvidenceSink(str(tmp_path))

    assert {
        "query",
        "lookup",
        "project",
        "reconcile",
        "export",
        "record_payment",
        "delete",
        "update",
    }.isdisjoint(dir(sink))

