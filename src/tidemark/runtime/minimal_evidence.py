"""Minimal durable local evidence required by the Order 8 execution gate.

This module writes only pre-execution correlation and local execution-outcome
records.  Each record is published as one immutable JSON file in an
append-only directory after a file flush, file synchronization, atomic link,
and directory synchronization.  It intentionally provides no query,
projection, reconciliation, export, payment, UI, database, or cloud surface.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from secrets import token_hex
from threading import Lock
from typing import Optional, Union, final

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
from tidemark.runtime.vocabulary import (
    DecisionOutcome,
    ExecutionOutcome,
    RuleId,
)


MINIMAL_EVIDENCE_SCHEMA_VERSION = "tidemark.minimal-execution-evidence.v1"
MINIMAL_EVIDENCE_PRODUCER_VERSION = "tidemark.runtime.execution-gate.v1"

_APPEND_FAILED = "evidence.append_failed.v1"
_DUPLICATE_RECORD = "evidence.duplicate_record.v1"
_INVALID_RECORD = "evidence.record_invalid.v1"
_PRE_EXECUTION_KIND = "pre_execution_correlation"
_OUTCOME_KIND = "execution_outcome"
_FAILURE_FACTS = frozenset(
    {
        "adapter-confirmed-failure",
        "unconfirmed-external-result",
    }
)


@final
@dataclass(frozen=True)
class PreExecutionCorrelationRecord:
    """Allowlisted non-secret correlation required before local mutation."""

    schema_version: str
    record_id: str
    execution_id: ExecutionId
    prepared_call_id: PreparedCallId
    call_id: CallId
    decision_id: DecisionId
    invocation_id: InvocationId
    tool_id: ToolId
    policy_version: PolicyVersion
    registry_version: RegistryVersion
    adapter_id: AdapterId
    adapter_version: AdapterVersion
    public_integrity_id: str
    authorization_outcome: DecisionOutcome
    authorization_rule_id: RuleId
    occurred_at: datetime
    producer_version: str

    def __post_init__(self) -> None:
        if not _pre_execution_record_valid(self):
            raise ValueError("invalid pre-execution correlation record")


@final
@dataclass(frozen=True)
class ExecutionOutcomeRecord:
    """Allowlisted local outcome record written after one adapter attempt."""

    schema_version: str
    record_id: str
    execution_id: ExecutionId
    prepared_call_id: PreparedCallId
    call_id: CallId
    decision_id: DecisionId
    invocation_id: InvocationId
    tool_id: ToolId
    policy_version: PolicyVersion
    registry_version: RegistryVersion
    adapter_id: AdapterId
    adapter_version: AdapterVersion
    public_integrity_id: str
    authorization_outcome: DecisionOutcome
    authorization_rule_id: RuleId
    execution_status: ExecutionOutcome
    external_result_confirmed: bool
    masked_failure_fact: Optional[str]
    occurred_at: datetime
    producer_version: str

    def __post_init__(self) -> None:
        if not _outcome_record_valid(self):
            raise ValueError("invalid execution outcome record")


@final
@dataclass(frozen=True)
class DurableAppendReceipt:
    """Immutable confirmation returned only after local synchronization."""

    schema_version: str
    record_id: str
    record_kind: str
    durable_at: datetime


@final
@dataclass(frozen=True)
class EvidenceAppendFailure:
    """Explicit append failure carrying no caller or protected detail."""

    record_id: Optional[str]
    failure_code: str


EvidenceAppendResult = Union[DurableAppendReceipt, EvidenceAppendFailure]


@final
class MinimalPreExecutionEvidenceSink:
    """Append exactly the two bounded Order 8 local record families."""

    __slots__ = ("_lock", "_root")

    def __init__(self, root_path: str) -> None:
        if type(root_path) is not str or root_path == "":
            raise ValueError("root_path requires an exact non-empty string")
        root = Path(root_path)
        root.mkdir(parents=True, exist_ok=True)
        if not root.is_dir():
            raise ValueError("root_path must identify a directory")
        self._root = root
        self._lock = Lock()

    def append_pre_execution(
        self, record: PreExecutionCorrelationRecord
    ) -> EvidenceAppendResult:
        """Durably append one exact pre-execution correlation record."""

        if (
            type(record) is not PreExecutionCorrelationRecord
            or not _pre_execution_record_valid(record)
        ):
            return EvidenceAppendFailure(None, _INVALID_RECORD)
        return self._append(
            record.record_id,
            _PRE_EXECUTION_KIND,
            _pre_execution_primitive(record),
        )

    def append_execution_outcome(
        self, record: ExecutionOutcomeRecord
    ) -> EvidenceAppendResult:
        """Durably append one exact local execution-outcome record."""

        if (
            type(record) is not ExecutionOutcomeRecord
            or not _outcome_record_valid(record)
        ):
            return EvidenceAppendFailure(None, _INVALID_RECORD)
        return self._append(
            record.record_id,
            _OUTCOME_KIND,
            _outcome_primitive(record),
        )

    def _append(
        self, record_id: str, record_kind: str, primitive: dict
    ) -> EvidenceAppendResult:
        final_path = self._root / (record_id + ".json")
        encoded = (
            json.dumps(
                {"record_kind": record_kind, **primitive},
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
        temp_path = self._root / (
            "." + record_id + "." + token_hex(16) + ".tmp"
        )

        with self._lock:
            if final_path.exists():
                return EvidenceAppendFailure(record_id, _DUPLICATE_RECORD)
            linked = False
            try:
                with temp_path.open("x", encoding="utf-8", newline="\n") as stream:
                    self._write(stream, encoded)
                    self._flush(stream)
                    self._synchronize(stream.fileno())
                os.link(str(temp_path), str(final_path))
                linked = True
                temp_path.unlink()
                directory_flags = os.O_RDONLY
                if hasattr(os, "O_DIRECTORY"):
                    directory_flags |= os.O_DIRECTORY
                directory_descriptor = os.open(str(self._root), directory_flags)
                try:
                    self._synchronize(directory_descriptor)
                finally:
                    os.close(directory_descriptor)
            except FileExistsError:
                _safe_unlink(temp_path)
                return EvidenceAppendFailure(record_id, _DUPLICATE_RECORD)
            except (OSError, TypeError, ValueError):
                _safe_unlink(temp_path)
                return EvidenceAppendFailure(record_id, _APPEND_FAILED)

        if not linked:
            return EvidenceAppendFailure(record_id, _APPEND_FAILED)
        return DurableAppendReceipt(
            schema_version=MINIMAL_EVIDENCE_SCHEMA_VERSION,
            record_id=record_id,
            record_kind=record_kind,
            durable_at=datetime.now(timezone.utc),
        )

    def _write(self, stream: object, encoded: str) -> None:
        stream.write(encoded)

    def _flush(self, stream: object) -> None:
        stream.flush()

    def _synchronize(self, descriptor: int) -> None:
        os.fsync(descriptor)

    def __repr__(self) -> str:
        return "MinimalPreExecutionEvidenceSink(local_append_only=True)"


def _safe_unlink(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _record_id_valid(value: object) -> bool:
    return (
        type(value) is str
        and value != ""
        and all(character.isalnum() or character in "-_." for character in value)
    )


def _identifier_valid(value: object, expected_type: type) -> bool:
    return (
        type(value) is expected_type
        and type(value.value) is str
        and value.value != ""
    )


def _common_record_valid(record: object) -> bool:
    return (
        type(record.schema_version) is str
        and record.schema_version == MINIMAL_EVIDENCE_SCHEMA_VERSION
        and _record_id_valid(record.record_id)
        and _identifier_valid(record.execution_id, ExecutionId)
        and _identifier_valid(record.prepared_call_id, PreparedCallId)
        and _identifier_valid(record.call_id, CallId)
        and _identifier_valid(record.decision_id, DecisionId)
        and _identifier_valid(record.invocation_id, InvocationId)
        and _identifier_valid(record.tool_id, ToolId)
        and _identifier_valid(record.policy_version, PolicyVersion)
        and _identifier_valid(record.registry_version, RegistryVersion)
        and _identifier_valid(record.adapter_id, AdapterId)
        and _identifier_valid(record.adapter_version, AdapterVersion)
        and type(record.public_integrity_id) is str
        and record.public_integrity_id.startswith("sha256:")
        and len(record.public_integrity_id) == 71
        and record.authorization_outcome is DecisionOutcome.ALLOW
        and record.authorization_rule_id is RuleId.AUTHORIZATION_ALLOW
        and type(record.occurred_at) is datetime
        and record.occurred_at.tzinfo is timezone.utc
        and type(record.producer_version) is str
        and record.producer_version == MINIMAL_EVIDENCE_PRODUCER_VERSION
    )


def _pre_execution_record_valid(record: object) -> bool:
    try:
        return type(record) is PreExecutionCorrelationRecord and _common_record_valid(
            record
        )
    except (AttributeError, TypeError, ValueError):
        return False


def _outcome_record_valid(record: object) -> bool:
    try:
        if type(record) is not ExecutionOutcomeRecord or not _common_record_valid(
            record
        ):
            return False
        if type(record.external_result_confirmed) is not bool:
            return False
        if record.execution_status is ExecutionOutcome.COMPLETED:
            return (
                record.external_result_confirmed is True
                and record.masked_failure_fact is None
            )
        return (
            record.execution_status is ExecutionOutcome.FAILED
            and type(record.masked_failure_fact) is str
            and record.masked_failure_fact in _FAILURE_FACTS
        )
    except (AttributeError, TypeError, ValueError):
        return False


def _common_primitive(record: object) -> dict:
    return {
        "schema_version": record.schema_version,
        "record_id": record.record_id,
        "execution_id": record.execution_id.value,
        "prepared_call_id": record.prepared_call_id.value,
        "call_id": record.call_id.value,
        "decision_id": record.decision_id.value,
        "invocation_id": record.invocation_id.value,
        "tool_id": record.tool_id.value,
        "policy_version": record.policy_version.value,
        "registry_version": record.registry_version.value,
        "adapter_id": record.adapter_id.value,
        "adapter_version": record.adapter_version.value,
        "public_integrity_id": record.public_integrity_id,
        "authorization_outcome": record.authorization_outcome.value,
        "authorization_rule_id": record.authorization_rule_id.value,
        "occurred_at": record.occurred_at.isoformat().replace("+00:00", "Z"),
        "producer_version": record.producer_version,
    }


def _pre_execution_primitive(record: PreExecutionCorrelationRecord) -> dict:
    return _common_primitive(record)


def _outcome_primitive(record: ExecutionOutcomeRecord) -> dict:
    primitive = _common_primitive(record)
    primitive.update(
        {
            "execution_status": record.execution_status.value,
            "external_result_confirmed": record.external_result_confirmed,
            "masked_failure_fact": record.masked_failure_fact,
        }
    )
    return primitive


__all__ = (
    "MINIMAL_EVIDENCE_PRODUCER_VERSION",
    "MINIMAL_EVIDENCE_SCHEMA_VERSION",
    "DurableAppendReceipt",
    "EvidenceAppendFailure",
    "EvidenceAppendResult",
    "ExecutionOutcomeRecord",
    "MinimalPreExecutionEvidenceSink",
    "PreExecutionCorrelationRecord",
)
