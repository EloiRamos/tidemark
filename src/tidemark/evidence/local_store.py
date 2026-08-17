"""Durable bounded append-only local storage for immutable audit events."""

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
from secrets import token_hex
from threading import Lock
from typing import Dict, Optional, Tuple, final

from tidemark.evidence.canonical import canonical_json_text
from tidemark.evidence.model import (
    AuditEvent,
    RetainedAuditEvent,
    StoredAuditEvent,
    audit_event_from_primitive,
    audit_event_to_primitive,
)
from tidemark.runtime.identifiers import (
    CallId,
    DecisionId,
    ExecutionId,
    InvocationId,
    PreparedCallId,
)


class EvidenceStoreError(RuntimeError):
    """Base class for fail-closed local evidence storage errors."""


class EvidenceDurabilityError(EvidenceStoreError):
    """The event did not complete the local durable append protocol."""


class DuplicateEventError(EvidenceStoreError):
    """An event identity already exists and cannot be overwritten."""


class InvalidTraceSequenceError(EvidenceStoreError):
    """An event does not carry the exact next sequence for its trace."""


class EvidenceStoreCorruptionError(EvidenceStoreError):
    """A persisted record is malformed, torn, or inconsistent."""


@final
@dataclass(frozen=True)
class AppendReceipt:
    """Immutable confirmation returned only after file and directory sync."""

    event_id: str
    event_type: str
    trace_id: str
    sequence: int
    event_digest: str
    durable_at: datetime

    def __post_init__(self) -> None:
        if type(self.event_id) is not str or self.event_id == "":
            raise ValueError("receipt event_id is invalid")
        if type(self.event_type) is not str or self.event_type == "":
            raise ValueError("receipt event_type is invalid")
        if type(self.trace_id) is not str or self.trace_id == "":
            raise ValueError("receipt trace_id is invalid")
        if type(self.sequence) is not int or self.sequence < 1:
            raise ValueError("receipt sequence is invalid")
        if (
            type(self.event_digest) is not str
            or not self.event_digest.startswith("sha256:")
            or len(self.event_digest) != 71
        ):
            raise ValueError("receipt digest is invalid")
        if (
            type(self.durable_at) is not datetime
            or self.durable_at.tzinfo is not timezone.utc
        ):
            raise ValueError("receipt durable_at requires UTC")


@final
class LocalAuditStore:
    """One store-owned directory with append and read-only query surfaces."""

    __slots__ = (
        "_by_id",
        "_digests",
        "_events_root",
        "_lock",
        "_ordered",
    )

    def __init__(self, root_path: str) -> None:
        if type(root_path) is not str or root_path == "":
            raise ValueError("root_path requires an exact non-empty string")
        root = Path(root_path)
        events_root = root / "events"
        try:
            events_root.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise EvidenceDurabilityError("evidence store create failed") from error
        if not events_root.is_dir():
            raise EvidenceDurabilityError("evidence store path is not a directory")
        self._events_root = events_root
        self._lock = Lock()
        self._by_id: Dict[str, StoredAuditEvent] = {}
        self._digests: Dict[str, str] = {}
        self._ordered: Tuple[StoredAuditEvent, ...] = ()
        self._load()

    def append(self, event: StoredAuditEvent) -> AppendReceipt:
        """Append one exact immutable event; never replace an existing event."""

        if type(event) not in (AuditEvent, RetainedAuditEvent):
            raise TypeError("append requires an exact immutable evidence event")
        primitive = audit_event_to_primitive(event)
        stored_event = audit_event_from_primitive(primitive)
        encoded = canonical_json_text(primitive, trailing_newline=True)
        digest = "sha256:" + sha256(encoded.encode("utf-8")).hexdigest()
        filename = sha256(event.event_id.encode("utf-8")).hexdigest() + ".json"
        final_path = self._events_root / filename
        temp_path = self._events_root / ("." + token_hex(32) + ".tmp")

        with self._lock:
            if event.event_id in self._by_id or final_path.exists():
                raise DuplicateEventError("duplicate evidence event identity")
            expected_sequence = self._next_sequence_unlocked(event.trace_id)
            if event.sequence != expected_sequence:
                raise InvalidTraceSequenceError("event trace sequence is not next")
            previous = self._last_digest_unlocked(event.trace_id)
            if (
                event.previous_event_digest is not None
                and event.previous_event_digest != previous
            ):
                raise InvalidTraceSequenceError("previous event digest does not match")
            linked = False
            try:
                with self._open_temp(temp_path) as stream:
                    written = self._write(stream, encoded)
                    if written != len(encoded):
                        raise OSError("partial evidence write")
                    self._flush(stream)
                    self._synchronize(stream.fileno())
                os.link(str(temp_path), str(final_path))
                linked = True
                temp_path.unlink()
                descriptor = self._open_directory()
                try:
                    self._synchronize(descriptor)
                finally:
                    os.close(descriptor)
            except FileExistsError as error:
                self._safe_unlink(temp_path)
                raise DuplicateEventError(
                    "duplicate evidence event identity"
                ) from error
            except (OSError, TypeError, ValueError) as error:
                self._safe_unlink(temp_path)
                if linked:
                    self._safe_unlink(final_path)
                    self._best_effort_sync_directory()
                raise EvidenceDurabilityError(
                    "evidence event was not durably appended"
                ) from error

            self._by_id[event.event_id] = stored_event
            self._digests[event.event_id] = digest
            self._ordered = self._ordered + (stored_event,)

        event_type = (
            event.event_type.value
            if type(event) is AuditEvent
            else event.event_type
        )
        return AppendReceipt(
            event_id=event.event_id,
            event_type=event_type,
            trace_id=event.trace_id,
            sequence=event.sequence,
            event_digest=digest,
            durable_at=datetime.now(timezone.utc),
        )

    def event_by_id(self, event_id: str) -> Optional[StoredAuditEvent]:
        if type(event_id) is not str or event_id == "":
            raise ValueError("event_id requires an exact non-empty string")
        with self._lock:
            event = self._by_id.get(event_id)
            return _detached(event) if event is not None else None

    def events_for_trace(self, trace_id: str) -> Tuple[StoredAuditEvent, ...]:
        if type(trace_id) is not str or trace_id == "":
            raise ValueError("trace_id requires an exact non-empty string")
        return self._matching("trace_id", trace_id)

    def events_for_invocation(
        self, invocation_id: InvocationId
    ) -> Tuple[StoredAuditEvent, ...]:
        if type(invocation_id) is not InvocationId:
            raise TypeError("invocation_id requires InvocationId")
        return self._matching("invocation_id", invocation_id)

    def events_for_call(self, call_id: CallId) -> Tuple[StoredAuditEvent, ...]:
        if type(call_id) is not CallId:
            raise TypeError("call_id requires CallId")
        return self._matching("call_id", call_id)

    def events_for_decision(
        self, decision_id: DecisionId
    ) -> Tuple[StoredAuditEvent, ...]:
        if type(decision_id) is not DecisionId:
            raise TypeError("decision_id requires DecisionId")
        return self._matching("decision_id", decision_id)

    def events_for_prepared_call(
        self, prepared_call_id: PreparedCallId
    ) -> Tuple[StoredAuditEvent, ...]:
        if type(prepared_call_id) is not PreparedCallId:
            raise TypeError("prepared_call_id requires PreparedCallId")
        return self._matching("prepared_call_id", prepared_call_id)

    def events_for_execution(
        self, execution_id: ExecutionId
    ) -> Tuple[StoredAuditEvent, ...]:
        if type(execution_id) is not ExecutionId:
            raise TypeError("execution_id requires ExecutionId")
        return self._matching("execution_id", execution_id)

    def ordered_events(self) -> Tuple[StoredAuditEvent, ...]:
        with self._lock:
            selected = tuple(
                sorted(
                    self._ordered,
                    key=lambda event: (event.trace_id, event.sequence),
                )
            )
        return tuple(_detached(event) for event in selected)

    def next_sequence(self, trace_id: str) -> int:
        if type(trace_id) is not str or trace_id == "":
            raise ValueError("trace_id requires an exact non-empty string")
        with self._lock:
            return self._next_sequence_unlocked(trace_id)

    def last_event_digest(self, trace_id: str) -> Optional[str]:
        if type(trace_id) is not str or trace_id == "":
            raise ValueError("trace_id requires an exact non-empty string")
        with self._lock:
            return self._last_digest_unlocked(trace_id)

    def _matching(self, name: str, value: object) -> Tuple[StoredAuditEvent, ...]:
        with self._lock:
            selected = tuple(
                event for event in self._ordered if getattr(event, name) == value
            )
        return tuple(
            _detached(event)
            for event in sorted(
                selected, key=lambda event: (event.trace_id, event.sequence)
            )
        )

    def _next_sequence_unlocked(self, trace_id: str) -> int:
        sequences = tuple(
            event.sequence for event in self._ordered if event.trace_id == trace_id
        )
        return (max(sequences) + 1) if sequences else 1

    def _last_digest_unlocked(self, trace_id: str) -> Optional[str]:
        candidates = tuple(
            event for event in self._ordered if event.trace_id == trace_id
        )
        if not candidates:
            return None
        last = max(candidates, key=lambda event: event.sequence)
        return self._digests[last.event_id]

    def _load(self) -> None:
        loaded = []
        digests = {}
        by_id = {}
        try:
            paths = tuple(self._events_root.glob("*.json"))
            for path in paths:
                encoded = path.read_text(encoding="utf-8")
                if not encoded.endswith("\n") or encoded.count("\n") != 1:
                    raise EvidenceStoreCorruptionError("persisted evidence is torn")
                primitive = json.loads(encoded)
                event = audit_event_from_primitive(primitive)
                canonical = canonical_json_text(
                    audit_event_to_primitive(event), trailing_newline=True
                )
                if canonical != encoded:
                    raise EvidenceStoreCorruptionError(
                        "persisted evidence is not canonical"
                    )
                expected_name = sha256(event.event_id.encode("utf-8")).hexdigest() + ".json"
                if path.name != expected_name or event.event_id in by_id:
                    raise EvidenceStoreCorruptionError(
                        "persisted evidence identity is inconsistent"
                    )
                by_id[event.event_id] = event
                digests[event.event_id] = "sha256:" + sha256(encoded.encode("utf-8")).hexdigest()
                loaded.append(event)
        except EvidenceStoreCorruptionError:
            raise
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise EvidenceStoreCorruptionError("persisted evidence is malformed") from error

        ordered = tuple(sorted(loaded, key=lambda event: (event.trace_id, event.sequence)))
        by_trace = {}
        for event in ordered:
            expected = by_trace.get(event.trace_id, 0) + 1
            if event.sequence != expected:
                raise EvidenceStoreCorruptionError("persisted trace sequence has a gap")
            previous = None
            prior_events = tuple(
                candidate
                for candidate in ordered
                if candidate.trace_id == event.trace_id
                and candidate.sequence == event.sequence - 1
            )
            if prior_events:
                previous = digests[prior_events[0].event_id]
            if event.previous_event_digest is not None and event.previous_event_digest != previous:
                raise EvidenceStoreCorruptionError("persisted digest chain differs")
            by_trace[event.trace_id] = event.sequence
        self._by_id = by_id
        self._digests = digests
        self._ordered = tuple(loaded)

    def _open_temp(self, path: Path):
        return path.open("x", encoding="utf-8", newline="\n")

    def _write(self, stream: object, encoded: str) -> int:
        return stream.write(encoded)

    def _flush(self, stream: object) -> None:
        stream.flush()

    def _synchronize(self, descriptor: int) -> None:
        os.fsync(descriptor)

    def _open_directory(self) -> int:
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        return os.open(str(self._events_root), flags)

    def _best_effort_sync_directory(self) -> None:
        try:
            descriptor = self._open_directory()
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError:
            pass

    @staticmethod
    def _safe_unlink(path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    def __repr__(self) -> str:
        return (
            "LocalAuditStore(append_only=True, "
            f"event_count={len(self.ordered_events())})"
        )


def _detached(event: StoredAuditEvent) -> StoredAuditEvent:
    return audit_event_from_primitive(audit_event_to_primitive(event))


__all__ = (
    "AppendReceipt",
    "DuplicateEventError",
    "EvidenceDurabilityError",
    "EvidenceStoreCorruptionError",
    "EvidenceStoreError",
    "InvalidTraceSequenceError",
    "LocalAuditStore",
)
