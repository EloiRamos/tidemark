"""Closed deterministic reconciliation findings for immutable evidence."""

from dataclasses import dataclass
from enum import Enum, unique
from hashlib import sha256
from typing import Dict, Iterable, Optional, Tuple, final

from tidemark.evidence.model import (
    AuditEvent,
    DecisionRecordedPayload,
    EvidenceEventType,
    EvidenceReconciledPayload,
    ModelNonAttemptPayload,
)
from tidemark.runtime.vocabulary import DecisionOutcome


@unique
class FindingDomain(str, Enum):
    INTEGRITY = "INTEGRITY"
    RECONCILIATION = "RECONCILIATION"
    MASKING = "MASKING"


@unique
class ReconciliationFindingCode(str, Enum):
    SCHEMA_GAP = "evidence.schema_gap.v1"
    NON_AUTHORITATIVE_RECORD = "evidence.non_authoritative_record.v1"
    MALFORMED_RECORD = "evidence.malformed_record.v1"
    DUPLICATE_EVENT_IDENTITY = "evidence.duplicate_event_identity.v1"
    SEQUENCE_GAP = "evidence.sequence_gap.v1"
    DIGEST_MISMATCH = "evidence.digest_mismatch.v1"
    EVENT_SCHEMA_INVALID = "evidence.event_schema_invalid.v1"
    FORBIDDEN_FIELD = "evidence.forbidden_field.v1"
    MASKING_VIOLATION = "evidence.masking_violation.v1"
    CORRELATION_MISMATCH = "evidence.correlation_mismatch.v1"
    ORPHAN_EVENT = "evidence.orphan_event.v1"
    MISSING_PREDECESSOR = "evidence.missing_predecessor.v1"
    MISSING_TERMINAL = "evidence.missing_terminal.v1"
    DUPLICATE_TERMINAL = "evidence.duplicate_terminal.v1"
    CONFLICTING_TERMINAL = "evidence.conflicting_terminal.v1"
    INVALID_TRANSITION = "evidence.invalid_transition.v1"
    DUPLICATE_SIDE_EFFECT = "evidence.duplicate_side_effect.v1"
    IMPOSSIBLE_SIDE_EFFECT = "evidence.impossible_side_effect.v1"
    REPLAY_INCONSISTENCY = "evidence.replay_inconsistency.v1"
    MODEL_NON_ATTEMPT_MISUSE = "evidence.model_non_attempt_misuse.v1"


_CODE_ORDER = {
    code: position for position, code in enumerate(ReconciliationFindingCode)
}

_INTEGRITY_CODES = {
    ReconciliationFindingCode.SCHEMA_GAP,
    ReconciliationFindingCode.NON_AUTHORITATIVE_RECORD,
    ReconciliationFindingCode.MALFORMED_RECORD,
    ReconciliationFindingCode.DUPLICATE_EVENT_IDENTITY,
    ReconciliationFindingCode.SEQUENCE_GAP,
    ReconciliationFindingCode.DIGEST_MISMATCH,
    ReconciliationFindingCode.EVENT_SCHEMA_INVALID,
}

_MASKING_CODES = {
    ReconciliationFindingCode.FORBIDDEN_FIELD,
    ReconciliationFindingCode.MASKING_VIOLATION,
}


@final
@dataclass(frozen=True)
class ReconciliationFinding:
    """One immutable non-secret integrity or trail finding."""

    code: ReconciliationFindingCode
    domain: FindingDomain
    sequence: int
    event_type: Optional[EvidenceEventType]
    location: str
    correlation_fingerprint: Optional[str]

    def __post_init__(self) -> None:
        if type(self.code) is not ReconciliationFindingCode:
            raise TypeError("finding code requires the closed vocabulary")
        if type(self.domain) is not FindingDomain:
            raise TypeError("finding domain requires FindingDomain")
        if type(self.sequence) is not int or self.sequence < 0:
            raise ValueError("finding sequence requires a non-negative int")
        if self.event_type is not None and type(self.event_type) is not EvidenceEventType:
            raise TypeError("finding event_type requires EvidenceEventType")
        if type(self.location) is not str or self.location == "":
            raise ValueError("finding location requires safe non-empty text")
        if self.correlation_fingerprint is not None and (
            type(self.correlation_fingerprint) is not str
            or not self.correlation_fingerprint.startswith("sha256:")
            or len(self.correlation_fingerprint) != 71
        ):
            raise ValueError("finding correlation requires a sha256 fingerprint")


@final
@dataclass(frozen=True)
class ReconciliationReport:
    findings: Tuple[ReconciliationFinding, ...]

    def __post_init__(self) -> None:
        if type(self.findings) is not tuple or any(
            type(item) is not ReconciliationFinding for item in self.findings
        ):
            raise TypeError("reconciliation findings require an exact tuple")

    @property
    def clean(self) -> bool:
        return not self.findings


def finding(
    code: ReconciliationFindingCode,
    *,
    sequence: int,
    event_type: Optional[EvidenceEventType],
    location: str,
    correlation: Optional[str] = None,
) -> ReconciliationFinding:
    if code in _MASKING_CODES:
        domain = FindingDomain.MASKING
    elif code in _INTEGRITY_CODES:
        domain = FindingDomain.INTEGRITY
    else:
        domain = FindingDomain.RECONCILIATION
    fingerprint = (
        None
        if correlation is None
        else "sha256:" + sha256(correlation.encode("utf-8")).hexdigest()
    )
    return ReconciliationFinding(
        code=code,
        domain=domain,
        sequence=sequence,
        event_type=event_type,
        location=location,
        correlation_fingerprint=fingerprint,
    )


def ordered_findings(
    values: Iterable[ReconciliationFinding],
) -> Tuple[ReconciliationFinding, ...]:
    unique_values = {
        (
            item.code,
            item.domain,
            item.sequence,
            item.event_type,
            item.location,
            item.correlation_fingerprint,
        ): item
        for item in values
    }
    return tuple(
        sorted(
            unique_values.values(),
            key=lambda item: (
                item.sequence,
                _CODE_ORDER[item.code],
                item.code.value,
                item.correlation_fingerprint or "",
                item.location,
            ),
        )
    )


def _value(identity: object) -> Optional[str]:
    value = getattr(identity, "value", None)
    return value if type(value) is str else None


def _event_sort_key(event: AuditEvent) -> tuple:
    return (
        event.trace_id,
        event.sequence,
        event.event_type.value,
        _value(event.invocation_id) or "",
        _value(event.call_id) or "",
        _value(event.decision_id) or "",
        _value(event.prepared_call_id) or "",
        _value(event.execution_id) or "",
    )


def _first(events: Tuple[AuditEvent, ...]) -> AuditEvent:
    return min(events, key=_event_sort_key)


def _event_types(
    events: Iterable[AuditEvent], event_type: EvidenceEventType
) -> Tuple[AuditEvent, ...]:
    return tuple(event for event in events if event.event_type is event_type)


def _semantic_tool_id(event: AuditEvent) -> Optional[str]:
    if event.event_type not in {
        EvidenceEventType.CALL_INTAKE_RECORDED,
        EvidenceEventType.DECISION_RECORDED,
        EvidenceEventType.CALLBACK_RECEIVED,
        EvidenceEventType.CALLBACK_VETOED,
        EvidenceEventType.CALLBACK_RELEASED,
        EvidenceEventType.CALLBACK_TOOL_ENTERED,
        EvidenceEventType.EXECUTION_STARTED,
    }:
        return None
    tool_id = getattr(event.payload, "tool_id", None)
    return _value(tool_id)


@final
class EvidenceReconciler:
    """Validate event-family transitions without changing source evidence."""

    __slots__ = ()

    def reconcile(
        self, event_stream: Tuple[AuditEvent, ...]
    ) -> ReconciliationReport:
        if type(event_stream) is not tuple or any(
            type(event) is not AuditEvent for event in event_stream
        ):
            raise TypeError("reconciliation requires exact authoritative events")
        events = tuple(
            sorted(
                event_stream,
                key=_event_sort_key,
            )
        )
        findings = []
        findings.extend(self._cross_trace_correlations(events))
        findings.extend(self._call_trails(events))
        findings.extend(self._execution_trails(events))
        findings.extend(self._prepared_trails(events))
        findings.extend(self._model_non_attempts(events))
        findings.extend(self._reconciliation_links(events))
        if events and not any(
            event.event_type
            not in {
                EvidenceEventType.EVIDENCE_RECONCILED,
                EvidenceEventType.EVIDENCE_EXPORT_FINALIZED,
            }
            for event in events
        ):
            event = _first(events)
            findings.append(
                finding(
                    ReconciliationFindingCode.MISSING_PREDECESSOR,
                    sequence=event.sequence,
                    event_type=event.event_type,
                    location="trail.authoritative_source",
                    correlation=event.trace_id,
                )
            )
        return ReconciliationReport(ordered_findings(findings))

    def _cross_trace_correlations(
        self, events: Tuple[AuditEvent, ...]
    ) -> Tuple[ReconciliationFinding, ...]:
        findings = []
        correlations = (
            ("invocation", "invocation_id"),
            ("call", "call_id"),
            ("decision", "decision_id"),
            ("prepared_call", "prepared_call_id"),
            ("execution", "execution_id"),
        )
        for label, attribute in correlations:
            grouped: Dict[str, list] = {}
            for event in events:
                identity = _value(getattr(event, attribute))
                if identity is not None:
                    grouped.setdefault(identity, []).append(event)
            for identity, correlated in grouped.items():
                if len({event.trace_id for event in correlated}) > 1:
                    event = _first(tuple(correlated))
                    findings.append(
                        finding(
                            ReconciliationFindingCode.CORRELATION_MISMATCH,
                            sequence=event.sequence,
                            event_type=event.event_type,
                            location=f"correlation.{label}.trace",
                            correlation=identity,
                        )
                    )
        return tuple(findings)

    def _call_trails(
        self, events: Tuple[AuditEvent, ...]
    ) -> Tuple[ReconciliationFinding, ...]:
        findings = []
        grouped: Dict[str, list] = {}
        for event in events:
            call_id = _value(event.call_id)
            if call_id is not None:
                grouped.setdefault(call_id, []).append(event)
        for call_id, values in grouped.items():
            call_events = tuple(sorted(values, key=lambda event: event.sequence))
            intakes = _event_types(call_events, EvidenceEventType.CALL_INTAKE_RECORDED)
            refusals = _event_types(call_events, EvidenceEventType.CALL_PREPARATION_REFUSED)
            decisions = _event_types(call_events, EvidenceEventType.DECISION_RECORDED)
            received = _event_types(call_events, EvidenceEventType.CALLBACK_RECEIVED)
            vetoed = _event_types(call_events, EvidenceEventType.CALLBACK_VETOED)
            released = _event_types(call_events, EvidenceEventType.CALLBACK_RELEASED)
            entered = _event_types(call_events, EvidenceEventType.CALLBACK_TOOL_ENTERED)
            starts = _event_types(call_events, EvidenceEventType.EXECUTION_STARTED)
            payments = _event_types(call_events, EvidenceEventType.PAYMENT_RECORDED)

            continuity = (
                ("invocation", "invocation_id"),
                ("policy_version", "policy_version"),
                ("registry_version", "registry_version"),
            )
            for label, attribute in continuity:
                correlated_values = {
                    _value(getattr(event, attribute))
                    for event in call_events
                    if getattr(event, attribute) is not None
                }
                if len(correlated_values) > 1:
                    event = _first(call_events)
                    findings.append(
                        finding(
                            ReconciliationFindingCode.CORRELATION_MISMATCH,
                            sequence=event.sequence,
                            event_type=event.event_type,
                            location=f"call.{label}_continuity",
                            correlation=call_id,
                        )
                    )
            tool_ids = {
                tool_id
                for tool_id in (_semantic_tool_id(event) for event in call_events)
                if tool_id is not None
            }
            if len(tool_ids) > 1:
                event = _first(call_events)
                findings.append(
                    finding(
                        ReconciliationFindingCode.CORRELATION_MISMATCH,
                        sequence=event.sequence,
                        event_type=event.event_type,
                        location="call.tool_continuity",
                        correlation=call_id,
                    )
                )

            if (decisions or refusals) and not intakes:
                event = _first(decisions or refusals)
                findings.append(
                    finding(
                        ReconciliationFindingCode.MISSING_PREDECESSOR,
                        sequence=event.sequence,
                        event_type=event.event_type,
                        location="call.intake_recorded",
                        correlation=call_id,
                    )
                )
            if len(intakes) > 1:
                event = intakes[1]
                findings.append(
                    finding(
                        ReconciliationFindingCode.INVALID_TRANSITION,
                        sequence=event.sequence,
                        event_type=event.event_type,
                        location="call.duplicate_intake",
                        correlation=call_id,
                    )
                )
            if len(decisions) > 1:
                event = decisions[1]
                findings.append(
                    finding(
                        ReconciliationFindingCode.DUPLICATE_TERMINAL,
                        sequence=event.sequence,
                        event_type=event.event_type,
                        location="call.authorization_decision",
                        correlation=call_id,
                    )
                )
            if decisions and refusals:
                event = _first(decisions + refusals)
                findings.append(
                    finding(
                        ReconciliationFindingCode.CONFLICTING_TERMINAL,
                        sequence=event.sequence,
                        event_type=event.event_type,
                        location="call.refusal_or_decision",
                        correlation=call_id,
                    )
                )
            if intakes and decisions and decisions[0].sequence < intakes[0].sequence:
                findings.append(
                    finding(
                        ReconciliationFindingCode.INVALID_TRANSITION,
                        sequence=decisions[0].sequence,
                        event_type=decisions[0].event_type,
                        location="call.decision_before_intake",
                        correlation=call_id,
                    )
                )
            if received and intakes and intakes[0].sequence < received[0].sequence:
                findings.append(
                    finding(
                        ReconciliationFindingCode.INVALID_TRANSITION,
                        sequence=intakes[0].sequence,
                        event_type=intakes[0].event_type,
                        location="callback.intake_before_receipt",
                        correlation=call_id,
                    )
                )
            if intakes and refusals and refusals[0].sequence < intakes[0].sequence:
                findings.append(
                    finding(
                        ReconciliationFindingCode.INVALID_TRANSITION,
                        sequence=refusals[0].sequence,
                        event_type=refusals[0].event_type,
                        location="call.refusal_before_intake",
                        correlation=call_id,
                    )
                )
            if vetoed and entered:
                event = _first(vetoed + entered)
                findings.append(
                    finding(
                        ReconciliationFindingCode.INVALID_TRANSITION,
                        sequence=event.sequence,
                        event_type=event.event_type,
                        location="callback.veto_then_tool_entry",
                        correlation=call_id,
                    )
                )
            if entered and not released:
                event = entered[0]
                findings.append(
                    finding(
                        ReconciliationFindingCode.MISSING_PREDECESSOR,
                        sequence=event.sequence,
                        event_type=event.event_type,
                        location="callback.released",
                        correlation=call_id,
                    )
                )
            if released and entered and entered[0].sequence < released[0].sequence:
                findings.append(
                    finding(
                        ReconciliationFindingCode.INVALID_TRANSITION,
                        sequence=entered[0].sequence,
                        event_type=entered[0].event_type,
                        location="callback.tool_entry_before_release",
                        correlation=call_id,
                    )
                )
            if len(released) > 1 or len(entered) > 1 or len(vetoed) > 1:
                repeated = (
                    (released[1] if len(released) > 1 else None)
                    or (entered[1] if len(entered) > 1 else None)
                    or vetoed[1]
                )
                findings.append(
                    finding(
                        ReconciliationFindingCode.DUPLICATE_TERMINAL,
                        sequence=repeated.sequence,
                        event_type=repeated.event_type,
                        location="callback.duplicate_transition",
                        correlation=call_id,
                    )
                )

            decision_event = decisions[0] if len(decisions) == 1 else None
            decision_payload = (
                decision_event.payload
                if decision_event is not None
                and type(decision_event.payload) is DecisionRecordedPayload
                else None
            )
            if decision_payload is not None:
                expected_decision_id = _value(decision_event.decision_id)
                mismatched_decision = tuple(
                    event
                    for event in call_events
                    if event is not decision_event
                    and event.decision_id is not None
                    and _value(event.decision_id) != expected_decision_id
                )
                if mismatched_decision:
                    event = mismatched_decision[0]
                    findings.append(
                        finding(
                            ReconciliationFindingCode.CORRELATION_MISMATCH,
                            sequence=event.sequence,
                            event_type=event.event_type,
                            location="authorization.decision_continuity",
                            correlation=call_id,
                        )
                    )
                if decision_payload.outcome is DecisionOutcome.DENY:
                    if starts or released or entered:
                        event = _first(starts + released + entered)
                        findings.append(
                            finding(
                                ReconciliationFindingCode.INVALID_TRANSITION,
                                sequence=event.sequence,
                                event_type=event.event_type,
                                location="authorization.deny_execution",
                                correlation=call_id,
                            )
                        )
                    if payments:
                        event = payments[0]
                        findings.append(
                            finding(
                                ReconciliationFindingCode.IMPOSSIBLE_SIDE_EFFECT,
                                sequence=event.sequence,
                                event_type=event.event_type,
                                location="authorization.deny_payment",
                                correlation=call_id,
                            )
                        )
                    if received and not vetoed:
                        findings.append(
                            finding(
                                ReconciliationFindingCode.MISSING_TERMINAL,
                                sequence=decision_event.sequence,
                                event_type=decision_event.event_type,
                                location="callback.vetoed",
                                correlation=call_id,
                            )
                        )
                elif decision_payload.outcome is DecisionOutcome.ALLOW:
                    if decision_event.prepared_call_id is None:
                        findings.append(
                            finding(
                                ReconciliationFindingCode.CORRELATION_MISMATCH,
                                sequence=decision_event.sequence,
                                event_type=decision_event.event_type,
                                location="authorization.allow_prepared_call",
                                correlation=call_id,
                            )
                        )
                    expected_prepared_id = _value(
                        decision_event.prepared_call_id
                    )
                    mismatched_prepared = tuple(
                        event
                        for event in call_events
                        if event is not decision_event
                        and event.prepared_call_id is not None
                        and _value(event.prepared_call_id)
                        != expected_prepared_id
                    )
                    if mismatched_prepared:
                        event = mismatched_prepared[0]
                        findings.append(
                            finding(
                                ReconciliationFindingCode.CORRELATION_MISMATCH,
                                sequence=event.sequence,
                                event_type=event.event_type,
                                location="authorization.prepared_call_continuity",
                                correlation=call_id,
                            )
                        )
                    if vetoed:
                        findings.append(
                            finding(
                                ReconciliationFindingCode.INVALID_TRANSITION,
                                sequence=vetoed[0].sequence,
                                event_type=vetoed[0].event_type,
                                location="authorization.allow_callback_veto",
                                correlation=call_id,
                            )
                        )
                    if starts and starts[0].sequence < decision_event.sequence:
                        findings.append(
                            finding(
                                ReconciliationFindingCode.INVALID_TRANSITION,
                                sequence=starts[0].sequence,
                                event_type=starts[0].event_type,
                                location="execution.start_before_allow",
                                correlation=call_id,
                            )
                        )
                    if received and not released:
                        findings.append(
                            finding(
                                ReconciliationFindingCode.MISSING_PREDECESSOR,
                                sequence=decision_event.sequence,
                                event_type=decision_event.event_type,
                                location="callback.released",
                                correlation=call_id,
                            )
                        )
                    terminal_evidence = tuple(
                        event
                        for event in call_events
                        if event.event_type
                        in {
                            EvidenceEventType.EXECUTION_REFUSED,
                            EvidenceEventType.EXECUTION_STARTED,
                            EvidenceEventType.EXECUTION_REPLAY_REJECTED,
                        }
                    )
                    if not terminal_evidence:
                        findings.append(
                            finding(
                                ReconciliationFindingCode.MISSING_TERMINAL,
                                sequence=decision_event.sequence,
                                event_type=decision_event.event_type,
                                location="authorization.allow_execution_outcome",
                                correlation=call_id,
                            )
                        )
                    completed = _event_types(
                        call_events, EvidenceEventType.EXECUTION_COMPLETED
                    )
                    if (
                        decision_payload.tool_id.value == "schedule_payment"
                        and completed
                        and not payments
                    ):
                        findings.append(
                            finding(
                                ReconciliationFindingCode.MISSING_TERMINAL,
                                sequence=completed[0].sequence,
                                event_type=completed[0].event_type,
                                location="payment.recorded",
                                correlation=call_id,
                            )
                        )

            if refusals:
                prohibited = decisions + starts + payments + released + entered
                if prohibited:
                    event = _first(prohibited)
                    findings.append(
                        finding(
                            ReconciliationFindingCode.INVALID_TRANSITION,
                            sequence=event.sequence,
                            event_type=event.event_type,
                            location="call.refusal_later_authority",
                            correlation=call_id,
                        )
                    )
                if received and not vetoed:
                    findings.append(
                        finding(
                            ReconciliationFindingCode.MISSING_TERMINAL,
                            sequence=refusals[0].sequence,
                            event_type=refusals[0].event_type,
                            location="callback.vetoed",
                            correlation=call_id,
                        )
                    )

            if intakes and not decisions and not refusals:
                event = intakes[0]
                findings.append(
                    finding(
                        ReconciliationFindingCode.MISSING_TERMINAL,
                        sequence=event.sequence,
                        event_type=event.event_type,
                        location="call.decision_or_refusal",
                        correlation=call_id,
                    )
                )
        return tuple(findings)

    def _execution_trails(
        self, events: Tuple[AuditEvent, ...]
    ) -> Tuple[ReconciliationFinding, ...]:
        findings = []
        grouped: Dict[str, list] = {}
        for event in events:
            execution_id = _value(event.execution_id)
            if execution_id is not None:
                grouped.setdefault(execution_id, []).append(event)
        for execution_id, values in grouped.items():
            execution_events = tuple(sorted(values, key=lambda event: event.sequence))
            starts = _event_types(execution_events, EvidenceEventType.EXECUTION_STARTED)
            completed = _event_types(execution_events, EvidenceEventType.EXECUTION_COMPLETED)
            failed = _event_types(execution_events, EvidenceEventType.EXECUTION_FAILED)
            refused = _event_types(execution_events, EvidenceEventType.EXECUTION_REFUSED)
            replayed = _event_types(execution_events, EvidenceEventType.EXECUTION_REPLAY_REJECTED)
            payments = _event_types(execution_events, EvidenceEventType.PAYMENT_RECORDED)
            terminals = completed + failed

            semantic_correlations = (
                ("invocation", "invocation_id"),
                ("call", "call_id"),
                ("decision", "decision_id"),
                ("prepared_call", "prepared_call_id"),
            )
            for label, attribute in semantic_correlations:
                values_for_kind = {
                    _value(getattr(event, attribute)) for event in execution_events
                }
                values_for_kind.discard(None)
                if len(values_for_kind) > 1:
                    event = _first(execution_events)
                    findings.append(
                        finding(
                            ReconciliationFindingCode.CORRELATION_MISMATCH,
                            sequence=event.sequence,
                            event_type=event.event_type,
                            location=f"execution.{label}",
                            correlation=execution_id,
                        )
                    )
            if terminals and not starts:
                event = _first(terminals)
                findings.extend(
                    (
                        finding(
                            ReconciliationFindingCode.ORPHAN_EVENT,
                            sequence=event.sequence,
                            event_type=event.event_type,
                            location="execution.terminal_without_start",
                            correlation=execution_id,
                        ),
                        finding(
                            ReconciliationFindingCode.MISSING_PREDECESSOR,
                            sequence=event.sequence,
                            event_type=event.event_type,
                            location="execution.started",
                            correlation=execution_id,
                        ),
                    )
                )
            if payments and not starts:
                event = payments[0]
                findings.append(
                    finding(
                        ReconciliationFindingCode.ORPHAN_EVENT,
                        sequence=event.sequence,
                        event_type=event.event_type,
                        location="payment.execution_started",
                        correlation=execution_id,
                    )
                )
            if starts and not terminals:
                event = starts[0]
                findings.append(
                    finding(
                        ReconciliationFindingCode.MISSING_TERMINAL,
                        sequence=event.sequence,
                        event_type=event.event_type,
                        location="execution.completed_or_failed",
                        correlation=execution_id,
                    )
                )
            if len(completed) > 1 or len(failed) > 1:
                repeated = completed[1] if len(completed) > 1 else failed[1]
                findings.append(
                    finding(
                        ReconciliationFindingCode.DUPLICATE_TERMINAL,
                        sequence=repeated.sequence,
                        event_type=repeated.event_type,
                        location="execution.duplicate_terminal",
                        correlation=execution_id,
                    )
                )
            if completed and failed:
                event = _first(completed + failed)
                findings.append(
                    finding(
                        ReconciliationFindingCode.CONFLICTING_TERMINAL,
                        sequence=event.sequence,
                        event_type=event.event_type,
                        location="execution.completed_and_failed",
                        correlation=execution_id,
                    )
                )
            if refused and starts:
                event = _first(refused + starts)
                findings.append(
                    finding(
                        ReconciliationFindingCode.INVALID_TRANSITION,
                        sequence=event.sequence,
                        event_type=event.event_type,
                        location="execution.refused_and_started",
                        correlation=execution_id,
                    )
                )
            if replayed and starts:
                event = _first(replayed + starts)
                findings.append(
                    finding(
                        ReconciliationFindingCode.INVALID_TRANSITION,
                        sequence=event.sequence,
                        event_type=event.event_type,
                        location="execution.replay_attempt_started",
                        correlation=execution_id,
                    )
                )
            if starts and terminals and _first(terminals).sequence < starts[0].sequence:
                event = _first(terminals)
                findings.append(
                    finding(
                        ReconciliationFindingCode.INVALID_TRANSITION,
                        sequence=event.sequence,
                        event_type=event.event_type,
                        location="execution.terminal_before_start",
                        correlation=execution_id,
                    )
                )
            if payments and starts:
                first_terminal_sequence = (
                    _first(terminals).sequence if terminals else starts[0].sequence
                )
                if payments[0].sequence < first_terminal_sequence:
                    findings.append(
                        finding(
                            ReconciliationFindingCode.INVALID_TRANSITION,
                            sequence=payments[0].sequence,
                            event_type=payments[0].event_type,
                            location="payment.before_execution_terminal",
                            correlation=execution_id,
                        )
                    )
        return tuple(findings)

    def _prepared_trails(
        self, events: Tuple[AuditEvent, ...]
    ) -> Tuple[ReconciliationFinding, ...]:
        findings = []
        grouped: Dict[str, list] = {}
        for event in events:
            prepared_id = _value(event.prepared_call_id)
            if prepared_id is not None:
                grouped.setdefault(prepared_id, []).append(event)
        for prepared_id, values in grouped.items():
            prepared_events = tuple(sorted(values, key=lambda event: event.sequence))
            starts = _event_types(prepared_events, EvidenceEventType.EXECUTION_STARTED)
            replays = _event_types(
                prepared_events, EvidenceEventType.EXECUTION_REPLAY_REJECTED
            )
            payments = _event_types(prepared_events, EvidenceEventType.PAYMENT_RECORDED)
            decisions = _event_types(prepared_events, EvidenceEventType.DECISION_RECORDED)
            if starts and not decisions:
                findings.extend(
                    (
                        finding(
                            ReconciliationFindingCode.ORPHAN_EVENT,
                            sequence=starts[0].sequence,
                            event_type=starts[0].event_type,
                            location="execution.prepared_decision_lineage",
                            correlation=prepared_id,
                        ),
                        finding(
                            ReconciliationFindingCode.MISSING_PREDECESSOR,
                            sequence=starts[0].sequence,
                            event_type=starts[0].event_type,
                            location="execution.allow_decision",
                            correlation=prepared_id,
                        ),
                    )
                )
            if len(starts) > 1:
                findings.append(
                    finding(
                        ReconciliationFindingCode.REPLAY_INCONSISTENCY,
                        sequence=starts[1].sequence,
                        event_type=starts[1].event_type,
                        location="prepared_call.second_execution_start",
                        correlation=prepared_id,
                    )
                )
            if len(payments) > 1:
                findings.append(
                    finding(
                        ReconciliationFindingCode.DUPLICATE_SIDE_EFFECT,
                        sequence=payments[1].sequence,
                        event_type=payments[1].event_type,
                        location="prepared_call.duplicate_payment",
                        correlation=prepared_id,
                    )
                )
            for replay in replays:
                prior_context = tuple(
                    event
                    for event in prepared_events
                    if event.sequence < replay.sequence
                    and event.event_type
                    in {
                        EvidenceEventType.EXECUTION_STARTED,
                        EvidenceEventType.EXECUTION_COMPLETED,
                        EvidenceEventType.EXECUTION_FAILED,
                    }
                )
                if not prior_context:
                    findings.append(
                        finding(
                            ReconciliationFindingCode.ORPHAN_EVENT,
                            sequence=replay.sequence,
                            event_type=replay.event_type,
                            location="replay.prior_execution",
                            correlation=prepared_id,
                        )
                    )
                if any(start.sequence > replay.sequence for start in starts):
                    findings.append(
                        finding(
                            ReconciliationFindingCode.REPLAY_INCONSISTENCY,
                            sequence=replay.sequence,
                            event_type=replay.event_type,
                            location="replay.followed_by_execution_start",
                            correlation=prepared_id,
                        )
                    )
        return tuple(findings)

    def _model_non_attempts(
        self, events: Tuple[AuditEvent, ...]
    ) -> Tuple[ReconciliationFinding, ...]:
        findings = []
        non_attempts = _event_types(events, EvidenceEventType.RUN_MODEL_NON_ATTEMPT)
        for non_attempt in non_attempts:
            invocation_id = _value(non_attempt.invocation_id)
            coexisting = tuple(
                event
                for event in events
                if event is not non_attempt
                and _value(event.invocation_id) == invocation_id
                and event.event_type
                not in {
                    EvidenceEventType.EVIDENCE_RECONCILED,
                    EvidenceEventType.EVIDENCE_EXPORT_FINALIZED,
                }
            )
            if coexisting:
                findings.append(
                    finding(
                        ReconciliationFindingCode.MODEL_NON_ATTEMPT_MISUSE,
                        sequence=non_attempt.sequence,
                        event_type=non_attempt.event_type,
                        location="model_non_attempt.coexisting_runtime_trail",
                        correlation=invocation_id,
                    )
                )
            if type(non_attempt.payload) is not ModelNonAttemptPayload:
                findings.append(
                    finding(
                        ReconciliationFindingCode.EVENT_SCHEMA_INVALID,
                        sequence=non_attempt.sequence,
                        event_type=non_attempt.event_type,
                        location="model_non_attempt.payload",
                        correlation=invocation_id,
                    )
                )
        return tuple(findings)

    def _reconciliation_links(
        self, events: Tuple[AuditEvent, ...]
    ) -> Tuple[ReconciliationFinding, ...]:
        findings = []
        by_id = {event.event_id: event for event in events}
        reconciliations = _event_types(
            events, EvidenceEventType.EVIDENCE_RECONCILED
        )
        for event in reconciliations:
            if type(event.payload) is not EvidenceReconciledPayload:
                continue
            missing = tuple(
                related_id
                for related_id in event.payload.related_event_ids
                if related_id not in by_id
            )
            if missing:
                findings.append(
                    finding(
                        ReconciliationFindingCode.ORPHAN_EVENT,
                        sequence=event.sequence,
                        event_type=event.event_type,
                        location="reconciliation.related_event",
                        correlation=event.trace_id,
                    )
                )
            recursive = tuple(
                related_id
                for related_id in event.payload.related_event_ids
                if related_id == event.event_id
                or (
                    related_id in by_id
                    and by_id[related_id].event_type
                    is EvidenceEventType.EVIDENCE_RECONCILED
                )
            )
            if recursive:
                findings.append(
                    finding(
                        ReconciliationFindingCode.INVALID_TRANSITION,
                        sequence=event.sequence,
                        event_type=event.event_type,
                        location="reconciliation.recursive_link",
                        correlation=event.trace_id,
                    )
                )
        return tuple(findings)

    def __repr__(self) -> str:
        return "EvidenceReconciler(read_only=True, repairs=False)"


__all__ = (
    "EvidenceReconciler",
    "FindingDomain",
    "ReconciliationFinding",
    "ReconciliationFindingCode",
    "ReconciliationReport",
)
