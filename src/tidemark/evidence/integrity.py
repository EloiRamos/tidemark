"""Read-only structural and masking review for persisted evidence."""

from dataclasses import dataclass, fields
from hashlib import sha256
from typing import Dict, Optional, Tuple, final

from tidemark.evidence.canonical import canonical_json_bytes
from tidemark.evidence.model import (
    EVIDENCE_SCHEMA_VERSION,
    ArgumentProjection,
    ArgumentShape,
    AuditEvent,
    CallbackPayload,
    CallIntakeRecordedPayload,
    CallPreparationRefusedPayload,
    DecisionRecordedPayload,
    DecisionRuleResult,
    EvidenceEventType,
    EvidenceExportFinalizedPayload,
    EvidenceReconciledPayload,
    ExecutionRefusedPayload,
    ExecutionReplayRejectedPayload,
    ExecutionStartedPayload,
    ExecutionTerminalPayload,
    MaskedReasonFact,
    ModelNonAttemptPayload,
    PaymentRecordedPayload,
    PolicyInstallationRefusedPayload,
    RetainedAuditEvent,
    StoredAuditEvent,
    audit_event_from_primitive,
    audit_event_to_primitive,
)
from tidemark.evidence.reconciliation import (
    EvidenceReconciler,
    ReconciliationFinding,
    ReconciliationFindingCode,
    finding,
    ordered_findings,
)
from tidemark.runtime.vocabulary import RuleId


_PAYLOAD_TYPES = {
    EvidenceEventType.POLICY_INSTALLATION_REFUSED: PolicyInstallationRefusedPayload,
    EvidenceEventType.CALL_INTAKE_RECORDED: CallIntakeRecordedPayload,
    EvidenceEventType.CALL_PREPARATION_REFUSED: CallPreparationRefusedPayload,
    EvidenceEventType.DECISION_RECORDED: DecisionRecordedPayload,
    EvidenceEventType.CALLBACK_RECEIVED: CallbackPayload,
    EvidenceEventType.CALLBACK_VETOED: CallbackPayload,
    EvidenceEventType.CALLBACK_RELEASED: CallbackPayload,
    EvidenceEventType.CALLBACK_TOOL_ENTERED: CallbackPayload,
    EvidenceEventType.EXECUTION_REFUSED: ExecutionRefusedPayload,
    EvidenceEventType.EXECUTION_STARTED: ExecutionStartedPayload,
    EvidenceEventType.EXECUTION_COMPLETED: ExecutionTerminalPayload,
    EvidenceEventType.EXECUTION_FAILED: ExecutionTerminalPayload,
    EvidenceEventType.EXECUTION_REPLAY_REJECTED: ExecutionReplayRejectedPayload,
    EvidenceEventType.PAYMENT_RECORDED: PaymentRecordedPayload,
    EvidenceEventType.RUN_MODEL_NON_ATTEMPT: ModelNonAttemptPayload,
    EvidenceEventType.EVIDENCE_RECONCILED: EvidenceReconciledPayload,
    EvidenceEventType.EVIDENCE_EXPORT_FINALIZED: EvidenceExportFinalizedPayload,
}

_ENVELOPE_FIELDS = frozenset(
    (
        "schema_version",
        "event_id",
        "event_type",
        "occurred_at",
        "sequence",
        "trace_id",
        "invocation_id",
        "call_id",
        "decision_id",
        "prepared_call_id",
        "execution_id",
        "producer",
        "payload",
        "previous_event_digest",
        "policy_version",
        "registry_version",
        "adapter_id",
        "adapter_version",
    )
)

_NESTED_FIELDS = {
    "argument_shapes": frozenset(field.name for field in fields(ArgumentShape)),
    "rule_results": frozenset(field.name for field in fields(DecisionRuleResult)),
    "argument_projections": frozenset(
        field.name for field in fields(ArgumentProjection)
    ),
    "masked_reason_facts": frozenset(
        field.name for field in fields(MaskedReasonFact)
    ),
}

_SAFE_MASKED_DISPLAYS = {
    "opaque-reference-selected",
    "protected-value-omitted",
    "value-omitted",
}
_SAFE_REASON_KEYS = {"argument_name", "rule_id"}
_SCHEDULE_PAYMENT_ARGUMENTS = {
    "amount_minor",
    "currency",
    "destination_reference",
}
_RESOLUTION_STATUSES = {
    "RESOLVED",
    "FAILED",
    "NOT_RESOLVED",
    "NOT_APPLICABLE",
}
_BINDING_STATUSES = {"MATCHED", "NOT_MATCHED", "NOT_APPLICABLE"}


@final
@dataclass(frozen=True)
class ForensicAuditRecord:
    """Sanitized, non-authoritative result of inspecting one raw primitive."""

    record_digest: str
    sequence: int
    event_type: Optional[EvidenceEventType]
    trace_fingerprint: Optional[str]
    findings: Tuple[ReconciliationFinding, ...]

    def __post_init__(self) -> None:
        if (
            type(self.record_digest) is not str
            or not self.record_digest.startswith("sha256:")
            or len(self.record_digest) != 71
        ):
            raise ValueError("forensic record requires a sha256 digest")
        if type(self.sequence) is not int or self.sequence < 0:
            raise ValueError("forensic sequence requires a non-negative int")
        if self.event_type is not None and type(self.event_type) is not EvidenceEventType:
            raise TypeError("forensic event_type requires EvidenceEventType")
        if self.trace_fingerprint is not None and (
            not self.trace_fingerprint.startswith("sha256:")
            or len(self.trace_fingerprint) != 71
        ):
            raise ValueError("forensic trace requires a sha256 fingerprint")
        if type(self.findings) is not tuple or any(
            type(item) is not ReconciliationFinding for item in self.findings
        ):
            raise TypeError("forensic findings require an exact tuple")

    @property
    def authoritative(self) -> bool:
        return False


ReviewEvidenceInput = Tuple[object, ...]


@final
@dataclass(frozen=True)
class IntegrityReport:
    findings: Tuple[ReconciliationFinding, ...]
    authoritative_event_count: int
    retained_record_count: int
    forensic_record_count: int
    malformed_record_count: int

    def __post_init__(self) -> None:
        if type(self.findings) is not tuple or any(
            type(item) is not ReconciliationFinding for item in self.findings
        ):
            raise TypeError("integrity findings require an exact tuple")
        for value in (
            self.authoritative_event_count,
            self.retained_record_count,
            self.forensic_record_count,
            self.malformed_record_count,
        ):
            if type(value) is not int or value < 0:
                raise ValueError("integrity counts require non-negative ints")

    @property
    def clean(self) -> bool:
        return not self.findings


@dataclass(frozen=True)
class _InspectedEvidence:
    authoritative_events: Tuple[AuditEvent, ...]
    report: IntegrityReport


def _encoded_digest(primitive: object) -> str:
    try:
        encoded = canonical_json_bytes(primitive)
    except (TypeError, ValueError, RecursionError):
        encoded = b"unsupported-forensic-primitive"
    return "sha256:" + sha256(encoded).hexdigest()


def _fingerprint(value: object) -> Optional[str]:
    if type(value) is not str or value == "":
        return None
    return "sha256:" + sha256(value.encode("utf-8")).hexdigest()


def _event_digest(event: StoredAuditEvent) -> str:
    encoded = canonical_json_bytes(
        audit_event_to_primitive(event), trailing_newline=True
    )
    return "sha256:" + sha256(encoded).hexdigest()


def _safe_sequence(value: object) -> int:
    return value if type(value) is int and value >= 0 else 0


def _known_type(value: object) -> Optional[EvidenceEventType]:
    try:
        return EvidenceEventType(value) if type(value) is str else None
    except ValueError:
        return None


def _stored_event_sort_key(event: StoredAuditEvent) -> tuple:
    def identity(name: str) -> str:
        value = getattr(getattr(event, name, None), "value", None)
        return value if type(value) is str else ""

    event_type = (
        event.event_type.value
        if type(event) is AuditEvent
        else "retained-non-authoritative"
    )
    return (
        event.trace_id,
        event.sequence,
        event_type,
        identity("invocation_id"),
        identity("call_id"),
        identity("decision_id"),
        identity("prepared_call_id"),
        identity("execution_id"),
    )


def _field_shape_findings(
    primitive: dict,
    *,
    sequence: int,
    event_type: Optional[EvidenceEventType],
) -> Tuple[ReconciliationFinding, ...]:
    findings = []
    keys = frozenset(primitive)
    if _ENVELOPE_FIELDS - keys:
        findings.append(
            finding(
                ReconciliationFindingCode.EVENT_SCHEMA_INVALID,
                sequence=sequence,
                event_type=event_type,
                location="envelope.missing_required_field",
            )
        )
    if keys - _ENVELOPE_FIELDS:
        findings.append(
            finding(
                ReconciliationFindingCode.FORBIDDEN_FIELD,
                sequence=sequence,
                event_type=event_type,
                location="envelope.unallowlisted_field",
            )
        )
    payload = primitive.get("payload")
    if event_type is None:
        return tuple(findings)
    if type(payload) is not dict:
        findings.append(
            finding(
                ReconciliationFindingCode.EVENT_SCHEMA_INVALID,
                sequence=sequence,
                event_type=event_type,
                location="payload.required_object",
            )
        )
        return tuple(findings)
    expected = frozenset(field.name for field in fields(_PAYLOAD_TYPES[event_type]))
    payload_keys = frozenset(payload)
    if expected - payload_keys:
        findings.append(
            finding(
                ReconciliationFindingCode.EVENT_SCHEMA_INVALID,
                sequence=sequence,
                event_type=event_type,
                location="payload.missing_required_field",
            )
        )
    if payload_keys - expected:
        findings.append(
            finding(
                ReconciliationFindingCode.FORBIDDEN_FIELD,
                sequence=sequence,
                event_type=event_type,
                location="payload.unallowlisted_field",
            )
        )
    for collection_name, expected_item_fields in _NESTED_FIELDS.items():
        if collection_name not in payload:
            continue
        collection = payload.get(collection_name)
        if type(collection) is not list:
            findings.append(
                finding(
                    ReconciliationFindingCode.EVENT_SCHEMA_INVALID,
                    sequence=sequence,
                    event_type=event_type,
                    location=f"payload.{collection_name}.required_list",
                )
            )
            continue
        for item in collection:
            if type(item) is not dict:
                findings.append(
                    finding(
                        ReconciliationFindingCode.EVENT_SCHEMA_INVALID,
                        sequence=sequence,
                        event_type=event_type,
                        location=f"payload.{collection_name}.required_object",
                    )
                )
                continue
            item_keys = frozenset(item)
            if expected_item_fields - item_keys:
                findings.append(
                    finding(
                        ReconciliationFindingCode.EVENT_SCHEMA_INVALID,
                        sequence=sequence,
                        event_type=event_type,
                        location=f"payload.{collection_name}.missing_required_field",
                    )
                )
            if item_keys - expected_item_fields:
                findings.append(
                    finding(
                        ReconciliationFindingCode.FORBIDDEN_FIELD,
                        sequence=sequence,
                        event_type=event_type,
                        location=f"payload.{collection_name}.unallowlisted_field",
                    )
                )
    return tuple(findings)


@final
class ForensicEvidenceInspector:
    """Inspect one already-parsed primitive without reading arbitrary files."""

    __slots__ = ()

    def inspect_primitive(self, primitive: object) -> ForensicAuditRecord:
        digest = _encoded_digest(primitive)
        if type(primitive) is not dict:
            malformed = finding(
                ReconciliationFindingCode.MALFORMED_RECORD,
                sequence=0,
                event_type=None,
                location="forensic.required_object",
            )
            return ForensicAuditRecord(
                record_digest=digest,
                sequence=0,
                event_type=None,
                trace_fingerprint=None,
                findings=(malformed,),
            )
        sequence = _safe_sequence(primitive.get("sequence"))
        event_type = _known_type(primitive.get("event_type"))
        findings = [
            finding(
                ReconciliationFindingCode.NON_AUTHORITATIVE_RECORD,
                sequence=sequence,
                event_type=event_type,
                location="forensic.review_input",
                correlation=digest,
            )
        ]
        findings.extend(
            _field_shape_findings(
                primitive, sequence=sequence, event_type=event_type
            )
        )
        schema_version = primitive.get("schema_version")
        event_type_value = primitive.get("event_type")
        if (
            schema_version != EVIDENCE_SCHEMA_VERSION
            or event_type is None
        ):
            findings.append(
                finding(
                    ReconciliationFindingCode.SCHEMA_GAP,
                    sequence=sequence,
                    event_type=event_type,
                    location=(
                        "schema.version"
                        if schema_version != EVIDENCE_SCHEMA_VERSION
                        else "schema.event_type"
                    ),
                    correlation=digest,
                )
            )
        parse_failed = False
        try:
            restored = audit_event_from_primitive(primitive)
            canonical = audit_event_to_primitive(restored)
            if canonical != primitive:
                parse_failed = True
        except (TypeError, ValueError, KeyError, RecursionError):
            parse_failed = True
        if parse_failed:
            findings.append(
                finding(
                    ReconciliationFindingCode.MALFORMED_RECORD,
                    sequence=sequence,
                    event_type=event_type,
                    location="forensic.canonical_parse",
                    correlation=digest,
                )
            )
        findings.extend(
            _primitive_masking_findings(
                primitive,
                sequence=sequence,
                event_type=event_type,
            )
        )
        return ForensicAuditRecord(
            record_digest=digest,
            sequence=sequence,
            event_type=event_type,
            trace_fingerprint=_fingerprint(primitive.get("trace_id")),
            findings=ordered_findings(findings),
        )

    def __repr__(self) -> str:
        return "ForensicEvidenceInspector(read_only=True, authoritative=False)"


def _masked_display_valid(value: object) -> bool:
    return (
        type(value) is str
        and (
            value in _SAFE_MASKED_DISPLAYS
            or "*" in value
            or (
                value.startswith("sha256:")
                and len(value) == 71
                and all(character in "0123456789abcdef" for character in value[7:])
            )
        )
    )


def _primitive_masking_findings(
    primitive: dict,
    *,
    sequence: int,
    event_type: Optional[EvidenceEventType],
) -> Tuple[ReconciliationFinding, ...]:
    if event_type is None or type(primitive.get("payload")) is not dict:
        return ()
    payload = primitive["payload"]
    findings = []
    for name in ("masked_display", "masked_destination_display"):
        values = []
        if name in payload:
            values.append(payload.get(name))
        if name == "masked_display" and type(payload.get("argument_projections")) is list:
            values.extend(
                item.get(name)
                for item in payload["argument_projections"]
                if type(item) is dict and name in item
            )
        if any(not _masked_display_valid(value) for value in values):
            findings.append(
                finding(
                    ReconciliationFindingCode.MASKING_VIOLATION,
                    sequence=sequence,
                    event_type=event_type,
                    location=f"payload.{name}",
                )
            )
    facts = payload.get("masked_reason_facts")
    argument_projections = payload.get("argument_projections")
    projected_names = (
        {
            item.get("name")
            for item in argument_projections
            if type(item) is dict
        }
        if type(argument_projections) is list
        else set()
    )
    if type(facts) is list:
        for fact in facts:
            if type(fact) is not dict or fact.get("key") not in _SAFE_REASON_KEYS:
                findings.append(
                    finding(
                        ReconciliationFindingCode.MASKING_VIOLATION,
                        sequence=sequence,
                        event_type=event_type,
                        location="payload.masked_reason_facts.key",
                    )
                )
                continue
            value = fact.get("value")
            value_allowed = (
                type(value) is str
                and (
                    (
                        fact.get("key") == "argument_name"
                        and value in projected_names
                        and value in _SCHEDULE_PAYMENT_ARGUMENTS
                    )
                    or (
                        fact.get("key") == "rule_id"
                        and value in {item.value for item in RuleId}
                    )
                )
            )
            if not value_allowed:
                findings.append(
                    finding(
                        ReconciliationFindingCode.MASKING_VIOLATION,
                        sequence=sequence,
                        event_type=event_type,
                        location="payload.masked_reason_facts.value",
                    )
                )
    if type(argument_projections) is list:
        for projection in argument_projections:
            if type(projection) is not dict:
                continue
            if (
                projection.get("name") not in _SCHEDULE_PAYMENT_ARGUMENTS
                or projection.get("resolution_status") not in _RESOLUTION_STATUSES
                or projection.get("binding_status") not in _BINDING_STATUSES
            ):
                findings.append(
                    finding(
                        ReconciliationFindingCode.MASKING_VIOLATION,
                        sequence=sequence,
                        event_type=event_type,
                        location="payload.argument_projections.allowlist",
                    )
                )
    return tuple(findings)


def _event_masking_findings(event: AuditEvent) -> Tuple[ReconciliationFinding, ...]:
    return _primitive_masking_findings(
        audit_event_to_primitive(event),
        sequence=event.sequence,
        event_type=event.event_type,
    )


def _inspect_event_stream(event_stream: ReviewEvidenceInput) -> _InspectedEvidence:
    if type(event_stream) is not tuple:
        raise TypeError("evidence review requires an exact immutable tuple")
    findings = []
    authoritative = []
    retained = []
    retained_count = 0
    forensic_count = 0
    malformed_count = 0
    identities: Dict[str, list] = {}

    for item in event_stream:
        if type(item) is ForensicAuditRecord:
            forensic_count += 1
            try:
                restored_forensic = ForensicAuditRecord(
                    record_digest=item.record_digest,
                    sequence=item.sequence,
                    event_type=item.event_type,
                    trace_fingerprint=item.trace_fingerprint,
                    findings=item.findings,
                )
                forensic_valid = restored_forensic == item
            except (AttributeError, TypeError, ValueError):
                forensic_valid = False
            if not forensic_valid:
                malformed_count += 1
                findings.append(
                    finding(
                        ReconciliationFindingCode.MALFORMED_RECORD,
                        sequence=_safe_sequence(getattr(item, "sequence", 0)),
                        event_type=(
                            item.event_type
                            if type(getattr(item, "event_type", None))
                            is EvidenceEventType
                            else None
                        ),
                        location="forensic.record_integrity",
                    )
                )
                continue
            findings.extend(restored_forensic.findings)
            if any(
                entry.code is ReconciliationFindingCode.MALFORMED_RECORD
                for entry in restored_forensic.findings
            ):
                malformed_count += 1
            continue
        if type(item) is RetainedAuditEvent:
            retained_count += 1
            try:
                restored_retained = audit_event_from_primitive(
                    audit_event_to_primitive(item)
                )
                retained_valid = (
                    type(restored_retained) is RetainedAuditEvent
                    and restored_retained == item
                )
            except (
                AttributeError,
                TypeError,
                ValueError,
                KeyError,
                RecursionError,
            ):
                retained_valid = False
            findings.append(
                finding(
                    ReconciliationFindingCode.SCHEMA_GAP,
                    sequence=_safe_sequence(getattr(item, "sequence", 0)),
                    event_type=None,
                    location="retained.unknown_schema_or_event",
                )
            )
            if not retained_valid:
                malformed_count += 1
                findings.append(
                    finding(
                        ReconciliationFindingCode.MALFORMED_RECORD,
                        sequence=_safe_sequence(getattr(item, "sequence", 0)),
                        event_type=None,
                        location="retained.canonical_parse",
                    )
                )
                continue
            identities.setdefault(restored_retained.event_id, []).append(
                restored_retained
            )
            retained.append(restored_retained)
            continue
        if type(item) is not AuditEvent:
            raise TypeError("review input requires stored events or forensic records")
        try:
            restored = audit_event_from_primitive(audit_event_to_primitive(item))
            valid = type(restored) is AuditEvent and restored == item
        except (AttributeError, TypeError, ValueError, KeyError, RecursionError):
            valid = False
        if not valid:
            malformed_count += 1
            findings.append(
                finding(
                    ReconciliationFindingCode.MALFORMED_RECORD,
                    sequence=_safe_sequence(getattr(item, "sequence", 0)),
                    event_type=(
                        item.event_type
                        if type(getattr(item, "event_type", None)) is EvidenceEventType
                        else None
                    ),
                    location="authoritative.canonical_parse",
                    correlation=(
                        item.event_id if type(getattr(item, "event_id", None)) is str else None
                    ),
                )
            )
            continue
        identities.setdefault(restored.event_id, []).append(restored)
        authoritative.append(restored)
        findings.extend(_event_masking_findings(restored))

    for event_id, duplicates in identities.items():
        if len(duplicates) > 1:
            first = min(
                duplicates,
                key=lambda event: (
                    _safe_sequence(getattr(event, "sequence", 0)),
                    getattr(event, "trace_id", ""),
                ),
            )
            findings.append(
                finding(
                    ReconciliationFindingCode.DUPLICATE_EVENT_IDENTITY,
                    sequence=_safe_sequence(getattr(first, "sequence", 0)),
                    event_type=(
                        first.event_type
                        if type(first) is AuditEvent
                        else None
                    ),
                    location="envelope.event_id",
                )
            )

    grouped: Dict[str, list] = {}
    for event in tuple(authoritative) + tuple(retained):
        grouped.setdefault(event.trace_id, []).append(event)
    for trace_id, trace_values in grouped.items():
        trace_events = tuple(
            sorted(
                trace_values,
                key=_stored_event_sort_key,
            )
        )
        expected = 1
        previous = None
        for event in trace_events:
            if event.sequence != expected:
                findings.append(
                    finding(
                        ReconciliationFindingCode.SEQUENCE_GAP,
                        sequence=event.sequence,
                        event_type=(
                            event.event_type if type(event) is AuditEvent else None
                        ),
                        location="envelope.sequence",
                        correlation=trace_id,
                    )
                )
                expected = event.sequence
            if event.previous_event_digest is not None and event.previous_event_digest != previous:
                findings.append(
                    finding(
                        ReconciliationFindingCode.DIGEST_MISMATCH,
                        sequence=event.sequence,
                        event_type=(
                            event.event_type if type(event) is AuditEvent else None
                        ),
                        location="envelope.previous_event_digest",
                        correlation=trace_id,
                    )
                )
            previous = _event_digest(event)
            expected += 1

    normalized = tuple(
        sorted(
            authoritative,
            key=_stored_event_sort_key,
        )
    )
    ordered = ordered_findings(findings)
    report = IntegrityReport(
        findings=ordered,
        authoritative_event_count=len(normalized),
        retained_record_count=retained_count,
        forensic_record_count=forensic_count,
        malformed_record_count=malformed_count,
    )
    return _InspectedEvidence(normalized, report)


@final
class EvidenceIntegrityChecker:
    """Revalidate evidence at review time without modifying its source."""

    __slots__ = ()

    def check(self, event_stream: ReviewEvidenceInput) -> IntegrityReport:
        inspected = _inspect_event_stream(event_stream)
        reconciliation = EvidenceReconciler().reconcile(
            inspected.authoritative_events
        )
        report = inspected.report
        return IntegrityReport(
            findings=ordered_findings(
                report.findings + reconciliation.findings
            ),
            authoritative_event_count=report.authoritative_event_count,
            retained_record_count=report.retained_record_count,
            forensic_record_count=report.forensic_record_count,
            malformed_record_count=report.malformed_record_count,
        )

    def __repr__(self) -> str:
        return "EvidenceIntegrityChecker(read_only=True, host_tamper_resistant=False)"


__all__ = (
    "EvidenceIntegrityChecker",
    "ForensicAuditRecord",
    "ForensicEvidenceInspector",
    "IntegrityReport",
)
