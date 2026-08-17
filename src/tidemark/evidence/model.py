"""Closed immutable TIDEMARK evidence envelope and event payloads."""

from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum, unique
from typing import Optional, Tuple, Union, final

from tidemark.runtime.identifiers import (
    AdapterId,
    AdapterVersion,
    CallId,
    DecisionId,
    ExecutionId,
    InvocationId,
    ParentId,
    PolicyVersion,
    PreparedCallId,
    RegistryVersion,
    ToolContractVersion,
    ToolId,
    TypeId,
)
from tidemark.runtime.vocabulary import (
    ArgumentRole,
    ConstraintId,
    DecisionOutcome,
    EvaluationStage,
    ProvenanceClass,
    RuleEvaluationOutcome,
    RuleId,
)


EVIDENCE_SCHEMA_VERSION = "tidemark.evidence.v1"
_SHA256_PREFIX = "sha256:"
_RetainedScalar = Union[str, bool, int, None]


@unique
class EvidenceEventType(str, Enum):
    POLICY_INSTALLATION_REFUSED = "policy.installation_refused"
    CALL_INTAKE_RECORDED = "call.intake_recorded"
    CALL_PREPARATION_REFUSED = "call.preparation_refused"
    DECISION_RECORDED = "decision.recorded"
    CALLBACK_RECEIVED = "callback.received"
    CALLBACK_VETOED = "callback.vetoed"
    CALLBACK_RELEASED = "callback.released"
    CALLBACK_TOOL_ENTERED = "callback.tool_entered"
    EXECUTION_REFUSED = "execution.refused"
    EXECUTION_STARTED = "execution.started"
    EXECUTION_COMPLETED = "execution.completed"
    EXECUTION_FAILED = "execution.failed"
    EXECUTION_REPLAY_REJECTED = "execution.replay_rejected"
    PAYMENT_RECORDED = "payment.recorded"
    RUN_MODEL_NON_ATTEMPT = "run.model_non_attempt"
    EVIDENCE_RECONCILED = "evidence.reconciled"
    EVIDENCE_EXPORT_FINALIZED = "evidence.export_finalized"


def _string(value: object, name: str) -> None:
    if type(value) is not str or value == "":
        raise ValueError(f"{name} requires an exact non-empty string")


def _utc(value: object, name: str) -> None:
    if type(value) is not datetime or value.tzinfo is not timezone.utc:
        raise ValueError(f"{name} requires an exact UTC datetime")


def _identifier(value: object, kind: type, name: str) -> None:
    if type(value) is not kind:
        raise TypeError(f"{name} requires {kind.__name__}")


def _optional_identifier(value: object, kind: type, name: str) -> None:
    if value is not None:
        _identifier(value, kind, name)


def _sha256(value: object, name: str) -> None:
    if (
        type(value) is not str
        or not value.startswith(_SHA256_PREFIX)
        or len(value) != 71
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise ValueError(f"{name} requires a sha256 identity")


def _tuple_of(value: object, kind: type, name: str) -> None:
    if type(value) is not tuple or any(type(item) is not kind for item in value):
        raise TypeError(f"{name} requires exact {kind.__name__} values")


@final
@dataclass(frozen=True)
class EvidenceProducer:
    component: str
    build_version: str

    def __post_init__(self) -> None:
        _string(self.component, "component")
        _string(self.build_version, "build_version")


@final
@dataclass(frozen=True)
class ArgumentShape:
    name: str
    type_name: str

    def __post_init__(self) -> None:
        _string(self.name, "name")
        _string(self.type_name, "type_name")


@final
@dataclass(frozen=True)
class DecisionRuleResult:
    rule_id: RuleId
    outcome: RuleEvaluationOutcome
    stage: EvaluationStage
    argument_name: Optional[str]
    constraint_id: Optional[ConstraintId]

    def __post_init__(self) -> None:
        _identifier(self.rule_id, RuleId, "rule_id")
        _identifier(self.outcome, RuleEvaluationOutcome, "outcome")
        _identifier(self.stage, EvaluationStage, "stage")
        if self.argument_name is not None:
            _string(self.argument_name, "argument_name")
        if self.constraint_id is not None:
            _identifier(self.constraint_id, ConstraintId, "constraint_id")


@final
@dataclass(frozen=True)
class ArgumentProjection:
    name: str
    role: ArgumentRole
    supported_type: TypeId
    provenance_class: ProvenanceClass
    resolution_status: str
    binding_status: str
    masked_display: str

    def __post_init__(self) -> None:
        _string(self.name, "name")
        _identifier(self.role, ArgumentRole, "role")
        _identifier(self.supported_type, TypeId, "supported_type")
        _identifier(self.provenance_class, ProvenanceClass, "provenance_class")
        _string(self.resolution_status, "resolution_status")
        _string(self.binding_status, "binding_status")
        _string(self.masked_display, "masked_display")


@final
@dataclass(frozen=True)
class MaskedReasonFact:
    key: str
    value: _RetainedScalar

    def __post_init__(self) -> None:
        _string(self.key, "key")
        if self.value is not None and type(self.value) not in (str, bool, int):
            raise TypeError("masked reason fact requires an exact scalar")


@final
@dataclass(frozen=True)
class PolicyInstallationRefusedPayload:
    refusal_code: str
    stage: str
    location: str
    masked_detail: str

    def __post_init__(self) -> None:
        for value, name in (
            (self.refusal_code, "refusal_code"),
            (self.stage, "stage"),
            (self.location, "location"),
            (self.masked_detail, "masked_detail"),
        ):
            _string(value, name)


@final
@dataclass(frozen=True)
class CallIntakeRecordedPayload:
    tool_id: ToolId
    contract_version: ToolContractVersion
    argument_shapes: Tuple[ArgumentShape, ...]

    def __post_init__(self) -> None:
        _identifier(self.tool_id, ToolId, "tool_id")
        _identifier(self.contract_version, ToolContractVersion, "contract_version")
        _tuple_of(self.argument_shapes, ArgumentShape, "argument_shapes")


@final
@dataclass(frozen=True)
class CallPreparationRefusedPayload:
    refusal_code: str
    stage: str
    location: str
    masked_detail: str

    def __post_init__(self) -> None:
        for value, name in (
            (self.refusal_code, "refusal_code"),
            (self.stage, "stage"),
            (self.location, "location"),
            (self.masked_detail, "masked_detail"),
        ):
            _string(value, name)


@final
@dataclass(frozen=True)
class DecisionRecordedPayload:
    outcome: DecisionOutcome
    stage: EvaluationStage
    primary_rule_id: RuleId
    rule_results: Tuple[DecisionRuleResult, ...]
    tool_id: ToolId
    contract_version: ToolContractVersion
    policy_version: PolicyVersion
    registry_version: RegistryVersion
    argument_projections: Tuple[ArgumentProjection, ...]
    masked_reason_facts: Tuple[MaskedReasonFact, ...]
    prepared_call_id: Optional[PreparedCallId]

    def __post_init__(self) -> None:
        if self.outcome not in (DecisionOutcome.DENY, DecisionOutcome.ALLOW):
            raise ValueError("decision evidence requires DENY or ALLOW")
        _identifier(self.stage, EvaluationStage, "stage")
        _identifier(self.primary_rule_id, RuleId, "primary_rule_id")
        _tuple_of(self.rule_results, DecisionRuleResult, "rule_results")
        if not self.rule_results:
            raise ValueError("decision evidence requires rule_results")
        _identifier(self.tool_id, ToolId, "tool_id")
        _identifier(self.contract_version, ToolContractVersion, "contract_version")
        _identifier(self.policy_version, PolicyVersion, "policy_version")
        _identifier(self.registry_version, RegistryVersion, "registry_version")
        _tuple_of(self.argument_projections, ArgumentProjection, "argument_projections")
        _tuple_of(self.masked_reason_facts, MaskedReasonFact, "masked_reason_facts")
        _optional_identifier(self.prepared_call_id, PreparedCallId, "prepared_call_id")
        if self.outcome is DecisionOutcome.DENY and self.prepared_call_id is not None:
            raise ValueError("DENY cannot carry prepared_call_id")
        if self.outcome is DecisionOutcome.ALLOW and self.prepared_call_id is None:
            raise ValueError("ALLOW requires prepared_call_id")


@final
@dataclass(frozen=True)
class CallbackPayload:
    framework_name: str
    framework_version: str
    callback_name: str
    framework_invocation_id: str
    framework_call_id: str
    tool_id: ToolId
    argument_shapes: Tuple[ArgumentShape, ...]

    def __post_init__(self) -> None:
        for value, name in (
            (self.framework_name, "framework_name"),
            (self.framework_version, "framework_version"),
            (self.callback_name, "callback_name"),
            (self.framework_invocation_id, "framework_invocation_id"),
            (self.framework_call_id, "framework_call_id"),
        ):
            _string(value, name)
        _identifier(self.tool_id, ToolId, "tool_id")
        _tuple_of(self.argument_shapes, ArgumentShape, "argument_shapes")


@final
@dataclass(frozen=True)
class ExecutionRefusedPayload:
    rule_id: RuleId
    masked_failure_fact: str

    def __post_init__(self) -> None:
        _identifier(self.rule_id, RuleId, "rule_id")
        _string(self.masked_failure_fact, "masked_failure_fact")


@final
@dataclass(frozen=True)
class ExecutionStartedPayload:
    tool_id: ToolId
    attempt_number: int
    idempotency_key_fingerprint: str
    started_at: datetime

    def __post_init__(self) -> None:
        _identifier(self.tool_id, ToolId, "tool_id")
        if type(self.attempt_number) is not int or self.attempt_number < 1:
            raise ValueError("attempt_number requires a positive exact int")
        _sha256(self.idempotency_key_fingerprint, "idempotency_key_fingerprint")
        _utc(self.started_at, "started_at")


@final
@dataclass(frozen=True)
class ExecutionTerminalPayload:
    external_result_confirmed: bool
    masked_failure_fact: Optional[str]

    def __post_init__(self) -> None:
        if type(self.external_result_confirmed) is not bool:
            raise TypeError("external_result_confirmed requires bool")
        if self.masked_failure_fact is not None:
            _string(self.masked_failure_fact, "masked_failure_fact")


@final
@dataclass(frozen=True)
class ExecutionReplayRejectedPayload:
    rule_id: RuleId

    def __post_init__(self) -> None:
        if self.rule_id is not RuleId.EXECUTION_REPLAY_REJECTED:
            raise ValueError("replay evidence requires the replay rule")


@final
@dataclass(frozen=True)
class PaymentRecordedPayload:
    payment_record_id: str
    execution_id: ExecutionId
    prepared_call_id: PreparedCallId
    idempotency_key_fingerprint: str
    amount_minor: int
    currency: str
    parent_id: ParentId
    destination_kind: str
    masked_destination_display: str
    status: str
    store_version: int
    created_at: datetime

    def __post_init__(self) -> None:
        _string(self.payment_record_id, "payment_record_id")
        _identifier(self.execution_id, ExecutionId, "execution_id")
        _identifier(self.prepared_call_id, PreparedCallId, "prepared_call_id")
        _sha256(self.idempotency_key_fingerprint, "idempotency_key_fingerprint")
        if type(self.amount_minor) is not int:
            raise TypeError("amount_minor requires exact int")
        _string(self.currency, "currency")
        _identifier(self.parent_id, ParentId, "parent_id")
        _string(self.destination_kind, "destination_kind")
        _string(self.masked_destination_display, "masked_destination_display")
        if "*" not in self.masked_destination_display and not self.masked_destination_display.startswith(_SHA256_PREFIX):
            raise ValueError("destination display must be masked or fingerprinted")
        if self.status != "RECORDED":
            raise ValueError("payment evidence status must be RECORDED")
        if type(self.store_version) is not int or self.store_version < 1:
            raise ValueError("store_version requires a positive exact int")
        _utc(self.created_at, "created_at")


@final
@dataclass(frozen=True)
class ModelNonAttemptPayload:
    reason_code: str
    candidate_tool_call_count: int

    def __post_init__(self) -> None:
        _string(self.reason_code, "reason_code")
        if self.reason_code.upper() == "DENY" or "veto" in self.reason_code.lower():
            raise ValueError("model non-attempt is not DENY or callback veto")
        if type(self.candidate_tool_call_count) is not int or self.candidate_tool_call_count != 0:
            raise ValueError("model non-attempt requires zero candidate calls")


@final
@dataclass(frozen=True)
class EvidenceReconciledPayload:
    related_event_ids: Tuple[str, ...]
    masked_detail: str

    def __post_init__(self) -> None:
        if type(self.related_event_ids) is not tuple or any(type(item) is not str or item == "" for item in self.related_event_ids):
            raise TypeError("related_event_ids require exact strings")
        _string(self.masked_detail, "masked_detail")


@final
@dataclass(frozen=True)
class EvidenceExportFinalizedPayload:
    export_id: str
    ordered_event_ids: Tuple[str, ...]
    event_digests: Tuple[str, ...]
    overall_digest: str
    schema_versions: Tuple[str, ...]

    def __post_init__(self) -> None:
        _string(self.export_id, "export_id")
        for values, name in (
            (self.ordered_event_ids, "ordered_event_ids"),
            (self.schema_versions, "schema_versions"),
        ):
            if type(values) is not tuple or any(type(item) is not str or item == "" for item in values):
                raise TypeError(f"{name} requires exact strings")
        if type(self.event_digests) is not tuple:
            raise TypeError("event_digests requires tuple")
        for digest in self.event_digests:
            _sha256(digest, "event_digest")
        _sha256(self.overall_digest, "overall_digest")


AuditPayload = Union[
    PolicyInstallationRefusedPayload,
    CallIntakeRecordedPayload,
    CallPreparationRefusedPayload,
    DecisionRecordedPayload,
    CallbackPayload,
    ExecutionRefusedPayload,
    ExecutionStartedPayload,
    ExecutionTerminalPayload,
    ExecutionReplayRejectedPayload,
    PaymentRecordedPayload,
    ModelNonAttemptPayload,
    EvidenceReconciledPayload,
    EvidenceExportFinalizedPayload,
]


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


@final
@dataclass(frozen=True)
class AuditEvent:
    schema_version: str
    event_id: str
    event_type: EvidenceEventType
    occurred_at: datetime
    sequence: int
    trace_id: str
    invocation_id: Optional[InvocationId]
    call_id: Optional[CallId]
    decision_id: Optional[DecisionId]
    prepared_call_id: Optional[PreparedCallId]
    execution_id: Optional[ExecutionId]
    policy_version: Optional[PolicyVersion]
    registry_version: Optional[RegistryVersion]
    adapter_id: Optional[AdapterId]
    adapter_version: Optional[AdapterVersion]
    producer: EvidenceProducer
    payload: AuditPayload
    previous_event_digest: Optional[str]

    def __post_init__(self) -> None:
        if self.schema_version != EVIDENCE_SCHEMA_VERSION or type(self.schema_version) is not str:
            raise ValueError("unknown schema requires retained-event model")
        _string(self.event_id, "event_id")
        if type(self.event_type) is not EvidenceEventType:
            raise TypeError("event_type requires the closed EvidenceEventType")
        _utc(self.occurred_at, "occurred_at")
        if type(self.sequence) is not int or self.sequence < 1:
            raise ValueError("sequence requires a positive exact int")
        _string(self.trace_id, "trace_id")
        for value, kind, name in (
            (self.invocation_id, InvocationId, "invocation_id"),
            (self.call_id, CallId, "call_id"),
            (self.decision_id, DecisionId, "decision_id"),
            (self.prepared_call_id, PreparedCallId, "prepared_call_id"),
            (self.execution_id, ExecutionId, "execution_id"),
            (self.policy_version, PolicyVersion, "policy_version"),
            (self.registry_version, RegistryVersion, "registry_version"),
            (self.adapter_id, AdapterId, "adapter_id"),
            (self.adapter_version, AdapterVersion, "adapter_version"),
        ):
            _optional_identifier(value, kind, name)
        if (self.adapter_id is None) != (self.adapter_version is None):
            raise ValueError("adapter identity and version must be paired")
        if type(self.producer) is not EvidenceProducer:
            raise TypeError("producer requires EvidenceProducer")
        if type(self.payload) is not _PAYLOAD_TYPES[self.event_type]:
            raise TypeError("event_type and payload type do not match")
        if self.previous_event_digest is not None:
            _sha256(self.previous_event_digest, "previous_event_digest")
        self._validate_correlations()

    @property
    def authoritative(self) -> bool:
        return True

    def _validate_correlations(self) -> None:
        event_type = self.event_type
        call_events = {
            EvidenceEventType.CALL_INTAKE_RECORDED,
            EvidenceEventType.CALL_PREPARATION_REFUSED,
            EvidenceEventType.DECISION_RECORDED,
            EvidenceEventType.CALLBACK_RECEIVED,
            EvidenceEventType.CALLBACK_VETOED,
            EvidenceEventType.CALLBACK_RELEASED,
            EvidenceEventType.CALLBACK_TOOL_ENTERED,
        }
        if event_type in call_events and (self.invocation_id is None or self.call_id is None):
            raise ValueError("call evidence requires invocation and call correlation")
        if event_type in {
            EvidenceEventType.CALL_INTAKE_RECORDED,
            EvidenceEventType.CALL_PREPARATION_REFUSED,
            EvidenceEventType.DECISION_RECORDED,
        } and (self.policy_version is None or self.registry_version is None):
            raise ValueError("runtime call evidence requires captured versions")
        if event_type is EvidenceEventType.DECISION_RECORDED:
            if self.decision_id is None:
                raise ValueError("decision evidence requires decision_id")
            payload = self.payload
            if payload.prepared_call_id != self.prepared_call_id:
                raise ValueError("decision prepared-call correlations differ")
            if (
                payload.policy_version != self.policy_version
                or payload.registry_version != self.registry_version
            ):
                raise ValueError("decision payload versions differ from envelope")
        if event_type in {EvidenceEventType.CALLBACK_RELEASED, EvidenceEventType.CALLBACK_TOOL_ENTERED} and (self.decision_id is None or self.prepared_call_id is None):
            raise ValueError("callback release/entry requires prepared lineage")
        execution_events = {
            EvidenceEventType.EXECUTION_STARTED,
            EvidenceEventType.EXECUTION_COMPLETED,
            EvidenceEventType.EXECUTION_FAILED,
            EvidenceEventType.EXECUTION_REPLAY_REJECTED,
            EvidenceEventType.PAYMENT_RECORDED,
        }
        if event_type in execution_events:
            required = (
                self.invocation_id,
                self.call_id,
                self.decision_id,
                self.prepared_call_id,
                self.execution_id,
                self.policy_version,
                self.registry_version,
                self.adapter_id,
                self.adapter_version,
            )
            if any(value is None for value in required):
                raise ValueError("execution/payment evidence requires complete lineage")
        if event_type is EvidenceEventType.EXECUTION_COMPLETED:
            if (
                self.payload.external_result_confirmed is not True
                or self.payload.masked_failure_fact is not None
            ):
                raise ValueError("completed execution requires confirmed success")
        if event_type is EvidenceEventType.EXECUTION_FAILED:
            if self.payload.masked_failure_fact is None:
                raise ValueError("failed execution requires a masked failure fact")
        if event_type is EvidenceEventType.CALLBACK_VETOED and self.prepared_call_id is not None:
            raise ValueError("callback veto cannot carry prepared execution authority")
        if event_type is EvidenceEventType.PAYMENT_RECORDED:
            if (
                self.payload.execution_id != self.execution_id
                or self.payload.prepared_call_id != self.prepared_call_id
            ):
                raise ValueError("payment payload correlations differ from envelope")
        if event_type is EvidenceEventType.RUN_MODEL_NON_ATTEMPT and self.invocation_id is None:
            raise ValueError("model non-attempt requires invocation correlation")
        if event_type is EvidenceEventType.EVIDENCE_EXPORT_FINALIZED and self.previous_event_digest is None:
            raise ValueError("finalized export event requires a previous digest")


@final
@dataclass(frozen=True)
class RetainedPayloadField:
    name: str
    value: _RetainedScalar

    def __post_init__(self) -> None:
        _string(self.name, "name")
        if self.value is not None and type(self.value) not in (str, bool, int):
            raise TypeError("retained payload values require exact inert scalars")


@final
@dataclass(frozen=True)
class RetainedAuditEvent:
    schema_version: str
    event_id: str
    event_type: str
    occurred_at: datetime
    sequence: int
    trace_id: str
    producer: EvidenceProducer
    payload: Tuple[RetainedPayloadField, ...]
    invocation_id: Optional[InvocationId] = None
    call_id: Optional[CallId] = None
    decision_id: Optional[DecisionId] = None
    prepared_call_id: Optional[PreparedCallId] = None
    execution_id: Optional[ExecutionId] = None
    policy_version: Optional[PolicyVersion] = None
    registry_version: Optional[RegistryVersion] = None
    adapter_id: Optional[AdapterId] = None
    adapter_version: Optional[AdapterVersion] = None
    previous_event_digest: Optional[str] = None

    def __post_init__(self) -> None:
        _string(self.schema_version, "schema_version")
        _string(self.event_id, "event_id")
        _string(self.event_type, "event_type")
        known_schema = self.schema_version == EVIDENCE_SCHEMA_VERSION
        known_event = self.event_type in {item.value for item in EvidenceEventType}
        if known_schema and known_event:
            raise ValueError("known events require the authoritative AuditEvent model")
        _utc(self.occurred_at, "occurred_at")
        if type(self.sequence) is not int or self.sequence < 1:
            raise ValueError("sequence requires a positive exact int")
        _string(self.trace_id, "trace_id")
        if type(self.producer) is not EvidenceProducer:
            raise TypeError("producer requires EvidenceProducer")
        _tuple_of(self.payload, RetainedPayloadField, "payload")
        for value, kind, name in (
            (self.invocation_id, InvocationId, "invocation_id"),
            (self.call_id, CallId, "call_id"),
            (self.decision_id, DecisionId, "decision_id"),
            (self.prepared_call_id, PreparedCallId, "prepared_call_id"),
            (self.execution_id, ExecutionId, "execution_id"),
            (self.policy_version, PolicyVersion, "policy_version"),
            (self.registry_version, RegistryVersion, "registry_version"),
            (self.adapter_id, AdapterId, "adapter_id"),
            (self.adapter_version, AdapterVersion, "adapter_version"),
        ):
            _optional_identifier(value, kind, name)
        if (self.adapter_id is None) != (self.adapter_version is None):
            raise ValueError("adapter identity and version must be paired")
        if self.previous_event_digest is not None:
            _sha256(self.previous_event_digest, "previous_event_digest")

    @property
    def authoritative(self) -> bool:
        return False


StoredAuditEvent = Union[AuditEvent, RetainedAuditEvent]


def _primitive(value: object) -> object:
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is datetime:
        _utc(value, "datetime")
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, Enum):
        return value.value
    if type(value) is tuple:
        return [_primitive(item) for item in value]
    if is_dataclass(value):
        if (
            value.__class__.__module__ == "tidemark.runtime.identifiers"
            and hasattr(value, "value")
            and type(value.value) is str
        ):
            return value.value
        return {field.name: _primitive(getattr(value, field.name)) for field in fields(value)}
    raise TypeError("evidence serialization encountered an unsupported value")


def audit_event_to_primitive(event: StoredAuditEvent) -> dict:
    if type(event) not in (AuditEvent, RetainedAuditEvent):
        raise TypeError("event requires an exact stored evidence event")
    result = {
        "schema_version": event.schema_version,
        "event_id": event.event_id,
        "event_type": event.event_type.value if type(event) is AuditEvent else event.event_type,
        "occurred_at": _primitive(event.occurred_at),
        "sequence": event.sequence,
        "trace_id": event.trace_id,
        "invocation_id": _primitive(event.invocation_id),
        "call_id": _primitive(event.call_id),
        "decision_id": _primitive(event.decision_id),
        "prepared_call_id": _primitive(event.prepared_call_id),
        "execution_id": _primitive(event.execution_id),
        "producer": _primitive(event.producer),
        "payload": _primitive(event.payload),
        "previous_event_digest": event.previous_event_digest,
        "policy_version": _primitive(event.policy_version),
        "registry_version": _primitive(event.registry_version),
        "adapter_id": _primitive(event.adapter_id),
        "adapter_version": _primitive(event.adapter_version),
    }
    return result


def _dt(value: object) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise ValueError("timestamp requires canonical UTC text")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    _utc(parsed, "timestamp")
    return parsed


def _id(value: object, kind: type) -> object:
    return None if value is None else kind(value)


def _producer(value: object) -> EvidenceProducer:
    if type(value) is not dict:
        raise TypeError("producer requires object")
    return EvidenceProducer(value.get("component"), value.get("build_version"))


def _argument_shapes(values: object) -> Tuple[ArgumentShape, ...]:
    if type(values) is not list:
        raise TypeError("argument_shapes requires list")
    return tuple(ArgumentShape(item.get("name"), item.get("type_name")) for item in values if type(item) is dict)


def _payload(event_type: EvidenceEventType, value: object) -> AuditPayload:
    if type(value) is not dict:
        raise TypeError("payload requires object")
    if event_type is EvidenceEventType.POLICY_INSTALLATION_REFUSED:
        return PolicyInstallationRefusedPayload(**value)
    if event_type is EvidenceEventType.CALL_INTAKE_RECORDED:
        return CallIntakeRecordedPayload(
            tool_id=ToolId(value.get("tool_id")),
            contract_version=ToolContractVersion(value.get("contract_version")),
            argument_shapes=_argument_shapes(value.get("argument_shapes")),
        )
    if event_type is EvidenceEventType.CALL_PREPARATION_REFUSED:
        return CallPreparationRefusedPayload(**value)
    if event_type is EvidenceEventType.DECISION_RECORDED:
        rule_results = tuple(
            DecisionRuleResult(
                rule_id=RuleId(item.get("rule_id")),
                outcome=RuleEvaluationOutcome(item.get("outcome")),
                stage=EvaluationStage(item.get("stage")),
                argument_name=item.get("argument_name"),
                constraint_id=_id(item.get("constraint_id"), ConstraintId),
            )
            for item in value.get("rule_results", [])
            if type(item) is dict
        )
        projections = tuple(
            ArgumentProjection(
                name=item.get("name"),
                role=ArgumentRole(item.get("role")),
                supported_type=TypeId(item.get("supported_type")),
                provenance_class=ProvenanceClass(item.get("provenance_class")),
                resolution_status=item.get("resolution_status"),
                binding_status=item.get("binding_status"),
                masked_display=item.get("masked_display"),
            )
            for item in value.get("argument_projections", [])
            if type(item) is dict
        )
        facts = tuple(
            MaskedReasonFact(item.get("key"), item.get("value"))
            for item in value.get("masked_reason_facts", [])
            if type(item) is dict
        )
        return DecisionRecordedPayload(
            outcome=DecisionOutcome(value.get("outcome")),
            stage=EvaluationStage(value.get("stage")),
            primary_rule_id=RuleId(value.get("primary_rule_id")),
            rule_results=rule_results,
            tool_id=ToolId(value.get("tool_id")),
            contract_version=ToolContractVersion(value.get("contract_version")),
            policy_version=PolicyVersion(value.get("policy_version")),
            registry_version=RegistryVersion(value.get("registry_version")),
            argument_projections=projections,
            masked_reason_facts=facts,
            prepared_call_id=_id(value.get("prepared_call_id"), PreparedCallId),
        )
    if event_type in {
        EvidenceEventType.CALLBACK_RECEIVED,
        EvidenceEventType.CALLBACK_VETOED,
        EvidenceEventType.CALLBACK_RELEASED,
        EvidenceEventType.CALLBACK_TOOL_ENTERED,
    }:
        return CallbackPayload(
            framework_name=value.get("framework_name"),
            framework_version=value.get("framework_version"),
            callback_name=value.get("callback_name"),
            framework_invocation_id=value.get("framework_invocation_id"),
            framework_call_id=value.get("framework_call_id"),
            tool_id=ToolId(value.get("tool_id")),
            argument_shapes=_argument_shapes(value.get("argument_shapes")),
        )
    if event_type is EvidenceEventType.EXECUTION_REFUSED:
        return ExecutionRefusedPayload(RuleId(value.get("rule_id")), value.get("masked_failure_fact"))
    if event_type is EvidenceEventType.EXECUTION_STARTED:
        return ExecutionStartedPayload(
            ToolId(value.get("tool_id")),
            value.get("attempt_number"),
            value.get("idempotency_key_fingerprint"),
            _dt(value.get("started_at")),
        )
    if event_type in {EvidenceEventType.EXECUTION_COMPLETED, EvidenceEventType.EXECUTION_FAILED}:
        return ExecutionTerminalPayload(value.get("external_result_confirmed"), value.get("masked_failure_fact"))
    if event_type is EvidenceEventType.EXECUTION_REPLAY_REJECTED:
        return ExecutionReplayRejectedPayload(RuleId(value.get("rule_id")))
    if event_type is EvidenceEventType.PAYMENT_RECORDED:
        return PaymentRecordedPayload(
            payment_record_id=value.get("payment_record_id"),
            execution_id=ExecutionId(value.get("execution_id")),
            prepared_call_id=PreparedCallId(value.get("prepared_call_id")),
            idempotency_key_fingerprint=value.get("idempotency_key_fingerprint"),
            amount_minor=value.get("amount_minor"),
            currency=value.get("currency"),
            parent_id=ParentId(value.get("parent_id")),
            destination_kind=value.get("destination_kind"),
            masked_destination_display=value.get("masked_destination_display"),
            status=value.get("status"),
            store_version=value.get("store_version"),
            created_at=_dt(value.get("created_at")),
        )
    if event_type is EvidenceEventType.RUN_MODEL_NON_ATTEMPT:
        return ModelNonAttemptPayload(value.get("reason_code"), value.get("candidate_tool_call_count"))
    if event_type is EvidenceEventType.EVIDENCE_RECONCILED:
        return EvidenceReconciledPayload(tuple(value.get("related_event_ids", [])), value.get("masked_detail"))
    if event_type is EvidenceEventType.EVIDENCE_EXPORT_FINALIZED:
        return EvidenceExportFinalizedPayload(
            value.get("export_id"),
            tuple(value.get("ordered_event_ids", [])),
            tuple(value.get("event_digests", [])),
            value.get("overall_digest"),
            tuple(value.get("schema_versions", [])),
        )
    raise ValueError("unsupported evidence payload")


def audit_event_from_primitive(value: object) -> StoredAuditEvent:
    if type(value) is not dict:
        raise TypeError("evidence primitive requires exact dict")
    schema_version = value.get("schema_version")
    event_type_value = value.get("event_type")
    if type(schema_version) is not str or type(event_type_value) is not str:
        raise ValueError("evidence primitive lacks schema/event identity")
    known_event_values = {item.value for item in EvidenceEventType}
    if schema_version != EVIDENCE_SCHEMA_VERSION or event_type_value not in known_event_values:
        payload_value = value.get("payload")
        if type(payload_value) is not list:
            raise TypeError("retained payload requires list")
        retained_payload = tuple(
            RetainedPayloadField(item.get("name"), item.get("value"))
            for item in payload_value
            if type(item) is dict
        )
        return RetainedAuditEvent(
            schema_version=schema_version,
            event_id=value.get("event_id"),
            event_type=event_type_value,
            occurred_at=_dt(value.get("occurred_at")),
            sequence=value.get("sequence"),
            trace_id=value.get("trace_id"),
            producer=_producer(value.get("producer")),
            payload=retained_payload,
            invocation_id=_id(value.get("invocation_id"), InvocationId),
            call_id=_id(value.get("call_id"), CallId),
            decision_id=_id(value.get("decision_id"), DecisionId),
            prepared_call_id=_id(value.get("prepared_call_id"), PreparedCallId),
            execution_id=_id(value.get("execution_id"), ExecutionId),
            policy_version=_id(value.get("policy_version"), PolicyVersion),
            registry_version=_id(value.get("registry_version"), RegistryVersion),
            adapter_id=_id(value.get("adapter_id"), AdapterId),
            adapter_version=_id(value.get("adapter_version"), AdapterVersion),
            previous_event_digest=value.get("previous_event_digest"),
        )
    event_type = EvidenceEventType(event_type_value)
    return AuditEvent(
        schema_version=schema_version,
        event_id=value.get("event_id"),
        event_type=event_type,
        occurred_at=_dt(value.get("occurred_at")),
        sequence=value.get("sequence"),
        trace_id=value.get("trace_id"),
        invocation_id=_id(value.get("invocation_id"), InvocationId),
        call_id=_id(value.get("call_id"), CallId),
        decision_id=_id(value.get("decision_id"), DecisionId),
        prepared_call_id=_id(value.get("prepared_call_id"), PreparedCallId),
        execution_id=_id(value.get("execution_id"), ExecutionId),
        policy_version=_id(value.get("policy_version"), PolicyVersion),
        registry_version=_id(value.get("registry_version"), RegistryVersion),
        adapter_id=_id(value.get("adapter_id"), AdapterId),
        adapter_version=_id(value.get("adapter_version"), AdapterVersion),
        producer=_producer(value.get("producer")),
        payload=_payload(event_type, value.get("payload")),
        previous_event_digest=value.get("previous_event_digest"),
    )


__all__ = (
    "EVIDENCE_SCHEMA_VERSION",
    "ArgumentProjection",
    "ArgumentShape",
    "AuditEvent",
    "AuditPayload",
    "CallbackPayload",
    "CallIntakeRecordedPayload",
    "CallPreparationRefusedPayload",
    "DecisionRecordedPayload",
    "DecisionRuleResult",
    "EvidenceEventType",
    "EvidenceExportFinalizedPayload",
    "EvidenceProducer",
    "EvidenceReconciledPayload",
    "ExecutionRefusedPayload",
    "ExecutionReplayRejectedPayload",
    "ExecutionStartedPayload",
    "ExecutionTerminalPayload",
    "MaskedReasonFact",
    "ModelNonAttemptPayload",
    "PaymentRecordedPayload",
    "PolicyInstallationRefusedPayload",
    "RetainedAuditEvent",
    "RetainedPayloadField",
    "StoredAuditEvent",
    "audit_event_from_primitive",
    "audit_event_to_primitive",
)
