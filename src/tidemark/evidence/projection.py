"""Deterministic immutable masked review projection for stored evidence."""

from dataclasses import dataclass, fields, is_dataclass
from enum import Enum, unique
from hashlib import sha256
from typing import Optional, Tuple, final

from tidemark.evidence.integrity import (
    ForensicAuditRecord,
    _inspect_event_stream,
)
from tidemark.evidence.model import (
    AuditEvent,
    DecisionRecordedPayload,
    EvidenceEventType,
    EvidenceExportFinalizedPayload,
    ExecutionTerminalPayload,
    PaymentRecordedPayload,
    PolicyInstallationRefusedPayload,
    CallPreparationRefusedPayload,
)
from tidemark.evidence.reconciliation import (
    EvidenceReconciler,
    FindingDomain,
    ReconciliationFinding,
    ReconciliationFindingCode,
    ordered_findings,
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


REVIEW_MASKING_PROFILE_VERSION = "tidemark.evidence.review-mask.v1"


@unique
class ProjectionStatus(str, Enum):
    CLEAN = "CLEAN"
    FAILED = "FAILED"


@unique
class EvidenceCompleteness(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"


@unique
class ProjectionDisposition(str, Enum):
    REFUSAL = "REFUSAL"
    DENY = "DENY"
    ALLOW = "ALLOW"
    MODEL_NON_ATTEMPT = "MODEL_NON_ATTEMPT"
    UNDETERMINED = "UNDETERMINED"
    CONFLICT = "CONFLICT"


@unique
class CallbackReviewAction(str, Enum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    RECEIVED = "RECEIVED"
    VETOED = "VETOED"
    RELEASED = "RELEASED"
    TOOL_ENTERED = "TOOL_ENTERED"
    CONFLICT = "CONFLICT"


@unique
class ExecutionReviewStatus(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    REFUSED = "REFUSED"
    COMPLETED = "COMPLETED"
    FAILED_CONFIRMED = "FAILED_CONFIRMED"
    FAILED_AMBIGUOUS = "FAILED_AMBIGUOUS"
    INCOMPLETE = "INCOMPLETE"
    CONFLICT = "CONFLICT"


@unique
class ReplayReviewState(str, Enum):
    NOT_OBSERVED = "NOT_OBSERVED"
    REJECTED = "REJECTED"
    INCONSISTENT = "INCONSISTENT"


_SAFE_DISPLAY_VALUES = {
    "opaque-reference-selected",
    "protected-value-omitted",
    "value-omitted",
}
_SAFE_ARGUMENT_NAMES = {
    "amount_minor",
    "currency",
    "destination_reference",
}
_SAFE_RESOLUTION_STATUSES = {
    "RESOLVED",
    "FAILED",
    "NOT_RESOLVED",
    "NOT_APPLICABLE",
}
_SAFE_BINDING_STATUSES = {"MATCHED", "NOT_MATCHED", "NOT_APPLICABLE"}


@final
@dataclass(frozen=True)
class ReviewArgumentFact:
    name: str
    role: ArgumentRole
    supported_type: TypeId
    provenance_class: ProvenanceClass
    resolution_status: str
    binding_status: str
    masked_display: str

    def __post_init__(self) -> None:
        if type(self.name) is not str or self.name == "":
            raise ValueError("review argument name is invalid")
        if type(self.role) is not ArgumentRole:
            raise TypeError("review role requires ArgumentRole")
        if type(self.supported_type) is not TypeId:
            raise TypeError("review supported_type requires TypeId")
        if type(self.provenance_class) is not ProvenanceClass:
            raise TypeError("review provenance requires ProvenanceClass")
        for value in (
            self.resolution_status,
            self.binding_status,
            self.masked_display,
        ):
            if type(value) is not str or value == "":
                raise ValueError("review argument facts require non-empty text")


@final
@dataclass(frozen=True)
class ReviewReasonFact:
    key: str
    value: object

    def __post_init__(self) -> None:
        if self.key not in {"argument_name", "rule_id"}:
            raise ValueError("review reason key is not allowlisted")
        if self.value is not None and type(self.value) not in (str, bool, int):
            raise TypeError("review reason value requires an exact scalar")


@final
@dataclass(frozen=True)
class ReviewProducerFact:
    component: str
    build_version: str

    def __post_init__(self) -> None:
        for value in (self.component, self.build_version):
            if type(value) is not str or value == "":
                raise ValueError("review producer facts require non-empty text")


@final
@dataclass(frozen=True)
class ReviewRuleFact:
    rule_id: RuleId
    outcome: RuleEvaluationOutcome
    stage: EvaluationStage
    argument_name: Optional[str]
    constraint_id: Optional[ConstraintId]

    def __post_init__(self) -> None:
        if type(self.rule_id) is not RuleId:
            raise TypeError("review rule identity requires RuleId")
        if type(self.outcome) is not RuleEvaluationOutcome:
            raise TypeError("review rule outcome requires RuleEvaluationOutcome")
        if type(self.stage) is not EvaluationStage:
            raise TypeError("review rule stage requires EvaluationStage")
        if self.argument_name is not None and (
            type(self.argument_name) is not str or self.argument_name == ""
        ):
            raise ValueError("review rule argument requires safe non-empty text")
        if self.constraint_id is not None and type(
            self.constraint_id
        ) is not ConstraintId:
            raise TypeError("review rule constraint requires ConstraintId")


@final
@dataclass(frozen=True)
class ReviewProjection:
    trace_id: str
    recorded_at: Optional[str]
    invocation_ids: Tuple[InvocationId, ...]
    call_ids: Tuple[CallId, ...]
    decision_ids: Tuple[DecisionId, ...]
    prepared_call_ids: Tuple[PreparedCallId, ...]
    execution_ids: Tuple[ExecutionId, ...]
    payment_record_ids: Tuple[str, ...]
    tool_ids: Tuple[ToolId, ...]
    tool_contract_versions: Tuple[ToolContractVersion, ...]
    policy_versions: Tuple[PolicyVersion, ...]
    registry_versions: Tuple[RegistryVersion, ...]
    producer_facts: Tuple[ReviewProducerFact, ...]
    evidence_schema_versions: Tuple[str, ...]
    export_digests: Tuple[str, ...]
    masking_profile_version: str
    authorization_outcome: Optional[DecisionOutcome]
    disposition: ProjectionDisposition
    primary_rule_id: Optional[RuleId]
    decision_stage: Optional[EvaluationStage]
    rule_facts: Tuple[ReviewRuleFact, ...]
    callback_action: CallbackReviewAction
    callback_trail: Tuple[EvidenceEventType, ...]
    execution_started: bool
    execution_start_count: int
    execution_status: ExecutionReviewStatus
    external_result_confirmed: Optional[bool]
    payment_recorded: bool
    payment_count: int
    replay_state: ReplayReviewState
    model_non_attempt: bool
    argument_facts: Tuple[ReviewArgumentFact, ...]
    masked_reason_facts: Tuple[ReviewReasonFact, ...]
    integrity_status: ProjectionStatus
    reconciliation_status: ProjectionStatus
    findings: Tuple[ReconciliationFinding, ...]
    schema_gap_count: int
    retained_record_count: int
    forensic_record_count: int
    malformed_record_count: int
    authoritative_event_count: int
    evidence_completeness: EvidenceCompleteness

    def __post_init__(self) -> None:
        if type(self.trace_id) is not str or self.trace_id == "":
            raise ValueError("projection trace_id requires non-empty text")
        if self.recorded_at is not None and (
            type(self.recorded_at) is not str or not self.recorded_at.endswith("Z")
        ):
            raise ValueError("projection recorded_at requires canonical UTC text")
        exact_tuples = (
            (self.invocation_ids, InvocationId),
            (self.call_ids, CallId),
            (self.decision_ids, DecisionId),
            (self.prepared_call_ids, PreparedCallId),
            (self.execution_ids, ExecutionId),
            (self.tool_ids, ToolId),
            (self.tool_contract_versions, ToolContractVersion),
            (self.producer_facts, ReviewProducerFact),
            (self.rule_facts, ReviewRuleFact),
            (self.argument_facts, ReviewArgumentFact),
            (self.masked_reason_facts, ReviewReasonFact),
            (self.findings, ReconciliationFinding),
        )
        for values, kind in exact_tuples:
            if type(values) is not tuple or any(type(item) is not kind for item in values):
                raise TypeError("projection collections require exact immutable values")
        if type(self.payment_record_ids) is not tuple or any(
            type(item) is not str or item == "" for item in self.payment_record_ids
        ):
            raise TypeError("payment correlations require exact strings")
        if type(self.policy_versions) is not tuple or any(
            type(item) is not PolicyVersion for item in self.policy_versions
        ):
            raise TypeError("policy correlations require PolicyVersion")
        if type(self.registry_versions) is not tuple or any(
            type(item) is not RegistryVersion for item in self.registry_versions
        ):
            raise TypeError("registry correlations require RegistryVersion")
        for values, name in (
            (self.evidence_schema_versions, "evidence schema versions"),
            (self.export_digests, "export digests"),
        ):
            if type(values) is not tuple or any(
                type(item) is not str or item == "" for item in values
            ):
                raise TypeError(f"{name} require exact strings")
        if self.masking_profile_version != REVIEW_MASKING_PROFILE_VERSION:
            raise ValueError("projection masking profile is unsupported")
        if self.authorization_outcome is not None and type(
            self.authorization_outcome
        ) is not DecisionOutcome:
            raise TypeError("authorization outcome requires DecisionOutcome")
        if self.primary_rule_id is not None and type(self.primary_rule_id) is not RuleId:
            raise TypeError("primary rule requires RuleId")
        if self.decision_stage is not None and type(
            self.decision_stage
        ) is not EvaluationStage:
            raise TypeError("decision stage requires EvaluationStage")
        for value, kind in (
            (self.disposition, ProjectionDisposition),
            (self.callback_action, CallbackReviewAction),
            (self.execution_status, ExecutionReviewStatus),
            (self.replay_state, ReplayReviewState),
            (self.integrity_status, ProjectionStatus),
            (self.reconciliation_status, ProjectionStatus),
            (self.evidence_completeness, EvidenceCompleteness),
        ):
            if type(value) is not kind:
                raise TypeError("projection status uses a closed value")
        if type(self.callback_trail) is not tuple or any(
            type(item) is not EvidenceEventType for item in self.callback_trail
        ):
            raise TypeError("callback trail requires event types")
        for count in (
            self.execution_start_count,
            self.payment_count,
            self.schema_gap_count,
            self.retained_record_count,
            self.forensic_record_count,
            self.malformed_record_count,
            self.authoritative_event_count,
        ):
            if type(count) is not int or count < 0:
                raise ValueError("projection counts require non-negative ints")
        for value in (
            self.execution_started,
            self.payment_recorded,
            self.model_non_attempt,
        ):
            if type(value) is not bool:
                raise TypeError("projection flags require bool")
        if self.external_result_confirmed is not None and type(
            self.external_result_confirmed
        ) is not bool:
            raise TypeError("external confirmation requires bool or None")


def _identity_tuple(events: Tuple[AuditEvent, ...], attribute: str, kind: type):
    values = {
        getattr(event, attribute).value
        for event in events
        if getattr(event, attribute) is not None
    }
    return tuple(kind(value) for value in sorted(values))


def _recorded_at(events: Tuple[AuditEvent, ...]) -> Optional[str]:
    if not events:
        return None
    explanatory_types = {
        EvidenceEventType.POLICY_INSTALLATION_REFUSED,
        EvidenceEventType.CALL_PREPARATION_REFUSED,
        EvidenceEventType.DECISION_RECORDED,
        EvidenceEventType.RUN_MODEL_NON_ATTEMPT,
    }
    candidates = tuple(
        event for event in events if event.event_type in explanatory_types
    ) or events
    selected = min(
        candidates,
        key=lambda event: (event.trace_id, event.sequence, event.event_type.value),
    )
    return selected.occurred_at.isoformat().replace("+00:00", "Z")


def _payload_identity_tuple(
    events: Tuple[AuditEvent, ...], attribute: str, kind: type
) -> tuple:
    values = {
        getattr(event.payload, attribute).value
        for event in events
        if type(getattr(event.payload, attribute, None)) is kind
    }
    return tuple(kind(value) for value in sorted(values))


def _decision_stage(events: Tuple[AuditEvent, ...]) -> Optional[EvaluationStage]:
    stages = {
        event.payload.stage
        for event in events
        if event.event_type is EvidenceEventType.DECISION_RECORDED
        and type(event.payload) is DecisionRecordedPayload
    }
    return next(iter(stages)) if len(stages) == 1 else None


def _rule_facts(events: Tuple[AuditEvent, ...]) -> Tuple[ReviewRuleFact, ...]:
    selected = []
    for event in sorted(events, key=lambda item: (item.trace_id, item.sequence)):
        if (
            event.event_type is EvidenceEventType.DECISION_RECORDED
            and type(event.payload) is DecisionRecordedPayload
        ):
            for result in event.payload.rule_results:
                selected.append(
                    ReviewRuleFact(
                        rule_id=result.rule_id,
                        outcome=result.outcome,
                        stage=result.stage,
                        argument_name=(
                            result.argument_name
                            if result.argument_name in _SAFE_ARGUMENT_NAMES
                            else "argument-omitted"
                            if result.argument_name is not None
                            else None
                        ),
                        constraint_id=result.constraint_id,
                    )
                )
    return tuple(selected)


def _export_digests(events: Tuple[AuditEvent, ...]) -> Tuple[str, ...]:
    values = {
        event.payload.overall_digest
        for event in events
        if event.event_type is EvidenceEventType.EVIDENCE_EXPORT_FINALIZED
        and type(event.payload) is EvidenceExportFinalizedPayload
    }
    return tuple(sorted(values))


def _trace_identity(events: Tuple[AuditEvent, ...], raw_stream: Tuple[object, ...]) -> str:
    traces = sorted({event.trace_id for event in events})
    if len(traces) == 1:
        return traces[0]
    if len(traces) > 1:
        digest = sha256("\x00".join(traces).encode("utf-8")).hexdigest()
        return "multiple-traces:sha256:" + digest
    retained_traces = sorted(
        {
            item.trace_id
            for item in raw_stream
            if hasattr(item, "trace_id")
            and type(getattr(item, "trace_id")) is str
            and getattr(item, "trace_id")
        }
    )
    forensic_traces = sorted(
        {
            item.trace_fingerprint
            for item in raw_stream
            if type(item) is ForensicAuditRecord
            and item.trace_fingerprint is not None
        }
    )
    inputs = retained_traces + forensic_traces
    if inputs:
        digest = sha256("\x00".join(inputs).encode("utf-8")).hexdigest()
        return "non-authoritative-trace:sha256:" + digest
    return "unresolved-trace"


def _safe_display(value: str) -> str:
    if (
        value in _SAFE_DISPLAY_VALUES
        or "*" in value
        or (
            value.startswith("sha256:")
            and len(value) == 71
            and all(character in "0123456789abcdef" for character in value[7:])
        )
    ):
        return value
    return "masked-value-omitted"


def _argument_facts(events: Tuple[AuditEvent, ...]) -> Tuple[ReviewArgumentFact, ...]:
    selected = []
    for event in events:
        if (
            event.event_type is EvidenceEventType.DECISION_RECORDED
            and type(event.payload) is DecisionRecordedPayload
        ):
            for item in event.payload.argument_projections:
                name = (
                    item.name
                    if item.name in _SAFE_ARGUMENT_NAMES
                    else "argument-omitted"
                )
                selected.append(
                    ReviewArgumentFact(
                        name=name,
                        role=item.role,
                        supported_type=item.supported_type,
                        provenance_class=item.provenance_class,
                        resolution_status=(
                            item.resolution_status
                            if item.resolution_status in _SAFE_RESOLUTION_STATUSES
                            else "STATUS_OMITTED"
                        ),
                        binding_status=(
                            item.binding_status
                            if item.binding_status in _SAFE_BINDING_STATUSES
                            else "STATUS_OMITTED"
                        ),
                        masked_display=_safe_display(item.masked_display),
                    )
                )
    unique = {
        (
            item.name,
            item.role,
            item.supported_type.value,
            item.provenance_class,
            item.resolution_status,
            item.binding_status,
            item.masked_display,
        ): item
        for item in selected
    }
    return tuple(
        sorted(
            unique.values(),
            key=lambda item: (
                item.name,
                item.role.value,
                item.supported_type.value,
            ),
        )
    )


def _reason_facts(events: Tuple[AuditEvent, ...]) -> Tuple[ReviewReasonFact, ...]:
    selected = []
    for event in events:
        if (
            event.event_type is EvidenceEventType.DECISION_RECORDED
            and type(event.payload) is DecisionRecordedPayload
        ):
            argument_names = {
                projection.name
                for projection in event.payload.argument_projections
                if projection.name in _SAFE_ARGUMENT_NAMES
            }
            for fact in event.payload.masked_reason_facts:
                if fact.key not in {"argument_name", "rule_id"}:
                    continue
                value = fact.value
                if (
                    fact.key == "argument_name"
                    and value not in argument_names
                ) or (
                    fact.key == "rule_id"
                    and value not in {item.value for item in RuleId}
                ):
                    value = "masked-value-omitted"
                selected.append(ReviewReasonFact(fact.key, value))
    unique = {(item.key, repr(item.value)): item for item in selected}
    return tuple(sorted(unique.values(), key=lambda item: (item.key, repr(item.value))))


def _disposition(
    events: Tuple[AuditEvent, ...]
) -> Tuple[ProjectionDisposition, Optional[DecisionOutcome], Optional[RuleId]]:
    decisions = tuple(
        event
        for event in events
        if event.event_type is EvidenceEventType.DECISION_RECORDED
        and type(event.payload) is DecisionRecordedPayload
    )
    refusals = tuple(
        event
        for event in events
        if event.event_type
        in {
            EvidenceEventType.POLICY_INSTALLATION_REFUSED,
            EvidenceEventType.CALL_PREPARATION_REFUSED,
        }
    )
    non_attempts = tuple(
        event
        for event in events
        if event.event_type is EvidenceEventType.RUN_MODEL_NON_ATTEMPT
    )
    if non_attempts and (decisions or refusals or len(non_attempts) > 1):
        return ProjectionDisposition.CONFLICT, None, None
    outcomes = {
        event.payload.outcome for event in decisions
    }
    if len(decisions) > 1 or len(outcomes) > 1 or (decisions and refusals):
        return ProjectionDisposition.CONFLICT, None, None
    if decisions:
        event = decisions[0]
        outcome = event.payload.outcome
        disposition = (
            ProjectionDisposition.ALLOW
            if outcome is DecisionOutcome.ALLOW
            else ProjectionDisposition.DENY
        )
        return disposition, outcome, event.payload.primary_rule_id
    if refusals:
        event = refusals[0]
        payload = event.payload
        code = (
            payload.refusal_code
            if type(payload)
            in (PolicyInstallationRefusedPayload, CallPreparationRefusedPayload)
            else None
        )
        try:
            rule = RuleId(code) if code is not None else None
        except ValueError:
            rule = None
        return ProjectionDisposition.REFUSAL, DecisionOutcome.REFUSAL, rule
    if non_attempts:
        return ProjectionDisposition.MODEL_NON_ATTEMPT, None, None
    return ProjectionDisposition.UNDETERMINED, None, None


def _callback(
    events: Tuple[AuditEvent, ...]
) -> Tuple[CallbackReviewAction, Tuple[EvidenceEventType, ...]]:
    callback_types = {
        EvidenceEventType.CALLBACK_RECEIVED,
        EvidenceEventType.CALLBACK_VETOED,
        EvidenceEventType.CALLBACK_RELEASED,
        EvidenceEventType.CALLBACK_TOOL_ENTERED,
    }
    trail = tuple(
        event.event_type
        for event in sorted(events, key=lambda event: event.sequence)
        if event.event_type in callback_types
    )
    present = set(trail)
    if (
        EvidenceEventType.CALLBACK_VETOED in present
        and (
            EvidenceEventType.CALLBACK_RELEASED in present
            or EvidenceEventType.CALLBACK_TOOL_ENTERED in present
        )
    ):
        action = CallbackReviewAction.CONFLICT
    elif EvidenceEventType.CALLBACK_TOOL_ENTERED in present:
        action = CallbackReviewAction.TOOL_ENTERED
    elif EvidenceEventType.CALLBACK_RELEASED in present:
        action = CallbackReviewAction.RELEASED
    elif EvidenceEventType.CALLBACK_VETOED in present:
        action = CallbackReviewAction.VETOED
    elif EvidenceEventType.CALLBACK_RECEIVED in present:
        action = CallbackReviewAction.RECEIVED
    else:
        action = CallbackReviewAction.NOT_APPLICABLE
    return action, trail


def _execution(
    events: Tuple[AuditEvent, ...]
) -> Tuple[bool, int, ExecutionReviewStatus, Optional[bool]]:
    starts = tuple(
        event for event in events if event.event_type is EvidenceEventType.EXECUTION_STARTED
    )
    completed = tuple(
        event for event in events if event.event_type is EvidenceEventType.EXECUTION_COMPLETED
    )
    failed = tuple(
        event for event in events if event.event_type is EvidenceEventType.EXECUTION_FAILED
    )
    refused = tuple(
        event for event in events if event.event_type is EvidenceEventType.EXECUTION_REFUSED
    )
    if (completed and failed) or len(completed) > 1 or len(failed) > 1:
        status = ExecutionReviewStatus.CONFLICT
        confirmed = None
    elif completed:
        status = ExecutionReviewStatus.COMPLETED
        confirmed = True
    elif failed:
        payload = failed[0].payload
        confirmed = (
            payload.external_result_confirmed
            if type(payload) is ExecutionTerminalPayload
            else None
        )
        status = (
            ExecutionReviewStatus.FAILED_CONFIRMED
            if confirmed is True
            else ExecutionReviewStatus.FAILED_AMBIGUOUS
        )
    elif starts:
        status = ExecutionReviewStatus.INCOMPLETE
        confirmed = None
    elif refused:
        status = ExecutionReviewStatus.REFUSED
        confirmed = False
    else:
        status = ExecutionReviewStatus.NOT_STARTED
        confirmed = None
    return bool(starts), len(starts), status, confirmed


def _replay_state(
    events: Tuple[AuditEvent, ...], findings: Tuple[ReconciliationFinding, ...]
) -> ReplayReviewState:
    if any(
        item.code is ReconciliationFindingCode.REPLAY_INCONSISTENCY
        for item in findings
    ):
        return ReplayReviewState.INCONSISTENT
    if any(
        event.event_type is EvidenceEventType.EXECUTION_REPLAY_REJECTED
        for event in events
    ):
        return ReplayReviewState.REJECTED
    return ReplayReviewState.NOT_OBSERVED


@final
class EvidenceProjector:
    """Produce a review-only interpretation from immutable evidence input."""

    __slots__ = ()

    def project(
        self,
        event_stream: Tuple[object, ...],
        masking_profile: str = REVIEW_MASKING_PROFILE_VERSION,
    ) -> ReviewProjection:
        if (
            type(masking_profile) is not str
            or masking_profile != REVIEW_MASKING_PROFILE_VERSION
        ):
            raise ValueError("unknown review masking profile")
        inspected = _inspect_event_stream(event_stream)
        events = inspected.authoritative_events
        reconciliation = EvidenceReconciler().reconcile(events)
        findings = ordered_findings(
            inspected.report.findings + reconciliation.findings
        )
        disposition, outcome, primary_rule = _disposition(events)
        callback_action, callback_trail = _callback(events)
        execution_started, start_count, execution_status, confirmed = _execution(events)
        payments = tuple(
            event
            for event in events
            if event.event_type is EvidenceEventType.PAYMENT_RECORDED
            and type(event.payload) is PaymentRecordedPayload
        )
        payment_ids = tuple(sorted({event.payload.payment_record_id for event in payments}))
        producers = tuple(
            ReviewProducerFact(component, build)
            for component, build in sorted(
                {
                    (event.producer.component, event.producer.build_version)
                    for event in events
                }
            )
        )
        integrity_failed = any(
            item.domain in {FindingDomain.INTEGRITY, FindingDomain.MASKING}
            for item in findings
        )
        reconciliation_failed = any(
            item.domain is FindingDomain.RECONCILIATION for item in findings
        )
        return ReviewProjection(
            trace_id=_trace_identity(events, event_stream),
            recorded_at=_recorded_at(events),
            invocation_ids=_identity_tuple(events, "invocation_id", InvocationId),
            call_ids=_identity_tuple(events, "call_id", CallId),
            decision_ids=_identity_tuple(events, "decision_id", DecisionId),
            prepared_call_ids=_identity_tuple(
                events, "prepared_call_id", PreparedCallId
            ),
            execution_ids=_identity_tuple(events, "execution_id", ExecutionId),
            payment_record_ids=payment_ids,
            tool_ids=_payload_identity_tuple(events, "tool_id", ToolId),
            tool_contract_versions=_payload_identity_tuple(
                events, "contract_version", ToolContractVersion
            ),
            policy_versions=_identity_tuple(events, "policy_version", PolicyVersion),
            registry_versions=_identity_tuple(
                events, "registry_version", RegistryVersion
            ),
            producer_facts=producers,
            evidence_schema_versions=tuple(
                sorted({event.schema_version for event in events})
            ),
            export_digests=_export_digests(events),
            masking_profile_version=masking_profile,
            authorization_outcome=outcome,
            disposition=disposition,
            primary_rule_id=primary_rule,
            decision_stage=_decision_stage(events),
            rule_facts=_rule_facts(events),
            callback_action=callback_action,
            callback_trail=callback_trail,
            execution_started=execution_started,
            execution_start_count=start_count,
            execution_status=execution_status,
            external_result_confirmed=confirmed,
            payment_recorded=bool(payments),
            payment_count=len(payments),
            replay_state=_replay_state(events, findings),
            model_non_attempt=any(
                event.event_type is EvidenceEventType.RUN_MODEL_NON_ATTEMPT
                for event in events
            ),
            argument_facts=_argument_facts(events),
            masked_reason_facts=_reason_facts(events),
            integrity_status=(
                ProjectionStatus.FAILED if integrity_failed else ProjectionStatus.CLEAN
            ),
            reconciliation_status=(
                ProjectionStatus.FAILED
                if reconciliation_failed
                else ProjectionStatus.CLEAN
            ),
            findings=findings,
            schema_gap_count=sum(
                1
                for item in findings
                if item.code is ReconciliationFindingCode.SCHEMA_GAP
            ),
            retained_record_count=inspected.report.retained_record_count,
            forensic_record_count=inspected.report.forensic_record_count,
            malformed_record_count=inspected.report.malformed_record_count,
            authoritative_event_count=inspected.report.authoritative_event_count,
            evidence_completeness=(
                EvidenceCompleteness.COMPLETE
                if not findings
                and disposition is not ProjectionDisposition.UNDETERMINED
                else EvidenceCompleteness.INCOMPLETE
            ),
        )

    def __repr__(self) -> str:
        return "EvidenceProjector(read_only=True, authorization_authority=False)"


def _primitive(value: object) -> object:
    if value is None or type(value) in (str, bool, int):
        return value
    if isinstance(value, Enum):
        return value.value
    if type(value) is tuple:
        return [_primitive(item) for item in value]
    if is_dataclass(value):
        if (
            value.__class__.__module__ == "tidemark.runtime.identifiers"
            and hasattr(value, "value")
        ):
            return value.value
        return {
            field.name: _primitive(getattr(value, field.name))
            for field in fields(value)
        }
    raise TypeError("review projection contains an unsupported value")


def review_projection_to_primitive(projection: ReviewProjection) -> dict:
    if type(projection) is not ReviewProjection:
        raise TypeError("projection requires exact ReviewProjection")
    return {
        field.name: _primitive(getattr(projection, field.name))
        for field in fields(projection)
    }


__all__ = (
    "CallbackReviewAction",
    "EvidenceCompleteness",
    "EvidenceProjector",
    "ExecutionReviewStatus",
    "ProjectionDisposition",
    "ProjectionStatus",
    "REVIEW_MASKING_PROFILE_VERSION",
    "ReplayReviewState",
    "ReviewArgumentFact",
    "ReviewProducerFact",
    "ReviewProjection",
    "ReviewReasonFact",
    "ReviewRuleFact",
    "review_projection_to_primitive",
)
