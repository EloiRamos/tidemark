"""Closed, safe W1 projection of prepared-call mechanism facts.

This module owns the W1 boundary from an exact prepared call to immutable
public metadata.  It intentionally names every accepted public field and does
not retain a prepared runtime object after snapshot construction.
"""

from dataclasses import dataclass
from enum import Enum, unique
import re
from typing import Optional, Tuple, final

from tidemark.evidence.projection import (
    EvidenceCompleteness,
    ExecutionReviewStatus,
    ProjectionDisposition,
    ProjectionStatus,
    ReplayReviewState,
    ReviewProjection,
)
from tidemark.runtime.identifiers import (
    AdapterId,
    AdapterVersion,
    PolicyVersion,
    PreparedCallId,
    RegistryVersion,
    ToolId,
    TypeId,
)
from tidemark.runtime.prepared_call import PreparedArgument, PreparedToolCall
from tidemark.runtime.vocabulary import ArgumentRole, RuleId


MECHANISM_PROJECTION_SCHEMA_VERSION = (
    "tidemark.prepared-call-mechanism-projection.v1"
)
LIFECYCLE_MODEL_VERSION = "tidemark.prepared-call-lifecycle.v1"

_INTEGRITY_ID_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_ALLOWED_ARGUMENT_NAMES = frozenset(
    {"amount_minor", "currency", "destination_reference"}
)
_FORBIDDEN_PUBLIC_TEXT = ("/", "\\", "\x00", "\n", "\r", "<", ">")


def _current_w2_catalogue() -> Tuple[str, tuple]:
    """Read the authoritative W2 metadata only when a projection is built.

    The deferred import preserves the deterministic harness import boundary:
    W2's package runner imports demo preflight, while W1 needs catalogue data
    only after the harness has finished loading.
    """

    from tidemark.proofs.catalogue import CATALOGUE_VERSION, PROOF_CATALOGUE

    return CATALOGUE_VERSION, PROOF_CATALOGUE


@unique
class ProposalCandidateState(str, Enum):
    CANDIDATE_PRESENT = "CANDIDATE_PRESENT"
    MODEL_NON_ATTEMPT = "MODEL_NON_ATTEMPT"


@unique
class ProposalForm(str, Enum):
    OPAQUE_REFERENCE_SELECTED = "OPAQUE_REFERENCE_SELECTED"
    RAW_PROTECTED_VALUE_REDACTED = "RAW_PROTECTED_VALUE_REDACTED"
    VALUE_OMITTED = "VALUE_OMITTED"
    NO_CANDIDATE = "NO_CANDIDATE"


@unique
class ProposalFactProvenance(str, Enum):
    UNTRUSTED_PROPOSAL = "UNTRUSTED_PROPOSAL"


@unique
class ProtectedResolutionState(str, Enum):
    RESOLVED = "RESOLVED"
    FAILED = "FAILED"
    NOT_RESOLVED = "NOT_RESOLVED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@unique
class ProtectedBindingState(str, Enum):
    MATCHED = "MATCHED"
    NOT_MATCHED = "NOT_MATCHED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@unique
class RuntimeValueState(str, Enum):
    BOUND_RUNTIME_PRIVATE = "BOUND_RUNTIME_PRIVATE"
    NOT_BOUND = "NOT_BOUND"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@unique
class LifecycleStageId(str, Enum):
    W1_L01 = "W1-L01"
    W1_L02 = "W1-L02"
    W1_L03 = "W1-L03"
    W1_L04 = "W1-L04"
    W1_L05 = "W1-L05"
    W1_L06 = "W1-L06"
    W1_L07 = "W1-L07"
    W1_L08 = "W1-L08"
    W1_L09 = "W1-L09"
    W1_L10 = "W1-L10"


@unique
class LifecycleTrustZone(str, Enum):
    UNTRUSTED = "UNTRUSTED"
    RUNTIME_TRUSTED = "RUNTIME_TRUSTED"
    EXECUTION_GATE = "EXECUTION_GATE"
    OBSERVED_EVIDENCE = "OBSERVED_EVIDENCE"


@unique
class LifecycleState(str, Enum):
    SATISFIED = "SATISFIED"
    FAILED = "FAILED"
    DENIED = "DENIED"
    REFUSED = "REFUSED"
    NOT_REACHED = "NOT_REACHED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    REPLAY_REJECTED = "REPLAY_REJECTED"
    UNCERTAIN = "UNCERTAIN"


@unique
class ClaimProvenance(str, Enum):
    OBSERVED_MASKED_EVIDENCE = "OBSERVED_MASKED_EVIDENCE"
    DERIVED_FROM_OBSERVED_EVIDENCE = "DERIVED_FROM_OBSERVED_EVIDENCE"
    DERIVED_IMPLEMENTED_CONTRACT = "DERIVED_IMPLEMENTED_CONTRACT"
    APPROVED_STATIC_PRODUCT_COPY = "APPROVED_STATIC_PRODUCT_COPY"


@unique
class LifecycleSummaryKey(str, Enum):
    UNTRUSTED_PROPOSAL = "UNTRUSTED_PROPOSAL"
    PROTECTED_ROLE_RECOGNITION = "PROTECTED_ROLE_RECOGNITION"
    TRUSTED_HANDLE_SELECTION = "TRUSTED_HANDLE_SELECTION"
    RUNTIME_RESOLUTION = "RUNTIME_RESOLUTION"
    TRUSTED_VALUE_BINDING = "TRUSTED_VALUE_BINDING"
    DETERMINISTIC_POLICY_EVALUATION = "DETERMINISTIC_POLICY_EVALUATION"
    PREPARED_CALL_SEALING = "PREPARED_CALL_SEALING"
    EXECUTION_TIME_REVALIDATION = "EXECUTION_TIME_REVALIDATION"
    EVIDENCE_BEFORE_EFFECT = "EVIDENCE_BEFORE_EFFECT"
    EFFECT_REFUSAL_REPLAY_EVIDENCE = "EFFECT_REFUSAL_REPLAY_EVIDENCE"


@unique
class PrivateBindingState(str, Enum):
    REGISTERED_BEFORE_RETURN = "REGISTERED_BEFORE_RETURN"
    NOT_CREATED = "NOT_CREATED"


@unique
class PayloadBindingState(str, Enum):
    EXACT_PAYLOAD_HMAC_BOUND = "EXACT_PAYLOAD_HMAC_BOUND"
    NOT_CREATED = "NOT_CREATED"


@unique
class CorrelationBindingState(str, Enum):
    EXACT_CORRELATIONS_BOUND = "EXACT_CORRELATIONS_BOUND"
    NOT_CREATED = "NOT_CREATED"


@unique
class AdapterBindingState(str, Enum):
    EXACT_ADAPTER_ID_VERSION_BOUND = "EXACT_ADAPTER_ID_VERSION_BOUND"
    NOT_CREATED = "NOT_CREATED"


@unique
class SingleUseTargetState(str, Enum):
    EXACT_PRIVATE_TARGET_SET_BOUND = "EXACT_PRIVATE_TARGET_SET_BOUND"
    NOT_CREATED = "NOT_CREATED"


@unique
class ObjectBindingState(str, Enum):
    EXACT_PREPARED_OBJECT_BOUND = "EXACT_PREPARED_OBJECT_BOUND"
    NOT_CREATED = "NOT_CREATED"


@unique
class TerminalDecision(str, Enum):
    REFUSAL = "REFUSAL"
    DENY = "DENY"
    ALLOW = "ALLOW"
    MODEL_NON_ATTEMPT = "MODEL_NON_ATTEMPT"
    CONFLICT = "CONFLICT"
    UNDETERMINED = "UNDETERMINED"


@unique
class UiProofExecutionStatus(str, Enum):
    REFERENCE_ONLY_NOT_EXECUTED_BY_UI = "REFERENCE_ONLY_NOT_EXECUTED_BY_UI"


def _require_exact_identifier(value: object, kind: type, field_name: str) -> None:
    if type(value) is not kind:
        raise TypeError(f"{field_name} requires {kind.__name__}")
    if type(value.value) is not str or value.value == "":
        raise ValueError(f"{field_name} requires a non-empty identifier")
    if any(token in value.value for token in _FORBIDDEN_PUBLIC_TEXT):
        raise ValueError(f"{field_name} is outside the safe public identifier set")


def _require_argument_name(value: object, field_name: str) -> None:
    if type(value) is not str or value not in _ALLOWED_ARGUMENT_NAMES:
        raise ValueError(f"{field_name} is not allowlisted")


@final
@dataclass(frozen=True)
class PreparedArgumentMetadata:
    name: str
    type_id: TypeId
    role: ArgumentRole

    def __post_init__(self) -> None:
        _require_argument_name(self.name, "name")
        _require_exact_identifier(self.type_id, TypeId, "type_id")
        if type(self.role) is not ArgumentRole:
            raise TypeError("role requires ArgumentRole")


@final
@dataclass(frozen=True)
class PreparedCallPublicSnapshot:
    prepared_call_id: PreparedCallId
    public_integrity_id: str
    tool_id: ToolId
    policy_version: PolicyVersion
    registry_version: RegistryVersion
    adapter_id: AdapterId
    adapter_version: AdapterVersion
    arguments: Tuple[PreparedArgumentMetadata, ...]

    def __post_init__(self) -> None:
        _require_exact_identifier(self.prepared_call_id, PreparedCallId, "prepared_call_id")
        if (
            type(self.public_integrity_id) is not str
            or _INTEGRITY_ID_PATTERN.fullmatch(self.public_integrity_id) is None
        ):
            raise ValueError("public_integrity_id requires a lowercase sha256 digest")
        _require_exact_identifier(self.tool_id, ToolId, "tool_id")
        _require_exact_identifier(self.policy_version, PolicyVersion, "policy_version")
        _require_exact_identifier(self.registry_version, RegistryVersion, "registry_version")
        _require_exact_identifier(self.adapter_id, AdapterId, "adapter_id")
        _require_exact_identifier(self.adapter_version, AdapterVersion, "adapter_version")
        if type(self.arguments) is not tuple or any(
            type(item) is not PreparedArgumentMetadata for item in self.arguments
        ):
            raise TypeError("arguments require exact PreparedArgumentMetadata values")
        names = tuple(item.name for item in self.arguments)
        if len(names) != len(set(names)):
            raise ValueError("argument metadata names must be unique")


def capture_prepared_call_public_snapshot(
    prepared_call: PreparedToolCall,
) -> PreparedCallPublicSnapshot:
    """Copy the exact allowed public fields before presentation can begin."""

    if type(prepared_call) is not PreparedToolCall:
        raise TypeError("prepared_call requires an exact PreparedToolCall")
    metadata = []
    for argument in prepared_call.arguments:
        if type(argument) is not PreparedArgument:
            raise TypeError("prepared_call arguments require exact PreparedArgument")
        metadata.append(
            PreparedArgumentMetadata(
                name=argument.name,
                type_id=argument.type_id,
                role=argument.role,
            )
        )
    return PreparedCallPublicSnapshot(
        prepared_call_id=prepared_call.prepared_call_id,
        public_integrity_id=prepared_call.integrity_id,
        tool_id=prepared_call.tool_id,
        policy_version=prepared_call.policy_version,
        registry_version=prepared_call.registry_version,
        adapter_id=prepared_call.adapter_id,
        adapter_version=prepared_call.adapter_version,
        arguments=tuple(metadata),
    )


@final
@dataclass(frozen=True)
class ProposalMechanismFact:
    candidate_state: ProposalCandidateState
    tool_id: Optional[ToolId]
    proposed_form: ProposalForm
    provenance: ProposalFactProvenance

    def __post_init__(self) -> None:
        if type(self.candidate_state) is not ProposalCandidateState:
            raise TypeError("candidate_state requires ProposalCandidateState")
        if self.tool_id is not None:
            _require_exact_identifier(self.tool_id, ToolId, "tool_id")
        if type(self.proposed_form) is not ProposalForm:
            raise TypeError("proposed_form requires ProposalForm")
        if type(self.provenance) is not ProposalFactProvenance:
            raise TypeError("provenance requires ProposalFactProvenance")
        if self.candidate_state is ProposalCandidateState.MODEL_NON_ATTEMPT:
            if self.tool_id is not None or self.proposed_form is not ProposalForm.NO_CANDIDATE:
                raise ValueError("model non-attempt cannot project a candidate")
        elif self.tool_id is None or self.proposed_form is ProposalForm.NO_CANDIDATE:
            raise ValueError("candidate requires a public tool and safe proposed form")


@final
@dataclass(frozen=True)
class ProtectedArgumentMechanismFact:
    name: str
    role: ArgumentRole
    supported_type: TypeId
    resolution_state: ProtectedResolutionState
    binding_state: ProtectedBindingState
    runtime_value_state: RuntimeValueState

    def __post_init__(self) -> None:
        _require_argument_name(self.name, "name")
        if type(self.role) is not ArgumentRole:
            raise TypeError("role requires ArgumentRole")
        if self.role is not ArgumentRole.PROTECTED_REFERENCE:
            raise ValueError("mechanism facts require protected arguments")
        _require_exact_identifier(self.supported_type, TypeId, "supported_type")
        if type(self.resolution_state) is not ProtectedResolutionState:
            raise TypeError("resolution_state requires ProtectedResolutionState")
        if type(self.binding_state) is not ProtectedBindingState:
            raise TypeError("binding_state requires ProtectedBindingState")
        if type(self.runtime_value_state) is not RuntimeValueState:
            raise TypeError("runtime_value_state requires RuntimeValueState")


@final
@dataclass(frozen=True)
class LifecycleStageFact:
    stage_id: LifecycleStageId
    ordinal: int
    title: str
    trust_zone: LifecycleTrustZone
    state: LifecycleState
    fact_provenance: ClaimProvenance
    safe_summary: LifecycleSummaryKey
    w2_property_ids: Tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.stage_id) is not LifecycleStageId:
            raise TypeError("stage_id requires LifecycleStageId")
        if type(self.ordinal) is not int or not 1 <= self.ordinal <= 10:
            raise ValueError("ordinal requires an exact value from 1 through 10")
        if type(self.title) is not str or self.title == "":
            raise ValueError("title requires safe text")
        if type(self.trust_zone) is not LifecycleTrustZone:
            raise TypeError("trust_zone requires LifecycleTrustZone")
        if type(self.state) is not LifecycleState:
            raise TypeError("state requires LifecycleState")
        if type(self.fact_provenance) is not ClaimProvenance:
            raise TypeError("fact_provenance requires ClaimProvenance")
        if type(self.safe_summary) is not LifecycleSummaryKey:
            raise TypeError("safe_summary requires LifecycleSummaryKey")
        if type(self.w2_property_ids) is not tuple or any(
            type(value) is not str for value in self.w2_property_ids
        ):
            raise TypeError("w2_property_ids require an exact string tuple")
        if not self.w2_property_ids or len(self.w2_property_ids) != len(set(self.w2_property_ids)):
            raise ValueError("w2_property_ids require non-empty unique values")
        expected = _lifecycle_contract_for_stage(self.stage_id)
        if (
            self.ordinal,
            self.title,
            self.trust_zone,
            self.fact_provenance,
            self.safe_summary,
            self.w2_property_ids,
        ) != expected[1:]:
            raise ValueError("lifecycle stage metadata diverges from the W1 contract")


@final
@dataclass(frozen=True)
class PreparedCallSealFact:
    prepared_call_present: bool
    public_prepared_call_id: Optional[PreparedCallId]
    public_integrity_id: Optional[str]
    adapter_id: Optional[AdapterId]
    adapter_version: Optional[AdapterVersion]
    argument_metadata: Tuple[PreparedArgumentMetadata, ...]
    private_binding_state: PrivateBindingState
    payload_binding_state: PayloadBindingState
    correlation_binding_state: CorrelationBindingState
    adapter_binding_state: AdapterBindingState
    single_use_target_state: SingleUseTargetState
    object_binding_state: ObjectBindingState
    private_material_projected: bool

    def __post_init__(self) -> None:
        if type(self.prepared_call_present) is not bool:
            raise TypeError("prepared_call_present requires bool")
        for value, kind, field_name in (
            (self.private_binding_state, PrivateBindingState, "private_binding_state"),
            (self.payload_binding_state, PayloadBindingState, "payload_binding_state"),
            (self.correlation_binding_state, CorrelationBindingState, "correlation_binding_state"),
            (self.adapter_binding_state, AdapterBindingState, "adapter_binding_state"),
            (self.single_use_target_state, SingleUseTargetState, "single_use_target_state"),
            (self.object_binding_state, ObjectBindingState, "object_binding_state"),
        ):
            if type(value) is not kind:
                raise TypeError(f"{field_name} requires {kind.__name__}")
        if type(self.private_material_projected) is not bool or self.private_material_projected:
            raise ValueError("private_material_projected must be false")
        if type(self.argument_metadata) is not tuple or any(
            type(item) is not PreparedArgumentMetadata
            for item in self.argument_metadata
        ):
            raise TypeError("argument_metadata requires exact metadata values")
        if self.prepared_call_present:
            _require_exact_identifier(self.public_prepared_call_id, PreparedCallId, "public_prepared_call_id")
            if (
                type(self.public_integrity_id) is not str
                or _INTEGRITY_ID_PATTERN.fullmatch(self.public_integrity_id) is None
            ):
                raise ValueError("public_integrity_id requires a lowercase sha256 digest")
            _require_exact_identifier(self.adapter_id, AdapterId, "adapter_id")
            _require_exact_identifier(self.adapter_version, AdapterVersion, "adapter_version")
            if (
                self.private_binding_state is not PrivateBindingState.REGISTERED_BEFORE_RETURN
                or self.payload_binding_state is not PayloadBindingState.EXACT_PAYLOAD_HMAC_BOUND
                or self.correlation_binding_state is not CorrelationBindingState.EXACT_CORRELATIONS_BOUND
                or self.adapter_binding_state is not AdapterBindingState.EXACT_ADAPTER_ID_VERSION_BOUND
                or self.single_use_target_state is not SingleUseTargetState.EXACT_PRIVATE_TARGET_SET_BOUND
                or self.object_binding_state is not ObjectBindingState.EXACT_PREPARED_OBJECT_BOUND
            ):
                raise ValueError("present prepared calls require closed binding coverage")
        elif (
            self.public_prepared_call_id is not None
            or self.public_integrity_id is not None
            or self.adapter_id is not None
            or self.adapter_version is not None
            or self.argument_metadata
            or self.private_binding_state is not PrivateBindingState.NOT_CREATED
            or self.payload_binding_state is not PayloadBindingState.NOT_CREATED
            or self.correlation_binding_state is not CorrelationBindingState.NOT_CREATED
            or self.adapter_binding_state is not AdapterBindingState.NOT_CREATED
            or self.single_use_target_state is not SingleUseTargetState.NOT_CREATED
            or self.object_binding_state is not ObjectBindingState.NOT_CREATED
        ):
            raise ValueError("absent prepared calls require exact not-created facts")


@final
@dataclass(frozen=True)
class LifecycleTerminalFact:
    decision: TerminalDecision
    primary_rule_id: Optional[RuleId]
    execution_status: ExecutionReviewStatus
    execution_start_count: int
    authoritative_synthetic_payment_count: int
    replay_state: ReplayReviewState
    external_result_confirmed: Optional[bool]
    evidence_completeness: EvidenceCompleteness
    integrity_status: ProjectionStatus
    reconciliation_status: ProjectionStatus

    def __post_init__(self) -> None:
        if type(self.decision) is not TerminalDecision:
            raise TypeError("decision requires TerminalDecision")
        if self.primary_rule_id is not None and type(self.primary_rule_id) is not RuleId:
            raise TypeError("primary_rule_id requires RuleId or None")
        for value, kind, field_name in (
            (self.execution_status, ExecutionReviewStatus, "execution_status"),
            (self.replay_state, ReplayReviewState, "replay_state"),
            (self.evidence_completeness, EvidenceCompleteness, "evidence_completeness"),
            (self.integrity_status, ProjectionStatus, "integrity_status"),
            (self.reconciliation_status, ProjectionStatus, "reconciliation_status"),
        ):
            if type(value) is not kind:
                raise TypeError(f"{field_name} requires {kind.__name__}")
        for value, field_name in (
            (self.execution_start_count, "execution_start_count"),
            (self.authoritative_synthetic_payment_count, "authoritative_synthetic_payment_count"),
        ):
            if type(value) is not int or value < 0:
                raise ValueError(f"{field_name} requires a non-negative exact int")
        if self.external_result_confirmed is not None and type(self.external_result_confirmed) is not bool:
            raise TypeError("external_result_confirmed requires bool or None")


_W2_REFERENCE_CONTRACTS = (
    ("W2-P01", "Runtime-issued selection may reach effect; raw protected supply may not."),
    ("W2-P02", "Post-ALLOW gate refusal remains ALLOW plus execution REFUSED."),
    ("W2-P03", "Local durable prerequisite only; no distributed transaction claim."),
    ("W2-P04", "One local capability, with no second local adapter entry or payment."),
    ("W2-P05", "Fixed 12 attempts/six-worker local proof; local at-most-once only, with no distributed exactly-once claim."),
    ("W2-P06", "Seven bounded failure classes; no host-tamper or attestation claim."),
    ("W2-P07", "Existence, kind, invocation, parent, active, and single-use context only; no identity or passkey claim."),
    ("W2-P08", "Proof PASS means uncertainty was preserved; it is not evidence PASS, execution success, or external-effect absence."),
)


def _w2_contract(property_id: str) -> Tuple[str, str]:
    _, catalogue = _current_w2_catalogue()
    for expected_id, qualifier in _W2_REFERENCE_CONTRACTS:
        if property_id == expected_id:
            for definition in catalogue:
                if definition.property_id == property_id:
                    return definition.property_title, qualifier
    raise ValueError("property_id is outside the closed W2 catalogue")


@final
@dataclass(frozen=True)
class W2ProofReference:
    property_id: str
    property_title: str
    catalogue_version: str
    reviewer_hint: str
    ui_execution_status: UiProofExecutionStatus
    qualifier: str

    def __post_init__(self) -> None:
        if type(self.property_id) is not str:
            raise TypeError("property_id requires an exact string")
        expected_title, expected_qualifier = _w2_contract(self.property_id)
        if type(self.property_title) is not str or self.property_title != expected_title:
            raise ValueError("property_title must match the current W2 catalogue")
        catalogue_version, _ = _current_w2_catalogue()
        if self.catalogue_version != catalogue_version:
            raise ValueError("catalogue_version must match the current W2 catalogue")
        if self.reviewer_hint != f"make prove PROPERTY={self.property_id}":
            raise ValueError("reviewer_hint must be the exact W2 proof command")
        if type(self.ui_execution_status) is not UiProofExecutionStatus:
            raise TypeError("ui_execution_status requires UiProofExecutionStatus")
        if type(self.qualifier) is not str or self.qualifier != expected_qualifier:
            raise ValueError("qualifier must match the closed W2 contract")


_LIFECYCLE_CONTRACT = (
    (LifecycleStageId.W1_L01, 1, "UNTRUSTED PROPOSAL", LifecycleTrustZone.UNTRUSTED, ClaimProvenance.DERIVED_FROM_OBSERVED_EVIDENCE, LifecycleSummaryKey.UNTRUSTED_PROPOSAL, ("W2-P01", "W2-P08")),
    (LifecycleStageId.W1_L02, 2, "PROTECTED-ROLE RECOGNITION", LifecycleTrustZone.RUNTIME_TRUSTED, ClaimProvenance.DERIVED_FROM_OBSERVED_EVIDENCE, LifecycleSummaryKey.PROTECTED_ROLE_RECOGNITION, ("W2-P01",)),
    (LifecycleStageId.W1_L03, 3, "TRUSTED HANDLE SELECTION", LifecycleTrustZone.RUNTIME_TRUSTED, ClaimProvenance.DERIVED_FROM_OBSERVED_EVIDENCE, LifecycleSummaryKey.TRUSTED_HANDLE_SELECTION, ("W2-P01",)),
    (LifecycleStageId.W1_L04, 4, "RUNTIME RESOLUTION", LifecycleTrustZone.RUNTIME_TRUSTED, ClaimProvenance.OBSERVED_MASKED_EVIDENCE, LifecycleSummaryKey.RUNTIME_RESOLUTION, ("W2-P07",)),
    (LifecycleStageId.W1_L05, 5, "TRUSTED VALUE BINDING", LifecycleTrustZone.RUNTIME_TRUSTED, ClaimProvenance.DERIVED_FROM_OBSERVED_EVIDENCE, LifecycleSummaryKey.TRUSTED_VALUE_BINDING, ("W2-P07",)),
    (LifecycleStageId.W1_L06, 6, "DETERMINISTIC POLICY EVALUATION", LifecycleTrustZone.RUNTIME_TRUSTED, ClaimProvenance.OBSERVED_MASKED_EVIDENCE, LifecycleSummaryKey.DETERMINISTIC_POLICY_EVALUATION, ("W2-P01", "W2-P07")),
    (LifecycleStageId.W1_L07, 7, "PREPARED-CALL SEALING", LifecycleTrustZone.RUNTIME_TRUSTED, ClaimProvenance.DERIVED_IMPLEMENTED_CONTRACT, LifecycleSummaryKey.PREPARED_CALL_SEALING, ("W2-P06",)),
    (LifecycleStageId.W1_L08, 8, "EXECUTION-TIME REVALIDATION", LifecycleTrustZone.EXECUTION_GATE, ClaimProvenance.DERIVED_IMPLEMENTED_CONTRACT, LifecycleSummaryKey.EXECUTION_TIME_REVALIDATION, ("W2-P02", "W2-P04", "W2-P05", "W2-P06")),
    (LifecycleStageId.W1_L09, 9, "EVIDENCE BEFORE EFFECT", LifecycleTrustZone.EXECUTION_GATE, ClaimProvenance.DERIVED_IMPLEMENTED_CONTRACT, LifecycleSummaryKey.EVIDENCE_BEFORE_EFFECT, ("W2-P03",)),
    (LifecycleStageId.W1_L10, 10, "EFFECT / REFUSAL / REPLAY EVIDENCE", LifecycleTrustZone.OBSERVED_EVIDENCE, ClaimProvenance.OBSERVED_MASKED_EVIDENCE, LifecycleSummaryKey.EFFECT_REFUSAL_REPLAY_EVIDENCE, ("W2-P02", "W2-P04", "W2-P05", "W2-P08")),
)


def _lifecycle_contract_for_stage(
    stage_id: LifecycleStageId,
) -> tuple:
    for contract in _LIFECYCLE_CONTRACT:
        if stage_id is contract[0]:
            return contract
    raise ValueError("stage_id is outside the closed W1 lifecycle")


@final
@dataclass(frozen=True)
class PreparedCallMechanismProjection:
    schema_version: str
    lifecycle_model_version: str
    proposal: ProposalMechanismFact
    protected_arguments: Tuple[ProtectedArgumentMechanismFact, ...]
    stages: Tuple[LifecycleStageFact, ...]
    seal: PreparedCallSealFact
    terminal: LifecycleTerminalFact
    proof_references: Tuple[W2ProofReference, ...]

    def __post_init__(self) -> None:
        if self.schema_version != MECHANISM_PROJECTION_SCHEMA_VERSION:
            raise ValueError("mechanism projection schema version is unsupported")
        if self.lifecycle_model_version != LIFECYCLE_MODEL_VERSION:
            raise ValueError("lifecycle model version is unsupported")
        if type(self.proposal) is not ProposalMechanismFact:
            raise TypeError("proposal requires ProposalMechanismFact")
        if type(self.protected_arguments) is not tuple or any(
            type(item) is not ProtectedArgumentMechanismFact
            for item in self.protected_arguments
        ):
            raise TypeError("protected_arguments require exact mechanism facts")
        if len({item.name for item in self.protected_arguments}) != len(self.protected_arguments):
            raise ValueError("protected argument facts must be unique")
        if type(self.stages) is not tuple or any(
            type(item) is not LifecycleStageFact for item in self.stages
        ):
            raise TypeError("stages require exact lifecycle facts")
        expected_stage_ids = tuple(item[0] for item in _LIFECYCLE_CONTRACT)
        if tuple(item.stage_id for item in self.stages) != expected_stage_ids:
            raise ValueError("lifecycle stages must be the exact ordered W1 contract")
        for stage, contract in zip(self.stages, _LIFECYCLE_CONTRACT):
            if (
                stage.ordinal,
                stage.title,
                stage.trust_zone,
                stage.fact_provenance,
                stage.safe_summary,
                stage.w2_property_ids,
            ) != contract[1:]:
                raise ValueError("lifecycle stage metadata diverges from the W1 contract")
        if type(self.seal) is not PreparedCallSealFact:
            raise TypeError("seal requires PreparedCallSealFact")
        if type(self.terminal) is not LifecycleTerminalFact:
            raise TypeError("terminal requires LifecycleTerminalFact")
        if type(self.proof_references) is not tuple or any(
            type(item) is not W2ProofReference for item in self.proof_references
        ):
            raise TypeError("proof_references require exact W2ProofReference values")
        expected_proof_ids = tuple(item[0] for item in _W2_REFERENCE_CONTRACTS)
        if tuple(item.property_id for item in self.proof_references) != expected_proof_ids:
            raise ValueError("proof references must be the exact ordered W2 contract")


def _single_review_tool_id(review: ReviewProjection) -> ToolId:
    if len(review.tool_ids) != 1:
        raise ValueError("candidate projection requires one safe tool correlation")
    return review.tool_ids[0]


def _validate_snapshot_review_alignment(
    snapshot: Optional[PreparedCallPublicSnapshot], review: ReviewProjection
) -> None:
    if snapshot is None:
        if review.prepared_call_ids:
            raise ValueError("prepared evidence requires a safe public snapshot")
        return
    if review.prepared_call_ids != (snapshot.prepared_call_id,):
        raise ValueError("prepared-call correlation does not match the safe snapshot")
    if review.tool_ids != (snapshot.tool_id,):
        raise ValueError("tool correlation does not match the safe snapshot")
    if review.policy_versions != (snapshot.policy_version,):
        raise ValueError("policy correlation does not match the safe snapshot")
    if review.registry_versions != (snapshot.registry_version,):
        raise ValueError("registry correlation does not match the safe snapshot")


def _protected_argument_facts(
    snapshot: Optional[PreparedCallPublicSnapshot], review: ReviewProjection
) -> Tuple[ProtectedArgumentMechanismFact, ...]:
    facts = []
    for observed in review.argument_facts:
        if observed.role is not ArgumentRole.PROTECTED_REFERENCE:
            continue
        try:
            resolution_state = ProtectedResolutionState(observed.resolution_status)
            binding_state = ProtectedBindingState(observed.binding_status)
        except ValueError:
            raise ValueError("review protected-argument state is outside the W1 contract") from None
        runtime_value_state = (
            RuntimeValueState.BOUND_RUNTIME_PRIVATE
            if snapshot is not None
            and resolution_state is ProtectedResolutionState.RESOLVED
            and binding_state is ProtectedBindingState.MATCHED
            else RuntimeValueState.NOT_BOUND
        )
        facts.append(
            ProtectedArgumentMechanismFact(
                name=observed.name,
                role=observed.role,
                supported_type=observed.supported_type,
                resolution_state=resolution_state,
                binding_state=binding_state,
                runtime_value_state=runtime_value_state,
            )
        )
    return tuple(facts)


def _proposal_fact(
    snapshot: Optional[PreparedCallPublicSnapshot], review: ReviewProjection
) -> ProposalMechanismFact:
    if review.model_non_attempt:
        if snapshot is not None:
            raise ValueError("model non-attempt cannot retain a prepared snapshot")
        return ProposalMechanismFact(
            candidate_state=ProposalCandidateState.MODEL_NON_ATTEMPT,
            tool_id=None,
            proposed_form=ProposalForm.NO_CANDIDATE,
            provenance=ProposalFactProvenance.UNTRUSTED_PROPOSAL,
        )
    tool_id = snapshot.tool_id if snapshot is not None else _single_review_tool_id(review)
    if review.primary_rule_id is RuleId.PROTECTED_RAW_VALUE_SUPPLIED:
        proposed_form = ProposalForm.RAW_PROTECTED_VALUE_REDACTED
    elif any(
        fact.role is ArgumentRole.PROTECTED_REFERENCE
        and fact.masked_display == "opaque-reference-selected"
        for fact in review.argument_facts
    ):
        proposed_form = ProposalForm.OPAQUE_REFERENCE_SELECTED
    else:
        proposed_form = ProposalForm.VALUE_OMITTED
    return ProposalMechanismFact(
        candidate_state=ProposalCandidateState.CANDIDATE_PRESENT,
        tool_id=tool_id,
        proposed_form=proposed_form,
        provenance=ProposalFactProvenance.UNTRUSTED_PROPOSAL,
    )


def _seal_fact(
    snapshot: Optional[PreparedCallPublicSnapshot],
) -> PreparedCallSealFact:
    if snapshot is None:
        return PreparedCallSealFact(
            prepared_call_present=False,
            public_prepared_call_id=None,
            public_integrity_id=None,
            adapter_id=None,
            adapter_version=None,
            argument_metadata=(),
            private_binding_state=PrivateBindingState.NOT_CREATED,
            payload_binding_state=PayloadBindingState.NOT_CREATED,
            correlation_binding_state=CorrelationBindingState.NOT_CREATED,
            adapter_binding_state=AdapterBindingState.NOT_CREATED,
            single_use_target_state=SingleUseTargetState.NOT_CREATED,
            object_binding_state=ObjectBindingState.NOT_CREATED,
            private_material_projected=False,
        )
    return PreparedCallSealFact(
        prepared_call_present=True,
        public_prepared_call_id=snapshot.prepared_call_id,
        public_integrity_id=snapshot.public_integrity_id,
        adapter_id=snapshot.adapter_id,
        adapter_version=snapshot.adapter_version,
        argument_metadata=snapshot.arguments,
        private_binding_state=PrivateBindingState.REGISTERED_BEFORE_RETURN,
        payload_binding_state=PayloadBindingState.EXACT_PAYLOAD_HMAC_BOUND,
        correlation_binding_state=CorrelationBindingState.EXACT_CORRELATIONS_BOUND,
        adapter_binding_state=AdapterBindingState.EXACT_ADAPTER_ID_VERSION_BOUND,
        single_use_target_state=SingleUseTargetState.EXACT_PRIVATE_TARGET_SET_BOUND,
        object_binding_state=ObjectBindingState.EXACT_PREPARED_OBJECT_BOUND,
        private_material_projected=False,
    )


def _terminal_fact(review: ReviewProjection) -> LifecycleTerminalFact:
    decision_by_disposition = (
        (ProjectionDisposition.REFUSAL, TerminalDecision.REFUSAL),
        (ProjectionDisposition.DENY, TerminalDecision.DENY),
        (ProjectionDisposition.ALLOW, TerminalDecision.ALLOW),
        (ProjectionDisposition.MODEL_NON_ATTEMPT, TerminalDecision.MODEL_NON_ATTEMPT),
        (ProjectionDisposition.CONFLICT, TerminalDecision.CONFLICT),
        (ProjectionDisposition.UNDETERMINED, TerminalDecision.UNDETERMINED),
    )
    for disposition, terminal_decision in decision_by_disposition:
        if review.disposition is disposition:
            return LifecycleTerminalFact(
                decision=terminal_decision,
                primary_rule_id=review.primary_rule_id,
                execution_status=review.execution_status,
                execution_start_count=review.execution_start_count,
                authoritative_synthetic_payment_count=review.payment_count,
                replay_state=review.replay_state,
                external_result_confirmed=review.external_result_confirmed,
                evidence_completeness=review.evidence_completeness,
                integrity_status=review.integrity_status,
                reconciliation_status=review.reconciliation_status,
            )
    raise ValueError("review disposition is outside the closed W1 contract")


def _policy_stage_state(terminal: LifecycleTerminalFact) -> LifecycleState:
    if terminal.decision is TerminalDecision.ALLOW:
        return LifecycleState.SATISFIED
    if terminal.decision is TerminalDecision.DENY:
        return LifecycleState.DENIED
    if terminal.decision is TerminalDecision.REFUSAL:
        return LifecycleState.REFUSED
    if terminal.decision is TerminalDecision.MODEL_NON_ATTEMPT:
        return LifecycleState.NOT_REACHED
    return LifecycleState.UNCERTAIN


def _resolution_stage_state(
    protected_arguments: Tuple[ProtectedArgumentMechanismFact, ...]
) -> LifecycleState:
    if not protected_arguments:
        return LifecycleState.REFUSED
    states = tuple(item.resolution_state for item in protected_arguments)
    if ProtectedResolutionState.FAILED in states:
        return LifecycleState.FAILED
    if all(item is ProtectedResolutionState.RESOLVED for item in states):
        return LifecycleState.SATISFIED
    if all(item is ProtectedResolutionState.NOT_APPLICABLE for item in states):
        return LifecycleState.NOT_APPLICABLE
    return LifecycleState.NOT_REACHED


def _binding_stage_state(
    protected_arguments: Tuple[ProtectedArgumentMechanismFact, ...]
) -> LifecycleState:
    if not protected_arguments:
        return LifecycleState.REFUSED
    states = tuple(item.binding_state for item in protected_arguments)
    if ProtectedBindingState.NOT_MATCHED in states:
        return LifecycleState.FAILED
    if all(item is ProtectedBindingState.MATCHED for item in states):
        return LifecycleState.SATISFIED
    if all(item is ProtectedBindingState.NOT_APPLICABLE for item in states):
        return LifecycleState.NOT_APPLICABLE
    return LifecycleState.NOT_REACHED


def _execution_revalidation_stage_state(
    snapshot: Optional[PreparedCallPublicSnapshot],
    terminal: LifecycleTerminalFact,
) -> LifecycleState:
    if snapshot is None:
        return LifecycleState.NOT_REACHED
    if terminal.replay_state is ReplayReviewState.REJECTED:
        return LifecycleState.REPLAY_REJECTED
    if terminal.execution_status is ExecutionReviewStatus.REFUSED:
        return LifecycleState.REFUSED
    if terminal.execution_status in {
        ExecutionReviewStatus.COMPLETED,
        ExecutionReviewStatus.FAILED_CONFIRMED,
        ExecutionReviewStatus.FAILED_AMBIGUOUS,
    }:
        return LifecycleState.SATISFIED
    if terminal.execution_status in {
        ExecutionReviewStatus.INCOMPLETE,
        ExecutionReviewStatus.CONFLICT,
    }:
        return LifecycleState.UNCERTAIN
    return LifecycleState.NOT_REACHED


def _effect_stage_state(terminal: LifecycleTerminalFact) -> LifecycleState:
    if terminal.decision is TerminalDecision.MODEL_NON_ATTEMPT:
        return LifecycleState.NOT_APPLICABLE
    if terminal.decision is TerminalDecision.DENY:
        return LifecycleState.DENIED
    if terminal.decision is TerminalDecision.REFUSAL:
        return LifecycleState.REFUSED
    if terminal.replay_state is ReplayReviewState.REJECTED:
        return LifecycleState.REPLAY_REJECTED
    if terminal.execution_status in {
        ExecutionReviewStatus.COMPLETED,
        ExecutionReviewStatus.FAILED_CONFIRMED,
        ExecutionReviewStatus.FAILED_AMBIGUOUS,
    }:
        return LifecycleState.SATISFIED
    if terminal.execution_status is ExecutionReviewStatus.REFUSED:
        return LifecycleState.REFUSED
    if terminal.execution_status in {
        ExecutionReviewStatus.INCOMPLETE,
        ExecutionReviewStatus.CONFLICT,
    }:
        return LifecycleState.UNCERTAIN
    return LifecycleState.NOT_REACHED


def _lifecycle_stages(
    snapshot: Optional[PreparedCallPublicSnapshot],
    proposal: ProposalMechanismFact,
    protected_arguments: Tuple[ProtectedArgumentMechanismFact, ...],
    terminal: LifecycleTerminalFact,
) -> Tuple[LifecycleStageFact, ...]:
    if proposal.candidate_state is ProposalCandidateState.MODEL_NON_ATTEMPT:
        states = (
            LifecycleState.NOT_APPLICABLE,
            LifecycleState.NOT_REACHED,
            LifecycleState.NOT_REACHED,
            LifecycleState.NOT_REACHED,
            LifecycleState.NOT_REACHED,
            LifecycleState.NOT_REACHED,
            LifecycleState.NOT_REACHED,
            LifecycleState.NOT_REACHED,
            LifecycleState.NOT_REACHED,
            LifecycleState.NOT_APPLICABLE,
        )
    else:
        resolution_state = _resolution_stage_state(protected_arguments)
        binding_state = _binding_stage_state(protected_arguments)
        policy_state = _policy_stage_state(terminal)
        sealing_state = (
            LifecycleState.SATISFIED
            if snapshot is not None
            else (
                LifecycleState.REFUSED
                if terminal.decision is TerminalDecision.ALLOW
                else LifecycleState.NOT_REACHED
            )
        )
        revalidation_state = _execution_revalidation_stage_state(snapshot, terminal)
        evidence_before_effect_state = (
            LifecycleState.SATISFIED
            if terminal.execution_start_count > 0
            else (
                LifecycleState.UNCERTAIN
                if revalidation_state is LifecycleState.UNCERTAIN
                else LifecycleState.NOT_REACHED
            )
        )
        states = (
            LifecycleState.SATISFIED,
            LifecycleState.SATISFIED
            if protected_arguments
            else LifecycleState.REFUSED,
            LifecycleState.FAILED
            if proposal.proposed_form is ProposalForm.RAW_PROTECTED_VALUE_REDACTED
            else LifecycleState.SATISFIED,
            resolution_state,
            binding_state,
            policy_state,
            sealing_state,
            revalidation_state,
            evidence_before_effect_state,
            _effect_stage_state(terminal),
        )
    return tuple(
        LifecycleStageFact(
            stage_id=contract[0],
            ordinal=contract[1],
            title=contract[2],
            trust_zone=contract[3],
            state=state,
            fact_provenance=contract[4],
            safe_summary=contract[5],
            w2_property_ids=contract[6],
        )
        for contract, state in zip(_LIFECYCLE_CONTRACT, states)
    )


def _proof_references() -> Tuple[W2ProofReference, ...]:
    catalogue_version, catalogue = _current_w2_catalogue()
    references = []
    for definition in catalogue:
        _, qualifier = _w2_contract(definition.property_id)
        references.append(
            W2ProofReference(
                property_id=definition.property_id,
                property_title=definition.property_title,
                catalogue_version=catalogue_version,
                reviewer_hint=f"make prove PROPERTY={definition.property_id}",
                ui_execution_status=UiProofExecutionStatus.REFERENCE_ONLY_NOT_EXECUTED_BY_UI,
                qualifier=qualifier,
            )
        )
    return tuple(references)


def build_mechanism_projection(
    snapshot: Optional[PreparedCallPublicSnapshot], review: ReviewProjection
) -> PreparedCallMechanismProjection:
    """Build one immutable W1 view from safe public and masked evidence facts."""

    if snapshot is not None and type(snapshot) is not PreparedCallPublicSnapshot:
        raise TypeError("snapshot requires PreparedCallPublicSnapshot or None")
    if type(review) is not ReviewProjection:
        raise TypeError("review requires an exact ReviewProjection")
    _validate_snapshot_review_alignment(snapshot, review)
    proposal = _proposal_fact(snapshot, review)
    protected_arguments = _protected_argument_facts(snapshot, review)
    terminal = _terminal_fact(review)
    return PreparedCallMechanismProjection(
        schema_version=MECHANISM_PROJECTION_SCHEMA_VERSION,
        lifecycle_model_version=LIFECYCLE_MODEL_VERSION,
        proposal=proposal,
        protected_arguments=protected_arguments,
        stages=_lifecycle_stages(snapshot, proposal, protected_arguments, terminal),
        seal=_seal_fact(snapshot),
        terminal=terminal,
        proof_references=_proof_references(),
    )


def _argument_metadata_primitive(
    metadata: PreparedArgumentMetadata,
) -> dict:
    return {
        "name": metadata.name,
        "type_id": metadata.type_id.value,
        "role": metadata.role.value,
    }


def _stage_primitive(stage: LifecycleStageFact) -> dict:
    return {
        "stage_id": stage.stage_id.value,
        "ordinal": stage.ordinal,
        "title": stage.title,
        "trust_zone": stage.trust_zone.value,
        "state": stage.state.value,
        "fact_provenance": stage.fact_provenance.value,
        "safe_summary": stage.safe_summary.value,
        "w2_property_ids": list(stage.w2_property_ids),
    }


def _proof_reference_primitive(reference: W2ProofReference) -> dict:
    return {
        "property_id": reference.property_id,
        "property_title": reference.property_title,
        "catalogue_version": reference.catalogue_version,
        "reviewer_hint": reference.reviewer_hint,
        "ui_execution_status": reference.ui_execution_status.value,
        "qualifier": reference.qualifier,
    }


def mechanism_projection_to_primitive(
    projection: PreparedCallMechanismProjection,
) -> dict:
    """Return the fixed browser-safe primitive form without generic reflection."""

    if type(projection) is not PreparedCallMechanismProjection:
        raise TypeError("projection requires an exact PreparedCallMechanismProjection")
    return {
        "schema_version": projection.schema_version,
        "lifecycle_model_version": projection.lifecycle_model_version,
        "proposal": {
            "candidate_state": projection.proposal.candidate_state.value,
            "tool_id": (
                projection.proposal.tool_id.value
                if projection.proposal.tool_id is not None
                else None
            ),
            "proposed_form": projection.proposal.proposed_form.value,
            "provenance": projection.proposal.provenance.value,
        },
        "protected_arguments": [
            {
                "name": item.name,
                "role": item.role.value,
                "supported_type": item.supported_type.value,
                "resolution_state": item.resolution_state.value,
                "binding_state": item.binding_state.value,
                "runtime_value_state": item.runtime_value_state.value,
            }
            for item in projection.protected_arguments
        ],
        "stages": [_stage_primitive(item) for item in projection.stages],
        "seal": {
            "prepared_call_present": projection.seal.prepared_call_present,
            "public_prepared_call_id": (
                projection.seal.public_prepared_call_id.value
                if projection.seal.public_prepared_call_id is not None
                else None
            ),
            "public_integrity_id": projection.seal.public_integrity_id,
            "adapter_id": (
                projection.seal.adapter_id.value
                if projection.seal.adapter_id is not None
                else None
            ),
            "adapter_version": (
                projection.seal.adapter_version.value
                if projection.seal.adapter_version is not None
                else None
            ),
            "argument_metadata": [
                _argument_metadata_primitive(item)
                for item in projection.seal.argument_metadata
            ],
            "private_binding_state": projection.seal.private_binding_state.value,
            "payload_binding_state": projection.seal.payload_binding_state.value,
            "correlation_binding_state": projection.seal.correlation_binding_state.value,
            "adapter_binding_state": projection.seal.adapter_binding_state.value,
            "single_use_target_state": projection.seal.single_use_target_state.value,
            "object_binding_state": projection.seal.object_binding_state.value,
            "private_material_projected": projection.seal.private_material_projected,
        },
        "terminal": {
            "decision": projection.terminal.decision.value,
            "primary_rule_id": (
                projection.terminal.primary_rule_id.value
                if projection.terminal.primary_rule_id is not None
                else None
            ),
            "execution_status": projection.terminal.execution_status.value,
            "execution_start_count": projection.terminal.execution_start_count,
            "authoritative_synthetic_payment_count": (
                projection.terminal.authoritative_synthetic_payment_count
            ),
            "replay_state": projection.terminal.replay_state.value,
            "external_result_confirmed": projection.terminal.external_result_confirmed,
            "evidence_completeness": projection.terminal.evidence_completeness.value,
            "integrity_status": projection.terminal.integrity_status.value,
            "reconciliation_status": projection.terminal.reconciliation_status.value,
        },
        "proof_references": [
            _proof_reference_primitive(item) for item in projection.proof_references
        ],
    }


__all__ = (
    "AdapterBindingState",
    "ClaimProvenance",
    "CorrelationBindingState",
    "LIFECYCLE_MODEL_VERSION",
    "LifecycleStageFact",
    "LifecycleStageId",
    "LifecycleState",
    "LifecycleSummaryKey",
    "LifecycleTerminalFact",
    "LifecycleTrustZone",
    "MECHANISM_PROJECTION_SCHEMA_VERSION",
    "ObjectBindingState",
    "PayloadBindingState",
    "PreparedArgumentMetadata",
    "PreparedCallMechanismProjection",
    "PreparedCallPublicSnapshot",
    "PreparedCallSealFact",
    "PrivateBindingState",
    "ProposalCandidateState",
    "ProposalFactProvenance",
    "ProposalForm",
    "ProposalMechanismFact",
    "ProtectedArgumentMechanismFact",
    "ProtectedBindingState",
    "ProtectedResolutionState",
    "RuntimeValueState",
    "SingleUseTargetState",
    "TerminalDecision",
    "UiProofExecutionStatus",
    "W2ProofReference",
    "build_mechanism_projection",
    "capture_prepared_call_public_snapshot",
    "mechanism_projection_to_primitive",
)
