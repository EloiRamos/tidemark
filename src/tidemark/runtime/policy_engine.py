"""Deterministic, framework-neutral evaluation of one policy snapshot.

The engine consumes an already captured immutable ``PolicySnapshot``, inert
canonical call values, inert resolution facts, and immutable call context.  It
performs no lookup, reference issuance, I/O, prepared-call construction,
execution, evidence persistence, model call, or clock read.
"""

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Tuple, Union, final

from tidemark.runtime.constraint_registry import (
    TRUSTED_CONSTRAINT_REGISTRY,
    _ConstraintOperand,
)
from tidemark.runtime.identifiers import (
    AdapterId,
    AdapterVersion,
    CallId,
    DecisionId,
    InvocationId,
    MaskingProfileId,
    ParentId,
    PolicyVersion,
    ReferenceId,
    RegistryVersion,
    ToolContractVersion,
    ToolId,
    TypeId,
)
from tidemark.runtime.policy_authoring import (
    AUTHORING_INTEGER_MAXIMUM,
    AUTHORING_INTEGER_MINIMUM,
)
from tidemark.runtime.policy_snapshot import (
    PolicySnapshot,
    SnapshotArgumentContract,
    SnapshotConstraintBinding,
    SnapshotRoleMetadata,
    SnapshotSignatureArgument,
    SnapshotToolPolicy,
)
from tidemark.runtime.vocabulary import (
    ArgumentRole,
    ConstraintId,
    DecisionOutcome,
    EffectClass,
    EvaluationStage,
    ProvenanceClass,
    Reversibility,
    RuleEvaluationOutcome,
    RuleId,
)


_RuntimeScalar = Union[str, bool, int, None, ReferenceId]
_RESOLUTION_FAILURE_RULES = (
    RuleId.REFERENCE_NOT_FOUND,
    RuleId.REFERENCE_KIND_MISMATCH,
    RuleId.REFERENCE_INVOCATION_MISMATCH,
    RuleId.REFERENCE_PARENT_MISMATCH,
    RuleId.REFERENCE_INACTIVE,
    RuleId.REFERENCE_ALREADY_CONSUMED,
)
_NO_PARAMETER_CONSTRAINTS = (
    ConstraintId.PROTECTED_REFERENCE_REQUIRED,
    ConstraintId.REFERENCE_INVOCATION_EQUALS,
    ConstraintId.REFERENCE_PARENT_EQUALS,
    ConstraintId.REFERENCE_ACTIVE,
    ConstraintId.REFERENCE_SINGLE_USE,
)
_PROTECTED_CONSTRAINTS = (
    ConstraintId.PROTECTED_REFERENCE_REQUIRED,
    ConstraintId.REFERENCE_KIND_EQUALS,
    ConstraintId.REFERENCE_INVOCATION_EQUALS,
    ConstraintId.REFERENCE_PARENT_EQUALS,
    ConstraintId.REFERENCE_ACTIVE,
    ConstraintId.REFERENCE_SINGLE_USE,
)
_VALUE_CONSTRAINTS = (
    ConstraintId.VALUE_INTEGER_MAXIMUM,
    ConstraintId.VALUE_ENUM_MEMBER,
)
_MISSING_RUNTIME_PROTECTED_VALUE = object()


def _require_exact_non_empty_string(value: object, field_name: str) -> None:
    if type(value) is not str or value == "":
        raise ValueError(f"{field_name} requires an exact, non-empty string")


def _require_exact_type(value: object, expected_type: type, field_name: str) -> None:
    if type(value) is not expected_type:
        raise TypeError(f"{field_name} requires {expected_type.__name__}")


@final
@dataclass(frozen=True)
class CanonicalSignatureArgument:
    """Inert signature metadata captured with a canonical call."""

    name: str
    required: bool
    type_id: TypeId

    def __post_init__(self) -> None:
        _require_exact_non_empty_string(self.name, "name")
        _require_exact_type(self.required, bool, "required")
        _require_exact_type(self.type_id, TypeId, "type_id")


@final
@dataclass(frozen=True)
class CanonicalArgument:
    """One inert canonical argument; ``None`` is a missing representation."""

    name: str
    value: _RuntimeScalar

    def __post_init__(self) -> None:
        _require_exact_non_empty_string(self.name, "name")
        value = self.value
        if value is None:
            return
        if type(value) not in (str, bool, int, ReferenceId):
            raise TypeError("value is not an exact supported runtime scalar")


@final
@dataclass(frozen=True)
class CanonicalCall:
    """Framework-neutral canonical call input without execution authority."""

    tool_id: ToolId
    contract_version: ToolContractVersion
    signature: Tuple[CanonicalSignatureArgument, ...]
    arguments: Tuple[CanonicalArgument, ...]

    def __post_init__(self) -> None:
        _require_exact_type(self.tool_id, ToolId, "tool_id")
        _require_exact_type(
            self.contract_version, ToolContractVersion, "contract_version"
        )
        _require_exact_type(self.signature, tuple, "signature")
        _require_exact_type(self.arguments, tuple, "arguments")
        if any(type(item) is not CanonicalSignatureArgument for item in self.signature):
            raise TypeError("signature entries must be canonical signature values")
        if any(type(item) is not CanonicalArgument for item in self.arguments):
            raise TypeError("arguments must be canonical argument values")


@final
@dataclass(frozen=True)
class CallContext:
    """Captured immutable versions and correlations for one evaluation."""

    call_id: CallId
    decision_id: DecisionId
    invocation_id: InvocationId
    parent_id: ParentId
    policy_version: PolicyVersion
    registry_version: RegistryVersion

    def __post_init__(self) -> None:
        _require_exact_type(self.call_id, CallId, "call_id")
        _require_exact_type(self.decision_id, DecisionId, "decision_id")
        _require_exact_type(self.invocation_id, InvocationId, "invocation_id")
        _require_exact_type(self.parent_id, ParentId, "parent_id")
        _require_exact_type(self.policy_version, PolicyVersion, "policy_version")
        _require_exact_type(
            self.registry_version, RegistryVersion, "registry_version"
        )


class _RuntimeProtectedValueCarrier:
    """Private carrier omitted from dataclass repr and serialization fields."""

    __slots__ = ("__protected_value",)

    def _initialize_runtime_protected_value(self) -> None:
        object.__setattr__(
            self,
            "_RuntimeProtectedValueCarrier__protected_value",
            _MISSING_RUNTIME_PROTECTED_VALUE,
        )

    def _store_runtime_protected_value(self, value: object) -> None:
        try:
            copied = deepcopy(value)
        except Exception as error:
            raise TypeError(
                "protected runtime value must support runtime copying"
            ) from error
        object.__setattr__(
            self,
            "_RuntimeProtectedValueCarrier__protected_value",
            copied,
        )

    def _copy_protected_value_for_runtime(self) -> object:
        value = self.__protected_value
        if value is _MISSING_RUNTIME_PROTECTED_VALUE:
            raise RuntimeError("resolved value has no runtime payload")
        try:
            return deepcopy(value)
        except Exception as error:
            raise TypeError(
                "protected runtime value must support runtime copying"
            ) from error


@final
@dataclass(frozen=True)
class Resolved(_RuntimeProtectedValueCarrier):
    """Trusted facts with an optional private runtime-only protected value."""

    kind: str
    invocation_id: InvocationId
    parent_id: ParentId
    active: bool
    consumed: bool

    def __post_init__(self) -> None:
        _require_exact_non_empty_string(self.kind, "kind")
        _require_exact_type(self.invocation_id, InvocationId, "invocation_id")
        _require_exact_type(self.parent_id, ParentId, "parent_id")
        _require_exact_type(self.active, bool, "active")
        _require_exact_type(self.consumed, bool, "consumed")
        self._initialize_runtime_protected_value()


def _resolved_with_runtime_protected_value(
    *,
    protected_value: object,
    kind: str,
    invocation_id: InvocationId,
    parent_id: ParentId,
    active: bool,
    consumed: bool,
) -> Resolved:
    """Build one resolver-owned result while keeping its payload private."""

    resolved = Resolved(
        kind=kind,
        invocation_id=invocation_id,
        parent_id=parent_id,
        active=active,
        consumed=consumed,
    )
    resolved._store_runtime_protected_value(protected_value)
    return resolved


@final
@dataclass(frozen=True)
class ResolutionFailure:
    """Stable inert resolution failure supplied by a later trusted resolver."""

    rule_id: RuleId

    def __post_init__(self) -> None:
        _require_exact_type(self.rule_id, RuleId, "rule_id")
        if self.rule_id not in _RESOLUTION_FAILURE_RULES:
            raise ValueError("rule_id is not a v1 resolution failure rule")


ResolutionResult = Union[Resolved, ResolutionFailure]


@final
@dataclass(frozen=True)
class ResolutionEntry:
    """One argument-correlated resolution result."""

    argument_name: str
    result: ResolutionResult

    def __post_init__(self) -> None:
        _require_exact_non_empty_string(self.argument_name, "argument_name")
        if type(self.result) not in (Resolved, ResolutionFailure):
            raise TypeError("result must be an exact resolution result value")


@final
@dataclass(frozen=True)
class ResolutionSet:
    """Immutable inert resolution results, never a resolver or store handle."""

    entries: Tuple[ResolutionEntry, ...]

    def __post_init__(self) -> None:
        _require_exact_type(self.entries, tuple, "entries")
        if any(type(item) is not ResolutionEntry for item in self.entries):
            raise TypeError("entries must contain exact resolution entries")
        names = tuple(item.argument_name for item in self.entries)
        if len(names) != len(set(names)):
            raise ValueError("resolution argument names must be unique")


@final
@dataclass(frozen=True)
class EvaluatedRuleResult:
    """One masked rule evaluation in deterministic trace order."""

    rule_id: RuleId
    outcome: RuleEvaluationOutcome
    evaluation_stage: EvaluationStage
    argument_name: Optional[str] = None
    constraint_id: Optional[ConstraintId] = None


@final
@dataclass(frozen=True)
class MaskedDecisionFact:
    """Allowlisted inert fact metadata with no argument or protected value."""

    rule_id: RuleId
    argument_name: Optional[str]
    constraint_id: Optional[ConstraintId]


@final
@dataclass(frozen=True)
class Decision:
    """Immutable authorization result; never an execution capability."""

    decision_id: DecisionId
    outcome: DecisionOutcome
    evaluation_stage: EvaluationStage
    primary_rule_id: RuleId
    rule_results: Tuple[EvaluatedRuleResult, ...]
    policy_version: PolicyVersion
    registry_version: RegistryVersion
    call_id: CallId
    invocation_id: InvocationId
    tool_id: ToolId
    masked_facts: Tuple[MaskedDecisionFact, ...]


def _result(
    rule_id: RuleId,
    outcome: RuleEvaluationOutcome,
    stage: EvaluationStage,
    argument_name: Optional[str] = None,
    constraint_id: Optional[ConstraintId] = None,
) -> EvaluatedRuleResult:
    return EvaluatedRuleResult(
        rule_id=rule_id,
        outcome=outcome,
        evaluation_stage=stage,
        argument_name=argument_name,
        constraint_id=constraint_id,
    )


def _pass(
    rule_id: RuleId,
    stage: EvaluationStage,
    argument_name: Optional[str] = None,
    constraint_id: Optional[ConstraintId] = None,
) -> EvaluatedRuleResult:
    return _result(
        rule_id,
        RuleEvaluationOutcome.PASS,
        stage,
        argument_name,
        constraint_id,
    )


def _fail(
    rule_id: RuleId,
    stage: EvaluationStage,
    argument_name: Optional[str] = None,
    constraint_id: Optional[ConstraintId] = None,
) -> EvaluatedRuleResult:
    return _result(
        rule_id,
        RuleEvaluationOutcome.FAIL,
        stage,
        argument_name,
        constraint_id,
    )


def _seal(
    outcome: DecisionOutcome,
    primary: EvaluatedRuleResult,
    results: Tuple[EvaluatedRuleResult, ...],
    call: CanonicalCall,
    context: CallContext,
) -> Decision:
    facts = tuple(
        MaskedDecisionFact(
            rule_id=item.rule_id,
            argument_name=item.argument_name,
            constraint_id=item.constraint_id,
        )
        for item in results
        if item.argument_name is not None or item.constraint_id is not None
    )
    return Decision(
        decision_id=context.decision_id,
        outcome=outcome,
        evaluation_stage=primary.evaluation_stage,
        primary_rule_id=primary.rule_id,
        rule_results=results,
        policy_version=context.policy_version,
        registry_version=context.registry_version,
        call_id=context.call_id,
        invocation_id=context.invocation_id,
        tool_id=call.tool_id,
        masked_facts=facts,
    )


def _append_failure(
    results: list,
    outcome: DecisionOutcome,
    failed: EvaluatedRuleResult,
    call: CanonicalCall,
    context: CallContext,
) -> Decision:
    results.append(failed)
    return _seal(outcome, failed, tuple(results), call, context)


def _find_tool_policy(
    snapshot: PolicySnapshot, tool_id: ToolId
) -> Optional[SnapshotToolPolicy]:
    for policy in snapshot.tool_policies:
        if type(policy) is SnapshotToolPolicy and policy.tool_id == tool_id:
            return policy
    return None


def _parameters_valid(binding: SnapshotConstraintBinding) -> bool:
    parameters = binding.parameters
    if type(parameters) is not tuple:
        return False
    names = []
    for pair in parameters:
        if type(pair) is not tuple or len(pair) != 2:
            return False
        name, value = pair
        if type(name) is not str or name == "":
            return False
        names.append(name)
        if type(value) not in (str, bool, int, tuple) and value is not None:
            return False
    if len(names) != len(set(names)):
        return False

    constraint_id = binding.constraint_id
    if constraint_id in _NO_PARAMETER_CONSTRAINTS:
        return parameters == ()
    if constraint_id is ConstraintId.REFERENCE_KIND_EQUALS:
        return (
            len(parameters) == 1
            and parameters[0][0] == "kind"
            and type(parameters[0][1]) is str
            and parameters[0][1] != ""
        )
    if constraint_id is ConstraintId.VALUE_INTEGER_MAXIMUM:
        return (
            len(parameters) == 1
            and parameters[0][0] == "maximum"
            and type(parameters[0][1]) is int
            and AUTHORING_INTEGER_MINIMUM
            <= parameters[0][1]
            <= AUTHORING_INTEGER_MAXIMUM
        )
    if constraint_id is ConstraintId.VALUE_ENUM_MEMBER:
        if len(parameters) != 1 or parameters[0][0] != "members":
            return False
        members = parameters[0][1]
        return (
            type(members) is tuple
            and all(type(member) is str for member in members)
            and len(members) == len(set(members))
        )
    return False


def _constraint_bindings_valid(
    argument: SnapshotArgumentContract,
) -> bool:
    bindings = argument.constraint_bindings
    if type(bindings) is not tuple:
        return False
    constraint_ids = []
    for binding in bindings:
        if type(binding) is not SnapshotConstraintBinding:
            return False
        if type(binding.constraint_id) is not ConstraintId:
            return False
        if (
            TRUSTED_CONSTRAINT_REGISTRY.implementation_id(
                binding.constraint_id
            )
            is None
        ):
            return False
        if not _parameters_valid(binding):
            return False
        constraint_ids.append(binding.constraint_id)
    if len(constraint_ids) != len(set(constraint_ids)):
        return False
    if argument.role is ArgumentRole.PROTECTED_REFERENCE:
        return (
            argument.required is True
            and ConstraintId.PROTECTED_REFERENCE_REQUIRED in constraint_ids
            and all(item in _PROTECTED_CONSTRAINTS for item in constraint_ids)
        )
    return all(item in _VALUE_CONSTRAINTS for item in constraint_ids)


def _tool_policy_state_valid(
    policy: SnapshotToolPolicy, snapshot: PolicySnapshot
) -> bool:
    if type(policy.tool_id) is not ToolId:
        return False
    if type(policy.contract_version) is not ToolContractVersion:
        return False
    if type(policy.policy_version) is not PolicyVersion:
        return False
    if policy.policy_version != snapshot.policy_version:
        return False
    if type(policy.signature) is not tuple or type(policy.arguments) is not tuple:
        return False
    if type(policy.role_metadata) is not tuple:
        return False
    if type(policy.effect_class) is not EffectClass:
        return False
    if type(policy.reversibility) is not Reversibility:
        return False
    if type(policy.adapter_id) is not AdapterId:
        return False
    if type(policy.adapter_version) is not AdapterVersion:
        return False
    if type(policy.masking_profile_id) is not MaskingProfileId:
        return False

    signature_names = []
    for item in policy.signature:
        if type(item) is not SnapshotSignatureArgument:
            return False
        if type(item.name) is not str or item.name == "":
            return False
        if type(item.required) is not bool or type(item.type_id) is not TypeId:
            return False
        signature_names.append(item.name)
    if len(signature_names) != len(set(signature_names)):
        return False

    argument_names = []
    positions = []
    for argument in policy.arguments:
        if type(argument) is not SnapshotArgumentContract:
            return False
        if type(argument.name) is not str or argument.name == "":
            return False
        if type(argument.position) is not int or argument.position < 0:
            return False
        if type(argument.type_id) is not TypeId:
            return False
        if type(argument.required) is not bool:
            return False
        if type(argument.role) is not ArgumentRole:
            return False
        if not _constraint_bindings_valid(argument):
            return False
        argument_names.append(argument.name)
        positions.append(argument.position)
    if len(argument_names) != len(set(argument_names)):
        return False
    if tuple(positions) != tuple(range(len(positions))):
        return False

    metadata_names = []
    for metadata in policy.role_metadata:
        if type(metadata) is not SnapshotRoleMetadata:
            return False
        if type(metadata.name) is not str or metadata.name == "":
            return False
        if type(metadata.role) is not ArgumentRole:
            return False
        if type(metadata.required_provenance) is not ProvenanceClass:
            return False
        metadata_names.append(metadata.name)
    if len(metadata_names) != len(set(metadata_names)):
        return False
    if len(policy.role_metadata) != len(policy.arguments):
        return False
    for metadata, argument in zip(policy.role_metadata, policy.arguments):
        expected = (
            ProvenanceClass.RUNTIME_TRUSTED
            if argument.role is ArgumentRole.PROTECTED_REFERENCE
            else ProvenanceClass.UNTRUSTED
        )
        if (
            metadata.name != argument.name
            or metadata.role is not argument.role
            or metadata.required_provenance is not expected
        ):
            return False
    return True


def _registry_state_complete(
    snapshot: PolicySnapshot,
    context: CallContext,
) -> bool:
    if type(snapshot.policy_version) is not PolicyVersion:
        return False
    if type(snapshot.registry_version) is not RegistryVersion:
        return False
    if snapshot.registry_version != context.registry_version:
        return False
    if type(snapshot.executable_tools) is not tuple:
        return False
    if any(type(item) is not ToolId for item in snapshot.executable_tools):
        return False
    if len(snapshot.executable_tools) != len(set(snapshot.executable_tools)):
        return False
    if type(snapshot.tool_policies) is not tuple:
        return False
    if any(type(item) is not SnapshotToolPolicy for item in snapshot.tool_policies):
        return False
    policy_tool_ids = tuple(policy.tool_id for policy in snapshot.tool_policies)
    if len(policy_tool_ids) != len(set(policy_tool_ids)):
        return False
    if set(policy_tool_ids) != set(snapshot.executable_tools):
        return False
    if not TRUSTED_CONSTRAINT_REGISTRY.is_complete():
        return False
    if any(
        not _tool_policy_state_valid(policy, snapshot)
        for policy in snapshot.tool_policies
    ):
        return False
    if type(snapshot.created_at) is not datetime:
        return False
    if snapshot.created_at.tzinfo is not timezone.utc:
        return False
    if (
        type(snapshot.integrity_id) is not str
        or not snapshot.integrity_id.startswith("sha256:")
        or len(snapshot.integrity_id) != 71
    ):
        return False
    return True


def _signature_matches(
    policy: SnapshotToolPolicy, call: CanonicalCall
) -> bool:
    if call.contract_version != policy.contract_version:
        return False
    expected_call_signature = tuple(
        CanonicalSignatureArgument(
            name=item.name,
            required=item.required,
            type_id=TypeId(item.type_id.value),
        )
        for item in policy.signature
    )
    if call.signature != expected_call_signature:
        return False
    if len(policy.signature) != len(policy.arguments):
        return False
    return all(
        signature.name == argument.name
        and signature.required is argument.required
        and signature.type_id == argument.type_id
        for signature, argument in zip(policy.signature, policy.arguments)
    )


def _argument_shape_valid(
    policy: SnapshotToolPolicy,
    call: CanonicalCall,
    resolution_set: ResolutionSet,
) -> bool:
    supplied_names = tuple(item.name for item in call.arguments)
    if len(supplied_names) != len(set(supplied_names)):
        return False
    contract_names = tuple(item.name for item in policy.arguments)
    if any(name not in contract_names for name in supplied_names):
        return False
    if any(
        item.required and item.name not in supplied_names
        for item in policy.arguments
    ):
        return False
    expected_supplied_order = tuple(
        name for name in contract_names if name in supplied_names
    )
    if supplied_names != expected_supplied_order:
        return False
    protected_names = tuple(
        item.name
        for item in policy.arguments
        if item.role is ArgumentRole.PROTECTED_REFERENCE
    )
    if any(
        entry.argument_name not in protected_names
        for entry in resolution_set.entries
    ):
        return False
    return True


def _binding(
    argument: SnapshotArgumentContract, constraint_id: ConstraintId
) -> Optional[SnapshotConstraintBinding]:
    for item in argument.constraint_bindings:
        if item.constraint_id is constraint_id:
            return item
    return None


def _resolution_by_name(
    resolution_set: ResolutionSet, argument_name: str
) -> Optional[ResolutionResult]:
    for entry in resolution_set.entries:
        if entry.argument_name == argument_name:
            return entry.result
    return None


def _constraint_result(
    constraint_id: ConstraintId, operand: _ConstraintOperand
) -> bool:
    evaluated = TRUSTED_CONSTRAINT_REGISTRY._evaluate(
        constraint_id, operand
    )
    return evaluated is True


@final
class PolicyEngine:
    """Stateless evaluation surface fixed to the trusted runtime registry."""

    __slots__ = ()

    def evaluate(
        self,
        snapshot: Optional[PolicySnapshot],
        canonical_call: CanonicalCall,
        resolution_set: ResolutionSet,
        call_context: CallContext,
    ) -> Decision:
        """Evaluate one captured snapshot in exact first-failure order."""

        _require_exact_type(canonical_call, CanonicalCall, "canonical_call")
        _require_exact_type(resolution_set, ResolutionSet, "resolution_set")
        _require_exact_type(call_context, CallContext, "call_context")
        results = []

        policy_rule = RuleId.RUNTIME_POLICY_UNAVAILABLE
        if (
            type(snapshot) is not PolicySnapshot
            or type(snapshot.policy_version) is not PolicyVersion
            or snapshot.policy_version != call_context.policy_version
        ):
            return _append_failure(
                results,
                DecisionOutcome.REFUSAL,
                _fail(policy_rule, EvaluationStage.STRUCTURE),
                canonical_call,
                call_context,
            )
        results.append(_pass(policy_rule, EvaluationStage.STRUCTURE))

        tool_rule = RuleId.CONTRACT_TOOL_UNKNOWN
        if canonical_call.tool_id not in snapshot.executable_tools:
            return _append_failure(
                results,
                DecisionOutcome.REFUSAL,
                _fail(tool_rule, EvaluationStage.STRUCTURE),
                canonical_call,
                call_context,
            )
        results.append(_pass(tool_rule, EvaluationStage.STRUCTURE))

        registry_rule = RuleId.CONTRACT_REGISTRY_INCOMPLETE
        tool_policy = _find_tool_policy(snapshot, canonical_call.tool_id)
        if (
            tool_policy is None
            or not _registry_state_complete(snapshot, call_context)
        ):
            return _append_failure(
                results,
                DecisionOutcome.REFUSAL,
                _fail(registry_rule, EvaluationStage.STRUCTURE),
                canonical_call,
                call_context,
            )
        results.append(_pass(registry_rule, EvaluationStage.STRUCTURE))

        signature_rule = RuleId.CONTRACT_SIGNATURE_MISMATCH
        if not _signature_matches(tool_policy, canonical_call):
            return _append_failure(
                results,
                DecisionOutcome.REFUSAL,
                _fail(signature_rule, EvaluationStage.STRUCTURE),
                canonical_call,
                call_context,
            )
        results.append(_pass(signature_rule, EvaluationStage.STRUCTURE))

        shape_rule = RuleId.CONTRACT_ARGUMENT_SHAPE_INVALID
        if not _argument_shape_valid(
            tool_policy, canonical_call, resolution_set
        ):
            return _append_failure(
                results,
                DecisionOutcome.DENY,
                _fail(shape_rule, EvaluationStage.STRUCTURE),
                canonical_call,
                call_context,
            )
        results.append(_pass(shape_rule, EvaluationStage.STRUCTURE))

        argument_values = {
            item.name: item.value for item in canonical_call.arguments
        }
        protected_arguments = tuple(
            item
            for item in tool_policy.arguments
            if item.role is ArgumentRole.PROTECTED_REFERENCE
        )

        representation_rule = RuleId.PROTECTED_RAW_VALUE_SUPPLIED
        required_constraint = ConstraintId.PROTECTED_REFERENCE_REQUIRED
        for argument in protected_arguments:
            binding = _binding(argument, required_constraint)
            passes = binding is not None and _constraint_result(
                required_constraint,
                _ConstraintOperand(
                    value=argument_values.get(argument.name),
                    parameters=binding.parameters,
                ),
            )
            evaluated = (
                _pass
                if passes
                else _fail
            )(
                representation_rule,
                EvaluationStage.REPRESENTATION,
                argument.name,
                required_constraint,
            )
            if not passes:
                return _append_failure(
                    results,
                    DecisionOutcome.DENY,
                    evaluated,
                    canonical_call,
                    call_context,
                )
            results.append(evaluated)

        not_found_rule = RuleId.REFERENCE_NOT_FOUND
        for argument in protected_arguments:
            resolution = _resolution_by_name(resolution_set, argument.name)
            passes = resolution is not None and not (
                type(resolution) is ResolutionFailure
                and resolution.rule_id is not_found_rule
            )
            evaluated = (_pass if passes else _fail)(
                not_found_rule,
                EvaluationStage.RESOLUTION,
                argument.name,
            )
            if not passes:
                return _append_failure(
                    results,
                    DecisionOutcome.DENY,
                    evaluated,
                    canonical_call,
                    call_context,
                )
            results.append(evaluated)

        protected_rule_families = (
            (
                RuleId.REFERENCE_KIND_MISMATCH,
                ConstraintId.REFERENCE_KIND_EQUALS,
                EvaluationStage.RESOLUTION,
            ),
            (
                RuleId.REFERENCE_INVOCATION_MISMATCH,
                ConstraintId.REFERENCE_INVOCATION_EQUALS,
                EvaluationStage.BINDING,
            ),
            (
                RuleId.REFERENCE_PARENT_MISMATCH,
                ConstraintId.REFERENCE_PARENT_EQUALS,
                EvaluationStage.BINDING,
            ),
            (
                RuleId.REFERENCE_INACTIVE,
                ConstraintId.REFERENCE_ACTIVE,
                EvaluationStage.LIFECYCLE,
            ),
            (
                RuleId.REFERENCE_ALREADY_CONSUMED,
                ConstraintId.REFERENCE_SINGLE_USE,
                EvaluationStage.LIFECYCLE,
            ),
        )
        for rule_id, constraint_id, stage in protected_rule_families:
            for argument in protected_arguments:
                binding = _binding(argument, constraint_id)
                resolution = _resolution_by_name(
                    resolution_set, argument.name
                )
                failure_matches = (
                    type(resolution) is ResolutionFailure
                    and resolution.rule_id is rule_id
                )
                if binding is None and not failure_matches:
                    continue
                if failure_matches:
                    passes = False
                elif type(resolution) is ResolutionFailure:
                    passes = True
                elif type(resolution) is Resolved and binding is not None:
                    passes = _constraint_result(
                        constraint_id,
                        _ConstraintOperand(
                            parameters=binding.parameters,
                            resolved_kind=resolution.kind,
                            invocation_matches=(
                                resolution.invocation_id
                                == call_context.invocation_id
                            ),
                            parent_matches=(
                                resolution.parent_id == call_context.parent_id
                            ),
                            active=resolution.active,
                            consumed=resolution.consumed,
                        ),
                    )
                else:
                    passes = False
                evaluated = (_pass if passes else _fail)(
                    rule_id,
                    stage,
                    argument.name,
                    constraint_id if binding is not None else None,
                )
                if not passes:
                    return _append_failure(
                        results,
                        DecisionOutcome.DENY,
                        evaluated,
                        canonical_call,
                        call_context,
                    )
                results.append(evaluated)

        value_rule = RuleId.VALUE_CONSTRAINT_FAILED
        for argument in tool_policy.arguments:
            if argument.role is not ArgumentRole.UNPROTECTED_INPUT:
                continue
            if argument.name not in argument_values:
                continue
            for binding in argument.constraint_bindings:
                if binding.constraint_id not in _VALUE_CONSTRAINTS:
                    continue
                passes = _constraint_result(
                    binding.constraint_id,
                    _ConstraintOperand(
                        value=argument_values[argument.name],
                        parameters=binding.parameters,
                    ),
                )
                evaluated = (_pass if passes else _fail)(
                    value_rule,
                    EvaluationStage.VALUE,
                    argument.name,
                    binding.constraint_id,
                )
                if not passes:
                    return _append_failure(
                        results,
                        DecisionOutcome.DENY,
                        evaluated,
                        canonical_call,
                        call_context,
                    )
                results.append(evaluated)

        allow = _pass(
            RuleId.AUTHORIZATION_ALLOW,
            EvaluationStage.AUTHORIZATION,
        )
        results.append(allow)
        return _seal(
            DecisionOutcome.ALLOW,
            allow,
            tuple(results),
            canonical_call,
            call_context,
        )


__all__ = (
    "CallContext",
    "CanonicalArgument",
    "CanonicalCall",
    "CanonicalSignatureArgument",
    "Decision",
    "EvaluatedRuleResult",
    "MaskedDecisionFact",
    "PolicyEngine",
    "ResolutionEntry",
    "ResolutionFailure",
    "ResolutionResult",
    "ResolutionSet",
    "Resolved",
)
