"""Immutable preparation of policy-allowed framework-neutral tool calls.

The pipeline resolves protected references through trusted runtime state,
evaluates one captured policy snapshot, and seals an inert prepared payload
only after ``ALLOW``.  It does not execute adapters, consume references,
persist evidence, or retain runtime authority objects in the prepared call.
"""

from dataclasses import InitVar, dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
from secrets import token_hex
from typing import Optional, Tuple, Union, final

from tidemark.runtime.identifiers import (
    AdapterId,
    AdapterVersion,
    CallId,
    DecisionId,
    InvocationId,
    PolicyVersion,
    PreparedCallId,
    ReferenceId,
    RegistryVersion,
    ToolId,
    TypeId,
)
from tidemark.runtime.execution_binding import (
    _register_runtime_execution_binding,
)
from tidemark.runtime.policy_engine import (
    CallContext,
    CanonicalCall,
    Decision,
    PolicyEngine,
    ResolutionEntry,
    ResolutionSet,
    Resolved,
)
from tidemark.runtime.policy_snapshot import (
    PolicySnapshot,
    SnapshotArgumentContract,
    SnapshotConstraintBinding,
    SnapshotToolPolicy,
)
from tidemark.runtime.reference_resolver import (
    ReferenceResolver,
    ResolutionRequest,
)
from tidemark.runtime.reference_store import TrustedReferenceStore
from tidemark.runtime.vocabulary import (
    ArgumentRole,
    ConstraintId,
    DecisionOutcome,
    PreparedCallState,
)


_PREPARED_CALL_ID_PREFIX = "prepared_"
_PREPARED_CALL_CONSTRUCTION_AUTHORITY = object()
_MISSING_PREPARED_RUNTIME_VALUE = object()


def _full_evidence_recorder_type() -> type:
    from tidemark.evidence.recorder import EvidenceRecorder as RecorderType

    return RecorderType


def _require_exact_type(
    value: object, expected_type: type, field_name: str
) -> None:
    if type(value) is not expected_type:
        raise TypeError(f"{field_name} requires {expected_type.__name__}")


def _require_exact_identifier(
    value: object, expected_type: type, field_name: str
) -> None:
    _require_exact_type(value, expected_type, field_name)
    if type(value.value) is not str or value.value == "":
        raise ValueError(
            f"{field_name} requires an exact, non-empty identifier value"
        )


def _require_exact_non_empty_string(value: object, field_name: str) -> None:
    if type(value) is not str or value == "":
        raise ValueError(f"{field_name} requires an exact, non-empty string")


@final
@dataclass(frozen=True)
class PreparedListValue:
    """Immutable canonical form of one runtime list value."""

    items: Tuple[object, ...]

    def __post_init__(self) -> None:
        _validate_prepared_items(self.items, "items")


@final
@dataclass(frozen=True)
class PreparedTupleValue:
    """Immutable canonical form of one runtime tuple value."""

    items: Tuple[object, ...]

    def __post_init__(self) -> None:
        _validate_prepared_items(self.items, "items")


@final
@dataclass(frozen=True)
class PreparedMappingEntry:
    """One exact-string key and immutable canonical runtime value."""

    key: str
    value: object

    def __post_init__(self) -> None:
        if type(self.key) is not str:
            raise TypeError("key requires str")
        if not _prepared_value_valid(self.value):
            raise TypeError("value is not an immutable prepared value")


@final
@dataclass(frozen=True)
class PreparedMappingValue:
    """Immutable, deterministically ordered canonical mapping value."""

    entries: Tuple[PreparedMappingEntry, ...]

    def __post_init__(self) -> None:
        _require_exact_type(self.entries, tuple, "entries")
        if any(type(item) is not PreparedMappingEntry for item in self.entries):
            raise TypeError("entries require exact prepared mapping entries")
        keys = tuple(item.key for item in self.entries)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("prepared mapping keys must be unique and ordered")


class _RuntimePreparedValueCarrier:
    """Private value carriage omitted from dataclass public projections."""

    __slots__ = ("__runtime_value",)

    def _initialize_runtime_value(self) -> None:
        object.__setattr__(
            self,
            "_RuntimePreparedValueCarrier__runtime_value",
            _MISSING_PREPARED_RUNTIME_VALUE,
        )

    def _store_runtime_value(self, value: object) -> None:
        if not _prepared_value_valid(value):
            raise TypeError("value is not an immutable prepared value")
        object.__setattr__(
            self,
            "_RuntimePreparedValueCarrier__runtime_value",
            value,
        )

    def _copy_value_for_runtime(self) -> object:
        value = self.__runtime_value
        if value is _MISSING_PREPARED_RUNTIME_VALUE:
            raise RuntimeError("prepared argument has no runtime payload")
        return value


@final
@dataclass(frozen=True)
class PreparedArgument(_RuntimePreparedValueCarrier):
    """Public metadata with a private detached immutable runtime value."""

    name: str
    type_id: TypeId
    role: ArgumentRole

    def __post_init__(self) -> None:
        _require_exact_non_empty_string(self.name, "name")
        _require_exact_identifier(self.type_id, TypeId, "type_id")
        _require_exact_type(self.role, ArgumentRole, "role")
        self._initialize_runtime_value()


def _prepared_argument_with_runtime_value(
    *,
    name: str,
    type_id: TypeId,
    role: ArgumentRole,
    value: object,
) -> PreparedArgument:
    argument = PreparedArgument(name=name, type_id=type_id, role=role)
    argument._store_runtime_value(value)
    return argument


@final
@dataclass(frozen=True)
class SingleUseExecutionCapability:
    """Inert issuance-time metadata for a future single-use gate."""

    state: PreparedCallState

    def __post_init__(self) -> None:
        _require_exact_type(self.state, PreparedCallState, "state")
        if self.state is not PreparedCallState.UNUSED:
            raise ValueError("a newly prepared capability must be unused")


@final
@dataclass(frozen=True)
class PreparedToolCall:
    """Runtime-owned immutable ALLOW-associated execution payload."""

    prepared_call_id: PreparedCallId
    call_id: CallId
    decision_id: DecisionId
    invocation_id: InvocationId
    tool_id: ToolId
    policy_version: PolicyVersion
    registry_version: RegistryVersion
    arguments: Tuple[PreparedArgument, ...]
    adapter_id: AdapterId
    adapter_version: AdapterVersion
    execution_capability: SingleUseExecutionCapability
    integrity_id: str
    _authority: InitVar[object] = None

    def __post_init__(self, _authority: object) -> None:
        if _authority is not _PREPARED_CALL_CONSTRUCTION_AUTHORITY:
            raise TypeError(
                "PreparedToolCall is created only by PreparedCallPipeline"
            )
        _require_exact_identifier(
            self.prepared_call_id, PreparedCallId, "prepared_call_id"
        )
        _require_exact_identifier(self.call_id, CallId, "call_id")
        _require_exact_identifier(self.decision_id, DecisionId, "decision_id")
        _require_exact_identifier(
            self.invocation_id, InvocationId, "invocation_id"
        )
        _require_exact_identifier(self.tool_id, ToolId, "tool_id")
        _require_exact_identifier(
            self.policy_version, PolicyVersion, "policy_version"
        )
        _require_exact_identifier(
            self.registry_version, RegistryVersion, "registry_version"
        )
        _require_exact_type(self.arguments, tuple, "arguments")
        if any(type(item) is not PreparedArgument for item in self.arguments):
            raise TypeError("arguments require exact prepared arguments")
        names = tuple(item.name for item in self.arguments)
        if len(names) != len(set(names)):
            raise ValueError("prepared argument names must be unique")
        _require_exact_identifier(self.adapter_id, AdapterId, "adapter_id")
        _require_exact_identifier(
            self.adapter_version, AdapterVersion, "adapter_version"
        )
        _require_exact_type(
            self.execution_capability,
            SingleUseExecutionCapability,
            "execution_capability",
        )
        if (
            type(self.integrity_id) is not str
            or not self.integrity_id.startswith("sha256:")
            or len(self.integrity_id) != 71
        ):
            raise ValueError("integrity_id requires a sha256 content identity")


@final
@dataclass(frozen=True)
class PreparationRefusal:
    """Immutable non-executable result for a non-ALLOW or sealing failure."""

    decision: Decision
    masked_detail: str

    def __post_init__(self) -> None:
        _require_exact_type(self.decision, Decision, "decision")
        _require_exact_non_empty_string(self.masked_detail, "masked_detail")


PreparationResult = Union[PreparedToolCall, PreparationRefusal]


@final
class PreparedCallPipeline:
    """Stateless preparation-only transition into one sealed payload."""

    __slots__ = ("_evidence_recorder",)

    def __init__(
        self, evidence_recorder: object = None
    ) -> None:
        if evidence_recorder is not None and type(
            evidence_recorder
        ) is not _full_evidence_recorder_type():
            raise TypeError("evidence_recorder requires trusted recorder")
        self._evidence_recorder = evidence_recorder

    def prepare(
        self,
        *,
        snapshot: Optional[PolicySnapshot],
        canonical_call: CanonicalCall,
        call_context: CallContext,
        trusted_store: TrustedReferenceStore,
        evaluation_time: datetime,
    ) -> PreparationResult:
        """Resolve, evaluate, and seal exactly one payload after ``ALLOW``."""

        _require_exact_type(canonical_call, CanonicalCall, "canonical_call")
        _require_exact_type(call_context, CallContext, "call_context")
        _require_exact_type(
            trusted_store, TrustedReferenceStore, "trusted_store"
        )
        _require_exact_utc_datetime(evaluation_time)

        if self._evidence_recorder is not None:
            self._evidence_recorder.record_call_intake(
                canonical_call, call_context
            )

        resolution_set = _resolve_protected_arguments(
            snapshot=snapshot,
            canonical_call=canonical_call,
            call_context=call_context,
            trusted_store=trusted_store,
            evaluation_time=evaluation_time,
        )
        decision = PolicyEngine().evaluate(
            snapshot,
            canonical_call,
            resolution_set,
            call_context,
        )
        if decision.outcome is not DecisionOutcome.ALLOW:
            refusal = PreparationRefusal(
                decision=decision,
                masked_detail="policy evaluation did not allow preparation",
            )
            if self._evidence_recorder is not None:
                if decision.outcome is DecisionOutcome.REFUSAL:
                    self._evidence_recorder.record_call_preparation_refusal(
                        decision=decision,
                        canonical_call=canonical_call,
                        masked_detail=refusal.masked_detail,
                    )
                else:
                    self._evidence_recorder.record_decision(
                        decision=decision,
                        canonical_call=canonical_call,
                        call_context=call_context,
                        snapshot=snapshot,
                        resolution_set=resolution_set,
                        prepared_call=None,
                    )
            return refusal

        tool_policy = _find_tool_policy(snapshot, canonical_call.tool_id)
        if tool_policy is None:
            refusal = PreparationRefusal(
                decision=decision,
                masked_detail="prepared payload construction refused",
            )
            if self._evidence_recorder is not None:
                self._evidence_recorder.record_call_preparation_refusal(
                    decision=decision,
                    canonical_call=canonical_call,
                    masked_detail=refusal.masked_detail,
                )
            return refusal
        try:
            arguments = _prepare_arguments(
                tool_policy, canonical_call, resolution_set
            )
        except (RuntimeError, TypeError, ValueError, RecursionError):
            refusal = PreparationRefusal(
                decision=decision,
                masked_detail="prepared payload construction refused",
            )
            if self._evidence_recorder is not None:
                self._evidence_recorder.record_call_preparation_refusal(
                    decision=decision,
                    canonical_call=canonical_call,
                    masked_detail=refusal.masked_detail,
                )
            return refusal

        prepared_call_id = PreparedCallId(
            _PREPARED_CALL_ID_PREFIX + token_hex(32)
        )
        call_id = CallId(decision.call_id.value)
        decision_id = DecisionId(decision.decision_id.value)
        invocation_id = InvocationId(decision.invocation_id.value)
        tool_id = ToolId(decision.tool_id.value)
        policy_version = PolicyVersion(decision.policy_version.value)
        registry_version = RegistryVersion(decision.registry_version.value)
        adapter_id = AdapterId(tool_policy.adapter_id.value)
        adapter_version = AdapterVersion(tool_policy.adapter_version.value)
        execution_capability = SingleUseExecutionCapability(
            state=PreparedCallState.UNUSED
        )
        integrity_id = _prepared_integrity_id(
            prepared_call_id=prepared_call_id,
            call_id=call_id,
            decision_id=decision_id,
            invocation_id=invocation_id,
            tool_id=tool_id,
            policy_version=policy_version,
            registry_version=registry_version,
            arguments=arguments,
            adapter_id=adapter_id,
            adapter_version=adapter_version,
            execution_capability=execution_capability,
        )
        prepared_call = PreparedToolCall(
            prepared_call_id=prepared_call_id,
            call_id=call_id,
            decision_id=decision_id,
            invocation_id=invocation_id,
            tool_id=tool_id,
            policy_version=policy_version,
            registry_version=registry_version,
            arguments=arguments,
            adapter_id=adapter_id,
            adapter_version=adapter_version,
            execution_capability=execution_capability,
            integrity_id=integrity_id,
            _authority=_PREPARED_CALL_CONSTRUCTION_AUTHORITY,
        )
        reference_targets = _single_use_reference_targets(
            tool_policy, canonical_call
        )
        if reference_targets is None or not _register_runtime_execution_binding(
            prepared_call=prepared_call,
            parent_id=call_context.parent_id,
            trusted_store=trusted_store,
            reference_targets=reference_targets,
        ):
            refusal = PreparationRefusal(
                decision=decision,
                masked_detail="prepared payload construction refused",
            )
            if self._evidence_recorder is not None:
                self._evidence_recorder.record_call_preparation_refusal(
                    decision=decision,
                    canonical_call=canonical_call,
                    masked_detail=refusal.masked_detail,
                )
            return refusal
        if self._evidence_recorder is not None:
            self._evidence_recorder.record_decision(
                decision=decision,
                canonical_call=canonical_call,
                call_context=call_context,
                snapshot=snapshot,
                resolution_set=resolution_set,
                prepared_call=prepared_call,
            )
        return prepared_call


def _require_exact_utc_datetime(value: object) -> None:
    if type(value) is not datetime:
        raise TypeError("evaluation_time requires datetime")
    if value.tzinfo is not timezone.utc:
        raise ValueError("evaluation_time requires UTC timezone")


def _find_tool_policy(
    snapshot: object, tool_id: ToolId
) -> Optional[SnapshotToolPolicy]:
    if type(snapshot) is not PolicySnapshot:
        return None
    for tool_policy in snapshot.tool_policies:
        if (
            type(tool_policy) is SnapshotToolPolicy
            and tool_policy.tool_id == tool_id
        ):
            return tool_policy
    return None


def _resolve_protected_arguments(
    *,
    snapshot: object,
    canonical_call: CanonicalCall,
    call_context: CallContext,
    trusted_store: TrustedReferenceStore,
    evaluation_time: datetime,
) -> ResolutionSet:
    tool_policy = _find_tool_policy(snapshot, canonical_call.tool_id)
    if tool_policy is None:
        return ResolutionSet(entries=())

    supplied = {item.name: item.value for item in canonical_call.arguments}
    entries = []
    for argument in tool_policy.arguments:
        if (
            type(argument) is not SnapshotArgumentContract
            or argument.role is not ArgumentRole.PROTECTED_REFERENCE
        ):
            continue
        reference_id = supplied.get(argument.name)
        expected_kind = _expected_kind(argument)
        if type(reference_id) is not ReferenceId or expected_kind is None:
            continue
        request = ResolutionRequest(
            reference_id=ReferenceId(reference_id.value),
            expected_kind=expected_kind,
            invocation_id=InvocationId(call_context.invocation_id.value),
            parent_id=call_context.parent_id,
            argument_name=argument.name,
            evaluation_time=evaluation_time,
        )
        result = ReferenceResolver().resolve(request, trusted_store)
        entries.append(
            ResolutionEntry(argument_name=argument.name, result=result)
        )
    return ResolutionSet(entries=tuple(entries))


def _expected_kind(argument: SnapshotArgumentContract) -> Optional[str]:
    for binding in argument.constraint_bindings:
        if (
            type(binding) is SnapshotConstraintBinding
            and binding.constraint_id is ConstraintId.REFERENCE_KIND_EQUALS
            and type(binding.parameters) is tuple
            and len(binding.parameters) == 1
            and binding.parameters[0][0] == "kind"
            and type(binding.parameters[0][1]) is str
            and binding.parameters[0][1] != ""
        ):
            return binding.parameters[0][1]
    return None


def _single_use_reference_targets(
    tool_policy: SnapshotToolPolicy,
    canonical_call: CanonicalCall,
) -> Optional[Tuple[ReferenceId, ...]]:
    supplied = {item.name: item.value for item in canonical_call.arguments}
    targets = []
    for argument in tool_policy.arguments:
        if argument.role is not ArgumentRole.PROTECTED_REFERENCE:
            continue
        if not any(
            type(binding) is SnapshotConstraintBinding
            and binding.constraint_id is ConstraintId.REFERENCE_SINGLE_USE
            for binding in argument.constraint_bindings
        ):
            continue
        reference_id = supplied.get(argument.name)
        if type(reference_id) is not ReferenceId:
            return None
        targets.append(ReferenceId(reference_id.value))
    if len(targets) != len(set(targets)):
        return None
    return tuple(targets)


def _prepare_arguments(
    tool_policy: SnapshotToolPolicy,
    canonical_call: CanonicalCall,
    resolution_set: ResolutionSet,
) -> Tuple[PreparedArgument, ...]:
    supplied = {item.name: item.value for item in canonical_call.arguments}
    resolved = {
        item.argument_name: item.result for item in resolution_set.entries
    }
    prepared = []
    for contract in tool_policy.arguments:
        if contract.name not in supplied:
            continue
        if contract.role is ArgumentRole.PROTECTED_REFERENCE:
            result = resolved.get(contract.name)
            if type(result) is not Resolved:
                raise RuntimeError("protected argument lacks resolved payload")
            value = result._copy_protected_value_for_runtime()
        else:
            value = supplied[contract.name]
        prepared.append(
            _prepared_argument_with_runtime_value(
                name=contract.name,
                type_id=TypeId(contract.type_id.value),
                role=contract.role,
                value=_freeze_runtime_value(value, ()),
            )
        )
    return tuple(prepared)


def _freeze_runtime_value(value: object, active_ids: Tuple[int, ...]) -> object:
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is ReferenceId:
        return ReferenceId(value.value)
    if type(value) not in (list, tuple, dict):
        raise TypeError("runtime value has no supported immutable form")

    value_id = id(value)
    if value_id in active_ids:
        raise ValueError("cyclic runtime values are unsupported")
    next_active = active_ids + (value_id,)
    if type(value) is list:
        return PreparedListValue(
            items=tuple(
                _freeze_runtime_value(item, next_active) for item in value
            )
        )
    if type(value) is tuple:
        return PreparedTupleValue(
            items=tuple(
                _freeze_runtime_value(item, next_active) for item in value
            )
        )

    if any(type(key) is not str for key in value):
        raise TypeError("runtime mapping keys require exact strings")
    return PreparedMappingValue(
        entries=tuple(
            PreparedMappingEntry(
                key=key,
                value=_freeze_runtime_value(value[key], next_active),
            )
            for key in sorted(value)
        )
    )


def _prepared_value_valid(value: object) -> bool:
    return value is None or type(value) in (
        str,
        bool,
        int,
        ReferenceId,
        PreparedListValue,
        PreparedTupleValue,
        PreparedMappingValue,
    )


def _validate_prepared_items(value: object, field_name: str) -> None:
    _require_exact_type(value, tuple, field_name)
    if any(not _prepared_value_valid(item) for item in value):
        raise TypeError(f"{field_name} contains a mutable prepared value")


def _prepared_integrity_id(
    *,
    prepared_call_id: PreparedCallId,
    call_id: CallId,
    decision_id: DecisionId,
    invocation_id: InvocationId,
    tool_id: ToolId,
    policy_version: PolicyVersion,
    registry_version: RegistryVersion,
    arguments: Tuple[PreparedArgument, ...],
    adapter_id: AdapterId,
    adapter_version: AdapterVersion,
    execution_capability: SingleUseExecutionCapability,
) -> str:
    canonical = {
        "prepared_call_id": prepared_call_id.value,
        "call_id": call_id.value,
        "decision_id": decision_id.value,
        "invocation_id": invocation_id.value,
        "tool_id": tool_id.value,
        "policy_version": policy_version.value,
        "registry_version": registry_version.value,
        "arguments": tuple(
            {
                "name": argument.name,
                "type_id": argument.type_id.value,
                "role": argument.role.value,
            }
            for argument in arguments
        ),
        "adapter_id": adapter_id.value,
        "adapter_version": adapter_version.value,
        "execution_capability": execution_capability.state.value,
    }
    encoded = json.dumps(
        canonical,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


__all__ = (
    "PreparationRefusal",
    "PreparationResult",
    "PreparedArgument",
    "PreparedCallPipeline",
    "PreparedListValue",
    "PreparedMappingEntry",
    "PreparedMappingValue",
    "PreparedToolCall",
    "PreparedTupleValue",
    "SingleUseExecutionCapability",
)
