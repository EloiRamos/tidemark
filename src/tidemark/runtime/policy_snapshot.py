"""Runtime-owned immutable policy snapshot installation and publication.

This module turns an already validated policy authoring value into a fresh,
immutable runtime graph and atomically replaces one installer-owned published
snapshot.  It contains no policy evaluation, constraint behavior, reference
resolution, prepared-call construction, execution, or evidence persistence.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import json
from threading import Lock
from typing import (
    FrozenSet,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    final,
)

from tidemark.evidence.recorder import EvidenceRecorder
from tidemark.runtime.identifiers import (
    AdapterId,
    AdapterVersion,
    MaskingProfileId,
    PolicyVersion,
    RegistryVersion,
    ToolContractVersion,
    ToolId,
    TypeId,
)
from tidemark.runtime.policy_authoring import (
    AUTHORING_INTEGER_MAXIMUM,
    AUTHORING_INTEGER_MINIMUM,
    AuthoringRefusal,
    ValidatedArgumentContract,
    ValidatedConstraintBinding,
    ValidatedPolicyAuthoring,
    ValidatedRoleMetadata,
    ValidatedSignatureArgument,
    ValidatedToolRegistration,
    validate_policy_authoring,
)
from tidemark.runtime.vocabulary import (
    ArgumentRole,
    ConstraintId,
    EffectClass,
    ProvenanceClass,
    Reversibility,
    RuleId,
)


_LocationPart = Union[str, int]
_Location = Tuple[_LocationPart, ...]
_ParameterScalar = Union[str, bool, int, None, Tuple[str, ...]]
_ParameterPair = Tuple[str, _ParameterScalar]


@final
@dataclass(frozen=True)
class SnapshotConstraintBinding:
    """Immutable constraint identity and inert parameters."""

    constraint_id: ConstraintId
    parameters: Tuple[_ParameterPair, ...]


@final
@dataclass(frozen=True)
class SnapshotSignatureArgument:
    """Immutable canonical signature entry."""

    name: str
    required: bool
    type_id: TypeId


@final
@dataclass(frozen=True)
class SnapshotArgumentContract:
    """Immutable argument contract held by a policy snapshot."""

    name: str
    position: int
    type_id: TypeId
    required: bool
    role: ArgumentRole
    constraint_bindings: Tuple[SnapshotConstraintBinding, ...]


@final
@dataclass(frozen=True)
class SnapshotRoleMetadata:
    """Immutable role and required-provenance metadata."""

    name: str
    role: ArgumentRole
    required_provenance: ProvenanceClass


@final
@dataclass(frozen=True)
class SnapshotToolPolicy:
    """Complete immutable policy metadata for one executable tool."""

    tool_id: ToolId
    contract_version: ToolContractVersion
    policy_version: PolicyVersion
    signature: Tuple[SnapshotSignatureArgument, ...]
    arguments: Tuple[SnapshotArgumentContract, ...]
    role_metadata: Tuple[SnapshotRoleMetadata, ...]
    effect_class: EffectClass
    reversibility: Reversibility
    adapter_id: AdapterId
    adapter_version: AdapterVersion
    masking_profile_id: MaskingProfileId


@final
@dataclass(frozen=True)
class PolicySnapshot:
    """Authoritative, immutable runtime policy publication."""

    policy_version: PolicyVersion
    registry_version: RegistryVersion
    executable_tools: Tuple[ToolId, ...]
    tool_policies: Tuple[SnapshotToolPolicy, ...]
    created_at: datetime = field(compare=False)
    integrity_id: str


@final
@dataclass(frozen=True)
class InstalledSnapshot:
    """Successful installation result carrying the published reference."""

    snapshot: PolicySnapshot


@final
@dataclass(frozen=True)
class InstallationRefusal:
    """Masked installation failure that publishes no partial state."""

    code: RuleId
    location: _Location
    masked_detail: str


PolicyInstallationResult = Union[InstalledSnapshot, InstallationRefusal]


@final
@dataclass(frozen=True)
class ConstraintBindingInspection:
    """Detached primitive inspection of one inert constraint binding."""

    constraint_id: str
    parameters: Tuple[_ParameterPair, ...]


@final
@dataclass(frozen=True)
class SignatureArgumentInspection:
    """Detached primitive inspection of one signature entry."""

    name: str
    required: bool
    type_id: str


@final
@dataclass(frozen=True)
class ArgumentContractInspection:
    """Detached primitive inspection of one argument contract."""

    name: str
    position: int
    type_id: str
    required: bool
    role: str
    constraint_bindings: Tuple[ConstraintBindingInspection, ...]


@final
@dataclass(frozen=True)
class RoleMetadataInspection:
    """Detached primitive inspection of role metadata."""

    name: str
    role: str
    required_provenance: str


@final
@dataclass(frozen=True)
class ToolPolicyInspection:
    """Detached primitive inspection of one tool policy."""

    tool_id: str
    contract_version: str
    policy_version: str
    signature: Tuple[SignatureArgumentInspection, ...]
    arguments: Tuple[ArgumentContractInspection, ...]
    role_metadata: Tuple[RoleMetadataInspection, ...]
    effect_class: str
    reversibility: str
    adapter_id: str
    adapter_version: str
    masking_profile_id: str


@final
@dataclass(frozen=True)
class SnapshotInspection:
    """Detached, immutable, non-authoritative view of a publication."""

    policy_version: str
    registry_version: str
    executable_tools: Tuple[str, ...]
    tool_policies: Tuple[ToolPolicyInspection, ...]
    created_at: str
    integrity_id: str


@dataclass(frozen=True)
class _PublicationState:
    snapshot: Optional[PolicySnapshot]
    installed_versions: FrozenSet[PolicyVersion]


class _SnapshotConstructionFailure(Exception):
    def __init__(
        self, code: RuleId, location: _Location, masked_detail: str
    ) -> None:
        super().__init__()
        self.code = code
        self.location = location
        self.masked_detail = masked_detail


@final
class PolicyInstaller:
    """Own and atomically replace one immutable snapshot publication."""

    __slots__ = ("_evidence_recorder", "_lock", "_publication")

    def __init__(
        self, evidence_recorder: Optional[EvidenceRecorder] = None
    ) -> None:
        if evidence_recorder is not None and type(
            evidence_recorder
        ) is not EvidenceRecorder:
            raise TypeError("evidence_recorder requires EvidenceRecorder")
        self._evidence_recorder = evidence_recorder
        self._lock = Lock()
        self._publication = _PublicationState(
            snapshot=None, installed_versions=frozenset()
        )

    def install(self, authoring: object) -> PolicyInstallationResult:
        """Freshly canonicalize and atomically publish validated authoring."""

        canonical = _revalidate_authoring(authoring)
        if type(canonical) is InstallationRefusal:
            return self._record_refusal(canonical)

        with self._lock:
            publication = self._publication
            if canonical.policy_version in publication.installed_versions:
                return self._record_refusal(InstallationRefusal(
                    code=RuleId.RUNTIME_POLICY_UNAVAILABLE,
                    location=("policy_version",),
                    masked_detail="policy version was already installed",
                ))

            policy_version = PolicyVersion(canonical.policy_version.value)
            snapshot = _create_snapshot(
                canonical,
                policy_version,
                datetime.now(timezone.utc),
            )
            next_publication = _PublicationState(
                snapshot=snapshot,
                installed_versions=(
                    publication.installed_versions | {policy_version}
                ),
            )
            self._publication = next_publication

        return InstalledSnapshot(snapshot=snapshot)

    def _record_refusal(
        self, refusal: InstallationRefusal
    ) -> InstallationRefusal:
        if self._evidence_recorder is not None:
            self._evidence_recorder.record_policy_installation_refusal(refusal)
        return refusal

    def capture_snapshot(self) -> Optional[PolicySnapshot]:
        """Capture the exact immutable publication reference currently active."""

        with self._lock:
            return self._publication.snapshot

    def inspect_snapshot(self) -> Optional[SnapshotInspection]:
        """Return a newly detached inspection graph for the active snapshot."""

        snapshot = self.capture_snapshot()
        if snapshot is None:
            return None
        return _inspect_snapshot(snapshot)


def _revalidate_authoring(
    authoring: object,
) -> Union[ValidatedPolicyAuthoring, InstallationRefusal]:
    try:
        primitive = _validated_authoring_to_primitive(authoring)
    except _SnapshotConstructionFailure as failure:
        return InstallationRefusal(
            code=failure.code,
            location=failure.location,
            masked_detail=failure.masked_detail,
        )

    validated = validate_policy_authoring(primitive)
    if type(validated) is AuthoringRefusal:
        return InstallationRefusal(
            code=validated.code,
            location=validated.location,
            masked_detail=validated.masked_detail,
        )
    return validated


def _validated_authoring_to_primitive(authoring: object) -> dict:
    if type(authoring) is not ValidatedPolicyAuthoring:
        _fail_policy(("policy_authoring",))

    return {
        "policy_version": _identifier_value(
            authoring.policy_version,
            PolicyVersion,
            ("policy_version",),
            RuleId.RUNTIME_POLICY_UNAVAILABLE,
        ),
        "registry_version": _identifier_value(
            authoring.registry_version,
            RegistryVersion,
            ("registry_version",),
        ),
        "executable_tools": _identifier_tuple(
            authoring.executable_tools,
            ToolId,
            ("executable_tools",),
        ),
        "tool_registrations": _registration_tuple(
            authoring.tool_registrations,
            ("tool_registrations",),
        ),
    }


def _registration_tuple(value: object, path: _Location) -> tuple:
    _require_tuple(value, path)
    return tuple(
        _registration_to_primitive(item, path + (index,))
        for index, item in enumerate(value)
    )


def _registration_to_primitive(value: object, path: _Location) -> dict:
    if type(value) is not ValidatedToolRegistration:
        _fail_registry(path)
    return {
        "tool_id": _identifier_value(
            value.tool_id, ToolId, path + ("tool_id",)
        ),
        "contract_version": _identifier_value(
            value.contract_version,
            ToolContractVersion,
            path + ("contract_version",),
        ),
        "policy_version": _identifier_value(
            value.policy_version,
            PolicyVersion,
            path + ("policy_version",),
        ),
        "signature": _signature_tuple(value.signature, path + ("signature",)),
        "arguments": _argument_tuple(value.arguments, path + ("arguments",)),
        "role_metadata": _role_metadata_tuple(
            value.role_metadata, path + ("role_metadata",)
        ),
        "effect_class": _enum_value(
            value.effect_class, EffectClass, path + ("effect_class",)
        ),
        "reversibility": _enum_value(
            value.reversibility, Reversibility, path + ("reversibility",)
        ),
        "adapter_id": _identifier_value(
            value.adapter_id, AdapterId, path + ("adapter_id",)
        ),
        "adapter_version": _identifier_value(
            value.adapter_version,
            AdapterVersion,
            path + ("adapter_version",),
        ),
        "masking_profile_id": _identifier_value(
            value.masking_profile_id,
            MaskingProfileId,
            path + ("masking_profile_id",),
        ),
    }


def _signature_tuple(value: object, path: _Location) -> tuple:
    _require_tuple(value, path)
    entries = []
    for index, item in enumerate(value):
        item_path = path + (index,)
        if type(item) is not ValidatedSignatureArgument:
            _fail_registry(item_path)
        entries.append(
            {
                "name": _string(item.name, item_path + ("name",)),
                "required": _boolean(
                    item.required, item_path + ("required",)
                ),
                "type_id": _identifier_value(
                    item.type_id, TypeId, item_path + ("type_id",)
                ),
            }
        )
    return tuple(entries)


def _argument_tuple(value: object, path: _Location) -> tuple:
    _require_tuple(value, path)
    entries = []
    for index, item in enumerate(value):
        item_path = path + (index,)
        if type(item) is not ValidatedArgumentContract:
            _fail_registry(item_path)
        entries.append(
            {
                "name": _string(item.name, item_path + ("name",)),
                "position": _integer(
                    item.position, item_path + ("position",)
                ),
                "type_id": _identifier_value(
                    item.type_id, TypeId, item_path + ("type_id",)
                ),
                "required": _boolean(
                    item.required, item_path + ("required",)
                ),
                "role": _enum_value(
                    item.role, ArgumentRole, item_path + ("role",)
                ),
                "constraint_bindings": _constraint_tuple(
                    item.constraint_bindings,
                    item_path + ("constraint_bindings",),
                ),
            }
        )
    return tuple(entries)


def _role_metadata_tuple(value: object, path: _Location) -> tuple:
    _require_tuple(value, path)
    entries = []
    for index, item in enumerate(value):
        item_path = path + (index,)
        if type(item) is not ValidatedRoleMetadata:
            _fail_registry(item_path)
        entries.append(
            {
                "name": _string(item.name, item_path + ("name",)),
                "role": _enum_value(
                    item.role, ArgumentRole, item_path + ("role",)
                ),
                "required_provenance": _enum_value(
                    item.required_provenance,
                    ProvenanceClass,
                    item_path + ("required_provenance",),
                ),
            }
        )
    return tuple(entries)


def _constraint_tuple(value: object, path: _Location) -> tuple:
    _require_tuple(value, path)
    entries = []
    for index, item in enumerate(value):
        item_path = path + (index,)
        if type(item) is not ValidatedConstraintBinding:
            _fail_registry(item_path)
        entries.append(
            {
                "constraint_id": _enum_value(
                    item.constraint_id,
                    ConstraintId,
                    item_path + ("constraint_id",),
                ),
                "parameters": _parameter_mapping(
                    item.parameters, item_path + ("parameters",)
                ),
            }
        )
    return tuple(entries)


def _parameter_mapping(value: object, path: _Location) -> dict:
    _require_tuple(value, path)
    parameters = {}
    for index, pair in enumerate(value):
        item_path = path + (index,)
        if type(pair) is not tuple or len(pair) != 2:
            _fail_registry(item_path)
        name = _string(pair[0], item_path + (0,))
        if name in parameters:
            _fail_registry(path)
        parameters[name] = _parameter_value(pair[1], item_path + (1,))
    return parameters


def _parameter_value(value: object, path: _Location) -> _ParameterScalar:
    if type(value) in (str, bool, int) or value is None:
        if type(value) is int:
            return _integer(value, path)
        return value
    if type(value) is tuple:
        return tuple(
            _string(item, path + (index,))
            for index, item in enumerate(value)
        )
    _fail_registry(path)


_IdentifierT = TypeVar("_IdentifierT")
_EnumT = TypeVar("_EnumT")


def _identifier_tuple(
    value: object, expected_type: Type[_IdentifierT], path: _Location
) -> tuple:
    _require_tuple(value, path)
    return tuple(
        _identifier_value(item, expected_type, path + (index,))
        for index, item in enumerate(value)
    )


def _identifier_value(
    value: object,
    expected_type: Type[_IdentifierT],
    path: _Location,
    code: RuleId = RuleId.CONTRACT_REGISTRY_INCOMPLETE,
) -> str:
    if type(value) is not expected_type:
        _fail(code, path)
    identifier = value.value
    if type(identifier) is not str or identifier == "":
        _fail(code, path)
    return identifier


def _enum_value(
    value: object, expected_type: Type[_EnumT], path: _Location
) -> str:
    if type(value) is not expected_type:
        _fail_registry(path)
    primitive = value.value
    if type(primitive) is not str:
        _fail_registry(path)
    return primitive


def _require_tuple(value: object, path: _Location) -> None:
    if type(value) is not tuple:
        _fail_registry(path)


def _string(value: object, path: _Location) -> str:
    if type(value) is not str:
        _fail_registry(path)
    return value


def _boolean(value: object, path: _Location) -> bool:
    if type(value) is not bool:
        _fail_registry(path)
    return value


def _integer(value: object, path: _Location) -> int:
    if type(value) is not int:
        _fail_registry(path)
    if value < AUTHORING_INTEGER_MINIMUM or value > AUTHORING_INTEGER_MAXIMUM:
        _fail_registry(path)
    return value


def _fail(code: RuleId, path: _Location) -> None:
    detail = (
        "validated policy authoring is unavailable"
        if code is RuleId.RUNTIME_POLICY_UNAVAILABLE
        else "validated policy authoring is incomplete or unsupported"
    )
    raise _SnapshotConstructionFailure(code, path, detail)


def _fail_policy(path: _Location) -> None:
    _fail(RuleId.RUNTIME_POLICY_UNAVAILABLE, path)


def _fail_registry(path: _Location) -> None:
    _fail(RuleId.CONTRACT_REGISTRY_INCOMPLETE, path)


def _create_snapshot(
    validated: ValidatedPolicyAuthoring,
    policy_version: PolicyVersion,
    created_at: datetime,
) -> PolicySnapshot:
    registry_version = RegistryVersion(validated.registry_version.value)
    executable_tools = tuple(
        ToolId(tool_id.value) for tool_id in validated.executable_tools
    )
    tool_policies = tuple(
        _create_tool_policy(registration, policy_version)
        for registration in validated.tool_registrations
    )
    integrity_id = _snapshot_integrity_id(
        policy_version, registry_version, executable_tools, tool_policies
    )
    return PolicySnapshot(
        policy_version=policy_version,
        registry_version=registry_version,
        executable_tools=executable_tools,
        tool_policies=tool_policies,
        created_at=created_at,
        integrity_id=integrity_id,
    )


def _create_tool_policy(
    registration: ValidatedToolRegistration,
    policy_version: PolicyVersion,
) -> SnapshotToolPolicy:
    return SnapshotToolPolicy(
        tool_id=ToolId(registration.tool_id.value),
        contract_version=ToolContractVersion(
            registration.contract_version.value
        ),
        policy_version=policy_version,
        signature=tuple(
            SnapshotSignatureArgument(
                name=item.name,
                required=item.required,
                type_id=TypeId(item.type_id.value),
            )
            for item in registration.signature
        ),
        arguments=tuple(
            SnapshotArgumentContract(
                name=item.name,
                position=item.position,
                type_id=TypeId(item.type_id.value),
                required=item.required,
                role=item.role,
                constraint_bindings=tuple(
                    SnapshotConstraintBinding(
                        constraint_id=binding.constraint_id,
                        parameters=_copy_parameter_pairs(binding.parameters),
                    )
                    for binding in item.constraint_bindings
                ),
            )
            for item in registration.arguments
        ),
        role_metadata=tuple(
            SnapshotRoleMetadata(
                name=item.name,
                role=item.role,
                required_provenance=item.required_provenance,
            )
            for item in registration.role_metadata
        ),
        effect_class=registration.effect_class,
        reversibility=registration.reversibility,
        adapter_id=AdapterId(registration.adapter_id.value),
        adapter_version=AdapterVersion(registration.adapter_version.value),
        masking_profile_id=MaskingProfileId(
            registration.masking_profile_id.value
        ),
    )


def _copy_parameter_pairs(
    parameters: Tuple[_ParameterPair, ...]
) -> Tuple[_ParameterPair, ...]:
    return tuple(
        (name, _copy_parameter_value(value)) for name, value in parameters
    )


def _copy_parameter_value(value: _ParameterScalar) -> _ParameterScalar:
    if type(value) is tuple:
        return tuple(item for item in value)
    return value


def _snapshot_integrity_id(
    policy_version: PolicyVersion,
    registry_version: RegistryVersion,
    executable_tools: Tuple[ToolId, ...],
    tool_policies: Tuple[SnapshotToolPolicy, ...],
) -> str:
    canonical = {
        "policy_version": policy_version.value,
        "registry_version": registry_version.value,
        "executable_tools": tuple(
            tool_id.value for tool_id in executable_tools
        ),
        "tool_policies": tuple(
            _tool_policy_primitive(tool_policy)
            for tool_policy in tool_policies
        ),
    }
    encoded = json.dumps(
        canonical,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


def _tool_policy_primitive(tool_policy: SnapshotToolPolicy) -> dict:
    return {
        "tool_id": tool_policy.tool_id.value,
        "contract_version": tool_policy.contract_version.value,
        "policy_version": tool_policy.policy_version.value,
        "signature": tuple(
            {
                "name": item.name,
                "required": item.required,
                "type_id": item.type_id.value,
            }
            for item in tool_policy.signature
        ),
        "arguments": tuple(
            {
                "name": item.name,
                "position": item.position,
                "type_id": item.type_id.value,
                "required": item.required,
                "role": item.role.value,
                "constraint_bindings": tuple(
                    {
                        "constraint_id": binding.constraint_id.value,
                        "parameters": binding.parameters,
                    }
                    for binding in item.constraint_bindings
                ),
            }
            for item in tool_policy.arguments
        ),
        "role_metadata": tuple(
            {
                "name": item.name,
                "role": item.role.value,
                "required_provenance": item.required_provenance.value,
            }
            for item in tool_policy.role_metadata
        ),
        "effect_class": tool_policy.effect_class.value,
        "reversibility": tool_policy.reversibility.value,
        "adapter_id": tool_policy.adapter_id.value,
        "adapter_version": tool_policy.adapter_version.value,
        "masking_profile_id": tool_policy.masking_profile_id.value,
    }


def _inspect_snapshot(snapshot: PolicySnapshot) -> SnapshotInspection:
    return SnapshotInspection(
        policy_version=snapshot.policy_version.value,
        registry_version=snapshot.registry_version.value,
        executable_tools=tuple(
            tool_id.value for tool_id in snapshot.executable_tools
        ),
        tool_policies=tuple(
            _inspect_tool_policy(tool_policy)
            for tool_policy in snapshot.tool_policies
        ),
        created_at=snapshot.created_at.isoformat().replace("+00:00", "Z"),
        integrity_id=snapshot.integrity_id,
    )


def _inspect_tool_policy(
    tool_policy: SnapshotToolPolicy,
) -> ToolPolicyInspection:
    return ToolPolicyInspection(
        tool_id=tool_policy.tool_id.value,
        contract_version=tool_policy.contract_version.value,
        policy_version=tool_policy.policy_version.value,
        signature=tuple(
            SignatureArgumentInspection(
                name=item.name,
                required=item.required,
                type_id=item.type_id.value,
            )
            for item in tool_policy.signature
        ),
        arguments=tuple(
            ArgumentContractInspection(
                name=item.name,
                position=item.position,
                type_id=item.type_id.value,
                required=item.required,
                role=item.role.value,
                constraint_bindings=tuple(
                    ConstraintBindingInspection(
                        constraint_id=binding.constraint_id.value,
                        parameters=_copy_parameter_pairs(binding.parameters),
                    )
                    for binding in item.constraint_bindings
                ),
            )
            for item in tool_policy.arguments
        ),
        role_metadata=tuple(
            RoleMetadataInspection(
                name=item.name,
                role=item.role.value,
                required_provenance=item.required_provenance.value,
            )
            for item in tool_policy.role_metadata
        ),
        effect_class=tool_policy.effect_class.value,
        reversibility=tool_policy.reversibility.value,
        adapter_id=tool_policy.adapter_id.value,
        adapter_version=tool_policy.adapter_version.value,
        masking_profile_id=tool_policy.masking_profile_id.value,
    )


__all__ = (
    "ArgumentContractInspection",
    "ConstraintBindingInspection",
    "InstallationRefusal",
    "InstalledSnapshot",
    "PolicyInstallationResult",
    "PolicyInstaller",
    "PolicySnapshot",
    "RoleMetadataInspection",
    "SignatureArgumentInspection",
    "SnapshotArgumentContract",
    "SnapshotConstraintBinding",
    "SnapshotInspection",
    "SnapshotRoleMetadata",
    "SnapshotSignatureArgument",
    "SnapshotToolPolicy",
    "ToolPolicyInspection",
)
