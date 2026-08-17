"""Strict construction boundary for inert v1 policy authoring data.

This module validates caller-owned authoring structures and produces detached,
immutable validated values.  It does not install or publish a policy snapshot,
evaluate policy, resolve references, prepare calls, or execute tools.
"""

from dataclasses import dataclass
from typing import FrozenSet, Tuple, Type, TypeVar, Union, final

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
from tidemark.runtime.vocabulary import (
    ArgumentRole,
    ConstraintId,
    EffectClass,
    ProvenanceClass,
    Reversibility,
    RuleId,
)


AUTHORING_INTEGER_MINIMUM = -(2**63)
AUTHORING_INTEGER_MAXIMUM = 2**63 - 1

_POLICY_FIELDS = frozenset(
    {
        "policy_version",
        "registry_version",
        "executable_tools",
        "tool_registrations",
    }
)
_REGISTRATION_FIELDS = frozenset(
    {
        "tool_id",
        "contract_version",
        "policy_version",
        "signature",
        "arguments",
        "role_metadata",
        "effect_class",
        "reversibility",
        "adapter_id",
        "adapter_version",
        "masking_profile_id",
    }
)
_SIGNATURE_FIELDS = frozenset({"name", "required", "type_id"})
_ARGUMENT_FIELDS = frozenset(
    {
        "name",
        "position",
        "type_id",
        "required",
        "role",
        "constraint_bindings",
    }
)
_ROLE_METADATA_FIELDS = frozenset(
    {"name", "role", "required_provenance"}
)
_CONSTRAINT_FIELDS = frozenset({"constraint_id", "parameters"})

_PROTECTED_CONSTRAINT_IDS = frozenset(
    {
        ConstraintId.PROTECTED_REFERENCE_REQUIRED,
        ConstraintId.REFERENCE_KIND_EQUALS,
        ConstraintId.REFERENCE_INVOCATION_EQUALS,
        ConstraintId.REFERENCE_PARENT_EQUALS,
        ConstraintId.REFERENCE_ACTIVE,
        ConstraintId.REFERENCE_SINGLE_USE,
    }
)
_VALUE_CONSTRAINT_IDS = frozenset(
    {
        ConstraintId.VALUE_INTEGER_MAXIMUM,
        ConstraintId.VALUE_ENUM_MEMBER,
    }
)

_LocationPart = Union[str, int]
_Location = Tuple[_LocationPart, ...]
_ParameterScalar = Union[str, bool, int, None, Tuple[str, ...]]
_ParameterPair = Tuple[str, _ParameterScalar]


@final
@dataclass(frozen=True)
class AuthoringRefusal:
    """Stable construction refusal; no validated authoring value was made."""

    code: RuleId
    location: _Location
    masked_detail: str


@final
@dataclass(frozen=True)
class ValidatedConstraintBinding:
    """Detached inert binding to runtime-owned constraint behavior."""

    constraint_id: ConstraintId
    parameters: Tuple[_ParameterPair, ...]


@final
@dataclass(frozen=True)
class ValidatedSignatureArgument:
    """Canonical signature metadata used only for registry parity checks."""

    name: str
    required: bool
    type_id: TypeId


@final
@dataclass(frozen=True)
class ValidatedArgumentContract:
    """Validated ordered argument contract without executable behavior."""

    name: str
    position: int
    type_id: TypeId
    required: bool
    role: ArgumentRole
    constraint_bindings: Tuple[ValidatedConstraintBinding, ...]


@final
@dataclass(frozen=True)
class ValidatedRoleMetadata:
    """Explicit role and required provenance for one registered argument."""

    name: str
    role: ArgumentRole
    required_provenance: ProvenanceClass


@final
@dataclass(frozen=True)
class ValidatedToolRegistration:
    """Complete inert registration metadata for one executable tool."""

    tool_id: ToolId
    contract_version: ToolContractVersion
    policy_version: PolicyVersion
    signature: Tuple[ValidatedSignatureArgument, ...]
    arguments: Tuple[ValidatedArgumentContract, ...]
    role_metadata: Tuple[ValidatedRoleMetadata, ...]
    effect_class: EffectClass
    reversibility: Reversibility
    adapter_id: AdapterId
    adapter_version: AdapterVersion
    masking_profile_id: MaskingProfileId


@final
@dataclass(frozen=True)
class ValidatedPolicyAuthoring:
    """Detached validated authoring data, explicitly not an installed snapshot."""

    policy_version: PolicyVersion
    registry_version: RegistryVersion
    executable_tools: Tuple[ToolId, ...]
    tool_registrations: Tuple[ValidatedToolRegistration, ...]


PolicyAuthoringValidationResult = Union[
    ValidatedPolicyAuthoring, AuthoringRefusal
]


class _ValidationFailure(Exception):
    def __init__(
        self, code: RuleId, location: _Location, masked_detail: str
    ) -> None:
        super().__init__()
        self.code = code
        self.location = location
        self.masked_detail = masked_detail


_EnumT = TypeVar("_EnumT")
_IdentifierT = TypeVar("_IdentifierT")


def validate_policy_authoring(authoring: object) -> PolicyAuthoringValidationResult:
    """Validate exact v1 authoring data without invoking caller behavior.

    Invalid inputs return a refusal carrying an existing stable ``RuleId``.
    Successful validation returns fresh identifiers, closed vocabulary values,
    dataclasses, and tuples that retain no caller-owned collection.
    """

    try:
        return _validate_policy_authoring(authoring)
    except _ValidationFailure as failure:
        return AuthoringRefusal(
            code=failure.code,
            location=failure.location,
            masked_detail=failure.masked_detail,
        )


def _validate_policy_authoring(authoring: object) -> ValidatedPolicyAuthoring:
    root: _Location = ()
    _require_shape(authoring, _POLICY_FIELDS, root)
    source = authoring

    policy_version = _parse_identifier(
        source["policy_version"],
        PolicyVersion,
        ("policy_version",),
        RuleId.RUNTIME_POLICY_UNAVAILABLE,
    )
    registry_version = _parse_identifier(
        source["registry_version"],
        RegistryVersion,
        ("registry_version",),
        RuleId.CONTRACT_REGISTRY_INCOMPLETE,
    )

    executable_tools = _parse_executable_tools(
        source["executable_tools"], ("executable_tools",)
    )
    registrations_source = source["tool_registrations"]
    _require_exact_tuple(
        registrations_source, ("tool_registrations",)
    )
    if len(registrations_source) == 0:
        _fail_registry(("tool_registrations",))

    registrations = tuple(
        _parse_tool_registration(
            registration,
            policy_version,
            ("tool_registrations", index),
        )
        for index, registration in enumerate(registrations_source)
    )

    registration_tool_ids = tuple(
        registration.tool_id for registration in registrations
    )
    if len(set(registration_tool_ids)) != len(registration_tool_ids):
        _fail_registry(("tool_registrations",))
    registration_pairs = tuple(
        (registration.tool_id, registration.contract_version)
        for registration in registrations
    )
    if len(set(registration_pairs)) != len(registration_pairs):
        _fail_registry(("tool_registrations",))
    if set(registration_tool_ids) != set(executable_tools):
        raise _ValidationFailure(
            RuleId.CONTRACT_TOOL_UNKNOWN,
            ("executable_tools",),
            "executable tool coverage is incomplete",
        )

    return ValidatedPolicyAuthoring(
        policy_version=policy_version,
        registry_version=registry_version,
        executable_tools=executable_tools,
        tool_registrations=registrations,
    )


def _parse_executable_tools(value: object, path: _Location) -> Tuple[ToolId, ...]:
    _require_exact_tuple(value, path)
    if len(value) == 0:
        _fail_registry(path)
    tools = tuple(
        _parse_identifier(
            item,
            ToolId,
            path + (index,),
            RuleId.CONTRACT_REGISTRY_INCOMPLETE,
        )
        for index, item in enumerate(value)
    )
    if len(set(tools)) != len(tools):
        _fail_registry(path)
    return tools


def _parse_tool_registration(
    value: object, expected_policy_version: PolicyVersion, path: _Location
) -> ValidatedToolRegistration:
    _require_shape(value, _REGISTRATION_FIELDS, path)
    source = value

    tool_id = _parse_identifier(
        source["tool_id"],
        ToolId,
        path + ("tool_id",),
        RuleId.CONTRACT_REGISTRY_INCOMPLETE,
    )
    contract_version = _parse_identifier(
        source["contract_version"],
        ToolContractVersion,
        path + ("contract_version",),
        RuleId.CONTRACT_REGISTRY_INCOMPLETE,
    )
    policy_version = _parse_identifier(
        source["policy_version"],
        PolicyVersion,
        path + ("policy_version",),
        RuleId.CONTRACT_REGISTRY_INCOMPLETE,
    )
    if policy_version != expected_policy_version:
        _fail_registry(path + ("policy_version",))

    signature = _parse_signature(source["signature"], path + ("signature",))
    arguments = _parse_arguments(source["arguments"], path + ("arguments",))
    role_metadata = _parse_role_metadata(
        source["role_metadata"], path + ("role_metadata",)
    )

    _validate_signature_parity(signature, arguments, path)
    _validate_role_metadata(role_metadata, arguments, path)

    effect_class = _parse_enum(
        source["effect_class"],
        EffectClass,
        path + ("effect_class",),
    )
    reversibility = _parse_enum(
        source["reversibility"],
        Reversibility,
        path + ("reversibility",),
    )
    adapter_id = _parse_identifier(
        source["adapter_id"],
        AdapterId,
        path + ("adapter_id",),
        RuleId.CONTRACT_REGISTRY_INCOMPLETE,
    )
    adapter_version = _parse_identifier(
        source["adapter_version"],
        AdapterVersion,
        path + ("adapter_version",),
        RuleId.CONTRACT_REGISTRY_INCOMPLETE,
    )
    masking_profile_id = _parse_identifier(
        source["masking_profile_id"],
        MaskingProfileId,
        path + ("masking_profile_id",),
        RuleId.CONTRACT_REGISTRY_INCOMPLETE,
    )

    return ValidatedToolRegistration(
        tool_id=tool_id,
        contract_version=contract_version,
        policy_version=policy_version,
        signature=signature,
        arguments=arguments,
        role_metadata=role_metadata,
        effect_class=effect_class,
        reversibility=reversibility,
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        masking_profile_id=masking_profile_id,
    )


def _parse_signature(
    value: object, path: _Location
) -> Tuple[ValidatedSignatureArgument, ...]:
    _require_exact_tuple(value, path)
    signature = []
    names = []
    for index, item in enumerate(value):
        item_path = path + (index,)
        _require_shape(item, _SIGNATURE_FIELDS, item_path)
        name = _parse_non_empty_string(item["name"], item_path + ("name",))
        required = _parse_boolean(
            item["required"], item_path + ("required",)
        )
        type_id = _parse_identifier(
            item["type_id"],
            TypeId,
            item_path + ("type_id",),
            RuleId.CONTRACT_REGISTRY_INCOMPLETE,
        )
        signature.append(
            ValidatedSignatureArgument(
                name=name, required=required, type_id=type_id
            )
        )
        names.append(name)
    if len(set(names)) != len(names):
        _fail_registry(path)
    return tuple(signature)


def _parse_arguments(
    value: object, path: _Location
) -> Tuple[ValidatedArgumentContract, ...]:
    _require_exact_tuple(value, path)
    arguments = []
    names = []
    positions = []
    for index, item in enumerate(value):
        item_path = path + (index,)
        _require_shape(item, _ARGUMENT_FIELDS, item_path)
        name = _parse_non_empty_string(item["name"], item_path + ("name",))
        position = _parse_bounded_integer(
            item["position"], item_path + ("position",)
        )
        if position < 0:
            _fail_registry(item_path + ("position",))
        type_id = _parse_identifier(
            item["type_id"],
            TypeId,
            item_path + ("type_id",),
            RuleId.CONTRACT_REGISTRY_INCOMPLETE,
        )
        required = _parse_boolean(
            item["required"], item_path + ("required",)
        )
        role = _parse_enum(item["role"], ArgumentRole, item_path + ("role",))
        constraints = _parse_constraint_bindings(
            item["constraint_bindings"],
            item_path + ("constraint_bindings",),
        )
        _validate_argument_constraint_roles(
            role, required, constraints, item_path
        )
        arguments.append(
            ValidatedArgumentContract(
                name=name,
                position=position,
                type_id=type_id,
                required=required,
                role=role,
                constraint_bindings=constraints,
            )
        )
        names.append(name)
        positions.append(position)

    if len(set(names)) != len(names) or len(set(positions)) != len(positions):
        _fail_registry(path)
    if tuple(positions) != tuple(range(len(positions))):
        _fail_registry(path)
    return tuple(arguments)


def _parse_role_metadata(
    value: object, path: _Location
) -> Tuple[ValidatedRoleMetadata, ...]:
    _require_exact_tuple(value, path)
    metadata = []
    names = []
    for index, item in enumerate(value):
        item_path = path + (index,)
        _require_shape(item, _ROLE_METADATA_FIELDS, item_path)
        name = _parse_non_empty_string(item["name"], item_path + ("name",))
        role = _parse_enum(item["role"], ArgumentRole, item_path + ("role",))
        provenance = _parse_enum(
            item["required_provenance"],
            ProvenanceClass,
            item_path + ("required_provenance",),
        )
        metadata.append(
            ValidatedRoleMetadata(
                name=name, role=role, required_provenance=provenance
            )
        )
        names.append(name)
    if len(set(names)) != len(names):
        _fail_registry(path)
    return tuple(metadata)


def _parse_constraint_bindings(
    value: object, path: _Location
) -> Tuple[ValidatedConstraintBinding, ...]:
    _require_exact_tuple(value, path)
    bindings = []
    constraint_ids = []
    for index, item in enumerate(value):
        item_path = path + (index,)
        _require_shape(item, _CONSTRAINT_FIELDS, item_path)
        constraint_id = _parse_enum(
            item["constraint_id"],
            ConstraintId,
            item_path + ("constraint_id",),
        )
        parameters = _parse_constraint_parameters(
            constraint_id, item["parameters"], item_path + ("parameters",)
        )
        bindings.append(
            ValidatedConstraintBinding(
                constraint_id=constraint_id, parameters=parameters
            )
        )
        constraint_ids.append(constraint_id)
    if len(set(constraint_ids)) != len(constraint_ids):
        _fail_registry(path)
    return tuple(bindings)


def _parse_constraint_parameters(
    constraint_id: ConstraintId, value: object, path: _Location
) -> Tuple[_ParameterPair, ...]:
    if constraint_id is ConstraintId.REFERENCE_KIND_EQUALS:
        _require_shape(value, frozenset({"kind"}), path)
        kind = _parse_non_empty_string(value["kind"], path + ("kind",))
        return (("kind", kind),)
    if constraint_id is ConstraintId.VALUE_INTEGER_MAXIMUM:
        _require_shape(value, frozenset({"maximum"}), path)
        maximum = _parse_bounded_integer(
            value["maximum"], path + ("maximum",)
        )
        return (("maximum", maximum),)
    if constraint_id is ConstraintId.VALUE_ENUM_MEMBER:
        _require_shape(value, frozenset({"members"}), path)
        members = _parse_string_tuple(
            value["members"], path + ("members",)
        )
        return (("members", members),)

    _require_shape(value, frozenset(), path)
    return ()


def _validate_argument_constraint_roles(
    role: ArgumentRole,
    required: bool,
    constraints: Tuple[ValidatedConstraintBinding, ...],
    path: _Location,
) -> None:
    constraint_ids = frozenset(
        binding.constraint_id for binding in constraints
    )
    if role is ArgumentRole.PROTECTED_REFERENCE:
        if not required:
            _fail_registry(path + ("required",))
        if ConstraintId.PROTECTED_REFERENCE_REQUIRED not in constraint_ids:
            _fail_registry(path + ("constraint_bindings",))
        if not constraint_ids.issubset(_PROTECTED_CONSTRAINT_IDS):
            _fail_registry(path + ("constraint_bindings",))
        return
    if not constraint_ids.issubset(_VALUE_CONSTRAINT_IDS):
        _fail_registry(path + ("constraint_bindings",))


def _validate_signature_parity(
    signature: Tuple[ValidatedSignatureArgument, ...],
    arguments: Tuple[ValidatedArgumentContract, ...],
    path: _Location,
) -> None:
    if len(signature) != len(arguments):
        _fail_signature(path)
    for signature_item, argument in zip(signature, arguments):
        if (
            signature_item.name != argument.name
            or signature_item.required is not argument.required
            or signature_item.type_id != argument.type_id
        ):
            _fail_signature(path)


def _validate_role_metadata(
    metadata: Tuple[ValidatedRoleMetadata, ...],
    arguments: Tuple[ValidatedArgumentContract, ...],
    path: _Location,
) -> None:
    if len(metadata) != len(arguments):
        _fail_registry(path + ("role_metadata",))
    for role_item, argument in zip(metadata, arguments):
        if role_item.name != argument.name or role_item.role is not argument.role:
            _fail_registry(path + ("role_metadata",))
        expected_provenance = (
            ProvenanceClass.RUNTIME_TRUSTED
            if argument.role is ArgumentRole.PROTECTED_REFERENCE
            else ProvenanceClass.UNTRUSTED
        )
        if role_item.required_provenance is not expected_provenance:
            _fail_registry(path + ("role_metadata",))


def _require_shape(
    value: object, fields: FrozenSet[str], path: _Location
) -> None:
    if type(value) is not dict:
        _fail_registry(path)
    keys = tuple(value.keys())
    if any(type(key) is not str for key in keys):
        _fail_registry(path)
    if frozenset(keys) != fields:
        _fail_registry(path)


def _require_exact_tuple(value: object, path: _Location) -> None:
    if type(value) is not tuple:
        _fail_registry(path)


def _parse_non_empty_string(value: object, path: _Location) -> str:
    if type(value) is not str or value == "":
        _fail_registry(path)
    return value


def _parse_string_tuple(value: object, path: _Location) -> Tuple[str, ...]:
    _require_exact_tuple(value, path)
    result = []
    for index, item in enumerate(value):
        if type(item) is not str:
            _fail_registry(path + (index,))
        result.append(item)
    if len(set(result)) != len(result):
        _fail_registry(path)
    return tuple(result)


def _parse_boolean(value: object, path: _Location) -> bool:
    if type(value) is not bool:
        _fail_registry(path)
    return value


def _parse_bounded_integer(value: object, path: _Location) -> int:
    if type(value) is not int:
        _fail_registry(path)
    if value < AUTHORING_INTEGER_MINIMUM or value > AUTHORING_INTEGER_MAXIMUM:
        _fail_registry(path)
    return value


def _parse_identifier(
    value: object,
    identifier_type: Type[_IdentifierT],
    path: _Location,
    code: RuleId,
) -> _IdentifierT:
    if type(value) is not str or value == "":
        raise _ValidationFailure(
            code, path, "authoring identity is unavailable or unsupported"
        )
    return identifier_type(value)


def _parse_enum(
    value: object, enum_type: Type[_EnumT], path: _Location
) -> _EnumT:
    if type(value) is not str:
        _fail_registry(path)
    member = enum_type._value2member_map_.get(value)
    if member is None:
        _fail_registry(path)
    return member


def _fail_registry(path: _Location) -> None:
    raise _ValidationFailure(
        RuleId.CONTRACT_REGISTRY_INCOMPLETE,
        path,
        "registry authoring metadata is incomplete or unsupported",
    )


def _fail_signature(path: _Location) -> None:
    raise _ValidationFailure(
        RuleId.CONTRACT_SIGNATURE_MISMATCH,
        path,
        "tool signature and argument contract do not match",
    )


__all__ = [
    "AUTHORING_INTEGER_MAXIMUM",
    "AUTHORING_INTEGER_MINIMUM",
    "AuthoringRefusal",
    "PolicyAuthoringValidationResult",
    "ValidatedArgumentContract",
    "ValidatedConstraintBinding",
    "ValidatedPolicyAuthoring",
    "ValidatedRoleMetadata",
    "ValidatedSignatureArgument",
    "ValidatedToolRegistration",
    "validate_policy_authoring",
]
