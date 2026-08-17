import functools

import pytest

from tidemark.runtime.identifiers import PolicyVersion
from tidemark.runtime.policy_authoring import (
    AuthoringRefusal,
    ValidatedPolicyAuthoring,
    validate_policy_authoring,
)
from tidemark.runtime.vocabulary import ArgumentRole, RuleId


def valid_authoring():
    return {
        "policy_version": "policy-2026-08-06",
        "registry_version": "registry-2026-08-06",
        "executable_tools": ("payments.create",),
        "tool_registrations": (
            {
                "tool_id": "payments.create",
                "contract_version": "payments.create.contract.v1",
                "policy_version": "policy-2026-08-06",
                "signature": (
                    {
                        "name": "amount_minor",
                        "required": True,
                        "type_id": "integer",
                    },
                    {
                        "name": "currency",
                        "required": True,
                        "type_id": "currency_code",
                    },
                    {
                        "name": "destination_reference",
                        "required": True,
                        "type_id": "destination_reference",
                    },
                ),
                "arguments": (
                    {
                        "name": "amount_minor",
                        "position": 0,
                        "type_id": "integer",
                        "required": True,
                        "role": "UNPROTECTED_INPUT",
                        "constraint_bindings": (
                            {
                                "constraint_id": "value.integer.maximum.v1",
                                "parameters": {"maximum": 10_000},
                            },
                        ),
                    },
                    {
                        "name": "currency",
                        "position": 1,
                        "type_id": "currency_code",
                        "required": True,
                        "role": "UNPROTECTED_INPUT",
                        "constraint_bindings": (
                            {
                                "constraint_id": "value.enum.member.v1",
                                "parameters": {"members": ("EUR", "USD")},
                            },
                        ),
                    },
                    {
                        "name": "destination_reference",
                        "position": 2,
                        "type_id": "destination_reference",
                        "required": True,
                        "role": "PROTECTED_REFERENCE",
                        "constraint_bindings": (
                            {
                                "constraint_id": "protected.reference.required.v1",
                                "parameters": {},
                            },
                            {
                                "constraint_id": "reference.kind.equals.v1",
                                "parameters": {"kind": "merchant_destination"},
                            },
                            {
                                "constraint_id": "reference.invocation.equals.v1",
                                "parameters": {},
                            },
                            {
                                "constraint_id": "reference.parent.equals.v1",
                                "parameters": {},
                            },
                            {
                                "constraint_id": "reference.active.v1",
                                "parameters": {},
                            },
                            {
                                "constraint_id": "reference.single_use.v1",
                                "parameters": {},
                            },
                        ),
                    },
                ),
                "role_metadata": (
                    {
                        "name": "amount_minor",
                        "role": "UNPROTECTED_INPUT",
                        "required_provenance": "UNTRUSTED",
                    },
                    {
                        "name": "currency",
                        "role": "UNPROTECTED_INPUT",
                        "required_provenance": "UNTRUSTED",
                    },
                    {
                        "name": "destination_reference",
                        "role": "PROTECTED_REFERENCE",
                        "required_provenance": "RUNTIME_TRUSTED",
                    },
                ),
                "effect_class": "SIDE_EFFECTING",
                "reversibility": "IRREVERSIBLE",
                "adapter_id": "payments.local.adapter",
                "adapter_version": "payments.local.adapter.v1",
                "masking_profile_id": "payments.masking.v1",
            },
        ),
    }


def assert_refused(authoring, code=RuleId.CONTRACT_REGISTRY_INCOMPLETE):
    result = validate_policy_authoring(authoring)

    assert type(result) is AuthoringRefusal
    assert result.code is code
    assert type(result.location) is tuple
    assert type(result.masked_detail) is str
    return result


def test_valid_minimal_policy_authoring_input_is_accepted():
    result = validate_policy_authoring(valid_authoring())

    assert type(result) is ValidatedPolicyAuthoring
    assert result.policy_version == PolicyVersion("policy-2026-08-06")
    assert tuple(tool.tool_id.value for tool in result.tool_registrations) == (
        "payments.create",
    )
    assert result.tool_registrations[0].arguments[2].role is (
        ArgumentRole.PROTECTED_REFERENCE
    )


@pytest.mark.parametrize(
    ("path", "unknown"),
    (
        (("tool_registrations", 0, "arguments", 0, "role"), "UNKNOWN_ROLE"),
        (
            ("tool_registrations", 0, "role_metadata", 0, "required_provenance"),
            "UNKNOWN_PROVENANCE",
        ),
        (("tool_registrations", 0, "effect_class"), "READ_ONLY"),
        (("tool_registrations", 0, "reversibility"), "UNKNOWN"),
    ),
)
def test_unknown_closed_vocabulary_is_refused(path, unknown):
    authoring = valid_authoring()
    target = authoring
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = unknown

    assert_refused(authoring)


def test_unknown_constraint_identity_is_refused():
    authoring = valid_authoring()
    authoring["tool_registrations"][0]["arguments"][0][
        "constraint_bindings"
    ][0]["constraint_id"] = "caller.constraint.v1"

    assert_refused(authoring)


def test_missing_required_tool_argument_coverage_is_refused():
    authoring = valid_authoring()
    registration = authoring["tool_registrations"][0]
    registration["arguments"] = registration["arguments"][:-1]
    registration["role_metadata"] = registration["role_metadata"][:-1]

    assert_refused(authoring, RuleId.CONTRACT_SIGNATURE_MISMATCH)


def test_extra_undeclared_argument_coverage_is_refused():
    authoring = valid_authoring()
    registration = authoring["tool_registrations"][0]
    registration["arguments"] += (
        {
            "name": "memo",
            "position": 3,
            "type_id": "string",
            "required": False,
            "role": "UNPROTECTED_INPUT",
            "constraint_bindings": (),
        },
    )
    registration["role_metadata"] += (
        {
            "name": "memo",
            "role": "UNPROTECTED_INPUT",
            "required_provenance": "UNTRUSTED",
        },
    )

    assert_refused(authoring, RuleId.CONTRACT_SIGNATURE_MISMATCH)


@pytest.mark.parametrize("field", ("name", "required", "type_id"))
def test_signature_contract_mismatch_is_refused(field):
    authoring = valid_authoring()
    signature = authoring["tool_registrations"][0]["signature"][0]
    replacements = {"name": "different", "required": False, "type_id": "string"}
    signature[field] = replacements[field]

    assert_refused(authoring, RuleId.CONTRACT_SIGNATURE_MISMATCH)


def test_missing_protected_role_metadata_is_refused():
    authoring = valid_authoring()
    authoring["tool_registrations"][0]["role_metadata"] = authoring[
        "tool_registrations"
    ][0]["role_metadata"][:-1]

    assert_refused(authoring)


@pytest.mark.parametrize(
    "missing_field",
    (
        "contract_version",
        "signature",
        "arguments",
        "role_metadata",
        "effect_class",
        "reversibility",
        "adapter_id",
        "adapter_version",
        "policy_version",
        "masking_profile_id",
    ),
)
def test_partial_registry_metadata_is_refused(missing_field):
    authoring = valid_authoring()
    del authoring["tool_registrations"][0][missing_field]

    assert_refused(authoring)


@pytest.mark.parametrize("extra_field", ("callable", "handler", "resolver"))
def test_extra_registration_fields_are_refused(extra_field):
    authoring = valid_authoring()
    authoring["tool_registrations"][0][extra_field] = None

    assert_refused(authoring)


def test_uncovered_executable_tool_is_refused():
    authoring = valid_authoring()
    authoring["executable_tools"] += ("reports.publish",)

    assert_refused(authoring, RuleId.CONTRACT_TOOL_UNKNOWN)


def test_registration_for_undeclared_executable_tool_is_refused():
    authoring = valid_authoring()
    duplicate = dict(authoring["tool_registrations"][0])
    duplicate["tool_id"] = "reports.publish"
    authoring["tool_registrations"] += (duplicate,)

    assert_refused(authoring, RuleId.CONTRACT_TOOL_UNKNOWN)


def test_duplicate_tool_contract_identity_is_refused():
    authoring = valid_authoring()
    authoring["tool_registrations"] += (
        authoring["tool_registrations"][0],
    )

    assert_refused(authoring)


def test_registration_policy_version_must_match_authoring_policy():
    authoring = valid_authoring()
    authoring["tool_registrations"][0][
        "policy_version"
    ] = "different-policy"

    assert_refused(authoring)


@pytest.mark.parametrize(
    "duplicate_kind",
    ("tool", "argument_name", "position", "role", "constraint"),
)
def test_duplicate_definitions_are_refused(duplicate_kind):
    authoring = valid_authoring()
    registration = authoring["tool_registrations"][0]
    if duplicate_kind == "tool":
        authoring["executable_tools"] += ("payments.create",)
    elif duplicate_kind == "argument_name":
        registration["arguments"][1]["name"] = "amount_minor"
    elif duplicate_kind == "position":
        registration["arguments"][1]["position"] = 0
    elif duplicate_kind == "role":
        registration["role_metadata"] += (registration["role_metadata"][0],)
    else:
        registration["arguments"][2]["constraint_bindings"] += (
            registration["arguments"][2]["constraint_bindings"][0],
        )

    assert_refused(authoring)


def test_protected_argument_cannot_use_unprotected_role_representation():
    authoring = valid_authoring()
    authoring["tool_registrations"][0]["arguments"][2][
        "role"
    ] = "UNPROTECTED_INPUT"

    assert_refused(authoring)


@pytest.mark.parametrize(
    ("metadata_index", "weakened"),
    ((2, "UNTRUSTED"), (0, "RUNTIME_TRUSTED")),
)
def test_unsupported_provenance_combinations_are_refused(
    metadata_index, weakened
):
    authoring = valid_authoring()
    authoring["tool_registrations"][0]["role_metadata"][metadata_index][
        "required_provenance"
    ] = weakened

    assert_refused(authoring)


def test_protected_argument_requires_protected_reference_constraint():
    authoring = valid_authoring()
    protected_argument = authoring["tool_registrations"][0]["arguments"][2]
    protected_argument["constraint_bindings"] = protected_argument[
        "constraint_bindings"
    ][1:]

    assert_refused(authoring)


def test_unprotected_argument_cannot_claim_protected_reference_requirement():
    authoring = valid_authoring()
    authoring["tool_registrations"][0]["arguments"][0][
        "constraint_bindings"
    ] += (
        {
            "constraint_id": "protected.reference.required.v1",
            "parameters": {},
        },
    )

    assert_refused(authoring)


def regular_function():
    return "must not run"


def make_closure():
    captured = "state"

    def closure():
        return captured

    return closure


class StatefulCallable:
    def __init__(self):
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return self.calls


@pytest.mark.parametrize(
    "executable",
    (
        regular_function,
        lambda: "must not run",
        make_closure(),
        functools.partial(regular_function),
        StatefulCallable(),
        property(lambda self: "must not run"),
    ),
)
def test_caller_supplied_executable_or_descriptor_is_refused(executable):
    authoring = valid_authoring()
    authoring["tool_registrations"][0]["arguments"][0][
        "constraint_bindings"
    ][0]["parameters"]["maximum"] = executable

    assert_refused(authoring)
    if type(executable) is StatefulCallable:
        assert executable.calls == 0


class CallerDict(dict):
    pass


class CallerTuple(tuple):
    pass


class CallerString(str):
    pass


class CallerInteger(int):
    pass


@pytest.mark.parametrize("subclass_kind", ("dict", "tuple", "str", "int"))
def test_subclasses_of_authoring_types_are_refused(subclass_kind):
    authoring = valid_authoring()
    if subclass_kind == "dict":
        authoring = CallerDict(authoring)
    elif subclass_kind == "tuple":
        authoring["tool_registrations"] = CallerTuple(
            authoring["tool_registrations"]
        )
    elif subclass_kind == "str":
        authoring["policy_version"] = CallerString("policy-2026-08-06")
    else:
        authoring["tool_registrations"][0]["arguments"][0][
            "position"
        ] = CallerInteger(0)

    expected_code = (
        RuleId.RUNTIME_POLICY_UNAVAILABLE
        if subclass_kind == "str"
        else RuleId.CONTRACT_REGISTRY_INCOMPLETE
    )
    assert_refused(authoring, expected_code)


def test_internal_runtime_values_are_not_authoring_values():
    authoring = valid_authoring()
    authoring["policy_version"] = PolicyVersion("policy-2026-08-06")

    assert_refused(authoring, RuleId.RUNTIME_POLICY_UNAVAILABLE)


def test_internal_closed_vocabulary_values_are_not_authoring_values():
    authoring = valid_authoring()
    authoring["tool_registrations"][0]["arguments"][0][
        "role"
    ] = ArgumentRole.UNPROTECTED_INPUT

    assert_refused(authoring)


@pytest.mark.parametrize(
    (
        "argument_index",
        "constraint_index",
        "parameter_name",
        "subclass_value",
    ),
    (
        (0, 0, "maximum", CallerInteger(10_000)),
        (1, 0, "members", (CallerString("EUR"),)),
        (2, 1, "kind", CallerString("merchant_destination")),
    ),
)
def test_scalar_subclass_inside_constraint_parameters_is_refused(
    argument_index, constraint_index, parameter_name, subclass_value
):
    authoring = valid_authoring()
    authoring["tool_registrations"][0]["arguments"][argument_index][
        "constraint_bindings"
    ][constraint_index]["parameters"][parameter_name] = subclass_value

    assert_refused(authoring)


@pytest.mark.parametrize(
    "unsupported",
    (
        ["EUR", "USD"],
        {"EUR", "USD"},
        {"nested": ("EUR",)},
        (("EUR",),),
        None,
    ),
)
def test_unsupported_constraint_parameter_containers_are_refused(unsupported):
    authoring = valid_authoring()
    authoring["tool_registrations"][0]["arguments"][1][
        "constraint_bindings"
    ][0]["parameters"]["members"] = unsupported

    assert_refused(authoring)


@pytest.mark.parametrize(
    ("constraint_index", "parameters"),
    (
        (0, {"unexpected": True}),
        (1, {}),
        (1, {"kind": 1}),
        (2, {"unexpected": None}),
        (3, {"unexpected": None}),
        (4, {"unexpected": None}),
        (5, {"unexpected": None}),
    ),
)
def test_wrong_parameter_schema_for_reference_constraint_is_refused(
    constraint_index, parameters
):
    authoring = valid_authoring()
    authoring["tool_registrations"][0]["arguments"][2][
        "constraint_bindings"
    ][constraint_index]["parameters"] = parameters

    assert_refused(authoring)


@pytest.mark.parametrize(
    "parameters",
    (
        {},
        {"maximum": True},
        {"maximum": 10_000.0},
        {"maximum": "10000"},
        {"maximum": 1, "extra": 2},
    ),
)
def test_wrong_parameter_schema_for_integer_maximum_is_refused(parameters):
    authoring = valid_authoring()
    authoring["tool_registrations"][0]["arguments"][0][
        "constraint_bindings"
    ][0]["parameters"] = parameters

    assert_refused(authoring)


@pytest.mark.parametrize("outside_bound", (-(2**63) - 1, 2**63))
def test_constraint_integer_outside_authoring_bound_is_refused(outside_bound):
    authoring = valid_authoring()
    authoring["tool_registrations"][0]["arguments"][0][
        "constraint_bindings"
    ][0]["parameters"]["maximum"] = outside_bound

    assert_refused(authoring)


@pytest.mark.parametrize(
    "parameters",
    (
        {},
        {"members": "EUR"},
        {"members": ("EUR", 1)},
        {"members": ("EUR",), "extra": None},
    ),
)
def test_wrong_parameter_schema_for_enum_membership_is_refused(parameters):
    authoring = valid_authoring()
    authoring["tool_registrations"][0]["arguments"][1][
        "constraint_bindings"
    ][0]["parameters"] = parameters

    assert_refused(authoring)


class ConversionTrap:
    def __init__(self):
        self.methods_called = []

    def __str__(self):
        self.methods_called.append("str")
        return "converted"

    def __int__(self):
        self.methods_called.append("int")
        return 10_000

    def __float__(self):
        self.methods_called.append("float")
        return 10_000.0

    def __bool__(self):
        self.methods_called.append("bool")
        return True


@pytest.mark.parametrize("location", ("identifier", "integer", "boolean"))
def test_caller_defined_conversion_methods_are_not_invoked(location):
    trap = ConversionTrap()
    authoring = valid_authoring()
    if location == "identifier":
        authoring["policy_version"] = trap
    elif location == "integer":
        authoring["tool_registrations"][0]["arguments"][0][
            "constraint_bindings"
        ][0]["parameters"]["maximum"] = trap
    else:
        authoring["tool_registrations"][0]["signature"][0]["required"] = trap

    expected_code = (
        RuleId.RUNTIME_POLICY_UNAVAILABLE
        if location == "identifier"
        else RuleId.CONTRACT_REGISTRY_INCOMPLETE
    )
    assert_refused(authoring, expected_code)
    assert trap.methods_called == []


def test_mutating_caller_structures_does_not_change_validated_authoring_value():
    authoring = valid_authoring()
    result = validate_policy_authoring(authoring)
    assert type(result) is ValidatedPolicyAuthoring

    authoring["policy_version"] = "changed"
    authoring["tool_registrations"][0]["arguments"][0][
        "constraint_bindings"
    ][0]["parameters"]["maximum"] = 1
    authoring["tool_registrations"][0]["role_metadata"][2][
        "required_provenance"
    ] = "UNTRUSTED"

    registration = result.tool_registrations[0]
    maximum = registration.arguments[0].constraint_bindings[0].parameters[0]
    protected_metadata = registration.role_metadata[2]
    assert result.policy_version == PolicyVersion("policy-2026-08-06")
    assert maximum == ("maximum", 10_000)
    assert protected_metadata.required_provenance.value == "RUNTIME_TRUSTED"


def test_validated_authoring_value_is_not_an_installed_snapshot():
    result = validate_policy_authoring(valid_authoring())

    assert type(result) is ValidatedPolicyAuthoring
    assert not hasattr(result, "created_at")
    assert not hasattr(result, "integrity_id")
    assert not hasattr(result, "install")
