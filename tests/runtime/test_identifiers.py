import json

import pytest

from tidemark.runtime.identifiers import (
    AdapterId,
    AdapterVersion,
    CallId,
    DecisionId,
    ExecutionId,
    InvalidIdentifierError,
    InvocationId,
    MaskingProfileId,
    ParentId,
    PolicyVersion,
    PreparedCallId,
    ReferenceId,
    RegistryVersion,
    ToolContractVersion,
    ToolId,
    TypeId,
)


IDENTIFIER_TYPES = (
    ToolId,
    ToolContractVersion,
    PolicyVersion,
    RegistryVersion,
    InvocationId,
    ParentId,
    ReferenceId,
    CallId,
    DecisionId,
    PreparedCallId,
    ExecutionId,
    AdapterId,
    AdapterVersion,
    MaskingProfileId,
    TypeId,
)


@pytest.mark.parametrize("identifier_type", IDENTIFIER_TYPES)
def test_identifier_round_trip_is_exact_and_deterministic(identifier_type):
    first = identifier_type.parse("opaque:value-01")
    second = identifier_type.parse("opaque:value-01")

    assert first == second
    assert hash(first) == hash(second)
    assert first.to_primitive() == "opaque:value-01"
    assert json.loads(json.dumps(first.to_primitive())) == "opaque:value-01"


@pytest.mark.parametrize("identifier_type", IDENTIFIER_TYPES)
@pytest.mark.parametrize("invalid", ["", None, 0, True, b"identifier"])
def test_identifier_rejects_invalid_values(identifier_type, invalid):
    with pytest.raises(InvalidIdentifierError):
        identifier_type.parse(invalid)


def test_identifier_rejects_string_subclasses():
    class CallerString(str):
        pass

    with pytest.raises(InvalidIdentifierError):
        ReferenceId.parse(CallerString("reference-01"))


def test_identifier_kind_is_part_of_equality_and_hashing():
    tool_id = ToolId("shared-value")
    call_id = CallId("shared-value")

    assert tool_id != call_id
    assert len({tool_id, call_id}) == 2


def test_identifier_does_not_normalize_opaque_content():
    identifier = InvocationId("  opaque value  ")

    assert identifier.to_primitive() == "  opaque value  "


def test_identifier_kinds_are_named_and_unique():
    kinds = tuple(identifier_type.KIND for identifier_type in IDENTIFIER_TYPES)

    assert all(kinds)
    assert len(kinds) == len(set(kinds))
