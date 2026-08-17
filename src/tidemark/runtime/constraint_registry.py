"""Closed runtime-owned behavior registry for the v1 constraint set.

Policy snapshots contain only ``ConstraintId`` values and inert parameters.
This module is the sole owner of their executable meaning.  It exposes no
registration, replacement, or caller-injection surface.
"""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Mapping, Optional, Tuple, final

from tidemark.runtime.identifiers import ReferenceId
from tidemark.runtime.vocabulary import ConstraintId


_ParameterValue = object
_ParameterPair = Tuple[str, _ParameterValue]


@dataclass(frozen=True)
class _ConstraintOperand:
    value: object = None
    parameters: Tuple[_ParameterPair, ...] = ()
    resolved_kind: Optional[str] = None
    invocation_matches: Optional[bool] = None
    parent_matches: Optional[bool] = None
    active: Optional[bool] = None
    consumed: Optional[bool] = None


_Behavior = Callable[[_ConstraintOperand], bool]


@dataclass(frozen=True)
class _TrustedImplementation:
    implementation_id: str
    behavior: _Behavior


def _parameter(
    operand: _ConstraintOperand, expected_name: str
) -> object:
    for name, value in operand.parameters:
        if name == expected_name:
            return value
    return None


def _protected_reference_required(operand: _ConstraintOperand) -> bool:
    return type(operand.value) is ReferenceId


def _reference_kind_equals(operand: _ConstraintOperand) -> bool:
    expected = _parameter(operand, "kind")
    return (
        type(expected) is str
        and type(operand.resolved_kind) is str
        and operand.resolved_kind == expected
    )


def _reference_invocation_equals(operand: _ConstraintOperand) -> bool:
    return operand.invocation_matches is True


def _reference_parent_equals(operand: _ConstraintOperand) -> bool:
    return operand.parent_matches is True


def _reference_active(operand: _ConstraintOperand) -> bool:
    return operand.active is True


def _reference_single_use(operand: _ConstraintOperand) -> bool:
    return operand.consumed is False


def _value_integer_maximum(operand: _ConstraintOperand) -> bool:
    maximum = _parameter(operand, "maximum")
    return (
        type(operand.value) is int
        and type(maximum) is int
        and operand.value <= maximum
    )


def _value_enum_member(operand: _ConstraintOperand) -> bool:
    members = _parameter(operand, "members")
    return (
        type(operand.value) is str
        and type(members) is tuple
        and operand.value in members
    )


_IMPLEMENTATIONS: Mapping[ConstraintId, _TrustedImplementation] = (
    MappingProxyType(
        {
            ConstraintId.PROTECTED_REFERENCE_REQUIRED: _TrustedImplementation(
                "tidemark.trusted_constraint.protected_reference_required.v1",
                _protected_reference_required,
            ),
            ConstraintId.REFERENCE_KIND_EQUALS: _TrustedImplementation(
                "tidemark.trusted_constraint.reference_kind_equals.v1",
                _reference_kind_equals,
            ),
            ConstraintId.REFERENCE_INVOCATION_EQUALS: _TrustedImplementation(
                "tidemark.trusted_constraint.reference_invocation_equals.v1",
                _reference_invocation_equals,
            ),
            ConstraintId.REFERENCE_PARENT_EQUALS: _TrustedImplementation(
                "tidemark.trusted_constraint.reference_parent_equals.v1",
                _reference_parent_equals,
            ),
            ConstraintId.REFERENCE_ACTIVE: _TrustedImplementation(
                "tidemark.trusted_constraint.reference_active.v1",
                _reference_active,
            ),
            ConstraintId.REFERENCE_SINGLE_USE: _TrustedImplementation(
                "tidemark.trusted_constraint.reference_single_use.v1",
                _reference_single_use,
            ),
            ConstraintId.VALUE_INTEGER_MAXIMUM: _TrustedImplementation(
                "tidemark.trusted_constraint.value_integer_maximum.v1",
                _value_integer_maximum,
            ),
            ConstraintId.VALUE_ENUM_MEMBER: _TrustedImplementation(
                "tidemark.trusted_constraint.value_enum_member.v1",
                _value_enum_member,
            ),
        }
    )
)


@final
class TrustedConstraintRegistry:
    """Read-only view of the fixed runtime-owned v1 behavior registry."""

    __slots__ = ()

    @property
    def constraint_ids(self) -> Tuple[ConstraintId, ...]:
        return tuple(ConstraintId)

    def implementation_id(self, constraint_id: object) -> Optional[str]:
        if type(constraint_id) is not ConstraintId:
            return None
        implementation = _IMPLEMENTATIONS.get(constraint_id)
        if implementation is None:
            return None
        return implementation.implementation_id

    def is_complete(self) -> bool:
        return tuple(_IMPLEMENTATIONS) == tuple(ConstraintId)

    def _evaluate(
        self, constraint_id: object, operand: _ConstraintOperand
    ) -> Optional[bool]:
        if type(constraint_id) is not ConstraintId:
            return None
        implementation = _IMPLEMENTATIONS.get(constraint_id)
        if implementation is None:
            return None
        return implementation.behavior(operand)


TRUSTED_CONSTRAINT_REGISTRY = TrustedConstraintRegistry()


__all__ = (
    "TRUSTED_CONSTRAINT_REGISTRY",
    "TrustedConstraintRegistry",
)
