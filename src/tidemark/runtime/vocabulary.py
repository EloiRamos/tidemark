"""Closed, versioned vocabulary for the TIDEMARK runtime contracts.

This module contains names only. It performs no policy evaluation, reference
resolution, prepared-call construction, execution, evidence persistence, or
framework integration.
"""

from enum import Enum, unique
from typing import Tuple, Type, TypeVar


RUNTIME_VOCABULARY_VERSION = "tidemark.runtime.v1"


class UnknownVocabularyValueError(ValueError):
    """Raised when an unrecognized or non-string closed value is parsed."""


_ClosedEnumT = TypeVar("_ClosedEnumT", bound="_ClosedStringEnum")


class _ClosedStringEnum(str, Enum):
    """Strict wire parsing shared by all closed runtime vocabularies."""

    @classmethod
    def parse(cls: Type[_ClosedEnumT], value: object) -> _ClosedEnumT:
        if type(value) is not str:
            raise UnknownVocabularyValueError(
                f"{cls.__name__} requires an exact string value"
            )
        try:
            return cls(value)
        except ValueError as error:
            raise UnknownVocabularyValueError(
                f"unrecognized {cls.__name__} value"
            ) from error

    def to_primitive(self) -> str:
        return self.value

    def __str__(self) -> str:
        return self.value


@unique
class ArgumentRole(_ClosedStringEnum):
    UNPROTECTED_INPUT = "UNPROTECTED_INPUT"
    PROTECTED_REFERENCE = "PROTECTED_REFERENCE"


@unique
class EffectClass(_ClosedStringEnum):
    SIDE_EFFECTING = "SIDE_EFFECTING"


@unique
class Reversibility(_ClosedStringEnum):
    REVERSIBLE = "REVERSIBLE"
    IRREVERSIBLE = "IRREVERSIBLE"


@unique
class DecisionOutcome(_ClosedStringEnum):
    REFUSAL = "REFUSAL"
    DENY = "DENY"
    ALLOW = "ALLOW"


@unique
class EvaluationStage(_ClosedStringEnum):
    STRUCTURE = "STRUCTURE"
    REPRESENTATION = "REPRESENTATION"
    RESOLUTION = "RESOLUTION"
    BINDING = "BINDING"
    LIFECYCLE = "LIFECYCLE"
    VALUE = "VALUE"
    AUTHORIZATION = "AUTHORIZATION"


@unique
class ProvenanceClass(_ClosedStringEnum):
    UNTRUSTED = "UNTRUSTED"
    RUNTIME_TRUSTED = "RUNTIME_TRUSTED"


@unique
class RuleEvaluationOutcome(_ClosedStringEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_EVALUATED = "NOT_EVALUATED"


@unique
class ExecutionOutcome(_ClosedStringEnum):
    REFUSED = "REFUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    REPLAY_REJECTED = "REPLAY_REJECTED"


@unique
class ResolutionResultKind(_ClosedStringEnum):
    RESOLVED = "RESOLVED"
    RESOLUTION_FAILURE = "RESOLUTION_FAILURE"


@unique
class PreparedCallState(_ClosedStringEnum):
    UNUSED = "UNUSED"
    CONSUMED = "CONSUMED"


@unique
class ConstraintId(_ClosedStringEnum):
    PROTECTED_REFERENCE_REQUIRED = "protected.reference.required.v1"
    REFERENCE_KIND_EQUALS = "reference.kind.equals.v1"
    REFERENCE_INVOCATION_EQUALS = "reference.invocation.equals.v1"
    REFERENCE_PARENT_EQUALS = "reference.parent.equals.v1"
    REFERENCE_ACTIVE = "reference.active.v1"
    REFERENCE_SINGLE_USE = "reference.single_use.v1"
    VALUE_INTEGER_MAXIMUM = "value.integer.maximum.v1"
    VALUE_ENUM_MEMBER = "value.enum.member.v1"


@unique
class RuleId(_ClosedStringEnum):
    RUNTIME_POLICY_UNAVAILABLE = "runtime.policy_unavailable.v1"
    CONTRACT_TOOL_UNKNOWN = "contract.tool_unknown.v1"
    CONTRACT_REGISTRY_INCOMPLETE = "contract.registry_incomplete.v1"
    CONTRACT_SIGNATURE_MISMATCH = "contract.signature_mismatch.v1"
    CONTRACT_ARGUMENT_SHAPE_INVALID = "contract.argument_shape_invalid.v1"
    PROTECTED_RAW_VALUE_SUPPLIED = "protected.raw_value_supplied.v1"
    REFERENCE_NOT_FOUND = "reference.not_found.v1"
    REFERENCE_KIND_MISMATCH = "reference.kind_mismatch.v1"
    REFERENCE_INVOCATION_MISMATCH = "reference.invocation_mismatch.v1"
    REFERENCE_PARENT_MISMATCH = "reference.parent_mismatch.v1"
    REFERENCE_INACTIVE = "reference.inactive.v1"
    REFERENCE_ALREADY_CONSUMED = "reference.already_consumed.v1"
    VALUE_CONSTRAINT_FAILED = "value.constraint_failed.v1"
    AUTHORIZATION_ALLOW = "authorization.allow.v1"
    EXECUTION_PREPARED_CALL_INVALID = "execution.prepared_call_invalid.v1"
    EXECUTION_REPLAY_REJECTED = "execution.replay_rejected.v1"


DECISION_RULE_IDS: Tuple[RuleId, ...] = (
    RuleId.RUNTIME_POLICY_UNAVAILABLE,
    RuleId.CONTRACT_TOOL_UNKNOWN,
    RuleId.CONTRACT_REGISTRY_INCOMPLETE,
    RuleId.CONTRACT_SIGNATURE_MISMATCH,
    RuleId.CONTRACT_ARGUMENT_SHAPE_INVALID,
    RuleId.PROTECTED_RAW_VALUE_SUPPLIED,
    RuleId.REFERENCE_NOT_FOUND,
    RuleId.REFERENCE_KIND_MISMATCH,
    RuleId.REFERENCE_INVOCATION_MISMATCH,
    RuleId.REFERENCE_PARENT_MISMATCH,
    RuleId.REFERENCE_INACTIVE,
    RuleId.REFERENCE_ALREADY_CONSUMED,
    RuleId.VALUE_CONSTRAINT_FAILED,
    RuleId.AUTHORIZATION_ALLOW,
)

EXECUTION_RULE_IDS: Tuple[RuleId, ...] = (
    RuleId.EXECUTION_PREPARED_CALL_INVALID,
    RuleId.EXECUTION_REPLAY_REJECTED,
)
