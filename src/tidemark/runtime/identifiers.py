"""Typed opaque identifiers used by framework-neutral runtime contracts.

These value objects preserve an already-issued identifier exactly. They do not
mint identifiers, inspect their content, or infer trust from their shape.
"""

from dataclasses import dataclass
from typing import ClassVar, Type, TypeVar, final


class InvalidIdentifierError(ValueError):
    """Raised when an identifier is not an exact, non-empty string."""


_IdentifierT = TypeVar("_IdentifierT", bound="_Identifier")


@dataclass(frozen=True)
class _Identifier:
    """Immutable base for identifiers whose kind is carried by their type."""

    value: str

    KIND: ClassVar[str]

    def __post_init__(self) -> None:
        if type(self.value) is not str or self.value == "":
            raise InvalidIdentifierError(
                f"{type(self).__name__} requires an exact, non-empty string"
            )

    @classmethod
    def parse(cls: Type[_IdentifierT], value: object) -> _IdentifierT:
        """Parse an internal wire value without normalization or coercion."""

        if type(value) is not str or value == "":
            raise InvalidIdentifierError(
                f"{cls.__name__} requires an exact, non-empty string"
            )
        return cls(value)

    def to_primitive(self) -> str:
        """Return the full internal correlation value for serialization."""

        return self.value

    def __str__(self) -> str:
        return self.value


@final
class ToolId(_Identifier):
    KIND = "tool"


@final
class ToolContractVersion(_Identifier):
    KIND = "tool_contract_version"


@final
class PolicyVersion(_Identifier):
    KIND = "policy_version"


@final
class RegistryVersion(_Identifier):
    KIND = "registry_version"


@final
class InvocationId(_Identifier):
    KIND = "invocation"


@final
class ParentId(_Identifier):
    KIND = "parent"


@final
class ReferenceId(_Identifier):
    KIND = "reference"


@final
class CallId(_Identifier):
    KIND = "call"


@final
class DecisionId(_Identifier):
    KIND = "decision"


@final
class PreparedCallId(_Identifier):
    KIND = "prepared_call"


@final
class ExecutionId(_Identifier):
    KIND = "execution"


@final
class AdapterId(_Identifier):
    KIND = "adapter"


@final
class AdapterVersion(_Identifier):
    KIND = "adapter_version"


@final
class MaskingProfileId(_Identifier):
    KIND = "masking_profile"


@final
class TypeId(_Identifier):
    KIND = "type"
