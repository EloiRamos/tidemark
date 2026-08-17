"""Read-only resolution of opaque references through trusted runtime state.

The resolver validates one exact request, reads one detached record from the
``TrustedReferenceStore``, and maps the first failed trusted fact to an
existing stable ``RuleId``.  It does not evaluate policy, prepare calls,
consume or deactivate references, execute tools, perform I/O, or persist data.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import final

from tidemark.runtime.identifiers import InvocationId, ParentId, ReferenceId
from tidemark.runtime.policy_engine import (
    ResolutionFailure,
    ResolutionResult,
    _resolved_with_runtime_protected_value,
)
from tidemark.runtime.reference_store import TrustedReferenceStore
from tidemark.runtime.vocabulary import RuleId


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


def _require_exact_utc_datetime(value: object, field_name: str) -> None:
    if type(value) is not datetime:
        raise TypeError(f"{field_name} requires datetime")
    if value.tzinfo is not timezone.utc:
        raise ValueError(f"{field_name} requires UTC timezone")


@final
@dataclass(frozen=True)
class ResolutionRequest:
    """Minimum trusted-binding expectations for one protected argument."""

    reference_id: ReferenceId
    expected_kind: str
    invocation_id: InvocationId
    parent_id: ParentId
    argument_name: str
    evaluation_time: datetime

    def __post_init__(self) -> None:
        _validate_request_fields(self)


@final
class ReferenceResolver:
    """Stateless read-only reference resolution through the trusted store."""

    __slots__ = ()

    def resolve(
        self,
        request: ResolutionRequest,
        trusted_store: TrustedReferenceStore,
    ) -> ResolutionResult:
        """Return the first resolver failure or detached trusted facts."""

        _require_exact_type(request, ResolutionRequest, "request")
        _validate_request_fields(request)
        _require_exact_type(
            trusted_store, TrustedReferenceStore, "trusted_store"
        )

        record = trusted_store._lookup_for_runtime(request.reference_id)
        if record is None:
            return ResolutionFailure(rule_id=RuleId.REFERENCE_NOT_FOUND)
        if record.kind != request.expected_kind:
            return ResolutionFailure(
                rule_id=RuleId.REFERENCE_KIND_MISMATCH
            )
        if record.invocation_id != request.invocation_id:
            return ResolutionFailure(
                rule_id=RuleId.REFERENCE_INVOCATION_MISMATCH
            )
        if record.parent_id != request.parent_id:
            return ResolutionFailure(
                rule_id=RuleId.REFERENCE_PARENT_MISMATCH
            )
        if record.active is not True:
            return ResolutionFailure(rule_id=RuleId.REFERENCE_INACTIVE)
        if record.consumed is not False:
            return ResolutionFailure(
                rule_id=RuleId.REFERENCE_ALREADY_CONSUMED
            )

        return _resolved_with_runtime_protected_value(
            protected_value=record.protected_value,
            kind=record.kind,
            invocation_id=record.invocation_id,
            parent_id=record.parent_id,
            active=record.active,
            consumed=record.consumed,
        )


def _validate_request_fields(request: ResolutionRequest) -> None:
    _require_exact_identifier(
        request.reference_id, ReferenceId, "reference_id"
    )
    _require_exact_non_empty_string(request.expected_kind, "expected_kind")
    _require_exact_identifier(
        request.invocation_id, InvocationId, "invocation_id"
    )
    _require_exact_identifier(request.parent_id, ParentId, "parent_id")
    _require_exact_non_empty_string(request.argument_name, "argument_name")
    _require_exact_utc_datetime(request.evaluation_time, "evaluation_time")


__all__ = (
    "ReferenceResolver",
    "ResolutionRequest",
)
