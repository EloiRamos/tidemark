"""Runtime-owned in-process storage for trusted protected references.

The store issues opaque identities, owns immutable record snapshots, exposes
only protected-value-free lookup metadata, and serializes lifecycle changes.
It does not resolve references, evaluate policy, prepare calls, execute tools,
persist data, or expose a model, UI, framework, or network surface.
"""

from copy import deepcopy
from dataclasses import dataclass, field, replace
from enum import Enum, unique
from secrets import token_hex
from threading import Lock
from typing import Dict, Optional, Tuple, Union, final

from tidemark.runtime.identifiers import InvocationId, ParentId, ReferenceId


_REFERENCE_ID_PREFIX = "ref_"
_ISSUER_CONSTRUCTION_AUTHORITY = object()


def _require_exact_non_empty_string(value: object, field_name: str) -> None:
    if type(value) is not str or value == "":
        raise ValueError(f"{field_name} requires an exact, non-empty string")


def _require_exact_type(
    value: object, expected_type: type, field_name: str
) -> None:
    if type(value) is not expected_type:
        raise TypeError(f"{field_name} requires {expected_type.__name__}")


def _copy_protected_value(value: object) -> object:
    try:
        return deepcopy(value)
    except Exception as error:
        raise TypeError("protected_value must support runtime copying") from error


@final
class TrustedRecord:
    """Runtime issuance input whose protected value has no public projection."""

    __slots__ = ("__kind", "__protected_value")

    def __init__(self, protected_value: object, kind: str) -> None:
        _require_exact_non_empty_string(kind, "kind")
        object.__setattr__(self, "_TrustedRecord__kind", kind)
        object.__setattr__(
            self,
            "_TrustedRecord__protected_value",
            _copy_protected_value(protected_value),
        )

    @property
    def kind(self) -> str:
        return self.__kind

    def _copy_protected_value(self) -> object:
        return _copy_protected_value(self.__protected_value)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("TrustedRecord is immutable")

    def __repr__(self) -> str:
        return (
            f"TrustedRecord(kind={self.__kind!r}, "
            "protected_value=<runtime-only>)"
        )


@final
@dataclass(frozen=True)
class ReferenceBinding:
    """Invocation and trusted-parent binding captured at issuance."""

    invocation_id: InvocationId
    parent_id: ParentId

    def __post_init__(self) -> None:
        _require_exact_type(self.invocation_id, InvocationId, "invocation_id")
        _require_exact_type(self.parent_id, ParentId, "parent_id")


@final
@dataclass(frozen=True)
class ReferenceLifecycle:
    """Initial lifecycle configuration; consumed always starts false."""

    active: bool
    single_use: bool

    def __post_init__(self) -> None:
        _require_exact_type(self.active, bool, "active")
        _require_exact_type(self.single_use, bool, "single_use")


@final
@dataclass(frozen=True)
class ReferenceMetadata:
    """Detached protected-value-free facts for a found reference."""

    reference_id: ReferenceId
    kind: str
    invocation_id: InvocationId
    parent_id: ParentId
    active: bool
    single_use: bool
    consumed: bool

    def __post_init__(self) -> None:
        _require_exact_type(self.reference_id, ReferenceId, "reference_id")
        _require_exact_non_empty_string(self.kind, "kind")
        _require_exact_type(self.invocation_id, InvocationId, "invocation_id")
        _require_exact_type(self.parent_id, ParentId, "parent_id")
        _require_exact_type(self.active, bool, "active")
        _require_exact_type(self.single_use, bool, "single_use")
        _require_exact_type(self.consumed, bool, "consumed")


@final
@dataclass(frozen=True)
class ReferenceNotFound:
    """Explicit store lookup result for an unknown opaque identity."""

    reference_id: ReferenceId

    def __post_init__(self) -> None:
        _require_exact_type(self.reference_id, ReferenceId, "reference_id")


ReferenceLookupResult = Union[ReferenceMetadata, ReferenceNotFound]


@unique
class ReferenceDeactivationOutcome(str, Enum):
    """Store-specific result of one deactivation attempt."""

    DEACTIVATED = "DEACTIVATED"
    ALREADY_INACTIVE = "ALREADY_INACTIVE"
    NOT_FOUND = "NOT_FOUND"


@unique
class ReferenceConsumptionOutcome(str, Enum):
    """Store-specific result of one single-use consumption attempt."""

    CONSUMED = "CONSUMED"
    ALREADY_CONSUMED = "ALREADY_CONSUMED"
    INACTIVE = "INACTIVE"
    NOT_SINGLE_USE = "NOT_SINGLE_USE"
    NOT_FOUND = "NOT_FOUND"


@dataclass(frozen=True)
class _StoredReferenceRecord:
    reference_id: ReferenceId
    protected_value: object = field(repr=False, compare=False)
    kind: str
    invocation_id: InvocationId
    parent_id: ParentId
    active: bool
    single_use: bool
    consumed: bool


@dataclass(frozen=True)
class _RuntimeReferenceRecord:
    """Private detached record for the future trusted resolver boundary."""

    reference_id: ReferenceId
    protected_value: object = field(repr=False, compare=False)
    kind: str
    invocation_id: InvocationId
    parent_id: ParentId
    active: bool
    single_use: bool
    consumed: bool


@dataclass(frozen=True)
class _ExecutionConsumptionPlan:
    """Private complete replacement prepared under the store lock."""

    records: Dict[ReferenceId, _StoredReferenceRecord] = field(
        repr=False, compare=False
    )


@final
class TrustedReferenceStore:
    """Own one isolated in-memory trusted-reference lifecycle."""

    __slots__ = ("_execution_authority", "_issuer", "_lock", "_records")

    def __init__(self) -> None:
        self._lock = Lock()
        self._records: Dict[ReferenceId, _StoredReferenceRecord] = {}
        self._execution_authority = object()
        self._issuer = ReferenceIssuer(
            self, _authority=_ISSUER_CONSTRUCTION_AUTHORITY
        )

    @property
    def issuer(self) -> "ReferenceIssuer":
        """Return the store-bound runtime issuance capability."""

        return self._issuer

    def lookup(self, reference_id: ReferenceId) -> ReferenceLookupResult:
        """Return detached inert metadata or an explicit not-found result."""

        _require_exact_type(reference_id, ReferenceId, "reference_id")
        with self._lock:
            record = self._records.get(reference_id)
            if record is None:
                return ReferenceNotFound(
                    reference_id=ReferenceId(reference_id.value)
                )
            return _metadata(record)

    def deactivate(
        self, reference_id: ReferenceId
    ) -> ReferenceDeactivationOutcome:
        """Atomically make an active record inactive."""

        _require_exact_type(reference_id, ReferenceId, "reference_id")
        with self._lock:
            record = self._records.get(reference_id)
            if record is None:
                return ReferenceDeactivationOutcome.NOT_FOUND
            if not record.active:
                return ReferenceDeactivationOutcome.ALREADY_INACTIVE
            self._records[reference_id] = replace(record, active=False)
            return ReferenceDeactivationOutcome.DEACTIVATED

    def consume(
        self, reference_id: ReferenceId
    ) -> ReferenceConsumptionOutcome:
        """Atomically consume an active single-use record at most once."""

        _require_exact_type(reference_id, ReferenceId, "reference_id")
        with self._lock:
            record = self._records.get(reference_id)
            if record is None:
                return ReferenceConsumptionOutcome.NOT_FOUND
            if record.consumed:
                return ReferenceConsumptionOutcome.ALREADY_CONSUMED
            if not record.active:
                return ReferenceConsumptionOutcome.INACTIVE
            if not record.single_use:
                return ReferenceConsumptionOutcome.NOT_SINGLE_USE
            self._records[reference_id] = replace(record, consumed=True)
            return ReferenceConsumptionOutcome.CONSUMED

    def _issue(
        self,
        trusted_record: TrustedRecord,
        binding: ReferenceBinding,
        lifecycle: ReferenceLifecycle,
    ) -> ReferenceId:
        protected_value = trusted_record._copy_protected_value()
        kind = trusted_record.kind
        invocation_id = InvocationId(binding.invocation_id.value)
        parent_id = ParentId(binding.parent_id.value)

        with self._lock:
            while True:
                reference_id = ReferenceId(
                    _REFERENCE_ID_PREFIX + token_hex(32)
                )
                if reference_id not in self._records:
                    break
            record = _StoredReferenceRecord(
                reference_id=reference_id,
                protected_value=protected_value,
                kind=kind,
                invocation_id=invocation_id,
                parent_id=parent_id,
                active=lifecycle.active,
                single_use=lifecycle.single_use,
                consumed=False,
            )
            self._records[reference_id] = record
            return ReferenceId(reference_id.value)

    def _lookup_for_runtime(
        self, reference_id: ReferenceId
    ) -> Optional[_RuntimeReferenceRecord]:
        """Return one private detached runtime record without consuming it."""

        _require_exact_type(reference_id, ReferenceId, "reference_id")
        with self._lock:
            record = self._records.get(reference_id)
            if record is None:
                return None
            return _RuntimeReferenceRecord(
                reference_id=ReferenceId(record.reference_id.value),
                protected_value=_copy_protected_value(
                    record.protected_value
                ),
                kind=record.kind,
                invocation_id=InvocationId(record.invocation_id.value),
                parent_id=ParentId(record.parent_id.value),
                active=record.active,
                single_use=record.single_use,
                consumed=record.consumed,
            )

    def _prepare_execution_consumption(
        self,
        reference_ids: Tuple[ReferenceId, ...],
        invocation_id: InvocationId,
        parent_id: ParentId,
    ) -> Tuple[str, Optional[_ExecutionConsumptionPlan]]:
        """Validate and prepare one all-target replacement under ``_lock``.

        The private execution coordinator must hold this store's lock for the
        complete prepare-and-commit sequence.  No authoritative record is
        changed until ``_commit_execution_consumption`` replaces the mapping.
        """

        if type(reference_ids) is not tuple:
            return "INVALID", None
        if any(type(item) is not ReferenceId for item in reference_ids):
            return "INVALID", None
        if len(reference_ids) != len(set(reference_ids)):
            return "INVALID", None
        if type(invocation_id) is not InvocationId:
            return "INVALID", None
        if type(parent_id) is not ParentId:
            return "INVALID", None

        selected = []
        for reference_id in reference_ids:
            record = self._records.get(reference_id)
            if record is None:
                return "INVALID", None
            selected.append(record)
        if any(record.consumed for record in selected):
            return "REPLAY", None
        if any(
            not record.active
            or not record.single_use
            or record.invocation_id != invocation_id
            or record.parent_id != parent_id
            for record in selected
        ):
            return "INVALID", None

        replacement = dict(self._records)
        for reference_id, record in zip(reference_ids, selected):
            if (
                record.reference_id != reference_id
            ):
                return "INVALID", None
            replacement[reference_id] = replace(record, consumed=True)
        return "READY", _ExecutionConsumptionPlan(records=replacement)

    def _commit_execution_consumption(
        self, plan: _ExecutionConsumptionPlan
    ) -> None:
        """Commit one previously complete plan while ``_lock`` is held."""

        if type(plan) is not _ExecutionConsumptionPlan:
            raise TypeError("execution consumption plan is invalid")
        self._records = plan.records

    def __repr__(self) -> str:
        with self._lock:
            record_count = len(self._records)
        return f"TrustedReferenceStore(record_count={record_count})"


@final
class ReferenceIssuer:
    """Store-bound capability for internal runtime reference issuance."""

    __slots__ = ("_store",)

    def __init__(
        self,
        store: TrustedReferenceStore,
        _authority: object = None,
    ) -> None:
        if (
            _authority is not _ISSUER_CONSTRUCTION_AUTHORITY
            or type(store) is not TrustedReferenceStore
        ):
            raise TypeError(
                "ReferenceIssuer is created only by TrustedReferenceStore"
            )
        self._store = store

    def issue(
        self,
        trusted_record: TrustedRecord,
        binding: ReferenceBinding,
        lifecycle: ReferenceLifecycle,
    ) -> ReferenceId:
        """Issue and store one freshly isolated trusted reference record."""

        _require_exact_type(trusted_record, TrustedRecord, "trusted_record")
        _require_exact_type(binding, ReferenceBinding, "binding")
        _require_exact_type(lifecycle, ReferenceLifecycle, "lifecycle")
        return self._store._issue(trusted_record, binding, lifecycle)

    def __repr__(self) -> str:
        return "ReferenceIssuer(runtime_owned=True)"


def _metadata(record: _StoredReferenceRecord) -> ReferenceMetadata:
    return ReferenceMetadata(
        reference_id=ReferenceId(record.reference_id.value),
        kind=record.kind,
        invocation_id=InvocationId(record.invocation_id.value),
        parent_id=ParentId(record.parent_id.value),
        active=record.active,
        single_use=record.single_use,
        consumed=record.consumed,
    )


__all__ = (
    "ReferenceBinding",
    "ReferenceConsumptionOutcome",
    "ReferenceDeactivationOutcome",
    "ReferenceIssuer",
    "ReferenceLifecycle",
    "ReferenceLookupResult",
    "ReferenceMetadata",
    "ReferenceNotFound",
    "TrustedRecord",
    "TrustedReferenceStore",
)
