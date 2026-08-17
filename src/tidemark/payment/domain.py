"""Bounded synthetic accounts-payable state and trusted payment adapter.

Payment-specific behavior remains outside the reusable policy core.  The
adapter accepts only the detached ``AdapterInvocation`` produced by the
execution gate and writes one masked, synthetic authoritative record.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from threading import Lock
from typing import Dict, Tuple, final

from tidemark.evidence.recorder import EvidenceRecorder
from tidemark.runtime.execution_gate import (
    AdapterArgument,
    AdapterInvocation,
    AdapterInvocationResult,
)
from tidemark.runtime.identifiers import (
    ExecutionId,
    ParentId,
    PreparedCallId,
    ToolId,
    TypeId,
)
from tidemark.runtime.policy_authoring import (
    AUTHORING_INTEGER_MAXIMUM,
    AUTHORING_INTEGER_MINIMUM,
)
from tidemark.runtime.vocabulary import ArgumentRole


PAYMENT_RECORDED_STATUS = "RECORDED"
_SCHEDULE_PAYMENT_TOOL_VALUE = "schedule_payment"
_AMOUNT_ARGUMENT_NAME = "amount_minor"
_CURRENCY_ARGUMENT_NAME = "currency"
_DESTINATION_ARGUMENT_NAME = "destination_reference"
_INTEGER_TYPE = TypeId("integer")
_CURRENCY_TYPE = TypeId("currency_code")
_DESTINATION_TYPE = TypeId("destination_reference")
_IDEMPOTENCY_DOMAIN = "tidemark.synthetic-payment.idempotency.v1:"
_PAYMENT_STORE_WRITE_AUTHORITY = object()


def _require_exact_non_empty_string(value: object, field_name: str) -> None:
    if type(value) is not str or value == "":
        raise ValueError(f"{field_name} requires an exact non-empty string")


@final
@dataclass(frozen=True)
class PurchaseOrderRecord:
    """Smallest trusted parent state needed by the payment demonstration."""

    parent_id: ParentId
    maximum_amount_minor: int
    allowed_currencies: Tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.parent_id) is not ParentId:
            raise TypeError("parent_id requires ParentId")
        if type(self.maximum_amount_minor) is not int:
            raise TypeError("maximum_amount_minor requires exact int")
        if not (
            AUTHORING_INTEGER_MINIMUM
            <= self.maximum_amount_minor
            <= AUTHORING_INTEGER_MAXIMUM
        ):
            raise ValueError("maximum_amount_minor is outside the v1 bound")
        if self.maximum_amount_minor < 0:
            raise ValueError("maximum_amount_minor cannot be negative")
        if type(self.allowed_currencies) is not tuple or not self.allowed_currencies:
            raise ValueError("allowed_currencies requires a non-empty tuple")
        if any(
            type(currency) is not str or currency == ""
            for currency in self.allowed_currencies
        ):
            raise ValueError("allowed_currencies contains an invalid value")
        if len(self.allowed_currencies) != len(set(self.allowed_currencies)):
            raise ValueError("allowed_currencies must be duplicate-free")


@final
@dataclass(frozen=True)
class SyntheticPaymentRecord:
    """Masked authoritative synthetic side effect for the reference workflow."""

    payment_record_id: str
    execution_id: ExecutionId
    prepared_call_id: PreparedCallId
    idempotency_key_fingerprint: str
    amount_minor: int
    currency: str
    parent_id: ParentId
    destination_kind: str
    masked_destination_display: str
    status: str
    store_version: int
    created_at: datetime

    def __post_init__(self) -> None:
        _require_exact_non_empty_string(
            self.payment_record_id, "payment_record_id"
        )
        if type(self.execution_id) is not ExecutionId:
            raise TypeError("execution_id requires ExecutionId")
        if type(self.prepared_call_id) is not PreparedCallId:
            raise TypeError("prepared_call_id requires PreparedCallId")
        if (
            type(self.idempotency_key_fingerprint) is not str
            or not self.idempotency_key_fingerprint.startswith("sha256:")
            or len(self.idempotency_key_fingerprint) != 71
        ):
            raise ValueError("idempotency_key_fingerprint is invalid")
        if type(self.amount_minor) is not int:
            raise TypeError("amount_minor requires exact int")
        _require_exact_non_empty_string(self.currency, "currency")
        if type(self.parent_id) is not ParentId:
            raise TypeError("parent_id requires ParentId")
        _require_exact_non_empty_string(self.destination_kind, "destination_kind")
        _require_exact_non_empty_string(
            self.masked_destination_display, "masked_destination_display"
        )
        if self.status != PAYMENT_RECORDED_STATUS:
            raise ValueError("status is not the bounded recorded value")
        if type(self.store_version) is not int or self.store_version < 1:
            raise ValueError("store_version requires a positive exact int")
        if type(self.created_at) is not datetime or self.created_at.tzinfo is not timezone.utc:
            raise ValueError("created_at requires an exact UTC datetime")


@final
class SyntheticPaymentStore:
    """In-memory authoritative store with one private append-only write path."""

    __slots__ = ("_by_idempotency", "_lock", "_records")

    def __init__(self) -> None:
        self._lock = Lock()
        self._records: Tuple[SyntheticPaymentRecord, ...] = ()
        self._by_idempotency: Dict[str, SyntheticPaymentRecord] = {}

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._records)

    def records(self) -> Tuple[SyntheticPaymentRecord, ...]:
        """Return the immutable authoritative record sequence."""

        with self._lock:
            return tuple(self._records)

    def _record(
        self,
        *,
        execution_id: ExecutionId,
        prepared_call_id: PreparedCallId,
        idempotency_key_fingerprint: str,
        amount_minor: int,
        currency: str,
        parent_id: ParentId,
        destination_kind: str,
        masked_destination_display: str,
        created_at: datetime,
        _authority: object,
    ) -> SyntheticPaymentRecord:
        if _authority is not _PAYMENT_STORE_WRITE_AUTHORITY:
            raise TypeError("payment records are adapter-created only")
        with self._lock:
            existing = self._by_idempotency.get(idempotency_key_fingerprint)
            if existing is not None:
                return existing
            version = len(self._records) + 1
            record = SyntheticPaymentRecord(
                payment_record_id=f"synthetic-payment-{version:06d}",
                execution_id=ExecutionId(execution_id.value),
                prepared_call_id=PreparedCallId(prepared_call_id.value),
                idempotency_key_fingerprint=idempotency_key_fingerprint,
                amount_minor=amount_minor,
                currency=currency,
                parent_id=ParentId(parent_id.value),
                destination_kind=destination_kind,
                masked_destination_display=masked_destination_display,
                status=PAYMENT_RECORDED_STATUS,
                store_version=version,
                created_at=created_at,
            )
            self._records = self._records + (record,)
            self._by_idempotency[idempotency_key_fingerprint] = record
            return record

    def __repr__(self) -> str:
        return f"SyntheticPaymentStore(record_count={self.count})"


@final
class SyntheticSchedulePaymentAdapter:
    """Trusted adapter for the single bounded ``schedule_payment`` tool."""

    __slots__ = (
        "_destination_kind",
        "_entry_count",
        "_fail_before_record",
        "_evidence_recorder",
        "_lock",
        "_masked_destination_display",
        "_payment_store",
        "_purchase_order",
    )

    def __init__(
        self,
        *,
        payment_store: SyntheticPaymentStore,
        purchase_order: PurchaseOrderRecord,
        destination_kind: str,
        masked_destination_display: str,
        fail_before_record: bool = False,
        evidence_recorder: object = None,
    ) -> None:
        if type(payment_store) is not SyntheticPaymentStore:
            raise TypeError("payment_store requires SyntheticPaymentStore")
        if type(purchase_order) is not PurchaseOrderRecord:
            raise TypeError("purchase_order requires PurchaseOrderRecord")
        _require_exact_non_empty_string(destination_kind, "destination_kind")
        _require_exact_non_empty_string(
            masked_destination_display, "masked_destination_display"
        )
        if type(fail_before_record) is not bool:
            raise TypeError("fail_before_record requires bool")
        if evidence_recorder is not None and type(
            evidence_recorder
        ) is not EvidenceRecorder:
            raise TypeError("evidence_recorder requires EvidenceRecorder")
        self._payment_store = payment_store
        self._purchase_order = purchase_order
        self._destination_kind = destination_kind
        self._masked_destination_display = masked_destination_display
        self._fail_before_record = fail_before_record
        self._evidence_recorder = evidence_recorder
        self._entry_count = 0
        self._lock = Lock()

    @property
    def entry_count(self) -> int:
        with self._lock:
            return self._entry_count

    def __call__(self, invocation: AdapterInvocation) -> AdapterInvocationResult:
        with self._lock:
            self._entry_count += 1
        if type(invocation) is not AdapterInvocation:
            return AdapterInvocationResult.confirmed_failure()
        parsed = _payment_arguments(invocation)
        if parsed is None:
            return AdapterInvocationResult.confirmed_failure()
        amount_minor, currency, protected_destination = parsed
        if self._fail_before_record:
            return AdapterInvocationResult.confirmed_failure()
        if protected_destination in self._masked_destination_display:
            return AdapterInvocationResult.confirmed_failure()

        fingerprint = _idempotency_fingerprint(invocation.prepared_call_id)
        try:
            record = self._payment_store._record(
                execution_id=invocation.execution_id,
                prepared_call_id=invocation.prepared_call_id,
                idempotency_key_fingerprint=fingerprint,
                amount_minor=amount_minor,
                currency=currency,
                parent_id=self._purchase_order.parent_id,
                destination_kind=self._destination_kind,
                masked_destination_display=self._masked_destination_display,
                created_at=datetime.now(timezone.utc),
                _authority=_PAYMENT_STORE_WRITE_AUTHORITY,
            )
        except (TypeError, ValueError, RuntimeError):
            return AdapterInvocationResult.confirmed_failure()
        if self._evidence_recorder is not None:
            try:
                self._evidence_recorder.stage_payment(record, invocation)
            except (TypeError, ValueError, RuntimeError):
                return AdapterInvocationResult.unconfirmed_failure()
        return AdapterInvocationResult.confirmed_success()

    def __repr__(self) -> str:
        return (
            "SyntheticSchedulePaymentAdapter("
            f"entry_count={self.entry_count}, automatic_retry=False)"
        )


def _payment_arguments(
    invocation: AdapterInvocation,
) -> object:
    if invocation.tool_id != ToolId(_SCHEDULE_PAYMENT_TOOL_VALUE):
        return None
    if type(invocation.arguments) is not tuple or len(invocation.arguments) != 3:
        return None
    amount, currency, destination = invocation.arguments
    expected = (
        (
            amount,
            _AMOUNT_ARGUMENT_NAME,
            _INTEGER_TYPE,
            ArgumentRole.UNPROTECTED_INPUT,
            int,
        ),
        (
            currency,
            _CURRENCY_ARGUMENT_NAME,
            _CURRENCY_TYPE,
            ArgumentRole.UNPROTECTED_INPUT,
            str,
        ),
        (
            destination,
            _DESTINATION_ARGUMENT_NAME,
            _DESTINATION_TYPE,
            ArgumentRole.PROTECTED_REFERENCE,
            str,
        ),
    )
    for argument, name, type_id, role, value_type in expected:
        if (
            type(argument) is not AdapterArgument
            or argument.name != name
            or argument.type_id != type_id
            or argument.role is not role
            or type(argument.value) is not value_type
        ):
            return None
    if currency.value == "" or destination.value == "":
        return None
    return amount.value, currency.value, destination.value


def _idempotency_fingerprint(prepared_call_id: PreparedCallId) -> str:
    encoded = (_IDEMPOTENCY_DOMAIN + prepared_call_id.value).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


__all__ = (
    "PAYMENT_RECORDED_STATUS",
    "PurchaseOrderRecord",
    "SyntheticPaymentRecord",
    "SyntheticPaymentStore",
    "SyntheticSchedulePaymentAdapter",
)
