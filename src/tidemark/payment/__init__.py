"""Synthetic payment vertical slice built on the TIDEMARK runtime."""

from tidemark.payment.domain import (
    PAYMENT_RECORDED_STATUS,
    PurchaseOrderRecord,
    SyntheticPaymentRecord,
    SyntheticPaymentStore,
    SyntheticSchedulePaymentAdapter,
)
from tidemark.payment.fixtures import (
    DESTINATION_ARGUMENT_NAME,
    MASKED_SYNTHETIC_DESTINATION,
    RAW_SYNTHETIC_DESTINATION,
    SCHEDULE_PAYMENT_TOOL_ID,
    SYNTHETIC_DESTINATION_KIND,
    SyntheticPaymentFixture,
    build_synthetic_payment_fixture,
    default_purchase_order,
)

__all__ = (
    "DESTINATION_ARGUMENT_NAME",
    "MASKED_SYNTHETIC_DESTINATION",
    "PAYMENT_RECORDED_STATUS",
    "PurchaseOrderRecord",
    "RAW_SYNTHETIC_DESTINATION",
    "SCHEDULE_PAYMENT_TOOL_ID",
    "SYNTHETIC_DESTINATION_KIND",
    "SyntheticPaymentFixture",
    "SyntheticPaymentRecord",
    "SyntheticPaymentStore",
    "SyntheticSchedulePaymentAdapter",
    "build_synthetic_payment_fixture",
    "default_purchase_order",
)
