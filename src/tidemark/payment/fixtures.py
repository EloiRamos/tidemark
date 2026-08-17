"""Deterministic product-native fixtures for the Order 9 payment slice."""

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Optional, final

from tidemark.evidence.local_store import LocalAuditStore
from tidemark.evidence.model import EvidenceProducer
from tidemark.evidence.recorder import EvidenceRecorder
from tidemark.payment.domain import (
    PurchaseOrderRecord,
    SyntheticPaymentStore,
    SyntheticSchedulePaymentAdapter,
)
from tidemark.runtime.execution_gate import ExecutionGate, TrustedAdapterRegistry
from tidemark.runtime.identifiers import (
    CallId,
    DecisionId,
    InvocationId,
    ParentId,
    PolicyVersion,
    ReferenceId,
    RegistryVersion,
    ToolContractVersion,
    ToolId,
    TypeId,
)
from tidemark.runtime.policy_authoring import (
    ValidatedPolicyAuthoring,
    validate_policy_authoring,
)
from tidemark.runtime.policy_engine import (
    CallContext,
    CanonicalArgument,
    CanonicalCall,
    CanonicalSignatureArgument,
    Decision,
    PolicyEngine,
    ResolutionEntry,
    ResolutionSet,
)
from tidemark.runtime.policy_snapshot import (
    InstalledSnapshot,
    PolicyInstaller,
    PolicySnapshot,
)
from tidemark.runtime.prepared_call import PreparationResult, PreparedCallPipeline
from tidemark.runtime.reference_resolver import ReferenceResolver, ResolutionRequest
from tidemark.runtime.reference_store import (
    ReferenceBinding,
    ReferenceLifecycle,
    ReferenceMetadata,
    TrustedRecord,
    TrustedReferenceStore,
)


SCHEDULE_PAYMENT_TOOL_ID = ToolId("schedule_payment")
SCHEDULE_PAYMENT_CONTRACT_VERSION = ToolContractVersion(
    "schedule_payment.contract.v1"
)
SCHEDULE_PAYMENT_POLICY_VERSION = PolicyVersion(
    "schedule_payment.policy.order-9.v1"
)
SCHEDULE_PAYMENT_REGISTRY_VERSION = RegistryVersion(
    "schedule_payment.registry.order-9.v1"
)
SYNTHETIC_DESTINATION_KIND = "synthetic_payment_destination"
DESTINATION_ARGUMENT_NAME = "destination_reference"
RAW_SYNTHETIC_DESTINATION = "synthetic-routing://beneficiary/order-9/4242"
MASKED_SYNTHETIC_DESTINATION = "synthetic-beneficiary-****4242"
DEFAULT_INVOCATION_ID = InvocationId("invocation-order-9-payment")
DEFAULT_EVALUATION_TIME = datetime(
    2026, 8, 7, 18, 0, tzinfo=timezone.utc
)

_DEFAULT_AMOUNT = object()
_DEFAULT_CURRENCY = object()
_DEFAULT_REFERENCE = object()
_CORRELATION_NAMESPACE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?")


def default_purchase_order() -> PurchaseOrderRecord:
    return PurchaseOrderRecord(
        parent_id=ParentId("purchase-order-order-9-001"),
        maximum_amount_minor=25_000,
        allowed_currencies=("EUR",),
    )


@final
@dataclass(frozen=True)
class SyntheticPaymentFixture:
    """Assembled local runtime for one bounded synthetic payment scenario."""

    purchase_order: PurchaseOrderRecord
    invocation_id: InvocationId
    snapshot: PolicySnapshot
    call_context: CallContext
    reference_store: TrustedReferenceStore
    destination_reference: ReferenceId
    payment_store: SyntheticPaymentStore
    adapter: SyntheticSchedulePaymentAdapter
    evidence_store: LocalAuditStore
    evidence_recorder: EvidenceRecorder
    evidence_sink: EvidenceRecorder
    execution_gate: ExecutionGate

    def canonical_call(
        self,
        *,
        amount_minor: object = _DEFAULT_AMOUNT,
        currency: object = _DEFAULT_CURRENCY,
        destination_reference: object = _DEFAULT_REFERENCE,
    ) -> CanonicalCall:
        actual_amount = (
            self.purchase_order.maximum_amount_minor
            if amount_minor is _DEFAULT_AMOUNT
            else amount_minor
        )
        actual_currency = (
            self.purchase_order.allowed_currencies[0]
            if currency is _DEFAULT_CURRENCY
            else currency
        )
        actual_reference = (
            self.destination_reference
            if destination_reference is _DEFAULT_REFERENCE
            else destination_reference
        )
        signature = tuple(
            CanonicalSignatureArgument(
                name=item.name,
                required=item.required,
                type_id=TypeId(item.type_id.value),
            )
            for item in self.snapshot.tool_policies[0].signature
        )
        return CanonicalCall(
            tool_id=ToolId(SCHEDULE_PAYMENT_TOOL_ID.value),
            contract_version=ToolContractVersion(
                SCHEDULE_PAYMENT_CONTRACT_VERSION.value
            ),
            signature=signature,
            arguments=(
                CanonicalArgument("amount_minor", actual_amount),
                CanonicalArgument("currency", actual_currency),
                CanonicalArgument(
                    DESTINATION_ARGUMENT_NAME, actual_reference
                ),
            ),
        )

    def evaluate(self, canonical_call: CanonicalCall) -> Decision:
        supplied = {
            argument.name: argument.value for argument in canonical_call.arguments
        }
        selected = supplied.get(DESTINATION_ARGUMENT_NAME)
        entries = ()
        if type(selected) is ReferenceId:
            result = ReferenceResolver().resolve(
                ResolutionRequest(
                    reference_id=ReferenceId(selected.value),
                    expected_kind=SYNTHETIC_DESTINATION_KIND,
                    invocation_id=InvocationId(self.invocation_id.value),
                    parent_id=ParentId(self.purchase_order.parent_id.value),
                    argument_name=DESTINATION_ARGUMENT_NAME,
                    evaluation_time=DEFAULT_EVALUATION_TIME,
                ),
                self.reference_store,
            )
            entries = (
                ResolutionEntry(
                    argument_name=DESTINATION_ARGUMENT_NAME,
                    result=result,
                ),
            )
        return PolicyEngine().evaluate(
            self.snapshot,
            canonical_call,
            ResolutionSet(entries=entries),
            self.call_context,
        )

    def prepare(self, canonical_call: CanonicalCall) -> PreparationResult:
        return PreparedCallPipeline(self.evidence_recorder).prepare(
            snapshot=self.snapshot,
            canonical_call=canonical_call,
            call_context=self.call_context,
            trusted_store=self.reference_store,
            evaluation_time=DEFAULT_EVALUATION_TIME,
        )

    def reference_metadata(self) -> ReferenceMetadata:
        metadata = self.reference_store.lookup(self.destination_reference)
        if type(metadata) is not ReferenceMetadata:
            raise RuntimeError("fixture destination reference is unavailable")
        return metadata


def build_synthetic_payment_fixture(
    evidence_root: str,
    *,
    purchase_order: Optional[PurchaseOrderRecord] = None,
    reference_invocation_id: Optional[InvocationId] = None,
    reference_parent_id: Optional[ParentId] = None,
    reference_active: bool = True,
    adapter_fail_before_record: bool = False,
    correlation_namespace: Optional[str] = None,
) -> SyntheticPaymentFixture:
    """Build fresh local state without model, network, cloud, or UI behavior."""

    active_purchase_order = purchase_order or default_purchase_order()
    if type(active_purchase_order) is not PurchaseOrderRecord:
        raise TypeError("purchase_order requires PurchaseOrderRecord")
    if type(reference_active) is not bool:
        raise TypeError("reference_active requires bool")
    if correlation_namespace is not None and (
        type(correlation_namespace) is not str
        or _CORRELATION_NAMESPACE.fullmatch(correlation_namespace) is None
    ):
        raise ValueError("correlation_namespace requires a bounded safe identifier")
    validated = validate_policy_authoring(
        _payment_policy_authoring(active_purchase_order)
    )
    if type(validated) is not ValidatedPolicyAuthoring:
        raise RuntimeError("synthetic payment policy fixture did not validate")
    installed = PolicyInstaller().install(validated)
    if type(installed) is not InstalledSnapshot:
        raise RuntimeError("synthetic payment policy fixture did not install")
    snapshot = installed.snapshot
    invocation_id = InvocationId(
        DEFAULT_INVOCATION_ID.value
        if correlation_namespace is None
        else f"invocation-{correlation_namespace}"
    )
    reference_store = TrustedReferenceStore()
    destination_reference = reference_store.issuer.issue(
        TrustedRecord(
            protected_value=RAW_SYNTHETIC_DESTINATION,
            kind=SYNTHETIC_DESTINATION_KIND,
        ),
        ReferenceBinding(
            invocation_id=(
                InvocationId(reference_invocation_id.value)
                if type(reference_invocation_id) is InvocationId
                else invocation_id
            ),
            parent_id=(
                ParentId(reference_parent_id.value)
                if type(reference_parent_id) is ParentId
                else ParentId(active_purchase_order.parent_id.value)
            ),
        ),
        ReferenceLifecycle(active=reference_active, single_use=True),
    )
    context = CallContext(
        call_id=CallId(
            "call-order-9-payment"
            if correlation_namespace is None
            else f"call-{correlation_namespace}"
        ),
        decision_id=DecisionId(
            "decision-order-9-payment"
            if correlation_namespace is None
            else f"decision-{correlation_namespace}"
        ),
        invocation_id=invocation_id,
        parent_id=ParentId(active_purchase_order.parent_id.value),
        policy_version=PolicyVersion(snapshot.policy_version.value),
        registry_version=RegistryVersion(snapshot.registry_version.value),
    )
    payment_store = SyntheticPaymentStore()
    evidence_store = LocalAuditStore(evidence_root)
    evidence_recorder = EvidenceRecorder(
        store=evidence_store,
        trace_id=(
            "trace-order-13-payment"
            if correlation_namespace is None
            else f"trace-{correlation_namespace}"
        ),
        producer=EvidenceProducer(
            "tidemark.runtime",
            "tidemark.order-13.v1",
        ),
        transaction_root_path=evidence_root,
    )
    adapter = SyntheticSchedulePaymentAdapter(
        payment_store=payment_store,
        purchase_order=active_purchase_order,
        destination_kind=SYNTHETIC_DESTINATION_KIND,
        masked_destination_display=MASKED_SYNTHETIC_DESTINATION,
        fail_before_record=adapter_fail_before_record,
        evidence_recorder=evidence_recorder,
    )
    adapter_registry = TrustedAdapterRegistry(
        tool_id=ToolId(SCHEDULE_PAYMENT_TOOL_ID.value),
        adapter_id=snapshot.tool_policies[0].adapter_id,
        adapter_version=snapshot.tool_policies[0].adapter_version,
        adapter=adapter,
    )
    execution_gate = ExecutionGate(
        adapter_registry=adapter_registry,
        evidence_sink=evidence_recorder,
    )
    return SyntheticPaymentFixture(
        purchase_order=active_purchase_order,
        invocation_id=invocation_id,
        snapshot=snapshot,
        call_context=context,
        reference_store=reference_store,
        destination_reference=destination_reference,
        payment_store=payment_store,
        adapter=adapter,
        evidence_store=evidence_store,
        evidence_recorder=evidence_recorder,
        evidence_sink=evidence_recorder,
        execution_gate=execution_gate,
    )


def _payment_policy_authoring(purchase_order: PurchaseOrderRecord) -> dict:
    policy_version = SCHEDULE_PAYMENT_POLICY_VERSION.value
    return {
        "policy_version": policy_version,
        "registry_version": SCHEDULE_PAYMENT_REGISTRY_VERSION.value,
        "executable_tools": (SCHEDULE_PAYMENT_TOOL_ID.value,),
        "tool_registrations": (
            {
                "tool_id": SCHEDULE_PAYMENT_TOOL_ID.value,
                "contract_version": SCHEDULE_PAYMENT_CONTRACT_VERSION.value,
                "policy_version": policy_version,
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
                        "name": DESTINATION_ARGUMENT_NAME,
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
                                "parameters": {
                                    "maximum": purchase_order.maximum_amount_minor
                                },
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
                                "parameters": {
                                    "members": purchase_order.allowed_currencies
                                },
                            },
                        ),
                    },
                    {
                        "name": DESTINATION_ARGUMENT_NAME,
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
                                "parameters": {
                                    "kind": SYNTHETIC_DESTINATION_KIND
                                },
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
                        "name": DESTINATION_ARGUMENT_NAME,
                        "role": "PROTECTED_REFERENCE",
                        "required_provenance": "RUNTIME_TRUSTED",
                    },
                ),
                "effect_class": "SIDE_EFFECTING",
                "reversibility": "IRREVERSIBLE",
                "adapter_id": "schedule_payment.synthetic.adapter",
                "adapter_version": "schedule_payment.synthetic.adapter.v1",
                "masking_profile_id": "schedule_payment.masking.v1",
            },
        ),
    }


__all__ = (
    "DEFAULT_EVALUATION_TIME",
    "DEFAULT_INVOCATION_ID",
    "DESTINATION_ARGUMENT_NAME",
    "MASKED_SYNTHETIC_DESTINATION",
    "RAW_SYNTHETIC_DESTINATION",
    "SCHEDULE_PAYMENT_CONTRACT_VERSION",
    "SCHEDULE_PAYMENT_POLICY_VERSION",
    "SCHEDULE_PAYMENT_REGISTRY_VERSION",
    "SCHEDULE_PAYMENT_TOOL_ID",
    "SYNTHETIC_DESTINATION_KIND",
    "SyntheticPaymentFixture",
    "build_synthetic_payment_fixture",
    "default_purchase_order",
)
