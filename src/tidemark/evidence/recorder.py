"""Producer-owned construction of immutable events for one local trace."""

from datetime import datetime, timezone
from hashlib import sha256
from secrets import token_hex
from threading import Lock
from typing import Dict, Optional, Tuple, final

from tidemark.evidence.local_store import AppendReceipt, LocalAuditStore
from tidemark.evidence.model import (
    EVIDENCE_SCHEMA_VERSION,
    ArgumentProjection,
    ArgumentShape,
    AuditEvent,
    CallbackPayload,
    CallIntakeRecordedPayload,
    CallPreparationRefusedPayload,
    DecisionRecordedPayload,
    DecisionRuleResult,
    EvidenceEventType,
    EvidenceProducer,
    ExecutionRefusedPayload,
    ExecutionReplayRejectedPayload,
    ExecutionStartedPayload,
    ExecutionTerminalPayload,
    MaskedReasonFact,
    ModelNonAttemptPayload,
    PaymentRecordedPayload,
    PolicyInstallationRefusedPayload,
)
from tidemark.runtime.identifiers import (
    AdapterId,
    AdapterVersion,
    CallId,
    DecisionId,
    ExecutionId,
    InvocationId,
    PolicyVersion,
    PreparedCallId,
    ReferenceId,
    RegistryVersion,
    ToolId,
    TypeId,
)
from tidemark.runtime.minimal_evidence import (
    DurableAppendReceipt,
    EvidenceAppendResult,
    ExecutionOutcomeRecord,
    MinimalPreExecutionEvidenceSink,
    PreExecutionCorrelationRecord,
)
from tidemark.runtime.vocabulary import (
    ArgumentRole,
    DecisionOutcome,
    ExecutionOutcome,
    ProvenanceClass,
    RuleId,
)


EVIDENCE_RECORDER_PRODUCER_VERSION = "tidemark.evidence.recorder.v1"
_CALLBACK_ADAPTER_ID = AdapterId("tidemark.google-adk.callback")
_IDEMPOTENCY_DOMAIN = "tidemark.synthetic-payment.idempotency.v1:"


@final
class EvidenceRecorder:
    """Append facts supplied by the definitive component that owns them."""

    __slots__ = (
        "_lock",
        "_execution_contexts",
        "_pending_payments",
        "_producer",
        "_store",
        "_trace_id",
        "_transaction_sink",
    )

    def __init__(
        self,
        *,
        store: LocalAuditStore,
        trace_id: str,
        producer: EvidenceProducer,
        transaction_root_path: str,
    ) -> None:
        if type(store) is not LocalAuditStore:
            raise TypeError("store requires LocalAuditStore")
        if type(trace_id) is not str or trace_id == "":
            raise ValueError("trace_id requires an exact non-empty string")
        if type(producer) is not EvidenceProducer:
            raise TypeError("producer requires EvidenceProducer")
        if type(transaction_root_path) is not str or transaction_root_path == "":
            raise ValueError("transaction_root_path requires a path string")
        self._store = store
        self._trace_id = trace_id
        self._producer = producer
        self._transaction_sink = MinimalPreExecutionEvidenceSink(
            transaction_root_path
        )
        self._pending_payments: Dict[str, Tuple[object, object]] = {}
        self._execution_contexts: Dict[
            str,
            Tuple[PolicyVersion, RegistryVersion, AdapterId, AdapterVersion],
        ] = {}
        self._lock = Lock()

    def record_policy_installation_refusal(self, refusal: object) -> AppendReceipt:
        from tidemark.runtime.policy_snapshot import InstallationRefusal

        if type(refusal) is not InstallationRefusal:
            raise TypeError("refusal requires InstallationRefusal")
        return self._append(
            EvidenceEventType.POLICY_INSTALLATION_REFUSED,
            PolicyInstallationRefusedPayload(
                refusal_code=refusal.code.value,
                stage="POLICY_INSTALLATION",
                location=".".join(str(part) for part in refusal.location),
                masked_detail=refusal.masked_detail,
            ),
        )

    def record_call_intake(self, canonical_call: object, call_context: object) -> AppendReceipt:
        from tidemark.runtime.policy_engine import CallContext, CanonicalCall

        if type(canonical_call) is not CanonicalCall:
            raise TypeError("canonical_call requires CanonicalCall")
        if type(call_context) is not CallContext:
            raise TypeError("call_context requires CallContext")
        shapes = tuple(
            ArgumentShape(argument.name, type(argument.value).__name__)
            for argument in canonical_call.arguments
        )
        return self._append(
            EvidenceEventType.CALL_INTAKE_RECORDED,
            CallIntakeRecordedPayload(
                tool_id=ToolId(canonical_call.tool_id.value),
                contract_version=canonical_call.contract_version,
                argument_shapes=shapes,
            ),
            invocation_id=call_context.invocation_id,
            call_id=call_context.call_id,
            policy_version=call_context.policy_version,
            registry_version=call_context.registry_version,
        )

    def record_call_preparation_refusal(
        self,
        *,
        decision: object,
        canonical_call: object,
        masked_detail: str,
    ) -> AppendReceipt:
        from tidemark.runtime.policy_engine import CanonicalCall, Decision

        if type(decision) is not Decision or type(canonical_call) is not CanonicalCall:
            raise TypeError("preparation refusal requires exact runtime values")
        if decision.outcome not in (
            DecisionOutcome.REFUSAL,
            DecisionOutcome.ALLOW,
        ):
            raise ValueError("preparation refusal evidence requires construction refusal")
        location = next(
            (
                result.argument_name
                for result in decision.rule_results
                if result.outcome.value == "FAIL" and result.argument_name is not None
            ),
            "call",
        )
        return self._append(
            EvidenceEventType.CALL_PREPARATION_REFUSED,
            CallPreparationRefusedPayload(
                refusal_code=(
                    decision.primary_rule_id.value
                    if decision.outcome is DecisionOutcome.REFUSAL
                    else "prepared-call-construction-refused"
                ),
                stage=decision.evaluation_stage.value,
                location=location,
                masked_detail=masked_detail,
            ),
            invocation_id=decision.invocation_id,
            call_id=decision.call_id,
            policy_version=decision.policy_version,
            registry_version=decision.registry_version,
        )

    def record_decision(
        self,
        *,
        decision: object,
        canonical_call: object,
        call_context: object,
        snapshot: object,
        resolution_set: object,
        prepared_call: Optional[object],
    ) -> AppendReceipt:
        from tidemark.runtime.policy_engine import (
            CanonicalCall,
            CallContext,
            Decision,
            ResolutionFailure,
            ResolutionSet,
            Resolved,
        )
        from tidemark.runtime.policy_snapshot import PolicySnapshot
        from tidemark.runtime.prepared_call import PreparedToolCall

        if type(decision) is not Decision or decision.outcome not in (
            DecisionOutcome.DENY,
            DecisionOutcome.ALLOW,
        ):
            raise ValueError("decision evidence requires sealed DENY or ALLOW")
        if type(canonical_call) is not CanonicalCall:
            raise TypeError("canonical_call requires CanonicalCall")
        if type(call_context) is not CallContext:
            raise TypeError("call_context requires CallContext")
        if type(snapshot) is not PolicySnapshot:
            raise TypeError("snapshot requires PolicySnapshot")
        if type(resolution_set) is not ResolutionSet:
            raise TypeError("resolution_set requires ResolutionSet")
        if prepared_call is not None and type(prepared_call) is not PreparedToolCall:
            raise TypeError("prepared_call requires PreparedToolCall or None")
        tool_policy = next(
            item for item in snapshot.tool_policies if item.tool_id == decision.tool_id
        )
        resolution_by_name = {
            item.argument_name: item.result for item in resolution_set.entries
        }
        canonical_by_name = {
            item.name: item.value for item in canonical_call.arguments
        }
        role_metadata = {item.name: item for item in tool_policy.role_metadata}
        projections = []
        for argument in tool_policy.arguments:
            resolution = resolution_by_name.get(argument.name)
            if argument.role is ArgumentRole.PROTECTED_REFERENCE:
                resolution_status = (
                    "RESOLVED"
                    if type(resolution) is Resolved
                    else "FAILED"
                    if type(resolution) is ResolutionFailure
                    else "NOT_RESOLVED"
                )
                binding_status = (
                    "MATCHED"
                    if type(resolution) is Resolved
                    and resolution.invocation_id == decision.invocation_id
                    and resolution.parent_id == call_context.parent_id
                    else "NOT_MATCHED"
                )
                supplied = canonical_by_name.get(argument.name)
                masked_display = (
                    "opaque-reference-selected"
                    if type(supplied) is ReferenceId
                    else "protected-value-omitted"
                )
            else:
                resolution_status = "NOT_APPLICABLE"
                binding_status = "NOT_APPLICABLE"
                masked_display = "value-omitted"
            metadata = role_metadata[argument.name]
            projections.append(
                ArgumentProjection(
                    name=argument.name,
                    role=argument.role,
                    supported_type=TypeId(argument.type_id.value),
                    provenance_class=metadata.required_provenance,
                    resolution_status=resolution_status,
                    binding_status=binding_status,
                    masked_display=masked_display,
                )
            )
        rule_results = tuple(
            DecisionRuleResult(
                rule_id=result.rule_id,
                outcome=result.outcome,
                stage=result.evaluation_stage,
                argument_name=result.argument_name,
                constraint_id=result.constraint_id,
            )
            for result in decision.rule_results
        )
        facts = tuple(
            MaskedReasonFact(
                "argument_name" if fact.argument_name is not None else "rule_id",
                fact.argument_name or fact.rule_id.value,
            )
            for fact in decision.masked_facts
        )
        prepared_call_id = (
            PreparedCallId(prepared_call.prepared_call_id.value)
            if type(prepared_call) is PreparedToolCall
            else None
        )
        return self._append(
            EvidenceEventType.DECISION_RECORDED,
            DecisionRecordedPayload(
                outcome=decision.outcome,
                stage=decision.evaluation_stage,
                primary_rule_id=decision.primary_rule_id,
                rule_results=rule_results,
                tool_id=ToolId(decision.tool_id.value),
                contract_version=tool_policy.contract_version,
                policy_version=PolicyVersion(decision.policy_version.value),
                registry_version=RegistryVersion(decision.registry_version.value),
                argument_projections=tuple(projections),
                masked_reason_facts=facts,
                prepared_call_id=prepared_call_id,
            ),
            invocation_id=decision.invocation_id,
            call_id=decision.call_id,
            decision_id=decision.decision_id,
            prepared_call_id=prepared_call_id,
            policy_version=decision.policy_version,
            registry_version=decision.registry_version,
            adapter_id=tool_policy.adapter_id,
            adapter_version=tool_policy.adapter_version,
        )

    def record_callback_received(self, transport: object, call_context: object) -> AppendReceipt:
        return self._record_callback(
            EvidenceEventType.CALLBACK_RECEIVED,
            "before_tool_callback",
            transport,
            call_context=call_context,
        )

    def record_callback_vetoed(
        self, transport: object, call_context: object, decision: object
    ) -> AppendReceipt:
        return self._record_callback(
            EvidenceEventType.CALLBACK_VETOED,
            "before_tool_callback",
            transport,
            call_context=call_context,
            decision=decision,
        )

    def record_callback_released(
        self, transport: object, call_context: object, prepared_call: object
    ) -> AppendReceipt:
        return self._record_callback(
            EvidenceEventType.CALLBACK_RELEASED,
            "before_tool_callback",
            transport,
            call_context=call_context,
            prepared_call=prepared_call,
        )

    def record_callback_tool_entered(
        self, transport: object, prepared_call: object
    ) -> AppendReceipt:
        return self._record_callback(
            EvidenceEventType.CALLBACK_TOOL_ENTERED,
            "schedule_payment",
            transport,
            prepared_call=prepared_call,
        )

    def _record_callback(
        self,
        event_type: EvidenceEventType,
        callback_name: str,
        transport: object,
        *,
        call_context: Optional[object] = None,
        decision: Optional[object] = None,
        prepared_call: Optional[object] = None,
    ) -> AppendReceipt:
        from tidemark.adapters.google_adk import AdkTransportMetadata
        from tidemark.runtime.policy_engine import CallContext, Decision
        from tidemark.runtime.prepared_call import PreparedToolCall

        if type(transport) is not AdkTransportMetadata:
            raise TypeError("transport requires AdkTransportMetadata")
        context = call_context if type(call_context) is CallContext else None
        sealed_decision = decision if type(decision) is Decision else None
        prepared = prepared_call if type(prepared_call) is PreparedToolCall else None
        if context is None and prepared is None:
            raise TypeError("callback evidence requires runtime correlation")
        invocation_id = (
            context.invocation_id if context is not None else prepared.invocation_id
        )
        call_id = context.call_id if context is not None else prepared.call_id
        policy_version = (
            context.policy_version if context is not None else prepared.policy_version
        )
        registry_version = (
            context.registry_version if context is not None else prepared.registry_version
        )
        callback_version = AdapterVersion(transport.callback_version)
        return self._append(
            event_type,
            CallbackPayload(
                framework_name=transport.framework_name,
                framework_version=transport.framework_version,
                callback_name=callback_name,
                framework_invocation_id=transport.invocation_correlation,
                framework_call_id=transport.function_call_correlation,
                tool_id=ToolId(transport.tool_name),
                argument_shapes=tuple(
                    ArgumentShape(name, type_name)
                    for name, type_name in zip(
                        transport.pending_argument_names,
                        transport.pending_argument_types,
                    )
                ),
            ),
            invocation_id=invocation_id,
            call_id=call_id,
            decision_id=(
                prepared.decision_id
                if prepared is not None
                else sealed_decision.decision_id
                if sealed_decision is not None
                else None
            ),
            prepared_call_id=(
                prepared.prepared_call_id if prepared is not None else None
            ),
            policy_version=policy_version,
            registry_version=registry_version,
            adapter_id=_CALLBACK_ADAPTER_ID,
            adapter_version=callback_version,
        )

    def append_pre_execution(
        self, record: PreExecutionCorrelationRecord
    ) -> EvidenceAppendResult:
        """Preserve the Order 8 durable prerequisite under recorder ownership."""

        return self._transaction_sink.append_pre_execution(record)

    def append_execution_outcome(
        self, record: ExecutionOutcomeRecord
    ) -> EvidenceAppendResult:
        """Compatibility surface for callers that still require minimal outcome."""

        return self._transaction_sink.append_execution_outcome(record)

    def record_execution_refused(
        self,
        prepared_call: object,
        execution_id: Optional[ExecutionId],
        failure_fact: str,
    ) -> AppendReceipt:
        from tidemark.runtime.prepared_call import PreparedToolCall

        prepared = prepared_call if type(prepared_call) is PreparedToolCall else None
        return self._append(
            EvidenceEventType.EXECUTION_REFUSED,
            ExecutionRefusedPayload(
                rule_id=RuleId.EXECUTION_PREPARED_CALL_INVALID,
                masked_failure_fact=failure_fact,
            ),
            invocation_id=prepared.invocation_id if prepared is not None else None,
            call_id=prepared.call_id if prepared is not None else None,
            decision_id=prepared.decision_id if prepared is not None else None,
            prepared_call_id=prepared.prepared_call_id if prepared is not None else None,
            execution_id=execution_id,
            policy_version=prepared.policy_version if prepared is not None else None,
            registry_version=prepared.registry_version if prepared is not None else None,
            adapter_id=prepared.adapter_id if prepared is not None else None,
            adapter_version=prepared.adapter_version if prepared is not None else None,
        )

    def record_execution_started(
        self,
        prepared_call: object,
        execution_id: ExecutionId,
        occurred_at: datetime,
    ) -> AppendReceipt:
        from tidemark.runtime.prepared_call import PreparedToolCall

        if type(prepared_call) is not PreparedToolCall:
            raise TypeError("prepared_call requires PreparedToolCall")
        if type(execution_id) is not ExecutionId:
            raise TypeError("execution_id requires ExecutionId")
        fingerprint = _idempotency_fingerprint(prepared_call.prepared_call_id)
        receipt = self._append(
            EvidenceEventType.EXECUTION_STARTED,
            ExecutionStartedPayload(
                tool_id=ToolId(prepared_call.tool_id.value),
                attempt_number=1,
                idempotency_key_fingerprint=fingerprint,
                started_at=occurred_at,
            ),
            invocation_id=prepared_call.invocation_id,
            call_id=prepared_call.call_id,
            decision_id=prepared_call.decision_id,
            prepared_call_id=prepared_call.prepared_call_id,
            execution_id=execution_id,
            policy_version=prepared_call.policy_version,
            registry_version=prepared_call.registry_version,
            adapter_id=prepared_call.adapter_id,
            adapter_version=prepared_call.adapter_version,
        )
        with self._lock:
            self._execution_contexts[execution_id.value] = (
                PolicyVersion(prepared_call.policy_version.value),
                RegistryVersion(prepared_call.registry_version.value),
                AdapterId(prepared_call.adapter_id.value),
                AdapterVersion(prepared_call.adapter_version.value),
            )
        return receipt

    def record_execution_replay_rejected(
        self, prepared_call: object, execution_id: ExecutionId
    ) -> AppendReceipt:
        from tidemark.runtime.prepared_call import PreparedToolCall

        if type(prepared_call) is not PreparedToolCall:
            raise TypeError("prepared_call requires PreparedToolCall")
        return self._append(
            EvidenceEventType.EXECUTION_REPLAY_REJECTED,
            ExecutionReplayRejectedPayload(RuleId.EXECUTION_REPLAY_REJECTED),
            invocation_id=prepared_call.invocation_id,
            call_id=prepared_call.call_id,
            decision_id=prepared_call.decision_id,
            prepared_call_id=prepared_call.prepared_call_id,
            execution_id=execution_id,
            policy_version=prepared_call.policy_version,
            registry_version=prepared_call.registry_version,
            adapter_id=prepared_call.adapter_id,
            adapter_version=prepared_call.adapter_version,
        )

    def record_execution_outcome(
        self,
        *,
        prepared_call: object,
        execution_id: ExecutionId,
        execution_status: ExecutionOutcome,
        external_result_confirmed: bool,
        failure_fact: Optional[str],
    ) -> AppendReceipt:
        from tidemark.runtime.prepared_call import PreparedToolCall

        if type(prepared_call) is not PreparedToolCall:
            raise TypeError("prepared_call requires PreparedToolCall")
        if execution_status not in (ExecutionOutcome.COMPLETED, ExecutionOutcome.FAILED):
            raise ValueError("terminal evidence requires COMPLETED or FAILED")
        event_type = (
            EvidenceEventType.EXECUTION_COMPLETED
            if execution_status is ExecutionOutcome.COMPLETED
            else EvidenceEventType.EXECUTION_FAILED
        )
        terminal = self._append(
            event_type,
            ExecutionTerminalPayload(
                external_result_confirmed=external_result_confirmed,
                masked_failure_fact=failure_fact,
            ),
            invocation_id=prepared_call.invocation_id,
            call_id=prepared_call.call_id,
            decision_id=prepared_call.decision_id,
            prepared_call_id=prepared_call.prepared_call_id,
            execution_id=execution_id,
            policy_version=prepared_call.policy_version,
            registry_version=prepared_call.registry_version,
            adapter_id=prepared_call.adapter_id,
            adapter_version=prepared_call.adapter_version,
        )
        with self._lock:
            pending = self._pending_payments.pop(execution_id.value, None)
        if pending is not None:
            record, invocation = pending
            self._append_payment(record, invocation)
        return terminal

    def stage_payment(self, record: object, invocation: object) -> None:
        from tidemark.payment.domain import SyntheticPaymentRecord
        from tidemark.runtime.execution_gate import AdapterInvocation

        if type(record) is not SyntheticPaymentRecord:
            raise TypeError("record requires SyntheticPaymentRecord")
        if type(invocation) is not AdapterInvocation:
            raise TypeError("invocation requires AdapterInvocation")
        if (
            record.execution_id != invocation.execution_id
            or record.prepared_call_id != invocation.prepared_call_id
        ):
            raise ValueError("payment and adapter correlations differ")
        with self._lock:
            if record.execution_id.value in self._pending_payments:
                raise ValueError("payment evidence is already staged")
            self._pending_payments[record.execution_id.value] = (record, invocation)

    def _append_payment(self, record: object, invocation: object) -> AppendReceipt:
        with self._lock:
            context = self._execution_contexts.get(invocation.execution_id.value)
        if context is None:
            raise RuntimeError("execution correlation is unavailable for payment")
        policy_version, registry_version, adapter_id, adapter_version = context
        return self._append(
            EvidenceEventType.PAYMENT_RECORDED,
            PaymentRecordedPayload(
                payment_record_id=record.payment_record_id,
                execution_id=ExecutionId(record.execution_id.value),
                prepared_call_id=PreparedCallId(record.prepared_call_id.value),
                idempotency_key_fingerprint=record.idempotency_key_fingerprint,
                amount_minor=record.amount_minor,
                currency=record.currency,
                parent_id=record.parent_id,
                destination_kind=record.destination_kind,
                masked_destination_display=record.masked_destination_display,
                status=record.status,
                store_version=record.store_version,
                created_at=record.created_at,
            ),
            invocation_id=invocation.invocation_id,
            call_id=invocation.call_id,
            decision_id=invocation.decision_id,
            prepared_call_id=invocation.prepared_call_id,
            execution_id=invocation.execution_id,
            policy_version=policy_version,
            registry_version=registry_version,
            adapter_id=adapter_id,
            adapter_version=adapter_version,
        )

    def record_model_non_attempt(
        self, *, invocation_id: InvocationId, reason_code: str
    ) -> AppendReceipt:
        if type(invocation_id) is not InvocationId:
            raise TypeError("invocation_id requires InvocationId")
        return self._append(
            EvidenceEventType.RUN_MODEL_NON_ATTEMPT,
            ModelNonAttemptPayload(reason_code, 0),
            invocation_id=invocation_id,
        )

    def _append(
        self,
        event_type: EvidenceEventType,
        payload: object,
        *,
        invocation_id: Optional[InvocationId] = None,
        call_id: Optional[CallId] = None,
        decision_id: Optional[DecisionId] = None,
        prepared_call_id: Optional[PreparedCallId] = None,
        execution_id: Optional[ExecutionId] = None,
        policy_version: Optional[PolicyVersion] = None,
        registry_version: Optional[RegistryVersion] = None,
        adapter_id: Optional[AdapterId] = None,
        adapter_version: Optional[AdapterVersion] = None,
    ) -> AppendReceipt:
        with self._lock:
            sequence = self._store.next_sequence(self._trace_id)
            previous_digest = self._store.last_event_digest(self._trace_id)
            event = AuditEvent(
                schema_version=EVIDENCE_SCHEMA_VERSION,
                event_id="event-" + token_hex(32),
                event_type=event_type,
                occurred_at=datetime.now(timezone.utc),
                sequence=sequence,
                trace_id=self._trace_id,
                invocation_id=invocation_id,
                call_id=call_id,
                decision_id=decision_id,
                prepared_call_id=prepared_call_id,
                execution_id=execution_id,
                policy_version=policy_version,
                registry_version=registry_version,
                adapter_id=adapter_id,
                adapter_version=adapter_version,
                producer=self._producer,
                payload=payload,
                previous_event_digest=previous_digest,
            )
            return self._store.append(event)

    def __repr__(self) -> str:
        return "EvidenceRecorder(append_only=True, authorization_authority=False)"


def _idempotency_fingerprint(prepared_call_id: PreparedCallId) -> str:
    encoded = (_IDEMPOTENCY_DOMAIN + prepared_call_id.value).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


__all__ = (
    "EVIDENCE_RECORDER_PRODUCER_VERSION",
    "EvidenceRecorder",
)
