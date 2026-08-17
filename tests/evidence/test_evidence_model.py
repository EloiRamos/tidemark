from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone

import pytest

from tidemark.evidence.model import (
    EVIDENCE_SCHEMA_VERSION,
    ArgumentProjection,
    ArgumentShape,
    AuditEvent,
    CallbackPayload,
    CallIntakeRecordedPayload,
    DecisionRecordedPayload,
    DecisionRuleResult,
    EvidenceEventType,
    EvidenceExportFinalizedPayload,
    EvidenceProducer,
    EvidenceReconciledPayload,
    ModelNonAttemptPayload,
    PaymentRecordedPayload,
    RetainedAuditEvent,
    RetainedPayloadField,
    audit_event_from_primitive,
    audit_event_to_primitive,
)
from tidemark.runtime.identifiers import (
    AdapterId,
    AdapterVersion,
    CallId,
    DecisionId,
    ExecutionId,
    InvocationId,
    ParentId,
    PolicyVersion,
    PreparedCallId,
    RegistryVersion,
    ToolContractVersion,
    ToolId,
    TypeId,
)
from tidemark.runtime.vocabulary import (
    ArgumentRole,
    ConstraintId,
    DecisionOutcome,
    EvaluationStage,
    ProvenanceClass,
    RuleEvaluationOutcome,
    RuleId,
)


NOW = datetime(2026, 8, 7, 20, 0, tzinfo=timezone.utc)
PRODUCER = EvidenceProducer("tidemark.tests", "order-13")


def _intake_payload():
    return CallIntakeRecordedPayload(
        tool_id=ToolId("schedule_payment"),
        contract_version=ToolContractVersion("contract.v1"),
        argument_shapes=(ArgumentShape("amount_minor", "int"),),
    )


def _event(**changes):
    values = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "event_id": "event-001",
        "event_type": EvidenceEventType.CALL_INTAKE_RECORDED,
        "occurred_at": NOW,
        "sequence": 1,
        "trace_id": "trace-001",
        "invocation_id": InvocationId("invocation-001"),
        "call_id": CallId("call-001"),
        "decision_id": None,
        "prepared_call_id": None,
        "execution_id": None,
        "policy_version": PolicyVersion("policy.v1"),
        "registry_version": RegistryVersion("registry.v1"),
        "adapter_id": None,
        "adapter_version": None,
        "producer": PRODUCER,
        "payload": _intake_payload(),
        "previous_event_digest": None,
    }
    values.update(changes)
    return AuditEvent(**values)


def _decision_payload(outcome=DecisionOutcome.DENY, prepared_call_id=None):
    return DecisionRecordedPayload(
        outcome=outcome,
        stage=(
            EvaluationStage.AUTHORIZATION
            if outcome is DecisionOutcome.ALLOW
            else EvaluationStage.REPRESENTATION
        ),
        primary_rule_id=(
            RuleId.AUTHORIZATION_ALLOW
            if outcome is DecisionOutcome.ALLOW
            else RuleId.PROTECTED_RAW_VALUE_SUPPLIED
        ),
        rule_results=(
            DecisionRuleResult(
                rule_id=(
                    RuleId.AUTHORIZATION_ALLOW
                    if outcome is DecisionOutcome.ALLOW
                    else RuleId.PROTECTED_RAW_VALUE_SUPPLIED
                ),
                outcome=(
                    RuleEvaluationOutcome.PASS
                    if outcome is DecisionOutcome.ALLOW
                    else RuleEvaluationOutcome.FAIL
                ),
                stage=(
                    EvaluationStage.AUTHORIZATION
                    if outcome is DecisionOutcome.ALLOW
                    else EvaluationStage.REPRESENTATION
                ),
                argument_name=(
                    None
                    if outcome is DecisionOutcome.ALLOW
                    else "destination_reference"
                ),
                constraint_id=(
                    None
                    if outcome is DecisionOutcome.ALLOW
                    else ConstraintId.PROTECTED_REFERENCE_REQUIRED
                ),
            ),
        ),
        tool_id=ToolId("schedule_payment"),
        contract_version=ToolContractVersion("contract.v1"),
        policy_version=PolicyVersion("policy.v1"),
        registry_version=RegistryVersion("registry.v1"),
        argument_projections=(
            ArgumentProjection(
                name="destination_reference",
                role=ArgumentRole.PROTECTED_REFERENCE,
                supported_type=TypeId("destination_reference"),
                provenance_class=ProvenanceClass.RUNTIME_TRUSTED,
                resolution_status="RESOLVED",
                binding_status="MATCHED",
                masked_display="synthetic-beneficiary-****4242",
            ),
        ),
        masked_reason_facts=(),
        prepared_call_id=prepared_call_id,
    )


def _decision_event(outcome=DecisionOutcome.DENY, prepared_call_id=None):
    return _event(
        event_id="decision-event",
        event_type=EvidenceEventType.DECISION_RECORDED,
        decision_id=DecisionId("decision-001"),
        prepared_call_id=prepared_call_id,
        payload=_decision_payload(outcome, prepared_call_id),
    )


def test_audit_event_round_trip_is_exact_and_detached():
    event = _event()

    primitive = audit_event_to_primitive(event)
    restored = audit_event_from_primitive(primitive)
    primitive["payload"]["argument_shapes"][0]["name"] = "changed"

    assert restored == event
    assert event.payload.argument_shapes[0].name == "amount_minor"
    assert asdict(event)["payload"]["argument_shapes"][0]["name"] == "amount_minor"


@pytest.mark.parametrize(
    "changes",
    (
        {"schema_version": "tidemark.evidence.v999"},
        {"event_type": "call.intake_recorded"},
        {"event_id": ""},
        {"occurred_at": NOW.replace(tzinfo=None)},
        {"occurred_at": NOW.astimezone(timezone(timedelta(hours=1)))},
        {"sequence": 0},
        {"sequence": True},
        {"trace_id": ""},
        {"invocation_id": None},
        {"call_id": None},
        {"producer": object()},
        {"payload": ModelNonAttemptPayload("no-candidate-tool-call", 0)},
    ),
)
def test_audit_event_rejects_invalid_envelope_or_payload_pairing(changes):
    with pytest.raises((TypeError, ValueError)):
        _event(**changes)


def test_deny_cannot_carry_a_prepared_call():
    prepared_call_id = PreparedCallId("prepared-001")

    with pytest.raises(ValueError):
        _decision_event(DecisionOutcome.DENY, prepared_call_id)


def test_allow_requires_exactly_one_matching_prepared_call():
    with pytest.raises(ValueError):
        _decision_event(DecisionOutcome.ALLOW, None)

    event = _decision_event(
        DecisionOutcome.ALLOW,
        PreparedCallId("prepared-001"),
    )
    with pytest.raises(ValueError):
        replace(
            event,
            payload=replace(
                event.payload,
                prepared_call_id=PreparedCallId("prepared-other"),
            ),
        )


def test_execution_started_requires_complete_execution_lineage():
    from tidemark.evidence.model import ExecutionStartedPayload

    with pytest.raises(ValueError):
        _event(
            event_type=EvidenceEventType.EXECUTION_STARTED,
            decision_id=DecisionId("decision-001"),
            prepared_call_id=PreparedCallId("prepared-001"),
            execution_id=None,
            adapter_id=AdapterId("adapter"),
            adapter_version=AdapterVersion("adapter.v1"),
            payload=ExecutionStartedPayload(
                tool_id=ToolId("schedule_payment"),
                attempt_number=1,
                idempotency_key_fingerprint="sha256:" + "a" * 64,
                started_at=NOW,
            ),
        )


def test_payment_payload_rejects_forbidden_and_non_masked_shapes():
    with pytest.raises(TypeError):
        PaymentRecordedPayload(
            payment_record_id="payment-001",
            execution_id=ExecutionId("execution-001"),
            prepared_call_id=PreparedCallId("prepared-001"),
            idempotency_key_fingerprint="sha256:" + "a" * 64,
            amount_minor=25_000,
            currency="EUR",
            parent_id=ParentId("po-001"),
            destination_kind="synthetic_payment_destination",
            masked_destination_display="synthetic-routing://raw-destination",
            status="RECORDED",
            store_version=1,
            created_at=NOW,
            raw_destination="synthetic-routing://raw-destination",
        )


def test_callback_payload_has_only_masked_transport_shape():
    protected_marker = "synthetic-routing://raw-destination"
    payload = CallbackPayload(
        framework_name="google-adk",
        framework_version="1.18.0",
        callback_name="before_tool_callback",
        framework_invocation_id="framework-invocation",
        framework_call_id="framework-call",
        tool_id=ToolId("schedule_payment"),
        argument_shapes=(ArgumentShape("destination_reference", "str"),),
    )

    primitive = asdict(payload)

    assert "provider_response" not in primitive
    assert "argument_values" not in primitive
    assert protected_marker not in repr(primitive.values())


def test_model_non_attempt_cannot_be_labeled_as_deny_or_veto():
    payload = ModelNonAttemptPayload(
        reason_code="no-candidate-tool-call",
        candidate_tool_call_count=0,
    )

    assert not hasattr(payload, "outcome")
    assert not hasattr(payload, "callback_action")
    with pytest.raises(ValueError):
        ModelNonAttemptPayload("DENY", 0)
    with pytest.raises(ValueError):
        ModelNonAttemptPayload("callback-vetoed", 0)


def test_custom_subclasses_callables_and_mutable_nested_values_are_rejected():
    class StringSubclass(str):
        pass

    with pytest.raises((TypeError, ValueError)):
        ArgumentShape(StringSubclass("amount_minor"), "int")
    with pytest.raises((TypeError, ValueError)):
        RetainedPayloadField("handler", lambda: None)
    with pytest.raises((TypeError, ValueError)):
        RetainedPayloadField("nested", ["mutable"])


def test_unknown_schema_or_event_is_retained_only_as_non_authoritative():
    retained = RetainedAuditEvent(
        schema_version="future.evidence.v2",
        event_id="future-event",
        event_type="future.event",
        occurred_at=NOW,
        sequence=1,
        trace_id="trace-future",
        producer=PRODUCER,
        payload=(RetainedPayloadField("masked_status", "UNKNOWN"),),
    )

    assert retained.authoritative is False
    assert not isinstance(retained, AuditEvent)
    assert audit_event_from_primitive(
        audit_event_to_primitive(retained)
    ) == retained


def test_all_closed_event_types_are_exactly_the_specified_family():
    assert {item.value for item in EvidenceEventType} == {
        "policy.installation_refused",
        "call.intake_recorded",
        "call.preparation_refused",
        "decision.recorded",
        "callback.received",
        "callback.vetoed",
        "callback.released",
        "callback.tool_entered",
        "execution.refused",
        "execution.started",
        "execution.completed",
        "execution.failed",
        "execution.replay_rejected",
        "payment.recorded",
        "run.model_non_attempt",
        "evidence.reconciled",
        "evidence.export_finalized",
    }


def test_deferred_reconciliation_and_export_events_are_representable_only():
    reconciled = _event(
        event_type=EvidenceEventType.EVIDENCE_RECONCILED,
        invocation_id=None,
        call_id=None,
        policy_version=None,
        registry_version=None,
        payload=EvidenceReconciledPayload(
            related_event_ids=("event-001",),
            masked_detail="correction-link-only",
        ),
    )
    export = _event(
        event_id="export-event",
        event_type=EvidenceEventType.EVIDENCE_EXPORT_FINALIZED,
        invocation_id=None,
        call_id=None,
        policy_version=None,
        registry_version=None,
        previous_event_digest="sha256:" + "a" * 64,
        payload=EvidenceExportFinalizedPayload(
            export_id="export-001",
            ordered_event_ids=("event-001",),
            event_digests=("sha256:" + "b" * 64,),
            overall_digest="sha256:" + "c" * 64,
            schema_versions=(EVIDENCE_SCHEMA_VERSION,),
        ),
    )

    assert audit_event_from_primitive(audit_event_to_primitive(reconciled)) == reconciled
    assert audit_event_from_primitive(audit_event_to_primitive(export)) == export
