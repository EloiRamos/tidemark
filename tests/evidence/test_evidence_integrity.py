import json
from dataclasses import asdict, replace

from tidemark.evidence.integrity import (
    EvidenceIntegrityChecker,
    ForensicEvidenceInspector,
)
from tidemark.evidence.model import (
    EvidenceEventType,
    EvidenceProducer,
    MaskedReasonFact,
    RetainedAuditEvent,
    RetainedPayloadField,
    audit_event_to_primitive,
)
from tidemark.evidence.projection import (
    EvidenceCompleteness,
    EvidenceProjector,
    ProjectionStatus,
    review_projection_to_primitive,
)
from tidemark.evidence.reconciliation import ReconciliationFindingCode
from tidemark.payment.fixtures import (
    RAW_SYNTHETIC_DESTINATION,
    build_synthetic_payment_fixture,
)


PROTECTED_MARKER = "protected-marker-order-14-DO-NOT-DISCLOSE"


def _codes(projection):
    return tuple(item.code for item in projection.findings)


def _deny_events(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    fixture.prepare(
        fixture.canonical_call(destination_reference=RAW_SYNTHETIC_DESTINATION)
    )
    return fixture.evidence_store.ordered_events()


def _success_events(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    prepared = fixture.prepare(fixture.canonical_call())
    fixture.execution_gate.execute(prepared)
    return fixture.evidence_store.ordered_events()


def test_sequence_gap_is_a_deterministic_integrity_failure(tmp_path):
    first, second = _deny_events(tmp_path)
    stream = (
        replace(first, previous_event_digest=None),
        replace(second, sequence=3, previous_event_digest=None),
    )

    first_projection = EvidenceProjector().project(stream)
    second_projection = EvidenceProjector().project(stream)

    assert ReconciliationFindingCode.SEQUENCE_GAP in _codes(first_projection)
    assert first_projection == second_projection
    assert first_projection.integrity_status is ProjectionStatus.FAILED
    assert first_projection.evidence_completeness is EvidenceCompleteness.INCOMPLETE


def test_digest_mismatch_is_detected_without_rewriting_lineage(tmp_path):
    events = _deny_events(tmp_path)
    first = events[0]
    corrupted = replace(
        events[1],
        previous_event_digest="sha256:" + "0" * 64,
    )
    stream = (first, corrupted)

    projection = EvidenceProjector().project(stream)

    assert ReconciliationFindingCode.DIGEST_MISMATCH in _codes(projection)
    assert stream[1].previous_event_digest == "sha256:" + "0" * 64
    assert not hasattr(EvidenceIntegrityChecker(), "rewrite_digest")


def test_duplicate_event_identity_is_detected_at_review_boundary(tmp_path):
    first = _deny_events(tmp_path)[0]
    duplicate = replace(first, sequence=2, previous_event_digest=None)

    report = EvidenceIntegrityChecker().check((first, duplicate))

    assert ReconciliationFindingCode.DUPLICATE_EVENT_IDENTITY in tuple(
        item.code for item in report.findings
    )


def test_cross_trace_reuse_of_a_call_correlation_is_visible(tmp_path):
    first, second = _deny_events(tmp_path)
    stream = (
        replace(first, previous_event_digest=None),
        replace(
            second,
            trace_id="trace-other",
            sequence=1,
            previous_event_digest=None,
        ),
    )

    projection = EvidenceProjector().project(stream)

    assert ReconciliationFindingCode.CORRELATION_MISMATCH in _codes(projection)
    assert projection.reconciliation_status is ProjectionStatus.FAILED


def test_retained_unknown_record_is_visible_but_non_authoritative(tmp_path):
    events = _deny_events(tmp_path)
    retained = RetainedAuditEvent(
        schema_version="future.evidence.v2",
        event_id="future-event",
        event_type="future.event",
        occurred_at=events[-1].occurred_at,
        sequence=3,
        trace_id=events[-1].trace_id,
        producer=EvidenceProducer("future.producer", "future.v2"),
        payload=(RetainedPayloadField("opaque_future_value", PROTECTED_MARKER),),
    )

    projection = EvidenceProjector().project(events + (retained,))
    public = repr(projection) + json.dumps(review_projection_to_primitive(projection))

    assert projection.retained_record_count == 1
    assert projection.schema_gap_count == 1
    assert ReconciliationFindingCode.SCHEMA_GAP in _codes(projection)
    assert projection.authoritative_event_count == 2
    assert PROTECTED_MARKER not in public


def test_forensic_known_record_reports_forbidden_data_without_disclosure(
    tmp_path,
):
    primitive = audit_event_to_primitive(_success_events(tmp_path)[-1])
    primitive["payload"]["raw_destination"] = PROTECTED_MARKER
    primitive["payload"]["masked_destination_display"] = PROTECTED_MARKER

    record = ForensicEvidenceInspector().inspect_primitive(primitive)
    projection = EvidenceProjector().project((record,))
    public_surfaces = (
        repr(record)
        + repr(record.findings)
        + repr(projection)
        + json.dumps(review_projection_to_primitive(projection), sort_keys=True)
    )

    assert record.authoritative is False
    assert projection.forensic_record_count == 1
    assert projection.authoritative_event_count == 0
    assert projection.malformed_record_count == 1
    assert ReconciliationFindingCode.NON_AUTHORITATIVE_RECORD in _codes(projection)
    assert ReconciliationFindingCode.MALFORMED_RECORD in _codes(projection)
    assert ReconciliationFindingCode.FORBIDDEN_FIELD in _codes(projection)
    assert ReconciliationFindingCode.MASKING_VIOLATION in _codes(projection)
    assert PROTECTED_MARKER not in public_surfaces


def test_structurally_valid_but_unallowlisted_reason_is_omitted(tmp_path):
    intake, decision = _deny_events(tmp_path)
    unsafe_decision = replace(
        decision,
        payload=replace(
            decision.payload,
            masked_reason_facts=(
                MaskedReasonFact("argument_name", PROTECTED_MARKER),
            ),
        ),
        previous_event_digest=None,
    )

    projection = EvidenceProjector().project(
        (replace(intake, previous_event_digest=None), unsafe_decision)
    )
    public = repr(projection) + json.dumps(
        review_projection_to_primitive(projection), sort_keys=True
    )

    assert ReconciliationFindingCode.MASKING_VIOLATION in _codes(projection)
    assert PROTECTED_MARKER not in public


def test_forensic_input_is_distinct_from_authoritative_store_load(tmp_path):
    event = _success_events(tmp_path)[0]
    record = ForensicEvidenceInspector().inspect_primitive(
        audit_event_to_primitive(event)
    )

    authoritative = EvidenceProjector().project((event,))
    forensic = EvidenceProjector().project((record,))

    assert authoritative.authoritative_event_count == 1
    assert authoritative.forensic_record_count == 0
    assert forensic.authoritative_event_count == 0
    assert forensic.forensic_record_count == 1
    assert ReconciliationFindingCode.NON_AUTHORITATIVE_RECORD in _codes(forensic)


def test_shuffled_input_reconstructs_same_projection_without_mutating_history(
    tmp_path,
):
    events = _success_events(tmp_path)
    shuffled = tuple(reversed(events))

    ordered_projection = EvidenceProjector().project(events)
    shuffled_projection = EvidenceProjector().project(shuffled)

    assert shuffled_projection == ordered_projection
    assert shuffled == tuple(reversed(events))


def test_shuffled_forensic_input_has_the_same_normalized_projection(tmp_path):
    events = _deny_events(tmp_path)
    inspector = ForensicEvidenceInspector()
    forensic = tuple(
        inspector.inspect_primitive(audit_event_to_primitive(event))
        for event in events
    )

    ordered = EvidenceProjector().project(forensic)
    shuffled = EvidenceProjector().project(tuple(reversed(forensic)))

    assert shuffled == ordered


def test_finding_order_is_sequence_then_closed_code_order(tmp_path):
    first, second = _deny_events(tmp_path)
    corrupted = replace(
        second,
        sequence=3,
        previous_event_digest="sha256:" + "0" * 64,
    )

    projection = EvidenceProjector().project((first, corrupted))
    codes_at_three = tuple(
        item.code for item in projection.findings if item.sequence == 3
    )

    assert codes_at_three[:2] == (
        ReconciliationFindingCode.SEQUENCE_GAP,
        ReconciliationFindingCode.DIGEST_MISMATCH,
    )


def test_invalid_input_error_does_not_echo_protected_content():
    try:
        EvidenceProjector().project((PROTECTED_MARKER,))
    except TypeError as error:
        rendered = repr(error) + str(error)
    else:
        raise AssertionError("invalid review input must be rejected")

    assert PROTECTED_MARKER not in rendered


def test_checker_makes_no_host_tamper_resistance_claim():
    rendered = repr(EvidenceIntegrityChecker())

    assert "host_tamper_resistant=False" in rendered
    assert "cryptographic host" not in rendered.lower()
