import json
import socket
from dataclasses import FrozenInstanceError, replace

import pytest

from tidemark.evidence import (
    EVIDENCE_PUBLICATION_SCHEMA_VERSION,
    EvidenceEventType,
    EvidencePublicationPackage,
    EvidenceReconciledPayload,
    PublicationBlockedError,
    PublicationCollisionError,
    PublicationDurabilityError,
    PublicationMaterializer,
    PublicationRequest,
    PublicationResultCounts,
    PublicationVerificationCode,
    RetainedAuditEvent,
    RetainedPayloadField,
    build_evidence_publication,
    parse_evidence_publication,
    verify_evidence_publication,
)
from tidemark.evidence.model import AuditEvent, EvidenceProducer
from tidemark.payment.fixtures import (
    RAW_SYNTHETIC_DESTINATION,
    build_synthetic_payment_fixture,
)


TRACE_ID = "trace-order-13-payment"
EXPORT_ID = "order-15-success"
FORBIDDEN_SENTINELS = (
    RAW_SYNTHETIC_DESTINATION,
    "protected-runtime-value-never-publish-order-15",
    "raw-prompt-order-15-DO-NOT-PUBLISH",
    "raw-provider-output-order-15-DO-NOT-PUBLISH",
    "synthetic-api-key-order-15-DO-NOT-PUBLISH",
)


def _canonical(value):
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _counts(events):
    types = tuple(
        event.event_type
        for event in events
        if type(event) is AuditEvent
    )
    decisions = tuple(
        event
        for event in events
        if type(event) is AuditEvent
        and event.event_type is EvidenceEventType.DECISION_RECORDED
    )
    return PublicationResultCounts(
        authoritative_event_count=sum(type(event) is AuditEvent for event in events),
        refusal_count=sum(
            event_type
            in {
                EvidenceEventType.POLICY_INSTALLATION_REFUSED,
                EvidenceEventType.CALL_PREPARATION_REFUSED,
            }
            for event_type in types
        ),
        deny_count=sum(event.payload.outcome.value == "DENY" for event in decisions),
        allow_count=sum(event.payload.outcome.value == "ALLOW" for event in decisions),
        model_non_attempt_count=types.count(EvidenceEventType.RUN_MODEL_NON_ATTEMPT),
        execution_start_count=types.count(EvidenceEventType.EXECUTION_STARTED),
        execution_completion_count=types.count(EvidenceEventType.EXECUTION_COMPLETED),
        execution_failure_count=types.count(EvidenceEventType.EXECUTION_FAILED),
        replay_rejection_count=types.count(EvidenceEventType.EXECUTION_REPLAY_REJECTED),
        payment_count=types.count(EvidenceEventType.PAYMENT_RECORDED),
        reconciliation_count=types.count(EvidenceEventType.EVIDENCE_RECONCILED),
        prior_export_count=types.count(EvidenceEventType.EVIDENCE_EXPORT_FINALIZED),
    )


def _success(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path / "evidence"))
    prepared = fixture.prepare(fixture.canonical_call())
    fixture.execution_gate.execute(prepared)
    events = fixture.evidence_store.events_for_trace(TRACE_ID)
    return fixture, events


def _request(events, *, export_id=EXPORT_ID, export_version=1, trace_id=TRACE_ID):
    return PublicationRequest(
        export_id=export_id,
        export_version=export_version,
        trace_id=trace_id,
        expected_counts=_counts(events),
    )


def _package(tmp_path, *, export_id=EXPORT_ID):
    _, events = _success(tmp_path)
    return build_evidence_publication(
        events,
        _request(events, export_id=export_id),
    )


def _changed_package_bytes(package, mutate):
    primitive = json.loads(package.canonical_bytes)
    mutate(primitive)
    return _canonical(primitive)


def test_valid_publication_is_byte_deterministic_and_self_describing(tmp_path):
    _, events = _success(tmp_path)
    request = _request(events)

    first = build_evidence_publication(events, request)
    second = build_evidence_publication(events, request)
    primitive = json.loads(first.canonical_bytes)

    assert type(first) is EvidencePublicationPackage
    assert first == second
    assert first.canonical_bytes == second.canonical_bytes
    assert primitive["schema_version"] == EVIDENCE_PUBLICATION_SCHEMA_VERSION
    assert primitive["package_type"] == "FINALIZED_EVIDENCE_EXPORT"
    assert primitive["publication_status"] == "FINALIZED"
    assert "published_at" not in primitive
    assert "created_at" not in primitive


def test_manifest_and_evidence_order_are_stable_and_authoritative(tmp_path):
    _, events = _success(tmp_path)

    ordered = build_evidence_publication(events, _request(events))
    shuffled = build_evidence_publication(
        tuple(reversed(events)),
        _request(events),
    )
    primitive = json.loads(ordered.canonical_bytes)

    assert shuffled == ordered
    assert [entry["name"] for entry in primitive["manifest"]["entries"]] == [
        "source",
        "evidence",
        "integrity",
        "reconciliation",
        "projection",
        "privacy",
    ]
    assert [record["sequence"] for record in primitive["evidence"]["records"]] == [
        event.sequence for event in events
    ]
    assert primitive["source"]["ordered_event_ids"] == [
        event.event_id for event in events
    ]


def test_valid_package_parse_round_trip_is_immutable(tmp_path):
    package = _package(tmp_path)

    restored = parse_evidence_publication(package.canonical_bytes)

    assert restored == package
    with pytest.raises(FrozenInstanceError):
        restored.canonical_bytes = b"changed"


def test_valid_package_passes_offline_digest_verification(tmp_path):
    package = _package(tmp_path)

    report = verify_evidence_publication(package.canonical_bytes)
    primitive = json.loads(package.canonical_bytes)

    assert report.valid is True
    assert report.findings == ()
    assert report.package == package
    assert primitive["digest_algorithm"] == "sha256"
    assert primitive["package_digest"].startswith("sha256:")
    assert primitive["manifest"]["manifest_digest"].startswith("sha256:")
    assert all(
        entry["digest"].startswith("sha256:")
        for entry in primitive["manifest"]["entries"]
    )


@pytest.mark.parametrize(
    "mutate",
    (
        lambda value: value["evidence"]["records"][0].__setitem__("event_id", "tampered-event"),
        lambda value: value["projection"]["value"].__setitem__("payment_count", 99),
        lambda value: value["manifest"]["entries"][0].__setitem__("byte_length", 1),
    ),
)
def test_evidence_projection_or_manifest_tampering_is_detected(tmp_path, mutate):
    package = _package(tmp_path)

    report = verify_evidence_publication(_changed_package_bytes(package, mutate))

    assert report.valid is False
    assert PublicationVerificationCode.DIGEST_MISMATCH in report.findings
    assert report.package is None


def test_truncated_package_is_rejected_without_repair(tmp_path):
    package = _package(tmp_path)

    report = verify_evidence_publication(package.canonical_bytes[:-17])

    assert report.valid is False
    assert report.findings == (PublicationVerificationCode.MALFORMED_PACKAGE,)
    with pytest.raises(ValueError, match="invalid evidence publication package"):
        parse_evidence_publication(package.canonical_bytes[:-17])


@pytest.mark.parametrize(
    "mutate",
    (
        lambda value: value.pop("projection"),
        lambda value: value.__setitem__("undeclared", {}),
        lambda value: value.__setitem__("schema_version", "tidemark.evidence.publication.v999"),
        lambda value: value["source"].__setitem__("undeclared", "value"),
    ),
)
def test_missing_extra_or_invalid_schema_content_is_rejected(tmp_path, mutate):
    package = _package(tmp_path)

    report = verify_evidence_publication(_changed_package_bytes(package, mutate))

    assert report.valid is False
    assert report.package is None


def test_non_canonical_json_and_duplicate_keys_are_rejected(tmp_path):
    package = _package(tmp_path)
    primitive = json.loads(package.canonical_bytes)
    pretty = json.dumps(primitive, indent=2, sort_keys=True).encode("utf-8")
    duplicate = b'{"schema_version":"a","schema_version":"b"}'

    pretty_report = verify_evidence_publication(pretty)
    duplicate_report = verify_evidence_publication(duplicate)

    assert pretty_report.findings == (
        PublicationVerificationCode.NON_CANONICAL_PACKAGE,
    )
    assert duplicate_report.findings == (
        PublicationVerificationCode.MALFORMED_PACKAGE,
    )


def test_integrity_failure_blocks_finalization(tmp_path):
    _, events = _success(tmp_path)
    broken = events[:-1] + (
        replace(events[-1], previous_event_digest="sha256:" + "0" * 64),
    )

    with pytest.raises(PublicationBlockedError) as caught:
        build_evidence_publication(broken, _request(events))

    assert "evidence.digest_mismatch.v1" in caught.value.finding_codes
    assert not any((tmp_path / "publication").glob("*"))


def test_reconciliation_failure_blocks_finalization_without_repair(tmp_path):
    _, events = _success(tmp_path)
    incomplete = events[:-1]

    with pytest.raises(PublicationBlockedError) as caught:
        build_evidence_publication(incomplete, _request(incomplete))

    assert "evidence.missing_terminal.v1" in caught.value.finding_codes
    assert incomplete == events[:-1]


def test_missing_digest_chain_link_blocks_finalization(tmp_path):
    _, events = _success(tmp_path)
    unlinked = events[:1] + (
        replace(events[1], previous_event_digest=None),
    ) + events[2:]

    with pytest.raises(PublicationBlockedError, match="source digest chain"):
        build_evidence_publication(unlinked, _request(events))


def test_unknown_record_is_not_promoted_or_published(tmp_path):
    _, events = _success(tmp_path)
    protected_marker = "retained-protected-order-15-DO-NOT-PUBLISH"
    retained = RetainedAuditEvent(
        schema_version="future.evidence.v2",
        event_id="future-event",
        event_type="future.event",
        occurred_at=events[-1].occurred_at,
        sequence=events[-1].sequence + 1,
        trace_id=TRACE_ID,
        producer=EvidenceProducer("future.producer", "future.v2"),
        payload=(RetainedPayloadField("opaque_future_value", protected_marker),),
        previous_event_digest=None,
    )

    with pytest.raises(PublicationBlockedError) as caught:
        build_evidence_publication(events + (retained,), _request(events))

    assert "evidence.schema_gap.v1" in caught.value.finding_codes
    assert protected_marker not in repr(caught.value)


def test_expected_and_actual_count_mismatch_blocks_finalization(tmp_path):
    _, events = _success(tmp_path)
    expected = replace(_counts(events), payment_count=0)
    request = PublicationRequest(EXPORT_ID, 1, TRACE_ID, expected)

    with pytest.raises(PublicationBlockedError, match="result counts"):
        build_evidence_publication(events, request)


def test_trace_scope_is_explicit_and_cannot_include_unrelated_events(tmp_path):
    _, first = _success(tmp_path / "first")
    fixture = build_synthetic_payment_fixture(str(tmp_path / "other"))
    fixture.evidence_recorder.record_model_non_attempt(
        invocation_id=fixture.invocation_id,
        reason_code="no-candidate-tool-call",
    )
    second = tuple(
        replace(event, trace_id="trace-unrelated")
        for event in fixture.evidence_store.ordered_events()
    )

    with pytest.raises(PublicationBlockedError, match="trace scope"):
        build_evidence_publication(first + second, _request(first))


def test_publication_contains_only_safe_evidence_and_no_local_path(tmp_path):
    package = _package(tmp_path)
    rendered = package.canonical_bytes.decode("utf-8")

    assert all(marker not in rendered for marker in FORBIDDEN_SENTINELS)
    assert "/Users/example-user/" not in rendered
    assert str(tmp_path) not in rendered
    assert "raw_prompt" not in rendered
    assert "raw_provider_output" not in rendered
    assert "credential" not in rendered
    assert json.loads(rendered)["privacy"] == {
        "absolute_path_detected": False,
        "forbidden_data_detected": False,
        "masking_profile_version": "tidemark.evidence.review-mask.v1",
        "schema_version": "tidemark.evidence.publication-privacy.v1",
        "status": "PASS",
    }


@pytest.mark.parametrize(
    "forbidden_value",
    (
        RAW_SYNTHETIC_DESTINATION,
        "/Users/example-user/private/order-15.txt",
        "raw-prompt-order-15-DO-NOT-PUBLISH",
        "GEMINI_API_KEY=synthetic-order-15-secret",
    ),
)
def test_publication_privacy_gate_blocks_forbidden_source_text(
    tmp_path, forbidden_value
):
    fixture = build_synthetic_payment_fixture(
        str(tmp_path / "evidence"), adapter_fail_before_record=True
    )
    prepared = fixture.prepare(fixture.canonical_call())
    fixture.execution_gate.execute(prepared)
    events = fixture.evidence_store.events_for_trace(TRACE_ID)
    unsafe = events[:-1] + (
        replace(
            events[-1],
            payload=replace(
                events[-1].payload,
                masked_failure_fact=forbidden_value,
            ),
        ),
    )

    with pytest.raises(PublicationBlockedError) as caught:
        build_evidence_publication(unsafe, _request(unsafe))

    assert caught.value.finding_codes in {
        ("publication.absolute_path_detected.v1",),
        ("publication.forbidden_data_detected.v1",),
    }
    assert forbidden_value not in repr(caught.value)


def test_caller_mutation_after_construction_cannot_change_package(tmp_path):
    _, events = _success(tmp_path)
    package = build_evidence_publication(events, _request(events))
    original = package.canonical_bytes
    primitive = json.loads(package.canonical_bytes)

    primitive["evidence"]["records"][0]["event_id"] = "caller-mutated"
    object.__setattr__(events[0], "event_id", "forced-source-mutation")

    assert package.canonical_bytes == original
    assert b"caller-mutated" not in package.canonical_bytes
    assert b"forced-source-mutation" not in package.canonical_bytes


@pytest.mark.parametrize(
    "export_id",
    (
        "../escape",
        "/absolute",
        "nested/name",
        "nested\\name",
        "contains\x00nul",
        ".",
        "..",
    ),
)
def test_unsafe_publication_identifiers_are_rejected(export_id):
    counts = PublicationResultCounts(*(0 for _ in range(12)))

    with pytest.raises(ValueError, match="export_id"):
        PublicationRequest(export_id, 1, "trace-safe", counts)


def test_materialization_is_exact_atomic_and_receipt_is_path_safe(tmp_path):
    package = _package(tmp_path / "source")
    root = tmp_path / "published"

    receipt = PublicationMaterializer(str(root)).materialize(package)
    final_path = root / receipt.artifact_name

    assert final_path.read_bytes() == package.canonical_bytes
    assert receipt.package_digest == package.package_digest
    assert receipt.byte_length == len(package.canonical_bytes)
    assert str(tmp_path) not in repr(receipt)
    assert tuple(path.name for path in root.iterdir()) == (receipt.artifact_name,)
    with pytest.raises(FrozenInstanceError):
        receipt.byte_length = 0


def test_existing_finalized_destination_is_never_overwritten(tmp_path):
    package = _package(tmp_path / "source")
    materializer = PublicationMaterializer(str(tmp_path / "published"))
    receipt = materializer.materialize(package)
    path = tmp_path / "published" / receipt.artifact_name
    original = path.read_bytes()

    with pytest.raises(PublicationCollisionError):
        materializer.materialize(package)

    assert path.read_bytes() == original


def test_materializer_uses_verified_bytes_not_mutated_package_metadata(tmp_path):
    package = _package(tmp_path / "source")
    object.__setattr__(package, "export_id", "../escaped")
    root = tmp_path / "published"

    receipt = PublicationMaterializer(str(root)).materialize(package)

    assert receipt.artifact_name == "order-15-success.v1.tidemark-evidence.json"
    assert (root / receipt.artifact_name).is_file()
    assert not (tmp_path / "escaped.v1.tidemark-evidence.json").exists()


class _WriteFailureMaterializer(PublicationMaterializer):
    def _write(self, stream, encoded):
        stream.write(encoded[: max(1, len(encoded) // 2)])
        raise OSError("controlled publication write failure")


class _DirectorySyncFailureMaterializer(PublicationMaterializer):
    def __init__(self, root_path):
        self._sync_count = 0
        super().__init__(root_path)

    def _synchronize(self, descriptor):
        self._sync_count += 1
        if self._sync_count == 2:
            raise OSError("controlled publication directory sync failure")
        return super()._synchronize(descriptor)


@pytest.mark.parametrize(
    "materializer_type",
    (_WriteFailureMaterializer, _DirectorySyncFailureMaterializer),
)
def test_materialization_failure_leaves_no_final_or_partial_artifact(
    tmp_path, materializer_type
):
    package = _package(tmp_path / "source")
    root = tmp_path / "published"

    with pytest.raises(PublicationDurabilityError):
        materializer_type(str(root)).materialize(package)

    assert not tuple(root.glob("*.json"))
    assert not tuple(root.glob(".*.tmp"))


def test_publication_is_read_only_and_appends_no_authoritative_event(tmp_path):
    fixture, events = _success(tmp_path)
    before = fixture.evidence_store.ordered_events()

    build_evidence_publication(events, _request(events))

    after = fixture.evidence_store.ordered_events()
    assert after == before
    assert all(
        event.event_type is not EvidenceEventType.EVIDENCE_EXPORT_FINALIZED
        for event in after
    )


def test_publication_surface_has_no_repair_or_source_mutation_api(tmp_path):
    package = _package(tmp_path)
    materializer = PublicationMaterializer(str(tmp_path / "published"))

    for target in (package, materializer):
        for forbidden in (
            "repair",
            "fix",
            "rewrite",
            "replace",
            "update",
            "upsert",
            "delete",
            "import_into_store",
        ):
            assert not hasattr(target, forbidden)


def test_correction_requires_a_new_export_version_and_preserves_link(tmp_path):
    fixture, events = _success(tmp_path)
    last = events[-1]
    correction = AuditEvent(
        schema_version=last.schema_version,
        event_id="event-order-15-reconciliation",
        event_type=EvidenceEventType.EVIDENCE_RECONCILED,
        occurred_at=last.occurred_at,
        sequence=last.sequence + 1,
        trace_id=last.trace_id,
        invocation_id=None,
        call_id=None,
        decision_id=None,
        prepared_call_id=None,
        execution_id=None,
        policy_version=None,
        registry_version=None,
        adapter_id=None,
        adapter_version=None,
        producer=last.producer,
        payload=EvidenceReconciledPayload(
            related_event_ids=(events[0].event_id,),
            masked_detail="reviewed-correction-link",
        ),
        previous_event_digest=fixture.evidence_store.last_event_digest(TRACE_ID),
    )
    fixture.evidence_store.append(correction)
    corrected = fixture.evidence_store.events_for_trace(TRACE_ID)

    with pytest.raises(PublicationBlockedError, match="new export version"):
        build_evidence_publication(corrected, _request(corrected))

    package = build_evidence_publication(
        corrected,
        _request(corrected, export_version=2),
    )
    primitive = json.loads(package.canonical_bytes)
    assert primitive["source"]["export_version"] == 2
    assert primitive["source"]["actual_result_counts"]["reconciliation_count"] == 1
    assert primitive["evidence"]["records"][-1]["event_type"] == "evidence.reconciled"


def test_verification_and_materialization_are_offline_only(tmp_path, monkeypatch):
    package = _package(tmp_path / "source")

    def forbid_network(self, address):
        raise AssertionError(f"Order 15 attempted network access: {address!r}")

    monkeypatch.setattr(socket.socket, "connect", forbid_network)

    assert verify_evidence_publication(package.canonical_bytes).valid is True
    PublicationMaterializer(str(tmp_path / "published")).materialize(package)
