from dataclasses import fields, replace

import pytest

from tidemark.evidence.mechanism_projection import (
    ClaimProvenance,
    LIFECYCLE_MODEL_VERSION,
    MECHANISM_PROJECTION_SCHEMA_VERSION,
    LifecycleStageId,
    LifecycleState,
    LifecycleStageFact,
    LifecycleTerminalFact,
    PreparedArgumentMetadata,
    PreparedCallMechanismProjection,
    PreparedCallPublicSnapshot,
    PreparedCallSealFact,
    ProposalMechanismFact,
    ProtectedArgumentMechanismFact,
    W2ProofReference,
    build_mechanism_projection,
    capture_prepared_call_public_snapshot,
    mechanism_projection_to_primitive,
)
from tidemark.evidence.projection import EvidenceProjector
from tidemark.demo import DeterministicDemoHarness
from tidemark.payment.fixtures import (
    RAW_SYNTHETIC_DESTINATION,
    build_synthetic_payment_fixture,
)
from tidemark.runtime.identifiers import ReferenceId, TypeId
from tidemark.runtime.prepared_call import PreparedToolCall
from tidemark.runtime.vocabulary import ArgumentRole
from tidemark.ui.run_summary import ScenarioId


def test_exact_closed_schema_has_the_frozen_public_fields():
    assert MECHANISM_PROJECTION_SCHEMA_VERSION == (
        "tidemark.prepared-call-mechanism-projection.v1"
    )
    assert LIFECYCLE_MODEL_VERSION == "tidemark.prepared-call-lifecycle.v1"

    assert tuple(field.name for field in fields(PreparedCallPublicSnapshot)) == (
        "prepared_call_id",
        "public_integrity_id",
        "tool_id",
        "policy_version",
        "registry_version",
        "adapter_id",
        "adapter_version",
        "arguments",
    )
    assert tuple(field.name for field in fields(PreparedArgumentMetadata)) == (
        "name",
        "type_id",
        "role",
    )
    assert tuple(field.name for field in fields(PreparedCallMechanismProjection)) == (
        "schema_version",
        "lifecycle_model_version",
        "proposal",
        "protected_arguments",
        "stages",
        "seal",
        "terminal",
        "proof_references",
    )
    assert tuple(field.name for field in fields(ProposalMechanismFact)) == (
        "candidate_state",
        "tool_id",
        "proposed_form",
        "provenance",
    )
    assert tuple(field.name for field in fields(ProtectedArgumentMechanismFact)) == (
        "name",
        "role",
        "supported_type",
        "resolution_state",
        "binding_state",
        "runtime_value_state",
    )
    assert tuple(field.name for field in fields(LifecycleStageFact)) == (
        "stage_id",
        "ordinal",
        "title",
        "trust_zone",
        "state",
        "fact_provenance",
        "safe_summary",
        "w2_property_ids",
    )
    assert tuple(field.name for field in fields(PreparedCallSealFact)) == (
        "prepared_call_present",
        "public_prepared_call_id",
        "public_integrity_id",
        "adapter_id",
        "adapter_version",
        "argument_metadata",
        "private_binding_state",
        "payload_binding_state",
        "correlation_binding_state",
        "adapter_binding_state",
        "single_use_target_state",
        "object_binding_state",
        "private_material_projected",
    )
    assert tuple(field.name for field in fields(LifecycleTerminalFact)) == (
        "decision",
        "primary_rule_id",
        "execution_status",
        "execution_start_count",
        "authoritative_synthetic_payment_count",
        "replay_state",
        "external_result_confirmed",
        "evidence_completeness",
        "integrity_status",
        "reconciliation_status",
    )
    assert tuple(field.name for field in fields(W2ProofReference)) == (
        "property_id",
        "property_title",
        "catalogue_version",
        "reviewer_hint",
        "ui_execution_status",
        "qualifier",
    )


def test_safe_snapshot_captures_only_allowlisted_public_prepared_call_metadata(
    tmp_path,
):
    fixture = build_synthetic_payment_fixture(
        str(tmp_path), correlation_namespace="w1b-public-snapshot"
    )
    prepared = fixture.prepare(fixture.canonical_call())

    assert type(prepared) is PreparedToolCall
    snapshot = capture_prepared_call_public_snapshot(prepared)

    assert snapshot.prepared_call_id == prepared.prepared_call_id
    assert snapshot.public_integrity_id == prepared.integrity_id
    assert snapshot.tool_id == prepared.tool_id
    assert snapshot.policy_version == prepared.policy_version
    assert snapshot.registry_version == prepared.registry_version
    assert snapshot.adapter_id == prepared.adapter_id
    assert snapshot.adapter_version == prepared.adapter_version
    assert tuple(item.name for item in snapshot.arguments) == (
        "amount_minor",
        "currency",
        "destination_reference",
    )
    assert RAW_SYNTHETIC_DESTINATION not in repr(snapshot)
    assert fixture.destination_reference.value not in repr(snapshot)


def test_safe_snapshot_rejects_subclasses_before_reading_any_public_field():
    class PreparedToolCallSubclass(PreparedToolCall):
        pass

    with pytest.raises(TypeError, match="exact PreparedToolCall"):
        capture_prepared_call_public_snapshot(
            object.__new__(PreparedToolCallSubclass)
        )


def test_projection_maps_prepared_allow_to_the_exact_lifecycle_and_w2_catalogue(
    tmp_path,
):
    fixture = build_synthetic_payment_fixture(
        str(tmp_path), correlation_namespace="w1b-projection-allow"
    )
    prepared = fixture.prepare(fixture.canonical_call())

    assert type(prepared) is PreparedToolCall
    snapshot = capture_prepared_call_public_snapshot(prepared)
    fixture.execution_gate.execute(prepared)
    review = EvidenceProjector().project(fixture.evidence_store.ordered_events())
    projection = build_mechanism_projection(snapshot, review)

    assert projection.seal.prepared_call_present is True
    assert projection.seal.public_prepared_call_id == snapshot.prepared_call_id
    assert projection.seal.public_integrity_id == snapshot.public_integrity_id
    assert projection.seal.private_material_projected is False
    assert tuple(item.name for item in projection.protected_arguments) == (
        "destination_reference",
    )
    assert projection.protected_arguments[0].role is ArgumentRole.PROTECTED_REFERENCE
    assert tuple(
        (item.stage_id, item.ordinal, item.title, item.w2_property_ids)
        for item in projection.stages
    ) == (
        (LifecycleStageId.W1_L01, 1, "UNTRUSTED PROPOSAL", ("W2-P01", "W2-P08")),
        (LifecycleStageId.W1_L02, 2, "PROTECTED-ROLE RECOGNITION", ("W2-P01",)),
        (LifecycleStageId.W1_L03, 3, "TRUSTED HANDLE SELECTION", ("W2-P01",)),
        (LifecycleStageId.W1_L04, 4, "RUNTIME RESOLUTION", ("W2-P07",)),
        (LifecycleStageId.W1_L05, 5, "TRUSTED VALUE BINDING", ("W2-P07",)),
        (LifecycleStageId.W1_L06, 6, "DETERMINISTIC POLICY EVALUATION", ("W2-P01", "W2-P07")),
        (LifecycleStageId.W1_L07, 7, "PREPARED-CALL SEALING", ("W2-P06",)),
        (LifecycleStageId.W1_L08, 8, "EXECUTION-TIME REVALIDATION", ("W2-P02", "W2-P04", "W2-P05", "W2-P06")),
        (LifecycleStageId.W1_L09, 9, "EVIDENCE BEFORE EFFECT", ("W2-P03",)),
        (LifecycleStageId.W1_L10, 10, "EFFECT / REFUSAL / REPLAY EVIDENCE", ("W2-P02", "W2-P04", "W2-P05", "W2-P08")),
    )
    assert projection.stages[7].state is LifecycleState.SATISFIED
    assert projection.stages[7].fact_provenance is ClaimProvenance.DERIVED_IMPLEMENTED_CONTRACT
    assert projection.stages[8].state is LifecycleState.SATISFIED
    assert projection.stages[8].fact_provenance is ClaimProvenance.DERIVED_IMPLEMENTED_CONTRACT
    assert tuple(item.property_id for item in projection.proof_references) == (
        "W2-P01",
        "W2-P02",
        "W2-P03",
        "W2-P04",
        "W2-P05",
        "W2-P06",
        "W2-P07",
        "W2-P08",
    )
    assert projection.proof_references[4].qualifier == (
        "Fixed 12 attempts/six-worker local proof; local at-most-once only, "
        "with no distributed exactly-once claim."
    )
    assert projection.proof_references[7].qualifier == (
        "Proof PASS means uncertainty was preserved; it is not evidence PASS, "
        "execution success, or external-effect absence."
    )


def _allowed_projection(tmp_path, namespace="w1b-closed-projection"):
    fixture = build_synthetic_payment_fixture(
        str(tmp_path), correlation_namespace=namespace
    )
    prepared = fixture.prepare(fixture.canonical_call())
    assert type(prepared) is PreparedToolCall
    snapshot = capture_prepared_call_public_snapshot(prepared)
    fixture.execution_gate.execute(prepared)
    review = EvidenceProjector().project(fixture.evidence_store.ordered_events())
    return snapshot, review, build_mechanism_projection(snapshot, review)


def test_closed_construction_rejects_invalid_digest_enums_private_material_and_terminal_counts(
    tmp_path,
):
    snapshot, _, projection = _allowed_projection(tmp_path)

    with pytest.raises(ValueError, match="lowercase sha256"):
        replace(snapshot, public_integrity_id="sha256:" + "A" * 64)
    with pytest.raises(TypeError, match="candidate_state"):
        replace(projection.proposal, candidate_state="UNKNOWN")
    with pytest.raises(TypeError, match="fact_provenance"):
        replace(projection.stages[0], fact_provenance="UNTRUSTED")
    with pytest.raises(ValueError, match="lifecycle stage metadata"):
        replace(projection.stages[0], title="UNREVIEWED LIFECYCLE TITLE")
    with pytest.raises(ValueError, match="private_material_projected"):
        replace(projection.seal, private_material_projected=True)
    with pytest.raises(ValueError, match="execution_start_count"):
        replace(projection.terminal, execution_start_count=-1)


def test_closed_construction_rejects_unknown_missing_duplicate_reordered_and_extra_stages(
    tmp_path,
):
    _, _, projection = _allowed_projection(tmp_path)
    stages = projection.stages

    with pytest.raises(TypeError, match="stage_id"):
        replace(stages[0], stage_id="W1-L11")
    with pytest.raises(ValueError, match="exact ordered W1 contract"):
        replace(projection, stages=stages[:-1])
    with pytest.raises(ValueError, match="exact ordered W1 contract"):
        replace(projection, stages=(stages[0],) + stages)
    with pytest.raises(ValueError, match="exact ordered W1 contract"):
        replace(projection, stages=(stages[1], stages[0]) + stages[2:])
    with pytest.raises(ValueError, match="exact ordered W1 contract"):
        replace(projection, stages=stages + (stages[-1],))


def test_closed_construction_rejects_unknown_duplicate_and_mismatched_w2_references(
    tmp_path,
):
    _, _, projection = _allowed_projection(tmp_path)
    reference = projection.proof_references[0]

    with pytest.raises(ValueError, match="closed W2 catalogue"):
        replace(reference, property_id="W2-P09")
    with pytest.raises(ValueError, match="property_title"):
        replace(reference, property_title="Wrong W2 title")
    with pytest.raises(ValueError, match="catalogue_version"):
        replace(reference, catalogue_version="tidemark.security-proof-catalogue.v9")
    with pytest.raises(ValueError, match="exact ordered W2 contract"):
        replace(
            projection,
            proof_references=projection.proof_references + (reference,),
        )


def test_safe_primitive_and_repr_exclude_raw_reference_path_and_html_sentinels(
    tmp_path,
):
    raw_sentinel = RAW_SYNTHETIC_DESTINATION
    path_sentinel = "/tmp/w1b-projection-do-not-render"
    html_sentinel = "<script>w1b-projection-do-not-render</script>"
    fixture = build_synthetic_payment_fixture(
        str(tmp_path), correlation_namespace="w1b-leakage"
    )
    prepared = fixture.prepare(fixture.canonical_call())

    assert type(prepared) is PreparedToolCall
    snapshot = capture_prepared_call_public_snapshot(prepared)
    fixture.execution_gate.execute(prepared)
    review = EvidenceProjector().project(fixture.evidence_store.ordered_events())
    projection = build_mechanism_projection(
        snapshot,
        replace(review, trace_id=path_sentinel + html_sentinel),
    )
    public = repr(projection) + repr(mechanism_projection_to_primitive(projection))

    for forbidden in (
        raw_sentinel,
        fixture.destination_reference.value,
        path_sentinel,
        html_sentinel,
    ):
        assert forbidden not in public
    assert snapshot.public_integrity_id in public
    assert snapshot.prepared_call_id.value in public


def test_synthetic_multiple_protected_metadata_preserves_order_without_values_or_tokens(
    tmp_path,
):
    raw_sentinel = "synthetic-routing://w1b-multiple-protected"
    reference_sentinel = "ref_w1b_multiple_protected_token"
    real_snapshot, review, _ = _allowed_projection(
        tmp_path, "w1b-synthetic-multiple"
    )
    snapshot = PreparedCallPublicSnapshot(
        prepared_call_id=real_snapshot.prepared_call_id,
        public_integrity_id="sha256:" + "1" * 64,
        tool_id=real_snapshot.tool_id,
        policy_version=real_snapshot.policy_version,
        registry_version=real_snapshot.registry_version,
        adapter_id=real_snapshot.adapter_id,
        adapter_version=real_snapshot.adapter_version,
        arguments=(
            PreparedArgumentMetadata(
                name="destination_reference",
                type_id=TypeId("payment_destination"),
                role=ArgumentRole.PROTECTED_REFERENCE,
            ),
            PreparedArgumentMetadata(
                name="currency",
                type_id=TypeId("currency_code"),
                role=ArgumentRole.PROTECTED_REFERENCE,
            ),
        ),
    )
    projection = build_mechanism_projection(snapshot, review)

    assert tuple(item.name for item in projection.seal.argument_metadata) == (
        "destination_reference",
        "currency",
    )
    public = repr(projection) + repr(mechanism_projection_to_primitive(projection))
    assert raw_sentinel not in public
    assert reference_sentinel not in public


def test_identical_safe_inputs_are_equal_and_fresh_correlations_have_the_same_semantics(
    tmp_path,
):
    first_snapshot, first_review, first = _allowed_projection(
        tmp_path / "first", "w1b-determinism-one"
    )
    same = build_mechanism_projection(first_snapshot, first_review)
    second_snapshot, _, second = _allowed_projection(
        tmp_path / "second", "w1b-determinism-two"
    )

    assert same == first
    assert mechanism_projection_to_primitive(same) == mechanism_projection_to_primitive(first)
    assert first_snapshot.prepared_call_id != second_snapshot.prepared_call_id
    assert first_snapshot.public_integrity_id != second_snapshot.public_integrity_id
    assert _normalized_semantic_signature(first) == _normalized_semantic_signature(second)


def test_exact_scenario_mappings_remain_truthful_without_a_seventh_scenario(tmp_path):
    allow_snapshot, _, allow = _allowed_projection(tmp_path / "allow", "w1b-map-allow")

    raw_fixture = build_synthetic_payment_fixture(
        str(tmp_path / "raw"), correlation_namespace="w1b-map-raw"
    )
    raw_fixture.prepare(
        raw_fixture.canonical_call(destination_reference=RAW_SYNTHETIC_DESTINATION)
    )
    raw = build_mechanism_projection(
        None, EvidenceProjector().project(raw_fixture.evidence_store.ordered_events())
    )

    forged_fixture = build_synthetic_payment_fixture(
        str(tmp_path / "forged"), correlation_namespace="w1b-map-forged"
    )
    forged_fixture.prepare(
        forged_fixture.canonical_call(
            destination_reference=ReferenceId("ref_w1b_forged_unknown")
        )
    )
    forged = build_mechanism_projection(
        None, EvidenceProjector().project(forged_fixture.evidence_store.ordered_events())
    )

    bound_fixture = build_synthetic_payment_fixture(
        str(tmp_path / "bound"), correlation_namespace="w1b-map-bound"
    )
    bound_fixture.prepare(
        bound_fixture.canonical_call(
            amount_minor=bound_fixture.purchase_order.maximum_amount_minor + 1
        )
    )
    bound = build_mechanism_projection(
        None, EvidenceProjector().project(bound_fixture.evidence_store.ordered_events())
    )

    replay_fixture = build_synthetic_payment_fixture(
        str(tmp_path / "replay"), correlation_namespace="w1b-map-replay"
    )
    replay_prepared = replay_fixture.prepare(replay_fixture.canonical_call())
    assert type(replay_prepared) is PreparedToolCall
    replay_snapshot = capture_prepared_call_public_snapshot(replay_prepared)
    replay_fixture.execution_gate.execute(replay_prepared)
    replay_fixture.execution_gate.execute(replay_prepared)
    replay = build_mechanism_projection(
        replay_snapshot,
        EvidenceProjector().project(replay_fixture.evidence_store.ordered_events()),
    )

    model = next(
        item
        for item in DeterministicDemoHarness(run_seed="w1b-map-model").run().scenarios
        if item.scenario_id is ScenarioId.MODEL_NON_ATTEMPT
    )
    non_attempt = build_mechanism_projection(None, model.projection)

    assert len((allow, raw, forged, bound, replay, non_attempt)) == 6
    assert allow.seal.prepared_call_present is True
    assert allow.stages[6].state is LifecycleState.SATISFIED
    assert raw.proposal.proposed_form.value == "RAW_PROTECTED_VALUE_REDACTED"
    assert raw.stages[2].state is LifecycleState.FAILED
    assert raw.stages[3].state is LifecycleState.NOT_REACHED
    assert raw.seal.prepared_call_present is False
    assert forged.stages[3].state is LifecycleState.FAILED
    assert forged.seal.prepared_call_present is False
    assert bound.stages[3].state is LifecycleState.SATISFIED
    assert bound.stages[4].state is LifecycleState.SATISFIED
    assert bound.stages[5].state is LifecycleState.DENIED
    assert bound.seal.prepared_call_present is False
    assert replay.stages[7].state is LifecycleState.REPLAY_REJECTED
    assert replay.stages[9].state is LifecycleState.REPLAY_REJECTED
    assert replay.terminal.execution_start_count == 1
    assert replay.terminal.authoritative_synthetic_payment_count == 1
    assert non_attempt.proposal.candidate_state.value == "MODEL_NON_ATTEMPT"
    assert non_attempt.seal.prepared_call_present is False
    assert non_attempt.stages[0].state is LifecycleState.NOT_APPLICABLE
    assert non_attempt.stages[9].state is LifecycleState.NOT_APPLICABLE
    assert allow_snapshot.public_integrity_id == allow.seal.public_integrity_id


def _normalized_semantic_signature(projection):
    return (
        projection.schema_version,
        projection.lifecycle_model_version,
        projection.proposal.candidate_state,
        projection.proposal.proposed_form,
        tuple(
            (
                item.name,
                item.role,
                item.supported_type,
                item.resolution_state,
                item.binding_state,
                item.runtime_value_state,
            )
            for item in projection.protected_arguments
        ),
        tuple(
            (item.stage_id, item.state, item.fact_provenance, item.w2_property_ids)
            for item in projection.stages
        ),
        projection.terminal,
        tuple(
            (item.property_id, item.property_title, item.catalogue_version, item.qualifier)
            for item in projection.proof_references
        ),
    )
