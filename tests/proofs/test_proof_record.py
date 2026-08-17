from dataclasses import FrozenInstanceError, replace
import json

import pytest

from tidemark.evidence.canonical import canonical_json_bytes
from tidemark.proofs.catalogue import PROOF_CATALOGUE
from tidemark.proofs.model import (
    PROOF_SUITE_KIND,
    PROOF_SUITE_SCHEMA,
    ProofInfrastructureErrorCode,
    ProofProvenance,
    ProofRecordError,
    ProofRunOutcome,
    ProofRunResult,
    ProofStatus,
    adjudicate_suite,
    parse_proof_suite,
    proof_suite_to_primitive,
    serialize_proof_suite,
    verify_proof_suite_bytes,
)


REVISION = "a" * 40


def _expected_observations():
    return tuple(
        (
            item.property_id,
            tuple(fixture.expected_observation for fixture in item.fixtures),
        )
        for item in PROOF_CATALOGUE
    )


def _suite(observations=None):
    return adjudicate_suite(
        catalogue=PROOF_CATALOGUE,
        selected_property_ids=tuple(item.property_id for item in PROOF_CATALOGUE),
        observed_by_property=observations or _expected_observations(),
        provenance=ProofProvenance(
            provenance_class="CLEAN_COMMITTED_LOCAL_SOURCE",
            source_revision=REVISION,
            live_model_calls_performed=0,
            google_cloud_accessed=False,
        ),
    )


def test_completed_suite_model_is_frozen_closed_and_passes_exact_observations():
    result = _suite()

    assert PROOF_SUITE_SCHEMA == "tidemark.security-proof-suite.v1"
    assert PROOF_SUITE_KIND == "TIDEMARK_SECURITY_PROPERTY_PROOF_SUITE"
    assert result.suite_status is ProofStatus.PASS
    assert result.catalogue_property_count == 8
    assert result.executed_property_count == 8
    assert all(item.proof_status is ProofStatus.PASS for item in result.properties)
    assert all(case.case_status is ProofStatus.PASS for item in result.properties for case in item.cases)
    with pytest.raises(FrozenInstanceError):
        result.suite_status = ProofStatus.FAIL


def test_complete_observation_mismatch_cascades_case_property_and_suite_fail():
    observed = list(_expected_observations())
    property_id, cases = observed[0]
    changed = replace(cases[0], authoritative_side_effect_count=99)
    observed[0] = (property_id, (changed, *cases[1:]))

    result = _suite(tuple(observed))

    assert result.properties[0].cases[0].case_status is ProofStatus.FAIL
    assert result.properties[0].proof_status is ProofStatus.FAIL
    assert result.suite_status is ProofStatus.FAIL
    assert all(item.proof_status is ProofStatus.PASS for item in result.properties[1:])


def test_infrastructure_error_is_discriminated_and_cannot_serialize_a_suite():
    run = ProofRunResult.error(ProofInfrastructureErrorCode.EXECUTION_ERROR)

    assert run.outcome is ProofRunOutcome.ERROR
    assert run.suite_result is None
    assert run.infrastructure_error is ProofInfrastructureErrorCode.EXECUTION_ERROR
    with pytest.raises((TypeError, ProofRecordError)):
        serialize_proof_suite(run)

    completed = ProofRunResult.completed(_suite())
    assert completed.outcome is ProofRunOutcome.COMPLETED
    assert completed.suite_result is not None
    assert completed.infrastructure_error is None


def test_canonical_round_trip_verifies_both_digest_levels_and_one_newline():
    result = _suite()
    encoded = serialize_proof_suite(result)

    assert encoded.endswith(b"\n")
    assert not encoded.endswith(b"\n\n")
    assert encoded == canonical_json_bytes(
        proof_suite_to_primitive(result), trailing_newline=True
    )
    assert parse_proof_suite(encoded) == result
    assert verify_proof_suite_bytes(encoded) is True
    assert all(
        item.observation_digest.startswith("sha256:")
        and len(item.observation_digest) == 71
        for item in result.properties
    )
    assert result.suite_digest.startswith("sha256:")
    assert len(result.suite_digest) == 71


@pytest.mark.parametrize(
    "mutator",
    (
        lambda encoded: encoded[:-1],
        lambda encoded: encoded + b"\n",
        lambda encoded: encoded.replace(b'"suite_status":"PASS"', b'"suite_status":"FAIL"', 1),
        lambda encoded: encoded.replace(b'"executed_property_count":8', b'"executed_property_count":true', 1),
        lambda encoded: encoded.replace(b'"decision_outcome":"ALLOW"', b'"decision_outcome":"UNKNOWN"', 1),
    ),
)
def test_parser_rejects_noncanonical_tampered_invalid_enum_or_invalid_type(mutator):
    with pytest.raises(ProofRecordError):
        parse_proof_suite(mutator(serialize_proof_suite(_suite())))


def test_parser_rejects_duplicate_unknown_and_missing_keys():
    encoded = serialize_proof_suite(_suite())
    text = encoded.decode("utf-8")
    duplicate = (
        '{"schema_version":"tidemark.security-proof-suite.v1",'
        + text[1:]
    ).encode("utf-8")
    with pytest.raises(ProofRecordError):
        parse_proof_suite(duplicate)

    primitive = json.loads(text)
    primitive["unknown"] = False
    with pytest.raises(ProofRecordError):
        parse_proof_suite(canonical_json_bytes(primitive, trailing_newline=True))

    primitive = json.loads(text)
    del primitive["selection"]
    with pytest.raises(ProofRecordError):
        parse_proof_suite(canonical_json_bytes(primitive, trailing_newline=True))

    primitive = json.loads(text)
    primitive["properties"][0]["cases"][0]["fixture_id"] = True
    with pytest.raises(ProofRecordError):
        parse_proof_suite(canonical_json_bytes(primitive, trailing_newline=True))


def test_model_repr_and_serialized_bytes_exclude_forbidden_dynamic_material():
    result = _suite()
    encoded = serialize_proof_suite(result)
    public = repr(result).encode("utf-8") + encoded
    forbidden = (
        b"synthetic-routing://beneficiary/order-9/4242",
        b"ref_",
        b"_payload_authenticator",
        b"private execution binding",
        b"/tmp/",
        b"/Users/",
        b"prompt",
        b"provider",
        b"cloud_project",
        b"timestamp",
    )
    assert all(value not in public for value in forbidden)
