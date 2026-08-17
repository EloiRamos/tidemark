"""W3-B tests for the five bounded, deterministic property domains."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

import pytest

from tidemark.payment.fixtures import RAW_SYNTHETIC_DESTINATION
from tidemark.verification.w3_contract import (
    PROPERTY_IDS,
    W3_D03_UNSORTED_SENTINEL_ORDINALS,
)

from w3_detectors import (
    D01_DIRECT_AUTHORITY_TAGS,
    D01_FULL_PATH_TAGS,
    D01_TAGS,
    D02_FAMILIES,
    D04_CATEGORIES,
    D05_CORRUPTION_CATEGORIES,
    DetectorStatus,
    materialize_w3_b,
    run_d01_detector,
    run_d03_detector,
    scan_w3_b_surfaces,
)
import w3_detectors


EXPECTED_COUNTS = {
    "W3-D01": 48,
    "W3-D02": 32,
    "W3-D03": 48,
    "W3-D04": 64,
    "W3-D05": 13,
}


def _source_tree_digest() -> str:
    digest = sha256()
    root = Path(__file__).resolve().parents[2] / "src" / "tidemark"
    for path in sorted(root.rglob("*.py")):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\x00")
        digest.update(path.read_bytes())
        digest.update(b"\x00")
    return digest.hexdigest()


@pytest.fixture(scope="module")
def three_materializations(tmp_path_factory):
    before = _source_tree_digest()
    root = tmp_path_factory.mktemp("w3-b-three-runs")
    runs = tuple(
        materialize_w3_b(root / f"run-{run_index}", run_index=run_index)
        for run_index in range(3)
    )
    after = _source_tree_digest()
    return runs, before, after


def _result(run, property_id):
    return next(
        result for result in run.property_results if result.property_id == property_id
    )


def test_exact_property_count_order_fingerprints_and_controls(
    three_materializations,
) -> None:
    runs, _, _ = three_materializations
    run = runs[0]

    assert run.property_count == 5
    assert run.generated_case_count == 205
    assert tuple(result.property_id for result in run.property_results) == PROPERTY_IDS
    assert tuple(
        result.generated_case_count for result in run.property_results
    ) == tuple(EXPECTED_COUNTS[property_id] for property_id in PROPERTY_IDS)
    assert all(result.control_case_count == 1 for result in run.property_results)
    assert all(result.control_passed for result in run.property_results)
    assert all(result.status is DetectorStatus.PASS for result in run.property_results)

    assert len(run.descriptors) == 205
    assert tuple(
        sum(descriptor.domain_id == property_id for descriptor in run.descriptors)
        for property_id in PROPERTY_IDS
    ) == (48, 32, 48, 64, 13)
    assert tuple(
        (descriptor.domain_id, descriptor.ordinal) for descriptor in run.descriptors
    ) == tuple(
        (property_id, ordinal)
        for property_id in PROPERTY_IDS
        for ordinal in range(EXPECTED_COUNTS[property_id])
    )
    assert all(
        descriptor.input_fingerprint.startswith("sha256:")
        and len(descriptor.input_fingerprint) == 71
        for descriptor in run.descriptors
    )
    assert len({descriptor.input_fingerprint for descriptor in run.descriptors}) == 205


def test_d01_exact_full_path_direct_authority_split_and_positive_control(
    three_materializations,
) -> None:
    run = three_materializations[0][0]
    result = _result(run, "W3-D01")

    assert D01_TAGS == (
        "NONE",
        "BOOL",
        "INT",
        "FINITE_FLOAT",
        "TEXT",
        "REFERENCE_SHAPED_TEXT",
        "RAW_PROTECTED_TEXT",
        "BYTES",
        "TUPLE",
        "LIST",
        "MAPPING",
        "REFERENCE_ID_SUBCLASS",
    )
    assert D01_FULL_PATH_TAGS == (
        "NONE",
        "BOOL",
        "INT",
        "TEXT",
        "REFERENCE_SHAPED_TEXT",
        "RAW_PROTECTED_TEXT",
    )
    assert D01_DIRECT_AUTHORITY_TAGS == (
        "FINITE_FLOAT",
        "BYTES",
        "TUPLE",
        "LIST",
        "MAPPING",
        "REFERENCE_ID_SUBCLASS",
    )
    assert result.fact("all_tags_observed") is True
    assert result.fact("full_path_denied_count") == result.fact(
        "full_path_case_count"
    )
    assert result.fact("direct_authority_false_count") == result.fact(
        "direct_authority_case_count"
    )
    assert result.fact("full_path_traversal_claim_count") == result.fact(
        "full_path_case_count"
    )
    assert result.fact("direct_full_path_traversal_claim_count") == 0
    assert result.fact("prepared_call_count") == 0
    assert result.fact("execution_attempt_count") == 0
    assert result.fact("adapter_entry_count") == 0
    assert result.fact("payment_count") == 0
    assert result.fact("positive_control_allow") is True
    assert result.fact("positive_control_prepared") is True
    assert result.status is DetectorStatus.PASS


def test_d01_permissive_test_double_is_detected(tmp_path, monkeypatch) -> None:
    original = w3_detectors._protected_reference_required

    def permissive(operand):
        return type(operand.value) is str or original(operand)

    monkeypatch.setattr(w3_detectors, "_protected_reference_required", permissive)
    result, _ = run_d01_detector(tmp_path / "permissive-d01", run_index=0)

    assert result.status is DetectorStatus.FAIL
    assert result.fact("representation_false_count") < 48


def test_d02_all_unissued_shapes_are_not_found_and_control_resolves(
    three_materializations,
) -> None:
    run = three_materializations[0][0]
    result = _result(run, "W3-D02")

    assert D02_FAMILIES == (
        "LOWERCASE_HEX_REFERENCE",
        "MIXED_CASE_HEX_REFERENCE",
        "NON_HEX_ALPHANUMERIC_REFERENCE",
        "ARBITRARY_TEXT_REFERENCE",
    )
    assert result.fact("family_counts") == (8, 8, 8, 8)
    assert result.fact("unique_unissued_count") == 32
    assert result.fact("reference_not_found_count") == 32
    assert result.fact("protected_payload_count") == 0
    assert result.fact("prepared_call_count") == 0
    assert result.fact("execution_attempt_count") == 0
    assert result.fact("adapter_entry_count") == 0
    assert result.fact("payment_count") == 0
    assert result.fact("positive_control_resolved") is True
    assert result.fact("reference_shape_is_issuance_authority") is False
    assert result.status is DetectorStatus.PASS


def test_d03_canonical_round_trip_and_all_unsorted_sentinels(
    three_materializations,
) -> None:
    run = three_materializations[0][0]
    result = _result(run, "W3-D03")

    assert result.fact("valid_utf8_json_count") == 48
    assert result.fact("newline_false_count") == 24
    assert result.fact("newline_true_count") == 24
    assert result.fact("parse_reserialize_identity_count") == 48
    assert result.fact("second_serialization_identity_count") == 48
    assert result.fact("sentinel_ordinals") == W3_D03_UNSORTED_SENTINEL_ORDINALS
    assert result.fact("sentinel_count") == 4
    assert result.fact("sentinel_widths_valid_count") == 4
    assert result.fact("sentinel_insertion_unsorted_count") == 4
    assert result.fact("sentinel_independent_sorted_bytes_count") == 4
    assert result.fact("positive_control_passed") is True
    assert result.status is DetectorStatus.PASS


def test_d03_sort_disabled_test_double_is_detected(monkeypatch) -> None:
    def sort_disabled(value, *, trailing_newline=False):
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=False,
        ).encode("utf-8")
        return encoded + (b"\n" if trailing_newline else b"")

    monkeypatch.setattr(w3_detectors, "canonical_json_bytes", sort_disabled)
    result, _ = run_d03_detector()

    assert result.status is DetectorStatus.FAIL
    assert result.fact("sentinel_independent_sorted_bytes_count") < 4


def test_d04_safe_display_categories_projection_control_and_shared_scanner(
    three_materializations,
) -> None:
    run = three_materializations[0][0]
    result = _result(run, "W3-D04")

    assert D04_CATEGORIES == (
        "CURRENT_SAFE_LITERAL",
        "STAR_MASKED_TEXT",
        "VALID_SHA256",
        "REFERENCE_TOKEN_OR_PREFIX",
        "RAW_PROTECTED_SENTINEL",
        "HTML_OR_SCRIPT_LIKE_TEXT",
        "CONTROL_OR_UNICODE_TEXT",
        "INVALID_SHA256_LOOKALIKE_OR_ARBITRARY_TEXT",
    )
    assert result.fact("category_counts") == (8, 8, 8, 8, 8, 8, 8, 8)
    assert result.fact("expected_unchanged_count") == 24
    assert result.fact("expected_masked_count") == 40
    assert result.fact("safe_display_match_count") == 64
    assert result.fact("unsafe_returned_unchanged_count") == 0
    assert result.fact("projection_integration_control_passed") is True
    scan = scan_w3_b_surfaces(run)
    assert scan.pass_all is True
    assert scan.secret_scan_pass is True
    assert scan.protected_data_scan_pass is True
    assert scan.absolute_path_scan_pass is True
    assert result.status is DetectorStatus.PASS


def test_d05_all_thirteen_corruptions_preserve_semantics_and_never_clean_success(
    three_materializations,
) -> None:
    run = three_materializations[0][0]
    result = _result(run, "W3-D05")

    assert D05_CORRUPTION_CATEGORIES == (
        "DELETE",
        "DUPLICATE_IDENTITY",
        "DUPLICATE_SEMANTIC_WITH_FRESH_ID",
    )
    assert result.fact("corruption_category_counts") == (5, 5, 3)
    assert result.fact("normalized_corruption_count") == 13
    assert result.fact("contiguous_sequence_count") == 13
    assert result.fact("all_previous_digest_none_count") == 13
    assert result.fact("selected_semantics_preserved_count") == 13
    assert result.fact("source_events_mutated_count") == 0
    assert result.fact("clean_success_count") == 0
    assert result.fact("positive_control_clean_success") is True
    assert result.status is DetectorStatus.PASS


def test_three_consecutive_materializations_are_byte_identical(
    three_materializations,
) -> None:
    runs, _, _ = three_materializations

    assert tuple(run.generated_case_count for run in runs) == (205, 205, 205)
    assert tuple(run.property_count for run in runs) == (5, 5, 5)
    assert all(run.controls_pass for run in runs)
    assert all(run.properties_pass for run in runs)
    assert len({run.descriptor_bytes for run in runs}) == 1
    assert len({run.domain_digests for run in runs}) == 1
    assert len({run.property_result_bytes for run in runs}) == 1


def test_safe_observations_exclude_raw_reference_private_and_path_data(
    three_materializations,
) -> None:
    run = three_materializations[0][0]
    public = run.descriptor_bytes + b"\n" + run.property_result_bytes

    assert RAW_SYNTHETIC_DESTINATION.encode("utf-8") not in public
    assert b"synthetic-routing://" not in public
    assert b"ref_" not in public
    assert b"RuntimePrivateExecutionBinding" not in public
    assert str(Path.cwd()).encode("utf-8") not in public


def test_materialization_does_not_change_the_source_tree(
    three_materializations,
) -> None:
    _, before, after = three_materializations
    assert after == before
