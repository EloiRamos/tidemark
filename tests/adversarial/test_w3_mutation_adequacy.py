"""W3-C tests for the closed mutation catalogue and adequacy semantics."""

from __future__ import annotations

from dataclasses import replace

import pytest

from tidemark.verification.w3_contract import (
    MUTANT_CATALOGUE,
    MUTANT_IDS,
    NOT_APPLICABLE_ALLOWED,
    MutantResult,
    OverallStatus,
    adjudicate_mutants,
)

from w3_mutants import (
    CHILD_RESULT_KEYS,
    CHILD_RESULT_SCHEMA,
    MUTATION_SPECS,
    ChildFaultMode,
    MutationHarnessError,
    parse_child_result,
    run_mutant_by_id,
    run_mutation_catalogue,
    serialize_child_result,
    serialize_mutation_run,
)


EXPECTED_DETECTORS = (
    ("W3-DET-D01-EXACT-REPRESENTATION",),
    ("W3-DET-D02-UNISSUED-NOT-TRUSTED",),
    ("W3-DET-D03-CANONICAL-ROUND-TRIP",),
    ("W3-DET-D04-SAFE-DISPLAY-CLOSED",),
    ("W3-DET-D04-SAFE-DISPLAY-CLOSED",),
    ("W3-DET-D04-SAFE-DISPLAY-CLOSED",),
    ("W2-P03-C02-PRE-EXECUTION-APPEND-FAILURE",),
    (
        "W2-P04-C01-SEQUENTIAL-REPLAY",
        "W2-P05-C01-CONCURRENT-REPLAY",
    ),
    ("W3-DET-D05-CORRUPTION-NOT-CLEAN-SUCCESS",),
    (
        "W2-P08-C01-MISSING-TERMINAL-EVIDENCE",
        "W2-P08-C02-CONFLICTING-TERMINAL-EVIDENCE",
        "W2-P08-C03-AMBIGUOUS-EXTERNAL-RESULT",
    ),
    ("W3-DET-CON-001-MINIMUM-STALE-CONSUME",),
    ("W3-DET-CON-002-MINIMUM-NONDURABLE-RECEIPT",),
)


@pytest.fixture(scope="module")
def catalogue_run():
    return run_mutation_catalogue(timeout_seconds=10.0)


def test_catalogue_ids_categories_order_and_detector_mapping_are_exact() -> None:
    assert tuple(spec.mutant_id for spec in MUTATION_SPECS) == MUTANT_IDS
    assert tuple(spec.category for spec in MUTATION_SPECS) == tuple(
        mutant.category for mutant in MUTANT_CATALOGUE
    )
    assert tuple(spec.detector_ids for spec in MUTATION_SPECS) == EXPECTED_DETECTORS
    assert len(MUTATION_SPECS) == 12
    assert all(spec.expected_result is MutantResult.KILLED for spec in MUTATION_SPECS)
    assert all(not hasattr(spec, "patch_target") for spec in MUTATION_SPECS)


def test_full_catalogue_uses_twelve_fresh_serial_children(catalogue_run) -> None:
    assert catalogue_run.child_process_count == 12
    assert catalogue_run.executed_serially is True
    assert catalogue_run.maximum_concurrent_children == 1
    assert tuple(item.mutant_id for item in catalogue_run.outcomes) == MUTANT_IDS
    assert len({item.child_instance_token for item in catalogue_run.outcomes}) == 12
    assert all(item.child_started for item in catalogue_run.outcomes)


def test_all_fixed_mutants_activate_and_are_killed(catalogue_run) -> None:
    assert catalogue_run.killed_count == 12
    assert catalogue_run.survived_count == 0
    assert catalogue_run.invalid_count == 0
    assert catalogue_run.overall_status is OverallStatus.PASS
    assert all(
        outcome.child_result.activation_probe_passed is True
        for outcome in catalogue_run.outcomes
    )
    assert all(
        outcome.child_result.result is MutantResult.KILLED
        for outcome in catalogue_run.outcomes
    )
    assert all(outcome.source_hashes_unchanged for outcome in catalogue_run.outcomes)


def test_child_result_schema_is_closed_canonical_and_digest_verified(
    catalogue_run,
) -> None:
    assert CHILD_RESULT_SCHEMA == "tidemark.w3.mutant-child-result.v1"
    assert CHILD_RESULT_KEYS == (
        "schema_version",
        "mutant_id",
        "activation_probe_passed",
        "detector_ids",
        "result",
        "safe_finding_candidate_id",
        "observation_digest",
    )
    for outcome in catalogue_run.outcomes:
        encoded = outcome.child_result_bytes
        assert not encoded.endswith(b"\n")
        assert serialize_child_result(outcome.child_result) == encoded
        assert parse_child_result(encoded) == outcome.child_result


def test_child_result_parser_rejects_missing_extra_duplicate_and_digest_drift(
    catalogue_run,
) -> None:
    result = catalogue_run.outcomes[0].child_result
    encoded = serialize_child_result(result)

    missing = encoded.replace(b'"schema_version":', b'"removed_schema_version":', 1)
    with pytest.raises(MutationHarnessError):
        parse_child_result(missing)

    extra = encoded[:-1] + b',"unexpected":false}'
    with pytest.raises(MutationHarnessError):
        parse_child_result(extra)

    duplicate = encoded.replace(
        b'{"activation_probe_passed":',
        b'{"activation_probe_passed":true,"activation_probe_passed":',
        1,
    )
    with pytest.raises(MutationHarnessError):
        parse_child_result(duplicate)

    drifted = replace(result, observation_digest="sha256:" + ("0" * 64))
    with pytest.raises(MutationHarnessError):
        serialize_child_result(drifted)


def test_unknown_mutant_id_rejects_without_starting_a_child() -> None:
    with pytest.raises(MutationHarnessError, match="unknown_mutant_id"):
        run_mutant_by_id("W3-MUT-UNKNOWN-999")


@pytest.mark.parametrize(
    "fault_mode",
    (
        ChildFaultMode.INACTIVE,
        ChildFaultMode.CRASH,
        ChildFaultMode.MALFORMED_RESULT,
    ),
)
def test_inactive_crash_and_malformed_child_are_invalid(fault_mode) -> None:
    outcome = run_mutant_by_id(
        MUTANT_IDS[0],
        timeout_seconds=2.0,
        fault_mode=fault_mode,
    )
    assert outcome.child_result.result is MutantResult.INVALID
    assert outcome.source_hashes_unchanged is True


def test_timeout_is_invalid_and_does_not_expose_child_output() -> None:
    outcome = run_mutant_by_id(
        MUTANT_IDS[0],
        timeout_seconds=0.05,
        fault_mode=ChildFaultMode.TIMEOUT,
    )
    assert outcome.child_result.result is MutantResult.INVALID
    assert outcome.child_result.activation_probe_passed is False
    assert outcome.child_result.safe_finding_candidate_id is None
    assert outcome.source_hashes_unchanged is True


def test_intentional_survivor_is_visible_and_overall_fail() -> None:
    outcome = run_mutant_by_id(
        MUTANT_IDS[0], fault_mode=ChildFaultMode.SURVIVE
    )
    assert outcome.child_result.activation_probe_passed is True
    assert outcome.child_result.result is MutantResult.SURVIVED
    assert outcome.child_result.safe_finding_candidate_id == "W3-FIND-REP-001"

    adjudication = adjudicate_mutants(
        (MutantResult.KILLED,) * 11 + (MutantResult.SURVIVED,)
    )
    assert adjudication.valid_mutants == 12
    assert adjudication.overall_status is OverallStatus.FAIL


def test_intentional_invalid_is_excluded_from_denominator_and_overall_error() -> None:
    adjudication = adjudicate_mutants(
        (MutantResult.KILLED,) * 11 + (MutantResult.INVALID,)
    )
    assert adjudication.valid_mutants == 11
    assert adjudication.adequacy_denominator == 11
    assert adjudication.overall_status is OverallStatus.ERROR


def test_all_killed_probe_is_pass_and_not_applicable_is_absent() -> None:
    adjudication = adjudicate_mutants((MutantResult.KILLED,) * 12)
    assert adjudication.overall_status is OverallStatus.PASS
    assert NOT_APPLICABLE_ALLOWED is False
    assert "NOT_APPLICABLE" not in MutantResult.__members__


def test_results_are_deterministically_ordered_and_serialized(catalogue_run) -> None:
    first = serialize_mutation_run(catalogue_run)
    second = serialize_mutation_run(catalogue_run)
    assert first == second
    assert tuple(item.mutant_id for item in catalogue_run.outcomes) == MUTANT_IDS


def test_closed_results_exclude_sensitive_host_path_thread_provider_and_raw_data(
    catalogue_run,
) -> None:
    encoded = serialize_mutation_run(catalogue_run)
    forbidden = (
        b"synthetic-routing://",
        b"ref_",
        b"RuntimePrivateExecutionBinding",
        b"private_authenticator",
        b"traceback",
        b"/Users/",
        b"/private/",
        b"hostname",
        b"thread_id",
        b"raw_prompt",
        b"raw_provider_output",
        b"GEMINI_API_KEY",
    )
    assert all(value not in encoded for value in forbidden)


def test_evid_002_uses_only_p08_and_preserves_unchanged_expectations(
    catalogue_run,
) -> None:
    outcome = next(
        item for item in catalogue_run.outcomes if item.mutant_id == "W3-MUT-EVID-002"
    )
    assert outcome.child_result.detector_ids == EXPECTED_DETECTORS[9]
    assert outcome.child_result.result is MutantResult.KILLED
    assert outcome.child_result.activation_probe_passed is True


def test_con_mutants_do_not_execute_the_w3_d_repetition_harness(catalogue_run) -> None:
    con_results = tuple(
        item for item in catalogue_run.outcomes if item.mutant_id.startswith("W3-MUT-CON-")
    )
    assert len(con_results) == 2
    assert all(item.w3_d_harness_executed is False for item in con_results)
