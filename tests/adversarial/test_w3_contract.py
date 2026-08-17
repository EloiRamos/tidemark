"""Frozen W3-A contract tests for bounded adversarial verification."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import json
import struct

import pytest

from tidemark.evidence.canonical import canonical_json_bytes
from tidemark.verification.w3_contract import (
    ADAPTIVE_GENERATION,
    ADEQUACY_METRIC,
    ADEQUACY_SCHEMA,
    ARTIFACT_KIND,
    ARTIFACT_ROOT_KEYS,
    CONCURRENCY_REPETITIONS_PER_SHAPE,
    CONCURRENCY_SHAPE_COUNT,
    CONCURRENCY_SHAPES,
    CONTRACT_DRIFT_CODE,
    DOMAIN_CONTRACT_DIGEST,
    EXPECTED_INVALID_COUNT,
    EXPECTED_KILLED_COUNT,
    EXPECTED_SURVIVED_COUNT,
    FIXED_SEED_COUNT,
    GENERATOR_SOURCE,
    GENERATOR_VERSION,
    INVALID_COUNTS_AS_SUCCESS,
    MUTANT_CATALOGUE,
    MUTANT_CATALOGUE_DIGEST,
    MUTANT_CATALOGUE_VERSION,
    MUTANT_COUNT,
    MUTANT_IDS,
    NOT_APPLICABLE_ALLOWED,
    PRODUCER,
    PROPERTY_DOMAINS,
    PROPERTY_DOMAIN_COUNT,
    PROPERTY_DOMAIN_VERSION,
    PROPERTY_IDS,
    RUNTIME_MODEL_GENERATION,
    SEED_CONTRACT_DIGEST,
    SUMMARY_KEYS,
    SURVIVOR_COUNTS_AS_SUCCESS,
    W3_D03_SENTINEL_GENERATE_AND_REJECT,
    W3_D03_SENTINEL_RETRY_OR_REPLACEMENT,
    W3_D03_SENTINEL_WIDTH_SELECTION,
    W3_D03_UNSORTED_SENTINEL_ORDINALS,
    W3_D01_GENERATED_CASE_COUNT,
    W3_D01_SEED,
    W3_D02_GENERATED_CASE_COUNT,
    W3_D02_SEED,
    W3_D03_GENERATED_CASE_COUNT,
    W3_D03_SEED,
    W3_D04_GENERATED_CASE_COUNT,
    W3_D04_SEED,
    W3_D05_GENERATED_CASE_COUNT,
    W3_D05_SEED,
    W3_MAXIMUM_GENERATED_CASE_COUNT,
    W3_TOTAL_GENERATED_CASE_COUNT,
    CaseDescriptor,
    ContractDriftError,
    MutantCategory,
    MutantResult,
    OverallStatus,
    Sha256Counter,
    adjudicate_mutants,
    d03_sentinel_width_from_decision,
    generate_d03_unsorted_sentinel,
    make_adequacy_artifact,
    parse_adequacy_artifact,
    serialize_adequacy_artifact,
    validate_case_descriptors,
    validate_contract,
)
from tidemark.verification.w3_runner import (
    EVIDENCE_JSON_FILENAME,
    EVIDENCE_MARKDOWN_FILENAME,
    RunnerError,
    execute_bounded_verification,
    parse_cli_arguments,
    require_passing_artifact,
    require_unchanged_source_hashes,
    scan_evidence_surfaces,
    validate_candidate_state,
    verify_evidence_bundle,
    write_evidence_bundle,
)


EXPECTED_PROPERTY_ROWS = (
    ("W3-D01", "tidemark-w3-d01-exact-representation-v1", 48),
    ("W3-D02", "tidemark-w3-d02-unissued-reference-v1", 32),
    ("W3-D03", "tidemark-w3-d03-canonical-json-v1", 48),
    ("W3-D04", "tidemark-w3-d04-safe-display-v1", 64),
    ("W3-D05", "tidemark-w3-d05-evidence-corruption-order-v1", 13),
)

EXPECTED_MUTANT_ROWS = (
    ("W3-MUT-REP-001", MutantCategory.REPRESENTATION_CORRUPTION),
    ("W3-MUT-REP-002", MutantCategory.REPRESENTATION_CORRUPTION),
    ("W3-MUT-REP-003", MutantCategory.REPRESENTATION_CORRUPTION),
    ("W3-MUT-PROJ-001", MutantCategory.PROJECTION_CORRUPTION),
    ("W3-MUT-PROJ-002", MutantCategory.PROJECTION_CORRUPTION),
    ("W3-MUT-PROJ-003", MutantCategory.PROJECTION_CORRUPTION),
    ("W3-MUT-ORD-001", MutantCategory.ORDERING_STATE_CORRUPTION),
    ("W3-MUT-ORD-002", MutantCategory.ORDERING_STATE_CORRUPTION),
    ("W3-MUT-EVID-001", MutantCategory.EVIDENCE_PROOF_REFERENCE_CORRUPTION),
    ("W3-MUT-EVID-002", MutantCategory.EVIDENCE_PROOF_REFERENCE_CORRUPTION),
    ("W3-MUT-CON-001", MutantCategory.CONCURRENCY_INTERLEAVING_CORRUPTION),
    ("W3-MUT-CON-002", MutantCategory.CONCURRENCY_INTERLEAVING_CORRUPTION),
)

EXPECTED_ROOT_KEYS = (
    "schema_version",
    "artifact_kind",
    "catalogue_version",
    "domain_contract_version",
    "generator_version",
    "source_revision",
    "producer",
    "seed_contract_digest",
    "domain_contract_digest",
    "mutant_catalogue_digest",
    "property_results",
    "mutant_results",
    "concurrency_results",
    "summary",
    "artifact_digest",
)

EXPECTED_SUMMARY_KEYS = (
    "property_count",
    "generated_case_count",
    "property_pass_count",
    "mutant_count",
    "killed_count",
    "survived_count",
    "invalid_count",
    "adequacy_numerator",
    "adequacy_denominator",
    "concurrency_shape_count",
    "concurrency_pass_count",
    "overall_status",
    "live_model_calls_performed",
    "provider_calls_performed",
    "google_cloud_accessed",
    "network_dependency_required",
)


def _artifact(
    mutant_results: tuple[MutantResult, ...] = (MutantResult.KILLED,) * 12,
) -> dict[str, object]:
    return make_adequacy_artifact(
        source_revision="a" * 40,
        property_results=tuple(
            {"property_id": property_id, "status": "PASS"}
            for property_id in PROPERTY_IDS
        ),
        mutant_results=tuple(
            {
                "mutant_id": mutant.mutant_id,
                "category": mutant.category.value,
                "result": result.value,
            }
            for mutant, result in zip(MUTANT_CATALOGUE, mutant_results)
        ),
        concurrency_results=tuple(
            {"shape_id": shape_id, "status": "PASS"}
            for shape_id in CONCURRENCY_SHAPES
        ),
    )


def _independent_artifact_digest(artifact: dict[str, object]) -> str:
    unsigned = dict(artifact)
    unsigned.pop("artifact_digest")
    return "sha256:" + sha256(canonical_json_bytes(unsigned)).hexdigest()


def test_property_domain_contract_is_exact_frozen_and_bounded() -> None:
    assert PROPERTY_DOMAIN_VERSION == "tidemark.w3.property-domains.v1"
    assert PROPERTY_DOMAIN_COUNT == FIXED_SEED_COUNT == 5
    assert PROPERTY_IDS == ("W3-D01", "W3-D02", "W3-D03", "W3-D04", "W3-D05")
    assert tuple(
        (domain.property_id, domain.seed, domain.generated_case_count)
        for domain in PROPERTY_DOMAINS
    ) == EXPECTED_PROPERTY_ROWS
    assert W3_TOTAL_GENERATED_CASE_COUNT == 205
    assert W3_MAXIMUM_GENERATED_CASE_COUNT == 205
    assert sum(domain.generated_case_count for domain in PROPERTY_DOMAINS) == 205
    assert (
        (W3_D01_SEED, W3_D01_GENERATED_CASE_COUNT),
        (W3_D02_SEED, W3_D02_GENERATED_CASE_COUNT),
        (W3_D03_SEED, W3_D03_GENERATED_CASE_COUNT),
        (W3_D04_SEED, W3_D04_GENERATED_CASE_COUNT),
        (W3_D05_SEED, W3_D05_GENERATED_CASE_COUNT),
    ) == tuple((seed, count) for _, seed, count in EXPECTED_PROPERTY_ROWS)
    with pytest.raises(FrozenInstanceError):
        PROPERTY_DOMAINS[0].seed = "changed"  # type: ignore[misc]


def test_generator_contract_is_exact_and_non_adaptive() -> None:
    assert GENERATOR_VERSION == "tidemark.w3.fixed-domain.v1"
    assert GENERATOR_SOURCE == "SHA256_COUNTER"
    assert ADAPTIVE_GENERATION is False
    assert RUNTIME_MODEL_GENERATION is False


def test_sha256_counter_block_matches_the_approved_byte_contract() -> None:
    domain_id = "W3-D03"
    seed = "tidemark-w3-d03-canonical-json-v1"
    case_index = 36
    block_index = 7
    expected = sha256(
        b"tidemark.w3.fixed-domain.v1"
        + b"\x00"
        + domain_id.encode("utf-8")
        + b"\x00"
        + seed.encode("utf-8")
        + b"\x00"
        + struct.pack(">Q", case_index)
        + b"\x00"
        + struct.pack(">I", block_index)
    ).digest()
    counter = Sha256Counter(domain_id=domain_id, seed=seed, case_index=case_index)
    assert counter.block(block_index) == expected
    assert counter.block(0) != counter.block(1)
    assert counter.map_unsigned(expected[:8], lower=2, upper=4) == (
        2 + (int.from_bytes(expected[:8], "big") % 3)
    )


@pytest.mark.parametrize("bad_value", [-1, 2**64, True])
def test_sha256_counter_rejects_invalid_case_indexes(bad_value: object) -> None:
    with pytest.raises(ContractDriftError, match=CONTRACT_DRIFT_CODE):
        Sha256Counter(domain_id="W3-D01", seed="seed", case_index=bad_value)  # type: ignore[arg-type]


def test_d03_sentinel_contract_uses_direct_width_and_reverse_lexical_insertion() -> None:
    assert W3_D03_UNSORTED_SENTINEL_ORDINALS == (0, 12, 24, 36)
    assert W3_D03_SENTINEL_WIDTH_SELECTION == "DETERMINISTIC_CLOSED_RANGE_2_3_4"
    assert W3_D03_SENTINEL_GENERATE_AND_REJECT is False
    assert W3_D03_SENTINEL_RETRY_OR_REPLACEMENT is False

    for ordinal in W3_D03_UNSORTED_SENTINEL_ORDINALS:
        counter = Sha256Counter(
            domain_id="W3-D03",
            seed="tidemark-w3-d03-canonical-json-v1",
            case_index=ordinal,
        )
        expected_width = 2 + (int.from_bytes(counter.block(0), "big") % 3)
        assert d03_sentinel_width_from_decision(counter.block(0)) == expected_width

        sentinel = generate_d03_unsorted_sentinel(ordinal)
        insertion_keys = tuple(sentinel.mapping)
        assert sentinel.width == expected_width
        assert len(insertion_keys) in {2, 3, 4}
        assert len(set(insertion_keys)) == sentinel.width
        assert insertion_keys == tuple(sorted(insertion_keys, reverse=True))
        assert insertion_keys != tuple(sorted(insertion_keys))
        assert sentinel.descriptor.category == "UNSORTED_OBJECT_SENTINEL"


def test_mutant_catalogue_is_exact_ordered_metadata_only() -> None:
    assert MUTANT_CATALOGUE_VERSION == "tidemark.w3.mutant-catalogue.v1"
    assert MUTANT_COUNT == 12
    assert EXPECTED_KILLED_COUNT == 12
    assert EXPECTED_SURVIVED_COUNT == EXPECTED_INVALID_COUNT == 0
    assert tuple((mutant.mutant_id, mutant.category) for mutant in MUTANT_CATALOGUE) == (
        EXPECTED_MUTANT_ROWS
    )
    assert MUTANT_IDS == tuple(row[0] for row in EXPECTED_MUTANT_ROWS)
    assert all(not hasattr(mutant, "apply") for mutant in MUTANT_CATALOGUE)


def test_concurrency_contract_is_exact_metadata_only() -> None:
    assert CONCURRENCY_SHAPE_COUNT == 2
    assert CONCURRENCY_SHAPES == ("W3-C01", "W3-C02")
    assert CONCURRENCY_REPETITIONS_PER_SHAPE == 3


def test_result_vocabulary_and_metric_are_closed() -> None:
    assert tuple(result.value for result in MutantResult) == (
        "KILLED",
        "SURVIVED",
        "INVALID",
    )
    assert "NOT_APPLICABLE" not in MutantResult.__members__
    assert NOT_APPLICABLE_ALLOWED is False
    assert ADEQUACY_SCHEMA == "tidemark.w3.mutation-adequacy.v1"
    assert ADEQUACY_METRIC == "KILLED_DIVIDED_BY_KILLED_PLUS_SURVIVED"
    assert SURVIVOR_COUNTS_AS_SUCCESS is False
    assert INVALID_COUNTS_AS_SUCCESS is False


def test_adequacy_adjudication_keeps_survivors_in_denominator() -> None:
    result = adjudicate_mutants(
        (MutantResult.KILLED,) * 11 + (MutantResult.SURVIVED,)
    )
    assert result.killed_count == 11
    assert result.survived_count == 1
    assert result.invalid_count == 0
    assert result.valid_mutants == 12
    assert result.adequacy_numerator == 11
    assert result.adequacy_denominator == 12
    assert result.overall_status is OverallStatus.FAIL


def test_adequacy_adjudication_makes_invalid_an_error() -> None:
    result = adjudicate_mutants(
        (MutantResult.KILLED,) * 11 + (MutantResult.INVALID,)
    )
    assert result.valid_mutants == 11
    assert result.adequacy_numerator == result.adequacy_denominator == 11
    assert result.overall_status is OverallStatus.ERROR


def test_artifact_schema_keys_values_and_digest_are_exact() -> None:
    artifact = _artifact()
    assert ARTIFACT_ROOT_KEYS == EXPECTED_ROOT_KEYS
    assert SUMMARY_KEYS == EXPECTED_SUMMARY_KEYS
    assert tuple(artifact) == EXPECTED_ROOT_KEYS
    assert tuple(artifact["summary"]) == EXPECTED_SUMMARY_KEYS  # type: ignore[arg-type]
    assert artifact["schema_version"] == "tidemark.w3.mutation-adequacy.v1"
    assert artifact["artifact_kind"] == ARTIFACT_KIND
    assert artifact["producer"] == PRODUCER == "tidemark.w3.verification-runner.v1"
    assert artifact["seed_contract_digest"] == SEED_CONTRACT_DIGEST
    assert artifact["domain_contract_digest"] == DOMAIN_CONTRACT_DIGEST
    assert artifact["mutant_catalogue_digest"] == MUTANT_CATALOGUE_DIGEST
    assert artifact["artifact_digest"] == _independent_artifact_digest(artifact)
    assert artifact["summary"]["overall_status"] == "PASS"  # type: ignore[index]


def test_artifact_serialization_is_canonical_and_round_trips() -> None:
    artifact = _artifact()
    encoded = serialize_adequacy_artifact(artifact)
    assert encoded.endswith(b"\n")
    assert not encoded.endswith(b"\n\n")
    assert encoded == canonical_json_bytes(artifact, trailing_newline=True)
    assert parse_adequacy_artifact(encoded) == artifact


@pytest.mark.parametrize("key", EXPECTED_ROOT_KEYS)
def test_artifact_rejects_each_missing_root_key(key: str) -> None:
    artifact = _artifact()
    artifact.pop(key)
    with pytest.raises(ContractDriftError, match=CONTRACT_DRIFT_CODE):
        serialize_adequacy_artifact(artifact)


def test_artifact_rejects_extra_unknown_and_missing_summary_data() -> None:
    extra = _artifact()
    extra["unexpected"] = False
    with pytest.raises(ContractDriftError, match=CONTRACT_DRIFT_CODE):
        serialize_adequacy_artifact(extra)

    unknown = _artifact()
    unknown["producer"] = "unknown-producer"
    with pytest.raises(ContractDriftError, match=CONTRACT_DRIFT_CODE):
        serialize_adequacy_artifact(unknown)

    missing_summary = _artifact()
    missing_summary["summary"].pop("invalid_count")  # type: ignore[union-attr]
    with pytest.raises(ContractDriftError, match=CONTRACT_DRIFT_CODE):
        serialize_adequacy_artifact(missing_summary)


def test_artifact_rejects_noncanonical_tampered_and_duplicate_json() -> None:
    artifact = _artifact()
    noncanonical = (json.dumps(artifact, indent=2) + "\n").encode("utf-8")
    with pytest.raises(ContractDriftError, match=CONTRACT_DRIFT_CODE):
        parse_adequacy_artifact(noncanonical)

    tampered = dict(artifact)
    tampered["producer"] = "tidemark.w3.other"
    tampered_bytes = canonical_json_bytes(tampered, trailing_newline=True)
    with pytest.raises(ContractDriftError, match=CONTRACT_DRIFT_CODE):
        parse_adequacy_artifact(tampered_bytes)

    encoded = serialize_adequacy_artifact(artifact)
    duplicate_key = encoded.replace(
        b'{"artifact_digest":',
        b'{"artifact_digest":"sha256:' + (b"0" * 64) + b'","artifact_digest":',
        1,
    )
    with pytest.raises(ContractDriftError, match=CONTRACT_DRIFT_CODE):
        parse_adequacy_artifact(duplicate_key)


@pytest.mark.parametrize("result", [MutantResult.SURVIVED, MutantResult.INVALID])
def test_artifact_overall_status_preserves_non_success(result: MutantResult) -> None:
    results = (MutantResult.KILLED,) * 11 + (result,)
    artifact = _artifact(results)
    expected = "FAIL" if result is MutantResult.SURVIVED else "ERROR"
    assert artifact["summary"]["overall_status"] == expected  # type: ignore[index]
    assert parse_adequacy_artifact(serialize_adequacy_artifact(artifact)) == artifact


def test_artifact_rejects_missing_extra_reordered_and_duplicate_result_ids() -> None:
    for result_key in ("property_results", "mutant_results", "concurrency_results"):
        missing = _artifact()
        missing[result_key].pop()  # type: ignore[union-attr]
        with pytest.raises(ContractDriftError, match=CONTRACT_DRIFT_CODE):
            serialize_adequacy_artifact(missing)

        extra = _artifact()
        extra[result_key].append(dict(extra[result_key][0]))  # type: ignore[union-attr,index]
        with pytest.raises(ContractDriftError, match=CONTRACT_DRIFT_CODE):
            serialize_adequacy_artifact(extra)

        reordered = _artifact()
        reordered[result_key][0], reordered[result_key][1] = (  # type: ignore[index]
            reordered[result_key][1],
            reordered[result_key][0],
        )
        with pytest.raises(ContractDriftError, match=CONTRACT_DRIFT_CODE):
            serialize_adequacy_artifact(reordered)

        duplicate = _artifact()
        duplicate[result_key][1] = dict(duplicate[result_key][0])  # type: ignore[index]
        with pytest.raises(ContractDriftError, match=CONTRACT_DRIFT_CODE):
            serialize_adequacy_artifact(duplicate)


def test_contract_validation_rejects_missing_extra_reordered_changed_and_duplicate_data() -> None:
    validate_contract()
    variants = (
        {"property_domains": PROPERTY_DOMAINS[:-1]},
        {"property_domains": PROPERTY_DOMAINS + (PROPERTY_DOMAINS[0],)},
        {"property_domains": tuple(reversed(PROPERTY_DOMAINS))},
        {
            "property_domains": (
                replace(PROPERTY_DOMAINS[0], seed="changed-seed"),
                *PROPERTY_DOMAINS[1:],
            )
        },
        {
            "property_domains": (
                PROPERTY_DOMAINS[0],
                replace(PROPERTY_DOMAINS[1], property_id="W3-D01"),
                *PROPERTY_DOMAINS[2:],
            )
        },
        {"mutant_catalogue": tuple(reversed(MUTANT_CATALOGUE))},
        {
            "mutant_catalogue": (
                MUTANT_CATALOGUE[0],
                replace(MUTANT_CATALOGUE[1], mutant_id="W3-MUT-REP-001"),
                *MUTANT_CATALOGUE[2:],
            )
        },
        {"concurrency_shapes": ("W3-C01", "W3-C03")},
        {"sentinel_ordinals": (0, 12, 24, 35)},
    )
    for variant in variants:
        with pytest.raises(ContractDriftError, match=CONTRACT_DRIFT_CODE):
            validate_contract(**variant)


def test_duplicate_case_descriptors_and_descriptor_drift_reject() -> None:
    descriptors = (
        CaseDescriptor(
            domain_id="W3-D01",
            ordinal=0,
            category="TEXT",
            shape_metadata=(("length", 4),),
            input_fingerprint="sha256:" + ("1" * 64),
        ),
        CaseDescriptor(
            domain_id="W3-D01",
            ordinal=1,
            category="BOOL",
            shape_metadata=(),
            input_fingerprint="sha256:" + ("2" * 64),
        ),
    )
    assert validate_case_descriptors(descriptors) == descriptors
    with pytest.raises(ContractDriftError, match=CONTRACT_DRIFT_CODE):
        validate_case_descriptors((descriptors[0], descriptors[0]))
    with pytest.raises(ContractDriftError, match=CONTRACT_DRIFT_CODE):
        validate_case_descriptors((descriptors[1], descriptors[0]))
    with pytest.raises(ContractDriftError, match=CONTRACT_DRIFT_CODE):
        CaseDescriptor(
            domain_id="W3-D99",
            ordinal=0,
            category="UNKNOWN",
            shape_metadata=(),
            input_fingerprint="sha256:" + ("3" * 64),
        )


@pytest.fixture(scope="module")
def w3_runner_bundle():
    return execute_bounded_verification(source_revision="a" * 40)


def test_runner_executes_the_complete_fixed_catalogue_and_round_trips(
    w3_runner_bundle,
) -> None:
    verified = verify_evidence_bundle(
        w3_runner_bundle.json_bytes,
        w3_runner_bundle.markdown_bytes,
        expected_source_revision="a" * 40,
    )
    assert verified == w3_runner_bundle.artifact
    assert verified["summary"] == {
        "property_count": 5,
        "generated_case_count": 205,
        "property_pass_count": 5,
        "mutant_count": 12,
        "killed_count": 12,
        "survived_count": 0,
        "invalid_count": 0,
        "adequacy_numerator": 12,
        "adequacy_denominator": 12,
        "concurrency_shape_count": 2,
        "concurrency_pass_count": 2,
        "overall_status": "PASS",
        "live_model_calls_performed": 0,
        "provider_calls_performed": 0,
        "google_cloud_accessed": False,
        "network_dependency_required": False,
    }


def test_two_complete_runner_materializations_are_byte_identical(
    w3_runner_bundle,
) -> None:
    second = execute_bounded_verification(source_revision="a" * 40)
    assert second.json_bytes == w3_runner_bundle.json_bytes
    assert second.markdown_bytes == w3_runner_bundle.markdown_bytes
    assert second.artifact["artifact_digest"] == w3_runner_bundle.artifact[
        "artifact_digest"
    ]


def test_runner_cli_is_closed_and_output_directory_is_exclusive(
    tmp_path,
    w3_runner_bundle,
) -> None:
    assert parse_cli_arguments(("--output-dir", str(tmp_path))) == tmp_path
    with pytest.raises(SystemExit):
        parse_cli_arguments(("--mutant", "W3-MUT-REP-001"))
    with pytest.raises(SystemExit):
        parse_cli_arguments(("--output-dir", str(tmp_path), "--workers", "2"))

    write_evidence_bundle(tmp_path, w3_runner_bundle)
    assert tuple(sorted(path.name for path in tmp_path.iterdir())) == tuple(
        sorted((EVIDENCE_JSON_FILENAME, EVIDENCE_MARKDOWN_FILENAME))
    )
    with pytest.raises(RunnerError, match="w3.output_directory_invalid.v1"):
        write_evidence_bundle(tmp_path, w3_runner_bundle)


def test_runner_rejects_dirty_provenance_and_changed_source_hashes() -> None:
    assert validate_candidate_state("a" * 40, "") == "a" * 40
    with pytest.raises(RunnerError, match="w3.source_not_clean.v1"):
        validate_candidate_state("a" * 40, " M src/tidemark/example.py")
    with pytest.raises(RunnerError, match="w3.source_revision_invalid.v1"):
        validate_candidate_state("not-a-revision", "")

    before = (("src/tidemark/example.py", "1" * 64),)
    require_unchanged_source_hashes(before, before)
    with pytest.raises(RunnerError, match="w3.source_hash_drift.v1"):
        require_unchanged_source_hashes(
            before,
            (("src/tidemark/example.py", "2" * 64),),
        )


def test_runner_fails_closed_on_scan_survivor_and_invalid() -> None:
    with pytest.raises(RunnerError, match="w3.surface_scan_failed.v1"):
        scan_evidence_surfaces((("w3.json", b"synthetic-routing://"),))
    for result in (MutantResult.SURVIVED, MutantResult.INVALID):
        with pytest.raises(RunnerError, match="w3.overall_status_not_pass.v1"):
            require_passing_artifact(
                _artifact((MutantResult.KILLED,) * 11 + (result,))
            )


def test_runner_markdown_is_derived_safe_and_offline(w3_runner_bundle) -> None:
    markdown = w3_runner_bundle.markdown_bytes
    assert markdown.startswith(b"# TIDEMARK Variant C W3 Mutation Adequacy\n")
    assert b"12 / 12" in markdown
    assert b"Live model calls | 0" in markdown
    assert b"Provider calls | 0" in markdown
    assert b"Google Cloud accessed | false" in markdown
    assert b"Network dependency required | false" in markdown
    scan_evidence_surfaces(
        (
            (EVIDENCE_JSON_FILENAME, w3_runner_bundle.json_bytes),
            (EVIDENCE_MARKDOWN_FILENAME, markdown),
        )
    )
