"""Frozen W3-A contracts for bounded adversarial verification.

This module contains metadata, deterministic descriptor construction, and
in-memory artifact validation only. It performs no runtime, provider, model,
cloud, network, mutation, concurrency, or durable evidence operation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
import re
import struct
from typing import Mapping, Optional, Sequence, Tuple

from tidemark.evidence.canonical import canonical_json_bytes


PROPERTY_DOMAIN_VERSION = "tidemark.w3.property-domains.v1"
PROPERTY_DOMAIN_COUNT = 5
FIXED_SEED_COUNT = 5

GENERATOR_VERSION = "tidemark.w3.fixed-domain.v1"
GENERATOR_SOURCE = "SHA256_COUNTER"
ADAPTIVE_GENERATION = False
RUNTIME_MODEL_GENERATION = False

W3_TOTAL_GENERATED_CASE_COUNT = 205
W3_MAXIMUM_GENERATED_CASE_COUNT = 205

W3_D01_SEED = "tidemark-w3-d01-exact-representation-v1"
W3_D01_GENERATED_CASE_COUNT = 48
W3_D02_SEED = "tidemark-w3-d02-unissued-reference-v1"
W3_D02_GENERATED_CASE_COUNT = 32
W3_D03_SEED = "tidemark-w3-d03-canonical-json-v1"
W3_D03_GENERATED_CASE_COUNT = 48
W3_D04_SEED = "tidemark-w3-d04-safe-display-v1"
W3_D04_GENERATED_CASE_COUNT = 64
W3_D05_SEED = "tidemark-w3-d05-evidence-corruption-order-v1"
W3_D05_GENERATED_CASE_COUNT = 13

W3_D03_UNSORTED_SENTINEL_ORDINALS = (0, 12, 24, 36)
W3_D03_SENTINEL_WIDTH_SELECTION = "DETERMINISTIC_CLOSED_RANGE_2_3_4"
W3_D03_SENTINEL_GENERATE_AND_REJECT = False
W3_D03_SENTINEL_RETRY_OR_REPLACEMENT = False

MUTANT_CATALOGUE_VERSION = "tidemark.w3.mutant-catalogue.v1"
MUTANT_COUNT = 12
EXPECTED_KILLED_COUNT = 12
EXPECTED_SURVIVED_COUNT = 0
EXPECTED_INVALID_COUNT = 0
NOT_APPLICABLE_ALLOWED = False

CONCURRENCY_SHAPE_COUNT = 2
CONCURRENCY_SHAPES = ("W3-C01", "W3-C02")
CONCURRENCY_REPETITIONS_PER_SHAPE = 3

ADEQUACY_SCHEMA = "tidemark.w3.mutation-adequacy.v1"
ADEQUACY_METRIC = "KILLED_DIVIDED_BY_KILLED_PLUS_SURVIVED"
SURVIVOR_COUNTS_AS_SUCCESS = False
INVALID_COUNTS_AS_SUCCESS = False

ARTIFACT_KIND = "TIDEMARK_W3_BOUNDED_ADVERSARIAL_VERIFICATION"
PRODUCER = "tidemark.w3.verification-runner.v1"
CONTRACT_DRIFT_CODE = "W3_CONTRACT_DRIFT"

ARTIFACT_ROOT_KEYS = (
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

SUMMARY_KEYS = (
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

_LOWER_HEX_40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256_VALUE = re.compile(r"sha256:[0-9a-f]{64}\Z")


class ContractDriftError(ValueError):
    """Raised whenever W3 v1 content differs from its closed contract."""


def _drift(detail: str) -> ContractDriftError:
    return ContractDriftError(f"{CONTRACT_DRIFT_CODE}: {detail}")


class MutantCategory(Enum):
    REPRESENTATION_CORRUPTION = "Representation corruption"
    PROJECTION_CORRUPTION = "Projection corruption"
    ORDERING_STATE_CORRUPTION = "Ordering/state corruption"
    EVIDENCE_PROOF_REFERENCE_CORRUPTION = "Evidence/proof-reference corruption"
    CONCURRENCY_INTERLEAVING_CORRUPTION = "Concurrency/interleaving corruption"


class MutantResult(Enum):
    KILLED = "KILLED"
    SURVIVED = "SURVIVED"
    INVALID = "INVALID"


class OverallStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"


@dataclass(frozen=True)
class PropertyDomain:
    property_id: str
    seed: str
    generated_case_count: int


PROPERTY_DOMAINS = (
    PropertyDomain("W3-D01", W3_D01_SEED, W3_D01_GENERATED_CASE_COUNT),
    PropertyDomain("W3-D02", W3_D02_SEED, W3_D02_GENERATED_CASE_COUNT),
    PropertyDomain("W3-D03", W3_D03_SEED, W3_D03_GENERATED_CASE_COUNT),
    PropertyDomain("W3-D04", W3_D04_SEED, W3_D04_GENERATED_CASE_COUNT),
    PropertyDomain("W3-D05", W3_D05_SEED, W3_D05_GENERATED_CASE_COUNT),
)
PROPERTY_IDS = tuple(domain.property_id for domain in PROPERTY_DOMAINS)


@dataclass(frozen=True)
class MutantDescriptor:
    mutant_id: str
    category: MutantCategory


MUTANT_CATALOGUE = (
    MutantDescriptor("W3-MUT-REP-001", MutantCategory.REPRESENTATION_CORRUPTION),
    MutantDescriptor("W3-MUT-REP-002", MutantCategory.REPRESENTATION_CORRUPTION),
    MutantDescriptor("W3-MUT-REP-003", MutantCategory.REPRESENTATION_CORRUPTION),
    MutantDescriptor("W3-MUT-PROJ-001", MutantCategory.PROJECTION_CORRUPTION),
    MutantDescriptor("W3-MUT-PROJ-002", MutantCategory.PROJECTION_CORRUPTION),
    MutantDescriptor("W3-MUT-PROJ-003", MutantCategory.PROJECTION_CORRUPTION),
    MutantDescriptor("W3-MUT-ORD-001", MutantCategory.ORDERING_STATE_CORRUPTION),
    MutantDescriptor("W3-MUT-ORD-002", MutantCategory.ORDERING_STATE_CORRUPTION),
    MutantDescriptor(
        "W3-MUT-EVID-001",
        MutantCategory.EVIDENCE_PROOF_REFERENCE_CORRUPTION,
    ),
    MutantDescriptor(
        "W3-MUT-EVID-002",
        MutantCategory.EVIDENCE_PROOF_REFERENCE_CORRUPTION,
    ),
    MutantDescriptor(
        "W3-MUT-CON-001",
        MutantCategory.CONCURRENCY_INTERLEAVING_CORRUPTION,
    ),
    MutantDescriptor(
        "W3-MUT-CON-002",
        MutantCategory.CONCURRENCY_INTERLEAVING_CORRUPTION,
    ),
)
MUTANT_IDS = tuple(mutant.mutant_id for mutant in MUTANT_CATALOGUE)


@dataclass(frozen=True)
class Sha256Counter:
    """The exact W3 SHA-256 counter input contract."""

    domain_id: str
    seed: str
    case_index: int

    def __post_init__(self) -> None:
        if type(self.domain_id) is not str or not self.domain_id:
            raise _drift("counter domain_id must be non-empty exact str")
        if type(self.seed) is not str or not self.seed:
            raise _drift("counter seed must be non-empty exact str")
        if (
            type(self.case_index) is not int
            or self.case_index < 0
            or self.case_index >= 2**64
        ):
            raise _drift("counter case_index is outside UINT64")

    def block(self, block_index: int) -> bytes:
        if (
            type(block_index) is not int
            or block_index < 0
            or block_index >= 2**32
        ):
            raise _drift("counter block_index is outside UINT32")
        payload = (
            GENERATOR_VERSION.encode("utf-8")
            + b"\x00"
            + self.domain_id.encode("utf-8")
            + b"\x00"
            + self.seed.encode("utf-8")
            + b"\x00"
            + struct.pack(">Q", self.case_index)
            + b"\x00"
            + struct.pack(">I", block_index)
        )
        return sha256(payload).digest()

    @staticmethod
    def map_unsigned(value: bytes, *, lower: int, upper: int) -> int:
        if type(value) is not bytes or not value:
            raise _drift("unsigned mapping requires non-empty exact bytes")
        if type(lower) is not int or type(upper) is not int or lower > upper:
            raise _drift("unsigned mapping requires a closed integer range")
        return lower + (int.from_bytes(value, "big") % (upper - lower + 1))


def d03_sentinel_width_from_decision(width_decision: bytes) -> int:
    """Map existing decision bytes directly to the closed width {2, 3, 4}."""

    return Sha256Counter.map_unsigned(width_decision, lower=2, upper=4)


@dataclass(frozen=True)
class CaseDescriptor:
    domain_id: str
    ordinal: int
    category: str
    shape_metadata: Tuple[Tuple[str, object], ...]
    input_fingerprint: str

    def __post_init__(self) -> None:
        if self.domain_id not in PROPERTY_IDS:
            raise _drift("unknown case descriptor domain")
        domain = PROPERTY_DOMAINS[PROPERTY_IDS.index(self.domain_id)]
        if (
            type(self.ordinal) is not int
            or self.ordinal < 0
            or self.ordinal >= domain.generated_case_count
        ):
            raise _drift("case descriptor ordinal outside domain")
        if type(self.category) is not str or not self.category:
            raise _drift("case descriptor category must be non-empty exact str")
        if type(self.shape_metadata) is not tuple:
            raise _drift("case descriptor shape metadata must be tuple")
        metadata_keys = []
        for entry in self.shape_metadata:
            if (
                type(entry) is not tuple
                or len(entry) != 2
                or type(entry[0]) is not str
                or not entry[0]
            ):
                raise _drift("case descriptor metadata entry is invalid")
            metadata_keys.append(entry[0])
        if len(metadata_keys) != len(set(metadata_keys)):
            raise _drift("case descriptor metadata keys duplicate")
        try:
            canonical_json_bytes(dict(self.shape_metadata))
        except (TypeError, ValueError) as exc:
            raise _drift("case descriptor metadata is not canonical JSON") from exc
        if (
            type(self.input_fingerprint) is not str
            or _SHA256_VALUE.fullmatch(self.input_fingerprint) is None
        ):
            raise _drift("case descriptor fingerprint is invalid")


@dataclass(frozen=True)
class D03UnsortedSentinel:
    width: int
    items: Tuple[Tuple[str, int], ...]
    descriptor: CaseDescriptor

    @property
    def mapping(self) -> dict:
        return dict(self.items)


def _digest(value: object) -> str:
    return "sha256:" + sha256(canonical_json_bytes(value)).hexdigest()


def generate_d03_unsorted_sentinel(ordinal: int) -> D03UnsortedSentinel:
    if ordinal not in W3_D03_UNSORTED_SENTINEL_ORDINALS:
        raise _drift("D03 ordinal is not a reserved sentinel")
    counter = Sha256Counter(
        domain_id="W3-D03",
        seed=W3_D03_SEED,
        case_index=ordinal,
    )
    width = d03_sentinel_width_from_decision(counter.block(0))
    generated_items = []
    for item_index in range(width):
        item_block = counter.block(item_index + 1)
        key = "key_" + item_block[:12].hex()
        value = int.from_bytes(item_block[12:20], "big")
        generated_items.append((key, value))
    if len({key for key, _ in generated_items}) != width:
        raise _drift("D03 sentinel key derivation collided")
    items = tuple(sorted(generated_items, key=lambda item: item[0], reverse=True))
    source_mapping = dict(items)
    descriptor = CaseDescriptor(
        domain_id="W3-D03",
        ordinal=ordinal,
        category="UNSORTED_OBJECT_SENTINEL",
        shape_metadata=(
            ("sentinel_width", width),
            ("insertion_rule", "REVERSE_LEXICOGRAPHIC"),
        ),
        input_fingerprint=_digest(source_mapping),
    )
    return D03UnsortedSentinel(width=width, items=items, descriptor=descriptor)


def validate_case_descriptors(
    descriptors: Sequence[CaseDescriptor],
) -> Tuple[CaseDescriptor, ...]:
    if isinstance(descriptors, (str, bytes)):
        raise _drift("case descriptors must be a bounded sequence")
    closed = tuple(descriptors)
    if any(type(descriptor) is not CaseDescriptor for descriptor in closed):
        raise _drift("unknown case descriptor type")
    identity_rows = tuple(
        (descriptor.domain_id, descriptor.ordinal) for descriptor in closed
    )
    fingerprints = tuple(descriptor.input_fingerprint for descriptor in closed)
    if len(identity_rows) != len(set(identity_rows)):
        raise _drift("duplicate case descriptor")
    if len(fingerprints) != len(set(fingerprints)):
        raise _drift("duplicate case descriptor fingerprint")
    expected_order = tuple(
        sorted(identity_rows, key=lambda row: (PROPERTY_IDS.index(row[0]), row[1]))
    )
    if identity_rows != expected_order:
        raise _drift("case descriptors are reordered")
    return closed


def _property_domain_rows(
    domains: Sequence[PropertyDomain],
) -> list:
    return [
        {
            "property_id": domain.property_id,
            "seed": domain.seed,
            "generated_case_count": domain.generated_case_count,
        }
        for domain in domains
    ]


def _mutant_rows(catalogue: Sequence[MutantDescriptor]) -> list:
    return [
        {"mutant_id": mutant.mutant_id, "category": mutant.category.value}
        for mutant in catalogue
    ]


_SEED_CONTRACT = {
    "fixed_seed_count": FIXED_SEED_COUNT,
    "generator_source": GENERATOR_SOURCE,
    "generator_version": GENERATOR_VERSION,
    "adaptive_generation": ADAPTIVE_GENERATION,
    "runtime_model_generation": RUNTIME_MODEL_GENERATION,
    "seeds": [
        {"property_id": domain.property_id, "seed": domain.seed}
        for domain in PROPERTY_DOMAINS
    ],
}

_DOMAIN_CONTRACT = {
    "property_domain_version": PROPERTY_DOMAIN_VERSION,
    "property_domain_count": PROPERTY_DOMAIN_COUNT,
    "domains": _property_domain_rows(PROPERTY_DOMAINS),
    "total_generated_case_count": W3_TOTAL_GENERATED_CASE_COUNT,
    "maximum_generated_case_count": W3_MAXIMUM_GENERATED_CASE_COUNT,
    "d03_unsorted_sentinel_ordinals": list(W3_D03_UNSORTED_SENTINEL_ORDINALS),
    "d03_sentinel_width_selection": W3_D03_SENTINEL_WIDTH_SELECTION,
    "d03_sentinel_generate_and_reject": W3_D03_SENTINEL_GENERATE_AND_REJECT,
    "d03_sentinel_retry_or_replacement": W3_D03_SENTINEL_RETRY_OR_REPLACEMENT,
    "d03_sentinel_insertion_rule": "REVERSE_LEXICOGRAPHIC",
}

_MUTANT_CONTRACT = {
    "catalogue_version": MUTANT_CATALOGUE_VERSION,
    "mutant_count": MUTANT_COUNT,
    "expected_killed_count": EXPECTED_KILLED_COUNT,
    "expected_survived_count": EXPECTED_SURVIVED_COUNT,
    "expected_invalid_count": EXPECTED_INVALID_COUNT,
    "not_applicable_allowed": NOT_APPLICABLE_ALLOWED,
    "mutants": _mutant_rows(MUTANT_CATALOGUE),
}

SEED_CONTRACT_DIGEST = _digest(_SEED_CONTRACT)
DOMAIN_CONTRACT_DIGEST = _digest(_DOMAIN_CONTRACT)
MUTANT_CATALOGUE_DIGEST = _digest(_MUTANT_CONTRACT)


def validate_contract(
    *,
    property_domains: Optional[Sequence[PropertyDomain]] = None,
    mutant_catalogue: Optional[Sequence[MutantDescriptor]] = None,
    concurrency_shapes: Optional[Sequence[str]] = None,
    sentinel_ordinals: Optional[Sequence[int]] = None,
) -> None:
    domains = tuple(PROPERTY_DOMAINS if property_domains is None else property_domains)
    mutants = tuple(MUTANT_CATALOGUE if mutant_catalogue is None else mutant_catalogue)
    shapes = tuple(
        CONCURRENCY_SHAPES if concurrency_shapes is None else concurrency_shapes
    )
    ordinals = tuple(
        W3_D03_UNSORTED_SENTINEL_ORDINALS
        if sentinel_ordinals is None
        else sentinel_ordinals
    )

    domain_ids = tuple(
        domain.property_id if type(domain) is PropertyDomain else None
        for domain in domains
    )
    mutant_ids = tuple(
        mutant.mutant_id if type(mutant) is MutantDescriptor else None
        for mutant in mutants
    )
    if len(domain_ids) != len(set(domain_ids)):
        raise _drift("duplicate property domain ID")
    if len(mutant_ids) != len(set(mutant_ids)):
        raise _drift("duplicate mutant ID")
    if domains != PROPERTY_DOMAINS:
        raise _drift("property domain contract differs")
    if mutants != MUTANT_CATALOGUE:
        raise _drift("mutant catalogue contract differs")
    if shapes != CONCURRENCY_SHAPES or len(shapes) != len(set(shapes)):
        raise _drift("concurrency shape contract differs")
    if ordinals != W3_D03_UNSORTED_SENTINEL_ORDINALS:
        raise _drift("D03 sentinel ordinal contract differs")
    if sum(domain.generated_case_count for domain in domains) != 205:
        raise _drift("generated case total differs")


@dataclass(frozen=True)
class AdequacyAdjudication:
    killed_count: int
    survived_count: int
    invalid_count: int
    valid_mutants: int
    adequacy_numerator: int
    adequacy_denominator: int
    overall_status: OverallStatus


def adjudicate_mutants(
    results: Sequence[MutantResult],
) -> AdequacyAdjudication:
    closed = tuple(results)
    if len(closed) != MUTANT_COUNT:
        raise _drift("mutant result count differs")
    if any(type(result) is not MutantResult for result in closed):
        raise _drift("unknown mutant result")
    killed = closed.count(MutantResult.KILLED)
    survived = closed.count(MutantResult.SURVIVED)
    invalid = closed.count(MutantResult.INVALID)
    valid = killed + survived
    if valid == 0:
        raise _drift("mutation adequacy denominator is zero")
    if invalid:
        status = OverallStatus.ERROR
    elif survived:
        status = OverallStatus.FAIL
    else:
        status = OverallStatus.PASS
    return AdequacyAdjudication(
        killed_count=killed,
        survived_count=survived,
        invalid_count=invalid,
        valid_mutants=valid,
        adequacy_numerator=killed,
        adequacy_denominator=valid,
        overall_status=status,
    )


def _closed_result_rows(
    rows: Sequence[Mapping[str, object]],
    *,
    id_key: str,
    expected_ids: Tuple[str, ...],
) -> list:
    if isinstance(rows, (str, bytes)):
        raise _drift(f"{id_key} rows must be a bounded sequence")
    closed = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise _drift(f"{id_key} row must be an object")
        closed.append(dict(row))
    actual_ids = tuple(row.get(id_key) for row in closed)
    if len(actual_ids) != len(set(actual_ids)):
        raise _drift(f"duplicate {id_key}")
    if actual_ids != expected_ids:
        raise _drift(f"missing, extra, unknown, or reordered {id_key}")
    return closed


def _status_count(rows: Sequence[Mapping[str, object]]) -> int:
    for row in rows:
        if row.get("status") not in {status.value for status in OverallStatus}:
            raise _drift("unknown property or concurrency status")
    return sum(row["status"] == OverallStatus.PASS.value for row in rows)


def _mutant_results(rows: Sequence[Mapping[str, object]]) -> Tuple[MutantResult, ...]:
    results = []
    for row, expected in zip(rows, MUTANT_CATALOGUE):
        if row.get("category") != expected.category.value:
            raise _drift("mutant category differs")
        try:
            result = MutantResult(row.get("result"))
        except (TypeError, ValueError) as exc:
            raise _drift("unknown mutant result vocabulary") from exc
        results.append(result)
    return tuple(results)


def _overall_status(
    adjudication: AdequacyAdjudication,
    *,
    property_pass_count: int,
    concurrency_pass_count: int,
) -> OverallStatus:
    if adjudication.overall_status is OverallStatus.ERROR:
        return OverallStatus.ERROR
    if (
        adjudication.overall_status is OverallStatus.FAIL
        or property_pass_count != PROPERTY_DOMAIN_COUNT
        or concurrency_pass_count != CONCURRENCY_SHAPE_COUNT
    ):
        return OverallStatus.FAIL
    return OverallStatus.PASS


def _artifact_digest(artifact: Mapping[str, object]) -> str:
    unsigned = dict(artifact)
    unsigned.pop("artifact_digest", None)
    return _digest(unsigned)


def make_adequacy_artifact(
    *,
    source_revision: str,
    property_results: Sequence[Mapping[str, object]],
    mutant_results: Sequence[Mapping[str, object]],
    concurrency_results: Sequence[Mapping[str, object]],
) -> dict:
    properties = _closed_result_rows(
        property_results, id_key="property_id", expected_ids=PROPERTY_IDS
    )
    mutants = _closed_result_rows(
        mutant_results, id_key="mutant_id", expected_ids=MUTANT_IDS
    )
    concurrency = _closed_result_rows(
        concurrency_results,
        id_key="shape_id",
        expected_ids=CONCURRENCY_SHAPES,
    )
    property_pass_count = _status_count(properties)
    concurrency_pass_count = _status_count(concurrency)
    adjudication = adjudicate_mutants(_mutant_results(mutants))
    overall = _overall_status(
        adjudication,
        property_pass_count=property_pass_count,
        concurrency_pass_count=concurrency_pass_count,
    )
    summary = {
        "property_count": PROPERTY_DOMAIN_COUNT,
        "generated_case_count": W3_TOTAL_GENERATED_CASE_COUNT,
        "property_pass_count": property_pass_count,
        "mutant_count": MUTANT_COUNT,
        "killed_count": adjudication.killed_count,
        "survived_count": adjudication.survived_count,
        "invalid_count": adjudication.invalid_count,
        "adequacy_numerator": adjudication.adequacy_numerator,
        "adequacy_denominator": adjudication.adequacy_denominator,
        "concurrency_shape_count": CONCURRENCY_SHAPE_COUNT,
        "concurrency_pass_count": concurrency_pass_count,
        "overall_status": overall.value,
        "live_model_calls_performed": 0,
        "provider_calls_performed": 0,
        "google_cloud_accessed": False,
        "network_dependency_required": False,
    }
    artifact = {
        "schema_version": ADEQUACY_SCHEMA,
        "artifact_kind": ARTIFACT_KIND,
        "catalogue_version": MUTANT_CATALOGUE_VERSION,
        "domain_contract_version": PROPERTY_DOMAIN_VERSION,
        "generator_version": GENERATOR_VERSION,
        "source_revision": source_revision,
        "producer": PRODUCER,
        "seed_contract_digest": SEED_CONTRACT_DIGEST,
        "domain_contract_digest": DOMAIN_CONTRACT_DIGEST,
        "mutant_catalogue_digest": MUTANT_CATALOGUE_DIGEST,
        "property_results": properties,
        "mutant_results": mutants,
        "concurrency_results": concurrency,
        "summary": summary,
    }
    artifact["artifact_digest"] = _artifact_digest(artifact)
    validate_adequacy_artifact(artifact)
    return artifact


def _exact_keys(value: Mapping[str, object], expected: Tuple[str, ...], label: str) -> None:
    if len(value) != len(expected) or set(value) != set(expected):
        raise _drift(f"{label} keys differ")


def _exact_nonnegative_int(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise _drift(f"{label} must be a non-negative exact int")
    return value


def validate_adequacy_artifact(artifact: Mapping[str, object]) -> None:
    if not isinstance(artifact, Mapping):
        raise _drift("artifact root must be an object")
    _exact_keys(artifact, ARTIFACT_ROOT_KEYS, "artifact root")
    exact_values = {
        "schema_version": ADEQUACY_SCHEMA,
        "artifact_kind": ARTIFACT_KIND,
        "catalogue_version": MUTANT_CATALOGUE_VERSION,
        "domain_contract_version": PROPERTY_DOMAIN_VERSION,
        "generator_version": GENERATOR_VERSION,
        "producer": PRODUCER,
        "seed_contract_digest": SEED_CONTRACT_DIGEST,
        "domain_contract_digest": DOMAIN_CONTRACT_DIGEST,
        "mutant_catalogue_digest": MUTANT_CATALOGUE_DIGEST,
    }
    for key, expected in exact_values.items():
        if artifact.get(key) != expected:
            raise _drift(f"artifact {key} differs")
    source_revision = artifact.get("source_revision")
    if (
        type(source_revision) is not str
        or _LOWER_HEX_40.fullmatch(source_revision) is None
    ):
        raise _drift("artifact source_revision is invalid")

    properties = _closed_result_rows(
        artifact.get("property_results"),  # type: ignore[arg-type]
        id_key="property_id",
        expected_ids=PROPERTY_IDS,
    )
    mutants = _closed_result_rows(
        artifact.get("mutant_results"),  # type: ignore[arg-type]
        id_key="mutant_id",
        expected_ids=MUTANT_IDS,
    )
    concurrency = _closed_result_rows(
        artifact.get("concurrency_results"),  # type: ignore[arg-type]
        id_key="shape_id",
        expected_ids=CONCURRENCY_SHAPES,
    )
    property_pass_count = _status_count(properties)
    concurrency_pass_count = _status_count(concurrency)
    adjudication = adjudicate_mutants(_mutant_results(mutants))
    overall = _overall_status(
        adjudication,
        property_pass_count=property_pass_count,
        concurrency_pass_count=concurrency_pass_count,
    )

    summary = artifact.get("summary")
    if not isinstance(summary, Mapping):
        raise _drift("artifact summary must be an object")
    _exact_keys(summary, SUMMARY_KEYS, "artifact summary")
    expected_summary = {
        "property_count": PROPERTY_DOMAIN_COUNT,
        "generated_case_count": W3_TOTAL_GENERATED_CASE_COUNT,
        "property_pass_count": property_pass_count,
        "mutant_count": MUTANT_COUNT,
        "killed_count": adjudication.killed_count,
        "survived_count": adjudication.survived_count,
        "invalid_count": adjudication.invalid_count,
        "adequacy_numerator": adjudication.adequacy_numerator,
        "adequacy_denominator": adjudication.adequacy_denominator,
        "concurrency_shape_count": CONCURRENCY_SHAPE_COUNT,
        "concurrency_pass_count": concurrency_pass_count,
        "overall_status": overall.value,
        "live_model_calls_performed": 0,
        "provider_calls_performed": 0,
        "google_cloud_accessed": False,
        "network_dependency_required": False,
    }
    for key in (
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
        "live_model_calls_performed",
        "provider_calls_performed",
    ):
        _exact_nonnegative_int(summary.get(key), key)
    if type(summary.get("google_cloud_accessed")) is not bool:
        raise _drift("google_cloud_accessed must be exact bool")
    if type(summary.get("network_dependency_required")) is not bool:
        raise _drift("network_dependency_required must be exact bool")
    if dict(summary) != expected_summary:
        raise _drift("artifact summary values differ")

    artifact_digest = artifact.get("artifact_digest")
    if (
        type(artifact_digest) is not str
        or _SHA256_VALUE.fullmatch(artifact_digest) is None
        or artifact_digest != _artifact_digest(artifact)
    ):
        raise _drift("artifact digest does not verify")


def serialize_adequacy_artifact(artifact: Mapping[str, object]) -> bytes:
    validate_adequacy_artifact(artifact)
    return canonical_json_bytes(artifact, trailing_newline=True)


def _reject_duplicate_pairs(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise _drift("duplicate JSON object key")
        result[key] = value
    return result


def parse_adequacy_artifact(encoded: bytes) -> dict:
    if type(encoded) is not bytes:
        raise _drift("artifact encoding must be exact bytes")
    if not encoded.endswith(b"\n") or encoded.endswith(b"\n\n"):
        raise _drift("artifact requires exactly one trailing newline")
    try:
        text = encoded.decode("utf-8")
        parsed = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ContractDriftError) as exc:
        raise _drift("artifact is not strict UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise _drift("artifact root must be an object")
    if canonical_json_bytes(parsed, trailing_newline=True) != encoded:
        raise _drift("artifact bytes are not canonical")
    validate_adequacy_artifact(parsed)
    return parsed


validate_contract()


__all__ = (
    "ADAPTIVE_GENERATION",
    "ADEQUACY_METRIC",
    "ADEQUACY_SCHEMA",
    "ARTIFACT_KIND",
    "ARTIFACT_ROOT_KEYS",
    "CONCURRENCY_REPETITIONS_PER_SHAPE",
    "CONCURRENCY_SHAPE_COUNT",
    "CONCURRENCY_SHAPES",
    "CONTRACT_DRIFT_CODE",
    "DOMAIN_CONTRACT_DIGEST",
    "EXPECTED_INVALID_COUNT",
    "EXPECTED_KILLED_COUNT",
    "EXPECTED_SURVIVED_COUNT",
    "FIXED_SEED_COUNT",
    "GENERATOR_SOURCE",
    "GENERATOR_VERSION",
    "INVALID_COUNTS_AS_SUCCESS",
    "MUTANT_CATALOGUE",
    "MUTANT_CATALOGUE_DIGEST",
    "MUTANT_CATALOGUE_VERSION",
    "MUTANT_COUNT",
    "MUTANT_IDS",
    "NOT_APPLICABLE_ALLOWED",
    "PRODUCER",
    "PROPERTY_DOMAINS",
    "PROPERTY_DOMAIN_COUNT",
    "PROPERTY_DOMAIN_VERSION",
    "PROPERTY_IDS",
    "RUNTIME_MODEL_GENERATION",
    "SEED_CONTRACT_DIGEST",
    "SUMMARY_KEYS",
    "SURVIVOR_COUNTS_AS_SUCCESS",
    "W3_D03_SENTINEL_GENERATE_AND_REJECT",
    "W3_D03_SENTINEL_RETRY_OR_REPLACEMENT",
    "W3_D03_SENTINEL_WIDTH_SELECTION",
    "W3_D03_UNSORTED_SENTINEL_ORDINALS",
    "W3_D01_GENERATED_CASE_COUNT",
    "W3_D01_SEED",
    "W3_D02_GENERATED_CASE_COUNT",
    "W3_D02_SEED",
    "W3_D03_GENERATED_CASE_COUNT",
    "W3_D03_SEED",
    "W3_D04_GENERATED_CASE_COUNT",
    "W3_D04_SEED",
    "W3_D05_GENERATED_CASE_COUNT",
    "W3_D05_SEED",
    "W3_MAXIMUM_GENERATED_CASE_COUNT",
    "W3_TOTAL_GENERATED_CASE_COUNT",
    "AdequacyAdjudication",
    "CaseDescriptor",
    "ContractDriftError",
    "D03UnsortedSentinel",
    "MutantCategory",
    "MutantDescriptor",
    "MutantResult",
    "OverallStatus",
    "PropertyDomain",
    "Sha256Counter",
    "adjudicate_mutants",
    "d03_sentinel_width_from_decision",
    "generate_d03_unsorted_sentinel",
    "make_adequacy_artifact",
    "parse_adequacy_artifact",
    "serialize_adequacy_artifact",
    "validate_adequacy_artifact",
    "validate_case_descriptors",
    "validate_contract",
)
