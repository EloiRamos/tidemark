"""Closed W3-B domain materializers and unmutated property detectors.

The module is test-owned. It exercises existing TIDEMARK mechanisms through
read-only or public seams and returns only deterministic, safe observations.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from hashlib import sha256
import json
from pathlib import Path
from typing import Sequence, Tuple

from tidemark.demo.rehearsal import DemoSurfaceScan, scan_demo_surfaces
from tidemark.evidence.canonical import canonical_json_bytes
from tidemark.evidence import projection as evidence_projection
from tidemark.evidence.integrity import EvidenceIntegrityChecker
from tidemark.evidence.model import AuditEvent, EvidenceEventType
from tidemark.evidence.projection import (
    EvidenceCompleteness,
    EvidenceProjector,
    ExecutionReviewStatus,
    ProjectionDisposition,
    ProjectionStatus,
    _SAFE_DISPLAY_VALUES,
    review_projection_to_primitive,
)
from tidemark.evidence.reconciliation import EvidenceReconciler
from tidemark.payment.fixtures import (
    DEFAULT_EVALUATION_TIME,
    RAW_SYNTHETIC_DESTINATION,
    SYNTHETIC_DESTINATION_KIND,
    build_synthetic_payment_fixture,
)
from tidemark.runtime.constraint_registry import (
    _ConstraintOperand,
    _protected_reference_required,
)
from tidemark.runtime.identifiers import InvocationId, ParentId, ReferenceId
from tidemark.runtime.policy_engine import ResolutionFailure, Resolved
from tidemark.runtime.prepared_call import PreparedToolCall
from tidemark.runtime.reference_resolver import ReferenceResolver, ResolutionRequest
from tidemark.runtime.vocabulary import DecisionOutcome, RuleId
from tidemark.verification.w3_contract import (
    PROPERTY_DOMAINS,
    PROPERTY_IDS,
    W3_D01_SEED,
    W3_D02_SEED,
    W3_D03_SEED,
    W3_D03_UNSORTED_SENTINEL_ORDINALS,
    W3_D04_SEED,
    W3_D05_SEED,
    W3_TOTAL_GENERATED_CASE_COUNT,
    CaseDescriptor,
    ContractDriftError,
    Sha256Counter,
    generate_d03_unsorted_sentinel,
    validate_case_descriptors,
)


D01_TAGS = (
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
D01_FULL_PATH_TAGS = (
    "NONE",
    "BOOL",
    "INT",
    "TEXT",
    "REFERENCE_SHAPED_TEXT",
    "RAW_PROTECTED_TEXT",
)
D01_DIRECT_AUTHORITY_TAGS = (
    "FINITE_FLOAT",
    "BYTES",
    "TUPLE",
    "LIST",
    "MAPPING",
    "REFERENCE_ID_SUBCLASS",
)

D02_FAMILIES = (
    "LOWERCASE_HEX_REFERENCE",
    "MIXED_CASE_HEX_REFERENCE",
    "NON_HEX_ALPHANUMERIC_REFERENCE",
    "ARBITRARY_TEXT_REFERENCE",
)

D04_CATEGORIES = (
    "CURRENT_SAFE_LITERAL",
    "STAR_MASKED_TEXT",
    "VALID_SHA256",
    "REFERENCE_TOKEN_OR_PREFIX",
    "RAW_PROTECTED_SENTINEL",
    "HTML_OR_SCRIPT_LIKE_TEXT",
    "CONTROL_OR_UNICODE_TEXT",
    "INVALID_SHA256_LOOKALIKE_OR_ARBITRARY_TEXT",
)

D05_CORRUPTION_CATEGORIES = (
    "DELETE",
    "DUPLICATE_IDENTITY",
    "DUPLICATE_SEMANTIC_WITH_FRESH_ID",
)

_D01_RAW_SENTINEL = RAW_SYNTHETIC_DESTINATION
_D03_STRING_ALPHABETS = (
    tuple("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "),
    tuple('"\\/\b\f\n\r\t'),
    tuple("<script>/=&'\""),
    tuple(chr(value) for value in range(0x00, 0x20)),
    ("é", "λ", "漢", "🙂", "Ω", "Ж"),
)
_D03_KEY_ALPHABET = tuple(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
)
_D04_SAFE_LITERALS = tuple(sorted(_SAFE_DISPLAY_VALUES))
_D05_EXPECTED_EVENT_TYPES = (
    EvidenceEventType.CALL_INTAKE_RECORDED,
    EvidenceEventType.DECISION_RECORDED,
    EvidenceEventType.EXECUTION_STARTED,
    EvidenceEventType.EXECUTION_COMPLETED,
    EvidenceEventType.PAYMENT_RECORDED,
)


class DetectorStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"


@dataclass(frozen=True)
class PropertyResult:
    property_id: str
    generated_case_count: int
    control_case_count: int
    control_passed: bool
    domain_digest: str
    detector_ids: Tuple[str, ...]
    status: DetectorStatus
    facts: Tuple[Tuple[str, object], ...]

    def fact(self, name: str) -> object:
        for key, value in self.facts:
            if key == name:
                return value
        raise KeyError(name)

    def to_primitive(self) -> dict:
        return {
            "property_id": self.property_id,
            "generated_case_count": self.generated_case_count,
            "control_case_count": self.control_case_count,
            "control_passed": self.control_passed,
            "domain_digest": self.domain_digest,
            "detector_ids": list(self.detector_ids),
            "status": self.status.value,
            "facts": {key: value for key, value in self.facts},
        }


@dataclass(frozen=True)
class W3BMaterialization:
    descriptors: Tuple[CaseDescriptor, ...]
    property_results: Tuple[PropertyResult, ...]
    descriptor_bytes: bytes
    domain_digests: Tuple[str, ...]
    property_result_bytes: bytes

    @property
    def generated_case_count(self) -> int:
        return len(self.descriptors)

    @property
    def property_count(self) -> int:
        return len(self.property_results)

    @property
    def controls_pass(self) -> bool:
        return all(result.control_passed for result in self.property_results)

    @property
    def properties_pass(self) -> bool:
        return all(
            result.status is DetectorStatus.PASS for result in self.property_results
        )


@dataclass(frozen=True)
class _GeneratedCase:
    descriptor: CaseDescriptor
    value: object = field(repr=False, compare=False)


class _ReferenceIdSubclass(ReferenceId):
    pass


class _DecisionStream:
    """Consume counter blocks in increasing order with no retry or replacement."""

    def __init__(self, domain_id: str, seed: str, ordinal: int) -> None:
        self._counter = Sha256Counter(domain_id, seed, ordinal)
        self._next_block = 0

    def bytes(self) -> bytes:
        value = self._counter.block(self._next_block)
        self._next_block += 1
        return value

    def integer(self, lower: int, upper: int) -> int:
        return Sha256Counter.map_unsigned(
            self.bytes(), lower=lower, upper=upper
        )

    def choice(self, values: Sequence[object]) -> object:
        if not values:
            raise ContractDriftError("W3_CONTRACT_DRIFT: empty generator choice")
        return values[self.integer(0, len(values) - 1)]

    def text(self, alphabet: Sequence[str], minimum: int, maximum: int) -> str:
        length = self.integer(minimum, maximum)
        return "".join(str(self.choice(alphabet)) for _ in range(length))


def _digest(value: object) -> str:
    return "sha256:" + sha256(canonical_json_bytes(value)).hexdigest()


def _safe_fingerprint_value(value: object) -> object:
    if value is None or type(value) in (str, bool, int, float):
        return value
    if isinstance(value, ReferenceId):
        return {
            "type": type(value).__name__,
            "value": value.value,
        }
    if type(value) is bytes:
        return {"type": "bytes", "hex": value.hex()}
    if type(value) in (tuple, list):
        return {
            "type": type(value).__name__,
            "items": [_safe_fingerprint_value(item) for item in value],
        }
    if type(value) is dict:
        return {
            "type": "mapping",
            "items": [
                [key, _safe_fingerprint_value(value[key])] for key in sorted(value)
            ],
        }
    raise ContractDriftError("W3_CONTRACT_DRIFT: unsupported fingerprint value")


def _descriptor(
    *,
    domain_id: str,
    ordinal: int,
    category: str,
    value: object,
    metadata: Tuple[Tuple[str, object], ...],
) -> CaseDescriptor:
    fingerprint_source = {
        "domain_id": domain_id,
        "ordinal": ordinal,
        "category": category,
        "value": _safe_fingerprint_value(value),
    }
    return CaseDescriptor(
        domain_id=domain_id,
        ordinal=ordinal,
        category=category,
        shape_metadata=metadata,
        input_fingerprint=_digest(fingerprint_source),
    )


def _descriptor_primitive(descriptor: CaseDescriptor) -> dict:
    return {
        "domain_id": descriptor.domain_id,
        "ordinal": descriptor.ordinal,
        "category": descriptor.category,
        "shape_metadata": {key: value for key, value in descriptor.shape_metadata},
        "input_fingerprint": descriptor.input_fingerprint,
    }


def _domain_digest(descriptors: Sequence[CaseDescriptor]) -> str:
    return _digest([_descriptor_primitive(item) for item in descriptors])


def _property_result(
    *,
    property_id: str,
    descriptors: Tuple[CaseDescriptor, ...],
    control_passed: bool,
    detector_ids: Tuple[str, ...],
    passed: bool,
    facts: Tuple[Tuple[str, object], ...],
) -> PropertyResult:
    return PropertyResult(
        property_id=property_id,
        generated_case_count=len(descriptors),
        control_case_count=1,
        control_passed=control_passed,
        domain_digest=_domain_digest(descriptors),
        detector_ids=detector_ids,
        status=DetectorStatus.PASS if passed and control_passed else DetectorStatus.FAIL,
        facts=facts,
    )


def _d01_value(tag: str, stream: _DecisionStream, ordinal: int) -> object:
    if tag == "NONE":
        return None
    if tag == "BOOL":
        return bool(stream.integer(0, 1))
    if tag == "INT":
        return stream.integer(-(2**31), 2**31 - 1)
    if tag == "FINITE_FLOAT":
        numerator = stream.integer(-(2**23), 2**23 - 1)
        return numerator / 1024
    if tag == "TEXT":
        return stream.text(tuple("abcdefghijklmnopqrstuvwxyz0123456789 -_"), 0, 64)
    if tag == "REFERENCE_SHAPED_TEXT":
        return "ref_" + stream.text(tuple("0123456789abcdef"), 64, 64)
    if tag == "RAW_PROTECTED_TEXT":
        return _D01_RAW_SENTINEL
    if tag == "BYTES":
        length = stream.integer(0, 8)
        return stream.bytes()[:length]
    if tag == "TUPLE":
        return tuple(stream.integer(-128, 127) for _ in range(stream.integer(0, 8)))
    if tag == "LIST":
        return [stream.integer(-128, 127) for _ in range(stream.integer(0, 8))]
    if tag == "MAPPING":
        width = stream.integer(0, 8)
        return {
            f"k{index}_{stream.text(tuple('abcdefghijklmnopqrstuvwxyz'), 1, 9)}"[:12]: (
                stream.integer(-128, 127)
            )
            for index in range(width)
        }
    if tag == "REFERENCE_ID_SUBCLASS":
        return _ReferenceIdSubclass(f"w3-d01-subclass-{ordinal:02d}")
    raise ContractDriftError("W3_CONTRACT_DRIFT: unknown D01 tag")


def _generate_d01_cases() -> Tuple[_GeneratedCase, ...]:
    cases = []
    for ordinal in range(48):
        stream = _DecisionStream("W3-D01", W3_D01_SEED, ordinal)
        tag = str(stream.choice(D01_TAGS))
        value = _d01_value(tag, stream, ordinal)
        path = "FULL_POLICY_REPRESENTATION" if tag in D01_FULL_PATH_TAGS else (
            "DIRECT_EXACT_CONSTRAINT_AUTHORITY"
        )
        descriptor = _descriptor(
            domain_id="W3-D01",
            ordinal=ordinal,
            category=tag,
            value=value,
            metadata=(("path", path),),
        )
        cases.append(_GeneratedCase(descriptor, value))
    return tuple(cases)


def run_d01_detector(
    work_root: Path, *, run_index: int
) -> Tuple[PropertyResult, Tuple[CaseDescriptor, ...]]:
    cases = _generate_d01_cases()
    fixture = build_synthetic_payment_fixture(
        str(Path(work_root)), correlation_namespace=f"w3b-d01-{run_index}"
    )
    representation_false_count = 0
    full_path_count = 0
    full_path_denied_count = 0
    full_path_exact_rule_count = 0
    direct_count = 0
    direct_false_count = 0
    observed_tags = []

    for case in cases:
        tag = case.descriptor.category
        observed_tags.append(tag)
        exact_representation = _protected_reference_required(
            _ConstraintOperand(value=case.value)
        )
        if exact_representation is False:
            representation_false_count += 1
        if tag in D01_FULL_PATH_TAGS:
            full_path_count += 1
            decision = fixture.evaluate(
                fixture.canonical_call(destination_reference=case.value)
            )
            if decision.outcome is DecisionOutcome.DENY:
                full_path_denied_count += 1
            if decision.primary_rule_id is RuleId.PROTECTED_RAW_VALUE_SUPPLIED:
                full_path_exact_rule_count += 1
        else:
            direct_count += 1
            if exact_representation is False:
                direct_false_count += 1

    negative_adapter_entries = fixture.adapter.entry_count
    negative_payment_count = fixture.payment_store.count
    negative_evidence_count = len(fixture.evidence_store.ordered_events())
    positive_call = fixture.canonical_call()
    positive_decision = fixture.evaluate(positive_call)
    positive_prepared = fixture.prepare(positive_call)
    control_passed = (
        positive_decision.outcome is DecisionOutcome.ALLOW
        and type(positive_prepared) is PreparedToolCall
        and fixture.adapter.entry_count == 0
        and fixture.payment_store.count == 0
    )
    all_tags_observed = set(observed_tags) == set(D01_TAGS)
    passed = (
        len(cases) == 48
        and all_tags_observed
        and representation_false_count == 48
        and full_path_denied_count == full_path_count
        and full_path_exact_rule_count == full_path_count
        and direct_false_count == direct_count
        and negative_adapter_entries == 0
        and negative_payment_count == 0
        and negative_evidence_count == 0
    )
    descriptors = tuple(case.descriptor for case in cases)
    facts = (
        ("all_tags_observed", all_tags_observed),
        ("representation_false_count", representation_false_count),
        ("full_path_case_count", full_path_count),
        ("full_path_denied_count", full_path_denied_count),
        ("full_path_exact_rule_count", full_path_exact_rule_count),
        ("direct_authority_case_count", direct_count),
        ("direct_authority_false_count", direct_false_count),
        ("full_path_traversal_claim_count", full_path_count),
        ("direct_full_path_traversal_claim_count", 0),
        ("prepared_call_count", 0),
        ("execution_attempt_count", 0),
        ("adapter_entry_count", negative_adapter_entries),
        ("payment_count", negative_payment_count),
        ("positive_control_allow", positive_decision.outcome is DecisionOutcome.ALLOW),
        ("positive_control_prepared", type(positive_prepared) is PreparedToolCall),
    )
    return (
        _property_result(
            property_id="W3-D01",
            descriptors=descriptors,
            control_passed=control_passed,
            detector_ids=("W3-DET-D01-EXACT-REPRESENTATION",),
            passed=passed,
            facts=facts,
        ),
        descriptors,
    )


def _d02_reference_value(
    family: str, stream: _DecisionStream, ordinal: int
) -> str:
    if family == "LOWERCASE_HEX_REFERENCE":
        return "ref_" + stream.text(tuple("0123456789abcdef"), 64, 64)
    if family == "MIXED_CASE_HEX_REFERENCE":
        tail = stream.text(tuple("0123456789abcdefABCDEF"), 62, 62)
        return "ref_aA" + tail
    if family == "NON_HEX_ALPHANUMERIC_REFERENCE":
        alphabet = tuple("ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ")
        return "ref_" + stream.text(alphabet, 64, 64)
    if family == "ARBITRARY_TEXT_REFERENCE":
        alphabet = tuple("abcXYZ09-_\\u") + ("é", "λ", "漢")
        return stream.text(alphabet, 1, 68)
    raise ContractDriftError(
        f"W3_CONTRACT_DRIFT: unknown D02 family at ordinal {ordinal}"
    )


def _generate_d02_cases() -> Tuple[_GeneratedCase, ...]:
    cases = []
    for ordinal in range(32):
        family = D02_FAMILIES[ordinal // 8]
        stream = _DecisionStream("W3-D02", W3_D02_SEED, ordinal)
        reference = ReferenceId(_d02_reference_value(family, stream, ordinal))
        descriptor = _descriptor(
            domain_id="W3-D02",
            ordinal=ordinal,
            category=family,
            value=reference,
            metadata=(("family_index", ordinal // 8),),
        )
        cases.append(_GeneratedCase(descriptor, reference))
    return tuple(cases)


def run_d02_detector(
    work_root: Path, *, run_index: int
) -> Tuple[PropertyResult, Tuple[CaseDescriptor, ...]]:
    cases = _generate_d02_cases()
    fixture = build_synthetic_payment_fixture(
        str(Path(work_root)), correlation_namespace=f"w3b-d02-{run_index}"
    )
    issued = fixture.destination_reference
    positive = ReferenceResolver().resolve(
        ResolutionRequest(
            reference_id=ReferenceId(issued.value),
            expected_kind=SYNTHETIC_DESTINATION_KIND,
            invocation_id=InvocationId(fixture.invocation_id.value),
            parent_id=ParentId(fixture.purchase_order.parent_id.value),
            argument_name="destination_reference",
            evaluation_time=DEFAULT_EVALUATION_TIME,
        ),
        fixture.reference_store,
    )
    not_found_count = 0
    protected_payload_count = 0
    generated_values = []
    for case in cases:
        reference = case.value
        generated_values.append(reference.value)
        if reference == issued:
            continue
        result = ReferenceResolver().resolve(
            ResolutionRequest(
                reference_id=reference,
                expected_kind=SYNTHETIC_DESTINATION_KIND,
                invocation_id=InvocationId(fixture.invocation_id.value),
                parent_id=ParentId(fixture.purchase_order.parent_id.value),
                argument_name="destination_reference",
                evaluation_time=DEFAULT_EVALUATION_TIME,
            ),
            fixture.reference_store,
        )
        if (
            type(result) is ResolutionFailure
            and result.rule_id is RuleId.REFERENCE_NOT_FOUND
        ):
            not_found_count += 1
        if hasattr(result, "protected_value") or hasattr(
            result, "_copy_protected_value_for_runtime"
        ):
            protected_payload_count += 1

    unique_count = len(set(generated_values))
    family_counts = tuple(
        sum(case.descriptor.category == family for case in cases)
        for family in D02_FAMILIES
    )
    control_passed = type(positive) is Resolved
    passed = (
        len(cases) == 32
        and unique_count == 32
        and issued.value not in generated_values
        and family_counts == (8, 8, 8, 8)
        and not_found_count == 32
        and protected_payload_count == 0
        and fixture.adapter.entry_count == 0
        and fixture.payment_store.count == 0
        and len(fixture.evidence_store.ordered_events()) == 0
    )
    descriptors = tuple(case.descriptor for case in cases)
    facts = (
        ("family_counts", family_counts),
        ("unique_unissued_count", unique_count),
        ("reference_not_found_count", not_found_count),
        ("protected_payload_count", protected_payload_count),
        ("prepared_call_count", 0),
        ("execution_attempt_count", 0),
        ("adapter_entry_count", fixture.adapter.entry_count),
        ("payment_count", fixture.payment_store.count),
        ("positive_control_resolved", control_passed),
        ("reference_shape_is_issuance_authority", False),
    )
    return (
        _property_result(
            property_id="W3-D02",
            descriptors=descriptors,
            control_passed=control_passed,
            detector_ids=("W3-DET-D02-UNISSUED-NOT-TRUSTED",),
            passed=passed,
            facts=facts,
        ),
        descriptors,
    )


def _d03_leaf(stream: _DecisionStream) -> object:
    leaf_type = stream.integer(0, 3)
    if leaf_type == 0:
        return None
    if leaf_type == 1:
        return bool(stream.integer(0, 1))
    if leaf_type == 2:
        return stream.integer(-(2**31), 2**31 - 1)
    alphabet = _D03_STRING_ALPHABETS[
        stream.integer(0, len(_D03_STRING_ALPHABETS) - 1)
    ]
    return stream.text(alphabet, 0, 32)


def _d03_key(stream: _DecisionStream, child_index: int) -> str:
    length = stream.integer(1, 16)
    prefix = "abcd"[child_index]
    if length == 1:
        return prefix
    return prefix + stream.text(_D03_KEY_ALPHABET, length - 1, length - 1)


def _d03_tree(stream: _DecisionStream, depth: int = 0) -> object:
    decision = stream.integer(0, 3 if depth < 3 else 0)
    if decision == 0:
        return _d03_leaf(stream)
    width = stream.integer(0, 4)
    if decision == 1:
        return [_d03_tree(stream, depth + 1) for _ in range(width)]
    if decision in (2, 3):
        values = []
        for child_index in range(width):
            key = _d03_key(stream, child_index)
            values.append((key, _d03_tree(stream, depth + 1)))
        if len({key for key, _ in values}) != width:
            raise ContractDriftError("W3_CONTRACT_DRIFT: duplicate D03 object key")
        return dict(values)
    raise ContractDriftError("W3_CONTRACT_DRIFT: unknown D03 decision")


def _json_shape(value: object) -> str:
    if value is None:
        return "NULL"
    if type(value) is bool:
        return "BOOL"
    if type(value) is int:
        return "INT"
    if type(value) is str:
        return "STRING"
    if type(value) is list:
        return "ARRAY"
    if type(value) is dict:
        return "OBJECT"
    raise ContractDriftError("W3_CONTRACT_DRIFT: unsupported D03 JSON shape")


def _generate_d03_cases() -> Tuple[_GeneratedCase, ...]:
    cases = []
    for ordinal in range(48):
        if ordinal in W3_D03_UNSORTED_SENTINEL_ORDINALS:
            sentinel = generate_d03_unsorted_sentinel(ordinal)
            value = sentinel.mapping
            category = "UNSORTED_OBJECT_SENTINEL"
            metadata = (
                ("trailing_newline", bool(ordinal % 2)),
                ("sentinel_width", sentinel.width),
                ("insertion_rule", "REVERSE_LEXICOGRAPHIC"),
            )
        else:
            stream = _DecisionStream("W3-D03", W3_D03_SEED, ordinal)
            value = _d03_tree(stream)
            category = _json_shape(value)
            metadata = (
                ("trailing_newline", bool(ordinal % 2)),
                ("maximum_depth", 3),
                ("maximum_width", 4),
            )
        descriptor = _descriptor(
            domain_id="W3-D03",
            ordinal=ordinal,
            category=category,
            value=value,
            metadata=metadata,
        )
        cases.append(_GeneratedCase(descriptor, value))
    return tuple(cases)


def _independent_json_bytes(value: object, trailing_newline: bool) -> bytes:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return encoded + (b"\n" if trailing_newline else b"")


def run_d03_detector() -> Tuple[PropertyResult, Tuple[CaseDescriptor, ...]]:
    cases = _generate_d03_cases()
    valid_json = 0
    newline_false = 0
    newline_true = 0
    round_trip = 0
    second_identity = 0
    sentinel_widths = 0
    sentinel_unsorted = 0
    sentinel_sorted_bytes = 0

    for case in cases:
        newline = bool(case.descriptor.ordinal % 2)
        production = canonical_json_bytes(case.value, trailing_newline=newline)
        expected = _independent_json_bytes(case.value, newline)
        try:
            parsed = json.loads(production.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        valid_json += 1
        actual_newlines = production.count(b"\n")
        if newline and actual_newlines == 1 and production.endswith(b"\n"):
            newline_true += 1
        if not newline and actual_newlines == 0 and not production.endswith(b"\n"):
            newline_false += 1
        if canonical_json_bytes(parsed, trailing_newline=newline) == production:
            round_trip += 1
        if canonical_json_bytes(case.value, trailing_newline=newline) == production:
            second_identity += 1
        if case.descriptor.ordinal in W3_D03_UNSORTED_SENTINEL_ORDINALS:
            keys = tuple(case.value)
            if len(keys) in {2, 3, 4}:
                sentinel_widths += 1
            if keys != tuple(sorted(keys)):
                sentinel_unsorted += 1
            if production == expected:
                sentinel_sorted_bytes += 1

    control = {"b": 2, "a": 1}
    control_passed = canonical_json_bytes(control) == _independent_json_bytes(
        control, False
    )
    descriptors = tuple(case.descriptor for case in cases)
    passed = (
        valid_json == 48
        and newline_false == 24
        and newline_true == 24
        and round_trip == 48
        and second_identity == 48
        and sentinel_widths == 4
        and sentinel_unsorted == 4
        and sentinel_sorted_bytes == 4
    )
    facts = (
        ("valid_utf8_json_count", valid_json),
        ("newline_false_count", newline_false),
        ("newline_true_count", newline_true),
        ("parse_reserialize_identity_count", round_trip),
        ("second_serialization_identity_count", second_identity),
        ("sentinel_ordinals", W3_D03_UNSORTED_SENTINEL_ORDINALS),
        ("sentinel_count", 4),
        ("sentinel_widths_valid_count", sentinel_widths),
        ("sentinel_insertion_unsorted_count", sentinel_unsorted),
        ("sentinel_independent_sorted_bytes_count", sentinel_sorted_bytes),
        ("positive_control_passed", control_passed),
    )
    return (
        _property_result(
            property_id="W3-D03",
            descriptors=descriptors,
            control_passed=control_passed,
            detector_ids=("W3-DET-D03-CANONICAL-ROUND-TRIP",),
            passed=passed,
            facts=facts,
        ),
        descriptors,
    )


def _d04_value(category: str, stream: _DecisionStream, ordinal: int) -> str:
    family_index = ordinal % 8
    if category == "CURRENT_SAFE_LITERAL":
        return _D04_SAFE_LITERALS[family_index % len(_D04_SAFE_LITERALS)]
    if category == "STAR_MASKED_TEXT":
        return f"masked-****{family_index:04d}"
    if category == "VALID_SHA256":
        return "sha256:" + stream.text(tuple("0123456789abcdef"), 64, 64)
    if category == "REFERENCE_TOKEN_OR_PREFIX":
        return "ref_" + stream.text(tuple("0123456789abcdef"), 8, 64)
    if category == "RAW_PROTECTED_SENTINEL":
        return f"{RAW_SYNTHETIC_DESTINATION}#{family_index}"
    if category == "HTML_OR_SCRIPT_LIKE_TEXT":
        return f"<script data-w3='{family_index}'>alert(1)</script>"
    if category == "CONTROL_OR_UNICODE_TEXT":
        return f"control\x00\nλ漢-{family_index}"
    if category == "INVALID_SHA256_LOOKALIKE_OR_ARBITRARY_TEXT":
        variants = (
            "SHA256:" + ("a" * 64),
            "sha256:" + ("A" * 64),
            "sha256:" + ("g" * 64),
            "sha256:" + ("a" * 63),
            "sha-256:" + ("a" * 64),
            "arbitrary-unknown-value",
            "sha256",
            "",
        )
        return variants[family_index]
    raise ContractDriftError("W3_CONTRACT_DRIFT: unknown D04 category")


def _generate_d04_cases() -> Tuple[_GeneratedCase, ...]:
    cases = []
    for ordinal in range(64):
        category = D04_CATEGORIES[ordinal // 8]
        stream = _DecisionStream("W3-D04", W3_D04_SEED, ordinal)
        value = _d04_value(category, stream, ordinal)
        descriptor = _descriptor(
            domain_id="W3-D04",
            ordinal=ordinal,
            category=category,
            value=value,
            metadata=(("category_index", ordinal // 8),),
        )
        cases.append(_GeneratedCase(descriptor, value))
    return tuple(cases)


def run_d04_detector(
    work_root: Path, *, run_index: int
) -> Tuple[PropertyResult, Tuple[CaseDescriptor, ...]]:
    cases = _generate_d04_cases()
    expected_unchanged = 0
    expected_masked = 0
    matched = 0
    unsafe_unchanged = 0
    safe_categories = {
        "CURRENT_SAFE_LITERAL",
        "STAR_MASKED_TEXT",
        "VALID_SHA256",
    }
    for case in cases:
        output = evidence_projection._safe_display(case.value)
        if case.descriptor.category in safe_categories:
            expected_unchanged += 1
            if output == case.value:
                matched += 1
        else:
            expected_masked += 1
            if output == "masked-value-omitted" and output != case.value:
                matched += 1
            if output == case.value:
                unsafe_unchanged += 1

    fixture = build_synthetic_payment_fixture(
        str(Path(work_root)), correlation_namespace=f"w3b-d04-{run_index}"
    )
    prepared = fixture.prepare(fixture.canonical_call())
    if type(prepared) is PreparedToolCall:
        fixture.execution_gate.execute(prepared)
    projection = EvidenceProjector().project(fixture.evidence_store.ordered_events())
    projection_bytes = canonical_json_bytes(review_projection_to_primitive(projection))
    projection_displays = tuple(fact.masked_display for fact in projection.argument_facts)
    integration_control = (
        type(prepared) is PreparedToolCall
        and projection.disposition is ProjectionDisposition.ALLOW
        and projection.execution_status is ExecutionReviewStatus.COMPLETED
        and projection.payment_count == 1
        and all(
            evidence_projection._safe_display(value) == value
            for value in projection_displays
        )
        and RAW_SYNTHETIC_DESTINATION.encode("utf-8") not in projection_bytes
    )
    category_counts = tuple(
        sum(case.descriptor.category == category for case in cases)
        for category in D04_CATEGORIES
    )
    passed = (
        len(cases) == 64
        and category_counts == (8, 8, 8, 8, 8, 8, 8, 8)
        and expected_unchanged == 24
        and expected_masked == 40
        and matched == 64
        and unsafe_unchanged == 0
    )
    descriptors = tuple(case.descriptor for case in cases)
    facts = (
        ("category_counts", category_counts),
        ("expected_unchanged_count", expected_unchanged),
        ("expected_masked_count", expected_masked),
        ("safe_display_match_count", matched),
        ("unsafe_returned_unchanged_count", unsafe_unchanged),
        ("projection_integration_control_passed", integration_control),
    )
    return (
        _property_result(
            property_id="W3-D04",
            descriptors=descriptors,
            control_passed=integration_control,
            detector_ids=("W3-DET-D04-SAFE-DISPLAY-CLOSED",),
            passed=passed,
            facts=facts,
        ),
        descriptors,
    )


@dataclass(frozen=True)
class _D05Corruption:
    category: str
    target_index: int


def _ordered_d05_corruptions() -> Tuple[_D05Corruption, ...]:
    corruptions = tuple(
        [_D05Corruption("DELETE", index) for index in range(5)]
        + [_D05Corruption("DUPLICATE_IDENTITY", index) for index in range(5)]
        + [
            _D05Corruption("DUPLICATE_SEMANTIC_WITH_FRESH_ID", index)
            for index in (1, 3, 4)
        ]
    )
    ranked = []
    for index, corruption in enumerate(corruptions):
        rank = Sha256Counter("W3-D05", W3_D05_SEED, index).block(0)
        ranked.append((rank, index, corruption))
    return tuple(item[2] for item in sorted(ranked))


def _normalize_events(events: Sequence[AuditEvent]) -> Tuple[AuditEvent, ...]:
    return tuple(
        replace(event, sequence=index, previous_event_digest=None)
        for index, event in enumerate(events, 1)
    )


def _apply_d05_corruption(
    events: Tuple[AuditEvent, ...], corruption: _D05Corruption, ordinal: int
) -> Tuple[AuditEvent, ...]:
    if corruption.category == "DELETE":
        selected = tuple(
            event for index, event in enumerate(events) if index != corruption.target_index
        )
    elif corruption.category == "DUPLICATE_IDENTITY":
        selected = events + (events[corruption.target_index],)
    elif corruption.category == "DUPLICATE_SEMANTIC_WITH_FRESH_ID":
        duplicate = replace(
            events[corruption.target_index],
            event_id=f"w3-d05-fresh-semantic-{ordinal:02d}",
        )
        selected = events + (duplicate,)
    else:
        raise ContractDriftError("W3_CONTRACT_DRIFT: unknown D05 corruption")
    return _normalize_events(selected)


def _d05_semantics_preserved(
    stream: Tuple[AuditEvent, ...],
    base_events: Tuple[AuditEvent, ...],
    corruption: _D05Corruption,
) -> bool:
    target = base_events[corruption.target_index]
    if corruption.category == "DELETE":
        return sum(event.event_type is target.event_type for event in stream) == 0
    if corruption.category == "DUPLICATE_IDENTITY":
        return sum(event.event_id == target.event_id for event in stream) == 2
    if corruption.category == "DUPLICATE_SEMANTIC_WITH_FRESH_ID":
        matching = tuple(event for event in stream if event.event_type is target.event_type)
        return len(matching) == 2 and len({event.event_id for event in matching}) == 2
    return False


def _clean_success(projection) -> bool:
    return (
        projection.disposition is ProjectionDisposition.ALLOW
        and projection.execution_status is ExecutionReviewStatus.COMPLETED
        and projection.payment_count == 1
        and projection.integrity_status is ProjectionStatus.CLEAN
        and projection.reconciliation_status is ProjectionStatus.CLEAN
        and projection.evidence_completeness is EvidenceCompleteness.COMPLETE
    )


def run_d05_detector(
    work_root: Path, *, run_index: int
) -> Tuple[PropertyResult, Tuple[CaseDescriptor, ...]]:
    fixture = build_synthetic_payment_fixture(
        str(Path(work_root)), correlation_namespace=f"w3b-d05-{run_index}"
    )
    prepared = fixture.prepare(fixture.canonical_call())
    if type(prepared) is PreparedToolCall:
        fixture.execution_gate.execute(prepared)
    events = fixture.evidence_store.ordered_events()
    original_events = tuple(events)
    base_types_exact = tuple(event.event_type for event in events) == (
        _D05_EXPECTED_EVENT_TYPES
    )
    control_projection = EvidenceProjector().project(events)
    control_passed = len(events) == 5 and base_types_exact and _clean_success(
        control_projection
    )

    descriptors = []
    normalized_count = 0
    contiguous_count = 0
    none_digest_count = 0
    preserved_count = 0
    clean_success_count = 0
    finding_count = 0
    source_mutated_count = 0
    corruptions = _ordered_d05_corruptions()
    for ordinal, corruption in enumerate(corruptions):
        stream = _apply_d05_corruption(events, corruption, ordinal)
        normalized_count += 1
        if tuple(event.sequence for event in stream) == tuple(
            range(1, len(stream) + 1)
        ):
            contiguous_count += 1
        if all(event.previous_event_digest is None for event in stream):
            none_digest_count += 1
        if _d05_semantics_preserved(stream, events, corruption):
            preserved_count += 1
        integrity = EvidenceIntegrityChecker().check(stream)
        reconciliation = EvidenceReconciler().reconcile(stream)
        projection = EvidenceProjector().project(stream)
        if integrity.findings or reconciliation.findings or projection.findings:
            finding_count += 1
        if _clean_success(projection):
            clean_success_count += 1
        if events != original_events:
            source_mutated_count += 1
        target_type = events[corruption.target_index].event_type.value
        descriptor_value = {
            "category": corruption.category,
            "target_event_type": target_type,
        }
        descriptors.append(
            _descriptor(
                domain_id="W3-D05",
                ordinal=ordinal,
                category=corruption.category,
                value=descriptor_value,
                metadata=(("target_event_type", target_type),),
            )
        )

    category_counts = tuple(
        sum(item.category == category for item in corruptions)
        for category in D05_CORRUPTION_CATEGORIES
    )
    closed_descriptors = tuple(descriptors)
    passed = (
        len(closed_descriptors) == 13
        and category_counts == (5, 5, 3)
        and normalized_count == 13
        and contiguous_count == 13
        and none_digest_count == 13
        and preserved_count == 13
        and finding_count == 13
        and clean_success_count == 0
        and source_mutated_count == 0
        and events == original_events
    )
    facts = (
        ("corruption_category_counts", category_counts),
        ("normalized_corruption_count", normalized_count),
        ("contiguous_sequence_count", contiguous_count),
        ("all_previous_digest_none_count", none_digest_count),
        ("selected_semantics_preserved_count", preserved_count),
        ("source_events_mutated_count", source_mutated_count),
        ("clean_success_count", clean_success_count),
        ("positive_control_clean_success", control_passed),
    )
    return (
        _property_result(
            property_id="W3-D05",
            descriptors=closed_descriptors,
            control_passed=control_passed,
            detector_ids=("W3-DET-D05-CORRUPTION-NOT-CLEAN-SUCCESS",),
            passed=passed,
            facts=facts,
        ),
        closed_descriptors,
    )


def materialize_w3_b(work_root: Path, *, run_index: int) -> W3BMaterialization:
    if type(run_index) is not int or run_index not in (0, 1, 2):
        raise ContractDriftError("W3_CONTRACT_DRIFT: W3-B run index must be 0, 1, or 2")
    root = Path(work_root)
    root.mkdir(parents=True, exist_ok=False)
    d01 = run_d01_detector(root / "d01", run_index=run_index)
    d02 = run_d02_detector(root / "d02", run_index=run_index)
    d03 = run_d03_detector()
    d04 = run_d04_detector(root / "d04", run_index=run_index)
    d05 = run_d05_detector(root / "d05", run_index=run_index)
    rows = (d01, d02, d03, d04, d05)
    results = tuple(row[0] for row in rows)
    descriptors = validate_case_descriptors(
        tuple(descriptor for row in rows for descriptor in row[1])
    )
    if tuple(result.property_id for result in results) != PROPERTY_IDS:
        raise ContractDriftError("W3_CONTRACT_DRIFT: W3-B property order differs")
    if len(descriptors) != W3_TOTAL_GENERATED_CASE_COUNT:
        raise ContractDriftError("W3_CONTRACT_DRIFT: W3-B case count differs")
    expected_counts = tuple(domain.generated_case_count for domain in PROPERTY_DOMAINS)
    if tuple(result.generated_case_count for result in results) != expected_counts:
        raise ContractDriftError("W3_CONTRACT_DRIFT: W3-B domain counts differ")
    descriptor_bytes = canonical_json_bytes(
        [_descriptor_primitive(descriptor) for descriptor in descriptors]
    )
    domain_digests = tuple(result.domain_digest for result in results)
    property_result_bytes = canonical_json_bytes(
        [result.to_primitive() for result in results]
    )
    return W3BMaterialization(
        descriptors=descriptors,
        property_results=results,
        descriptor_bytes=descriptor_bytes,
        domain_digests=domain_digests,
        property_result_bytes=property_result_bytes,
    )


def scan_w3_b_surfaces(materialization: W3BMaterialization) -> DemoSurfaceScan:
    if type(materialization) is not W3BMaterialization:
        raise TypeError("W3-B surface scan requires exact materialization")
    return scan_demo_surfaces(
        (
            ("w3-b-descriptors.json", materialization.descriptor_bytes),
            ("w3-b-property-results.json", materialization.property_result_bytes),
        ),
        extra_forbidden_values=(RAW_SYNTHETIC_DESTINATION.encode("utf-8"),),
    )


__all__ = (
    "D01_DIRECT_AUTHORITY_TAGS",
    "D01_FULL_PATH_TAGS",
    "D01_TAGS",
    "D02_FAMILIES",
    "D04_CATEGORIES",
    "D05_CORRUPTION_CATEGORIES",
    "DetectorStatus",
    "PropertyResult",
    "W3BMaterialization",
    "materialize_w3_b",
    "run_d01_detector",
    "run_d03_detector",
    "scan_w3_b_surfaces",
)
