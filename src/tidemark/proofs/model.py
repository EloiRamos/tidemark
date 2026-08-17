"""Closed deterministic model for completed TIDEMARK security proof suites."""

from dataclasses import dataclass
from enum import Enum, unique
from hashlib import sha256
import json
import re
from typing import Optional, Tuple, final

from tidemark.evidence.canonical import canonical_json_bytes
from tidemark.evidence.projection import EvidenceCompleteness, ExecutionReviewStatus
from tidemark.runtime.vocabulary import (
    DecisionOutcome,
    PreparedCallState,
    RuleId,
)


PROOF_SUITE_SCHEMA = "tidemark.security-proof-suite.v1"
PROOF_SUITE_KIND = "TIDEMARK_SECURITY_PROPERTY_PROOF_SUITE"

_CATALOGUE_VERSION_PATTERN = re.compile(r"tidemark\.security-proof-catalogue\.v[1-9][0-9]*")
_PROPERTY_ID_PATTERN = re.compile(r"W2-P0[1-8]")
_FIXTURE_ID_PATTERN = re.compile(r"W2-P0[1-8]-C[0-9]{2}-[a-z0-9-]+")
_REVISION_PATTERN = re.compile(r"[0-9a-f]{40}")
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")


class ProofRecordError(ValueError):
    """A proof record is incomplete, open, noncanonical, or unverifiable."""


@unique
class ProofStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"


@unique
class ProofRunOutcome(str, Enum):
    COMPLETED = "COMPLETED"
    ERROR = "ERROR"


@unique
class ProofInfrastructureErrorCode(str, Enum):
    SELECTION_INVALID = "proof.selection_invalid.v1"
    PREFLIGHT_FAILED = "proof.preflight_failed.v1"
    PROVENANCE_FAILED = "proof.provenance_failed.v1"
    EXECUTION_ERROR = "proof.execution_error.v1"
    SURFACE_SCAN_FAILED = "proof.surface_scan_failed.v1"
    SERIALIZATION_FAILED = "proof.serialization_failed.v1"
    VERIFICATION_FAILED = "proof.verification_failed.v1"
    PUBLICATION_FAILED = "proof.publication_failed.v1"


@unique
class ExpectedSecurityOutcome(str, Enum):
    SELECTION_IS_NOT_SUPPLY = "SELECTION_IS_NOT_SUPPLY"
    ALLOW_IS_NOT_EXECUTED = "ALLOW_IS_NOT_EXECUTED"
    EVIDENCE_BEFORE_EFFECT = "EVIDENCE_BEFORE_EFFECT"
    REPLAY_IS_NOT_A_SECOND_SIDE_EFFECT = "REPLAY_IS_NOT_A_SECOND_SIDE_EFFECT"
    CONCURRENT_REPLAY_IS_LOCALLY_AT_MOST_ONCE = "CONCURRENT_REPLAY_IS_LOCALLY_AT_MOST_ONCE"
    PREPARED_CALL_TAMPERING_FAILS_CLOSED = "PREPARED_CALL_TAMPERING_FAILS_CLOSED"
    PROTECTED_REFERENCE_CONTEXT_IS_BOUND = "PROTECTED_REFERENCE_CONTEXT_IS_BOUND"
    INCOMPLETE_OR_CONFLICTING_EVIDENCE_IS_NOT_PASS = "INCOMPLETE_OR_CONFLICTING_EVIDENCE_IS_NOT_PASS"


@unique
class ProofReferenceState(str, Enum):
    NOT_FOUND = "NOT_FOUND"
    ACTIVE_UNCONSUMED = "ACTIVE_UNCONSUMED"
    INACTIVE_UNCONSUMED = "INACTIVE_UNCONSUMED"
    ACTIVE_CONSUMED = "ACTIVE_CONSUMED"
    INACTIVE_CONSUMED = "INACTIVE_CONSUMED"


@unique
class ProofExternalResultStatus(str, Enum):
    CONFIRMED_SUCCESS = "CONFIRMED_SUCCESS"
    CONFIRMED_FAILURE = "CONFIRMED_FAILURE"
    UNCONFIRMED = "UNCONFIRMED"


@unique
class ProofEvidenceStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"


@unique
class ProofFindingCode(str, Enum):
    MISSING_TERMINAL = "evidence.missing_terminal.v1"
    CONFLICTING_TERMINAL = "evidence.conflicting_terminal.v1"


def _exact_non_empty_string(value: object, name: str) -> None:
    if type(value) is not str or value == "":
        raise TypeError(f"{name} requires an exact non-empty string")


def _optional_non_negative_int(value: object, name: str) -> None:
    if value is not None and (type(value) is not int or value < 0):
        raise TypeError(f"{name} requires a non-negative exact int or None")


def _optional_exact_bool(value: object, name: str) -> None:
    if value is not None and type(value) is not bool:
        raise TypeError(f"{name} requires exact bool or None")


def _exact_tuple(value: object, item_type: type, name: str) -> None:
    if type(value) is not tuple or any(type(item) is not item_type for item in value):
        raise TypeError(f"{name} requires an exact tuple of {item_type.__name__}")


@final
@dataclass(frozen=True)
class ProofExecutionOutcomeCounts:
    refused: int
    completed: int
    failed: int
    replay_rejected: int

    def __post_init__(self) -> None:
        for name in ("refused", "completed", "failed", "replay_rejected"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise TypeError(f"{name} requires a non-negative exact int")


@final
@dataclass(frozen=True)
class ProofObservation:
    decision_outcome: Optional[DecisionOutcome]
    decision_rule_id: Optional[RuleId]
    prepared_call_count: Optional[int]
    execution_attempt_count: Optional[int]
    execution_outcomes: Optional[ProofExecutionOutcomeCounts]
    adapter_entry_count: Optional[int]
    authoritative_side_effect_count: Optional[int]
    capability_state: Optional[PreparedCallState]
    reference_states: Tuple[ProofReferenceState, ...]
    pre_execution_record_count: Optional[int]
    external_result_status: Optional[ProofExternalResultStatus]
    evidence_integrity_status: Optional[ProofEvidenceStatus]
    evidence_reconciliation_status: Optional[ProofEvidenceStatus]
    evidence_completeness: Optional[EvidenceCompleteness]
    evidence_execution_status: Optional[ExecutionReviewStatus]
    evidence_success_claimed: Optional[bool]
    external_effect_absence_claimed: Optional[bool]
    finding_codes: Tuple[ProofFindingCode, ...]

    def __post_init__(self) -> None:
        optional_enums = (
            (self.decision_outcome, DecisionOutcome, "decision_outcome"),
            (self.decision_rule_id, RuleId, "decision_rule_id"),
            (self.execution_outcomes, ProofExecutionOutcomeCounts, "execution_outcomes"),
            (self.capability_state, PreparedCallState, "capability_state"),
            (self.external_result_status, ProofExternalResultStatus, "external_result_status"),
            (self.evidence_integrity_status, ProofEvidenceStatus, "evidence_integrity_status"),
            (self.evidence_reconciliation_status, ProofEvidenceStatus, "evidence_reconciliation_status"),
            (self.evidence_completeness, EvidenceCompleteness, "evidence_completeness"),
            (self.evidence_execution_status, ExecutionReviewStatus, "evidence_execution_status"),
        )
        for value, expected, name in optional_enums:
            if value is not None and type(value) is not expected:
                raise TypeError(f"{name} requires {expected.__name__} or None")
        for name in (
            "prepared_call_count",
            "execution_attempt_count",
            "adapter_entry_count",
            "authoritative_side_effect_count",
            "pre_execution_record_count",
        ):
            _optional_non_negative_int(getattr(self, name), name)
        _exact_tuple(self.reference_states, ProofReferenceState, "reference_states")
        _exact_tuple(self.finding_codes, ProofFindingCode, "finding_codes")
        if len(self.reference_states) != len(set(self.reference_states)):
            raise ValueError("reference_states must be duplicate-free")
        if len(self.finding_codes) != len(set(self.finding_codes)):
            raise ValueError("finding_codes must be duplicate-free")
        _optional_exact_bool(self.evidence_success_claimed, "evidence_success_claimed")
        _optional_exact_bool(
            self.external_effect_absence_claimed,
            "external_effect_absence_claimed",
        )


@final
@dataclass(frozen=True)
class ProofCaseDefinition:
    fixture_id: str
    expected_security_outcome: ExpectedSecurityOutcome
    expected_observation: ProofObservation

    def __post_init__(self) -> None:
        if type(self.fixture_id) is not str or _FIXTURE_ID_PATTERN.fullmatch(self.fixture_id) is None:
            raise ValueError("fixture_id is outside the closed W2 fixture namespace")
        if type(self.expected_security_outcome) is not ExpectedSecurityOutcome:
            raise TypeError("expected_security_outcome requires closed enum")
        if type(self.expected_observation) is not ProofObservation:
            raise TypeError("expected_observation requires ProofObservation")


@final
@dataclass(frozen=True)
class ProofPropertyDefinition:
    property_id: str
    property_title: str
    claim: str
    invariant: str
    evidence_anchor_ids: Tuple[str, ...]
    expected_security_outcome: ExpectedSecurityOutcome
    fixtures: Tuple[ProofCaseDefinition, ...]
    non_claims: Tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.property_id) is not str or _PROPERTY_ID_PATTERN.fullmatch(self.property_id) is None:
            raise ValueError("property_id is outside the closed W2 property namespace")
        for name in ("property_title", "claim", "invariant"):
            _exact_non_empty_string(getattr(self, name), name)
        _exact_tuple(self.evidence_anchor_ids, str, "evidence_anchor_ids")
        _exact_tuple(self.fixtures, ProofCaseDefinition, "fixtures")
        _exact_tuple(self.non_claims, str, "non_claims")
        if not self.evidence_anchor_ids or not self.fixtures or not self.non_claims:
            raise ValueError("property metadata cannot be empty")
        if len(self.evidence_anchor_ids) != len(set(self.evidence_anchor_ids)):
            raise ValueError("evidence anchors must be duplicate-free")
        if type(self.expected_security_outcome) is not ExpectedSecurityOutcome:
            raise TypeError("expected_security_outcome requires closed enum")
        if any(
            fixture.expected_security_outcome is not self.expected_security_outcome
            or not fixture.fixture_id.startswith(self.property_id + "-")
            for fixture in self.fixtures
        ):
            raise ValueError("fixture metadata must remain bound to its property")


@final
@dataclass(frozen=True)
class ProofProvenance:
    provenance_class: str
    source_revision: str
    live_model_calls_performed: int
    google_cloud_accessed: bool

    def __post_init__(self) -> None:
        if self.provenance_class != "CLEAN_COMMITTED_LOCAL_SOURCE":
            raise ValueError("provenance_class is outside the closed value")
        if type(self.source_revision) is not str or _REVISION_PATTERN.fullmatch(self.source_revision) is None:
            raise ValueError("source_revision requires 40 lowercase hex characters")
        if type(self.live_model_calls_performed) is not int or self.live_model_calls_performed != 0:
            raise ValueError("proof provenance requires zero live model calls")
        if type(self.google_cloud_accessed) is not bool or self.google_cloud_accessed:
            raise ValueError("proof provenance requires google_cloud_accessed=false")


@final
@dataclass(frozen=True)
class ProofCaseResult:
    fixture_id: str
    expected_security_outcome: ExpectedSecurityOutcome
    observed: ProofObservation
    case_status: ProofStatus

    def __post_init__(self) -> None:
        if type(self.fixture_id) is not str or _FIXTURE_ID_PATTERN.fullmatch(self.fixture_id) is None:
            raise ValueError("fixture_id is invalid")
        if type(self.expected_security_outcome) is not ExpectedSecurityOutcome:
            raise TypeError("expected_security_outcome requires closed enum")
        if type(self.observed) is not ProofObservation:
            raise TypeError("observed requires ProofObservation")
        if type(self.case_status) is not ProofStatus:
            raise TypeError("case_status requires ProofStatus")


@final
@dataclass(frozen=True)
class ProofPropertyResult:
    property_id: str
    property_title: str
    invariant: str
    evidence_anchor_ids: Tuple[str, ...]
    expected_security_outcome: ExpectedSecurityOutcome
    cases: Tuple[ProofCaseResult, ...]
    proof_status: ProofStatus
    observation_digest: str

    def __post_init__(self) -> None:
        if type(self.property_id) is not str or _PROPERTY_ID_PATTERN.fullmatch(self.property_id) is None:
            raise ValueError("property_id is invalid")
        _exact_non_empty_string(self.property_title, "property_title")
        _exact_non_empty_string(self.invariant, "invariant")
        _exact_tuple(self.evidence_anchor_ids, str, "evidence_anchor_ids")
        _exact_tuple(self.cases, ProofCaseResult, "cases")
        if not self.evidence_anchor_ids or not self.cases:
            raise ValueError("property results require anchors and complete cases")
        if len(self.evidence_anchor_ids) != len(set(self.evidence_anchor_ids)):
            raise ValueError("property result anchors must be duplicate-free")
        if type(self.expected_security_outcome) is not ExpectedSecurityOutcome:
            raise TypeError("expected_security_outcome requires closed enum")
        if type(self.proof_status) is not ProofStatus:
            raise TypeError("proof_status requires ProofStatus")
        if any(
            item.expected_security_outcome is not self.expected_security_outcome
            for item in self.cases
        ):
            raise ValueError("case outcomes must remain bound to the property")
        expected_status = (
            ProofStatus.PASS
            if all(item.case_status is ProofStatus.PASS for item in self.cases)
            else ProofStatus.FAIL
        )
        if self.proof_status is not expected_status:
            raise ValueError("proof_status must match complete case statuses")
        if type(self.observation_digest) is not str or _DIGEST_PATTERN.fullmatch(self.observation_digest) is None:
            raise ValueError("observation_digest requires sha256 lowercase hex")


@final
@dataclass(frozen=True)
class ProofSuiteResult:
    schema_version: str
    suite_kind: str
    catalogue_version: str
    selection: Tuple[str, ...]
    catalogue_property_count: int
    executed_property_count: int
    suite_status: ProofStatus
    provenance: ProofProvenance
    properties: Tuple[ProofPropertyResult, ...]
    suite_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != PROOF_SUITE_SCHEMA:
            raise ValueError("schema_version is not the closed proof schema")
        if self.suite_kind != PROOF_SUITE_KIND:
            raise ValueError("suite_kind is not the closed proof suite kind")
        if type(self.catalogue_version) is not str or _CATALOGUE_VERSION_PATTERN.fullmatch(self.catalogue_version) is None:
            raise ValueError("catalogue_version is invalid")
        _exact_tuple(self.selection, str, "selection")
        _exact_tuple(self.properties, ProofPropertyResult, "properties")
        if not self.selection or self.selection != tuple(item.property_id for item in self.properties):
            raise ValueError("selection must exactly match ordered property results")
        if len(self.selection) != len(set(self.selection)):
            raise ValueError("selection must be duplicate-free")
        if type(self.catalogue_property_count) is not int or self.catalogue_property_count != 8:
            raise ValueError("catalogue_property_count must be exactly 8")
        if type(self.executed_property_count) is not int or self.executed_property_count != len(self.properties):
            raise ValueError("executed_property_count does not match properties")
        if type(self.suite_status) is not ProofStatus:
            raise TypeError("suite_status requires ProofStatus")
        if type(self.provenance) is not ProofProvenance:
            raise TypeError("provenance requires ProofProvenance")
        if type(self.suite_digest) is not str or _DIGEST_PATTERN.fullmatch(self.suite_digest) is None:
            raise ValueError("suite_digest requires sha256 lowercase hex")
        expected_status = (
            ProofStatus.PASS
            if all(item.proof_status is ProofStatus.PASS for item in self.properties)
            else ProofStatus.FAIL
        )
        if self.suite_status is not expected_status:
            raise ValueError("suite_status must match complete property statuses")


@final
@dataclass(frozen=True)
class ProofRunResult:
    outcome: ProofRunOutcome
    suite_result: Optional[ProofSuiteResult]
    infrastructure_error: Optional[ProofInfrastructureErrorCode]

    def __post_init__(self) -> None:
        if type(self.outcome) is not ProofRunOutcome:
            raise TypeError("outcome requires ProofRunOutcome")
        if self.outcome is ProofRunOutcome.COMPLETED:
            if type(self.suite_result) is not ProofSuiteResult or self.infrastructure_error is not None:
                raise ValueError("COMPLETED requires one suite and no infrastructure error")
        elif self.suite_result is not None or type(self.infrastructure_error) is not ProofInfrastructureErrorCode:
            raise ValueError("ERROR requires no suite and one infrastructure error")

    @classmethod
    def completed(cls, suite_result: ProofSuiteResult) -> "ProofRunResult":
        return cls(ProofRunOutcome.COMPLETED, suite_result, None)

    @classmethod
    def error(cls, code: ProofInfrastructureErrorCode) -> "ProofRunResult":
        return cls(ProofRunOutcome.ERROR, None, code)


def _enum_value(value: object) -> object:
    return value.value if isinstance(value, Enum) else value


def _counts_to_primitive(value: Optional[ProofExecutionOutcomeCounts]) -> object:
    if value is None:
        return None
    return {
        "refused": value.refused,
        "completed": value.completed,
        "failed": value.failed,
        "replay_rejected": value.replay_rejected,
    }


def proof_observation_to_primitive(value: ProofObservation) -> dict:
    if type(value) is not ProofObservation:
        raise TypeError("value requires ProofObservation")
    return {
        "decision_outcome": _enum_value(value.decision_outcome),
        "decision_rule_id": _enum_value(value.decision_rule_id),
        "prepared_call_count": value.prepared_call_count,
        "execution_attempt_count": value.execution_attempt_count,
        "execution_outcomes": _counts_to_primitive(value.execution_outcomes),
        "adapter_entry_count": value.adapter_entry_count,
        "authoritative_side_effect_count": value.authoritative_side_effect_count,
        "capability_state": _enum_value(value.capability_state),
        "reference_states": [_enum_value(item) for item in value.reference_states],
        "pre_execution_record_count": value.pre_execution_record_count,
        "external_result_status": _enum_value(value.external_result_status),
        "evidence_integrity_status": _enum_value(value.evidence_integrity_status),
        "evidence_reconciliation_status": _enum_value(value.evidence_reconciliation_status),
        "evidence_completeness": _enum_value(value.evidence_completeness),
        "evidence_execution_status": _enum_value(value.evidence_execution_status),
        "evidence_success_claimed": value.evidence_success_claimed,
        "external_effect_absence_claimed": value.external_effect_absence_claimed,
        "finding_codes": [_enum_value(item) for item in value.finding_codes],
    }


def _case_to_primitive(value: ProofCaseResult) -> dict:
    return {
        "fixture_id": value.fixture_id,
        "expected_security_outcome": value.expected_security_outcome.value,
        "observed": proof_observation_to_primitive(value.observed),
        "case_status": value.case_status.value,
    }


def _property_to_primitive(value: ProofPropertyResult) -> dict:
    return {
        "property_id": value.property_id,
        "property_title": value.property_title,
        "invariant": value.invariant,
        "evidence_anchor_ids": list(value.evidence_anchor_ids),
        "expected_security_outcome": value.expected_security_outcome.value,
        "cases": [_case_to_primitive(item) for item in value.cases],
        "proof_status": value.proof_status.value,
        "observation_digest": value.observation_digest,
    }


def _provenance_to_primitive(value: ProofProvenance) -> dict:
    return {
        "class": value.provenance_class,
        "source_revision": value.source_revision,
        "live_model_calls_performed": value.live_model_calls_performed,
        "google_cloud_accessed": value.google_cloud_accessed,
    }


def proof_suite_to_primitive(value: ProofSuiteResult) -> dict:
    if type(value) is not ProofSuiteResult:
        raise TypeError("value requires completed ProofSuiteResult")
    return {
        "schema_version": value.schema_version,
        "suite_kind": value.suite_kind,
        "catalogue_version": value.catalogue_version,
        "selection": list(value.selection),
        "catalogue_property_count": value.catalogue_property_count,
        "executed_property_count": value.executed_property_count,
        "suite_status": value.suite_status.value,
        "provenance": _provenance_to_primitive(value.provenance),
        "properties": [_property_to_primitive(item) for item in value.properties],
        "suite_digest": value.suite_digest,
    }


def _digest(value: object) -> str:
    return "sha256:" + sha256(canonical_json_bytes(value)).hexdigest()


def _observation_digest(cases: Tuple[ProofCaseResult, ...]) -> str:
    return _digest(
        [
            {
                "fixture_id": item.fixture_id,
                "observed": proof_observation_to_primitive(item.observed),
            }
            for item in cases
        ]
    )


def _suite_digest(primitive: dict) -> str:
    without_digest = dict(primitive)
    without_digest.pop("suite_digest", None)
    return _digest(without_digest)


def adjudicate_suite(
    *,
    catalogue: Tuple[ProofPropertyDefinition, ...],
    selected_property_ids: Tuple[str, ...],
    observed_by_property: Tuple[Tuple[str, Tuple[ProofObservation, ...]], ...],
    provenance: ProofProvenance,
) -> ProofSuiteResult:
    """Purely compare complete safe observations with the fixed catalogue."""

    _exact_tuple(catalogue, ProofPropertyDefinition, "catalogue")
    _exact_tuple(selected_property_ids, str, "selected_property_ids")
    if len(catalogue) != 8 or tuple(item.property_id for item in catalogue) != tuple(
        f"W2-P{index:02d}" for index in range(1, 9)
    ):
        raise ValueError("catalogue is not the exact ordered W2 catalogue")
    selected = tuple(item for item in catalogue if item.property_id in selected_property_ids)
    if tuple(item.property_id for item in selected) != selected_property_ids:
        raise ValueError("selected properties must be known, unique, and catalogue ordered")
    if type(observed_by_property) is not tuple:
        raise TypeError("observed_by_property requires an exact tuple")
    if tuple(item[0] for item in observed_by_property) != selected_property_ids:
        raise ValueError("observations must exactly match selected property order")
    observed_map = {}
    for pair in observed_by_property:
        if type(pair) is not tuple or len(pair) != 2 or type(pair[0]) is not str:
            raise TypeError("property observations require exact pairs")
        _exact_tuple(pair[1], ProofObservation, "property observations")
        observed_map[pair[0]] = pair[1]

    properties = []
    for definition in selected:
        observations = observed_map[definition.property_id]
        if len(observations) != len(definition.fixtures):
            raise ValueError("property observation count is incomplete")
        cases = tuple(
            ProofCaseResult(
                fixture_id=fixture.fixture_id,
                expected_security_outcome=fixture.expected_security_outcome,
                observed=observed,
                case_status=(
                    ProofStatus.PASS
                    if observed == fixture.expected_observation
                    else ProofStatus.FAIL
                ),
            )
            for fixture, observed in zip(definition.fixtures, observations)
        )
        proof_status = (
            ProofStatus.PASS
            if all(item.case_status is ProofStatus.PASS for item in cases)
            else ProofStatus.FAIL
        )
        properties.append(
            ProofPropertyResult(
                property_id=definition.property_id,
                property_title=definition.property_title,
                invariant=definition.invariant,
                evidence_anchor_ids=definition.evidence_anchor_ids,
                expected_security_outcome=definition.expected_security_outcome,
                cases=cases,
                proof_status=proof_status,
                observation_digest=_observation_digest(cases),
            )
        )
    property_results = tuple(properties)
    suite_status = (
        ProofStatus.PASS
        if all(item.proof_status is ProofStatus.PASS for item in property_results)
        else ProofStatus.FAIL
    )
    primitive = {
        "schema_version": PROOF_SUITE_SCHEMA,
        "suite_kind": PROOF_SUITE_KIND,
        "catalogue_version": "tidemark.security-proof-catalogue.v1",
        "selection": list(selected_property_ids),
        "catalogue_property_count": len(catalogue),
        "executed_property_count": len(property_results),
        "suite_status": suite_status.value,
        "provenance": _provenance_to_primitive(provenance),
        "properties": [_property_to_primitive(item) for item in property_results],
    }
    return ProofSuiteResult(
        schema_version=PROOF_SUITE_SCHEMA,
        suite_kind=PROOF_SUITE_KIND,
        catalogue_version="tidemark.security-proof-catalogue.v1",
        selection=selected_property_ids,
        catalogue_property_count=len(catalogue),
        executed_property_count=len(property_results),
        suite_status=suite_status,
        provenance=provenance,
        properties=property_results,
        suite_digest=_suite_digest(primitive),
    )


def _exact_keys(value: object, keys: frozenset, name: str) -> dict:
    if type(value) is not dict or frozenset(value) != keys:
        raise ProofRecordError(f"{name} has unknown or missing keys")
    return value


def _parse_enum(enum_type: type, value: object, name: str):
    if type(value) is not str:
        raise ProofRecordError(f"{name} requires an exact string enum")
    try:
        return enum_type(value)
    except ValueError as error:
        raise ProofRecordError(f"{name} contains an unknown enum value") from error


def _parse_optional_enum(enum_type: type, value: object, name: str):
    return None if value is None else _parse_enum(enum_type, value, name)


def _parse_optional_int(value: object, name: str) -> Optional[int]:
    if value is None:
        return None
    if type(value) is not int or value < 0:
        raise ProofRecordError(f"{name} requires non-negative exact int or null")
    return value


def _parse_optional_bool(value: object, name: str) -> Optional[bool]:
    if value is not None and type(value) is not bool:
        raise ProofRecordError(f"{name} requires exact bool or null")
    return value


def _parse_list(value: object, name: str) -> list:
    if type(value) is not list:
        raise ProofRecordError(f"{name} requires an exact JSON array")
    return value


def _parse_counts(value: object) -> Optional[ProofExecutionOutcomeCounts]:
    if value is None:
        return None
    source = _exact_keys(
        value,
        frozenset(("refused", "completed", "failed", "replay_rejected")),
        "execution_outcomes",
    )
    counts = tuple(_parse_optional_int(source[name], name) for name in ("refused", "completed", "failed", "replay_rejected"))
    if any(item is None for item in counts):
        raise ProofRecordError("execution outcome counts cannot be null")
    return ProofExecutionOutcomeCounts(*counts)


_OBSERVATION_KEYS = frozenset(
    (
        "decision_outcome",
        "decision_rule_id",
        "prepared_call_count",
        "execution_attempt_count",
        "execution_outcomes",
        "adapter_entry_count",
        "authoritative_side_effect_count",
        "capability_state",
        "reference_states",
        "pre_execution_record_count",
        "external_result_status",
        "evidence_integrity_status",
        "evidence_reconciliation_status",
        "evidence_completeness",
        "evidence_execution_status",
        "evidence_success_claimed",
        "external_effect_absence_claimed",
        "finding_codes",
    )
)


def _observation_from_primitive(value: object) -> ProofObservation:
    source = _exact_keys(value, _OBSERVATION_KEYS, "observed")
    references = tuple(
        _parse_enum(ProofReferenceState, item, "reference_states")
        for item in _parse_list(source["reference_states"], "reference_states")
    )
    findings = tuple(
        _parse_enum(ProofFindingCode, item, "finding_codes")
        for item in _parse_list(source["finding_codes"], "finding_codes")
    )
    return ProofObservation(
        decision_outcome=_parse_optional_enum(DecisionOutcome, source["decision_outcome"], "decision_outcome"),
        decision_rule_id=_parse_optional_enum(RuleId, source["decision_rule_id"], "decision_rule_id"),
        prepared_call_count=_parse_optional_int(source["prepared_call_count"], "prepared_call_count"),
        execution_attempt_count=_parse_optional_int(source["execution_attempt_count"], "execution_attempt_count"),
        execution_outcomes=_parse_counts(source["execution_outcomes"]),
        adapter_entry_count=_parse_optional_int(source["adapter_entry_count"], "adapter_entry_count"),
        authoritative_side_effect_count=_parse_optional_int(source["authoritative_side_effect_count"], "authoritative_side_effect_count"),
        capability_state=_parse_optional_enum(PreparedCallState, source["capability_state"], "capability_state"),
        reference_states=references,
        pre_execution_record_count=_parse_optional_int(source["pre_execution_record_count"], "pre_execution_record_count"),
        external_result_status=_parse_optional_enum(ProofExternalResultStatus, source["external_result_status"], "external_result_status"),
        evidence_integrity_status=_parse_optional_enum(ProofEvidenceStatus, source["evidence_integrity_status"], "evidence_integrity_status"),
        evidence_reconciliation_status=_parse_optional_enum(ProofEvidenceStatus, source["evidence_reconciliation_status"], "evidence_reconciliation_status"),
        evidence_completeness=_parse_optional_enum(EvidenceCompleteness, source["evidence_completeness"], "evidence_completeness"),
        evidence_execution_status=_parse_optional_enum(ExecutionReviewStatus, source["evidence_execution_status"], "evidence_execution_status"),
        evidence_success_claimed=_parse_optional_bool(source["evidence_success_claimed"], "evidence_success_claimed"),
        external_effect_absence_claimed=_parse_optional_bool(source["external_effect_absence_claimed"], "external_effect_absence_claimed"),
        finding_codes=findings,
    )


def _case_from_primitive(value: object) -> ProofCaseResult:
    source = _exact_keys(value, frozenset(("fixture_id", "expected_security_outcome", "observed", "case_status")), "case")
    return ProofCaseResult(
        fixture_id=source["fixture_id"],
        expected_security_outcome=_parse_enum(ExpectedSecurityOutcome, source["expected_security_outcome"], "expected_security_outcome"),
        observed=_observation_from_primitive(source["observed"]),
        case_status=_parse_enum(ProofStatus, source["case_status"], "case_status"),
    )


def _property_from_primitive(value: object) -> ProofPropertyResult:
    source = _exact_keys(
        value,
        frozenset(("property_id", "property_title", "invariant", "evidence_anchor_ids", "expected_security_outcome", "cases", "proof_status", "observation_digest")),
        "property",
    )
    anchors = tuple(_parse_list(source["evidence_anchor_ids"], "evidence_anchor_ids"))
    if any(type(item) is not str for item in anchors):
        raise ProofRecordError("evidence_anchor_ids require exact strings")
    cases = tuple(_case_from_primitive(item) for item in _parse_list(source["cases"], "cases"))
    result = ProofPropertyResult(
        property_id=source["property_id"],
        property_title=source["property_title"],
        invariant=source["invariant"],
        evidence_anchor_ids=anchors,
        expected_security_outcome=_parse_enum(ExpectedSecurityOutcome, source["expected_security_outcome"], "expected_security_outcome"),
        cases=cases,
        proof_status=_parse_enum(ProofStatus, source["proof_status"], "proof_status"),
        observation_digest=source["observation_digest"],
    )
    if result.observation_digest != _observation_digest(result.cases):
        raise ProofRecordError("observation digest mismatch")
    expected_status = ProofStatus.PASS if all(item.case_status is ProofStatus.PASS for item in cases) else ProofStatus.FAIL
    if result.proof_status is not expected_status:
        raise ProofRecordError("property status does not match case statuses")
    return result


def _provenance_from_primitive(value: object) -> ProofProvenance:
    source = _exact_keys(value, frozenset(("class", "source_revision", "live_model_calls_performed", "google_cloud_accessed")), "provenance")
    try:
        return ProofProvenance(
            provenance_class=source["class"],
            source_revision=source["source_revision"],
            live_model_calls_performed=source["live_model_calls_performed"],
            google_cloud_accessed=source["google_cloud_accessed"],
        )
    except (TypeError, ValueError) as error:
        raise ProofRecordError("provenance is invalid") from error


class _DuplicateKeyError(ValueError):
    pass


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError("duplicate key")
        result[key] = value
    return result


def _strict_json(encoded: bytes) -> object:
    def reject_constant(value):
        raise ValueError("non-finite JSON number")

    return json.loads(
        encoded.decode("utf-8"),
        object_pairs_hook=_strict_object,
        parse_constant=reject_constant,
    )


_ROOT_KEYS = frozenset(
    (
        "schema_version",
        "suite_kind",
        "catalogue_version",
        "selection",
        "catalogue_property_count",
        "executed_property_count",
        "suite_status",
        "provenance",
        "properties",
        "suite_digest",
    )
)


def parse_proof_suite(encoded: bytes) -> ProofSuiteResult:
    """Strictly parse and verify one canonical completed proof suite."""

    if type(encoded) is not bytes or not encoded.endswith(b"\n") or encoded.endswith(b"\n\n"):
        raise ProofRecordError("proof bytes require one trailing newline")
    try:
        primitive = _strict_json(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as error:
        raise ProofRecordError("proof bytes are not strict JSON") from error
    if canonical_json_bytes(primitive, trailing_newline=True) != encoded:
        raise ProofRecordError("proof bytes are not canonical")
    try:
        source = _exact_keys(primitive, _ROOT_KEYS, "proof suite")
        selection = tuple(_parse_list(source["selection"], "selection"))
        if any(type(item) is not str for item in selection):
            raise ProofRecordError("selection requires exact strings")
        properties = tuple(
            _property_from_primitive(item)
            for item in _parse_list(source["properties"], "properties")
        )
        if type(source["catalogue_property_count"]) is not int or type(source["executed_property_count"]) is not int:
            raise ProofRecordError("suite counts require exact integers")
        result = ProofSuiteResult(
            schema_version=source["schema_version"],
            suite_kind=source["suite_kind"],
            catalogue_version=source["catalogue_version"],
            selection=selection,
            catalogue_property_count=source["catalogue_property_count"],
            executed_property_count=source["executed_property_count"],
            suite_status=_parse_enum(ProofStatus, source["suite_status"], "suite_status"),
            provenance=_provenance_from_primitive(source["provenance"]),
            properties=properties,
            suite_digest=source["suite_digest"],
        )
    except ProofRecordError:
        raise
    except (TypeError, ValueError) as error:
        raise ProofRecordError("proof suite model is invalid") from error
    if result.suite_digest != _suite_digest(primitive):
        raise ProofRecordError("suite digest mismatch")
    return result


def serialize_proof_suite(value: ProofSuiteResult) -> bytes:
    if type(value) is not ProofSuiteResult:
        raise TypeError("only a completed ProofSuiteResult can be serialized")
    primitive = proof_suite_to_primitive(value)
    if any(item.observation_digest != _observation_digest(item.cases) for item in value.properties):
        raise ProofRecordError("observation digest mismatch")
    if value.suite_digest != _suite_digest(primitive):
        raise ProofRecordError("suite digest mismatch")
    return canonical_json_bytes(primitive, trailing_newline=True)


def verify_proof_suite_bytes(encoded: bytes) -> bool:
    parse_proof_suite(encoded)
    return True


__all__ = (
    "PROOF_SUITE_KIND",
    "PROOF_SUITE_SCHEMA",
    "ExpectedSecurityOutcome",
    "ProofCaseDefinition",
    "ProofCaseResult",
    "ProofEvidenceStatus",
    "ProofExecutionOutcomeCounts",
    "ProofExternalResultStatus",
    "ProofFindingCode",
    "ProofInfrastructureErrorCode",
    "ProofObservation",
    "ProofPropertyDefinition",
    "ProofPropertyResult",
    "ProofProvenance",
    "ProofRecordError",
    "ProofReferenceState",
    "ProofRunOutcome",
    "ProofRunResult",
    "ProofStatus",
    "ProofSuiteResult",
    "adjudicate_suite",
    "parse_proof_suite",
    "proof_observation_to_primitive",
    "proof_suite_to_primitive",
    "serialize_proof_suite",
    "verify_proof_suite_bytes",
)
