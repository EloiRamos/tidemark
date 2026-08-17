"""Deterministic finalized publication packages derived from evidence."""

from dataclasses import dataclass, fields
from enum import Enum, unique
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from secrets import token_hex
from typing import Optional, Tuple, final

from tidemark.evidence.canonical import canonical_json_bytes
from tidemark.evidence.integrity import EvidenceIntegrityChecker
from tidemark.evidence.model import (
    EVIDENCE_SCHEMA_VERSION,
    AuditEvent,
    DecisionRecordedPayload,
    EvidenceEventType,
    StoredAuditEvent,
    audit_event_from_primitive,
    audit_event_to_primitive,
)
from tidemark.evidence.projection import (
    EvidenceCompleteness,
    EvidenceProjector,
    ProjectionStatus,
    REVIEW_MASKING_PROFILE_VERSION,
    review_projection_to_primitive,
)
from tidemark.evidence.reconciliation import EvidenceReconciler
from tidemark.runtime.vocabulary import DecisionOutcome


EVIDENCE_PUBLICATION_SCHEMA_VERSION = "tidemark.evidence.publication.v1"
PUBLICATION_SOURCE_SCHEMA_VERSION = "tidemark.evidence.publication-source.v1"
PUBLICATION_INTEGRITY_SCHEMA_VERSION = "tidemark.evidence.integrity.v1"
PUBLICATION_RECONCILIATION_SCHEMA_VERSION = (
    "tidemark.evidence.reconciliation.v1"
)
PUBLICATION_PROJECTION_SCHEMA_VERSION = "tidemark.evidence.review-projection.v1"
PUBLICATION_PRIVACY_SCHEMA_VERSION = (
    "tidemark.evidence.publication-privacy.v1"
)
PUBLICATION_MANIFEST_SCHEMA_VERSION = "tidemark.evidence.manifest.v1"
PUBLICATION_PACKAGE_TYPE = "FINALIZED_EVIDENCE_EXPORT"
PUBLICATION_STATUS = "FINALIZED"
PUBLICATION_DIGEST_ALGORITHM = "sha256"
INTEGRITY_CHECKER_VERSION = "tidemark.evidence.integrity-checker.v1"
RECONCILIATION_CHECKER_VERSION = "tidemark.evidence.reconciler.v1"

_SHA256_PREFIX = "sha256:"
_EXPORT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_ABSOLUTE_PATH = re.compile(
    rb"(?:/(?:Users|home|tmp|private/tmp|var/folders)/|[A-Za-z]:\\(?:Users|Temp|Documents)\\)"
)
_FORBIDDEN_PUBLICATION_DATA = re.compile(
    rb"(?:"
    rb"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    rb"AIza[0-9A-Za-z_-]{20,}|"
    rb"sk-[0-9A-Za-z_-]{16,}|"
    rb"synthetic-routing://|"
    rb"raw[_-]?prompt|"
    rb"raw[_-]?provider[_-]?output|"
    rb"(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)[\"']?\s*[:=]"
    rb")",
    re.IGNORECASE,
)

_ROOT_FIELDS = frozenset(
    (
        "schema_version",
        "package_type",
        "publication_status",
        "digest_algorithm",
        "source",
        "evidence",
        "integrity",
        "reconciliation",
        "projection",
        "privacy",
        "manifest",
        "package_digest",
    )
)
_SOURCE_FIELDS = frozenset(
    (
        "schema_version",
        "export_id",
        "export_version",
        "scope",
        "event_count",
        "first_sequence",
        "last_sequence",
        "ordered_event_ids",
        "ordered_event_digests",
        "source_digest",
        "versions",
        "expected_result_counts",
        "actual_result_counts",
    )
)
_VERSION_FIELDS = frozenset(
    (
        "evidence_schema_versions",
        "producer_versions",
        "policy_versions",
        "registry_versions",
        "adapter_versions",
        "tool_contract_versions",
        "framework_versions",
        "masking_profile_version",
    )
)
_MANIFEST_COMPONENT_ORDER = (
    "source",
    "evidence",
    "integrity",
    "reconciliation",
    "projection",
    "privacy",
)
_COMPONENT_SCHEMAS = {
    "source": PUBLICATION_SOURCE_SCHEMA_VERSION,
    "evidence": EVIDENCE_SCHEMA_VERSION,
    "integrity": PUBLICATION_INTEGRITY_SCHEMA_VERSION,
    "reconciliation": PUBLICATION_RECONCILIATION_SCHEMA_VERSION,
    "projection": PUBLICATION_PROJECTION_SCHEMA_VERSION,
    "privacy": PUBLICATION_PRIVACY_SCHEMA_VERSION,
}


class PublicationError(RuntimeError):
    """Base class for fail-closed publication errors."""


class PublicationBlockedError(PublicationError):
    """Source evidence or publication inputs cannot be finalized."""

    def __init__(self, message: str, finding_codes: Tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.finding_codes = finding_codes


class PublicationDurabilityError(PublicationError):
    """A package did not complete the local durable materialization protocol."""


class PublicationCollisionError(PublicationError):
    """A finalized destination already exists and cannot be replaced."""


@unique
class PublicationVerificationCode(str, Enum):
    MALFORMED_PACKAGE = "publication.malformed_package.v1"
    NON_CANONICAL_PACKAGE = "publication.non_canonical_package.v1"
    SCHEMA_INVALID = "publication.schema_invalid.v1"
    DIGEST_MISMATCH = "publication.digest_mismatch.v1"
    CONTENT_INVALID = "publication.content_invalid.v1"


@final
@dataclass(frozen=True)
class PublicationResultCounts:
    authoritative_event_count: int
    refusal_count: int
    deny_count: int
    allow_count: int
    model_non_attempt_count: int
    execution_start_count: int
    execution_completion_count: int
    execution_failure_count: int
    replay_rejection_count: int
    payment_count: int
    reconciliation_count: int
    prior_export_count: int

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or value < 0:
                raise ValueError("publication result counts require non-negative ints")


@final
@dataclass(frozen=True)
class PublicationRequest:
    export_id: str
    export_version: int
    trace_id: str
    expected_counts: PublicationResultCounts

    def __post_init__(self) -> None:
        if (
            type(self.export_id) is not str
            or _EXPORT_ID.fullmatch(self.export_id) is None
            or self.export_id in {".", ".."}
            or ".." in self.export_id
        ):
            raise ValueError("export_id requires a safe publication identifier")
        if type(self.export_version) is not int or self.export_version < 1:
            raise ValueError("export_version requires a positive exact int")
        if (
            type(self.trace_id) is not str
            or self.trace_id == ""
            or len(self.trace_id) > 255
            or "\x00" in self.trace_id
            or _ABSOLUTE_PATH.search(self.trace_id.encode("utf-8")) is not None
        ):
            raise ValueError("trace_id is not publication safe")
        if type(self.expected_counts) is not PublicationResultCounts:
            raise TypeError("expected_counts requires PublicationResultCounts")


@final
@dataclass(frozen=True, init=False)
class EvidencePublicationPackage:
    """Immutable canonical bytes; never an authoritative evidence store."""

    canonical_bytes: bytes
    package_digest: str
    export_id: str
    export_version: int
    trace_id: str

    @classmethod
    def _verified(
        cls,
        encoded: bytes,
        *,
        package_digest: str,
        export_id: str,
        export_version: int,
        trace_id: str,
    ) -> "EvidencePublicationPackage":
        package = object.__new__(cls)
        object.__setattr__(package, "canonical_bytes", bytes(encoded))
        object.__setattr__(package, "package_digest", package_digest)
        object.__setattr__(package, "export_id", export_id)
        object.__setattr__(package, "export_version", export_version)
        object.__setattr__(package, "trace_id", trace_id)
        return package

    def __repr__(self) -> str:
        return (
            "EvidencePublicationPackage(derived=True, immutable=True, "
            f"export_id={self.export_id!r}, export_version={self.export_version})"
        )


@final
@dataclass(frozen=True)
class PublicationVerification:
    valid: bool
    findings: Tuple[PublicationVerificationCode, ...]
    package: Optional[EvidencePublicationPackage]

    def __post_init__(self) -> None:
        if type(self.valid) is not bool:
            raise TypeError("verification validity requires bool")
        if type(self.findings) is not tuple or any(
            type(item) is not PublicationVerificationCode for item in self.findings
        ):
            raise TypeError("verification findings require closed values")
        if self.package is not None and type(self.package) is not EvidencePublicationPackage:
            raise TypeError("verified package requires EvidencePublicationPackage")
        if self.valid != (not self.findings and self.package is not None):
            raise ValueError("verification status and findings differ")


@final
@dataclass(frozen=True)
class PublicationReceipt:
    artifact_name: str
    package_digest: str
    byte_length: int

    def __post_init__(self) -> None:
        if type(self.artifact_name) is not str or self.artifact_name == "":
            raise ValueError("artifact_name is invalid")
        _require_digest(self.package_digest, "package_digest")
        if type(self.byte_length) is not int or self.byte_length < 1:
            raise ValueError("byte_length requires a positive exact int")


def _canonical_bytes(value: object) -> bytes:
    return canonical_json_bytes(value)


def _digest_bytes(value: bytes) -> str:
    return _SHA256_PREFIX + sha256(value).hexdigest()


def _require_digest(value: object, name: str) -> None:
    if (
        type(value) is not str
        or not value.startswith(_SHA256_PREFIX)
        or len(value) != 71
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise ValueError(f"{name} requires a sha256 digest")


def _event_bytes(event: StoredAuditEvent) -> bytes:
    return _canonical_bytes(audit_event_to_primitive(event)) + b"\n"


def _event_digest(event: StoredAuditEvent) -> str:
    return _digest_bytes(_event_bytes(event))


def _counts_to_primitive(counts: PublicationResultCounts) -> dict:
    return {field.name: getattr(counts, field.name) for field in fields(counts)}


def _counts_from_events(events: Tuple[AuditEvent, ...]) -> PublicationResultCounts:
    event_types = tuple(event.event_type for event in events)
    decisions = tuple(
        event.payload
        for event in events
        if event.event_type is EvidenceEventType.DECISION_RECORDED
        and type(event.payload) is DecisionRecordedPayload
    )
    return PublicationResultCounts(
        authoritative_event_count=len(events),
        refusal_count=sum(
            event_type
            in {
                EvidenceEventType.POLICY_INSTALLATION_REFUSED,
                EvidenceEventType.CALL_PREPARATION_REFUSED,
            }
            for event_type in event_types
        ),
        deny_count=sum(
            payload.outcome is DecisionOutcome.DENY for payload in decisions
        ),
        allow_count=sum(
            payload.outcome is DecisionOutcome.ALLOW for payload in decisions
        ),
        model_non_attempt_count=event_types.count(
            EvidenceEventType.RUN_MODEL_NON_ATTEMPT
        ),
        execution_start_count=event_types.count(
            EvidenceEventType.EXECUTION_STARTED
        ),
        execution_completion_count=event_types.count(
            EvidenceEventType.EXECUTION_COMPLETED
        ),
        execution_failure_count=event_types.count(
            EvidenceEventType.EXECUTION_FAILED
        ),
        replay_rejection_count=event_types.count(
            EvidenceEventType.EXECUTION_REPLAY_REJECTED
        ),
        payment_count=event_types.count(EvidenceEventType.PAYMENT_RECORDED),
        reconciliation_count=event_types.count(
            EvidenceEventType.EVIDENCE_RECONCILED
        ),
        prior_export_count=event_types.count(
            EvidenceEventType.EVIDENCE_EXPORT_FINALIZED
        ),
    )


def _version_value(value: object) -> Optional[str]:
    selected = getattr(value, "value", None)
    return selected if type(selected) is str else None


def _source_versions(events: Tuple[AuditEvent, ...]) -> dict:
    def identity_versions(attribute: str) -> list:
        return sorted(
            {
                value
                for value in (
                    _version_value(getattr(event, attribute)) for event in events
                )
                if value is not None
            }
        )

    contract_versions = sorted(
        {
            value
            for value in (
                _version_value(getattr(event.payload, "contract_version", None))
                for event in events
            )
            if value is not None
        }
    )
    framework_versions = sorted(
        {
            value
            for value in (
                getattr(event.payload, "framework_version", None)
                for event in events
            )
            if type(value) is str and value != ""
        }
    )
    producers = [
        {"component": component, "build_version": build_version}
        for component, build_version in sorted(
            {(event.producer.component, event.producer.build_version) for event in events}
        )
    ]
    return {
        "evidence_schema_versions": sorted({event.schema_version for event in events}),
        "producer_versions": producers,
        "policy_versions": identity_versions("policy_version"),
        "registry_versions": identity_versions("registry_version"),
        "adapter_versions": identity_versions("adapter_version"),
        "tool_contract_versions": contract_versions,
        "framework_versions": framework_versions,
        "masking_profile_version": REVIEW_MASKING_PROFILE_VERSION,
    }


def _ordered_authoritative_events(
    event_stream: Tuple[object, ...], request: PublicationRequest
) -> Tuple[AuditEvent, ...]:
    if type(event_stream) is not tuple:
        raise TypeError("publication source requires an exact immutable tuple")
    if not event_stream:
        raise PublicationBlockedError("publication source is empty")
    traces = {
        getattr(event, "trace_id")
        for event in event_stream
        if type(getattr(event, "trace_id", None)) is str
    }
    if traces != {request.trace_id} or len(traces) != 1:
        raise PublicationBlockedError("publication trace scope is not exact")
    ordered_source = tuple(
        sorted(
            event_stream,
            key=lambda event: getattr(event, "sequence", 0),
        )
    )
    if all(type(event) is AuditEvent for event in ordered_source) and (
        ordered_source[0].sequence != 1
        or ordered_source[0].previous_event_digest is not None
        or any(event.previous_event_digest is None for event in ordered_source[1:])
    ):
        raise PublicationBlockedError("source digest chain is incomplete")
    report = EvidenceIntegrityChecker().check(event_stream)
    if report.findings:
        raise PublicationBlockedError(
            "source evidence failed integrity or reconciliation",
            tuple(finding.code.value for finding in report.findings),
        )
    if any(type(event) is not AuditEvent for event in event_stream):
        raise PublicationBlockedError("publication source is not authoritative")
    events = tuple(sorted(event_stream, key=lambda event: event.sequence))
    if (
        events[0].sequence != 1
        or events[0].previous_event_digest is not None
        or any(event.previous_event_digest is None for event in events[1:])
    ):
        raise PublicationBlockedError("source digest chain is incomplete")
    if any(event.trace_id != request.trace_id for event in events):
        raise PublicationBlockedError("publication trace scope is not exact")
    return events


def _privacy_gate(events: Tuple[AuditEvent, ...]) -> None:
    encoded = b"".join(_event_bytes(event) for event in events)
    if _ABSOLUTE_PATH.search(encoded) is not None:
        raise PublicationBlockedError(
            "publication privacy scan failed",
            ("publication.absolute_path_detected.v1",),
        )
    if _FORBIDDEN_PUBLICATION_DATA.search(encoded) is not None:
        raise PublicationBlockedError(
            "publication privacy scan failed",
            ("publication.forbidden_data_detected.v1",),
        )


def _component_entry(
    name: str, component: dict, *, record_count: int
) -> dict:
    encoded = _canonical_bytes(component)
    return {
        "name": name,
        "media_type": "application/json",
        "schema_version": _COMPONENT_SCHEMAS[name],
        "record_count": record_count,
        "byte_length": len(encoded),
        "digest": _digest_bytes(encoded),
    }


def _prepare_components(
    event_stream: Tuple[object, ...], request: PublicationRequest
) -> dict:
    events = _ordered_authoritative_events(event_stream, request)
    _privacy_gate(events)
    actual_counts = _counts_from_events(events)
    if actual_counts != request.expected_counts:
        raise PublicationBlockedError("publication result counts do not match")
    if actual_counts.reconciliation_count and request.export_version == 1:
        raise PublicationBlockedError("a correction requires a new export version")

    projection = EvidenceProjector().project(events)
    reconciliation = EvidenceReconciler().reconcile(events)
    if (
        projection.integrity_status is not ProjectionStatus.CLEAN
        or projection.reconciliation_status is not ProjectionStatus.CLEAN
        or projection.evidence_completeness is not EvidenceCompleteness.COMPLETE
        or projection.findings
        or reconciliation.findings
    ):
        raise PublicationBlockedError("publication projection is not complete")

    event_digests = tuple(_event_digest(event) for event in events)
    source_digest = _digest_bytes(b"".join(_event_bytes(event) for event in events))
    source = {
        "schema_version": PUBLICATION_SOURCE_SCHEMA_VERSION,
        "export_id": request.export_id,
        "export_version": request.export_version,
        "scope": {"type": "TRACE", "trace_id": request.trace_id},
        "event_count": len(events),
        "first_sequence": events[0].sequence,
        "last_sequence": events[-1].sequence,
        "ordered_event_ids": [event.event_id for event in events],
        "ordered_event_digests": list(event_digests),
        "source_digest": source_digest,
        "versions": _source_versions(events),
        "expected_result_counts": _counts_to_primitive(request.expected_counts),
        "actual_result_counts": _counts_to_primitive(actual_counts),
    }
    evidence = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "records": [audit_event_to_primitive(event) for event in events],
    }
    integrity = {
        "schema_version": PUBLICATION_INTEGRITY_SCHEMA_VERSION,
        "checker_version": INTEGRITY_CHECKER_VERSION,
        "status": "CLEAN",
        "checked_record_count": len(events),
        "findings": [],
    }
    reconciliation_component = {
        "schema_version": PUBLICATION_RECONCILIATION_SCHEMA_VERSION,
        "checker_version": RECONCILIATION_CHECKER_VERSION,
        "status": "CLEAN",
        "findings": [],
    }
    projection_component = {
        "schema_version": PUBLICATION_PROJECTION_SCHEMA_VERSION,
        "value": review_projection_to_primitive(projection),
    }
    privacy = {
        "schema_version": PUBLICATION_PRIVACY_SCHEMA_VERSION,
        "masking_profile_version": REVIEW_MASKING_PROFILE_VERSION,
        "status": "PASS",
        "forbidden_data_detected": False,
        "absolute_path_detected": False,
    }
    return {
        "source": source,
        "evidence": evidence,
        "integrity": integrity,
        "reconciliation": reconciliation_component,
        "projection": projection_component,
        "privacy": privacy,
    }


def _assemble_primitive(
    event_stream: Tuple[object, ...], request: PublicationRequest
) -> dict:
    components = _prepare_components(event_stream, request)
    record_counts = {
        "source": 1,
        "evidence": components["source"]["event_count"],
        "integrity": len(components["integrity"]["findings"]),
        "reconciliation": len(components["reconciliation"]["findings"]),
        "projection": 1,
        "privacy": 1,
    }
    entries = [
        _component_entry(
            name,
            components[name],
            record_count=record_counts[name],
        )
        for name in _MANIFEST_COMPONENT_ORDER
    ]
    manifest_core = {
        "schema_version": PUBLICATION_MANIFEST_SCHEMA_VERSION,
        "digest_algorithm": PUBLICATION_DIGEST_ALGORITHM,
        "entries": entries,
    }
    manifest = dict(manifest_core)
    manifest["manifest_digest"] = _digest_bytes(_canonical_bytes(manifest_core))
    package = {
        "schema_version": EVIDENCE_PUBLICATION_SCHEMA_VERSION,
        "package_type": PUBLICATION_PACKAGE_TYPE,
        "publication_status": PUBLICATION_STATUS,
        "digest_algorithm": PUBLICATION_DIGEST_ALGORITHM,
        **components,
        "manifest": manifest,
    }
    package["package_digest"] = _digest_bytes(_canonical_bytes(package))
    return package


def build_evidence_publication(
    event_stream: Tuple[object, ...], request: PublicationRequest
) -> EvidencePublicationPackage:
    """Build one finalized trace package without mutating source evidence."""

    if type(request) is not PublicationRequest:
        raise TypeError("publication requires PublicationRequest")
    primitive = _assemble_primitive(event_stream, request)
    encoded = _canonical_bytes(primitive)
    report = verify_evidence_publication(encoded)
    if not report.valid or report.package is None:
        raise PublicationBlockedError("assembled publication failed verification")
    return report.package


class _DuplicateKeyError(ValueError):
    pass


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError("duplicate JSON key")
        result[key] = value
    return result


def _strict_json(encoded: bytes) -> object:
    if type(encoded) is not bytes or not encoded:
        raise ValueError("publication requires non-empty bytes")

    def reject_constant(value):
        raise ValueError("non-finite JSON value")

    return json.loads(
        encoded.decode("utf-8"),
        object_pairs_hook=_strict_object,
        parse_constant=reject_constant,
    )


def _exact_keys(value: object, expected: frozenset) -> bool:
    return type(value) is dict and frozenset(value) == expected


def _shape_is_closed(primitive: dict) -> bool:
    if not _exact_keys(primitive, _ROOT_FIELDS):
        return False
    source = primitive.get("source")
    if not _exact_keys(source, _SOURCE_FIELDS):
        return False
    if not _exact_keys(source.get("scope"), frozenset(("type", "trace_id"))):
        return False
    if not _exact_keys(source.get("versions"), _VERSION_FIELDS):
        return False
    count_fields = frozenset(field.name for field in fields(PublicationResultCounts))
    if not _exact_keys(source.get("expected_result_counts"), count_fields):
        return False
    if not _exact_keys(source.get("actual_result_counts"), count_fields):
        return False
    if not _exact_keys(
        primitive.get("evidence"), frozenset(("schema_version", "records"))
    ):
        return False
    if not _exact_keys(
        primitive.get("integrity"),
        frozenset(
            (
                "schema_version",
                "checker_version",
                "status",
                "checked_record_count",
                "findings",
            )
        ),
    ):
        return False
    if not _exact_keys(
        primitive.get("reconciliation"),
        frozenset(("schema_version", "checker_version", "status", "findings")),
    ):
        return False
    if not _exact_keys(
        primitive.get("projection"), frozenset(("schema_version", "value"))
    ):
        return False
    if not _exact_keys(
        primitive.get("privacy"),
        frozenset(
            (
                "schema_version",
                "masking_profile_version",
                "status",
                "forbidden_data_detected",
                "absolute_path_detected",
            )
        ),
    ):
        return False
    manifest = primitive.get("manifest")
    if not _exact_keys(
        manifest,
        frozenset(
            ("schema_version", "digest_algorithm", "entries", "manifest_digest")
        ),
    ):
        return False
    entries = manifest.get("entries")
    if type(entries) is not list or len(entries) != len(_MANIFEST_COMPONENT_ORDER):
        return False
    entry_fields = frozenset(
        (
            "name",
            "media_type",
            "schema_version",
            "record_count",
            "byte_length",
            "digest",
        )
    )
    return all(_exact_keys(entry, entry_fields) for entry in entries)


def _digest_bindings_valid(primitive: dict) -> bool:
    try:
        supplied_package_digest = primitive["package_digest"]
        _require_digest(supplied_package_digest, "package_digest")
        without_package_digest = dict(primitive)
        without_package_digest.pop("package_digest")
        if _digest_bytes(_canonical_bytes(without_package_digest)) != supplied_package_digest:
            return False

        manifest = primitive["manifest"]
        manifest_core = {
            "schema_version": manifest["schema_version"],
            "digest_algorithm": manifest["digest_algorithm"],
            "entries": manifest["entries"],
        }
        _require_digest(manifest["manifest_digest"], "manifest_digest")
        if _digest_bytes(_canonical_bytes(manifest_core)) != manifest["manifest_digest"]:
            return False
        for expected_name, entry in zip(
            _MANIFEST_COMPONENT_ORDER, manifest["entries"]
        ):
            if entry["name"] != expected_name:
                return False
            component_bytes = _canonical_bytes(primitive[expected_name])
            _require_digest(entry["digest"], "component digest")
            if entry["digest"] != _digest_bytes(component_bytes):
                return False
            if entry["byte_length"] != len(component_bytes):
                return False
        return True
    except (KeyError, TypeError, ValueError):
        return False


def _request_from_primitive(source: dict) -> PublicationRequest:
    expected_values = source["expected_result_counts"]
    counts = PublicationResultCounts(
        **{
            field.name: expected_values[field.name]
            for field in fields(PublicationResultCounts)
        }
    )
    return PublicationRequest(
        export_id=source["export_id"],
        export_version=source["export_version"],
        trace_id=source["scope"]["trace_id"],
        expected_counts=counts,
    )


def _events_from_primitive(evidence: dict) -> Tuple[AuditEvent, ...]:
    records = evidence["records"]
    if type(records) is not list:
        raise TypeError("publication evidence records require list")
    events = []
    for record in records:
        event = audit_event_from_primitive(record)
        if type(event) is not AuditEvent or audit_event_to_primitive(event) != record:
            raise ValueError("publication evidence record is not authoritative")
        events.append(event)
    return tuple(events)


def verify_evidence_publication(value: object) -> PublicationVerification:
    """Verify canonical structure and all bindings without repairing content."""

    encoded = (
        value.canonical_bytes
        if type(value) is EvidencePublicationPackage
        else value
    )
    try:
        primitive = _strict_json(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return PublicationVerification(
            False, (PublicationVerificationCode.MALFORMED_PACKAGE,), None
        )
    try:
        canonical = _canonical_bytes(primitive)
    except (TypeError, ValueError, RecursionError):
        return PublicationVerification(
            False, (PublicationVerificationCode.MALFORMED_PACKAGE,), None
        )
    if encoded != canonical:
        return PublicationVerification(
            False, (PublicationVerificationCode.NON_CANONICAL_PACKAGE,), None
        )
    if type(primitive) is not dict or not _shape_is_closed(primitive):
        return PublicationVerification(
            False, (PublicationVerificationCode.SCHEMA_INVALID,), None
        )
    if not _digest_bindings_valid(primitive):
        return PublicationVerification(
            False, (PublicationVerificationCode.DIGEST_MISMATCH,), None
        )
    if (
        primitive["schema_version"] != EVIDENCE_PUBLICATION_SCHEMA_VERSION
        or primitive["package_type"] != PUBLICATION_PACKAGE_TYPE
        or primitive["publication_status"] != PUBLICATION_STATUS
        or primitive["digest_algorithm"] != PUBLICATION_DIGEST_ALGORITHM
        or primitive["source"]["schema_version"] != PUBLICATION_SOURCE_SCHEMA_VERSION
        or primitive["source"]["scope"]["type"] != "TRACE"
        or primitive["evidence"]["schema_version"] != EVIDENCE_SCHEMA_VERSION
        or primitive["integrity"]["schema_version"] != PUBLICATION_INTEGRITY_SCHEMA_VERSION
        or primitive["integrity"]["checker_version"] != INTEGRITY_CHECKER_VERSION
        or primitive["reconciliation"]["schema_version"]
        != PUBLICATION_RECONCILIATION_SCHEMA_VERSION
        or primitive["reconciliation"]["checker_version"]
        != RECONCILIATION_CHECKER_VERSION
        or primitive["projection"]["schema_version"]
        != PUBLICATION_PROJECTION_SCHEMA_VERSION
        or primitive["privacy"]["schema_version"]
        != PUBLICATION_PRIVACY_SCHEMA_VERSION
        or primitive["manifest"]["schema_version"]
        != PUBLICATION_MANIFEST_SCHEMA_VERSION
    ):
        return PublicationVerification(
            False, (PublicationVerificationCode.SCHEMA_INVALID,), None
        )
    try:
        request = _request_from_primitive(primitive["source"])
        events = _events_from_primitive(primitive["evidence"])
        reconstructed = _assemble_primitive(events, request)
        reconstructed_encoded = _canonical_bytes(reconstructed)
    except (KeyError, TypeError, ValueError, PublicationBlockedError):
        return PublicationVerification(
            False, (PublicationVerificationCode.CONTENT_INVALID,), None
        )
    if reconstructed_encoded != encoded:
        return PublicationVerification(
            False, (PublicationVerificationCode.CONTENT_INVALID,), None
        )
    package = EvidencePublicationPackage._verified(
        encoded,
        package_digest=primitive["package_digest"],
        export_id=request.export_id,
        export_version=request.export_version,
        trace_id=request.trace_id,
    )
    return PublicationVerification(True, (), package)


def parse_evidence_publication(encoded: bytes) -> EvidencePublicationPackage:
    """Parse one valid package into an immutable inspection-only value."""

    report = verify_evidence_publication(encoded)
    if not report.valid or report.package is None:
        raise ValueError("invalid evidence publication package")
    return report.package


@final
class PublicationMaterializer:
    """Durably materialize one verified package without replacement."""

    __slots__ = ("_root",)

    def __init__(self, root_path: str) -> None:
        if type(root_path) is not str or root_path == "":
            raise ValueError("root_path requires an exact non-empty string")
        root = Path(root_path)
        try:
            root.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise PublicationDurabilityError(
                "publication root creation failed"
            ) from error
        if not root.is_dir():
            raise PublicationDurabilityError("publication root is not a directory")
        self._root = root

    def materialize(
        self, package: EvidencePublicationPackage
    ) -> PublicationReceipt:
        if type(package) is not EvidencePublicationPackage:
            raise TypeError("materialization requires EvidencePublicationPackage")
        verification = verify_evidence_publication(package.canonical_bytes)
        if not verification.valid or verification.package is None:
            raise PublicationBlockedError("publication package is not verified")
        verified_package = verification.package
        artifact_name = (
            f"{verified_package.export_id}.v{verified_package.export_version}"
            ".tidemark-evidence.json"
        )
        final_path = self._root / artifact_name
        temp_path = self._root / ("." + token_hex(32) + ".tmp")
        linked = False
        try:
            with self._open_temp(temp_path) as stream:
                written = self._write(stream, verified_package.canonical_bytes)
                if written != len(verified_package.canonical_bytes):
                    raise OSError("partial publication write")
                self._flush(stream)
                self._synchronize(stream.fileno())
            os.link(str(temp_path), str(final_path))
            linked = True
            temp_path.unlink()
            descriptor = self._open_directory()
            try:
                self._synchronize(descriptor)
            finally:
                os.close(descriptor)
        except FileExistsError as error:
            self._safe_unlink(temp_path)
            raise PublicationCollisionError(
                "finalized publication already exists"
            ) from error
        except (OSError, TypeError, ValueError) as error:
            self._safe_unlink(temp_path)
            if linked:
                self._safe_unlink(final_path)
                self._best_effort_sync_directory()
            raise PublicationDurabilityError(
                "publication was not durably materialized"
            ) from error
        return PublicationReceipt(
            artifact_name=artifact_name,
            package_digest=verified_package.package_digest,
            byte_length=len(verified_package.canonical_bytes),
        )

    def _open_temp(self, path: Path):
        return path.open("xb")

    def _write(self, stream: object, encoded: bytes) -> int:
        return stream.write(encoded)

    def _flush(self, stream: object) -> None:
        stream.flush()

    def _synchronize(self, descriptor: int) -> None:
        os.fsync(descriptor)

    def _open_directory(self) -> int:
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        return os.open(str(self._root), flags)

    def _best_effort_sync_directory(self) -> None:
        try:
            descriptor = self._open_directory()
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError:
            pass

    @staticmethod
    def _safe_unlink(path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    def __repr__(self) -> str:
        return "PublicationMaterializer(no_replace=True, atomic=True)"


__all__ = (
    "EVIDENCE_PUBLICATION_SCHEMA_VERSION",
    "EvidencePublicationPackage",
    "PublicationBlockedError",
    "PublicationCollisionError",
    "PublicationDurabilityError",
    "PublicationError",
    "PublicationMaterializer",
    "PublicationReceipt",
    "PublicationRequest",
    "PublicationResultCounts",
    "PublicationVerification",
    "PublicationVerificationCode",
    "build_evidence_publication",
    "parse_evidence_publication",
    "verify_evidence_publication",
)
