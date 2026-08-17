"""Closed canonical manifest for every public TIDEMARK demo artifact set."""

from dataclasses import dataclass, replace
from enum import Enum, unique
from hashlib import sha256
from importlib import metadata
import json
from pathlib import Path, PurePath, PureWindowsPath
import platform
import re
from typing import Optional, Tuple, final

from tidemark.demo.preflight import (
    RepositoryProvenance,
    TIDEMARK_VERSION,
    recheck_repository_provenance,
)
from tidemark.demo.rehearsal import DemoRehearsalArtifact, scan_demo_surfaces
from tidemark.evidence.canonical import canonical_json_bytes
from tidemark.ui.final_ui import DESIGN_AUTHORITY


RUN_MANIFEST_SCHEMA_VERSION = "tidemark.demo.run-manifest.v1"
RUN_MANIFEST_KIND = "TIDEMARK_DEMO_RUN"
PROVENANCE_CLASS = "DETERMINISTIC_OFFLINE_NOT_CURRENT_LIVE_PROVIDER_OUTPUT"
_CAPTURE_SCHEMA = "tidemark.demo.capture-rehearsal.v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_SAFE_LEAF = re.compile(r"[a-z0-9][a-z0-9.-]{0,127}\Z")


@unique
class RunMode(str, Enum):
    STANDARD = "STANDARD"
    CAPTURE = "CAPTURE"
    DETERMINISTIC_FALLBACK = "DETERMINISTIC_FALLBACK"


@unique
class ManifestPresentationMode(str, Enum):
    NORMAL = "NORMAL"
    VIDEO_SAFE = "VIDEO_SAFE"


@unique
class RunManifestFailureCode(str, Enum):
    INVALID_INPUT = "demo.manifest.invalid_input.v1"
    PROVENANCE_FAILED = "demo.manifest.provenance_failed.v1"
    SURFACE_SCAN_FAILED = "demo.manifest.surface_scan_failed.v1"
    NON_CANONICAL = "demo.manifest.non_canonical.v1"
    DIGEST_MISMATCH = "demo.manifest.digest_mismatch.v1"
    ARTIFACT_SET_MISMATCH = "demo.manifest.artifact_set_mismatch.v1"


class RunManifestError(RuntimeError):
    __slots__ = ("code",)

    def __init__(self, code: RunManifestFailureCode) -> None:
        self.code = code
        super().__init__(code.value)


def _require_exact_string(value: object, name: str) -> str:
    if type(value) is not str or not value:
        raise RunManifestError(RunManifestFailureCode.INVALID_INPUT)
    return value


def _safe_leaf(value: object) -> str:
    name = _require_exact_string(value, "logical_name")
    if (
        _SAFE_LEAF.fullmatch(name) is None
        or name in {".", "..", "run-manifest.json"}
        or ".." in name
        or PurePath(name).name != name
        or PureWindowsPath(name).name != name
        or PureWindowsPath(name).drive
    ):
        raise RunManifestError(RunManifestFailureCode.INVALID_INPUT)
    return name


def _digest_bytes(content: bytes) -> str:
    return f"sha256:{sha256(content).hexdigest()}"


@final
@dataclass(frozen=True)
class ManifestSoftware:
    tidemark_version: str
    python_version: str
    source_revision: str

    def __post_init__(self) -> None:
        if self.tidemark_version != TIDEMARK_VERSION:
            raise RunManifestError(RunManifestFailureCode.INVALID_INPUT)
        if type(self.python_version) is not str or not re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+", self.python_version
        ):
            raise RunManifestError(RunManifestFailureCode.INVALID_INPUT)
        if type(self.source_revision) is not str or _COMMIT.fullmatch(
            self.source_revision
        ) is None:
            raise RunManifestError(RunManifestFailureCode.INVALID_INPUT)


@final
@dataclass(frozen=True)
class ManifestSchemas:
    rehearsal_schema: str
    capture_schema: Optional[str]
    manifest_schema: str
    design_authority: str

    def __post_init__(self) -> None:
        if (
            self.rehearsal_schema != "tidemark.demo.rehearsal.v1"
            or self.capture_schema not in {None, _CAPTURE_SCHEMA}
            or self.manifest_schema != RUN_MANIFEST_SCHEMA_VERSION
            or self.design_authority != DESIGN_AUTHORITY
        ):
            raise RunManifestError(RunManifestFailureCode.INVALID_INPUT)


@final
@dataclass(frozen=True)
class ManifestCounts:
    fresh_run_count: int
    scenario_count: int
    artifact_count: int

    def __post_init__(self) -> None:
        if any(type(value) is not int or value < 1 for value in (
            self.fresh_run_count,
            self.scenario_count,
            self.artifact_count,
        )):
            raise RunManifestError(RunManifestFailureCode.INVALID_INPUT)


@final
@dataclass(frozen=True)
class ManifestArtifact:
    logical_name: str
    media_type: str
    byte_length: int
    digest: str

    def __post_init__(self) -> None:
        _safe_leaf(self.logical_name)
        if self.media_type not in {"text/html", "application/json"}:
            raise RunManifestError(RunManifestFailureCode.INVALID_INPUT)
        if type(self.byte_length) is not int or self.byte_length < 1:
            raise RunManifestError(RunManifestFailureCode.INVALID_INPUT)
        if type(self.digest) is not str or _DIGEST.fullmatch(self.digest) is None:
            raise RunManifestError(RunManifestFailureCode.INVALID_INPUT)


@final
@dataclass(frozen=True)
class RunManifest:
    schema_version: str
    manifest_kind: str
    run_mode: RunMode
    presentation_mode: ManifestPresentationMode
    status: str
    provenance_class: str
    software: ManifestSoftware
    schemas: ManifestSchemas
    counts: ManifestCounts
    artifacts: Tuple[ManifestArtifact, ...]
    manifest_digest: str

    def __post_init__(self) -> None:
        if (
            self.schema_version != RUN_MANIFEST_SCHEMA_VERSION
            or self.manifest_kind != RUN_MANIFEST_KIND
            or type(self.run_mode) is not RunMode
            or type(self.presentation_mode) is not ManifestPresentationMode
            or self.status != "PASS"
            or self.provenance_class != PROVENANCE_CLASS
            or type(self.software) is not ManifestSoftware
            or type(self.schemas) is not ManifestSchemas
            or type(self.counts) is not ManifestCounts
            or type(self.artifacts) is not tuple
            or any(type(item) is not ManifestArtifact for item in self.artifacts)
            or type(self.manifest_digest) is not str
            or _DIGEST.fullmatch(self.manifest_digest) is None
        ):
            raise RunManifestError(RunManifestFailureCode.INVALID_INPUT)
        names = tuple(item.logical_name for item in self.artifacts)
        if names != tuple(sorted(names)) or len(names) != len(set(names)):
            raise RunManifestError(RunManifestFailureCode.INVALID_INPUT)
        if self.counts.artifact_count != len(self.artifacts):
            raise RunManifestError(RunManifestFailureCode.INVALID_INPUT)


def _artifact_primitive(artifact: ManifestArtifact) -> dict:
    return {
        "logical_name": artifact.logical_name,
        "media_type": artifact.media_type,
        "byte_length": artifact.byte_length,
        "digest": artifact.digest,
    }


def _primitive(manifest: RunManifest, *, include_digest: bool = True) -> dict:
    value = {
        "schema_version": manifest.schema_version,
        "manifest_kind": manifest.manifest_kind,
        "run_mode": manifest.run_mode.value,
        "presentation_mode": manifest.presentation_mode.value,
        "status": manifest.status,
        "provenance_class": manifest.provenance_class,
        "software": {
            "tidemark_version": manifest.software.tidemark_version,
            "python_version": manifest.software.python_version,
            "source_revision": manifest.software.source_revision,
        },
        "schemas": {
            "rehearsal_schema": manifest.schemas.rehearsal_schema,
            "capture_schema": manifest.schemas.capture_schema,
            "manifest_schema": manifest.schemas.manifest_schema,
            "design_authority": manifest.schemas.design_authority,
        },
        "counts": {
            "fresh_run_count": manifest.counts.fresh_run_count,
            "scenario_count": manifest.counts.scenario_count,
            "artifact_count": manifest.counts.artifact_count,
        },
        "artifacts": [_artifact_primitive(item) for item in manifest.artifacts],
    }
    if include_digest:
        value["manifest_digest"] = manifest.manifest_digest
    return value


def build_run_manifest(
    *,
    repository_provenance: RepositoryProvenance,
    run_mode: RunMode,
    presentation_mode: ManifestPresentationMode,
    artifacts: Tuple[DemoRehearsalArtifact, ...],
    fresh_run_count: int,
    scenario_count: int,
    capture_schema: Optional[str],
) -> RunManifest:
    """Build only after the exact preflight repository is re-attested."""

    if not recheck_repository_provenance(repository_provenance):
        raise RunManifestError(RunManifestFailureCode.PROVENANCE_FAILED)
    if (
        type(run_mode) is not RunMode
        or type(presentation_mode) is not ManifestPresentationMode
        or type(artifacts) is not tuple
        or any(type(item) is not DemoRehearsalArtifact for item in artifacts)
        or type(fresh_run_count) is not int
        or type(scenario_count) is not int
    ):
        raise RunManifestError(RunManifestFailureCode.INVALID_INPUT)
    if run_mode is RunMode.STANDARD:
        valid_mode = (
            presentation_mode is ManifestPresentationMode.NORMAL
            and 2 <= fresh_run_count <= 10
            and capture_schema is None
        )
    else:
        valid_mode = (
            presentation_mode is ManifestPresentationMode.VIDEO_SAFE
            and fresh_run_count == 3
            and capture_schema == _CAPTURE_SCHEMA
        )
    if not valid_mode or scenario_count != 6:
        raise RunManifestError(RunManifestFailureCode.INVALID_INPUT)
    scan = scan_demo_surfaces(
        tuple((item.name, item.content) for item in artifacts)
        + tuple((item.name, item.name.encode("ascii")) for item in artifacts)
    )
    if not scan.pass_all:
        raise RunManifestError(RunManifestFailureCode.SURFACE_SCAN_FAILED)
    entries = tuple(
        sorted(
            (
                ManifestArtifact(
                    logical_name=_safe_leaf(item.name),
                    media_type=item.media_type,
                    byte_length=len(item.content),
                    digest=_digest_bytes(item.content),
                )
                for item in artifacts
            ),
            key=lambda item: item.logical_name,
        )
    )
    if len(entries) != len({item.logical_name for item in entries}):
        raise RunManifestError(RunManifestFailureCode.INVALID_INPUT)
    provisional = RunManifest(
        schema_version=RUN_MANIFEST_SCHEMA_VERSION,
        manifest_kind=RUN_MANIFEST_KIND,
        run_mode=run_mode,
        presentation_mode=presentation_mode,
        status="PASS",
        provenance_class=PROVENANCE_CLASS,
        software=ManifestSoftware(
            tidemark_version=TIDEMARK_VERSION,
            python_version=platform.python_version(),
            source_revision=repository_provenance.source_revision,
        ),
        schemas=ManifestSchemas(
            rehearsal_schema="tidemark.demo.rehearsal.v1",
            capture_schema=capture_schema,
            manifest_schema=RUN_MANIFEST_SCHEMA_VERSION,
            design_authority=DESIGN_AUTHORITY,
        ),
        counts=ManifestCounts(fresh_run_count, scenario_count, len(entries)),
        artifacts=entries,
        manifest_digest="sha256:" + "0" * 64,
    )
    digest = _digest_bytes(canonical_json_bytes(_primitive(provisional, include_digest=False)))
    manifest = replace(provisional, manifest_digest=digest)
    encoded = serialize_run_manifest(manifest)
    if not scan_demo_surfaces((("run-manifest.json", encoded),)).pass_all:
        raise RunManifestError(RunManifestFailureCode.SURFACE_SCAN_FAILED)
    return manifest


def serialize_run_manifest(manifest: RunManifest) -> bytes:
    if type(manifest) is not RunManifest:
        raise RunManifestError(RunManifestFailureCode.INVALID_INPUT)
    return canonical_json_bytes(_primitive(manifest), trailing_newline=True)


def _exact(value: object, keys: Tuple[str, ...]) -> dict:
    if type(value) is not dict or set(value) != set(keys):
        raise RunManifestError(RunManifestFailureCode.INVALID_INPUT)
    return value


def _parse(encoded: bytes) -> RunManifest:
    if type(encoded) is not bytes or not encoded.endswith(b"\n") or encoded.endswith(b"\n\n"):
        raise RunManifestError(RunManifestFailureCode.NON_CANONICAL)
    try:
        primitive = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RunManifestError(RunManifestFailureCode.NON_CANONICAL) from None
    root = _exact(
        primitive,
        (
            "schema_version", "manifest_kind", "run_mode", "presentation_mode",
            "status", "provenance_class", "software", "schemas", "counts",
            "artifacts", "manifest_digest",
        ),
    )
    software = _exact(root["software"], ("tidemark_version", "python_version", "source_revision"))
    schemas = _exact(root["schemas"], ("rehearsal_schema", "capture_schema", "manifest_schema", "design_authority"))
    counts = _exact(root["counts"], ("fresh_run_count", "scenario_count", "artifact_count"))
    if type(root["artifacts"]) is not list:
        raise RunManifestError(RunManifestFailureCode.INVALID_INPUT)
    entries = []
    for raw in root["artifacts"]:
        item = _exact(raw, ("logical_name", "media_type", "byte_length", "digest"))
        entries.append(ManifestArtifact(**item))
    try:
        manifest = RunManifest(
            schema_version=root["schema_version"],
            manifest_kind=root["manifest_kind"],
            run_mode=RunMode(root["run_mode"]),
            presentation_mode=ManifestPresentationMode(root["presentation_mode"]),
            status=root["status"],
            provenance_class=root["provenance_class"],
            software=ManifestSoftware(**software),
            schemas=ManifestSchemas(**schemas),
            counts=ManifestCounts(**counts),
            artifacts=tuple(entries),
            manifest_digest=root["manifest_digest"],
        )
    except (TypeError, ValueError):
        raise RunManifestError(RunManifestFailureCode.INVALID_INPUT) from None
    canonical = serialize_run_manifest(manifest)
    if canonical != encoded:
        raise RunManifestError(RunManifestFailureCode.NON_CANONICAL)
    expected = _digest_bytes(canonical_json_bytes(_primitive(manifest, include_digest=False)))
    if expected != manifest.manifest_digest:
        raise RunManifestError(RunManifestFailureCode.DIGEST_MISMATCH)
    return manifest


def verify_run_manifest(
    encoded: bytes,
    artifacts: Tuple[DemoRehearsalArtifact, ...],
) -> RunManifest:
    manifest = _parse(encoded)
    if type(artifacts) is not tuple or any(
        type(item) is not DemoRehearsalArtifact for item in artifacts
    ):
        raise RunManifestError(RunManifestFailureCode.INVALID_INPUT)
    actual = tuple(
        sorted(
            (
                ManifestArtifact(
                    item.name,
                    item.media_type,
                    len(item.content),
                    _digest_bytes(item.content),
                )
                for item in artifacts
            ),
            key=lambda item: item.logical_name,
        )
    )
    if actual != manifest.artifacts:
        raise RunManifestError(RunManifestFailureCode.ARTIFACT_SET_MISMATCH)
    scan = scan_demo_surfaces(
        (("run-manifest.json", encoded),)
        + tuple((item.name, item.content) for item in artifacts)
    )
    if not scan.pass_all:
        raise RunManifestError(RunManifestFailureCode.SURFACE_SCAN_FAILED)
    return manifest


def verify_materialized_run_manifest(root: str) -> RunManifest:
    if type(root) is not str or not root:
        raise RunManifestError(RunManifestFailureCode.INVALID_INPUT)
    directory = Path(root)
    try:
        if not directory.is_dir() or directory.is_symlink():
            raise RunManifestError(RunManifestFailureCode.ARTIFACT_SET_MISMATCH)
        children = tuple(directory.iterdir())
        if any(not child.is_file() or child.is_symlink() for child in children):
            raise RunManifestError(RunManifestFailureCode.ARTIFACT_SET_MISMATCH)
        manifest_path = directory / "run-manifest.json"
        encoded = manifest_path.read_bytes()
        preliminary = _parse(encoded)
        expected_names = {item.logical_name for item in preliminary.artifacts}
        actual_names = {item.name for item in children}
        if actual_names != expected_names | {"run-manifest.json"}:
            raise RunManifestError(RunManifestFailureCode.ARTIFACT_SET_MISMATCH)
        artifacts = tuple(
            DemoRehearsalArtifact(
                item.logical_name,
                item.media_type,
                (directory / item.logical_name).read_bytes(),
            )
            for item in preliminary.artifacts
        )
    except RunManifestError:
        raise
    except (OSError, TypeError, ValueError):
        raise RunManifestError(RunManifestFailureCode.ARTIFACT_SET_MISMATCH) from None
    return verify_run_manifest(encoded, artifacts)


__all__ = (
    "ManifestArtifact",
    "ManifestCounts",
    "ManifestPresentationMode",
    "ManifestSchemas",
    "ManifestSoftware",
    "PROVENANCE_CLASS",
    "RUN_MANIFEST_SCHEMA_VERSION",
    "RunManifest",
    "RunManifestError",
    "RunManifestFailureCode",
    "RunMode",
    "build_run_manifest",
    "serialize_run_manifest",
    "verify_materialized_run_manifest",
    "verify_run_manifest",
)
