"""Operator-safe rehearsal over the existing deterministic demo harness.

This module measures and materializes already-generated, read-only demo
surfaces. It owns no authorization, execution, reset, retry, provider, cloud,
or evidence-repair behavior.
"""

from dataclasses import asdict, dataclass
from enum import Enum, unique
import json
import math
import os
from pathlib import Path
import re
import shutil
from statistics import median
import tempfile
from time import perf_counter
from typing import Optional, Tuple, final

from tidemark.demo.harness import (
    DemoHarnessError,
    DemoHarnessRun,
    DeterministicDemoHarness,
)
from tidemark.evidence.projection import (
    ExecutionReviewStatus,
    ProjectionDisposition,
    ReplayReviewState,
)
from tidemark.evidence.publication import verify_evidence_publication
from tidemark.payment.fixtures import RAW_SYNTHETIC_DESTINATION
from tidemark.runtime.vocabulary import RuleId
from tidemark.ui.decision_review import render_decision_review_workspace
from tidemark.ui.final_ui import build_final_ui_scenarios, render_final_ui
from tidemark.ui.run_summary import (
    ComparisonStatus,
    EvidenceMode,
    REQUIRED_SCENARIO_ORDER,
    RunStatus,
    ScenarioId,
    ScenarioIntegrityStatus,
    render_demo_run_summary,
)


DEMO_REHEARSAL_SCHEMA_VERSION = "tidemark.demo.rehearsal.v1"
DEFAULT_REHEARSAL_SAMPLE_COUNT = 2
_MAX_REHEARSAL_SAMPLE_COUNT = 10
_ARTIFACT_NAME = re.compile(r"[a-z0-9][a-z0-9.-]{0,127}\Z")
_ABSOLUTE_PATH = re.compile(
    rb"(?:/(?:Users|home|tmp|private/tmp|var/folders|private/var/folders)/|"
    rb"[A-Za-z]:\\(?:Users|Temp|Documents)\\)"
)
_SECRET_DATA = re.compile(
    rb"(?:"
    + b"GEMINI"
    + b"_API_KEY"
    + rb"|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    rb"AIza[0-9A-Za-z_-]{20,}|"
    rb"sk-[0-9A-Za-z_-]{16,}|"
    rb"(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)[\"']?\s*[:=]"
    rb")",
    re.IGNORECASE,
)
_PROTECTED_DATA = re.compile(
    re.escape(RAW_SYNTHETIC_DESTINATION.encode("utf-8"))
    + rb"|synthetic-routing://|ref_order_18_forged_unknown",
    re.IGNORECASE,
)
_RAW_PROVIDER_DATA = re.compile(
    rb"(?:raw[_-]?prompt|raw[_-]?provider[_-]?output)[\"']?\s*[:=]",
    re.IGNORECASE,
)
_PRIVATE_EXECUTION_DATA = re.compile(
    rb"(?:RuntimePrivateExecutionBinding|private_authenticator|runtime_private_authenticator)",
    re.IGNORECASE,
)


@unique
class DemoSurfaceFindingCode(str, Enum):
    SECRET = "demo.surface.secret_detected.v1"
    PROTECTED_DATA = "demo.surface.protected_data_detected.v1"
    RAW_PROVIDER_DATA = "demo.surface.raw_provider_data_detected.v1"
    PRIVATE_EXECUTION_DATA = "demo.surface.private_execution_data_detected.v1"
    ABSOLUTE_PATH = "demo.surface.absolute_path_detected.v1"


@unique
class DemoRehearsalFailureCode(str, Enum):
    HARNESS_FAILED = "demo.rehearsal.harness_failed.v1"
    SEMANTIC_VALIDATION_FAILED = "demo.rehearsal.semantic_validation_failed.v1"
    PUBLICATION_VERIFICATION_FAILED = (
        "demo.rehearsal.publication_verification_failed.v1"
    )
    RENDERING_FAILED = "demo.rehearsal.rendering_failed.v1"
    SURFACE_SCAN_FAILED = "demo.rehearsal.surface_scan_failed.v1"
    OUTPUT_DIRECTORY_INVALID = "demo.rehearsal.output_directory_invalid.v1"
    PREFLIGHT_FAILED = "demo.rehearsal.preflight_failed.v1"
    MANIFEST_FAILED = "demo.rehearsal.manifest_failed.v1"
    MATERIALIZATION_FAILED = "demo.rehearsal.materialization_failed.v1"
    STAGING_CLEANUP_FAILED = "demo.rehearsal.staging_cleanup_failed.v1"


class DemoRehearsalError(RuntimeError):
    """Bounded rehearsal failure without nested exception or path detail."""

    __slots__ = ("code",)

    def __init__(self, code: DemoRehearsalFailureCode) -> None:
        if type(code) is not DemoRehearsalFailureCode:
            raise TypeError("rehearsal failure requires DemoRehearsalFailureCode")
        self.code = code
        super().__init__(code.value)


@final
@dataclass(frozen=True)
class DemoSurfaceFinding:
    code: DemoSurfaceFindingCode
    surface_name: str

    def __post_init__(self) -> None:
        if type(self.code) is not DemoSurfaceFindingCode:
            raise TypeError("surface finding requires DemoSurfaceFindingCode")
        if (
            type(self.surface_name) is not str
            or _ARTIFACT_NAME.fullmatch(self.surface_name) is None
            or ".." in self.surface_name
        ):
            raise ValueError("surface finding name is invalid")


@final
@dataclass(frozen=True)
class DemoSurfaceScan:
    findings: Tuple[DemoSurfaceFinding, ...]

    def __post_init__(self) -> None:
        if type(self.findings) is not tuple or any(
            type(item) is not DemoSurfaceFinding for item in self.findings
        ):
            raise TypeError("surface scan findings require an immutable tuple")

    @property
    def pass_all(self) -> bool:
        return not self.findings

    @property
    def secret_scan_pass(self) -> bool:
        return not any(
            item.code is DemoSurfaceFindingCode.SECRET for item in self.findings
        )

    @property
    def protected_data_scan_pass(self) -> bool:
        protected_codes = {
            DemoSurfaceFindingCode.PROTECTED_DATA,
            DemoSurfaceFindingCode.RAW_PROVIDER_DATA,
            DemoSurfaceFindingCode.PRIVATE_EXECUTION_DATA,
        }
        return not any(item.code in protected_codes for item in self.findings)

    @property
    def absolute_path_scan_pass(self) -> bool:
        return not any(
            item.code is DemoSurfaceFindingCode.ABSOLUTE_PATH
            for item in self.findings
        )

    def __repr__(self) -> str:
        return (
            "DemoSurfaceScan("
            f"pass_all={self.pass_all}, finding_count={len(self.findings)})"
        )


@final
@dataclass(frozen=True)
class TimingStatistics:
    sample_count: int
    minimum_seconds: float
    median_seconds: float
    maximum_seconds: float

    def __post_init__(self) -> None:
        if type(self.sample_count) is not int or self.sample_count < 1:
            raise ValueError("timing sample_count requires a positive exact int")
        values = (
            self.minimum_seconds,
            self.median_seconds,
            self.maximum_seconds,
        )
        if any(
            type(value) is not float or not math.isfinite(value) or value < 0
            for value in values
        ):
            raise ValueError("timing values require finite non-negative floats")
        if not (
            self.minimum_seconds
            <= self.median_seconds
            <= self.maximum_seconds
        ):
            raise ValueError("timing values require minimum/median/maximum order")


@final
@dataclass(frozen=True)
class DemoRehearsalTimings:
    full_harness_runtime: TimingStatistics
    run_summary_render: TimingStatistics
    decision_review_render: TimingStatistics
    publication_verification: TimingStatistics
    complete_sample: TimingStatistics


@final
@dataclass(frozen=True)
class RehearsalScenarioFact:
    scenario_id: ScenarioId
    disposition: ProjectionDisposition
    primary_rule_id: Optional[RuleId]
    execution_status: ExecutionReviewStatus
    execution_start_count: int
    payment_count: int
    replay_state: ReplayReviewState
    model_non_attempt: bool
    mode: EvidenceMode
    comparison: ComparisonStatus
    integrity: ScenarioIntegrityStatus


@final
@dataclass(frozen=True)
class DemoRehearsalArtifact:
    name: str
    media_type: str
    content: bytes

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str
            or _ARTIFACT_NAME.fullmatch(self.name) is None
            or ".." in self.name
        ):
            raise ValueError("rehearsal artifact name is invalid")
        if self.media_type not in {"text/html", "application/json"}:
            raise ValueError("rehearsal artifact media type is unsupported")
        if type(self.content) is not bytes or not self.content:
            raise ValueError("rehearsal artifact requires non-empty bytes")

    def __repr__(self) -> str:
        return (
            "DemoRehearsalArtifact("
            f"name={self.name!r}, media_type={self.media_type!r}, "
            f"byte_length={len(self.content)})"
        )


@final
@dataclass(frozen=True)
class DemoRehearsalReport:
    status: RunStatus
    sample_count: int
    run_ids: Tuple[str, ...]
    required_scenario_count: int
    all_required_scenarios_rehearsed: bool
    publication_verification_count: int
    scenarios: Tuple[RehearsalScenarioFact, ...]
    timings: DemoRehearsalTimings
    secret_scan_pass: bool
    protected_data_scan_pass: bool
    absolute_path_scan_pass: bool
    artifact_names: Tuple[str, ...]

    def to_json_bytes(self) -> bytes:
        primitive = {
            "schema_version": DEMO_REHEARSAL_SCHEMA_VERSION,
            "status": self.status.value,
            "mode": (
                "DETERMINISTIC / EVIDENCE FALLBACK / OFFLINE / "
                "NOT CURRENT LIVE PROVIDER OUTPUT"
            ),
            "deterministic": True,
            "offline": True,
            "not_current_live_provider_output": True,
            "offline_fallback_explicit": True,
            "offline_presented_as_live": False,
            "sample_count": self.sample_count,
            "run_ids": list(self.run_ids),
            "required_scenario_count": self.required_scenario_count,
            "all_required_scenarios_rehearsed": self.all_required_scenarios_rehearsed,
            "publication_verification_count": self.publication_verification_count,
            "secret_scan_pass": self.secret_scan_pass,
            "protected_data_scan_pass": self.protected_data_scan_pass,
            "absolute_path_scan_pass": self.absolute_path_scan_pass,
            "real_provider_credential_required": False,
            "provider_requests_performed": False,
            "network_requests_performed": False,
            "google_cloud_used": False,
            "personal_spend_eur": 0,
            "prior_authority_reset_or_unconsumed": False,
            "artifact_names": list(self.artifact_names),
            "scenarios": [_scenario_fact_primitive(item) for item in self.scenarios],
            "timings": {
                "full_harness_runtime_seconds": _timing_primitive(
                    self.timings.full_harness_runtime
                ),
                "run_summary_render_seconds": _timing_primitive(
                    self.timings.run_summary_render
                ),
                "decision_review_render_seconds": _timing_primitive(
                    self.timings.decision_review_render
                ),
                "publication_verification_seconds": _timing_primitive(
                    self.timings.publication_verification
                ),
                "complete_sample_seconds": _timing_primitive(
                    self.timings.complete_sample
                ),
            },
        }
        return (
            json.dumps(primitive, sort_keys=True, indent=2).encode("utf-8")
            + b"\n"
        )

    def __repr__(self) -> str:
        return (
            "DemoRehearsalReport("
            f"status={self.status.value!r}, sample_count={self.sample_count}, "
            f"scenario_count={len(self.scenarios)}, provider_free=True)"
        )


@final
@dataclass(frozen=True)
class DemoRehearsalResult:
    report: DemoRehearsalReport
    artifacts: Tuple[DemoRehearsalArtifact, ...]

    def __post_init__(self) -> None:
        if type(self.report) is not DemoRehearsalReport:
            raise TypeError("rehearsal result requires DemoRehearsalReport")
        if type(self.artifacts) is not tuple or any(
            type(item) is not DemoRehearsalArtifact for item in self.artifacts
        ):
            raise TypeError("rehearsal artifacts require an immutable tuple")
        if tuple(item.name for item in self.artifacts) != self.report.artifact_names:
            raise ValueError("rehearsal report and artifact names differ")

    def __repr__(self) -> str:
        return (
            "DemoRehearsalResult("
            f"status={self.report.status.value!r}, "
            f"artifact_count={len(self.artifacts)}, read_only=True)"
        )


def scan_demo_surfaces(
    surfaces: Tuple[Tuple[str, bytes], ...],
    *,
    extra_forbidden_values: Tuple[bytes, ...] = (),
) -> DemoSurfaceScan:
    """Apply the bounded TIDEMARK demo-publication checks to public bytes."""

    if type(surfaces) is not tuple or any(
        type(item) is not tuple
        or len(item) != 2
        or type(item[0]) is not str
        or _ARTIFACT_NAME.fullmatch(item[0]) is None
        or ".." in item[0]
        or type(item[1]) is not bytes
        for item in surfaces
    ):
        raise TypeError("demo surfaces require immutable safe-name/bytes pairs")
    if type(extra_forbidden_values) is not tuple or any(
        type(item) is not bytes or not item for item in extra_forbidden_values
    ):
        raise TypeError("extra forbidden values require non-empty bytes")

    findings = []
    checks = (
        (DemoSurfaceFindingCode.SECRET, _SECRET_DATA),
        (DemoSurfaceFindingCode.PROTECTED_DATA, _PROTECTED_DATA),
        (DemoSurfaceFindingCode.RAW_PROVIDER_DATA, _RAW_PROVIDER_DATA),
        (DemoSurfaceFindingCode.PRIVATE_EXECUTION_DATA, _PRIVATE_EXECUTION_DATA),
        (DemoSurfaceFindingCode.ABSOLUTE_PATH, _ABSOLUTE_PATH),
    )
    for surface_name, content in surfaces:
        for code, pattern in checks:
            if pattern.search(content) is not None:
                findings.append(DemoSurfaceFinding(code, surface_name))
        if any(value in content for value in extra_forbidden_values):
            findings.append(
                DemoSurfaceFinding(
                    DemoSurfaceFindingCode.ABSOLUTE_PATH,
                    surface_name,
                )
            )
    return DemoSurfaceScan(tuple(findings))


def run_demo_rehearsal(
    *,
    sample_count: int = DEFAULT_REHEARSAL_SAMPLE_COUNT,
    seed_prefix: str = "order-19-rehearsal",
) -> DemoRehearsalResult:
    """Run independent planned samples; stop immediately on any failed sample."""

    _validate_rehearsal_inputs(sample_count, seed_prefix)
    runs = []
    run_ids = []
    surfaces = []
    harness_timings = []
    summary_timings = []
    decision_timings = []
    publication_timings = []
    sample_timings = []
    publication_verification_count = 0

    for sample_number in range(1, sample_count + 1):
        sample_started = perf_counter()
        harness_started = perf_counter()
        try:
            run = DeterministicDemoHarness(
                run_seed=f"{seed_prefix}-{sample_number:02d}"
            ).run()
        except (DemoHarnessError, OSError, RuntimeError, TypeError, ValueError):
            raise DemoRehearsalError(
                DemoRehearsalFailureCode.HARNESS_FAILED
            ) from None
        harness_timings.append(perf_counter() - harness_started)
        _validate_run(run)

        publication_started = perf_counter()
        for scenario in run.scenarios:
            verification = verify_evidence_publication(
                scenario.publication_package
            )
            if (
                not verification.valid
                or verification.package is None
                or verification.package.trace_id != scenario.projection.trace_id
            ):
                raise DemoRehearsalError(
                    DemoRehearsalFailureCode.PUBLICATION_VERIFICATION_FAILED
                )
            publication_verification_count += 1
        publication_timings.append(perf_counter() - publication_started)

        summary_started = perf_counter()
        try:
            rendered_summary = render_demo_run_summary(run.summary)
        except (RuntimeError, TypeError, ValueError):
            raise DemoRehearsalError(
                DemoRehearsalFailureCode.RENDERING_FAILED
            ) from None
        summary_timings.append(perf_counter() - summary_started)
        if rendered_summary != run.run_summary_html:
            raise DemoRehearsalError(
                DemoRehearsalFailureCode.RENDERING_FAILED
            )
        try:
            rendered_final_ui = render_final_ui(
                run.summary,
                build_final_ui_scenarios(
                    run.summary,
                        tuple(
                            (
                                scenario.scenario_id,
                                scenario.projection,
                                scenario.mechanism_projection,
                            )
                            for scenario in run.scenarios
                        ),
                ),
            )
        except (RuntimeError, TypeError, ValueError):
            raise DemoRehearsalError(
                DemoRehearsalFailureCode.RENDERING_FAILED
            ) from None
        if rendered_final_ui != run.integrated_ui_html:
            raise DemoRehearsalError(
                DemoRehearsalFailureCode.RENDERING_FAILED
            )

        decision_started = perf_counter()
        try:
            rendered_decisions = tuple(
                render_decision_review_workspace(scenario.projection)
                for scenario in run.scenarios
            )
        except (RuntimeError, TypeError, ValueError):
            raise DemoRehearsalError(
                DemoRehearsalFailureCode.RENDERING_FAILED
            ) from None
        decision_timings.append(perf_counter() - decision_started)
        if any(
            rendered != scenario.decision_review_artifact.html
            for rendered, scenario in zip(rendered_decisions, run.scenarios)
        ):
            raise DemoRehearsalError(
                DemoRehearsalFailureCode.RENDERING_FAILED
            )

        sample_surfaces = _run_surfaces(run, sample_number)
        scan = scan_demo_surfaces(sample_surfaces)
        if not scan.pass_all:
            raise DemoRehearsalError(
                DemoRehearsalFailureCode.SURFACE_SCAN_FAILED
            )
        surfaces.extend(sample_surfaces)
        runs.append(run)
        run_ids.append(run.run_id)
        sample_timings.append(perf_counter() - sample_started)

    if len(set(run_ids)) != sample_count:
        raise DemoRehearsalError(
            DemoRehearsalFailureCode.SEMANTIC_VALIDATION_FAILED
        )
    final_run = runs[-1]
    final_scan = scan_demo_surfaces(tuple(surfaces))
    if not final_scan.pass_all:
        raise DemoRehearsalError(
            DemoRehearsalFailureCode.SURFACE_SCAN_FAILED
        )

    artifact_names = (
        "index.html",
        *(scenario.decision_review_artifact.reference for scenario in final_run.scenarios),
        "demo-rehearsal-report.json",
    )
    timings = DemoRehearsalTimings(
        full_harness_runtime=_timing_statistics(harness_timings),
        run_summary_render=_timing_statistics(summary_timings),
        decision_review_render=_timing_statistics(decision_timings),
        publication_verification=_timing_statistics(publication_timings),
        complete_sample=_timing_statistics(sample_timings),
    )
    report = DemoRehearsalReport(
        status=final_run.summary.status,
        sample_count=sample_count,
        run_ids=tuple(run_ids),
        required_scenario_count=len(REQUIRED_SCENARIO_ORDER),
        all_required_scenarios_rehearsed=True,
        publication_verification_count=publication_verification_count,
        scenarios=_scenario_facts(final_run),
        timings=timings,
        secret_scan_pass=final_scan.secret_scan_pass,
        protected_data_scan_pass=final_scan.protected_data_scan_pass,
        absolute_path_scan_pass=final_scan.absolute_path_scan_pass,
        artifact_names=artifact_names,
    )
    artifacts = (
        DemoRehearsalArtifact(
            "index.html",
            "text/html",
            final_run.integrated_ui_html.encode("utf-8"),
        ),
        *(
            DemoRehearsalArtifact(
                scenario.decision_review_artifact.reference,
                "text/html",
                scenario.decision_review_artifact.html.encode("utf-8"),
            )
            for scenario in final_run.scenarios
        ),
        DemoRehearsalArtifact(
            "demo-rehearsal-report.json",
            "application/json",
            report.to_json_bytes(),
        ),
    )
    artifact_scan = scan_demo_surfaces(
        tuple((artifact.name, artifact.content) for artifact in artifacts)
    )
    if not artifact_scan.pass_all:
        raise DemoRehearsalError(
            DemoRehearsalFailureCode.SURFACE_SCAN_FAILED
        )
    return DemoRehearsalResult(report, artifacts)


def materialize_demo_rehearsal(
    output_directory: str,
    *,
    sample_count: int = DEFAULT_REHEARSAL_SAMPLE_COUNT,
    seed_prefix: str = "order-19-rehearsal",
) -> DemoRehearsalResult:
    """Write a clean-source, manifest-backed standard artifact set atomically."""

    root = _empty_output_directory(output_directory)
    from tidemark.demo.manifest import (
        ManifestPresentationMode,
        RunManifestError,
        RunMode,
        build_run_manifest,
        serialize_run_manifest,
        verify_materialized_run_manifest,
        verify_run_manifest,
    )
    from tidemark.demo.preflight import (
        LocalReadiness,
        PreflightProfile,
        run_preflight,
    )

    preflight = run_preflight(
        profile=PreflightProfile.REPRODUCTION,
        output_root=output_directory,
    )
    if (
        preflight.local_readiness is not LocalReadiness.PASS
        or preflight.repository_provenance is None
    ):
        raise DemoRehearsalError(DemoRehearsalFailureCode.PREFLIGHT_FAILED)
    result = run_demo_rehearsal(
        sample_count=sample_count,
        seed_prefix=seed_prefix,
    )
    try:
        resolved_root = str(root.resolve()).encode("utf-8")
        resolved_working_directory = str(Path.cwd().resolve()).encode("utf-8")
    except OSError:
        raise DemoRehearsalError(
            DemoRehearsalFailureCode.OUTPUT_DIRECTORY_INVALID
        ) from None
    scan = scan_demo_surfaces(
        tuple((artifact.name, artifact.content) for artifact in result.artifacts),
        extra_forbidden_values=(resolved_root, resolved_working_directory),
    )
    if not scan.pass_all:
        raise DemoRehearsalError(
            DemoRehearsalFailureCode.SURFACE_SCAN_FAILED
        )
    try:
        manifest = build_run_manifest(
            repository_provenance=preflight.repository_provenance,
            run_mode=RunMode.STANDARD,
            presentation_mode=ManifestPresentationMode.NORMAL,
            artifacts=result.artifacts,
            fresh_run_count=sample_count,
            scenario_count=len(REQUIRED_SCENARIO_ORDER),
            capture_schema=None,
        )
        encoded_manifest = serialize_run_manifest(manifest)
        verify_run_manifest(encoded_manifest, result.artifacts)
    except (RunManifestError, RuntimeError, TypeError, ValueError):
        raise DemoRehearsalError(
            DemoRehearsalFailureCode.MANIFEST_FAILED
        ) from None
    staging = None
    try:
        staging = Path(tempfile.mkdtemp(prefix=".tidemark-standard-", dir=str(root)))
        for artifact in result.artifacts:
            with (staging / artifact.name).open("xb") as stream:
                written = stream.write(artifact.content)
                if written != len(artifact.content):
                    raise OSError("partial rehearsal artifact write")
                stream.flush()
                os.fsync(stream.fileno())
        with (staging / "run-manifest.json").open("xb") as stream:
            written = stream.write(encoded_manifest)
            if written != len(encoded_manifest):
                raise OSError("partial run manifest write")
            stream.flush()
            os.fsync(stream.fileno())
        verify_materialized_run_manifest(str(staging))
        if tuple(root.iterdir()) != (staging,):
            raise OSError("output root changed during materialization")
        staging.rename(root / "artifacts")
        staging = None
    except (OSError, RunManifestError, RuntimeError, TypeError, ValueError):
        if staging is not None and staging.exists():
            try:
                shutil.rmtree(str(staging))
            except OSError:
                raise DemoRehearsalError(
                    DemoRehearsalFailureCode.STAGING_CLEANUP_FAILED
                ) from None
        raise DemoRehearsalError(
            DemoRehearsalFailureCode.MATERIALIZATION_FAILED
        ) from None
    return result


def _validate_rehearsal_inputs(sample_count: int, seed_prefix: str) -> None:
    if (
        type(sample_count) is not int
        or sample_count < DEFAULT_REHEARSAL_SAMPLE_COUNT
        or sample_count > _MAX_REHEARSAL_SAMPLE_COUNT
    ):
        raise ValueError("sample_count requires a bounded value from 2 through 10")
    if type(seed_prefix) is not str or not seed_prefix or len(seed_prefix) > 128:
        raise ValueError("seed_prefix requires a bounded non-empty exact string")


def _validate_run(run: DemoHarnessRun) -> None:
    if type(run) is not DemoHarnessRun:
        raise DemoRehearsalError(
            DemoRehearsalFailureCode.SEMANTIC_VALIDATION_FAILED
        )
    if (
        run.summary.status is not RunStatus.PASS
        or tuple(item.scenario_id for item in run.scenarios)
        != REQUIRED_SCENARIO_ORDER
        or len(run.scenarios) != len(REQUIRED_SCENARIO_ORDER)
        or run.summary.match_count != len(REQUIRED_SCENARIO_ORDER)
        or any(
            item.provenance.mode
            not in {EvidenceMode.EVIDENCE_FALLBACK, EvidenceMode.MODEL_NON_ATTEMPT}
            for item in run.scenarios
        )
    ):
        raise DemoRehearsalError(
            DemoRehearsalFailureCode.SEMANTIC_VALIDATION_FAILED
        )


def _run_surfaces(
    run: DemoHarnessRun, sample_number: int
) -> Tuple[Tuple[str, bytes], ...]:
    prefix = f"sample-{sample_number}"
    return (
        (f"{prefix}-result-repr.txt", repr(run).encode("utf-8")),
        (
            f"{prefix}-result-serialization.txt",
            repr(asdict(run)).encode("utf-8"),
        ),
        (f"{prefix}-run-summary.html", run.run_summary_html.encode("utf-8")),
        (f"{prefix}-integrated-ui.html", run.integrated_ui_html.encode("utf-8")),
        *(
            (
                f"{prefix}-{scenario.decision_review_artifact.reference}",
                scenario.decision_review_artifact.html.encode("utf-8"),
            )
            for scenario in run.scenarios
        ),
        *(
            (
                f"{prefix}-publication-"
                f"{scenario.scenario_id.value.lower().replace('_', '-')}.json",
                scenario.publication_package.canonical_bytes,
            )
            for scenario in run.scenarios
        ),
    )


def _scenario_facts(run: DemoHarnessRun) -> Tuple[RehearsalScenarioFact, ...]:
    summaries = {item.scenario_id: item for item in run.summary.scenarios}
    return tuple(
        RehearsalScenarioFact(
            scenario_id=scenario.scenario_id,
            disposition=scenario.projection.disposition,
            primary_rule_id=scenario.projection.primary_rule_id,
            execution_status=scenario.projection.execution_status,
            execution_start_count=scenario.projection.execution_start_count,
            payment_count=scenario.projection.payment_count,
            replay_state=scenario.projection.replay_state,
            model_non_attempt=scenario.projection.model_non_attempt,
            mode=scenario.provenance.mode,
            comparison=summaries[scenario.scenario_id].comparison,
            integrity=summaries[scenario.scenario_id].integrity,
        )
        for scenario in run.scenarios
    )


def _timing_statistics(samples) -> TimingStatistics:
    normalized = tuple(float(value) for value in samples)
    return TimingStatistics(
        sample_count=len(normalized),
        minimum_seconds=min(normalized),
        median_seconds=float(median(normalized)),
        maximum_seconds=max(normalized),
    )


def _timing_primitive(statistic: TimingStatistics) -> dict:
    return {
        "sample_count": statistic.sample_count,
        "minimum": round(statistic.minimum_seconds, 6),
        "median": round(statistic.median_seconds, 6),
        "maximum": round(statistic.maximum_seconds, 6),
    }


def _scenario_fact_primitive(fact: RehearsalScenarioFact) -> dict:
    return {
        "scenario_id": fact.scenario_id.value,
        "disposition": fact.disposition.value,
        "primary_rule_id": (
            fact.primary_rule_id.value if fact.primary_rule_id is not None else None
        ),
        "execution_status": fact.execution_status.value,
        "execution_start_count": fact.execution_start_count,
        "payment_count": fact.payment_count,
        "replay_state": fact.replay_state.value,
        "model_non_attempt": fact.model_non_attempt,
        "mode": fact.mode.value,
        "comparison": fact.comparison.value,
        "integrity": fact.integrity.value,
    }


def _empty_output_directory(value: str) -> Path:
    if type(value) is not str or not value:
        raise DemoRehearsalError(
            DemoRehearsalFailureCode.OUTPUT_DIRECTORY_INVALID
        )
    root = Path(value)
    try:
        valid = (
            root.exists()
            and root.is_dir()
            and not root.is_symlink()
            and not any(root.iterdir())
        )
    except OSError:
        valid = False
    if not valid:
        raise DemoRehearsalError(
            DemoRehearsalFailureCode.OUTPUT_DIRECTORY_INVALID
        )
    return root


__all__ = (
    "DEFAULT_REHEARSAL_SAMPLE_COUNT",
    "DEMO_REHEARSAL_SCHEMA_VERSION",
    "DemoRehearsalArtifact",
    "DemoRehearsalError",
    "DemoRehearsalFailureCode",
    "DemoRehearsalReport",
    "DemoRehearsalResult",
    "DemoRehearsalTimings",
    "DemoSurfaceFinding",
    "DemoSurfaceFindingCode",
    "DemoSurfaceScan",
    "RehearsalScenarioFact",
    "TimingStatistics",
    "materialize_demo_rehearsal",
    "run_demo_rehearsal",
    "scan_demo_surfaces",
)
