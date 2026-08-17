"""Bounded three-run capture rehearsal and deterministic fallback."""

from dataclasses import dataclass, fields, is_dataclass
from enum import Enum, unique
from hashlib import sha256
import os
from pathlib import Path
import shutil
from statistics import median
import tempfile
from time import perf_counter
from typing import Optional, Tuple, final

from tidemark.demo.harness import DemoHarnessRun, DeterministicDemoHarness
from tidemark.demo.manifest import (
    ManifestPresentationMode,
    PROVENANCE_CLASS,
    RunManifest,
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
from tidemark.demo.rehearsal import (
    DEMO_REHEARSAL_SCHEMA_VERSION,
    DemoRehearsalArtifact,
    DemoRehearsalReport,
    DemoRehearsalTimings,
    RehearsalScenarioFact,
    TimingStatistics,
    scan_demo_surfaces,
)
from tidemark.evidence.canonical import canonical_json_bytes
from tidemark.evidence.publication import verify_evidence_publication
from tidemark.ui.decision_review import render_decision_review_workspace
from tidemark.ui.final_ui import (
    PresentationMode,
    build_final_ui_scenarios,
    render_final_ui,
)
from tidemark.ui.run_summary import (
    DemoRunSummary,
    REQUIRED_SCENARIO_ORDER,
    RunStatus,
    ScenarioSummary,
    render_demo_run_summary,
)


CAPTURE_RUN_COUNT = 3
CAPTURE_REHEARSAL_SCHEMA_VERSION = "tidemark.demo.capture-rehearsal.v1"
_SNAPSHOT_SCHEMA_VERSION = "tidemark.demo.capture-semantic-snapshot.v1"


@unique
class CaptureProfile(str, Enum):
    CAPTURE = "CAPTURE"
    DETERMINISTIC_FALLBACK = "DETERMINISTIC_FALLBACK"


@unique
class CaptureFailureCode(str, Enum):
    PREFLIGHT_FAILED = "demo.capture.preflight_failed.v1"
    HARNESS_FAILED = "demo.capture.harness_failed.v1"
    SEMANTIC_VALIDATION_FAILED = "demo.capture.semantic_validation_failed.v1"
    SEMANTIC_MISMATCH = "demo.capture.semantic_mismatch.v1"
    RENDERING_FAILED = "demo.capture.rendering_failed.v1"
    SURFACE_SCAN_FAILED = "demo.capture.surface_scan_failed.v1"
    MANIFEST_FAILED = "demo.capture.manifest_failed.v1"
    MATERIALIZATION_FAILED = "demo.capture.materialization_failed.v1"
    STAGING_CLEANUP_FAILED = "demo.capture.staging_cleanup_failed.v1"


class CaptureRehearsalError(RuntimeError):
    __slots__ = ("code", "run_ordinal")

    def __init__(
        self,
        code: CaptureFailureCode,
        run_ordinal: Optional[int] = None,
    ) -> None:
        if type(code) is not CaptureFailureCode:
            raise TypeError("capture failure requires CaptureFailureCode")
        if run_ordinal is not None and (
            type(run_ordinal) is not int
            or run_ordinal < 1
            or run_ordinal > CAPTURE_RUN_COUNT
        ):
            raise ValueError("capture failure ordinal is invalid")
        self.code = code
        self.run_ordinal = run_ordinal
        suffix = "" if run_ordinal is None else f":run-{run_ordinal}"
        super().__init__(code.value + suffix)


@final
@dataclass(frozen=True)
class CaptureSemanticSnapshot:
    schema_version: str
    scenario_count: int
    summary: Tuple[dict, ...]
    projections: Tuple[dict, ...]
    publications: Tuple[dict, ...]
    presentation_contract: dict
    surface_scan_pass: bool

    def __post_init__(self) -> None:
        if (
            self.schema_version != _SNAPSHOT_SCHEMA_VERSION
            or self.scenario_count != 6
            or type(self.summary) is not tuple
            or type(self.projections) is not tuple
            or type(self.publications) is not tuple
            or len(self.summary) != self.scenario_count
            or len(self.projections) != self.scenario_count
            or len(self.publications) != self.scenario_count
            or type(self.presentation_contract) is not dict
            or self.surface_scan_pass is not True
        ):
            raise CaptureRehearsalError(
                CaptureFailureCode.SEMANTIC_VALIDATION_FAILED
            )

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "schema_version": self.schema_version,
                "scenario_count": self.scenario_count,
                "summary": list(self.summary),
                "projections": list(self.projections),
                "publications": list(self.publications),
                "presentation_contract": self.presentation_contract,
                "surface_scan_pass": self.surface_scan_pass,
            }
        )

    @property
    def digest(self) -> str:
        return "sha256:" + sha256(self.canonical_bytes()).hexdigest()


@final
@dataclass(frozen=True)
class CaptureRehearsalSummary:
    profile: CaptureProfile
    semantic_snapshot_digest: str
    schema_version: str = CAPTURE_REHEARSAL_SCHEMA_VERSION
    status: str = "PASS"
    run_count: int = CAPTURE_RUN_COUNT
    semantic_equality: bool = True
    scenario_count: int = 6
    presentation_mode: str = "VIDEO_SAFE"
    provenance_class: str = PROVENANCE_CLASS
    surface_scan_pass: bool = True
    provider_requests_performed: bool = False
    network_requests_performed: bool = False
    google_cloud_used: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.profile) is not CaptureProfile
            or self.schema_version != CAPTURE_REHEARSAL_SCHEMA_VERSION
            or self.status != "PASS"
            or self.run_count != CAPTURE_RUN_COUNT
            or self.semantic_equality is not True
            or type(self.semantic_snapshot_digest) is not str
            or len(self.semantic_snapshot_digest) != 71
            or not self.semantic_snapshot_digest.startswith("sha256:")
            or self.scenario_count != 6
            or self.presentation_mode != "VIDEO_SAFE"
            or self.provenance_class != PROVENANCE_CLASS
            or self.surface_scan_pass is not True
            or self.provider_requests_performed is not False
            or self.network_requests_performed is not False
            or self.google_cloud_used is not False
        ):
            raise CaptureRehearsalError(
                CaptureFailureCode.SEMANTIC_VALIDATION_FAILED
            )

    def to_json_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "schema_version": self.schema_version,
                "profile": self.profile.value,
                "status": self.status,
                "run_count": self.run_count,
                "semantic_equality": self.semantic_equality,
                "semantic_snapshot_digest": self.semantic_snapshot_digest,
                "scenario_count": self.scenario_count,
                "presentation_mode": self.presentation_mode,
                "provenance_class": self.provenance_class,
                "surface_scan_pass": self.surface_scan_pass,
                "provider_requests_performed": self.provider_requests_performed,
                "network_requests_performed": self.network_requests_performed,
                "google_cloud_used": self.google_cloud_used,
            },
            trailing_newline=True,
        )


@final
@dataclass(frozen=True)
class CaptureRehearsalResult:
    summary: CaptureRehearsalSummary
    manifest: RunManifest


def _value(value):
    if isinstance(value, Enum):
        return value.value
    if value is not None and is_dataclass(value) and tuple(field.name for field in fields(type(value))) == (
        "value",
    ):
        return value.value
    return value


_SCENARIO_SUMMARY_FIELDS = (
    "scenario_id", "display_name", "mode", "provenance_label",
    "provider_evidence_digest", "expected_decision", "expected_primary_rule",
    "expected_execution", "expected_execution_start_count",
    "expected_payment_count", "expected_replay", "expected_model_attempt",
    "observed_decision", "observed_primary_rule", "observed_execution",
    "observed_execution_start_count", "observed_payment_count",
    "observed_replay", "observed_model_attempt", "callback_action",
    "projection_completeness", "projection_integrity",
    "projection_reconciliation", "publication_status", "integrity",
    "comparison", "decision_review_reference",
)


def _summary_snapshot(summary: DemoRunSummary) -> Tuple[dict, ...]:
    if tuple(field.name for field in fields(DemoRunSummary)) != (
        "run_identity", "scenarios", "required_scenario_count",
        "observed_scenario_count", "missing_scenario_count", "match_count",
        "mismatch_count", "incomplete_count", "status", "integrity",
        "provenance_summary",
    ):
        raise CaptureRehearsalError(CaptureFailureCode.SEMANTIC_VALIDATION_FAILED)
    if tuple(field.name for field in fields(ScenarioSummary)) != (
        "scenario_id", "display_name", "mode", "provenance_label",
        "provider_evidence_digest", "expected_decision", "expected_primary_rule",
        "expected_execution", "expected_execution_start_count",
        "expected_payment_count", "expected_replay", "expected_model_attempt",
        "observed_decision", "observed_primary_rule", "observed_execution",
        "observed_execution_start_count", "observed_payment_count",
        "observed_replay", "observed_model_attempt", "callback_action",
        "projection_completeness", "projection_integrity",
        "projection_reconciliation", "publication_status", "publication_digest",
        "integrity", "comparison", "decision_review_reference",
    ):
        raise CaptureRehearsalError(CaptureFailureCode.SEMANTIC_VALIDATION_FAILED)
    run_facts = {
        "run_identity_present": bool(summary.run_identity),
        "run_identity_digest_valid": _is_digest(summary.run_identity),
        "required_scenario_count": summary.required_scenario_count,
        "observed_scenario_count": summary.observed_scenario_count,
        "missing_scenario_count": summary.missing_scenario_count,
        "match_count": summary.match_count,
        "mismatch_count": summary.mismatch_count,
        "incomplete_count": summary.incomplete_count,
        "status": summary.status.value,
        "integrity": summary.integrity.value,
        "provenance_summary": summary.provenance_summary,
    }
    values = []
    for scenario in summary.scenarios:
        item = {name: _value(getattr(scenario, name)) for name in _SCENARIO_SUMMARY_FIELDS}
        item["publication_digest_present"] = scenario.publication_digest is not None
        item["publication_digest_valid"] = (
            scenario.publication_digest is None or _is_digest(scenario.publication_digest)
        )
        item["run"] = run_facts
        values.append(item)
    return tuple(values)


def _is_digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _projection_snapshot(projection) -> dict:
    expected_fields = (
        "trace_id", "recorded_at", "invocation_ids", "call_ids", "decision_ids",
        "prepared_call_ids", "execution_ids", "payment_record_ids", "tool_ids",
        "tool_contract_versions", "policy_versions", "registry_versions",
        "producer_facts", "evidence_schema_versions", "export_digests",
        "masking_profile_version", "authorization_outcome", "disposition",
        "primary_rule_id", "decision_stage", "rule_facts", "callback_action",
        "callback_trail", "execution_started", "execution_start_count",
        "execution_status", "external_result_confirmed", "payment_recorded",
        "payment_count", "replay_state", "model_non_attempt", "argument_facts",
        "masked_reason_facts", "integrity_status", "reconciliation_status",
        "findings", "schema_gap_count", "retained_record_count",
        "forensic_record_count", "malformed_record_count",
        "authoritative_event_count", "evidence_completeness",
    )
    if tuple(field.name for field in fields(type(projection))) != expected_fields:
        raise CaptureRehearsalError(CaptureFailureCode.SEMANTIC_VALIDATION_FAILED)
    correlations = {
        "trace_id_present": bool(projection.trace_id),
        "recorded_at_present": projection.recorded_at is not None,
        "recorded_at_canonical": (
            projection.recorded_at is None or projection.recorded_at.endswith("Z")
        ),
        "invocation_id_count": len(projection.invocation_ids),
        "call_id_count": len(projection.call_ids),
        "decision_id_count": len(projection.decision_ids),
        "prepared_call_id_count": len(projection.prepared_call_ids),
        "execution_id_count": len(projection.execution_ids),
        "payment_record_id_count": len(projection.payment_record_ids),
        "export_digest_count": len(projection.export_digests),
        "export_digests_valid": all(_is_digest(item) for item in projection.export_digests),
    }
    return {
        "correlation_shapes": correlations,
        "tool_ids": [_value(item) for item in projection.tool_ids],
        "tool_contract_versions": [_value(item) for item in projection.tool_contract_versions],
        "policy_versions": [_value(item) for item in projection.policy_versions],
        "registry_versions": [_value(item) for item in projection.registry_versions],
        "producer_facts": [
            {"component": item.component, "build_version": item.build_version}
            for item in projection.producer_facts
        ],
        "evidence_schema_versions": list(projection.evidence_schema_versions),
        "masking_profile_version": projection.masking_profile_version,
        "authorization_outcome": _value(projection.authorization_outcome),
        "disposition": projection.disposition.value,
        "primary_rule_id": _value(projection.primary_rule_id),
        "decision_stage": _value(projection.decision_stage),
        "rule_facts": [
            {
                "rule_id": item.rule_id.value,
                "outcome": item.outcome.value,
                "stage": item.stage.value,
                "argument_name": item.argument_name,
                "constraint_id": _value(item.constraint_id),
            }
            for item in projection.rule_facts
        ],
        "callback_action": projection.callback_action.value,
        "callback_trail": [item.value for item in projection.callback_trail],
        "execution_started": projection.execution_started,
        "execution_start_count": projection.execution_start_count,
        "execution_status": projection.execution_status.value,
        "external_result_confirmed": projection.external_result_confirmed,
        "payment_recorded": projection.payment_recorded,
        "payment_count": projection.payment_count,
        "replay_state": projection.replay_state.value,
        "model_non_attempt": projection.model_non_attempt,
        "argument_facts": [
            {
                "name": item.name,
                "role": item.role.value,
                "supported_type": item.supported_type.value,
                "provenance_class": item.provenance_class.value,
                "resolution_status": item.resolution_status,
                "binding_status": item.binding_status,
                "masked_display": item.masked_display,
            }
            for item in projection.argument_facts
        ],
        "masked_reason_facts": [
            {"key": item.key, "value": _value(item.value)}
            for item in projection.masked_reason_facts
        ],
        "integrity_status": projection.integrity_status.value,
        "reconciliation_status": projection.reconciliation_status.value,
        "findings": [
            {
                "code": item.code.value,
                "domain": item.domain.value,
                "sequence": item.sequence,
                "event_type": _value(item.event_type),
                "location": item.location,
                "correlation_fingerprint_present": item.correlation_fingerprint is not None,
                "correlation_fingerprint_valid": (
                    item.correlation_fingerprint is None
                    or _is_digest(item.correlation_fingerprint)
                ),
            }
            for item in projection.findings
        ],
        "schema_gap_count": projection.schema_gap_count,
        "retained_record_count": projection.retained_record_count,
        "forensic_record_count": projection.forensic_record_count,
        "malformed_record_count": projection.malformed_record_count,
        "authoritative_event_count": projection.authoritative_event_count,
        "evidence_completeness": projection.evidence_completeness.value,
    }


def _publication_snapshot(run: DemoHarnessRun) -> Tuple[dict, ...]:
    publications = []
    for scenario in run.scenarios:
        verification = verify_evidence_publication(scenario.publication_package)
        package = verification.package
        publications.append(
            {
                "verified": verification.valid,
                "finding_codes": [item.value for item in verification.findings],
                "package_present": package is not None,
                "package_digest_valid": (
                    package is not None and _is_digest(package.package_digest)
                ),
                "export_id_present": package is not None and bool(package.export_id),
                "export_version": None if package is None else package.export_version,
                "trace_id_present": package is not None and bool(package.trace_id),
            }
        )
    return tuple(publications)


def _published_artifact_specs(run: DemoHarnessRun) -> Tuple[Tuple[str, str], ...]:
    return tuple(sorted((
        ("index.html", "text/html"),
        *(
            (item.decision_review_artifact.reference, "text/html")
            for item in run.scenarios
        ),
        ("demo-rehearsal-report.json", "application/json"),
        ("capture-rehearsal-summary.json", "application/json"),
    )))


def _capture_semantic_snapshot(
    run: DemoHarnessRun,
    publications: Optional[Tuple[dict, ...]] = None,
) -> CaptureSemanticSnapshot:
    if (
        type(run) is not DemoHarnessRun
        or run.summary.status is not RunStatus.PASS
        or tuple(item.scenario_id for item in run.scenarios) != REQUIRED_SCENARIO_ORDER
        or tuple(item.scenario_id for item in run.summary.scenarios) != REQUIRED_SCENARIO_ORDER
    ):
        raise CaptureRehearsalError(CaptureFailureCode.SEMANTIC_VALIDATION_FAILED)
    publication_facts = (
        _publication_snapshot(run) if publications is None else publications
    )
    surfaces = (
        ("run-summary.html", run.run_summary_html.encode("utf-8")),
        ("integrated-ui.html", run.integrated_ui_html.encode("utf-8")),
        *(
            (scenario.decision_review_artifact.reference, scenario.decision_review_artifact.html.encode("utf-8"))
            for scenario in run.scenarios
        ),
        *(
            (
                f"publication-{scenario.scenario_id.value.lower().replace('_', '-')}.json",
                scenario.publication_package.canonical_bytes,
            )
            for scenario in run.scenarios
        ),
    )
    scan = scan_demo_surfaces(tuple(surfaces))
    artifact_specs = _published_artifact_specs(run)
    presentation = {
        "artifact_names": [name for name, _ in artifact_specs],
        "media_types": [media_type for _, media_type in artifact_specs],
        "surface_count": run.integrated_ui_html.count('data-surface="'),
        "guided_step_count": run.integrated_ui_html.count('data-step="'),
        "read_only": "READ-ONLY" in run.integrated_ui_html,
        "no_network": all(
            token not in run.integrated_ui_html
            for token in ("fetch(", "XMLHttpRequest", "WebSocket", "EventSource")
        ),
    }
    return CaptureSemanticSnapshot(
        schema_version=_SNAPSHOT_SCHEMA_VERSION,
        scenario_count=len(run.scenarios),
        summary=_summary_snapshot(run.summary),
        projections=tuple(_projection_snapshot(item.projection) for item in run.scenarios),
        publications=publication_facts,
        presentation_contract=presentation,
        surface_scan_pass=scan.pass_all,
    )


def _timing_statistics(samples) -> TimingStatistics:
    values = tuple(float(value) for value in samples)
    return TimingStatistics(
        sample_count=len(values),
        minimum_seconds=min(values),
        median_seconds=float(median(values)),
        maximum_seconds=max(values),
    )


def _capture_artifacts(
    runs: Tuple[DemoHarnessRun, ...],
    timings: DemoRehearsalTimings,
    capture_summary: CaptureRehearsalSummary,
) -> Tuple[DemoRehearsalArtifact, ...]:
    final_run = runs[-1]
    try:
        summary_html = render_demo_run_summary(final_run.summary)
        if summary_html != final_run.run_summary_html:
            raise ValueError("summary mismatch")
        scenarios = build_final_ui_scenarios(
            final_run.summary,
            tuple(
                (
                    item.scenario_id,
                    item.projection,
                    item.mechanism_projection,
                )
                for item in final_run.scenarios
            ),
        )
        final_html = render_final_ui(
            final_run.summary,
            scenarios,
            presentation_mode=PresentationMode.VIDEO_SAFE,
        )
        decision_html = tuple(
            render_decision_review_workspace(item.projection)
            for item in final_run.scenarios
        )
        if any(
            rendered != scenario.decision_review_artifact.html
            for rendered, scenario in zip(decision_html, final_run.scenarios)
        ):
            raise ValueError("decision mismatch")
    except (RuntimeError, TypeError, ValueError):
        raise CaptureRehearsalError(CaptureFailureCode.RENDERING_FAILED) from None
    artifact_specs = _published_artifact_specs(final_run)
    content_by_name = {
        "index.html": final_html.encode("utf-8"),
        "capture-rehearsal-summary.json": capture_summary.to_json_bytes(),
        **{
            scenario.decision_review_artifact.reference: rendered.encode("utf-8")
            for scenario, rendered in zip(final_run.scenarios, decision_html)
        },
    }
    publication_scan = scan_demo_surfaces(
        tuple(sorted(content_by_name.items()))
    )
    summaries = {item.scenario_id: item for item in final_run.summary.scenarios}
    report = DemoRehearsalReport(
        status=final_run.summary.status,
        sample_count=CAPTURE_RUN_COUNT,
        run_ids=tuple(item.run_id for item in runs),
        required_scenario_count=6,
        all_required_scenarios_rehearsed=True,
        publication_verification_count=18,
        scenarios=tuple(
            RehearsalScenarioFact(
                scenario_id=item.scenario_id,
                disposition=item.projection.disposition,
                primary_rule_id=item.projection.primary_rule_id,
                execution_status=item.projection.execution_status,
                execution_start_count=item.projection.execution_start_count,
                payment_count=item.projection.payment_count,
                replay_state=item.projection.replay_state,
                model_non_attempt=item.projection.model_non_attempt,
                mode=item.provenance.mode,
                comparison=summaries[item.scenario_id].comparison,
                integrity=summaries[item.scenario_id].integrity,
            )
            for item in final_run.scenarios
        ),
        timings=timings,
        secret_scan_pass=publication_scan.secret_scan_pass,
        protected_data_scan_pass=publication_scan.protected_data_scan_pass,
        absolute_path_scan_pass=publication_scan.absolute_path_scan_pass,
        artifact_names=tuple(name for name, _ in artifact_specs),
    )
    content_by_name["demo-rehearsal-report.json"] = report.to_json_bytes()
    return tuple(
        DemoRehearsalArtifact(name, media_type, content_by_name[name])
        for name, media_type in artifact_specs
    )


def _cleanup_staging(staging: Optional[Path]) -> None:
    if staging is None or not staging.exists():
        return
    try:
        shutil.rmtree(str(staging))
    except OSError:
        raise CaptureRehearsalError(CaptureFailureCode.STAGING_CLEANUP_FAILED) from None


def _materialize(
    root: Path,
    artifacts: Tuple[DemoRehearsalArtifact, ...],
    manifest: RunManifest,
) -> None:
    staging = None
    try:
        staging = Path(tempfile.mkdtemp(prefix=".tidemark-capture-", dir=str(root)))
        for artifact in artifacts:
            with (staging / artifact.name).open("xb") as stream:
                if stream.write(artifact.content) != len(artifact.content):
                    raise OSError("partial write")
                stream.flush()
                os.fsync(stream.fileno())
        encoded = serialize_run_manifest(manifest)
        with (staging / "run-manifest.json").open("xb") as stream:
            if stream.write(encoded) != len(encoded):
                raise OSError("partial write")
            stream.flush()
            os.fsync(stream.fileno())
        verify_materialized_run_manifest(str(staging))
        if tuple(root.iterdir()) != (staging,):
            raise OSError("output root changed")
        destination = root / "artifacts"
        staging.rename(destination)
        staging = None
    except CaptureRehearsalError:
        _cleanup_staging(staging)
        raise
    except (OSError, RunManifestError, RuntimeError, TypeError, ValueError):
        _cleanup_staging(staging)
        raise CaptureRehearsalError(CaptureFailureCode.MATERIALIZATION_FAILED) from None


def run_capture_rehearsal(
    *, profile: CaptureProfile, output_root: str
) -> CaptureRehearsalResult:
    """Run exactly three independent offline samples and publish atomically."""

    if type(profile) is not CaptureProfile:
        raise TypeError("capture profile requires CaptureProfile")
    preflight = run_preflight(
        profile=PreflightProfile.CAPTURE,
        output_root=output_root,
    )
    if (
        preflight.local_readiness is not LocalReadiness.PASS
        or preflight.repository_provenance is None
    ):
        raise CaptureRehearsalError(CaptureFailureCode.PREFLIGHT_FAILED)
    runs = []
    baseline = None
    harness_timings = []
    summary_timings = []
    decision_timings = []
    publication_timings = []
    sample_timings = []
    for ordinal in range(1, CAPTURE_RUN_COUNT + 1):
        sample_started = perf_counter()
        harness_started = perf_counter()
        try:
            run = DeterministicDemoHarness(
                run_seed=f"phase-1-{profile.value.lower()}-{ordinal}"
            ).run()
        except (OSError, RuntimeError, TypeError, ValueError):
            raise CaptureRehearsalError(
                CaptureFailureCode.HARNESS_FAILED, ordinal
            ) from None
        harness_timings.append(perf_counter() - harness_started)
        try:
            publication_started = perf_counter()
            publications = _publication_snapshot(run)
            publication_timings.append(perf_counter() - publication_started)

            snapshot = _capture_semantic_snapshot(run, publications)
            if baseline is None:
                baseline = snapshot
            elif snapshot.canonical_bytes() != baseline.canonical_bytes():
                raise CaptureRehearsalError(
                    CaptureFailureCode.SEMANTIC_MISMATCH, ordinal
                )

            summary_started = perf_counter()
            rendered_summary = render_demo_run_summary(run.summary)
            summary_timings.append(perf_counter() - summary_started)
            if rendered_summary != run.run_summary_html:
                raise ValueError("summary mismatch")
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
            if rendered_final_ui != run.integrated_ui_html:
                raise ValueError("integrated UI mismatch")

            decision_started = perf_counter()
            rendered_decisions = tuple(
                render_decision_review_workspace(scenario.projection)
                for scenario in run.scenarios
            )
            decision_timings.append(perf_counter() - decision_started)
            if any(
                rendered != scenario.decision_review_artifact.html
                for rendered, scenario in zip(rendered_decisions, run.scenarios)
            ):
                raise ValueError("decision mismatch")
        except CaptureRehearsalError:
            raise
        except (OSError, RuntimeError, TypeError, ValueError):
            raise CaptureRehearsalError(
                CaptureFailureCode.RENDERING_FAILED, ordinal
            ) from None
        runs.append(run)
        sample_timings.append(perf_counter() - sample_started)
    if baseline is None or len(runs) != CAPTURE_RUN_COUNT:
        raise CaptureRehearsalError(CaptureFailureCode.SEMANTIC_VALIDATION_FAILED)
    summary = CaptureRehearsalSummary(profile, baseline.digest)
    timings = DemoRehearsalTimings(
        full_harness_runtime=_timing_statistics(harness_timings),
        run_summary_render=_timing_statistics(summary_timings),
        decision_review_render=_timing_statistics(decision_timings),
        publication_verification=_timing_statistics(publication_timings),
        complete_sample=_timing_statistics(sample_timings),
    )
    artifacts = _capture_artifacts(tuple(runs), timings, summary)
    try:
        root = Path(output_root)
        forbidden = (str(root.resolve()).encode(), str(Path.cwd().resolve()).encode())
        scan = scan_demo_surfaces(
            tuple((item.name, item.content) for item in artifacts),
            extra_forbidden_values=forbidden,
        )
    except (OSError, TypeError, ValueError):
        raise CaptureRehearsalError(CaptureFailureCode.SURFACE_SCAN_FAILED) from None
    if not scan.pass_all:
        raise CaptureRehearsalError(CaptureFailureCode.SURFACE_SCAN_FAILED)
    try:
        manifest = build_run_manifest(
            repository_provenance=preflight.repository_provenance,
            run_mode=(
                RunMode.CAPTURE
                if profile is CaptureProfile.CAPTURE
                else RunMode.DETERMINISTIC_FALLBACK
            ),
            presentation_mode=ManifestPresentationMode.VIDEO_SAFE,
            artifacts=artifacts,
            fresh_run_count=CAPTURE_RUN_COUNT,
            scenario_count=6,
            capture_schema=CAPTURE_REHEARSAL_SCHEMA_VERSION,
        )
        verify_run_manifest(serialize_run_manifest(manifest), artifacts)
    except (RunManifestError, RuntimeError, TypeError, ValueError):
        raise CaptureRehearsalError(CaptureFailureCode.MANIFEST_FAILED) from None
    _materialize(root, artifacts, manifest)
    return CaptureRehearsalResult(summary, manifest)


__all__ = (
    "CAPTURE_REHEARSAL_SCHEMA_VERSION",
    "CAPTURE_RUN_COUNT",
    "CaptureFailureCode",
    "CaptureProfile",
    "CaptureRehearsalError",
    "CaptureRehearsalResult",
    "CaptureRehearsalSummary",
    "CaptureSemanticSnapshot",
    "run_capture_rehearsal",
)
