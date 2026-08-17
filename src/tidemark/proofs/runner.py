"""Deterministic W2 proof orchestration and safe reviewer output."""

from contextlib import ExitStack
import os
from pathlib import Path
import tempfile
from typing import Optional, Tuple

from tidemark.demo.preflight import (
    LocalReadiness,
    PreflightProfile,
    recheck_repository_provenance,
    run_preflight,
)
from tidemark.demo.rehearsal import scan_demo_surfaces
from tidemark.proofs.catalogue import PROOF_CATALOGUE
from tidemark.proofs.fixtures import execute_proof_fixture
from tidemark.proofs.model import (
    PROOF_SUITE_SCHEMA,
    ProofInfrastructureErrorCode,
    ProofProvenance,
    ProofRunOutcome,
    ProofRunResult,
    ProofStatus,
    adjudicate_suite,
    serialize_proof_suite,
    verify_proof_suite_bytes,
)


CORE_PROPERTY_IDS = ("W2-P01", "W2-P02", "W2-P03")
MECHANISM_PROPERTY_IDS = tuple(item.property_id for item in PROOF_CATALOGUE)
PROOF_ARTIFACT_NAME = "security-proof-suite.json"
_TERMINAL_SURFACE_NAME = "security-proof-terminal.txt"


def _run_properties(
    workspace_root: Path,
    *,
    source_revision: str,
    selected_property_ids: Tuple[str, ...],
) -> ProofRunResult:
    if not isinstance(workspace_root, Path):
        return ProofRunResult.error(ProofInfrastructureErrorCode.EXECUTION_ERROR)
    selected = tuple(
        definition
        for definition in PROOF_CATALOGUE
        if definition.property_id in selected_property_ids
    )
    try:
        observed = tuple(
            (
                definition.property_id,
                tuple(
                    execute_proof_fixture(
                        fixture.fixture_id,
                        workspace_root / fixture.fixture_id,
                    )
                    for fixture in definition.fixtures
                ),
            )
            for definition in selected
        )
        result = adjudicate_suite(
            catalogue=PROOF_CATALOGUE,
            selected_property_ids=selected_property_ids,
            observed_by_property=observed,
            provenance=ProofProvenance(
                provenance_class="CLEAN_COMMITTED_LOCAL_SOURCE",
                source_revision=source_revision,
                live_model_calls_performed=0,
                google_cloud_accessed=False,
            ),
        )
    except Exception:
        return ProofRunResult.error(ProofInfrastructureErrorCode.EXECUTION_ERROR)
    return ProofRunResult.completed(result)


def run_core_proof_properties(
    workspace_root: Path,
    *,
    source_revision: str,
) -> ProofRunResult:
    """Run only W2-P01 through W2-P03 for focused mechanism validation."""

    return _run_properties(
        workspace_root,
        source_revision=source_revision,
        selected_property_ids=CORE_PROPERTY_IDS,
    )


def run_mechanism_proof_properties(
    workspace_root: Path,
    *,
    source_revision: str,
) -> ProofRunResult:
    """Run all 23 fixed mechanism cases without public materialization."""

    return _run_properties(
        workspace_root,
        source_revision=source_revision,
        selected_property_ids=MECHANISM_PROPERTY_IDS,
    )


def render_error(code: ProofInfrastructureErrorCode) -> bytes:
    """Render the only public infrastructure-error envelope."""

    if type(code) is not ProofInfrastructureErrorCode:
        raise TypeError("code requires ProofInfrastructureErrorCode")
    return (
        "PROOF_RUN_STATUS=ERROR\n"
        f"PROOF_INFRASTRUCTURE_ERROR={code.value}\n"
        "PROPERTY_RESULTS_EMITTED=0\n"
        "LIVE_MODEL_CALLS_PERFORMED=0\n"
        "GOOGLE_CLOUD_ACCESSED=false\n"
    ).encode("ascii")


def render_proof_run(
    run: ProofRunResult,
    *,
    artifact_materialized: bool = False,
) -> bytes:
    """Render only closed aggregate facts from a completed run or safe error."""

    if type(run) is not ProofRunResult or type(artifact_materialized) is not bool:
        raise TypeError("renderer requires an exact proof run and bool")
    if run.outcome is ProofRunOutcome.ERROR:
        return render_error(run.infrastructure_error)

    suite = run.suite_result
    lines = [
        f"PROOF_SUITE_SCHEMA={PROOF_SUITE_SCHEMA}",
        f"SOURCE_REVISION={suite.provenance.source_revision}",
    ]
    for result in suite.properties:
        lines.append(f"PROPERTY={result.property_id}:{result.proof_status.value}")
        lines.append(f"PROPERTY_CASE_COUNT={result.property_id}:{len(result.cases)}")
        if result.property_id == "W2-P08":
            states = ",".join(
                case.observed.evidence_execution_status.value
                for case in result.cases
            )
            success_claims = sum(
                case.observed.evidence_success_claimed is True
                for case in result.cases
            )
            absence_claims = sum(
                case.observed.external_effect_absence_claimed is True
                for case in result.cases
            )
            lines.extend(
                (
                    "P08_PROOF_MEANING=UNCERTAINTY_PRESERVED",
                    f"P08_EVIDENCE_EXECUTION_STATES={states}",
                    f"P08_EVIDENCE_SUCCESS_CLAIMS={success_claims}",
                    f"P08_EXTERNAL_EFFECT_ABSENCE_CLAIMS={absence_claims}",
                )
            )
    lines.extend(
        (
            f"SUITE_STATUS={suite.suite_status.value}",
            f"EXECUTED_PROPERTY_COUNT={suite.executed_property_count}",
            "LIVE_MODEL_CALLS_PERFORMED=0",
            "GOOGLE_CLOUD_ACCESSED=false",
        )
    )
    if artifact_materialized:
        lines.append(f"ARTIFACT={PROOF_ARTIFACT_NAME}")
    return ("\n".join(lines) + "\n").encode("ascii")


def proof_exit_code(run: ProofRunResult) -> int:
    """Map the closed run outcome to the reviewer CLI exit contract."""

    if type(run) is not ProofRunResult:
        raise TypeError("exit mapping requires ProofRunResult")
    if run.outcome is ProofRunOutcome.ERROR:
        return 2
    return 0 if run.suite_result.suite_status is ProofStatus.PASS else 1


def _output_directory_ready(output_dir: Path) -> bool:
    try:
        return (
            isinstance(output_dir, Path)
            and output_dir.exists()
            and output_dir.is_dir()
            and not output_dir.is_symlink()
            and not any(output_dir.iterdir())
            and not (output_dir / PROOF_ARTIFACT_NAME).exists()
        )
    except (OSError, TypeError, ValueError):
        return False


def _exclusive_link(source: str, target: str) -> None:
    os.link(source, target)


def _publish_atomic(output_dir: Path, encoded: bytes) -> None:
    """Publish verified bytes with exclusive final-name creation."""

    target = output_dir / PROOF_ARTIFACT_NAME
    descriptor = None
    staged = None
    linked = False
    try:
        descriptor, staged_name = tempfile.mkstemp(
            prefix=".tidemark-security-proof-",
            suffix=".tmp",
            dir=str(output_dir),
        )
        staged = Path(staged_name)
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise OSError("short proof publication write")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        if staged.read_bytes() != encoded:
            raise OSError("staged proof bytes differ")
        _exclusive_link(str(staged), str(target))
        linked = True
        staged.unlink()
        staged = None
        directory_descriptor = os.open(str(output_dir), os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except Exception:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if staged is not None:
            try:
                staged.unlink()
            except OSError:
                pass
        if linked:
            try:
                target.unlink()
            except OSError:
                pass
        raise


def run_security_proofs(
    *,
    property_id: Optional[str] = None,
    output_dir: Optional[Path] = None,
) -> ProofRunResult:
    """Run the fixed all-property suite or one exact property fail closed."""

    if property_id is None:
        selected_property_ids = MECHANISM_PROPERTY_IDS
    elif type(property_id) is str and property_id in MECHANISM_PROPERTY_IDS:
        selected_property_ids = (property_id,)
    else:
        return ProofRunResult.error(ProofInfrastructureErrorCode.SELECTION_INVALID)

    if output_dir is not None and not _output_directory_ready(output_dir):
        return ProofRunResult.error(ProofInfrastructureErrorCode.PREFLIGHT_FAILED)

    with ExitStack() as stack:
        if output_dir is None:
            preflight_root = Path(
                stack.enter_context(
                    tempfile.TemporaryDirectory(prefix="tidemark-proof-preflight-")
                )
            )
        else:
            preflight_root = output_dir
        workspace_root = Path(
            stack.enter_context(
                tempfile.TemporaryDirectory(prefix="tidemark-proof-workspace-")
            )
        )

        try:
            preflight = run_preflight(
                profile=PreflightProfile.REPRODUCTION,
                output_root=str(preflight_root),
            )
        except Exception:
            return ProofRunResult.error(ProofInfrastructureErrorCode.PREFLIGHT_FAILED)
        if (
            preflight.local_readiness is not LocalReadiness.PASS
            or preflight.repository_provenance is None
        ):
            return ProofRunResult.error(ProofInfrastructureErrorCode.PREFLIGHT_FAILED)

        provenance = preflight.repository_provenance
        run = _run_properties(
            workspace_root,
            source_revision=provenance.source_revision,
            selected_property_ids=selected_property_ids,
        )
        if run.outcome is ProofRunOutcome.ERROR:
            return run
        try:
            if not recheck_repository_provenance(provenance):
                return ProofRunResult.error(
                    ProofInfrastructureErrorCode.PROVENANCE_FAILED
                )
        except Exception:
            return ProofRunResult.error(ProofInfrastructureErrorCode.PROVENANCE_FAILED)

        try:
            artifact_bytes = serialize_proof_suite(run.suite_result)
        except Exception:
            return ProofRunResult.error(
                ProofInfrastructureErrorCode.SERIALIZATION_FAILED
            )
        try:
            if verify_proof_suite_bytes(artifact_bytes) is not True:
                raise ValueError("proof verification returned false")
        except Exception:
            return ProofRunResult.error(
                ProofInfrastructureErrorCode.VERIFICATION_FAILED
            )

        try:
            transcript = render_proof_run(
                run,
                artifact_materialized=output_dir is not None,
            )
            forbidden_paths = tuple(
                dict.fromkeys(
                    str(path).encode("utf-8")
                    for path in (preflight_root, workspace_root, output_dir)
                    if path is not None
                )
            )
            scan = scan_demo_surfaces(
                (
                    (_TERMINAL_SURFACE_NAME, transcript),
                    (PROOF_ARTIFACT_NAME, artifact_bytes),
                ),
                extra_forbidden_values=forbidden_paths,
            )
            if not scan.pass_all:
                raise ValueError("proof surface rejected")
        except Exception:
            return ProofRunResult.error(
                ProofInfrastructureErrorCode.SURFACE_SCAN_FAILED
            )

        if output_dir is not None:
            try:
                if not recheck_repository_provenance(provenance):
                    return ProofRunResult.error(
                        ProofInfrastructureErrorCode.PROVENANCE_FAILED
                    )
            except Exception:
                return ProofRunResult.error(
                    ProofInfrastructureErrorCode.PROVENANCE_FAILED
                )
            try:
                _publish_atomic(output_dir, artifact_bytes)
            except Exception:
                return ProofRunResult.error(
                    ProofInfrastructureErrorCode.PUBLICATION_FAILED
                )
        return run


__all__ = (
    "CORE_PROPERTY_IDS",
    "MECHANISM_PROPERTY_IDS",
    "PROOF_ARTIFACT_NAME",
    "proof_exit_code",
    "render_error",
    "render_proof_run",
    "run_core_proof_properties",
    "run_mechanism_proof_properties",
    "run_security_proofs",
)
