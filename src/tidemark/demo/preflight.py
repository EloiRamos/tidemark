"""Deterministic local readiness checks for manifest-backed demo artifacts.

This module deliberately performs no provider, credential, Google ADK, cloud,
or billing inspection.  Its repository provenance is an internal attestation
used only by the run-manifest owner.
"""

from dataclasses import dataclass
from enum import Enum, unique
from importlib import metadata
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Optional, Tuple, final

from tidemark.demo.rehearsal import scan_demo_surfaces
from tidemark.evidence.canonical import canonical_json_bytes


MINIMUM_PYTHON = (3, 9)
TIDEMARK_VERSION = "0.1.0"
PYTEST_VERSION = "8.4.2"
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_ATTESTATION = object()
_REQUIRED_LAYOUT = (
    "Makefile",
    "pyproject.toml",
    "scripts/run_demo_rehearsal.py",
    "src/tidemark/demo/preflight.py",
    "src/tidemark/demo/manifest.py",
    "src/tidemark/demo/capture.py",
    "src/tidemark/demo/rehearsal.py",
    "src/tidemark/ui/final_ui.py",
)
_CAPTURE_PROOFS = (
    "docs/evidence/ORDER_12_LIVE_MODEL_PROOF_v1.0.md",
    "docs/evidence/ORDER_21_CLOUD_DEPLOYMENT_PROOF_v1.0.md",
)


@unique
class PreflightProfile(str, Enum):
    REPRODUCTION = "REPRODUCTION"
    CAPTURE = "CAPTURE"


@unique
class LocalReadiness(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"


@unique
class LiveGateState(str, Enum):
    NOT_EVALUATED = "NOT_EVALUATED"


@unique
class PreflightCheckCode(str, Enum):
    PYTHON_FLOOR = "preflight.01.python_floor.v1"
    PACKAGE_DEPENDENCIES = "preflight.02.package_dependencies.v1"
    REPOSITORY_LAYOUT = "preflight.03.repository_layout.v1"
    REPOSITORY_PROVENANCE = "preflight.04.repository_provenance.v1"
    OUTPUT_ROOT = "preflight.05.output_root.v1"
    PUBLICATION_HELPERS = "preflight.06.publication_helpers.v1"
    CAPTURE_PROOFS = "preflight.07.capture_proofs.v1"
    CAPTURE_PROJECTIONS = "preflight.08.capture_projections.v1"
    CAPTURE_UI_SMOKE = "preflight.09.capture_ui_smoke.v1"
    NO_ARTIFACTS_CREATED = "preflight.10.no_artifacts_created.v1"


@final
@dataclass(frozen=True)
class PreflightCheck:
    code: PreflightCheckCode
    passed: bool

    def __post_init__(self) -> None:
        if type(self.code) is not PreflightCheckCode:
            raise TypeError("preflight check requires a closed code")
        if type(self.passed) is not bool:
            raise TypeError("preflight check status requires bool")


@final
@dataclass(frozen=True, init=False)
class RepositoryProvenance:
    source_revision: str
    _root: Path
    _attestation: object

    @classmethod
    def _verified(cls, source_revision: str, root: Path) -> "RepositoryProvenance":
        value = object.__new__(cls)
        object.__setattr__(value, "source_revision", source_revision)
        object.__setattr__(value, "_root", root)
        object.__setattr__(value, "_attestation", _ATTESTATION)
        return value

    def __repr__(self) -> str:
        return (
            "RepositoryProvenance("
            f"source_revision={self.source_revision!r}, clean=True)"
        )


@final
@dataclass(frozen=True)
class PreflightResult:
    profile: PreflightProfile
    local_readiness: LocalReadiness
    live_gate_state: LiveGateState
    checks: Tuple[PreflightCheck, ...]
    repository_provenance: Optional[RepositoryProvenance]
    live_model_calls_performed: int = 0
    google_cloud_accessed: bool = False

    def __post_init__(self) -> None:
        if type(self.profile) is not PreflightProfile:
            raise TypeError("preflight result requires a closed profile")
        if type(self.local_readiness) is not LocalReadiness:
            raise TypeError("preflight result requires local readiness")
        if type(self.live_gate_state) is not LiveGateState:
            raise TypeError("preflight result requires live gate state")
        if type(self.checks) is not tuple or any(
            type(check) is not PreflightCheck for check in self.checks
        ):
            raise TypeError("preflight checks require an immutable tuple")
        expected = tuple(code for code in PreflightCheckCode if any(
            item.code is code for item in self.checks
        ))
        if tuple(item.code for item in self.checks) != expected:
            raise ValueError("preflight checks are not in closed order")
        if self.local_readiness is LocalReadiness.PASS:
            if not self.checks or not all(item.passed for item in self.checks):
                raise ValueError("passing preflight requires every check")
            if type(self.repository_provenance) is not RepositoryProvenance:
                raise ValueError("passing preflight requires repository provenance")
        elif self.repository_provenance is not None:
            raise ValueError("failed preflight cannot carry repository provenance")
        if self.live_model_calls_performed != 0 or self.google_cloud_accessed is not False:
            raise ValueError("preflight cannot report live or cloud activity")

    @property
    def failed_codes(self) -> Tuple[PreflightCheckCode, ...]:
        return tuple(item.code for item in self.checks if not item.passed)

    def diagnostic_lines(self) -> Tuple[str, ...]:
        return (
            f"PREFLIGHT_PROFILE={self.profile.value}",
            f"LOCAL_READINESS={self.local_readiness.value}",
            f"LIVE_GATE_STATE={self.live_gate_state.value}",
            *(f"CHECK={item.code.value}:{'PASS' if item.passed else 'FAIL'}" for item in self.checks),
            "LIVE_MODEL_CALLS_PERFORMED=0",
            "GOOGLE_CLOUD_ACCESSED=false",
        )


def _executing_package_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _repository_root() -> Path:
    return _executing_package_root().parents[1]


def _repository_layout_ready(root: Path) -> bool:
    try:
        return (
            _executing_package_root().resolve()
            == (root / "src" / "tidemark").resolve()
            and all((root / relative).is_file() for relative in _REQUIRED_LAYOUT)
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return False


def _git(root: Path, *arguments: str) -> Optional[str]:
    try:
        completed = subprocess.run(
            ("git", "-C", str(root), *arguments),
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout


def _clean_revision(root: Path) -> Optional[str]:
    revision_output = _git(root, "rev-parse", "--verify", "HEAD")
    status = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    whitespace = _git(root, "diff", "--check")
    if revision_output is None or status is None or whitespace is None:
        return None
    revision = revision_output.strip()
    if (
        _COMMIT.fullmatch(revision) is None
        or status != ""
        or whitespace != ""
    ):
        return None
    return revision


def _output_root_ready(value: str) -> bool:
    if type(value) is not str or not value:
        return False
    root = Path(value)
    sentinel = root / ".tidemark-preflight-sentinel"
    descriptor = None
    try:
        if (
            not root.exists()
            or not root.is_dir()
            or root.is_symlink()
            or any(root.iterdir())
        ):
            return False
        descriptor = os.open(
            str(sentinel),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        written = os.write(descriptor, b"tidemark-preflight\n")
        if written != len(b"tidemark-preflight\n"):
            return False
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        sentinel.unlink()
        return not any(root.iterdir())
    except (OSError, TypeError, ValueError):
        return False
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            if sentinel.exists() and sentinel.is_file() and not sentinel.is_symlink():
                sentinel.unlink()
        except OSError:
            pass


def _package_dependencies_ready() -> bool:
    try:
        __import__("tidemark")
        return metadata.version("pytest") == PYTEST_VERSION
    except (ImportError, metadata.PackageNotFoundError, ValueError):
        return False


def _publication_helpers_ready() -> bool:
    try:
        canonical = canonical_json_bytes({"b": 2, "a": 1})
        safe = scan_demo_surfaces((("self-test.json", canonical),))
        rejected = scan_demo_surfaces(
            (("self-test.txt", b"synthetic-routing://private"),)
        )
        return canonical == b'{"a":1,"b":2}' and safe.pass_all and not rejected.pass_all
    except (ImportError, OSError, RuntimeError, TypeError, ValueError):
        return False


def _capture_proofs_ready(root: Path) -> bool:
    for relative in _CAPTURE_PROOFS:
        target = root / relative
        if not target.is_file() or target.is_symlink():
            return False
        tracked = _git(root, "ls-files", "--error-unmatch", "--", relative)
        if tracked is None or tracked.strip() != relative:
            return False
    return True


def _capture_projections_ready() -> bool:
    try:
        from tidemark.ui.final_ui import (
            CommittedCloudProof,
            CommittedHistoricalLiveProof,
        )

        return (
            type(CommittedCloudProof()) is CommittedCloudProof
            and type(CommittedHistoricalLiveProof()) is CommittedHistoricalLiveProof
        )
    except (ImportError, RuntimeError, TypeError, ValueError):
        return False


def _capture_ui_smoke_ready() -> bool:
    try:
        from tidemark.demo.harness import DeterministicDemoHarness

        run = DeterministicDemoHarness(run_seed="phase-1-preflight-smoke").run()
        encoded = run.integrated_ui_html.encode("utf-8")
        return (
            run.summary.status.value == "PASS"
            and encoded.count(b'data-surface="') == 4
            and encoded.count(b'data-step="') == 5
            and scan_demo_surfaces((("preflight-smoke.html", encoded),)).pass_all
        )
    except (ImportError, OSError, RuntimeError, TypeError, ValueError):
        return False


def run_preflight(*, profile: PreflightProfile, output_root: str) -> PreflightResult:
    """Run the selected closed local profile and return no environment detail."""

    if type(profile) is not PreflightProfile:
        raise TypeError("preflight profile requires PreflightProfile")
    root = _repository_root()
    revision = _clean_revision(root)
    checks = [
        PreflightCheck(
            PreflightCheckCode.PYTHON_FLOOR,
            sys.version_info[:2] >= MINIMUM_PYTHON,
        ),
        PreflightCheck(
            PreflightCheckCode.PACKAGE_DEPENDENCIES,
            _package_dependencies_ready(),
        ),
        PreflightCheck(
            PreflightCheckCode.REPOSITORY_LAYOUT,
            _repository_layout_ready(root),
        ),
        PreflightCheck(
            PreflightCheckCode.REPOSITORY_PROVENANCE,
            revision is not None,
        ),
        PreflightCheck(
            PreflightCheckCode.OUTPUT_ROOT,
            _output_root_ready(output_root),
        ),
        PreflightCheck(
            PreflightCheckCode.PUBLICATION_HELPERS,
            _publication_helpers_ready(),
        ),
    ]
    if profile is PreflightProfile.CAPTURE:
        checks.extend(
            (
                PreflightCheck(
                    PreflightCheckCode.CAPTURE_PROOFS,
                    _capture_proofs_ready(root),
                ),
                PreflightCheck(
                    PreflightCheckCode.CAPTURE_PROJECTIONS,
                    _capture_projections_ready(),
                ),
                PreflightCheck(
                    PreflightCheckCode.CAPTURE_UI_SMOKE,
                    _capture_ui_smoke_ready(),
                ),
                PreflightCheck(
                    PreflightCheckCode.NO_ARTIFACTS_CREATED,
                    _output_root_is_empty(output_root),
                ),
            )
        )
    passed = all(item.passed for item in checks)
    provenance = (
        RepositoryProvenance._verified(revision, root)
        if passed and revision is not None
        else None
    )
    return PreflightResult(
        profile=profile,
        local_readiness=LocalReadiness.PASS if passed else LocalReadiness.FAIL,
        live_gate_state=LiveGateState.NOT_EVALUATED,
        checks=tuple(checks),
        repository_provenance=provenance,
    )


def _output_root_is_empty(value: str) -> bool:
    try:
        root = Path(value)
        return root.is_dir() and not root.is_symlink() and not any(root.iterdir())
    except (OSError, TypeError, ValueError):
        return False


def recheck_repository_provenance(
    provenance: Optional[RepositoryProvenance],
) -> bool:
    """Confirm the exact attested repository is still at the same clean HEAD."""

    if (
        type(provenance) is not RepositoryProvenance
        or provenance._attestation is not _ATTESTATION
    ):
        return False
    revision = _clean_revision(provenance._root)
    return revision is not None and revision == provenance.source_revision


__all__ = (
    "LiveGateState",
    "LocalReadiness",
    "MINIMUM_PYTHON",
    "PYTEST_VERSION",
    "PreflightCheck",
    "PreflightCheckCode",
    "PreflightProfile",
    "PreflightResult",
    "RepositoryProvenance",
    "TIDEMARK_VERSION",
    "recheck_repository_provenance",
    "run_preflight",
)
