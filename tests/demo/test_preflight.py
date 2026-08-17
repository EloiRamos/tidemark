import builtins
import os
import subprocess
from pathlib import Path

import pytest

from tidemark.demo import preflight as preflight_module
from tidemark.demo.preflight import (
    LiveGateState,
    LocalReadiness,
    PreflightCheckCode,
    PreflightProfile,
    recheck_repository_provenance,
    run_preflight,
)


def _git(repo: Path, *arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ("git", "-C", str(repo), *arguments),
        check=True,
        capture_output=True,
        text=True,
    )


def _repository(tmp_path: Path, *, commit: bool = True) -> Path:
    repo = tmp_path / "repository"
    required = (
        "Makefile",
        "pyproject.toml",
        "scripts/run_demo_rehearsal.py",
        "src/tidemark/demo/preflight.py",
        "src/tidemark/demo/manifest.py",
        "src/tidemark/demo/capture.py",
        "src/tidemark/demo/rehearsal.py",
        "src/tidemark/ui/final_ui.py",
        "docs/evidence/ORDER_12_LIVE_MODEL_PROOF_v1.0.md",
        "docs/evidence/ORDER_21_CLOUD_DEPLOYMENT_PROOF_v1.0.md",
    )
    repo.mkdir()
    for relative in required:
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("fixture\n")
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "TIDEMARK Test")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "add", ".")
    if commit:
        _git(repo, "commit", "-qm", "fixture")
    return repo


def _output(tmp_path: Path) -> Path:
    output = tmp_path / "output"
    output.mkdir()
    return output


def _run(monkeypatch, repo: Path, output: Path, profile=PreflightProfile.REPRODUCTION):
    monkeypatch.setattr(preflight_module, "_repository_root", lambda: repo)
    monkeypatch.setattr(
        preflight_module,
        "_executing_package_root",
        lambda: repo / "src" / "tidemark",
        raising=False,
    )
    return run_preflight(profile=profile, output_root=str(output))


@pytest.mark.parametrize("profile", tuple(PreflightProfile))
def test_clean_committed_preflight_passes_with_closed_content_free_diagnostics(
    tmp_path, monkeypatch, profile
):
    repo = _repository(tmp_path)
    output = _output(tmp_path)

    result = _run(monkeypatch, repo, output, profile)

    assert result.local_readiness is LocalReadiness.PASS
    assert result.live_gate_state is LiveGateState.NOT_EVALUATED
    assert result.repository_provenance is not None
    assert result.repository_provenance.source_revision == _git(
        repo, "rev-parse", "HEAD"
    ).stdout.strip()
    assert tuple(check.code for check in result.checks) == tuple(
        sorted((check.code for check in result.checks), key=lambda item: item.value)
    )
    assert all(check.passed for check in result.checks)
    assert tuple(output.iterdir()) == ()
    diagnostics = "\n".join(result.diagnostic_lines())
    assert str(repo) not in diagnostics
    assert str(output) not in diagnostics
    assert "example.invalid" not in diagnostics
    assert "LIVE_GATE_STATE=NOT_EVALUATED" in diagnostics
    assert "LIVE_MODEL_CALLS_PERFORMED=0" in diagnostics
    assert "GOOGLE_CLOUD_ACCESSED=false" in diagnostics


@pytest.mark.parametrize("dirt", ("tracked", "untracked"))
@pytest.mark.parametrize("profile", tuple(PreflightProfile))
def test_preflight_rejects_tracked_and_untracked_dirt(
    tmp_path, monkeypatch, dirt, profile
):
    repo = _repository(tmp_path)
    output = _output(tmp_path)
    if dirt == "tracked":
        (repo / "Makefile").write_text("changed\n")
    else:
        (repo / "untracked-secret-free.txt").write_text("dirt\n")

    result = _run(monkeypatch, repo, output, profile)

    assert result.local_readiness is LocalReadiness.FAIL
    assert result.repository_provenance is None
    assert PreflightCheckCode.REPOSITORY_PROVENANCE in result.failed_codes
    assert tuple(output.iterdir()) == ()


def test_preflight_rejects_repository_without_commit(tmp_path, monkeypatch):
    repo = _repository(tmp_path, commit=False)
    result = _run(monkeypatch, repo, _output(tmp_path))

    assert result.local_readiness is LocalReadiness.FAIL
    assert result.repository_provenance is None
    assert PreflightCheckCode.REPOSITORY_PROVENANCE in result.failed_codes


def test_preflight_rejects_unsupported_python_floor(tmp_path, monkeypatch):
    repo = _repository(tmp_path)
    monkeypatch.setattr(preflight_module.sys, "version_info", (3, 8, 20))

    result = _run(monkeypatch, repo, _output(tmp_path))

    assert result.local_readiness is LocalReadiness.FAIL
    assert PreflightCheckCode.PYTHON_FLOOR in result.failed_codes


@pytest.mark.parametrize(
    "failure",
    ("missing-tidemark", "missing-pytest", "wrong-pytest-version"),
)
def test_preflight_rejects_missing_or_wrong_test_dependency(
    tmp_path, monkeypatch, failure
):
    repo = _repository(tmp_path)
    original_import = builtins.__import__

    def package_import(name, *args, **kwargs):
        if failure == "missing-tidemark" and name == "tidemark":
            raise ImportError("tidemark unavailable")
        return original_import(name, *args, **kwargs)

    def version(name):
        assert name == "pytest"
        if failure == "missing-pytest":
            raise preflight_module.metadata.PackageNotFoundError(name)
        return "0.0.0"

    monkeypatch.setattr(builtins, "__import__", package_import)
    monkeypatch.setattr(preflight_module.metadata, "version", version)
    result = _run(monkeypatch, repo, _output(tmp_path))

    assert result.local_readiness is LocalReadiness.FAIL
    assert PreflightCheckCode.PACKAGE_DEPENDENCIES in result.failed_codes


def test_preflight_rejects_wrong_repository_layout(tmp_path, monkeypatch):
    repo = _repository(tmp_path)
    (repo / "Makefile").unlink()

    result = _run(monkeypatch, repo, _output(tmp_path))

    assert result.local_readiness is LocalReadiness.FAIL
    assert PreflightCheckCode.REPOSITORY_LAYOUT in result.failed_codes


def test_preflight_rejects_repository_not_containing_executing_package(
    tmp_path, monkeypatch
):
    repo = _repository(tmp_path)
    monkeypatch.setattr(preflight_module, "_repository_root", lambda: repo)
    monkeypatch.setattr(
        preflight_module,
        "_executing_package_root",
        lambda: tmp_path / "other" / "src" / "tidemark",
        raising=False,
    )

    result = run_preflight(
        profile=PreflightProfile.REPRODUCTION,
        output_root=str(_output(tmp_path)),
    )

    assert result.local_readiness is LocalReadiness.FAIL
    assert PreflightCheckCode.REPOSITORY_LAYOUT in result.failed_codes


def test_post_preflight_recheck_rejects_changed_head(tmp_path, monkeypatch):
    repo = _repository(tmp_path)
    result = _run(monkeypatch, repo, _output(tmp_path))
    (repo / "later.txt").write_text("new committed source\n")
    _git(repo, "add", "later.txt")
    _git(repo, "commit", "-qm", "later")

    assert recheck_repository_provenance(result.repository_provenance) is False


def test_post_preflight_recheck_rejects_worktree_mutation(tmp_path, monkeypatch):
    repo = _repository(tmp_path)
    result = _run(monkeypatch, repo, _output(tmp_path))
    (repo / "later.txt").write_text("untracked mutation\n")

    assert recheck_repository_provenance(result.repository_provenance) is False


def test_reproduction_preflight_never_imports_or_version_checks_google_adk(
    tmp_path, monkeypatch
):
    repo = _repository(tmp_path)
    output = _output(tmp_path)
    original_version = preflight_module.metadata.version

    def blocked_version(name):
        if name in {"google-adk", "google_adk"}:
            raise AssertionError("generic reproduction inspected Google ADK")
        return original_version(name)

    monkeypatch.setattr(preflight_module.metadata, "version", blocked_version)
    result = _run(monkeypatch, repo, output)

    assert result.local_readiness is LocalReadiness.PASS


def test_reproduction_preflight_passes_when_google_adk_import_is_blocked(
    tmp_path, monkeypatch
):
    repo = _repository(tmp_path)
    output = _output(tmp_path)
    original_import = builtins.__import__
    original_version = preflight_module.metadata.version

    def blocked_import(name, *args, **kwargs):
        if name == "google" or name.startswith("google."):
            raise ImportError("Google ADK unavailable")
        return original_import(name, *args, **kwargs)

    def blocked_version(name):
        if name in {"google-adk", "google_adk"}:
            raise preflight_module.metadata.PackageNotFoundError(name)
        return original_version(name)

    monkeypatch.setattr(builtins, "__import__", blocked_import)
    monkeypatch.setattr(preflight_module.metadata, "version", blocked_version)

    result = _run(monkeypatch, repo, output)

    assert result.local_readiness is LocalReadiness.PASS


@pytest.mark.parametrize("case", ("nonempty", "symlink", "missing"))
def test_preflight_rejects_invalid_output_root_without_disclosing_it(
    tmp_path, monkeypatch, case
):
    repo = _repository(tmp_path)
    output = tmp_path / "output"
    if case == "nonempty":
        output.mkdir()
        (output / "preserve.txt").write_text("preserve\n")
    elif case == "symlink":
        target = tmp_path / "target"
        target.mkdir()
        output.symlink_to(target, target_is_directory=True)

    result = _run(monkeypatch, repo, output)

    assert result.local_readiness is LocalReadiness.FAIL
    assert PreflightCheckCode.OUTPUT_ROOT in result.failed_codes
    assert str(output) not in "\n".join(result.diagnostic_lines())


def test_preflight_rejects_unwritable_output_root(tmp_path, monkeypatch):
    repo = _repository(tmp_path)
    output = _output(tmp_path)
    original_open = preflight_module.os.open

    def denied_open(path, flags, mode=0o777):
        if path == str(output / ".tidemark-preflight-sentinel"):
            raise PermissionError("fixture is unwritable")
        return original_open(path, flags, mode)

    monkeypatch.setattr(preflight_module.os, "open", denied_open)
    result = _run(monkeypatch, repo, output)

    assert result.local_readiness is LocalReadiness.FAIL
    assert PreflightCheckCode.OUTPUT_ROOT in result.failed_codes


@pytest.mark.parametrize("proof_state", ("missing", "untracked"))
def test_capture_preflight_rejects_missing_or_untracked_required_proof(
    tmp_path, monkeypatch, proof_state
):
    repo = _repository(tmp_path)
    proof = repo / "docs" / "evidence" / "ORDER_12_LIVE_MODEL_PROOF_v1.0.md"
    if proof_state == "missing":
        proof.unlink()
    else:
        _git(repo, "rm", "--cached", str(proof.relative_to(repo)))

    result = _run(
        monkeypatch,
        repo,
        _output(tmp_path),
        PreflightProfile.CAPTURE,
    )

    assert result.local_readiness is LocalReadiness.FAIL
    assert PreflightCheckCode.CAPTURE_PROOFS in result.failed_codes


def test_capture_preflight_rejects_ui_smoke_failure(tmp_path, monkeypatch):
    repo = _repository(tmp_path)

    class FailingHarness:
        def __init__(self, **kwargs):
            pass

        def run(self):
            raise RuntimeError("smoke failed")

    monkeypatch.setattr(
        "tidemark.demo.harness.DeterministicDemoHarness",
        FailingHarness,
    )
    result = _run(
        monkeypatch,
        repo,
        _output(tmp_path),
        PreflightProfile.CAPTURE,
    )

    assert result.local_readiness is LocalReadiness.FAIL
    assert PreflightCheckCode.CAPTURE_UI_SMOKE in result.failed_codes


def test_preflight_self_test_failure_is_closed_and_content_free(tmp_path, monkeypatch):
    repo = _repository(tmp_path)
    output = _output(tmp_path)
    monkeypatch.setattr(
        preflight_module,
        "canonical_json_bytes",
        lambda value, **kwargs: (_ for _ in ()).throw(RuntimeError("private detail")),
    )

    result = _run(monkeypatch, repo, output)

    assert result.local_readiness is LocalReadiness.FAIL
    assert PreflightCheckCode.PUBLICATION_HELPERS in result.failed_codes
    assert "private detail" not in "\n".join(result.diagnostic_lines())
