import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from tidemark.demo import preflight as preflight_module
from tidemark.demo.manifest import (
    RUN_MANIFEST_SCHEMA_VERSION,
    ManifestPresentationMode,
    RunManifestError,
    RunMode,
    build_run_manifest,
    serialize_run_manifest,
    verify_materialized_run_manifest,
    verify_run_manifest,
)
from tidemark.demo.preflight import PreflightProfile, run_preflight
from tidemark.demo.rehearsal import DemoRehearsalArtifact


def _git(repo: Path, *arguments: str) -> str:
    return subprocess.run(
        ("git", "-C", str(repo), *arguments),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _provenance(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repository"
    for relative in (
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
    ):
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("fixture\n")
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "TIDEMARK Test")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "fixture")
    output = tmp_path / "output"
    output.mkdir()
    monkeypatch.setattr(preflight_module, "_repository_root", lambda: repo)
    monkeypatch.setattr(
        preflight_module,
        "_executing_package_root",
        lambda: repo / "src" / "tidemark",
    )
    result = run_preflight(
        profile=PreflightProfile.REPRODUCTION,
        output_root=str(output),
    )
    assert result.repository_provenance is not None
    return repo, result.repository_provenance


def _artifacts(*, sensitive: bytes = b""):
    names = (
        "index.html",
        "decision-review-benign.html",
        "decision-review-raw.html",
        "decision-review-forged.html",
        "decision-review-bound.html",
        "decision-review-replay.html",
        "decision-review-non-attempt.html",
        "demo-rehearsal-report.json",
    )
    return tuple(
        DemoRehearsalArtifact(
            name,
            "application/json" if name.endswith(".json") else "text/html",
            (b"{}\n" if name.endswith(".json") else b"<!doctype html>safe")
            + (sensitive if index == 0 else b""),
        )
        for index, name in enumerate(names)
    )


def _manifest(provenance, artifacts=None, mode=RunMode.STANDARD):
    artifacts = artifacts or _artifacts()
    return build_run_manifest(
        repository_provenance=provenance,
        run_mode=mode,
        presentation_mode=(
            ManifestPresentationMode.NORMAL
            if mode is RunMode.STANDARD
            else ManifestPresentationMode.VIDEO_SAFE
        ),
        artifacts=artifacts,
        fresh_run_count=2 if mode is RunMode.STANDARD else 3,
        scenario_count=6,
        capture_schema=(
            None
            if mode is RunMode.STANDARD
            else "tidemark.demo.capture-rehearsal.v1"
        ),
    )


def test_manifest_is_canonical_stable_self_digesting_and_source_bound(
    tmp_path, monkeypatch
):
    repo, provenance = _provenance(tmp_path, monkeypatch)
    artifacts = _artifacts()
    manifest = _manifest(provenance, artifacts)
    encoded = serialize_run_manifest(manifest)

    assert encoded.endswith(b"\n") and not encoded.endswith(b"\n\n")
    assert json.dumps(
        json.loads(encoded), ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode() + b"\n" == encoded
    assert manifest.schema_version == RUN_MANIFEST_SCHEMA_VERSION
    assert manifest.software.source_revision == _git(repo, "rev-parse", "HEAD")
    assert serialize_run_manifest(_manifest(provenance, artifacts)) == encoded
    assert verify_run_manifest(encoded, artifacts) == manifest


@pytest.mark.parametrize("mode", tuple(RunMode))
def test_all_modes_require_unchanged_clean_repository_provenance(
    tmp_path, monkeypatch, mode
):
    repo, provenance = _provenance(tmp_path, monkeypatch)
    (repo / "untracked.txt").write_text("post-preflight dirt\n")

    with pytest.raises(RunManifestError):
        _manifest(provenance, mode=mode)


def test_manifest_rejects_artifact_mutation_noncanonical_json_and_unknown_fields(
    tmp_path, monkeypatch
):
    _, provenance = _provenance(tmp_path, monkeypatch)
    artifacts = _artifacts()
    encoded = serialize_run_manifest(_manifest(provenance, artifacts))
    mutated = (replace(artifacts[0], content=b"changed"), *artifacts[1:])

    with pytest.raises(RunManifestError):
        verify_run_manifest(encoded, tuple(mutated))
    with pytest.raises(RunManifestError):
        verify_run_manifest(b" " + encoded, artifacts)
    primitive = json.loads(encoded)
    primitive["unexpected"] = True
    with pytest.raises(RunManifestError):
        verify_run_manifest(json.dumps(primitive).encode() + b"\n", artifacts)


@pytest.mark.parametrize(
    "payload",
    (
        b"GEMINI_API_KEY=do-not-publish",
        b"synthetic-routing://beneficiary/private",
        b"raw_provider_output=private",
        b"RuntimePrivateExecutionBinding",
        b"/Users/operator/private/demo.json",
    ),
)
def test_manifest_rejects_every_shared_sensitive_surface_category(
    tmp_path, monkeypatch, payload
):
    _, provenance = _provenance(tmp_path, monkeypatch)

    with pytest.raises(RunManifestError):
        _manifest(provenance, _artifacts(sensitive=payload))


@pytest.mark.parametrize(
    "unsafe_name",
    ("../escape.html", "nested/file.html", "/absolute.html", "C:\\escape.html"),
)
def test_artifact_logical_names_are_safe_leaves(tmp_path, monkeypatch, unsafe_name):
    _, provenance = _provenance(tmp_path, monkeypatch)
    artifacts = list(_artifacts())

    with pytest.raises((ValueError, RunManifestError)):
        artifacts[0] = DemoRehearsalArtifact(unsafe_name, "text/html", b"safe")


def test_materialized_verifier_requires_exact_file_set(tmp_path, monkeypatch):
    _, provenance = _provenance(tmp_path, monkeypatch)
    artifacts = _artifacts()
    manifest = _manifest(provenance, artifacts)
    root = tmp_path / "materialized"
    root.mkdir()
    for artifact in artifacts:
        (root / artifact.name).write_bytes(artifact.content)
    (root / "run-manifest.json").write_bytes(serialize_run_manifest(manifest))

    assert verify_materialized_run_manifest(str(root)) == manifest
    (root / "extra.txt").write_text("unlisted\n")
    with pytest.raises(RunManifestError):
        verify_materialized_run_manifest(str(root))
