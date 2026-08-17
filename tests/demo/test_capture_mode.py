import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from tidemark.demo import capture as capture_module
from tidemark.demo import preflight as preflight_module
from tidemark.demo.capture import (
    CAPTURE_RUN_COUNT,
    CAPTURE_REHEARSAL_SCHEMA_VERSION,
    CaptureFailureCode,
    CaptureProfile,
    CaptureRehearsalError,
    run_capture_rehearsal,
)
from tidemark.demo.harness import DeterministicDemoHarness as RealHarness
from tidemark.demo.manifest import RunMode, verify_materialized_run_manifest
from tidemark.demo.rehearsal import scan_demo_surfaces


def _git(repo: Path, *arguments: str) -> None:
    subprocess.run(
        ("git", "-C", str(repo), *arguments),
        check=True,
        capture_output=True,
        text=True,
    )


def _clean_repository(tmp_path: Path, monkeypatch) -> Path:
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
    monkeypatch.setattr(preflight_module, "_repository_root", lambda: repo)
    monkeypatch.setattr(
        preflight_module,
        "_executing_package_root",
        lambda: repo / "src" / "tidemark",
    )
    return repo


def _output(tmp_path: Path) -> Path:
    output = tmp_path / "output"
    output.mkdir()
    return output


def test_capture_executes_exactly_three_fresh_runs_and_materializes_complete_set(
    tmp_path, monkeypatch
):
    _clean_repository(tmp_path, monkeypatch)
    output = _output(tmp_path)
    instances = []

    class CountingHarness:
        def __init__(self, **kwargs):
            self.delegate = RealHarness(**kwargs)
            instances.append(self)

        def run(self):
            return self.delegate.run()

    monkeypatch.setattr(capture_module, "DeterministicDemoHarness", CountingHarness)
    result = run_capture_rehearsal(
        profile=CaptureProfile.CAPTURE,
        output_root=str(output),
    )

    assert CAPTURE_RUN_COUNT == 3
    assert len(instances) == 3
    assert result.summary.run_count == 3
    assert result.summary.semantic_equality is True
    assert result.summary.surface_scan_pass is True
    assert result.summary.schema_version == CAPTURE_REHEARSAL_SCHEMA_VERSION
    assert result.manifest.run_mode is RunMode.CAPTURE
    assert tuple(path.name for path in output.iterdir()) == ("artifacts",)
    materialized = output / "artifacts"
    assert verify_materialized_run_manifest(str(materialized)) == result.manifest
    report = json.loads((materialized / "demo-rehearsal-report.json").read_text())
    manifest = json.loads((materialized / "run-manifest.json").read_text())
    assert report["artifact_names"] == [
        item["logical_name"] for item in manifest["artifacts"]
    ]
    assert (materialized / "index.html").is_file()
    assert (materialized / "capture-rehearsal-summary.json").is_file()
    assert len(tuple(materialized.glob("decision-review-*.html"))) == 6
    assert len(tuple(materialized.iterdir())) == 10
    assert scan_demo_surfaces(
        tuple((path.name, path.read_bytes()) for path in materialized.iterdir())
    ).pass_all


@pytest.mark.parametrize("profile", tuple(CaptureProfile))
def test_capture_profiles_publish_real_measurements_not_fabricated_zero_samples(
    tmp_path, monkeypatch, profile
):
    _clean_repository(tmp_path, monkeypatch)
    output = _output(tmp_path)

    run_capture_rehearsal(profile=profile, output_root=str(output))

    report = json.loads(
        (output / "artifacts" / "demo-rehearsal-report.json").read_text()
    )
    for statistic in report["timings"].values():
        assert statistic["sample_count"] == CAPTURE_RUN_COUNT
        assert 0.0 <= statistic["minimum"] <= statistic["median"]
        assert statistic["median"] <= statistic["maximum"] < 60.0
        assert statistic["maximum"] > 0.0


def test_meaningful_second_run_difference_fails_immediately_without_third_or_artifacts(
    tmp_path, monkeypatch
):
    _clean_repository(tmp_path, monkeypatch)
    output = _output(tmp_path)
    calls = 0

    class DifferingHarness:
        def __init__(self, **kwargs):
            self.delegate = RealHarness(**kwargs)

        def run(self):
            nonlocal calls
            calls += 1
            run = self.delegate.run()
            if calls == 2:
                changed = replace(run.summary, provenance_summary="meaningful difference")
                return replace(run, summary=changed)
            return run

    monkeypatch.setattr(capture_module, "DeterministicDemoHarness", DifferingHarness)

    with pytest.raises(CaptureRehearsalError) as caught:
        run_capture_rehearsal(
            profile=CaptureProfile.CAPTURE,
            output_root=str(output),
        )

    assert caught.value.code is CaptureFailureCode.SEMANTIC_MISMATCH
    assert caught.value.run_ordinal == 2
    assert calls == 2
    assert tuple(output.iterdir()) == ()
    assert "meaningful difference" not in str(caught.value)


def test_legitimate_identity_time_and_derived_digest_variation_compares_equal(
    tmp_path, monkeypatch
):
    _clean_repository(tmp_path, monkeypatch)
    result = run_capture_rehearsal(
        profile=CaptureProfile.CAPTURE,
        output_root=str(_output(tmp_path)),
    )

    assert result.summary.semantic_equality is True
    assert result.summary.semantic_snapshot_digest.startswith("sha256:")
    assert len(result.summary.semantic_snapshot_digest) == 71


def test_failure_before_rename_removes_only_process_owned_staging(
    tmp_path, monkeypatch
):
    _clean_repository(tmp_path, monkeypatch)
    output = _output(tmp_path)

    def fail_manifest(**kwargs):
        raise RuntimeError("private manifest detail")

    monkeypatch.setattr(capture_module, "build_run_manifest", fail_manifest)

    with pytest.raises(CaptureRehearsalError) as caught:
        run_capture_rehearsal(
            profile=CaptureProfile.CAPTURE,
            output_root=str(output),
        )

    assert caught.value.code is CaptureFailureCode.MANIFEST_FAILED
    assert tuple(output.iterdir()) == ()
    assert "private manifest detail" not in str(caught.value)


def test_failure_to_cleanup_process_owned_staging_is_explicit(
    tmp_path, monkeypatch
):
    _clean_repository(tmp_path, monkeypatch)
    output = _output(tmp_path)

    monkeypatch.setattr(
        capture_module,
        "verify_materialized_run_manifest",
        lambda root: (_ for _ in ()).throw(RuntimeError("verification failed")),
    )
    original_rmtree = capture_module.shutil.rmtree

    def fail_capture_cleanup(root, *args, **kwargs):
        if Path(root).name.startswith(".tidemark-capture-"):
            raise OSError("cleanup failed")
        return original_rmtree(root, *args, **kwargs)

    monkeypatch.setattr(capture_module.shutil, "rmtree", fail_capture_cleanup)

    with pytest.raises(CaptureRehearsalError) as caught:
        run_capture_rehearsal(
            profile=CaptureProfile.CAPTURE,
            output_root=str(output),
        )

    assert caught.value.code is CaptureFailureCode.STAGING_CLEANUP_FAILED
    assert not (output / "artifacts").exists()
    assert "cleanup failed" not in str(caught.value)


def test_dirty_preflight_runs_no_harness_and_emits_no_artifact(tmp_path, monkeypatch):
    repo = _clean_repository(tmp_path, monkeypatch)
    output = _output(tmp_path)
    (repo / "untracked.txt").write_text("dirt\n")
    calls = 0

    class ForbiddenHarness:
        def __init__(self, **kwargs):
            nonlocal calls
            calls += 1

        def run(self):
            raise AssertionError("dirty preflight reached harness")

    monkeypatch.setattr(capture_module, "DeterministicDemoHarness", ForbiddenHarness)

    with pytest.raises(CaptureRehearsalError) as caught:
        run_capture_rehearsal(
            profile=CaptureProfile.CAPTURE,
            output_root=str(output),
        )

    assert caught.value.code is CaptureFailureCode.PREFLIGHT_FAILED
    assert calls == 0
    assert tuple(output.iterdir()) == ()


def test_deterministic_fallback_is_explicit_in_summary_manifest_and_ui(
    tmp_path, monkeypatch
):
    _clean_repository(tmp_path, monkeypatch)
    output = _output(tmp_path)
    result = run_capture_rehearsal(
        profile=CaptureProfile.DETERMINISTIC_FALLBACK,
        output_root=str(output),
    )
    root = output / "artifacts"
    summary = json.loads((root / "capture-rehearsal-summary.json").read_text())
    manifest = json.loads((root / "run-manifest.json").read_text())
    html = (root / "index.html").read_text()

    assert result.manifest.run_mode is RunMode.DETERMINISTIC_FALLBACK
    assert summary["profile"] == "DETERMINISTIC_FALLBACK"
    assert summary["provenance_class"] == (
        "DETERMINISTIC_OFFLINE_NOT_CURRENT_LIVE_PROVIDER_OUTPUT"
    )
    assert manifest["run_mode"] == "DETERMINISTIC_FALLBACK"
    assert manifest["provenance_class"] == summary["provenance_class"]
    assert (
        "DETERMINISTIC · EVIDENCE FALLBACK / OFFLINE · "
        "NOT CURRENT LIVE PROVIDER OUTPUT"
    ) in html
    assert "HISTORICAL LIVE MODEL PROVENANCE" in html
    assert "not current offline run" in html
    assert summary["provider_requests_performed"] is False
    assert summary["network_requests_performed"] is False
    assert summary["google_cloud_used"] is False
