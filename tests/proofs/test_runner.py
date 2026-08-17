import ast
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import os
import subprocess
import sys

import pytest

from tidemark.demo.preflight import LocalReadiness
from tidemark.proofs.model import (
    PROOF_SUITE_SCHEMA,
    ProofInfrastructureErrorCode,
    ProofRunOutcome,
    ProofStatus,
    parse_proof_suite,
)
from tidemark.proofs import runner as proof_runner


ROOT = Path(__file__).resolve().parents[2]
REVISION = "a" * 40
ARTIFACT = "security-proof-suite.json"
VERIFY_RECIPE = (
    "verify:\n"
    "\t@PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src $(PYTHON) -m pytest "
    "-p no:cacheprovider -q tests/demo/test_preflight.py "
    "tests/demo/test_run_manifest.py tests/demo/test_capture_mode.py "
    "tests/demo/test_demo_hardening.py tests/ui/test_video_safe_mode.py "
    "tests/ui/test_final_ui_integration.py\n"
)


def _passing_preflight(*, profile, output_root):
    return SimpleNamespace(
        local_readiness=LocalReadiness.PASS,
        repository_provenance=SimpleNamespace(source_revision=REVISION),
    )


@pytest.fixture
def clean_provenance(monkeypatch):
    monkeypatch.setattr(proof_runner, "run_preflight", _passing_preflight)
    monkeypatch.setattr(
        proof_runner,
        "recheck_repository_provenance",
        lambda provenance: True,
    )


def test_all_properties_complete_pass_in_catalogue_order(clean_provenance):
    run = proof_runner.run_security_proofs()

    assert run.outcome is ProofRunOutcome.COMPLETED
    assert run.suite_result.suite_status is ProofStatus.PASS
    assert run.suite_result.executed_property_count == 8
    assert run.suite_result.selection == tuple(
        f"W2-P{index:02d}" for index in range(1, 9)
    )
    transcript = proof_runner.render_proof_run(run)
    assert transcript.startswith(
        f"PROOF_SUITE_SCHEMA={PROOF_SUITE_SCHEMA}\n".encode()
    )
    assert transcript.count(b"PROPERTY=W2-P") == 8
    assert b"SUITE_STATUS=PASS\n" in transcript
    assert b"EXECUTED_PROPERTY_COUNT=8\n" in transcript
    assert b"LIVE_MODEL_CALLS_PERFORMED=0\n" in transcript
    assert b"GOOGLE_CLOUD_ACCESSED=false\n" in transcript


def test_exact_single_property_pass_runs_only_its_fixture(
    clean_provenance, monkeypatch
):
    calls = []
    original = proof_runner.execute_proof_fixture

    def record(fixture_id, workspace_root):
        calls.append(fixture_id)
        return original(fixture_id, workspace_root)

    monkeypatch.setattr(proof_runner, "execute_proof_fixture", record)
    run = proof_runner.run_security_proofs(property_id="W2-P05")

    assert run.outcome is ProofRunOutcome.COMPLETED
    assert run.suite_result.suite_status is ProofStatus.PASS
    assert run.suite_result.selection == ("W2-P05",)
    assert calls == ["W2-P05-C01-concurrent-replay"]


def test_unknown_selection_is_error_before_preflight_or_fixtures(monkeypatch):
    calls = []
    monkeypatch.setattr(
        proof_runner,
        "run_preflight",
        lambda **kwargs: calls.append("preflight"),
    )
    monkeypatch.setattr(
        proof_runner,
        "execute_proof_fixture",
        lambda *args: calls.append("fixture"),
    )

    run = proof_runner.run_security_proofs(property_id="W2-P99")

    assert calls == []
    assert run.outcome is ProofRunOutcome.ERROR
    assert run.suite_result is None
    assert run.infrastructure_error is ProofInfrastructureErrorCode.SELECTION_INVALID
    transcript = proof_runner.render_proof_run(run)
    assert transcript == (
        b"PROOF_RUN_STATUS=ERROR\n"
        b"PROOF_INFRASTRUCTURE_ERROR=proof.selection_invalid.v1\n"
        b"PROPERTY_RESULTS_EMITTED=0\n"
        b"LIVE_MODEL_CALLS_PERFORMED=0\n"
        b"GOOGLE_CLOUD_ACCESSED=false\n"
    )


def test_complete_invariant_mismatch_is_completed_fail_and_exit_one(
    clean_provenance, monkeypatch
):
    original = proof_runner.execute_proof_fixture

    def mismatch(fixture_id, workspace_root):
        observed = original(fixture_id, workspace_root)
        if fixture_id == "W2-P04-C01-sequential-replay":
            return replace(observed, adapter_entry_count=2)
        return observed

    monkeypatch.setattr(proof_runner, "execute_proof_fixture", mismatch)
    run = proof_runner.run_security_proofs(property_id="W2-P04")

    assert run.outcome is ProofRunOutcome.COMPLETED
    assert run.suite_result.suite_status is ProofStatus.FAIL
    assert proof_runner.proof_exit_code(run) == 1
    assert b"SUITE_STATUS=FAIL\n" in proof_runner.render_proof_run(run)


def test_fixture_exception_is_error_two_without_pass_fail_or_exception_text(
    clean_provenance, monkeypatch, tmp_path
):
    secret = str(tmp_path / "private-exception-path")

    def fail(*args):
        raise RuntimeError(secret)

    monkeypatch.setattr(proof_runner, "execute_proof_fixture", fail)
    run = proof_runner.run_security_proofs(property_id="W2-P01")
    transcript = proof_runner.render_proof_run(run)

    assert run.infrastructure_error is ProofInfrastructureErrorCode.EXECUTION_ERROR
    assert proof_runner.proof_exit_code(run) == 2
    assert b"PROPERTY=" not in transcript
    assert b"SUITE_STATUS=" not in transcript
    assert secret.encode() not in transcript


def test_dirty_tree_is_rejected_by_real_phase_one_preflight(tmp_path):
    checkout = tmp_path / "dirty-checkout"
    cloned = subprocess.run(
        ("git", "clone", "--no-local", str(ROOT), str(checkout)),
        check=False,
        capture_output=True,
    )
    assert cloned.returncode == 0
    (checkout / "w2-dirty-marker.txt").write_text("dirty\n", encoding="utf-8")

    completed = subprocess.run(
        (sys.executable, "scripts/run_security_proofs.py", "--property", "W2-P05"),
        cwd=checkout,
        env={**os.environ, "PYTHONPATH": "src", "PYTHONDONTWRITEBYTECODE": "1"},
        check=False,
        capture_output=True,
    )

    assert completed.returncode == 2
    assert completed.stderr == b""
    assert completed.stdout == proof_runner.render_error(
        ProofInfrastructureErrorCode.PREFLIGHT_FAILED
    )


def test_clean_candidate_preflight_allows_runner(clean_provenance):
    run = proof_runner.run_security_proofs(property_id="W2-P01")

    assert run.outcome is ProofRunOutcome.COMPLETED
    assert run.suite_result.provenance.source_revision == REVISION


def test_post_proof_source_mutation_is_provenance_error_and_writes_no_artifact(
    clean_provenance, monkeypatch, tmp_path
):
    monkeypatch.setattr(
        proof_runner,
        "recheck_repository_provenance",
        lambda provenance: False,
    )

    run = proof_runner.run_security_proofs(output_dir=tmp_path)

    assert run.infrastructure_error is ProofInfrastructureErrorCode.PROVENANCE_FAILED
    assert not (tmp_path / ARTIFACT).exists()


@pytest.mark.parametrize("kind", ("nonempty", "symlink", "target"))
def test_invalid_output_directory_is_rejected_without_overwrite(
    clean_provenance, tmp_path, kind
):
    output = tmp_path / "output"
    output.mkdir()
    if kind == "nonempty":
        (output / "unrelated.txt").write_text("preserve", encoding="utf-8")
    elif kind == "target":
        (output / ARTIFACT).write_text("preserve", encoding="utf-8")
    else:
        real = tmp_path / "real"
        real.mkdir()
        output.rmdir()
        output.symlink_to(real, target_is_directory=True)

    run = proof_runner.run_security_proofs(output_dir=output)

    assert run.outcome is ProofRunOutcome.ERROR
    assert run.infrastructure_error is ProofInfrastructureErrorCode.PREFLIGHT_FAILED
    if kind == "target":
        assert (output / ARTIFACT).read_text(encoding="utf-8") == "preserve"


def test_completed_fail_may_materialize_verified_artifact(
    clean_provenance, monkeypatch, tmp_path
):
    original = proof_runner.execute_proof_fixture

    def mismatch(fixture_id, workspace_root):
        observed = original(fixture_id, workspace_root)
        return replace(observed, adapter_entry_count=2)

    monkeypatch.setattr(proof_runner, "execute_proof_fixture", mismatch)

    run = proof_runner.run_security_proofs(
        property_id="W2-P04", output_dir=tmp_path
    )
    parsed = parse_proof_suite((tmp_path / ARTIFACT).read_bytes())

    assert run.suite_result.suite_status is ProofStatus.FAIL
    assert parsed.suite_status is ProofStatus.FAIL
    assert b"ARTIFACT=security-proof-suite.json\n" in proof_runner.render_proof_run(
        run, artifact_materialized=True
    )


def test_two_fresh_full_runs_are_byte_identical_and_stably_ordered(
    clean_provenance, tmp_path
):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()

    first_run = proof_runner.run_security_proofs(output_dir=first)
    second_run = proof_runner.run_security_proofs(output_dir=second)
    first_bytes = (first / ARTIFACT).read_bytes()
    second_bytes = (second / ARTIFACT).read_bytes()
    parsed = parse_proof_suite(first_bytes)

    assert first_run.outcome is ProofRunOutcome.COMPLETED
    assert second_run.outcome is ProofRunOutcome.COMPLETED
    assert first_bytes == second_bytes
    assert parsed.selection == tuple(f"W2-P{index:02d}" for index in range(1, 9))
    assert tuple(item.property_id for item in parsed.properties) == parsed.selection


@pytest.mark.parametrize(
    ("seam", "code"),
    (
        ("serialize_proof_suite", ProofInfrastructureErrorCode.SERIALIZATION_FAILED),
        ("verify_proof_suite_bytes", ProofInfrastructureErrorCode.VERIFICATION_FAILED),
    ),
)
def test_serialization_and_verification_failures_write_no_artifact(
    clean_provenance, monkeypatch, tmp_path, seam, code
):
    def fail(*args):
        raise RuntimeError("must not escape")

    monkeypatch.setattr(proof_runner, seam, fail)
    run = proof_runner.run_security_proofs(output_dir=tmp_path)

    assert run.infrastructure_error is code
    assert not (tmp_path / ARTIFACT).exists()


def test_surface_scan_covers_transcript_artifact_and_actual_paths(
    clean_provenance, monkeypatch, tmp_path
):
    calls = []

    def reject(surfaces, *, extra_forbidden_values=()):
        calls.append((surfaces, extra_forbidden_values))
        return SimpleNamespace(pass_all=False)

    monkeypatch.setattr(proof_runner, "scan_demo_surfaces", reject)
    run = proof_runner.run_security_proofs(output_dir=tmp_path)

    assert run.infrastructure_error is ProofInfrastructureErrorCode.SURFACE_SCAN_FAILED
    assert not (tmp_path / ARTIFACT).exists()
    assert len(calls) == 1
    names = tuple(item[0] for item in calls[0][0])
    assert names == ("security-proof-terminal.txt", ARTIFACT)
    assert str(tmp_path).encode() in calls[0][1]


def test_publication_is_atomic_exclusive_and_cleans_temporary_file(
    clean_provenance, monkeypatch, tmp_path
):
    real_link = os.link
    observed = []

    def inspect_link(source, target):
        source_path = Path(source)
        target_path = Path(target)
        observed.append((source_path.read_bytes(), target_path.exists()))
        return real_link(source, target)

    monkeypatch.setattr(proof_runner, "_exclusive_link", inspect_link)
    run = proof_runner.run_security_proofs(
        property_id="W2-P05", output_dir=tmp_path
    )

    assert run.outcome is ProofRunOutcome.COMPLETED
    assert observed and observed[0][1] is False
    assert parse_proof_suite(observed[0][0]).suite_status is ProofStatus.PASS
    assert tuple(path.name for path in tmp_path.iterdir()) == (ARTIFACT,)


def test_publication_failure_removes_temporary_and_final_artifacts(
    clean_provenance, monkeypatch, tmp_path
):
    def fail_link(source, target):
        raise OSError("publication path must not escape")

    monkeypatch.setattr(proof_runner, "_exclusive_link", fail_link)
    run = proof_runner.run_security_proofs(output_dir=tmp_path)

    assert run.infrastructure_error is ProofInfrastructureErrorCode.PUBLICATION_FAILED
    assert tuple(tmp_path.iterdir()) == ()


def test_p08_terminal_states_proof_pass_means_uncertainty_was_preserved(
    clean_provenance,
):
    run = proof_runner.run_security_proofs(property_id="W2-P08")
    transcript = proof_runner.render_proof_run(run)

    assert b"PROPERTY=W2-P08:PASS\n" in transcript
    assert b"P08_PROOF_MEANING=UNCERTAINTY_PRESERVED\n" in transcript
    assert b"P08_EVIDENCE_SUCCESS_CLAIMS=0\n" in transcript
    assert b"P08_EXTERNAL_EFFECT_ABSENCE_CLAIMS=0\n" in transcript


def test_cli_unknown_property_uses_only_closed_error_envelope():
    completed = subprocess.run(
        (sys.executable, "scripts/run_security_proofs.py", "--property", "W2-P99"),
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": "src", "PYTHONDONTWRITEBYTECODE": "1"},
        check=False,
        capture_output=True,
    )

    assert completed.returncode == 2
    assert completed.stderr == b""
    assert completed.stdout == proof_runner.render_error(
        ProofInfrastructureErrorCode.SELECTION_INVALID
    )


def test_proof_sources_have_no_provider_network_cloud_or_test_dependencies():
    forbidden_roots = {"socket", "urllib", "http", "requests", "google", "pytest", "tests"}
    for relative in (
        "src/tidemark/proofs/runner.py",
        "scripts/run_security_proofs.py",
    ):
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            (node.module or "").split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        assert imports.isdisjoint(forbidden_roots)


def test_makefile_adds_only_prove_and_preserves_verify_recipe_text():
    source = (ROOT / "Makefile").read_text(encoding="utf-8")

    assert VERIFY_RECIPE in source
    assert "PROVE_TARGET := prove" in source
    assert ".PHONY: preflight verify demo $(PROVE_TARGET)" in source
    assert "$(PROVE_TARGET):\n" in source
    assert "scripts/run_security_proofs.py" in source
    assert '$(if $(PROPERTY),--property "$(PROPERTY)",)' in source
    assert '$(if $(OUTPUT_DIR),--output-dir "$(OUTPUT_DIR)",)' in source
