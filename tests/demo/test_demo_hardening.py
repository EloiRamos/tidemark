import json
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from tidemark.demo import (
    DemoHarnessError,
    DemoHarnessFailureCode,
    DeterministicDemoHarness,
)
from tidemark.demo import harness as harness_module
from tidemark.demo.rehearsal import (
    DemoRehearsalError,
    DemoRehearsalFailureCode,
    DemoSurfaceFindingCode,
    materialize_demo_rehearsal,
    run_demo_rehearsal,
    scan_demo_surfaces,
)
from tidemark.evidence.projection import (
    ExecutionReviewStatus,
    ProjectionDisposition,
    ReplayReviewState,
)
from tidemark.runtime.vocabulary import RuleId
from tidemark.ui.run_summary import (
    ComparisonStatus,
    EvidenceMode,
    REQUIRED_SCENARIO_CONTRACTS,
    REQUIRED_SCENARIO_ORDER,
    RunStatus,
    ScenarioId,
    ScenarioIntegrityStatus,
)


ROOT = Path(__file__).resolve().parents[2]
RUNBOOK = ROOT / "docs" / "runbooks" / "TIDEMARK_DEMO_RUNBOOK_v1.0.md"
SCRIPT = ROOT / "scripts" / "run_demo_rehearsal.py"
MAKEFILE = ROOT / "Makefile"
PYPROJECT = ROOT / "pyproject.toml"
README = ROOT / "README.md"


def _fact_by_id(report):
    return {fact.scenario_id: fact for fact in report.scenarios}


def _git(repo, *arguments):
    return subprocess.run(
        ("git", "-C", str(repo), *arguments),
        check=True,
        capture_output=True,
        text=True,
    )


def _preflight_repository(tmp_path, monkeypatch):
    from tidemark.demo import preflight as preflight_module

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


def _committed_checkout(tmp_path):
    checkout = tmp_path / "checkout"
    shutil.copytree(
        ROOT,
        checkout,
        ignore=shutil.ignore_patterns(".git", ".pytest_cache", "__pycache__", "*.pyc"),
    )
    _git(checkout, "init", "-q")
    _git(checkout, "config", "user.name", "TIDEMARK Test")
    _git(checkout, "config", "user.email", "test@example.invalid")
    _git(checkout, "add", ".")
    _git(checkout, "commit", "-qm", "fixture")
    return checkout


def test_two_clean_rehearsals_pass_from_fresh_state():
    result = run_demo_rehearsal(sample_count=2, seed_prefix="order-19-clean")
    report = result.report

    assert report.status is RunStatus.PASS
    assert report.sample_count == 2
    assert report.required_scenario_count == 6
    assert report.all_required_scenarios_rehearsed is True
    assert report.publication_verification_count == 12
    assert len(report.run_ids) == len(set(report.run_ids)) == 2
    assert tuple(fact.scenario_id for fact in report.scenarios) == REQUIRED_SCENARIO_ORDER
    assert all(fact.comparison is ComparisonStatus.MATCH for fact in report.scenarios)
    assert all(
        fact.integrity is ScenarioIntegrityStatus.CLEAN_COMPLETE
        for fact in report.scenarios
    )


def test_rehearsal_rerender_preserves_w1_lifecycle_without_new_artifact_type():
    result = run_demo_rehearsal(
        sample_count=2,
        seed_prefix="w1-c-d-rehearsal",
    )
    index = next(item for item in result.artifacts if item.name == "index.html")
    rendered = index.content.decode("utf-8")

    assert tuple(item.name for item in result.artifacts).count("index.html") == 1
    assert len(result.artifacts) == 8
    assert rendered.count("PREPARED CALL LIFECYCLE EXPLORER") == 6
    assert rendered.count('data-lifecycle-select="') == 60
    assert rendered.count("REFERENCE ONLY - NOT EXECUTED BY THIS UI") == 48
    assert "ALLOW IS NOT EXECUTED" in rendered
    assert "private_material_projected=false" in rendered
    assert result.report.protected_data_scan_pass is True
    assert result.report.secret_scan_pass is True


def test_fresh_restart_does_not_reset_or_unconsume_prior_authority(monkeypatch):
    original = harness_module.build_synthetic_payment_fixture
    fixtures = []

    def capture(*args, **kwargs):
        fixture = original(*args, **kwargs)
        fixtures.append(fixture)
        return fixture

    monkeypatch.setattr(harness_module, "build_synthetic_payment_fixture", capture)
    result = run_demo_rehearsal(sample_count=2, seed_prefix="order-19-restart")

    first_run = tuple(fixtures[:5])
    second_run = tuple(fixtures[5:])
    first_states = tuple(item.reference_metadata().consumed for item in first_run)
    assert result.report.status is RunStatus.PASS
    assert len(first_run) == len(second_run) == 5
    assert first_states == (True, False, False, False, True)
    assert tuple(item.reference_metadata().consumed for item in first_run) == first_states
    assert all(
        first.reference_store is not second.reference_store
        and first.payment_store is not second.payment_store
        and first.evidence_store is not second.evidence_store
        for first, second in zip(first_run, second_run)
    )


def test_rehearsal_scenario_matrix_matches_the_canonical_order_17_contract():
    report = run_demo_rehearsal(
        sample_count=2,
        seed_prefix="order-19-matrix",
    ).report

    actual = _fact_by_id(report)
    for expected in REQUIRED_SCENARIO_CONTRACTS:
        fact = actual[expected.scenario_id]
        assert fact.disposition is expected.decision
        assert fact.primary_rule_id is expected.primary_rule_id
        assert fact.execution_status is expected.execution_status
        assert fact.execution_start_count == expected.execution_start_count
        assert fact.payment_count == expected.payment_count
        assert fact.replay_state is expected.replay_state
        assert fact.model_non_attempt is expected.model_non_attempt


def test_offline_and_model_non_attempt_labels_cannot_be_presented_as_live_enforcement():
    result = run_demo_rehearsal(
        sample_count=2,
        seed_prefix="order-19-labels",
    )
    facts = _fact_by_id(result.report)
    rendered = b"\n".join(artifact.content for artifact in result.artifacts).decode(
        "utf-8"
    )

    assert all(
        fact.mode in {EvidenceMode.EVIDENCE_FALLBACK, EvidenceMode.MODEL_NON_ATTEMPT}
        for fact in facts.values()
    )
    assert facts[ScenarioId.MODEL_NON_ATTEMPT].disposition is ProjectionDisposition.MODEL_NON_ATTEMPT
    assert facts[ScenarioId.MODEL_NON_ATTEMPT].primary_rule_id is None
    assert facts[ScenarioId.MODEL_NON_ATTEMPT].execution_start_count == 0
    assert "EVIDENCE FALLBACK / OFFLINE" in rendered
    assert "HISTORICAL LIVE MODEL PROVENANCE" in rendered
    assert "historical committed evidence" in rendered
    assert "not current offline run" in rendered
    assert "not a live query" in rendered
    assert "not Order 21 cloud proof" in rendered
    assert "MODEL NON-ATTEMPT / NO ENFORCEMENT CLAIM" in rendered
    assert "not DENY, not callback veto, and not enforcement success" in rendered
    assert "LIVE MODEL / PROVIDER-BACKED EVIDENCE" not in rendered


def test_replay_remains_one_execution_and_one_payment():
    replay = _fact_by_id(
        run_demo_rehearsal(
            sample_count=2,
            seed_prefix="order-19-replay",
        ).report
    )[ScenarioId.REPLAY_REJECTION]

    assert replay.disposition is ProjectionDisposition.ALLOW
    assert replay.primary_rule_id is RuleId.AUTHORIZATION_ALLOW
    assert replay.execution_status is ExecutionReviewStatus.COMPLETED
    assert replay.execution_start_count == 1
    assert replay.payment_count == 1
    assert replay.replay_state is ReplayReviewState.REJECTED


def test_offline_rehearsal_needs_no_credential_and_succeeds_with_network_blocked(
    monkeypatch,
):
    def blocked_connect(*args, **kwargs):
        raise AssertionError("Order 19 offline rehearsal attempted network access")

    monkeypatch.setattr(socket.socket, "connect", blocked_connect)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    without_credential = run_demo_rehearsal(
        sample_count=2,
        seed_prefix="order-19-no-credential",
    )
    monkeypatch.setenv("GEMINI_API_KEY", "order-19-sentinel-must-not-be-read")
    with_sentinel = run_demo_rehearsal(
        sample_count=2,
        seed_prefix="order-19-sentinel-credential",
    )

    assert without_credential.report.status is RunStatus.PASS
    assert with_sentinel.report.status is RunStatus.PASS
    assert without_credential.report.secret_scan_pass is True
    assert with_sentinel.report.secret_scan_pass is True


@pytest.mark.parametrize(
    ("payload", "finding"),
    (
        (b"GEMINI_API_KEY=do-not-publish", DemoSurfaceFindingCode.SECRET),
        (b"synthetic-routing://beneficiary/private", DemoSurfaceFindingCode.PROTECTED_DATA),
        (b"raw_provider_output=private", DemoSurfaceFindingCode.RAW_PROVIDER_DATA),
        (b"RuntimePrivateExecutionBinding", DemoSurfaceFindingCode.PRIVATE_EXECUTION_DATA),
        (b"/Users/operator/private/demo.json", DemoSurfaceFindingCode.ABSOLUTE_PATH),
    ),
)
def test_bounded_demo_surface_scan_detects_each_forbidden_category(payload, finding):
    scan = scan_demo_surfaces((("sentinel.txt", payload),))

    assert scan.pass_all is False
    assert finding in tuple(item.code for item in scan.findings)
    assert payload.decode("utf-8") not in repr(scan)


def test_materialization_writes_only_read_only_path_free_public_artifacts(
    tmp_path, monkeypatch
):
    _preflight_repository(tmp_path, monkeypatch)
    output = tmp_path / "output"
    output.mkdir()
    result = materialize_demo_rehearsal(
        str(output),
        sample_count=2,
        seed_prefix="order-19-materialize",
    )
    artifact_root = output / "artifacts"
    names = tuple(sorted(path.name for path in artifact_root.iterdir()))
    combined = b"".join(path.read_bytes() for path in artifact_root.iterdir())
    report = json.loads((artifact_root / "demo-rehearsal-report.json").read_text())

    assert names == tuple(sorted(
        (*[artifact.name for artifact in result.artifacts], "run-manifest.json")
    ))
    assert "index.html" in names
    assert len(tuple(name for name in names if name.startswith("decision-review-"))) == 6
    assert report["status"] == "PASS"
    assert report["sample_count"] == 2
    assert str(output).encode("utf-8") not in combined
    assert str(ROOT).encode("utf-8") not in combined
    for forbidden_tag in (b"<form", b"<input", b"<textarea", b"<select"):
        assert forbidden_tag not in combined.lower()
    final_ui = (artifact_root / "index.html").read_text()
    assert final_ui.count('data-surface="') == 4
    assert "Guided demo" in final_ui
    for forbidden_control in (
        ">Approve<",
        ">Deny<",
        ">Retry<",
        ">Execute<",
        ">Reveal<",
        ">Edit policy<",
    ):
        assert forbidden_control not in final_ui


def test_nonempty_artifact_directory_fails_bounded_and_fresh_directory_recovers(
    tmp_path, monkeypatch
):
    _preflight_repository(tmp_path, monkeypatch)
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    marker = occupied / "preserve.txt"
    marker.write_text("existing operator artifact")

    with pytest.raises(DemoRehearsalError) as caught:
        materialize_demo_rehearsal(str(occupied))

    assert caught.value.code is DemoRehearsalFailureCode.OUTPUT_DIRECTORY_INVALID
    assert marker.read_text() == "existing operator artifact"
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    recovered = materialize_demo_rehearsal(
        str(fresh),
        seed_prefix="order-19-after-path-failure",
    )
    assert recovered.report.status is RunStatus.PASS


def test_timing_capture_is_bounded_nonsecret_and_does_not_change_results():
    result = run_demo_rehearsal(
        sample_count=3,
        seed_prefix="order-19-timing",
    )

    for statistic in (
        result.report.timings.full_harness_runtime,
        result.report.timings.run_summary_render,
        result.report.timings.decision_review_render,
        result.report.timings.publication_verification,
        result.report.timings.complete_sample,
    ):
        assert statistic.sample_count == 3
        assert 0 <= statistic.minimum_seconds <= statistic.median_seconds
        assert statistic.median_seconds <= statistic.maximum_seconds < 60
        assert statistic.maximum_seconds > 0.0
    encoded = result.report.to_json_bytes()
    assert result.report.status is RunStatus.PASS
    assert b"GEMINI_API_KEY" not in encoded
    assert str(ROOT).encode("utf-8") not in encoded


@pytest.mark.parametrize(
    ("target", "replacement", "expected_code"),
    (
        (
            "_record_runtime_scenario",
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("secret detail")),
            DemoHarnessFailureCode.SCENARIO_GENERATION_FAILED,
        ),
        (
            "EvidenceProjector",
            lambda: type(
                "FailingProjector",
                (),
                {"project": lambda self, events: (_ for _ in ()).throw(RuntimeError("secret detail"))},
            )(),
            DemoHarnessFailureCode.PROJECTION_FAILED,
        ),
        (
            "build_evidence_publication",
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("secret detail")),
            DemoHarnessFailureCode.PUBLICATION_FAILED,
        ),
        (
            "render_decision_review_workspace",
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("secret detail")),
            DemoHarnessFailureCode.DECISION_REVIEW_FAILED,
        ),
        (
            "render_demo_run_summary",
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("secret detail")),
            DemoHarnessFailureCode.RUN_SUMMARY_FAILED,
        ),
    ),
)
def test_every_harness_failure_stage_is_bounded_and_a_fresh_restart_succeeds(
    monkeypatch,
    target,
    replacement,
    expected_code,
):
    with monkeypatch.context() as context:
        context.setattr(harness_module, target, replacement)
        with pytest.raises(DemoHarnessError) as caught:
            DeterministicDemoHarness(run_seed="order-19-failure-stage").run()

    assert caught.value.code is expected_code
    assert "secret detail" not in str(caught.value)
    recovered = DeterministicDemoHarness(
        run_seed="order-19-fresh-recovery"
    ).run()
    assert recovered.summary.status is RunStatus.PASS


def test_rehearsal_failure_is_not_hidden_by_retry_or_partial_success(monkeypatch):
    calls = 0

    class FailingHarness:
        def __init__(self, **kwargs):
            pass

        def run(self):
            nonlocal calls
            calls += 1
            raise DemoHarnessError(
                DemoHarnessFailureCode.SCENARIO_GENERATION_FAILED,
                ScenarioId.BENIGN_ALLOW,
            )

    monkeypatch.setattr("tidemark.demo.rehearsal.DeterministicDemoHarness", FailingHarness)

    with pytest.raises(DemoRehearsalError) as caught:
        run_demo_rehearsal(sample_count=2, seed_prefix="order-19-no-retry")

    assert caught.value.code is DemoRehearsalFailureCode.HARNESS_FAILED
    assert calls == 1


def test_runbook_matrix_and_operational_commands_match_repository_contracts():
    text = RUNBOOK.read_text()

    assert SCRIPT.is_file()
    assert 'make demo PROFILE=standard OUTPUT_DIR="$DEMO_DIR"' in text
    assert 'make demo PROFILE=capture OUTPUT_DIR="$CAPTURE_DIR"' in text
    assert "python3 -m http.server --bind 127.0.0.1" in text
    for expected in REQUIRED_SCENARIO_CONTRACTS:
        rule = (
            expected.primary_rule_id.value
            if expected.primary_rule_id is not None
            else "NOT APPLICABLE"
        )
        fragment = (
            f"| `{expected.scenario_id.value}` | `{expected.decision.value}` | "
            f"`{rule}` | `{expected.execution_status.value}` | "
            f"{expected.execution_start_count} | {expected.payment_count} |"
        )
        assert fragment in text
    assert "offline deterministic demo requires no provider secret" in text
    assert "MODEL_NON_ATTEMPT ≠ DENY ≠ callback veto ≠ policy enforcement success" in text
    assert "fresh construction and disposal" in text


def test_documented_rehearsal_command_runs_in_a_clean_process_without_credentials(tmp_path):
    checkout = _committed_checkout(tmp_path)
    output = tmp_path / "output"
    output.mkdir()
    environment = dict(os.environ)
    environment.pop("GEMINI_API_KEY", None)
    environment["PYTHONPATH"] = str(checkout / "src")
    completed = subprocess.run(
        [
            sys.executable,
            str(checkout / "scripts" / "run_demo_rehearsal.py"),
            "--output-dir",
            str(output),
            "--samples",
            "2",
        ],
        cwd=checkout,
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )

    assert "ORDER_19_REHEARSAL=PASS" in completed.stdout
    assert "REQUIRED_SCENARIO_COUNT=6" in completed.stdout
    assert "OFFLINE_FALLBACK_EXPLICIT=true" in completed.stdout
    assert "ARTIFACT_SET_MATERIALIZED=true" in completed.stdout
    assert "OPEN_ARTIFACT=artifacts/index.html" in completed.stdout
    assert str(output) not in completed.stdout
    assert (output / "artifacts" / "index.html").is_file()
    assert (output / "artifacts" / "run-manifest.json").is_file()


def test_order_19_helper_adds_no_ui_authority_or_order_20_logic():
    sources = (
        (ROOT / "src" / "tidemark" / "demo" / "rehearsal.py").read_text(),
        SCRIPT.read_text(),
    )
    combined = "\n".join(sources)

    assert "google.cloud" not in combined
    assert "google.adk" not in combined
    assert "google.genai" not in combined
    assert "deploy(" not in combined
    assert "submission_package" not in combined
    assert "GEMINI_API_KEY" not in combined
    assert all(
        token not in combined
        for token in (
            "def unconsume",
            "def reactivate",
            "def reset_capability",
            "def retry_execution",
            "def force_allow",
            "def force_deny",
        )
    )


def test_phase1_makefile_exposes_only_the_three_public_targets():
    text = MAKEFILE.read_text()
    targets = tuple(
        match.group(1)
        for match in re.finditer(r"^([a-z][a-z0-9_-]*):", text, re.MULTILINE)
    )

    assert targets == ("preflight", "verify", "demo")
    assert "prove:" not in text
    assert "reproduce:" not in text
    assert ".github" not in text
    assert "verify_gemini_live" not in text


@pytest.mark.parametrize("profile", ("capture", "fallback"))
def test_capture_profiles_reject_samples_instead_of_overriding_fixed_count(
    tmp_path, profile
):
    checkout = _committed_checkout(tmp_path)
    output = tmp_path / "output"
    output.mkdir()
    completed = subprocess.run(
        [
            sys.executable,
            str(checkout / "scripts" / "run_demo_rehearsal.py"),
            "--output-dir",
            str(output),
            "--profile",
            profile,
            "--samples",
            "3",
        ],
        cwd=checkout,
        env={**os.environ, "PYTHONPATH": str(checkout / "src")},
        capture_output=True,
        text=True,
    )

    assert completed.returncode != 0
    assert "FAILURE_CODE=demo.rehearsal.invalid_input.v1" in completed.stdout
    assert tuple(output.iterdir()) == ()


def test_capture_cli_terminal_output_is_stable_content_free_and_exactly_three(
    tmp_path,
):
    checkout = _committed_checkout(tmp_path)
    output = tmp_path / "output"
    output.mkdir()
    completed = subprocess.run(
        [
            sys.executable,
            str(checkout / "scripts" / "run_demo_rehearsal.py"),
            "--output-dir",
            str(output),
            "--profile",
            "capture",
        ],
        cwd=checkout,
        env={**os.environ, "PYTHONPATH": str(checkout / "src")},
        capture_output=True,
        text=True,
        check=True,
    )

    for line in (
        "CAPTURE_REHEARSAL=PASS",
        "PROFILE=CAPTURE",
        "RUN_COUNT=3",
        "SEMANTIC_EQUALITY=true",
        "ARTIFACT_SET_MATERIALIZED=true",
        "OPEN_ARTIFACT=artifacts/index.html",
        "LIVE_GATE_STATE=NOT_EVALUATED",
        "LIVE_MODEL_CALLS_PERFORMED=0",
        "GOOGLE_CLOUD_ACCESSED=false",
    ):
        assert line in completed.stdout.splitlines()
    assert str(output) not in completed.stdout
    rendered = (output / "artifacts" / "index.html").read_text()
    assert rendered.count("PREPARED CALL LIFECYCLE EXPLORER") == 6
    assert rendered.count('data-lifecycle-select="') == 60
    assert rendered.count("REFERENCE ONLY - NOT EXECUTED BY THIS UI") == 48
    assert rendered.count('data-surface="') == 4
    assert rendered.count('data-step="') == 5
    assert "synthetic-routing://" not in rendered
    assert "private_material_projected=false" in rendered


@pytest.mark.parametrize("profile", ("standard", "capture", "fallback"))
def test_dirty_cli_profile_emits_no_manifest_backed_pass(tmp_path, profile):
    checkout = _committed_checkout(tmp_path)
    output = tmp_path / "output"
    output.mkdir()
    (checkout / "dirty.txt").write_text("untracked dirt\n")
    completed = subprocess.run(
        [
            sys.executable,
            str(checkout / "scripts" / "run_demo_rehearsal.py"),
            "--output-dir",
            str(output),
            "--profile",
            profile,
        ],
        cwd=checkout,
        env={**os.environ, "PYTHONPATH": str(checkout / "src")},
        capture_output=True,
        text=True,
    )

    assert completed.returncode != 0
    assert "=PASS" not in completed.stdout
    assert not tuple(output.rglob("run-manifest.json"))


def test_preflight_only_is_local_content_free_and_creates_no_artifacts(tmp_path):
    checkout = _committed_checkout(tmp_path)
    output = tmp_path / "output"
    output.mkdir()
    completed = subprocess.run(
        [
            sys.executable,
            str(checkout / "scripts" / "run_demo_rehearsal.py"),
            "--output-dir",
            str(output),
            "--profile",
            "standard",
            "--preflight-only",
        ],
        cwd=checkout,
        env={**os.environ, "PYTHONPATH": str(checkout / "src")},
        capture_output=True,
        text=True,
        check=True,
    )

    assert "LOCAL_READINESS=PASS" in completed.stdout
    assert "LIVE_GATE_STATE=NOT_EVALUATED" in completed.stdout
    assert str(checkout) not in completed.stdout
    assert str(output) not in completed.stdout
    assert tuple(output.iterdir()) == ()


def test_python_floor_and_declared_test_dependency_are_aligned_everywhere():
    pyproject = PYPROJECT.read_text()
    readme = README.read_text()
    runbook = RUNBOOK.read_text()
    preflight = (ROOT / "src" / "tidemark" / "demo" / "preflight.py").read_text()

    assert 'requires-python = ">=3.9"' in pyproject
    assert 'dev = ["pytest==8.4.2"]' in pyproject
    assert "Python 3.9 or newer" in readme
    assert "Python 3.9 or newer" in runbook
    assert "MINIMUM_PYTHON = (3, 9)" in preflight
    assert '"google-adk==1.18.0"' in pyproject


def test_readme_documents_the_full_suite_as_a_separate_closure_command():
    readme = README.read_text()

    assert (
        "PYTHONDONTWRITEBYTECODE=1 python3 -m pytest "
        "-p no:cacheprovider -q"
    ) in readme


def test_runbook_names_capture_snapshot_schema_and_distinguishes_scan_roles():
    runbook = RUNBOOK.read_text()

    assert (
        "CAPTURE_SEMANTIC_SNAPSHOT_SCHEMA="
        "tidemark.demo.capture-semantic-snapshot.v1"
    ) in runbook
    assert "preflight scanner self-test" in runbook
    assert "candidate public outputs" in runbook
