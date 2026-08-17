import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tidemark.demo.cloud_proof import build_cloud_proof
from tidemark.ui.run_summary import REQUIRED_SCENARIO_ORDER, ScenarioId


COMMIT = "73c11c6"
TREE_DIGEST = "sha256:" + "a" * 64
ROOT = Path(__file__).resolve().parents[2]


def _proof():
    return build_cloud_proof(
        repository_commit=COMMIT,
        source_tree_digest=TREE_DIGEST,
    )


def test_cloud_proof_is_bounded_provider_free_and_complete():
    proof = _proof()

    assert proof["schema_version"] == "tidemark.order-21.cloud-proof.v1"
    assert proof["repository_commit"] == COMMIT
    assert proof["source_tree_digest"] == TREE_DIGEST
    assert proof["platform"] == "google-cloud-run-job"
    assert proof["provider_mode"] == "offline"
    assert proof["sample_count"] == 2
    assert proof["required_scenario_count"] == 6
    assert proof["all_required_scenarios_verified"] is True
    assert proof["publication_verification_count"] == 12
    assert proof["execution_override_used"] is False
    assert proof["live_model_used"] is False
    assert proof["gemini_calls"] == 0
    assert proof["application_network_calls"] == 0
    assert tuple(item["scenario_id"] for item in proof["scenarios"]) == tuple(
        item.value for item in REQUIRED_SCENARIO_ORDER
    )


def test_cloud_proof_preserves_replay_at_most_once_counts():
    proof = _proof()
    replay = next(
        item
        for item in proof["scenarios"]
        if item["scenario_id"] == ScenarioId.REPLAY_REJECTION.value
    )

    assert replay["execution_start_count"] == 1
    assert replay["payment_count"] == 1
    assert replay["replay_state"] == "REJECTED"
    assert proof["replay_total_execution_start_count"] == 1
    assert proof["replay_total_payment_count"] == 1
    assert proof["replay_rejection_present"] is True


@pytest.mark.parametrize(
    ("commit", "digest"),
    (
        ("not-a-commit", TREE_DIGEST),
        (COMMIT, "not-a-digest"),
    ),
)
def test_cloud_proof_rejects_unbounded_source_identity(commit, digest):
    with pytest.raises(ValueError):
        build_cloud_proof(repository_commit=commit, source_tree_digest=digest)


def test_cloud_proof_cli_emits_one_small_identifier_free_json_line():
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    environment["TIDEMARK_REPOSITORY_COMMIT"] = COMMIT
    environment["TIDEMARK_SOURCE_TREE_DIGEST"] = TREE_DIGEST
    completed = subprocess.run(
        [sys.executable, "-m", "tidemark.demo.cloud_proof"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=60,
    )

    assert completed.returncode == 0
    assert completed.stderr == ""
    assert completed.stdout.count("\n") == 1
    assert len(completed.stdout.encode("utf-8")) < 64 * 1024
    proof = json.loads(completed.stdout)
    assert proof["all_required_scenarios_verified"] is True
    assert proof["application_network_calls"] == 0
    assert "/Users/" not in completed.stdout
    assert "/home/" not in completed.stdout


def test_cloud_proof_cli_fails_closed_without_source_identity():
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    environment.pop("TIDEMARK_REPOSITORY_COMMIT", None)
    environment.pop("TIDEMARK_SOURCE_TREE_DIGEST", None)
    completed = subprocess.run(
        [sys.executable, "-m", "tidemark.demo.cloud_proof"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=60,
    )

    assert completed.returncode == 1
    assert json.loads(completed.stdout) == {
        "failure_code": "order21.cloud_proof.failed.v1",
        "schema_version": "tidemark.order-21.cloud-proof.v1",
        "status": "FAIL",
    }
