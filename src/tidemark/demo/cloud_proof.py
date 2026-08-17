"""Bounded provider-free proof entrypoint for the Order 21 Cloud Run Job.

The entrypoint composes the existing deterministic rehearsal and emits one
small allowlisted JSON envelope. It owns no authorization, retry, persistence,
provider, network, or cloud-control behavior.
"""

from contextlib import contextmanager
import json
import os
import re
import socket
from typing import Iterator

from tidemark.demo.rehearsal import DemoRehearsalError, run_demo_rehearsal
from tidemark.payment.fixtures import (
    SCHEDULE_PAYMENT_POLICY_VERSION,
    SCHEDULE_PAYMENT_REGISTRY_VERSION,
)
from tidemark.ui.run_summary import RunStatus, ScenarioId


CLOUD_PROOF_SCHEMA_VERSION = "tidemark.order-21.cloud-proof.v1"
CLOUD_PROOF_SAMPLE_COUNT = 2
CLOUD_PROOF_SEED_PREFIX = "order-21-cloud-proof"
SYNTHETIC_ADAPTER_VERSION = "schedule_payment.synthetic.adapter.v1"
_REVISION = re.compile(r"[0-9a-f]{7,40}\Z")
_TREE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


@contextmanager
def _blocked_network(counter: list[int]) -> Iterator[None]:
    original_connect = socket.socket.connect

    def refuse_connect(*_args, **_kwargs):
        counter[0] += 1
        raise OSError("order-21 application network is disabled")

    socket.socket.connect = refuse_connect
    try:
        yield
    finally:
        socket.socket.connect = original_connect


def build_cloud_proof(
    *, repository_commit: str, source_tree_digest: str
) -> dict:
    """Return one deterministic, identifier-free proof envelope."""

    if type(repository_commit) is not str or _REVISION.fullmatch(repository_commit) is None:
        raise ValueError("repository_commit requires a lowercase hexadecimal revision")
    if type(source_tree_digest) is not str or _TREE_DIGEST.fullmatch(source_tree_digest) is None:
        raise ValueError("source_tree_digest requires a sha256 digest")

    network_attempts = [0]
    with _blocked_network(network_attempts):
        result = run_demo_rehearsal(
            sample_count=CLOUD_PROOF_SAMPLE_COUNT,
            seed_prefix=CLOUD_PROOF_SEED_PREFIX,
        )

    report = result.report
    if network_attempts[0] != 0 or report.status is not RunStatus.PASS:
        raise RuntimeError("order-21 cloud proof failed closed")

    scenarios = tuple(
        {
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
        for fact in report.scenarios
    )
    replay = next(
        item for item in scenarios if item["scenario_id"] == ScenarioId.REPLAY_REJECTION.value
    )
    return {
        "schema_version": CLOUD_PROOF_SCHEMA_VERSION,
        "repository_commit": repository_commit,
        "source_tree_digest": source_tree_digest,
        "platform": "google-cloud-run-job",
        "provider_mode": "offline",
        "policy_version": SCHEDULE_PAYMENT_POLICY_VERSION.value,
        "registry_version": SCHEDULE_PAYMENT_REGISTRY_VERSION.value,
        "adapter_version": SYNTHETIC_ADAPTER_VERSION,
        "sample_count": report.sample_count,
        "required_scenario_count": report.required_scenario_count,
        "all_required_scenarios_verified": report.all_required_scenarios_rehearsed,
        "publication_verification_count": report.publication_verification_count,
        "secret_scan_pass": report.secret_scan_pass,
        "protected_data_scan_pass": report.protected_data_scan_pass,
        "absolute_path_scan_pass": report.absolute_path_scan_pass,
        "execution_override_used": False,
        "live_model_used": False,
        "gemini_calls": 0,
        "application_network_calls": network_attempts[0],
        "replay_total_execution_start_count": replay["execution_start_count"],
        "replay_total_payment_count": replay["payment_count"],
        "replay_rejection_present": replay["replay_state"] == "REJECTED",
        "scenarios": scenarios,
    }


def main() -> int:
    repository_commit = os.environ.get("TIDEMARK_REPOSITORY_COMMIT", "")
    source_tree_digest = os.environ.get("TIDEMARK_SOURCE_TREE_DIGEST", "")
    try:
        proof = build_cloud_proof(
            repository_commit=repository_commit,
            source_tree_digest=source_tree_digest,
        )
    except (DemoRehearsalError, OSError, RuntimeError, TypeError, ValueError):
        print(
            json.dumps(
                {
                    "schema_version": CLOUD_PROOF_SCHEMA_VERSION,
                    "status": "FAIL",
                    "failure_code": "order21.cloud_proof.failed.v1",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1

    print(json.dumps(proof, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = (
    "CLOUD_PROOF_SAMPLE_COUNT",
    "CLOUD_PROOF_SCHEMA_VERSION",
    "CLOUD_PROOF_SEED_PREFIX",
    "SYNTHETIC_ADAPTER_VERSION",
    "build_cloud_proof",
    "main",
)
