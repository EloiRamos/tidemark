"""Closed local runner for Variant C W3 bounded verification evidence."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from hashlib import sha256
import importlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Mapping, Sequence, Tuple

from tidemark.demo.rehearsal import scan_demo_surfaces
from tidemark.evidence.canonical import canonical_json_bytes
from tidemark.verification.w3_contract import (
    CONCURRENCY_REPETITIONS_PER_SHAPE,
    CONCURRENCY_SHAPES,
    MUTANT_CATALOGUE,
    MUTANT_IDS,
    PROPERTY_DOMAINS,
    PROPERTY_IDS,
    ContractDriftError,
    MutantResult,
    OverallStatus,
    make_adequacy_artifact,
    parse_adequacy_artifact,
    serialize_adequacy_artifact,
    validate_contract,
)


EVIDENCE_JSON_FILENAME = "TIDEMARK_VARIANT_C_W3_MUTATION_ADEQUACY_v1.json"
EVIDENCE_MARKDOWN_FILENAME = "TIDEMARK_VARIANT_C_W3_MUTATION_ADEQUACY_v1.0.md"

_REVISION = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ERROR_CODES = frozenset(
    {
        "w3.cli_invalid.v1",
        "w3.source_revision_invalid.v1",
        "w3.source_not_clean.v1",
        "w3.source_hash_drift.v1",
        "w3.component_execution_failed.v1",
        "w3.result_contract_drift.v1",
        "w3.overall_status_not_pass.v1",
        "w3.artifact_verification_failed.v1",
        "w3.markdown_verification_failed.v1",
        "w3.surface_scan_failed.v1",
        "w3.output_directory_invalid.v1",
        "w3.output_materialization_failed.v1",
    }
)

_PROPERTY_ROW_KEYS = (
    "property_id",
    "seed",
    "generated_case_count",
    "control_case_count",
    "control_passed",
    "domain_digest",
    "detector_ids",
    "status",
    "observation_digest",
)
_MUTANT_ROW_KEYS = (
    "mutant_id",
    "category",
    "targets",
    "expected_result",
    "result",
    "activation_probe_passed",
    "detector_ids",
    "safe_finding_candidate_id",
    "observation_digest",
)
_CONCURRENCY_ROW_KEYS = (
    "shape_id",
    "repetition_count",
    "passed_repetition_count",
    "detector_ids",
    "normalized_state",
    "status",
    "observation_digest",
)

_MUTANT_TARGETS = (
    ("W3-D01", "SELECTION_NOT_SUPPLY"),
    ("W3-D02", "TRUSTED_STORE_ISSUANCE"),
    ("W3-D03", "CANONICAL_BYTES"),
    ("W3-D04", "SAFE_DISPLAY"),
    ("W3-D04", "REFERENCE_SECRECY"),
    ("W3-D04", "OUTPUT_ENCODING_BOUNDARY"),
    ("W2-P03", "EVIDENCE_BEFORE_EFFECT"),
    ("W2-P04", "W2-P05", "LOCAL_SINGLE_USE"),
    ("W3-D05", "EVIDENCE_COMPLETENESS"),
    ("W2-P08", "UNCERTAINTY_PRESERVATION"),
    ("W3-C01", "CURRENT_STATE_VETO"),
    ("W3-C02", "DURABLE_RECEIPT_PREREQUISITE"),
)


class RunnerError(RuntimeError):
    """One closed W3 runner failure code without nested sensitive detail."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        if type(code) is not str or code not in _ERROR_CODES:
            raise ValueError("runner error requires a closed W3 code")
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class EvidenceBundle:
    artifact: dict
    json_bytes: bytes
    markdown_bytes: bytes


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def parse_cli_arguments(argv: Sequence[str]) -> Path:
    parser = argparse.ArgumentParser(
        prog="run_w3_verification.py",
        allow_abbrev=False,
    )
    parser.add_argument("--output-dir", required=True)
    namespace = parser.parse_args(tuple(argv))
    output_dir = Path(namespace.output_dir)
    _require_empty_output_directory(output_dir)
    return output_dir


def _require_empty_output_directory(output_dir: Path) -> None:
    try:
        valid = (
            isinstance(output_dir, Path)
            and not output_dir.is_symlink()
            and output_dir.is_dir()
            and not any(output_dir.iterdir())
        )
    except OSError:
        valid = False
    if not valid:
        raise RunnerError("w3.output_directory_invalid.v1")


def validate_candidate_state(revision: str, porcelain: str) -> str:
    if type(revision) is not str or _REVISION.fullmatch(revision) is None:
        raise RunnerError("w3.source_revision_invalid.v1")
    if type(porcelain) is not str or porcelain != "":
        raise RunnerError("w3.source_not_clean.v1")
    return revision


def _git_output(arguments: Tuple[str, ...]) -> str:
    try:
        completed = subprocess.run(
            ("git", "-C", str(_repository_root()), *arguments),
            capture_output=True,
            check=False,
            text=True,
        )
    except OSError:
        raise RunnerError("w3.source_not_clean.v1") from None
    if completed.returncode != 0 or completed.stderr != "":
        raise RunnerError("w3.source_not_clean.v1")
    return completed.stdout


def clean_candidate_revision() -> str:
    revision = _git_output(("rev-parse", "HEAD")).strip()
    porcelain = _git_output(
        ("status", "--porcelain=v1", "--untracked-files=all")
    )
    return validate_candidate_state(revision, porcelain)


def _source_hashes() -> Tuple[Tuple[str, str], ...]:
    repository = _repository_root()
    source_root = repository / "src" / "tidemark"
    paths = tuple(sorted(source_root.rglob("*.py"))) + (
        repository / "scripts" / "verify_gemini_live.py",
        repository / "scripts" / "run_w3_verification.py",
        repository / "tests" / "adversarial" / "test_w3_contract.py",
        repository / "tests" / "adversarial" / "w3_detectors.py",
        repository / "tests" / "adversarial" / "test_w3_property_domains.py",
        repository / "tests" / "adversarial" / "w3_mutants.py",
        repository / "tests" / "adversarial" / "test_w3_mutation_adequacy.py",
        repository / "tests" / "security" / "test_w3_concurrency_depth.py",
    )
    try:
        return tuple(
            (
                path.relative_to(repository).as_posix(),
                sha256(path.read_bytes()).hexdigest(),
            )
            for path in paths
        )
    except OSError:
        raise RunnerError("w3.source_hash_drift.v1") from None


def require_unchanged_source_hashes(
    before: Tuple[Tuple[str, str], ...],
    after: Tuple[Tuple[str, str], ...],
) -> None:
    if type(before) is not tuple or type(after) is not tuple or before != after:
        raise RunnerError("w3.source_hash_drift.v1")


def _load_fixed_components():
    repository = _repository_root()
    fixed_paths = (
        repository / "tests" / "adversarial",
        repository / "tests" / "security",
    )
    for path in reversed(fixed_paths):
        value = str(path)
        if value not in sys.path:
            sys.path.insert(0, value)
    return (
        importlib.import_module("w3_detectors"),
        importlib.import_module("w3_mutants"),
        importlib.import_module("test_w3_concurrency_depth"),
    )


def _digest(value: object) -> str:
    return "sha256:" + sha256(canonical_json_bytes(value)).hexdigest()


def _with_observation_digest(row: Mapping[str, object]) -> dict:
    closed = dict(row)
    closed["observation_digest"] = _digest(closed)
    return closed


def _property_rows(materialization) -> Tuple[dict, ...]:
    domains = {domain.property_id: domain for domain in PROPERTY_DOMAINS}
    return tuple(
        _with_observation_digest(
            {
                "property_id": result.property_id,
                "seed": domains[result.property_id].seed,
                "generated_case_count": result.generated_case_count,
                "control_case_count": result.control_case_count,
                "control_passed": result.control_passed,
                "domain_digest": result.domain_digest,
                "detector_ids": list(result.detector_ids),
                "status": result.status.value,
            }
        )
        for result in materialization.property_results
    )


def _mutant_rows(run, mutation_specs) -> Tuple[dict, ...]:
    rows = []
    for descriptor, spec, targets, outcome in zip(
        MUTANT_CATALOGUE,
        mutation_specs,
        _MUTANT_TARGETS,
        run.outcomes,
    ):
        rows.append(
            _with_observation_digest(
                {
                    "mutant_id": descriptor.mutant_id,
                    "category": descriptor.category.value,
                    "targets": list(targets),
                    "expected_result": spec.expected_result.value,
                    "result": outcome.child_result.result.value,
                    "activation_probe_passed": (
                        outcome.child_result.activation_probe_passed
                    ),
                    "detector_ids": list(outcome.child_result.detector_ids),
                    "safe_finding_candidate_id": (
                        outcome.child_result.safe_finding_candidate_id
                    ),
                }
            )
        )
    return tuple(rows)


def _concurrency_rows(run, concurrency_module) -> Tuple[dict, ...]:
    rows = []
    for shape_id in CONCURRENCY_SHAPES:
        results = tuple(
            result for result in run.results if result.shape_id == shape_id
        )
        normalized = tuple(
            concurrency_module.normalized_concurrency_result_bytes(result)
            for result in results
        )
        if len(results) != CONCURRENCY_REPETITIONS_PER_SHAPE or len(set(normalized)) != 1:
            raise RunnerError("w3.result_contract_drift.v1")
        normalized_state = json.loads(normalized[0].decode("utf-8"))
        normalized_state.pop("repetition_index", None)
        normalized_state.pop("observation_digest", None)
        passed = sum(result.overall_status.value == "PASS" for result in results)
        rows.append(
            _with_observation_digest(
                {
                    "shape_id": shape_id,
                    "repetition_count": len(results),
                    "passed_repetition_count": passed,
                    "detector_ids": list(results[0].detector_ids),
                    "normalized_state": normalized_state,
                    "status": "PASS" if passed == len(results) else "ERROR",
                }
            )
        )
    return tuple(rows)


def _exact_row_keys(row: Mapping[str, object], expected: Tuple[str, ...]) -> bool:
    return len(row) == len(expected) and set(row) == set(expected)


def _verify_observation_digest(row: Mapping[str, object]) -> None:
    unsigned = dict(row)
    claimed = unsigned.pop("observation_digest", None)
    if (
        type(claimed) is not str
        or _DIGEST.fullmatch(claimed) is None
        or claimed != _digest(unsigned)
    ):
        raise RunnerError("w3.artifact_verification_failed.v1")


def _validate_runner_rows(artifact: Mapping[str, object]) -> None:
    properties = artifact.get("property_results")
    mutants = artifact.get("mutant_results")
    concurrency = artifact.get("concurrency_results")
    if not all(type(rows) is list for rows in (properties, mutants, concurrency)):
        raise RunnerError("w3.artifact_verification_failed.v1")
    assert type(properties) is list
    assert type(mutants) is list
    assert type(concurrency) is list
    if (
        tuple(row.get("property_id") for row in properties) != PROPERTY_IDS
        or tuple(row.get("mutant_id") for row in mutants) != MUTANT_IDS
        or tuple(row.get("shape_id") for row in concurrency) != CONCURRENCY_SHAPES
    ):
        raise RunnerError("w3.artifact_verification_failed.v1")
    for row in properties:
        if not isinstance(row, Mapping) or not _exact_row_keys(row, _PROPERTY_ROW_KEYS):
            raise RunnerError("w3.artifact_verification_failed.v1")
        _verify_observation_digest(row)
    for row in mutants:
        if not isinstance(row, Mapping) or not _exact_row_keys(row, _MUTANT_ROW_KEYS):
            raise RunnerError("w3.artifact_verification_failed.v1")
        _verify_observation_digest(row)
    for row in concurrency:
        if not isinstance(row, Mapping) or not _exact_row_keys(
            row, _CONCURRENCY_ROW_KEYS
        ):
            raise RunnerError("w3.artifact_verification_failed.v1")
        _verify_observation_digest(row)


def require_passing_artifact(artifact: Mapping[str, object]) -> None:
    try:
        summary = artifact.get("summary")
        overall = summary.get("overall_status") if isinstance(summary, Mapping) else None
        if overall != OverallStatus.PASS.value:
            raise RunnerError("w3.overall_status_not_pass.v1")
    except AttributeError:
        raise RunnerError("w3.overall_status_not_pass.v1") from None


def _markdown_table(headers: Tuple[str, ...], rows: Sequence[Tuple[str, ...]]) -> list:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return lines


def render_markdown(artifact: Mapping[str, object]) -> bytes:
    try:
        summary = artifact["summary"]
        properties = artifact["property_results"]
        mutants = artifact["mutant_results"]
        concurrency = artifact["concurrency_results"]
        lines = [
            "# TIDEMARK Variant C W3 Mutation Adequacy",
            "",
            "Schema version: `" + str(artifact["schema_version"]) + "`",
            "Source revision: `" + str(artifact["source_revision"]) + "`",
            "Catalogue version: `" + str(artifact["catalogue_version"]) + "`",
            "Domain contract: `" + str(artifact["domain_contract_version"]) + "`",
            "Artifact digest: `" + str(artifact["artifact_digest"]) + "`",
            "",
            "## Summary",
            "",
        ]
        lines.extend(
            _markdown_table(
                ("Measure", "Value"),
                (
                    ("Overall status", str(summary["overall_status"])),
                    ("Properties passed", f"{summary['property_pass_count']} / 5"),
                    ("Generated cases", str(summary["generated_case_count"])),
                    (
                        "Mutation adequacy",
                        f"{summary['adequacy_numerator']} / {summary['adequacy_denominator']}",
                    ),
                    ("Concurrency shapes passed", f"{summary['concurrency_pass_count']} / 2"),
                ),
            )
        )
        lines.extend(("", "## Property domains", ""))
        lines.extend(
            _markdown_table(
                ("ID", "Seed", "Cases", "Controls", "Detectors", "Status"),
                tuple(
                    (
                        str(row["property_id"]),
                        str(row["seed"]),
                        str(row["generated_case_count"]),
                        str(row["control_case_count"]),
                        ", ".join(row["detector_ids"]),
                        str(row["status"]),
                    )
                    for row in properties
                ),
            )
        )
        lines.extend(("", "## Mutant catalogue", ""))
        lines.extend(
            _markdown_table(
                ("ID", "Category", "Targets", "Expected", "Actual", "Activated"),
                tuple(
                    (
                        str(row["mutant_id"]),
                        str(row["category"]),
                        ", ".join(row["targets"]),
                        str(row["expected_result"]),
                        str(row["result"]),
                        str(row["activation_probe_passed"]).lower(),
                    )
                    for row in mutants
                ),
            )
        )
        lines.extend(("", "## Concurrency shapes", ""))
        lines.extend(
            _markdown_table(
                ("ID", "Repetitions", "Passed", "Detectors", "Status"),
                tuple(
                    (
                        str(row["shape_id"]),
                        str(row["repetition_count"]),
                        str(row["passed_repetition_count"]),
                        ", ".join(row["detector_ids"]),
                        str(row["status"]),
                    )
                    for row in concurrency
                ),
            )
        )
        survivors = tuple(
            row["mutant_id"] for row in mutants if row["result"] == "SURVIVED"
        )
        lines.extend(("", "## Survivors and findings", ""))
        lines.append("None." if not survivors else ", ".join(survivors))
        lines.extend(
            (
                "",
                "## Non-claims",
                "",
                "- A killed mutant is not proof of production security.",
                "- High mutation adequacy is not absence of unknown defects.",
                "- No distributed or external exactly-once guarantee is claimed.",
                "- No scheduler fairness guarantee is claimed.",
                "",
                "## Offline execution state",
                "",
            )
        )
        lines.extend(
            _markdown_table(
                ("Boundary", "Value"),
                (
                    ("Live model calls", str(summary["live_model_calls_performed"])),
                    ("Provider calls", str(summary["provider_calls_performed"])),
                    (
                        "Google Cloud accessed",
                        str(summary["google_cloud_accessed"]).lower(),
                    ),
                    (
                        "Network dependency required",
                        str(summary["network_dependency_required"]).lower(),
                    ),
                ),
            )
        )
    except (KeyError, TypeError, ValueError):
        raise RunnerError("w3.markdown_verification_failed.v1") from None
    return ("\n".join(lines) + "\n").encode("utf-8")


def scan_evidence_surfaces(surfaces: Tuple[Tuple[str, bytes], ...]) -> None:
    if type(surfaces) is not tuple or any(
        type(item) is not tuple
        or len(item) != 2
        or type(item[0]) is not str
        or not item[0]
        or type(item[1]) is not bytes
        for item in surfaces
    ):
        raise RunnerError("w3.surface_scan_failed.v1")
    safe_names = tuple(
        (f"w3-surface-{index:02d}", content)
        for index, (_, content) in enumerate(surfaces, 1)
    )
    scan = scan_demo_surfaces(
        safe_names,
        extra_forbidden_values=(
            b"ref_",
            b"thread_id",
            b"thread_name",
            b"hostname",
        ),
    )
    if not scan.pass_all:
        raise RunnerError("w3.surface_scan_failed.v1")


def verify_evidence_bundle(
    json_bytes: bytes,
    markdown_bytes: bytes,
    *,
    expected_source_revision: str,
) -> dict:
    try:
        artifact = parse_adequacy_artifact(json_bytes)
    except ContractDriftError:
        raise RunnerError("w3.artifact_verification_failed.v1") from None
    if artifact.get("source_revision") != expected_source_revision:
        raise RunnerError("w3.artifact_verification_failed.v1")
    _validate_runner_rows(artifact)
    require_passing_artifact(artifact)
    if render_markdown(artifact) != markdown_bytes:
        raise RunnerError("w3.markdown_verification_failed.v1")
    scan_evidence_surfaces(
        (
            (EVIDENCE_JSON_FILENAME, json_bytes),
            (EVIDENCE_MARKDOWN_FILENAME, markdown_bytes),
        )
    )
    return artifact


def execute_bounded_verification(*, source_revision: str) -> EvidenceBundle:
    validate_candidate_state(source_revision, "")
    before = _source_hashes()
    validate_contract()
    detectors, mutants, concurrency_module = _load_fixed_components()
    try:
        with tempfile.TemporaryDirectory(prefix="tidemark-w3-run-") as temporary:
            root = Path(temporary)
            property_runs = tuple(
                detectors.materialize_w3_b(root / f"properties-{index}", run_index=index)
                for index in range(3)
            )
            first_property_run = property_runs[0]
            if not (
                all(run.generated_case_count == 205 for run in property_runs)
                and all(run.property_count == 5 for run in property_runs)
                and all(run.controls_pass and run.properties_pass for run in property_runs)
                and len({run.descriptor_bytes for run in property_runs}) == 1
                and len({run.domain_digests for run in property_runs}) == 1
                and len({run.property_result_bytes for run in property_runs}) == 1
            ):
                raise RunnerError("w3.result_contract_drift.v1")

            mutation_run = mutants.run_mutation_catalogue(timeout_seconds=10.0)
            concurrency_root = root / "concurrency"
            concurrency_root.mkdir()
            concurrency_run = concurrency_module.run_w3_d(concurrency_root)
            property_rows = _property_rows(first_property_run)
            mutant_rows = _mutant_rows(mutation_run, mutants.MUTATION_SPECS)
            concurrency_rows = _concurrency_rows(
                concurrency_run, concurrency_module
            )
    except RunnerError:
        raise
    except Exception:
        raise RunnerError("w3.component_execution_failed.v1") from None

    require_unchanged_source_hashes(before, _source_hashes())
    artifact = make_adequacy_artifact(
        source_revision=source_revision,
        property_results=property_rows,
        mutant_results=mutant_rows,
        concurrency_results=concurrency_rows,
    )
    require_passing_artifact(artifact)
    json_bytes = serialize_adequacy_artifact(artifact)
    markdown_bytes = render_markdown(artifact)
    if json_bytes != serialize_adequacy_artifact(artifact):
        raise RunnerError("w3.artifact_verification_failed.v1")
    if markdown_bytes != render_markdown(artifact):
        raise RunnerError("w3.markdown_verification_failed.v1")
    verified = verify_evidence_bundle(
        json_bytes,
        markdown_bytes,
        expected_source_revision=source_revision,
    )
    return EvidenceBundle(verified, json_bytes, markdown_bytes)


def write_evidence_bundle(output_dir: Path, bundle: EvidenceBundle) -> None:
    _require_empty_output_directory(output_dir)
    if type(bundle) is not EvidenceBundle:
        raise RunnerError("w3.output_materialization_failed.v1")
    verify_evidence_bundle(
        bundle.json_bytes,
        bundle.markdown_bytes,
        expected_source_revision=str(bundle.artifact.get("source_revision")),
    )
    created = []
    try:
        for name, content in (
            (EVIDENCE_JSON_FILENAME, bundle.json_bytes),
            (EVIDENCE_MARKDOWN_FILENAME, bundle.markdown_bytes),
        ):
            target = output_dir / name
            with target.open("xb") as stream:
                stream.write(content)
            created.append(target)
    except (OSError, RunnerError):
        for target in created:
            try:
                target.unlink()
            except OSError:
                pass
        raise RunnerError("w3.output_materialization_failed.v1") from None


def run_clean_candidate(output_dir: Path) -> EvidenceBundle:
    revision = clean_candidate_revision()
    before = _source_hashes()
    bundle = execute_bounded_verification(source_revision=revision)
    require_unchanged_source_hashes(before, _source_hashes())
    if clean_candidate_revision() != revision:
        raise RunnerError("w3.source_hash_drift.v1")
    write_evidence_bundle(output_dir, bundle)
    verify_evidence_bundle(
        (output_dir / EVIDENCE_JSON_FILENAME).read_bytes(),
        (output_dir / EVIDENCE_MARKDOWN_FILENAME).read_bytes(),
        expected_source_revision=revision,
    )
    return bundle


def main(argv: Sequence[str] = ()) -> int:
    try:
        output_dir = parse_cli_arguments(argv)
        bundle = run_clean_candidate(output_dir)
    except RunnerError as error:
        print("W3_VERIFICATION_STATUS=ERROR", file=sys.stderr)
        print(f"W3_ERROR_CODE={error.code}", file=sys.stderr)
        return 1
    print("W3_VERIFICATION_STATUS=PASS")
    print(f"SOURCE_REVISION={bundle.artifact['source_revision']}")
    print(f"ARTIFACT_DIGEST={bundle.artifact['artifact_digest']}")
    return 0


__all__ = (
    "EVIDENCE_JSON_FILENAME",
    "EVIDENCE_MARKDOWN_FILENAME",
    "EvidenceBundle",
    "RunnerError",
    "clean_candidate_revision",
    "execute_bounded_verification",
    "main",
    "parse_cli_arguments",
    "render_markdown",
    "require_passing_artifact",
    "require_unchanged_source_hashes",
    "run_clean_candidate",
    "scan_evidence_surfaces",
    "validate_candidate_state",
    "verify_evidence_bundle",
    "write_evidence_bundle",
)
