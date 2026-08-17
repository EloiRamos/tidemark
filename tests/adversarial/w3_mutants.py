"""Closed W3-C mutation catalogue and fresh-child execution harness.

This test-owned module contains only the twelve approved mutations.  Every
mutation is installed in memory in one child process, restored in ``finally``,
and judged by an independently meaningful W3-B or fixed W2 detector.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import MappingProxyType
from typing import Callable, Mapping, Optional, Tuple

from tidemark.evidence.canonical import canonical_json_bytes
from tidemark.verification.w3_contract import (
    MUTANT_CATALOGUE,
    MUTANT_IDS,
    MutantCategory,
    MutantResult,
    OverallStatus,
    adjudicate_mutants,
)


CHILD_RESULT_SCHEMA = "tidemark.w3.mutant-child-result.v1"
CHILD_RESULT_KEYS = (
    "schema_version",
    "mutant_id",
    "activation_probe_passed",
    "detector_ids",
    "result",
    "safe_finding_candidate_id",
    "observation_digest",
)
_MUTATION_RUN_SCHEMA = "tidemark.w3.mutation-run.v1"
_DIGEST_PREFIX = "sha256:"


class MutationHarnessError(ValueError):
    """A closed mutation-harness contract was violated."""


class ChildFaultMode(Enum):
    NONE = "NONE"
    INACTIVE = "INACTIVE"
    CRASH = "CRASH"
    MALFORMED_RESULT = "MALFORMED_RESULT"
    TIMEOUT = "TIMEOUT"
    SURVIVE = "SURVIVE"


@dataclass(frozen=True)
class MutationSpec:
    mutant_id: str
    category: MutantCategory
    detector_ids: Tuple[str, ...]
    expected_result: MutantResult = MutantResult.KILLED


_DETECTOR_SETS = (
    ("W3-DET-D01-EXACT-REPRESENTATION",),
    ("W3-DET-D02-UNISSUED-NOT-TRUSTED",),
    ("W3-DET-D03-CANONICAL-ROUND-TRIP",),
    ("W3-DET-D04-SAFE-DISPLAY-CLOSED",),
    ("W3-DET-D04-SAFE-DISPLAY-CLOSED",),
    ("W3-DET-D04-SAFE-DISPLAY-CLOSED",),
    ("W2-P03-C02-PRE-EXECUTION-APPEND-FAILURE",),
    (
        "W2-P04-C01-SEQUENTIAL-REPLAY",
        "W2-P05-C01-CONCURRENT-REPLAY",
    ),
    ("W3-DET-D05-CORRUPTION-NOT-CLEAN-SUCCESS",),
    (
        "W2-P08-C01-MISSING-TERMINAL-EVIDENCE",
        "W2-P08-C02-CONFLICTING-TERMINAL-EVIDENCE",
        "W2-P08-C03-AMBIGUOUS-EXTERNAL-RESULT",
    ),
    ("W3-DET-CON-001-MINIMUM-STALE-CONSUME",),
    ("W3-DET-CON-002-MINIMUM-NONDURABLE-RECEIPT",),
)

MUTATION_SPECS = tuple(
    MutationSpec(descriptor.mutant_id, descriptor.category, detector_ids)
    for descriptor, detector_ids in zip(MUTANT_CATALOGUE, _DETECTOR_SETS)
)
_SPEC_BY_ID = {spec.mutant_id: spec for spec in MUTATION_SPECS}


@dataclass(frozen=True)
class ChildResult:
    schema_version: str
    mutant_id: str
    activation_probe_passed: bool
    detector_ids: Tuple[str, ...]
    result: MutantResult
    safe_finding_candidate_id: Optional[str]
    observation_digest: str


@dataclass(frozen=True)
class MutationOutcome:
    mutant_id: str
    child_result: ChildResult
    child_result_bytes: bytes
    source_hashes_unchanged: bool
    child_started: bool
    child_instance_token: str
    w3_d_harness_executed: bool = False


@dataclass(frozen=True)
class MutationRun:
    outcomes: Tuple[MutationOutcome, ...]
    child_process_count: int
    executed_serially: bool
    maximum_concurrent_children: int
    killed_count: int
    survived_count: int
    invalid_count: int
    overall_status: OverallStatus


def _spec(mutant_id: object) -> MutationSpec:
    if type(mutant_id) is not str or mutant_id not in _SPEC_BY_ID:
        raise MutationHarnessError("W3_MUTATION_HARNESS: unknown_mutant_id")
    return _SPEC_BY_ID[mutant_id]


def _finding_id(mutant_id: str) -> str:
    return "W3-FIND-" + mutant_id.removeprefix("W3-MUT-")


def _child_primitive(result: ChildResult, *, include_digest: bool) -> dict:
    primitive = {
        "schema_version": result.schema_version,
        "mutant_id": result.mutant_id,
        "activation_probe_passed": result.activation_probe_passed,
        "detector_ids": list(result.detector_ids),
        "result": result.result.value,
        "safe_finding_candidate_id": result.safe_finding_candidate_id,
    }
    if include_digest:
        primitive["observation_digest"] = result.observation_digest
    return primitive


def _observation_digest(result: ChildResult) -> str:
    return _DIGEST_PREFIX + sha256(
        canonical_json_bytes(_child_primitive(result, include_digest=False))
    ).hexdigest()


def _closed_child_result(
    spec: MutationSpec,
    *,
    activated: bool,
    detector_executed: bool,
    violation_observed: bool,
) -> ChildResult:
    if not activated or not detector_executed:
        result = MutantResult.INVALID
    elif violation_observed:
        result = MutantResult.KILLED
    else:
        result = MutantResult.SURVIVED
    finding = _finding_id(spec.mutant_id) if result is MutantResult.SURVIVED else None
    candidate = ChildResult(
        schema_version=CHILD_RESULT_SCHEMA,
        mutant_id=spec.mutant_id,
        activation_probe_passed=activated,
        detector_ids=spec.detector_ids,
        result=result,
        safe_finding_candidate_id=finding,
        observation_digest="",
    )
    return replace(candidate, observation_digest=_observation_digest(candidate))


def _invalid_child_result(spec: MutationSpec) -> ChildResult:
    return _closed_child_result(
        spec,
        activated=False,
        detector_executed=False,
        violation_observed=False,
    )


def _validate_child_result(result: object) -> ChildResult:
    if type(result) is not ChildResult:
        raise MutationHarnessError("W3_MUTATION_HARNESS: child_result_type")
    spec = _spec(result.mutant_id)
    if result.schema_version != CHILD_RESULT_SCHEMA:
        raise MutationHarnessError("W3_MUTATION_HARNESS: child_schema")
    if type(result.activation_probe_passed) is not bool:
        raise MutationHarnessError("W3_MUTATION_HARNESS: activation_type")
    if result.detector_ids != spec.detector_ids:
        raise MutationHarnessError("W3_MUTATION_HARNESS: detector_mapping")
    if type(result.result) is not MutantResult:
        raise MutationHarnessError("W3_MUTATION_HARNESS: result_vocabulary")
    expected_finding = (
        _finding_id(result.mutant_id)
        if result.result is MutantResult.SURVIVED
        else None
    )
    if result.safe_finding_candidate_id != expected_finding:
        raise MutationHarnessError("W3_MUTATION_HARNESS: finding_contract")
    if result.result in (MutantResult.KILLED, MutantResult.SURVIVED) and not (
        result.activation_probe_passed
    ):
        raise MutationHarnessError("W3_MUTATION_HARNESS: inactive_valid_result")
    if result.observation_digest != _observation_digest(result):
        raise MutationHarnessError("W3_MUTATION_HARNESS: digest_mismatch")
    return result


def serialize_child_result(result: ChildResult) -> bytes:
    validated = _validate_child_result(result)
    return canonical_json_bytes(_child_primitive(validated, include_digest=True))


def _closed_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise MutationHarnessError("W3_MUTATION_HARNESS: duplicate_key")
        result[key] = value
    return result


def parse_child_result(encoded: bytes) -> ChildResult:
    if type(encoded) is not bytes or not encoded or encoded.endswith(b"\n"):
        raise MutationHarnessError("W3_MUTATION_HARNESS: child_bytes")
    try:
        primitive = json.loads(encoded.decode("utf-8"), object_pairs_hook=_closed_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MutationHarnessError("W3_MUTATION_HARNESS: malformed_child_json") from exc
    if type(primitive) is not dict or tuple(sorted(primitive)) != tuple(
        sorted(CHILD_RESULT_KEYS)
    ):
        raise MutationHarnessError("W3_MUTATION_HARNESS: child_keys")
    if canonical_json_bytes(primitive) != encoded:
        raise MutationHarnessError("W3_MUTATION_HARNESS: noncanonical_child_json")
    try:
        if type(primitive["detector_ids"]) is not list or any(
            type(value) is not str for value in primitive["detector_ids"]
        ):
            raise MutationHarnessError("W3_MUTATION_HARNESS: detector_ids")
        result = ChildResult(
            schema_version=primitive["schema_version"],
            mutant_id=primitive["mutant_id"],
            activation_probe_passed=primitive["activation_probe_passed"],
            detector_ids=tuple(primitive["detector_ids"]),
            result=MutantResult(primitive["result"]),
            safe_finding_candidate_id=primitive["safe_finding_candidate_id"],
            observation_digest=primitive["observation_digest"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise MutationHarnessError("W3_MUTATION_HARNESS: child_values") from exc
    return _validate_child_result(result)


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _source_hashes() -> Tuple[Tuple[str, str], ...]:
    repository = _repository_root()
    source_root = repository / "src" / "tidemark"
    paths = tuple(sorted(source_root.rglob("*.py"))) + (
        repository / "scripts" / "verify_gemini_live.py",
        repository / "tests" / "adversarial" / "test_w3_contract.py",
        repository / "tests" / "adversarial" / "w3_detectors.py",
        repository / "tests" / "adversarial" / "test_w3_property_domains.py",
        repository / "tests" / "adversarial" / "w3_mutants.py",
        repository / "tests" / "adversarial" / "test_w3_mutation_adequacy.py",
    )
    return tuple(
        (
            path.relative_to(repository).as_posix(),
            sha256(path.read_bytes()).hexdigest(),
        )
        for path in paths
    )


def _expected_observation(fixture_id: str):
    from tidemark.proofs.catalogue import PROOF_CATALOGUE

    for property_definition in PROOF_CATALOGUE:
        for fixture in property_definition.fixtures:
            if fixture.fixture_id == fixture_id:
                return fixture.expected_observation
    raise MutationHarnessError("W3_MUTATION_HARNESS: unknown_fixed_fixture")


def _execute_fixture(fixture_id: str, workspace: Path):
    from tidemark.proofs.fixtures import execute_proof_fixture

    return execute_proof_fixture(fixture_id, workspace / fixture_id)


def _mutate_rep_001(workspace: Path) -> Tuple[bool, bool, bool]:
    from tidemark.runtime import constraint_registry as registry
    from tidemark.runtime.constraint_registry import _ConstraintOperand
    from tidemark.runtime.vocabulary import ConstraintId
    from w3_detectors import DetectorStatus, run_d01_detector

    original = registry._IMPLEMENTATIONS
    trusted = original[ConstraintId.PROTECTED_REFERENCE_REQUIRED]

    def corrupted(operand):
        if type(operand.value) is str:
            return True
        return trusted.behavior(operand)

    replacement = dict(original)
    replacement[ConstraintId.PROTECTED_REFERENCE_REQUIRED] = replace(
        trusted, behavior=corrupted
    )
    activation = False
    try:
        registry._IMPLEMENTATIONS = MappingProxyType(replacement)
        activation = registry.TRUSTED_CONSTRAINT_REGISTRY._evaluate(
            ConstraintId.PROTECTED_REFERENCE_REQUIRED,
            _ConstraintOperand(value="closed-probe"),
        ) is True
        detected, _ = run_d01_detector(workspace / "d01", run_index=0)
        return activation, True, detected.status is DetectorStatus.FAIL
    finally:
        registry._IMPLEMENTATIONS = original


def _mutate_rep_002(workspace: Path) -> Tuple[bool, bool, bool]:
    from tidemark.runtime.policy_engine import ResolutionFailure, Resolved
    from tidemark.runtime.reference_resolver import ReferenceResolver
    from w3_detectors import DetectorStatus, run_d02_detector

    original = ReferenceResolver.resolve
    cached = []
    activations = []

    def corrupted(self, request, trusted_store):
        result = original(self, request, trusted_store)
        if type(result) is Resolved:
            cached[:] = [result]
        elif (
            type(result) is ResolutionFailure
            and request.reference_id.value.startswith("ref_")
            and cached
        ):
            activations.append(True)
            return cached[0]
        return result

    try:
        ReferenceResolver.resolve = corrupted
        detected, _ = run_d02_detector(workspace / "d02", run_index=0)
        return bool(activations), True, detected.status is DetectorStatus.FAIL
    finally:
        ReferenceResolver.resolve = original


def _mutate_rep_003(workspace: Path) -> Tuple[bool, bool, bool]:
    import w3_detectors
    from w3_detectors import DetectorStatus

    original = w3_detectors.canonical_json_bytes
    activations = []

    def corrupted(value, trailing_newline=False):
        if type(value) is dict:
            activations.append(True)
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=False,
        ).encode("utf-8")
        return encoded + (b"\n" if trailing_newline else b"")

    try:
        w3_detectors.canonical_json_bytes = corrupted
        detected, _ = w3_detectors.run_d03_detector()
        return bool(activations), True, detected.status is DetectorStatus.FAIL
    finally:
        w3_detectors.canonical_json_bytes = original


def _mutate_projection(
    workspace: Path,
    selector: Callable[[str], bool],
) -> Tuple[bool, bool, bool]:
    from tidemark.evidence import projection
    from w3_detectors import DetectorStatus, run_d04_detector

    original = projection._safe_display
    activations = []

    def corrupted(value):
        if type(value) is str and selector(value):
            activations.append(True)
            return value
        return original(value)

    try:
        projection._safe_display = corrupted
        detected, _ = run_d04_detector(workspace / "d04", run_index=0)
        return bool(activations), True, detected.status is DetectorStatus.FAIL
    finally:
        projection._safe_display = original


def _mutate_proj_001(workspace: Path) -> Tuple[bool, bool, bool]:
    return _mutate_projection(workspace, lambda value: value == "arbitrary-unknown-value")


def _mutate_proj_002(workspace: Path) -> Tuple[bool, bool, bool]:
    return _mutate_projection(workspace, lambda value: value.startswith("ref_"))


def _mutate_proj_003(workspace: Path) -> Tuple[bool, bool, bool]:
    return _mutate_projection(
        workspace,
        lambda value: "<" in value or any(ord(character) < 32 for character in value),
    )


def _mutate_ord_001(workspace: Path) -> Tuple[bool, bool, bool]:
    from tidemark.runtime import execution_gate
    from tidemark.runtime.execution_binding import _RuntimePrivateExecutionBinding

    fixture_id = "W2-P03-C02-pre-execution-append-failure"
    original = execution_gate.ExecutionGate.execute
    activations = []

    def corrupted(self, prepared_call):
        binding = execution_gate._validate_runtime_execution_binding(prepared_call)
        if type(binding) is _RuntimePrivateExecutionBinding:
            outcome = execution_gate._atomic_consume_runtime_execution_binding(
                prepared_call, binding
            )
            if outcome == "CONSUMED":
                activations.append(True)
        return original(self, prepared_call)

    try:
        execution_gate.ExecutionGate.execute = corrupted
        observed = _execute_fixture(fixture_id, workspace)
        return bool(activations), True, observed != _expected_observation(fixture_id)
    finally:
        execution_gate.ExecutionGate.execute = original


def _mutate_ord_002(workspace: Path) -> Tuple[bool, bool, bool]:
    from tidemark.runtime import execution_gate

    fixture_ids = (
        "W2-P04-C01-sequential-replay",
        "W2-P05-C01-concurrent-replay",
    )
    original = execution_gate._atomic_consume_runtime_execution_binding
    activations = []

    def corrupted(prepared_call, binding):
        activations.append(True)
        return "CONSUMED"

    try:
        execution_gate._atomic_consume_runtime_execution_binding = corrupted
        observations = tuple(
            _execute_fixture(fixture_id, workspace) for fixture_id in fixture_ids
        )
        violation = any(
            observed != _expected_observation(fixture_id)
            for fixture_id, observed in zip(fixture_ids, observations)
        )
        return bool(activations), True, violation
    finally:
        execution_gate._atomic_consume_runtime_execution_binding = original


def _mutate_evid_001(workspace: Path) -> Tuple[bool, bool, bool]:
    from tidemark.evidence.projection import (
        EvidenceCompleteness,
        EvidenceProjector,
        ProjectionStatus,
    )
    from w3_detectors import DetectorStatus, run_d05_detector

    original = EvidenceProjector.project
    activations = []

    def corrupted(self, event_stream, masking_profile=None):
        if masking_profile is None:
            projected = original(self, event_stream)
        else:
            projected = original(self, event_stream, masking_profile)
        if projected.findings:
            activations.append(True)
            return replace(
                projected,
                integrity_status=ProjectionStatus.CLEAN,
                reconciliation_status=ProjectionStatus.CLEAN,
                evidence_completeness=EvidenceCompleteness.COMPLETE,
            )
        return projected

    try:
        EvidenceProjector.project = corrupted
        detected, _ = run_d05_detector(workspace / "d05", run_index=0)
        return bool(activations), True, detected.status is DetectorStatus.FAIL
    finally:
        EvidenceProjector.project = original


def _mutate_evid_002(workspace: Path) -> Tuple[bool, bool, bool]:
    from tidemark.proofs import runner as proof_runner
    from tidemark.proofs.catalogue import PROOF_CATALOGUE
    from tidemark.proofs.fixtures import EVIDENCE_PROOF_FIXTURE_IDS
    from tidemark.proofs.model import (
        ProofProvenance,
        ProofStatus,
        adjudicate_suite,
    )

    original = proof_runner.execute_proof_fixture
    activations = []

    def corrupted(fixture_id, workspace_root):
        observed = original(fixture_id, workspace_root)
        if fixture_id in EVIDENCE_PROOF_FIXTURE_IDS:
            activations.append(True)
            return replace(
                observed,
                evidence_success_claimed=True,
                external_effect_absence_claimed=True,
            )
        return observed

    try:
        proof_runner.execute_proof_fixture = corrupted
        observations = tuple(
            proof_runner.execute_proof_fixture(
                fixture_id, workspace / fixture_id
            )
            for fixture_id in EVIDENCE_PROOF_FIXTURE_IDS
        )
        suite = adjudicate_suite(
            catalogue=PROOF_CATALOGUE,
            selected_property_ids=("W2-P08",),
            observed_by_property=(("W2-P08", observations),),
            provenance=ProofProvenance(
                provenance_class="CLEAN_COMMITTED_LOCAL_SOURCE",
                source_revision="a" * 40,
                live_model_calls_performed=0,
                google_cloud_accessed=False,
            ),
        )
        violation = (
            suite.suite_status is ProofStatus.FAIL
            and all(item.evidence_success_claimed is True for item in observations)
            and all(
                item.external_effect_absence_claimed is True for item in observations
            )
        )
        return len(activations) == 3, True, violation
    finally:
        proof_runner.execute_proof_fixture = original


def _mutate_con_001(workspace: Path) -> Tuple[bool, bool, bool]:
    from tidemark.runtime import execution_gate

    fixture_id = "W2-P04-C01-sequential-replay"
    original = execution_gate._atomic_consume_runtime_execution_binding
    activations = []

    def corrupted(prepared_call, binding):
        outcome = original(prepared_call, binding)
        if outcome == "REPLAY":
            activations.append(True)
            return "CONSUMED"
        return outcome

    try:
        execution_gate._atomic_consume_runtime_execution_binding = corrupted
        observed = _execute_fixture(fixture_id, workspace)
        return bool(activations), True, observed != _expected_observation(fixture_id)
    finally:
        execution_gate._atomic_consume_runtime_execution_binding = original


def _mutate_con_002(workspace: Path) -> Tuple[bool, bool, bool]:
    from tidemark.runtime.minimal_evidence import (
        DurableAppendReceipt,
        MinimalPreExecutionEvidenceSink,
    )

    fixture_id = "W2-P03-C02-pre-execution-append-failure"
    original = MinimalPreExecutionEvidenceSink.append_pre_execution
    activations = []

    def corrupted(self, record):
        try:
            result = original(self, record)
        except Exception:
            result = None
        if type(result) is not DurableAppendReceipt:
            activations.append(True)
            return DurableAppendReceipt(
                schema_version=record.schema_version,
                record_id=record.record_id,
                record_kind="pre_execution_correlation",
                durable_at=datetime.now(timezone.utc),
            )
        return result

    try:
        MinimalPreExecutionEvidenceSink.append_pre_execution = corrupted
        observed = _execute_fixture(fixture_id, workspace)
        return bool(activations), True, observed != _expected_observation(fixture_id)
    finally:
        MinimalPreExecutionEvidenceSink.append_pre_execution = original


_MUTATION_EXECUTORS: Mapping[str, Callable[[Path], Tuple[bool, bool, bool]]] = {
    "W3-MUT-REP-001": _mutate_rep_001,
    "W3-MUT-REP-002": _mutate_rep_002,
    "W3-MUT-REP-003": _mutate_rep_003,
    "W3-MUT-PROJ-001": _mutate_proj_001,
    "W3-MUT-PROJ-002": _mutate_proj_002,
    "W3-MUT-PROJ-003": _mutate_proj_003,
    "W3-MUT-ORD-001": _mutate_ord_001,
    "W3-MUT-ORD-002": _mutate_ord_002,
    "W3-MUT-EVID-001": _mutate_evid_001,
    "W3-MUT-EVID-002": _mutate_evid_002,
    "W3-MUT-CON-001": _mutate_con_001,
    "W3-MUT-CON-002": _mutate_con_002,
}


def _execute_in_child(
    spec: MutationSpec,
    fault_mode: ChildFaultMode,
    workspace: Path,
) -> ChildResult:
    if fault_mode is ChildFaultMode.INACTIVE:
        return _invalid_child_result(spec)
    if fault_mode is ChildFaultMode.SURVIVE:
        return _closed_child_result(
            spec,
            activated=True,
            detector_executed=True,
            violation_observed=False,
        )
    before = _source_hashes()
    try:
        activated, detector_executed, violation = _MUTATION_EXECUTORS[
            spec.mutant_id
        ](workspace)
    except Exception:
        activated, detector_executed, violation = False, False, False
    after = _source_hashes()
    if before != after:
        return _invalid_child_result(spec)
    return _closed_child_result(
        spec,
        activated=activated,
        detector_executed=detector_executed,
        violation_observed=violation,
    )


def _child_main() -> int:
    try:
        spec = _spec(os.environ.get("W3_MUTANT_ID"))
        fault_mode = ChildFaultMode(os.environ.get("W3_FAULT_MODE", "NONE"))
        workspace = Path(os.environ["W3_CHILD_WORKSPACE"])
        if fault_mode is ChildFaultMode.CRASH:
            return 70
        if fault_mode is ChildFaultMode.MALFORMED_RESULT:
            sys.stdout.buffer.write(b"{}")
            return 0
        if fault_mode is ChildFaultMode.TIMEOUT:
            time.sleep(5)
            return 0
        result = _execute_in_child(spec, fault_mode, workspace)
        sys.stdout.buffer.write(serialize_child_result(result))
        return 0
    except Exception:
        return 71


def run_mutant_by_id(
    mutant_id: str,
    *,
    timeout_seconds: float = 10.0,
    fault_mode: ChildFaultMode = ChildFaultMode.NONE,
    child_instance_token: str = "child-instance-01",
) -> MutationOutcome:
    spec = _spec(mutant_id)
    if type(timeout_seconds) not in (int, float) or timeout_seconds <= 0:
        raise MutationHarnessError("W3_MUTATION_HARNESS: invalid_timeout")
    if type(fault_mode) is not ChildFaultMode:
        raise MutationHarnessError("W3_MUTATION_HARNESS: fault_mode")
    if type(child_instance_token) is not str or not child_instance_token:
        raise MutationHarnessError("W3_MUTATION_HARNESS: child_token")

    before = _source_hashes()
    child_started = False
    parsed = None
    with tempfile.TemporaryDirectory(prefix="tidemark-w3-c-") as temporary:
        env = {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": os.pathsep.join(
                (
                    str(_repository_root() / "src"),
                    str(_repository_root() / "tests" / "adversarial"),
                )
            ),
            "W3_MUTANT_ID": spec.mutant_id,
            "W3_FAULT_MODE": fault_mode.value,
            "W3_CHILD_WORKSPACE": str(Path(temporary) / "workspace"),
        }
        try:
            child_started = True
            completed = subprocess.run(
                (sys.executable, str(Path(__file__).resolve()), "--child"),
                cwd=str(_repository_root()),
                env=env,
                capture_output=True,
                check=False,
                timeout=float(timeout_seconds),
            )
            if completed.returncode == 0 and completed.stderr == b"":
                parsed = parse_child_result(completed.stdout)
        except (subprocess.TimeoutExpired, MutationHarnessError, OSError):
            parsed = None
    after = _source_hashes()
    unchanged = before == after
    if parsed is None or not unchanged:
        parsed = _invalid_child_result(spec)
    encoded = serialize_child_result(parsed)
    return MutationOutcome(
        mutant_id=spec.mutant_id,
        child_result=parsed,
        child_result_bytes=encoded,
        source_hashes_unchanged=unchanged,
        child_started=child_started,
        child_instance_token=child_instance_token,
        w3_d_harness_executed=False,
    )


def run_mutation_catalogue(*, timeout_seconds: float = 10.0) -> MutationRun:
    outcomes = tuple(
        run_mutant_by_id(
            mutant_id,
            timeout_seconds=timeout_seconds,
            child_instance_token=f"child-instance-{index:02d}",
        )
        for index, mutant_id in enumerate(MUTANT_IDS, 1)
    )
    adjudication = adjudicate_mutants(
        tuple(outcome.child_result.result for outcome in outcomes)
    )
    return MutationRun(
        outcomes=outcomes,
        child_process_count=len(outcomes),
        executed_serially=True,
        maximum_concurrent_children=1,
        killed_count=adjudication.killed_count,
        survived_count=adjudication.survived_count,
        invalid_count=adjudication.invalid_count,
        overall_status=adjudication.overall_status,
    )


def serialize_mutation_run(run: MutationRun) -> bytes:
    if type(run) is not MutationRun or tuple(
        outcome.mutant_id for outcome in run.outcomes
    ) != MUTANT_IDS:
        raise MutationHarnessError("W3_MUTATION_HARNESS: mutation_run_order")
    primitive = {
        "schema_version": _MUTATION_RUN_SCHEMA,
        "child_process_count": run.child_process_count,
        "executed_serially": run.executed_serially,
        "maximum_concurrent_children": run.maximum_concurrent_children,
        "outcomes": [
            _child_primitive(outcome.child_result, include_digest=True)
            for outcome in run.outcomes
        ],
        "summary": {
            "killed_count": run.killed_count,
            "survived_count": run.survived_count,
            "invalid_count": run.invalid_count,
            "overall_status": run.overall_status.value,
        },
    }
    return canonical_json_bytes(primitive)


if __name__ == "__main__" and sys.argv[1:] == ["--child"]:
    raise SystemExit(_child_main())
