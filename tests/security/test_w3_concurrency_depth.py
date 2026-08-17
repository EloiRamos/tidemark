"""W3-D tests for the two fixed deterministic concurrency shapes."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from hashlib import sha256
import inspect
import json
from pathlib import Path
from threading import Event, Thread, local
from typing import Optional, Tuple

import pytest

from tidemark.evidence.canonical import canonical_json_bytes
from tidemark.verification.w3_contract import (
    CONCURRENCY_REPETITIONS_PER_SHAPE,
    CONCURRENCY_SHAPE_COUNT,
    CONCURRENCY_SHAPES,
)


EXPECTED_RESULT_KEYS = (
    "shape_id",
    "repetition_index",
    "decision_counts",
    "prepared_call_count",
    "execution_status_counts",
    "adapter_entry_count",
    "payment_count",
    "reference_state",
    "capability_states",
    "durable_pre_execution_record_count",
    "overall_status",
    "detector_ids",
    "timeout_or_deadlock",
    "source_hashes_unchanged",
    "shape_facts",
    "observation_digest",
)


@pytest.fixture(scope="module")
def w3_d_run(tmp_path_factory):
    return run_w3_d(tmp_path_factory.mktemp("w3-d-concurrency"))


def test_concurrency_contract_has_exact_two_ordered_shapes_and_three_runs() -> None:
    assert CONCURRENCY_SHAPE_COUNT == 2
    assert CONCURRENCY_SHAPES == ("W3-C01", "W3-C02")
    assert CONCURRENCY_REPETITIONS_PER_SHAPE == 3


def test_materialization_has_only_six_ordered_fresh_runs(w3_d_run) -> None:
    assert w3_d_run.shape_count == 2
    assert w3_d_run.repetitions_per_shape == 3
    assert w3_d_run.total_run_count == 6
    assert tuple(
        (result.shape_id, result.repetition_index) for result in w3_d_run.results
    ) == tuple(
        (shape_id, repetition)
        for shape_id in CONCURRENCY_SHAPES
        for repetition in range(3)
    )


def test_c01_exact_stale_preparation_and_replay_semantics(w3_d_run) -> None:
    results = tuple(
        result for result in w3_d_run.results if result.shape_id == "W3-C01"
    )
    assert len(results) == 3
    for result in results:
        assert result.decision_counts == (
            ("ALLOW", 2),
            ("DENY", 0),
            ("REFUSAL", 0),
        )
        assert result.prepared_call_count == 2
        assert result.execution_status_counts == (
            ("REFUSED", 0),
            ("COMPLETED", 1),
            ("FAILED", 0),
            ("REPLAY_REJECTED", 1),
        )
        assert result.adapter_entry_count == 1
        assert result.payment_count == 1
        assert result.reference_state == "CONSUMED"
        assert result.capability_states == (
            ("winner", "CONSUMED"),
            ("stale_contender", "UNUSED"),
        )
        assert result.durable_pre_execution_record_count == 2
        assert result.fact("external_effect_count") == 1
        assert result.fact("losing_contender_status") == "REPLAY_REJECTED"
        assert result.overall_status is ConcurrencyRunStatus.PASS


def test_c02_exact_failed_append_then_valid_contender_semantics(w3_d_run) -> None:
    results = tuple(
        result for result in w3_d_run.results if result.shape_id == "W3-C02"
    )
    assert len(results) == 3
    for result in results:
        assert result.decision_counts == (
            ("ALLOW", 2),
            ("DENY", 0),
            ("REFUSAL", 0),
        )
        assert result.prepared_call_count == 2
        assert result.execution_status_counts == (
            ("REFUSED", 1),
            ("COMPLETED", 1),
            ("FAILED", 0),
            ("REPLAY_REJECTED", 0),
        )
        assert result.adapter_entry_count == 1
        assert result.payment_count == 1
        assert result.reference_state == "CONSUMED"
        assert result.capability_states == (
            ("failed_contender", "UNUSED"),
            ("successful_contender", "CONSUMED"),
        )
        assert result.durable_pre_execution_record_count == 1
        assert result.fact("failed_contender_append_failure") is True
        assert result.fact("failed_contender_consumed") is False
        assert result.fact("successful_contender_append_success") is True
        assert result.fact("successful_contender_consumed") is True
        assert result.fact("external_effect_count") == 1
        assert result.overall_status is ConcurrencyRunStatus.PASS


def test_explicit_synchronization_has_no_sleep_or_scheduler_or_retry_oracle(
    w3_d_run,
) -> None:
    implementation = inspect.getsource(_run_c01) + inspect.getsource(_run_c02)
    assert "Event(" in implementation
    assert ".sleep(" not in implementation
    assert all(result.fact("explicit_synchronization_used") for result in w3_d_run.results)
    assert all(
        result.fact("sleep_based_scheduling_used") is False
        for result in w3_d_run.results
    )
    assert all(
        result.fact("retry_until_green_used") is False for result in w3_d_run.results
    )
    assert all(result.timeout_or_deadlock is False for result in w3_d_run.results)


def test_timeout_is_fail_closed_and_never_retried() -> None:
    with pytest.raises(
        ConcurrencyHarnessError,
        match="w3.concurrency_timeout_or_deadlock.v1",
    ):
        _wait_for_event(Event(), timeout_seconds=0.001)


def test_repetitions_have_identical_normalized_state_and_result_bytes(
    w3_d_run,
) -> None:
    for shape_id in CONCURRENCY_SHAPES:
        results = tuple(
            result for result in w3_d_run.results if result.shape_id == shape_id
        )
        assert len({normalized_concurrency_result_bytes(item) for item in results}) == 1
        assert len({item.observation_digest for item in results}) == 1


def test_closed_results_are_canonical_safe_and_exclude_dynamic_identity(
    w3_d_run,
) -> None:
    forbidden = (
        b"synthetic-routing://",
        b"ref_",
        b"RuntimePrivateExecutionBinding",
        b"private_authenticator",
        b"/Users/",
        b"/private/",
        b"hostname",
        b"thread_id",
        b"thread_name",
        b"timestamp",
        b"provider",
        b"raw_prompt",
    )
    for result in w3_d_run.results:
        primitive = result.to_primitive()
        assert tuple(primitive) == EXPECTED_RESULT_KEYS
        encoded = serialize_concurrency_result(result)
        assert not encoded.endswith(b"\n")
        assert encoded == canonical_json_bytes(json.loads(encoded.decode("utf-8")))
        assert all(value not in encoded for value in forbidden)


def test_no_stronger_exactly_once_or_fairness_claim_is_made(w3_d_run) -> None:
    for result in w3_d_run.results:
        assert result.fact("distributed_exactly_once_claimed") is False
        assert result.fact("external_effect_exactly_once_claimed") is False
        assert result.fact("global_scheduler_fairness_claimed") is False


def test_all_six_runs_pass_and_source_hashes_remain_unchanged(w3_d_run) -> None:
    assert w3_d_run.overall_status is ConcurrencyRunStatus.PASS
    assert all(
        result.overall_status is ConcurrencyRunStatus.PASS
        for result in w3_d_run.results
    )
    assert all(result.source_hashes_unchanged for result in w3_d_run.results)


_EVENT_TIMEOUT_SECONDS = 2.0
_JOIN_TIMEOUT_SECONDS = 5.0
_TIMEOUT_CODE = "w3.concurrency_timeout_or_deadlock.v1"
_DECISION_KEYS = ("ALLOW", "DENY", "REFUSAL")
_EXECUTION_KEYS = ("REFUSED", "COMPLETED", "FAILED", "REPLAY_REJECTED")
_C01_DETECTORS = ("W3-DET-C01-STALE-PREPARATION-CURRENT-STATE-VETO",)
_C02_DETECTORS = ("W3-DET-C02-FAILED-APPEND-PRESERVES-AUTHORITY",)


class ConcurrencyHarnessError(RuntimeError):
    """A deterministic W3-D synchronization or closed-result gate failed."""


class ConcurrencyRunStatus(Enum):
    PASS = "PASS"
    ERROR = "ERROR"


@dataclass(frozen=True)
class ConcurrencyResult:
    shape_id: str
    repetition_index: int
    decision_counts: Tuple[Tuple[str, int], ...]
    prepared_call_count: int
    execution_status_counts: Tuple[Tuple[str, int], ...]
    adapter_entry_count: int
    payment_count: int
    reference_state: str
    capability_states: Tuple[Tuple[str, str], ...]
    durable_pre_execution_record_count: int
    overall_status: ConcurrencyRunStatus
    detector_ids: Tuple[str, ...]
    timeout_or_deadlock: bool
    source_hashes_unchanged: bool
    shape_facts: Tuple[Tuple[str, object], ...]
    observation_digest: str

    def fact(self, name: str) -> object:
        for key, value in self.shape_facts:
            if key == name:
                return value
        raise KeyError(name)

    def to_primitive(self) -> dict:
        return _result_primitive(self, normalized=False, include_digest=True)


@dataclass(frozen=True)
class W3DRun:
    results: Tuple[ConcurrencyResult, ...]
    shape_count: int
    repetitions_per_shape: int
    total_run_count: int
    overall_status: ConcurrencyRunStatus


def _wait_for_event(event: Event, *, timeout_seconds: float) -> None:
    if type(event) is not Event or type(timeout_seconds) not in (int, float):
        raise TypeError("closed event wait requires Event and numeric timeout")
    if timeout_seconds <= 0 or not event.wait(timeout=timeout_seconds):
        raise ConcurrencyHarnessError(_TIMEOUT_CODE)


def _join_thread(thread: Thread) -> None:
    thread.join(timeout=_JOIN_TIMEOUT_SECONDS)
    if thread.is_alive():
        raise ConcurrencyHarnessError(_TIMEOUT_CODE)


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
        repository / "tests" / "security" / "test_w3_concurrency_depth.py",
    )
    return tuple(
        (
            path.relative_to(repository).as_posix(),
            sha256(path.read_bytes()).hexdigest(),
        )
        for path in paths
    )


def _result_primitive(
    result: ConcurrencyResult,
    *,
    normalized: bool,
    include_digest: bool,
) -> dict:
    primitive = {
        "shape_id": result.shape_id,
        "repetition_index": 0 if normalized else result.repetition_index,
        "decision_counts": dict(result.decision_counts),
        "prepared_call_count": result.prepared_call_count,
        "execution_status_counts": dict(result.execution_status_counts),
        "adapter_entry_count": result.adapter_entry_count,
        "payment_count": result.payment_count,
        "reference_state": result.reference_state,
        "capability_states": dict(result.capability_states),
        "durable_pre_execution_record_count": (
            result.durable_pre_execution_record_count
        ),
        "overall_status": result.overall_status.value,
        "detector_ids": list(result.detector_ids),
        "timeout_or_deadlock": result.timeout_or_deadlock,
        "source_hashes_unchanged": result.source_hashes_unchanged,
        "shape_facts": dict(result.shape_facts),
    }
    if include_digest:
        primitive["observation_digest"] = result.observation_digest
    return primitive


def _observation_digest(result: ConcurrencyResult) -> str:
    primitive = _result_primitive(result, normalized=True, include_digest=False)
    return "sha256:" + sha256(canonical_json_bytes(primitive)).hexdigest()


def _complete_result(result: ConcurrencyResult) -> ConcurrencyResult:
    return replace(result, observation_digest=_observation_digest(result))


def serialize_concurrency_result(result: ConcurrencyResult) -> bytes:
    if type(result) is not ConcurrencyResult:
        raise ConcurrencyHarnessError("w3.concurrency_result_invalid.v1")
    if result.observation_digest != _observation_digest(result):
        raise ConcurrencyHarnessError("w3.concurrency_digest_invalid.v1")
    return canonical_json_bytes(result.to_primitive())


def normalized_concurrency_result_bytes(result: ConcurrencyResult) -> bytes:
    if result.observation_digest != _observation_digest(result):
        raise ConcurrencyHarnessError("w3.concurrency_digest_invalid.v1")
    return canonical_json_bytes(
        _result_primitive(result, normalized=True, include_digest=True)
    )


def _decision_counts(preparations: Tuple[object, ...]) -> Tuple[Tuple[str, int], ...]:
    from tidemark.runtime.prepared_call import PreparationRefusal, PreparedToolCall
    from tidemark.runtime.vocabulary import DecisionOutcome

    counts = {key: 0 for key in _DECISION_KEYS}
    for preparation in preparations:
        if type(preparation) is PreparedToolCall:
            counts["ALLOW"] += 1
        elif type(preparation) is PreparationRefusal:
            counts[preparation.decision.outcome.value] += 1
    return tuple((key, counts[key]) for key in _DECISION_KEYS)


def _execution_counts(outcomes: Tuple[object, ...]) -> Tuple[Tuple[str, int], ...]:
    from tidemark.runtime.execution_gate import ExecutionResult

    return tuple(
        (
            key,
            sum(
                type(outcome) is ExecutionResult and outcome.status.value == key
                for outcome in outcomes
            ),
        )
        for key in _EXECUTION_KEYS
    )


def _capability_state(preparation: object) -> str:
    from tidemark.runtime.execution_binding import _lookup_runtime_execution_binding
    from tidemark.runtime.prepared_call import PreparedToolCall

    if type(preparation) is not PreparedToolCall:
        return "NOT_PREPARED"
    binding = _lookup_runtime_execution_binding(preparation.prepared_call_id)
    state = getattr(binding, "_capability_state", None)
    return getattr(state, "value", "MISSING")


def _reference_state(fixture) -> str:
    metadata = fixture.reference_metadata()
    return "CONSUMED" if metadata.consumed else "UNCONSUMED"


def _base_shape_facts() -> Tuple[Tuple[str, object], ...]:
    return (
        ("explicit_synchronization_used", True),
        ("sleep_based_scheduling_used", False),
        ("retry_until_green_used", False),
        ("distributed_exactly_once_claimed", False),
        ("external_effect_exactly_once_claimed", False),
        ("global_scheduler_fairness_claimed", False),
    )


def _run_c01(root: Path, repetition_index: int) -> ConcurrencyResult:
    from tidemark.payment.fixtures import build_synthetic_payment_fixture
    from tidemark.runtime.policy_engine import Resolved
    from tidemark.runtime.prepared_call import PreparedToolCall
    from tidemark.runtime.reference_resolver import ReferenceResolver
    from tidemark.runtime.vocabulary import ExecutionOutcome

    before = _source_hashes()
    fixture = build_synthetic_payment_fixture(
        str(root), correlation_namespace=f"w3d-c01-{repetition_index}"
    )
    prepared_a = fixture.prepare(fixture.canonical_call())
    if type(prepared_a) is not PreparedToolCall:
        raise ConcurrencyHarnessError("w3.concurrency_contract_drift.v1")

    b_resolved = Event()
    release_b = Event()
    actor = local()
    original_resolve = ReferenceResolver.resolve
    thread_errors = []
    observed = {}

    def resolving_with_pause(self, request, trusted_store):
        result = original_resolve(self, request, trusted_store)
        if getattr(actor, "role", None) == "stale_contender":
            if type(result) is not Resolved:
                thread_errors.append(True)
            b_resolved.set()
            _wait_for_event(release_b, timeout_seconds=_EVENT_TIMEOUT_SECONDS)
        return result

    def stale_contender() -> None:
        actor.role = "stale_contender"
        try:
            prepared = fixture.prepare(fixture.canonical_call())
            observed["prepared"] = prepared
            if type(prepared) is PreparedToolCall:
                observed["execution"] = fixture.execution_gate.execute(prepared)
        except Exception:
            thread_errors.append(True)

    contender = Thread(target=stale_contender)
    started = False
    try:
        ReferenceResolver.resolve = resolving_with_pause
        contender.start()
        started = True
        _wait_for_event(b_resolved, timeout_seconds=_EVENT_TIMEOUT_SECONDS)
        outcome_a = fixture.execution_gate.execute(prepared_a)
        release_b.set()
        _join_thread(contender)
    finally:
        release_b.set()
        if started and contender.is_alive():
            contender.join(timeout=_JOIN_TIMEOUT_SECONDS)
        ReferenceResolver.resolve = original_resolve

    if contender.is_alive() or thread_errors:
        raise ConcurrencyHarnessError(_TIMEOUT_CODE)
    prepared_b = observed.get("prepared")
    outcome_b = observed.get("execution")
    preparations = (prepared_a, prepared_b)
    outcomes = (outcome_a, outcome_b)
    decision_counts = _decision_counts(preparations)
    execution_counts = _execution_counts(outcomes)
    capability_states = (
        ("winner", _capability_state(prepared_a)),
        ("stale_contender", _capability_state(prepared_b)),
    )
    durable_count = len(tuple(root.glob("pre-*.json")))
    reference_state = _reference_state(fixture)
    unchanged = before == _source_hashes()
    exact = (
        decision_counts == (("ALLOW", 2), ("DENY", 0), ("REFUSAL", 0))
        and execution_counts
        == (
            ("REFUSED", 0),
            ("COMPLETED", 1),
            ("FAILED", 0),
            ("REPLAY_REJECTED", 1),
        )
        and getattr(outcome_a, "status", None) is ExecutionOutcome.COMPLETED
        and getattr(outcome_b, "status", None) is ExecutionOutcome.REPLAY_REJECTED
        and fixture.adapter.entry_count == 1
        and fixture.payment_store.count == 1
        and reference_state == "CONSUMED"
        and capability_states
        == (("winner", "CONSUMED"), ("stale_contender", "UNUSED"))
        and durable_count == 2
        and unchanged
    )
    result = ConcurrencyResult(
        shape_id="W3-C01",
        repetition_index=repetition_index,
        decision_counts=decision_counts,
        prepared_call_count=sum(
            type(item) is PreparedToolCall for item in preparations
        ),
        execution_status_counts=execution_counts,
        adapter_entry_count=fixture.adapter.entry_count,
        payment_count=fixture.payment_store.count,
        reference_state=reference_state,
        capability_states=capability_states,
        durable_pre_execution_record_count=durable_count,
        overall_status=(
            ConcurrencyRunStatus.PASS if exact else ConcurrencyRunStatus.ERROR
        ),
        detector_ids=_C01_DETECTORS,
        timeout_or_deadlock=False,
        source_hashes_unchanged=unchanged,
        shape_facts=_base_shape_facts()
        + (
            ("external_effect_count", fixture.payment_store.count),
            (
                "losing_contender_status",
                getattr(getattr(outcome_b, "status", None), "value", "MISSING"),
            ),
        ),
        observation_digest="",
    )
    return _complete_result(result)


def _run_c02(root: Path, repetition_index: int) -> ConcurrencyResult:
    from tidemark.payment.fixtures import build_synthetic_payment_fixture
    from tidemark.runtime.execution_gate import ExecutionGate, TrustedAdapterRegistry
    from tidemark.runtime.minimal_evidence import MinimalPreExecutionEvidenceSink
    from tidemark.runtime.prepared_call import PreparedToolCall
    from tidemark.runtime.vocabulary import ExecutionOutcome

    before = _source_hashes()
    fixture = build_synthetic_payment_fixture(
        str(root / "fixture"),
        correlation_namespace=f"w3d-c02-{repetition_index}",
    )
    prepared_f = fixture.prepare(fixture.canonical_call())
    prepared_s = fixture.prepare(fixture.canonical_call())
    if type(prepared_f) is not PreparedToolCall or type(prepared_s) is not PreparedToolCall:
        raise ConcurrencyHarnessError("w3.concurrency_contract_drift.v1")

    registry = TrustedAdapterRegistry(
        tool_id=prepared_f.tool_id,
        adapter_id=prepared_f.adapter_id,
        adapter_version=prepared_f.adapter_version,
        adapter=fixture.adapter,
    )
    failing_root = root / "failing-sink"
    failing_sink = MinimalPreExecutionEvidenceSink(str(failing_root))
    displaced_root = root / "displaced-failing-sink"
    failing_root.rename(displaced_root)
    failing_root.touch(exist_ok=False)
    successful_root = root / "successful-sink"
    successful_sink = MinimalPreExecutionEvidenceSink(str(successful_root))
    failing_gate = ExecutionGate(adapter_registry=registry, evidence_sink=failing_sink)
    successful_gate = ExecutionGate(
        adapter_registry=registry, evidence_sink=successful_sink
    )

    f_append_entered = Event()
    s_append_entered = Event()
    release_f = Event()
    release_s = Event()
    actor = local()
    original_append = MinimalPreExecutionEvidenceSink.append_pre_execution
    thread_errors = []
    observed = {}

    def append_with_pause(self, record):
        role = getattr(actor, "role", None)
        if role == "failed_contender":
            f_append_entered.set()
            _wait_for_event(release_f, timeout_seconds=_EVENT_TIMEOUT_SECONDS)
        elif role == "successful_contender":
            s_append_entered.set()
            _wait_for_event(release_s, timeout_seconds=_EVENT_TIMEOUT_SECONDS)
        return original_append(self, record)

    def failed_contender() -> None:
        actor.role = "failed_contender"
        try:
            observed["failed"] = failing_gate.execute(prepared_f)
        except Exception:
            thread_errors.append(True)

    def successful_contender() -> None:
        actor.role = "successful_contender"
        try:
            observed["successful"] = successful_gate.execute(prepared_s)
        except Exception:
            thread_errors.append(True)

    failed_thread = Thread(target=failed_contender)
    successful_thread = Thread(target=successful_contender)
    failed_started = False
    successful_started = False
    failed_unconsumed_before_success = False
    try:
        MinimalPreExecutionEvidenceSink.append_pre_execution = append_with_pause
        failed_thread.start()
        failed_started = True
        successful_thread.start()
        successful_started = True
        _wait_for_event(f_append_entered, timeout_seconds=_EVENT_TIMEOUT_SECONDS)
        _wait_for_event(s_append_entered, timeout_seconds=_EVENT_TIMEOUT_SECONDS)
        release_f.set()
        _join_thread(failed_thread)
        failed_unconsumed_before_success = (
            _capability_state(prepared_f) == "UNUSED"
            and _reference_state(fixture) == "UNCONSUMED"
        )
        release_s.set()
        _join_thread(successful_thread)
    finally:
        release_f.set()
        release_s.set()
        if failed_started and failed_thread.is_alive():
            failed_thread.join(timeout=_JOIN_TIMEOUT_SECONDS)
        if successful_started and successful_thread.is_alive():
            successful_thread.join(timeout=_JOIN_TIMEOUT_SECONDS)
        MinimalPreExecutionEvidenceSink.append_pre_execution = original_append

    if failed_thread.is_alive() or successful_thread.is_alive() or thread_errors:
        raise ConcurrencyHarnessError(_TIMEOUT_CODE)
    outcome_f = observed.get("failed")
    outcome_s = observed.get("successful")
    preparations = (prepared_f, prepared_s)
    outcomes = (outcome_f, outcome_s)
    decision_counts = _decision_counts(preparations)
    execution_counts = _execution_counts(outcomes)
    capability_states = (
        ("failed_contender", _capability_state(prepared_f)),
        ("successful_contender", _capability_state(prepared_s)),
    )
    failed_durable_count = len(tuple(displaced_root.glob("pre-*.json")))
    successful_durable_count = len(tuple(successful_root.glob("pre-*.json")))
    durable_count = failed_durable_count + successful_durable_count
    reference_state = _reference_state(fixture)
    unchanged = before == _source_hashes()
    failed_append_failure = (
        getattr(outcome_f, "status", None) is ExecutionOutcome.REFUSED
        and failed_durable_count == 0
    )
    successful_append_success = successful_durable_count == 1
    exact = (
        decision_counts == (("ALLOW", 2), ("DENY", 0), ("REFUSAL", 0))
        and execution_counts
        == (
            ("REFUSED", 1),
            ("COMPLETED", 1),
            ("FAILED", 0),
            ("REPLAY_REJECTED", 0),
        )
        and failed_append_failure
        and failed_unconsumed_before_success
        and successful_append_success
        and getattr(outcome_s, "status", None) is ExecutionOutcome.COMPLETED
        and fixture.adapter.entry_count == 1
        and fixture.payment_store.count == 1
        and reference_state == "CONSUMED"
        and capability_states
        == (
            ("failed_contender", "UNUSED"),
            ("successful_contender", "CONSUMED"),
        )
        and durable_count == 1
        and unchanged
    )
    result = ConcurrencyResult(
        shape_id="W3-C02",
        repetition_index=repetition_index,
        decision_counts=decision_counts,
        prepared_call_count=sum(
            type(item) is PreparedToolCall for item in preparations
        ),
        execution_status_counts=execution_counts,
        adapter_entry_count=fixture.adapter.entry_count,
        payment_count=fixture.payment_store.count,
        reference_state=reference_state,
        capability_states=capability_states,
        durable_pre_execution_record_count=durable_count,
        overall_status=(
            ConcurrencyRunStatus.PASS if exact else ConcurrencyRunStatus.ERROR
        ),
        detector_ids=_C02_DETECTORS,
        timeout_or_deadlock=False,
        source_hashes_unchanged=unchanged,
        shape_facts=_base_shape_facts()
        + (
            ("failed_contender_append_failure", failed_append_failure),
            ("failed_contender_consumed", not failed_unconsumed_before_success),
            ("successful_contender_append_success", successful_append_success),
            (
                "successful_contender_consumed",
                _capability_state(prepared_s) == "CONSUMED",
            ),
            ("external_effect_count", fixture.payment_store.count),
        ),
        observation_digest="",
    )
    return _complete_result(result)


def run_w3_d(work_root: Path) -> W3DRun:
    if not isinstance(work_root, Path) or not work_root.is_dir():
        raise ConcurrencyHarnessError("w3.concurrency_workspace_invalid.v1")
    runners = (("W3-C01", _run_c01), ("W3-C02", _run_c02))
    if tuple(item[0] for item in runners) != CONCURRENCY_SHAPES:
        raise ConcurrencyHarnessError("w3.concurrency_contract_drift.v1")
    results = tuple(
        runner(work_root / f"{shape_id.lower()}-{repetition}", repetition)
        for shape_id, runner in runners
        for repetition in range(CONCURRENCY_REPETITIONS_PER_SHAPE)
    )
    overall_status = (
        ConcurrencyRunStatus.PASS
        if len(results) == 6
        and all(result.overall_status is ConcurrencyRunStatus.PASS for result in results)
        else ConcurrencyRunStatus.ERROR
    )
    return W3DRun(
        results=results,
        shape_count=CONCURRENCY_SHAPE_COUNT,
        repetitions_per_shape=CONCURRENCY_REPETITIONS_PER_SHAPE,
        total_run_count=len(results),
        overall_status=overall_status,
    )
