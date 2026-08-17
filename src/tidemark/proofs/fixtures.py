"""Fixed product-native W2 security-property proof fixtures."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Tuple

from tidemark.evidence.integrity import EvidenceIntegrityChecker
from tidemark.evidence.model import EvidenceEventType, ExecutionTerminalPayload
from tidemark.evidence.projection import (
    EvidenceCompleteness,
    EvidenceProjector,
    ProjectionStatus,
)
from tidemark.evidence.reconciliation import EvidenceReconciler
from tidemark.runtime import execution_gate as execution_gate_module
from tidemark.payment.fixtures import (
    RAW_SYNTHETIC_DESTINATION,
    SyntheticPaymentFixture,
    build_synthetic_payment_fixture,
)
from tidemark.proofs.model import (
    ProofExecutionOutcomeCounts,
    ProofEvidenceStatus,
    ProofExternalResultStatus,
    ProofFindingCode,
    ProofObservation,
    ProofReferenceState,
)
from tidemark.runtime.execution_binding import _lookup_runtime_execution_binding
from tidemark.runtime.execution_gate import (
    AdapterInvocation,
    AdapterInvocationResult,
    ExecutionGate,
    ExecutionResult,
    TrustedAdapterRegistry,
)
from tidemark.runtime.identifiers import (
    AdapterId,
    AdapterVersion,
    DecisionId,
    InvocationId,
    ParentId,
    ReferenceId,
)
from tidemark.runtime.minimal_evidence import MinimalPreExecutionEvidenceSink
from tidemark.runtime.policy_engine import Decision
from tidemark.runtime.prepared_call import PreparationRefusal, PreparedToolCall
from tidemark.runtime.reference_store import (
    ReferenceBinding,
    ReferenceConsumptionOutcome,
    ReferenceDeactivationOutcome,
    ReferenceLifecycle,
    ReferenceMetadata,
    TrustedRecord,
)
from tidemark.runtime.vocabulary import (
    DecisionOutcome,
    ExecutionOutcome,
    PreparedCallState,
    RuleId,
)


CORE_PROOF_FIXTURE_IDS = (
    "W2-P01-C01-runtime-reference-selection",
    "W2-P01-C02-raw-protected-value-supply",
    "W2-P02-C01-post-allow-reference-deactivation",
    "W2-P03-C01-durable-evidence-before-effect",
    "W2-P03-C02-pre-execution-append-failure",
)

REPLAY_PROOF_FIXTURE_IDS = (
    "W2-P04-C01-sequential-replay",
    "W2-P05-C01-concurrent-replay",
)

TAMPER_PROOF_FIXTURE_IDS = (
    "W2-P06-C01-public-integrity",
    "W2-P06-C02-binding-missing",
    "W2-P06-C03-correlation",
    "W2-P06-C04-authenticator",
    "W2-P06-C05-payload",
    "W2-P06-C06-adapter-identity",
    "W2-P06-C07-adapter-version",
)

REFERENCE_PROOF_FIXTURE_IDS = (
    "W2-P07-C01-reference-not-found",
    "W2-P07-C02-wrong-kind",
    "W2-P07-C03-wrong-invocation",
    "W2-P07-C04-wrong-parent",
    "W2-P07-C05-inactive-reference",
    "W2-P07-C06-consumed-reference",
)

EVIDENCE_PROOF_FIXTURE_IDS = (
    "W2-P08-C01-missing-terminal-evidence",
    "W2-P08-C02-conflicting-terminal-evidence",
    "W2-P08-C03-ambiguous-external-result",
)


def _fresh_fixture(root: Path, **fixture_options) -> SyntheticPaymentFixture:
    if not isinstance(root, Path):
        raise TypeError("proof fixture workspace requires pathlib.Path")
    if root.exists():
        if not root.is_dir() or any(root.iterdir()):
            raise ValueError("proof fixture workspace must be an empty directory")
    else:
        root.mkdir(parents=True, exist_ok=False)
    return build_synthetic_payment_fixture(str(root), **fixture_options)


def _decision(fixture: SyntheticPaymentFixture, call: object) -> Decision:
    decision = fixture.evaluate(call)
    if type(decision) is not Decision:
        raise RuntimeError("proof fixture did not produce an exact decision")
    return decision


def _prepared(fixture: SyntheticPaymentFixture, call: object) -> PreparedToolCall:
    preparation = fixture.prepare(call)
    if type(preparation) is not PreparedToolCall:
        raise RuntimeError("proof fixture did not produce one prepared call")
    return preparation


def _capability_state(prepared: PreparedToolCall) -> PreparedCallState:
    binding = _lookup_runtime_execution_binding(prepared.prepared_call_id)
    state = getattr(binding, "_capability_state", None)
    if type(state) is not PreparedCallState:
        raise RuntimeError("runtime capability state is unavailable")
    return state


def _reference_state(
    fixture: SyntheticPaymentFixture,
    reference_id=None,
) -> ProofReferenceState:
    selected = fixture.destination_reference if reference_id is None else reference_id
    metadata = fixture.reference_store.lookup(selected)
    if type(metadata) is not ReferenceMetadata:
        return ProofReferenceState.NOT_FOUND
    if metadata.active and metadata.consumed:
        return ProofReferenceState.ACTIVE_CONSUMED
    if metadata.active and not metadata.consumed:
        return ProofReferenceState.ACTIVE_UNCONSUMED
    if not metadata.active and metadata.consumed:
        return ProofReferenceState.INACTIVE_CONSUMED
    return ProofReferenceState.INACTIVE_UNCONSUMED


def _execution_counts(results: Tuple[ExecutionResult, ...]) -> ProofExecutionOutcomeCounts:
    if type(results) is not tuple or any(type(item) is not ExecutionResult for item in results):
        raise TypeError("execution results require an exact tuple")
    return ProofExecutionOutcomeCounts(
        refused=sum(item.status is ExecutionOutcome.REFUSED for item in results),
        completed=sum(item.status is ExecutionOutcome.COMPLETED for item in results),
        failed=sum(item.status is ExecutionOutcome.FAILED for item in results),
        replay_rejected=sum(item.status is ExecutionOutcome.REPLAY_REJECTED for item in results),
    )


def _runtime_observation(
    *,
    fixture: SyntheticPaymentFixture,
    decision: Decision,
    prepared: object,
    results: Tuple[ExecutionResult, ...],
    pre_execution_record_count=None,
    reference_id=None,
    adapter_entry_count=None,
) -> ProofObservation:
    prepared_count = 1 if type(prepared) is PreparedToolCall else 0
    capability_state = (
        _capability_state(prepared)
        if type(prepared) is PreparedToolCall
        else None
    )
    return ProofObservation(
        decision_outcome=decision.outcome,
        decision_rule_id=decision.primary_rule_id,
        prepared_call_count=prepared_count,
        execution_attempt_count=len(results),
        execution_outcomes=_execution_counts(results),
        adapter_entry_count=(
            fixture.adapter.entry_count
            if adapter_entry_count is None
            else adapter_entry_count
        ),
        authoritative_side_effect_count=fixture.payment_store.count,
        capability_state=capability_state,
        reference_states=(_reference_state(fixture, reference_id),),
        pre_execution_record_count=pre_execution_record_count,
        external_result_status=None,
        evidence_integrity_status=None,
        evidence_reconciliation_status=None,
        evidence_completeness=None,
        evidence_execution_status=None,
        evidence_success_claimed=None,
        external_effect_absence_claimed=None,
        finding_codes=(),
    )


def _p01_reference_selection(root: Path) -> ProofObservation:
    fixture = _fresh_fixture(root)
    call = fixture.canonical_call()
    decision = _decision(fixture, call)
    if decision.outcome is not DecisionOutcome.ALLOW:
        raise RuntimeError("legitimate selection did not produce ALLOW")
    prepared = _prepared(fixture, call)
    result = fixture.execution_gate.execute(prepared)
    return _runtime_observation(
        fixture=fixture,
        decision=decision,
        prepared=prepared,
        results=(result,),
    )


def _p01_raw_supply(root: Path) -> ProofObservation:
    fixture = _fresh_fixture(root)
    call = fixture.canonical_call(
        destination_reference=RAW_SYNTHETIC_DESTINATION
    )
    preparation = fixture.prepare(call)
    if type(preparation) is not PreparationRefusal:
        raise RuntimeError("raw protected supply unexpectedly prepared")
    decision = preparation.decision
    return _runtime_observation(
        fixture=fixture,
        decision=decision,
        prepared=preparation,
        results=(),
    )


def _p02_post_allow_deactivation(root: Path) -> ProofObservation:
    fixture = _fresh_fixture(root)
    call = fixture.canonical_call()
    decision = _decision(fixture, call)
    if decision.outcome is not DecisionOutcome.ALLOW:
        raise RuntimeError("legitimate preparation precondition did not ALLOW")
    prepared = _prepared(fixture, call)
    deactivation = fixture.reference_store.deactivate(
        fixture.destination_reference
    )
    if deactivation is not ReferenceDeactivationOutcome.DEACTIVATED:
        raise RuntimeError("proof fixture reference did not deactivate")
    result = fixture.execution_gate.execute(prepared)
    pre_count = len(tuple(root.glob("pre-*.json")))
    return _runtime_observation(
        fixture=fixture,
        decision=decision,
        prepared=prepared,
        results=(result,),
        pre_execution_record_count=pre_count,
    )


class _OrderingPaymentAdapter:
    __slots__ = (
        "_delegate",
        "_fixture",
        "_prepared",
        "_root",
        "entry_count",
        "validated_at_entry",
    )

    def __init__(
        self,
        *,
        fixture: SyntheticPaymentFixture,
        prepared: PreparedToolCall,
        root: Path,
    ) -> None:
        self._delegate = fixture.adapter
        self._fixture = fixture
        self._prepared = prepared
        self._root = root
        self.entry_count = 0
        self.validated_at_entry = False

    def __call__(self, invocation: AdapterInvocation) -> AdapterInvocationResult:
        self.entry_count += 1
        pre_count = len(tuple(self._root.glob("pre-*.json")))
        capability_state = _capability_state(self._prepared)
        reference_state = _reference_state(self._fixture)
        payment_count_before_delegation = self._fixture.payment_store.count
        if (
            pre_count != 1
            or capability_state is not PreparedCallState.CONSUMED
            or reference_state is not ProofReferenceState.ACTIVE_CONSUMED
            or payment_count_before_delegation != 0
        ):
            raise RuntimeError("evidence/effect ordering invariant did not hold at adapter entry")
        self.validated_at_entry = True
        return self._delegate(invocation)


def _gate_for(
    *,
    prepared: PreparedToolCall,
    adapter: object,
    evidence_sink: object,
) -> ExecutionGate:
    registry = TrustedAdapterRegistry(
        tool_id=prepared.tool_id,
        adapter_id=prepared.adapter_id,
        adapter_version=prepared.adapter_version,
        adapter=adapter,
    )
    return ExecutionGate(adapter_registry=registry, evidence_sink=evidence_sink)


def _p03_evidence_before_effect(root: Path) -> ProofObservation:
    fixture = _fresh_fixture(root)
    call = fixture.canonical_call()
    decision = _decision(fixture, call)
    prepared = _prepared(fixture, call)
    observer = _OrderingPaymentAdapter(
        fixture=fixture,
        prepared=prepared,
        root=root,
    )
    gate = _gate_for(
        prepared=prepared,
        adapter=observer,
        evidence_sink=fixture.evidence_recorder,
    )
    result = gate.execute(prepared)
    if not observer.validated_at_entry or observer.entry_count != 1:
        raise RuntimeError("ordering adapter did not validate one entry")
    return _runtime_observation(
        fixture=fixture,
        decision=decision,
        prepared=prepared,
        results=(result,),
        pre_execution_record_count=len(tuple(root.glob("pre-*.json"))),
    )


def _p03_unavailable_sink(root: Path) -> ProofObservation:
    fixture = _fresh_fixture(root)
    call = fixture.canonical_call()
    decision = _decision(fixture, call)
    prepared = _prepared(fixture, call)

    sink_root = root / "unavailable-sink"
    sink = MinimalPreExecutionEvidenceSink(str(sink_root))
    displaced_root = root / "displaced-sink"
    sink_root.rename(displaced_root)
    sink_root.touch(exist_ok=False)

    gate = _gate_for(
        prepared=prepared,
        adapter=fixture.adapter,
        evidence_sink=sink,
    )
    result = gate.execute(prepared)
    pre_count = len(tuple(displaced_root.glob("pre-*.json")))
    return _runtime_observation(
        fixture=fixture,
        decision=decision,
        prepared=prepared,
        results=(result,),
        pre_execution_record_count=pre_count,
    )


def _prepared_fixture(root: Path):
    fixture = _fresh_fixture(root)
    call = fixture.canonical_call()
    decision = _decision(fixture, call)
    if decision.outcome is not DecisionOutcome.ALLOW:
        raise RuntimeError("legitimate proof precondition did not ALLOW")
    return fixture, decision, _prepared(fixture, call)


def _p04_sequential_replay(root: Path) -> ProofObservation:
    fixture, decision, prepared = _prepared_fixture(root)
    results = tuple(fixture.execution_gate.execute(prepared) for _ in range(2))
    return _runtime_observation(
        fixture=fixture,
        decision=decision,
        prepared=prepared,
        results=results,
    )


def _p05_concurrent_replay(root: Path) -> ProofObservation:
    fixture, decision, prepared = _prepared_fixture(root)
    with ThreadPoolExecutor(max_workers=6) as executor:
        results = tuple(
            executor.map(fixture.execution_gate.execute, (prepared,) * 12)
        )
    return _runtime_observation(
        fixture=fixture,
        decision=decision,
        prepared=prepared,
        results=results,
    )


def _tamper_result_observation(
    *,
    fixture: SyntheticPaymentFixture,
    decision: Decision,
    prepared: PreparedToolCall,
    result: ExecutionResult,
) -> ProofObservation:
    if (
        result.status is not ExecutionOutcome.REFUSED
        or result.rule_id is not RuleId.EXECUTION_PREPARED_CALL_INVALID
    ):
        raise RuntimeError("tamper case did not produce the exact closed refusal")
    return _runtime_observation(
        fixture=fixture,
        decision=decision,
        prepared=prepared,
        results=(result,),
    )


def _p06_tamper(root: Path, fixture_id: str) -> ProofObservation:
    fixture, decision, prepared = _prepared_fixture(root)

    if fixture_id == TAMPER_PROOF_FIXTURE_IDS[0]:
        object.__setattr__(prepared, "integrity_id", "sha256:" + "0" * 64)
        result = fixture.execution_gate.execute(prepared)
    elif fixture_id == TAMPER_PROOF_FIXTURE_IDS[1]:
        original = execution_gate_module._validate_runtime_execution_binding
        try:
            execution_gate_module._validate_runtime_execution_binding = (
                lambda value: None
            )
            result = fixture.execution_gate.execute(prepared)
        finally:
            execution_gate_module._validate_runtime_execution_binding = original
            if execution_gate_module._validate_runtime_execution_binding is not original:
                raise RuntimeError("tamper seam restoration failed")
    elif fixture_id == TAMPER_PROOF_FIXTURE_IDS[2]:
        binding = _lookup_runtime_execution_binding(prepared.prepared_call_id)
        if binding is None:
            raise RuntimeError("runtime binding unavailable for correlation case")
        object.__setattr__(
            binding,
            "decision_id",
            DecisionId("w2-proof-correlation-mismatch"),
        )
        result = fixture.execution_gate.execute(prepared)
    elif fixture_id == TAMPER_PROOF_FIXTURE_IDS[3]:
        binding = _lookup_runtime_execution_binding(prepared.prepared_call_id)
        if binding is None:
            raise RuntimeError("runtime binding unavailable for authenticator case")
        object.__setattr__(binding, "_payload_authenticator", b"w2-invalid")
        result = fixture.execution_gate.execute(prepared)
    elif fixture_id == TAMPER_PROOF_FIXTURE_IDS[4]:
        object.__setattr__(
            prepared.arguments[2],
            "_RuntimePreparedValueCarrier__runtime_value",
            "w2-private-payload-substitution",
        )
        result = fixture.execution_gate.execute(prepared)
    else:
        registry = TrustedAdapterRegistry(
            tool_id=prepared.tool_id,
            adapter_id=(
                AdapterId("w2.proof.adapter-mismatch")
                if fixture_id == TAMPER_PROOF_FIXTURE_IDS[5]
                else prepared.adapter_id
            ),
            adapter_version=(
                AdapterVersion("w2.proof.adapter-version-mismatch")
                if fixture_id == TAMPER_PROOF_FIXTURE_IDS[6]
                else prepared.adapter_version
            ),
            adapter=fixture.adapter,
        )
        gate = ExecutionGate(
            adapter_registry=registry,
            evidence_sink=fixture.evidence_recorder,
        )
        result = gate.execute(prepared)

    return _tamper_result_observation(
        fixture=fixture,
        decision=decision,
        prepared=prepared,
        result=result,
    )


def _p07_reference_context(root: Path, fixture_id: str) -> ProofObservation:
    selected_reference = None
    if fixture_id == REFERENCE_PROOF_FIXTURE_IDS[0]:
        fixture = _fresh_fixture(root)
        selected_reference = ReferenceId("ref_w2_proof_unresolvable")
    elif fixture_id == REFERENCE_PROOF_FIXTURE_IDS[1]:
        fixture = _fresh_fixture(root)
        selected_reference = fixture.reference_store.issuer.issue(
            TrustedRecord(RAW_SYNTHETIC_DESTINATION, "w2.proof.wrong-kind"),
            ReferenceBinding(
                fixture.invocation_id,
                fixture.purchase_order.parent_id,
            ),
            ReferenceLifecycle(active=True, single_use=True),
        )
    elif fixture_id == REFERENCE_PROOF_FIXTURE_IDS[2]:
        fixture = _fresh_fixture(
            root,
            reference_invocation_id=InvocationId("w2-proof-wrong-invocation"),
        )
    elif fixture_id == REFERENCE_PROOF_FIXTURE_IDS[3]:
        fixture = _fresh_fixture(
            root,
            reference_parent_id=ParentId("w2-proof-wrong-parent"),
        )
    elif fixture_id == REFERENCE_PROOF_FIXTURE_IDS[4]:
        fixture = _fresh_fixture(root, reference_active=False)
    else:
        fixture = _fresh_fixture(root)
        consumption = fixture.reference_store.consume(
            fixture.destination_reference
        )
        if consumption is not ReferenceConsumptionOutcome.CONSUMED:
            raise RuntimeError("reference proof precondition did not consume")

    call = fixture.canonical_call(
        destination_reference=(
            selected_reference
            if selected_reference is not None
            else fixture.destination_reference
        )
    )
    decision = _decision(fixture, call)
    preparation = fixture.prepare(call)
    if type(preparation) is not PreparationRefusal:
        raise RuntimeError("invalid reference context unexpectedly prepared")
    return _runtime_observation(
        fixture=fixture,
        decision=decision,
        prepared=preparation,
        results=(),
        reference_id=selected_reference,
    )


def _normalized_events(events):
    return tuple(
        replace(event, sequence=index, previous_event_digest=None)
        for index, event in enumerate(events, 1)
    )


def _proof_evidence_status(clean: bool) -> ProofEvidenceStatus:
    if type(clean) is not bool:
        raise TypeError("evidence status requires exact bool")
    return ProofEvidenceStatus.PASS if clean else ProofEvidenceStatus.FAIL


def _p08_incomplete_or_conflicting(
    root: Path,
    fixture_id: str,
) -> ProofObservation:
    fixture, decision, prepared = _prepared_fixture(root)
    result = fixture.execution_gate.execute(prepared)
    if result.status is not ExecutionOutcome.COMPLETED:
        raise RuntimeError("evidence proof baseline did not complete")
    events = fixture.evidence_store.ordered_events()

    if fixture_id == EVIDENCE_PROOF_FIXTURE_IDS[0]:
        candidate = _normalized_events(events[:3])
        expected_finding = ProofFindingCode.MISSING_TERMINAL
        completeness = EvidenceCompleteness.INCOMPLETE
    else:
        failed = replace(
            events[3],
            event_id="w2-proof-conflicting-terminal",
            event_type=EvidenceEventType.EXECUTION_FAILED,
            payload=ExecutionTerminalPayload(
                external_result_confirmed=True,
                masked_failure_fact="adapter-confirmed-failure",
            ),
        )
        candidate = _normalized_events(
            (events[0], events[1], events[2], events[3], failed, events[4])
        )
        expected_finding = ProofFindingCode.CONFLICTING_TERMINAL
        completeness = EvidenceCompleteness.COMPLETE

    integrity = EvidenceIntegrityChecker().check(candidate)
    reconciliation = EvidenceReconciler().reconcile(candidate)
    projection = EvidenceProjector().project(candidate)
    integrity_clean = (
        projection.integrity_status is ProjectionStatus.CLEAN
        if fixture_id == EVIDENCE_PROOF_FIXTURE_IDS[0]
        else integrity.clean
    )
    return ProofObservation(
        decision_outcome=decision.outcome,
        decision_rule_id=None,
        prepared_call_count=None,
        execution_attempt_count=None,
        execution_outcomes=None,
        adapter_entry_count=None,
        authoritative_side_effect_count=None,
        capability_state=None,
        reference_states=(),
        pre_execution_record_count=None,
        external_result_status=None,
        evidence_integrity_status=_proof_evidence_status(integrity_clean),
        evidence_reconciliation_status=_proof_evidence_status(
            reconciliation.clean
        ),
        evidence_completeness=completeness,
        evidence_execution_status=projection.execution_status,
        evidence_success_claimed=False,
        external_effect_absence_claimed=False,
        finding_codes=(expected_finding,),
    )


class _AmbiguousAdapter:
    __slots__ = ("entry_count",)

    def __init__(self) -> None:
        self.entry_count = 0

    def __call__(self, invocation: AdapterInvocation) -> AdapterInvocationResult:
        self.entry_count += 1
        return AdapterInvocationResult.unconfirmed_failure()


def _p08_ambiguous_external_result(root: Path) -> ProofObservation:
    fixture, decision, prepared = _prepared_fixture(root)
    adapter = _AmbiguousAdapter()
    gate = _gate_for(
        prepared=prepared,
        adapter=adapter,
        evidence_sink=fixture.evidence_recorder,
    )
    result = gate.execute(prepared)
    projection = EvidenceProjector().project(
        fixture.evidence_store.ordered_events()
    )
    base = _runtime_observation(
        fixture=fixture,
        decision=decision,
        prepared=prepared,
        results=(result,),
        adapter_entry_count=adapter.entry_count,
    )
    return replace(
        base,
        external_result_status=ProofExternalResultStatus.UNCONFIRMED,
        evidence_integrity_status=_proof_evidence_status(
            projection.integrity_status is ProjectionStatus.CLEAN
        ),
        evidence_reconciliation_status=_proof_evidence_status(
            projection.reconciliation_status is ProjectionStatus.CLEAN
        ),
        evidence_completeness=projection.evidence_completeness,
        evidence_execution_status=projection.execution_status,
        evidence_success_claimed=False,
        external_effect_absence_claimed=False,
    )


def execute_proof_fixture(fixture_id: str, workspace_root: Path) -> ProofObservation:
    """Execute one implemented closed W2 fixture identity."""

    implemented_ids = (
        CORE_PROOF_FIXTURE_IDS
        + REPLAY_PROOF_FIXTURE_IDS
        + TAMPER_PROOF_FIXTURE_IDS
        + REFERENCE_PROOF_FIXTURE_IDS
        + EVIDENCE_PROOF_FIXTURE_IDS
    )
    if type(fixture_id) is not str or fixture_id not in implemented_ids:
        raise ValueError("fixture_id is not implemented")
    if not isinstance(workspace_root, Path):
        raise TypeError("workspace_root requires pathlib.Path")
    if fixture_id == CORE_PROOF_FIXTURE_IDS[0]:
        observed = _p01_reference_selection(workspace_root)
    elif fixture_id == CORE_PROOF_FIXTURE_IDS[1]:
        observed = _p01_raw_supply(workspace_root)
    elif fixture_id == CORE_PROOF_FIXTURE_IDS[2]:
        observed = _p02_post_allow_deactivation(workspace_root)
    elif fixture_id == CORE_PROOF_FIXTURE_IDS[3]:
        observed = _p03_evidence_before_effect(workspace_root)
    elif fixture_id == CORE_PROOF_FIXTURE_IDS[4]:
        observed = _p03_unavailable_sink(workspace_root)
    elif fixture_id == REPLAY_PROOF_FIXTURE_IDS[0]:
        observed = _p04_sequential_replay(workspace_root)
    elif fixture_id == REPLAY_PROOF_FIXTURE_IDS[1]:
        observed = _p05_concurrent_replay(workspace_root)
    elif fixture_id in TAMPER_PROOF_FIXTURE_IDS:
        observed = _p06_tamper(workspace_root, fixture_id)
    elif fixture_id in REFERENCE_PROOF_FIXTURE_IDS:
        observed = _p07_reference_context(workspace_root, fixture_id)
    elif fixture_id == EVIDENCE_PROOF_FIXTURE_IDS[2]:
        observed = _p08_ambiguous_external_result(workspace_root)
    else:
        observed = _p08_incomplete_or_conflicting(workspace_root, fixture_id)
    if type(observed) is not ProofObservation:
        raise RuntimeError("proof fixture did not produce a closed observation")
    return observed


__all__ = (
    "CORE_PROOF_FIXTURE_IDS",
    "EVIDENCE_PROOF_FIXTURE_IDS",
    "REPLAY_PROOF_FIXTURE_IDS",
    "REFERENCE_PROOF_FIXTURE_IDS",
    "TAMPER_PROOF_FIXTURE_IDS",
    "execute_proof_fixture",
)
