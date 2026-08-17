"""Fresh-state deterministic demo harness for the six required scenarios.

The harness composes the existing payment fixture, prepared-call execution
gate, evidence recorder, projector, publication verifier, and read-only UI. It
owns no authorization decision, reset capability, provider transport, or
runtime-private store after a run returns.
"""

from dataclasses import dataclass
from enum import Enum, unique
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Dict, Optional, Tuple, final

from tidemark.evidence.local_store import LocalAuditStore
from tidemark.evidence.model import (
    AuditEvent,
    DecisionRecordedPayload,
    EvidenceEventType,
    EvidenceProducer,
)
from tidemark.evidence.projection import EvidenceProjector, ReviewProjection
from tidemark.evidence.mechanism_projection import (
    PreparedCallMechanismProjection,
    PreparedCallPublicSnapshot,
    build_mechanism_projection,
    capture_prepared_call_public_snapshot,
)
from tidemark.evidence.publication import (
    EvidencePublicationPackage,
    PublicationRequest,
    PublicationResultCounts,
    build_evidence_publication,
    verify_evidence_publication,
)
from tidemark.evidence.recorder import EvidenceRecorder
from tidemark.payment.fixtures import (
    RAW_SYNTHETIC_DESTINATION,
    build_synthetic_payment_fixture,
)
from tidemark.runtime.identifiers import InvocationId, ReferenceId
from tidemark.runtime.prepared_call import PreparedToolCall
from tidemark.runtime.vocabulary import DecisionOutcome
from tidemark.ui.decision_review import render_decision_review_workspace
from tidemark.ui.final_ui import build_final_ui_scenarios, render_final_ui
from tidemark.ui.run_summary import (
    DemoRunSummary,
    EvidenceMode,
    REQUIRED_SCENARIO_ORDER,
    ScenarioEvidence,
    ScenarioId,
    ScenarioProvenance,
    build_demo_run_summary,
    render_demo_run_summary,
)


_RUN_ID_DOMAIN = b"tidemark.deterministic-demo-harness.v1:"
_PRODUCER = EvidenceProducer("tidemark.demo", "tidemark.order-18.v1")
_MODEL_NON_ATTEMPT_REASON = "no-candidate-tool-call"


@unique
class DemoHarnessFailureCode(str, Enum):
    SCENARIO_GENERATION_FAILED = "demo.scenario_generation_failed.v1"
    PROJECTION_FAILED = "demo.projection_failed.v1"
    PUBLICATION_FAILED = "demo.publication_failed.v1"
    DECISION_REVIEW_FAILED = "demo.decision_review_failed.v1"
    RUN_SUMMARY_FAILED = "demo.run_summary_failed.v1"


class DemoHarnessError(RuntimeError):
    """Bounded failure that omits underlying exception detail."""

    __slots__ = ("code", "scenario_id")

    def __init__(
        self,
        code: DemoHarnessFailureCode,
        scenario_id: Optional[ScenarioId],
    ) -> None:
        if type(code) is not DemoHarnessFailureCode:
            raise TypeError("demo failure code requires DemoHarnessFailureCode")
        if scenario_id is not None and type(scenario_id) is not ScenarioId:
            raise TypeError("demo failure scenario requires ScenarioId or None")
        self.code = code
        self.scenario_id = scenario_id
        label = scenario_id.value if scenario_id is not None else "RUN"
        super().__init__(f"{label}: {code.value}")


@final
@dataclass(frozen=True)
class DecisionReviewArtifact:
    reference: str
    html: str

    def __post_init__(self) -> None:
        if (
            type(self.reference) is not str
            or not self.reference.startswith("decision-review-")
            or not self.reference.endswith(".html")
            or "/" in self.reference
            or ".." in self.reference
        ):
            raise ValueError("decision review reference is invalid")
        if type(self.html) is not str or self.html == "":
            raise ValueError("decision review artifact requires HTML")

    def __repr__(self) -> str:
        return f"DecisionReviewArtifact(reference={self.reference!r}, read_only=True)"


@final
@dataclass(frozen=True)
class DemoScenarioResult:
    scenario_id: ScenarioId
    projection: ReviewProjection
    mechanism_projection: PreparedCallMechanismProjection
    publication_package: EvidencePublicationPackage
    provenance: ScenarioProvenance
    decision_review_artifact: DecisionReviewArtifact

    def __post_init__(self) -> None:
        if type(self.scenario_id) is not ScenarioId:
            raise TypeError("demo scenario requires ScenarioId")
        if type(self.projection) is not ReviewProjection:
            raise TypeError("demo scenario requires ReviewProjection")
        if type(self.mechanism_projection) is not PreparedCallMechanismProjection:
            raise TypeError("demo scenario requires PreparedCallMechanismProjection")
        if type(self.publication_package) is not EvidencePublicationPackage:
            raise TypeError("demo scenario requires EvidencePublicationPackage")
        if type(self.provenance) is not ScenarioProvenance:
            raise TypeError("demo scenario requires ScenarioProvenance")
        if type(self.decision_review_artifact) is not DecisionReviewArtifact:
            raise TypeError("demo scenario requires DecisionReviewArtifact")

    def __repr__(self) -> str:
        return (
            "DemoScenarioResult("
            f"scenario_id={self.scenario_id.value!r}, "
            f"trace_id={self.projection.trace_id!r}, immutable=True)"
        )


@final
@dataclass(frozen=True)
class DemoHarnessRun:
    run_id: str
    scenarios: Tuple[DemoScenarioResult, ...]
    summary: DemoRunSummary
    run_summary_html: str
    integrated_ui_html: str

    def __post_init__(self) -> None:
        if (
            type(self.run_id) is not str
            or not self.run_id.startswith("demo-run-")
            or len(self.run_id) != 41
        ):
            raise ValueError("demo run_id is invalid")
        if type(self.scenarios) is not tuple or any(
            type(item) is not DemoScenarioResult for item in self.scenarios
        ):
            raise TypeError("demo scenarios require an immutable tuple")
        if tuple(item.scenario_id for item in self.scenarios) != REQUIRED_SCENARIO_ORDER:
            raise ValueError("demo scenarios require canonical order")
        if type(self.summary) is not DemoRunSummary:
            raise TypeError("demo run requires DemoRunSummary")
        if type(self.run_summary_html) is not str or self.run_summary_html == "":
            raise ValueError("demo run requires rendered summary")
        if type(self.integrated_ui_html) is not str or self.integrated_ui_html == "":
            raise ValueError("demo run requires rendered integrated UI")

    def __repr__(self) -> str:
        return (
            "DemoHarnessRun("
            f"run_id={self.run_id!r}, scenario_count={len(self.scenarios)}, "
            f"status={self.summary.status.value!r}, immutable=True)"
        )


@final
@dataclass(frozen=True)
class _GeneratedScenario:
    scenario_id: ScenarioId
    projection: ReviewProjection
    mechanism_projection: PreparedCallMechanismProjection
    publication_package: EvidencePublicationPackage
    provenance: ScenarioProvenance


@final
class DeterministicDemoHarness:
    """Generate one complete run from newly constructed disposable state."""

    __slots__ = ("_execution_order", "_seed_digest")

    def __init__(
        self,
        *,
        run_seed: str = "order-18-default",
        scenario_execution_order: Tuple[ScenarioId, ...] = REQUIRED_SCENARIO_ORDER,
    ) -> None:
        if type(run_seed) is not str or run_seed == "":
            raise ValueError("run_seed requires an exact non-empty string")
        if type(scenario_execution_order) is not tuple:
            raise TypeError("scenario_execution_order requires tuple")
        if any(type(item) is not ScenarioId for item in scenario_execution_order):
            raise TypeError("scenario_execution_order requires ScenarioId values")
        if (
            len(scenario_execution_order) != len(REQUIRED_SCENARIO_ORDER)
            or len(set(scenario_execution_order)) != len(REQUIRED_SCENARIO_ORDER)
            or set(scenario_execution_order) != set(REQUIRED_SCENARIO_ORDER)
        ):
            raise ValueError("scenario_execution_order requires a complete scenario permutation")
        self._seed_digest = sha256(
            _RUN_ID_DOMAIN + run_seed.encode("utf-8")
        ).hexdigest()
        self._execution_order = tuple(scenario_execution_order)

    def run(self) -> DemoHarnessRun:
        run_id = "demo-run-" + self._seed_digest[:32]
        generated: Dict[ScenarioId, _GeneratedScenario] = {}
        with TemporaryDirectory(prefix="tidemark-order-18-") as disposable_root:
            root = Path(disposable_root)
            for scenario_id in self._execution_order:
                generated[scenario_id] = self._generate_scenario(
                    root, scenario_id
                )

        evidence = tuple(
            ScenarioEvidence(
                scenario_id=scenario_id,
                projection=generated[scenario_id].projection,
                publication=generated[scenario_id].publication_package,
                provenance=generated[scenario_id].provenance,
            )
            for scenario_id in REQUIRED_SCENARIO_ORDER
        )
        try:
            summary = build_demo_run_summary(run_id, evidence)
            summary_html = render_demo_run_summary(summary)
        except (RuntimeError, TypeError, ValueError):
            raise DemoHarnessError(
                DemoHarnessFailureCode.RUN_SUMMARY_FAILED, None
            ) from None

        summary_by_id = {item.scenario_id: item for item in summary.scenarios}
        results = []
        for scenario_id in REQUIRED_SCENARIO_ORDER:
            scenario = generated[scenario_id]
            try:
                review_html = render_decision_review_workspace(
                    scenario.projection
                )
                reference = summary_by_id[
                    scenario_id
                ].decision_review_reference
                artifact = DecisionReviewArtifact(reference, review_html)
            except (KeyError, RuntimeError, TypeError, ValueError):
                raise DemoHarnessError(
                    DemoHarnessFailureCode.DECISION_REVIEW_FAILED,
                    scenario_id,
                ) from None
            results.append(
                DemoScenarioResult(
                    scenario_id=scenario_id,
                    projection=scenario.projection,
                    mechanism_projection=scenario.mechanism_projection,
                    publication_package=scenario.publication_package,
                    provenance=scenario.provenance,
                    decision_review_artifact=artifact,
                )
            )
        immutable_results = tuple(results)
        try:
            integrated_ui_html = render_final_ui(
                summary,
                build_final_ui_scenarios(
                    summary,
                    tuple(
                        (
                            item.scenario_id,
                            item.projection,
                            item.mechanism_projection,
                        )
                        for item in immutable_results
                    ),
                ),
            )
        except (RuntimeError, TypeError, ValueError):
            raise DemoHarnessError(
                DemoHarnessFailureCode.RUN_SUMMARY_FAILED, None
            ) from None
        return DemoHarnessRun(
            run_id,
            immutable_results,
            summary,
            summary_html,
            integrated_ui_html,
        )

    def _generate_scenario(
        self, root: Path, scenario_id: ScenarioId
    ) -> _GeneratedScenario:
        namespace = self._namespace(scenario_id)
        try:
            if scenario_id is ScenarioId.MODEL_NON_ATTEMPT:
                events, safe_snapshot = _record_model_non_attempt(
                    root / namespace, namespace
                )
            else:
                events, safe_snapshot = _record_runtime_scenario(
                    root / namespace,
                    namespace,
                    scenario_id,
                )
        except (OSError, RuntimeError, TypeError, ValueError):
            raise DemoHarnessError(
                DemoHarnessFailureCode.SCENARIO_GENERATION_FAILED,
                scenario_id,
            ) from None

        try:
            projection = EvidenceProjector().project(events)
            mechanism_projection = build_mechanism_projection(
                safe_snapshot, projection
            )
        except (RuntimeError, TypeError, ValueError):
            raise DemoHarnessError(
                DemoHarnessFailureCode.PROJECTION_FAILED,
                scenario_id,
            ) from None

        try:
            publication = build_evidence_publication(
                events,
                PublicationRequest(
                    export_id="order-18-" + _scenario_slug(scenario_id),
                    export_version=1,
                    trace_id=projection.trace_id,
                    expected_counts=_publication_counts(events),
                ),
            )
            verification = verify_evidence_publication(publication)
            if (
                not verification.valid
                or verification.package is None
                or verification.package.trace_id != projection.trace_id
            ):
                raise RuntimeError("publication verification failed")
        except (RuntimeError, TypeError, ValueError):
            raise DemoHarnessError(
                DemoHarnessFailureCode.PUBLICATION_FAILED,
                scenario_id,
            ) from None

        provenance = ScenarioProvenance(
            EvidenceMode.MODEL_NON_ATTEMPT
            if scenario_id is ScenarioId.MODEL_NON_ATTEMPT
            else EvidenceMode.EVIDENCE_FALLBACK
        )
        return _GeneratedScenario(
            scenario_id,
            projection,
            mechanism_projection,
            publication,
            provenance,
        )

    def _namespace(self, scenario_id: ScenarioId) -> str:
        return self._seed_digest[:16] + "-" + _scenario_slug(scenario_id)

    def __repr__(self) -> str:
        return "DeterministicDemoHarness(fresh_state=True, provider_free=True)"


def _scenario_slug(scenario_id: ScenarioId) -> str:
    return scenario_id.value.lower().replace("_", "-")


def _record_runtime_scenario(
    root: Path,
    namespace: str,
    scenario_id: ScenarioId,
) -> Tuple[Tuple[AuditEvent, ...], Optional[PreparedCallPublicSnapshot]]:
    fixture = build_synthetic_payment_fixture(
        str(root), correlation_namespace=namespace
    )
    safe_snapshot = None
    if scenario_id is ScenarioId.BENIGN_ALLOW:
        prepared = fixture.prepare(fixture.canonical_call())
        if type(prepared) is PreparedToolCall:
            safe_snapshot = capture_prepared_call_public_snapshot(prepared)
            fixture.execution_gate.execute(prepared)
    elif scenario_id is ScenarioId.RAW_PROTECTED_VALUE_DENY:
        fixture.prepare(
            fixture.canonical_call(
                destination_reference=RAW_SYNTHETIC_DESTINATION
            )
        )
    elif scenario_id is ScenarioId.FORGED_OR_MISBOUND_REFERENCE_DENY:
        fixture.prepare(
            fixture.canonical_call(
                destination_reference=ReferenceId(
                    "ref_order_18_forged_unknown"
                )
            )
        )
    elif scenario_id is ScenarioId.BOUND_DENY:
        fixture.prepare(
            fixture.canonical_call(
                amount_minor=fixture.purchase_order.maximum_amount_minor + 1
            )
        )
    elif scenario_id is ScenarioId.REPLAY_REJECTION:
        prepared = fixture.prepare(fixture.canonical_call())
        if type(prepared) is PreparedToolCall:
            safe_snapshot = capture_prepared_call_public_snapshot(prepared)
            fixture.execution_gate.execute(prepared)
            fixture.execution_gate.execute(prepared)
    else:
        raise ValueError("runtime scenario identity is unsupported")
    events = fixture.evidence_store.ordered_events()
    if any(type(event) is not AuditEvent for event in events):
        raise RuntimeError("runtime scenario did not produce authoritative events")
    return events, safe_snapshot


def _record_model_non_attempt(
    root: Path, namespace: str
) -> Tuple[Tuple[AuditEvent, ...], Optional[PreparedCallPublicSnapshot]]:
    store = LocalAuditStore(str(root))
    recorder = EvidenceRecorder(
        store=store,
        trace_id=f"trace-{namespace}",
        producer=_PRODUCER,
        transaction_root_path=str(root),
    )
    recorder.record_model_non_attempt(
        invocation_id=InvocationId(f"invocation-{namespace}"),
        reason_code=_MODEL_NON_ATTEMPT_REASON,
    )
    events = store.ordered_events()
    if any(type(event) is not AuditEvent for event in events):
        raise RuntimeError("model non-attempt did not produce authoritative evidence")
    return events, None


def _publication_counts(
    events: Tuple[AuditEvent, ...]
) -> PublicationResultCounts:
    event_types = tuple(event.event_type for event in events)
    decisions = tuple(
        event.payload
        for event in events
        if event.event_type is EvidenceEventType.DECISION_RECORDED
        and type(event.payload) is DecisionRecordedPayload
    )
    return PublicationResultCounts(
        authoritative_event_count=len(events),
        refusal_count=sum(
            event_type
            in {
                EvidenceEventType.POLICY_INSTALLATION_REFUSED,
                EvidenceEventType.CALL_PREPARATION_REFUSED,
            }
            for event_type in event_types
        ),
        deny_count=sum(
            decision.outcome is DecisionOutcome.DENY for decision in decisions
        ),
        allow_count=sum(
            decision.outcome is DecisionOutcome.ALLOW for decision in decisions
        ),
        model_non_attempt_count=event_types.count(
            EvidenceEventType.RUN_MODEL_NON_ATTEMPT
        ),
        execution_start_count=event_types.count(
            EvidenceEventType.EXECUTION_STARTED
        ),
        execution_completion_count=event_types.count(
            EvidenceEventType.EXECUTION_COMPLETED
        ),
        execution_failure_count=event_types.count(
            EvidenceEventType.EXECUTION_FAILED
        ),
        replay_rejection_count=event_types.count(
            EvidenceEventType.EXECUTION_REPLAY_REJECTED
        ),
        payment_count=event_types.count(EvidenceEventType.PAYMENT_RECORDED),
        reconciliation_count=event_types.count(
            EvidenceEventType.EVIDENCE_RECONCILED
        ),
        prior_export_count=event_types.count(
            EvidenceEventType.EVIDENCE_EXPORT_FINALIZED
        ),
    )


__all__ = (
    "DecisionReviewArtifact",
    "DemoHarnessError",
    "DemoHarnessFailureCode",
    "DemoHarnessRun",
    "DemoScenarioResult",
    "DeterministicDemoHarness",
)
