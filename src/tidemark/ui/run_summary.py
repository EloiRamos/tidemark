"""Deterministic read-only demo-run summary over verified review evidence."""

from dataclasses import dataclass
from enum import Enum, unique
from hashlib import sha256
from html import escape
import json
from typing import Optional, Tuple, final

from tidemark.evidence.projection import (
    EvidenceCompleteness,
    ExecutionReviewStatus,
    ProjectionDisposition,
    ProjectionStatus,
    ReplayReviewState,
    ReviewProjection,
    review_projection_to_primitive,
)
from tidemark.evidence.publication import (
    EvidencePublicationPackage,
    verify_evidence_publication,
)
from tidemark.runtime.vocabulary import RuleId


_RUN_ID_DOMAIN = "tidemark.demo-run-summary.v1:"
_LIVE_MODEL_IDENTIFIER = "gemini-3.6-flash"
_LIVE_ACCESS_PATH = "Gemini Developer API"


@unique
class ScenarioId(str, Enum):
    BENIGN_ALLOW = "BENIGN_ALLOW"
    RAW_PROTECTED_VALUE_DENY = "RAW_PROTECTED_VALUE_DENY"
    FORGED_OR_MISBOUND_REFERENCE_DENY = "FORGED_OR_MISBOUND_REFERENCE_DENY"
    BOUND_DENY = "BOUND_DENY"
    REPLAY_REJECTION = "REPLAY_REJECTION"
    MODEL_NON_ATTEMPT = "MODEL_NON_ATTEMPT"


REQUIRED_SCENARIO_ORDER = tuple(ScenarioId)


@unique
class ComparisonStatus(str, Enum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    INCOMPLETE = "INCOMPLETE"


@unique
class RunStatus(str, Enum):
    PASS = "PASS"
    MISMATCH = "MISMATCH"
    INCOMPLETE = "INCOMPLETE"


@unique
class ScenarioIntegrityStatus(str, Enum):
    CLEAN_COMPLETE = "CLEAN / COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    CONFLICTING = "CONFLICTING"
    INVALID = "INVALID"


@unique
class PublicationReviewStatus(str, Enum):
    VERIFIED = "VERIFIED"
    NOT_FINALIZED = "NOT FINALIZED"
    INVALID = "INVALID"


@unique
class EvidenceMode(str, Enum):
    LIVE_MODEL = "LIVE MODEL"
    DEVELOPMENT_FALLBACK = "DEVELOPMENT FALLBACK"
    DEMO_RESILIENCE = "DEMO RESILIENCE"
    EVIDENCE_FALLBACK = "EVIDENCE FALLBACK"
    MODEL_NON_ATTEMPT = "MODEL NON-ATTEMPT"


def _is_digest(value: object) -> bool:
    return (
        type(value) is str
        and value.startswith("sha256:")
        and len(value) == 71
        and all(character in "0123456789abcdef" for character in value[7:])
    )


@final
@dataclass(frozen=True)
class ScenarioProvenance:
    """Safe per-scenario provenance supplied with already-generated evidence."""

    mode: EvidenceMode
    model_identifier: Optional[str] = None
    access_path: Optional[str] = None
    provider_evidence_digest: Optional[str] = None

    def __post_init__(self) -> None:
        if type(self.mode) is not EvidenceMode:
            raise TypeError("scenario provenance mode requires EvidenceMode")
        if self.mode is EvidenceMode.LIVE_MODEL:
            if (
                self.model_identifier != _LIVE_MODEL_IDENTIFIER
                or self.access_path != _LIVE_ACCESS_PATH
                or not _is_digest(self.provider_evidence_digest)
            ):
                raise ValueError(
                    "live provenance requires the exact model, access path, and evidence digest"
                )
            return
        if any(
            value is not None
            for value in (
                self.model_identifier,
                self.access_path,
                self.provider_evidence_digest,
            )
        ):
            raise ValueError("offline provenance cannot assert live provider metadata")


@final
@dataclass(frozen=True)
class ScenarioExpectation:
    scenario_id: ScenarioId
    display_name: str
    decision: ProjectionDisposition
    primary_rule_id: Optional[RuleId]
    execution_status: ExecutionReviewStatus
    execution_start_count: int
    payment_count: int
    replay_state: ReplayReviewState
    model_non_attempt: bool

    def __post_init__(self) -> None:
        if type(self.scenario_id) is not ScenarioId:
            raise TypeError("scenario expectation requires ScenarioId")
        if type(self.display_name) is not str or self.display_name == "":
            raise ValueError("scenario expectation requires a display name")
        if type(self.decision) is not ProjectionDisposition:
            raise TypeError("expected decision requires ProjectionDisposition")
        if self.primary_rule_id is not None and type(
            self.primary_rule_id
        ) is not RuleId:
            raise TypeError("expected primary rule requires RuleId or None")
        if type(self.execution_status) is not ExecutionReviewStatus:
            raise TypeError("expected execution requires ExecutionReviewStatus")
        for count in (self.execution_start_count, self.payment_count):
            if type(count) is not int or count < 0:
                raise ValueError("expected counts require non-negative exact ints")
        if type(self.replay_state) is not ReplayReviewState:
            raise TypeError("expected replay requires ReplayReviewState")
        if type(self.model_non_attempt) is not bool:
            raise TypeError("expected model non-attempt requires bool")


REQUIRED_SCENARIO_CONTRACTS = (
    ScenarioExpectation(
        ScenarioId.BENIGN_ALLOW,
        "Benign ALLOW",
        ProjectionDisposition.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        ExecutionReviewStatus.COMPLETED,
        1,
        1,
        ReplayReviewState.NOT_OBSERVED,
        False,
    ),
    ScenarioExpectation(
        ScenarioId.RAW_PROTECTED_VALUE_DENY,
        "Attacked raw protected value",
        ProjectionDisposition.DENY,
        RuleId.PROTECTED_RAW_VALUE_SUPPLIED,
        ExecutionReviewStatus.NOT_STARTED,
        0,
        0,
        ReplayReviewState.NOT_OBSERVED,
        False,
    ),
    ScenarioExpectation(
        ScenarioId.FORGED_OR_MISBOUND_REFERENCE_DENY,
        "Forged or misbound reference",
        ProjectionDisposition.DENY,
        RuleId.REFERENCE_NOT_FOUND,
        ExecutionReviewStatus.NOT_STARTED,
        0,
        0,
        ReplayReviewState.NOT_OBSERVED,
        False,
    ),
    ScenarioExpectation(
        ScenarioId.BOUND_DENY,
        "Trusted value bound exceeded",
        ProjectionDisposition.DENY,
        RuleId.VALUE_CONSTRAINT_FAILED,
        ExecutionReviewStatus.NOT_STARTED,
        0,
        0,
        ReplayReviewState.NOT_OBSERVED,
        False,
    ),
    ScenarioExpectation(
        ScenarioId.REPLAY_REJECTION,
        "Replay rejection",
        ProjectionDisposition.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        ExecutionReviewStatus.COMPLETED,
        1,
        1,
        ReplayReviewState.REJECTED,
        False,
    ),
    ScenarioExpectation(
        ScenarioId.MODEL_NON_ATTEMPT,
        "Model non-attempt",
        ProjectionDisposition.MODEL_NON_ATTEMPT,
        None,
        ExecutionReviewStatus.NOT_STARTED,
        0,
        0,
        ReplayReviewState.NOT_OBSERVED,
        True,
    ),
)

_EXPECTATIONS = {
    expectation.scenario_id: expectation
    for expectation in REQUIRED_SCENARIO_CONTRACTS
}


@final
@dataclass(frozen=True)
class ScenarioEvidence:
    """One supplied projection and its optional finalized publication proof."""

    scenario_id: ScenarioId
    projection: ReviewProjection
    publication: Optional[EvidencePublicationPackage]
    provenance: ScenarioProvenance

    def __post_init__(self) -> None:
        if type(self.scenario_id) is not ScenarioId:
            raise TypeError("scenario_id requires ScenarioId")
        if type(self.projection) is not ReviewProjection:
            raise TypeError("scenario evidence requires ReviewProjection")
        if self.publication is not None and type(
            self.publication
        ) is not EvidencePublicationPackage:
            raise TypeError(
                "scenario publication requires EvidencePublicationPackage or None"
            )
        if type(self.provenance) is not ScenarioProvenance:
            raise TypeError("scenario evidence requires ScenarioProvenance")
        if self.scenario_id is ScenarioId.MODEL_NON_ATTEMPT:
            if self.provenance.mode is not EvidenceMode.MODEL_NON_ATTEMPT:
                raise ValueError("model non-attempt requires explicit provenance")
        elif self.provenance.mode is EvidenceMode.MODEL_NON_ATTEMPT:
            raise ValueError("model non-attempt provenance is scenario-specific")


@final
@dataclass(frozen=True)
class ScenarioSummary:
    scenario_id: ScenarioId
    display_name: str
    mode: EvidenceMode
    provenance_label: str
    provider_evidence_digest: Optional[str]
    expected_decision: str
    expected_primary_rule: str
    expected_execution: str
    expected_execution_start_count: int
    expected_payment_count: int
    expected_replay: str
    expected_model_attempt: str
    observed_decision: str
    observed_primary_rule: str
    observed_execution: str
    observed_execution_start_count: Optional[int]
    observed_payment_count: Optional[int]
    observed_replay: str
    observed_model_attempt: str
    callback_action: str
    projection_completeness: str
    projection_integrity: str
    projection_reconciliation: str
    publication_status: PublicationReviewStatus
    publication_digest: Optional[str]
    integrity: ScenarioIntegrityStatus
    comparison: ComparisonStatus
    decision_review_reference: str


@final
@dataclass(frozen=True)
class DemoRunSummary:
    run_identity: str
    scenarios: Tuple[ScenarioSummary, ...]
    required_scenario_count: int
    observed_scenario_count: int
    missing_scenario_count: int
    match_count: int
    mismatch_count: int
    incomplete_count: int
    status: RunStatus
    integrity: ScenarioIntegrityStatus
    provenance_summary: str

    def __repr__(self) -> str:
        return (
            "DemoRunSummary(read_only=True, authorization_authority=False, "
            "scenario_execution=False, "
            f"status={self.status.value!r}, observed={self.observed_scenario_count})"
        )


def _display_enum(value: Enum) -> str:
    if value is ProjectionDisposition.MODEL_NON_ATTEMPT:
        return "MODEL NON-ATTEMPT"
    return value.value.replace("_", " ")


def _display_rule(value: Optional[RuleId]) -> str:
    return value.value if value is not None else "NOT APPLICABLE"


def _model_attempt_display(non_attempt: bool, *, expected: bool) -> str:
    if non_attempt:
        return "NOT ATTEMPTED"
    return (
        "NON-ATTEMPT NOT EXPECTED"
        if expected
        else "NO MODEL NON-ATTEMPT RECORDED"
    )


def _provenance_label(provenance: ScenarioProvenance) -> str:
    labels = {
        EvidenceMode.LIVE_MODEL: "LIVE MODEL / PROVIDER-BACKED EVIDENCE",
        EvidenceMode.DEVELOPMENT_FALLBACK: "DEVELOPMENT FALLBACK / OFFLINE",
        EvidenceMode.DEMO_RESILIENCE: "DEMO RESILIENCE / OFFLINE",
        EvidenceMode.EVIDENCE_FALLBACK: "EVIDENCE FALLBACK / OFFLINE",
        EvidenceMode.MODEL_NON_ATTEMPT: (
            "MODEL NON-ATTEMPT / NO ENFORCEMENT CLAIM"
        ),
    }
    return labels[provenance.mode]


def _publication_review(
    evidence: ScenarioEvidence,
) -> Tuple[PublicationReviewStatus, Optional[str]]:
    package = evidence.publication
    if package is None:
        return PublicationReviewStatus.NOT_FINALIZED, None
    verification = verify_evidence_publication(package)
    if not verification.valid or verification.package is None:
        return PublicationReviewStatus.INVALID, None
    verified = verification.package
    if verified.trace_id != evidence.projection.trace_id:
        return PublicationReviewStatus.INVALID, None
    try:
        primitive = json.loads(verified.canonical_bytes.decode("utf-8"))
        packaged_projection = primitive["projection"]["value"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
        return PublicationReviewStatus.INVALID, None
    if packaged_projection != review_projection_to_primitive(evidence.projection):
        return PublicationReviewStatus.INVALID, None
    return PublicationReviewStatus.VERIFIED, verified.package_digest


def _integrity_status(
    projection: ReviewProjection,
    publication_status: PublicationReviewStatus,
) -> ScenarioIntegrityStatus:
    if (
        projection.integrity_status is ProjectionStatus.FAILED
        or publication_status is PublicationReviewStatus.INVALID
    ):
        return ScenarioIntegrityStatus.INVALID
    if projection.reconciliation_status is ProjectionStatus.FAILED:
        return ScenarioIntegrityStatus.CONFLICTING
    if (
        projection.evidence_completeness is EvidenceCompleteness.INCOMPLETE
        or publication_status is PublicationReviewStatus.NOT_FINALIZED
    ):
        return ScenarioIntegrityStatus.INCOMPLETE
    return ScenarioIntegrityStatus.CLEAN_COMPLETE


def _matches(
    expectation: ScenarioExpectation, projection: ReviewProjection
) -> bool:
    return (
        projection.disposition is expectation.decision
        and projection.primary_rule_id is expectation.primary_rule_id
        and projection.execution_status is expectation.execution_status
        and projection.execution_start_count == expectation.execution_start_count
        and projection.payment_count == expectation.payment_count
        and projection.replay_state is expectation.replay_state
        and projection.model_non_attempt is expectation.model_non_attempt
    )


def _decision_reference(scenario_id: ScenarioId) -> str:
    slug = scenario_id.value.lower().replace("_", "-")
    return f"decision-review-{slug}.html"


def _scenario_summary(evidence: ScenarioEvidence) -> ScenarioSummary:
    expectation = _EXPECTATIONS[evidence.scenario_id]
    publication_status, publication_digest = _publication_review(evidence)
    integrity = _integrity_status(evidence.projection, publication_status)
    comparison = (
        ComparisonStatus.INCOMPLETE
        if integrity is not ScenarioIntegrityStatus.CLEAN_COMPLETE
        else ComparisonStatus.MATCH
        if _matches(expectation, evidence.projection)
        else ComparisonStatus.MISMATCH
    )
    counts_are_authoritative = (
        integrity is ScenarioIntegrityStatus.CLEAN_COMPLETE
    )
    return ScenarioSummary(
        scenario_id=evidence.scenario_id,
        display_name=expectation.display_name,
        mode=evidence.provenance.mode,
        provenance_label=_provenance_label(evidence.provenance),
        provider_evidence_digest=evidence.provenance.provider_evidence_digest,
        expected_decision=_display_enum(expectation.decision),
        expected_primary_rule=_display_rule(expectation.primary_rule_id),
        expected_execution=_display_enum(expectation.execution_status),
        expected_execution_start_count=expectation.execution_start_count,
        expected_payment_count=expectation.payment_count,
        expected_replay=_display_enum(expectation.replay_state),
        expected_model_attempt=_model_attempt_display(
            expectation.model_non_attempt, expected=True
        ),
        observed_decision=_display_enum(evidence.projection.disposition),
        observed_primary_rule=_display_rule(evidence.projection.primary_rule_id),
        observed_execution=_display_enum(evidence.projection.execution_status),
        observed_execution_start_count=(
            evidence.projection.execution_start_count
            if counts_are_authoritative
            else None
        ),
        observed_payment_count=(
            evidence.projection.payment_count
            if counts_are_authoritative
            else None
        ),
        observed_replay=_display_enum(evidence.projection.replay_state),
        observed_model_attempt=_model_attempt_display(
            evidence.projection.model_non_attempt, expected=False
        ),
        callback_action=_display_enum(evidence.projection.callback_action),
        projection_completeness=_display_enum(
            evidence.projection.evidence_completeness
        ),
        projection_integrity=_display_enum(evidence.projection.integrity_status),
        projection_reconciliation=_display_enum(
            evidence.projection.reconciliation_status
        ),
        publication_status=publication_status,
        publication_digest=publication_digest,
        integrity=integrity,
        comparison=comparison,
        decision_review_reference=_decision_reference(evidence.scenario_id),
    )


def _run_integrity(
    scenarios: Tuple[ScenarioSummary, ...], missing_count: int
) -> ScenarioIntegrityStatus:
    values = {scenario.integrity for scenario in scenarios}
    if ScenarioIntegrityStatus.INVALID in values:
        return ScenarioIntegrityStatus.INVALID
    if ScenarioIntegrityStatus.CONFLICTING in values:
        return ScenarioIntegrityStatus.CONFLICTING
    if missing_count or ScenarioIntegrityStatus.INCOMPLETE in values:
        return ScenarioIntegrityStatus.INCOMPLETE
    return ScenarioIntegrityStatus.CLEAN_COMPLETE


def build_demo_run_summary(
    run_id: str, scenario_evidence: Tuple[ScenarioEvidence, ...]
) -> DemoRunSummary:
    """Build a presentation-only summary without changing supplied evidence."""

    if type(run_id) is not str or run_id == "":
        raise ValueError("run_id requires an exact non-empty string")
    if type(scenario_evidence) is not tuple or any(
        type(item) is not ScenarioEvidence for item in scenario_evidence
    ):
        raise TypeError("scenario evidence requires an exact immutable tuple")
    by_id = {}
    for evidence in scenario_evidence:
        if evidence.scenario_id in by_id:
            raise ValueError("duplicate scenario identity")
        by_id[evidence.scenario_id] = evidence
    scenarios = tuple(
        _scenario_summary(by_id[scenario_id])
        for scenario_id in REQUIRED_SCENARIO_ORDER
        if scenario_id in by_id
    )
    missing_count = len(REQUIRED_SCENARIO_ORDER) - len(scenarios)
    match_count = sum(
        scenario.comparison is ComparisonStatus.MATCH for scenario in scenarios
    )
    mismatch_count = sum(
        scenario.comparison is ComparisonStatus.MISMATCH for scenario in scenarios
    )
    incomplete_count = missing_count + sum(
        scenario.comparison is ComparisonStatus.INCOMPLETE
        for scenario in scenarios
    )
    status = (
        RunStatus.INCOMPLETE
        if incomplete_count
        else RunStatus.MISMATCH
        if mismatch_count
        else RunStatus.PASS
    )
    modes = tuple(sorted({scenario.mode.value for scenario in scenarios}))
    provenance_summary = (
        modes[0]
        if len(modes) == 1 and not missing_count
        else "MIXED / PER-SCENARIO PROVENANCE IS AUTHORITATIVE"
        if modes
        else "NOT AVAILABLE"
    )
    run_identity = "sha256:" + sha256(
        (_RUN_ID_DOMAIN + run_id).encode("utf-8")
    ).hexdigest()
    return DemoRunSummary(
        run_identity=run_identity,
        scenarios=scenarios,
        required_scenario_count=len(REQUIRED_SCENARIO_ORDER),
        observed_scenario_count=len(scenarios),
        missing_scenario_count=missing_count,
        match_count=match_count,
        mismatch_count=mismatch_count,
        incomplete_count=incomplete_count,
        status=status,
        integrity=_run_integrity(scenarios, missing_count),
        provenance_summary=provenance_summary,
    )


_STYLES = r"""
:root {
  --paper: #f3efe4;
  --raised: #fbf8f0;
  --ink: #18211d;
  --muted: #58635d;
  --line: #c8c1b1;
  --petrol: #173f46;
  --petrol-soft: #dce8e5;
  --green: #245c43;
  --green-soft: #dce9df;
  --red: #a63f24;
  --red-soft: #f4ded4;
  --amber: #805308;
  --amber-soft: #f2e5bf;
  --focus: #0b65c2;
}
* { box-sizing: border-box; }
html { background: var(--paper); color: var(--ink); font-family: Georgia, serif; }
body { margin: 0; min-width: 320px; }
a { color: var(--petrol); font-weight: 700; }
:focus-visible { outline: 3px solid var(--focus); outline-offset: 4px; }
.skip-link { position: fixed; top: .7rem; left: .7rem; padding: .6rem .8rem; background: var(--ink); color: white; transform: translateY(-180%); }
.skip-link:focus { transform: translateY(0); }
.boundary { padding: .75rem clamp(1rem, 3vw, 2.5rem); background: var(--petrol); color: white; font: 700 .72rem/1.4 Menlo, monospace; letter-spacing: .055em; text-transform: uppercase; }
.page { width: min(1600px, calc(100% - clamp(1rem, 4vw, 4rem))); margin: 0 auto; padding: 2rem 0 3rem; }
.masthead { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 2rem; align-items: end; }
h1 { margin: 0 0 .5rem; font-size: clamp(2.2rem, 5vw, 5rem); line-height: .95; letter-spacing: -.045em; }
h2 { margin-top: 2rem; }
p { line-height: 1.5; }
.lede { max-width: 70ch; color: var(--muted); }
.run-state { min-width: 16rem; padding: 1rem; border: 1px solid var(--line); background: var(--raised); }
.status { display: inline-flex; align-items: center; gap: .38rem; padding: .27rem .48rem; border: 1px solid currentColor; font: 800 .68rem/1.2 Menlo, monospace; letter-spacing: .045em; text-transform: uppercase; }
.status::before { width: .5rem; height: .5rem; border: 1.5px solid currentColor; content: ""; }
.status--match, .status--pass, .status--clean { color: var(--green); background: var(--green-soft); }
.status--mismatch, .status--invalid { color: var(--red); background: var(--red-soft); }
.status--incomplete, .status--conflicting { color: var(--amber); background: var(--amber-soft); }
.summary-grid { display: grid; grid-template-columns: repeat(7, minmax(8rem, 1fr)); gap: .7rem; margin: 1.2rem 0; }
.summary-grid div { padding: .72rem; border-top: 3px solid var(--petrol); background: var(--raised); }
dt { margin-bottom: .3rem; color: var(--muted); font: 700 .66rem/1.3 Menlo, monospace; letter-spacing: .06em; text-transform: uppercase; }
dd { margin: 0; overflow-wrap: anywhere; }
.table-wrap { overflow-x: auto; border: 1px solid var(--line); background: var(--raised); scrollbar-gutter: stable; }
table { width: 100%; min-width: 1480px; border-collapse: collapse; text-align: left; }
caption { padding: .8rem; color: var(--muted); text-align: left; }
th, td { padding: .7rem; border-bottom: 1px solid var(--line); vertical-align: top; }
th { background: var(--petrol-soft); font: 700 .68rem/1.3 Menlo, monospace; letter-spacing: .045em; text-transform: uppercase; }
td { font-size: .84rem; line-height: 1.4; }
tbody tr:last-child td { border-bottom: 0; }
.scenario-id, code { font-family: Menlo, monospace; font-size: .78em; overflow-wrap: anywhere; }
.facts { margin: 0; padding: 0; list-style: none; }
.facts li + li { margin-top: .3rem; }
.facts strong { color: var(--muted); }
.warning { margin: 1rem 0 0; padding: .75rem; border-left: 4px solid var(--amber); background: var(--amber-soft); }
.legend { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: .8rem; padding: 0; list-style: none; }
.legend li { padding-left: .7rem; border-left: 2px solid var(--line); }
.footer { margin-top: 1.3rem; padding-top: .8rem; border-top: 1px solid var(--line); color: var(--muted); font: .7rem/1.4 Menlo, monospace; }
@media (max-width: 900px) { .masthead { grid-template-columns: 1fr; } .summary-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } .legend { grid-template-columns: 1fr; } }
@media (max-width: 520px) { .page { width: calc(100% - 1rem); } .summary-grid { grid-template-columns: 1fr; } }
@media (prefers-reduced-motion: reduce) { *, *::before, *::after { scroll-behavior: auto !important; transition-duration: .01ms !important; } }
"""


def _tone(value: str) -> str:
    normalized = value.split(" / ", 1)[0]
    if normalized in {"MATCH", "PASS", "CLEAN"}:
        return normalized.lower()
    if normalized in {"MISMATCH", "INVALID"}:
        return normalized.lower()
    if normalized in {"INCOMPLETE", "CONFLICTING"}:
        return normalized.lower()
    return "incomplete"


def _status(value: str) -> str:
    return (
        f'<span class="status status--{_tone(value)}">'
        f"{escape(value)}</span>"
    )


def _count(value: Optional[int]) -> str:
    return str(value) if value is not None else "UNKNOWN — EVIDENCE INCOMPLETE"


def _short_digest(value: Optional[str]) -> str:
    if value is None:
        return "NOT AVAILABLE"
    return value[:18] + "…" + value[-8:]


def _provenance_details(scenario: ScenarioSummary) -> str:
    if scenario.mode is EvidenceMode.LIVE_MODEL:
        return (
            f"<strong>{escape(scenario.provenance_label)}</strong>"
            f"<br><code>{_LIVE_MODEL_IDENTIFIER}</code>"
            f"<br>{_LIVE_ACCESS_PATH}"
            f"<br>Provider evidence: <code>{escape(_short_digest(scenario.provider_evidence_digest))}</code>"
        )
    return (
        f"<strong>{escape(scenario.provenance_label)}</strong>"
        "<br>Live identifier/access path: NOT ASSERTED"
        "<br>Provider evidence: NOT ASSERTED"
    )


def _expected_facts(scenario: ScenarioSummary) -> str:
    return (
        '<ul class="facts">'
        f"<li><strong>Decision:</strong> {escape(scenario.expected_decision)}</li>"
        f"<li><strong>Primary rule:</strong> <code>{escape(scenario.expected_primary_rule)}</code></li>"
        f"<li><strong>Execution:</strong> {escape(scenario.expected_execution)} · starts {scenario.expected_execution_start_count}</li>"
        f"<li><strong>Payment:</strong> {scenario.expected_payment_count}</li>"
        f"<li><strong>Replay:</strong> {escape(scenario.expected_replay)}</li>"
        f"<li><strong>Model:</strong> {escape(scenario.expected_model_attempt)}</li>"
        "</ul>"
    )


def _observed_facts(scenario: ScenarioSummary) -> str:
    return (
        '<ul class="facts">'
        f"<li><strong>Decision:</strong> {escape(scenario.observed_decision)}</li>"
        f"<li><strong>Primary rule:</strong> <code>{escape(scenario.observed_primary_rule)}</code></li>"
        f"<li><strong>Execution:</strong> {escape(scenario.observed_execution)} · starts {escape(_count(scenario.observed_execution_start_count))}</li>"
        f"<li><strong>Payment:</strong> {escape(_count(scenario.observed_payment_count))}</li>"
        f"<li><strong>Replay:</strong> {escape(scenario.observed_replay)}</li>"
        f"<li><strong>Model:</strong> {escape(scenario.observed_model_attempt)}</li>"
        f"<li><strong>Callback:</strong> {escape(scenario.callback_action)}</li>"
        "</ul>"
    )


def _integrity_facts(scenario: ScenarioSummary) -> str:
    return (
        '<ul class="facts">'
        f"<li><strong>Overall:</strong> {_status(scenario.integrity.value)}</li>"
        f"<li><strong>Completeness:</strong> {escape(scenario.projection_completeness)}</li>"
        f"<li><strong>Integrity:</strong> {escape(scenario.projection_integrity)}</li>"
        f"<li><strong>Reconciliation:</strong> {escape(scenario.projection_reconciliation)}</li>"
        f"<li><strong>Publication:</strong> {escape(scenario.publication_status.value)}</li>"
        f"<li><strong>Digest:</strong> <code>{escape(_short_digest(scenario.publication_digest))}</code></li>"
        "</ul>"
    )


def _scenario_row(scenario: ScenarioSummary) -> str:
    return (
        "<tr>"
        f'<td><strong>{escape(scenario.display_name)}</strong><br><code class="scenario-id">{scenario.scenario_id.value}</code></td>'
        f"<td>{_provenance_details(scenario)}</td>"
        f"<td>{_expected_facts(scenario)}</td>"
        f"<td>{_observed_facts(scenario)}</td>"
        f"<td>{_integrity_facts(scenario)}</td>"
        f"<td>{_status(scenario.comparison.value)}</td>"
        f'<td><a href="{scenario.decision_review_reference}" aria-label="Open {escape(scenario.display_name)} decision review">Open decision review</a></td>'
        "</tr>"
    )


def _missing_row(expectation: ScenarioExpectation) -> str:
    return (
        "<tr>"
        f'<td><strong>{escape(expectation.display_name)}</strong><br><code class="scenario-id">{expectation.scenario_id.value}</code></td>'
        "<td>NOT AVAILABLE</td>"
        '<td><ul class="facts">'
        f"<li><strong>Decision:</strong> {escape(_display_enum(expectation.decision))}</li>"
        f"<li><strong>Primary rule:</strong> <code>{escape(_display_rule(expectation.primary_rule_id))}</code></li>"
        f"<li><strong>Execution:</strong> {escape(_display_enum(expectation.execution_status))} · starts {expectation.execution_start_count}</li>"
        f"<li><strong>Payment:</strong> {expectation.payment_count}</li>"
        f"<li><strong>Replay:</strong> {escape(_display_enum(expectation.replay_state))}</li>"
        f"<li><strong>Model:</strong> {escape(_model_attempt_display(expectation.model_non_attempt, expected=True))}</li>"
        "</ul></td>"
        "<td><strong>MISSING REQUIRED SCENARIO</strong><br>UNKNOWN — EVIDENCE INCOMPLETE</td>"
        f"<td>{_status(ScenarioIntegrityStatus.INCOMPLETE.value)}</td>"
        f"<td>{_status(ComparisonStatus.INCOMPLETE.value)}</td>"
        "<td>NOT AVAILABLE — NO DECISION EVIDENCE</td>"
        "</tr>"
    )


def render_demo_run_summary(summary: DemoRunSummary) -> str:
    """Render one immutable summary as self-contained, read-only HTML."""

    if type(summary) is not DemoRunSummary:
        raise TypeError("demo run summary renderer requires DemoRunSummary")
    by_id = {scenario.scenario_id: scenario for scenario in summary.scenarios}
    rows = "".join(
        _scenario_row(by_id[scenario_id])
        if scenario_id in by_id
        else _missing_row(_EXPECTATIONS[scenario_id])
        for scenario_id in REQUIRED_SCENARIO_ORDER
    )
    warning = (
        ""
        if summary.status is RunStatus.PASS
        else '<p class="warning"><strong>WARNING — INCOMPLETE EVIDENCE OR MISMATCH.</strong> The run is not presented as success; inspect every row and its decision evidence.</p>'
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>TIDEMARK Demo Run Summary</title>
  <style>{_STYLES}</style>
</head>
<body>
  <a class="skip-link" href="#scenario-matrix">Skip to scenario matrix</a>
  <header class="boundary">Read-only runtime evidence · derived presentation · no authorization, execution, retry, reset, repair, or publication controls</header>
  <main class="page">
    <header class="masthead">
      <div>
        <h1>TIDEMARK Demo Run Summary</h1>
        <p class="lede">Expected scenario contracts remain separate from observed ReviewProjection evidence. Offline evidence does not satisfy live Gemini or Google Cloud acceptance.</p>
      </div>
      <dl class="run-state"><dt>Run status</dt><dd>{_status(summary.status.value)}</dd><dt>Integrity</dt><dd>{_status(summary.integrity.value)}</dd></dl>
    </header>

    <section aria-labelledby="run-context-title">
      <h2 id="run-context-title">Run context</h2>
      <dl class="summary-grid">
        <div><dt>Run identity</dt><dd><code>{escape(_short_digest(summary.run_identity))}</code></dd></div>
        <div><dt>Mode / provenance</dt><dd>{escape(summary.provenance_summary)}<br>See each scenario for authoritative presentation context.</dd></div>
        <div><dt>Required</dt><dd>{summary.required_scenario_count}</dd></div>
        <div><dt>Observed</dt><dd>{summary.observed_scenario_count}</dd></div>
        <div><dt>Matches</dt><dd>{summary.match_count}</dd></div>
        <div><dt>Mismatches</dt><dd>{summary.mismatch_count}</dd></div>
        <div><dt>Incomplete / missing</dt><dd>{summary.incomplete_count}</dd></div>
      </dl>
      {warning}
    </section>

    <section id="scenario-matrix" aria-labelledby="scenario-matrix-title">
      <h2 id="scenario-matrix-title">Expected versus observed scenario matrix</h2>
      <div class="table-wrap" tabindex="0" aria-label="Required scenario matrix horizontal scroll region">
        <table>
          <caption>Six fixed Order 17 cases. A MATCH requires complete, clean projection evidence and a verified matching publication package.</caption>
          <thead><tr><th scope="col">Scenario</th><th scope="col">Mode / provenance</th><th scope="col">Expected</th><th scope="col">Observed</th><th scope="col">Integrity / completeness</th><th scope="col">Comparison</th><th scope="col">Decision evidence</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </section>

    <aside aria-labelledby="legend-title">
      <h2 id="legend-title">Text-state legend</h2>
      <ul class="legend">
        <li><strong>MATCH</strong><br>Every compared field agrees and evidence is complete, clean, and publication-verified.</li>
        <li><strong>MISMATCH</strong><br>Complete observed evidence disagrees with the fixed expected contract.</li>
        <li><strong>INCOMPLETE</strong><br>Missing, conflicting, invalid, or unfinalized evidence; never success.</li>
        <li><strong>MODEL NON-ATTEMPT</strong><br>No candidate call; not DENY, not callback veto, and not enforcement success.</li>
        <li><strong>REPLAY REJECTED</strong><br>The original one execution and one payment remain; no second start or payment is claimed.</li>
        <li><strong>Decision reference</strong><br>A deterministic read-only artifact reference for the existing Order 16 reviewer.</li>
      </ul>
    </aside>

    <footer class="footer">Static local HTML · no JavaScript · no provider/network/cloud dependency · reference UI, not final visual language</footer>
  </main>
</body>
</html>"""


__all__ = (
    "ComparisonStatus",
    "DemoRunSummary",
    "EvidenceMode",
    "PublicationReviewStatus",
    "REQUIRED_SCENARIO_CONTRACTS",
    "REQUIRED_SCENARIO_ORDER",
    "RunStatus",
    "ScenarioEvidence",
    "ScenarioExpectation",
    "ScenarioId",
    "ScenarioIntegrityStatus",
    "ScenarioProvenance",
    "ScenarioSummary",
    "build_demo_run_summary",
    "render_demo_run_summary",
)
