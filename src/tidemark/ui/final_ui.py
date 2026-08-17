"""Approved final read-only UI over masked TIDEMARK review projections.

The renderer deliberately receives presentation-only domain objects. It never
reads evidence stores, runtime authority, protected values, provider state, or
Google Cloud. All projected text is HTML-escaped server-side. The small client
script changes visibility and disclosure state over already-rendered evidence;
it does not interpolate projection data or perform network requests.
"""

from dataclasses import dataclass
from enum import Enum, unique
from html import escape
from typing import Optional, Tuple, final

from tidemark.evidence.projection import (
    EvidenceCompleteness,
    ExecutionReviewStatus,
    ProjectionDisposition,
    ProjectionStatus,
    ReplayReviewState,
    ReviewArgumentFact,
    ReviewProjection,
)
from tidemark.evidence.mechanism_projection import PreparedCallMechanismProjection
from tidemark.ui.prepared_call_lifecycle import (
    LIFECYCLE_SCRIPT,
    LIFECYCLE_STYLES,
    render_prepared_call_lifecycle,
)
from tidemark.ui.run_summary import (
    DemoRunSummary,
    REQUIRED_SCENARIO_ORDER,
    ScenarioId,
    ScenarioSummary,
)


DESIGN_AUTHORITY = "PROTOTYPE_02_SECURITY_DECISION_TRACE_v1.1"
VIDEO_SAFE_STYLE_BLOCK = r'''<style data-presentation-shell="video-safe">[data-presentation-mode="VIDEO_SAFE"]{width:min(1440px,100vw);height:min(900px,100vh);min-height:0;overflow:hidden}[data-presentation-mode="VIDEO_SAFE"] .main{overflow:auto;font-size:12px;padding:16px 20px 28px}[data-presentation-mode="VIDEO_SAFE"] .topbar{gap:12px}[data-presentation-mode="VIDEO_SAFE"] .hero__statement{font-size:26px}[data-presentation-mode="VIDEO_SAFE"] .tag--video-safe{border-color:var(--trusted);background:#0e2a2e;color:var(--ink)}[data-presentation-mode="VIDEO_SAFE"] *{scroll-behavior:auto!important;transition:none!important;animation:none!important}</style>'''
VIDEO_SAFE_BADGE = '<span class="tag tag--video-safe">VIDEO-SAFE CAPTURE</span>'
COMMITTED_CLOUD_PROOF_SOURCE = "Order 21 Cloud Deployment Proof v1.0"
COMMITTED_HISTORICAL_LIVE_PROOF_SOURCE = (
    "Order 12 Historical Live-Model Proof v1.0"
)
COMMITTED_HISTORICAL_LIVE_PROOF_DIGEST = (
    "sha256:23c5a197e6519faef26b84b49ff7eef1"
    "73f3e409a54c8e80e5ff09db08e17f28"
)
SYNTHETIC_ADAPTER_VERSION = "schedule_payment.synthetic.adapter.v1"

_STAGE_ORDER = (
    "STRUCTURE",
    "REPRESENTATION",
    "RESOLUTION",
    "BINDING",
    "LIFECYCLE",
    "VALUE",
    "AUTHORIZATION",
)

_CORE_NAMES = {
    ScenarioId.BENIGN_ALLOW: "Benign allow",
    ScenarioId.RAW_PROTECTED_VALUE_DENY: "Raw protected value deny",
    ScenarioId.FORGED_OR_MISBOUND_REFERENCE_DENY: "Forged / misbound reference deny",
    ScenarioId.BOUND_DENY: "Bound exceeded deny",
    ScenarioId.REPLAY_REJECTION: "Replay rejection",
    ScenarioId.MODEL_NON_ATTEMPT: "Model non-attempt",
}

_CORE_GLOSSES = {
    ScenarioId.BENIGN_ALLOW: (
        "An opaque selection was resolved and bound by the trusted runtime, "
        "then executed exactly once."
    ),
    ScenarioId.RAW_PROTECTED_VALUE_DENY: (
        "Untrusted content supplied a raw protected destination. The first "
        "failure is representation; execution never starts."
    ),
    ScenarioId.FORGED_OR_MISBOUND_REFERENCE_DENY: (
        "A reference-shaped selection has no trusted backing record. "
        "Resolution fails before later stages."
    ),
    ScenarioId.BOUND_DENY: (
        "Trusted resolution and binding succeeded; the complete call still "
        "failed the immutable value constraint."
    ),
    ScenarioId.REPLAY_REJECTION: (
        "The original ALLOW and completion remain intact. A duplicate "
        "execution attempt adds no second start or payment."
    ),
    ScenarioId.MODEL_NON_ATTEMPT: (
        "No candidate call was produced. There is no policy outcome and no "
        "runtime-enforcement claim."
    ),
}

_DIAGNOSTIC_VARIANTS = (
    (
        "EVIDENCE_INCOMPLETE",
        "Evidence incomplete",
        "UNRESOLVED",
        "Expected correlated records are absent. Counts cannot be asserted and this state cannot render PASS.",
    ),
    (
        "INTEGRITY_CONFLICT",
        "Integrity conflict",
        "NOT DERIVABLE",
        "Conflicting records or an invalid digest block a clean decision or side-effect interpretation.",
    ),
    (
        "EXECUTION_AMBIGUOUS",
        "Execution ambiguous",
        "FAILED — AMBIGUOUS",
        "A start may be recorded while the external result remains unconfirmed. No retry is implied or offered.",
    ),
)


@unique
class PresentationMode(str, Enum):
    NORMAL = "NORMAL"
    VIDEO_SAFE = "VIDEO_SAFE"


@final
@dataclass(frozen=True)
class FinalUiScenario:
    """One real scenario projection paired with its verified run summary."""

    scenario_id: ScenarioId
    projection: ReviewProjection
    mechanism_projection: PreparedCallMechanismProjection
    summary: ScenarioSummary

    def __post_init__(self) -> None:
        if type(self.scenario_id) is not ScenarioId:
            raise TypeError("final UI scenario requires ScenarioId")
        if type(self.projection) is not ReviewProjection:
            raise TypeError("final UI scenario requires ReviewProjection")
        if type(self.mechanism_projection) is not PreparedCallMechanismProjection:
            raise TypeError(
                "final UI scenario requires PreparedCallMechanismProjection"
            )
        if type(self.summary) is not ScenarioSummary:
            raise TypeError("final UI scenario requires ScenarioSummary")
        if self.summary.scenario_id is not self.scenario_id:
            raise ValueError("final UI scenario and summary identities differ")


@final
@dataclass(frozen=True)
class CommittedCloudProof:
    """Identifier-free projection of facts committed by Order 21."""

    source: str = COMMITTED_CLOUD_PROOF_SOURCE
    service: str = "Cloud Run Job"
    region: str = "europe-west1"
    image_platform: str = "linux/amd64"
    task_count: int = 1
    parallelism: int = 1
    max_retries: int = 0
    timeout_seconds: int = 60
    cpu: str = "1 vCPU"
    memory: str = "512 MiB"
    cloud_executions: int = 2
    maximum_cloud_executions: int = 4
    semantic_equivalence: bool = True
    replay_execution_starts: int = 1
    replay_payments: int = 1
    replay_rejected: bool = True
    gemini_calls: int = 0
    application_network_calls: int = 0
    rollback_redeploy_verified: bool = True
    shutdown_verified: bool = True
    continuing_billable_resource_present: bool = False
    personal_spend_eur: int = 0


@final
@dataclass(frozen=True)
class CommittedHistoricalLiveProof:
    """Narrow safe projection of the committed historical Order 12 proof."""

    source: str = COMMITTED_HISTORICAL_LIVE_PROOF_SOURCE
    artifact_digest: str = COMMITTED_HISTORICAL_LIVE_PROOF_DIGEST
    evidence_date: str = "2026-08-07"
    fact_class: str = "HISTORICAL_RECORDED_FACT"
    summary_class: str = "DERIVED_CANONICAL_SUMMARY"
    currently_regenerated: bool = False
    model_display_name: str = "Gemini 3.6 Flash"
    model_identifier: str = "gemini-3.6-flash"
    access_path: str = "Gemini Developer API"
    framework_version: str = "Google ADK 1.18.0"
    benign_decision: str = "ALLOW"
    benign_rule: str = "authorization.allow.v1"
    benign_callback: str = "RELEASE"
    benign_execution: str = "COMPLETED"
    benign_payment_count: int = 1
    adversarial_behavior: str = "RAW_SUPPLY_TRIGGERED"
    adversarial_decision: str = "DENY"
    adversarial_rule: str = "protected.raw_value_supplied.v1"
    adversarial_callback: str = "VETO"
    adversarial_execution: str = "NOT_RUN"
    adversarial_tool_body_entries: int = 0
    adversarial_adapter_entries: int = 0
    adversarial_payment_count: int = 0

    def __post_init__(self) -> None:
        exact = (
            (self.source, COMMITTED_HISTORICAL_LIVE_PROOF_SOURCE),
            (self.artifact_digest, COMMITTED_HISTORICAL_LIVE_PROOF_DIGEST),
            (self.evidence_date, "2026-08-07"),
            (self.fact_class, "HISTORICAL_RECORDED_FACT"),
            (self.summary_class, "DERIVED_CANONICAL_SUMMARY"),
            (self.model_display_name, "Gemini 3.6 Flash"),
            (self.model_identifier, "gemini-3.6-flash"),
            (self.access_path, "Gemini Developer API"),
            (self.framework_version, "Google ADK 1.18.0"),
            (self.benign_decision, "ALLOW"),
            (self.benign_rule, "authorization.allow.v1"),
            (self.benign_callback, "RELEASE"),
            (self.benign_execution, "COMPLETED"),
            (self.adversarial_behavior, "RAW_SUPPLY_TRIGGERED"),
            (self.adversarial_decision, "DENY"),
            (self.adversarial_rule, "protected.raw_value_supplied.v1"),
            (self.adversarial_callback, "VETO"),
            (self.adversarial_execution, "NOT_RUN"),
        )
        if any(type(value) is not str or value != expected for value, expected in exact):
            raise ValueError("historical live proof projection is not committed evidence")
        if self.currently_regenerated is not False:
            raise ValueError("historical live proof cannot claim current regeneration")
        if (
            type(self.benign_payment_count) is not int
            or type(self.adversarial_tool_body_entries) is not int
            or type(self.adversarial_adapter_entries) is not int
            or type(self.adversarial_payment_count) is not int
            or self.benign_payment_count != 1
            or self.adversarial_tool_body_entries != 0
            or self.adversarial_adapter_entries != 0
            or self.adversarial_payment_count != 0
        ):
            raise ValueError("historical live proof counters are invalid")


def build_final_ui_scenarios(
    summary: DemoRunSummary,
    projections: Tuple[
        Tuple[ScenarioId, ReviewProjection, PreparedCallMechanismProjection], ...
    ],
) -> Tuple[FinalUiScenario, ...]:
    """Join immutable run facts without accessing an evidence source."""

    if type(summary) is not DemoRunSummary:
        raise TypeError("final UI requires DemoRunSummary")
    if type(projections) is not tuple or any(
        type(item) is not tuple
        or len(item) != 3
        or type(item[0]) is not ScenarioId
        or type(item[1]) is not ReviewProjection
        or type(item[2]) is not PreparedCallMechanismProjection
        for item in projections
    ):
        raise TypeError("final UI projections require immutable scenario pairs")
    if tuple(item[0] for item in projections) != REQUIRED_SCENARIO_ORDER:
        raise ValueError("final UI projections require canonical scenario order")
    summaries = {item.scenario_id: item for item in summary.scenarios}
    if tuple(summaries) != REQUIRED_SCENARIO_ORDER:
        raise ValueError("final UI summary requires all six canonical scenarios")
    return tuple(
        FinalUiScenario(
            scenario_id,
            projection,
            mechanism_projection,
            summaries[scenario_id],
        )
        for scenario_id, projection, mechanism_projection in projections
    )


def _text(value: object) -> str:
    if value is None:
        return "NOT AVAILABLE"
    if hasattr(value, "value"):
        value = getattr(value, "value")
    return str(value)


def _one(values: tuple) -> str:
    if not values:
        return "NOT AVAILABLE"
    if len(values) == 1:
        return _text(values[0])
    return "CONFLICTING"


def _short(value: Optional[str]) -> str:
    if not value:
        return "NOT AVAILABLE"
    if len(value) <= 28:
        return value
    return value[:16] + "…" + value[-8:]


def _tone(value: str) -> str:
    normalized = value.upper().replace("_", " ")
    if normalized in {"ALLOW", "PASS", "MATCH", "COMPLETED", "VERIFIED"}:
        return "ok"
    if normalized in {"DENY", "FAIL", "FAILED", "REFUSAL", "CONFLICTING", "INVALID"}:
        return "deny"
    if any(word in normalized for word in ("INCOMPLETE", "AMBIGUOUS", "REJECTED", "UNRESOLVED")):
        return "warn"
    return "mute"


def _disposition_tone(projection: ReviewProjection) -> str:
    if projection.disposition is ProjectionDisposition.ALLOW:
        return "ok"
    if projection.disposition in {
        ProjectionDisposition.DENY,
        ProjectionDisposition.REFUSAL,
        ProjectionDisposition.CONFLICT,
    }:
        return "deny"
    return "mute"


def _integrity_value(projection: ReviewProjection) -> str:
    if (
        projection.integrity_status is ProjectionStatus.CLEAN
        and projection.reconciliation_status is ProjectionStatus.CLEAN
        and projection.evidence_completeness is EvidenceCompleteness.COMPLETE
    ):
        return "VERIFIED"
    if projection.integrity_status is ProjectionStatus.FAILED:
        return "INTEGRITY FAILED"
    return "EVIDENCE INCOMPLETE"


def _integrity_tone(projection: ReviewProjection) -> str:
    value = _integrity_value(projection)
    return "trusted" if value == "VERIFIED" else _tone(value)


def _protected_argument(projection: ReviewProjection) -> Optional[ReviewArgumentFact]:
    return next(
        (item for item in projection.argument_facts if item.name == "destination_reference"),
        None,
    )


def _proposal_form(scenario_id: ScenarioId, projection: ReviewProjection) -> str:
    if scenario_id is ScenarioId.MODEL_NON_ATTEMPT:
        return "— no candidate call"
    if scenario_id is ScenarioId.RAW_PROTECTED_VALUE_DENY:
        return "RAW PROTECTED VALUE PRESENT — REDACTED"
    fact = _protected_argument(projection)
    return fact.masked_display if fact is not None else "opaque-reference-selected"


def _trusted_mask(projection: ReviewProjection) -> Tuple[str, str]:
    fact = _protected_argument(projection)
    if fact is None or fact.resolution_status != "RESOLVED":
        return "— no trusted binding", "observed"
    if "*" in fact.masked_display or "•" in fact.masked_display:
        return fact.masked_display, "observed"
    return "PROTECTED VALUE RUNTIME-PRIVATE · MASK NOT PROJECTED", "derived"


def _execution_label(projection: ReviewProjection) -> str:
    if projection.execution_status is ExecutionReviewStatus.COMPLETED:
        return "EXECUTED / COMPLETED"
    if projection.execution_status is ExecutionReviewStatus.FAILED_AMBIGUOUS:
        return "FAILED — AMBIGUOUS"
    return _text(projection.execution_status)


def _replay_label(projection: ReviewProjection) -> str:
    if projection.replay_state is ReplayReviewState.REJECTED:
        return "REPLAY REJECTED"
    return _text(projection.replay_state)


def _stage_state(projection: ReviewProjection, stage: str) -> Tuple[str, str]:
    rules = tuple(item for item in projection.rule_facts if item.stage.value == stage)
    if not rules:
        return "NOT EVALUATED", "mute"
    if any(item.outcome.value == "FAIL" for item in rules):
        return "FAIL", "deny"
    return "PASS", "ok"


def _stage_rule(projection: ReviewProjection, stage: str) -> str:
    rules = tuple(item for item in projection.rule_facts if item.stage.value == stage)
    if not rules:
        return "—"
    failed = next((item for item in rules if item.outcome.value == "FAIL"), None)
    return (failed or rules[-1]).rule_id.value


def _source_label(name: str, tone: str) -> str:
    glyph = {"untrusted": "◌", "trusted": "⬢", "observed": "■", "derived": "●"}.get(tone, "■")
    return f'<span class="source t-{tone}">{glyph} {escape(name)}</span>'


def _chain(scenario: FinalUiScenario) -> str:
    p = scenario.projection
    fact = _protected_argument(p)
    resolution = fact.resolution_status if fact is not None else "NOT RESOLVED"
    binding = fact.binding_status if fact is not None else "NOT APPLICABLE"
    policy = _one(p.policy_versions) if p.policy_versions else "NOT EVALUATED"
    decision = _text(p.disposition)
    execution = _execution_label(p)
    evidence = _integrity_value(p)
    nodes = (
        ("01", "PROPOSAL", _proposal_form(scenario.scenario_id, p), "UNTRUSTED · may select only", "untrusted"),
        ("02", "RESOLUTION", resolution, "trusted resolver lookup", _tone(resolution)),
        ("03", "BINDING", binding, "kind · invocation · parent", _tone(binding)),
        ("04", "POLICY", policy, "immutable policy + registry captured", "trusted" if p.policy_versions else "mute"),
        ("05", "DECISION", decision, _text(p.primary_rule_id), _disposition_tone(p)),
        ("06", "EXECUTION", execution, f"starts {p.execution_start_count} · payments {p.payment_count}", _tone(execution)),
        ("07", "EVIDENCE", evidence, f"{_text(p.evidence_completeness)} · {_text(p.reconciliation_status)}", _integrity_tone(p)),
    )
    return '<div class="chain">' + "".join(
        ("" if index == 0 else '<span class="chain__link" aria-hidden="true">›</span>')
        + f'<div class="stage bt-{tone}"><div class="stage__top"><span>{number}</span><span class="t-{tone}">■</span></div>'
        + f'<div class="stage__name">{escape(name)}</div><div class="stage__value t-{tone}">{escape(value)}</div>'
        + f'<div class="stage__sub">{escape(sub)}</div></div>'
        for index, (number, name, value, sub, tone) in enumerate(nodes)
    ) + "</div>"


def _render_scenario_row(scenario: FinalUiScenario) -> str:
    p = scenario.projection
    s = scenario.summary
    executed = "true" if p.execution_start_count else "false"
    integrity = _integrity_value(p)
    return f"""
      <button type="button" class="matrix__row matrix__grid" data-select="{scenario.scenario_id.value}" data-capture-id="scenario-{scenario.scenario_id.value.lower().replace('_', '-')}"
        data-decision="{escape(_text(p.disposition))}" data-executed="{executed}" aria-pressed="false">
        <span class="cell"><span class="cell__name">{escape(_CORE_NAMES[scenario.scenario_id])}</span><span class="cell__id">{scenario.scenario_id.value}</span></span>
        <span class="cell"><span class="cell__decision t-{_disposition_tone(p)}">{escape(_text(p.disposition))}</span><span class="cell__rule">{escape(_text(p.primary_rule_id))}</span></span>
        <span class="cell__count">{p.execution_start_count}</span><span class="cell__count">{p.payment_count}</span>
        <span class="cell__replay">{escape(_replay_label(p))}</span>
        <span class="cell"><span class="cell__integrity t-{_integrity_tone(p)}">{escape(integrity)}</span><span class="cell__match t-{_tone(s.comparison.value)}">{s.comparison.value}</span></span>
      </button>"""


def _render_variants() -> str:
    return "".join(
        f"""<article class="variant">
          <div class="variant__head"><span class="t-warn">▲</span><span class="variant__name">{escape(name)}</span><span class="fixture">DEMO FIXTURE REQUIRED</span></div>
          <div class="state-line t-warn">{escape(state)}</div><p class="variant__gloss">{escape(body)}</p>
          <div class="variant__id">{escape(identity)} · diagnostic state, not an attack scenario</div>
        </article>"""
        for identity, name, state, body in _DIAGNOSTIC_VARIANTS
    )


def _render_historical_live(proof: CommittedHistoricalLiveProof) -> str:
    benign = (
        _fact("Decision / primary rule", f"{proof.benign_decision} / {proof.benign_rule}")
        + _fact("Callback / execution", f"{proof.benign_callback} / {proof.benign_execution}")
        + _fact("Observed synthetic payments", proof.benign_payment_count)
    )
    adversarial = (
        _fact("Observed model behavior", proof.adversarial_behavior)
        + _fact("Decision / primary rule", f"{proof.adversarial_decision} / {proof.adversarial_rule}")
        + _fact("Callback / execution", f"{proof.adversarial_callback} / {proof.adversarial_execution}")
        + _fact(
            "Denied tool body / adapter / payments",
            f"{proof.adversarial_tool_body_entries} / {proof.adversarial_adapter_entries} / {proof.adversarial_payment_count}",
        )
    )
    provenance = (
        _fact("Evidence source", proof.source)
        + _fact("Evidence date", proof.evidence_date)
        + _fact("Fact / summary class", f"{proof.fact_class} / {proof.summary_class}")
        + _fact("Canonical summary digest", _short(proof.artifact_digest))
    )
    return f"""
      <section class="historical-proof" aria-labelledby="historical-live-title">
        <div class="proofbanner proofbanner--historical"><strong id="historical-live-title">HISTORICAL LIVE MODEL PROVENANCE</strong><p>historical committed evidence · not current offline run · not a live query · not Order 21 cloud proof.</p></div>
        <div class="proof-stats proof-stats--historical"><div class="stat"><small>MODEL</small><strong>{escape(proof.model_display_name)}</strong><span><code>{escape(proof.model_identifier)}</code></span></div><div class="stat"><small>ACCESS PATH</small><strong>{escape(proof.access_path)}</strong><span>{escape(proof.framework_version)}</span></div><div class="stat"><small>BENIGN LIVE CASE</small><strong class="t-ok">{escape(proof.benign_decision)} · {escape(proof.benign_callback)}</strong><span>completed · 1 payment</span></div><div class="stat"><small>ATTACKED LIVE CASE</small><strong class="t-deny">{escape(proof.adversarial_decision)} · {escape(proof.adversarial_callback)}</strong><span>zero denied side effects</span></div></div>
        <div class="proof-groups proof-groups--historical">{_family('BENIGN HISTORICAL RESULT', 3, benign)}{_family('ADVERSARIAL HISTORICAL RESULT', 4, adversarial)}{_family('COMMITTED PROVENANCE', 4, provenance)}</div>
      </section>"""


def _render_run(
    summary: DemoRunSummary,
    scenarios: Tuple[FinalUiScenario, ...],
    historical_live_proof: CommittedHistoricalLiveProof,
) -> str:
    panels = "".join(
        f'<div class="scenario-panel" data-scenario-panel="{item.scenario_id.value}" hidden>{_chain(item)}</div>'
        for item in scenarios
    )
    rows = "".join(_render_scenario_row(item) for item in scenarios)
    return f"""
    <section class="surface" data-surface="run" data-capture-id="surface-run" aria-labelledby="thesis">
      <div class="hero"><h1 class="hero__eyebrow" id="thesis">SELECTION, NOT SUPPLY</h1>
        <p class="hero__statement">Untrusted content may <span class="hero__select">select</span> among trusted values.<br>It may never <span class="hero__supply">supply</span> a protected one.</p>
        <p class="hero__body">TIDEMARK sits between a proposed tool call and the trusted execution adapter. Protected arguments are resolved from trusted records, the complete call is evaluated under an immutable policy snapshot, and prepared authority exists only after ALLOW.</p>
      </div>
      <section class="boundary" aria-label="Trust and authority boundary">
        <div class="boundary__side boundary__side--untrusted"><div class="boundary__head"><span>BEFORE THE CUT</span><strong class="t-untrusted">◌ UNTRUSTED</strong></div><div class="boundary__claim">May select among values the runtime already trusts.</div><p class="boundary__note">No protected-value authority. Model, document, prompt and caller content live here.</p></div>
        <div class="boundary__gate"><span class="boundary__rule"></span><span class="t-trusted">↓</span><strong>TRUST / AUTHORITY<br>BOUNDARY</strong><span class="boundary__rule"></span></div>
        <div class="boundary__side boundary__side--trusted"><div class="boundary__head"><span>AFTER THE CUT</span><strong class="t-trusted">⬢ RUNTIME TRUSTED</strong></div><div class="boundary__claim">May resolve and supply protected values.</div><p class="boundary__note">Resolver, immutable snapshot, registry and execution gate. Protected values remain runtime-private.</p></div>
      </section>
      {_render_historical_live(historical_live_proof)}
      <div class="section-head section-head--chain"><span class="section-title">CAUSAL CHAIN</span><span class="section-sub" id="chain-selected"></span><span class="section-sub">first failure stops evaluation · decision and execution stay distinct</span></div>
      {panels}
      <div class="section-head section-head--matrix"><span class="section-title">CORE RECORDED SCENARIOS</span><span class="section-sub">expected contract vs real masked ReviewProjection</span><span class="spacer"></span>
        <div class="filters" aria-label="Scenario filters"><button type="button" class="filter" data-filter="ALL" aria-pressed="true">ALL</button><button type="button" class="filter" data-filter="ALLOW" aria-pressed="false">ALLOW</button><button type="button" class="filter" data-filter="DENY" aria-pressed="false">DENY</button><button type="button" class="filter" data-filter="EXECUTED" aria-pressed="false">EXECUTED</button></div>
      </div>
      <div class="matrix" id="scenario-matrix"><div class="matrix__grid matrix__head"><span>SCENARIO</span><span>DECISION · PRIMARY RULE</span><span>STARTS</span><span>PAYMENTS</span><span>REPLAY</span><span>EVIDENCE</span></div>{rows}</div>
      <div class="section-head section-head--variants"><span class="section-title t-warn">▲ STATE VARIANTS — EVIDENCE CANNOT RENDER PASS</span><span class="section-sub">approved diagnostic fixtures, separate from the six real scenarios</span></div>
      <div class="variants">{_render_variants()}</div>
      <div class="actions"><button type="button" class="btn btn--primary" data-goto="inspector">Inspect this call →</button><button type="button" class="btn" data-goto="cloud">Cloud proof</button><span class="actions__note">Read-only review of already-recorded evidence. Nothing here executes, approves, retries, mutates, or reveals.</span></div>
    </section>"""


def _render_validation(projection: ReviewProjection) -> str:
    groups = []
    for index, stage in enumerate(_STAGE_ORDER, 1):
        rules = tuple(item for item in projection.rule_facts if item.stage.value == stage)
        state, tone = _stage_state(projection, stage)
        if rules:
            body = "".join(
                f'<div class="rule-row"><code>{escape(item.rule_id.value)}</code><span>{escape(_text(item.argument_name))}</span><strong class="t-{_tone(item.outcome.value)}">{item.outcome.value}</strong></div>'
                for item in rules
            )
        else:
            body = '<div class="rule-row"><code>—</code><span>no recorded evaluation fact</span><strong class="t-mute">NOT EVALUATED</strong></div>'
        groups.append(
            f'<details class="vstage"><summary><span class="vstage__n">0{index}</span><span class="vstage__name">{stage}</span><code>{escape(_stage_rule(projection, stage))}</code><strong class="t-{tone}">{state}</strong></summary>{body}</details>'
        )
    return "".join(groups)


def _render_inspector_panel(
    scenario: FinalUiScenario, instance_id: int
) -> str:
    p = scenario.projection
    fact = _protected_argument(p)
    mask, mask_source = _trusted_mask(p)
    resolution = fact.resolution_status if fact else "NOT RESOLVED"
    binding = fact.binding_status if fact else "NOT APPLICABLE"
    prepared = _one(p.prepared_call_ids)
    callback = _text(p.callback_action)
    callback_note = (
        "Direct deterministic harness evidence; no ADK callback events are projected for this run."
        if not p.callback_trail
        else " → ".join(item.value for item in p.callback_trail)
    )
    notice = ""
    if _integrity_value(p) != "VERIFIED":
        notice = '<div class="notice"><strong>▲ EVIDENCE CANNOT RENDER PASS</strong><p>Completeness, integrity, or reconciliation is not clean for this projection.</p></div>'
    elif scenario.scenario_id is ScenarioId.MODEL_NON_ATTEMPT:
        notice = '<div class="notice"><strong>MODEL NON-ATTEMPT / NO ENFORCEMENT CLAIM</strong><p>No candidate call exists: not DENY, not callback veto, and not enforcement success.</p></div>'
    return f"""
    <article class="scenario-panel" data-scenario-panel="{scenario.scenario_id.value}" hidden>
      <div class="callhead"><span class="callhead__tool">{escape(_one(p.tool_ids))}</span><span class="callhead__group"><span class="callhead__k">SECURITY DECISION</span><strong class="callhead__decision t-{_disposition_tone(p)}">{escape(_text(p.disposition))}</strong></span><span class="callhead__group"><span class="callhead__k">PRIMARY RULE</span><code>{escape(_text(p.primary_rule_id))}</code></span></div>
      {notice}
      <div class="duo">
        <section class="provenance provenance--untrusted"><div class="source t-untrusted">◌ UNTRUSTED PROPOSAL</div><h2>destination_reference</h2><p class="meta">role PROTECTED_REFERENCE · proposal representation is derived from the fixed scenario contract</p><div class="provenance__value">{escape(_proposal_form(scenario.scenario_id, p))}</div><p>The model may select an opaque reference. It cannot supply a protected value or mint or resolve a reference.</p></section>
        <section class="provenance provenance--trusted"><div class="source t-trusted">⬢ TRUSTED RUNTIME BINDING</div><div class="provenance__pair"><div><span>RESOLUTION</span><strong>{escape(resolution)}</strong></div><div><span>BINDING</span><strong>{escape(binding)}</strong></div></div><div class="provenance__mask">{escape(mask)}</div>{_source_label(mask_source.upper(), mask_source)}<p>The browser receives only this evidence-safe projection. No raw destination, reference token, prepared payload, or authenticator is present.</p></section>
      </div>
      {render_prepared_call_lifecycle(scenario.mechanism_projection, instance_id=instance_id)}
      <div class="section-head section-head--chain"><span class="section-title">ORDERED VALIDATION</span><span class="section-sub">real stable rules grouped into seven evaluation stages · first failure stops evaluation</span></div>
      <div class="validation">{_render_validation(p)}</div>
      <div class="divider"><span></span><strong>A DECISION IS NOT AN EXECUTION</strong><span></span></div>
      <div class="inspector-grid"><div class="duo">
        <section class="card"><div class="card__k">EXECUTION GATE</div><div class="state-line t-{_tone(_execution_label(p))}">{escape(_execution_label(p))}</div><div class="counters-lg"><span><small>EXECUTION STARTS</small><strong>{p.execution_start_count}</strong></span><span><small>SYNTHETIC PAYMENTS</small><strong>{p.payment_count}</strong></span></div><p>Observed execution evidence remains separate from the security decision. The payment is synthetic.</p></section>
        <section class="card"><div class="card__k">REPLAY · AT MOST ONCE</div><div class="state-line t-{_tone(_replay_label(p))}">{escape(_replay_label(p))}</div><div class="card__k callback-k">CALLBACK EVIDENCE</div><code>{escape(callback)}</code><p>{escape(callback_note)}</p></section>
      </div><aside class="stack">
        <section class="card"><div class="card__k">CONTRACT &amp; POLICY CONTEXT</div><dl class="kv"><div><dt>TOOL CONTRACT</dt><dd>{escape(_one(p.tool_contract_versions))}</dd></div><div><dt>POLICY</dt><dd>{escape(_one(p.policy_versions))}</dd></div><div><dt>REGISTRY</dt><dd>{escape(_one(p.registry_versions))}</dd></div><div><dt>ADAPTER</dt><dd>{SYNTHETIC_ADAPTER_VERSION}<br>{_source_label('APPROVED STATIC PRODUCT COPY', 'derived')}</dd></div></dl></section>
        <section class="card"><div class="card__k">PREPARED CALL</div><code>{escape(_short(prepared))}</code><p>{'Real safe correlation from ReviewProjection.' if p.prepared_call_ids else 'No prepared call is present for this outcome.'} Integrity payload and authenticators are not projected.</p></section>
        <section class="card"><div class="card__k">EVIDENCE</div><div class="state-line t-{_integrity_tone(p)}">{escape(_integrity_value(p))}</div><code>{escape(_short(p.trace_id))}</code><p>Publication {escape(scenario.summary.publication_status.value)} · {escape(_short(scenario.summary.publication_digest))}</p><button type="button" class="btn btn--primary btn--small" data-goto="trace">Evidence trace →</button></section>
      </aside></div>
    </article>"""


def _render_inspector(scenarios: Tuple[FinalUiScenario, ...]) -> str:
    picker = "".join(
        f'<button type="button" class="pick" data-select="{item.scenario_id.value}" aria-pressed="false"><span class="t-{_disposition_tone(item.projection)}">■</span>{escape(_CORE_NAMES[item.scenario_id])}</button>'
        for item in scenarios
    )
    panels = "".join(
        _render_inspector_panel(item, instance_id)
        for instance_id, item in enumerate(scenarios, 1)
    )
    return f'<section class="surface" data-surface="inspector" data-capture-id="surface-inspector" hidden><div class="picker" aria-label="Recorded scenarios">{picker}</div>{panels}</section>'


def _argument_events(projection: ReviewProjection) -> str:
    if not projection.argument_facts:
        return '<div class="event"><span>—</span><code>no candidate argument facts</code><span class="t-derived">● DERIVED</span><span>MODEL NON-ATTEMPT; no policy evaluation occurred.</span></div>'
    return "".join(
        f'<div class="event"><span>■</span><code>{escape(item.name)}</code><span class="t-observed">■ OBSERVED</span><span>{escape(item.role.value)} · {escape(item.provenance_class.value)} · resolution {escape(item.resolution_status)} · binding {escape(item.binding_status)} · {escape(item.masked_display)}</span></div>'
        for item in projection.argument_facts
    )


def _rule_events(projection: ReviewProjection) -> str:
    if not projection.rule_facts:
        return '<div class="event"><span>—</span><code>no decision trace</code><span class="t-derived">● DERIVED</span><span>NOT EVALUATED; no enforcement claim.</span></div>'
    return "".join(
        f'<div class="event"><span>■</span><code>{escape(item.rule_id.value)}</code><span class="t-observed">■ OBSERVED</span><span>{escape(item.stage.value)} · {escape(item.outcome.value)} · {escape(_text(item.argument_name))}</span></div>'
        for item in projection.rule_facts
    )


def _family(title: str, count: int, body: str, *, open_by_default: bool = False) -> str:
    opened = " open" if open_by_default else ""
    return f'<details class="family"{opened}><summary><span>{escape(title)}</span><small>{count} facts</small></summary>{body}</details>'


def _render_trace_panel(scenario: FinalUiScenario) -> str:
    p = scenario.projection
    contract_body = f'<div class="event"><span>⬢</span><code>tool / contract</code><span class="t-trusted">⬢ RUNTIME TRUSTED</span><span>{escape(_one(p.tool_ids))} · {escape(_one(p.tool_contract_versions))}</span></div><div class="event"><span>⬢</span><code>policy / registry</code><span class="t-trusted">⬢ RUNTIME TRUSTED</span><span>{escape(_one(p.policy_versions))} · {escape(_one(p.registry_versions))}</span></div>'
    execution_body = f'<div class="event"><span>■</span><code>callback projection</code><span class="t-observed">■ OBSERVED</span><span>{escape(_text(p.callback_action))} · {len(p.callback_trail)} callback events</span></div><div class="event"><span>■</span><code>execution projection</code><span class="t-observed">■ OBSERVED</span><span>{escape(_execution_label(p))} · starts {p.execution_start_count} · payments {p.payment_count}</span></div><div class="event"><span>■</span><code>replay projection</code><span class="t-observed">■ OBSERVED</span><span>{escape(_replay_label(p))}</span></div>'
    publication_body = f'<div class="event"><span>●</span><code>review projection</code><span class="t-derived">● DERIVED</span><span>{escape(_integrity_value(p))} · completeness {escape(_text(p.evidence_completeness))} · authoritative records {p.authoritative_event_count}</span></div><div class="event"><span>⬢</span><code>publication</code><span class="t-trusted">⬢ RUNTIME TRUSTED</span><span>{escape(scenario.summary.publication_status.value)} · {escape(_short(scenario.summary.publication_digest))}</span></div>'
    families = (
        _family("POLICY & CONTRACT SNAPSHOT", 2, contract_body)
        + _family("PROPOSAL, RESOLUTION & BINDING", len(p.argument_facts), _argument_events(p), open_by_default=True)
        + _family("SECURITY DECISION", len(p.rule_facts), _rule_events(p), open_by_default=True)
        + _family("SIDE EFFECT / EXECUTION", 3, execution_body, open_by_default=True)
        + _family("PROJECTION, RECONCILIATION & PUBLICATION", 2, publication_body)
    )
    producers = " · ".join(f"{item.component} {item.build_version}" for item in p.producer_facts) or "NOT AVAILABLE"
    findings = "0 findings" if not p.findings else f"{len(p.findings)} findings"
    return f"""
    <article class="scenario-panel" data-scenario-panel="{scenario.scenario_id.value}" hidden>
      <header class="screen-head"><span class="screen-head__k">EVIDENCE TRACE</span><strong>{escape(_CORE_NAMES[scenario.scenario_id])}</strong><code>{escape(_short(p.trace_id))}</code><span class="spacer"></span><span class="tag">REAL MASKED PROJECTION · NO RAW RECORD BROWSER</span></header>
      <div class="legend"><div>{_source_label('UNTRUSTED', 'untrusted')}<small>proposal provenance</small></div><div>{_source_label('RUNTIME TRUSTED', 'trusted')}<small>runtime authority facts</small></div><div>{_source_label('OBSERVED', 'observed')}<small>direct projected evidence</small></div><div>{_source_label('DERIVED', 'derived')}<small>interface interpretation</small></div><div><span class="source">◎ SECURITY DECISION / SIDE EFFECT</span><small>separate families</small></div></div>
      <div class="split"><div class="families">{families}</div><aside class="stack"><section class="card"><div class="card__k">RECONCILIATION</div><div class="state-line t-{_integrity_tone(p)}">{escape(_text(p.reconciliation_status))}</div><p>{escape(findings)} · retained {p.retained_record_count} · authoritative {p.authoritative_event_count} · malformed {p.malformed_record_count}</p></section><section class="card"><div class="card__k">PUBLICATION &amp; INTEGRITY</div><dl class="kv"><div><dt>EVIDENCE SCHEMA</dt><dd>{escape(_one(p.evidence_schema_versions))}</dd></div><div><dt>MASKING PROFILE</dt><dd>{escape(p.masking_profile_version)}</dd></div><div><dt>PRODUCER / BUILD</dt><dd>{escape(producers)}</dd></div><div><dt>FINALIZED DIGEST</dt><dd>{escape(_short(scenario.summary.publication_digest))}</dd></div></dl><p>Evidence construction, integrity, the decision, and the side effect remain distinct.</p><button type="button" class="btn btn--small" data-goto="inspector">← Back to inspector</button></section></aside></div>
    </article>"""


def _render_trace(scenarios: Tuple[FinalUiScenario, ...]) -> str:
    return '<section class="surface" data-surface="trace" data-capture-id="surface-trace" hidden>' + "".join(_render_trace_panel(item) for item in scenarios) + "</section>"


def _fact(label: str, value: object) -> str:
    rendered = "YES" if value is True else "NO" if value is False else str(value)
    return f'<div class="fact"><span>{escape(label)}</span><strong>{escape(rendered)}</strong></div>'


def _render_cloud(proof: CommittedCloudProof) -> str:
    configuration = "".join(
        _fact(label, value)
        for label, value in (
            ("Service", proof.service), ("Region", proof.region), ("Image platform", proof.image_platform),
            ("Task count", proof.task_count), ("Parallelism", proof.parallelism), ("Max retries", proof.max_retries),
            ("Timeout", f"{proof.timeout_seconds} s"), ("CPU", proof.cpu), ("Memory", proof.memory),
        )
    )
    execution = "".join(
        _fact(label, value)
        for label, value in (
            ("Cloud executions", f"{proof.cloud_executions} of maximum {proof.maximum_cloud_executions}"),
            ("Execution mode", "provider-free deterministic proof"),
            ("Local / cloud semantic equivalence", proof.semantic_equivalence),
            ("Replay execution starts", proof.replay_execution_starts), ("Replay synthetic payments", proof.replay_payments),
            ("Replay rejected", proof.replay_rejected), ("Gemini calls in cloud proof", proof.gemini_calls),
            ("Application network calls", proof.application_network_calls),
        )
    )
    shutdown = "".join(
        _fact(label, value)
        for label, value in (
            ("Rollback / redeploy", proof.rollback_redeploy_verified), ("Shutdown", proof.shutdown_verified),
            ("Removed after proof", "job · repository/image · runtime service account · staging bucket · temporary IAM bindings"),
            ("Continuing billable resource", proof.continuing_billable_resource_present),
            ("Personal spend observed", f"€{proof.personal_spend_eur} · not a future guarantee"),
        )
    )
    sequence = (
        ("LOCAL DETERMINISTIC RUN", "provider-free, offline evidence"),
        ("SAME SEMANTICS", "identical runtime vocabulary and ordering"),
        ("GOOGLE CLOUD RUN JOB", f"{proof.region} · {proof.image_platform}"),
        ("2 / 4 BOUNDED EXECUTIONS", "both provider-free"),
        ("SEMANTIC EQUIVALENCE VERIFIED", "1 start · 1 payment · replay rejected"),
        ("ROLLBACK / REDEPLOY VERIFIED", "captured configuration reproduced"),
        ("RESOURCES REMOVED", "shutdown verified · no continuing billable resource"),
    )
    sequence_html = "".join(f'<div class="seq__row"><span>●</span><div><strong>{escape(title)}</strong><small>{escape(body)}</small></div></div>' for title, body in sequence)
    return f"""
    <section class="surface" data-surface="cloud" data-capture-id="surface-cloud" hidden>
      <div class="proofbanner"><strong>⬢ COMPLETED CLOUD EVIDENCE — RESOURCES REMOVED AFTER VERIFIED SHUTDOWN</strong><p>Persisted, redacted {escape(proof.source)}. This is not a live cloud query, active hosted service, production deployment, public endpoint, or Gemini cloud run.</p></div>
      <div class="proof-layout"><section class="card"><div class="card__k">PROOF SEQUENCE</div><div class="seq">{sequence_html}</div></section><div>
        <div class="proof-stats"><div class="stat"><small>SERVICE · REGION</small><strong>Cloud Run Job<br>europe-west1</strong></div><div class="stat"><small>BOUNDED EXECUTIONS</small><strong>2 / 4</strong><span>both provider-free</span></div><div class="stat"><small>GEMINI · NETWORK CALLS</small><strong>0 / 0</strong><span>in the cloud proof</span></div><div class="stat"><small>PERSONAL SPEND</small><strong>€0</strong><span>observed, not a guarantee</span></div></div>
        <div class="proof-groups">{_family('DEPLOYMENT CONFIGURATION', 9, configuration, open_by_default=True)}{_family('EXECUTION, EQUIVALENCE & COUNTERS', 8, execution, open_by_default=True)}{_family('ROLLBACK, SHUTDOWN & COST', 5, shutdown)}{_family('PROVENANCE & NON-GOALS', 4, _fact('Cloud role', 'execution-environment evidence, not a new trust authority') + _fact('Historical live-model proof', 'separate provenance; not this cloud proof') + _fact('Hosted service', 'none') + _fact('Live cloud query', 'none'))}</div>
        <div class="actions"><button type="button" class="btn btn--small" data-goto="run">← Matching local semantics</button><span class="actions__note">Committed evidence only. No cloud identifiers, console URLs, credentials, or active-resource claims are present.</span></div>
      </div></div>
    </section>"""


_STYLES = r"""
:root{--bg:#070f1a;--chrome:#050c16;--panel:#0e1a28;--panel-head:#0a1626;--sel:#12222f;--hover:#132234;--line:#22344a;--line-soft:#16273a;--ink:#f4f7fa;--ink2:#c9d3dd;--ink3:#a7b1bd;--ink4:#7e8a97;--ink5:#5f6d7c;--untrusted:#9a8ce0;--trusted:#4ad6c9;--observed:#7fa9de;--derived:#a7b1bd;--ok:#61d095;--deny:#ff6b6b;--warn:#f6c85f;--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;--mono:ui-monospace,Menlo,Monaco,Consolas,monospace}
*{box-sizing:border-box}html,body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans)}body{min-width:1280px}button{font:inherit;color:inherit;background:none;border:0;padding:0;cursor:pointer;text-align:left}[hidden]{display:none!important}:focus-visible{outline:2px solid var(--trusted);outline-offset:2px}.app{height:100vh;min-height:660px;display:flex;flex-direction:column}.app__body{display:flex;flex:1;min-height:0}.main{flex:1;min-width:0;overflow:auto;padding:22px 26px 40px}.spacer{flex:1}.topbar{height:44px;display:flex;align-items:center;gap:18px;padding:0 18px;background:var(--chrome);border-bottom:1px solid var(--line)}.brand{font:600 13.5px/1 var(--mono);letter-spacing:.16em}.topbar__sub,.actions__note{font:400 10.5px/1.45 var(--mono);color:var(--ink5)}.tag{padding:3px 8px;border:1px solid var(--line);border-radius:3px;font:500 9.5px/1 var(--mono);letter-spacing:.08em;color:var(--ink4)}.tag--offline{border-style:dashed;border-color:#6b5a22;color:var(--warn)}.counters{display:flex;gap:14px}.counter{font:500 10px/1 var(--mono);color:var(--ink5)}.counter strong{color:var(--ink3);margin-right:4px}.guidedbar{display:flex;gap:9px;align-items:center;padding:8px 18px;background:var(--panel-head);border-bottom:1px solid var(--line)}.step,.btn,.filter,.pick{border:1px solid var(--line);border-radius:3px;color:var(--ink3)}.step{padding:5px 10px;font-size:11.5px}.step[aria-current=true],.btn--primary,.filter[aria-pressed=true],.pick[aria-pressed=true]{border-color:var(--trusted);background:#0e2a2e;color:var(--ink)}.rail{width:104px;flex:none;background:var(--chrome);border-right:1px solid var(--line);padding-top:10px}.rail__item{display:flex;flex-direction:column;align-items:center;gap:4px;width:100%;padding:11px 6px;border-left:2px solid transparent;color:var(--ink3)}.rail__item[aria-selected=true]{border-color:var(--trusted);background:#0e1e2c;color:var(--ink)}.rail__n{font:600 9.5px var(--mono);color:var(--ink5)}.rail__label{font-size:11.5px;text-align:center}.rail__meta{margin:14px 8px;padding-top:12px;border-top:1px solid var(--line);font:500 10px/1.35 var(--mono);color:var(--ink3);overflow-wrap:anywhere}.hero{padding:6px 0 4px}.hero__eyebrow,.section-title{margin:0;font:600 11.5px/1 var(--mono);letter-spacing:.22em;color:var(--trusted)}.hero__statement{margin:12px 0 0;max-width:37ch;font-size:30px;line-height:1.28}.hero__select{color:var(--untrusted)}.hero__supply{color:var(--trusted)}.hero__body{max-width:82ch;margin:10px 0 0;color:var(--ink4);font-size:13.5px;line-height:1.55}.boundary{margin-top:20px;display:grid;grid-template-columns:1fr 188px 1fr}.boundary__side{padding:16px 18px;border-radius:5px}.boundary__side--untrusted{border:1px dashed var(--untrusted)}.boundary__side--trusted{border:1px solid var(--trusted);background:#0b1d23}.boundary__head{display:flex;gap:10px;font:600 10px var(--mono);color:var(--ink5)}.boundary__claim{margin-top:10px;font-size:17px}.boundary__note{color:var(--ink3);font-size:13px;line-height:1.5}.boundary__gate{display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;font:600 10px/1.45 var(--mono);letter-spacing:.1em;color:var(--ink3)}.boundary__rule{width:1px;flex:1;background:var(--line)}.historical-proof{margin-top:20px}.proofbanner--historical{border-color:var(--observed);background:#0b1928}.proofbanner--historical strong{color:var(--observed)}.proof-stats--historical{margin-top:10px}.proof-stats--historical .stat strong{font-size:17px}.proof-groups--historical{grid-template-columns:repeat(3,minmax(0,1fr))}.section-head{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}.section-head--chain{margin-top:26px}.section-head--matrix{margin-top:30px;padding-top:20px;border-top:1px solid var(--line-soft)}.section-head--variants{margin-top:26px}.section-sub{font:400 12px var(--mono);color:var(--ink5)}.chain{display:flex;align-items:stretch;margin-top:12px}.chain__link{width:16px;display:flex;align-items:center;justify-content:center;color:#3a4c63}.stage{flex:1;min-width:0;min-height:132px;display:flex;flex-direction:column;padding:14px 13px 13px;border:1px solid var(--line);border-top:3px solid var(--line);border-radius:4px;background:var(--panel)}.stage__top{display:flex;gap:7px;font:600 11px var(--mono);color:var(--ink5)}.stage__name{margin-top:6px;font:600 11.5px var(--mono);letter-spacing:.1em}.stage__value{margin-top:auto;font:600 14px/1.3 var(--mono);overflow-wrap:anywhere}.stage__sub{margin-top:6px;padding-top:7px;border-top:1px solid #1a2a3c;font:400 10.5px/1.4 var(--mono);color:var(--ink4);overflow-wrap:anywhere}.matrix{margin-top:8px;border:1px solid var(--line);border-radius:4px;overflow:hidden;background:var(--panel)}.matrix__grid{display:grid;grid-template-columns:minmax(210px,1.5fr) minmax(150px,1.2fr) 62px 74px minmax(120px,1fr) minmax(130px,1fr);gap:12px;align-items:center}.matrix__head{padding:6px 12px;background:var(--panel-head);font:600 9.5px var(--mono);letter-spacing:.08em;color:var(--ink5)}.matrix__row{width:100%;padding:10px 12px;border-top:1px solid var(--line-soft);border-left:3px solid transparent}.matrix__row:hover{background:var(--hover)}.matrix__row[aria-pressed=true]{border-left-color:var(--trusted);background:var(--sel)}.cell{display:flex;flex-direction:column;gap:3px;min-width:0}.cell__name{font-size:13.5px}.cell__id,.cell__rule{font:400 10px/1.3 var(--mono);color:var(--ink5);overflow-wrap:anywhere}.cell__decision,.cell__count{font:600 12.5px var(--mono)}.cell__replay,.cell__integrity,.cell__match{font:500 11px/1.3 var(--mono)}.filters,.picker,.actions{display:flex;gap:6px;flex-wrap:wrap}.filter{padding:4px 9px;font:500 10.5px var(--mono)}.variants{margin-top:8px;display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.variant{padding:10px 13px;border:1px solid var(--line);border-radius:4px;background:var(--panel)}.variant__head{display:flex;align-items:center;gap:8px}.variant__name{font-size:13.5px}.variant__gloss{font-size:11.5px;line-height:1.45;color:var(--ink3)}.variant__id{font:400 9.5px var(--mono);color:var(--ink5)}.fixture{padding:2px 5px;border:1px solid #4a3f1c;border-radius:2px;font:600 8.5px var(--mono);color:var(--warn)}.actions{margin-top:22px;align-items:center}.btn{padding:10px 16px;font-size:12.5px}.btn--small{padding:9px 13px}.picker{margin-bottom:12px}.pick{padding:6px 11px;background:var(--panel);font-size:12px}.callhead{display:flex;gap:20px;align-items:center;flex-wrap:wrap;padding:12px 14px;border:1px solid var(--line);border-radius:4px;background:var(--panel)}.callhead__tool{font:600 16px var(--mono)}.callhead__group{display:flex;flex-direction:column;gap:4px}.callhead__k,.card__k{font:600 9.5px var(--mono);letter-spacing:.13em;color:var(--ink5)}.callhead__decision{font:600 20px var(--mono)}code{font-family:var(--mono);overflow-wrap:anywhere}.notice{margin-top:10px;padding:13px 15px;border:1px solid var(--warn);background:#1a170d;color:var(--warn)}.notice p{color:var(--ink2);margin-bottom:0}.duo{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px}.provenance{padding:14px;border-radius:4px}.provenance--untrusted{border:1px dashed var(--untrusted)}.provenance--trusted{border:1px solid var(--trusted);background:#0b1d23}.source{font:600 9.5px var(--mono);letter-spacing:.08em}.provenance h2{font:600 16px var(--mono)}.provenance p,.card p{color:var(--ink3);font-size:12px;line-height:1.5}.meta{font:400 10.5px var(--mono)!important;color:var(--ink5)!important}.provenance__value,.provenance__mask{padding:10px 11px;border-radius:3px;font:500 14px/1.35 var(--mono);overflow-wrap:anywhere}.provenance__value{border:1px dashed #3a3358;color:#c9bff0}.provenance__mask{margin:10px 0;border:1px solid #1f4a4e;background:#08171c;color:var(--trusted)}.provenance__pair{display:grid;grid-template-columns:1fr 1fr;gap:10px}.provenance__pair span{display:block;font:600 9.5px var(--mono);color:var(--ink5)}.provenance__pair strong{display:block;margin-top:5px;font:600 14px var(--mono)}.validation{display:flex;flex-direction:column;gap:5px;margin-top:8px}.vstage{border:1px solid var(--line);border-radius:3px;background:var(--panel)}.vstage summary{display:grid;grid-template-columns:24px 132px minmax(0,1fr) 132px;gap:10px;align-items:center;padding:9px 12px;cursor:pointer;list-style:none}.vstage summary::-webkit-details-marker{display:none}.vstage__n{color:var(--ink5);font:11px var(--mono)}.vstage__name{font:600 12.5px var(--mono)}.rule-row{display:grid;grid-template-columns:minmax(0,1.3fr) minmax(0,1fr) 120px;gap:10px;padding:9px 14px 9px 168px;border-top:1px solid var(--line-soft);font-size:11.5px;color:var(--ink3)}.divider{display:flex;gap:14px;align-items:center;margin:14px 0 10px}.divider span{height:1px;flex:1;background:var(--line)}.divider strong{font:600 11px var(--mono);letter-spacing:.16em;color:var(--warn)}.inspector-grid{display:grid;grid-template-columns:minmax(0,1fr) 322px;gap:14px}.card{padding:13px;border:1px solid var(--line);border-radius:4px;background:var(--panel)}.stack{display:flex;flex-direction:column;gap:10px}.state-line{margin-top:8px;font:600 15px/1.25 var(--mono)}.counters-lg{display:flex;gap:26px;margin-top:12px}.counters-lg small{display:block;font:600 9px var(--mono);color:var(--ink5)}.counters-lg strong{display:block;margin-top:4px;font:600 30px var(--mono)}.callback-k{margin-top:14px}.kv{display:flex;flex-direction:column;gap:8px}.kv div{min-width:0}.kv dt{font:600 9px var(--mono);color:var(--ink5)}.kv dd{margin:3px 0 0;font:500 11.5px/1.35 var(--mono);overflow-wrap:anywhere}.screen-head{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap}.screen-head__k{font:600 10px var(--mono);letter-spacing:.18em;color:var(--ink4)}.legend{display:flex;gap:20px;flex-wrap:wrap;margin-top:10px;padding:10px 14px;border:1px solid var(--line);background:var(--panel)}.legend div{display:flex;flex-direction:column;gap:4px}.legend small{color:var(--ink4)}.split{display:grid;grid-template-columns:minmax(0,1fr) 322px;gap:14px;margin-top:12px}.families{display:flex;flex-direction:column;gap:7px}.family{border:1px solid var(--line);border-radius:4px;background:var(--panel);overflow:hidden}.family summary{display:flex;justify-content:space-between;padding:11px 14px;cursor:pointer;font:600 12px var(--mono);letter-spacing:.05em}.family summary small{color:var(--ink5)}.event{display:grid;grid-template-columns:28px minmax(0,1.2fr) 126px minmax(0,1.7fr);gap:10px;padding:9px 14px;border-top:1px solid var(--line-soft);font-size:11.5px;line-height:1.4}.event>span:last-child{color:var(--ink3)}.proofbanner{padding:13px 15px;border:1px solid var(--trusted);border-radius:4px;background:#0b1d23}.proofbanner strong{font:600 12.5px var(--mono);color:var(--trusted)}.proofbanner p{max-width:110ch;color:var(--ink2);font-size:13.5px;line-height:1.55}.proof-layout{display:grid;grid-template-columns:236px minmax(0,1fr);gap:14px;margin-top:12px}.seq{display:flex;flex-direction:column;gap:10px;margin-top:10px}.seq__row{display:flex;gap:9px;color:var(--trusted)}.seq__row div{display:flex;flex-direction:column}.seq__row strong{font:600 10.5px var(--mono);color:var(--ink)}.seq__row small{margin-top:3px;color:var(--ink4)}.proof-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.stat{padding:13px;border:1px solid var(--line);border-radius:4px;background:var(--panel)}.stat small,.stat span{display:block;color:var(--ink5);font:600 9px/1.4 var(--mono)}.stat strong{display:block;margin:8px 0 5px;font:600 22px/1.2 var(--mono)}.proof-groups{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:10px;margin-top:10px}.fact{padding:9px 14px;border-top:1px solid var(--line-soft)}.fact span{display:block;color:var(--ink4);font:11px var(--mono)}.fact strong{display:block;margin-top:3px;font:500 12px/1.4 var(--mono);overflow-wrap:anywhere}.t-untrusted{color:var(--untrusted)}.t-trusted{color:var(--trusted)}.t-observed{color:var(--observed)}.t-derived{color:var(--derived)}.t-ok{color:var(--ok)}.t-deny{color:var(--deny)}.t-warn{color:var(--warn)}.t-mute{color:var(--ink3)}.bt-untrusted{border-top-color:var(--untrusted)}.bt-trusted{border-top-color:var(--trusted)}.bt-ok{border-top-color:var(--ok)}.bt-deny{border-top-color:var(--deny)}.bt-warn{border-top-color:var(--warn)}.bt-mute{border-top-color:var(--ink3)}
@media(max-width:1439px){.main{padding:18px 20px 36px}.boundary{grid-template-columns:1fr 150px 1fr}.hero__statement{font-size:27px}.inspector-grid,.split{grid-template-columns:minmax(0,1fr) 290px}.proof-layout{grid-template-columns:210px minmax(0,1fr)}}@media(min-width:1800px){.main{padding:26px 34px 48px}.hero__statement{font-size:32px}}@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;transition:none!important}}
"""


_SCRIPT = r"""
(function(){'use strict';
var state={surface:'run',selected:'BENIGN_ALLOW',guided:false,step:0};
var steps=[['run','BENIGN_ALLOW'],['inspector','BENIGN_ALLOW'],['inspector','RAW_PROTECTED_VALUE_DENY'],['inspector','REPLAY_REJECTION'],['cloud','REPLAY_REJECTION']];
function all(q){return Array.prototype.slice.call(document.querySelectorAll(q));}
function render(){
 all('[data-surface]').forEach(function(n){n.hidden=n.getAttribute('data-surface')!==state.surface;});
 all('.rail [data-goto]').forEach(function(n){n.setAttribute('aria-selected',String(n.getAttribute('data-goto')===state.surface));});
 all('[data-scenario-panel]').forEach(function(n){n.hidden=n.getAttribute('data-scenario-panel')!==state.selected;});
 all('[data-select]').forEach(function(n){n.setAttribute('aria-pressed',String(n.getAttribute('data-select')===state.selected));});
 var selected=document.getElementById('selected-scenario'); if(selected)selected.textContent=state.selected;
 var chain=document.getElementById('chain-selected'); if(chain)chain.textContent=state.selected;
 var guided=document.getElementById('guidedbar'); guided.hidden=!state.guided;
 document.getElementById('guided-toggle').setAttribute('aria-pressed',String(state.guided));
 all('[data-step]').forEach(function(n){n.setAttribute('aria-current',String(Number(n.getAttribute('data-step'))===state.step));});
}
document.addEventListener('click',function(e){var n=e.target.closest('button');if(!n)return;
 if(n.hasAttribute('data-goto')){state.surface=n.getAttribute('data-goto');document.getElementById('main').scrollTop=0;}
 if(n.hasAttribute('data-select'))state.selected=n.getAttribute('data-select');
 if(n.hasAttribute('data-filter')){var f=n.getAttribute('data-filter');all('[data-filter]').forEach(function(x){x.setAttribute('aria-pressed',String(x===n));});all('.matrix__row').forEach(function(x){x.hidden=!(f==='ALL'||x.getAttribute('data-decision')===f||(f==='EXECUTED'&&x.getAttribute('data-executed')==='true'));});}
 if(n.id==='guided-toggle'){state.guided=!state.guided;state.step=0;if(state.guided){state.surface=steps[0][0];state.selected=steps[0][1];}}
 if(n.hasAttribute('data-step')){state.step=Number(n.getAttribute('data-step'));state.surface=steps[state.step][0];state.selected=steps[state.step][1];}
 if(n.id==='guided-prev'){state.step=Math.max(0,state.step-1);state.surface=steps[state.step][0];state.selected=steps[state.step][1];}
 if(n.id==='guided-next'){state.step=Math.min(4,state.step+1);state.surface=steps[state.step][0];state.selected=steps[state.step][1];}
 render();
});
window.addEventListener('keydown',function(e){if(!state.guided)return;if(e.key==='ArrowLeft')document.getElementById('guided-prev').click();if(e.key==='ArrowRight')document.getElementById('guided-next').click();});
render();
})();
"""


def render_final_ui(
    summary: DemoRunSummary,
    scenarios: Tuple[FinalUiScenario, ...],
    cloud_proof: CommittedCloudProof = CommittedCloudProof(),
    historical_live_proof: CommittedHistoricalLiveProof = CommittedHistoricalLiveProof(),
    *,
    presentation_mode: PresentationMode = PresentationMode.NORMAL,
) -> str:
    """Render the approved self-contained UI from safe immutable projections."""

    if type(summary) is not DemoRunSummary:
        raise TypeError("final UI renderer requires DemoRunSummary")
    if type(scenarios) is not tuple or any(
        type(item) is not FinalUiScenario for item in scenarios
    ):
        raise TypeError("final UI renderer requires FinalUiScenario tuple")
    if tuple(item.scenario_id for item in scenarios) != REQUIRED_SCENARIO_ORDER:
        raise ValueError("final UI renderer requires all six scenarios in order")
    if type(cloud_proof) is not CommittedCloudProof:
        raise TypeError("final UI renderer requires committed cloud proof projection")
    if type(historical_live_proof) is not CommittedHistoricalLiveProof:
        raise TypeError(
            "final UI renderer requires committed historical live proof projection"
        )
    if type(presentation_mode) is not PresentationMode:
        raise TypeError("final UI renderer requires PresentationMode")
    starts = sum(item.projection.execution_start_count for item in scenarios)
    payments = sum(item.projection.payment_count for item in scenarios)
    replays = sum(item.projection.replay_state is ReplayReviewState.REJECTED for item in scenarios)
    guided_steps = "".join(
        f'<button type="button" class="step" data-step="{index}" data-capture-id="guided-step-{index + 1}" aria-current="false"><span>0{index + 1}</span> {escape(title)}</button>'
        for index, title in enumerate(("Orient", "Benign allow", "Raw-value deny", "Replay", "Cloud proof"))
    )
    rail = "".join(
        f'<button type="button" class="rail__item" data-goto="{key}" aria-selected="false"><span class="rail__n">0{index}</span><span class="rail__label">{escape(label)}</span></button>'
        for index, (key, label) in enumerate((("run", "Demo Run"), ("inspector", "Prepared Call Inspector"), ("trace", "Evidence Trace"), ("cloud", "Cloud Proof")), 1)
    )
    presentation_style = (
        VIDEO_SAFE_STYLE_BLOCK
        if presentation_mode is PresentationMode.VIDEO_SAFE
        else ""
    )
    presentation_badge = (
        VIDEO_SAFE_BADGE
        if presentation_mode is PresentationMode.VIDEO_SAFE
        else ""
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>TIDEMARK — Security Decision Trace</title><meta name="description" content="TIDEMARK read-only evidence and inspection workspace. {DESIGN_AUTHORITY}."><link rel="icon" href="data:,"><style>{_STYLES}{LIFECYCLE_STYLES}</style>{presentation_style}</head>
<body><div class="app" data-presentation-mode="{presentation_mode.value}"><header class="topbar"><span class="brand">TIDEMARK</span><span class="topbar__sub">deterministic run · 6 core scenarios · 3 state variants</span><span class="tag tag--offline">DETERMINISTIC · EVIDENCE FALLBACK / OFFLINE · NOT CURRENT LIVE PROVIDER OUTPUT</span>{presentation_badge}<span class="spacer"></span><div class="counters"><span class="counter"><strong>{starts}</strong> STARTS</span><span class="counter"><strong>{payments}</strong> SYNTHETIC PAYMENTS</span><span class="counter"><strong>{replays}</strong> REPLAY REJECTED</span></div><button type="button" class="btn btn--small" id="guided-toggle" aria-pressed="false">Guided demo</button><span class="tag">READ-ONLY</span></header>
<div class="guidedbar" id="guidedbar" hidden><strong class="section-title">GUIDED DEMO</strong>{guided_steps}<span class="spacer"></span><span class="topbar__sub">← → keys · recorded evidence only</span><button type="button" class="btn btn--small" id="guided-prev" aria-label="Previous guided step">←</button><button type="button" class="btn btn--small" id="guided-next" aria-label="Next guided step">→</button></div>
<div class="app__body"><nav class="rail" aria-label="Product surfaces">{rail}<div class="rail__meta">SELECTED<div id="selected-scenario"></div></div></nav><main class="main" id="main" tabindex="-1">{_render_run(summary, scenarios, historical_live_proof)}{_render_inspector(scenarios)}{_render_trace(scenarios)}{_render_cloud(cloud_proof)}</main></div></div><script>{_SCRIPT}{LIFECYCLE_SCRIPT}</script></body></html>"""


__all__ = (
    "COMMITTED_CLOUD_PROOF_SOURCE",
    "COMMITTED_HISTORICAL_LIVE_PROOF_DIGEST",
    "COMMITTED_HISTORICAL_LIVE_PROOF_SOURCE",
    "DESIGN_AUTHORITY",
    "PresentationMode",
    "VIDEO_SAFE_BADGE",
    "VIDEO_SAFE_STYLE_BLOCK",
    "CommittedCloudProof",
    "CommittedHistoricalLiveProof",
    "FinalUiScenario",
    "build_final_ui_scenarios",
    "render_final_ui",
)
