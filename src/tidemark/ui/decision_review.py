"""Dependency-free single-screen review workspace for one ReviewProjection."""

from html import escape
from typing import Iterable, Optional

from tidemark.evidence.projection import (
    CallbackReviewAction,
    EvidenceCompleteness,
    ExecutionReviewStatus,
    ProjectionDisposition,
    ProjectionStatus,
    ReplayReviewState,
    ReviewProjection,
)


_SELECTED_MODEL_DISPLAY_NAME = "Gemini 3.6 Flash"
_OFFLINE_PROVENANCE = "EVIDENCE FALLBACK"


_STYLES = r"""
:root {
  --paper: #f3efe4;
  --paper-raised: #fbf8f0;
  --ink: #18211d;
  --ink-soft: #53605a;
  --line: #c8c1b1;
  --line-strong: #8e897d;
  --petrol: #173f46;
  --petrol-soft: #dce8e5;
  --signal: #b94b28;
  --signal-soft: #f4ded4;
  --amber: #8a5b08;
  --amber-soft: #f2e5bf;
  --green: #245c43;
  --green-soft: #dce9df;
  --focus: #0b65c2;
  --shadow: 0 16px 36px rgba(24, 33, 29, 0.09);
}

* { box-sizing: border-box; }

html {
  background: var(--paper);
  color: var(--ink);
  font-family: "Iowan Old Style", "Palatino Linotype", Palatino, serif;
  scroll-behavior: smooth;
}

body {
  margin: 0;
  min-width: 320px;
  min-height: 100vh;
  background:
    linear-gradient(rgba(24, 33, 29, 0.035) 1px, transparent 1px),
    linear-gradient(90deg, rgba(24, 33, 29, 0.035) 1px, transparent 1px),
    var(--paper);
  background-size: 24px 24px;
}

a { color: inherit; }

.skip-link {
  position: fixed;
  z-index: 10;
  top: 0.75rem;
  left: 0.75rem;
  padding: 0.65rem 0.9rem;
  background: var(--ink);
  color: var(--paper-raised);
  transform: translateY(-180%);
}

.skip-link:focus { transform: translateY(0); }

:focus-visible {
  outline: 3px solid var(--focus);
  outline-offset: 4px;
}

.boundary-banner {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 1rem;
  align-items: center;
  padding: 0.72rem clamp(1rem, 3vw, 2.6rem);
  border-bottom: 1px solid #0d282d;
  background: var(--petrol);
  color: #f9f6ed;
  font-family: Menlo, Monaco, Consolas, monospace;
  font-size: 0.72rem;
  letter-spacing: 0.055em;
  text-transform: uppercase;
}

.boundary-banner strong { color: #ffffff; }

.workspace {
  width: min(1540px, calc(100% - clamp(1.2rem, 4vw, 4.5rem)));
  margin: 0 auto;
  padding: clamp(1.35rem, 2.5vw, 2.7rem) 0 3rem;
}

.masthead {
  display: grid;
  grid-template-columns: minmax(0, 1.25fr) minmax(18rem, 0.75fr);
  gap: clamp(1.25rem, 3vw, 3.5rem);
  align-items: end;
  margin-bottom: 1.25rem;
}

.eyebrow,
.source-label,
.panel-kicker,
th,
dt,
.meta-label {
  font-family: Menlo, Monaco, Consolas, monospace;
  font-size: 0.66rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.eyebrow { margin: 0 0 0.35rem; color: var(--signal); }

h1, h2, h3, p { margin-top: 0; }

h1 {
  max-width: 18ch;
  margin-bottom: 0.45rem;
  font-size: clamp(2.15rem, 4.2vw, 4.85rem);
  font-weight: 500;
  letter-spacing: -0.055em;
  line-height: 0.92;
}

.dek {
  max-width: 66ch;
  margin-bottom: 0;
  color: var(--ink-soft);
  font-size: 1rem;
  line-height: 1.5;
}

.hero-states {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.65rem;
}

.hero-state {
  min-height: 5.3rem;
  padding: 0.9rem;
  border-top: 4px solid var(--line-strong);
  background: rgba(251, 248, 240, 0.72);
}

.hero-state .meta-label { display: block; margin-bottom: 0.62rem; color: var(--ink-soft); }

.workspace-grid {
  display: grid;
  grid-template-columns: repeat(12, minmax(0, 1fr));
  gap: 0.85rem;
  align-items: start;
}

.panel {
  min-width: 0;
  border: 1px solid var(--line);
  background: rgba(251, 248, 240, 0.92);
  box-shadow: var(--shadow);
}

.panel__head {
  display: flex;
  gap: 1rem;
  justify-content: space-between;
  align-items: baseline;
  padding: 0.8rem 0.95rem 0.72rem;
  border-bottom: 1px solid var(--line);
  background: rgba(23, 63, 70, 0.055);
}

.panel__head h2,
.panel__head h3 {
  margin: 0;
  font-size: 1.02rem;
  font-weight: 650;
}

.panel__body { padding: 0.9rem 0.95rem 1rem; }

.decision-list { grid-column: span 4; }
.decision-summary { grid-column: span 8; }
.argument-review { grid-column: span 8; }
.review-rail { grid-column: span 4; display: grid; gap: 0.85rem; }
.rule-trace { grid-column: span 8; }
.evidence-column { grid-column: span 4; display: grid; gap: 0.85rem; }
.state-legend { grid-column: 1 / -1; }

.source-label {
  display: inline-flex;
  align-items: center;
  gap: 0.42rem;
  color: var(--ink-soft);
  white-space: nowrap;
}

.source-label::before {
  width: 0.55rem;
  height: 0.55rem;
  border: 1px solid currentColor;
  content: "";
}

.source-label--derived::before { border-radius: 50%; background: var(--amber-soft); }
.source-label--observed::before { background: var(--petrol-soft); }

.status {
  display: inline-flex;
  gap: 0.42rem;
  align-items: center;
  min-height: 1.65rem;
  padding: 0.27rem 0.48rem;
  border: 1px solid currentColor;
  font-family: Menlo, Monaco, Consolas, monospace;
  font-size: 0.67rem;
  font-weight: 800;
  letter-spacing: 0.055em;
  line-height: 1.15;
  text-transform: uppercase;
}

.status__mark { width: 0.53rem; height: 0.53rem; border: 1.5px solid currentColor; }
.status--positive { color: var(--green); background: var(--green-soft); }
.status--positive .status__mark { border-radius: 50%; background: currentColor; }
.status--negative { color: var(--signal); background: var(--signal-soft); }
.status--negative .status__mark { transform: rotate(45deg); background: currentColor; }
.status--warning { color: var(--amber); background: var(--amber-soft); }
.status--warning .status__mark { border-radius: 50% 50% 0 50%; transform: rotate(45deg); }
.status--neutral { color: var(--petrol); background: var(--petrol-soft); }

.summary-copy {
  max-width: 64ch;
  margin-bottom: 0.9rem;
  font-size: 1.08rem;
  line-height: 1.45;
}

.summary-grid,
.proof-grid,
.context-grid,
.correlation-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.72rem 1.1rem;
  margin: 0;
}

.summary-grid > div,
.proof-grid > div,
.context-grid > div,
.correlation-grid > div {
  min-width: 0;
  padding-top: 0.54rem;
  border-top: 1px solid var(--line);
}

dt { margin-bottom: 0.3rem; color: var(--ink-soft); }
dd { margin: 0; overflow-wrap: anywhere; line-height: 1.35; }

code {
  font-family: Menlo, Monaco, Consolas, monospace;
  font-size: 0.75em;
  overflow-wrap: anywhere;
}

.table-wrap { overflow-x: auto; }

table {
  width: 100%;
  border-collapse: collapse;
  text-align: left;
}

caption {
  padding: 0 0 0.65rem;
  color: var(--ink-soft);
  text-align: left;
  font-size: 0.82rem;
}

th, td { padding: 0.58rem 0.52rem; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--ink-soft); }
td { font-size: 0.84rem; line-height: 1.35; overflow-wrap: anywhere; }
tbody tr:last-child td { border-bottom: 0; }
.decision-records { margin: 0; padding: 0; list-style: none; }
.decision-record {
  padding: 0.72rem 0.78rem 0.82rem;
  box-shadow: inset 4px 0 0 var(--signal);
  background: rgba(185, 75, 40, 0.055);
}
.decision-record > strong { display: block; margin-bottom: 0.65rem; font-size: 0.96rem; }
.decision-record__grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.62rem 0.78rem;
  margin: 0;
}
.decision-record__grid > div { min-width: 0; padding-top: 0.42rem; border-top: 1px solid var(--line); }
.argument-review table { min-width: 850px; }
.rule-trace table { min-width: 760px; }
.argument-review th:nth-child(2),
.argument-review td:nth-child(2),
.argument-review th:nth-child(4),
.argument-review td:nth-child(4),
.argument-review th:nth-child(5),
.argument-review td:nth-child(5),
.argument-review th:nth-child(6),
.argument-review td:nth-child(6) { white-space: nowrap; }
.rule-scroll { max-height: 25rem; overflow: auto; scrollbar-gutter: stable; }

.timeline,
.findings,
.legend-list {
  margin: 0;
  padding: 0;
  list-style: none;
}

.timeline li {
  position: relative;
  margin-left: 0.36rem;
  padding: 0 0 0.78rem 1.35rem;
  border-left: 1px solid var(--line-strong);
  font-size: 0.84rem;
  line-height: 1.4;
}

.timeline li:last-child { padding-bottom: 0; }
.timeline li::before {
  position: absolute;
  top: 0.1rem;
  left: -0.36rem;
  width: 0.64rem;
  height: 0.64rem;
  border: 2px solid var(--paper-raised);
  border-radius: 50%;
  background: var(--petrol);
  box-shadow: 0 0 0 1px var(--petrol);
  content: "";
}

.timeline code { display: block; margin-top: 0.16rem; color: var(--ink-soft); }
.proof-grid { margin-bottom: 0.8rem; }
.proof-note, .integrity-warning, .empty-state {
  margin: 0.75rem 0 0;
  padding: 0.66rem 0.74rem;
  border-left: 3px solid var(--line-strong);
  background: rgba(24, 33, 29, 0.045);
  color: var(--ink-soft);
  font-size: 0.8rem;
  line-height: 1.4;
}

.integrity-warning { border-color: var(--amber); background: var(--amber-soft); color: #604006; }

.findings { margin-top: 0.75rem; }
.findings li { padding: 0.42rem 0; border-top: 1px solid var(--line); font-size: 0.77rem; }
.findings code { display: block; }

.legend-list {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 0.8rem;
}

.legend-list li { padding-left: 0.7rem; border-left: 2px solid var(--line-strong); }
.legend-list strong { display: block; margin-bottom: 0.24rem; font-size: 0.76rem; }
.legend-list span { color: var(--ink-soft); font-size: 0.76rem; line-height: 1.35; }

.workspace-footer {
  display: flex;
  justify-content: space-between;
  gap: 1rem;
  margin-top: 1rem;
  padding-top: 0.85rem;
  border-top: 1px solid var(--line-strong);
  color: var(--ink-soft);
  font-family: Menlo, Monaco, Consolas, monospace;
  font-size: 0.67rem;
  text-transform: uppercase;
}

@media (max-width: 1000px) {
  .masthead { grid-template-columns: 1fr; }
  .decision-list, .decision-summary, .argument-review, .review-rail,
  .rule-trace, .evidence-column { grid-column: 1 / -1; }
  .legend-list { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}

@media (max-width: 620px) {
  .boundary-banner { grid-template-columns: 1fr; }
  .workspace { width: min(100% - 1rem, 1540px); }
  .hero-states, .summary-grid, .proof-grid, .context-grid, .correlation-grid,
  .legend-list { grid-template-columns: 1fr; }
  th, td { padding-left: 0.38rem; padding-right: 0.38rem; }
  .workspace-footer { display: block; }
}

@media print {
  body { background: #fff; }
  .skip-link { display: none; }
  .workspace { width: 100%; }
  .panel { break-inside: avoid; box-shadow: none; }
}

@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
  *, *::before, *::after { transition-duration: 0.01ms !important; }
}
"""


def _text(value: object) -> str:
    raw = getattr(value, "value", value)
    if raw is None:
        return "NOT AVAILABLE"
    return str(raw)


def _canonical_state(value: object) -> str:
    return _text(value).replace("_", " ")


def _short(value: object) -> str:
    text = _text(value)
    if len(text) <= 18:
        return text
    return text[:10] + "…" + text[-5:]


def _one(values: tuple) -> str:
    if not values:
        return "NOT AVAILABLE"
    if len(values) != 1:
        return "CONFLICT"
    return _text(values[0])


def _tone(state: str) -> str:
    if state in {"ALLOW", "COMPLETED", "EXECUTED", "RECORDED", "PASS", "COMPLETE", "CLEAN", "RELEASED", "TOOL ENTERED"}:
        return "positive"
    if state in {"DENY", "REFUSAL", "FAILED", "EXECUTION REFUSED", "VETOED", "CONFLICT"}:
        return "negative"
    if state in {"INCOMPLETE", "UNKNOWN", "WARNING", "REPLAY REJECTED", "MODEL NON-ATTEMPT"}:
        return "warning"
    return "neutral"


def _status(state: str, tone: Optional[str] = None) -> str:
    safe_state = escape(state)
    safe_tone = tone or _tone(state)
    return (
        f'<span class="status status--{safe_tone}">'
        '<span class="status__mark" aria-hidden="true"></span>'
        f"<span>{safe_state}</span></span>"
    )


def _disposition_state(projection: ReviewProjection) -> str:
    if projection.disposition is ProjectionDisposition.MODEL_NON_ATTEMPT:
        return "MODEL NON-ATTEMPT"
    return _canonical_state(projection.disposition)


def _execution_state(projection: ReviewProjection) -> str:
    if projection.replay_state is ReplayReviewState.REJECTED:
        return "REPLAY REJECTED"
    mapping = {
        ExecutionReviewStatus.NOT_STARTED: "NOT STARTED",
        ExecutionReviewStatus.REFUSED: "EXECUTION REFUSED",
        ExecutionReviewStatus.COMPLETED: "EXECUTED",
        ExecutionReviewStatus.FAILED_CONFIRMED: "FAILED",
        ExecutionReviewStatus.FAILED_AMBIGUOUS: "FAILED",
        ExecutionReviewStatus.INCOMPLETE: "INCOMPLETE",
        ExecutionReviewStatus.CONFLICT: "CONFLICT",
    }
    return mapping[projection.execution_status]


def _terminal_state(projection: ReviewProjection) -> str:
    mapping = {
        ExecutionReviewStatus.NOT_STARTED: "NOT STARTED",
        ExecutionReviewStatus.REFUSED: "EXECUTION REFUSED",
        ExecutionReviewStatus.COMPLETED: "COMPLETED",
        ExecutionReviewStatus.FAILED_CONFIRMED: "FAILED",
        ExecutionReviewStatus.FAILED_AMBIGUOUS: "FAILED",
        ExecutionReviewStatus.INCOMPLETE: "INCOMPLETE",
        ExecutionReviewStatus.CONFLICT: "CONFLICT",
    }
    return mapping[projection.execution_status]


def _payment_state(projection: ReviewProjection) -> str:
    if projection.evidence_completeness is EvidenceCompleteness.INCOMPLETE:
        return "UNKNOWN"
    if projection.execution_status is ExecutionReviewStatus.FAILED_AMBIGUOUS:
        return "UNKNOWN"
    return "RECORDED" if projection.payment_recorded else "NOT RECORDED"


def _decision_explanation(projection: ReviewProjection) -> str:
    explanations = {
        ProjectionDisposition.REFUSAL: (
            "Construction was refused; no authorization decision was sealed."
        ),
        ProjectionDisposition.DENY: (
            "The runtime recorded DENY for the reviewed tool call."
        ),
        ProjectionDisposition.ALLOW: (
            "The runtime recorded ALLOW. Execution remains a separate observed outcome."
        ),
        ProjectionDisposition.MODEL_NON_ATTEMPT: (
            "The model produced no candidate tool call; this is not an authorization decision or enforcement success."
        ),
        ProjectionDisposition.UNDETERMINED: (
            "The evidence does not support a determined authorization disposition."
        ),
        ProjectionDisposition.CONFLICT: (
            "The projected authorization trail conflicts and cannot support one disposition."
        ),
    }
    return explanations[projection.disposition]


def _observed_at(projection: ReviewProjection) -> str:
    return projection.recorded_at or "NOT AVAILABLE"


def _rule_rows(projection: ReviewProjection) -> str:
    if not projection.rule_facts:
        return (
            '<tr><td colspan="5"><span class="empty-state">'
            "NOT AVAILABLE — no ordered decision rule trace is present in the projection."
            "</span></td></tr>"
        )
    rows = []
    for position, fact in enumerate(projection.rule_facts, 1):
        rows.append(
            "<tr>"
            f"<td>{position}</td>"
            f"<td><code>{escape(_text(fact.rule_id))}</code></td>"
            f"<td>{_status(_canonical_state(fact.outcome))}</td>"
            f"<td>{escape(_canonical_state(fact.stage))}</td>"
            f"<td>{escape(fact.argument_name or 'NOT APPLICABLE')}"
            f"<br><code>{escape(_text(fact.constraint_id))}</code></td>"
            "</tr>"
        )
    return "".join(rows)


def _argument_rows(projection: ReviewProjection) -> str:
    if not projection.argument_facts:
        return (
            '<tr><td colspan="6"><span class="empty-state">'
            "NOT AVAILABLE — no argument projection is present for this state."
            "</span></td></tr>"
        )
    rows = []
    for fact in projection.argument_facts:
        rows.append(
            "<tr>"
            f"<td><code>{escape(fact.name)}</code></td>"
            f"<td>{escape(_text(fact.role))}</td>"
            f"<td>{escape(fact.masked_display)}</td>"
            f"<td>{escape(_text(fact.provenance_class))}</td>"
            f"<td>{escape(fact.resolution_status)}</td>"
            f"<td>{escape(fact.binding_status)}</td>"
            "</tr>"
        )
    return "".join(rows)


def _callback_items(projection: ReviewProjection) -> str:
    if not projection.callback_trail:
        return (
            "<li><strong>NOT APPLICABLE</strong>"
            "<code>no callback event projected</code></li>"
        )
    labels = {
        "callback.received": "RECEIVED",
        "callback.vetoed": "VETOED",
        "callback.released": "RELEASED",
        "callback.tool_entered": "TOOL ENTERED",
    }
    return "".join(
        "<li>"
        f"<strong>{escape(labels.get(event_type.value, event_type.value.upper()))}</strong>"
        f"<code>{escape(event_type.value)}</code>"
        "</li>"
        for event_type in projection.callback_trail
    )


def _producer_text(projection: ReviewProjection) -> str:
    if not projection.producer_facts:
        return "NOT AVAILABLE"
    return "; ".join(
        f"{item.component} / {item.build_version}"
        for item in projection.producer_facts
    )


def _correlations(label: str, values: Iterable[object]) -> str:
    values = tuple(values)
    rendered = ", ".join(_short(item) for item in values) if values else "NOT APPLICABLE"
    return f"<div><dt>{escape(label)}</dt><dd><code>{escape(rendered)}</code></dd></div>"


def _masking_state(projection: ReviewProjection) -> str:
    if any(item.domain.value == "MASKING" for item in projection.findings):
        return "FAILED"
    if projection.integrity_status is ProjectionStatus.CLEAN:
        return "PASS"
    return "WARNING"


def _finding_items(projection: ReviewProjection) -> str:
    if not projection.findings:
        return "<li>No integrity or reconciliation findings in ReviewProjection.</li>"
    return "".join(
        "<li>"
        f"{_status(item.domain.value, 'warning')}"
        f"<code>{escape(item.code.value)}</code>"
        f"<span>Sequence {item.sequence} · {escape(item.location)}</span>"
        "</li>"
        for item in projection.findings
    )


def _integrity_notice(projection: ReviewProjection) -> str:
    if projection.evidence_completeness is EvidenceCompleteness.COMPLETE:
        return (
            '<p class="proof-note">COMPLETE means the current projection has no '
            "integrity or reconciliation finding. It is not a production-readiness claim.</p>"
        )
    return (
        '<p class="integrity-warning"><strong>WARNING — EVIDENCE INCOMPLETE.</strong> '
        "The workspace does not convert missing, conflicting, or non-authoritative evidence "
        "into a success state.</p>"
    )


def _external_confirmation(projection: ReviewProjection) -> str:
    if projection.execution_status in {
        ExecutionReviewStatus.NOT_STARTED,
        ExecutionReviewStatus.REFUSED,
    }:
        return "NOT APPLICABLE — EXECUTION DID NOT START"
    if projection.execution_status is ExecutionReviewStatus.INCOMPLETE:
        return "UNKNOWN — EVIDENCE INCOMPLETE"
    if projection.execution_status is ExecutionReviewStatus.CONFLICT:
        return "UNKNOWN — EVIDENCE CONFLICT"
    if projection.execution_status is ExecutionReviewStatus.FAILED_AMBIGUOUS:
        return "EXTERNAL RESULT UNCONFIRMED"
    if projection.external_result_confirmed is True:
        return "EXTERNAL RESULT CONFIRMED"
    if projection.external_result_confirmed is False:
        return "EXTERNAL RESULT UNCONFIRMED"
    return "NOT APPLICABLE"


def _export_digest(projection: ReviewProjection) -> str:
    if not projection.export_digests:
        return "NOT FINALIZED"
    if len(projection.export_digests) != 1:
        return "CONFLICT"
    return _short(projection.export_digests[0])


def render_decision_review_workspace(projection: ReviewProjection) -> str:
    """Render one immutable projection as a self-contained read-only HTML page."""

    if type(projection) is not ReviewProjection:
        raise TypeError("decision review workspace requires exact ReviewProjection")

    decision_state = _disposition_state(projection)
    execution_state = _execution_state(projection)
    terminal_state = _terminal_state(projection)
    payment_state = _payment_state(projection)
    callback_state = _canonical_state(projection.callback_action)
    completeness = _canonical_state(projection.evidence_completeness)
    integrity = _canonical_state(projection.integrity_status)
    reconciliation = _canonical_state(projection.reconciliation_status)
    tool = _one(projection.tool_ids)
    contract = _one(projection.tool_contract_versions)
    stage = _canonical_state(projection.decision_stage)
    primary_rule = _text(projection.primary_rule_id)
    policy = _one(projection.policy_versions)
    registry = _one(projection.registry_versions)
    schema = ", ".join(projection.evidence_schema_versions) or "NOT AVAILABLE"
    observed_at = _observed_at(projection)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <style>{_STYLES}</style>
</head>
<body>
  <a class="skip-link" href="#decision-detail">Skip to selected decision</a>
  <header class="boundary-banner">
    <span><strong>Read-only runtime evidence</strong> · {_OFFLINE_PROVENANCE} · not production-ready</span>
    <span>No authorization, execution, repair, export, or policy controls</span>
  </header>

  <main class="workspace" id="decision-detail" tabindex="-1">
    <header class="masthead">
      <div>
        <p class="eyebrow">Decision evidence / single selected record</p>
        <h1>TIDEMARK Decision Review</h1>
        <p class="dek">An explanation of an already-recorded runtime decision. The screen reads a masked ReviewProjection; it does not make or change the decision.</p>
      </div>
      <div class="hero-states" aria-label="Primary decision and execution states">
        <div class="hero-state"><span class="meta-label">Decision outcome</span>{_status(decision_state)}</div>
        <div class="hero-state"><span class="meta-label">Execution outcome</span>{_status(execution_state)}</div>
      </div>
    </header>

    <div class="workspace-grid">
      <nav class="panel decision-list" id="decision-list" aria-labelledby="decision-list-title">
        <div class="panel__head">
          <h2 id="decision-list-title">Decision list</h2>
          <span class="source-label source-label--derived">Derived review state</span>
        </div>
        <div class="panel__body">
          <p class="proof-note">One supplied record is selected; no selector is required.</p>
          <ol class="decision-records">
            <li class="decision-record">
              <strong>Selected decision</strong>
              <dl class="decision-record__grid">
                <div><dt>Time</dt><dd>{escape(observed_at)}</dd></div>
                <div><dt>Tool</dt><dd><code>{escape(tool)}</code></dd></div>
                <div><dt>Decision</dt><dd>{_status(decision_state)}</dd></div>
                <div><dt>Execution</dt><dd>{_status(execution_state)}</dd></div>
                <div><dt>Primary rule</dt><dd><code>{escape(primary_rule)}</code></dd></div>
                <div><dt>Scenario</dt><dd>NOT PRESENT IN PROJECTION</dd></div>
              </dl>
            </li>
          </ol>
        </div>
      </nav>

      <section class="panel decision-summary" id="decision-summary" aria-labelledby="decision-summary-title">
        <div class="panel__head">
          <h2 id="decision-summary-title">Decision summary</h2>
          <span class="source-label source-label--observed">Observed evidence</span>
        </div>
        <div class="panel__body">
          <p class="summary-copy">{escape(_decision_explanation(projection))}</p>
          <dl class="summary-grid">
            <div><dt>Outcome</dt><dd>{_status(decision_state)}</dd></div>
            <div><dt>Tool</dt><dd><code>{escape(tool)}</code></dd></div>
            <div><dt>Primary rule</dt><dd><code>{escape(primary_rule)}</code></dd></div>
            <div><dt>Decision stage</dt><dd>{escape(stage)}</dd></div>
            <div><dt>Policy version</dt><dd><code>{escape(policy)}</code></dd></div>
            <div><dt>Tool contract</dt><dd><code>{escape(contract)}</code></dd></div>
          </dl>
        </div>
      </section>

      <section class="panel argument-review" id="argument-review" aria-labelledby="argument-review-title">
        <div class="panel__head">
          <h2 id="argument-review-title">Argument &amp; provenance review</h2>
          <span class="source-label source-label--observed">Observed evidence</span>
        </div>
        <div class="panel__body table-wrap" tabindex="0" aria-label="Argument review scroll region">
          <table>
            <caption>Protected values remain absent; supplied form and masked display are the review surface.</caption>
            <thead><tr><th>Argument</th><th>Role</th><th>Supplied form / masked value</th><th>Provenance class</th><th>Resolution</th><th>Binding</th></tr></thead>
            <tbody>{_argument_rows(projection)}</tbody>
          </table>
        </div>
      </section>

      <div class="review-rail">
        <section class="panel" id="callback-timeline" aria-labelledby="callback-title">
          <div class="panel__head"><h2 id="callback-title">Callback timeline</h2><span class="source-label source-label--derived">Derived review state</span></div>
          <div class="panel__body">
            <p>{_status(callback_state)}</p>
            <ol class="timeline">{_callback_items(projection)}</ol>
          </div>
        </section>

        <section class="panel" id="execution-proof" aria-labelledby="execution-title">
          <div class="panel__head"><h2 id="execution-title">Execution &amp; side-effect proof</h2><span class="source-label source-label--derived">Derived review state</span></div>
          <div class="panel__body">
            <dl class="proof-grid">
              <div><dt>Execution start</dt><dd>{_status('STARTED' if projection.execution_started else 'NOT STARTED')}</dd></div>
              <div><dt>Start marker count</dt><dd>{projection.execution_start_count}</dd></div>
              <div><dt>Terminal outcome</dt><dd>{_status(terminal_state)}</dd></div>
              <div><dt>External result</dt><dd>{escape(_external_confirmation(projection))}</dd></div>
              <div><dt>Replay state</dt><dd>{_status(_canonical_state(projection.replay_state))}</dd></div>
              <div><dt>Authoritative payment</dt><dd>{_status(payment_state)}</dd></div>
              <div><dt>Payment record count</dt><dd>{projection.payment_count}</dd></div>
              <div><dt>Payment state basis</dt><dd>ReviewProjection</dd></div>
            </dl>
            <p class="proof-note">Decision outcome and execution outcome are separate. An ALLOW is never rewritten by a later refusal, failure, or replay rejection.</p>
          </div>
        </section>
      </div>

      <section class="panel rule-trace" id="rule-trace" aria-labelledby="rule-trace-title">
        <div class="panel__head"><h2 id="rule-trace-title">Ordered rule trace</h2><span class="source-label source-label--observed">Observed evidence</span></div>
        <div class="panel__body table-wrap rule-scroll" tabindex="0" aria-label="Ordered rule trace scroll region">
          <table>
            <caption>Canonical rule identities remain visible in recorded evaluation order.</caption>
            <thead><tr><th>Order</th><th>Rule ID</th><th>Result</th><th>Stage</th><th>Argument / constraint</th></tr></thead>
            <tbody>{_rule_rows(projection)}</tbody>
          </table>
        </div>
      </section>

      <div class="evidence-column">
        <section class="panel" id="correlation-panel" aria-labelledby="correlation-title">
          <div class="panel__head"><h2 id="correlation-title">Correlation panel</h2><span class="source-label source-label--observed">Observed evidence</span></div>
          <div class="panel__body"><dl class="correlation-grid">
            {_correlations('Trace', (projection.trace_id,))}
            {_correlations('Invocation', projection.invocation_ids)}
            {_correlations('Call', projection.call_ids)}
            {_correlations('Decision', projection.decision_ids)}
            {_correlations('Prepared call', projection.prepared_call_ids)}
            {_correlations('Execution', projection.execution_ids)}
          </dl></div>
        </section>

        <section class="panel" id="evidence-integrity" aria-labelledby="integrity-title">
          <div class="panel__head"><h2 id="integrity-title">Evidence integrity &amp; run context</h2><span class="source-label source-label--derived">Derived review state</span></div>
          <div class="panel__body">
            <dl class="context-grid">
              <div><dt>Completeness</dt><dd>{_status(completeness)}</dd></div>
              <div><dt>Integrity</dt><dd>{_status(integrity)}</dd></div>
              <div><dt>Reconciliation</dt><dd>{_status(reconciliation)}</dd></div>
              <div><dt>Masking scan</dt><dd>{_status(_masking_state(projection))}</dd></div>
              <div><dt>Evidence schema / protocol</dt><dd><code>{escape(schema)}</code></dd></div>
              <div><dt>Projection masking profile</dt><dd><code>{escape(projection.masking_profile_version)}</code></dd></div>
              <div><dt>Producer / build</dt><dd><code>{escape(_producer_text(projection))}</code></dd></div>
              <div><dt>Policy / registry</dt><dd><code>{escape(policy)} / {escape(registry)}</code></dd></div>
              <div><dt>Run provenance</dt><dd>{_status(_OFFLINE_PROVENANCE, 'warning')}</dd></div>
              <div><dt>Selected live model</dt><dd>{_SELECTED_MODEL_DISPLAY_NAME}<br><small>Not asserted as used by this evidence fallback projection.</small></dd></div>
              <div><dt>Live identifier / access path</dt><dd>NOT ASSERTED FOR EVIDENCE FALLBACK</dd></div>
              <div><dt>Fixture version</dt><dd>NOT PRESENT IN PROJECTION</dd></div>
              <div><dt>Finalized export digest</dt><dd><code>{escape(_export_digest(projection))}</code></dd></div>
              <div><dt>Authoritative events</dt><dd>{projection.authoritative_event_count}</dd></div>
            </dl>
            {_integrity_notice(projection)}
            <ul class="findings">{_finding_items(projection)}</ul>
          </div>
        </section>
      </div>

      <aside class="panel state-legend" id="state-legend" aria-labelledby="legend-title">
        <div class="panel__head"><h2 id="legend-title">State legend</h2><span class="source-label source-label--derived">Text is authoritative</span></div>
        <div class="panel__body">
          <ul class="legend-list">
            <li><strong>MODEL NON-ATTEMPT</strong><span>No candidate call; not DENY, veto, or enforcement success.</span></li>
            <li><strong>REFUSAL</strong><span>No complete executable call or decision could be constructed.</span></li>
            <li><strong>DENY</strong><span>A decision rejected a complete-enough canonical proposal.</span></li>
            <li><strong>ALLOW</strong><span>Authorization may create one prepared call; execution is separate.</span></li>
            <li><strong>EXECUTION REFUSED</strong><span>A prepared call was rejected before execution started.</span></li>
            <li><strong>EXECUTED / COMPLETED</strong><span>The execution boundary was crossed and the local attempt completed.</span></li>
            <li><strong>FAILED</strong><span>Execution failed or remained externally ambiguous; ALLOW does not become DENY.</span></li>
            <li><strong>REPLAY REJECTED</strong><span>A consumed attempt added no second execution start.</span></li>
            <li><strong>RECORDED / NOT RECORDED</strong><span>Authoritative synthetic payment evidence state, never inferred from color.</span></li>
            <li><strong>COMPLETE / INCOMPLETE</strong><span>Whether integrity and reconciliation permit this explanation.</span></li>
          </ul>
        </div>
      </aside>
    </div>

    <footer class="workspace-footer">
      <span>Static local HTML · no JavaScript · no provider or network dependency</span>
      <span>Projection input only · read-only</span>
    </footer>
  </main>
</body>
</html>"""


__all__ = ("render_decision_review_workspace",)
