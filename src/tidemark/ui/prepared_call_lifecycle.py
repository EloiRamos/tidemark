"""Encoded, read-only rendering for the W1 prepared-call lifecycle explorer.

The renderer accepts only the closed W1 mechanism projection and a bounded
presentation instance number. All security facts are present in the returned
HTML before client-side stage selection changes visibility or focus.
"""

from html import escape
from typing import Tuple

from tidemark.evidence.mechanism_projection import (
    ClaimProvenance,
    LifecycleStageFact,
    LifecycleStageId,
    PreparedCallMechanismProjection,
    W2ProofReference,
)


_REFERENCE_ONLY_LABEL = "REFERENCE ONLY - NOT EXECUTED BY THIS UI"
_NOT_CREATED = "NOT_CREATED (null)"
_TRANSACTION_SEQUENCE = (
    "valid prepared capability"
    " → execution-time gate validation"
    " → durable pre-execution evidence"
    " → local atomic single-use consumption/commit"
    " → adapter entry"
    " → outcome evidence"
)

_STAGE_EXPLANATIONS = {
    LifecycleStageId.W1_L01: (
        "Nothing supplied by the proposal is trusted.",
        "Only the candidate state, public tool correlation, and safe proposed form are projected.",
        "No candidate means no policy evaluation and no enforcement claim.",
    ),
    LifecycleStageId.W1_L02: (
        "The immutable tool contract owns protected-role classification.",
        "Argument name, PROTECTED_REFERENCE role, and supported type are safe metadata.",
        "A missing or inconsistent contract is construction refusal, never a trusted value.",
    ),
    LifecycleStageId.W1_L03: (
        "Only a runtime-issued opaque selection can represent a protected argument.",
        "The browser sees the selection class, never the reference token.",
        "Raw protected supply fails representation and cannot reach resolution or preparation.",
    ),
    LifecycleStageId.W1_L04: (
        "Trusted runtime lookup owns existence and kind validation.",
        "Only the masked resolution state and safe rule outcome are visible.",
        "Forged, unresolvable, or wrong-kind references fail closed.",
    ),
    LifecycleStageId.W1_L05: (
        "A resolved value remains runtime-private.",
        "Invocation, parent, active, and single-use context bind the protected selection.",
        "A context or lifecycle mismatch produces the existing exact DENY rule.",
    ),
    LifecycleStageId.W1_L06: (
        "One immutable policy snapshot and trusted registry determine evaluation.",
        "Structure, representation, resolution, binding, lifecycle, value, and authorization stay ordered.",
        "The first failure remains visible; later policy stages are NOT EVALUATED.",
    ),
    LifecycleStageId.W1_L07: (
        "Only ALLOW may produce an immutable prepared capability.",
        "Public identity and digest are separated from runtime-private payload, correlation, object, adapter, and target coverage.",
        "DENY, refusal, non-attempt, or binding-registration failure creates no prepared capability.",
    ),
    LifecycleStageId.W1_L08: (
        "The execution gate owns the transaction's only execution-time revalidation.",
        "The prepared object, payload, correlations, adapter identity/version, and current local authority are covered.",
        "Post-ALLOW invalid state is execution REFUSED, not retroactive DENY; replay remains distinct.",
    ),
    LifecycleStageId.W1_L09: (
        "The implemented contract requires durable pre-execution evidence after successful L08.",
        "The local order is receipt, atomic single-use consumption/commit, then adapter entry.",
        "Receipt failure leaves local authority unconsumed and causes no adapter entry or payment.",
    ),
    LifecycleStageId.W1_L10: (
        "Masked outcome evidence, not the ALLOW decision, supports execution review.",
        "Execution, payment, replay, completeness, integrity, and reconciliation remain distinct facts.",
        "Incomplete, conflicting, or ambiguous evidence never becomes success or external-effect absence.",
    ),
}


LIFECYCLE_STYLES = r"""
.w1-lifecycle{margin-top:16px;padding:14px;border:1px solid var(--line);border-radius:5px;background:#09131f;min-width:0}.w1-lifecycle__head{display:flex;align-items:flex-start;gap:12px;flex-wrap:wrap}.w1-lifecycle__head h2{margin:4px 0 0;font:600 18px var(--mono)}.w1-lifecycle__intro{max-width:92ch;margin:6px 0 0;color:var(--ink3);font-size:12px;line-height:1.5}.w1-provenance-legend{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,205px),1fr));gap:6px;margin-top:12px}.w1-provenance-legend span{padding:7px 8px;border:1px solid var(--line-soft);font:600 9px/1.4 var(--mono);overflow-wrap:anywhere}.w1-lifecycle__tabs{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,130px),1fr));gap:5px;margin-top:12px}.w1-lifecycle__tab{min-width:0;padding:8px;border:1px solid var(--line);border-radius:3px;text-align:left;color:var(--ink3);background:var(--panel)}.w1-lifecycle__tab span{display:block}.w1-lifecycle__tab-id{font:600 9px var(--mono);color:var(--ink5)}.w1-lifecycle__tab-title{margin-top:4px;font:600 9.5px/1.35 var(--mono);overflow-wrap:anywhere}.w1-lifecycle__tab[aria-selected=true]{border-color:var(--trusted);background:#0e2a2e;color:var(--ink)}.w1-lifecycle__panel{margin-top:8px;padding:12px;border:1px solid var(--line);background:var(--panel)}.w1-lifecycle__panel-head{display:flex;gap:9px;align-items:baseline;flex-wrap:wrap}.w1-lifecycle__panel-head h3{margin:0;font:600 14px/1.35 var(--mono)}.w1-lifecycle__badge{padding:3px 6px;border:1px solid var(--line);font:600 9px/1.3 var(--mono);overflow-wrap:anywhere}.w1-lifecycle__rows{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,230px),1fr));gap:8px;margin-top:10px}.w1-lifecycle__row{padding:9px;border-top:2px solid var(--line);background:#0b1623;min-width:0}.w1-lifecycle__row span,.w1-seal__fact span,.w1-lane span{display:block;font:600 9px/1.35 var(--mono);letter-spacing:.08em;color:var(--ink5)}.w1-lifecycle__row strong,.w1-seal__fact strong,.w1-lane strong{display:block;margin-top:5px;font:500 11px/1.45 var(--mono);overflow-wrap:anywhere}.w1-seal,.w1-transaction,.w1-proof-links{margin-top:12px;border:1px solid var(--line);background:var(--panel)}.w1-section-head{padding:10px 12px;border-bottom:1px solid var(--line);font:600 10px var(--mono);letter-spacing:.14em;color:var(--trusted)}.w1-seal__grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,220px),1fr));gap:0}.w1-seal__fact{padding:9px 12px;border-bottom:1px solid var(--line-soft);min-width:0}.w1-argument-list{margin:5px 0 0;padding-left:18px;font:500 10.5px/1.5 var(--mono)}.w1-allow-divider{display:flex;align-items:center;gap:12px;margin:14px 0 8px}.w1-allow-divider span{height:1px;flex:1;background:var(--warn)}.w1-allow-divider strong{font:600 11px var(--mono);letter-spacing:.16em;color:var(--warn)}.w1-lanes{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.w1-lane{padding:11px;border:1px solid var(--line);background:var(--panel)}.w1-transaction__sequence{padding:12px;font:600 11px/1.7 var(--mono);color:var(--ink);overflow-wrap:anywhere}.w1-transaction__note{margin:0;padding:0 12px 12px;color:var(--ink3);font-size:11px;line-height:1.5}.w1-proof-links>summary{padding:11px 12px;cursor:pointer;font:600 11px var(--mono);color:var(--trusted)}.w1-proof-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,300px),1fr));gap:8px;padding:0 12px 12px;margin:0;list-style:none}.w1-proof{padding:10px;border:1px solid var(--line-soft);min-width:0}.w1-proof__title{font:600 11px/1.4 var(--mono)}.w1-proof__status{margin-top:5px;color:var(--warn);font:600 9px/1.4 var(--mono)}.w1-proof p{margin:6px 0;color:var(--ink3);font-size:10.5px;line-height:1.45}.w1-proof code{font-size:10px}.w1-p08{margin:0 12px 12px;padding:10px;border:1px solid var(--warn);color:var(--ink2);font-size:11px;line-height:1.5}.w1-p08 strong{display:block;color:var(--warn);font:600 11px var(--mono)}.w1-p08 ul{margin:5px 0 0;padding-left:18px}
@media(max-width:1439px){.w1-lifecycle{padding:12px}.w1-lifecycle__tabs{grid-template-columns:repeat(auto-fit,minmax(min(100%,115px),1fr))}.w1-lanes{grid-template-columns:1fr}}
@media(max-width:1280px){.w1-lifecycle__tabs{grid-template-columns:repeat(5,minmax(0,1fr))}.w1-lifecycle__rows{grid-template-columns:1fr}.w1-proof-list{grid-template-columns:1fr}}
"""


LIFECYCLE_SCRIPT = r"""
(function(){'use strict';
function all(root,q){return Array.prototype.slice.call(root.querySelectorAll(q));}
function choose(root,button,moveFocus){
 var key=button.getAttribute('data-lifecycle-select');
 all(root,'[data-lifecycle-select]').forEach(function(n){var chosen=n===button;n.setAttribute('aria-selected',String(chosen));n.setAttribute('tabindex',chosen?'0':'-1');});
 all(root,'[data-lifecycle-panel]').forEach(function(n){n.hidden=n.getAttribute('data-lifecycle-panel')!==key;});
 if(moveFocus)button.focus();
}
document.addEventListener('click',function(event){var button=event.target.closest('[data-lifecycle-select]');if(!button)return;var root=button.closest('.w1-lifecycle');if(root)choose(root,button,false);});
document.addEventListener('keydown',function(event){var button=event.target.closest('[data-lifecycle-select]');if(!button)return;var root=button.closest('.w1-lifecycle');var buttons=all(root,'[data-lifecycle-select]');var index=buttons.indexOf(button);var next=index;if(event.key==='ArrowRight')next=(index+1)%buttons.length;else if(event.key==='ArrowLeft')next=(index+buttons.length-1)%buttons.length;else if(event.key==='Home')next=0;else if(event.key==='End')next=buttons.length-1;else return;event.preventDefault();choose(root,buttons[next],true);});
})();
"""


def _safe(value: object) -> str:
    if value is None:
        return "null"
    if hasattr(value, "value"):
        value = getattr(value, "value")
    if type(value) is bool:
        return "true" if value else "false"
    return str(value)


def _e(value: object) -> str:
    return escape(_safe(value), quote=True)


def _protected_summary(projection: PreparedCallMechanismProjection) -> str:
    if not projection.protected_arguments:
        return "NO PROTECTED ARGUMENT FACT"
    return " · ".join(
        f"{item.name}: {item.role.value} / {item.supported_type.value}"
        for item in projection.protected_arguments
    )


def _protected_state(projection: PreparedCallMechanismProjection) -> str:
    if not projection.protected_arguments:
        return "NOT_APPLICABLE"
    return " · ".join(
        f"{item.name}: resolution {item.resolution_state.value}; "
        f"binding {item.binding_state.value}; value {item.runtime_value_state.value}"
        for item in projection.protected_arguments
    )


def _scenario_fact(stage: LifecycleStageFact, projection: PreparedCallMechanismProjection) -> str:
    if stage.stage_id is LifecycleStageId.W1_L01:
        return (
            f"{projection.proposal.candidate_state.value} · "
            f"{projection.proposal.proposed_form.value} · "
            f"{_safe(projection.proposal.tool_id)}"
        )
    if stage.stage_id in {
        LifecycleStageId.W1_L02,
        LifecycleStageId.W1_L03,
    }:
        return _protected_summary(projection)
    if stage.stage_id in {
        LifecycleStageId.W1_L04,
        LifecycleStageId.W1_L05,
    }:
        return _protected_state(projection)
    if stage.stage_id is LifecycleStageId.W1_L06:
        return (
            f"decision {projection.terminal.decision.value} · primary rule "
            f"{_safe(projection.terminal.primary_rule_id)}"
        )
    if stage.stage_id is LifecycleStageId.W1_L07:
        return (
            "prepared capability PRESENT"
            if projection.seal.prepared_call_present
            else "prepared capability NOT_CREATED (null)"
        )
    if stage.stage_id is LifecycleStageId.W1_L08:
        return f"execution {projection.terminal.execution_status.value} · replay {projection.terminal.replay_state.value}"
    if stage.stage_id is LifecycleStageId.W1_L09:
        return "DERIVED_IMPLEMENTED_CONTRACT · W2-P03 reference"
    return (
        f"starts {projection.terminal.execution_start_count} · synthetic payments "
        f"{projection.terminal.authoritative_synthetic_payment_count} · "
        f"evidence {projection.terminal.evidence_completeness.value}"
    )


def _render_stage_panel(
    stage: LifecycleStageFact,
    projection: PreparedCallMechanismProjection,
    instance_id: int,
    selected: bool,
) -> str:
    trusted, bound, fails_closed = _STAGE_EXPLANATIONS[stage.stage_id]
    panel_id = f"w1-lifecycle-{instance_id}-{stage.stage_id.value}-panel"
    tab_id = f"w1-lifecycle-{instance_id}-{stage.stage_id.value}-tab"
    hidden = "" if selected else " hidden"
    return (
        f'<section class="w1-lifecycle__panel" id="{panel_id}" '
        f'data-lifecycle-panel="{stage.stage_id.value}" role="tabpanel" '
        f'aria-labelledby="{tab_id}"{hidden}>'
        f'<div class="w1-lifecycle__panel-head"><code>{stage.stage_id.value}</code>'
        f'<h3>{escape(stage.title)}</h3>'
        f'<span class="w1-lifecycle__badge">{stage.trust_zone.value}</span>'
        f'<span class="w1-lifecycle__badge">{stage.state.value}</span>'
        f'<span class="w1-lifecycle__badge">{stage.fact_provenance.value}</span></div>'
        f'<p class="w1-lifecycle__intro">CURRENT SAFE FACT · {_e(_scenario_fact(stage, projection))}</p>'
        '<div class="w1-lifecycle__rows">'
        f'<div class="w1-lifecycle__row"><span>WHAT IS TRUSTED</span><strong>{escape(trusted)}</strong></div>'
        f'<div class="w1-lifecycle__row"><span>WHAT IS BOUND</span><strong>{escape(bound)}</strong></div>'
        f'<div class="w1-lifecycle__row"><span>WHAT FAILS CLOSED</span><strong>{escape(fails_closed)}</strong></div>'
        "</div></section>"
    )


def _render_seal(projection: PreparedCallMechanismProjection) -> str:
    seal = projection.seal
    if seal.prepared_call_present:
        capability = "PRESENT"
        prepared_id = _safe(seal.public_prepared_call_id)
        digest = _safe(seal.public_integrity_id)
        adapter = f"{_safe(seal.adapter_id)} / {_safe(seal.adapter_version)}"
        arguments = "".join(
            f"<li>{_e(item.name)} · {_e(item.type_id)} · {_e(item.role)}</li>"
            for item in seal.argument_metadata
        )
    else:
        capability = prepared_id = digest = adapter = _NOT_CREATED
        arguments = f"<li>{_NOT_CREATED} (empty)</li>"
    coverage = (
        ("Private binding", seal.private_binding_state),
        ("Payload coverage", seal.payload_binding_state),
        ("Correlation coverage", seal.correlation_binding_state),
        ("Adapter coverage", seal.adapter_binding_state),
        ("Single-use target coverage", seal.single_use_target_state),
        ("Prepared-object coverage", seal.object_binding_state),
    )
    coverage_html = "".join(
        f'<div class="w1-seal__fact"><span>{escape(label)}</span><strong>{_e(value)}</strong></div>'
        for label, value in coverage
    )
    return (
        '<section class="w1-seal" aria-label="Safe prepared-call sealing facts">'
        '<div class="w1-section-head">PREPARED-CALL SEALING · DERIVED_IMPLEMENTED_CONTRACT · W2-P06</div>'
        '<div class="w1-seal__grid">'
        f'<div class="w1-seal__fact"><span>Prepared capability</span><strong>{escape(capability)}</strong></div>'
        f'<div class="w1-seal__fact"><span>Public prepared-call ID</span><strong>{_e(prepared_id)}</strong></div>'
        f'<div class="w1-seal__fact"><span>Public integrity digest</span><strong>{_e(digest)}</strong></div>'
        f'<div class="w1-seal__fact"><span>Adapter ID / version</span><strong>{_e(adapter)}</strong></div>'
        f'{coverage_html}'
        '<div class="w1-seal__fact"><span>Browser boundary</span><strong>private_material_projected=false</strong></div>'
        f'<div class="w1-seal__fact"><span>Safe argument metadata</span><strong><ul class="w1-argument-list">{arguments}</ul></strong></div>'
        "</div></section>"
    )


def _render_decision_and_transaction(projection: PreparedCallMechanismProjection) -> str:
    terminal = projection.terminal
    return (
        '<div class="w1-allow-divider"><span></span><strong>ALLOW IS NOT EXECUTED</strong><span></span></div>'
        '<div class="w1-lanes" aria-label="Decision and execution are separate">'
        f'<section class="w1-lane"><span>DECISION</span><strong>{terminal.decision.value}</strong>'
        f'<span>PRIMARY RULE</span><strong>{_e(terminal.primary_rule_id)}</strong></section>'
        f'<section class="w1-lane"><span>EXECUTION</span><strong>{terminal.execution_status.value}</strong>'
        f'<span>REPLAY</span><strong>{terminal.replay_state.value}</strong>'
        f'<span>EXECUTION STARTS</span><strong>{terminal.execution_start_count}</strong>'
        f'<span>SYNTHETIC PAYMENTS</span><strong>{terminal.authoritative_synthetic_payment_count}</strong></section>'
        "</div>"
        '<section class="w1-transaction" aria-label="One execution transaction">'
        '<div class="w1-section-head">ONE EXECUTION TRANSACTION · DERIVED_IMPLEMENTED_CONTRACT · W2-P03</div>'
        f'<div class="w1-transaction__sequence">{_TRANSACTION_SEQUENCE}</div>'
        '<p class="w1-transaction__note">This is one execution transaction. L08 is the only execution-time revalidation. L09 begins after successful L08: durable receipt, then local consume/commit, then adapter entry. The guarantee is local at-most-once adapter entry only. No distributed transaction, global ordering, external exactly-once, or guaranteed external idempotency is claimed.</p>'
        "</section>"
    )


def _render_proof(reference: W2ProofReference) -> str:
    return (
        '<li class="w1-proof">'
        f'<div class="w1-proof__title">{escape(reference.property_id)} · {escape(reference.property_title)}</div>'
        f'<div class="w1-proof__status">{_REFERENCE_ONLY_LABEL}</div>'
        f'<p>{escape(reference.qualifier)}</p>'
        f'<code>{escape(reference.reviewer_hint)}</code>'
        "</li>"
    )


def _render_proof_references(references: Tuple[W2ProofReference, ...]) -> str:
    return (
        '<details class="w1-proof-links" open><summary>W2 PROOF REFERENCES · READ-ONLY REVIEWER HINTS</summary>'
        '<ul class="w1-proof-list">'
        + "".join(_render_proof(reference) for reference in references)
        + "</ul>"
        '<div class="w1-p08"><strong>W2-P08 · uncertainty is not success</strong>'
        'Proof PASS means uncertainty was preserved correctly. It does NOT mean:'
        '<ul><li>evidence PASS</li><li>execution success</li><li>external effect absence</li></ul></div>'
        "</details>"
    )


def render_prepared_call_lifecycle(
    projection: PreparedCallMechanismProjection,
    *,
    instance_id: int,
) -> str:
    """Render one exact W1 projection with view-only stage selection."""

    if type(projection) is not PreparedCallMechanismProjection:
        raise TypeError("lifecycle renderer requires PreparedCallMechanismProjection")
    if type(instance_id) is not int or not 1 <= instance_id <= 6:
        raise ValueError("lifecycle renderer instance_id requires 1 through 6")
    tabs = []
    panels = []
    for index, stage in enumerate(projection.stages):
        selected = index == 0
        selected_text = "true" if selected else "false"
        tabindex = "0" if selected else "-1"
        tab_id = f"w1-lifecycle-{instance_id}-{stage.stage_id.value}-tab"
        panel_id = f"w1-lifecycle-{instance_id}-{stage.stage_id.value}-panel"
        tabs.append(
            f'<button type="button" class="w1-lifecycle__tab" id="{tab_id}" '
            f'data-lifecycle-select="{stage.stage_id.value}" role="tab" '
            f'aria-selected="{selected_text}" aria-controls="{panel_id}" tabindex="{tabindex}">'
            f'<span class="w1-lifecycle__tab-id">{stage.stage_id.value}</span>'
            f'<span class="w1-lifecycle__tab-title">{escape(stage.title)}</span></button>'
        )
        panels.append(_render_stage_panel(stage, projection, instance_id, selected))
    provenance = "".join(
        f"<span>{item.value}</span>"
        for item in (
            ClaimProvenance.OBSERVED_MASKED_EVIDENCE,
            ClaimProvenance.DERIVED_FROM_OBSERVED_EVIDENCE,
            ClaimProvenance.DERIVED_IMPLEMENTED_CONTRACT,
            ClaimProvenance.APPROVED_STATIC_PRODUCT_COPY,
        )
    )
    return (
        f'<section class="w1-lifecycle" data-lifecycle-instance="{instance_id}" '
        'aria-label="Prepared Call Lifecycle Explorer">'
        '<div class="w1-lifecycle__head"><div><span class="section-title">PREPARED CALL LIFECYCLE EXPLORER</span>'
        '<h2>Selection becomes bounded local authority—or fails closed.</h2>'
        '<p class="w1-lifecycle__intro">Ten fixed stages explain trust, binding, policy, sealing, execution-time validation, evidence-before-effect, and outcome evidence without projecting a protected value or reference token.</p></div></div>'
        f'<div class="w1-provenance-legend" aria-label="Claim provenance grammar">{provenance}</div>'
        f'<div class="w1-lifecycle__tabs" role="tablist" aria-label="Prepared-call lifecycle stages">{"".join(tabs)}</div>'
        + "".join(panels)
        + _render_seal(projection)
        + _render_decision_and_transaction(projection)
        + _render_proof_references(projection.proof_references)
        + "</section>"
    )


__all__ = (
    "LIFECYCLE_SCRIPT",
    "LIFECYCLE_STYLES",
    "render_prepared_call_lifecycle",
)
