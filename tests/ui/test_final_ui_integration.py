import inspect
from dataclasses import replace
from html.parser import HTMLParser

import pytest

from tidemark.demo.harness import DeterministicDemoHarness
from tidemark.payment.fixtures import RAW_SYNTHETIC_DESTINATION
from tidemark.ui import final_ui
from tidemark.ui.final_ui import (
    COMMITTED_HISTORICAL_LIVE_PROOF_DIGEST,
    DESIGN_AUTHORITY,
    CommittedHistoricalLiveProof,
    build_final_ui_scenarios,
    render_final_ui,
)
from tidemark.ui.run_summary import ScenarioId


class _Audit(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.attrs = []
        self.buttons = []
        self._button = None

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs.extend(attrs)
        if tag == "button":
            self._button = []

    def handle_data(self, data):
        if self._button is not None:
            self._button.append(data)

    def handle_endtag(self, tag):
        if tag == "button" and self._button is not None:
            self.buttons.append(" ".join("".join(self._button).split()))
            self._button = None


def _run(seed="final-ui-integration"):
    return DeterministicDemoHarness(run_seed=seed).run()


def _scenarios(run):
    return build_final_ui_scenarios(
        run.summary,
        tuple(
            (item.scenario_id, item.projection, item.mechanism_projection)
            for item in run.scenarios
        ),
    )


def _panel(html, scenario_id, occurrence=0):
    marker = f'data-scenario-panel="{scenario_id.value}"'
    start = -1
    for _ in range(occurrence + 1):
        start = html.index(marker, start + 1)
    end = html.find('data-scenario-panel="', start + len(marker))
    return html[start:] if end < 0 else html[start:end]


def test_final_ui_exposes_four_surfaces_and_five_step_guided_demo():
    rendered = _run().integrated_ui_html
    audit = _Audit()
    audit.feed(rendered)

    assert rendered.count('data-surface="') == 4
    for surface in ("run", "inspector", "trace", "cloud"):
        assert f'data-surface="{surface}"' in rendered
    assert rendered.count('data-step="') == 5
    assert "01</span> Orient" in rendered
    assert "05</span> Cloud proof" in rendered
    assert "ArrowLeft" in rendered and "ArrowRight" in rendered
    assert "state.surface=steps[0][0]" in rendered
    assert "fetch(" not in rendered
    assert "XMLHttpRequest" not in rendered


def test_six_real_core_scenarios_and_three_fixture_variants_stay_separate():
    rendered = _run().integrated_ui_html

    for scenario_id in ScenarioId:
        assert f'data-select="{scenario_id.value}"' in rendered
    assert rendered.count('class="variant"') == 3
    assert rendered.count("DEMO FIXTURE REQUIRED") == 3
    assert "diagnostic state, not an attack scenario" in rendered
    assert "6 core scenarios · 3 state variants" in rendered


def test_seven_stage_causal_chain_keeps_policy_decision_execution_and_evidence():
    rendered = _run().integrated_ui_html
    allow_chain = _panel(rendered, ScenarioId.BENIGN_ALLOW, 0)
    positions = [
        allow_chain.index(f">{name}<")
        for name in (
            "PROPOSAL",
            "RESOLUTION",
            "BINDING",
            "POLICY",
            "DECISION",
            "EXECUTION",
            "EVIDENCE",
        )
    ]

    assert positions == sorted(positions)
    assert allow_chain.count('class="stage ') == 7
    assert "A DECISION IS NOT AN EXECUTION" in rendered
    assert "first failure stops evaluation" in rendered


def test_lifecycle_explorer_is_composed_inside_each_existing_inspector_panel():
    rendered = _run().integrated_ui_html
    allow = _panel(rendered, ScenarioId.BENIGN_ALLOW, 1)
    raw = _panel(rendered, ScenarioId.RAW_PROTECTED_VALUE_DENY, 1)

    assert rendered.count("PREPARED CALL LIFECYCLE EXPLORER") == 6
    assert rendered.count('data-lifecycle-select="') == 60
    assert (
        allow.index("TRUSTED RUNTIME BINDING")
        < allow.index("PREPARED CALL LIFECYCLE EXPLORER")
        < allow.index("ORDERED VALIDATION")
    )
    assert "REGISTERED_BEFORE_RETURN" in allow
    assert "Prepared capability</span><strong>PRESENT</strong>" in allow
    assert "Prepared capability</span><strong>NOT_CREATED (null)</strong>" in raw
    assert "RAW_PROTECTED_VALUE_REDACTED" in raw
    assert "ALLOW IS NOT EXECUTED" in allow
    assert "A DECISION IS NOT AN EXECUTION" in allow


def test_lifecycle_integration_preserves_both_existing_chains_exactly():
    rendered = _run().integrated_ui_html
    allow_run = _panel(rendered, ScenarioId.BENIGN_ALLOW, 0)
    allow_inspector = _panel(rendered, ScenarioId.BENIGN_ALLOW, 1)

    assert allow_run.count('class="stage ') == 7
    for stage in (
        "PROPOSAL",
        "RESOLUTION",
        "BINDING",
        "POLICY",
        "DECISION",
        "EXECUTION",
        "EVIDENCE",
    ):
        assert f">{stage}<" in allow_run
    assert allow_inspector.count('class="vstage"') == 7
    for stage in (
        "STRUCTURE",
        "REPRESENTATION",
        "RESOLUTION",
        "BINDING",
        "LIFECYCLE",
        "VALUE",
        "AUTHORIZATION",
    ):
        assert f'<span class="vstage__name">{stage}</span>' in allow_inspector


def test_real_first_failure_trace_stops_after_raw_value_representation_failure():
    rendered = _run().integrated_ui_html
    raw_inspector = _panel(rendered, ScenarioId.RAW_PROTECTED_VALUE_DENY, 1)

    assert "protected.raw_value_supplied.v1" in raw_inspector
    assert "REPRESENTATION" in raw_inspector and ">FAIL<" in raw_inspector
    for stage in ("RESOLUTION", "BINDING", "LIFECYCLE", "VALUE", "AUTHORIZATION"):
        stage_start = raw_inspector.index(f'<span class="vstage__name">{stage}</span>')
        stage_end = raw_inspector.index("</summary>", stage_start)
        assert "NOT EVALUATED" in raw_inspector[stage_start:stage_end]


def test_real_decision_execution_payment_and_replay_counts_are_preserved():
    rendered = _run().integrated_ui_html
    allow = _panel(rendered, ScenarioId.BENIGN_ALLOW, 1)
    raw = _panel(rendered, ScenarioId.RAW_PROTECTED_VALUE_DENY, 1)
    replay = _panel(rendered, ScenarioId.REPLAY_REJECTION, 1)

    assert "ALLOW" in allow and "EXECUTED / COMPLETED" in allow
    assert "EXECUTION STARTS</small><strong>1" in allow
    assert "SYNTHETIC PAYMENTS</small><strong>1" in allow
    assert "DENY" in raw and "NOT_STARTED" in raw
    assert "EXECUTION STARTS</small><strong>0" in raw
    assert "SYNTHETIC PAYMENTS</small><strong>0" in raw
    assert "REPLAY REJECTED" in replay
    assert "EXECUTION STARTS</small><strong>1" in replay
    assert "SYNTHETIC PAYMENTS</small><strong>1" in replay


def test_model_non_attempt_never_claims_runtime_enforcement():
    rendered = _run().integrated_ui_html
    panel = _panel(rendered, ScenarioId.MODEL_NON_ATTEMPT, 1)

    assert "MODEL NON-ATTEMPT / NO ENFORCEMENT CLAIM" in panel
    assert "not DENY, not callback veto, and not enforcement success" in panel
    assert "NOT EVALUATED" in panel
    assert "EXECUTION STARTS</small><strong>0" in panel


def test_browser_facing_artifact_contains_only_masked_projection_values():
    run = _run()
    rendered = run.integrated_ui_html

    assert RAW_SYNTHETIC_DESTINATION not in rendered
    assert "synthetic-routing://" not in rendered
    assert "PROTECTED VALUE RUNTIME-PRIVATE · MASK NOT PROJECTED" in rendered
    assert "fixed mask" not in rendered.lower()
    assert "reveal" not in " ".join(_AuditButtons(rendered)).lower()
    for scenario in run.scenarios:
        projection = scenario.projection
        assert all(item.masked_display in rendered for item in projection.argument_facts)


def _AuditButtons(rendered):
    audit = _Audit()
    audit.feed(rendered)
    return audit.buttons


def test_ui_has_view_controls_but_no_runtime_mutation_or_reveal_controls():
    rendered = _run().integrated_ui_html
    audit = _Audit()
    audit.feed(rendered)
    button_text = {item.lower() for item in audit.buttons}

    assert "button" in audit.tags
    assert not ({"form", "input", "textarea", "select"} & set(audit.tags))
    for forbidden in {
        "approve",
        "retry",
        "execute",
        "re-execute",
        "reveal",
        "copy raw protected value",
        "edit policy",
        "edit registry",
        "deploy",
        "delete evidence",
    }:
        assert forbidden not in button_text
    assert any("inspect this call" in item for item in button_text)
    assert any("evidence trace" in item for item in button_text)


def test_cloud_proof_is_committed_completed_evidence_not_a_live_resource_claim():
    rendered = _run().integrated_ui_html

    assert "COMPLETED CLOUD EVIDENCE — RESOURCES REMOVED AFTER VERIFIED SHUTDOWN" in rendered
    assert "Cloud Run Job" in rendered
    assert "europe-west1" in rendered
    assert "linux/amd64" in rendered
    assert "Gemini calls in cloud proof" in rendered and ">0<" in rendered
    assert "Application network calls" in rendered
    assert "not a live cloud query" in rendered
    assert "public endpoint" in rendered
    assert "Google Cloud Console" not in rendered


def test_historical_live_proof_is_committed_and_separate_from_current_and_cloud():
    rendered = _run().integrated_ui_html

    assert "HISTORICAL LIVE MODEL PROVENANCE" in rendered
    assert "historical committed evidence" in rendered
    assert "not current offline run" in rendered
    assert "not a live query" in rendered
    assert "not Order 21 cloud proof" in rendered
    assert "EVIDENCE FALLBACK / OFFLINE" in rendered
    assert "Gemini 3.6 Flash" in rendered
    assert "gemini-3.6-flash" in rendered
    assert "Gemini Developer API" in rendered
    assert "Google ADK 1.18.0" in rendered
    assert "authorization.allow.v1" in rendered
    assert "protected.raw_value_supplied.v1" in rendered
    assert "zero denied side effects" in rendered
    assert COMMITTED_HISTORICAL_LIVE_PROOF_DIGEST[:16] in rendered
    assert rendered.index("HISTORICAL LIVE MODEL PROVENANCE") < rendered.index(
        "CAUSAL CHAIN"
    )
    assert "LIVE MODEL / PROVIDER-BACKED EVIDENCE" not in rendered


def test_historical_live_projection_is_exact_type_closed_and_read_only():
    run = _run()
    scenarios = _scenarios(run)

    with pytest.raises(TypeError):
        render_final_ui(
            run.summary,
            scenarios,
            historical_live_proof=object(),
        )
    with pytest.raises(ValueError):
        replace(
            CommittedHistoricalLiveProof(),
            source='<img src=x onerror="alert(1)">',
        )
    with pytest.raises(ValueError):
        replace(CommittedHistoricalLiveProof(), currently_regenerated=True)


def test_real_projection_and_publication_correlations_are_rendered_with_output_encoding():
    run = _run()
    scenarios = list(_scenarios(run))
    injected = replace(scenarios[0].projection, trace_id='<img src=x onerror="alert(1)">')
    scenarios[0] = replace(scenarios[0], projection=injected)

    rendered = render_final_ui(run.summary, tuple(scenarios))

    assert '<img src=x onerror="alert(1)">' not in rendered
    assert "&lt;img src=x onerr" in rendered
    assert "ert(1)&quot;&gt;" in rendered
    assert run.summary.scenarios[0].publication_digest[:16] in rendered
    assert run.scenarios[0].projection.policy_versions[0].value in rendered
    assert run.scenarios[0].projection.registry_versions[0].value in rendered


def test_incomplete_conflict_and_ambiguous_variants_cannot_look_like_pass():
    rendered = _run().integrated_ui_html
    variants = rendered[rendered.index('class="variants"'):rendered.index('class="actions"', rendered.index('class="variants"'))]

    assert "EVIDENCE_INCOMPLETE" in variants
    assert "INTEGRITY_CONFLICT" in variants
    assert "EXECUTION_AMBIGUOUS" in variants
    assert ">PASS<" not in variants
    assert "DEMO FIXTURE REQUIRED" in variants


def test_final_ui_module_has_no_runtime_authority_evidence_store_or_provider_import():
    source = inspect.getsource(final_ui)
    import_lines = "\n".join(
        line for line in source.splitlines() if line.startswith(("from ", "import "))
    )

    for forbidden in (
        "AuditEvent",
        "LocalAuditStore",
        "EvidenceRecorder",
        "PolicyEngine",
        "TrustedReferenceStore",
        "ReferenceResolver",
        "PreparedToolCall",
        "ExecutionGate",
        "SyntheticPaymentStore",
        "google.adk",
        "google.genai",
    ):
        assert forbidden not in import_lines
    assert "from tidemark.evidence.projection import" in source
    assert DESIGN_AUTHORITY == "PROTOTYPE_02_SECURITY_DECISION_TRACE_v1.1"
