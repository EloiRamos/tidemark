import inspect
import re
from dataclasses import FrozenInstanceError, replace
from html.parser import HTMLParser

from tidemark.evidence.projection import (
    CallbackReviewAction,
    EvidenceProjector,
    ExecutionReviewStatus,
    ReviewRuleFact,
)
from tidemark.evidence.model import EvidenceEventType
from tidemark.payment.fixtures import (
    RAW_SYNTHETIC_DESTINATION,
    build_synthetic_payment_fixture,
)
from tidemark.runtime.execution_gate import (
    AdapterInvocationResult,
    ExecutionGate,
    TrustedAdapterRegistry,
)
from tidemark.runtime.identifiers import ToolContractVersion, ToolId
from tidemark.runtime.policy_engine import CanonicalCall
from tidemark.runtime.vocabulary import (
    EvaluationStage,
    RuleEvaluationOutcome,
    RuleId,
)
from tidemark.ui import decision_review
from tidemark.ui.decision_review import render_decision_review_workspace


class _DocumentAudit(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.attributes = []
        self.ids = []
        self._depth = 0
        self._active_ids = []
        self.text_by_id = {}

    def handle_starttag(self, tag, attrs):
        self._depth += 1
        normalized = dict(attrs)
        self.tags.append(tag)
        self.attributes.extend(attrs)
        if "id" in normalized:
            element_id = normalized["id"]
            self.ids.append(element_id)
            self.text_by_id[element_id] = []
            self._active_ids.append((element_id, self._depth))

    def handle_startendtag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend(attrs)

    def handle_data(self, data):
        for element_id, _ in self._active_ids:
            self.text_by_id[element_id].append(data)

    def handle_endtag(self, tag):
        self._active_ids = [
            active for active in self._active_ids if active[1] != self._depth
        ]
        self._depth -= 1

    def text(self, element_id):
        return " ".join("".join(self.text_by_id[element_id]).split())


def _project(fixture):
    return EvidenceProjector().project(fixture.evidence_store.ordered_events())


def _allow_projection(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    prepared = fixture.prepare(fixture.canonical_call())
    fixture.execution_gate.execute(prepared)
    return fixture, _project(fixture)


def _deny_projection(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    fixture.prepare(
        fixture.canonical_call(destination_reference=RAW_SYNTHETIC_DESTINATION)
    )
    return fixture, _project(fixture)


def test_review_projection_exposes_the_safe_ui_demo_facts(tmp_path):
    fixture, projection = _allow_projection(tmp_path)

    assert projection.recorded_at.endswith("Z")
    assert projection.tool_ids == (ToolId("schedule_payment"),)
    assert projection.tool_contract_versions == (
        ToolContractVersion("schedule_payment.contract.v1"),
    )
    assert projection.decision_stage is EvaluationStage.AUTHORIZATION
    assert projection.rule_facts
    assert all(type(item) is ReviewRuleFact for item in projection.rule_facts)
    assert projection.rule_facts[-1].rule_id is RuleId.AUTHORIZATION_ALLOW
    assert projection.rule_facts[-1].outcome is RuleEvaluationOutcome.PASS
    assert projection.evidence_schema_versions == ("tidemark.evidence.v1",)
    assert projection.export_digests == ()
    assert fixture.evidence_store.ordered_events()


def test_workspace_renders_every_order_16_component_from_one_projection(tmp_path):
    _, projection = _allow_projection(tmp_path)

    rendered = render_decision_review_workspace(projection)
    audit = _DocumentAudit()
    audit.feed(rendered)
    visible_text = " ".join(rendered.split())

    assert "TIDEMARK Decision Review" in visible_text
    assert "Read-only runtime evidence" in visible_text
    assert "EVIDENCE FALLBACK" in visible_text
    assert "Gemini 3.6 Flash" in visible_text
    assert "not production-ready" in visible_text
    assert audit.text("decision-list")
    assert "Selected decision" in audit.text("decision-list")
    assert "schedule_payment" in audit.text("decision-list")
    assert "NOT PRESENT IN PROJECTION" in audit.text("decision-list")
    assert "ALLOW" in audit.text("decision-summary")
    assert "authorization.allow.v1" in audit.text("decision-summary")
    assert "AUTHORIZATION" in audit.text("decision-summary")
    assert "schedule_payment" in audit.text("decision-summary")
    assert "RUNTIME_TRUSTED" in audit.text("argument-review")
    assert "opaque-reference-selected" in audit.text("argument-review")
    assert "authorization.allow.v1" in audit.text("rule-trace")
    assert "PASS" in audit.text("rule-trace")
    assert "NOT APPLICABLE" in audit.text("callback-timeline")
    assert "COMPLETED" in audit.text("execution-proof")
    assert "RECORDED" in audit.text("execution-proof")
    assert "trace" in audit.text("correlation-panel").lower()
    assert "tidemark.evidence.v1" in audit.text("evidence-integrity")
    assert "COMPLETE" in audit.text("evidence-integrity")
    assert "PASS" in audit.text("evidence-integrity")
    assert "MODEL NON-ATTEMPT" in audit.text("state-legend")
    assert "Observed evidence" in visible_text
    assert "Derived review state" in visible_text
    assert len(audit.ids) == len(set(audit.ids))


def test_workspace_is_semantic_keyboard_visible_and_has_no_write_controls(tmp_path):
    _, projection = _allow_projection(tmp_path)

    rendered = render_decision_review_workspace(projection)
    audit = _DocumentAudit()
    audit.feed(rendered)

    assert "main" in audit.tags
    assert "header" in audit.tags
    assert "nav" in audit.tags
    assert "section" in audit.tags
    assert "table" in audit.tags
    assert "caption" in audit.tags
    assert "ol" in audit.tags
    assert "dl" in audit.tags
    assert "a" in audit.tags
    assert not ({"button", "form", "input", "select", "textarea"} & set(audit.tags))
    assert "script" not in audit.tags
    assert ("href", "#decision-detail") in audit.attributes
    assert ("tabindex", "-1") in audit.attributes
    assert all(not name.startswith("data-") for name, _ in audit.attributes)
    assert all(name != "title" for name, _ in audit.attributes)
    assert ":focus-visible" in rendered
    assert "outline:" in rendered
    assert "@media (prefers-reduced-motion: reduce)" in rendered


def test_workspace_never_renders_raw_protected_or_runtime_private_values(tmp_path):
    fixture, projection = _deny_projection(tmp_path)
    reference_id = fixture.destination_reference.value

    rendered = render_decision_review_workspace(projection)

    assert RAW_SYNTHETIC_DESTINATION not in rendered
    assert reference_id not in rendered
    assert "/Users/" not in rendered
    assert "GEMINI_API_KEY" not in rendered
    assert "BEGIN PRIVATE KEY" not in rendered
    assert "protected-value-omitted" in rendered
    assert "protected.raw_value_supplied.v1" in rendered
    assert "NOT RECORDED" in rendered


def test_allow_and_ambiguous_execution_failure_remain_separate(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    prepared = fixture.prepare(fixture.canonical_call())
    gate = ExecutionGate(
        adapter_registry=TrustedAdapterRegistry(
            tool_id=prepared.tool_id,
            adapter_id=prepared.adapter_id,
            adapter_version=prepared.adapter_version,
            adapter=lambda invocation: AdapterInvocationResult.unconfirmed_failure(),
        ),
        evidence_sink=fixture.evidence_recorder,
    )
    gate.execute(prepared)
    projection = _project(fixture)

    rendered = render_decision_review_workspace(projection)
    audit = _DocumentAudit()
    audit.feed(rendered)

    assert projection.execution_status is ExecutionReviewStatus.FAILED_AMBIGUOUS
    assert "ALLOW" in audit.text("decision-summary")
    assert "FAILED" in audit.text("execution-proof")
    assert "EXTERNAL RESULT UNCONFIRMED" in audit.text("execution-proof")
    assert "UNKNOWN" in audit.text("execution-proof")
    assert "NO SIDE EFFECT" not in rendered.upper()


def test_incomplete_evidence_renders_warning_and_unknown_payment_state(tmp_path):
    fixture, _ = _allow_projection(tmp_path)
    incomplete = EvidenceProjector().project(
        fixture.evidence_store.ordered_events()[:3]
    )

    rendered = render_decision_review_workspace(incomplete)
    audit = _DocumentAudit()
    audit.feed(rendered)

    assert "INCOMPLETE" in audit.text("evidence-integrity")
    assert "WARNING" in audit.text("evidence-integrity")
    assert "UNKNOWN" in audit.text("execution-proof")
    assert "RECORDED" not in audit.text("execution-proof")


def test_pre_start_execution_refusal_does_not_imply_an_external_result(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    prepared = fixture.prepare(fixture.canonical_call())
    object.__setattr__(prepared, "integrity_id", "sha256:" + "0" * 64)
    fixture.execution_gate.execute(prepared)

    rendered = render_decision_review_workspace(_project(fixture))
    audit = _DocumentAudit()
    audit.feed(rendered)

    assert "ALLOW" in audit.text("decision-summary")
    assert "EXECUTION REFUSED" in audit.text("execution-proof")
    assert "NOT STARTED" in audit.text("execution-proof")
    assert "NOT APPLICABLE — EXECUTION DID NOT START" in audit.text(
        "execution-proof"
    )


def test_replay_rejection_preserves_original_completion_and_exact_counts(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    prepared = fixture.prepare(fixture.canonical_call())
    fixture.execution_gate.execute(prepared)
    fixture.execution_gate.execute(prepared)

    rendered = render_decision_review_workspace(_project(fixture))
    audit = _DocumentAudit()
    audit.feed(rendered)

    assert "ALLOW" in audit.text("decision-summary")
    assert "COMPLETED" in audit.text("execution-proof")
    assert "REJECTED" in audit.text("execution-proof")
    assert "<dt>Start marker count</dt><dd>1</dd>" in rendered
    assert "<dt>Payment record count</dt><dd>1</dd>" in rendered
    assert "REPLAY REJECTED" in rendered


def test_model_non_attempt_is_not_presented_as_enforcement_success(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    fixture.evidence_recorder.record_model_non_attempt(
        invocation_id=fixture.invocation_id,
        reason_code="no-candidate-tool-call",
    )

    rendered = render_decision_review_workspace(_project(fixture))
    audit = _DocumentAudit()
    audit.feed(rendered)

    assert "MODEL NON-ATTEMPT" in audit.text("decision-summary")
    assert "NOT APPLICABLE" in audit.text("callback-timeline")
    assert "NOT STARTED" in audit.text("execution-proof")
    assert "not an authorization decision" in audit.text("decision-summary")


def test_refusal_remains_distinct_and_does_not_fabricate_execution(tmp_path):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    valid = fixture.canonical_call()
    fixture.prepare(
        CanonicalCall(
            tool_id=ToolId("unknown_tool"),
            contract_version=valid.contract_version,
            signature=valid.signature,
            arguments=valid.arguments,
        )
    )

    rendered = render_decision_review_workspace(_project(fixture))
    audit = _DocumentAudit()
    audit.feed(rendered)

    assert "REFUSAL" in audit.text("decision-summary")
    assert "NOT STARTED" in audit.text("execution-proof")
    assert "NOT RECORDED" in audit.text("execution-proof")
    assert "DENY" not in audit.text("decision-summary")


def test_core_deny_and_callback_veto_are_rendered_as_separate_facts(tmp_path):
    _, projection = _deny_projection(tmp_path)
    projection = replace(
        projection,
        callback_action=CallbackReviewAction.VETOED,
        callback_trail=(
            EvidenceEventType.CALLBACK_RECEIVED,
            EvidenceEventType.CALLBACK_VETOED,
        ),
    )

    rendered = render_decision_review_workspace(projection)
    audit = _DocumentAudit()
    audit.feed(rendered)

    assert "DENY" in audit.text("decision-summary")
    assert "VETOED" in audit.text("callback-timeline")
    assert "callback.received" in audit.text("callback-timeline")
    assert "callback.vetoed" in audit.text("callback-timeline")
    assert "NOT STARTED" in audit.text("execution-proof")


def test_renderer_is_deterministic_exact_type_only_and_immutable(tmp_path):
    _, projection = _allow_projection(tmp_path)

    first = render_decision_review_workspace(projection)
    second = render_decision_review_workspace(projection)

    assert first == second
    try:
        projection.payment_count = 99
    except FrozenInstanceError:
        pass
    else:
        raise AssertionError("ReviewProjection must remain immutable")

    try:
        render_decision_review_workspace(object())
    except TypeError as error:
        assert "ReviewProjection" in str(error)
    else:
        raise AssertionError("renderer must reject non-projection input")


def test_ui_module_imports_no_runtime_authority_or_evidence_source_objects():
    source = inspect.getsource(decision_review)
    import_lines = "\n".join(
        line for line in source.splitlines() if line.startswith(("from ", "import "))
    )

    for forbidden in (
        "AuditEvent",
        "LocalAuditStore",
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
    assert re.search(r"\bReviewProjection\b", source)
