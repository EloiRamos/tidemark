from dataclasses import replace
from html.parser import HTMLParser
from pathlib import Path

from tidemark.demo import DeterministicDemoHarness
from tidemark.runtime.identifiers import PreparedCallId
from tidemark.ui.prepared_call_lifecycle import (
    LIFECYCLE_SCRIPT,
    LIFECYCLE_STYLES,
    render_prepared_call_lifecycle,
)
from tidemark.ui.run_summary import ScenarioId


class _LifecycleAudit(HTMLParser):
    def __init__(self):
        super().__init__()
        self.start_tags = []
        self.buttons = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        self.start_tags.append((tag, attributes))
        if tag == "button":
            self.buttons.append(attributes)


def _run(seed="w1-c-d-lifecycle"):
    return DeterministicDemoHarness(run_seed=seed).run()


def _projection(scenario_id=ScenarioId.BENIGN_ALLOW):
    return next(
        item.mechanism_projection
        for item in _run().scenarios
        if item.scenario_id is scenario_id
    )


def test_renderer_emits_exact_ten_stage_lifecycle_in_order_with_all_facts_present():
    rendered = render_prepared_call_lifecycle(_projection(), instance_id=1)
    expected = (
        ("W1-L01", "UNTRUSTED PROPOSAL"),
        ("W1-L02", "PROTECTED-ROLE RECOGNITION"),
        ("W1-L03", "TRUSTED HANDLE SELECTION"),
        ("W1-L04", "RUNTIME RESOLUTION"),
        ("W1-L05", "TRUSTED VALUE BINDING"),
        ("W1-L06", "DETERMINISTIC POLICY EVALUATION"),
        ("W1-L07", "PREPARED-CALL SEALING"),
        ("W1-L08", "EXECUTION-TIME REVALIDATION"),
        ("W1-L09", "EVIDENCE BEFORE EFFECT"),
        ("W1-L10", "EFFECT / REFUSAL / REPLAY EVIDENCE"),
    )

    assert rendered.count('data-lifecycle-select="') == 10
    assert rendered.count('role="tabpanel"') == 10
    offsets = []
    for stage_id, title in expected:
        assert rendered.count(f'>{stage_id}<') >= 2
        assert rendered.count(f'>{title}<') >= 2
        offsets.append(rendered.index(f'data-lifecycle-select="{stage_id}"'))
    assert offsets == sorted(offsets)
    assert rendered.count("WHAT IS TRUSTED") == 10
    assert rendered.count("WHAT IS BOUND") == 10
    assert rendered.count("WHAT FAILS CLOSED") == 10


def test_renderer_makes_provenance_sealing_and_not_created_semantics_explicit():
    allowed = render_prepared_call_lifecycle(_projection(), instance_id=1)
    denied = render_prepared_call_lifecycle(
        _projection(ScenarioId.RAW_PROTECTED_VALUE_DENY), instance_id=2
    )

    for provenance in (
        "OBSERVED_MASKED_EVIDENCE",
        "DERIVED_FROM_OBSERVED_EVIDENCE",
        "DERIVED_IMPLEMENTED_CONTRACT",
        "APPROVED_STATIC_PRODUCT_COPY",
    ):
        assert provenance in allowed
    assert "REGISTERED_BEFORE_RETURN" in allowed
    assert "EXACT_PAYLOAD_HMAC_BOUND" in allowed
    assert "EXACT_CORRELATIONS_BOUND" in allowed
    assert "EXACT_ADAPTER_ID_VERSION_BOUND" in allowed
    assert "EXACT_PRIVATE_TARGET_SET_BOUND" in allowed
    assert "EXACT_PREPARED_OBJECT_BOUND" in allowed
    assert "private_material_projected=false" in allowed
    assert "Public prepared-call ID" in allowed
    assert "Public integrity digest" in allowed

    assert "Prepared capability</span><strong>NOT_CREATED (null)</strong>" in denied
    assert "Public prepared-call ID</span><strong>NOT_CREATED (null)</strong>" in denied
    assert "Public integrity digest</span><strong>NOT_CREATED (null)</strong>" in denied
    assert "private_material_projected=false" in denied


def test_allow_execution_and_single_transaction_semantics_are_visibly_separate():
    allowed = render_prepared_call_lifecycle(_projection(), instance_id=1)
    replay = render_prepared_call_lifecycle(
        _projection(ScenarioId.REPLAY_REJECTION), instance_id=2
    )

    assert "ALLOW IS NOT EXECUTED" in allowed
    assert '<span>DECISION</span><strong>ALLOW</strong>' in allowed
    assert '<span>EXECUTION</span><strong>COMPLETED</strong>' in allowed
    sequence = (
        "valid prepared capability"
        " → execution-time gate validation"
        " → durable pre-execution evidence"
        " → local atomic single-use consumption/commit"
        " → adapter entry"
        " → outcome evidence"
    )
    assert sequence in allowed
    assert "L08 is the only execution-time revalidation" in allowed
    assert "one execution transaction" in allowed
    assert "local at-most-once adapter entry" in allowed
    assert "No distributed transaction, global ordering, external exactly-once, or guaranteed external idempotency" in allowed
    assert "REPLAY_REJECTED" in replay
    assert '<span>EXECUTION STARTS</span><strong>1</strong>' in replay
    assert '<span>SYNTHETIC PAYMENTS</span><strong>1</strong>' in replay


def test_w2_references_are_exact_noninteractive_reference_only_metadata():
    rendered = render_prepared_call_lifecycle(_projection(), instance_id=1)
    titles = (
        "Selection Is Not Supply",
        "ALLOW Is Not Executed",
        "Evidence Before Effect",
        "Replay Is Not a Second Side Effect",
        "Concurrent Replay Is Locally At-Most-Once",
        "Prepared-Call Tampering Fails Closed",
        "Protected Reference Context Is Bound",
        "Incomplete or Conflicting Evidence Is Not PASS",
    )

    assert rendered.count("REFERENCE ONLY - NOT EXECUTED BY THIS UI") == 8
    for ordinal, title in enumerate(titles, 1):
        property_id = f"W2-P{ordinal:02d}"
        assert property_id in rendered
        assert title in rendered
        assert f"make prove PROPERTY={property_id}" in rendered
    assert "Proof PASS means uncertainty was preserved correctly." in rendered
    assert "It does NOT mean:" in rendered
    assert "evidence PASS" in rendered
    assert "execution success" in rendered
    assert "external effect absence" in rendered
    assert "proof-status" not in rendered.lower()
    assert "last-run" not in rendered.lower()
    assert "artifact digest" not in rendered.lower()


def test_renderer_is_read_only_aria_selectable_and_contains_no_execution_path():
    rendered = render_prepared_call_lifecycle(_projection(), instance_id=1)
    audit = _LifecycleAudit()
    audit.feed(rendered)

    assert len(audit.buttons) == 10
    assert all(button.get("type") == "button" for button in audit.buttons)
    assert all("data-lifecycle-select" in button for button in audit.buttons)
    assert sum(button.get("aria-selected") == "true" for button in audit.buttons) == 1
    assert sum(button.get("tabindex") == "0" for button in audit.buttons) == 1
    assert not any(
        tag in {"form", "input", "textarea", "select", "a"}
        for tag, _ in audit.start_tags
    )
    assert "ArrowLeft" in LIFECYCLE_SCRIPT
    assert "ArrowRight" in LIFECYCLE_SCRIPT
    assert "Home" in LIFECYCLE_SCRIPT
    assert "End" in LIFECYCLE_SCRIPT
    assert ".focus()" in LIFECYCLE_SCRIPT
    for forbidden in (
        "fetch(",
        "XMLHttpRequest",
        "WebSocket",
        "EventSource",
        "sendBeacon",
        "subprocess",
        "os.system",
        "shell",
    ):
        assert forbidden not in rendered + LIFECYCLE_SCRIPT


def test_renderer_escapes_contract_permitted_malicious_looking_public_identifier():
    projection = _projection()
    sentinel = 'pc_&quot; autofocus onfocus=&quot;alert(1)&amp;safe'
    malicious = 'pc_" autofocus onfocus="alert(1)&safe'
    seal = replace(
        projection.seal,
        public_prepared_call_id=PreparedCallId(malicious),
    )
    rendered = render_prepared_call_lifecycle(
        replace(projection, seal=seal), instance_id=1
    )
    audit = _LifecycleAudit()
    audit.feed(rendered)

    assert malicious not in rendered
    assert sentinel in rendered
    assert not any("onfocus" in attrs for _, attrs in audit.start_tags)
    assert not any(tag in {"img", "script"} for tag, _ in audit.start_tags)


def test_responsive_assets_wrap_without_hiding_security_facts():
    assert "grid-template-columns:repeat(auto-fit,minmax(min(100%," in LIFECYCLE_STYLES
    assert "overflow-wrap:anywhere" in LIFECYCLE_STYLES
    assert "overflow-x:auto" not in LIFECYCLE_STYLES
    for width in (1439, 1280):
        assert f"max-width:{width}px" in LIFECYCLE_STYLES
    assert "display:none" not in LIFECYCLE_STYLES


def test_renderer_source_has_no_runtime_authority_network_shell_or_raw_store_imports():
    source = Path("src/tidemark/ui/prepared_call_lifecycle.py").read_text()

    assert "from tidemark.evidence.mechanism_projection import" in source
    for forbidden in (
        "tidemark.runtime.",
        "reference_store",
        "reference_resolver",
        "execution_binding",
        "payment.fixtures",
        "evidence.local_store",
        "evidence.recorder",
        "requests",
        "urllib",
        "httpx",
        "subprocess",
        "socket",
        "os.system",
    ):
        assert forbidden not in source
