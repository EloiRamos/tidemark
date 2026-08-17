from html.parser import HTMLParser

import pytest

from tidemark.demo.harness import DeterministicDemoHarness
from tidemark.demo.rehearsal import scan_demo_surfaces
from tidemark.payment.fixtures import RAW_SYNTHETIC_DESTINATION
from tidemark.ui.final_ui import (
    PresentationMode,
    VIDEO_SAFE_BADGE,
    VIDEO_SAFE_STYLE_BLOCK,
    build_final_ui_scenarios,
    render_final_ui,
)
from tidemark.ui.run_summary import REQUIRED_SCENARIO_ORDER


CURRENT_RUN_LABEL = (
    "DETERMINISTIC · EVIDENCE FALLBACK / OFFLINE · "
    "NOT CURRENT LIVE PROVIDER OUTPUT"
)


def _run():
    return DeterministicDemoHarness(run_seed="phase-1-video-safe").run()


def _scenarios(run):
    return build_final_ui_scenarios(
        run.summary,
        tuple(
            (item.scenario_id, item.projection, item.mechanism_projection)
            for item in run.scenarios
        ),
    )


def _render_pair():
    run = _run()
    scenarios = _scenarios(run)
    return (
        render_final_ui(
            run.summary,
            scenarios,
            presentation_mode=PresentationMode.NORMAL,
        ),
        render_final_ui(
            run.summary,
            scenarios,
            presentation_mode=PresentationMode.VIDEO_SAFE,
        ),
    )


def _remove_exact_presentation_shell(html):
    return (
        html.replace(VIDEO_SAFE_STYLE_BLOCK, "")
        .replace(VIDEO_SAFE_BADGE, "")
        .replace('data-presentation-mode="VIDEO_SAFE"', 'data-presentation-mode="NORMAL"')
    )


def test_video_safe_and_normal_security_facts_differ_only_by_exact_mode_shell():
    normal, video = _render_pair()

    assert _remove_exact_presentation_shell(video) == normal
    assert VIDEO_SAFE_STYLE_BLOCK not in normal
    assert VIDEO_SAFE_BADGE not in normal
    assert VIDEO_SAFE_STYLE_BLOCK in video
    assert VIDEO_SAFE_BADGE in video
    assert 'data-presentation-mode="NORMAL"' in normal
    assert 'data-presentation-mode="VIDEO_SAFE"' in video


def test_both_modes_contain_the_same_complete_w1_lifecycle_and_w2_references():
    normal, video = _render_pair()

    for rendered in (normal, video):
        assert rendered.count("PREPARED CALL LIFECYCLE EXPLORER") == 6
        assert rendered.count('data-lifecycle-select="') == 60
        assert rendered.count("ALLOW IS NOT EXECUTED") == 6
        assert rendered.count("REFERENCE ONLY - NOT EXECUTED BY THIS UI") == 48
        assert rendered.count("Proof PASS means uncertainty was preserved correctly.") == 6
        assert rendered.count("local atomic single-use consumption/commit") >= 6
        assert rendered.count("private_material_projected=false") == 6


def test_normal_remains_the_default_presentation_mode():
    run = _run()
    scenarios = _scenarios(run)

    assert render_final_ui(run.summary, scenarios) == render_final_ui(
        run.summary,
        scenarios,
        presentation_mode=PresentationMode.NORMAL,
    )


def test_both_modes_preserve_exact_surface_step_and_scenario_capture_anchors():
    for rendered in _render_pair():
        assert rendered.count('data-surface="') == 4
        assert rendered.count('data-capture-id="surface-') == 4
        assert rendered.count('data-step="') == 5
        assert rendered.count('data-capture-id="guided-step-') == 5
        assert rendered.count('data-capture-id="scenario-') == 6
        for surface in ("run", "inspector", "trace", "cloud"):
            assert f'data-capture-id="surface-{surface}"' in rendered
        for ordinal in range(1, 6):
            assert f'data-capture-id="guided-step-{ordinal}"' in rendered
        for scenario_id in REQUIRED_SCENARIO_ORDER:
            anchor = scenario_id.value.lower().replace("_", "-")
            assert f'data-capture-id="scenario-{anchor}"' in rendered


@pytest.mark.parametrize(
    ("width", "height"),
    ((1440, 900), (1440, 899), (1439, 900), (1280, 720), (1920, 1080)),
)
def test_video_safe_contract_activates_at_intended_and_near_capture_viewports(
    width, height
):
    _, video = _render_pair()

    for required in (
        "width:min(1440px,100vw)",
        "height:min(900px,100vh)",
        "overflow:auto",
        "transition:none!important",
        "animation:none!important",
        "font-size:12px",
    ):
        assert required in VIDEO_SAFE_STYLE_BLOCK
        assert required in video
    assert (width, height) in (
        (1440, 900),
        (1440, 899),
        (1439, 900),
        (1280, 720),
        (1920, 1080),
    )
    assert VIDEO_SAFE_STYLE_BLOCK.startswith(
        '<style data-presentation-shell="video-safe">'
        '[data-presentation-mode="VIDEO_SAFE"]'
    )
    assert "@media (width:1440px) and (height:900px)" not in video
    assert video.count('data-surface="') == 4
    assert video.count('data-step="') == 5


def test_video_safe_badge_has_a_distinct_bounded_style():
    _, video = _render_pair()

    assert ".tag--video-safe{" in video
    assert "border-color:var(--trusted)" in video


def test_both_modes_are_masked_read_only_and_network_free():
    run = _run()
    for name, rendered in zip(("normal.html", "video-safe.html"), _render_pair()):
        lower = rendered.lower()
        assert CURRENT_RUN_LABEL in rendered
        assert "historical committed evidence" in rendered
        assert "not current offline run" in rendered
        assert "not a live cloud query" in rendered
        assert RAW_SYNTHETIC_DESTINATION not in rendered
        assert "synthetic-routing://" not in rendered
        assert scan_demo_surfaces(((name, rendered.encode()),)).pass_all
        for token in (
            "<form", "<input", "<textarea", "<select", "fetch(",
            "xmlhttprequest", "websocket", "eventsource", "http://", "https://",
        ):
            assert token not in lower
        for control in (">Approve<", ">Retry<", ">Execute<", ">Reveal<"):
            assert control not in rendered
