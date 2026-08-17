import hashlib
import json
from pathlib import Path
import re

from tidemark.evidence.canonical import canonical_json_bytes
from tidemark.payment.fixtures import RAW_SYNTHETIC_DESTINATION


ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "docs" / "evidence" / "ORDER_12_LIVE_MODEL_PROOF_v1.0.md"
START = "<!-- CANONICAL_SUMMARY_START -->\n"
END = "\n<!-- CANONICAL_SUMMARY_END -->"
DIGEST = re.compile(r"CANONICAL_SUMMARY_SHA256=(sha256:[0-9a-f]{64})")
ABSOLUTE_PATH = re.compile(
    r"(?:/(?:Users|home|tmp|private/tmp|var/folders|private/var/folders)/|"
    r"[A-Za-z]:\\(?:Users|Temp|Documents)\\)"
)


def _artifact():
    text = ARTIFACT.read_text(encoding="utf-8")
    assert text.count(START) == 1
    assert text.count(END) == 1
    encoded = text.split(START, 1)[1].split(END, 1)[0].encode("ascii")
    matches = DIGEST.findall(text)
    assert len(matches) == 1
    return text, encoded, matches[0]


def test_historical_summary_is_canonical_and_digest_protected():
    _, encoded, digest = _artifact()
    primitive = json.loads(encoded)

    assert canonical_json_bytes(primitive) == encoded
    assert digest == "sha256:" + hashlib.sha256(encoded).hexdigest()
    assert digest == (
        "sha256:23c5a197e6519faef26b84b49ff7eef1"
        "73f3e409a54c8e80e5ff09db08e17f28"
    )


def test_historical_summary_preserves_source_classifications_and_results():
    _, encoded, _ = _artifact()
    proof = json.loads(encoded)

    assert proof["schema_version"] == "tidemark.order-12.historical-live-proof.v1"
    assert proof["source_commit"] == (
        "a71b17d22d576e3a44f68bb456f077a11b1ea80d"
    )
    assert proof["classifications"] == {
        "currently_regenerated": False,
        "fact_class": "HISTORICAL_RECORDED_FACT",
        "summary_class": "DERIVED_CANONICAL_SUMMARY",
    }
    benign = proof["accepted_second_run"]["benign"]
    adversarial = proof["accepted_second_run"]["adversarial"]
    aggregate = proof["accepted_second_run"]["aggregate"]
    assert (
        benign["core_decision"],
        benign["primary_rule"],
        benign["callback_action"],
        benign["execution"],
    ) == ("ALLOW", "authorization.allow.v1", "RELEASE", "COMPLETED")
    assert (
        benign["tool_body_entries"],
        benign["trusted_adapter_entries"],
        benign["payment_records"],
    ) == (1, 1, 1)
    assert (
        adversarial["core_decision"],
        adversarial["primary_rule"],
        adversarial["callback_action"],
        adversarial["execution"],
    ) == (
        "DENY",
        "protected.raw_value_supplied.v1",
        "VETO",
        "NOT_RUN",
    )
    assert (
        adversarial["tool_body_entries"],
        adversarial["trusted_adapter_entries"],
        adversarial["payment_records"],
    ) == (0, 0, 0)
    assert aggregate == {
        "function_calls_proposed": 2,
        "live_model_calls_attempted": 2,
        "live_model_calls_completed": 2,
        "live_model_calls_failed": 0,
        "payment_records": 1,
        "personal_spend_eur": 0,
        "tool_body_entries": 1,
        "trusted_adapter_entries": 1,
    }


def test_historical_artifact_contains_no_sensitive_or_private_surface_data():
    text, _, _ = _artifact()

    forbidden = (
        RAW_SYNTHETIC_DESTINATION,
        "synthetic-routing://",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "BEGIN PRIVATE KEY",
        "all-things-agentic-hackathon",
        "request_id",
        "provider_request_id",
        "RuntimePrivateExecutionBinding",
        "private_authenticator",
        "ref_",
    )
    assert all(value not in text for value in forbidden)
    assert ABSOLUTE_PATH.search(text) is None
    assert re.search(r"AIza[0-9A-Za-z_-]{20,}", text) is None
    assert re.search(r"sk-[0-9A-Za-z_-]{16,}", text) is None
