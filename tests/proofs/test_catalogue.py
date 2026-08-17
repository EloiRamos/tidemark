import ast
from pathlib import Path


from tidemark.proofs.catalogue import (
    CATALOGUE_VERSION,
    PROOF_CATALOGUE,
    PROOF_PROPERTY_COUNT,
    PROOF_FIXTURE_COUNT,
)


ROOT = Path(__file__).resolve().parents[2]


EXPECTED_PROPERTIES = (
    ("W2-P01", "Selection Is Not Supply", 2),
    ("W2-P02", "ALLOW Is Not Executed", 1),
    ("W2-P03", "Evidence Before Effect", 2),
    ("W2-P04", "Replay Is Not a Second Side Effect", 1),
    ("W2-P05", "Concurrent Replay Is Locally At-Most-Once", 1),
    ("W2-P06", "Prepared-Call Tampering Fails Closed", 7),
    ("W2-P07", "Protected Reference Context Is Bound", 6),
    ("W2-P08", "Incomplete or Conflicting Evidence Is Not PASS", 3),
)

EXPECTED_FIXTURE_IDS = (
    "W2-P01-C01-runtime-reference-selection",
    "W2-P01-C02-raw-protected-value-supply",
    "W2-P02-C01-post-allow-reference-deactivation",
    "W2-P03-C01-durable-evidence-before-effect",
    "W2-P03-C02-pre-execution-append-failure",
    "W2-P04-C01-sequential-replay",
    "W2-P05-C01-concurrent-replay",
    "W2-P06-C01-public-integrity",
    "W2-P06-C02-binding-missing",
    "W2-P06-C03-correlation",
    "W2-P06-C04-authenticator",
    "W2-P06-C05-payload",
    "W2-P06-C06-adapter-identity",
    "W2-P06-C07-adapter-version",
    "W2-P07-C01-reference-not-found",
    "W2-P07-C02-wrong-kind",
    "W2-P07-C03-wrong-invocation",
    "W2-P07-C04-wrong-parent",
    "W2-P07-C05-inactive-reference",
    "W2-P07-C06-consumed-reference",
    "W2-P08-C01-missing-terminal-evidence",
    "W2-P08-C02-conflicting-terminal-evidence",
    "W2-P08-C03-ambiguous-external-result",
)


ANCHOR_AUTHORITIES = {
    "matrix:A01_legitimate_allow": ("tests/security/test_core_security_matrix.py", "A01_legitimate_allow"),
    "matrix:B01_raw_protected_value": ("tests/security/test_core_security_matrix.py", "B01_raw_protected_value"),
    "matrix:C01_forged_reference": ("tests/security/test_core_security_matrix.py", "C01_forged_reference"),
    "matrix:C02_wrong_kind": ("tests/security/test_core_security_matrix.py", "C02_wrong_kind"),
    "matrix:C03_wrong_invocation": ("tests/security/test_core_security_matrix.py", "C03_wrong_invocation"),
    "matrix:C04_wrong_parent": ("tests/security/test_core_security_matrix.py", "C04_wrong_parent"),
    "matrix:C05_inactive_reference": ("tests/security/test_core_security_matrix.py", "C05_inactive_reference"),
    "matrix:C06_consumed_reference": ("tests/security/test_core_security_matrix.py", "C06_consumed_reference"),
    "matrix:G01_public_integrity_mismatch": ("tests/security/test_core_security_matrix.py", "G01_public_integrity_mismatch"),
    "matrix:G02_missing_private_binding": ("tests/security/test_core_security_matrix.py", "G02_missing_private_binding"),
    "matrix:G03_private_correlation_mismatch": ("tests/security/test_core_security_matrix.py", "G03_private_correlation_mismatch"),
    "matrix:G04_integrity_authenticator_mismatch": ("tests/security/test_core_security_matrix.py", "G04_private_authenticator_mismatch"),
    "matrix:G05_private_payload_substitution": ("tests/security/test_core_security_matrix.py", "G05_private_payload_substitution"),
    "matrix:G06_adapter_identity_mismatch": ("tests/security/test_core_security_matrix.py", "G06_adapter_identity_mismatch"),
    "matrix:G07_adapter_version_mismatch": ("tests/security/test_core_security_matrix.py", "G07_adapter_version_mismatch"),
    "matrix:H01_pre_execution_evidence_failure": ("tests/security/test_core_security_matrix.py", "H01_pre_execution_evidence_failure"),
    "matrix:I01_sequential_replay": ("tests/security/test_core_security_matrix.py", "I01_sequential_replay"),
    "matrix:J01_concurrent_replay": ("tests/security/test_core_security_matrix.py", "J01_concurrent_replay"),
    "test:policy_engine:raw_supply_denied": ("tests/runtime/test_policy_engine.py", "test_raw_or_missing_protected_representation_is_denied"),
    "test:policy_engine:legitimate_call_allowed": ("tests/runtime/test_policy_engine.py", "test_complete_legitimate_call_returns_allow_without_preparing_or_executing"),
    "test:execution_gate:invalid_target_preserves_authority": ("tests/runtime/test_execution_gate.py", "test_invalid_second_target_leaves_all_references_and_capability_unused"),
    "test:evidence_projection:allow_refusal_stays_allow": ("tests/evidence/test_evidence_projection.py", "test_valid_pre_start_execution_refusal_does_not_become_deny"),
    "test:execution_gate:append_failure_prevents_action": ("tests/runtime/test_execution_gate.py", "test_pre_execution_append_failure_causes_zero_mutation_and_zero_adapter_calls"),
    "test:execution_gate:durability_failure_prevents_action": ("tests/runtime/test_execution_gate.py", "test_pre_execution_durability_failure_causes_zero_state_or_adapter_action"),
    "test:execution_gate:durable_append_precedes_effect": ("tests/runtime/test_execution_gate.py", "test_durable_append_precedes_atomic_mutation_and_adapter_entry"),
    "test:execution_gate:sequential_replay_at_most_once": ("tests/runtime/test_execution_gate.py", "test_replay_is_rejected_and_adapter_count_remains_exactly_one"),
    "test:evidence_projection:replay_rejected": ("tests/evidence/test_evidence_projection.py", "test_valid_replay_is_rejected_without_second_start_or_payment"),
    "test:execution_gate:concurrent_replay_one_winner": ("tests/runtime/test_execution_gate.py", "test_concurrent_attempts_have_one_winner_and_all_losers_replay_rejected"),
    "test:reference_resolver:not_found": ("tests/runtime/test_reference_resolver.py", "test_unknown_reference_maps_to_exact_not_found_rule"),
    "test:reference_resolver:wrong_kind": ("tests/runtime/test_reference_resolver.py", "test_wrong_kind_maps_to_exact_kind_mismatch_rule"),
    "test:reference_resolver:wrong_invocation": ("tests/runtime/test_reference_resolver.py", "test_wrong_invocation_maps_to_exact_invocation_mismatch_rule"),
    "test:reference_resolver:wrong_parent": ("tests/runtime/test_reference_resolver.py", "test_wrong_parent_maps_to_exact_parent_mismatch_rule"),
    "test:reference_resolver:inactive": ("tests/runtime/test_reference_resolver.py", "test_inactive_reference_maps_to_exact_inactive_rule"),
    "test:reference_resolver:consumed": ("tests/runtime/test_reference_resolver.py", "test_active_consumed_reference_maps_to_exact_already_consumed_rule"),
    "test:evidence_reconciliation:missing_terminal": ("tests/evidence/test_evidence_reconciliation.py", "test_started_execution_missing_terminal_is_incomplete"),
    "test:evidence_reconciliation:conflicting_terminal": ("tests/evidence/test_evidence_reconciliation.py", "test_completed_and_failed_for_one_execution_conflict"),
    "test:evidence_projection:ambiguous_result": ("tests/evidence/test_evidence_projection.py", "test_ambiguous_external_failure_is_visible_without_absence_claim"),
}


def _defined_test_names(path):
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def test_catalogue_has_the_exact_final_order_and_fixture_count():
    assert CATALOGUE_VERSION == "tidemark.security-proof-catalogue.v1"
    assert PROOF_PROPERTY_COUNT == 8
    assert PROOF_FIXTURE_COUNT == 23
    assert tuple(
        (item.property_id, item.property_title, len(item.fixtures))
        for item in PROOF_CATALOGUE
    ) == EXPECTED_PROPERTIES

    fixture_ids = tuple(
        fixture.fixture_id
        for item in PROOF_CATALOGUE
        for fixture in item.fixtures
    )
    assert fixture_ids == EXPECTED_FIXTURE_IDS
    assert len(fixture_ids) == len(set(fixture_ids)) == 23
    assert all(fixture_id.startswith(f"{item.property_id}-C") for item in PROOF_CATALOGUE for fixture_id in (fixture.fixture_id for fixture in item.fixtures))


def test_catalogue_is_closed_inert_and_has_no_overlapping_fixture_authority():
    assert type(PROOF_CATALOGUE) is tuple
    assert all(type(item.fixtures) is tuple for item in PROOF_CATALOGUE)
    assert all(item.claim and item.invariant and item.non_claims for item in PROOF_CATALOGUE)
    assert all(item.evidence_anchor_ids for item in PROOF_CATALOGUE)

    source = (ROOT / "src/tidemark/proofs/catalogue.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_modules = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert "pytest" not in imported_modules
    assert not any(name == "tests" or name.startswith("tests.") for name in imported_modules)


def test_every_logical_anchor_resolves_to_existing_test_authority_without_importing_tests():
    catalogue_anchors = {
        anchor
        for item in PROOF_CATALOGUE
        for anchor in item.evidence_anchor_ids
    }
    assert catalogue_anchors == set(ANCHOR_AUTHORITIES)

    names_by_path = {}
    for anchor, (path, authority) in ANCHOR_AUTHORITIES.items():
        source = (ROOT / path).read_text(encoding="utf-8")
        if anchor.startswith("matrix:"):
            assert f'"{authority}"' in source
        else:
            names_by_path.setdefault(path, _defined_test_names(path))
            assert authority in names_by_path[path]


def test_threat_model_states_executable_j01_attempt_and_worker_truth():
    source = (
        ROOT
        / "docs/security/TIDEMARK_SECURITY_INVARIANT_TRACEABILITY_AND_THREAT_MODEL_v1.0.md"
    ).read_text(encoding="utf-8")
    assert "12 attempts through a six-worker pool" in source
    assert "twelve-thread concurrent replay" not in source.lower()
