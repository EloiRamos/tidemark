"""Fixed W2 security-property catalogue and exact safe expectations."""

from tidemark.evidence.projection import EvidenceCompleteness, ExecutionReviewStatus
from tidemark.proofs.model import (
    ExpectedSecurityOutcome,
    ProofCaseDefinition,
    ProofEvidenceStatus,
    ProofExecutionOutcomeCounts,
    ProofExternalResultStatus,
    ProofFindingCode,
    ProofObservation,
    ProofPropertyDefinition,
    ProofReferenceState,
)
from tidemark.runtime.vocabulary import DecisionOutcome, PreparedCallState, RuleId


CATALOGUE_VERSION = "tidemark.security-proof-catalogue.v1"
PROOF_PROPERTY_COUNT = 8
PROOF_FIXTURE_COUNT = 23


def _observation(
    *,
    decision_outcome=None,
    decision_rule_id=None,
    prepared_call_count=None,
    execution_attempt_count=None,
    execution_outcomes=None,
    adapter_entry_count=None,
    authoritative_side_effect_count=None,
    capability_state=None,
    reference_states=(),
    pre_execution_record_count=None,
    external_result_status=None,
    evidence_integrity_status=None,
    evidence_reconciliation_status=None,
    evidence_completeness=None,
    evidence_execution_status=None,
    evidence_success_claimed=None,
    external_effect_absence_claimed=None,
    finding_codes=(),
):
    return ProofObservation(
        decision_outcome=decision_outcome,
        decision_rule_id=decision_rule_id,
        prepared_call_count=prepared_call_count,
        execution_attempt_count=execution_attempt_count,
        execution_outcomes=execution_outcomes,
        adapter_entry_count=adapter_entry_count,
        authoritative_side_effect_count=authoritative_side_effect_count,
        capability_state=capability_state,
        reference_states=reference_states,
        pre_execution_record_count=pre_execution_record_count,
        external_result_status=external_result_status,
        evidence_integrity_status=evidence_integrity_status,
        evidence_reconciliation_status=evidence_reconciliation_status,
        evidence_completeness=evidence_completeness,
        evidence_execution_status=evidence_execution_status,
        evidence_success_claimed=evidence_success_claimed,
        external_effect_absence_claimed=external_effect_absence_claimed,
        finding_codes=finding_codes,
    )


def _case(fixture_id, outcome, observation):
    return ProofCaseDefinition(
        fixture_id=fixture_id,
        expected_security_outcome=outcome,
        expected_observation=observation,
    )


_ZERO_EXECUTION = ProofExecutionOutcomeCounts(0, 0, 0, 0)
_ONE_COMPLETED = ProofExecutionOutcomeCounts(0, 1, 0, 0)
_ONE_REFUSED = ProofExecutionOutcomeCounts(1, 0, 0, 0)

_P01 = ExpectedSecurityOutcome.SELECTION_IS_NOT_SUPPLY
_P02 = ExpectedSecurityOutcome.ALLOW_IS_NOT_EXECUTED
_P03 = ExpectedSecurityOutcome.EVIDENCE_BEFORE_EFFECT
_P04 = ExpectedSecurityOutcome.REPLAY_IS_NOT_A_SECOND_SIDE_EFFECT
_P05 = ExpectedSecurityOutcome.CONCURRENT_REPLAY_IS_LOCALLY_AT_MOST_ONCE
_P06 = ExpectedSecurityOutcome.PREPARED_CALL_TAMPERING_FAILS_CLOSED
_P07 = ExpectedSecurityOutcome.PROTECTED_REFERENCE_CONTEXT_IS_BOUND
_P08 = ExpectedSecurityOutcome.INCOMPLETE_OR_CONFLICTING_EVIDENCE_IS_NOT_PASS


PROOF_CATALOGUE = (
    ProofPropertyDefinition(
        property_id="W2-P01",
        property_title="Selection Is Not Supply",
        claim="A valid runtime-issued protected reference may reach one authorized effect while raw protected-value supply is denied before preparation.",
        invariant="A protected role requires an exact ReferenceId resolved from trusted runtime state; textual equality or schema validity does not create trusted supply.",
        evidence_anchor_ids=(
            "matrix:A01_legitimate_allow",
            "matrix:B01_raw_protected_value",
            "test:policy_engine:raw_supply_denied",
            "test:policy_engine:legitimate_call_allowed",
        ),
        expected_security_outcome=_P01,
        fixtures=(
            _case(
                "W2-P01-C01-runtime-reference-selection",
                _P01,
                _observation(
                    decision_outcome=DecisionOutcome.ALLOW,
                    decision_rule_id=RuleId.AUTHORIZATION_ALLOW,
                    prepared_call_count=1,
                    execution_attempt_count=1,
                    execution_outcomes=_ONE_COMPLETED,
                    adapter_entry_count=1,
                    authoritative_side_effect_count=1,
                    capability_state=PreparedCallState.CONSUMED,
                    reference_states=(ProofReferenceState.ACTIVE_CONSUMED,),
                ),
            ),
            _case(
                "W2-P01-C02-raw-protected-value-supply",
                _P01,
                _observation(
                    decision_outcome=DecisionOutcome.DENY,
                    decision_rule_id=RuleId.PROTECTED_RAW_VALUE_SUPPLIED,
                    prepared_call_count=0,
                    execution_attempt_count=0,
                    execution_outcomes=_ZERO_EXECUTION,
                    adapter_entry_count=0,
                    authoritative_side_effect_count=0,
                    reference_states=(ProofReferenceState.ACTIVE_UNCONSUMED,),
                ),
            ),
        ),
        non_claims=(
            "general prompt-injection prevention",
            "cryptographic reference authenticity",
            "identity or host-compromise resistance",
        ),
    ),
    ProofPropertyDefinition(
        property_id="W2-P02",
        property_title="ALLOW Is Not Executed",
        claim="An ALLOW decision does not enter the adapter when current single-use reference state fails the execution transaction.",
        invariant="Decision and execution remain separate; the execution gate independently validates and atomically consumes current runtime authority.",
        evidence_anchor_ids=(
            "test:execution_gate:invalid_target_preserves_authority",
            "test:evidence_projection:allow_refusal_stays_allow",
        ),
        expected_security_outcome=_P02,
        fixtures=(
            _case(
                "W2-P02-C01-post-allow-reference-deactivation",
                _P02,
                _observation(
                    decision_outcome=DecisionOutcome.ALLOW,
                    decision_rule_id=RuleId.AUTHORIZATION_ALLOW,
                    prepared_call_count=1,
                    execution_attempt_count=1,
                    execution_outcomes=_ONE_REFUSED,
                    adapter_entry_count=0,
                    authoritative_side_effect_count=0,
                    capability_state=PreparedCallState.UNUSED,
                    reference_states=(ProofReferenceState.INACTIVE_UNCONSUMED,),
                    pre_execution_record_count=1,
                ),
            ),
        ),
        non_claims=(
            "ALLOW always executes",
            "authorization is reusable",
            "external systems share TIDEMARK runtime state",
        ),
    ),
    ProofPropertyDefinition(
        property_id="W2-P03",
        property_title="Evidence Before Effect",
        claim="Durable pre-execution evidence exists before adapter entry, and append failure prevents consumption, entry, and payment.",
        invariant="No bounded local effect may occur without the required durable pre-execution correlation record.",
        evidence_anchor_ids=(
            "matrix:H01_pre_execution_evidence_failure",
            "test:execution_gate:append_failure_prevents_action",
            "test:execution_gate:durability_failure_prevents_action",
            "test:execution_gate:durable_append_precedes_effect",
        ),
        expected_security_outcome=_P03,
        fixtures=(
            _case(
                "W2-P03-C01-durable-evidence-before-effect",
                _P03,
                _observation(
                    decision_outcome=DecisionOutcome.ALLOW,
                    decision_rule_id=RuleId.AUTHORIZATION_ALLOW,
                    prepared_call_count=1,
                    execution_attempt_count=1,
                    execution_outcomes=_ONE_COMPLETED,
                    adapter_entry_count=1,
                    authoritative_side_effect_count=1,
                    capability_state=PreparedCallState.CONSUMED,
                    reference_states=(ProofReferenceState.ACTIVE_CONSUMED,),
                    pre_execution_record_count=1,
                ),
            ),
            _case(
                "W2-P03-C02-pre-execution-append-failure",
                _P03,
                _observation(
                    decision_outcome=DecisionOutcome.ALLOW,
                    decision_rule_id=RuleId.AUTHORIZATION_ALLOW,
                    prepared_call_count=1,
                    execution_attempt_count=1,
                    execution_outcomes=_ONE_REFUSED,
                    adapter_entry_count=0,
                    authoritative_side_effect_count=0,
                    capability_state=PreparedCallState.UNUSED,
                    reference_states=(ProofReferenceState.ACTIVE_UNCONSUMED,),
                    pre_execution_record_count=0,
                ),
            ),
        ),
        non_claims=(
            "global or distributed event ordering",
            "external transaction atomicity",
            "post-effect evidence can veto an effect already performed",
        ),
    ),
    ProofPropertyDefinition(
        property_id="W2-P04",
        property_title="Replay Is Not a Second Side Effect",
        claim="Sequential reuse of one prepared capability yields one completion and one replay rejection without a second payment.",
        invariant="A prepared capability and its reference are single-use in the local runtime.",
        evidence_anchor_ids=(
            "matrix:I01_sequential_replay",
            "test:execution_gate:sequential_replay_at_most_once",
            "test:evidence_projection:replay_rejected",
        ),
        expected_security_outcome=_P04,
        fixtures=(
            _case(
                "W2-P04-C01-sequential-replay",
                _P04,
                _observation(
                    decision_outcome=DecisionOutcome.ALLOW,
                    decision_rule_id=RuleId.AUTHORIZATION_ALLOW,
                    prepared_call_count=1,
                    execution_attempt_count=2,
                    execution_outcomes=ProofExecutionOutcomeCounts(0, 1, 0, 1),
                    adapter_entry_count=1,
                    authoritative_side_effect_count=1,
                    capability_state=PreparedCallState.CONSUMED,
                    reference_states=(ProofReferenceState.ACTIVE_CONSUMED,),
                ),
            ),
        ),
        non_claims=(
            "distributed exactly-once effects",
            "external idempotency",
            "retry safety outside the local capability boundary",
        ),
    ),
    ProofPropertyDefinition(
        property_id="W2-P05",
        property_title="Concurrent Replay Is Locally At-Most-Once",
        claim="Twelve attempts through a six-worker pool yield one local completion and eleven replay rejections.",
        invariant="Concurrent reuse of one local capability/reference pair is at-most-once at the adapter-entry boundary.",
        evidence_anchor_ids=(
            "matrix:J01_concurrent_replay",
            "test:execution_gate:concurrent_replay_one_winner",
        ),
        expected_security_outcome=_P05,
        fixtures=(
            _case(
                "W2-P05-C01-concurrent-replay",
                _P05,
                _observation(
                    decision_outcome=DecisionOutcome.ALLOW,
                    decision_rule_id=RuleId.AUTHORIZATION_ALLOW,
                    prepared_call_count=1,
                    execution_attempt_count=12,
                    execution_outcomes=ProofExecutionOutcomeCounts(0, 1, 0, 11),
                    adapter_entry_count=1,
                    authoritative_side_effect_count=1,
                    capability_state=PreparedCallState.CONSUMED,
                    reference_states=(ProofReferenceState.ACTIVE_CONSUMED,),
                ),
            ),
        ),
        non_claims=(
            "load capacity or fairness",
            "twelve simultaneous operating-system threads",
            "multi-process or distributed exclusion",
        ),
    ),
    ProofPropertyDefinition(
        property_id="W2-P06",
        property_title="Prepared-Call Tampering Fails Closed",
        claim="Seven existing prepared-call integrity and adapter-binding failure classes are refused before adapter entry or payment.",
        invariant="Execution requires an intact prepared object, exact runtime-held bindings and payload, and the trusted adapter identity and version.",
        evidence_anchor_ids=(
            "matrix:G01_public_integrity_mismatch",
            "matrix:G02_missing_private_binding",
            "matrix:G03_private_correlation_mismatch",
            "matrix:G04_integrity_authenticator_mismatch",
            "matrix:G05_private_payload_substitution",
            "matrix:G06_adapter_identity_mismatch",
            "matrix:G07_adapter_version_mismatch",
        ),
        expected_security_outcome=_P06,
        fixtures=tuple(
            _case(
                fixture_id,
                _P06,
                _observation(
                    decision_outcome=DecisionOutcome.ALLOW,
                    decision_rule_id=RuleId.AUTHORIZATION_ALLOW,
                    prepared_call_count=1,
                    execution_attempt_count=1,
                    execution_outcomes=_ONE_REFUSED,
                    adapter_entry_count=0,
                    authoritative_side_effect_count=0,
                    capability_state=PreparedCallState.UNUSED,
                    reference_states=(ProofReferenceState.ACTIVE_UNCONSUMED,),
                ),
            )
            for fixture_id in (
                "W2-P06-C01-public-integrity",
                "W2-P06-C02-binding-missing",
                "W2-P06-C03-correlation",
                "W2-P06-C04-authenticator",
                "W2-P06-C05-payload",
                "W2-P06-C06-adapter-identity",
                "W2-P06-C07-adapter-version",
            )
        ),
        non_claims=(
            "host-tamper resistance",
            "third-party attestation or signatures",
            "adapter supply-chain provenance",
        ),
    ),
    ProofPropertyDefinition(
        property_id="W2-P07",
        property_title="Protected Reference Context Is Bound",
        claim="Unresolvable or context/lifecycle-invalid protected references are denied with distinct current rules before preparation or effect.",
        invariant="Resolution is bound to trusted record existence, kind, invocation, parent, active state, and single-use lifecycle.",
        evidence_anchor_ids=(
            "matrix:C01_forged_reference",
            "matrix:C02_wrong_kind",
            "matrix:C03_wrong_invocation",
            "matrix:C04_wrong_parent",
            "matrix:C05_inactive_reference",
            "matrix:C06_consumed_reference",
            "test:reference_resolver:not_found",
            "test:reference_resolver:wrong_kind",
            "test:reference_resolver:wrong_invocation",
            "test:reference_resolver:wrong_parent",
            "test:reference_resolver:inactive",
            "test:reference_resolver:consumed",
        ),
        expected_security_outcome=_P07,
        fixtures=tuple(
            _case(
                fixture_id,
                _P07,
                _observation(
                    decision_outcome=DecisionOutcome.DENY,
                    decision_rule_id=rule,
                    prepared_call_count=0,
                    execution_attempt_count=0,
                    execution_outcomes=_ZERO_EXECUTION,
                    adapter_entry_count=0,
                    authoritative_side_effect_count=0,
                    reference_states=(state,),
                ),
            )
            for fixture_id, rule, state in (
                ("W2-P07-C01-reference-not-found", RuleId.REFERENCE_NOT_FOUND, ProofReferenceState.NOT_FOUND),
                ("W2-P07-C02-wrong-kind", RuleId.REFERENCE_KIND_MISMATCH, ProofReferenceState.ACTIVE_UNCONSUMED),
                ("W2-P07-C03-wrong-invocation", RuleId.REFERENCE_INVOCATION_MISMATCH, ProofReferenceState.ACTIVE_UNCONSUMED),
                ("W2-P07-C04-wrong-parent", RuleId.REFERENCE_PARENT_MISMATCH, ProofReferenceState.ACTIVE_UNCONSUMED),
                ("W2-P07-C05-inactive-reference", RuleId.REFERENCE_INACTIVE, ProofReferenceState.INACTIVE_UNCONSUMED),
                ("W2-P07-C06-consumed-reference", RuleId.REFERENCE_ALREADY_CONSUMED, ProofReferenceState.ACTIVE_CONSUMED),
            )
        ),
        non_claims=(
            "identity, roles, grants, or delegation",
            "passkeys or signing",
            "reference expiry or a generalized authority lifecycle",
        ),
    ),
    ProofPropertyDefinition(
        property_id="W2-P08",
        property_title="Incomplete or Conflicting Evidence Is Not PASS",
        claim="Incomplete, conflicting, or ambiguous evidence remains explicitly non-successful rather than becoming a false success or absence claim.",
        invariant="Observed evidence remains distinct from interpretation; uncertainty and contradiction fail closed at the review boundary.",
        evidence_anchor_ids=(
            "test:evidence_reconciliation:missing_terminal",
            "test:evidence_reconciliation:conflicting_terminal",
            "test:evidence_projection:ambiguous_result",
        ),
        expected_security_outcome=_P08,
        fixtures=(
            _case(
                "W2-P08-C01-missing-terminal-evidence",
                _P08,
                _observation(
                    decision_outcome=DecisionOutcome.ALLOW,
                    evidence_integrity_status=ProofEvidenceStatus.PASS,
                    evidence_reconciliation_status=ProofEvidenceStatus.FAIL,
                    evidence_completeness=EvidenceCompleteness.INCOMPLETE,
                    evidence_execution_status=ExecutionReviewStatus.INCOMPLETE,
                    evidence_success_claimed=False,
                    external_effect_absence_claimed=False,
                    finding_codes=(ProofFindingCode.MISSING_TERMINAL,),
                ),
            ),
            _case(
                "W2-P08-C02-conflicting-terminal-evidence",
                _P08,
                _observation(
                    decision_outcome=DecisionOutcome.ALLOW,
                    evidence_integrity_status=ProofEvidenceStatus.FAIL,
                    evidence_reconciliation_status=ProofEvidenceStatus.FAIL,
                    evidence_completeness=EvidenceCompleteness.COMPLETE,
                    evidence_execution_status=ExecutionReviewStatus.CONFLICT,
                    evidence_success_claimed=False,
                    external_effect_absence_claimed=False,
                    finding_codes=(ProofFindingCode.CONFLICTING_TERMINAL,),
                ),
            ),
            _case(
                "W2-P08-C03-ambiguous-external-result",
                _P08,
                _observation(
                    decision_outcome=DecisionOutcome.ALLOW,
                    decision_rule_id=RuleId.AUTHORIZATION_ALLOW,
                    prepared_call_count=1,
                    execution_attempt_count=1,
                    execution_outcomes=ProofExecutionOutcomeCounts(0, 0, 1, 0),
                    adapter_entry_count=1,
                    authoritative_side_effect_count=0,
                    capability_state=PreparedCallState.CONSUMED,
                    reference_states=(ProofReferenceState.ACTIVE_CONSUMED,),
                    external_result_status=ProofExternalResultStatus.UNCONFIRMED,
                    evidence_integrity_status=ProofEvidenceStatus.PASS,
                    evidence_reconciliation_status=ProofEvidenceStatus.PASS,
                    evidence_completeness=EvidenceCompleteness.COMPLETE,
                    evidence_execution_status=ExecutionReviewStatus.FAILED_AMBIGUOUS,
                    evidence_success_claimed=False,
                    external_effect_absence_claimed=False,
                ),
            ),
        ),
        non_claims=(
            "complete evidence proves external reality",
            "zero local records proves external-effect absence",
            "compliance, non-repudiation, or third-party verification",
        ),
    ),
)


if len(PROOF_CATALOGUE) != PROOF_PROPERTY_COUNT or sum(
    len(item.fixtures) for item in PROOF_CATALOGUE
) != PROOF_FIXTURE_COUNT:
    raise RuntimeError("closed W2 proof catalogue count mismatch")


__all__ = (
    "CATALOGUE_VERSION",
    "PROOF_CATALOGUE",
    "PROOF_FIXTURE_COUNT",
    "PROOF_PROPERTY_COUNT",
)
