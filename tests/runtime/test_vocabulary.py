import json

import pytest

from tidemark.runtime.vocabulary import (
    DECISION_RULE_IDS,
    EXECUTION_RULE_IDS,
    RUNTIME_VOCABULARY_VERSION,
    ArgumentRole,
    ConstraintId,
    DecisionOutcome,
    EffectClass,
    EvaluationStage,
    ExecutionOutcome,
    PreparedCallState,
    ProvenanceClass,
    ResolutionResultKind,
    Reversibility,
    RuleEvaluationOutcome,
    RuleId,
    UnknownVocabularyValueError,
)


CLOSED_ENUM_TYPES = (
    ArgumentRole,
    EffectClass,
    Reversibility,
    DecisionOutcome,
    EvaluationStage,
    ProvenanceClass,
    RuleEvaluationOutcome,
    ExecutionOutcome,
    ResolutionResultKind,
    PreparedCallState,
    ConstraintId,
    RuleId,
)

EXPECTED_CLOSED_VALUES = {
    ArgumentRole: ("UNPROTECTED_INPUT", "PROTECTED_REFERENCE"),
    EffectClass: ("SIDE_EFFECTING",),
    Reversibility: ("REVERSIBLE", "IRREVERSIBLE"),
    DecisionOutcome: ("REFUSAL", "DENY", "ALLOW"),
    EvaluationStage: (
        "STRUCTURE",
        "REPRESENTATION",
        "RESOLUTION",
        "BINDING",
        "LIFECYCLE",
        "VALUE",
        "AUTHORIZATION",
    ),
    ProvenanceClass: ("UNTRUSTED", "RUNTIME_TRUSTED"),
    RuleEvaluationOutcome: ("PASS", "FAIL", "NOT_EVALUATED"),
    ExecutionOutcome: (
        "REFUSED",
        "COMPLETED",
        "FAILED",
        "REPLAY_REJECTED",
    ),
    ResolutionResultKind: ("RESOLVED", "RESOLUTION_FAILURE"),
    PreparedCallState: ("UNUSED", "CONSUMED"),
    ConstraintId: (
        "protected.reference.required.v1",
        "reference.kind.equals.v1",
        "reference.invocation.equals.v1",
        "reference.parent.equals.v1",
        "reference.active.v1",
        "reference.single_use.v1",
        "value.integer.maximum.v1",
        "value.enum.member.v1",
    ),
    RuleId: (
        "runtime.policy_unavailable.v1",
        "contract.tool_unknown.v1",
        "contract.registry_incomplete.v1",
        "contract.signature_mismatch.v1",
        "contract.argument_shape_invalid.v1",
        "protected.raw_value_supplied.v1",
        "reference.not_found.v1",
        "reference.kind_mismatch.v1",
        "reference.invocation_mismatch.v1",
        "reference.parent_mismatch.v1",
        "reference.inactive.v1",
        "reference.already_consumed.v1",
        "value.constraint_failed.v1",
        "authorization.allow.v1",
        "execution.prepared_call_invalid.v1",
        "execution.replay_rejected.v1",
    ),
}


@pytest.mark.parametrize("enum_type", CLOSED_ENUM_TYPES)
def test_closed_values_round_trip_through_wire_serialization(enum_type):
    for member in enum_type:
        primitive = member.to_primitive()

        assert enum_type.parse(primitive) is member
        assert json.loads(json.dumps(member)) == primitive
        assert str(member) == primitive


@pytest.mark.parametrize("enum_type", CLOSED_ENUM_TYPES)
def test_closed_values_have_no_undocumented_members(enum_type):
    assert tuple(member.value for member in enum_type) == EXPECTED_CLOSED_VALUES[
        enum_type
    ]


@pytest.mark.parametrize("enum_type", CLOSED_ENUM_TYPES)
@pytest.mark.parametrize("invalid", ["UNKNOWN", "", None, 1, True])
def test_closed_values_reject_unknown_or_non_string_input(enum_type, invalid):
    with pytest.raises(UnknownVocabularyValueError):
        enum_type.parse(invalid)


@pytest.mark.parametrize("enum_type", CLOSED_ENUM_TYPES)
def test_closed_values_reject_string_subclasses(enum_type):
    class CallerString(str):
        pass

    with pytest.raises(UnknownVocabularyValueError):
        enum_type.parse(CallerString(next(iter(enum_type)).value))


def test_runtime_vocabulary_has_stable_version():
    assert RUNTIME_VOCABULARY_VERSION == "tidemark.runtime.v1"


def test_argument_roles_are_exactly_the_v1_contract_values():
    assert tuple(ArgumentRole) == (
        ArgumentRole.UNPROTECTED_INPUT,
        ArgumentRole.PROTECTED_REFERENCE,
    )


def test_decision_outcomes_are_closed():
    assert tuple(DecisionOutcome) == (
        DecisionOutcome.REFUSAL,
        DecisionOutcome.DENY,
        DecisionOutcome.ALLOW,
    )


def test_evaluation_stages_are_exactly_the_documented_order():
    assert tuple(EvaluationStage) == (
        EvaluationStage.STRUCTURE,
        EvaluationStage.REPRESENTATION,
        EvaluationStage.RESOLUTION,
        EvaluationStage.BINDING,
        EvaluationStage.LIFECYCLE,
        EvaluationStage.VALUE,
        EvaluationStage.AUTHORIZATION,
    )


def test_constraint_ids_are_exact_and_stable():
    assert tuple(member.value for member in ConstraintId) == (
        "protected.reference.required.v1",
        "reference.kind.equals.v1",
        "reference.invocation.equals.v1",
        "reference.parent.equals.v1",
        "reference.active.v1",
        "reference.single_use.v1",
        "value.integer.maximum.v1",
        "value.enum.member.v1",
    )


def test_decision_rule_ids_are_exact_and_in_first_failure_order():
    assert tuple(member.value for member in DECISION_RULE_IDS) == (
        "runtime.policy_unavailable.v1",
        "contract.tool_unknown.v1",
        "contract.registry_incomplete.v1",
        "contract.signature_mismatch.v1",
        "contract.argument_shape_invalid.v1",
        "protected.raw_value_supplied.v1",
        "reference.not_found.v1",
        "reference.kind_mismatch.v1",
        "reference.invocation_mismatch.v1",
        "reference.parent_mismatch.v1",
        "reference.inactive.v1",
        "reference.already_consumed.v1",
        "value.constraint_failed.v1",
        "authorization.allow.v1",
    )


def test_execution_rule_ids_are_exact_and_separate_from_decision_rules():
    assert tuple(member.value for member in EXECUTION_RULE_IDS) == (
        "execution.prepared_call_invalid.v1",
        "execution.replay_rejected.v1",
    )
    assert set(DECISION_RULE_IDS).isdisjoint(EXECUTION_RULE_IDS)
    assert tuple(RuleId) == DECISION_RULE_IDS + EXECUTION_RULE_IDS
