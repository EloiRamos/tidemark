from dataclasses import FrozenInstanceError, asdict, replace
import builtins
import inspect
import socket

import pytest

from tidemark.runtime.constraint_registry import (
    TRUSTED_CONSTRAINT_REGISTRY,
    TrustedConstraintRegistry,
)
from tidemark.runtime.identifiers import (
    CallId,
    DecisionId,
    InvocationId,
    ParentId,
    PolicyVersion,
    ReferenceId,
    RegistryVersion,
    ToolContractVersion,
    ToolId,
    TypeId,
)
from tidemark.runtime.policy_authoring import (
    ValidatedPolicyAuthoring,
    validate_policy_authoring,
)
from tidemark.runtime.policy_engine import (
    CallContext,
    CanonicalArgument,
    CanonicalCall,
    CanonicalSignatureArgument,
    Decision,
    PolicyEngine,
    ResolutionEntry,
    ResolutionFailure,
    ResolutionSet,
    Resolved,
)
from tidemark.runtime.policy_snapshot import (
    InstalledSnapshot,
    PolicyInstaller,
    SnapshotConstraintBinding,
)
from tidemark.runtime.vocabulary import (
    DECISION_RULE_IDS,
    ConstraintId,
    DecisionOutcome,
    EvaluationStage,
    RuleEvaluationOutcome,
    RuleId,
)


def valid_authoring(
    policy_version="policy-order-4-v1",
    registry_version="registry-order-4-v1",
):
    return {
        "policy_version": policy_version,
        "registry_version": registry_version,
        "executable_tools": ("transfers.submit",),
        "tool_registrations": (
            {
                "tool_id": "transfers.submit",
                "contract_version": "transfers.submit.contract.v1",
                "policy_version": policy_version,
                "signature": (
                    {
                        "name": "amount_minor",
                        "required": True,
                        "type_id": "integer",
                    },
                    {
                        "name": "currency",
                        "required": True,
                        "type_id": "currency_code",
                    },
                    {
                        "name": "destination_reference",
                        "required": True,
                        "type_id": "destination_reference",
                    },
                ),
                "arguments": (
                    {
                        "name": "amount_minor",
                        "position": 0,
                        "type_id": "integer",
                        "required": True,
                        "role": "UNPROTECTED_INPUT",
                        "constraint_bindings": (
                            {
                                "constraint_id": "value.integer.maximum.v1",
                                "parameters": {"maximum": 10_000},
                            },
                        ),
                    },
                    {
                        "name": "currency",
                        "position": 1,
                        "type_id": "currency_code",
                        "required": True,
                        "role": "UNPROTECTED_INPUT",
                        "constraint_bindings": (
                            {
                                "constraint_id": "value.enum.member.v1",
                                "parameters": {"members": ("EUR", "USD")},
                            },
                        ),
                    },
                    {
                        "name": "destination_reference",
                        "position": 2,
                        "type_id": "destination_reference",
                        "required": True,
                        "role": "PROTECTED_REFERENCE",
                        "constraint_bindings": (
                            {
                                "constraint_id": (
                                    "protected.reference.required.v1"
                                ),
                                "parameters": {},
                            },
                            {
                                "constraint_id": "reference.kind.equals.v1",
                                "parameters": {"kind": "destination"},
                            },
                            {
                                "constraint_id": (
                                    "reference.invocation.equals.v1"
                                ),
                                "parameters": {},
                            },
                            {
                                "constraint_id": "reference.parent.equals.v1",
                                "parameters": {},
                            },
                            {
                                "constraint_id": "reference.active.v1",
                                "parameters": {},
                            },
                            {
                                "constraint_id": "reference.single_use.v1",
                                "parameters": {},
                            },
                        ),
                    },
                ),
                "role_metadata": (
                    {
                        "name": "amount_minor",
                        "role": "UNPROTECTED_INPUT",
                        "required_provenance": "UNTRUSTED",
                    },
                    {
                        "name": "currency",
                        "role": "UNPROTECTED_INPUT",
                        "required_provenance": "UNTRUSTED",
                    },
                    {
                        "name": "destination_reference",
                        "role": "PROTECTED_REFERENCE",
                        "required_provenance": "RUNTIME_TRUSTED",
                    },
                ),
                "effect_class": "SIDE_EFFECTING",
                "reversibility": "IRREVERSIBLE",
                "adapter_id": "transfers.local.adapter",
                "adapter_version": "transfers.local.adapter.v1",
                "masking_profile_id": "transfers.masking.v1",
            },
        ),
    }


def install_snapshot(
    policy_version="policy-order-4-v1",
    registry_version="registry-order-4-v1",
    installer=None,
):
    authoring = valid_authoring(policy_version, registry_version)
    validated = validate_policy_authoring(authoring)
    assert type(validated) is ValidatedPolicyAuthoring
    active_installer = installer or PolicyInstaller()
    installed = active_installer.install(validated)
    assert type(installed) is InstalledSnapshot
    return installed.snapshot


def canonical_signature(snapshot):
    return tuple(
        CanonicalSignatureArgument(
            name=item.name,
            required=item.required,
            type_id=TypeId(item.type_id.value),
        )
        for item in snapshot.tool_policies[0].signature
    )


def valid_call(snapshot, **values):
    supplied = {
        "amount_minor": 5_000,
        "currency": "EUR",
        "destination_reference": ReferenceId("ref:opaque:valid"),
    }
    supplied.update(values)
    return CanonicalCall(
        tool_id=ToolId("transfers.submit"),
        contract_version=ToolContractVersion(
            "transfers.submit.contract.v1"
        ),
        signature=canonical_signature(snapshot),
        arguments=tuple(
            CanonicalArgument(name=name, value=supplied[name])
            for name in (
                "amount_minor",
                "currency",
                "destination_reference",
            )
            if name in supplied
        ),
    )


def valid_context(snapshot, **changes):
    fields = {
        "call_id": CallId("call-order-4-001"),
        "decision_id": DecisionId("decision-order-4-001"),
        "invocation_id": InvocationId("invocation-order-4-001"),
        "parent_id": ParentId("parent-order-4-001"),
        "policy_version": PolicyVersion(snapshot.policy_version.value),
        "registry_version": RegistryVersion(snapshot.registry_version.value),
    }
    fields.update(changes)
    return CallContext(**fields)


def valid_resolution(context, **changes):
    fields = {
        "kind": "destination",
        "invocation_id": InvocationId(context.invocation_id.value),
        "parent_id": ParentId(context.parent_id.value),
        "active": True,
        "consumed": False,
    }
    fields.update(changes)
    return ResolutionSet(
        entries=(
            ResolutionEntry(
                argument_name="destination_reference",
                result=Resolved(**fields),
            ),
        )
    )


def evaluate(snapshot=None, call=None, resolution_set=None, context=None):
    actual_snapshot = snapshot or install_snapshot()
    actual_context = context or valid_context(actual_snapshot)
    return PolicyEngine().evaluate(
        actual_snapshot,
        call or valid_call(actual_snapshot),
        resolution_set or valid_resolution(actual_context),
        actual_context,
    )


def replace_argument(call, name, value):
    return replace(
        call,
        arguments=tuple(
            replace(argument, value=value)
            if argument.name == name
            else argument
            for argument in call.arguments
        ),
    )


def assert_primary(decision, outcome, rule_id, stage):
    assert type(decision) is Decision
    assert decision.outcome is outcome
    assert decision.primary_rule_id is rule_id
    assert decision.evaluation_stage is stage
    assert decision.rule_results[-1].rule_id is rule_id
    assert decision.rule_results[-1].outcome is RuleEvaluationOutcome.FAIL


def test_trusted_registry_exactly_covers_the_closed_v1_constraint_set():
    assert TRUSTED_CONSTRAINT_REGISTRY.constraint_ids == tuple(ConstraintId)
    assert TRUSTED_CONSTRAINT_REGISTRY.is_complete()


@pytest.mark.parametrize("constraint_id", tuple(ConstraintId))
def test_every_v1_constraint_resolves_to_named_trusted_behavior(constraint_id):
    implementation_id = TRUSTED_CONSTRAINT_REGISTRY.implementation_id(
        constraint_id
    )

    assert type(implementation_id) is str
    assert implementation_id.startswith("tidemark.trusted_constraint.")


def test_unknown_constraint_has_no_trusted_implementation():
    assert TRUSTED_CONSTRAINT_REGISTRY.implementation_id(object()) is None


def test_registry_has_no_dynamic_registration_or_replacement_surface():
    registry = TrustedConstraintRegistry()

    assert not hasattr(registry, "register")
    assert not hasattr(registry, "replace")
    assert not hasattr(registry, "unregister")
    with pytest.raises(AttributeError):
        registry.constraint_ids = ()
    with pytest.raises(TypeError):
        PolicyEngine(registry=registry)


def test_caller_created_registry_cannot_change_engine_behavior():
    caller_registry = TrustedConstraintRegistry()
    snapshot = install_snapshot()
    context = valid_context(snapshot)

    with pytest.raises(AttributeError):
        caller_registry.caller_behavior = lambda *_: True

    decision = PolicyEngine().evaluate(
        snapshot,
        valid_call(snapshot, amount_minor=10_001),
        valid_resolution(context),
        context,
    )
    assert decision.primary_rule_id is RuleId.VALUE_CONSTRAINT_FAILED


def test_unknown_snapshot_constraint_implementation_fails_closed():
    snapshot = install_snapshot()
    policy = snapshot.tool_policies[0]
    argument = policy.arguments[0]
    unknown_binding = SnapshotConstraintBinding(
        constraint_id=object(),
        parameters=argument.constraint_bindings[0].parameters,
    )
    malformed_argument = replace(
        argument, constraint_bindings=(unknown_binding,)
    )
    malformed_policy = replace(
        policy,
        arguments=(malformed_argument,) + policy.arguments[1:],
    )
    malformed_snapshot = replace(snapshot, tool_policies=(malformed_policy,))
    context = valid_context(malformed_snapshot)

    decision = PolicyEngine().evaluate(
        malformed_snapshot,
        valid_call(snapshot),
        valid_resolution(context),
        context,
    )

    assert_primary(
        decision,
        DecisionOutcome.REFUSAL,
        RuleId.CONTRACT_REGISTRY_INCOMPLETE,
        EvaluationStage.STRUCTURE,
    )


def test_policy_snapshot_contains_only_inert_constraint_data():
    snapshot = install_snapshot()

    for policy in snapshot.tool_policies:
        for argument in policy.arguments:
            for binding in argument.constraint_bindings:
                assert type(binding.constraint_id) is ConstraintId
                assert not any(callable(value) for _, value in binding.parameters)
    assert "TrustedConstraintRegistry" not in repr(snapshot)


def test_identical_inputs_produce_equal_decisions():
    snapshot = install_snapshot()
    context = valid_context(snapshot)
    call = valid_call(snapshot)
    resolution_set = valid_resolution(context)

    first = PolicyEngine().evaluate(snapshot, call, resolution_set, context)
    second = PolicyEngine().evaluate(snapshot, call, resolution_set, context)

    assert first == second
    assert hash(first) == hash(second)


def test_equivalent_fresh_inputs_produce_equal_decisions():
    first_snapshot = install_snapshot()
    second_snapshot = install_snapshot()
    first_context = valid_context(first_snapshot)
    second_context = valid_context(second_snapshot)

    first = PolicyEngine().evaluate(
        first_snapshot,
        valid_call(first_snapshot),
        valid_resolution(first_context),
        first_context,
    )
    second = PolicyEngine().evaluate(
        second_snapshot,
        valid_call(second_snapshot),
        valid_resolution(second_context),
        second_context,
    )

    assert first == second


def test_rule_trace_order_is_stable_and_follows_authoritative_rule_order():
    decision = evaluate()
    indexes = tuple(
        DECISION_RULE_IDS.index(result.rule_id)
        for result in decision.rule_results
    )

    assert indexes == tuple(sorted(indexes))
    assert decision.rule_results[-1].rule_id is RuleId.AUTHORIZATION_ALLOW


def test_value_argument_evaluation_uses_tool_contract_order():
    decision = evaluate()
    value_results = tuple(
        result
        for result in decision.rule_results
        if result.rule_id is RuleId.VALUE_CONSTRAINT_FAILED
    )

    assert tuple(result.argument_name for result in value_results) == (
        "amount_minor",
        "currency",
    )


def test_first_failure_wins_over_all_later_failures():
    snapshot = install_snapshot()
    context = valid_context(snapshot)
    call = valid_call(
        snapshot,
        amount_minor=10_001,
        currency="GBP",
        destination_reference="raw-protected-value",
    )
    resolution_set = ResolutionSet(
        entries=(
            ResolutionEntry(
                argument_name="destination_reference",
                result=ResolutionFailure(
                    rule_id=RuleId.REFERENCE_NOT_FOUND
                ),
            ),
        )
    )

    decision = PolicyEngine().evaluate(
        snapshot, call, resolution_set, context
    )

    assert_primary(
        decision,
        DecisionOutcome.DENY,
        RuleId.PROTECTED_RAW_VALUE_SUPPLIED,
        EvaluationStage.REPRESENTATION,
    )


def test_policy_unavailable_returns_refusal():
    snapshot = install_snapshot()
    context = valid_context(snapshot)

    decision = PolicyEngine().evaluate(
        None,
        valid_call(snapshot),
        valid_resolution(context),
        context,
    )

    assert_primary(
        decision,
        DecisionOutcome.REFUSAL,
        RuleId.RUNTIME_POLICY_UNAVAILABLE,
        EvaluationStage.STRUCTURE,
    )


def test_context_policy_version_mismatch_returns_policy_refusal():
    snapshot = install_snapshot()
    context = valid_context(
        snapshot, policy_version=PolicyVersion("different-policy")
    )

    decision = PolicyEngine().evaluate(
        snapshot,
        valid_call(snapshot),
        valid_resolution(context),
        context,
    )

    assert decision.primary_rule_id is RuleId.RUNTIME_POLICY_UNAVAILABLE


def test_unknown_tool_returns_refusal():
    snapshot = install_snapshot()
    context = valid_context(snapshot)
    call = replace(valid_call(snapshot), tool_id=ToolId("unknown.tool"))

    decision = PolicyEngine().evaluate(
        snapshot, call, valid_resolution(context), context
    )

    assert_primary(
        decision,
        DecisionOutcome.REFUSAL,
        RuleId.CONTRACT_TOOL_UNKNOWN,
        EvaluationStage.STRUCTURE,
    )


def test_incomplete_snapshot_state_returns_registry_refusal():
    snapshot = install_snapshot()
    malformed = replace(snapshot, tool_policies=())
    context = valid_context(malformed)

    decision = PolicyEngine().evaluate(
        malformed,
        valid_call(snapshot),
        valid_resolution(context),
        context,
    )

    assert decision.primary_rule_id is RuleId.CONTRACT_REGISTRY_INCOMPLETE


def test_context_registry_version_mismatch_returns_registry_refusal():
    snapshot = install_snapshot()
    context = valid_context(
        snapshot, registry_version=RegistryVersion("different-registry")
    )

    decision = PolicyEngine().evaluate(
        snapshot,
        valid_call(snapshot),
        valid_resolution(context),
        context,
    )

    assert decision.primary_rule_id is RuleId.CONTRACT_REGISTRY_INCOMPLETE


@pytest.mark.parametrize("mismatch", ("signature", "contract_version"))
def test_signature_or_contract_version_mismatch_returns_refusal(mismatch):
    snapshot = install_snapshot()
    context = valid_context(snapshot)
    call = valid_call(snapshot)
    if mismatch == "signature":
        signature = list(call.signature)
        signature[0] = replace(signature[0], type_id=TypeId("string"))
        call = replace(call, signature=tuple(signature))
    else:
        call = replace(
            call, contract_version=ToolContractVersion("different-contract")
        )

    decision = PolicyEngine().evaluate(
        snapshot, call, valid_resolution(context), context
    )

    assert_primary(
        decision,
        DecisionOutcome.REFUSAL,
        RuleId.CONTRACT_SIGNATURE_MISMATCH,
        EvaluationStage.STRUCTURE,
    )


@pytest.mark.parametrize("shape", ("missing_required", "extra", "reordered"))
def test_invalid_argument_shape_is_denied(shape):
    snapshot = install_snapshot()
    context = valid_context(snapshot)
    call = valid_call(snapshot)
    if shape == "missing_required":
        call = replace(call, arguments=call.arguments[1:])
    elif shape == "extra":
        call = replace(
            call,
            arguments=call.arguments
            + (CanonicalArgument(name="extra", value="value"),),
        )
    else:
        call = replace(
            call,
            arguments=(call.arguments[1], call.arguments[0])
            + call.arguments[2:],
        )

    decision = PolicyEngine().evaluate(
        snapshot, call, valid_resolution(context), context
    )

    assert_primary(
        decision,
        DecisionOutcome.DENY,
        RuleId.CONTRACT_ARGUMENT_SHAPE_INVALID,
        EvaluationStage.STRUCTURE,
    )


@pytest.mark.parametrize("protected_value", ("raw-destination", None))
def test_raw_or_missing_protected_representation_is_denied(protected_value):
    snapshot = install_snapshot()
    context = valid_context(snapshot)

    decision = PolicyEngine().evaluate(
        snapshot,
        valid_call(snapshot, destination_reference=protected_value),
        valid_resolution(context),
        context,
    )

    assert_primary(
        decision,
        DecisionOutcome.DENY,
        RuleId.PROTECTED_RAW_VALUE_SUPPLIED,
        EvaluationStage.REPRESENTATION,
    )


def test_missing_resolution_entry_is_denied_as_not_found():
    snapshot = install_snapshot()
    context = valid_context(snapshot)

    decision = PolicyEngine().evaluate(
        snapshot,
        valid_call(snapshot),
        ResolutionSet(entries=()),
        context,
    )

    assert_primary(
        decision,
        DecisionOutcome.DENY,
        RuleId.REFERENCE_NOT_FOUND,
        EvaluationStage.RESOLUTION,
    )


def test_explicit_not_found_resolution_failure_is_denied():
    snapshot = install_snapshot()
    context = valid_context(snapshot)
    resolution_set = ResolutionSet(
        entries=(
            ResolutionEntry(
                argument_name="destination_reference",
                result=ResolutionFailure(
                    rule_id=RuleId.REFERENCE_NOT_FOUND
                ),
            ),
        )
    )

    decision = PolicyEngine().evaluate(
        snapshot, valid_call(snapshot), resolution_set, context
    )

    assert decision.primary_rule_id is RuleId.REFERENCE_NOT_FOUND


@pytest.mark.parametrize(
    ("resolution_change", "rule_id", "stage"),
    (
        (
            {"kind": "wrong-kind"},
            RuleId.REFERENCE_KIND_MISMATCH,
            EvaluationStage.RESOLUTION,
        ),
        (
            {"invocation_id": InvocationId("wrong-invocation")},
            RuleId.REFERENCE_INVOCATION_MISMATCH,
            EvaluationStage.BINDING,
        ),
        (
            {"parent_id": ParentId("wrong-parent")},
            RuleId.REFERENCE_PARENT_MISMATCH,
            EvaluationStage.BINDING,
        ),
        (
            {"active": False},
            RuleId.REFERENCE_INACTIVE,
            EvaluationStage.LIFECYCLE,
        ),
        (
            {"consumed": True},
            RuleId.REFERENCE_ALREADY_CONSUMED,
            EvaluationStage.LIFECYCLE,
        ),
    ),
)
def test_protected_resolution_fact_failures_are_isolated(
    resolution_change, rule_id, stage
):
    snapshot = install_snapshot()
    context = valid_context(snapshot)

    decision = PolicyEngine().evaluate(
        snapshot,
        valid_call(snapshot),
        valid_resolution(context, **resolution_change),
        context,
    )

    assert_primary(decision, DecisionOutcome.DENY, rule_id, stage)


def test_resolution_failure_for_later_rule_is_preserved():
    snapshot = install_snapshot()
    context = valid_context(snapshot)
    resolution_set = ResolutionSet(
        entries=(
            ResolutionEntry(
                argument_name="destination_reference",
                result=ResolutionFailure(
                    rule_id=RuleId.REFERENCE_PARENT_MISMATCH
                ),
            ),
        )
    )

    decision = PolicyEngine().evaluate(
        snapshot, valid_call(snapshot), resolution_set, context
    )

    assert decision.primary_rule_id is RuleId.REFERENCE_PARENT_MISMATCH


@pytest.mark.parametrize("amount", (10_000, -1))
def test_integer_maximum_accepts_exact_integers_at_or_below_bound(amount):
    decision = evaluate(call=valid_call(install_snapshot(), amount_minor=amount))

    assert decision.outcome is DecisionOutcome.ALLOW


@pytest.mark.parametrize("amount", (10_001, "5000", True))
def test_integer_maximum_fails_closed_for_excess_or_wrong_exact_type(amount):
    snapshot = install_snapshot()
    decision = evaluate(
        snapshot=snapshot,
        call=valid_call(snapshot, amount_minor=amount),
    )

    assert_primary(
        decision,
        DecisionOutcome.DENY,
        RuleId.VALUE_CONSTRAINT_FAILED,
        EvaluationStage.VALUE,
    )


@pytest.mark.parametrize("currency", ("EUR", "USD"))
def test_enum_membership_accepts_exact_string_members(currency):
    snapshot = install_snapshot()
    decision = evaluate(snapshot=snapshot, call=valid_call(snapshot, currency=currency))

    assert decision.outcome is DecisionOutcome.ALLOW


@pytest.mark.parametrize("currency", ("GBP", 1, True))
def test_enum_membership_fails_closed_for_nonmember_or_wrong_type(currency):
    snapshot = install_snapshot()
    decision = evaluate(snapshot=snapshot, call=valid_call(snapshot, currency=currency))

    assert decision.primary_rule_id is RuleId.VALUE_CONSTRAINT_FAILED


def test_complete_legitimate_call_returns_allow_without_preparing_or_executing():
    decision = evaluate()

    assert decision.outcome is DecisionOutcome.ALLOW
    assert decision.primary_rule_id is RuleId.AUTHORIZATION_ALLOW
    assert decision.evaluation_stage is EvaluationStage.AUTHORIZATION
    assert decision.rule_results[-1].outcome is RuleEvaluationOutcome.PASS
    assert not hasattr(decision, "prepared_call")
    assert not hasattr(PolicyEngine(), "execute")


def test_engine_evaluates_the_exact_captured_snapshot_after_replacement():
    installer = PolicyInstaller()
    captured = install_snapshot("policy-v1", installer=installer)
    install_snapshot("policy-v2", installer=installer)
    context = valid_context(captured)

    decision = PolicyEngine().evaluate(
        captured,
        valid_call(captured),
        valid_resolution(context),
        context,
    )

    assert decision.policy_version == PolicyVersion("policy-v1")
    assert decision.outcome is DecisionOutcome.ALLOW


def test_source_mutation_cannot_change_snapshot_or_decision():
    authoring = valid_authoring()
    validated = validate_policy_authoring(authoring)
    assert type(validated) is ValidatedPolicyAuthoring
    installed = PolicyInstaller().install(validated)
    assert type(installed) is InstalledSnapshot
    snapshot = installed.snapshot
    context = valid_context(snapshot)
    decision = PolicyEngine().evaluate(
        snapshot,
        valid_call(snapshot),
        valid_resolution(context),
        context,
    )

    authoring["policy_version"] = "caller-mutated"
    authoring["tool_registrations"][0]["arguments"][0][
        "constraint_bindings"
    ][0]["parameters"]["maximum"] = 1

    assert decision.outcome is DecisionOutcome.ALLOW
    assert snapshot.policy_version == PolicyVersion("policy-order-4-v1")


def test_mutating_call_and_resolution_source_lists_retains_no_caller_state():
    snapshot = install_snapshot()
    context = valid_context(snapshot)
    argument_source = list(valid_call(snapshot).arguments)
    resolution_source = list(valid_resolution(context).entries)
    call = replace(valid_call(snapshot), arguments=tuple(argument_source))
    resolution_set = ResolutionSet(entries=tuple(resolution_source))
    decision = PolicyEngine().evaluate(
        snapshot, call, resolution_set, context
    )

    argument_source[0] = CanonicalArgument("amount_minor", 99_999)
    resolution_source[0] = ResolutionEntry(
        "destination_reference",
        ResolutionFailure(RuleId.REFERENCE_NOT_FOUND),
    )

    assert decision.outcome is DecisionOutcome.ALLOW
    assert call.arguments[0].value == 5_000
    assert type(resolution_set.entries[0].result) is Resolved


def test_decision_and_all_nested_results_are_immutable():
    decision = evaluate()

    with pytest.raises(FrozenInstanceError):
        decision.outcome = DecisionOutcome.DENY
    with pytest.raises(FrozenInstanceError):
        decision.rule_results[0].outcome = RuleEvaluationOutcome.FAIL
    with pytest.raises(TypeError):
        decision.rule_results[0] = decision.rule_results[0]


def test_no_caller_owned_executable_state_is_retained():
    decision = evaluate()

    assert not any(
        callable(value)
        for name, value in inspect.getmembers(decision)
        if not name.startswith("__")
    )


def test_protected_values_and_reference_ids_do_not_appear_in_decision_data():
    protected_value = "acct:protected:never-return"
    protected_reference = ReferenceId("ref:opaque:must-not-return")
    snapshot = install_snapshot()
    context = valid_context(snapshot)
    call = valid_call(snapshot, destination_reference=protected_reference)
    resolution_set = valid_resolution(context)

    decision = PolicyEngine().evaluate(
        snapshot, call, resolution_set, context
    )
    rendered = repr(decision) + repr(asdict(decision))

    assert protected_value not in rendered
    assert protected_reference.value not in rendered
    assert not hasattr(resolution_set.entries[0].result, "protected_value")


def test_raw_protected_value_is_not_reflected_in_deny_decision():
    protected_value = "acct:protected:raw-secret"
    snapshot = install_snapshot()
    context = valid_context(snapshot)

    decision = PolicyEngine().evaluate(
        snapshot,
        valid_call(snapshot, destination_reference=protected_value),
        valid_resolution(context),
        context,
    )

    assert protected_value not in repr(decision)
    assert protected_value not in repr(asdict(decision))


def test_evaluation_performs_no_file_network_or_clock_io(monkeypatch):
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("policy evaluation attempted I/O")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)

    decision = evaluate()

    assert decision.outcome is DecisionOutcome.ALLOW
    assert calls == []


def test_order_4_surface_has_no_prepared_call_store_resolver_or_execution_type():
    from tidemark.runtime import policy_engine

    forbidden = {
        "PreparedToolCall",
        "ReferenceResolver",
        "ReferenceIssuer",
        "TrustedReferenceStore",
        "ExecutionGate",
    }

    assert forbidden.isdisjoint(vars(policy_engine))
    assert not any(
        name.startswith(("adk", "gemini", "google", "cloud", "payment"))
        for name in vars(policy_engine)
    )


def test_order_4_public_runtime_surface_exports_only_inert_inputs_and_decision():
    import tidemark.runtime as runtime

    expected = {
        "TRUSTED_CONSTRAINT_REGISTRY",
        "TrustedConstraintRegistry",
        "CallContext",
        "CanonicalArgument",
        "CanonicalCall",
        "CanonicalSignatureArgument",
        "Decision",
        "EvaluatedRuleResult",
        "MaskedDecisionFact",
        "PolicyEngine",
        "ResolutionEntry",
        "ResolutionFailure",
        "ResolutionSet",
        "Resolved",
    }

    assert expected.issubset(set(runtime.__all__))
    assert not hasattr(runtime, "PreparedToolCall")
    assert not hasattr(runtime, "ExecutionGate")
