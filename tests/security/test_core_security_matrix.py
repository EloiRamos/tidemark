import ast
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, asdict, dataclass, replace
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple

import pytest

from tidemark.payment.domain import PurchaseOrderRecord
from tidemark.payment.fixtures import (
    DEFAULT_EVALUATION_TIME,
    RAW_SYNTHETIC_DESTINATION,
    SYNTHETIC_DESTINATION_KIND,
    _payment_policy_authoring,
    build_synthetic_payment_fixture,
    default_purchase_order,
)
from tidemark.runtime import execution_gate as execution_gate_module
from tidemark.runtime.execution_binding import (
    _lookup_runtime_execution_binding,
)
from tidemark.runtime.execution_gate import (
    AdapterInvocationResult,
    ExecutionGate,
    TrustedAdapterRegistry,
)
from tidemark.runtime.identifiers import (
    AdapterId,
    AdapterVersion,
    DecisionId,
    InvocationId,
    ParentId,
    ReferenceId,
    ToolId,
    TypeId,
)
from tidemark.runtime.minimal_evidence import (
    EvidenceAppendFailure,
    MinimalPreExecutionEvidenceSink,
)
from tidemark.runtime.policy_authoring import (
    ValidatedPolicyAuthoring,
    validate_policy_authoring,
)
from tidemark.runtime.policy_engine import (
    CanonicalArgument,
    Decision,
)
from tidemark.runtime.policy_snapshot import (
    InstalledSnapshot,
    PolicyInstaller,
    SnapshotConstraintBinding,
)
from tidemark.runtime.prepared_call import PreparedToolCall
from tidemark.runtime.reference_resolver import (
    ReferenceResolver,
    ResolutionRequest,
)
from tidemark.runtime.reference_store import (
    ReferenceBinding,
    ReferenceConsumptionOutcome,
    ReferenceLifecycle,
    ReferenceMetadata,
    ReferenceNotFound,
    TrustedRecord,
)
from tidemark.runtime.vocabulary import (
    DecisionOutcome,
    ExecutionOutcome,
    PreparedCallState,
    RuleId,
)


REPEATABILITY_ITERATIONS = 10
CONCURRENT_ATTEMPTS = 12
NOT_APPLICABLE = "NOT_APPLICABLE"
UNCONSUMED = "UNCONSUMED"
INACTIVE = "INACTIVE"
NOT_FOUND = "NOT_FOUND"

# Counts are ordered REFUSED, COMPLETED, FAILED, REPLAY_REJECTED.
NO_EXECUTION = (0, 0, 0, 0)
ONE_COMPLETED = (0, 1, 0, 0)
ONE_REFUSED = (1, 0, 0, 0)
COMPLETED_THEN_REPLAY = (0, 1, 0, 1)
FAILED_THEN_REPLAY = (0, 0, 1, 1)

# Counts are ordered execution.prepared_call_invalid.v1, then replay rejection.
NO_EXECUTION_RULE = (0, 0)
ONE_PREPARED_INVALID = (1, 0)
ONE_REPLAY_RULE = (0, 1)


@dataclass(frozen=True)
class MatrixScenario:
    scenario_id: str
    category: str
    attacker_controlled_input: str
    trusted_state: str
    expected_decision_outcome: DecisionOutcome
    expected_primary_rule: RuleId
    expected_execution_counts: Tuple[int, int, int, int]
    expected_execution_rule_counts: Tuple[int, int]
    expected_prepared_call_count: int
    expected_adapter_entries: int
    expected_payment_count: int
    expected_capability_state: str
    expected_reference_state: str
    expected_protected_value_leakage: bool = False


@dataclass(frozen=True)
class MatrixObservation:
    decision_outcome: DecisionOutcome
    primary_rule: RuleId
    execution_counts: Tuple[int, int, int, int]
    execution_rule_counts: Tuple[int, int]
    prepared_call_count: int
    adapter_entries: int
    payment_count: int
    capability_state: str
    reference_state: str
    protected_value_leakage: bool


CORE_SECURITY_MATRIX = (
    MatrixScenario(
        "A01_legitimate_allow",
        "A legitimate ALLOW",
        "valid amount, allowed currency, opaque destination reference",
        "trusted PO; matching active unconsumed single-use destination",
        DecisionOutcome.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        ONE_COMPLETED,
        NO_EXECUTION_RULE,
        1,
        1,
        1,
        PreparedCallState.CONSUMED.value,
        PreparedCallState.CONSUMED.value,
    ),
    MatrixScenario(
        "B01_raw_protected_value",
        "B raw protected-value attack",
        "raw synthetic destination string",
        "valid trusted PO and an unrelated valid opaque reference",
        DecisionOutcome.DENY,
        RuleId.PROTECTED_RAW_VALUE_SUPPLIED,
        NO_EXECUTION,
        NO_EXECUTION_RULE,
        0,
        0,
        0,
        NOT_APPLICABLE,
        NOT_APPLICABLE,
    ),
    MatrixScenario(
        "C01_forged_reference",
        "C forgery/reference attack",
        "unknown opaque-looking ReferenceId",
        "valid trusted PO and empty lookup for the selected identifier",
        DecisionOutcome.DENY,
        RuleId.REFERENCE_NOT_FOUND,
        NO_EXECUTION,
        NO_EXECUTION_RULE,
        0,
        0,
        0,
        NOT_APPLICABLE,
        NOT_FOUND,
    ),
    MatrixScenario(
        "C02_wrong_kind",
        "C forgery/reference attack",
        "reference selecting a record of the wrong trusted kind",
        "matching invocation/parent and active unconsumed lifecycle",
        DecisionOutcome.DENY,
        RuleId.REFERENCE_KIND_MISMATCH,
        NO_EXECUTION,
        NO_EXECUTION_RULE,
        0,
        0,
        0,
        NOT_APPLICABLE,
        UNCONSUMED,
    ),
    MatrixScenario(
        "C03_wrong_invocation",
        "C forgery/reference attack",
        "reference bound to a different invocation",
        "correct kind/parent and active unconsumed lifecycle",
        DecisionOutcome.DENY,
        RuleId.REFERENCE_INVOCATION_MISMATCH,
        NO_EXECUTION,
        NO_EXECUTION_RULE,
        0,
        0,
        0,
        NOT_APPLICABLE,
        UNCONSUMED,
    ),
    MatrixScenario(
        "C04_wrong_parent",
        "C forgery/reference attack",
        "reference bound to a different parent",
        "correct kind/invocation and active unconsumed lifecycle",
        DecisionOutcome.DENY,
        RuleId.REFERENCE_PARENT_MISMATCH,
        NO_EXECUTION,
        NO_EXECUTION_RULE,
        0,
        0,
        0,
        NOT_APPLICABLE,
        UNCONSUMED,
    ),
    MatrixScenario(
        "C05_inactive_reference",
        "C forgery/reference attack",
        "selected inactive reference",
        "correct kind/invocation/parent and unconsumed lifecycle",
        DecisionOutcome.DENY,
        RuleId.REFERENCE_INACTIVE,
        NO_EXECUTION,
        NO_EXECUTION_RULE,
        0,
        0,
        0,
        NOT_APPLICABLE,
        INACTIVE,
    ),
    MatrixScenario(
        "C06_consumed_reference",
        "C forgery/reference attack",
        "selected already-consumed reference",
        "correct kind/invocation/parent and active lifecycle",
        DecisionOutcome.DENY,
        RuleId.REFERENCE_ALREADY_CONSUMED,
        NO_EXECUTION,
        NO_EXECUTION_RULE,
        0,
        0,
        0,
        NOT_APPLICABLE,
        PreparedCallState.CONSUMED.value,
    ),
    MatrixScenario(
        "D01_amount_at_trusted_maximum",
        "D trusted-bound attack",
        "amount equal to the PO maximum",
        "installed maximum sourced from the trusted PO",
        DecisionOutcome.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        ONE_COMPLETED,
        NO_EXECUTION_RULE,
        1,
        1,
        1,
        PreparedCallState.CONSUMED.value,
        PreparedCallState.CONSUMED.value,
    ),
    MatrixScenario(
        "D02_amount_above_trusted_maximum",
        "D trusted-bound attack",
        "amount one minor unit above the PO maximum",
        "installed maximum sourced from the trusted PO",
        DecisionOutcome.DENY,
        RuleId.VALUE_CONSTRAINT_FAILED,
        NO_EXECUTION,
        NO_EXECUTION_RULE,
        0,
        0,
        0,
        NOT_APPLICABLE,
        UNCONSUMED,
    ),
    MatrixScenario(
        "D03_allowed_trusted_currency",
        "D trusted-bound attack",
        "GBP selected from the trusted PO allowlist",
        "installed currency members are exactly EUR and GBP",
        DecisionOutcome.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        ONE_COMPLETED,
        NO_EXECUTION_RULE,
        1,
        1,
        1,
        PreparedCallState.CONSUMED.value,
        PreparedCallState.CONSUMED.value,
    ),
    MatrixScenario(
        "D04_unsupported_currency",
        "D trusted-bound attack",
        "USD absent from the trusted PO allowlist",
        "installed currency members are exactly EUR",
        DecisionOutcome.DENY,
        RuleId.VALUE_CONSTRAINT_FAILED,
        NO_EXECUTION,
        NO_EXECUTION_RULE,
        0,
        0,
        0,
        NOT_APPLICABLE,
        UNCONSUMED,
    ),
    MatrixScenario(
        "E01_authoring_source_mutation",
        "E mutation/isolation attack",
        "caller downgrades source maximum and currency after installation",
        "fresh immutable snapshot retains original trusted PO constraints",
        DecisionOutcome.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        ONE_COMPLETED,
        NO_EXECUTION_RULE,
        1,
        1,
        1,
        PreparedCallState.CONSUMED.value,
        PreparedCallState.CONSUMED.value,
    ),
    MatrixScenario(
        "E02_snapshot_inspection_mutation",
        "E mutation/isolation attack",
        "caller creates a downgraded detached inspection graph",
        "authoritative snapshot retains the trusted maximum",
        DecisionOutcome.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        ONE_COMPLETED,
        NO_EXECUTION_RULE,
        1,
        1,
        1,
        PreparedCallState.CONSUMED.value,
        PreparedCallState.CONSUMED.value,
    ),
    MatrixScenario(
        "E03_canonical_source_mutation",
        "E mutation/isolation attack",
        "caller replaces source-list entries after canonical construction",
        "canonical call retains the valid original tuple",
        DecisionOutcome.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        ONE_COMPLETED,
        NO_EXECUTION_RULE,
        1,
        1,
        1,
        PreparedCallState.CONSUMED.value,
        PreparedCallState.CONSUMED.value,
    ),
    MatrixScenario(
        "E04_resolver_payload_mutation",
        "E mutation/isolation attack",
        "runtime-private resolver payload changed after preparation",
        "prepared payload holds a detached copy of the trusted destination",
        DecisionOutcome.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        ONE_COMPLETED,
        NO_EXECUTION_RULE,
        1,
        1,
        1,
        PreparedCallState.CONSUMED.value,
        PreparedCallState.CONSUMED.value,
    ),
    MatrixScenario(
        "E05_prepared_public_mutation",
        "E mutation/isolation attack",
        "ordinary mutation of prepared public and nested fields",
        "frozen prepared capability and private authoritative payload",
        DecisionOutcome.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        ONE_COMPLETED,
        NO_EXECUTION_RULE,
        1,
        1,
        1,
        PreparedCallState.CONSUMED.value,
        PreparedCallState.CONSUMED.value,
    ),
    MatrixScenario(
        "E06_payment_adapter_input_mutation",
        "E mutation/isolation attack",
        "adapter attempts to mutate its detached invocation",
        "frozen adapter input and unchanged prepared capability",
        DecisionOutcome.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        ONE_COMPLETED,
        NO_EXECUTION_RULE,
        1,
        1,
        1,
        PreparedCallState.CONSUMED.value,
        PreparedCallState.CONSUMED.value,
    ),
    MatrixScenario(
        "F01_unknown_tool",
        "F malformed registry/contract state",
        "unknown tool identity",
        "complete schedule_payment registry and valid remaining call data",
        DecisionOutcome.REFUSAL,
        RuleId.CONTRACT_TOOL_UNKNOWN,
        NO_EXECUTION,
        NO_EXECUTION_RULE,
        0,
        0,
        0,
        NOT_APPLICABLE,
        UNCONSUMED,
    ),
    MatrixScenario(
        "F02_incomplete_registry",
        "F malformed registry/contract state",
        "snapshot with missing tool-policy coverage",
        "captured versions and otherwise valid call/reference state",
        DecisionOutcome.REFUSAL,
        RuleId.CONTRACT_REGISTRY_INCOMPLETE,
        NO_EXECUTION,
        NO_EXECUTION_RULE,
        0,
        0,
        0,
        NOT_APPLICABLE,
        UNCONSUMED,
    ),
    MatrixScenario(
        "F03_signature_mismatch",
        "F malformed registry/contract state",
        "canonical signature type differs from trusted registration",
        "complete registry and otherwise valid call/reference state",
        DecisionOutcome.REFUSAL,
        RuleId.CONTRACT_SIGNATURE_MISMATCH,
        NO_EXECUTION,
        NO_EXECUTION_RULE,
        0,
        0,
        0,
        NOT_APPLICABLE,
        UNCONSUMED,
    ),
    MatrixScenario(
        "F04_unknown_constraint_implementation",
        "F malformed registry/contract state",
        "snapshot binding with no trusted constraint implementation",
        "supported malformed-snapshot test construction and valid call state",
        DecisionOutcome.REFUSAL,
        RuleId.CONTRACT_REGISTRY_INCOMPLETE,
        NO_EXECUTION,
        NO_EXECUTION_RULE,
        0,
        0,
        0,
        NOT_APPLICABLE,
        UNCONSUMED,
    ),
    MatrixScenario(
        "G01_public_integrity_mismatch",
        "G prepared-call integrity attack",
        "public integrity identifier substitution",
        "valid ALLOW and matching unused private binding",
        DecisionOutcome.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        ONE_REFUSED,
        ONE_PREPARED_INVALID,
        1,
        0,
        0,
        PreparedCallState.UNUSED.value,
        UNCONSUMED,
    ),
    MatrixScenario(
        "G02_missing_private_binding",
        "G prepared-call integrity attack",
        "private binding lookup made unavailable",
        "valid public prepared call and otherwise matching runtime state",
        DecisionOutcome.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        ONE_REFUSED,
        ONE_PREPARED_INVALID,
        1,
        0,
        0,
        PreparedCallState.UNUSED.value,
        UNCONSUMED,
    ),
    MatrixScenario(
        "G03_private_correlation_mismatch",
        "G prepared-call integrity attack",
        "private decision correlation substitution",
        "valid public prepared call and untouched payload authenticator",
        DecisionOutcome.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        ONE_REFUSED,
        ONE_PREPARED_INVALID,
        1,
        0,
        0,
        PreparedCallState.UNUSED.value,
        UNCONSUMED,
    ),
    MatrixScenario(
        "G04_private_authenticator_mismatch",
        "G prepared-call integrity attack",
        "runtime-private payload authenticator substitution",
        "valid public correlations and untouched prepared payload",
        DecisionOutcome.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        ONE_REFUSED,
        ONE_PREPARED_INVALID,
        1,
        0,
        0,
        PreparedCallState.UNUSED.value,
        UNCONSUMED,
    ),
    MatrixScenario(
        "G05_private_payload_substitution",
        "G prepared-call integrity attack",
        "runtime-private protected payload substitution",
        "valid public integrity and original private authenticator",
        DecisionOutcome.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        ONE_REFUSED,
        ONE_PREPARED_INVALID,
        1,
        0,
        0,
        PreparedCallState.UNUSED.value,
        UNCONSUMED,
    ),
    MatrixScenario(
        "G06_adapter_identity_mismatch",
        "G prepared-call integrity attack",
        "trusted registry adapter identity mismatch",
        "valid prepared call and matching tool/version",
        DecisionOutcome.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        ONE_REFUSED,
        ONE_PREPARED_INVALID,
        1,
        0,
        0,
        PreparedCallState.UNUSED.value,
        UNCONSUMED,
    ),
    MatrixScenario(
        "G07_adapter_version_mismatch",
        "G prepared-call integrity attack",
        "trusted registry adapter version mismatch",
        "valid prepared call and matching tool/identity",
        DecisionOutcome.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        ONE_REFUSED,
        ONE_PREPARED_INVALID,
        1,
        0,
        0,
        PreparedCallState.UNUSED.value,
        UNCONSUMED,
    ),
    MatrixScenario(
        "H01_pre_execution_evidence_failure",
        "H pre-execution evidence failure",
        "injected durable pre-execution append failure",
        "valid ALLOW, unused capability, and unconsumed reference",
        DecisionOutcome.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        ONE_REFUSED,
        ONE_PREPARED_INVALID,
        1,
        0,
        0,
        PreparedCallState.UNUSED.value,
        UNCONSUMED,
    ),
    MatrixScenario(
        "I01_sequential_replay",
        "I sequential replay",
        "same prepared capability executed twice",
        "one valid unused capability and single-use reference",
        DecisionOutcome.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        COMPLETED_THEN_REPLAY,
        ONE_REPLAY_RULE,
        1,
        1,
        1,
        PreparedCallState.CONSUMED.value,
        PreparedCallState.CONSUMED.value,
    ),
    MatrixScenario(
        "J01_concurrent_replay",
        "J concurrent replay",
        "12 concurrent executions of one prepared capability",
        "one valid unused capability and single-use reference",
        DecisionOutcome.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        (0, 1, 0, CONCURRENT_ATTEMPTS - 1),
        (0, CONCURRENT_ATTEMPTS - 1),
        1,
        1,
        1,
        PreparedCallState.CONSUMED.value,
        PreparedCallState.CONSUMED.value,
    ),
    MatrixScenario(
        "K01_adapter_confirmed_failure",
        "K adapter failure",
        "confirmed adapter failure before payment write, then replay",
        "valid ALLOW and one single-use execution authority",
        DecisionOutcome.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        FAILED_THEN_REPLAY,
        ONE_REPLAY_RULE,
        1,
        1,
        0,
        PreparedCallState.CONSUMED.value,
        PreparedCallState.CONSUMED.value,
    ),
    MatrixScenario(
        "K02_ambiguous_execution",
        "K ambiguous execution",
        "unconfirmed adapter result, then replay",
        "valid ALLOW and one single-use execution authority",
        DecisionOutcome.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        FAILED_THEN_REPLAY,
        ONE_REPLAY_RULE,
        1,
        1,
        0,
        PreparedCallState.CONSUMED.value,
        PreparedCallState.CONSUMED.value,
    ),
    MatrixScenario(
        "L01_public_protected_value_hygiene",
        "L public protected-value hygiene",
        "distinctive protected destination and opaque reference marker",
        "valid end-to-end execution with masked public records",
        DecisionOutcome.ALLOW,
        RuleId.AUTHORIZATION_ALLOW,
        ONE_COMPLETED,
        NO_EXECUTION_RULE,
        1,
        1,
        1,
        PreparedCallState.CONSUMED.value,
        PreparedCallState.CONSUMED.value,
        False,
    ),
)


def _reference_state(fixture, reference_id: Optional[ReferenceId]) -> str:
    if reference_id is None:
        return NOT_APPLICABLE
    metadata = fixture.reference_store.lookup(reference_id)
    if type(metadata) is ReferenceNotFound:
        return NOT_FOUND
    assert type(metadata) is ReferenceMetadata
    if metadata.active is False:
        return INACTIVE
    return PreparedCallState.CONSUMED.value if metadata.consumed else UNCONSUMED


def _capability_state(preparation: object) -> str:
    if type(preparation) is not PreparedToolCall:
        return NOT_APPLICABLE
    binding = _lookup_runtime_execution_binding(preparation.prepared_call_id)
    if binding is None:
        return "MISSING"
    return binding._capability_state.value


def _observe(
    fixture,
    decision: Decision,
    preparation: object,
    outcomes: Tuple[object, ...] = (),
    *,
    reference_id: Optional[ReferenceId],
    adapter_entries: Optional[int] = None,
    protected_value_leakage: bool = False,
) -> MatrixObservation:
    statuses = (
        ExecutionOutcome.REFUSED,
        ExecutionOutcome.COMPLETED,
        ExecutionOutcome.FAILED,
        ExecutionOutcome.REPLAY_REJECTED,
    )
    rules = (
        RuleId.EXECUTION_PREPARED_CALL_INVALID,
        RuleId.EXECUTION_REPLAY_REJECTED,
    )
    return MatrixObservation(
        decision_outcome=decision.outcome,
        primary_rule=decision.primary_rule_id,
        execution_counts=tuple(
            sum(outcome.status is status for outcome in outcomes)
            for status in statuses
        ),
        execution_rule_counts=tuple(
            sum(outcome.rule_id is rule for outcome in outcomes)
            for rule in rules
        ),
        prepared_call_count=int(type(preparation) is PreparedToolCall),
        adapter_entries=(
            fixture.adapter.entry_count
            if adapter_entries is None
            else adapter_entries
        ),
        payment_count=fixture.payment_store.count,
        capability_state=_capability_state(preparation),
        reference_state=_reference_state(fixture, reference_id),
        protected_value_leakage=protected_value_leakage,
    )


def _evaluate_and_prepare(fixture, call):
    decision = fixture.evaluate(call)
    preparation = fixture.prepare(call)
    return decision, preparation


def _standard_payment_run(
    root: Path,
    *,
    fixture_options: Optional[dict] = None,
    call_options: Optional[dict] = None,
    execute_count: int = 0,
    reference_id: object = None,
) -> MatrixObservation:
    fixture = build_synthetic_payment_fixture(
        str(root), **(fixture_options or {})
    )
    call = fixture.canonical_call(**(call_options or {}))
    decision, preparation = _evaluate_and_prepare(fixture, call)
    outcomes = ()
    if execute_count:
        assert type(preparation) is PreparedToolCall
        outcomes = tuple(
            fixture.execution_gate.execute(preparation)
            for _ in range(execute_count)
        )
    selected = (
        fixture.destination_reference
        if reference_id is None
        else reference_id
    )
    return _observe(
        fixture,
        decision,
        preparation,
        outcomes,
        reference_id=selected,
    )


def _assert_trusted_po_constraints(fixture) -> None:
    policy = fixture.snapshot.tool_policies[0]
    assert policy.arguments[0].constraint_bindings[0].parameters == (
        ("maximum", fixture.purchase_order.maximum_amount_minor),
    )
    assert policy.arguments[1].constraint_bindings[0].parameters == (
        ("members", fixture.purchase_order.allowed_currencies),
    )


def _run_raw_value(root: Path) -> MatrixObservation:
    fixture = build_synthetic_payment_fixture(str(root))
    call = fixture.canonical_call(destination_reference=RAW_SYNTHETIC_DESTINATION)
    decision, preparation = _evaluate_and_prepare(fixture, call)
    return _observe(
        fixture, decision, preparation, reference_id=None
    )


def _run_forged_reference(root: Path) -> MatrixObservation:
    forged = ReferenceId("ref_order_10_forged_unknown")
    return _standard_payment_run(
        root,
        call_options={"destination_reference": forged},
        reference_id=forged,
    )


def _run_wrong_kind(root: Path) -> MatrixObservation:
    fixture = build_synthetic_payment_fixture(str(root))
    wrong_kind = fixture.reference_store.issuer.issue(
        TrustedRecord(RAW_SYNTHETIC_DESTINATION, "attacker_wrong_kind"),
        ReferenceBinding(fixture.invocation_id, fixture.purchase_order.parent_id),
        ReferenceLifecycle(active=True, single_use=True),
    )
    call = fixture.canonical_call(destination_reference=wrong_kind)
    decision, preparation = _evaluate_and_prepare(fixture, call)
    return _observe(
        fixture, decision, preparation, reference_id=wrong_kind
    )


def _run_consumed_reference(root: Path) -> MatrixObservation:
    fixture = build_synthetic_payment_fixture(str(root))
    assert fixture.reference_store.consume(fixture.destination_reference) is (
        ReferenceConsumptionOutcome.CONSUMED
    )
    decision, preparation = _evaluate_and_prepare(
        fixture, fixture.canonical_call()
    )
    return _observe(
        fixture,
        decision,
        preparation,
        reference_id=fixture.destination_reference,
    )


def _run_amount_at_maximum(root: Path) -> MatrixObservation:
    fixture = build_synthetic_payment_fixture(str(root))
    _assert_trusted_po_constraints(fixture)
    call = fixture.canonical_call(
        amount_minor=fixture.purchase_order.maximum_amount_minor
    )
    decision, preparation = _evaluate_and_prepare(fixture, call)
    assert type(preparation) is PreparedToolCall
    outcome = fixture.execution_gate.execute(preparation)
    return _observe(
        fixture,
        decision,
        preparation,
        (outcome,),
        reference_id=fixture.destination_reference,
    )


def _run_amount_above_maximum(root: Path) -> MatrixObservation:
    fixture = build_synthetic_payment_fixture(str(root))
    _assert_trusted_po_constraints(fixture)
    call = fixture.canonical_call(
        amount_minor=fixture.purchase_order.maximum_amount_minor + 1
    )
    decision, preparation = _evaluate_and_prepare(fixture, call)
    return _observe(
        fixture,
        decision,
        preparation,
        reference_id=fixture.destination_reference,
    )


def _run_allowed_currency(root: Path) -> MatrixObservation:
    purchase_order = PurchaseOrderRecord(
        ParentId("purchase-order-order-10-currency"),
        25_000,
        ("EUR", "GBP"),
    )
    fixture = build_synthetic_payment_fixture(
        str(root), purchase_order=purchase_order
    )
    _assert_trusted_po_constraints(fixture)
    decision, preparation = _evaluate_and_prepare(
        fixture, fixture.canonical_call(currency="GBP")
    )
    assert type(preparation) is PreparedToolCall
    outcome = fixture.execution_gate.execute(preparation)
    return _observe(
        fixture,
        decision,
        preparation,
        (outcome,),
        reference_id=fixture.destination_reference,
    )


def _run_unsupported_currency(root: Path) -> MatrixObservation:
    fixture = build_synthetic_payment_fixture(str(root))
    _assert_trusted_po_constraints(fixture)
    decision, preparation = _evaluate_and_prepare(
        fixture, fixture.canonical_call(currency="USD")
    )
    return _observe(
        fixture,
        decision,
        preparation,
        reference_id=fixture.destination_reference,
    )


def _fixture_with_snapshot(root: Path, snapshot):
    fixture = build_synthetic_payment_fixture(str(root))
    return replace(fixture, snapshot=snapshot)


def _run_authoring_source_mutation(root: Path) -> MatrixObservation:
    purchase_order = default_purchase_order()
    source = _payment_policy_authoring(purchase_order)
    validated = validate_policy_authoring(source)
    assert type(validated) is ValidatedPolicyAuthoring
    installed = PolicyInstaller().install(validated)
    assert type(installed) is InstalledSnapshot
    source["tool_registrations"][0]["arguments"][0][
        "constraint_bindings"
    ][0]["parameters"]["maximum"] = 1
    source["tool_registrations"][0]["arguments"][1][
        "constraint_bindings"
    ][0]["parameters"]["members"] = ("USD",)
    fixture = _fixture_with_snapshot(root, installed.snapshot)
    _assert_trusted_po_constraints(fixture)
    decision, preparation = _evaluate_and_prepare(
        fixture, fixture.canonical_call()
    )
    assert type(preparation) is PreparedToolCall
    outcome = fixture.execution_gate.execute(preparation)
    return _observe(
        fixture,
        decision,
        preparation,
        (outcome,),
        reference_id=fixture.destination_reference,
    )


def _run_snapshot_inspection_mutation(root: Path) -> MatrixObservation:
    purchase_order = default_purchase_order()
    validated = validate_policy_authoring(_payment_policy_authoring(purchase_order))
    assert type(validated) is ValidatedPolicyAuthoring
    installer = PolicyInstaller()
    installed = installer.install(validated)
    assert type(installed) is InstalledSnapshot
    inspection = installer.inspect_snapshot()
    assert inspection is not None
    policy_view = inspection.tool_policies[0]
    amount_view = policy_view.arguments[0]
    binding_view = amount_view.constraint_bindings[0]
    downgraded_binding = replace(binding_view, parameters=(("maximum", 1),))
    downgraded_amount = replace(
        amount_view, constraint_bindings=(downgraded_binding,)
    )
    downgraded_policy = replace(
        policy_view,
        arguments=(downgraded_amount,) + policy_view.arguments[1:],
    )
    downgraded_inspection = replace(
        inspection, tool_policies=(downgraded_policy,)
    )
    assert downgraded_inspection.tool_policies[0].arguments[0].constraint_bindings[
        0
    ].parameters == (("maximum", 1),)
    fixture = _fixture_with_snapshot(root, installed.snapshot)
    _assert_trusted_po_constraints(fixture)
    decision, preparation = _evaluate_and_prepare(
        fixture, fixture.canonical_call()
    )
    assert type(preparation) is PreparedToolCall
    outcome = fixture.execution_gate.execute(preparation)
    return _observe(
        fixture,
        decision,
        preparation,
        (outcome,),
        reference_id=fixture.destination_reference,
    )


def _run_canonical_source_mutation(root: Path) -> MatrixObservation:
    fixture = build_synthetic_payment_fixture(str(root))
    base_call = fixture.canonical_call()
    source_arguments = list(base_call.arguments)
    canonical_call = replace(base_call, arguments=tuple(source_arguments))
    source_arguments[0] = CanonicalArgument(
        "amount_minor", fixture.purchase_order.maximum_amount_minor + 1
    )
    source_arguments[2] = CanonicalArgument(
        "destination_reference", RAW_SYNTHETIC_DESTINATION
    )
    decision, preparation = _evaluate_and_prepare(fixture, canonical_call)
    assert type(preparation) is PreparedToolCall
    outcome = fixture.execution_gate.execute(preparation)
    return _observe(
        fixture,
        decision,
        preparation,
        (outcome,),
        reference_id=fixture.destination_reference,
    )


def _run_resolver_payload_mutation(root: Path) -> MatrixObservation:
    fixture = build_synthetic_payment_fixture(str(root))
    resolved = ReferenceResolver().resolve(
        ResolutionRequest(
            reference_id=fixture.destination_reference,
            expected_kind=SYNTHETIC_DESTINATION_KIND,
            invocation_id=fixture.invocation_id,
            parent_id=fixture.purchase_order.parent_id,
            argument_name="destination_reference",
            evaluation_time=DEFAULT_EVALUATION_TIME,
        ),
        fixture.reference_store,
    )
    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(
            ReferenceResolver,
            "resolve",
            lambda self, request, trusted_store: resolved,
        )
        decision, preparation = _evaluate_and_prepare(
            fixture, fixture.canonical_call()
        )
    assert type(preparation) is PreparedToolCall
    object.__setattr__(
        resolved,
        "_RuntimeProtectedValueCarrier__protected_value",
        "attacker-mutated-resolver-payload-order-10",
    )
    assert preparation.arguments[2]._copy_value_for_runtime() == (
        RAW_SYNTHETIC_DESTINATION
    )
    outcome = fixture.execution_gate.execute(preparation)
    return _observe(
        fixture,
        decision,
        preparation,
        (outcome,),
        reference_id=fixture.destination_reference,
    )


def _run_prepared_public_mutation(root: Path) -> MatrixObservation:
    fixture = build_synthetic_payment_fixture(str(root))
    decision, preparation = _evaluate_and_prepare(
        fixture, fixture.canonical_call()
    )
    assert type(preparation) is PreparedToolCall
    with pytest.raises(FrozenInstanceError):
        preparation.adapter_id = AdapterId("attacker.adapter")
    with pytest.raises(FrozenInstanceError):
        preparation.arguments[0].name = "attacker_amount"
    with pytest.raises(FrozenInstanceError):
        preparation.arguments[0].type_id.value = "attacker_type"
    outcome = fixture.execution_gate.execute(preparation)
    return _observe(
        fixture,
        decision,
        preparation,
        (outcome,),
        reference_id=fixture.destination_reference,
    )


def _run_payment_adapter_input_mutation(root: Path) -> MatrixObservation:
    fixture = build_synthetic_payment_fixture(str(root))
    decision, preparation = _evaluate_and_prepare(
        fixture, fixture.canonical_call()
    )
    assert type(preparation) is PreparedToolCall
    blocked_mutations = []

    def mutation_attempt(invocation):
        try:
            invocation.arguments[0].value = 0
        except FrozenInstanceError:
            blocked_mutations.append("argument")
        try:
            invocation.arguments = ()
        except FrozenInstanceError:
            blocked_mutations.append("invocation")
        return fixture.adapter(invocation)

    registry = TrustedAdapterRegistry(
        tool_id=preparation.tool_id,
        adapter_id=preparation.adapter_id,
        adapter_version=preparation.adapter_version,
        adapter=mutation_attempt,
    )
    gate = ExecutionGate(
        adapter_registry=registry,
        evidence_sink=MinimalPreExecutionEvidenceSink(str(root / "adapter-input")),
    )
    outcome = gate.execute(preparation)
    assert blocked_mutations == ["argument", "invocation"]
    return _observe(
        fixture,
        decision,
        preparation,
        (outcome,),
        reference_id=fixture.destination_reference,
    )


def _run_incomplete_registry(root: Path) -> MatrixObservation:
    fixture = build_synthetic_payment_fixture(str(root))
    malformed = replace(fixture.snapshot, tool_policies=())
    altered = replace(fixture, snapshot=malformed)
    decision, preparation = _evaluate_and_prepare(
        altered, fixture.canonical_call()
    )
    return _observe(
        altered,
        decision,
        preparation,
        reference_id=fixture.destination_reference,
    )


def _run_unknown_tool(root: Path) -> MatrixObservation:
    fixture = build_synthetic_payment_fixture(str(root))
    call = replace(
        fixture.canonical_call(), tool_id=ToolId("attacker.unknown_tool")
    )
    decision, preparation = _evaluate_and_prepare(fixture, call)
    return _observe(
        fixture,
        decision,
        preparation,
        reference_id=fixture.destination_reference,
    )


def _run_signature_mismatch(root: Path) -> MatrixObservation:
    fixture = build_synthetic_payment_fixture(str(root))
    call = fixture.canonical_call()
    signature = list(call.signature)
    signature[0] = replace(signature[0], type_id=TypeId("attacker_string"))
    mismatched = replace(call, signature=tuple(signature))
    decision, preparation = _evaluate_and_prepare(fixture, mismatched)
    return _observe(
        fixture,
        decision,
        preparation,
        reference_id=fixture.destination_reference,
    )


def _run_unknown_constraint_implementation(root: Path) -> MatrixObservation:
    fixture = build_synthetic_payment_fixture(str(root))
    policy = fixture.snapshot.tool_policies[0]
    argument = policy.arguments[0]
    existing = argument.constraint_bindings[0]
    unknown = SnapshotConstraintBinding(
        constraint_id=object(), parameters=existing.parameters
    )
    malformed_argument = replace(argument, constraint_bindings=(unknown,))
    malformed_policy = replace(
        policy, arguments=(malformed_argument,) + policy.arguments[1:]
    )
    malformed_snapshot = replace(
        fixture.snapshot, tool_policies=(malformed_policy,)
    )
    altered = replace(fixture, snapshot=malformed_snapshot)
    decision, preparation = _evaluate_and_prepare(
        altered, fixture.canonical_call()
    )
    return _observe(
        altered,
        decision,
        preparation,
        reference_id=fixture.destination_reference,
    )


def _prepared_fixture(root: Path):
    fixture = build_synthetic_payment_fixture(str(root))
    decision, preparation = _evaluate_and_prepare(
        fixture, fixture.canonical_call()
    )
    assert decision.outcome is DecisionOutcome.ALLOW
    assert type(preparation) is PreparedToolCall
    return fixture, decision, preparation


def _run_public_integrity_mismatch(root: Path) -> MatrixObservation:
    fixture, decision, preparation = _prepared_fixture(root)
    object.__setattr__(preparation, "integrity_id", "sha256:" + "0" * 64)
    outcome = fixture.execution_gate.execute(preparation)
    return _observe(
        fixture,
        decision,
        preparation,
        (outcome,),
        reference_id=fixture.destination_reference,
    )


def _run_missing_private_binding(root: Path) -> MatrixObservation:
    fixture, decision, preparation = _prepared_fixture(root)
    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(
            execution_gate_module,
            "_validate_runtime_execution_binding",
            lambda value: None,
        )
        outcome = fixture.execution_gate.execute(preparation)
    return _observe(
        fixture,
        decision,
        preparation,
        (outcome,),
        reference_id=fixture.destination_reference,
    )


def _run_private_correlation_mismatch(root: Path) -> MatrixObservation:
    fixture, decision, preparation = _prepared_fixture(root)
    binding = _lookup_runtime_execution_binding(preparation.prepared_call_id)
    assert binding is not None
    object.__setattr__(
        binding,
        "decision_id",
        DecisionId("attacker-substituted-decision"),
    )
    outcome = fixture.execution_gate.execute(preparation)
    return _observe(
        fixture,
        decision,
        preparation,
        (outcome,),
        reference_id=fixture.destination_reference,
    )


def _run_private_authenticator_mismatch(root: Path) -> MatrixObservation:
    fixture, decision, preparation = _prepared_fixture(root)
    binding = _lookup_runtime_execution_binding(preparation.prepared_call_id)
    assert binding is not None
    object.__setattr__(binding, "_payload_authenticator", b"attacker-invalid")
    outcome = fixture.execution_gate.execute(preparation)
    return _observe(
        fixture,
        decision,
        preparation,
        (outcome,),
        reference_id=fixture.destination_reference,
    )


def _run_private_payload_substitution(root: Path) -> MatrixObservation:
    fixture, decision, preparation = _prepared_fixture(root)
    object.__setattr__(
        preparation.arguments[2],
        "_RuntimePreparedValueCarrier__runtime_value",
        "attacker-substituted-private-payload-order-10",
    )
    outcome = fixture.execution_gate.execute(preparation)
    return _observe(
        fixture,
        decision,
        preparation,
        (outcome,),
        reference_id=fixture.destination_reference,
    )


def _run_adapter_mismatch(
    root: Path, *, adapter_id=None, adapter_version=None
) -> MatrixObservation:
    fixture, decision, preparation = _prepared_fixture(root)
    registry = TrustedAdapterRegistry(
        tool_id=preparation.tool_id,
        adapter_id=adapter_id or preparation.adapter_id,
        adapter_version=adapter_version or preparation.adapter_version,
        adapter=fixture.adapter,
    )
    gate = ExecutionGate(
        adapter_registry=registry,
        evidence_sink=MinimalPreExecutionEvidenceSink(str(root / "mismatch")),
    )
    outcome = gate.execute(preparation)
    return _observe(
        fixture,
        decision,
        preparation,
        (outcome,),
        reference_id=fixture.destination_reference,
    )


def _run_pre_execution_evidence_failure(root: Path) -> MatrixObservation:
    fixture, decision, preparation = _prepared_fixture(root)
    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(
            MinimalPreExecutionEvidenceSink,
            "append_pre_execution",
            lambda self, record: EvidenceAppendFailure(
                record_id=record.record_id,
                failure_code="evidence.append_failed.v1",
            ),
        )
        outcome = fixture.execution_gate.execute(preparation)
    return _observe(
        fixture,
        decision,
        preparation,
        (outcome,),
        reference_id=fixture.destination_reference,
    )


def _run_concurrent_replay(root: Path) -> MatrixObservation:
    fixture, decision, preparation = _prepared_fixture(root)
    with ThreadPoolExecutor(max_workers=6) as executor:
        outcomes = tuple(
            executor.map(
                fixture.execution_gate.execute,
                (preparation,) * CONCURRENT_ATTEMPTS,
            )
        )
    return _observe(
        fixture,
        decision,
        preparation,
        outcomes,
        reference_id=fixture.destination_reference,
    )


class _AmbiguousAdapter:
    def __init__(self) -> None:
        self.entry_count = 0

    def __call__(self, invocation):
        self.entry_count += 1
        return AdapterInvocationResult.unconfirmed_failure()


def _run_ambiguous_execution(root: Path) -> MatrixObservation:
    fixture, decision, preparation = _prepared_fixture(root)
    adapter = _AmbiguousAdapter()
    registry = TrustedAdapterRegistry(
        tool_id=preparation.tool_id,
        adapter_id=preparation.adapter_id,
        adapter_version=preparation.adapter_version,
        adapter=adapter,
    )
    gate = ExecutionGate(
        adapter_registry=registry,
        evidence_sink=MinimalPreExecutionEvidenceSink(str(root / "ambiguous")),
    )
    outcomes = (gate.execute(preparation), gate.execute(preparation))
    assert outcomes[0].external_result_confirmed is False
    return _observe(
        fixture,
        decision,
        preparation,
        outcomes,
        reference_id=fixture.destination_reference,
        adapter_entries=adapter.entry_count,
    )


def _run_public_hygiene(root: Path) -> MatrixObservation:
    fixture, decision, preparation = _prepared_fixture(root)
    outcome = fixture.execution_gate.execute(preparation)
    record = fixture.payment_store.records()[0]
    evidence = "".join(
        path.read_text(encoding="utf-8") for path in root.glob("*.json")
    )
    public_views = (
        repr(decision),
        repr(asdict(decision)),
        repr(preparation),
        repr(asdict(preparation)),
        repr(outcome),
        repr(asdict(outcome)),
        repr(record),
        repr(asdict(record)),
        evidence,
        repr(fixture.reference_store),
        repr(fixture.payment_store),
        repr(fixture.adapter),
    )
    leakage = any(
        RAW_SYNTHETIC_DESTINATION in view for view in public_views
    )
    leakage = leakage or any(
        fixture.destination_reference.value in view
        for view in (
            repr(record),
            repr(asdict(record)),
            evidence,
            repr(fixture.payment_store),
            repr(fixture.adapter),
        )
    )
    leakage = leakage or hasattr(record, "reference_id") or hasattr(
        record, "raw_destination"
    )
    return _observe(
        fixture,
        decision,
        preparation,
        (outcome,),
        reference_id=fixture.destination_reference,
        protected_value_leakage=leakage,
    )


ScenarioRunner = Callable[[Path], MatrixObservation]
SCENARIO_RUNNERS: Dict[str, ScenarioRunner] = {
    "A01_legitimate_allow": lambda root: _standard_payment_run(
        root, execute_count=1
    ),
    "B01_raw_protected_value": _run_raw_value,
    "C01_forged_reference": _run_forged_reference,
    "C02_wrong_kind": _run_wrong_kind,
    "C03_wrong_invocation": lambda root: _standard_payment_run(
        root,
        fixture_options={
            "reference_invocation_id": InvocationId(
                "attacker-wrong-invocation-order-10"
            )
        },
    ),
    "C04_wrong_parent": lambda root: _standard_payment_run(
        root,
        fixture_options={
            "reference_parent_id": ParentId("attacker-wrong-parent-order-10")
        },
    ),
    "C05_inactive_reference": lambda root: _standard_payment_run(
        root, fixture_options={"reference_active": False}
    ),
    "C06_consumed_reference": _run_consumed_reference,
    "D01_amount_at_trusted_maximum": _run_amount_at_maximum,
    "D02_amount_above_trusted_maximum": _run_amount_above_maximum,
    "D03_allowed_trusted_currency": _run_allowed_currency,
    "D04_unsupported_currency": _run_unsupported_currency,
    "E01_authoring_source_mutation": _run_authoring_source_mutation,
    "E02_snapshot_inspection_mutation": _run_snapshot_inspection_mutation,
    "E03_canonical_source_mutation": _run_canonical_source_mutation,
    "E04_resolver_payload_mutation": _run_resolver_payload_mutation,
    "E05_prepared_public_mutation": _run_prepared_public_mutation,
    "E06_payment_adapter_input_mutation": _run_payment_adapter_input_mutation,
    "F01_unknown_tool": _run_unknown_tool,
    "F02_incomplete_registry": _run_incomplete_registry,
    "F03_signature_mismatch": _run_signature_mismatch,
    "F04_unknown_constraint_implementation": _run_unknown_constraint_implementation,
    "G01_public_integrity_mismatch": _run_public_integrity_mismatch,
    "G02_missing_private_binding": _run_missing_private_binding,
    "G03_private_correlation_mismatch": _run_private_correlation_mismatch,
    "G04_private_authenticator_mismatch": _run_private_authenticator_mismatch,
    "G05_private_payload_substitution": _run_private_payload_substitution,
    "G06_adapter_identity_mismatch": lambda root: _run_adapter_mismatch(
        root, adapter_id=AdapterId("attacker.adapter.identity")
    ),
    "G07_adapter_version_mismatch": lambda root: _run_adapter_mismatch(
        root, adapter_version=AdapterVersion("attacker.adapter.version")
    ),
    "H01_pre_execution_evidence_failure": _run_pre_execution_evidence_failure,
    "I01_sequential_replay": lambda root: _standard_payment_run(
        root, execute_count=2
    ),
    "J01_concurrent_replay": _run_concurrent_replay,
    "K01_adapter_confirmed_failure": lambda root: _standard_payment_run(
        root,
        fixture_options={"adapter_fail_before_record": True},
        execute_count=2,
    ),
    "K02_ambiguous_execution": _run_ambiguous_execution,
    "L01_public_protected_value_hygiene": _run_public_hygiene,
}


def _expected_observation(scenario: MatrixScenario) -> MatrixObservation:
    return MatrixObservation(
        decision_outcome=scenario.expected_decision_outcome,
        primary_rule=scenario.expected_primary_rule,
        execution_counts=scenario.expected_execution_counts,
        execution_rule_counts=scenario.expected_execution_rule_counts,
        prepared_call_count=scenario.expected_prepared_call_count,
        adapter_entries=scenario.expected_adapter_entries,
        payment_count=scenario.expected_payment_count,
        capability_state=scenario.expected_capability_state,
        reference_state=scenario.expected_reference_state,
        protected_value_leakage=scenario.expected_protected_value_leakage,
    )


def test_matrix_catalog_is_complete_stable_and_inert():
    scenario_ids = tuple(item.scenario_id for item in CORE_SECURITY_MATRIX)

    assert len(CORE_SECURITY_MATRIX) == 35
    assert len(scenario_ids) == len(set(scenario_ids))
    assert set(scenario_ids) == set(SCENARIO_RUNNERS)
    assert {item.scenario_id[0] for item in CORE_SECURITY_MATRIX} == set(
        "ABCDEFGHIJKL"
    )
    assert all(item.attacker_controlled_input for item in CORE_SECURITY_MATRIX)
    assert all(item.trusted_state for item in CORE_SECURITY_MATRIX)


@pytest.mark.parametrize(
    "scenario",
    CORE_SECURITY_MATRIX,
    ids=lambda item: item.scenario_id,
)
def test_core_security_matrix_scenario(tmp_path, scenario):
    observed = SCENARIO_RUNNERS[scenario.scenario_id](
        tmp_path / scenario.scenario_id
    )

    assert observed == _expected_observation(scenario)


def test_complete_matrix_is_semantically_repeatable_from_fresh_state(tmp_path):
    expected = {
        scenario.scenario_id: _expected_observation(scenario)
        for scenario in CORE_SECURITY_MATRIX
    }

    for iteration in range(REPEATABILITY_ITERATIONS):
        for scenario in CORE_SECURITY_MATRIX:
            observed = SCENARIO_RUNNERS[scenario.scenario_id](
                tmp_path
                / f"iteration-{iteration:02d}"
                / scenario.scenario_id
            )
            assert observed == expected[scenario.scenario_id]


def test_matrix_uses_only_product_native_sources():
    source = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    import_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            import_roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            import_roots.add(node.module.split(".")[0])

    forbidden_fragments = (
        "tidemark-" + "spike",
        "tidemark_" + "spike",
        "all-things-agentic-" + "evaluation",
    )
    assert import_roots <= {
        "ast",
        "concurrent",
        "dataclasses",
        "pathlib",
        "typing",
        "pytest",
        "tidemark",
    }
    assert all(fragment not in source for fragment in forbidden_fragments)
    assert not any(
        root.endswith("sp" + "ike") for root in import_roots
    )
