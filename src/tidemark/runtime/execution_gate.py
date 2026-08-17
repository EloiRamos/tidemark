"""Order 8 local execution gate for intact prepared capabilities only.

The gate validates public/private integrity, resolves one startup-bound trusted
adapter, requires durable pre-execution correlation, atomically consumes local
authority, invokes the adapter at most once, and persists one local outcome.
It performs no retry and never mutates the sealed policy decision.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hmac
from secrets import token_hex
from typing import Callable, Optional, Tuple, final

from tidemark.evidence.local_store import AppendReceipt
from tidemark.runtime.execution_binding import (
    _RuntimePrivateExecutionBinding,
    _atomic_consume_runtime_execution_binding,
    _validate_runtime_execution_binding,
)
from tidemark.runtime.identifiers import (
    AdapterId,
    AdapterVersion,
    CallId,
    DecisionId,
    ExecutionId,
    InvocationId,
    PolicyVersion,
    PreparedCallId,
    RegistryVersion,
    ToolId,
    TypeId,
)
from tidemark.runtime.minimal_evidence import (
    MINIMAL_EVIDENCE_PRODUCER_VERSION,
    MINIMAL_EVIDENCE_SCHEMA_VERSION,
    DurableAppendReceipt,
    ExecutionOutcomeRecord,
    MinimalPreExecutionEvidenceSink,
    PreExecutionCorrelationRecord,
)
from tidemark.runtime.prepared_call import (
    PreparedArgument,
    PreparedListValue,
    PreparedMappingEntry,
    PreparedMappingValue,
    PreparedToolCall,
    PreparedTupleValue,
    SingleUseExecutionCapability,
    _prepared_integrity_id,
    _prepared_value_valid,
)
from tidemark.runtime.vocabulary import (
    ArgumentRole,
    DecisionOutcome,
    ExecutionOutcome,
    PreparedCallState,
    RuleId,
)


_EXECUTION_ID_PREFIX = "execution_"
_PRE_RECORD_PREFIX = "pre-"
_OUTCOME_RECORD_PREFIX = "outcome-"
_PREPARED_INVALID = "prepared-call-invalid"
_PRE_EXECUTION_EVIDENCE_FAILED = "pre-execution-evidence-append-failed"
_OUTCOME_EVIDENCE_FAILED = "outcome-evidence-append-failed"
_ADAPTER_CONFIRMED_FAILURE = "adapter-confirmed-failure"
_UNCONFIRMED_EXTERNAL_RESULT = "unconfirmed-external-result"
_RESULT_FAILURE_FACTS = frozenset(
    {
        _PREPARED_INVALID,
        _PRE_EXECUTION_EVIDENCE_FAILED,
        _OUTCOME_EVIDENCE_FAILED,
        _ADAPTER_CONFIRMED_FAILURE,
        _UNCONFIRMED_EXTERNAL_RESULT,
    }
)


def _full_evidence_recorder_type() -> type:
    from tidemark.evidence.recorder import EvidenceRecorder as RecorderType

    return RecorderType


@final
@dataclass(frozen=True)
class AdapterArgument:
    """One detached immutable prepared argument delivered to the adapter."""

    name: str
    type_id: TypeId
    role: ArgumentRole
    value: object

    def __post_init__(self) -> None:
        if type(self.name) is not str or self.name == "":
            raise ValueError("adapter argument name is invalid")
        if type(self.type_id) is not TypeId:
            raise TypeError("adapter argument type_id is invalid")
        if type(self.role) is not ArgumentRole:
            raise TypeError("adapter argument role is invalid")
        if not _prepared_value_valid(self.value):
            raise TypeError("adapter argument value is invalid")


@final
@dataclass(frozen=True)
class AdapterInvocation:
    """Exact bounded payload and allowed correlations for one adapter entry."""

    tool_id: ToolId
    execution_id: ExecutionId
    prepared_call_id: PreparedCallId
    call_id: CallId
    decision_id: DecisionId
    invocation_id: InvocationId
    arguments: Tuple[AdapterArgument, ...]

    def __post_init__(self) -> None:
        expected = (
            (self.tool_id, ToolId),
            (self.execution_id, ExecutionId),
            (self.prepared_call_id, PreparedCallId),
            (self.call_id, CallId),
            (self.decision_id, DecisionId),
            (self.invocation_id, InvocationId),
        )
        if any(type(value) is not kind for value, kind in expected):
            raise TypeError("adapter invocation correlation is invalid")
        if type(self.arguments) is not tuple or any(
            type(argument) is not AdapterArgument for argument in self.arguments
        ):
            raise TypeError("adapter invocation arguments are invalid")


@final
@dataclass(frozen=True)
class AdapterInvocationResult:
    """Trusted adapter's confirmation classification without result payload."""

    succeeded: bool
    external_result_confirmed: bool

    def __post_init__(self) -> None:
        if type(self.succeeded) is not bool:
            raise TypeError("succeeded requires bool")
        if type(self.external_result_confirmed) is not bool:
            raise TypeError("external_result_confirmed requires bool")
        if self.succeeded and not self.external_result_confirmed:
            raise ValueError("success requires confirmed external result")

    @classmethod
    def confirmed_success(cls) -> "AdapterInvocationResult":
        return cls(succeeded=True, external_result_confirmed=True)

    @classmethod
    def confirmed_failure(cls) -> "AdapterInvocationResult":
        return cls(succeeded=False, external_result_confirmed=True)

    @classmethod
    def unconfirmed_failure(cls) -> "AdapterInvocationResult":
        return cls(succeeded=False, external_result_confirmed=False)


@final
@dataclass(frozen=True)
class ExecutionResult:
    """Immutable execution outcome separate from the policy decision."""

    status: ExecutionOutcome
    rule_id: Optional[RuleId]
    execution_id: Optional[ExecutionId]
    prepared_call_id: Optional[PreparedCallId]
    decision_id: Optional[DecisionId]
    external_result_confirmed: bool
    failure_fact: Optional[str]

    def __post_init__(self) -> None:
        if type(self.status) is not ExecutionOutcome:
            raise TypeError("status requires ExecutionOutcome")
        if self.rule_id is not None and type(self.rule_id) is not RuleId:
            raise TypeError("rule_id requires RuleId or None")
        for value, kind in (
            (self.execution_id, ExecutionId),
            (self.prepared_call_id, PreparedCallId),
            (self.decision_id, DecisionId),
        ):
            if value is not None and type(value) is not kind:
                raise TypeError("execution correlation has an invalid type")
        if type(self.external_result_confirmed) is not bool:
            raise TypeError("external_result_confirmed requires bool")
        if self.failure_fact is not None and (
            type(self.failure_fact) is not str
            or self.failure_fact not in _RESULT_FAILURE_FACTS
        ):
            raise ValueError("failure_fact is not allowlisted")


@dataclass(frozen=True)
class _TrustedAdapterBinding:
    tool_id: ToolId
    adapter_id: AdapterId
    adapter_version: AdapterVersion
    adapter: Callable[[AdapterInvocation], AdapterInvocationResult] = field(
        repr=False, compare=False
    )


@final
class TrustedAdapterRegistry:
    """Immutable one-tool in-process adapter binding configured at startup."""

    __slots__ = ("_binding",)

    def __init__(
        self,
        *,
        tool_id: ToolId,
        adapter_id: AdapterId,
        adapter_version: AdapterVersion,
        adapter: Callable[[AdapterInvocation], AdapterInvocationResult],
    ) -> None:
        if type(tool_id) is not ToolId:
            raise TypeError("tool_id requires ToolId")
        if type(adapter_id) is not AdapterId:
            raise TypeError("adapter_id requires AdapterId")
        if type(adapter_version) is not AdapterVersion:
            raise TypeError("adapter_version requires AdapterVersion")
        if not callable(adapter):
            raise TypeError("adapter requires trusted callable")
        self._binding = _TrustedAdapterBinding(
            tool_id=ToolId(tool_id.value),
            adapter_id=AdapterId(adapter_id.value),
            adapter_version=AdapterVersion(adapter_version.value),
            adapter=adapter,
        )

    def _resolve(
        self,
        tool_id: ToolId,
        adapter_id: AdapterId,
        adapter_version: AdapterVersion,
    ) -> Optional[_TrustedAdapterBinding]:
        binding = self._binding
        if (
            type(tool_id) is not ToolId
            or type(adapter_id) is not AdapterId
            or type(adapter_version) is not AdapterVersion
            or binding.tool_id != tool_id
            or binding.adapter_id != adapter_id
            or binding.adapter_version != adapter_version
        ):
            return None
        return binding

    def __repr__(self) -> str:
        return "TrustedAdapterRegistry(binding_count=1)"


@final
class ExecutionGate:
    """Perform the exact six-step local execution sequence once."""

    __slots__ = ("_adapter_registry", "_evidence_sink")

    def __init__(
        self,
        *,
        adapter_registry: TrustedAdapterRegistry,
        evidence_sink: object,
    ) -> None:
        if type(adapter_registry) is not TrustedAdapterRegistry:
            raise TypeError("adapter_registry requires trusted registry")
        if type(evidence_sink) not in (
            MinimalPreExecutionEvidenceSink,
            _full_evidence_recorder_type(),
        ):
            raise TypeError("evidence_sink requires trusted evidence sink")
        self._adapter_registry = adapter_registry
        self._evidence_sink = evidence_sink

    def execute(self, prepared_call: object) -> ExecutionResult:
        """Execute only an exact intact runtime-prepared capability."""

        # Step 1: exact public shape/integrity and private binding integrity.
        if not _prepared_call_public_integrity_valid(prepared_call):
            return self._refused(prepared_call, None, _PREPARED_INVALID)
        binding = _validate_runtime_execution_binding(prepared_call)
        if type(binding) is not _RuntimePrivateExecutionBinding:
            return self._refused(prepared_call, None, _PREPARED_INVALID)
        adapter_invocation_arguments = _detach_adapter_arguments(prepared_call)
        if adapter_invocation_arguments is None:
            return self._refused(prepared_call, None, _PREPARED_INVALID)

        # Step 2: resolve only the exact startup-bound trusted adapter.
        adapter_binding = self._adapter_registry._resolve(
            prepared_call.tool_id,
            prepared_call.adapter_id,
            prepared_call.adapter_version,
        )
        if adapter_binding is None:
            return self._refused(prepared_call, None, _PREPARED_INVALID)

        execution_id = ExecutionId(_EXECUTION_ID_PREFIX + token_hex(32))
        occurred_at = datetime.now(timezone.utc)

        # Step 3: require a durable pre-execution correlation receipt.
        pre_record = _pre_execution_record(
            prepared_call, execution_id, occurred_at
        )
        try:
            pre_receipt = self._evidence_sink.append_pre_execution(pre_record)
        except Exception:
            pre_receipt = None
        if type(pre_receipt) is not DurableAppendReceipt:
            return self._refused(
                prepared_call,
                execution_id,
                _PRE_EXECUTION_EVIDENCE_FAILED,
            )

        # Step 4: one local all-or-none capability/reference transition.
        consumption = _atomic_consume_runtime_execution_binding(
            prepared_call, binding
        )
        if consumption == "REPLAY":
            if type(self._evidence_sink) is _full_evidence_recorder_type():
                try:
                    self._evidence_sink.record_execution_replay_rejected(
                        prepared_call, execution_id
                    )
                except Exception:
                    pass
            return ExecutionResult(
                status=ExecutionOutcome.REPLAY_REJECTED,
                rule_id=RuleId.EXECUTION_REPLAY_REJECTED,
                execution_id=execution_id,
                prepared_call_id=PreparedCallId(
                    prepared_call.prepared_call_id.value
                ),
                decision_id=DecisionId(prepared_call.decision_id.value),
                external_result_confirmed=False,
                failure_fact=None,
            )
        if consumption != "CONSUMED":
            return self._refused(
                prepared_call, execution_id, _PREPARED_INVALID
            )

        if type(self._evidence_sink) is _full_evidence_recorder_type():
            try:
                start_receipt = self._evidence_sink.record_execution_started(
                    prepared_call, execution_id, occurred_at
                )
            except Exception:
                start_receipt = None
            if type(start_receipt) is not AppendReceipt:
                return _execution_result(
                    prepared_call=prepared_call,
                    execution_id=execution_id,
                    status=ExecutionOutcome.FAILED,
                    external_result_confirmed=False,
                    failure_fact=_OUTCOME_EVIDENCE_FAILED,
                )

        invocation = AdapterInvocation(
            tool_id=ToolId(prepared_call.tool_id.value),
            execution_id=ExecutionId(execution_id.value),
            prepared_call_id=PreparedCallId(
                prepared_call.prepared_call_id.value
            ),
            call_id=CallId(prepared_call.call_id.value),
            decision_id=DecisionId(prepared_call.decision_id.value),
            invocation_id=InvocationId(prepared_call.invocation_id.value),
            arguments=adapter_invocation_arguments,
        )

        # Step 5: enter the selected adapter exactly once, outside state locks.
        try:
            adapter_result = adapter_binding.adapter(invocation)
        except BaseException:
            adapter_result = AdapterInvocationResult.unconfirmed_failure()
        if type(adapter_result) is not AdapterInvocationResult:
            adapter_result = AdapterInvocationResult.unconfirmed_failure()

        if adapter_result.succeeded:
            candidate_status = ExecutionOutcome.COMPLETED
            failure_fact = None
        else:
            candidate_status = ExecutionOutcome.FAILED
            failure_fact = (
                _ADAPTER_CONFIRMED_FAILURE
                if adapter_result.external_result_confirmed
                else _UNCONFIRMED_EXTERNAL_RESULT
            )

        # Step 6: persist and return one immutable local execution outcome.
        outcome_record = _execution_outcome_record(
            prepared_call=prepared_call,
            execution_id=execution_id,
            execution_status=candidate_status,
            external_result_confirmed=(
                adapter_result.external_result_confirmed
            ),
            failure_fact=failure_fact,
        )
        try:
            if type(self._evidence_sink) is _full_evidence_recorder_type():
                outcome_receipt = self._evidence_sink.record_execution_outcome(
                    prepared_call=prepared_call,
                    execution_id=execution_id,
                    execution_status=candidate_status,
                    external_result_confirmed=(
                        adapter_result.external_result_confirmed
                    ),
                    failure_fact=failure_fact,
                )
                outcome_persisted = type(outcome_receipt) is AppendReceipt
            else:
                outcome_receipt = self._evidence_sink.append_execution_outcome(
                    outcome_record
                )
                outcome_persisted = type(outcome_receipt) is DurableAppendReceipt
        except Exception:
            outcome_persisted = False
        if not outcome_persisted:
            return _execution_result(
                prepared_call=prepared_call,
                execution_id=execution_id,
                status=ExecutionOutcome.FAILED,
                external_result_confirmed=(
                    adapter_result.external_result_confirmed
                ),
                failure_fact=_OUTCOME_EVIDENCE_FAILED,
            )
        return _execution_result(
            prepared_call=prepared_call,
            execution_id=execution_id,
            status=candidate_status,
            external_result_confirmed=(
                adapter_result.external_result_confirmed
            ),
            failure_fact=failure_fact,
        )

    def _refused(
        self,
        prepared_call: object,
        execution_id: Optional[ExecutionId],
        failure_fact: str,
    ) -> ExecutionResult:
        if type(self._evidence_sink) is _full_evidence_recorder_type():
            try:
                self._evidence_sink.record_execution_refused(
                    prepared_call, execution_id, failure_fact
                )
            except Exception:
                pass
        return _refused(prepared_call, execution_id, failure_fact)

    def __repr__(self) -> str:
        return "ExecutionGate(local_at_most_once=True)"


def _prepared_call_public_integrity_valid(prepared_call: object) -> bool:
    if type(prepared_call) is not PreparedToolCall:
        return False
    try:
        identifiers = (
            (prepared_call.prepared_call_id, PreparedCallId),
            (prepared_call.call_id, CallId),
            (prepared_call.decision_id, DecisionId),
            (prepared_call.invocation_id, InvocationId),
            (prepared_call.tool_id, ToolId),
            (prepared_call.policy_version, PolicyVersion),
            (prepared_call.registry_version, RegistryVersion),
            (prepared_call.adapter_id, AdapterId),
            (prepared_call.adapter_version, AdapterVersion),
        )
        if any(
            type(value) is not kind
            or type(value.value) is not str
            or value.value == ""
            for value, kind in identifiers
        ):
            return False
        if type(prepared_call.arguments) is not tuple or any(
            type(argument) is not PreparedArgument
            for argument in prepared_call.arguments
        ):
            return False
        if len({argument.name for argument in prepared_call.arguments}) != len(
            prepared_call.arguments
        ):
            return False
        if (
            type(prepared_call.execution_capability)
            is not SingleUseExecutionCapability
            or prepared_call.execution_capability.state
            is not PreparedCallState.UNUSED
        ):
            return False
        expected = _prepared_integrity_id(
            prepared_call_id=prepared_call.prepared_call_id,
            call_id=prepared_call.call_id,
            decision_id=prepared_call.decision_id,
            invocation_id=prepared_call.invocation_id,
            tool_id=prepared_call.tool_id,
            policy_version=prepared_call.policy_version,
            registry_version=prepared_call.registry_version,
            arguments=prepared_call.arguments,
            adapter_id=prepared_call.adapter_id,
            adapter_version=prepared_call.adapter_version,
            execution_capability=prepared_call.execution_capability,
        )
        return type(prepared_call.integrity_id) is str and hmac.compare_digest(
            prepared_call.integrity_id, expected
        )
    except (AttributeError, TypeError, ValueError, RuntimeError):
        return False


def _detach_adapter_arguments(
    prepared_call: PreparedToolCall,
) -> Optional[Tuple[AdapterArgument, ...]]:
    try:
        return tuple(
            AdapterArgument(
                name=argument.name,
                type_id=TypeId(argument.type_id.value),
                role=argument.role,
                value=_copy_prepared_value(
                    argument._copy_value_for_runtime()
                ),
            )
            for argument in prepared_call.arguments
        )
    except (AttributeError, TypeError, ValueError, RuntimeError):
        return None


def _copy_prepared_value(value: object) -> object:
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is PreparedListValue:
        return PreparedListValue(
            tuple(_copy_prepared_value(item) for item in value.items)
        )
    if type(value) is PreparedTupleValue:
        return PreparedTupleValue(
            tuple(_copy_prepared_value(item) for item in value.items)
        )
    if type(value) is PreparedMappingValue:
        return PreparedMappingValue(
            tuple(
                PreparedMappingEntry(
                    entry.key, _copy_prepared_value(entry.value)
                )
                for entry in value.entries
            )
        )
    raise TypeError("adapter payload contains an unsupported value")


def _pre_execution_record(
    prepared_call: PreparedToolCall,
    execution_id: ExecutionId,
    occurred_at: datetime,
) -> PreExecutionCorrelationRecord:
    return PreExecutionCorrelationRecord(
        schema_version=MINIMAL_EVIDENCE_SCHEMA_VERSION,
        record_id=_PRE_RECORD_PREFIX + execution_id.value,
        execution_id=ExecutionId(execution_id.value),
        prepared_call_id=PreparedCallId(prepared_call.prepared_call_id.value),
        call_id=CallId(prepared_call.call_id.value),
        decision_id=DecisionId(prepared_call.decision_id.value),
        invocation_id=InvocationId(prepared_call.invocation_id.value),
        tool_id=ToolId(prepared_call.tool_id.value),
        policy_version=PolicyVersion(prepared_call.policy_version.value),
        registry_version=RegistryVersion(prepared_call.registry_version.value),
        adapter_id=AdapterId(prepared_call.adapter_id.value),
        adapter_version=AdapterVersion(prepared_call.adapter_version.value),
        public_integrity_id=prepared_call.integrity_id,
        authorization_outcome=DecisionOutcome.ALLOW,
        authorization_rule_id=RuleId.AUTHORIZATION_ALLOW,
        occurred_at=occurred_at,
        producer_version=MINIMAL_EVIDENCE_PRODUCER_VERSION,
    )


def _execution_outcome_record(
    *,
    prepared_call: PreparedToolCall,
    execution_id: ExecutionId,
    execution_status: ExecutionOutcome,
    external_result_confirmed: bool,
    failure_fact: Optional[str],
) -> ExecutionOutcomeRecord:
    return ExecutionOutcomeRecord(
        schema_version=MINIMAL_EVIDENCE_SCHEMA_VERSION,
        record_id=_OUTCOME_RECORD_PREFIX + execution_id.value,
        execution_id=ExecutionId(execution_id.value),
        prepared_call_id=PreparedCallId(prepared_call.prepared_call_id.value),
        call_id=CallId(prepared_call.call_id.value),
        decision_id=DecisionId(prepared_call.decision_id.value),
        invocation_id=InvocationId(prepared_call.invocation_id.value),
        tool_id=ToolId(prepared_call.tool_id.value),
        policy_version=PolicyVersion(prepared_call.policy_version.value),
        registry_version=RegistryVersion(prepared_call.registry_version.value),
        adapter_id=AdapterId(prepared_call.adapter_id.value),
        adapter_version=AdapterVersion(prepared_call.adapter_version.value),
        public_integrity_id=prepared_call.integrity_id,
        authorization_outcome=DecisionOutcome.ALLOW,
        authorization_rule_id=RuleId.AUTHORIZATION_ALLOW,
        execution_status=execution_status,
        external_result_confirmed=external_result_confirmed,
        masked_failure_fact=failure_fact,
        occurred_at=datetime.now(timezone.utc),
        producer_version=MINIMAL_EVIDENCE_PRODUCER_VERSION,
    )


def _refused(
    prepared_call: object,
    execution_id: Optional[ExecutionId],
    failure_fact: str,
) -> ExecutionResult:
    return ExecutionResult(
        status=ExecutionOutcome.REFUSED,
        rule_id=RuleId.EXECUTION_PREPARED_CALL_INVALID,
        execution_id=(
            ExecutionId(execution_id.value)
            if type(execution_id) is ExecutionId
            else None
        ),
        prepared_call_id=(
            PreparedCallId(prepared_call.prepared_call_id.value)
            if type(prepared_call) is PreparedToolCall
            and type(prepared_call.prepared_call_id) is PreparedCallId
            else None
        ),
        decision_id=(
            DecisionId(prepared_call.decision_id.value)
            if type(prepared_call) is PreparedToolCall
            and type(prepared_call.decision_id) is DecisionId
            else None
        ),
        external_result_confirmed=False,
        failure_fact=failure_fact,
    )


def _execution_result(
    *,
    prepared_call: PreparedToolCall,
    execution_id: ExecutionId,
    status: ExecutionOutcome,
    external_result_confirmed: bool,
    failure_fact: Optional[str],
) -> ExecutionResult:
    return ExecutionResult(
        status=status,
        rule_id=None,
        execution_id=ExecutionId(execution_id.value),
        prepared_call_id=PreparedCallId(prepared_call.prepared_call_id.value),
        decision_id=DecisionId(prepared_call.decision_id.value),
        external_result_confirmed=external_result_confirmed,
        failure_fact=failure_fact,
    )


__all__ = (
    "AdapterArgument",
    "AdapterInvocation",
    "AdapterInvocationResult",
    "ExecutionGate",
    "ExecutionResult",
    "TrustedAdapterRegistry",
)
