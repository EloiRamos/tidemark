"""Thin Google ADK callback transport for the bounded payment workflow.

Google ADK objects and pending argument containers end at this module.  The
callback translates their inert values into product-native contracts, invokes
the existing preparation pipeline, and uses ADK's callback override only as a
transport consequence of the core result.  The registered ADK tool body never
uses its raw framework arguments as execution authority; it releases only the
sealed ``PreparedToolCall`` previously issued by TIDEMARK.
"""

from dataclasses import dataclass
from enum import Enum, unique
from importlib.metadata import version
from threading import Lock
from typing import Dict, Optional, Tuple, final
import warnings

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from google.adk.tools.base_tool import BaseTool
    from google.adk.tools.function_tool import FunctionTool
    from google.adk.tools.tool_context import ToolContext

from tidemark.payment.fixtures import (
    DEFAULT_EVALUATION_TIME,
    DESTINATION_ARGUMENT_NAME,
    SyntheticPaymentFixture,
)
from tidemark.runtime.execution_gate import ExecutionResult
from tidemark.runtime.identifiers import (
    CallId,
    DecisionId,
    InvocationId,
    PreparedCallId,
    ReferenceId,
    RegistryVersion,
    ToolContractVersion,
    ToolId,
    TypeId,
)
from tidemark.runtime.policy_engine import (
    CallContext,
    CanonicalArgument,
    CanonicalCall,
    CanonicalSignatureArgument,
)
from tidemark.runtime.prepared_call import (
    PreparationRefusal,
    PreparedCallPipeline,
    PreparedToolCall,
)
from tidemark.runtime.vocabulary import (
    DecisionOutcome,
    EvaluationStage,
    RuleId,
)


ADK_DISTRIBUTION_VERSION = version("google-adk")
ADK_CALLBACK_ADAPTER_VERSION = "tidemark.google-adk.callback.v1"
_FRAMEWORK_NAME = "google-adk"
_CALL_ID_PREFIX = "adk-call:"
_DECISION_ID_PREFIX = "adk-decision:"
_EXPECTED_ARGUMENT_NAMES = (
    "amount_minor",
    "currency",
    DESTINATION_ARGUMENT_NAME,
)


@unique
class AdkCallbackAction(str, Enum):
    """The bounded framework consequence of one core preparation result."""

    VETO = "VETO"
    RELEASE = "RELEASE"


@final
@dataclass(frozen=True)
class AdkTransportMetadata:
    """Protected-value-free transport facts captured at callback intake."""

    framework_name: str
    framework_version: str
    callback_version: str
    tool_name: str
    invocation_correlation: str
    function_call_correlation: str
    pending_argument_names: Tuple[str, ...]
    pending_argument_types: Tuple[str, ...]

    def __post_init__(self) -> None:
        strings = (
            self.framework_name,
            self.framework_version,
            self.callback_version,
            self.tool_name,
            self.invocation_correlation,
            self.function_call_correlation,
        )
        if any(type(item) is not str or item == "" for item in strings):
            raise ValueError("ADK transport metadata requires exact strings")
        if type(self.pending_argument_names) is not tuple or type(
            self.pending_argument_types
        ) is not tuple:
            raise TypeError("pending argument metadata requires tuples")
        if len(self.pending_argument_names) != len(
            self.pending_argument_types
        ):
            raise ValueError("pending argument metadata lengths differ")
        if any(
            type(item) is not str or item == ""
            for item in self.pending_argument_names
            + self.pending_argument_types
        ):
            raise ValueError("pending argument metadata is invalid")


@final
@dataclass(frozen=True)
class AdkCallbackResult:
    """Minimal callback result without framework or execution authority."""

    action: AdkCallbackAction
    core_outcome: DecisionOutcome
    rule_id: RuleId
    evaluation_stage: EvaluationStage
    transport: AdkTransportMetadata
    prepared_call_id: Optional[PreparedCallId]

    def __post_init__(self) -> None:
        if type(self.action) is not AdkCallbackAction:
            raise TypeError("action requires AdkCallbackAction")
        if type(self.core_outcome) is not DecisionOutcome:
            raise TypeError("core_outcome requires DecisionOutcome")
        if type(self.rule_id) is not RuleId:
            raise TypeError("rule_id requires RuleId")
        if type(self.evaluation_stage) is not EvaluationStage:
            raise TypeError("evaluation_stage requires EvaluationStage")
        if type(self.transport) is not AdkTransportMetadata:
            raise TypeError("transport requires AdkTransportMetadata")
        if self.prepared_call_id is not None and type(
            self.prepared_call_id
        ) is not PreparedCallId:
            raise TypeError("prepared_call_id requires PreparedCallId or None")
        if self.action is AdkCallbackAction.RELEASE:
            if (
                self.core_outcome is not DecisionOutcome.ALLOW
                or self.rule_id is not RuleId.AUTHORIZATION_ALLOW
                or self.prepared_call_id is None
            ):
                raise ValueError("release requires a sealed core ALLOW")
        elif self.prepared_call_id is not None:
            raise ValueError("veto cannot expose a prepared call identity")


@final
class AdkSchedulePaymentCallbackAdapter:
    """Translate ADK pending calls and release only sealed payment calls."""

    __slots__ = (
        "_fixture",
        "_last_callback_result",
        "_last_execution_result",
        "_lock",
        "_prepared_call_count",
        "_released",
        "_released_call_count",
        "_tool_body_entry_count",
    )

    def __init__(self, fixture: SyntheticPaymentFixture) -> None:
        if type(fixture) is not SyntheticPaymentFixture:
            raise TypeError("fixture requires SyntheticPaymentFixture")
        self._fixture = fixture
        self._lock = Lock()
        self._released: Dict[
            Tuple[str, str], Tuple[PreparedToolCall, AdkTransportMetadata]
        ] = {}
        self._last_callback_result: Optional[AdkCallbackResult] = None
        self._last_execution_result: Optional[ExecutionResult] = None
        self._prepared_call_count = 0
        self._released_call_count = 0
        self._tool_body_entry_count = 0

    def build_tool(self) -> FunctionTool:
        """Create the sole ADK-visible ``schedule_payment`` function tool."""

        return FunctionTool(self.schedule_payment)

    def before_tool_callback(
        self,
        tool: BaseTool,
        args: dict,
        tool_context: ToolContext,
    ) -> Optional[dict]:
        """Veto REFUSAL/DENY or stage one core-sealed call for release."""

        transport = _transport_metadata(tool, args, tool_context)
        canonical_call = _canonical_call(
            fixture=self._fixture,
            tool_name=transport.tool_name,
            args=args,
        )
        call_context = _call_context(self._fixture, transport)
        self._fixture.evidence_recorder.record_callback_received(
            transport, call_context
        )
        preparation = PreparedCallPipeline(
            self._fixture.evidence_recorder
        ).prepare(
            snapshot=self._fixture.snapshot,
            canonical_call=canonical_call,
            call_context=call_context,
            trusted_store=self._fixture.reference_store,
            evaluation_time=DEFAULT_EVALUATION_TIME,
        )

        if type(preparation) is PreparationRefusal:
            decision = preparation.decision
            result = AdkCallbackResult(
                action=AdkCallbackAction.VETO,
                core_outcome=decision.outcome,
                rule_id=decision.primary_rule_id,
                evaluation_stage=decision.evaluation_stage,
                transport=transport,
                prepared_call_id=None,
            )
            with self._lock:
                self._last_callback_result = result
            self._fixture.evidence_recorder.record_callback_vetoed(
                transport, call_context, decision
            )
            return _veto_response(result)

        if type(preparation) is not PreparedToolCall:
            raise RuntimeError("core preparation returned an unsupported result")

        key = _release_key(transport)
        with self._lock:
            if key in self._released:
                raise RuntimeError("duplicate ADK function-call correlation")
            self._released[key] = (preparation, transport)
            self._prepared_call_count += 1
            result = AdkCallbackResult(
                action=AdkCallbackAction.RELEASE,
                core_outcome=DecisionOutcome.ALLOW,
                rule_id=RuleId.AUTHORIZATION_ALLOW,
                evaluation_stage=EvaluationStage.AUTHORIZATION,
                transport=transport,
                prepared_call_id=PreparedCallId(
                    preparation.prepared_call_id.value
                ),
            )
            self._last_callback_result = result
        self._fixture.evidence_recorder.record_callback_released(
            transport, call_context, preparation
        )
        return None

    def schedule_payment(
        self,
        amount_minor: int,
        currency: str,
        destination_reference: str,
        tool_context: ToolContext,
    ) -> dict:
        """Execute only the sealed TIDEMARK call prepared by the callback."""

        del amount_minor, currency, destination_reference
        key = (tool_context.invocation_id, tool_context.function_call_id or "")
        with self._lock:
            self._tool_body_entry_count += 1
            released = self._released.pop(key, None)
            prepared_call = released[0] if released is not None else None
            transport = released[1] if released is not None else None
            if prepared_call is not None:
                self._released_call_count += 1
        if type(prepared_call) is not PreparedToolCall:
            return {
                "execution_status": "REFUSED",
                "rule_id": RuleId.EXECUTION_PREPARED_CALL_INVALID.value,
            }

        self._fixture.evidence_recorder.record_callback_tool_entered(
            transport, prepared_call
        )

        execution = self._fixture.execution_gate.execute(prepared_call)
        with self._lock:
            self._last_execution_result = execution
        return {
            "execution_status": execution.status.value,
            "rule_id": (
                execution.rule_id.value
                if execution.rule_id is not None
                else None
            ),
            "execution_id": (
                execution.execution_id.value
                if execution.execution_id is not None
                else None
            ),
            "prepared_call_id": prepared_call.prepared_call_id.value,
        }

    @property
    def last_callback_result(self) -> AdkCallbackResult:
        with self._lock:
            result = self._last_callback_result
        if result is None:
            raise RuntimeError("no ADK callback result is available")
        return result

    @property
    def last_execution_result(self) -> ExecutionResult:
        with self._lock:
            result = self._last_execution_result
        if result is None:
            raise RuntimeError("no ADK execution result is available")
        return result

    @property
    def prepared_call_count(self) -> int:
        with self._lock:
            return self._prepared_call_count

    @property
    def released_call_count(self) -> int:
        with self._lock:
            return self._released_call_count

    @property
    def tool_body_entry_count(self) -> int:
        with self._lock:
            return self._tool_body_entry_count

    def __repr__(self) -> str:
        return (
            "AdkSchedulePaymentCallbackAdapter("
            f"callback_version={ADK_CALLBACK_ADAPTER_VERSION!r}, "
            f"prepared_call_count={self.prepared_call_count}, "
            f"tool_body_entry_count={self.tool_body_entry_count})"
        )


def _transport_metadata(
    tool: object,
    args: object,
    tool_context: object,
) -> AdkTransportMetadata:
    if type(tool_context) is not ToolContext:
        raise TypeError("tool_context requires exact ToolContext")
    tool_name = getattr(tool, "name", None)
    if type(tool_name) is not str or tool_name == "":
        raise ValueError("ADK tool name is unavailable")
    if type(args) is not dict:
        raise TypeError("ADK pending arguments require exact dict")
    if any(type(name) is not str or name == "" for name in args):
        raise ValueError("ADK pending argument names are invalid")
    if type(tool_context.invocation_id) is not str or not (
        tool_context.invocation_id
    ):
        raise ValueError("ADK invocation correlation is unavailable")
    if type(tool_context.function_call_id) is not str or not (
        tool_context.function_call_id
    ):
        raise ValueError("ADK function-call correlation is unavailable")
    names = tuple(args)
    return AdkTransportMetadata(
        framework_name=_FRAMEWORK_NAME,
        framework_version=ADK_DISTRIBUTION_VERSION,
        callback_version=ADK_CALLBACK_ADAPTER_VERSION,
        tool_name=tool_name,
        invocation_correlation=tool_context.invocation_id,
        function_call_correlation=tool_context.function_call_id,
        pending_argument_names=names,
        pending_argument_types=tuple(type(args[name]).__name__ for name in names),
    )


def _canonical_call(
    *,
    fixture: SyntheticPaymentFixture,
    tool_name: str,
    args: dict,
) -> CanonicalCall:
    policy = fixture.snapshot.tool_policies[0]
    signature = tuple(
        CanonicalSignatureArgument(
            name=item.name,
            required=item.required,
            type_id=TypeId(item.type_id.value),
        )
        for item in policy.signature
    )
    arguments = []
    for name in _EXPECTED_ARGUMENT_NAMES:
        if name not in args:
            continue
        value = _canonical_transport_value(fixture, name, args[name])
        arguments.append(CanonicalArgument(name=name, value=value))
    for name in sorted(set(args) - set(_EXPECTED_ARGUMENT_NAMES)):
        arguments.append(
            CanonicalArgument(
                name=name,
                value=_canonical_transport_value(fixture, name, args[name]),
            )
        )
    return CanonicalCall(
        tool_id=ToolId(tool_name),
        contract_version=ToolContractVersion(policy.contract_version.value),
        signature=signature,
        arguments=tuple(arguments),
    )


def _canonical_transport_value(
    fixture: SyntheticPaymentFixture,
    name: str,
    value: object,
) -> object:
    if (
        name == DESTINATION_ARGUMENT_NAME
        and type(value) is str
        and value == fixture.destination_reference.value
    ):
        return ReferenceId(value)
    if value is None or type(value) in (str, bool, int):
        return value
    return None


def _call_context(
    fixture: SyntheticPaymentFixture,
    transport: AdkTransportMetadata,
) -> CallContext:
    return CallContext(
        call_id=CallId(_CALL_ID_PREFIX + transport.function_call_correlation),
        decision_id=DecisionId(
            _DECISION_ID_PREFIX + transport.function_call_correlation
        ),
        invocation_id=InvocationId(transport.invocation_correlation),
        parent_id=fixture.purchase_order.parent_id,
        policy_version=fixture.snapshot.policy_version,
        registry_version=RegistryVersion(fixture.snapshot.registry_version.value),
    )


def _release_key(transport: AdkTransportMetadata) -> Tuple[str, str]:
    return (
        transport.invocation_correlation,
        transport.function_call_correlation,
    )


def _veto_response(result: AdkCallbackResult) -> dict:
    return {
        "callback_action": result.action.value,
        "core_outcome": result.core_outcome.value,
        "rule_id": result.rule_id.value,
        "evaluation_stage": result.evaluation_stage.value,
        "framework": result.transport.framework_name,
        "framework_version": result.transport.framework_version,
        "callback_version": result.transport.callback_version,
        "tool_name": result.transport.tool_name,
        "invocation_correlation": result.transport.invocation_correlation,
        "function_call_correlation": (
            result.transport.function_call_correlation
        ),
    }


__all__ = (
    "ADK_CALLBACK_ADAPTER_VERSION",
    "ADK_DISTRIBUTION_VERSION",
    "AdkCallbackAction",
    "AdkCallbackResult",
    "AdkSchedulePaymentCallbackAdapter",
    "AdkTransportMetadata",
)
