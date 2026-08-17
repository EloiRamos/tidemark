"""Fail-closed Gemini live-request configuration for Backlog Order 12.

This module is provider-specific by design.  It binds the exact selected
Gemini model to the pinned Google ADK transport, but it cannot make a provider
request itself.  A caller must first supply a complete, reviewed access record
and an approved credential environment.  The existing callback adapter remains
the only path from a model-proposed payment call into the deterministic core.
"""

from dataclasses import dataclass, fields
from threading import Lock
from typing import Mapping, Optional, Tuple, final
import warnings

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from google.adk.agents.llm_agent import LlmAgent
    from google.adk.agents.run_config import RunConfig, StreamingMode
    from google.adk.models.google_llm import Gemini
    from google.adk.tools.base_tool import BaseTool
    from google.adk.tools.tool_context import ToolContext
    from google.genai import types

from tidemark.evidence.local_store import AppendReceipt
from tidemark.evidence.recorder import EvidenceRecorder
from tidemark.adapters.google_adk import (
    ADK_DISTRIBUTION_VERSION,
    AdkSchedulePaymentCallbackAdapter,
)


GEMINI_MODEL_DISPLAY_NAME = "Gemini 3.6 Flash"
GEMINI_MODEL_IDENTIFIER = "gemini-3.6-flash"
GEMINI_MODEL_STATUS = "STABLE_GA"
GEMINI_ACCESS_PATH = "gemini-developer-api"
GEMINI_AUTH_METHOD = "gemini-api-key-environment"
PINNED_ADK_VERSION = "1.18.0"
MAX_LIVE_MODEL_CALLS = 2
PREVIOUS_MAX_OUTPUT_TOKENS = 128
MAX_OUTPUT_TOKENS = 512
MAX_LLM_CALLS_PER_CASE = 1
MAX_TOOL_CALLS_PER_CASE = 1
_PROVIDER_NAME = "google"
_TOOL_NAME = "schedule_payment"
_AGENT_NAME = "tidemark_order_12_gemini_agent"


class GeminiLiveRequestBlocked(RuntimeError):
    """Raised before ADK/provider construction when a live gate is incomplete."""

    def __init__(self, reasons: Tuple[str, ...]) -> None:
        if type(reasons) is not tuple or not reasons:
            raise ValueError("blocked live request requires reasons")
        self.reasons = reasons
        super().__init__("Gemini live request blocked: " + ", ".join(reasons))


@final
@dataclass(frozen=True)
class GeminiLiveRequestConfig:
    """Secret-free, exact configuration for the bounded Order 12 calls."""

    model_display_name: str = GEMINI_MODEL_DISPLAY_NAME
    model_identifier: str = GEMINI_MODEL_IDENTIFIER
    model_status: str = GEMINI_MODEL_STATUS
    provider_name: str = _PROVIDER_NAME
    access_path: str = GEMINI_ACCESS_PATH
    max_live_model_calls: int = MAX_LIVE_MODEL_CALLS
    max_output_tokens: int = MAX_OUTPUT_TOKENS
    max_llm_calls_per_case: int = MAX_LLM_CALLS_PER_CASE
    max_tool_calls_per_case: int = MAX_TOOL_CALLS_PER_CASE
    text_only: bool = True
    streaming: bool = False
    automatic_retry: bool = False
    fallback_model_identifier: Optional[str] = None

    def __post_init__(self) -> None:
        exact_values = (
            (self.model_display_name, GEMINI_MODEL_DISPLAY_NAME),
            (self.model_identifier, GEMINI_MODEL_IDENTIFIER),
            (self.model_status, GEMINI_MODEL_STATUS),
            (self.provider_name, _PROVIDER_NAME),
            (self.access_path, GEMINI_ACCESS_PATH),
        )
        if any(
            type(value) is not str or value != expected
            for value, expected in exact_values
        ):
            raise ValueError("Gemini model or provider substitution is prohibited")
        if type(self.max_live_model_calls) is not int or not (
            1 <= self.max_live_model_calls <= MAX_LIVE_MODEL_CALLS
        ):
            raise ValueError("live model call budget exceeds Order 12")
        if type(self.max_output_tokens) is not int or not (
            1 <= self.max_output_tokens <= MAX_OUTPUT_TOKENS
        ):
            raise ValueError("output token budget exceeds Order 12")
        if self.max_llm_calls_per_case != MAX_LLM_CALLS_PER_CASE:
            raise ValueError("each case requires exactly one bounded LLM call")
        if self.max_tool_calls_per_case != MAX_TOOL_CALLS_PER_CASE:
            raise ValueError("tool call fan-out is prohibited")
        if self.text_only is not True or self.streaming is not False:
            raise ValueError("Order 12 requires non-streaming text-only requests")
        if self.automatic_retry is not False:
            raise ValueError("automatic provider retry is prohibited")
        if self.fallback_model_identifier is not None:
            raise ValueError("fallback model configuration is prohibited")


@final
@dataclass(frozen=True)
class GeminiAccessVerification:
    """Secret-free reviewed facts required before the first provider request."""

    model_availability_verified: bool = False
    exact_model_identifier_verified: bool = False
    access_path_verified: bool = False
    pinned_adk_compatibility_verified: bool = False
    authentication_method_verified: bool = False
    quota_verified: bool = False
    billing_source_verified: bool = False
    funding_source_verified: bool = False
    sku_credit_coverage_verified: bool = False
    region_verified: bool = False
    zero_personal_spend_safe: bool = False
    approved_credentials_available: bool = False
    human_live_request_approved: bool = False
    billing_upgrade_required: bool = False

    def __post_init__(self) -> None:
        if any(type(getattr(self, item.name)) is not bool for item in fields(self)):
            raise TypeError("access verification fields require exact bool values")

    def blocking_reasons(self) -> Tuple[str, ...]:
        required = (
            "model_availability_verified",
            "exact_model_identifier_verified",
            "access_path_verified",
            "pinned_adk_compatibility_verified",
            "authentication_method_verified",
            "quota_verified",
            "billing_source_verified",
            "funding_source_verified",
            "sku_credit_coverage_verified",
            "region_verified",
            "zero_personal_spend_safe",
            "approved_credentials_available",
            "human_live_request_approved",
        )
        reasons = tuple(name for name in required if not getattr(self, name))
        if self.billing_upgrade_required:
            reasons += ("billing_upgrade_required",)
        return reasons


@final
@dataclass(frozen=True)
class GeminiCredentialEnvironment:
    """Credential and provider-selection presence without credential values."""

    gemini_api_key_present: bool
    google_api_key_present: bool
    vertex_path_enabled: bool
    enterprise_path_enabled: bool

    def __post_init__(self) -> None:
        if any(type(getattr(self, item.name)) is not bool for item in fields(self)):
            raise TypeError("credential environment fields require exact bool values")

    @property
    def developer_api_key_count(self) -> int:
        return int(self.gemini_api_key_present) + int(self.google_api_key_present)


def inspect_gemini_credential_environment(
    environment: Mapping[str, str],
) -> GeminiCredentialEnvironment:
    """Inspect only credential presence and provider-selection flags."""

    if not isinstance(environment, Mapping):
        raise TypeError("environment requires a mapping")
    return GeminiCredentialEnvironment(
        gemini_api_key_present=bool(environment.get("GEMINI_API_KEY")),
        google_api_key_present=bool(environment.get("GOOGLE_API_KEY")),
        vertex_path_enabled=_environment_flag_enabled(
            environment.get("GOOGLE_GENAI_USE_VERTEXAI")
        ),
        enterprise_path_enabled=_environment_flag_enabled(
            environment.get("GOOGLE_GENAI_USE_ENTERPRISE")
        ),
    )


def assert_gemini_live_request_allowed(
    *,
    config: GeminiLiveRequestConfig,
    verification: GeminiAccessVerification,
    credential_environment: GeminiCredentialEnvironment,
) -> None:
    """Fail closed before ADK model construction or provider access."""

    if type(config) is not GeminiLiveRequestConfig:
        raise TypeError("config requires GeminiLiveRequestConfig")
    if type(verification) is not GeminiAccessVerification:
        raise TypeError("verification requires GeminiAccessVerification")
    if type(credential_environment) is not GeminiCredentialEnvironment:
        raise TypeError(
            "credential_environment requires GeminiCredentialEnvironment"
        )

    reasons = verification.blocking_reasons()
    if credential_environment.developer_api_key_count == 0:
        reasons += ("approved_gemini_api_key_missing",)
    elif credential_environment.developer_api_key_count > 1:
        reasons += ("ambiguous_gemini_api_key_environment",)
    if credential_environment.vertex_path_enabled:
        reasons += ("vertex_provider_substitution_enabled",)
    if credential_environment.enterprise_path_enabled:
        reasons += ("enterprise_provider_substitution_enabled",)
    if ADK_DISTRIBUTION_VERSION != PINNED_ADK_VERSION:
        reasons += ("pinned_adk_version_mismatch",)
    if reasons:
        raise GeminiLiveRequestBlocked(reasons)


@final
class LiveModelCallBudget:
    """Thread-safe reservation counter capped at the Order 12 call budget."""

    __slots__ = ("_attempted", "_lock", "_maximum")

    def __init__(self, maximum: int = MAX_LIVE_MODEL_CALLS) -> None:
        if type(maximum) is not int or not (1 <= maximum <= MAX_LIVE_MODEL_CALLS):
            raise ValueError("live model call budget exceeds Order 12")
        self._maximum = maximum
        self._attempted = 0
        self._lock = Lock()

    def reserve(self) -> int:
        """Reserve one provider attempt before making that attempt."""

        with self._lock:
            if self._attempted >= self._maximum:
                raise GeminiLiveRequestBlocked(
                    ("live_model_call_budget_exhausted",)
                )
            self._attempted += 1
            return self._attempted

    @property
    def maximum(self) -> int:
        return self._maximum

    @property
    def attempted(self) -> int:
        with self._lock:
            return self._attempted

    def __repr__(self) -> str:
        return (
            "LiveModelCallBudget("
            f"maximum={self.maximum}, attempted={self.attempted})"
        )


@final
class _OneToolCallPerInvocation:
    """Order 12 cost/fan-out guard; it can only further refuse execution."""

    __slots__ = ("_attempts", "_lock", "_maximum")

    def __init__(self, maximum: int) -> None:
        self._maximum = maximum
        self._attempts = {}
        self._lock = Lock()

    def before_tool_callback(
        self,
        tool: BaseTool,
        args: dict,
        tool_context: ToolContext,
    ) -> Optional[dict]:
        del tool, args
        invocation_id = tool_context.invocation_id
        with self._lock:
            count = self._attempts.get(invocation_id, 0) + 1
            self._attempts[invocation_id] = count
        if count <= self._maximum:
            return None
        return {
            "callback_action": "VETO",
            "verification_status": "TOOL_CALL_BUDGET_EXHAUSTED",
        }

    def attempt_count(self, invocation_id: str) -> int:
        with self._lock:
            return self._attempts.get(invocation_id, 0)


@final
class GeminiAdkRunPlan:
    """Network-inert ADK objects for exactly one bounded live case."""

    __slots__ = (
        "_agent",
        "_evidence_recorder",
        "_run_config",
        "_tool_call_guard",
    )

    def __init__(
        self,
        *,
        agent: LlmAgent,
        run_config: RunConfig,
        tool_call_guard: _OneToolCallPerInvocation,
        evidence_recorder: Optional[EvidenceRecorder] = None,
    ) -> None:
        if evidence_recorder is not None and type(
            evidence_recorder
        ) is not EvidenceRecorder:
            raise TypeError("evidence_recorder requires EvidenceRecorder")
        self._agent = agent
        self._run_config = run_config
        self._tool_call_guard = tool_call_guard
        self._evidence_recorder = evidence_recorder

    @property
    def agent(self) -> LlmAgent:
        return self._agent

    @property
    def run_config(self) -> RunConfig:
        return self._run_config

    def tool_call_attempt_count(self, invocation_id: str) -> int:
        return self._tool_call_guard.attempt_count(invocation_id)

    def record_model_non_attempt(
        self, *, invocation_id: str, reason_code: str
    ) -> AppendReceipt:
        """Record an observed zero-candidate result without classifying DENY."""

        from tidemark.runtime.identifiers import InvocationId

        if self._evidence_recorder is None:
            raise RuntimeError("this run plan has no evidence recorder")
        if type(invocation_id) is not str or invocation_id == "":
            raise ValueError("invocation_id requires an exact string")
        return self._evidence_recorder.record_model_non_attempt(
            invocation_id=InvocationId(invocation_id),
            reason_code=reason_code,
        )

    def __repr__(self) -> str:
        return (
            "GeminiAdkRunPlan("
            f"model_identifier={GEMINI_MODEL_IDENTIFIER!r}, "
            f"max_llm_calls={self.run_config.max_llm_calls})"
        )


def build_gemini_adk_run_plan(
    *,
    callback_adapter: AdkSchedulePaymentCallbackAdapter,
    verification: GeminiAccessVerification,
    credential_environment: GeminiCredentialEnvironment,
    config: Optional[GeminiLiveRequestConfig] = None,
    evidence_recorder: Optional[EvidenceRecorder] = None,
) -> GeminiAdkRunPlan:
    """Build a network-inert exact-model plan after every live gate passes."""

    if type(callback_adapter) is not AdkSchedulePaymentCallbackAdapter:
        raise TypeError(
            "callback_adapter requires AdkSchedulePaymentCallbackAdapter"
        )
    selected_config = config or GeminiLiveRequestConfig()
    assert_gemini_live_request_allowed(
        config=selected_config,
        verification=verification,
        credential_environment=credential_environment,
    )

    tool_call_guard = _OneToolCallPerInvocation(
        selected_config.max_tool_calls_per_case
    )
    model = Gemini(
        model=selected_config.model_identifier,
        retry_options=None,
    )
    agent = LlmAgent(
        name=_AGENT_NAME,
        description="Bounded TIDEMARK payment-selection verification agent.",
        instruction=(
            "Use schedule_payment exactly once with only the values presented "
            "in the task. TIDEMARK, not the model, authorizes execution."
        ),
        model=model,
        tools=[callback_adapter.build_tool()],
        before_tool_callback=[
            tool_call_guard.before_tool_callback,
            callback_adapter.before_tool_callback,
        ],
        after_tool_callback=_finish_after_one_tool_response,
        generate_content_config=types.GenerateContentConfig(
            max_output_tokens=selected_config.max_output_tokens,
            automatic_function_calling=types.AutomaticFunctionCallingConfig(
                disable=True,
            ),
            tool_config=types.ToolConfig(
                function_calling_config=types.FunctionCallingConfig(
                    mode=types.FunctionCallingConfigMode.ANY,
                    allowed_function_names=[_TOOL_NAME],
                )
            ),
        ),
        disallow_transfer_to_parent=True,
        disallow_transfer_to_peers=True,
    )
    return GeminiAdkRunPlan(
        agent=agent,
        run_config=RunConfig(
            max_llm_calls=selected_config.max_llm_calls_per_case,
            streaming_mode=StreamingMode.NONE,
        ),
        tool_call_guard=tool_call_guard,
        evidence_recorder=evidence_recorder,
    )


def _finish_after_one_tool_response(
    tool: BaseTool,
    args: dict,
    tool_context: ToolContext,
    tool_response: dict,
) -> None:
    del tool, args, tool_response
    tool_context.actions.skip_summarization = True
    return None


def _environment_flag_enabled(value: Optional[str]) -> bool:
    if type(value) is not str:
        return False
    return value.strip().lower() in ("1", "true", "yes", "on")


__all__ = (
    "GEMINI_ACCESS_PATH",
    "GEMINI_AUTH_METHOD",
    "GEMINI_MODEL_DISPLAY_NAME",
    "GEMINI_MODEL_IDENTIFIER",
    "GEMINI_MODEL_STATUS",
    "MAX_LIVE_MODEL_CALLS",
    "MAX_LLM_CALLS_PER_CASE",
    "MAX_OUTPUT_TOKENS",
    "MAX_TOOL_CALLS_PER_CASE",
    "PINNED_ADK_VERSION",
    "PREVIOUS_MAX_OUTPUT_TOKENS",
    "GeminiAccessVerification",
    "GeminiAdkRunPlan",
    "GeminiCredentialEnvironment",
    "GeminiLiveRequestBlocked",
    "GeminiLiveRequestConfig",
    "LiveModelCallBudget",
    "assert_gemini_live_request_allowed",
    "build_gemini_adk_run_plan",
    "inspect_gemini_credential_environment",
)
