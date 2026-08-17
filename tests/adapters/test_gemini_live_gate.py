import ast
import asyncio
import copy
from dataclasses import asdict, replace
import importlib.util
import json
from pathlib import Path
import socket
import sys
import warnings

import pytest
from pydantic import ValidationError

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from google.adk.agents.invocation_context import InvocationContext
    from google.adk.agents.run_config import StreamingMode
    from google.adk.events import Event
    from google.adk.flows.llm_flows.functions import (
        handle_function_call_list_async,
    )
    from google.adk.models.google_llm import Gemini
    from google.adk.sessions.in_memory_session_service import (
        InMemorySessionService,
    )
    from google.adk.sessions.session import Session
    from google.genai import types
    from google.genai._api_client import retry_args

from tidemark.adapters.gemini_live import (
    GEMINI_ACCESS_PATH,
    GEMINI_AUTH_METHOD,
    GEMINI_MODEL_DISPLAY_NAME,
    GEMINI_MODEL_IDENTIFIER,
    GEMINI_MODEL_STATUS,
    MAX_LIVE_MODEL_CALLS,
    MAX_LLM_CALLS_PER_CASE,
    MAX_OUTPUT_TOKENS,
    MAX_TOOL_CALLS_PER_CASE,
    PINNED_ADK_VERSION,
    PREVIOUS_MAX_OUTPUT_TOKENS,
    GeminiAccessVerification,
    GeminiCredentialEnvironment,
    GeminiLiveRequestBlocked,
    GeminiLiveRequestConfig,
    LiveModelCallBudget,
    assert_gemini_live_request_allowed,
    build_gemini_adk_run_plan,
    inspect_gemini_credential_environment,
)
from tidemark.adapters.google_adk import (
    ADK_DISTRIBUTION_VERSION,
    AdkSchedulePaymentCallbackAdapter,
)
from tidemark.payment.fixtures import (
    DEFAULT_INVOCATION_ID,
    RAW_SYNTHETIC_DESTINATION,
    build_synthetic_payment_fixture,
)


def _approved_verification():
    return GeminiAccessVerification(
        model_availability_verified=True,
        exact_model_identifier_verified=True,
        access_path_verified=True,
        pinned_adk_compatibility_verified=True,
        authentication_method_verified=True,
        quota_verified=True,
        billing_source_verified=True,
        funding_source_verified=True,
        sku_credit_coverage_verified=True,
        region_verified=True,
        zero_personal_spend_safe=True,
        approved_credentials_available=True,
        human_live_request_approved=True,
        billing_upgrade_required=False,
    )


def _approved_credential_environment():
    return GeminiCredentialEnvironment(
        gemini_api_key_present=True,
        google_api_key_present=False,
        vertex_path_enabled=False,
        enterprise_path_enabled=False,
    )


def _build_plan(
    tmp_path,
    verification=None,
    credential_environment=None,
    config=None,
):
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    adapter = AdkSchedulePaymentCallbackAdapter(fixture)
    plan = build_gemini_adk_run_plan(
        callback_adapter=adapter,
        verification=verification or _approved_verification(),
        credential_environment=(
            credential_environment or _approved_credential_environment()
        ),
        config=config,
    )
    return fixture, adapter, plan


class _SdkBoundaryIntercepted(Exception):
    pass


def _load_live_verifier():
    project_root = Path(__file__).parents[2]
    path = project_root / "scripts" / "verify_gemini_live.py"
    spec = importlib.util.spec_from_file_location(
        "tidemark_order_12_live_verifier",
        path,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _safe_live_result():
    def case(
        case_id,
        destination_class,
        decision,
        rule,
        callback,
        execution,
        count,
    ):
        return {
            "case": case_id,
            "model_request_attempted": True,
            "provider_response_received": True,
            "tool_call_proposed": True,
            "observed_model_arguments": {
                "argument_names": [
                    "amount_minor",
                    "currency",
                    "destination_reference",
                ],
                "argument_types": {
                    "amount_minor": "int",
                    "currency": "str",
                    "destination_reference": "str",
                },
                "amount_minor": 25000,
                "currency": "EUR",
                "destination_reference": destination_class,
            },
            "provider_error_class": None,
            "proposed_tool_name": "schedule_payment",
            "model_behavior": "TOOL_CALL_PROPOSED",
            "model_version": GEMINI_MODEL_IDENTIFIER,
            "finish_reasons": ["STOP"],
            "provider_error_codes": [],
            "response_part_kinds": ["FUNCTION_CALL", "FUNCTION_RESPONSE"],
            "candidate_count": None,
            "provider_response_event_count": 1,
            "function_call_parts_present": True,
            "usage": {
                "prompt_tokens": 10,
                "candidate_tokens": 5,
                "thought_tokens": 4,
                "total_tokens": 19,
            },
            "core_decision": decision,
            "primary_rule": rule,
            "callback_action": callback,
            "tool_body_entries": count,
            "trusted_adapter_entries": count,
            "payment_records": count,
            "execution": execution,
            "required_function_contract_satisfied": True,
            "case_verification_status": "CORE_MEDIATED",
        }

    benign = case(
        "benign",
        "TRUSTED_OPAQUE_REFERENCE",
        "ALLOW",
        "authorization.allow.v1",
        "RELEASE",
        "COMPLETED",
        1,
    )
    adversarial = case(
        "adversarial",
        "RAW_PROTECTED_VALUE",
        "DENY",
        "protected.raw_value_supplied.v1",
        "VETO",
        "NOT_RUN",
        0,
    )
    adversarial["attack_model_behavior"] = "RAW_SUPPLY_TRIGGERED"
    return {
        "access_gate": "PASS",
        "project": "synthetic-project-identifier-must-not-persist",
        "billing_tier": "Free tier",
        "access_path": GEMINI_ACCESS_PATH,
        "model_identifier": GEMINI_MODEL_IDENTIFIER,
        "quota": {"rpm": 5, "rpd": 20, "tpm_approx": 250000},
        "live_model_call_budget": 2,
        "live_model_calls_attempted": 2,
        "live_model_calls_completed": 2,
        "live_model_calls_failed": 0,
        "personal_spend_eur": 0,
        "raw_provider_output": "synthetic-provider-content-must-not-persist",
        "credential_marker": "synthetic-secret-must-not-persist",
        "request_id": "synthetic-request-id-must-not-persist",
        "cases": [benign, adversarial],
    }


async def _capture_sdk_request(
    tmp_path,
    monkeypatch,
    case_name,
    request_config=None,
):
    verifier = _load_live_verifier()
    fixture, _, plan = _build_plan(tmp_path, config=request_config)
    monkeypatch.setenv(
        "GEMINI_API_KEY",
        "synthetic-offline-sdk-boundary-not-a-credential",
    )
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_GENAI_USE_VERTEXAI", raising=False)
    monkeypatch.delenv("GOOGLE_GENAI_USE_ENTERPRISE", raising=False)

    def forbidden_socket_connect(*args, **kwargs):
        del args, kwargs
        raise AssertionError("offline request capture opened a network socket")

    monkeypatch.setattr(socket.socket, "connect", forbidden_socket_connect)
    prompt_factory = {
        "benign": verifier._benign_prompt,
        "adversarial": verifier._adversarial_prompt,
    }[case_name]
    captured = {}
    transport_attempts = []
    async_models = plan.agent.model.api_client.aio.models

    async def forbidden_transport(*args, **kwargs):
        transport_attempts.append((len(args), tuple(sorted(kwargs))))
        raise AssertionError("offline request capture reached network transport")

    async def intercept(*, model, contents, config=None):
        captured.update(model=model, contents=contents, config=config)
        raise _SdkBoundaryIntercepted()

    async_models._api_client.async_request = forbidden_transport
    async_models.generate_content = intercept
    session_service = InMemorySessionService()
    session = await session_service.create_session(
        app_name="tidemark-order-12-offline-capture",
        user_id="offline-reviewer",
        session_id=case_name,
    )
    prompt = prompt_factory(fixture)
    user_content = types.Content(
        role="user",
        parts=[types.Part(text=prompt)],
    )
    session.events.append(
        Event(
            author="user",
            content=user_content,
            invocation_id=DEFAULT_INVOCATION_ID.value,
        )
    )
    context = InvocationContext(
        invocation_id=DEFAULT_INVOCATION_ID.value,
        agent=plan.agent,
        session=session,
        session_service=session_service,
        user_content=user_content,
        run_config=plan.run_config,
    )

    with pytest.raises(_SdkBoundaryIntercepted):
        async for _ in plan.agent.run_async(context):
            pass

    assert transport_attempts == []
    from google.genai import _common, models

    serialized = models._GenerateContentParameters_to_mldev(
        async_models._api_client,
        captured,
    )
    serialized = _common.convert_to_dict(serialized)
    serialized = _common.encode_unserializable_types(serialized)
    return captured, serialized


def test_exact_model_and_request_configuration_has_no_fallback():
    config = GeminiLiveRequestConfig()

    assert GEMINI_MODEL_DISPLAY_NAME == "Gemini 3.6 Flash"
    assert GEMINI_MODEL_IDENTIFIER == "gemini-3.6-flash"
    assert GEMINI_MODEL_STATUS == "STABLE_GA"
    assert GEMINI_ACCESS_PATH == "gemini-developer-api"
    assert GEMINI_AUTH_METHOD == "gemini-api-key-environment"
    assert PINNED_ADK_VERSION == ADK_DISTRIBUTION_VERSION == "1.18.0"
    assert config.max_live_model_calls == MAX_LIVE_MODEL_CALLS == 2
    assert PREVIOUS_MAX_OUTPUT_TOKENS == 128
    assert config.max_output_tokens == MAX_OUTPUT_TOKENS == 512
    assert config.max_llm_calls_per_case == MAX_LLM_CALLS_PER_CASE == 1
    assert config.max_tool_calls_per_case == MAX_TOOL_CALLS_PER_CASE == 1
    assert config.text_only is True
    assert config.streaming is False
    assert config.automatic_retry is False
    assert config.fallback_model_identifier is None


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("model_identifier", "gemini-3.5-flash"),
        ("model_display_name", "Another model"),
        ("model_status", "PREVIEW"),
        ("provider_name", "another-provider"),
        ("access_path", "vertex-ai"),
        ("fallback_model_identifier", "gemini-3.5-flash"),
    ),
)
def test_model_provider_or_fallback_substitution_fails_closed(field, value):
    with pytest.raises(
        ValueError,
        match="substitution|fallback",
    ):
        GeminiLiveRequestConfig(**{field: value})


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("max_live_model_calls", 3, "call budget"),
        ("max_output_tokens", 513, "output token"),
        ("max_llm_calls_per_case", 2, "exactly one"),
        ("max_tool_calls_per_case", 2, "fan-out"),
        ("text_only", False, "text-only"),
        ("streaming", True, "text-only"),
        ("automatic_retry", True, "retry"),
    ),
)
def test_unbounded_or_cost_expanding_configuration_is_rejected(
    field,
    value,
    message,
):
    with pytest.raises(ValueError, match=message):
        GeminiLiveRequestConfig(**{field: value})


def test_incomplete_access_verification_blocks_with_all_missing_facts():
    verification = GeminiAccessVerification()

    with pytest.raises(GeminiLiveRequestBlocked) as caught:
        assert_gemini_live_request_allowed(
            config=GeminiLiveRequestConfig(),
            verification=verification,
            credential_environment=GeminiCredentialEnvironment(
                gemini_api_key_present=False,
                google_api_key_present=False,
                vertex_path_enabled=False,
                enterprise_path_enabled=False,
            ),
        )

    assert "quota_verified" in caught.value.reasons
    assert "billing_source_verified" in caught.value.reasons
    assert "funding_source_verified" in caught.value.reasons
    assert "sku_credit_coverage_verified" in caught.value.reasons
    assert "zero_personal_spend_safe" in caught.value.reasons
    assert "approved_gemini_api_key_missing" in caught.value.reasons


@pytest.mark.parametrize(
    "field",
    (
        "quota_verified",
        "billing_source_verified",
        "funding_source_verified",
        "sku_credit_coverage_verified",
        "zero_personal_spend_safe",
        "approved_credentials_available",
        "human_live_request_approved",
    ),
)
def test_each_cost_or_approval_prerequisite_blocks_before_provider_creation(
    tmp_path,
    monkeypatch,
    field,
):
    verification = replace(_approved_verification(), **{field: False})

    def forbidden_model_construction(*args, **kwargs):
        raise AssertionError("provider model constructed before live gate")

    monkeypatch.setattr(
        "tidemark.adapters.gemini_live.Gemini",
        forbidden_model_construction,
    )
    fixture = build_synthetic_payment_fixture(str(tmp_path))
    adapter = AdkSchedulePaymentCallbackAdapter(fixture)

    with pytest.raises(GeminiLiveRequestBlocked) as caught:
        build_gemini_adk_run_plan(
            callback_adapter=adapter,
            verification=verification,
            credential_environment=_approved_credential_environment(),
        )

    assert field in caught.value.reasons
    assert fixture.adapter.entry_count == 0
    assert fixture.payment_store.count == 0


def test_billing_upgrade_requirement_blocks_even_with_other_facts_verified():
    verification = replace(
        _approved_verification(),
        billing_upgrade_required=True,
    )

    with pytest.raises(GeminiLiveRequestBlocked) as caught:
        assert_gemini_live_request_allowed(
            config=GeminiLiveRequestConfig(),
            verification=verification,
            credential_environment=_approved_credential_environment(),
        )

    assert caught.value.reasons == ("billing_upgrade_required",)


def test_credential_probe_keeps_only_presence_and_provider_selection():
    probe = inspect_gemini_credential_environment(
        {
            "GEMINI_API_KEY": "synthetic-not-a-real-key",
            "GOOGLE_GENAI_USE_VERTEXAI": "false",
            "GOOGLE_GENAI_USE_ENTERPRISE": "0",
            "HACKATHON_PROMOTION_CODE": "synthetic-not-a-real-code",
        }
    )

    assert probe == _approved_credential_environment()
    assert "synthetic-not-a-real-key" not in repr(probe)
    assert "synthetic-not-a-real-code" not in repr(probe)
    assert set(asdict(probe)) == {
        "gemini_api_key_present",
        "google_api_key_present",
        "vertex_path_enabled",
        "enterprise_path_enabled",
    }


@pytest.mark.parametrize(
    ("probe", "reason"),
    (
        (
            GeminiCredentialEnvironment(False, False, False, False),
            "approved_gemini_api_key_missing",
        ),
        (
            GeminiCredentialEnvironment(True, True, False, False),
            "ambiguous_gemini_api_key_environment",
        ),
        (
            GeminiCredentialEnvironment(True, False, True, False),
            "vertex_provider_substitution_enabled",
        ),
        (
            GeminiCredentialEnvironment(True, False, False, True),
            "enterprise_provider_substitution_enabled",
        ),
    ),
)
def test_missing_credential_or_provider_path_substitution_blocks(probe, reason):
    with pytest.raises(GeminiLiveRequestBlocked) as caught:
        assert_gemini_live_request_allowed(
            config=GeminiLiveRequestConfig(),
            verification=_approved_verification(),
            credential_environment=probe,
        )

    assert reason in caught.value.reasons


def test_network_inert_adk_plan_is_exact_bounded_and_has_no_retry(tmp_path):
    _, _, plan = _build_plan(tmp_path)
    agent = plan.agent
    config = agent.generate_content_config

    assert type(agent.model) is Gemini
    assert agent.model.model == GEMINI_MODEL_IDENTIFIER
    assert agent.model.retry_options is None
    assert retry_args(agent.model.retry_options)[
        "stop"
    ].max_attempt_number == 1
    assert "api_client" not in agent.model.__dict__
    assert len(agent.tools) == 1
    assert agent.tools[0].name == "schedule_payment"
    assert len(agent.canonical_before_tool_callbacks) == 2
    assert len(agent.canonical_after_tool_callbacks) == 1
    assert agent.planner is None
    assert config.max_output_tokens == MAX_OUTPUT_TOKENS
    assert config.temperature is None
    assert config.top_p is None
    assert config.top_k is None
    assert config.candidate_count is None
    assert config.thinking_config is None
    assert config.automatic_function_calling.disable is True
    function_config = config.tool_config.function_calling_config
    assert function_config.mode is types.FunctionCallingConfigMode.ANY
    assert function_config.allowed_function_names == ["schedule_payment"]
    assert plan.run_config.max_llm_calls == MAX_LLM_CALLS_PER_CASE
    assert plan.run_config.streaming_mode is StreamingMode.NONE


@pytest.mark.parametrize("case_name", ("benign", "adversarial"))
@pytest.mark.parametrize(
    "max_output_tokens",
    (PREVIOUS_MAX_OUTPUT_TOKENS, MAX_OUTPUT_TOKENS),
)
def test_sdk_bound_request_requires_only_schedule_payment_offline(
    tmp_path,
    monkeypatch,
    case_name,
    max_output_tokens,
):
    captured, serialized = asyncio.run(
        _capture_sdk_request(
            tmp_path,
            monkeypatch,
            case_name,
            GeminiLiveRequestConfig(max_output_tokens=max_output_tokens),
        )
    )
    config = captured["config"]
    function_config = config.tool_config.function_calling_config
    declarations = tuple(
        declaration
        for tool in config.tools
        for declaration in (tool.function_declarations or ())
    )

    assert captured["model"] == GEMINI_MODEL_IDENTIFIER
    assert len(declarations) == 1
    assert declarations[0].name == "schedule_payment"
    assert tuple(declarations[0].parameters.required) == (
        "amount_minor",
        "currency",
        "destination_reference",
    )
    assert function_config.mode is types.FunctionCallingConfigMode.ANY
    assert function_config.allowed_function_names == ["schedule_payment"]
    assert config.automatic_function_calling.disable is True
    assert config.max_output_tokens == max_output_tokens
    assert config.thinking_config is None
    assert config.candidate_count is None
    assert len(captured["contents"]) == 1
    assert captured["contents"][0].role == "user"
    assert len(captured["contents"][0].parts) == 1
    assert captured["contents"][0].parts[0].text
    assert "Use schedule_payment exactly once" in str(
        config.system_instruction
    )
    assert serialized["_url"]["model"] == "models/gemini-3.6-flash"
    assert serialized["generationConfig"]["maxOutputTokens"] == (
        max_output_tokens
    )
    assert "thinkingConfig" not in serialized["generationConfig"]
    assert "candidateCount" not in serialized["generationConfig"]
    assert "automaticFunctionCalling" not in serialized["generationConfig"]
    assert len(serialized["contents"]) == 1
    assert len(serialized["tools"]) == 1
    serialized_declarations = serialized["tools"][0][
        "functionDeclarations"
    ]
    assert len(serialized_declarations) == 1
    assert serialized_declarations[0]["name"] == "schedule_payment"
    serialized_function_config = serialized["toolConfig"][
        "function_calling_config"
    ]
    assert serialized_function_config["mode"] == "ANY"
    assert serialized_function_config["allowed_function_names"] == [
        "schedule_payment"
    ]


def test_pinned_sdk_rejects_low_thinking_level_before_adk_or_provider():
    assert "thinking_level" not in types.ThinkingConfig.model_fields
    assert not hasattr(types, "ThinkingLevel")

    with pytest.raises(ValidationError) as caught:
        types.ThinkingConfig(thinking_level="low")

    assert tuple(error["type"] for error in caught.value.errors()) == (
        "extra_forbidden",
    )


def test_async_sdk_transport_used_by_adk_is_hard_blocked(
    tmp_path,
    monkeypatch,
):
    _, _, plan = _build_plan(tmp_path)
    monkeypatch.setenv(
        "GEMINI_API_KEY",
        "synthetic-offline-transport-block-not-a-credential",
    )
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_GENAI_USE_VERTEXAI", raising=False)
    monkeypatch.delenv("GOOGLE_GENAI_USE_ENTERPRISE", raising=False)

    def forbidden_socket_connect(*args, **kwargs):
        del args, kwargs
        raise AssertionError("offline transport probe opened a network socket")

    monkeypatch.setattr(socket.socket, "connect", forbidden_socket_connect)
    transport_attempts = []
    async_models = plan.agent.model.api_client.aio.models

    async def forbidden_transport(*args, **kwargs):
        transport_attempts.append((len(args), tuple(sorted(kwargs))))
        raise _SdkBoundaryIntercepted()

    async_models._api_client.async_request = forbidden_transport
    async_models._api_client.async_request_streamed = forbidden_transport

    async def exercise_adk_async_path():
        session_service = InMemorySessionService()
        session = await session_service.create_session(
            app_name="tidemark-order-12-network-block",
            user_id="offline-reviewer",
            session_id="async-transport",
        )
        user_content = types.Content(
            role="user",
            parts=[types.Part(text="synthetic offline transport probe")],
        )
        context = InvocationContext(
            invocation_id=DEFAULT_INVOCATION_ID.value,
            agent=plan.agent,
            session=session,
            session_service=session_service,
            user_content=user_content,
            run_config=plan.run_config,
        )
        async for _ in plan.agent.run_async(context):
            pass

    with pytest.raises(_SdkBoundaryIntercepted):
        asyncio.run(exercise_adk_async_path())

    assert len(transport_attempts) == 1


def test_live_verifier_preserves_non_call_diagnostics_without_content():
    verifier = _load_live_verifier()
    metadata = verifier._response_metadata(
        [
            Event(
                author="tidemark_order_12_gemini_agent",
                model_version=GEMINI_MODEL_IDENTIFIER,
                finish_reason=types.FinishReason.MAX_TOKENS,
                error_code="MAX_TOKENS",
                content=types.Content(
                    role="model",
                    parts=[types.Part(text="synthetic-provider-content")],
                ),
                usage_metadata=types.GenerateContentResponseUsageMetadata(
                    prompt_token_count=40,
                    candidates_token_count=0,
                    thoughts_token_count=128,
                    total_token_count=168,
                ),
            )
        ]
    )

    assert metadata == {
        "finish_reasons": ["MAX_TOKENS"],
        "provider_error_codes": ["MAX_TOKENS"],
        "response_part_kinds": ["TEXT"],
        "candidate_count": None,
        "provider_response_event_count": 1,
        "function_call_parts_present": False,
        "usage": {
            "prompt_tokens": 40,
            "candidate_tokens": 0,
            "thought_tokens": 128,
            "total_tokens": 168,
        },
    }
    assert "synthetic-provider-content" not in repr(metadata)


def test_live_verifier_reports_function_call_presence_without_arguments():
    verifier = _load_live_verifier()
    metadata = verifier._response_metadata(
        [
            Event(
                author="tidemark_order_12_gemini_agent",
                model_version=GEMINI_MODEL_IDENTIFIER,
                finish_reason=types.FinishReason.STOP,
                content=types.Content(
                    role="model",
                    parts=[
                        types.Part(
                            function_call=types.FunctionCall(
                                name="schedule_payment",
                                args={},
                            )
                        )
                    ],
                ),
            )
        ]
    )

    assert metadata["candidate_count"] is None
    assert metadata["provider_response_event_count"] == 1
    assert metadata["response_part_kinds"] == ["FUNCTION_CALL"]
    assert metadata["function_call_parts_present"] is True
    assert "schedule_payment" not in repr(metadata)


def test_one_model_turn_and_tool_fanout_guard_allow_only_one_payment(tmp_path):
    fixture, adapter, plan = _build_plan(tmp_path)
    agent = plan.agent
    tool = agent.tools[0]
    invocation_id = DEFAULT_INVOCATION_ID.value
    context = InvocationContext(
        invocation_id=invocation_id,
        agent=agent,
        session=Session(
            id="order-12-bounded-session",
            app_name="tidemark-order-12",
            user_id="synthetic-reviewer",
            state={},
        ),
        session_service=InMemorySessionService(),
        run_config=plan.run_config,
    )
    args = {
        "amount_minor": fixture.purchase_order.maximum_amount_minor,
        "currency": fixture.purchase_order.allowed_currencies[0],
        "destination_reference": fixture.destination_reference.value,
    }
    function_calls = [
        types.FunctionCall(
            id=f"order-12-function-{number}",
            name=tool.name,
            args=args,
        )
        for number in (1, 2)
    ]

    event = asyncio.run(
        handle_function_call_list_async(
            context,
            function_calls,
            {tool.name: tool},
        )
    )
    responses = tuple(
        response.response for response in event.get_function_responses()
    )

    assert plan.tool_call_attempt_count(invocation_id) == 2
    assert adapter.prepared_call_count == 1
    assert adapter.tool_body_entry_count == 1
    assert fixture.adapter.entry_count == 1
    assert fixture.payment_store.count == 1
    assert event.actions.skip_summarization is True
    assert sum(
        response.get("verification_status")
        == "TOOL_CALL_BUDGET_EXHAUSTED"
        for response in responses
    ) == 1


def test_live_model_call_budget_is_reserved_before_attempt_and_capped():
    budget = LiveModelCallBudget()

    assert budget.reserve() == 1
    assert budget.reserve() == 2
    assert budget.attempted == 2
    with pytest.raises(
        GeminiLiveRequestBlocked,
        match="live_model_call_budget_exhausted",
    ):
        budget.reserve()
    assert budget.attempted == 2


def test_order_12_configuration_and_plans_do_not_retain_secret_values(tmp_path):
    secret_marker = "synthetic-secret-material-not-real"
    promotion_marker = "synthetic-promotion-material-not-real"
    probe = inspect_gemini_credential_environment(
        {
            "GEMINI_API_KEY": secret_marker,
            "HACKATHON_PROMOTION_CODE": promotion_marker,
        }
    )
    _, _, plan = _build_plan(tmp_path, credential_environment=probe)
    config = GeminiLiveRequestConfig()
    verification = _approved_verification()
    budget = LiveModelCallBudget()
    public_views = (
        repr(config),
        repr(asdict(config)),
        repr(verification),
        repr(asdict(verification)),
        repr(probe),
        repr(asdict(probe)),
        repr(plan),
        repr(budget),
    )

    assert all(secret_marker not in view for view in public_views)
    assert all(promotion_marker not in view for view in public_views)


def test_framework_neutral_runtime_has_no_gemini_or_google_imports():
    runtime_root = Path(__file__).parents[2] / "src" / "tidemark" / "runtime"

    for path in runtime_root.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported_modules = tuple(
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        ) + tuple(
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
        assert all(
            not module.startswith(("google", "gemini"))
            for module in imported_modules
        )


def test_order_12_code_has_no_spike_dependency_or_network_entry_point():
    project_root = Path(__file__).parents[2]
    implementation = (
        project_root / "src" / "tidemark" / "adapters" / "gemini_live.py"
    )
    source = implementation.read_text(encoding="utf-8")
    imported_modules = tuple(
        alias.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Import)
        for alias in node.names
    ) + tuple(
        node.module or ""
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom)
    )

    assert "spike" not in source.lower()
    assert all(
        not module.startswith(("requests", "httpx", "urllib"))
        for module in imported_modules
    )


def test_future_live_evidence_envelope_is_canonical_stable_and_allowlisted():
    verifier = _load_live_verifier()
    result = _safe_live_result()

    first = verifier.build_live_evidence_envelope(result)
    second = verifier.build_live_evidence_envelope(copy.deepcopy(result))
    first_bytes = verifier.serialize_live_evidence_envelope(first)
    second_bytes = verifier.serialize_live_evidence_envelope(second)

    assert first == second
    assert first_bytes == second_bytes
    assert verifier.verify_live_evidence_envelope(first_bytes) == first
    assert first["schema_version"] == "tidemark.gemini-live-evidence.v1"
    assert first["evidence_kind"] == "FUTURE_LIVE_VERIFICATION"
    assert set(first) == {
        "schema_version",
        "evidence_kind",
        "model_identifier",
        "access_path",
        "framework_version",
        "sdk_version",
        "request_controls",
        "budget_observation",
        "cases",
        "envelope_digest",
    }
    assert first["request_controls"] == {
        "maximum_live_calls": 2,
        "maximum_llm_calls_per_case": 1,
        "maximum_tool_calls_per_case": 1,
        "maximum_output_tokens_per_call": 512,
        "function_calling_mode": "ANY",
        "allowed_functions": ["schedule_payment"],
        "streaming": False,
        "automatic_retry": False,
        "automatic_function_calling": False,
        "model_or_provider_fallback": False,
    }
    assert first["envelope_digest"].startswith("sha256:")
    assert len(first["envelope_digest"]) == 71


def test_future_live_evidence_excludes_raw_values_content_secrets_and_ids():
    verifier = _load_live_verifier()
    result = _safe_live_result()
    result["cases"][0]["raw_prompt"] = "synthetic-raw-prompt-must-not-persist"
    result["cases"][1]["raw_destination"] = RAW_SYNTHETIC_DESTINATION

    encoded = verifier.serialize_live_evidence_envelope(
        verifier.build_live_evidence_envelope(result)
    )
    rendered = encoded.decode("utf-8")

    for forbidden in (
        "synthetic-project-identifier-must-not-persist",
        "synthetic-provider-content-must-not-persist",
        "synthetic-secret-must-not-persist",
        "synthetic-request-id-must-not-persist",
        "synthetic-raw-prompt-must-not-persist",
        RAW_SYNTHETIC_DESTINATION,
        "amount_minor\":25000",
        "currency\":\"EUR",
        "request_id",
        "raw_provider_output",
    ):
        assert forbidden not in rendered
    assert "/Users/" not in rendered
    assert "/home/" not in rendered
    assert "GEMINI_API_KEY" not in rendered


@pytest.mark.parametrize(
    "mutation",
    (
        "unknown-field",
        "digest-mismatch",
        "unsupported-case-order",
    ),
)
def test_future_live_evidence_verifier_fails_closed_on_unsupported_input(mutation):
    verifier = _load_live_verifier()
    envelope = verifier.build_live_evidence_envelope(_safe_live_result())
    if mutation == "unknown-field":
        envelope["unexpected"] = True
    elif mutation == "digest-mismatch":
        envelope["envelope_digest"] = "sha256:" + "0" * 64
    else:
        envelope["cases"] = list(reversed(envelope["cases"]))
    encoded = verifier.canonical_json_bytes(envelope, trailing_newline=True)

    with pytest.raises(verifier.LiveEvidenceEnvelopeError):
        verifier.verify_live_evidence_envelope(encoded)


def test_future_live_evidence_verifier_rejects_malformed_and_noncanonical_bytes():
    verifier = _load_live_verifier()
    envelope = verifier.build_live_evidence_envelope(_safe_live_result())

    with pytest.raises(verifier.LiveEvidenceEnvelopeError):
        verifier.verify_live_evidence_envelope(b"{not-json}\n")
    with pytest.raises(verifier.LiveEvidenceEnvelopeError):
        verifier.verify_live_evidence_envelope(
            json.dumps(envelope, indent=2, sort_keys=True).encode("utf-8")
        )


def test_future_live_evidence_output_is_explicit_exclusive_and_non_overwriting(
    tmp_path,
):
    verifier = _load_live_verifier()
    target = tmp_path / "future-live-proof.json"
    encoded = verifier.serialize_live_evidence_envelope(
        verifier.build_live_evidence_envelope(_safe_live_result())
    )

    validated = verifier._validated_output_path(str(target))
    verifier._persist_live_evidence(validated, encoded)

    assert target.read_bytes() == encoded
    assert verifier.verify_live_evidence_envelope(target.read_bytes())
    with pytest.raises(verifier.LiveEvidenceEnvelopeError):
        verifier._validated_output_path(str(target))

    linked = tmp_path / "linked-proof.json"
    linked.symlink_to(target)
    with pytest.raises(verifier.LiveEvidenceEnvelopeError):
        verifier._validated_output_path(str(linked))


def test_future_live_evidence_default_cli_does_not_persist_or_call_provider(
    tmp_path,
    monkeypatch,
    capsys,
):
    verifier = _load_live_verifier()
    provider_calls = []

    async def offline_result():
        provider_calls.append("synthetic-offline-substitute")
        return _safe_live_result()

    monkeypatch.setattr(verifier, "_run_live_verification", offline_result)
    monkeypatch.setattr(sys, "argv", ["verify_gemini_live.py", "--approved-live-run"])
    monkeypatch.chdir(tmp_path)

    assert verifier.main() == 0
    assert provider_calls == ["synthetic-offline-substitute"]
    assert tuple(tmp_path.iterdir()) == ()
    assert "LIVE_EVIDENCE_WRITTEN" not in capsys.readouterr().out
