"""LLM provider tests: interface, JSON validation, error mapping (spec §14-§17)."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from backend.module2_chain.app.config import ConfigError
from backend.module2_chain.llm.base import (
    LLMAuthError,
    LLMInvalidJSONError,
    LLMProvider,
    LLMProviderError,
    LLMQuotaError,
    LLMRateLimitError,
    LLMSchemaError,
    LLMTimeoutError,
    extract_json_object,
)
from backend.module2_chain.llm.client import HTTPXChatTransport
from backend.module2_chain.llm.deepseek import DeepSeekProvider
from backend.module2_chain.llm.factory import CloudProviderChain, create_llm_provider
from backend.module2_chain.llm.finetuned import FineTunedModelProvider
from backend.module2_chain.llm.mock import MockLLMProvider, NullLLMProvider
from backend.module2_chain.llm.schemas import AttackAnalysisRequest, LLMAttackAnalysis


def _request() -> AttackAnalysisRequest:
    return AttackAnalysisRequest(
        task_id="task_1",
        candidate_id="cand_1",
        prompt_version="attack_analysis.v1",
        system_prompt="system",
        user_prompt="user",
        evidence_event_ids=["evt_1", "evt_2"],
        allowed_tactics=["TA0043"],
        allowed_techniques=["T1595"],
        metadata={"attacker_ips": ["10.0.0.8"], "victim_ips": ["10.0.0.12"]},
    )


VALID_ANALYSIS = {
    "candidate_id": "cand_1",
    "verdict": "attack",
    "attack_summary": "Scanning followed by exploitation.",
    "attacker_assessment": "Single source, opportunistic behaviour.",
    "victim_assessment": "One exposed service.",
    "stages": [
        {
            "stage_index": 1,
            "tactic": "TA0043",
            "technique": "T1595",
            "narrative": "Port sweep observed.",
            "evidence_event_ids": ["evt_1"],
            "confidence": 0.8,
        }
    ],
    "threat_entities": [],
    "uncertainties": [],
    "confidence": 0.75,
}


def _chat_response(content: str, *, status: int = 200) -> httpx.Response:
    return httpx.Response(
        status,
        json={
            "id": "chatcmpl-1",
            "model": "deepseek-chat",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 120, "completion_tokens": 42, "total_tokens": 162},
        },
    )


def _provider(config, handler) -> DeepSeekProvider:
    """DeepSeek provider wired to an ``httpx.MockTransport`` (no network)."""

    settings = config.llm.providers.deepseek.model_copy(
        update={"api_key": SecretStr("test-key")}
    )
    transport = HTTPXChatTransport(
        base_url=settings.base_url,
        api_key="test-key",
        transport=httpx.MockTransport(handler),
    )
    return DeepSeekProvider(settings, config.llm, transport=transport)


async def test_deepseek_returns_validated_analysis(config) -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization")
        captured["body"] = json.loads(request.content)
        return _chat_response(json.dumps(VALID_ANALYSIS))

    provider = _provider(config, handler)
    analysis = await provider.analyze_attack_scenario(_request())
    assert isinstance(analysis, LLMAttackAnalysis)
    assert analysis.candidate_id == "cand_1"
    assert analysis.provider == "deepseek"
    assert analysis.usage is not None
    assert analysis.usage.input_tokens == 120
    assert analysis.usage.output_tokens == 42
    assert analysis.usage.latency_ms >= 0
    assert captured["url"].endswith("/chat/completions")
    assert captured["auth"] == "Bearer test-key"
    assert captured["body"]["response_format"] == {"type": "json_object"}
    assert captured["body"]["model"] == config.llm.providers.deepseek.model


async def test_deepseek_accepts_fenced_json(config) -> None:
    fenced = f"```json\n{json.dumps(VALID_ANALYSIS)}\n```"
    provider = _provider(config, lambda request: _chat_response(fenced))
    analysis = await provider.analyze_attack_scenario(_request())
    assert analysis.stages[0].tactic == "TA0043"


async def test_deepseek_missing_api_key_raises_auth_error(config) -> None:
    settings = config.llm.providers.deepseek.model_copy(
        update={"api_key": None, "api_key_env": "MISSING_KEY_ENV_VAR_XYZ"}
    )
    provider = DeepSeekProvider(
        settings,
        config.llm,
        transport=HTTPXChatTransport(
            base_url=settings.base_url,
            api_key=None,
            transport=httpx.MockTransport(lambda request: _chat_response("{}")),
        ),
    )
    assert provider.enabled is False
    with pytest.raises(LLMAuthError):
        await provider.analyze_attack_scenario(_request())


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (401, {"error": "bad key"}, LLMAuthError),
        (403, {"error": "forbidden"}, LLMAuthError),
        (402, {"error": "payment"}, LLMQuotaError),
        (429, {"error": "rate limit exceeded"}, LLMRateLimitError),
        (429, {"error": "insufficient balance"}, LLMQuotaError),
        (503, {"error": "unavailable"}, LLMProviderError),
    ],
)
async def test_http_errors_are_mapped(config, status: int, body: dict, expected: type) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=body)

    provider = _provider(config, handler)
    with pytest.raises(expected):
        await provider.analyze_attack_scenario(_request())


async def test_timeout_and_network_errors_are_mapped(config) -> None:
    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("too slow", request=request)

    with pytest.raises(LLMTimeoutError):
        await _provider(config, timeout_handler).analyze_attack_scenario(_request())

    def network_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with pytest.raises(LLMProviderError):
        await _provider(config, network_handler).analyze_attack_scenario(_request())


async def test_invalid_json_and_schema_errors(config) -> None:
    with pytest.raises(LLMInvalidJSONError):
        await _provider(
            config, lambda request: _chat_response("I think this is an attack.")
        ).analyze_attack_scenario(_request())

    with pytest.raises(LLMSchemaError):
        await _provider(
            config,
            lambda request: _chat_response(json.dumps({"stages": [{"stage_index": 1}]})),
        ).analyze_attack_scenario(_request())


def test_json_extraction_helper() -> None:
    assert extract_json_object('{"a": 1}') == {"a": 1}
    assert extract_json_object('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json_object('Here you go: {"a": 1} — done') == {"a": 1}
    with pytest.raises(LLMInvalidJSONError):
        extract_json_object("no json here")
    with pytest.raises(LLMInvalidJSONError):
        extract_json_object("")


async def test_mock_provider_uses_fixture_and_interpolates(config, mock_provider) -> None:
    request = _request()
    analysis = await mock_provider.analyze_attack_scenario(request)
    assert analysis.candidate_id == "cand_1"
    assert analysis.stages
    assert analysis.stages[0].evidence_event_ids == ["evt_1", "evt_2"]
    assert analysis.usage is not None and analysis.usage.input_tokens
    assert mock_provider.calls == 1


async def test_mock_provider_failure_modes(config, mock_fixture) -> None:
    settings = config.llm.providers.mock
    cases = {
        "timeout": LLMTimeoutError,
        "provider_error": LLMProviderError,
        "invalid_json": LLMInvalidJSONError,
        "schema_error": LLMSchemaError,
    }
    for mode, expected in cases.items():
        provider = MockLLMProvider(
            settings.model_copy(update={"failure_mode": mode}),
            config.llm,
            fixture=mock_fixture,
        )
        with pytest.raises(expected):
            await provider.analyze_attack_scenario(_request())


async def test_mock_provider_default_answer_without_fixture(config) -> None:
    provider = MockLLMProvider(
        config.llm.providers.mock, config.llm, fixture_path="/nonexistent/fixture.json"
    )
    analysis = await provider.analyze_attack_scenario(_request())
    assert analysis.candidate_id == "cand_1"
    assert analysis.stages
    assert any("MockLLMProvider" in item for item in analysis.uncertainties)


async def test_null_provider_is_disabled(config) -> None:
    provider = NullLLMProvider()
    assert provider.enabled is False
    with pytest.raises(LLMProviderError):
        await provider.analyze_attack_scenario(_request())


async def test_finetuned_provider_reuses_the_same_interface(config) -> None:
    settings = config.llm.providers.finetuned.model_copy(
        update={"base_url": "http://model-host:8000/v1", "model": "sec-llm-v1"}
    )
    transport = HTTPXChatTransport(
        base_url=settings.base_url,
        api_key=None,
        transport=httpx.MockTransport(lambda request: _chat_response(json.dumps(VALID_ANALYSIS))),
    )
    provider = FineTunedModelProvider(settings, config.llm, transport=transport)
    assert isinstance(provider, LLMProvider)
    analysis = await provider.analyze_attack_scenario(_request())
    assert analysis.provider == "finetuned"
    assert analysis.model == "sec-llm-v1"
    assert analysis.stages[0].tactic == "TA0043"


async def test_finetuned_provider_unconfigured_raises_provider_error(config) -> None:
    settings = config.llm.providers.finetuned.model_copy(update={"base_url": "", "model": ""})
    provider = FineTunedModelProvider(settings, config.llm)
    assert provider.enabled is False
    with pytest.raises(LLMProviderError):
        await provider.analyze_attack_scenario(_request())


def test_factory_returns_the_configured_provider(config) -> None:
    for name, expected in (
        ("mock", MockLLMProvider),
        ("disabled", NullLLMProvider),
        ("deepseek", DeepSeekProvider),
        ("finetuned", FineTunedModelProvider),
    ):
        selected = config.model_copy(
            update={"llm": config.llm.model_copy(update={"provider": name})}
        )
        provider = create_llm_provider(selected)
        assert isinstance(provider, expected)
    cloud_config = config.model_copy(update={
        "llm": config.llm.model_copy(update={"provider": "cloud_chain"})
    })
    assert isinstance(create_llm_provider(cloud_config), CloudProviderChain)


def test_factory_rejects_unknown_provider(config) -> None:
    with pytest.raises(ConfigError):
        create_llm_provider(config, provider_name="not-a-provider")


def test_all_providers_satisfy_the_protocol(config) -> None:
    assert isinstance(create_llm_provider(config), LLMProvider)
