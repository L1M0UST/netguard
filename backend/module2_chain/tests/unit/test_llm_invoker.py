"""LLM invoker tests: retries, timeouts, concurrency, fallback (spec §18/§19)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from backend.common.schemas.enums import LLMCallStatus
from backend.module2_chain.llm.base import (
    LLMAuthError,
    LLMInvalidJSONError,
    LLMProviderError,
    LLMQuotaError,
    LLMTimeoutError,
)
from backend.module2_chain.llm.invoker import LLMInvoker
from backend.module2_chain.llm.mock import NullLLMProvider
from backend.module2_chain.llm.schemas import (
    AttackAnalysisRequest,
    LLMAttackAnalysis,
    LLMStage,
    LLMUsage,
)


class ScriptedProvider:
    """Provider double that replays a scripted list of results/exceptions."""

    name = "scripted"
    model = "scripted-1"
    enabled = True

    def __init__(self, outcomes: list[Any], *, delay: float = 0.0) -> None:
        self.outcomes = outcomes
        self.calls = 0
        self.delay = delay
        self.active = 0
        self.max_active = 0

    async def analyze_attack_scenario(
        self, request: AttackAnalysisRequest
    ) -> LLMAttackAnalysis:
        self.calls += 1
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            outcome = self.outcomes[min(self.calls - 1, len(self.outcomes) - 1)]
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        finally:
            self.active -= 1

    async def aclose(self) -> None:
        """Nothing to release."""

    def health(self) -> dict[str, Any]:
        return {"provider": self.name, "calls": self.calls}


def _analysis(candidate_id: str = "cand_1") -> LLMAttackAnalysis:
    return LLMAttackAnalysis(
        candidate_id=candidate_id,
        verdict="attack",
        attack_summary="summary",
        stages=[
            LLMStage(
                stage_index=1,
                tactic="TA0043",
                technique="T1595",
                narrative="scan",
                evidence_event_ids=["evt_1"],
                confidence=0.8,
            )
        ],
        confidence=0.7,
        usage=LLMUsage(input_tokens=100, output_tokens=50, total_tokens=150, latency_ms=12.5),
    )


def _request(candidate_id: str = "cand_1") -> AttackAnalysisRequest:
    return AttackAnalysisRequest(
        task_id="task_1",
        candidate_id=candidate_id,
        prompt_version="attack_analysis.v1",
        system_prompt="system",
        user_prompt="user",
        evidence_event_ids=["evt_1", "evt_2"],
        allowed_tactics=["TA0043"],
        allowed_techniques=["T1595"],
        metadata={
            "attacker_ips": ["10.0.0.8"],
            "victim_ips": ["10.0.0.12"],
            "candidate_techniques": [
                {
                    "tactic": "TA0043",
                    "technique": "T1595",
                    "tactic_name": "Reconnaissance",
                    "technique_name": "Active Scanning",
                    "confidence": 0.7,
                    "evidence_event_ids": ["evt_1"],
                    "reason": "port scan keywords matched",
                }
            ],
        },
    )


async def test_successful_call_records_tokens_and_latency(config) -> None:
    provider = ScriptedProvider([_analysis()])
    invoker = LLMInvoker(config, provider)
    result = await invoker.analyze(_request())
    assert result.record.status is LLMCallStatus.SUCCESS
    assert result.record.input_tokens == 100
    assert result.record.output_tokens == 50
    assert result.record.latency_ms >= 0
    assert result.record.retry_count == 0
    assert result.degraded is False
    assert invoker.metrics.calls == 1
    assert invoker.summary()["provider"] == "scripted"


async def test_timeout_is_retried_then_succeeds(config) -> None:
    provider = ScriptedProvider([LLMTimeoutError("timeout"), _analysis()])
    invoker = LLMInvoker(config, provider)
    result = await invoker.analyze(_request())
    assert provider.calls == 2
    assert result.record.retry_count == 1
    assert result.record.status is LLMCallStatus.SUCCESS


async def test_persistent_failure_degrades_to_rule_based_fallback(config) -> None:
    provider = ScriptedProvider([LLMTimeoutError("timeout")])
    invoker = LLMInvoker(config, provider)
    result = await invoker.analyze(_request())
    assert result.record.status is LLMCallStatus.TIMEOUT
    assert result.record.fallback_used is True
    assert result.record.error
    assert result.analysis.degraded is True
    assert result.analysis.provider == "rule_based_fallback"
    assert result.analysis.stages
    assert result.analysis.stages[0].evidence_event_ids == ["evt_1"]
    assert invoker.metrics.failures == 1


async def test_explicitly_disabled_provider_skips_retries_and_uses_fallback(config) -> None:
    invoker = LLMInvoker(config, NullLLMProvider())
    result = await invoker.analyze(_request())
    assert result.record.status is LLMCallStatus.DISABLED
    assert result.record.fallback_used is True
    assert result.record.retry_count == 0
    assert result.record.attempts == []
    assert result.analysis.provider == "rule_based_fallback"
    assert invoker.metrics.summary()["retries"] == 0


async def test_auth_error_is_not_retried(config) -> None:
    provider = ScriptedProvider([LLMAuthError("bad key")])
    invoker = LLMInvoker(config, provider)
    result = await invoker.analyze(_request())
    assert provider.calls == 1
    assert result.record.status is LLMCallStatus.AUTH_ERROR
    assert result.record.fallback_used is True


async def test_quota_error_is_not_retried(config) -> None:
    provider = ScriptedProvider([LLMQuotaError("quota exhausted")])
    invoker = LLMInvoker(config, provider)
    result = await invoker.analyze(_request())
    assert provider.calls == 1
    assert result.record.status is LLMCallStatus.QUOTA_EXHAUSTED


async def test_invalid_json_is_retried_up_to_the_limit(config) -> None:
    provider = ScriptedProvider([LLMInvalidJSONError("not json")])
    invoker = LLMInvoker(config, provider)
    result = await invoker.analyze(_request())
    assert provider.calls == config.llm.max_retries + 1
    assert result.record.status is LLMCallStatus.INVALID_JSON
    assert len(result.record.attempts) == config.llm.max_retries + 1


async def test_fail_closed_configuration_propagates_the_error(config) -> None:
    closed = config.model_copy(
        update={"llm": config.llm.model_copy(update={"fail_open": False, "max_retries": 0})}
    )
    provider = ScriptedProvider([LLMProviderError("boom")])
    invoker = LLMInvoker(closed, provider)
    assert invoker.fallback is None
    with pytest.raises(LLMProviderError):
        await invoker.analyze(_request())


async def test_concurrency_is_capped_by_configuration(config) -> None:
    limited = config.model_copy(
        update={"llm": config.llm.model_copy(update={"max_concurrency": 2})}
    )
    provider = ScriptedProvider([_analysis()], delay=0.02)
    invoker = LLMInvoker(limited, provider)
    requests = [_request(f"cand_{index}") for index in range(6)]
    results = await invoker.analyze_batch(requests)
    assert len(results) == 6
    assert provider.max_active <= 2


async def test_batch_of_zero_requests_is_a_noop(config) -> None:
    provider = ScriptedProvider([_analysis()])
    invoker = LLMInvoker(config, provider)
    assert await invoker.analyze_batch([]) == []
    assert provider.calls == 0


async def test_candidate_id_from_the_model_is_ignored(config) -> None:
    provider = ScriptedProvider([_analysis(candidate_id="cand_wrong")])
    invoker = LLMInvoker(config, provider)
    result = await invoker.analyze(_request("cand_1"))
    assert result.analysis.candidate_id == "cand_1"
    assert result.record.candidate_id == "cand_1"


async def test_metrics_expose_latency_percentiles(config) -> None:
    provider = ScriptedProvider([_analysis()], delay=0.005)
    invoker = LLMInvoker(config, provider)
    await invoker.analyze_batch([_request(f"cand_{index}") for index in range(4)])
    summary = invoker.summary()
    assert summary["calls"] == 4
    assert summary["latency_p95_ms"] is not None
    assert summary["input_tokens"] == 400


async def test_fallback_analysis_is_still_evidence_bound(config) -> None:
    request = _request()
    request.metadata["candidate_techniques"] = [
        {
            "tactic": "TA0043",
            "technique": "T1595",
            "confidence": 0.6,
            "evidence_event_ids": ["evt_2"],
            "reason": "scan",
        },
        {
            "tactic": "TA0001",
            "technique": "T1190",
            "confidence": 0.9,
            "evidence_event_ids": ["evt_does_not_exist"],
            "reason": "exploit",
        },
    ]
    provider = ScriptedProvider([LLMProviderError("down")])
    invoker = LLMInvoker(config, provider)
    result = await invoker.analyze(request)
    evidence = {
        event_id for stage in result.analysis.stages for event_id in stage.evidence_event_ids
    }
    assert evidence <= {"evt_1", "evt_2"}
    assert result.analysis.degraded is True
    assert result.analysis.uncertainties
