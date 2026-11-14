"""LLMInvoker - concurrency, timeout, retry, validation, fallback, records.

Every business rule about *how* the LLM is called lives here:

* one call per **attack candidate** (never per raw event);
* a semaphore caps concurrency at ``llm.max_concurrency``;
* retries are bounded by ``llm.max_retries`` and never retry auth/quota errors;
* output is schema validated and the candidate id is enforced;
* failures degrade to :class:`FallbackAttackAnalyzer` and set ``llm_degraded``.
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Any

from backend.common.schemas.enums import LLMCallStatus
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.llm.base import (
    LLMAuthError,
    LLMError,
    LLMInvalidJSONError,
    LLMProvider,
    LLMProviderError,
    LLMQuotaError,
    LLMRateLimitError,
    LLMSchemaError,
    LLMTimeoutError,
)
from backend.module2_chain.llm.fallback import FallbackAttackAnalyzer
from backend.module2_chain.llm.schemas import (
    AttackAnalysisRequest,
    LLMAttackAnalysis,
    LLMCallRecord,
)

logger = get_logger("llm.invoker")

RETRY_BASE_DELAY_SECONDS = 0.5
RETRY_MAX_DELAY_SECONDS = 4.0
_NON_RETRYABLE = (LLMAuthError, LLMQuotaError)
_RETRYABLE = (LLMTimeoutError, LLMRateLimitError, LLMInvalidJSONError, LLMProviderError)


@dataclass(slots=True)
class InvocationResult:
    """Result of one logical LLM call."""

    analysis: LLMAttackAnalysis
    record: LLMCallRecord

    @property
    def degraded(self) -> bool:
        return self.analysis.degraded or self.record.fallback_used


@dataclass(slots=True)
class InvokerMetrics:
    """Aggregated LLM metrics for one task run."""

    calls: int = 0
    successes: int = 0
    failures: int = 0
    fallbacks: int = 0
    retries: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    latencies_ms: list[float] = field(default_factory=list)

    def observe(self, record: LLMCallRecord) -> None:
        self.calls += 1
        self.retries += record.retry_count
        self.input_tokens += record.input_tokens or 0
        self.output_tokens += record.output_tokens or 0
        if record.latency_ms:
            self.latencies_ms.append(record.latency_ms)
        if record.fallback_used:
            self.fallbacks += 1
            self.failures += 1
        elif record.ok:
            self.successes += 1
        else:
            self.failures += 1

    def percentile(self, quantile: float) -> float | None:
        if not self.latencies_ms:
            return None
        ordered = sorted(self.latencies_ms)
        if len(ordered) == 1:
            return ordered[0]
        position = quantile * (len(ordered) - 1)
        lower = int(position)
        upper = min(lower + 1, len(ordered) - 1)
        fraction = position - lower
        return ordered[lower] * (1 - fraction) + ordered[upper] * fraction

    def summary(self) -> dict[str, Any]:
        return {
            "calls": self.calls,
            "successes": self.successes,
            "failures": self.failures,
            "fallbacks": self.fallbacks,
            "retries": self.retries,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "latency_p50_ms": self.percentile(0.5),
            "latency_p95_ms": self.percentile(0.95),
            "latency_p99_ms": self.percentile(0.99),
        }


class LLMInvoker:
    """Sole entry point used by the pipeline to obtain LLM reasoning."""

    def __init__(
        self,
        config: AppConfig,
        provider: LLMProvider,
        *,
        fallback: LLMProvider | None = None,
    ) -> None:
        self.config = config
        self.settings = config.llm
        self.provider = provider
        self.fallback = (
            fallback
            if fallback is not None
            else (FallbackAttackAnalyzer(config) if self.settings.fail_open else None)
        )
        self.metrics = InvokerMetrics()
        self._semaphore = asyncio.Semaphore(max(1, self.settings.max_concurrency))

    # ------------------------------------------------------------------ #
    async def analyze(self, request: AttackAnalysisRequest) -> InvocationResult:
        """One logical call with retries, validation and fallback."""

        started = time.perf_counter()
        attempts: list[dict[str, Any]] = []
        retry_count = 0
        last_error: LLMError | None = None
        if not bool(getattr(self.provider, "enabled", True)):
            # An explicitly disabled provider is an intentional offline mode,
            # not a transient outage. Retry/backoff only delays deterministic
            # fallback and makes local-only acceptance runs needlessly slow.
            return await self._degrade(
                request,
                LLMProviderError("LLM provider is disabled by configuration"),
                started,
                attempts,
                retry_count,
                disabled=True,
            )
        max_attempts = self.settings.max_retries + 1

        async with self._semaphore:
            for attempt in range(1, max_attempts + 1):
                attempt_started = time.perf_counter()
                try:
                    analysis = await self.provider.analyze_attack_scenario(request)
                except LLMError as exc:
                    last_error = exc
                    attempts.append(
                        {
                            "attempt": attempt,
                            "status": type(exc).__name__,
                            "error": str(exc)[:400],
                            "latency_ms": round(
                                (time.perf_counter() - attempt_started) * 1000.0, 3
                            ),
                        }
                    )
                    if not self._should_retry(exc) or attempt >= max_attempts:
                        break
                    retry_count += 1
                    await self._backoff(attempt)
                    continue
                except Exception as exc:  # pragma: no cover - unexpected provider bug
                    last_error = LLMProviderError(f"unexpected provider failure: {exc}")
                    attempts.append(
                        {
                            "attempt": attempt,
                            "status": type(exc).__name__,
                            "error": str(exc)[:400],
                        }
                    )
                    if attempt >= max_attempts:
                        break
                    retry_count += 1
                    await self._backoff(attempt)
                    continue

                analysis = self._enforce_candidate_id(analysis, request)
                latency_ms = (time.perf_counter() - started) * 1000.0
                usage = analysis.usage
                record = LLMCallRecord(
                    request_id=request.request_id,
                    task_id=request.task_id,
                    candidate_id=request.candidate_id,
                    provider=analysis.provider or self.provider.name,
                    model=(usage.model if usage and usage.model else analysis.model or self.provider.model),
                    prompt_version=request.prompt_version,
                    input_tokens=usage.input_tokens if usage else None,
                    output_tokens=usage.output_tokens if usage else None,
                    total_tokens=usage.total_tokens if usage else None,
                    latency_ms=round(latency_ms, 3),
                    retry_count=retry_count,
                    status=LLMCallStatus.SUCCESS,
                    fallback_used=False,
                    attempts=attempts,
                    estimated_prompt_chars=request.estimated_chars,
                )
                self.metrics.observe(record)
                self._log_call(record, request)
                return InvocationResult(analysis=analysis, record=record)

        return await self._degrade(request, last_error, started, attempts, retry_count)

    async def analyze_batch(
        self, requests: list[AttackAnalysisRequest]
    ) -> list[InvocationResult]:
        """Run many candidate analyses with bounded concurrency."""

        if not requests:
            return []
        tasks = [asyncio.create_task(self.analyze(request)) for request in requests]
        return await asyncio.gather(*tasks)

    # ------------------------------------------------------------------ #
    async def _degrade(
        self,
        request: AttackAnalysisRequest,
        error: LLMError | None,
        started: float,
        attempts: list[dict[str, Any]],
        retry_count: int,
        *,
        disabled: bool = False,
    ) -> InvocationResult:
        error_message = str(error) if error else "unknown LLM failure"
        status = LLMCallStatus.DISABLED if disabled else _status_for(error)
        if self.fallback is None:
            logger.error(
                "LLM failed and no fallback analyser is enabled",
                extra={
                    "task_id": request.task_id,
                    "candidate_id": request.candidate_id,
                    "stage": "llm",
                    "provider": self.provider.name,
                    "status": str(status),
                    "error": error_message[:300],
                },
            )
            raise error or LLMProviderError(error_message)

        degraded_request = request.model_copy(
            update={
                "metadata": {
                    **(request.metadata or {}),
                    "llm_error": error_message,
                }
            }
        )
        analysis = await self.fallback.analyze_attack_scenario(degraded_request)
        analysis = analysis.model_copy(update={"degraded": True, "degraded_reason": error_message})
        latency_ms = (time.perf_counter() - started) * 1000.0
        record = LLMCallRecord(
            request_id=request.request_id,
            task_id=request.task_id,
            candidate_id=request.candidate_id,
            provider=self.provider.name,
            model=self.provider.model,
            prompt_version=request.prompt_version,
            latency_ms=round(latency_ms, 3),
            retry_count=retry_count,
            status=status,
            error=error_message[:500],
            fallback_used=True,
            attempts=attempts,
            estimated_prompt_chars=request.estimated_chars,
        )
        self.metrics.observe(record)
        self._log_call(record, request)
        return InvocationResult(analysis=analysis, record=record)

    # ------------------------------------------------------------------ #
    def _should_retry(self, error: LLMError) -> bool:
        if isinstance(error, (_NON_RETRYABLE, LLMSchemaError)):
            return False
        return isinstance(error, _RETRYABLE)

    async def _backoff(self, attempt: int) -> None:
        delay = min(RETRY_MAX_DELAY_SECONDS, RETRY_BASE_DELAY_SECONDS * (2 ** (attempt - 1)))
        delay += random.uniform(0, delay / 4)  # noqa: S311 - jitter, not security relevant
        await asyncio.sleep(delay)

    @staticmethod
    def _enforce_candidate_id(
        analysis: LLMAttackAnalysis, request: AttackAnalysisRequest
    ) -> LLMAttackAnalysis:
        if analysis.candidate_id == request.candidate_id:
            return analysis
        logger.warning(
            "model returned a mismatched candidate_id; enforcing the request id",
            extra={
                "task_id": request.task_id,
                "candidate_id": request.candidate_id,
                "stage": "llm",
                "model_candidate_id": analysis.candidate_id,
            },
        )
        return analysis.model_copy(update={"candidate_id": request.candidate_id})

    def _log_call(self, record: LLMCallRecord, request: AttackAnalysisRequest) -> None:
        logger.info(
            "llm call finished",
            extra={
                "task_id": request.task_id,
                "candidate_id": request.candidate_id,
                "stage": "llm",
                "provider": record.provider,
                "model": record.model,
                "latency_ms": record.latency_ms,
                "tokens": record.total_tokens,
                "input_tokens": record.input_tokens,
                "output_tokens": record.output_tokens,
                "status": str(record.status),
                "retries": record.retry_count,
                "fallback": record.fallback_used,
            },
        )

    def summary(self) -> dict[str, Any]:
        return {
            "provider": self.provider.name,
            "model": self.provider.model,
            "prompt_version": self.settings.prompt_version,
            "max_concurrency": self.settings.max_concurrency,
            "fallback_enabled": self.fallback is not None,
            **self.metrics.summary(),
        }

    async def aclose(self) -> None:
        await self.provider.aclose()
        if self.fallback is not None:
            await self.fallback.aclose()


def _status_for(error: LLMError | None) -> LLMCallStatus:
    if error is None:
        return LLMCallStatus.PROVIDER_ERROR
    if isinstance(error, LLMTimeoutError):
        return LLMCallStatus.TIMEOUT
    if isinstance(error, LLMAuthError):
        return LLMCallStatus.AUTH_ERROR
    if isinstance(error, LLMQuotaError):
        return LLMCallStatus.QUOTA_EXHAUSTED
    if isinstance(error, LLMRateLimitError):
        return LLMCallStatus.RATE_LIMITED
    if isinstance(error, LLMInvalidJSONError):
        return LLMCallStatus.INVALID_JSON
    if isinstance(error, LLMSchemaError):
        return LLMCallStatus.SCHEMA_ERROR
    return LLMCallStatus.PROVIDER_ERROR
