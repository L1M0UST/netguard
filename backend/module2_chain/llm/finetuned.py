"""Fine-tuned security-domain model provider.

Implements the very same :class:`LLMProvider` contract as
:class:`~backend.module2_chain.llm.deepseek.DeepSeekProvider`.  Switching the
running model is a configuration change::

    LLM_PROVIDER=finetuned
    FINETUNED_API_BASE_URL=http://model-host:8000/v1
    FINETUNED_MODEL=sec-llm-v1

The endpoint may be a vLLM server, an Ollama gateway, a FastAPI shim or any
other OpenAI-compatible deployment - business code is untouched.
"""

from __future__ import annotations

from backend.module2_chain.app.config import FineTunedSettings, LLMSettings
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.llm.base import (
    BaseLLMProvider,
    LLMAuthError,
    LLMProviderError,
    parse_analysis,
)
from backend.module2_chain.llm.client import ChatRequest, ChatTransport, build_transport
from backend.module2_chain.llm.schemas import (
    AttackAnalysisRequest,
    LLMAttackAnalysis,
    LLMUsage,
)

logger = get_logger("llm.finetuned")


class FineTunedModelProvider(BaseLLMProvider):
    """OpenAI-compatible client for a self-hosted / fine-tuned model."""

    name = "finetuned"

    def __init__(
        self,
        settings: FineTunedSettings,
        llm_settings: LLMSettings,
        *,
        transport: ChatTransport | None = None,
    ) -> None:
        self.settings = settings
        self.llm_settings = llm_settings
        self.model = settings.model or None
        self.api_key = settings.resolved_api_key()
        self.timeout_seconds = settings.timeout_seconds or llm_settings.timeout_seconds
        self.enabled = bool(settings.base_url and settings.model)
        if not self.enabled:
            logger.warning(
                "fine-tuned provider is not fully configured "
                "(FINETUNED_API_BASE_URL / FINETUNED_MODEL missing)",
                extra={"stage": "llm", "provider": self.name},
            )
        self._transport = transport or (
            build_transport(
                base_url=settings.base_url,
                api_key=self.api_key,
                transport_kind=settings.transport,
                headers=settings.extra_headers,
            )
            if settings.base_url
            else None
        )

    # ------------------------------------------------------------------ #
    def _build_chat_request(self, request: AttackAnalysisRequest) -> ChatRequest:
        system_prompt = self.settings.system_prompt or request.system_prompt
        return ChatRequest(
            model=request.model or self.model or "",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": request.user_prompt},
            ],
            temperature=(
                request.temperature
                if request.temperature is not None
                else self.llm_settings.temperature
            ),
            max_tokens=request.max_output_tokens or self.llm_settings.max_output_tokens,
            response_format=(
                self.settings.response_format
                if self.settings.response_format != "none"
                else None
            ),
            timeout=self.timeout_seconds,
            extra_headers=dict(self.settings.extra_headers),
            extra_body=dict(self.settings.extra_body),
            request_id=request.request_id,
        )

    async def analyze_attack_scenario(
        self, request: AttackAnalysisRequest
    ) -> LLMAttackAnalysis:
        if not self._transport:
            raise LLMProviderError(
                "fine-tuned provider is not configured: set FINETUNED_API_BASE_URL "
                "and FINETUNED_MODEL (LLM_PROVIDER=finetuned)"
            )
        if self.settings.strict and not self.api_key and self.settings.api_key_env:
            raise LLMAuthError(
                f"strict mode: {self.settings.api_key_env} is required for the "
                "fine-tuned provider"
            )
        response = await self._transport.complete(self._build_chat_request(request))
        analysis = parse_analysis(response.content, request=request)
        analysis = self.finalise(analysis, request)
        usage = LLMUsage(
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            total_tokens=response.total_tokens,
            model=response.model or self.model,
            latency_ms=response.latency_ms,
            finish_reason=response.finish_reason,
        )
        return analysis.model_copy(update={"usage": usage, "raw_response": None})

    async def aclose(self) -> None:
        if self._transport is not None:
            await self._transport.aclose()

    def health(self) -> dict[str, object]:
        return {
            **super().health(),
            "base_url": self.settings.base_url or None,
            "api_key_configured": bool(self.api_key),
            "transport": type(self._transport).__name__ if self._transport else None,
        }
