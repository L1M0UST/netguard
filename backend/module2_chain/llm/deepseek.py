"""DeepSeek provider (OpenAI-compatible API).

* the API key, base URL and model come from configuration/environment only;
* the provider is the *only* place that knows this vendor exists.
"""

from __future__ import annotations

from backend.module2_chain.app.config import DeepSeekSettings, LLMSettings
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.llm.base import (
    BaseLLMProvider,
    LLMAuthError,
    parse_analysis,
)
from backend.module2_chain.llm.client import ChatRequest, ChatTransport, build_transport
from backend.module2_chain.llm.schemas import (
    AttackAnalysisRequest,
    LLMAttackAnalysis,
    LLMUsage,
)

logger = get_logger("llm.deepseek")


class DeepSeekProvider(BaseLLMProvider):
    """Talks to any OpenAI-compatible DeepSeek endpoint."""

    name = "deepseek"

    def __init__(
        self,
        settings: DeepSeekSettings,
        llm_settings: LLMSettings,
        *,
        transport: ChatTransport | None = None,
        provider_name: str = "deepseek",
        requires_session: bool = False,
    ) -> None:
        self.name = provider_name
        self.requires_session = requires_session
        self.settings = settings
        self.llm_settings = llm_settings
        self.model = settings.model or None
        self.api_key = settings.resolved_api_key()
        self.enabled = bool(self.api_key)
        self._transport = transport or build_transport(
            base_url=settings.base_url,
            api_key=self.api_key,
            transport_kind=settings.transport,
            headers=settings.extra_headers,
        )
        if not self.enabled:
            logger.warning(
                "DeepSeek provider is configured without an API key; "
                "calls will fail over to the rule-based analyser",
                extra={"stage": "llm", "provider": self.name, "model": self.model},
            )

    # ------------------------------------------------------------------ #
    def _build_chat_request(self, request: AttackAnalysisRequest) -> ChatRequest:
        headers = dict(self.settings.extra_headers)
        if self.requires_session:
            # Required by OpenCode Go; stable for every candidate in one task.
            headers.setdefault("User-Agent", "NetGuard-Security-Research/1.0")
            headers["x-opencode-session"] = f"netguard-m2-{request.task_id}"[:128]
        return ChatRequest(
            model=request.model or self.model or self.settings.model,
            messages=request.messages,
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
            timeout=self.llm_settings.timeout_seconds,
            extra_headers=headers,
            extra_body=dict(self.settings.extra_body),
            request_id=request.request_id,
        )

    async def analyze_attack_scenario(
        self, request: AttackAnalysisRequest
    ) -> LLMAttackAnalysis:
        if not self.api_key:
            raise LLMAuthError(
                f"no API key configured for provider 'deepseek' "
                f"(set {self.settings.api_key_env})"
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
        await self._transport.aclose()

    def health(self) -> dict[str, object]:
        return {
            **super().health(),
            "base_url": self.settings.base_url,
            "api_key_configured": bool(self.api_key),
            "transport": type(self._transport).__name__,
        }
