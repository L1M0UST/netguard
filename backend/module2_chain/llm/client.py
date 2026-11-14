"""OpenAI-compatible chat client used by the real providers.

The transport is pluggable so a provider never talks to ``httpx`` or a vendor
SDK directly:

* :class:`HTTPXChatTransport` - default, dependency-light, works with DeepSeek,
  vLLM, Ollama, LM Studio, a FastAPI shim, ...
* :class:`OpenAISDKTransport` - optional, used only when ``openai`` is installed
  *and* selected in configuration.

Both speak the ``POST {base_url}/chat/completions`` protocol.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.llm.base import (
    LLMAuthError,
    LLMError,
    LLMProviderError,
    LLMQuotaError,
    LLMRateLimitError,
    LLMTimeoutError,
)

logger = get_logger("llm.client")

_QUOTA_MARKERS = ("quota", "insufficient", "billing", "balance", "exceeded your current")
_RATE_LIMIT_MARKERS = ("rate limit", "too many requests", " tpm", " rpm")


@dataclass(slots=True)
class ChatRequest:
    """Provider-neutral chat completion request."""

    model: str
    messages: list[dict[str, str]]
    temperature: float = 0.1
    max_tokens: int | None = None
    response_format: str | None = None
    timeout: float = 30.0
    extra_headers: dict[str, str] = field(default_factory=dict)
    extra_body: dict[str, Any] = field(default_factory=dict)
    request_id: str | None = None


@dataclass(slots=True)
class ChatResponse:
    """Provider-neutral chat completion response."""

    content: str
    model: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None
    latency_ms: float = 0.0
    finish_reason: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class ChatTransport(Protocol):
    """Minimal transport contract."""

    async def complete(self, request: ChatRequest) -> ChatResponse: ...

    async def aclose(self) -> None: ...


def normalise_endpoint(base_url: str) -> str:
    """Return the ``chat/completions`` URL for an OpenAI-compatible base URL."""

    trimmed = (base_url or "").strip().rstrip("/")
    if not trimmed:
        raise LLMProviderError("provider base_url is empty")
    if trimmed.endswith("/chat/completions"):
        return trimmed
    return f"{trimmed}/chat/completions"


def classify_http_error(status_code: int, body: str) -> LLMProviderError:
    """Map an HTTP error to the matching :class:`LLMError` subclass."""

    lowered = (body or "").lower()
    if status_code in (401, 403):
        return LLMAuthError(f"authentication failed (HTTP {status_code})")
    if status_code == 402:
        return LLMQuotaError(f"payment required (HTTP {status_code})")
    if status_code == 429:
        if any(marker in lowered for marker in _QUOTA_MARKERS):
            return LLMQuotaError("quota exhausted (HTTP 429)")
        if not lowered or any(marker in lowered for marker in _RATE_LIMIT_MARKERS):
            return LLMRateLimitError("rate limited (HTTP 429)")
        return LLMQuotaError(f"HTTP 429: {body[:200]}")
    if status_code >= 500:
        return LLMProviderError(f"provider error (HTTP {status_code})")
    return LLMProviderError(f"unexpected HTTP {status_code}: {body[:200]}")


def _chat_response_from_body(
    body: dict[str, Any], *, latency_ms: float, raw: dict[str, Any]
) -> ChatResponse:
    choices = body.get("choices") or []
    if not isinstance(choices, list) or not choices:
        raise LLMProviderError("provider response contains no choices")
    choice = choices[0] if isinstance(choices[0], dict) else {}
    message = choice.get("message") or {}
    content = message.get("content") or ""
    usage = body.get("usage") or {}
    return ChatResponse(
        content=content if isinstance(content, str) else json.dumps(content),
        model=body.get("model"),
        input_tokens=usage.get("prompt_tokens") or usage.get("input_tokens"),
        output_tokens=usage.get("completion_tokens") or usage.get("output_tokens"),
        total_tokens=usage.get("total_tokens"),
        latency_ms=latency_ms,
        finish_reason=choice.get("finish_reason"),
        raw=raw,
    )


class HTTPXChatTransport:
    """OpenAI-compatible transport built on ``httpx``."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None,
        default_headers: dict[str, str] | None = None,
        transport: Any | None = None,
        verify: bool = True,
    ) -> None:
        self.endpoint = normalise_endpoint(base_url)
        self.api_key = api_key
        self._headers = dict(default_headers or {})
        self._transport = transport
        self._verify = verify
        self._client: Any | None = None

    def _build_client(self) -> Any:
        import httpx

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            **self._headers,
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return httpx.AsyncClient(headers=headers, transport=self._transport, verify=self._verify)

    async def complete(self, request: ChatRequest) -> ChatResponse:
        import httpx

        if self._client is None:
            self._client = self._build_client()
        payload: dict[str, Any] = {
            "model": request.model,
            "messages": request.messages,
            "temperature": request.temperature,
            "stream": False,
        }
        if request.max_tokens:
            payload["max_tokens"] = request.max_tokens
        if request.response_format:
            payload["response_format"] = {"type": request.response_format}
        if request.extra_body:
            payload.update(request.extra_body)

        started = time.perf_counter()
        try:
            response = await self._client.post(
                self.endpoint,
                content=json.dumps(payload).encode("utf-8"),
                timeout=httpx.Timeout(request.timeout),
                headers=request.extra_headers or None,
            )
        except httpx.TimeoutException as exc:
            raise LLMTimeoutError(f"provider timed out after {request.timeout}s") from exc
        except httpx.HTTPError as exc:
            raise LLMProviderError(f"network error talking to provider: {exc}") from exc
        latency_ms = (time.perf_counter() - started) * 1000.0

        if response.status_code >= 400:
            raise classify_http_error(response.status_code, response.text)
        try:
            body = response.json()
        except ValueError as exc:
            raise LLMProviderError("provider returned a non-JSON envelope") from exc
        if not isinstance(body, dict):
            raise LLMProviderError("provider returned an unexpected envelope type")
        return _chat_response_from_body(body, latency_ms=latency_ms, raw=body)

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


class OpenAISDKTransport:
    """Optional transport based on the official ``openai`` SDK."""

    def __init__(self, *, base_url: str, api_key: str | None) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self.api_key = api_key
        self._client: Any | None = None

    @staticmethod
    def available() -> bool:
        try:
            import openai  # noqa: F401
        except ImportError:
            return False
        return True

    async def complete(self, request: ChatRequest) -> ChatResponse:
        try:
            from openai import AsyncOpenAI
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise LLMProviderError(
                "openai SDK transport requested but the 'openai' package is not installed"
            ) from exc

        if self._client is None:
            self._client = AsyncOpenAI(
                base_url=self.base_url, api_key=self.api_key, timeout=request.timeout
            )
        payload: dict[str, Any] = {
            "model": request.model,
            "messages": request.messages,
            "temperature": request.temperature,
            "stream": False,
        }
        if request.max_tokens:
            payload["max_tokens"] = request.max_tokens
        if request.response_format:
            payload["response_format"] = {"type": request.response_format}
        payload.update(request.extra_body)

        started = time.perf_counter()
        try:
            completion = await self._client.chat.completions.create(**payload)
        except Exception as exc:  # pragma: no cover - SDK specific errors
            raise _map_sdk_error(exc) from exc
        latency_ms = (time.perf_counter() - started) * 1000.0
        body = completion.model_dump() if hasattr(completion, "model_dump") else {}
        return _chat_response_from_body(body, latency_ms=latency_ms, raw=body)

    async def aclose(self) -> None:
        if self._client is not None:  # pragma: no cover - environment dependent
            await self._client.close()
            self._client = None


def _map_sdk_error(exc: Exception) -> LLMError:
    name = type(exc).__name__.lower()
    text = str(exc)
    if "timeout" in name:
        return LLMTimeoutError(text)
    if "authentication" in name or "permission" in name:
        return LLMAuthError(text)
    if "ratelimit" in name or "rate_limit" in name:
        return LLMRateLimitError(text)
    if "connection" in name:
        return LLMProviderError(f"network error: {text}")
    return LLMProviderError(text)


def build_transport(
    *,
    base_url: str,
    api_key: str | None,
    transport_kind: str = "httpx",
    headers: dict[str, str] | None = None,
    transport: Any | None = None,
) -> ChatTransport:
    """Select a transport implementation.

    ``transport_kind='auto'`` prefers the OpenAI SDK when it is importable, and
    falls back to ``httpx`` otherwise.  Tests inject an ``httpx.MockTransport``.
    """

    if transport is not None:
        return HTTPXChatTransport(
            base_url=base_url,
            api_key=api_key,
            default_headers=headers,
            transport=transport,
        )
    if transport_kind == "sdk" or (
        transport_kind == "auto" and OpenAISDKTransport.available()
    ):
        if OpenAISDKTransport.available():
            return OpenAISDKTransport(base_url=base_url, api_key=api_key)
        logger.warning(
            "openai SDK transport requested but unavailable; using httpx",
            extra={"stage": "llm"},
        )
    return HTTPXChatTransport(base_url=base_url, api_key=api_key, default_headers=headers)
