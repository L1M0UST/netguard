"""Provider factory - the single place that knows provider names.

Business code calls :func:`create_llm_provider` and receives an
:class:`~backend.module2_chain.llm.base.LLMProvider`.  Adding a new vendor means
adding one entry to ``_PROVIDER_BUILDERS``; no ``if/else`` chains leak into the
pipeline.
"""

from __future__ import annotations

from collections.abc import Callable

from backend.module2_chain.app.config import AppConfig, ConfigError
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.llm.base import LLMError, LLMProvider, LLMProviderError
from backend.module2_chain.llm.client import ChatTransport
from backend.module2_chain.llm.deepseek import DeepSeekProvider
from backend.module2_chain.llm.finetuned import FineTunedModelProvider
from backend.module2_chain.llm.mock import MockLLMProvider, NullLLMProvider

logger = get_logger("llm.factory")

ProviderBuilder = Callable[[AppConfig, ChatTransport | None], LLMProvider]


def _build_deepseek(config: AppConfig, transport: ChatTransport | None) -> LLMProvider:
    return DeepSeekProvider(config.llm.providers.deepseek, config.llm, transport=transport)


class CloudProviderChain:
    """Ordered cloud fallback that retains the actual vendor on every result."""

    name = "cloud_chain"
    model = None

    def __init__(self, providers: list[LLMProvider]) -> None:
        self.providers = providers
        self.enabled = any(bool(getattr(item, "enabled", False)) for item in providers)
        self.calls = 0
        self.failures: list[str] = []

    async def analyze_attack_scenario(self, request):  # type: ignore[no-untyped-def]
        errors: list[str] = []
        for provider in self.providers:
            if not getattr(provider, "enabled", False):
                continue
            try:
                result = await provider.analyze_attack_scenario(request)
                self.calls += 1
                return result
            except LLMError as exc:
                errors.append(f"{provider.name}:{type(exc).__name__}")
        self.failures.extend(errors)
        raise LLMProviderError("all cloud providers failed: " + ", ".join(errors or ["none configured"]))

    async def aclose(self) -> None:
        for provider in self.providers:
            await provider.aclose()

    def health(self) -> dict[str, object]:
        return {"provider": self.name, "enabled": self.enabled, "calls": self.calls,
                "providers": [item.health() for item in self.providers], "recent_failures": self.failures[-10:]}


def _build_cloud_chain(config: AppConfig, transport: ChatTransport | None) -> LLMProvider:
    # All are OpenAI-compatible, but OpenCode Go additionally requires a stable
    # session header.  Order is explicit and auditable: Go -> Command Code -> DeepSeek.
    return CloudProviderChain([
        DeepSeekProvider(config.llm.providers.opencode_go, config.llm, transport=transport,
                         provider_name="opencode_go", requires_session=True),
        DeepSeekProvider(config.llm.providers.commandcode, config.llm, transport=transport,
                         provider_name="commandcode"),
        DeepSeekProvider(config.llm.providers.deepseek, config.llm, transport=transport,
                         provider_name="deepseek"),
    ])


def _build_opencode_go(config: AppConfig, transport: ChatTransport | None) -> LLMProvider:
    return DeepSeekProvider(config.llm.providers.opencode_go, config.llm, transport=transport,
                           provider_name="opencode_go", requires_session=True)


def _build_commandcode(config: AppConfig, transport: ChatTransport | None) -> LLMProvider:
    return DeepSeekProvider(config.llm.providers.commandcode, config.llm, transport=transport,
                           provider_name="commandcode")


def _build_finetuned(config: AppConfig, transport: ChatTransport | None) -> LLMProvider:
    return FineTunedModelProvider(config.llm.providers.finetuned, config.llm, transport=transport)


def _build_mock(config: AppConfig, transport: ChatTransport | None) -> LLMProvider:
    del transport
    return MockLLMProvider(config.llm.providers.mock, config.llm)


def _build_disabled(config: AppConfig, transport: ChatTransport | None) -> LLMProvider:
    del config, transport
    return NullLLMProvider()


_PROVIDER_BUILDERS: dict[str, ProviderBuilder] = {
    "cloud_chain": _build_cloud_chain,
    "opencode_go": _build_opencode_go,
    "commandcode": _build_commandcode,
    "deepseek": _build_deepseek,
    "finetuned": _build_finetuned,
    "mock": _build_mock,
    "disabled": _build_disabled,
    "none": _build_disabled,
}

SUPPORTED_PROVIDERS: tuple[str, ...] = ("cloud_chain", "opencode_go", "commandcode", "deepseek", "finetuned", "mock", "disabled")


def create_llm_provider(
    config: AppConfig,
    *,
    transport: ChatTransport | None = None,
    provider_name: str | None = None,
) -> LLMProvider:
    """Instantiate the configured provider.

    ``transport`` is an injection point for tests (``httpx.MockTransport`` based
    transport, recording fakes, ...).
    """

    name = (provider_name or config.llm.provider or "deepseek").strip().lower()
    builder = _PROVIDER_BUILDERS.get(name)
    if builder is None:
        raise ConfigError(
            f"unknown LLM provider {name!r}; supported providers: "
            f"{', '.join(SUPPORTED_PROVIDERS)}"
        )
    try:
        provider = builder(config, transport)
    except LLMProviderError:
        raise
    logger.info(
        "LLM provider initialised",
        extra={
            "stage": "llm",
            "provider": name,
            "model": getattr(provider, "model", None),
            "enabled": getattr(provider, "enabled", False),
        },
    )
    return provider
