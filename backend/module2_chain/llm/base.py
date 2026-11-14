"""The ``LLMProvider`` abstraction.

Every provider - DeepSeek today, a fine-tuned security model tomorrow, a mock
in tests - implements the same coroutine:

.. code-block:: python

    async def analyze_attack_scenario(
        self, request: AttackAnalysisRequest
    ) -> LLMAttackAnalysis: ...

Nothing above this module may import a vendor SDK, a concrete URL or a concrete
model name.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from typing import Any, Protocol, runtime_checkable

from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.llm.schemas import AttackAnalysisRequest, LLMAttackAnalysis

logger = get_logger("llm")

_FENCE_PATTERN = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


class LLMError(RuntimeError):
    """Base class for every LLM failure (always recoverable via fallback)."""


class LLMTimeoutError(LLMError):
    """The provider did not answer inside the configured timeout."""


class LLMProviderError(LLMError):
    """Transport/provider level failure (network, 5xx, malformed envelope)."""


class LLMAuthError(LLMProviderError):
    """Authentication/authorisation failure (bad or missing API key)."""


class LLMQuotaError(LLMProviderError):
    """Quota exhausted / billing problem."""


class LLMRateLimitError(LLMProviderError):
    """Rate limited; retry later."""


class LLMInvalidJSONError(LLMError):
    """The model answered with something that is not JSON."""


class LLMSchemaError(LLMError):
    """The JSON did not match :class:`LLMAttackAnalysis`."""


@runtime_checkable
class LLMProvider(Protocol):
    """The only LLM interface the business layer knows about."""

    name: str
    model: str | None
    enabled: bool

    async def analyze_attack_scenario(
        self, request: AttackAnalysisRequest
    ) -> LLMAttackAnalysis:
        """Analyse one aggregated attack candidate and return strict JSON."""

    async def aclose(self) -> None:
        """Release provider resources (HTTP connections, ...)."""

    def health(self) -> dict[str, Any]:
        """Small self-description for status files and metrics."""


def extract_json_object(text: str) -> dict[str, Any]:
    """Parse a JSON object out of a model answer.

    Handles the shapes models actually produce: a raw JSON document, a fenced
    ```json block, or JSON embedded in a chatty answer.  Nothing else is
    accepted - free-form prose is never scraped into an attack chain.
    """

    if not text or not text.strip():
        raise LLMInvalidJSONError("empty response")
    candidate = text.strip()
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        match = _FENCE_PATTERN.search(candidate)
        if match:
            try:
                parsed = json.loads(match.group(1).strip())
            except json.JSONDecodeError as exc:
                raise LLMInvalidJSONError(f"fenced block is not valid JSON: {exc}") from exc
        else:
            start = candidate.find("{")
            end = candidate.rfind("}")
            if start == -1 or end <= start:
                raise LLMInvalidJSONError("response contains no JSON object") from None
            try:
                parsed = json.loads(candidate[start : end + 1])
            except json.JSONDecodeError as exc:
                raise LLMInvalidJSONError(f"response is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise LLMInvalidJSONError(f"expected a JSON object, got {type(parsed).__name__}")
    return parsed


def parse_analysis(text: str, *, request: AttackAnalysisRequest) -> LLMAttackAnalysis:
    """Strict JSON + schema validation, with request provenance attached."""

    from pydantic import ValidationError

    payload = extract_json_object(text)
    payload.setdefault("candidate_id", request.candidate_id)
    try:
        analysis = LLMAttackAnalysis.model_validate(payload)
    except ValidationError as exc:
        raise LLMSchemaError(str(exc)) from exc
    return analysis.model_copy(
        update={
            "request_id": request.request_id,
            "prompt_version": request.prompt_version,
        }
    )


class BaseLLMProvider(ABC):
    """Shared behaviour for concrete providers."""

    name: str = "base"
    model: str | None = None
    enabled: bool = True

    @abstractmethod
    async def analyze_attack_scenario(
        self, request: AttackAnalysisRequest
    ) -> LLMAttackAnalysis:
        raise NotImplementedError

    async def aclose(self) -> None:  # noqa: B027 - optional hook, not abstract
        """Default: nothing to release."""

    def health(self) -> dict[str, Any]:
        return {
            "provider": self.name,
            "model": self.model,
            "enabled": self.enabled,
        }

    def finalise(
        self, analysis: LLMAttackAnalysis, request: AttackAnalysisRequest
    ) -> LLMAttackAnalysis:
        """Attach provenance that must never be trusted from the model itself."""

        return analysis.model_copy(
            update={
                "candidate_id": analysis.candidate_id or request.candidate_id,
                "request_id": request.request_id,
                "prompt_version": request.prompt_version,
                "provider": self.name,
                "model": analysis.model or self.model,
            }
        )
