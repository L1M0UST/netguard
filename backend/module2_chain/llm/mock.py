"""Deterministic mock providers for unit / integration / CI runs.

``LLM_PROVIDER=mock`` must be enough to exercise the whole pipeline without a
network call or an API key.  Failure modes can be forced so that timeout,
provider error, malformed JSON and schema-error paths stay testable.
"""

from __future__ import annotations

import asyncio
import json
import random
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from backend.module2_chain.app.config import LLMSettings, MockSettings
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.llm.base import (
    BaseLLMProvider,
    LLMInvalidJSONError,
    LLMProviderError,
    LLMSchemaError,
    LLMTimeoutError,
)
from backend.module2_chain.llm.schemas import (
    AttackAnalysisRequest,
    LLMAttackAnalysis,
    LLMStage,
    LLMThreatEntity,
    LLMUsage,
)

logger = get_logger("llm.mock")


class MockLLMProvider(BaseLLMProvider):
    """Fixture driven provider used by tests and offline development."""

    name = "mock"

    def __init__(
        self,
        settings: MockSettings,
        llm_settings: LLMSettings | None = None,
        *,
        fixture_path: str | Path | None = None,
        fixture: dict[str, Any] | None = None,
    ) -> None:
        self.settings = settings
        self.llm_settings = llm_settings
        self.model = "mock-model"
        self.enabled = True
        self.failure_mode = settings.failure_mode
        self.fail_rate = settings.fail_rate
        # A seeded PRNG is exactly what a deterministic test double needs.
        self._random = random.Random(settings.seed)  # noqa: S311
        resolved_fixture = fixture_path or settings.fixture
        self._fixture_path: Path | None = Path(resolved_fixture) if resolved_fixture else None
        self.fixture: dict[str, Any] = fixture if fixture is not None else self._load_fixture()
        self.calls = 0

    # ------------------------------------------------------------------ #
    def _load_fixture(self) -> dict[str, Any]:
        if self._fixture_path is None or not self._fixture_path.is_file():
            logger.warning(
                "mock LLM fixture not found; using the built-in default answer",
                extra={"stage": "llm", "path": str(self._fixture_path)},
            )
            return {}
        try:
            payload = json.loads(self._fixture_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive
            raise LLMProviderError(f"mock fixture is not valid JSON: {exc}") from exc
        return payload if isinstance(payload, dict) else {}

    def _template_for(self, request: AttackAnalysisRequest) -> dict[str, Any]:
        if not self.fixture:
            return _default_template(request)
        entry = self.fixture.get(request.candidate_id) or self.fixture.get("default")
        if entry is None:
            entry = next(
                (value for key, value in self.fixture.items() if isinstance(value, dict)),
                {},
            )
        template = _interpolate(entry, _interpolation_context(request))
        return template if isinstance(template, dict) else {}

    # ------------------------------------------------------------------ #
    async def analyze_attack_scenario(
        self, request: AttackAnalysisRequest
    ) -> LLMAttackAnalysis:
        self.calls += 1
        if self.settings.latency_ms > 0:
            await asyncio.sleep(self.settings.latency_ms / 1000.0)

        mode = self.failure_mode
        if mode == "none" and self.fail_rate > 0 and self._random.random() < self.fail_rate:
            mode = "provider_error"
        if mode == "timeout":
            raise LLMTimeoutError("mock timeout")
        if mode == "provider_error":
            raise LLMProviderError("mock provider error")
        if mode == "invalid_json":
            raise LLMInvalidJSONError("mock invalid JSON")
        if mode == "schema_error":
            raise LLMSchemaError("mock schema error")

        payload = self._template_for(request)
        payload.setdefault("candidate_id", request.candidate_id)
        try:
            analysis = LLMAttackAnalysis.model_validate(payload)
        except ValidationError as exc:
            raise LLMSchemaError(str(exc)) from exc
        analysis = self.finalise(analysis, request)
        usage = LLMUsage(
            input_tokens=max(1, request.estimated_chars // 4),
            output_tokens=200,
            total_tokens=max(1, request.estimated_chars // 4) + 200,
            model=self.model,
            latency_ms=self.settings.latency_ms,
        )
        return analysis.model_copy(update={"usage": usage})

    async def aclose(self) -> None:
        """Nothing to release."""

    def health(self) -> dict[str, object]:
        return {
            **super().health(),
            "failure_mode": self.failure_mode,
            "calls": self.calls,
            "fixture": str(self._fixture_path) if self._fixture_path else None,
        }


class NullLLMProvider(BaseLLMProvider):
    """``LLM_PROVIDER=disabled`` - the pipeline runs purely on rules."""

    name = "disabled"
    model: str | None = None
    enabled = False

    async def analyze_attack_scenario(
        self, request: AttackAnalysisRequest
    ) -> LLMAttackAnalysis:
        raise LLMProviderError("LLM provider is disabled by configuration")

    def health(self) -> dict[str, object]:
        return {"provider": self.name, "enabled": False}


def _interpolation_context(request: AttackAnalysisRequest) -> dict[str, Any]:
    event_ids = list(request.evidence_event_ids)
    techniques = request.allowed_techniques
    tactics = request.allowed_tactics
    metadata = request.metadata or {}
    attacker_ips = metadata.get("attacker_ips") or []
    victim_ips = metadata.get("victim_ips") or []
    return {
        "candidate_id": request.candidate_id,
        "task_id": request.task_id,
        "event_ids": event_ids,
        "first_event_id": event_ids[0] if event_ids else "",
        "tactic_1": tactics[0] if tactics else "TA0043",
        "technique_1": techniques[0] if techniques else "T1595",
        "attacker_ip": attacker_ips[0] if attacker_ips else "unknown",
        "victim_ip": victim_ips[0] if victim_ips else "unknown",
        "event_count": len(event_ids),
    }


def _interpolate(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, str):
        if value == "{{event_ids}}":
            return list(context.get("event_ids") or [])
        rendered = value
        for key, replacement in context.items():
            rendered = rendered.replace(f"{{{{{key}}}}}", str(replacement))
        return rendered
    if isinstance(value, list):
        expanded: list[Any] = []
        for item in value:
            result = _interpolate(item, context)
            if isinstance(result, list) and item == "{{event_ids}}":
                expanded.extend(result)
            else:
                expanded.append(result)
        return expanded
    if isinstance(value, dict):
        return {key: _interpolate(item, context) for key, item in value.items()}
    return value


def _default_template(request: AttackAnalysisRequest) -> dict[str, Any]:
    event_ids = list(request.evidence_event_ids)[:3]
    techniques = list(request.allowed_techniques)
    tactics = list(request.allowed_tactics)
    stages: list[dict[str, Any]] = []
    for index, event_id in enumerate(event_ids[:3], start=1):
        stages.append(
            {
                "stage_index": index,
                "tactic": tactics[min(index - 1, len(tactics) - 1)] if tactics else "TA0043",
                "technique": techniques[min(index - 1, len(techniques) - 1)]
                if techniques
                else None,
                "narrative": (
                    f"Mock narrative for stage {index} of candidate "
                    f"{request.candidate_id} derived from event {event_id}."
                ),
                "evidence_event_ids": [event_id],
                "confidence": 0.6,
            }
        )
    return {
        "candidate_id": request.candidate_id,
        "verdict": "suspicious" if len(event_ids) < 2 else "attack",
        "attack_summary": (
            f"Mock analysis for candidate {request.candidate_id}: "
            f"{len(event_ids)} evidence event(s) grouped by the correlation engine."
        ),
        "attacker_assessment": "Mock attacker assessment (offline mode).",
        "victim_assessment": "Mock victim assessment (offline mode).",
        "stages": stages,
        "threat_entities": [],
        "uncertainties": ["analysis produced by MockLLMProvider (no real model was called)"],
        "severity_hint": None,
        "confidence": 0.5,
    }


__all__ = ["LLMStage", "LLMThreatEntity", "MockLLMProvider", "NullLLMProvider"]
