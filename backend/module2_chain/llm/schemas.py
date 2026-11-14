"""LLM request/response contracts (Pydantic v2, validated, evidence bound).

The LLM is *not* the final authority: its output is schema-validated here and
then cross-checked against real events by
:class:`~backend.module2_chain.attack.evidence_validator.EvidenceValidator`.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.common.schemas.enums import LLMCallStatus


class LLMUsage(BaseModel):
    """Token usage / latency reported by a provider."""

    model_config = ConfigDict(extra="allow")

    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None
    model: str | None = None
    latency_ms: float = 0.0
    finish_reason: str | None = None


class LLMStage(BaseModel):
    """One attack stage proposed by the model."""

    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)

    stage_index: int = Field(ge=1)
    tactic: str
    technique: str | None = None
    narrative: str = ""
    evidence_event_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    @field_validator("evidence_event_ids", mode="before")
    @classmethod
    def _coerce_evidence(cls, value: Any) -> Any:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return value

    @field_validator("technique", "narrative", mode="before")
    @classmethod
    def _null_to_default(cls, value: Any) -> Any:
        return "" if value is None else value


class LLMThreatEntity(BaseModel):
    """Threat entity proposed by the model."""

    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)

    entity_type: str
    value: str
    role: str = "unknown"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_event_ids: list[str] = Field(default_factory=list)


class LLMAttackAnalysis(BaseModel):
    """Strict JSON answer of one attack-scenario analysis."""

    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)

    candidate_id: str
    verdict: Literal["attack", "suspicious", "benign", "unknown"] = "unknown"
    attack_summary: str = ""
    attacker_assessment: str = ""
    victim_assessment: str = ""
    stages: list[LLMStage] = Field(default_factory=list)
    threat_entities: list[LLMThreatEntity] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    severity_hint: str | None = Field(
        default=None,
        description="Advisory only - severity is decided by the deterministic RiskScorer.",
    )
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    # ---- provenance (filled in by the provider/invoker, not by the model) ----
    prompt_version: str | None = None
    provider: str | None = None
    model: str | None = None
    request_id: str | None = None
    usage: LLMUsage | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    degraded: bool = False
    degraded_reason: str | None = None
    raw_response: dict[str, Any] | None = None

    @field_validator("stages")
    @classmethod
    def _sort_stages(cls, value: list[LLMStage]) -> list[LLMStage]:
        return sorted(value, key=lambda stage: stage.stage_index)

    @property
    def evidence_event_ids(self) -> list[str]:
        seen: dict[str, None] = {}
        for stage in self.stages:
            for event_id in stage.evidence_event_ids:
                seen.setdefault(event_id, None)
        return list(seen)


class AttackAnalysisRequest(BaseModel):
    """Provider-agnostic request handed to every :class:`LLMProvider`."""

    model_config = ConfigDict(extra="allow")

    request_id: str = Field(default_factory=lambda: f"req_{uuid.uuid4().hex[:16]}")
    task_id: str
    candidate_id: str
    prompt_version: str
    system_prompt: str
    user_prompt: str
    evidence_event_ids: list[str] = Field(default_factory=list)
    allowed_tactics: list[str] = Field(default_factory=list)
    allowed_techniques: list[str] = Field(default_factory=list)
    evidence_summary: dict[str, Any] = Field(default_factory=dict)
    temperature: float | None = None
    max_output_tokens: int | None = None
    model: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def messages(self) -> list[dict[str, str]]:
        return [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": self.user_prompt},
        ]

    @property
    def estimated_chars(self) -> int:
        return len(self.system_prompt) + len(self.user_prompt)


class LLMCallRecord(BaseModel):
    """Audit record of exactly one logical LLM call (spec §18)."""

    model_config = ConfigDict(extra="allow")

    request_id: str
    task_id: str
    candidate_id: str
    provider: str
    model: str | None = None
    prompt_version: str
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None
    latency_ms: float = 0.0
    retry_count: int = 0
    status: LLMCallStatus = LLMCallStatus.SUCCESS
    error: str | None = None
    fallback_used: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    attempts: list[dict[str, Any]] = Field(default_factory=list)
    estimated_prompt_chars: int | None = None

    @property
    def ok(self) -> bool:
        return self.status == LLMCallStatus.SUCCESS
