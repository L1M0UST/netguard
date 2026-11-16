"""Attack correlation contracts: candidates, techniques, chains, risk scores.

These models cross the Module 2 -> Module 3 boundary (``AttackChain``) or are
internal to the correlation pipeline (``AttackCandidate``).  Module 3 may read
``AttackCandidate`` for drill-down, therefore it lives in the public schema.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.common.schemas.enums import Severity, TechniqueSource
from backend.common.schemas.version import ATTACK_CHAIN_SCHEMA_VERSION

_BASE_CONFIG = ConfigDict(extra="allow", populate_by_name=True, str_strip_whitespace=True)


class ScoreSummary(BaseModel):
    """Aggregated Module 1 detection score of one candidate group."""

    model_config = _BASE_CONFIG

    event_count: int = Field(default=0, ge=0)
    max_score: float = 0.0
    mean_score: float = 0.0
    sum_score: float = 0.0
    p95_score: float = 0.0


class RiskFactor(BaseModel):
    """One explainable contribution to a risk or confidence score."""

    model_config = _BASE_CONFIG

    name: str
    weight: float
    value: float
    contribution: float
    description: str | None = None
    evidence_event_ids: list[str] = Field(default_factory=list)


class RiskScore(BaseModel):
    """Deterministic, explainable risk score."""

    model_config = _BASE_CONFIG

    score: float = Field(default=0.0, ge=0.0, le=100.0)
    severity: Severity = Severity.INFO
    factors: list[RiskFactor] = Field(default_factory=list)
    rationale: list[str] = Field(default_factory=list)


class CandidateTechnique(BaseModel):
    """ATT&CK tactic/technique candidate derived from rules, IOC or the LLM."""

    model_config = _BASE_CONFIG

    tactic_id: str
    tactic_name: str
    technique_id: str | None = None
    technique_name: str | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_event_ids: list[str] = Field(default_factory=list)
    reason: str = ""
    source: TechniqueSource = TechniqueSource.RULE
    matched_rules: list[str] = Field(default_factory=list)


class ThreatIntelRef(BaseModel):
    """Threat-intelligence enrichment attached to a candidate/chain."""

    model_config = _BASE_CONFIG

    indicator: str
    indicator_type: str
    malicious: bool = False
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    source: str = "local"
    tags: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    description: str | None = None
    evidence_event_ids: list[str] = Field(default_factory=list)


class AttackCandidate(BaseModel):
    """Correlated group of suspicious events that plausibly belong together."""

    model_config = _BASE_CONFIG

    candidate_id: str
    task_id: str
    attacker_ips: list[str] = Field(default_factory=list)
    victim_ips: list[str] = Field(default_factory=list)
    victim_ports: list[int] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    protocols: list[str] = Field(default_factory=list)
    rule_hits: list[str] = Field(default_factory=list)
    ioc_hits: list[str] = Field(default_factory=list)
    score_summary: ScoreSummary = Field(default_factory=ScoreSummary)
    # ---- additive v1.0.0 fields ----------------------------------------
    session_ids: list[str] = Field(default_factory=list)
    attack_categories: list[str] = Field(default_factory=list)
    cluster_keys: list[str] = Field(default_factory=list)
    correlation_score: float = Field(default=0.0, ge=0.0, le=1.0)
    correlation_reasons: list[str] = Field(default_factory=list)
    threat_intel: list[ThreatIntelRef] = Field(default_factory=list)
    techniques: list[CandidateTechnique] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_window(self) -> AttackCandidate:
        if self.last_seen < self.first_seen:
            object.__setattr__(self, "last_seen", self.first_seen)
        return self

    @property
    def duration_seconds(self) -> float:
        return max(0.0, (self.last_seen - self.first_seen).total_seconds())


class ChainStage(BaseModel):
    """One ordered stage of an attack chain."""

    model_config = _BASE_CONFIG

    stage_index: int = Field(ge=1)
    tactic: str
    technique: str | None = None
    narrative: str = ""
    evidence_event_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    tactic_name: str | None = None
    technique_name: str | None = None
    source: TechniqueSource = TechniqueSource.RULE

    @field_validator("evidence_event_ids")
    @classmethod
    def _dedupe_evidence(cls, value: list[str]) -> list[str]:
        seen: dict[str, None] = {}
        for item in value:
            if item:
                seen.setdefault(item, None)
        return list(seen)


class LLMMeta(BaseModel):
    """Provenance of the (optional) LLM reasoning behind a chain."""

    model_config = _BASE_CONFIG

    provider: str = "none"
    model: str | None = None
    prompt_version: str | None = None
    request_id: str | None = None
    status: str = "not_called"
    llm_degraded: bool = False
    latency_ms: float | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    retry_count: int = 0
    error: str | None = None


class AttackChain(BaseModel):
    """Module 2 -> Module 3 primary output."""

    model_config = _BASE_CONFIG

    schema_version: str = ATTACK_CHAIN_SCHEMA_VERSION
    chain_id: str
    task_id: str
    stages: list[ChainStage] = Field(default_factory=list)
    severity: Severity = Severity.INFO
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    summary: str = ""
    mitre_tactics: list[str] = Field(default_factory=list)
    llm_meta: LLMMeta = Field(default_factory=LLMMeta)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    # ---- additive v1.0.0 fields ----------------------------------------
    fingerprint: str | None = None
    risk_score: RiskScore = Field(default_factory=RiskScore)
    confidence_factors: list[RiskFactor] = Field(default_factory=list)
    attacker_ips: list[str] = Field(default_factory=list)
    victim_ips: list[str] = Field(default_factory=list)
    victim_ports: list[int] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    candidate_ids: list[str] = Field(default_factory=list)
    threat_entities: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    # ---- why these events were correlated into one chain (edge evidence) ----
    correlation_score: float = Field(default=0.0, ge=0.0, le=1.0)
    correlation_reasons: list[str] = Field(default_factory=list)
    evidence_validation: dict[str, Any] = Field(default_factory=dict)
    llm_degraded: bool = False
    deduplicated_from: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @property
    def tactic_ids(self) -> list[str]:
        ordered: dict[str, None] = {}
        for stage in sorted(self.stages, key=lambda item: item.stage_index):
            ordered.setdefault(stage.tactic, None)
        return list(ordered)

    @property
    def technique_ids(self) -> list[str]:
        return [stage.technique for stage in self.stages if stage.technique]

    def all_evidence_event_ids(self) -> list[str]:
        ordered: dict[str, None] = {}
        for stage in sorted(self.stages, key=lambda item: item.stage_index):
            for event_id in stage.evidence_event_ids:
                ordered.setdefault(event_id, None)
        return list(ordered)
