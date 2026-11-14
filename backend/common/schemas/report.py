"""``RiskEventReport`` contract - "风险事件报告" for Module 3."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from backend.common.schemas.enums import MitigationKind, Severity
from backend.common.schemas.version import RISK_EVENT_REPORT_SCHEMA_VERSION

_BASE_CONFIG = ConfigDict(extra="allow", populate_by_name=True, str_strip_whitespace=True)


class Mitigation(BaseModel):
    """A remediation hint.

    ``evidence_based`` mitigations are directly supported by the evidence;
    ``general_recommendation`` ones are generic hardening advice and are
    flagged as such so downstream consumers can render them differently.
    """

    model_config = _BASE_CONFIG

    mitigation_id: str
    title: str
    description: str
    recommendation_type: MitigationKind = MitigationKind.GENERAL_RECOMMENDATION
    priority: str = "medium"
    related_techniques: list[str] = Field(default_factory=list)
    related_entities: list[str] = Field(default_factory=list)
    evidence_event_ids: list[str] = Field(default_factory=list)
    evidence_chain_ids: list[str] = Field(default_factory=list)


class ReportStatistics(BaseModel):
    """Counters required by the Module 2 acceptance criteria."""

    model_config = _BASE_CONFIG

    total_suspicious_events: int = Field(default=0, ge=0)
    deduplicated_events: int = Field(default=0, ge=0)
    total_attack_candidates: int = Field(default=0, ge=0)
    total_attack_events: int = Field(default=0, ge=0)
    critical_count: int = Field(default=0, ge=0)
    high_count: int = Field(default=0, ge=0)
    medium_count: int = Field(default=0, ge=0)
    low_count: int = Field(default=0, ge=0)
    info_count: int = Field(default=0, ge=0)
    attacker_count: int = Field(default=0, ge=0)
    victim_count: int = Field(default=0, ge=0)
    technique_count: int = Field(default=0, ge=0)
    tactic_count: int = Field(default=0, ge=0)
    entity_count: int = Field(default=0, ge=0)
    ioc_hit_count: int = Field(default=0, ge=0)
    llm_calls: int = Field(default=0, ge=0)
    llm_failures: int = Field(default=0, ge=0)
    llm_degraded_chains: int = Field(default=0, ge=0)


class ReportAttackEvent(BaseModel):
    """Compact projection of an attack chain for report/UI rendering."""

    model_config = _BASE_CONFIG

    chain_id: str
    alert_id: str | None = None
    title: str
    summary: str = ""
    severity: Severity = Severity.INFO
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    attacker_ips: list[str] = Field(default_factory=list)
    victim_ips: list[str] = Field(default_factory=list)
    victim_ports: list[int] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    stage_count: int = Field(default=0, ge=0)
    evidence_event_ids: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    llm_degraded: bool = False
    risk_factors: list[dict[str, Any]] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)


class ReportAttackerSummary(BaseModel):
    """Compact attacker projection for the report."""

    model_config = _BASE_CONFIG

    attacker_id: str
    attacker_ips: list[str] = Field(default_factory=list)
    attack_count: int = Field(default=0, ge=0)
    max_severity: Severity = Severity.INFO
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    techniques: list[str] = Field(default_factory=list)
    target_assets: list[str] = Field(default_factory=list)
    behavior_summary: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    attribution: str = "Not Determined"
    evidence_event_ids: list[str] = Field(default_factory=list)


class ReportVictimSummary(BaseModel):
    """Compact victim projection for the report."""

    model_config = _BASE_CONFIG

    victim_ip: str
    attack_count: int = Field(default=0, ge=0)
    max_severity: Severity = Severity.INFO
    tactics: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    targeted_ports: list[int] = Field(default_factory=list)
    asset_weight: float = 1.0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    evidence_event_ids: list[str] = Field(default_factory=list)


class ReportHighlight(BaseModel):
    """One narrative highlight shown at the top of the UI."""

    model_config = _BASE_CONFIG

    highlight_id: str
    title: str
    description: str
    severity: Severity = Severity.INFO
    chain_id: str | None = None
    evidence_event_ids: list[str] = Field(default_factory=list)


class EvidenceSummary(BaseModel):
    """Audit trail of how many events survived which stage."""

    model_config = _BASE_CONFIG

    total_input_events: int = Field(default=0, ge=0)
    unique_events: int = Field(default=0, ge=0)
    events_in_chains: int = Field(default=0, ge=0)
    events_without_chain: int = Field(default=0, ge=0)
    candidate_count: int = Field(default=0, ge=0)
    dropped_llm_evidence: int = Field(default=0, ge=0)
    validation_issues: int = Field(default=0, ge=0)
    per_stage: dict[str, int] = Field(default_factory=dict)


class RiskEventReport(BaseModel):
    """Top-level report written to ``05_m2_output/task_xxx/reports/report.json``."""

    model_config = _BASE_CONFIG

    schema_version: str = RISK_EVENT_REPORT_SCHEMA_VERSION
    report_id: str
    task_id: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    overview: str = ""
    statistics: ReportStatistics = Field(default_factory=ReportStatistics)
    attack_events: list[ReportAttackEvent] = Field(default_factory=list)
    attackers: list[ReportAttackerSummary] = Field(default_factory=list)
    victims: list[ReportVictimSummary] = Field(default_factory=list)
    threat_entities: list[dict[str, Any]] = Field(default_factory=list)
    highlights: list[ReportHighlight] = Field(default_factory=list)
    recommendations: list[Mitigation] = Field(default_factory=list)
    evidence_summary: EvidenceSummary = Field(default_factory=EvidenceSummary)
    llm_meta: dict[str, Any] = Field(default_factory=dict)
    metrics: dict[str, Any] = Field(default_factory=dict)
    data_contract: dict[str, str] = Field(default_factory=dict)
