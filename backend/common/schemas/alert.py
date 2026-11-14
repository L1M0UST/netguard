"""``Alert`` contract consumed by Module 3."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from backend.common.schemas.enums import Severity
from backend.common.schemas.version import ALERT_SCHEMA_VERSION


class Alert(BaseModel):
    """Actionable alert derived from one attack chain."""

    model_config = ConfigDict(extra="allow", populate_by_name=True, str_strip_whitespace=True)

    schema_version: str = ALERT_SCHEMA_VERSION
    alert_id: str
    task_id: str
    chain_id: str
    title: str
    description: str = ""
    severity: Severity = Severity.INFO
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    attacker_ips: list[str] = Field(default_factory=list)
    victim_ips: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    evidence_event_ids: list[str] = Field(default_factory=list)
    fingerprint: str | None = None
    source: str = "module2_chain"
    status: str = "new"
    llm_degraded: bool = False
    risk_factors: list[dict[str, Any]] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
