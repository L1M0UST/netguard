"""``AttackerProfile`` contract - "攻击者画像".

Profiles are *evidence bounded*: when the evidence does not support a claim
(group name, nationality, real identity, ...) the field must stay ``None`` or
``"Not Determined"``.  Never invent attribution.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from backend.common.schemas.enums import Severity
from backend.common.schemas.version import ATTACKER_PROFILE_SCHEMA_VERSION

UNKNOWN_ATTRIBUTION = "Not Determined"


class AttackerProfile(BaseModel):
    """Aggregated behavioural picture of one attacker entity."""

    model_config = ConfigDict(extra="allow", populate_by_name=True, str_strip_whitespace=True)

    schema_version: str = ATTACKER_PROFILE_SCHEMA_VERSION
    attacker_id: str
    task_id: str
    attacker_ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    usernames: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    target_assets: list[str] = Field(default_factory=list)
    target_ports: list[int] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    attack_count: int = Field(default=0, ge=0)
    severity_distribution: dict[str, int] = Field(default_factory=dict)
    behavior_summary: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_event_ids: list[str] = Field(default_factory=list)
    chain_ids: list[str] = Field(default_factory=list)
    # ---- attribution fields: unknown unless evidence proves otherwise ----
    attribution: str = UNKNOWN_ATTRIBUTION
    attribution_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    attribution_evidence_event_ids: list[str] = Field(default_factory=list)
    max_severity: Severity = Severity.INFO
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    observed_iocs: list[str] = Field(default_factory=list)
    attack_patterns: list[str] = Field(default_factory=list)
    llm_degraded: bool = False
    notes: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)
