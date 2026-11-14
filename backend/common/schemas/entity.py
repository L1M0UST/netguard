"""``ThreatEntity`` contract - "威胁要素" extracted from attack chains."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from backend.common.schemas.enums import EntityRole, EntityType
from backend.common.schemas.version import THREAT_ENTITY_SCHEMA_VERSION


class ThreatEntity(BaseModel):
    """A single observable/indicator with an evidence trail."""

    model_config = ConfigDict(extra="allow", populate_by_name=True, str_strip_whitespace=True)

    schema_version: str = THREAT_ENTITY_SCHEMA_VERSION
    entity_id: str
    entity_type: EntityType
    value: str
    role: EntityRole = EntityRole.UNKNOWN
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_event_ids: list[str] = Field(default_factory=list)
    chain_ids: list[str] = Field(default_factory=list)
    task_id: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    source: str = "module2_chain"
    tags: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)
