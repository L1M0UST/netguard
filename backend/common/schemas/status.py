"""Task status contract written to ``06_status/m2/task_xxx.json``."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.common.schemas.enums import TaskStatus
from backend.common.schemas.version import TASK_STATUS_SCHEMA_VERSION


class BatchProgress(BaseModel):
    """Bookkeeping for one consumed ``SuspiciousEventBatch.v1``."""

    model_config = ConfigDict(extra="allow")

    batch_id: str
    file_name: str | None = None
    sha256: str | None = None
    row_count: int = 0
    status: str = "pending"
    error: str | None = None


class TaskStatusRecord(BaseModel):
    """Status of one Module 2 task run."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    schema_version: str = TASK_STATUS_SCHEMA_VERSION
    task_id: str
    status: TaskStatus = TaskStatus.PENDING
    progress: float = Field(default=0.0, ge=0.0, le=100.0)
    current_stage: str | None = None
    input_batches: int = Field(default=0, ge=0)
    processed_batches: int = Field(default=0, ge=0)
    attack_candidates: int = Field(default=0, ge=0)
    attack_events: int = Field(default=0, ge=0)
    llm_calls: int = Field(default=0, ge=0)
    llm_failures: int = Field(default=0, ge=0)
    started_at: datetime | None = None
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    error: str | None = None
    batches: list[BatchProgress] = Field(default_factory=list)
    output_path: str | None = None
    idempotent_replay: bool = False
    metrics: dict[str, Any] = Field(default_factory=dict)

    @field_validator("progress")
    @classmethod
    def _clamp(cls, value: float) -> float:
        return max(0.0, min(100.0, value))

    def touch(self) -> TaskStatusRecord:
        self.updated_at = datetime.now(UTC)
        return self
