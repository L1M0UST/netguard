"""Internal pipeline models (not part of the shared contract)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from backend.common.schemas.attack import AttackCandidate, AttackChain
from backend.common.schemas.enums import Severity, TaskStatus
from backend.common.schemas.suspicious_event import SuspiciousEvent

_CFG = ConfigDict(extra="allow", arbitrary_types_allowed=True)

IssueSeverity = Literal["error", "warning", "info"]


class ValidationIssue(BaseModel):
    """One integrity/compatibility problem found in an input batch."""

    model_config = _CFG

    code: str
    message: str
    severity: IssueSeverity = "error"
    location: str | None = None
    task_id: str | None = None
    batch_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class WorkspaceTaskDescriptor(BaseModel):
    """A task folder discovered in the inbox."""

    model_config = _CFG

    task_id: str
    task_dir: Path
    marker: str
    manifest_path: Path | None = None
    batch_files: list[Path] = Field(default_factory=list)
    total_size_bytes: int = 0
    modified_at: float = 0.0
    owner: str | None = None
    claimed_at: datetime | None = None
    stale: bool = False


class ClaimOutcome(BaseModel):
    """Result of trying to become the sole processor of a task folder."""

    model_config = _CFG

    claimed: bool
    task_id: str
    reason: str = ""
    owner: str | None = None
    claimed_at: datetime | None = None
    recovered_stale_lease: bool = False
    descriptor: WorkspaceTaskDescriptor | None = None


class ValidationResult(BaseModel):
    """Outcome of input validation for one task (all batches combined)."""

    model_config = _CFG

    task_id: str
    valid: bool
    issues: list[ValidationIssue] = Field(default_factory=list)
    verified_files: list[str] = Field(default_factory=list)
    batch_ids: list[str] = Field(default_factory=list)
    manifest_checksum: str | None = None
    schema_versions: list[str] = Field(default_factory=list)

    @property
    def errors(self) -> list[ValidationIssue]:
        return [issue for issue in self.issues if issue.severity == "error"]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [issue for issue in self.issues if issue.severity == "warning"]


class IngestionResult(BaseModel):
    """Normalised suspicious events read from all batches of one task."""

    model_config = _CFG

    task_id: str
    events: list[SuspiciousEvent] = Field(default_factory=list)
    batch_ids: list[str] = Field(default_factory=list)
    batch_row_counts: dict[str, int] = Field(default_factory=dict)
    raw_row_count: int = 0
    dropped_row_count: int = 0
    issues: list[ValidationIssue] = Field(default_factory=list)

    @property
    def event_count(self) -> int:
        return len(self.events)


class DeduplicationResult(BaseModel):
    """Events after deterministic de-duplication."""

    model_config = _CFG

    events: list[SuspiciousEvent] = Field(default_factory=list)
    input_count: int = 0
    duplicate_event_id_count: int = 0
    content_duplicate_count: int = 0
    duplicate_event_ids: list[str] = Field(default_factory=list)

    @property
    def output_count(self) -> int:
        return len(self.events)

    @property
    def dropped_count(self) -> int:
        return self.duplicate_event_id_count + self.content_duplicate_count


class StageTiming(BaseModel):
    """Wall-clock timing of one pipeline stage."""

    model_config = _CFG

    stage: str
    duration_ms: float
    items: int | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class MetricsSnapshot(BaseModel):
    """Per-task performance metrics written to ``metrics.json``."""

    model_config = _CFG

    task_id: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    total_duration_ms: float = 0.0
    stage_timings: list[StageTiming] = Field(default_factory=list)
    events_ingested: int = 0
    events_deduplicated: int = 0
    events_unique: int = 0
    events_in_chains: int = 0
    candidates: int = 0
    chains: int = 0
    alerts: int = 0
    llm_calls: int = 0
    llm_failures: int = 0
    llm_tokens_input: int = 0
    llm_tokens_output: int = 0
    llm_latency_p50_ms: float | None = None
    llm_latency_p95_ms: float | None = None
    llm_latency_p99_ms: float | None = None
    events_per_second: float = 0.0
    candidates_per_second: float = 0.0
    llm_calls_per_candidate: float = 0.0
    llm_call_ratio: float = 0.0
    peak_memory_mb: float | None = None
    extra: dict[str, Any] = Field(default_factory=dict)

    def stage_duration(self, stage: str) -> float | None:
        for timing in self.stage_timings:
            if timing.stage == stage:
                return timing.duration_ms
        return None


class EvidenceIssue(BaseModel):
    """One problem found while validating LLM output against real events."""

    model_config = _CFG

    code: str
    message: str
    severity: IssueSeverity = "warning"
    stage_index: int | None = None
    event_id: str | None = None
    field: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class EvidenceValidationResult(BaseModel):
    """Evidence Validation stage output."""

    model_config = _CFG

    candidate_id: str
    valid: bool = True
    hallucination_detected: bool = False
    degraded_to_rules: bool = False
    issues: list[EvidenceIssue] = Field(default_factory=list)
    unknown_event_ids: list[str] = Field(default_factory=list)
    dropped_stage_indexes: list[int] = Field(default_factory=list)
    valid_evidence_count: int = 0
    confidence_penalty: float = 0.0
    notes: list[str] = Field(default_factory=list)

    @property
    def error_count(self) -> int:
        return len([issue for issue in self.issues if issue.severity == "error"])

    @property
    def warning_count(self) -> int:
        return len([issue for issue in self.issues if issue.severity == "warning"])


class CandidateAnalysis(BaseModel):
    """End-to-end analysis state of a single attack candidate."""

    model_config = _CFG

    candidate: AttackCandidate
    stage: str = "pending"
    llm_analysis: Any | None = None
    llm_record: Any | None = None
    validation: EvidenceValidationResult | None = None
    fallback_used: bool = False
    error: str | None = None
    chain: AttackChain | None = None

    @property
    def llm_degraded(self) -> bool:
        return self.fallback_used or bool(self.error)


class TaskOutcome(BaseModel):
    """Result of processing a single task folder."""

    model_config = _CFG

    task_id: str
    status: TaskStatus
    chain_ids: list[str] = Field(default_factory=list)
    alert_ids: list[str] = Field(default_factory=list)
    attacker_ids: list[str] = Field(default_factory=list)
    entity_count: int = 0
    candidate_count: int = 0
    event_count: int = 0
    badge: Severity = Severity.INFO
    bundle_path: Path | None = None
    report_path: Path | None = None
    metrics: MetricsSnapshot | None = None
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    skipped_reason: str | None = None
    idempotent_replay: bool = False
    duration_ms: float = 0.0
