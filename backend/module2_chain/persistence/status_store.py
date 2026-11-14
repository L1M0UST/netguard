"""Task status files (M2-F21, spec §31).

``06_status/m2/task_xxx.json`` is written atomically after every stage so an
operator can follow progress and a crashed run can be diagnosed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from backend.common.schemas.enums import TaskStatus
from backend.common.schemas.status import BatchProgress, TaskStatusRecord
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.reporting.atomic_io import atomic_write_json

logger = get_logger("persistence.status_store")


class TaskStatusStore:
    """Reads and writes ``06_status/m2`` documents."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.directory = config.status_dir

    def path(self, task_id: str) -> Path:
        return self.directory / f"{task_id}.json"

    def load(self, task_id: str) -> TaskStatusRecord | None:
        path = self.path(task_id)
        if not path.is_file():
            return None
        try:
            return TaskStatusRecord.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception as exc:  # pragma: no cover - corrupted status file
            logger.warning(
                "could not read the task status file",
                extra={"task_id": task_id, "stage": "status", "error": str(exc)},
            )
            return None

    def save(self, record: TaskStatusRecord) -> Path:
        record.touch()
        return atomic_write_json(
            self.path(record.task_id),
            record.model_dump(mode="json"),
            fsync=self.config.workspace.atomic_write.fsync,
        )

    def start(self, task_id: str, *, input_batches: int = 0) -> TaskStatusRecord:
        record = TaskStatusRecord(
            task_id=task_id,
            status=TaskStatus.PROCESSING,
            progress=1.0,
            current_stage="discovery",
            input_batches=input_batches,
            started_at=datetime.now(UTC),
        )
        self.save(record)
        return record

    def update(
        self,
        task_id: str,
        *,
        progress: float | None = None,
        current_stage: str | None = None,
        status: TaskStatus | None = None,
        **fields: Any,
    ) -> TaskStatusRecord:
        record = self.load(task_id) or TaskStatusRecord(task_id=task_id)
        if progress is not None:
            record.progress = progress
        if current_stage is not None:
            record.current_stage = current_stage
        if status is not None:
            record.status = status
        for key, value in fields.items():
            if hasattr(record, key):
                setattr(record, key, value)
        self.save(record)
        return record

    def complete(
        self,
        task_id: str,
        *,
        output_path: str | None = None,
        counts: dict[str, int] | None = None,
        metrics: dict[str, Any] | None = None,
        idempotent_replay: bool = False,
    ) -> TaskStatusRecord:
        record = self.load(task_id) or TaskStatusRecord(task_id=task_id)
        record.status = TaskStatus.COMPLETED
        record.progress = 100.0
        record.current_stage = "bundle_write"
        record.completed_at = datetime.now(UTC)
        record.output_path = output_path
        record.idempotent_replay = idempotent_replay
        if counts:
            record.processed_batches = counts.get("processed_batches", record.processed_batches)
            record.attack_candidates = counts.get("attack_candidates", record.attack_candidates)
            record.attack_events = counts.get("attack_events", record.attack_events)
            record.llm_calls = counts.get("llm_calls", record.llm_calls)
            record.llm_failures = counts.get("llm_failures", record.llm_failures)
        if metrics:
            record.metrics = metrics
        self.save(record)
        return record

    def fail(
        self, task_id: str, *, error: str, progress: float | None = None
    ) -> TaskStatusRecord:
        record = self.load(task_id) or TaskStatusRecord(task_id=task_id)
        record.status = TaskStatus.FAILED
        record.error = error[:2000]
        record.completed_at = datetime.now(UTC)
        if progress is not None:
            record.progress = progress
        self.save(record)
        return record

    def cancel(self, task_id: str, *, reason: str = "cancelled") -> TaskStatusRecord:
        record = self.load(task_id) or TaskStatusRecord(task_id=task_id)
        record.status = TaskStatus.CANCELLED
        record.error = reason
        record.completed_at = datetime.now(UTC)
        self.save(record)
        return record

    def set_batches(self, task_id: str, batches: list[BatchProgress]) -> TaskStatusRecord:
        record = self.load(task_id) or TaskStatusRecord(task_id=task_id)
        record.batches = batches
        record.input_batches = len(batches)
        record.processed_batches = sum(1 for batch in batches if batch.status == "processed")
        self.save(record)
        return record
