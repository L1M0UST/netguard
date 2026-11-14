"""Read ``SuspiciousEventBatch.v1`` parquet files into pydantic models (M2-F1).

Columnar I/O uses Polars.  Three physical layouts are supported so that Module 1
may pick whichever is convenient **without breaking the contract**:

1. dotted columns   - ``event.event_id``, ``detection.score``
2. nested structs   - ``event`` / ``detection`` struct columns
3. snake_case flat  - ``event_id``, ``matched_rules``

Rows that cannot be parsed are dropped with a structured ``info``/``error``
issue instead of failing the whole task.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import polars as pl
from pydantic import ValidationError

from backend.common.schemas.workspace import MANIFEST_FILE
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.ingestion.validator import BatchValidator
from backend.module2_chain.scanner.manifest import load_manifest
from backend.module2_chain.schemas.internal import (
    IngestionResult,
    ValidationIssue,
    WorkspaceTaskDescriptor,
)

logger = get_logger("ingestion.batch_reader")

EVENT_FIELDS = frozenset(
    {
        "event_id",
        "task_id",
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "payload_digest",
        "raw_ref",
        "source_file",
    }
)
DETECTION_FIELDS = frozenset({"matched_rules", "ioc_hits", "score", "reason", "detector"})
TOP_LEVEL_FIELDS = frozenset({"session_id", "emitted_at", "schema_version"})


class BatchFormatError(RuntimeError):
    """Raised when a batch file cannot be read at all (corrupted input)."""


class BatchReader:
    """Reads all batches of a task into normalised :class:`SuspiciousEvent` objects."""

    def __init__(self, config: AppConfig, *, validator: BatchValidator | None = None) -> None:
        self.config = config
        self.validator = validator or BatchValidator(config)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def read_task(
        self,
        descriptor: WorkspaceTaskDescriptor,
        *,
        file_paths: Iterable[Path] | None = None,
    ) -> IngestionResult:
        """Read every batch of a task folder."""

        paths = list(file_paths) if file_paths is not None else list(descriptor.batch_files)
        if descriptor.manifest_path is None and self.config.ingestion.require_manifest:
            raise BatchFormatError(
                f"task {descriptor.task_id} has no {MANIFEST_FILE} and "
                "ingestion.require_manifest is enabled"
            )

        result = IngestionResult(task_id=descriptor.task_id)
        batch_ids = self._batch_ids(descriptor)
        result.batch_ids = batch_ids

        for index, path in enumerate(sorted(paths)):
            batch_id = batch_ids[index] if index < len(batch_ids) else path.stem
            events, issues, raw_rows = self.read_file(path, task_id=descriptor.task_id)
            result.events.extend(events)
            result.issues.extend(issues)
            result.raw_row_count += raw_rows
            result.dropped_row_count += max(0, raw_rows - len(events))
            result.batch_row_counts[batch_id] = raw_rows

        result.issues.extend(
            self.validator.validate_events(result.events, expected_task_id=descriptor.task_id)
        )
        logger.info(
            "batch ingestion finished",
            extra={
                "task_id": descriptor.task_id,
                "stage": "ingestion",
                "batches": len(paths),
                "rows": result.raw_row_count,
                "events": result.event_count,
                "dropped": result.dropped_row_count,
            },
        )
        return result

    def read_file(
        self, path: Path, *, task_id: str | None = None
    ) -> tuple[list[Any], list[ValidationIssue], int]:
        """Read a single parquet file."""

        path = Path(path)
        if not path.is_file():
            raise BatchFormatError(f"batch file not found: {path}")
        try:
            frame = pl.read_parquet(path)
        except Exception as exc:  # pragma: no cover - polars raises many types
            raise BatchFormatError(f"cannot read parquet file {path}: {exc}") from exc

        raw_rows = frame.height
        if raw_rows > self.config.ingestion.max_rows_per_batch:
            raise BatchFormatError(
                f"{path} contains {raw_rows} rows, exceeding "
                f"ingestion.max_rows_per_batch={self.config.ingestion.max_rows_per_batch}"
            )

        events: list[Any] = []
        issues: list[ValidationIssue] = []
        for row_index, row in enumerate(frame.iter_rows(named=True)):
            try:
                event = self._row_to_event(row)
            except (ValidationError, ValueError, TypeError) as exc:
                issues.append(
                    ValidationIssue(
                        code="row_parse_error",
                        message=f"row {row_index} could not be parsed: {exc}",
                        severity="error",
                        task_id=task_id,
                        location=str(path),
                        details={"row_index": row_index},
                    )
                )
                continue
            if task_id and event.event.task_id != task_id:
                event.event.task_id = task_id
            row_issues = self.validator.validate_event(event)
            fatal = [issue for issue in row_issues if issue.severity == "error"]
            issues.extend(row_issues)
            if fatal:
                continue
            events.append(event)
        return events, issues, raw_rows

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    def _batch_ids(self, descriptor: WorkspaceTaskDescriptor) -> list[str]:
        if descriptor.manifest_path is None:
            return []
        try:
            manifest = load_manifest(descriptor.manifest_path)
        except Exception:  # pragma: no cover - already validated earlier
            return []
        ids = [manifest.batch_id]
        for ref in manifest.files:
            ids.append(Path(ref.path).stem)
        return ids

    def _row_to_event(self, row: Mapping[str, Any]) -> Any:
        from backend.common.schemas.suspicious_event import SuspiciousEvent

        payload = row_to_payload(row)
        return SuspiciousEvent.model_validate(payload)


def row_to_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    """Normalise one physical row into the nested contract layout."""

    nested: dict[str, dict[str, Any]] = {}
    flat: dict[str, Any] = {}
    for key, value in row.items():
        if key is None:
            continue
        if isinstance(value, Mapping) and key in {"event", "detection"}:
            nested.setdefault(key, {}).update(value)
            continue
        if "." in key:
            head, _, tail = key.partition(".")
            nested.setdefault(head, {})[tail] = value
            continue
        if key in EVENT_FIELDS:
            nested.setdefault("event", {})[key] = value
            continue
        if key in DETECTION_FIELDS:
            nested.setdefault("detection", {})[key] = value
            continue
        if key in TOP_LEVEL_FIELDS:
            flat[key] = value
            continue
        flat[key] = value

    payload: dict[str, Any] = dict(flat)
    payload.update(nested)
    event_payload = payload.get("event")
    if isinstance(event_payload, Mapping) and "timestamp" in event_payload:
        event_payload = dict(event_payload)
        event_payload["timestamp"] = normalise_timestamp(event_payload["timestamp"])
        payload["event"] = event_payload
    if "emitted_at" in payload:
        payload["emitted_at"] = normalise_timestamp(payload["emitted_at"])
    return payload


def normalise_timestamp(value: Any) -> Any:
    """Assume UTC for naive timestamps coming from parquet."""

    if isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value
