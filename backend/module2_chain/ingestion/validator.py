"""Input integrity and schema validation (M2-F2).

Two levels are checked:

* **transport level** - markers, manifest, sha256, file size, schema version;
* **record level** - required fields, timestamp sanity, task id consistency.

Only *transport* problems that threaten integrity (corrupted input, unsupported
schema, unreadable workspace) abort the task.  Record level problems drop the
offending row and continue, so a single dirty row can never fail a task.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from backend.common.schemas.suspicious_event import SuspiciousEvent
from backend.common.schemas.workspace import MANIFEST_FILE
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.scanner.manifest import (
    ManifestError,
    load_manifest,
    load_manifest_payload,
    manifest_checksum,
    verify_manifest,
)
from backend.module2_chain.schemas.internal import (
    ValidationIssue,
    ValidationResult,
    WorkspaceTaskDescriptor,
)

logger = get_logger("ingestion.validator")


class BatchValidator:
    """Validates a discovered task folder before it is consumed."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    # ------------------------------------------------------------------ #
    # Transport level
    # ------------------------------------------------------------------ #
    def validate_descriptor(self, descriptor: WorkspaceTaskDescriptor) -> ValidationResult:
        result = ValidationResult(task_id=descriptor.task_id, valid=True)
        ws = self.config.workspace
        if descriptor.marker.upper() not in {
            ws.ready_marker.upper(),
            ws.processing_marker.upper(),
        }:
            result.issues.append(
                ValidationIssue(
                    code="invalid_marker_state",
                    message=(
                        f"task marker is {descriptor.marker!r}; expected "
                        f"{ws.ready_marker!r} or {ws.processing_marker!r}"
                    ),
                    severity="error",
                    task_id=descriptor.task_id,
                    location=str(descriptor.task_dir),
                )
            )

        if not descriptor.batch_files:
            result.issues.append(
                ValidationIssue(
                    code="no_batch_files",
                    message="task folder contains no parquet batch files",
                    severity="error",
                    task_id=descriptor.task_id,
                    location=str(descriptor.task_dir),
                )
            )

        if descriptor.manifest_path is None:
            if self.config.ingestion.require_manifest:
                result.issues.append(
                    ValidationIssue(
                        code="manifest_missing",
                        message=f"{MANIFEST_FILE} is required but missing",
                        severity="error",
                        task_id=descriptor.task_id,
                        location=str(descriptor.task_dir),
                    )
                )
            result.valid = not result.errors
            return result

        raw_payload: dict[str, object] | None = None
        try:
            raw_payload = load_manifest_payload(descriptor.manifest_path)
            manifest = load_manifest(descriptor.manifest_path)
        except ManifestError as exc:
            result.issues.append(
                ValidationIssue(
                    code="manifest_unreadable",
                    message=str(exc),
                    severity="error",
                    task_id=descriptor.task_id,
                    location=str(descriptor.manifest_path),
                )
            )
            result.valid = False
            return result

        if manifest.task_id != descriptor.task_id:
            result.issues.append(
                ValidationIssue(
                    code="task_id_mismatch",
                    message=(
                        f"manifest.task_id={manifest.task_id!r} does not match folder "
                        f"name {descriptor.task_id!r}"
                    ),
                    severity="error",
                    task_id=descriptor.task_id,
                    batch_id=manifest.batch_id,
                    location=str(descriptor.manifest_path),
                )
            )

        result.batch_ids.append(manifest.batch_id)
        result.schema_versions.append(manifest.schema_version)
        result.manifest_checksum = (
            manifest.checksum or manifest_checksum(raw_payload)
            if raw_payload is not None
            else manifest.checksum
        )
        result.issues.extend(
            verify_manifest(
                manifest,
                descriptor.task_dir,
                settings=self.config.ingestion,
                raw_payload=raw_payload,
                manifest_path=descriptor.manifest_path,
            )
        )

        declared = {ref.path for ref in manifest.files}
        discovered = {str(path.relative_to(descriptor.task_dir)) for path in descriptor.batch_files}
        for extra in sorted(discovered - declared):
            result.issues.append(
                ValidationIssue(
                    code="undeclared_batch_file",
                    message=f"{extra} exists in the folder but is not declared in the manifest",
                    severity="warning",
                    task_id=descriptor.task_id,
                    batch_id=manifest.batch_id,
                    location=str(descriptor.task_dir / extra),
                )
            )
        for missing in sorted(declared - discovered):
            result.issues.append(
                ValidationIssue(
                    code="declared_file_not_discovered",
                    message=f"{missing} is declared but was not discovered on disk",
                    severity="error",
                    task_id=descriptor.task_id,
                    batch_id=manifest.batch_id,
                    location=str(descriptor.task_dir / missing),
                )
            )
        result.verified_files = sorted(declared & discovered)
        result.valid = not result.errors

        logger.info(
            "batch validation finished",
            extra={
                "task_id": descriptor.task_id,
                "batch_id": manifest.batch_id,
                "stage": "validation",
                "valid": result.valid,
                "errors": len(result.errors),
                "warnings": len(result.warnings),
            },
        )
        return result

    # ------------------------------------------------------------------ #
    # Record level
    # ------------------------------------------------------------------ #
    def validate_event(self, event: SuspiciousEvent) -> list[ValidationIssue]:
        """Per-record checks.  ``error`` issues drop the row."""

        issues: list[ValidationIssue] = []
        now = datetime.now(UTC)
        timestamp = _as_utc(event.event.timestamp)

        if not event.event.event_id:
            issues.append(
                ValidationIssue(
                    code="missing_event_id",
                    message="event_id is empty",
                    severity="error",
                    task_id=event.event.task_id,
                )
            )
        if not event.event.src_ip and not event.event.dst_ip:
            issues.append(
                ValidationIssue(
                    code="missing_addresses",
                    message="both src_ip and dst_ip are empty",
                    severity="error",
                    task_id=event.event.task_id,
                )
            )
        elif event.event.src_ip and event.event.src_ip == event.event.dst_ip:
            issues.append(
                ValidationIssue(
                    code="identical_addresses",
                    message="src_ip equals dst_ip",
                    severity="info",
                    task_id=event.event.task_id,
                )
            )
        if timestamp > now + timedelta(
            seconds=self.config.ingestion.reject_future_timestamps_seconds
        ):
            issues.append(
                ValidationIssue(
                    code="future_timestamp",
                    message=f"timestamp {timestamp.isoformat()} is too far in the future",
                    severity="error",
                    task_id=event.event.task_id,
                )
            )
        if timestamp.year < self.config.ingestion.reject_ancient_timestamps_year:
            issues.append(
                ValidationIssue(
                    code="ancient_timestamp",
                    message=f"timestamp {timestamp.isoformat()} predates the accepted range",
                    severity="error",
                    task_id=event.event.task_id,
                )
            )
        if event.detection.score < 0:
            issues.append(
                ValidationIssue(
                    code="negative_score",
                    message=f"detection.score={event.detection.score} is negative",
                    severity="warning",
                    task_id=event.event.task_id,
                )
            )
        return issues

    def validate_events(
        self,
        events: list[SuspiciousEvent],
        *,
        expected_task_id: str | None = None,
    ) -> list[ValidationIssue]:
        """Cross-record checks (task id consistency, duplicate ids)."""

        issues: list[ValidationIssue] = []
        seen: dict[str, int] = {}
        for event in events:
            if expected_task_id and event.event.task_id != expected_task_id:
                issues.append(
                    ValidationIssue(
                        code="event_task_id_mismatch",
                        message=(
                            f"event {event.event_id} belongs to task "
                            f"{event.event.task_id!r} but was found in {expected_task_id!r}"
                        ),
                        severity="error",
                        task_id=expected_task_id,
                        details={"event_id": event.event_id},
                    )
                )
            seen[event.event.event_id] = seen.get(event.event.event_id, 0) + 1
        duplicated = [event_id for event_id, count in seen.items() if count > 1]
        if duplicated:
            issues.append(
                ValidationIssue(
                    code="duplicate_event_ids",
                    message=f"{len(duplicated)} event_id values appear more than once",
                    severity="warning",
                    task_id=expected_task_id,
                    details={"sample": duplicated[:10], "count": len(duplicated)},
                )
            )
        return issues


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
