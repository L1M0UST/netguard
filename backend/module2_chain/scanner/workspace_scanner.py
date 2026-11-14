"""Read-only discovery of ``04_m2_inbox`` task folders.

The scanner is strictly read-only: it never creates, renames or deletes a file.
Claiming (``READY`` -> ``PROCESSING``) is delegated to
:class:`~backend.module2_chain.scanner.claim.TaskClaimer`.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from backend.common.schemas.workspace import MANIFEST_FILE, TEMP_SUFFIX
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.schemas.internal import WorkspaceTaskDescriptor

logger = get_logger("scanner")

TASK_PREFIX = "task_"


class WorkspaceScanner:
    """Enumerate consumable tasks in the shared inbox."""

    def __init__(self, config: AppConfig, *, inbox_dir: Path | None = None) -> None:
        self.config = config
        self.inbox_dir = Path(inbox_dir) if inbox_dir else config.inbox_dir

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def is_task_dir(self, path: Path) -> bool:
        return path.is_dir() and path.name.startswith(TASK_PREFIX)

    def marker_of(self, task_dir: Path) -> str:
        """Return the highest-priority marker present in a task folder."""

        ws = self.config.workspace
        if (task_dir / ws.done_marker).is_file():
            return ws.done_marker
        if (task_dir / ws.ready_marker).is_file():
            return ws.ready_marker
        if (task_dir / ws.processing_marker).is_file():
            return ws.processing_marker
        if (task_dir / ws.failed_marker).is_file():
            return ws.failed_marker
        return "UNMARKED"

    def batch_files(self, task_dir: Path) -> list[Path]:
        """Payload files of a task folder (parquet, excludes temp/partial files)."""

        candidates: list[Path] = []
        for entry in sorted(task_dir.iterdir()):
            if not entry.is_file():
                continue
            name = entry.name
            if name.endswith(TEMP_SUFFIX) or name.startswith("."):
                continue
            if name in {
                MANIFEST_FILE,
                self.config.workspace.ready_marker,
                self.config.workspace.processing_marker,
                self.config.workspace.done_marker,
                self.config.workspace.failed_marker,
            }:
                continue
            if self.config.ingestion.batch_format in {"parquet", "auto"} and (
                entry.suffix.lower() not in {".parquet", ".pq"}
            ):
                continue
            candidates.append(entry)
        return candidates

    def describe(self, task_dir: Path) -> WorkspaceTaskDescriptor:
        task_dir = Path(task_dir)
        files = self.batch_files(task_dir)
        manifest_path = task_dir / MANIFEST_FILE
        total_size = 0
        for file_path in files:
            try:
                total_size += file_path.stat().st_size
            except OSError:  # pragma: no cover - race with producer
                continue
        try:
            modified_at = task_dir.stat().st_mtime
        except OSError:  # pragma: no cover - race with producer
            modified_at = 0.0
        return WorkspaceTaskDescriptor(
            task_id=task_dir.name,
            task_dir=task_dir,
            marker=self.marker_of(task_dir),
            manifest_path=manifest_path if manifest_path.is_file() else None,
            batch_files=files,
            total_size_bytes=total_size,
            modified_at=modified_at,
            stale=(datetime.now(UTC).timestamp() - modified_at)
            > self.config.workspace.claim.stale_after_seconds,
        )

    def iter_task_dirs(self) -> Iterable[Path]:
        if not self.inbox_dir.is_dir():
            logger.warning(
                "inbox directory does not exist",
                extra={"stage": "discovery", "path": str(self.inbox_dir)},
            )
            return []
        return [entry for entry in sorted(self.inbox_dir.iterdir()) if self.is_task_dir(entry)]

    def scan(
        self,
        *,
        states: Iterable[str] | None = None,
        include_processed: bool = False,
    ) -> list[WorkspaceTaskDescriptor]:
        """Return descriptors for task folders in the requested states.

        By default only ``READY`` folders are returned, which is what the
        regular pipeline consumes.
        """

        wanted = {state.upper() for state in states} if states else {self.config.workspace.ready_marker}
        descriptors: list[WorkspaceTaskDescriptor] = []
        for task_dir in self.iter_task_dirs():
            descriptor = self.describe(task_dir)
            marker = descriptor.marker.upper()
            if marker in wanted:
                if marker == self.config.workspace.done_marker.upper() and not include_processed:
                    continue
                descriptors.append(descriptor)
        descriptors.sort(key=lambda item: item.modified_at)
        return descriptors

    def find_task(self, task_id: str) -> WorkspaceTaskDescriptor | None:
        task_dir = self.inbox_dir / task_id
        if not self.is_task_dir(task_dir):
            return None
        return self.describe(task_dir)
