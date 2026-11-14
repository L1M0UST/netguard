"""Atomic claim of a task folder (``READY`` -> ``PROCESSING`` -> ``DONE``).

Crash safety relies on two independent mechanisms:

1. ``os.rename(READY, PROCESSING)`` - a single atomic filesystem operation, so
   only one worker can win the race.
2. a heartbeat lock file (see :class:`~backend.module2_chain.app.lifecycle.TaskLease`)
   - if the winner dies, another worker can steal the lease after
   ``workspace.claim.stale_after_seconds``.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.lifecycle import TaskLease, default_owner_id
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.schemas.internal import ClaimOutcome, WorkspaceTaskDescriptor

logger = get_logger("scanner.claim")


class TaskClaimer:
    """Owns the ``READY``/``PROCESSING``/``DONE`` marker state machine."""

    def __init__(self, config: AppConfig, *, owner: str | None = None) -> None:
        self.config = config
        self.owner = owner or config.workspace.claim.owner or default_owner_id()
        self._leases: dict[str, TaskLease] = {}

    # ------------------------------------------------------------------ #
    # Claim / release
    # ------------------------------------------------------------------ #
    def claim(self, descriptor: WorkspaceTaskDescriptor, *, force: bool = False) -> ClaimOutcome:
        """Claim a task folder.

        ``force=True`` allows re-processing a folder that already has a
        ``DONE`` marker (used for idempotency tests and manual replays).
        """

        task_dir = descriptor.task_dir
        if self.config.workspace.claim.enabled and not force:
            lease = TaskLease(
                task_dir,
                owner=self.owner,
                stale_after_seconds=self.config.workspace.claim.stale_after_seconds,
                heartbeat_seconds=self.config.workspace.claim.heartbeat_seconds,
            )
            if not lease.acquire():
                return ClaimOutcome(
                    claimed=False,
                    task_id=descriptor.task_id,
                    reason="task lease held by another worker",
                    owner=self.owner,
                    descriptor=descriptor,
                )
            self._leases[descriptor.task_id] = lease
            recovered = lease.recovered_stale_lease
        else:
            recovered = False

        ws = self.config.workspace
        ready = task_dir / ws.ready_marker
        processing = task_dir / ws.processing_marker
        done = task_dir / ws.done_marker

        if done.is_file() and not force:
            self.release(descriptor.task_id)
            return ClaimOutcome(
                claimed=False,
                task_id=descriptor.task_id,
                reason="task already completed (DONE marker present)",
                owner=self.owner,
                descriptor=descriptor,
            )

        if ready.is_file():
            try:
                os.replace(ready, processing)
            except FileNotFoundError:
                # Lost the race between scan and claim.
                self.release(descriptor.task_id)
                return ClaimOutcome(
                    claimed=False,
                    task_id=descriptor.task_id,
                    reason="another worker claimed this task first",
                    owner=self.owner,
                    descriptor=descriptor,
                )
        elif processing.is_file():
            if not recovered and not force:
                self.release(descriptor.task_id)
                return ClaimOutcome(
                    claimed=False,
                    task_id=descriptor.task_id,
                    reason="task is already being processed",
                    owner=self.owner,
                    descriptor=descriptor,
                )
            logger.warning(
                "resuming a task left in PROCESSING state",
                extra={"task_id": descriptor.task_id, "stage": "recovery"},
            )
        elif not force:
            self.release(descriptor.task_id)
            return ClaimOutcome(
                claimed=False,
                task_id=descriptor.task_id,
                reason="READY marker missing",
                owner=self.owner,
                descriptor=descriptor,
            )

        if done.is_file() and force:
            done.unlink(missing_ok=True)
        if not processing.is_file():
            processing.write_text(
                json.dumps(
                    {
                        "task_id": descriptor.task_id,
                        "owner": self.owner,
                        "claimed_at": datetime.now(UTC).isoformat(),
                    }
                ),
                encoding="utf-8",
            )

        descriptor.marker = ws.processing_marker
        descriptor.owner = self.owner
        descriptor.claimed_at = datetime.now(UTC)
        logger.info(
            "claimed task",
            extra={
                "task_id": descriptor.task_id,
                "stage": "claim",
                "batches": len(descriptor.batch_files),
                "recovered": recovered,
            },
        )
        return ClaimOutcome(
            claimed=True,
            task_id=descriptor.task_id,
            reason="claimed",
            owner=self.owner,
            claimed_at=descriptor.claimed_at,
            recovered_stale_lease=recovered,
            descriptor=descriptor,
        )

    def complete(self, task_id: str, task_dir: Path) -> Path:
        """Publish ``DONE`` and drop the ``PROCESSING`` marker."""

        ws = self.config.workspace
        processing = task_dir / ws.processing_marker
        done = task_dir / ws.done_marker
        processing.unlink(missing_ok=True)
        done.write_text(
            json.dumps(
                {
                    "task_id": task_id,
                    "owner": self.owner,
                    "completed_at": datetime.now(UTC).isoformat(),
                }
            ),
            encoding="utf-8",
        )
        self.release(task_id)
        return done

    def fail(self, task_id: str, task_dir: Path, *, error: str) -> Path:
        """Mark a task as failed; keeps the payload for a manual retry."""

        ws = self.config.workspace
        processing = task_dir / ws.processing_marker
        failed = task_dir / ws.failed_marker
        processing.unlink(missing_ok=True)
        failed.write_text(
            json.dumps(
                {
                    "task_id": task_id,
                    "owner": self.owner,
                    "failed_at": datetime.now(UTC).isoformat(),
                    "error": error,
                }
            ),
            encoding="utf-8",
        )
        self.release(task_id)
        return failed

    def requeue(self, descriptor: WorkspaceTaskDescriptor) -> None:
        """Reset a ``FAILED`` folder back to ``READY`` so it can be retried."""

        ws = self.config.workspace
        (descriptor.task_dir / ws.failed_marker).unlink(missing_ok=True)
        (descriptor.task_dir / ws.processing_marker).unlink(missing_ok=True)
        (descriptor.task_dir / ws.done_marker).unlink(missing_ok=True)
        (descriptor.task_dir / ws.ready_marker).write_text(
            json.dumps(
                {
                    "task_id": descriptor.task_id,
                    "requeued_by": self.owner,
                    "requeued_at": datetime.now(UTC).isoformat(),
                }
            ),
            encoding="utf-8",
        )

    def release(self, task_id: str) -> None:
        lease = self._leases.pop(task_id, None)
        if lease is not None:
            lease.release()

    def release_all(self) -> None:
        for task_id in list(self._leases):
            self.release(task_id)

    def __enter__(self) -> TaskClaimer:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.release_all()
