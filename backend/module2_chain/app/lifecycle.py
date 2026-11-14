"""Application lifecycle helpers: workspace bootstrap, leases, cancellation.

Module 2 is a batch application, so "lifecycle" means:

* prepare the shared-workspace directories,
* take an exclusive :class:`TaskLease` on a ``task_xxx`` folder (crash safe),
* propagate cooperative cancellation (SIGINT/SIGTERM) to the pipeline,
* release the lease and publish a terminal status.
"""

from __future__ import annotations

import json
import os
import platform
import signal
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from types import FrameType
from typing import Any

from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger

logger = get_logger("lifecycle")

LOCK_FILE_NAME = ".m2_task_lock.json"


class TaskCancelledError(RuntimeError):
    """Raised when the current task run was cancelled."""


class CancellationToken:
    """Cooperative cancellation flag shared across threads and async tasks."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._reason: str | None = None

    def cancel(self, reason: str = "cancelled by caller") -> None:
        if not self._event.is_set():
            self._reason = reason
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str | None:
        return self._reason

    def raise_if_cancelled(self) -> None:
        if self._event.is_set():
            raise TaskCancelledError(self._reason or "task cancelled")

    def wait(self, timeout: float) -> bool:
        return self._event.wait(timeout)


def default_owner_id() -> str:
    """Stable-ish worker identity used for claims and crash recovery."""

    return f"{platform.node()}:{os.getpid()}"


class TaskLease:
    """Exclusive, crash-detectable lease over one task directory.

    The lease is a small JSON file written atomically next to the ``PROCESSING``
    marker.  A lease whose heartbeat is older than
    ``workspace.claim.stale_after_seconds`` is considered abandoned and can be
    stolen by another worker (``/ crash recovery /``).
    """

    def __init__(
        self,
        task_dir: Path,
        *,
        owner: str | None = None,
        stale_after_seconds: float = 900.0,
        heartbeat_seconds: float = 30.0,
    ) -> None:
        self.task_dir = Path(task_dir)
        self.owner = owner or default_owner_id()
        self.stale_after_seconds = stale_after_seconds
        self.heartbeat_seconds = heartbeat_seconds
        self.lock_path = self.task_dir / LOCK_FILE_NAME
        self._heartbeat_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._acquired = False
        self.recovered_stale_lease = False

    # ------------------------------------------------------------------ #
    def _read_lock(self) -> dict[str, Any] | None:
        try:
            payload = json.loads(self.lock_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (json.JSONDecodeError, OSError):
            return None
        return payload if isinstance(payload, dict) else None

    def _write_lock(self) -> None:
        payload = {
            "owner": self.owner,
            "pid": os.getpid(),
            "host": platform.node(),
            "acquired_at": datetime.now(UTC).isoformat(),
            "heartbeat_at": time.time(),
        }
        tmp_path = self.lock_path.with_suffix(self.lock_path.suffix + ".tmp")
        tmp_path.write_text(json.dumps(payload), encoding="utf-8")
        os.replace(tmp_path, self.lock_path)

    def is_stale(self, now: float | None = None) -> bool:
        payload = self._read_lock()
        if payload is None:
            return True
        heartbeat = float(payload.get("heartbeat_at") or 0.0)
        current = time.time() if now is None else now
        return (current - heartbeat) > self.stale_after_seconds

    def acquire(self) -> bool:
        """Try to acquire the lease.  Returns ``False`` if another worker holds it."""

        existing = self._read_lock()
        if existing is not None and existing.get("owner") != self.owner:
            if not self.is_stale():
                logger.info(
                    "task lease is held by another worker",
                    extra={"task_id": self.task_dir.name, "owner": existing.get("owner")},
                )
                return False
            self.recovered_stale_lease = True
            logger.warning(
                "stealing stale task lease",
                extra={
                    "task_id": self.task_dir.name,
                    "previous_owner": existing.get("owner"),
                    "stage": "recovery",
                },
            )
        self.task_dir.mkdir(parents=True, exist_ok=True)
        self._write_lock()
        self._acquired = True
        self._start_heartbeat()
        return True

    def _start_heartbeat(self) -> None:
        if self.heartbeat_seconds <= 0:
            return

        def _beat() -> None:
            while not self._stop.wait(self.heartbeat_seconds):
                try:
                    self._write_lock()
                except OSError:  # pragma: no cover - defensive
                    logger.warning("failed to refresh task lease heartbeat")

        self._heartbeat_thread = threading.Thread(
            target=_beat, name=f"m2-lease-{self.task_dir.name}", daemon=True
        )
        self._heartbeat_thread.start()

    def release(self) -> None:
        self._stop.set()
        if self._heartbeat_thread is not None:
            self._heartbeat_thread.join(timeout=2.0)
            self._heartbeat_thread = None
        if self._acquired:
            try:
                self.lock_path.unlink(missing_ok=True)
            except OSError:  # pragma: no cover - defensive
                logger.warning("failed to remove task lease file")
            self._acquired = False

    def __enter__(self) -> TaskLease:
        if not self.acquire():
            raise RuntimeError(f"task lease for {self.task_dir} is not available")
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.release()


def ensure_workspace(config: AppConfig) -> dict[str, Path]:
    """Create the shared-workspace directories if they are missing."""

    paths = {
        "inbox": config.inbox_dir,
        "output": config.output_dir,
        "status": config.status_dir,
    }
    if config.workspace.auto_create:
        for path in paths.values():
            path.mkdir(parents=True, exist_ok=True)
        if config.persistence.enable_registry:
            config.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        config.threat_intel_dir.mkdir(parents=True, exist_ok=True)
    return paths


def _handle_signal(token: CancellationToken, signum: int, frame: FrameType | None) -> None:
    del frame
    name = signal.Signals(signum).name
    logger.warning("received termination signal", extra={"stage": "shutdown", "signal": name})
    token.cancel(f"received {name}")


@contextmanager
def signal_cancellation() -> Iterator[CancellationToken]:
    """Install SIGINT/SIGTERM handlers that cancel the pipeline cooperatively."""

    token = CancellationToken()
    previous: dict[Any, Any] = {}

    def _handler(signum: int, frame: FrameType | None) -> None:
        _handle_signal(token, signum, frame)

    for sig in (signal.SIGINT, signal.SIGTERM):
        # pragma: no cover - non-main thread
        with suppress(ValueError, OSError):
            previous[sig] = signal.getsignal(sig)
            signal.signal(sig, _handler)
    try:
        yield token
    finally:
        for sig, handler in previous.items():
            # pragma: no cover - non-main thread
            with suppress(ValueError, OSError):
                signal.signal(sig, handler)
