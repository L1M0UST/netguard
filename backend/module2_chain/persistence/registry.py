"""Idempotency registry (M2-F23, spec §32).

Guarantees that replaying the same inbox never produces duplicate chains,
alerts or reports:

* a ``(task_id, batch_id, sha256)`` record marks a batch as consumed;
* ``processed_tasks`` remembers the manifest checksum of a finished task;
* ``fingerprints`` remembers the attack fingerprints already emitted.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from backend.common.schemas.attack import AttackChain
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.llm.schemas import LLMCallRecord
from backend.module2_chain.persistence.sqlite import SqliteStore

logger = get_logger("persistence.registry")


class ProcessedRegistry:
    """Local SQLite registry of everything Module 2 already processed."""

    def __init__(self, config: AppConfig, *, store: SqliteStore | None = None) -> None:
        self.config = config
        self.store = store or SqliteStore(
            path=config.sqlite_path,
            busy_timeout_ms=config.persistence.busy_timeout_ms,
        )
        self.enabled = config.persistence.enable_registry
        if self.enabled:
            self.store.initialize()

    # ------------------------------------------------------------------ #
    # Batches
    # ------------------------------------------------------------------ #
    def mark_batch(
        self,
        *,
        task_id: str,
        batch_id: str,
        sha256: str | None = None,
        row_count: int = 0,
        status: str = "processed",
    ) -> None:
        if not self.enabled:
            return
        with self.store.transaction() as cursor:
            cursor.execute(
                """
                INSERT INTO processed_batches
                    (task_id, batch_id, sha256, row_count, status, processed_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id, batch_id) DO UPDATE SET
                    sha256 = excluded.sha256,
                    row_count = excluded.row_count,
                    status = excluded.status,
                    processed_at = excluded.processed_at
                """,
                (task_id, batch_id, sha256, row_count, status, _now()),
            )

    def batch_status(self, task_id: str, batch_id: str) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        with self.store.cursor() as cursor:
            row = cursor.execute(
                "SELECT * FROM processed_batches WHERE task_id = ? AND batch_id = ?",
                (task_id, batch_id),
            ).fetchone()
        return dict(row) if row else None

    def is_batch_processed(
        self, task_id: str, batch_id: str, sha256: str | None = None
    ) -> bool:
        record = self.batch_status(task_id, batch_id)
        if record is None or record.get("status") != "processed":
            return False
        # Content changed (different sha256) -> must be reprocessed.
        return not (sha256 and record.get("sha256") and record["sha256"] != sha256)

    # ------------------------------------------------------------------ #
    # Tasks
    # ------------------------------------------------------------------ #
    def mark_task(
        self,
        *,
        task_id: str,
        status: str,
        input_checksum: str | None = None,
        output_path: str | None = None,
        attack_events: int = 0,
        attack_candidates: int = 0,
    ) -> None:
        if not self.enabled:
            return
        with self.store.transaction() as cursor:
            cursor.execute(
                """
                INSERT INTO processed_tasks
                    (task_id, status, input_checksum, output_path, attack_events,
                     attack_candidates, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    status = excluded.status,
                    input_checksum = excluded.input_checksum,
                    output_path = excluded.output_path,
                    attack_events = excluded.attack_events,
                    attack_candidates = excluded.attack_candidates,
                    updated_at = excluded.updated_at
                """,
                (
                    task_id,
                    status,
                    input_checksum,
                    output_path,
                    attack_events,
                    attack_candidates,
                    _now(),
                ),
            )

    def task_record(self, task_id: str) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        with self.store.cursor() as cursor:
            row = cursor.execute(
                "SELECT * FROM processed_tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
        return dict(row) if row else None

    def is_task_completed(self, task_id: str, input_checksum: str | None = None) -> bool:
        record = self.task_record(task_id)
        if record is None or record.get("status") != "completed":
            return False
        return not (
            input_checksum and record.get("input_checksum") not in (None, input_checksum)
        )

    def reset_task(self, task_id: str) -> None:
        """Forget a task so it can be reprocessed from scratch."""

        if not self.enabled:
            return
        with self.store.transaction() as cursor:
            cursor.execute("DELETE FROM processed_tasks WHERE task_id = ?", (task_id,))
            cursor.execute("DELETE FROM processed_batches WHERE task_id = ?", (task_id,))
            cursor.execute("DELETE FROM fingerprints WHERE task_id = ?", (task_id,))
        logger.info(
            "registry entries cleared", extra={"task_id": task_id, "stage": "registry"}
        )

    # ------------------------------------------------------------------ #
    # Fingerprints
    # ------------------------------------------------------------------ #
    def record_fingerprints(self, task_id: str, chains: list[AttackChain]) -> None:
        if not self.enabled or not chains:
            return
        with self.store.transaction() as cursor:
            for chain in chains:
                if not chain.fingerprint:
                    continue
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO fingerprints
                        (fingerprint, task_id, chain_id, severity, risk_score, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        chain.fingerprint,
                        task_id,
                        chain.chain_id,
                        str(chain.severity),
                        chain.risk_score.score,
                        _now(),
                    ),
                )

    def known_fingerprints(self, *, exclude_task: str | None = None) -> set[str]:
        if not self.enabled:
            return set()
        with self.store.cursor() as cursor:
            if exclude_task:
                rows = cursor.execute(
                    "SELECT DISTINCT fingerprint FROM fingerprints WHERE task_id != ?",
                    (exclude_task,),
                ).fetchall()
            else:
                rows = cursor.execute(
                    "SELECT DISTINCT fingerprint FROM fingerprints"
                ).fetchall()
        return {row["fingerprint"] for row in rows}

    # ------------------------------------------------------------------ #
    # LLM calls
    # ------------------------------------------------------------------ #
    def record_llm_calls(self, records: list[LLMCallRecord]) -> None:
        if not self.enabled or not records:
            return
        with self.store.transaction() as cursor:
            for record in records:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO llm_calls
                        (request_id, task_id, candidate_id, provider, model, prompt_version,
                         input_tokens, output_tokens, latency_ms, retry_count, status,
                         fallback_used, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.request_id,
                        record.task_id,
                        record.candidate_id,
                        record.provider,
                        record.model,
                        record.prompt_version,
                        record.input_tokens,
                        record.output_tokens,
                        record.latency_ms,
                        record.retry_count,
                        str(record.status),
                        1 if record.fallback_used else 0,
                        record.created_at.isoformat(),
                    ),
                )

    def llm_call_count(self, task_id: str | None = None) -> int:
        if not self.enabled:
            return 0
        with self.store.cursor() as cursor:
            if task_id:
                row = cursor.execute(
                    "SELECT COUNT(*) AS count FROM llm_calls WHERE task_id = ?", (task_id,)
                ).fetchone()
            else:
                row = cursor.execute("SELECT COUNT(*) AS count FROM llm_calls").fetchone()
        return int(row["count"]) if row else 0

    # ------------------------------------------------------------------ #
    def stats(self) -> dict[str, Any]:
        if not self.enabled:
            return {"enabled": False}
        with self.store.cursor() as cursor:
            tasks = cursor.execute("SELECT COUNT(*) AS c FROM processed_tasks").fetchone()["c"]
            batches = cursor.execute(
                "SELECT COUNT(*) AS c FROM processed_batches"
            ).fetchone()["c"]
            fingerprints = cursor.execute(
                "SELECT COUNT(*) AS c FROM fingerprints"
            ).fetchone()["c"]
            calls = cursor.execute("SELECT COUNT(*) AS c FROM llm_calls").fetchone()["c"]
        return {
            "enabled": True,
            "path": str(self.store.path),
            "tasks": tasks,
            "batches": batches,
            "fingerprints": fingerprints,
            "llm_calls": calls,
        }

    def close(self) -> None:
        self.store.close()


def _now() -> str:
    return datetime.now(UTC).isoformat()


def registry_path(config: AppConfig) -> Path:
    return config.sqlite_path
