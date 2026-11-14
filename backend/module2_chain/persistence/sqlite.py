"""Thin SQLite wrapper used for Module 2 local state."""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from backend.module2_chain.app.logging import get_logger

logger = get_logger("persistence.sqlite")

SCHEMA_VERSION = 1

_SCHEMA_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS processed_batches (
        task_id TEXT NOT NULL,
        batch_id TEXT NOT NULL,
        sha256 TEXT,
        row_count INTEGER DEFAULT 0,
        status TEXT NOT NULL,
        processed_at TEXT NOT NULL,
        PRIMARY KEY (task_id, batch_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS processed_tasks (
        task_id TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        input_checksum TEXT,
        output_path TEXT,
        attack_events INTEGER DEFAULT 0,
        attack_candidates INTEGER DEFAULT 0,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS fingerprints (
        fingerprint TEXT NOT NULL,
        task_id TEXT NOT NULL,
        chain_id TEXT NOT NULL,
        severity TEXT,
        risk_score REAL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (fingerprint, task_id, chain_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS llm_calls (
        request_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        candidate_id TEXT,
        provider TEXT,
        model TEXT,
        prompt_version TEXT,
        input_tokens INTEGER,
        output_tokens INTEGER,
        latency_ms REAL,
        retry_count INTEGER DEFAULT 0,
        status TEXT,
        fallback_used INTEGER DEFAULT 0,
        created_at TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_fingerprints_task ON fingerprints (task_id)",
    "CREATE INDEX IF NOT EXISTS idx_llm_calls_task ON llm_calls (task_id)",
    """
    CREATE TABLE IF NOT EXISTS schema_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
)


class SqliteStore:
    """Connection helper with WAL, foreign keys and a busy timeout."""

    def __init__(self, path: str | Path, *, busy_timeout_ms: int = 5000) -> None:
        self.path = Path(path)
        self.busy_timeout_ms = busy_timeout_ms
        self._local = threading.local()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        connection = self._local.__dict__.get("connection")
        if connection is None:
            connection = sqlite3.connect(
                str(self.path), timeout=self.busy_timeout_ms / 1000.0, isolation_level=None
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=NORMAL")
            connection.execute(f"PRAGMA busy_timeout={int(self.busy_timeout_ms)}")
            self._local.connection = connection
        return connection

    @contextmanager
    def cursor(self) -> Iterator[sqlite3.Cursor]:
        connection = self._connect()
        cursor = connection.cursor()
        try:
            yield cursor
        finally:
            cursor.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Cursor]:
        connection = self._connect()
        cursor = connection.cursor()
        try:
            cursor.execute("BEGIN")
            yield cursor
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            cursor.close()

    def initialize(self) -> None:
        with self.transaction() as cursor:
            for statement in _SCHEMA_STATEMENTS:
                cursor.execute(statement)
            cursor.execute(
                "INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
        logger.info(
            "sqlite state database ready",
            extra={"stage": "persistence", "path": str(self.path)},
        )

    def close(self) -> None:
        connection = self._local.__dict__.pop("connection", None)
        if connection is not None:
            connection.close()
