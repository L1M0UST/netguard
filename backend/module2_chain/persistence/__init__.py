"""Module 2 local state: SQLite registry plus status files.

This database only ever stores Module 2's own bookkeeping (processed batches,
fingerprints, LLM call records).  It is **not** a shared business database and
is never touched by Module 1 or Module 3.
"""

from backend.module2_chain.persistence.registry import ProcessedRegistry
from backend.module2_chain.persistence.sqlite import SqliteStore
from backend.module2_chain.persistence.status_store import TaskStatusStore

__all__ = ["ProcessedRegistry", "SqliteStore", "TaskStatusStore"]
