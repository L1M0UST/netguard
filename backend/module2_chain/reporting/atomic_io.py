"""Atomic, crash-safe file delivery primitives.

Every artefact written by Module 2 follows the same discipline as the upstream
contract:

1. write ``<name>.tmp`` in the destination directory,
2. ``flush`` + ``fsync``,
3. ``os.replace`` onto the final name (atomic on POSIX),
4. optionally ``fsync`` the directory so the rename survives a crash.
"""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path
from typing import Any

import orjson

from backend.module2_chain.app.logging import get_logger

logger = get_logger("reporting.atomic_io")

TEMP_SUFFIX = ".tmp"
_CHUNK_SIZE = 1 << 20


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def replace_with_retry(temp_path: Path, destination: Path, attempts: int = 6,
                       delay: float = 0.2) -> None:
    """``os.replace`` with a short retry for Windows reader conflicts.

    On Windows the rename fails with WinError 5 while another process holds the
    destination open for reading (the M3 BFF polls ``status.json`` during a
    run); such readers close within milliseconds, so retrying converges.
    """
    for attempt in range(attempts):
        try:
            os.replace(temp_path, destination)
            return
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(delay)


def fsync_directory(path: Path) -> None:
    """Best-effort directory fsync (ignored on platforms that refuse it)."""

    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:  # pragma: no cover - platform dependent
        return
    try:
        os.fsync(fd)
    except OSError:  # pragma: no cover - platform dependent
        pass
    finally:
        os.close(fd)


def atomic_write_bytes(
    path: str | Path,
    data: bytes,
    *,
    fsync: bool = True,
    create_parents: bool = True,
) -> Path:
    """Write ``data`` to ``path`` atomically and return the final path."""

    destination = Path(path)
    if create_parents:
        destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path = destination.with_name(destination.name + TEMP_SUFFIX)
    with temp_path.open("wb") as handle:
        handle.write(data)
        handle.flush()
        if fsync:
            os.fsync(handle.fileno())
    replace_with_retry(temp_path, destination)
    if fsync:
        fsync_directory(destination.parent)
    return destination


def atomic_write_json(
    path: str | Path,
    payload: Any,
    *,
    fsync: bool = True,
    indent: bool = True,
) -> Path:
    """Serialise ``payload`` with orjson and write it atomically."""

    option = orjson.OPT_INDENT_2 if indent else 0
    data = orjson.dumps(payload, option=option | orjson.OPT_NON_STR_KEYS)
    return atomic_write_bytes(path, data, fsync=fsync)


def atomic_write_text(
    path: str | Path, text: str, *, fsync: bool = True
) -> Path:
    return atomic_write_bytes(path, text.encode("utf-8"), fsync=fsync)
