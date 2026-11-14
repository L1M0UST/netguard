"""Structured JSON logging with correlation context.

Every log record carries the module name plus whatever task/batch/candidate
/stage context is currently bound.  Secrets are redacted and long values are
truncated: raw payloads and API keys must never reach the log stream.

Required fields per the Module 2 spec::

    timestamp, level, module, task_id, batch_id, candidate_id, stage, message

LLM calls additionally emit ``provider``, ``model``, ``latency_ms``, tokens
and ``status``.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import time
from collections.abc import Iterator, Mapping, MutableMapping
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any

_CONTEXT: ContextVar[dict[str, Any] | None] = ContextVar("module2_log_context", default=None)

MODULE_NAME = "module2_chain"

_DEFAULT_REDACT_KEYS: tuple[str, ...] = (
    "api_key",
    "apikey",
    "authorization",
    "token",
    "password",
    "secret",
)

_SECRET_PATTERN = re.compile(
    r"(sk-[A-Za-z0-9_\-]{8,}"
    r"|Bearer\s+[A-Za-z0-9._\-]{8,}"
    r"|(?<![A-Za-z0-9])[A-Za-z0-9_\-]{40,}(?![A-Za-z0-9]))"
)

RESERVED_RECORD_ATTRS = frozenset(
    {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "taskName",
        "message",
        "asctime",
        "extra",
    }
)

_MAX_VALUE_CHARS = 512


def bind_context(**values: Any) -> Any:
    """Bind correlation context for the current task (async safe)."""

    merged = {**_current_context(), **{k: v for k, v in values.items() if v is not None}}
    return _CONTEXT.set(merged)


def clear_context() -> None:
    _CONTEXT.set(None)


def _current_context() -> dict[str, Any]:
    """Bound logging context (never a mutable default)."""

    return _CONTEXT.get() or {}


@contextmanager
def log_context(**values: Any) -> Iterator[None]:
    """Temporarily bind context values."""

    token = bind_context(**values)
    try:
        yield
    finally:
        _CONTEXT.reset(token)


def current_context() -> dict[str, Any]:
    return dict(_current_context())


def _truncate(value: str, limit: int = _MAX_VALUE_CHARS) -> str:
    if len(value) <= limit:
        return value
    return f"{value[:limit]}...[truncated {len(value) - limit} chars]"


def _redact(key: str, value: Any, redact_keys: tuple[str, ...]) -> Any:
    lowered = key.lower()
    if any(marker in lowered for marker in redact_keys):
        return "***redacted***"
    if isinstance(value, str):
        if _SECRET_PATTERN.search(value):
            return "***redacted***"
        return _truncate(value)
    if isinstance(value, Mapping):
        return {str(k): _redact(str(k), v, redact_keys) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(key, item, redact_keys) for item in value]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _truncate(str(value))


def _json_default(value: Any) -> str:
    return str(value)


class JsonLogFormatter(logging.Formatter):
    """Render log records as single-line JSON objects."""

    def __init__(
        self,
        *,
        module_name: str = MODULE_NAME,
        redact_keys: tuple[str, ...] = _DEFAULT_REDACT_KEYS,
        static_fields: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__()
        self.module_name = module_name
        self.redact_keys = tuple(redact_keys)
        self.static_fields = dict(static_fields or {})

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "module": self.module_name,
            "logger": record.name,
            "message": self._safe_message(record),
        }
        payload.update(self.static_fields)
        payload.update(self._extra_fields(record))

        context = _current_context()
        if context:
            payload.update(
                {key: _redact(key, value, self.redact_keys) for key, value in context.items()}
            )

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
            payload["error_type"] = getattr(record.exc_info[0], "__name__", "Exception")

        try:
            return json.dumps(payload, ensure_ascii=False, default=_json_default)
        except (TypeError, ValueError):  # pragma: no cover - defensive
            return json.dumps({"level": record.levelname, "message": str(record.msg)})

    @staticmethod
    def _safe_message(record: logging.LogRecord) -> str:
        try:
            return str(record.getMessage())
        except Exception:  # pragma: no cover - defensive
            return str(record.msg)

    def _extra_fields(self, record: logging.LogRecord) -> dict[str, Any]:
        extras: dict[str, Any] = {}
        for key, value in record.__dict__.items():
            if key in RESERVED_RECORD_ATTRS or key.startswith("_"):
                continue
            extras[key] = _redact(key, value, self.redact_keys)
        return extras


class TextLogFormatter(logging.Formatter):
    """Human friendly formatter for local development."""

    def __init__(self, *, module_name: str = MODULE_NAME) -> None:
        super().__init__(
            fmt=f"%(asctime)s %(levelname)-8s [{module_name}] %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        context = _current_context()
        if not context:
            return base
        rendered = " ".join(f"{key}={value}" for key, value in context.items())
        return f"{base} | {rendered}"


def safe_extra(values: Mapping[str, Any]) -> dict[str, Any]:
    """Return an ``extra=`` mapping that never collides with LogRecord fields."""

    safe: dict[str, Any] = {}
    for key, value in values.items():
        safe[f"{key}_" if key in RESERVED_RECORD_ATTRS else key] = value
    return safe


class ContextLogger(logging.LoggerAdapter):  # type: ignore[type-arg]
    """Logger adapter that merges bound context and per-call fields."""

    def process(
        self, msg: Any, kwargs: MutableMapping[str, Any]
    ) -> tuple[Any, MutableMapping[str, Any]]:
        merged: dict[str, Any] = dict(self.extra or {})
        merged.update(_current_context())
        merged.update(kwargs.get("extra") or {})
        kwargs["extra"] = safe_extra(merged)
        return msg, kwargs


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a logger inside the ``module2_chain`` namespace."""

    suffix = name or "app"
    if suffix.startswith(("module2_chain", "backend.")):
        return logging.getLogger(suffix)
    return logging.getLogger(f"module2_chain.{suffix}")


def get_context_logger(name: str | None = None, **extra: Any) -> ContextLogger:
    """Return a logger that always emits the supplied structured fields."""

    return ContextLogger(get_logger(name), safe_extra(extra))


def configure_logging(
    *,
    level: str = "INFO",
    fmt: str = "json",
    log_file: str | Path | None = None,
    redact_keys: tuple[str, ...] | None = None,
    static_fields: Mapping[str, Any] | None = None,
    stream: Any = None,
) -> logging.Logger:
    """Configure the ``module2_chain`` logger tree and return its root."""

    logger = logging.getLogger("module2_chain")
    logger.setLevel(level.upper())
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    formatter: logging.Formatter
    if fmt == "json":
        formatter = JsonLogFormatter(
            redact_keys=redact_keys or _DEFAULT_REDACT_KEYS,
            static_fields=static_fields,
        )
    else:
        formatter = TextLogFormatter()

    console = logging.StreamHandler(stream or sys.stderr)
    console.setFormatter(formatter)
    logger.addHandler(console)

    if log_file is not None:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
