"""``SuspiciousEventBatch.v1`` - the Module 1 -> Module 2 data contract.

Field semantics are frozen.  Module 2 must not reinterpret them; it may only
read them and derive *new* (clearly namespaced) fields.

``event.*``      - normalised network/alert facts produced by Module 1.
``detection.*``  - what Module 1's L1/L2/L3 stages concluded about the event.
``session_id``   - Module 1 session aggregation key (may be ``None``).
``emitted_at``   - when Module 1 emitted the record.

The contract is additive-only inside MAJOR version 1: unknown columns are
preserved as model extras instead of being dropped.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.common.schemas.version import SUSPICIOUS_EVENT_BATCH_SCHEMA_VERSION

_BASE_CONFIG = ConfigDict(
    extra="allow",
    populate_by_name=True,
    validate_assignment=False,
    str_strip_whitespace=True,
)

EVENT_FIELDS: frozenset[str] = frozenset(
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

DETECTION_FIELDS: frozenset[str] = frozenset(
    {"matched_rules", "ioc_hits", "score", "reason", "detector"}
)

TOP_LEVEL_FIELDS: frozenset[str] = frozenset({"session_id", "emitted_at", "schema_version"})


class EventCore(BaseModel):
    """``event`` sub-document of a suspicious event."""

    model_config = _BASE_CONFIG

    event_id: str
    task_id: str
    timestamp: datetime
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None
    payload_digest: str | None = None
    raw_ref: str | None = None
    source_file: str | None = None

    @field_validator("protocol")
    @classmethod
    def _normalise_protocol(cls, value: str | None) -> str | None:
        return value.lower() if isinstance(value, str) else value


class Detection(BaseModel):
    """``detection`` sub-document of a suspicious event."""

    model_config = _BASE_CONFIG

    matched_rules: list[str] = Field(default_factory=list)
    ioc_hits: list[str] = Field(default_factory=list)
    score: float = 0.0
    reason: str | None = None
    detector: str | None = None

    @field_validator("matched_rules", "ioc_hits", mode="before")
    @classmethod
    def _coerce_sequence(cls, value: Any) -> Any:
        if value is None:
            return []
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value


class SuspiciousEvent(BaseModel):
    """One suspicious event emitted by Module 1."""

    model_config = _BASE_CONFIG

    event: EventCore
    detection: Detection = Field(default_factory=Detection)
    session_id: str | None = None
    emitted_at: datetime | None = None
    schema_version: str = SUSPICIOUS_EVENT_BATCH_SCHEMA_VERSION

    # ---- convenience accessors (read-only, never persisted) -------------
    @property
    def event_id(self) -> str:
        return self.event.event_id

    @property
    def task_id(self) -> str:
        return self.event.task_id

    @property
    def timestamp(self) -> datetime:
        return self.event.timestamp

    @property
    def src_ip(self) -> str | None:
        return self.event.src_ip

    @property
    def dst_ip(self) -> str | None:
        return self.event.dst_ip

    @property
    def dst_port(self) -> int | None:
        return self.event.dst_port

    @property
    def protocol(self) -> str | None:
        return self.event.protocol

    @property
    def score(self) -> float:
        return self.detection.score

    @property
    def rule_signature(self) -> str:
        """Stable, ordered signature of the matched rules."""

        return "|".join(sorted(rule.lower() for rule in self.detection.matched_rules))

    def to_flat_dict(self) -> dict[str, Any]:
        """Flatten to the dotted-column layout used by the parquet contract."""

        flat: dict[str, Any] = {
            "event.event_id": self.event.event_id,
            "event.task_id": self.event.task_id,
            "event.timestamp": self.event.timestamp,
            "event.src_ip": self.event.src_ip,
            "event.dst_ip": self.event.dst_ip,
            "event.src_port": self.event.src_port,
            "event.dst_port": self.event.dst_port,
            "event.protocol": self.event.protocol,
            "event.payload_digest": self.event.payload_digest,
            "event.raw_ref": self.event.raw_ref,
            "event.source_file": self.event.source_file,
            "detection.matched_rules": list(self.detection.matched_rules),
            "detection.ioc_hits": list(self.detection.ioc_hits),
            "detection.score": self.detection.score,
            "detection.reason": self.detection.reason,
            "detection.detector": self.detection.detector,
            "session_id": self.session_id,
            "emitted_at": self.emitted_at,
            "schema_version": self.schema_version,
        }
        for key, value in (self.event.model_extra or {}).items():
            flat.setdefault(f"event.{key}", value)
        for key, value in (self.detection.model_extra or {}).items():
            flat.setdefault(f"detection.{key}", value)
        for key, value in (self.model_extra or {}).items():
            flat.setdefault(key, value)
        return flat

    @classmethod
    def from_flat_dict(cls, row: dict[str, Any]) -> SuspiciousEvent:
        """Rebuild from either a flat (``event.src_ip``) or nested mapping.

        Unknown (additive) columns are preserved so that a v1 producer may add
        fields without Module 2 losing information.
        """

        if isinstance(row.get("event"), dict) or isinstance(row.get("detection"), dict):
            return cls.model_validate(row)

        def pick(name: str) -> Any:
            return row.get(name, row.get(name.replace(".", "_")))

        event_payload: dict[str, Any] = {
            "event_id": pick("event.event_id"),
            "task_id": pick("event.task_id"),
            "timestamp": pick("event.timestamp"),
            "src_ip": pick("event.src_ip"),
            "dst_ip": pick("event.dst_ip"),
            "src_port": pick("event.src_port"),
            "dst_port": pick("event.dst_port"),
            "protocol": pick("event.protocol"),
            "payload_digest": pick("event.payload_digest"),
            "raw_ref": pick("event.raw_ref"),
            "source_file": pick("event.source_file"),
        }
        detection_payload: dict[str, Any] = {
            "matched_rules": pick("detection.matched_rules"),
            "ioc_hits": pick("detection.ioc_hits"),
            "score": pick("detection.score"),
            "reason": pick("detection.reason"),
            "detector": pick("detection.detector"),
        }
        top_level: dict[str, Any] = {
            "session_id": pick("session_id"),
            "emitted_at": pick("emitted_at"),
            "schema_version": pick("schema_version")
            or SUSPICIOUS_EVENT_BATCH_SCHEMA_VERSION,
        }

        for key, value in row.items():
            namespace, _, short = key.partition(".")
            if namespace == "event" and short in EVENT_FIELDS:
                continue
            if namespace == "detection" and short in DETECTION_FIELDS:
                continue
            if namespace == "event":
                event_payload[short] = value
                continue
            if namespace == "detection":
                detection_payload[short] = value
                continue
            if key in EVENT_FIELDS or key in DETECTION_FIELDS or key in TOP_LEVEL_FIELDS:
                continue
            top_level[key] = value

        return cls(
            event=EventCore.model_validate(event_payload),
            detection=Detection.model_validate(detection_payload),
            **top_level,
        )


class BatchFileRef(BaseModel):
    """Reference to one payload file inside a ``SuspiciousEventBatch.v1``."""

    model_config = _BASE_CONFIG

    path: str
    sha256: str
    size_bytes: int = Field(ge=0)
    row_count: int | None = Field(default=None, ge=0)
    schema_version: str = SUSPICIOUS_EVENT_BATCH_SCHEMA_VERSION


class SuspiciousEventBatchManifest(BaseModel):
    """``manifest.json`` shipped next to the parquet batches."""

    model_config = _BASE_CONFIG

    schema_version: str = SUSPICIOUS_EVENT_BATCH_SCHEMA_VERSION
    task_id: str
    batch_id: str
    producer: str = "module1"
    created_at: datetime | None = None
    event_count: int = Field(default=0, ge=0)
    files: list[BatchFileRef] = Field(default_factory=list)
    checksum: str | None = Field(
        default=None,
        description="sha256 of the canonical manifest body (without this field).",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def total_rows(self) -> int:
        counted = sum(ref.row_count or 0 for ref in self.files)
        return counted or self.event_count
