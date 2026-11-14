"""Bundle manifest describing a Module 2 output directory."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from backend.common.schemas.version import MODULE2_BUNDLE_MANIFEST_SCHEMA_VERSION


class BundleFileRef(BaseModel):
    """One file inside a bundle, with integrity metadata."""

    model_config = ConfigDict(extra="allow")

    path: str
    sha256: str
    size_bytes: int = Field(ge=0)
    content_type: str = "application/json"
    record_count: int | None = None
    schema_version: str | None = None


class BundleManifest(BaseModel):
    """``manifest.json`` of ``05_m2_output/task_xxx``."""

    model_config = ConfigDict(extra="allow")

    schema_version: str = MODULE2_BUNDLE_MANIFEST_SCHEMA_VERSION
    task_id: str
    producer: str = "module2_chain"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    files: list[BundleFileRef] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)
    schema_versions: dict[str, str] = Field(default_factory=dict)
    input_batches: list[str] = Field(default_factory=list)
    input_checksums: list[str] = Field(default_factory=list)
    run: dict[str, object] = Field(default_factory=dict)
    checksum: str | None = None
