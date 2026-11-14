"""``manifest.json`` loading and integrity verification.

Module 1 guarantees that every payload file is written as ``*.tmp``, fsynced,
hashed and renamed before ``READY`` appears.  Module 2 re-verifies the declared
``sha256`` and ``file_size`` so that a partially copied or corrupted batch can
never enter the pipeline.

The manifest checksum is always computed over the **raw JSON payload on disk**
(excluding the ``checksum`` key), so it never depends on how a producer
serialised a datetime.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import orjson
from pydantic import ValidationError

from backend.common.schemas.suspicious_event import (
    BatchFileRef,
    SuspiciousEventBatchManifest,
)
from backend.common.schemas.version import SUSPICIOUS_EVENT_BATCH_SCHEMA_VERSION
from backend.module2_chain.app.config import AppConfig, IngestionSettings
from backend.module2_chain.schemas.internal import ValidationIssue

_CHUNK_SIZE = 1 << 20


class ManifestError(RuntimeError):
    """Raised when ``manifest.json`` is missing, malformed or unreadable."""


def compute_sha256(path: str | Path, *, chunk_size: int = _CHUNK_SIZE) -> str:
    """Streaming sha256 of a file."""

    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def canonical_manifest_body(payload: dict[str, Any]) -> bytes:
    """Canonical (sorted, compact) JSON body used for the manifest checksum."""

    body = {key: value for key, value in payload.items() if key != "checksum"}
    return orjson.dumps(body, option=orjson.OPT_SORT_KEYS)


def manifest_checksum(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_manifest_body(payload)).hexdigest()


def load_manifest_payload(path: str | Path) -> dict[str, Any]:
    """Read the raw manifest JSON (no validation)."""

    manifest_path = Path(path)
    if not manifest_path.is_file():
        raise ManifestError(f"manifest not found: {manifest_path}")
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ManifestError(f"manifest is not valid JSON: {manifest_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ManifestError(f"manifest root must be an object: {manifest_path}")
    return raw


def load_manifest(path: str | Path) -> SuspiciousEventBatchManifest:
    """Load and parse a batch manifest."""

    raw = load_manifest_payload(path)
    try:
        return SuspiciousEventBatchManifest.model_validate(raw)
    except ValidationError as exc:
        raise ManifestError(f"manifest failed schema validation: {path}: {exc}") from exc


def verify_manifest(
    manifest: SuspiciousEventBatchManifest,
    base_dir: str | Path,
    *,
    settings: AppConfig | IngestionSettings | None = None,
    raw_payload: dict[str, Any] | None = None,
    manifest_path: str | Path | None = None,
) -> list[ValidationIssue]:
    """Verify a manifest against the files on disk.

    Returns a list of issues; an empty list means "safe to consume".
    """

    ingestion = settings.ingestion if isinstance(settings, AppConfig) else settings
    ingestion = ingestion or IngestionSettings()
    base = Path(base_dir)
    issues: list[ValidationIssue] = []

    allowed = set(ingestion.allowed_schema_versions) or {SUSPICIOUS_EVENT_BATCH_SCHEMA_VERSION}
    if manifest.schema_version not in allowed:
        issues.append(
            ValidationIssue(
                code="unsupported_schema_version",
                message=(
                    f"batch schema_version={manifest.schema_version!r} is not supported "
                    f"(expected one of {sorted(allowed)})"
                ),
                severity="error",
                task_id=manifest.task_id,
                batch_id=manifest.batch_id,
                location=str(base),
            )
        )

    if not manifest.files:
        issues.append(
            ValidationIssue(
                code="empty_manifest",
                message="manifest declares no payload files",
                severity="error",
                task_id=manifest.task_id,
                batch_id=manifest.batch_id,
                location=str(base),
            )
        )
        return issues

    total_rows = 0
    for ref in manifest.files:
        file_path = base / ref.path
        if not file_path.is_file():
            issues.append(
                ValidationIssue(
                    code="missing_batch_file",
                    message=f"declared batch file is missing: {ref.path}",
                    severity="error",
                    task_id=manifest.task_id,
                    batch_id=manifest.batch_id,
                    location=str(file_path),
                )
            )
            continue
        actual_size = file_path.stat().st_size
        if ingestion.verify_file_size and actual_size != ref.size_bytes:
            issues.append(
                ValidationIssue(
                    code="file_size_mismatch",
                    message=(
                        f"{ref.path}: size {actual_size} does not match manifest "
                        f"{ref.size_bytes}"
                    ),
                    severity="error",
                    task_id=manifest.task_id,
                    batch_id=manifest.batch_id,
                    location=str(file_path),
                    details={"expected": ref.size_bytes, "actual": actual_size},
                )
            )
        if ingestion.verify_sha256:
            actual_hash = compute_sha256(file_path)
            if actual_hash.lower() != ref.sha256.lower():
                issues.append(
                    ValidationIssue(
                        code="sha256_mismatch",
                        message=f"{ref.path}: sha256 mismatch (file may be corrupted)",
                        severity="error",
                        task_id=manifest.task_id,
                        batch_id=manifest.batch_id,
                        location=str(file_path),
                        details={"expected": ref.sha256, "actual": actual_hash},
                    )
                )
        total_rows += ref.row_count or 0

    if manifest.event_count and total_rows and total_rows != manifest.event_count:
        issues.append(
            ValidationIssue(
                code="event_count_mismatch",
                message=(
                    f"manifest.event_count={manifest.event_count} but file row counts sum to "
                    f"{total_rows}"
                ),
                severity="warning",
                task_id=manifest.task_id,
                batch_id=manifest.batch_id,
            )
        )
    if manifest.event_count > ingestion.max_rows_per_batch * max(1, len(manifest.files)):
        issues.append(
            ValidationIssue(
                code="batch_too_large",
                message=(
                    f"manifest.event_count={manifest.event_count} exceeds "
                    "ingestion.max_rows_per_batch"
                ),
                severity="error",
                task_id=manifest.task_id,
                batch_id=manifest.batch_id,
            )
        )

    if manifest.checksum is not None:
        expected = _expected_checksum(
            manifest, raw_payload=raw_payload, manifest_path=manifest_path, base=base
        )
        if expected is not None and expected != manifest.checksum:
            issues.append(
                ValidationIssue(
                    code="manifest_checksum_mismatch",
                    message="manifest body does not match its declared checksum",
                    severity="error",
                    task_id=manifest.task_id,
                    batch_id=manifest.batch_id,
                    location=str(base),
                    details={"expected": manifest.checksum, "actual": expected},
                )
            )

    return issues


def _expected_checksum(
    manifest: SuspiciousEventBatchManifest,
    *,
    raw_payload: dict[str, Any] | None,
    manifest_path: str | Path | None,
    base: Path,
) -> str | None:
    """Checksum of the producer's canonical body (raw JSON when available)."""

    payload = raw_payload
    if payload is None:
        candidate = Path(manifest_path) if manifest_path else (base / "manifest.json")
        if candidate.is_file():
            try:
                payload = load_manifest_payload(candidate)
            except ManifestError:
                payload = None
    if payload is None:
        payload = manifest.model_dump(mode="json")
    return manifest_checksum(payload)


def build_file_ref(path: Path, relative_to: Path, *, row_count: int | None = None) -> BatchFileRef:
    """Helper used by fixture generators / Module 1 emulators."""

    return BatchFileRef(
        path=str(path.relative_to(relative_to)),
        sha256=compute_sha256(path),
        size_bytes=path.stat().st_size,
        row_count=row_count,
    )
