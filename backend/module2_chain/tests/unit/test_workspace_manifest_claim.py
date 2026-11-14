"""Workspace discovery, manifest verification and claiming tests."""

from __future__ import annotations

import json
import time
from pathlib import Path

import polars as pl
import pytest

from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.devtools.synthetic import write_batch
from backend.module2_chain.ingestion.validator import BatchValidator
from backend.module2_chain.scanner.claim import TaskClaimer
from backend.module2_chain.scanner.manifest import (
    ManifestError,
    compute_sha256,
    load_manifest,
    manifest_checksum,
)
from backend.module2_chain.scanner.workspace_scanner import WorkspaceScanner


@pytest.fixture
def task_dir(config: AppConfig, event_factory) -> Path:
    events = [event_factory("evt_0001", task_id="task_a"), event_factory("evt_0002", task_id="task_a")]
    return write_batch(config.inbox_dir, events, task_id="task_a")


def test_scanner_discovers_ready_tasks_only(config: AppConfig, task_dir: Path) -> None:
    scanner = WorkspaceScanner(config)
    ready = scanner.scan()
    assert [item.task_id for item in ready] == ["task_a"]
    assert ready[0].marker == "READY"
    assert len(ready[0].batch_files) == 1
    assert scanner.scan(states=["DONE"]) == []
    (task_dir / "DONE").write_text("{}", encoding="utf-8")
    assert scanner.scan() == []
    assert [item.task_id for item in scanner.scan(include_processed=True, states=["DONE"])] == [
        "task_a"
    ]


def test_scanner_ignores_temp_and_marker_files(config: AppConfig, task_dir: Path) -> None:
    (task_dir / "batch_000002.parquet.tmp").write_bytes(b"partial")
    (task_dir / ".hidden.parquet").write_bytes(b"partial")
    scanner = WorkspaceScanner(config)
    names = {path.name for path in scanner.batch_files(task_dir)}
    assert names == {"batch_000001.parquet"}


def test_missing_manifest_is_rejected(config: AppConfig, task_dir: Path) -> None:
    (task_dir / "manifest.json").unlink()
    descriptor = WorkspaceScanner(config).describe(task_dir)
    result = BatchValidator(config).validate_descriptor(descriptor)
    assert not result.valid
    assert {issue.code for issue in result.errors} == {"manifest_missing"}


def test_sha256_mismatch_is_detected(config: AppConfig, task_dir: Path) -> None:
    payload = task_dir / "batch_000001.parquet"
    payload.write_bytes(payload.read_bytes() + b"corruption")
    descriptor = WorkspaceScanner(config).describe(task_dir)
    result = BatchValidator(config).validate_descriptor(descriptor)
    codes = {issue.code for issue in result.errors}
    assert "sha256_mismatch" in codes
    assert not result.valid


def test_file_size_mismatch_is_detected(config: AppConfig, task_dir: Path) -> None:
    manifest_path = task_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0]["size_bytes"] = manifest["files"][0]["size_bytes"] + 10
    manifest["checksum"] = manifest_checksum(manifest)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = BatchValidator(config).validate_descriptor(
        WorkspaceScanner(config).describe(task_dir)
    )
    assert "file_size_mismatch" in {issue.code for issue in result.errors}


def test_unsupported_schema_version_is_rejected(config: AppConfig, task_dir: Path) -> None:
    manifest_path = task_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["schema_version"] = "9.9.9"
    manifest["checksum"] = manifest_checksum(manifest)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = BatchValidator(config).validate_descriptor(
        WorkspaceScanner(config).describe(task_dir)
    )
    assert "unsupported_schema_version" in {issue.code for issue in result.errors}


def test_manifest_checksum_mismatch_is_detected(config: AppConfig, task_dir: Path) -> None:
    manifest_path = task_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["event_count"] = 999
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = BatchValidator(config).validate_descriptor(
        WorkspaceScanner(config).describe(task_dir)
    )
    assert "manifest_checksum_mismatch" in {issue.code for issue in result.errors}


def test_corrupted_manifest_is_reported(config: AppConfig, task_dir: Path) -> None:
    (task_dir / "manifest.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(ManifestError):
        load_manifest(task_dir / "manifest.json")
    result = BatchValidator(config).validate_descriptor(
        WorkspaceScanner(config).describe(task_dir)
    )
    assert "manifest_unreadable" in {issue.code for issue in result.errors}


def test_task_id_mismatch_is_rejected(config: AppConfig, task_dir: Path) -> None:
    manifest_path = task_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["task_id"] = "task_other"
    manifest["checksum"] = manifest_checksum(manifest)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = BatchValidator(config).validate_descriptor(
        WorkspaceScanner(config).describe(task_dir)
    )
    assert "task_id_mismatch" in {issue.code for issue in result.errors}


def test_valid_task_passes_validation(config: AppConfig, task_dir: Path) -> None:
    descriptor = WorkspaceScanner(config).describe(task_dir)
    result = BatchValidator(config).validate_descriptor(descriptor)
    assert result.valid
    assert result.manifest_checksum
    assert result.verified_files == ["batch_000001.parquet"]


def test_claim_moves_ready_to_processing(config: AppConfig, task_dir: Path) -> None:
    descriptor = WorkspaceScanner(config).describe(task_dir)
    claimer = TaskClaimer(config, owner="worker-1")
    outcome = claimer.claim(descriptor)
    assert outcome.claimed
    assert (task_dir / "PROCESSING").is_file()
    assert not (task_dir / "READY").is_file()
    claimer.complete("task_a", task_dir)
    assert (task_dir / "DONE").is_file()
    assert not (task_dir / "PROCESSING").is_file()


def test_second_worker_cannot_claim_the_same_task(config: AppConfig, task_dir: Path) -> None:
    descriptor_first = WorkspaceScanner(config).describe(task_dir)
    first = TaskClaimer(config, owner="worker-1")
    assert first.claim(descriptor_first).claimed
    descriptor_second = WorkspaceScanner(config).describe(task_dir)
    second = TaskClaimer(config, owner="worker-2")
    outcome = second.claim(descriptor_second)
    assert not outcome.claimed
    assert "held by another worker" in outcome.reason or "already being processed" in outcome.reason
    first.release_all()


def test_stale_processing_task_is_recovered(config: AppConfig, task_dir: Path) -> None:
    descriptor = WorkspaceScanner(config).describe(task_dir)
    crashed = TaskClaimer(config, owner="worker-crashed")
    assert crashed.claim(descriptor).claimed
    # Simulate a crash: the heartbeat file is old and the lock is not released.
    lock_path = task_dir / ".m2_task_lock.json"
    payload = json.loads(lock_path.read_text(encoding="utf-8"))
    payload["heartbeat_at"] = time.time() - config.workspace.claim.stale_after_seconds - 60
    lock_path.write_text(json.dumps(payload), encoding="utf-8")

    descriptor = WorkspaceScanner(config).describe(task_dir)
    recovery = TaskClaimer(config, owner="worker-new")
    outcome = recovery.claim(descriptor)
    assert outcome.claimed
    assert outcome.recovered_stale_lease
    recovery.release_all()


def test_fresh_lock_blocks_recovery(config: AppConfig, task_dir: Path) -> None:
    descriptor = WorkspaceScanner(config).describe(task_dir)
    holder = TaskClaimer(config, owner="worker-holder")
    assert holder.claim(descriptor).claimed
    outcome = TaskClaimer(config, owner="worker-other").claim(
        WorkspaceScanner(config).describe(task_dir)
    )
    assert not outcome.claimed
    holder.release_all()


def test_failed_task_can_be_requeued(config: AppConfig, task_dir: Path) -> None:
    descriptor = WorkspaceScanner(config).describe(task_dir)
    claimer = TaskClaimer(config, owner="worker-1")
    claimer.claim(descriptor)
    claimer.fail("task_a", task_dir, error="boom")
    assert (task_dir / "FAILED").is_file()
    descriptor = WorkspaceScanner(config).describe(task_dir)
    claimer.requeue(descriptor)
    assert (task_dir / "READY").is_file()
    assert not (task_dir / "FAILED").is_file()


def test_sha256_helper_matches_hashlib(tmp_path: Path) -> None:
    import hashlib

    path = tmp_path / "payload.bin"
    path.write_bytes(b"module2")
    assert compute_sha256(path) == hashlib.sha256(b"module2").hexdigest()


def test_parquet_payload_is_readable_and_dotted(tmp_path: Path, config: AppConfig, event_factory) -> None:
    events = [event_factory("evt_0001", task_id="task_pq")]
    task_dir = write_batch(config.inbox_dir, events, task_id="task_pq")
    frame = pl.read_parquet(task_dir / "batch_000001.parquet")
    assert "event.event_id" in frame.columns
    assert frame.height == 1
    assert frame["event.event_id"][0] == "evt_0001"
