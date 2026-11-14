"""Crash recovery, cancellation and per-candidate failure isolation."""

from __future__ import annotations

import json
import time

import pytest

from backend.common.schemas.enums import TaskStatus
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.lifecycle import CancellationToken
from backend.module2_chain.devtools.synthetic import build_mixed_batch, write_batch
from backend.module2_chain.pipeline import Module2Pipeline
from backend.module2_chain.scanner.claim import TaskClaimer
from backend.module2_chain.scanner.workspace_scanner import WorkspaceScanner


async def test_crashed_processing_task_is_recovered(config: AppConfig, mock_provider) -> None:
    task_dir = write_batch(
        config.inbox_dir, build_mixed_batch(task_id="task_crash")[:6], task_id="task_crash"
    )
    descriptor = WorkspaceScanner(config).describe(task_dir)
    crashed = TaskClaimer(config, owner="worker-crashed")
    assert crashed.claim(descriptor).claimed

    # Simulate the crash: the lease heartbeat goes stale and is never released.
    lock_path = task_dir / ".m2_task_lock.json"
    payload = json.loads(lock_path.read_text(encoding="utf-8"))
    payload["heartbeat_at"] = time.time() - config.workspace.claim.stale_after_seconds - 30
    lock_path.write_text(json.dumps(payload), encoding="utf-8")

    pipeline = Module2Pipeline(config, provider=mock_provider)
    try:
        outcomes = await pipeline.run_once()
    finally:
        await pipeline.aclose()
        pipeline.registry.close()

    assert len(outcomes) == 1
    assert outcomes[0].status is TaskStatus.COMPLETED
    assert (config.output_dir / "task_crash" / "DONE").is_file()
    assert (task_dir / "DONE").is_file()
    assert not (task_dir / "PROCESSING").is_file()
    assert not lock_path.exists()


async def test_fresh_lease_is_not_stolen(config: AppConfig, mock_provider) -> None:
    task_dir = write_batch(
        config.inbox_dir, build_mixed_batch(task_id="task_busy")[:6], task_id="task_busy"
    )
    descriptor = WorkspaceScanner(config).describe(task_dir)
    holder = TaskClaimer(config, owner="worker-holder")
    assert holder.claim(descriptor).claimed

    pipeline = Module2Pipeline(config, provider=mock_provider)
    try:
        outcomes = await pipeline.run_once()
    finally:
        await pipeline.aclose()
        pipeline.registry.close()
        holder.release_all()

    assert len(outcomes) == 1
    assert outcomes[0].status is TaskStatus.PENDING
    reason = outcomes[0].skipped_reason or ""
    assert "held by another worker" in reason or "already being processed" in reason


async def test_cancellation_stops_the_run(config: AppConfig, mock_provider) -> None:
    write_batch(
        config.inbox_dir, build_mixed_batch(task_id="task_cancel")[:4], task_id="task_cancel"
    )
    token = CancellationToken()
    token.cancel("test cancellation")
    pipeline = Module2Pipeline(config, provider=mock_provider)
    try:
        outcomes = await pipeline.run_once(token=token)
    finally:
        await pipeline.aclose()
        pipeline.registry.close()
    assert outcomes == []
    assert not (config.output_dir / "task_cancel").exists()


async def test_one_failing_candidate_does_not_stop_the_task(
    config: AppConfig, mock_provider, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_batch(
        config.inbox_dir, build_mixed_batch(task_id="task_isolate"), task_id="task_isolate"
    )
    pipeline = Module2Pipeline(config, provider=mock_provider)
    original = pipeline.evidence_validator.validate
    seen = {"count": 0}

    def flaky(candidate, analysis, candidate_events, techniques):
        seen["count"] += 1
        if seen["count"] == 1:
            raise RuntimeError("synthetic candidate failure")
        return original(candidate, analysis, candidate_events, techniques)

    monkeypatch.setattr(pipeline.evidence_validator, "validate", flaky)
    try:
        outcomes = await pipeline.run_once(max_tasks=1)
    finally:
        await pipeline.aclose()
        pipeline.registry.close()

    assert outcomes[0].status is TaskStatus.COMPLETED
    assert any("synthetic candidate failure" in warning for warning in outcomes[0].warnings)
    assert outcomes[0].chain_ids


async def test_registry_records_batches_and_fingerprints(
    config: AppConfig, mock_provider
) -> None:
    write_batch(
        config.inbox_dir, build_mixed_batch(task_id="task_registry")[:8], task_id="task_registry"
    )
    pipeline = Module2Pipeline(config, provider=mock_provider)
    try:
        await pipeline.run_once(max_tasks=1)
        stats = pipeline.registry.stats()
        assert stats["tasks"] == 1
        assert stats["batches"] >= 1
        assert stats["fingerprints"] >= 1
        assert stats["llm_calls"] >= 1
        assert pipeline.registry.is_task_completed("task_registry")
        assert pipeline.registry.llm_call_count("task_registry") >= 1
    finally:
        await pipeline.aclose()
        pipeline.registry.close()


async def test_failed_task_can_be_retried(config: AppConfig, mock_provider) -> None:
    task_dir = write_batch(
        config.inbox_dir, build_mixed_batch(task_id="task_retry")[:6], task_id="task_retry"
    )
    payload = task_dir / "batch_000001.parquet"
    original = payload.read_bytes()
    payload.write_bytes(original[:32])

    pipeline = Module2Pipeline(config, provider=mock_provider)
    try:
        first = await pipeline.run_once(max_tasks=1)
        assert first[0].status is TaskStatus.FAILED
        assert (task_dir / "FAILED").is_file()
        # Operator repairs the batch and requeues the failed task.
        payload.write_bytes(original)
        second = await pipeline.run_once(retry_failed=True)
    finally:
        await pipeline.aclose()
        pipeline.registry.close()
    assert second[0].status is TaskStatus.COMPLETED
    assert (task_dir / "DONE").is_file()
    assert not (task_dir / "FAILED").is_file()
