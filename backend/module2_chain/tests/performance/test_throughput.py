"""Performance / throughput tests (spec §38).

The goal is not micro-benchmarking but a guard rail: correlation must stay
sub-linear enough for 10k events and the LLM must never be called per event.
"""

from __future__ import annotations

import json
import shutil
import time
from datetime import timedelta

import pytest

from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.lifecycle import ensure_workspace
from backend.module2_chain.attack.knowledge import load_knowledge_base
from backend.module2_chain.correlation.engine import CorrelationEngine
from backend.module2_chain.devtools.synthetic import (
    BASE_TIME,
    build_events_for_count,
    build_mixed_batch,
    write_batch,
)
from backend.module2_chain.pipeline import Module2Pipeline

pytestmark = pytest.mark.performance


def test_correlation_handles_10k_events(config: AppConfig) -> None:
    events = build_events_for_count(10_000, task_id="task_perf_10k")
    engine = CorrelationEngine(
        config, knowledge=load_knowledge_base(config.attack_kb_path)
    )
    started = time.perf_counter()
    candidates = engine.correlate(events)
    duration = time.perf_counter() - started
    throughput = len(events) / duration

    assert duration < 120.0, f"correlation took {duration:.1f}s for 10k events"
    assert throughput > 200, f"only {throughput:.0f} events/s"
    assert len(candidates) > 100
    assert all(candidate.event_ids for candidate in candidates)


def test_dense_single_attacker_burst_stays_bounded(config: AppConfig) -> None:
    """2000 events from one attacker inside one window is the worst case."""

    base = build_events_for_count(2000, task_id="task_dense")
    events = [
        event.model_copy(
            update={
                "event": event.event.model_copy(
                    update={
                        "event_id": f"dense_{index:05d}",
                        "src_ip": "203.0.113.9",
                        "timestamp": BASE_TIME + timedelta(seconds=index * 0.1),
                    }
                )
            }
        )
        for index, event in enumerate(base)
    ]
    engine = CorrelationEngine(
        config, knowledge=load_knowledge_base(config.attack_kb_path)
    )
    started = time.perf_counter()
    candidates = engine.correlate(events)
    duration = time.perf_counter() - started
    assert duration < 60.0
    assert len(candidates) == 1
    assert candidates[0].score_summary.event_count > 100


async def test_full_pipeline_throughput_and_llm_call_ratio(
    config: AppConfig, mock_provider
) -> None:
    events = build_events_for_count(1000, task_id="task_perf_pipeline")
    write_batch(config.inbox_dir, events, task_id="task_perf_pipeline")
    pipeline = Module2Pipeline(config, provider=mock_provider)
    started = time.perf_counter()
    try:
        outcomes = await pipeline.run_once(max_tasks=1)
    finally:
        await pipeline.aclose()
        pipeline.registry.close()
    wall_seconds = time.perf_counter() - started

    outcome = outcomes[0]
    bundle = outcome.bundle_path
    assert bundle is not None
    metrics = json.loads((bundle / "metrics.json").read_text(encoding="utf-8"))

    assert metrics["events_unique"] == 1000
    assert metrics["llm_calls"] <= metrics["candidates"]
    assert metrics["llm_calls_per_candidate"] <= 1.0
    assert metrics["llm_call_ratio"] < 0.5
    assert metrics["events_per_second"] > 100, metrics["events_per_second"]
    assert metrics["stage_timings"]
    assert metrics["peak_memory_mb"] is None or metrics["peak_memory_mb"] > 0
    assert wall_seconds < 300

    # A single task with 1000 events must not produce thousands of artifacts.
    assert metrics["chains"] == metrics["candidates"]
    assert len(outcome.chain_ids) == metrics["chains"]


async def test_pipeline_scales_linearly_enough_for_two_sizes(
    config: AppConfig, mock_provider
) -> None:
    """500 vs 1500 events: the growth factor must stay reasonable."""

    timings: dict[int, float] = {}
    for size in (500, 1500):
        task_id = f"task_scale_{size}"
        events = build_events_for_count(size, task_id=task_id)
        write_batch(config.inbox_dir, events, task_id=task_id)
        pipeline = Module2Pipeline(config, provider=mock_provider)
        started = time.perf_counter()
        try:
            outcomes = await pipeline.run_once(task_ids=[task_id])
        finally:
            await pipeline.aclose()
            pipeline.registry.close()
        assert outcomes[0].status.value == "completed"
        timings[size] = time.perf_counter() - started

    growth = timings[1500] / max(timings[500], 1e-6)
    assert growth < 12.0, f"unexpected super-linear growth: {timings}"


def test_reference_data_loading_is_fast(config: AppConfig) -> None:
    from backend.module2_chain.threat_intel.service import ThreatIntelService

    started = time.perf_counter()
    service = ThreatIntelService(config)
    load_seconds = time.perf_counter() - started
    assert load_seconds < 5.0
    for indicator in ("203.0.113.45", "evil-c2.example.com", "CVE-2021-44228"):
        assert service.enrich(indicator) is not None


def test_bundle_writing_scales_with_chains(config: AppConfig) -> None:
    from backend.module2_chain.reporting.bundle_writer import BundlePayload, BundleWriter
    from backend.module2_chain.tests.conftest import make_event
    from backend.module2_chain.tests.unit.test_profiling_entities_report import _chains

    groups = [
        [
            make_event(
                f"evt_{index:04d}",
                src_ip=f"198.18.9.{index + 1}",
                rules=["l1_port_scan_sweep"],
            )
        ]
        for index in range(60)
    ]
    chains = _chains(config, groups)
    writer = BundleWriter(config)
    started = time.perf_counter()
    result = writer.write(BundlePayload(task_id="task_bundle_perf", chains=chains))
    duration = time.perf_counter() - started
    assert duration < 30.0
    assert (result.bundle_dir / "DONE").is_file()
    assert len(result.files) > 0


def test_workspace_is_clean_after_performance_runs(config: AppConfig) -> None:
    """No temp directories must survive a finished run."""

    write_batch(
        config.inbox_dir, build_mixed_batch(task_id="task_clean")[:6], task_id="task_clean"
    )
    ensure_workspace(config)
    assert not list(config.output_dir.glob("*.tmp"))
    shutil.rmtree(config.inbox_dir / "task_clean", ignore_errors=True)
