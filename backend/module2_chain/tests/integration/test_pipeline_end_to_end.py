"""End-to-end pipeline integration tests (no Module 1, no Module 3, no network)."""

from __future__ import annotations

import json
from pathlib import Path

import polars as pl
import pytest

from backend.common.schemas.enums import TaskStatus
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.devtools.synthetic import build_mixed_batch, write_batch
from backend.module2_chain.pipeline import Module2Pipeline
from backend.module2_chain.reporting.atomic_io import sha256_file


def _bundle_files(bundle: Path) -> set[str]:
    return {
        str(path.relative_to(bundle))
        for path in bundle.rglob("*")
        if path.is_file()
    }


async def test_full_pipeline_produces_a_consumable_bundle(config: AppConfig, pipeline) -> None:
    events = build_mixed_batch(task_id="task_e2e")
    write_batch(config.inbox_dir, events, task_id="task_e2e")

    outcomes = await pipeline.run_once(max_tasks=1)

    assert len(outcomes) == 1
    outcome = outcomes[0]
    assert outcome.status is TaskStatus.COMPLETED
    assert outcome.bundle_path is not None
    assert outcome.report_path is not None and outcome.report_path.is_file()

    bundle = outcome.bundle_path
    files = _bundle_files(bundle)
    assert {"chains.json", "alerts.json", "attackers.json", "entities.json", "manifest.json", "metrics.json", "DONE"} <= files
    assert (bundle / "reports" / "report.json").is_file()
    assert (bundle / "chains" / "chains.json").is_file()
    assert (bundle / "evidence" / "evidence_summary.json").is_file()

    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    for ref in manifest["files"]:
        path = bundle / ref["path"]
        assert path.is_file()
        assert sha256_file(path) == ref["sha256"]

    chains = json.loads((bundle / "chains.json").read_text(encoding="utf-8"))
    alerts = json.loads((bundle / "alerts.json").read_text(encoding="utf-8"))
    report = json.loads((bundle / "reports" / "report.json").read_text(encoding="utf-8"))
    assert chains and alerts
    assert report["statistics"]["total_attack_events"] == len(chains)
    assert report["statistics"]["total_suspicious_events"] >= len(chains)
    for chain in chains:
        assert chain["stages"]
        for stage in chain["stages"]:
            assert stage["evidence_event_ids"]
        assert chain["risk_score"]["factors"]
        assert chain["llm_meta"]["prompt_version"] == config.llm.prompt_version

    # Inbox marker state machine completed.
    task_dir = config.inbox_dir / "task_e2e"
    assert (task_dir / "DONE").is_file()
    assert not (task_dir / "PROCESSING").is_file()
    assert not (task_dir / ".m2_task_lock.json").exists()

    # Status file + registry.
    status = json.loads(
        (config.status_dir / "task_e2e.json").read_text(encoding="utf-8")
    )
    assert status["status"] == "completed"
    assert status["progress"] == 100.0
    assert status["attack_events"] == len(chains)
    assert status["processed_batches"] >= 1
    registry_stats = pipeline.registry.stats()
    assert registry_stats["tasks"] == 1
    assert registry_stats["fingerprints"] >= 1


async def test_llm_calls_are_per_candidate_not_per_event(config: AppConfig, pipeline) -> None:
    events = build_mixed_batch(task_id="task_ratio")
    write_batch(config.inbox_dir, events, task_id="task_ratio")
    outcomes = await pipeline.run_once(max_tasks=1)
    bundle = outcomes[0].bundle_path
    assert bundle is not None
    metrics = json.loads((bundle / "metrics.json").read_text(encoding="utf-8"))
    assert metrics["llm_calls"] <= metrics["candidates"]
    assert metrics["llm_call_ratio"] < 0.5
    assert metrics["events_per_second"] > 0
    assert metrics["stage_timings"]


async def test_replaying_the_same_task_is_idempotent(config: AppConfig, mock_provider) -> None:
    events = build_mixed_batch(task_id="task_idem")
    write_batch(config.inbox_dir, events, task_id="task_idem")

    first_pipeline = Module2Pipeline(config, provider=mock_provider)
    try:
        first = await first_pipeline.run_once(max_tasks=1)
        chains_before = json.loads(
            (first[0].bundle_path / "chains.json").read_text(encoding="utf-8")
        )
        registry = first_pipeline.registry
        # Simulate an operator replaying the inbox: READY appears again.
        task_dir = config.inbox_dir / "task_idem"
        (task_dir / "DONE").unlink()
        write_batch(config.inbox_dir, events, task_id="task_idem")
    finally:
        await first_pipeline.aclose()
        registry.close()

    second_pipeline = Module2Pipeline(config, provider=mock_provider)
    try:
        second = await second_pipeline.run_once(max_tasks=1)
    finally:
        await second_pipeline.aclose()
        second_pipeline.registry.close()

    assert second[0].status is TaskStatus.COMPLETED
    assert second[0].idempotent_replay is True
    assert second[0].chain_ids == []
    chains_after = json.loads(
        (config.output_dir / "task_idem" / "chains.json").read_text(encoding="utf-8")
    )
    assert [chain["chain_id"] for chain in chains_after] == [
        chain["chain_id"] for chain in chains_before
    ]


async def test_force_reprocess_is_deterministic(config: AppConfig, mock_provider) -> None:
    events = build_mixed_batch(task_id="task_force")
    write_batch(config.inbox_dir, events, task_id="task_force")
    pipeline = Module2Pipeline(config, provider=mock_provider)
    try:
        first = await pipeline.run_once(max_tasks=1)
        chains_first = json.loads(
            (first[0].bundle_path / "chains.json").read_text(encoding="utf-8")
        )
        second = await pipeline.run_once(task_ids=["task_force"], force=True)
    finally:
        await pipeline.aclose()
        pipeline.registry.close()
    chains_second = json.loads(
        (second[0].bundle_path / "chains.json").read_text(encoding="utf-8")
    )
    assert [chain["chain_id"] for chain in chains_first] == [
        chain["chain_id"] for chain in chains_second
    ]
    assert [chain["fingerprint"] for chain in chains_first] == [
        chain["fingerprint"] for chain in chains_second
    ]


async def test_empty_batch_completes_with_an_empty_bundle(config: AppConfig, pipeline) -> None:
    write_batch(config.inbox_dir, [], task_id="task_empty")
    outcomes = await pipeline.run_once(max_tasks=1)
    outcome = outcomes[0]
    assert outcome.status is TaskStatus.COMPLETED
    bundle = outcome.bundle_path
    assert bundle is not None and (bundle / "DONE").is_file()
    chains = json.loads((bundle / "chains.json").read_text(encoding="utf-8"))
    report = json.loads((bundle / "reports" / "report.json").read_text(encoding="utf-8"))
    assert chains == []
    assert report["statistics"]["total_attack_events"] == 0
    assert "no attack event" in report["overview"]


async def test_multiple_batches_in_one_task_are_merged(config: AppConfig, pipeline) -> None:
    from backend.module2_chain.devtools.synthetic import build_events
    from backend.module2_chain.reporting.atomic_io import atomic_write_json
    from backend.module2_chain.scanner.manifest import build_file_ref, manifest_checksum

    task_dir = config.inbox_dir / "task_multi"
    task_dir.mkdir(parents=True, exist_ok=True)
    # A shared counter keeps event ids unique across both batch files.
    counter: list[int] = [0]
    first = build_events(
        "scanning", task_id="task_multi", attacker="10.0.0.8", event_counter=counter
    ).events
    second = build_events(
        "exploitation", task_id="task_multi", attacker="10.0.0.8", event_counter=counter
    ).events
    refs = []
    for index, payload in enumerate((first, second), start=1):
        rows = [event.to_flat_dict() for event in payload]
        path = task_dir / f"batch_{index:06d}.parquet"
        pl.DataFrame(rows, infer_schema_length=None).write_parquet(path)
        refs.append(
            build_file_ref(path, task_dir, row_count=len(payload)).model_dump(mode="json")
        )
    manifest = {
        "schema_version": "1.0.0",
        "task_id": "task_multi",
        "batch_id": "batch_multi",
        "producer": "module1_fake",
        "created_at": "2024-05-01T12:00:00+00:00",
        "event_count": len(first) + len(second),
        "files": refs,
    }
    manifest["checksum"] = manifest_checksum(manifest)
    atomic_write_json(task_dir / "manifest.json", manifest)
    (task_dir / "READY").write_text("{}", encoding="utf-8")

    outcomes = await pipeline.run_once(max_tasks=1)
    assert outcomes[0].status is TaskStatus.COMPLETED
    assert outcomes[0].event_count == len(first) + len(second)
    status = json.loads(
        (config.status_dir / "task_multi.json").read_text(encoding="utf-8")
    )
    assert status["processed_batches"] == 2


async def test_multiple_tasks_are_processed_independently(config: AppConfig, pipeline) -> None:
    write_batch(
        config.inbox_dir,
        build_mixed_batch(task_id="task_a")[:6],
        task_id="task_a",
    )
    write_batch(
        config.inbox_dir,
        build_mixed_batch(task_id="task_b", seed=99)[:6],
        task_id="task_b",
    )
    outcomes = await pipeline.run_once()
    assert {outcome.task_id for outcome in outcomes} == {"task_a", "task_b"}
    assert all(outcome.status is TaskStatus.COMPLETED for outcome in outcomes)
    assert (config.output_dir / "task_a" / "DONE").is_file()
    assert (config.output_dir / "task_b" / "DONE").is_file()


async def test_fixture_batch_can_be_processed(config: AppConfig, pipeline, fixtures_dir: Path) -> None:
    """The generated fixture batch must be consumable as-is (spec §43)."""

    source = fixtures_dir / "events" / "task_fixture_events"
    target = config.inbox_dir / "task_fixture_events"
    target.mkdir(parents=True, exist_ok=True)
    for name in ("batch_000001.parquet", "manifest.json", "READY"):
        (target / name).write_bytes((source / name).read_bytes())
    outcomes = await pipeline.run_once(max_tasks=1)
    assert outcomes[0].status is TaskStatus.COMPLETED
    assert outcomes[0].event_count >= 100
    assert outcomes[0].chain_ids


async def test_fixture_artifacts_validate_against_the_contract(fixtures_dir: Path) -> None:
    from backend.common.schemas.attack import AttackChain
    from backend.common.schemas.profile import AttackerProfile

    candidates = json.loads(
        (fixtures_dir / "attack_candidates.json").read_text(encoding="utf-8")
    )
    chains_raw = json.loads(
        (fixtures_dir / "attack_chains.json").read_text(encoding="utf-8")
    )
    profiles_raw = json.loads(
        (fixtures_dir / "attacker_profiles.json").read_text(encoding="utf-8")
    )
    assert len(candidates) >= 100
    assert len(chains_raw) >= 20
    assert len(profiles_raw) >= 10
    for chain in chains_raw:
        model = AttackChain.model_validate(chain)
        assert [stage.stage_index for stage in model.stages] == list(
            range(1, len(model.stages) + 1)
        )
    for profile in profiles_raw:
        assert AttackerProfile.model_validate(profile).attribution == "Not Determined"


@pytest.mark.parametrize("seed", [1, 2, 3])
async def test_pipeline_is_deterministic_across_seeds(
    config: AppConfig, mock_provider, seed: int
) -> None:
    events = build_mixed_batch(task_id=f"task_seed_{seed}", seed=seed)
    write_batch(config.inbox_dir, events, task_id=f"task_seed_{seed}")
    pipeline = Module2Pipeline(config, provider=mock_provider)
    try:
        first = await pipeline.run_once(max_tasks=1)
        chains_first = json.loads(
            (first[0].bundle_path / "chains.json").read_text(encoding="utf-8")
        )
        second = await pipeline.run_once(task_ids=[f"task_seed_{seed}"], force=True)
    finally:
        await pipeline.aclose()
        pipeline.registry.close()
    chains_second = json.loads(
        (second[0].bundle_path / "chains.json").read_text(encoding="utf-8")
    )
    assert [chain["chain_id"] for chain in chains_first] == [
        chain["chain_id"] for chain in chains_second
    ]
