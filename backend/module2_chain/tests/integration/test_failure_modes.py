"""Failure handling and LLM degradation (spec §19/§47)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from backend.common.schemas.enums import TaskStatus
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.devtools.synthetic import build_mixed_batch, write_batch
from backend.module2_chain.llm.base import (
    LLMAuthError,
    LLMInvalidJSONError,
    LLMProviderError,
    LLMTimeoutError,
)
from backend.module2_chain.llm.schemas import AttackAnalysisRequest, LLMAttackAnalysis
from backend.module2_chain.persistence.registry import ProcessedRegistry
from backend.module2_chain.pipeline import Module2Pipeline
from backend.module2_chain.scanner.manifest import manifest_checksum


class FailingProvider:
    """Provider that always fails with a configured error."""

    name = "failing"
    model = None
    enabled = True

    def __init__(self, error: Exception) -> None:
        self.error = error
        self.calls = 0

    async def analyze_attack_scenario(
        self, request: AttackAnalysisRequest
    ) -> LLMAttackAnalysis:
        self.calls += 1
        raise self.error

    async def aclose(self) -> None:
        """Nothing to release."""

    def health(self) -> dict[str, Any]:
        return {"provider": self.name, "calls": self.calls}


def _pipeline(config: AppConfig, provider: Any) -> Module2Pipeline:
    return Module2Pipeline(
        config, provider=provider, registry=ProcessedRegistry(config)
    )


@pytest.mark.parametrize(
    "error",
    [
        LLMTimeoutError("timeout"),
        LLMProviderError("provider down"),
        LLMInvalidJSONError("bad json"),
        LLMAuthError("missing key"),
    ],
)
async def test_llm_failures_never_fail_the_task(config: AppConfig, error: Exception) -> None:
    events = build_mixed_batch(task_id="task_degrade")
    write_batch(config.inbox_dir, events, task_id="task_degrade")
    pipeline = _pipeline(config, FailingProvider(error))
    try:
        outcomes = await pipeline.run_once(max_tasks=1)
    finally:
        await pipeline.aclose()
        pipeline.registry.close()

    outcome = outcomes[0]
    assert outcome.status is TaskStatus.COMPLETED
    bundle = outcome.bundle_path
    assert bundle is not None and (bundle / "DONE").is_file()
    chains = json.loads((bundle / "chains.json").read_text(encoding="utf-8"))
    assert chains
    assert all(chain["llm_degraded"] is True for chain in chains)
    assert all(chain["stages"] for chain in chains)
    assert all(chain["llm_meta"]["llm_degraded"] for chain in chains)
    assert all(chain["uncertainties"] for chain in chains)
    status = json.loads(
        (config.status_dir / "task_degrade.json").read_text(encoding="utf-8")
    )
    assert status["llm_failures"] == status["llm_calls"] > 0


async def test_corrupted_parquet_fails_only_that_task(config: AppConfig, mock_provider) -> None:
    good = build_mixed_batch(task_id="task_good")[:6]
    write_batch(config.inbox_dir, good, task_id="task_good")
    broken = write_batch(config.inbox_dir, good, task_id="task_broken")
    payload = broken / "batch_000001.parquet"
    payload.write_bytes(payload.read_bytes()[:64])

    pipeline = Module2Pipeline(config, provider=mock_provider)
    try:
        outcomes = await pipeline.run_once()
    finally:
        await pipeline.aclose()
        pipeline.registry.close()

    by_task = {outcome.task_id: outcome for outcome in outcomes}
    assert by_task["task_good"].status is TaskStatus.COMPLETED
    assert by_task["task_broken"].status is TaskStatus.FAILED
    assert by_task["task_broken"].errors
    assert (config.inbox_dir / "task_broken" / "FAILED").is_file()
    assert not (config.output_dir / "task_broken" / "DONE").exists()
    status = json.loads(
        (config.status_dir / "task_broken.json").read_text(encoding="utf-8")
    )
    assert status["status"] == "failed"
    assert status["error"]


async def test_sha256_mismatch_fails_the_task(config: AppConfig, mock_provider) -> None:
    task_dir = write_batch(
        config.inbox_dir, build_mixed_batch(task_id="task_hash")[:4], task_id="task_hash"
    )
    manifest_path = task_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    pipeline = Module2Pipeline(config, provider=mock_provider)
    try:
        outcomes = await pipeline.run_once(max_tasks=1)
    finally:
        await pipeline.aclose()
        pipeline.registry.close()
    assert outcomes[0].status is TaskStatus.FAILED
    assert "sha256" in " ".join(outcomes[0].errors)


async def test_unsupported_schema_version_fails_the_task(
    config: AppConfig, mock_provider
) -> None:
    task_dir = write_batch(
        config.inbox_dir, build_mixed_batch(task_id="task_schema")[:4], task_id="task_schema"
    )
    manifest_path = task_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["schema_version"] = "2.0.0"
    manifest["checksum"] = manifest_checksum(manifest)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    pipeline = Module2Pipeline(config, provider=mock_provider)
    try:
        outcomes = await pipeline.run_once(max_tasks=1)
    finally:
        await pipeline.aclose()
        pipeline.registry.close()
    assert outcomes[0].status is TaskStatus.FAILED
    assert "schema_version" in " ".join(outcomes[0].errors)


async def test_task_without_ready_marker_is_not_consumed(
    config: AppConfig, mock_provider
) -> None:
    write_batch(
        config.inbox_dir,
        build_mixed_batch(task_id="task_notready")[:4],
        task_id="task_notready",
        ready=False,
    )
    pipeline = Module2Pipeline(config, provider=mock_provider)
    try:
        outcomes = await pipeline.run_once()
    finally:
        await pipeline.aclose()
        pipeline.registry.close()
    assert outcomes == []
    assert not (config.output_dir / "task_notready").exists()


async def test_missing_declared_file_fails_validation(config: AppConfig, mock_provider) -> None:
    task_dir = write_batch(
        config.inbox_dir,
        build_mixed_batch(task_id="task_missingfile")[:4],
        task_id="task_missingfile",
    )
    (task_dir / "batch_000001.parquet").unlink()
    pipeline = Module2Pipeline(config, provider=mock_provider)
    try:
        outcomes = await pipeline.run_once(max_tasks=1)
    finally:
        await pipeline.aclose()
        pipeline.registry.close()
    assert outcomes[0].status is TaskStatus.FAILED
    assert "missing" in " ".join(outcomes[0].errors).lower()


async def test_broken_rows_are_dropped_instead_of_failing_the_task(
    config: AppConfig, mock_provider
) -> None:
    events = build_mixed_batch(task_id="task_dirty")[:6]
    broken = events[0].model_copy(
        update={
            "event": events[0].event.model_copy(update={"src_ip": None, "dst_ip": None})
        }
    )
    write_batch(config.inbox_dir, [*events, broken], task_id="task_dirty")
    pipeline = Module2Pipeline(config, provider=mock_provider)
    try:
        outcomes = await pipeline.run_once(max_tasks=1)
    finally:
        await pipeline.aclose()
        pipeline.registry.close()
    assert outcomes[0].status is TaskStatus.COMPLETED
    assert 0 < outcomes[0].event_count < len(events) + 1


async def test_deepseek_without_api_key_degrades_gracefully(
    config: AppConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The default (DeepSeek) provider must degrade without failing the task."""

    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    selected = config.model_copy(
        update={
            "llm": config.llm.model_copy(
                update={
                    "provider": "deepseek",
                    "providers": config.llm.providers.model_copy(
                        update={
                            "deepseek": config.llm.providers.deepseek.model_copy(
                                update={
                                    "api_key": None,
                                    "api_key_env": "ENV_VAR_THAT_IS_NOT_SET",
                                }
                            )
                        }
                    ),
                }
            )
        }
    )
    write_batch(
        selected.inbox_dir,
        build_mixed_batch(task_id="task_deepseek")[:8],
        task_id="task_deepseek",
    )
    pipeline = Module2Pipeline(selected)
    try:
        outcomes = await pipeline.run_once(max_tasks=1)
    finally:
        await pipeline.aclose()
        pipeline.registry.close()
    assert outcomes[0].status is TaskStatus.COMPLETED
    chains = json.loads((outcomes[0].bundle_path / "chains.json").read_text(encoding="utf-8"))
    assert chains
    assert all(chain["llm_degraded"] for chain in chains)
    assert all(chain["llm_meta"]["status"] == "auth_error" for chain in chains)
