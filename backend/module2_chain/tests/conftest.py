"""Shared pytest fixtures.

All tests run against a **throwaway shared workspace** under ``tmp_path`` and
the ``mock`` LLM provider: no test ever touches the DeepSeek API (spec §44).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from backend.common.schemas.suspicious_event import SuspiciousEvent
from backend.module2_chain.app.config import AppConfig, load_config, reset_config_cache
from backend.module2_chain.app.lifecycle import ensure_workspace
from backend.module2_chain.devtools.synthetic import write_batch
from backend.module2_chain.llm.mock import MockLLMProvider
from backend.module2_chain.pipeline import Module2Pipeline

PROJECT_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_DIR = PROJECT_ROOT / "tests" / "fixtures"
BASE_TIME = datetime(2024, 5, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _clear_config_cache() -> Iterator[None]:
    reset_config_cache()
    yield
    reset_config_cache()


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    return tmp_path / "workspace"


def build_config(
    workspace: Path,
    *,
    project_root: Path = PROJECT_ROOT,
    env: dict[str, str] | None = None,
) -> AppConfig:
    """Config pointing at a temporary workspace, with repo resources intact."""

    overrides = {
        "WORKSPACE_PATH": str(workspace),
        "SQLITE_PATH": str(workspace / "06_status" / "m2" / "module2_state.db"),
        "LLM_PROVIDER": "mock",
        "MOCK_LLM_FIXTURE": "",
        # 测试固定使用仓库自带的种子情报；运行时真实情报（bridge 导出）不参与测试，
        # 避免"测试数据被运行时数据覆盖"的耦合。
        "THREAT_INTEL_PATH": str(PROJECT_ROOT / "data" / "threat_intel_seed"),
        **(env or {}),
    }
    config = load_config(
        PROJECT_ROOT / "config.yaml", project_root=project_root, env=overrides
    )
    ensure_workspace(config)
    return config


@pytest.fixture
def config(workspace: Path) -> AppConfig:
    return build_config(workspace)


@pytest.fixture
def make_config() -> Any:
    return build_config


@pytest.fixture
def mock_fixture() -> dict[str, Any]:
    return {
        "default": {
            "verdict": "attack",
            "attack_summary": "Mock summary for {{candidate_id}}",
            "attacker_assessment": "Mock attacker",
            "victim_assessment": "Mock victim",
            "stages": [
                {
                    "stage_index": 1,
                    "tactic": "{{tactic_1}}",
                    "technique": "{{technique_1}}",
                    "narrative": "Mock narrative",
                    "evidence_event_ids": "{{event_ids}}",
                    "confidence": 0.8,
                }
            ],
            "threat_entities": [],
            "uncertainties": [],
            "confidence": 0.7,
        }
    }


@pytest.fixture
def mock_provider(config: AppConfig, mock_fixture: dict[str, Any]) -> MockLLMProvider:
    return MockLLMProvider(
        config.llm.providers.mock, config.llm, fixture=mock_fixture
    )


@pytest.fixture
def pipeline(config: AppConfig, mock_provider: MockLLMProvider) -> Iterator[Module2Pipeline]:
    instance = Module2Pipeline(config, provider=mock_provider)
    yield instance
    instance.registry.close()


def make_event(
    event_id: str,
    *,
    task_id: str = "task_test",
    timestamp: datetime | None = None,
    src_ip: str | None = "10.0.0.8",
    dst_ip: str | None = "10.0.0.12",
    src_port: int | None = 40000,
    dst_port: int | None = 80,
    protocol: str | None = "tcp",
    rules: list[str] | None = None,
    ioc_hits: list[str] | None = None,
    score: float = 60.0,
    reason: str | None = None,
    detector: str | None = "test_detector",
    session_id: str | None = None,
    payload_digest: str | None = None,
) -> SuspiciousEvent:
    """Factory for contract-compliant suspicious events."""

    return SuspiciousEvent.model_validate(
        {
            "event": {
                "event_id": event_id,
                "task_id": task_id,
                "timestamp": timestamp or BASE_TIME,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "payload_digest": payload_digest or f"digest-{event_id}",
                "raw_ref": f"raw/{event_id}",
                "source_file": "unit-test.pcap",
            },
            "detection": {
                "matched_rules": rules if rules is not None else ["l1_port_scan_sweep"],
                "ioc_hits": ioc_hits or [],
                "score": score,
                "reason": reason if reason is not None else "unit test reason",
                "detector": detector,
            },
            "session_id": session_id,
            "emitted_at": BASE_TIME,
        }
    )


@pytest.fixture
def event_factory() -> Any:
    return make_event


def offset(seconds: float) -> datetime:
    return BASE_TIME + timedelta(seconds=seconds)


@pytest.fixture
def write_task_batch() -> Any:
    """Write a task folder into a workspace's inbox."""

    def _write(
        config: AppConfig,
        events: list[SuspiciousEvent],
        *,
        task_id: str = "task_test",
        ready: bool = True,
    ) -> Path:
        return write_batch(config.inbox_dir, events, task_id=task_id, ready=ready)

    return _write


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURE_DIR


def load_fixture(name: str) -> Any:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))
