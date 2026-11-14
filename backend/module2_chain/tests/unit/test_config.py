"""Configuration system tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.module2_chain.app.config import (
    ENV_OVERRIDES,
    ConfigError,
    load_config,
    read_dotenv,
)


def test_defaults_load_from_repo_config(tmp_path: Path) -> None:
    config = load_config(
        Path(__file__).resolve().parents[4] / "config.yaml",
        project_root=tmp_path,
        env={},
    )
    assert config.correlation.correlation_window_seconds == 300
    assert config.llm.max_concurrency >= 1
    assert config.llm.max_retries <= 2
    assert config.llm.provider in {"deepseek", "finetuned", "mock", "disabled"}
    assert config.risk.severity_thresholds.critical > config.risk.severity_thresholds.high


def test_environment_overrides_are_applied(tmp_path: Path) -> None:
    config = load_config(
        Path(__file__).resolve().parents[4] / "config.yaml",
        project_root=tmp_path,
        env={
            "LLM_PROVIDER": "mock",
            "LLM_MAX_CONCURRENCY": "9",
            "CORRELATION_WINDOW_SECONDS": "42",
            "DEEPSEEK_MODEL": "custom-model",
            "WORKSPACE_PATH": str(tmp_path / "ws"),
        },
    )
    assert config.llm.provider == "mock"
    assert config.llm.max_concurrency == 9
    assert config.correlation.correlation_window_seconds == 42
    assert config.llm.providers.deepseek.model == "custom-model"
    assert config.workspace.root == str(tmp_path / "ws")


def test_dotenv_is_read_and_never_required(tmp_path: Path) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_text(
        "# comment\nexport LLM_PROVIDER=mock\nDEEPSEEK_API_KEY=sk-secret-value-123456\n",
        encoding="utf-8",
    )
    values = read_dotenv(dotenv)
    assert values["LLM_PROVIDER"] == "mock"
    config = load_config(
        Path(__file__).resolve().parents[4] / "config.yaml",
        project_root=tmp_path,
        env={},
        dotenv_path=dotenv,
    )
    assert config.llm.provider == "mock"
    # Secrets are wrapped in SecretStr and never leak through dumps.
    dumped = config.model_dump_json()
    assert "sk-secret-value-123456" not in dumped


def test_env_override_map_has_no_duplicates() -> None:
    assert len(ENV_OVERRIDES) == len(set(ENV_OVERRIDES.values()))
    assert "LLM_PROVIDER" in ENV_OVERRIDES
    assert ENV_OVERRIDES["DEEPSEEK_API_KEY"].startswith("llm.providers.deepseek")


def test_secret_values_are_not_serialised(tmp_path: Path) -> None:
    config = load_config(
        Path(__file__).resolve().parents[4] / "config.yaml",
        project_root=tmp_path,
        env={"LLM_PROVIDER": "deepseek", "DEEPSEEK_API_KEY": "sk-abcdefghijklmnop"},
    )
    assert config.llm.providers.deepseek.resolved_api_key() == "sk-abcdefghijklmnop"
    assert "sk-abcdefghijklmnop" not in repr(config.llm.providers.deepseek)


def test_unknown_config_section_fails_fast(tmp_path: Path) -> None:
    bad = tmp_path / "config.yaml"
    bad.write_text("unknown_section:\n  value: 1\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(bad, env={})


def test_paths_are_resolved_against_project_root(tmp_path: Path) -> None:
    config = load_config(
        Path(__file__).resolve().parents[4] / "config.yaml",
        project_root=tmp_path,
        env={"WORKSPACE_PATH": "shared"},
    )
    assert config.inbox_dir == tmp_path / "shared" / "04_m2_inbox"
    assert config.output_dir == tmp_path / "shared" / "05_m2_output"
    assert config.status_dir == tmp_path / "shared" / "06_status" / "m2"
    assert config.attack_kb_path == (
        tmp_path / "backend" / "module2_chain" / "attack" / "knowledge" / "attack_kb.yaml"
    )
    assert config.sqlite_path == tmp_path / "workspace" / "06_status" / "m2" / "module2_state.db"
