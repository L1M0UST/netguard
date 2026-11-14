"""Structured logging and atomic bundle delivery tests."""

from __future__ import annotations

import json
from pathlib import Path

import polars as pl

from backend.module2_chain.app.logging import (
    JsonLogFormatter,
    bind_context,
    clear_context,
    configure_logging,
)
from backend.module2_chain.reporting.atomic_io import (
    atomic_write_bytes,
    atomic_write_json,
    sha256_file,
)
from backend.module2_chain.reporting.bundle_writer import BundlePayload, BundleWriter


def test_json_log_formatter_emits_required_fields() -> None:
    import logging

    formatter = JsonLogFormatter(static_fields={"environment": "test"})
    record = logging.LogRecord(
        name="module2_chain.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello %s",
        args=("world",),
        exc_info=None,
    )
    record.candidate_id = "cand_1"
    token = bind_context(task_id="task_1", stage="correlation", batch_id="batch_000001")
    try:
        payload = json.loads(formatter.format(record))
    finally:
        clear_context()
        del token
    assert payload["level"] == "INFO"
    assert payload["module"] == "module2_chain"
    assert payload["message"] == "hello world"
    assert payload["task_id"] == "task_1"
    assert payload["batch_id"] == "batch_000001"
    assert payload["stage"] == "correlation"
    assert payload["candidate_id"] == "cand_1"
    assert payload["timestamp"].endswith("Z")


def test_api_keys_are_redacted() -> None:
    import logging

    formatter = JsonLogFormatter()
    record = logging.LogRecord(
        name="module2_chain.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="calling provider",
        args=(),
        exc_info=None,
    )
    record.api_key = "sk-abcdefghijklmnopqrstuvwxyz"
    record.authorization = "Bearer sk-abcdefghijklmnopqrstuvwxyz"
    payload = json.loads(formatter.format(record))
    assert payload["api_key"] == "***redacted***"
    assert payload["authorization"] == "***redacted***"
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in json.dumps(payload)


def test_long_values_are_truncated() -> None:
    import logging

    formatter = JsonLogFormatter()
    record = logging.LogRecord(
        name="module2_chain.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="payload",
        args=(),
        exc_info=None,
    )
    record.payload_snippet = "GET /index.html?param=value HTTP/1.1 " * 200
    payload = json.loads(formatter.format(record))
    assert len(payload["payload_snippet"]) < 600
    assert "truncated" in payload["payload_snippet"]


def test_configure_logging_switches_format() -> None:
    logger = configure_logging(level="WARNING", fmt="json")
    assert logger.level == 30
    assert isinstance(logger.handlers[0].formatter, JsonLogFormatter)


def test_atomic_write_is_durable_and_leaves_no_temp_files(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "payload.json"
    atomic_write_json(target, {"a": 1})
    assert json.loads(target.read_text(encoding="utf-8")) == {"a": 1}
    assert not list(target.parent.glob("*.tmp"))
    binary = tmp_path / "payload.bin"
    atomic_write_bytes(binary, b"data")
    assert binary.read_bytes() == b"data"


def test_bundle_writer_publishes_everything_with_a_manifest(config, tmp_path: Path) -> None:
    from backend.module2_chain.tests.conftest import make_event
    from backend.module2_chain.tests.unit.test_profiling_entities_report import _chains

    groups = [[make_event("evt_1", rules=["l1_port_scan_sweep"])]]
    chains = _chains(config, groups)
    writer = BundleWriter(config)
    result = writer.write(
        BundlePayload(
            task_id="task_bundle",
            chains=chains,
            alerts=[],
            attackers=[],
            entities=[],
            report=None,
            metrics={"events": 1},
            evidence={"chain": {"event_ids": ["evt_1"]}},
            input_batches=["batch_000001"],
            input_checksums=["abc"],
            run={"provider": "mock"},
        )
    )
    bundle = result.bundle_dir
    for relative in (
        "chains/chains.json",
        "chains.json",
        "alerts/alerts.json",
        "alerts.json",
        "attackers/attackers.json",
        "entities/entities.json",
        "metrics.json",
        "manifest.json",
        "DONE",
    ):
        assert (bundle / relative).is_file(), relative
    assert not (bundle.parent / "task_bundle.tmp").exists()
    assert result.done_marker.is_file()

    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["task_id"] == "task_bundle"
    assert manifest["counts"]["chains"] == len(chains)
    for ref in manifest["files"]:
        path = bundle / ref["path"]
        assert path.is_file()
        assert sha256_file(path) == ref["sha256"]
        assert path.stat().st_size == ref["size_bytes"]
    done = json.loads((bundle / "DONE").read_text(encoding="utf-8"))
    assert done["task_id"] == "task_bundle"


def test_bundle_parquet_mirrors_are_readable(config) -> None:
    from backend.module2_chain.tests.conftest import make_event
    from backend.module2_chain.tests.unit.test_profiling_entities_report import _chains

    groups = [[make_event("evt_1", rules=["l1_port_scan_sweep"])]]
    chains = _chains(config, groups)
    result = BundleWriter(config).write(
        BundlePayload(task_id="task_parquet", chains=chains)
    )
    frame = pl.read_parquet(result.bundle_dir / "chains" / "chains.parquet")
    assert frame.height == len(chains)
    assert "chain_id" in frame.columns
    assert "severity" in frame.columns


def test_bundle_replaces_a_previous_version(config) -> None:
    from backend.module2_chain.tests.conftest import make_event
    from backend.module2_chain.tests.unit.test_profiling_entities_report import _chains

    groups = [[make_event("evt_1", rules=["l1_port_scan_sweep"])]]
    chains = _chains(config, groups)
    writer = BundleWriter(config)
    first = writer.write(BundlePayload(task_id="task_repeat", chains=chains))
    stale = first.bundle_dir / "stale.json"
    stale.write_text("{}", encoding="utf-8")
    second = writer.write(BundlePayload(task_id="task_repeat", chains=chains))
    assert second.bundle_dir == first.bundle_dir
    assert not stale.exists()
    assert (second.bundle_dir / "DONE").is_file()
