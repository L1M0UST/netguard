"""Module 2 command line entry point.

Module 2 is a *batch application*, not a service: every command either scans the
shared workspace, processes a task folder, or inspects local state.  There is no
``/analyze`` endpoint and no server socket anywhere in this package.

Commands::

    python -m backend.module2_chain.main run            # scan + process once
    python -m backend.module2_chain.main watch          # poll the inbox
    python -m backend.module2_chain.main task --task-id task_x --force
    python -m backend.module2_chain.main status
    python -m backend.module2_chain.main registry --stats
    python -m backend.module2_chain.main providers
    python -m backend.module2_chain.main selftest
    python -m backend.module2_chain.main sample-output
    python -m backend.module2_chain.main validate-config
"""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from backend.module2_chain.app.config import (
    AppConfig,
    ConfigError,
    get_config,
    load_config,
    reset_config_cache,
)
from backend.module2_chain.app.lifecycle import ensure_workspace, signal_cancellation
from backend.module2_chain.app.logging import configure_logging, get_logger
from backend.module2_chain.attack.knowledge import (
    knowledge_base_summary,
    load_knowledge_base,
)
from backend.module2_chain.devtools.synthetic import build_mixed_batch, write_batch
from backend.module2_chain.llm.factory import SUPPORTED_PROVIDERS, create_llm_provider
from backend.module2_chain.persistence.registry import ProcessedRegistry
from backend.module2_chain.persistence.status_store import TaskStatusStore
from backend.module2_chain.pipeline import Module2Pipeline

logger = get_logger("cli")

DEFAULT_WATCH_INTERVAL_SECONDS = 10.0

#: Repository root (``.../NetworkAttackAnalysisSystem``).
REPO_ROOT = Path(__file__).resolve().parents[2]


def default_config_path() -> Path:
    return Path.cwd() / "config.yaml" if (Path.cwd() / "config.yaml").is_file() else REPO_ROOT / "config.yaml"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="module2-chain",
        description=(
            "Module 2 - attack correlation and intelligent judgement engine "
            "(shared-workspace batch application, no network API)"
        ),
    )
    parser.add_argument("--config", help="path to config.yaml", default=None)
    parser.add_argument("--workspace-root", help="override workspace.root", default=None)
    parser.add_argument("--log-level", default=None, help="DEBUG/INFO/WARNING/ERROR")
    parser.add_argument("--log-format", choices=["json", "text"], default=None)
    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser("run", help="process every ready task once")
    run.add_argument("--max-tasks", type=int, default=None)
    run.add_argument("--task-id", action="append", default=None)
    run.add_argument("--force", action="store_true", help="reprocess even if already done")
    run.add_argument("--retry-failed", action="store_true", help="requeue FAILED tasks")

    watch = sub.add_parser("watch", help="poll the inbox and process new tasks")
    watch.add_argument("--interval", type=float, default=DEFAULT_WATCH_INTERVAL_SECONDS)
    watch.add_argument("--max-iterations", type=int, default=None)
    watch.add_argument("--force", action="store_true")
    watch.add_argument("--retry-failed", action="store_true")

    task = sub.add_parser("task", help="process one task folder")
    task.add_argument("--task-id", required=True)
    task.add_argument("--force", action="store_true")

    status = sub.add_parser("status", help="show task status")
    status.add_argument("--task-id", default=None)

    registry = sub.add_parser("registry", help="inspect or reset the local registry")
    registry.add_argument("--stats", action="store_true")
    registry.add_argument("--reset-task", default=None, help="forget a task id")

    sub.add_parser("providers", help="show the configured LLM provider")

    selftest = sub.add_parser("selftest", help="run an end-to-end fake-batch self test")
    selftest.add_argument("--dir", default=None, help="workspace directory (default: temp)")
    selftest.add_argument("--events", type=int, default=180)
    selftest.add_argument("--keep", action="store_true", help="keep the temporary workspace")
    selftest.add_argument("--provider", default="mock", help="LLM provider for the self test")

    sample = sub.add_parser("sample-output", help="write the sample_output/ bundle")
    sample.add_argument("--out", default="sample_output")
    sample.add_argument("--events", type=int, default=200)

    sub.add_parser("validate-config", help="parse and validate config + knowledge base")
    return parser


# ---------------------------------------------------------------------- #
def _configure_logging(config: AppConfig, args: argparse.Namespace) -> None:
    configure_logging(
        level=args.log_level or config.logging.level,
        fmt=args.log_format or config.logging.format,
        log_file=config.logging.file,
        redact_keys=tuple(config.logging.redact_keys),
        static_fields={"environment": config.app.environment},
    )


def _load(args: argparse.Namespace) -> AppConfig:
    """Load the effective configuration for a workspace oriented command."""

    project_root = Path(args.workspace_root or Path.cwd()).resolve()
    config = load_config(
        args.config or default_config_path(),
        project_root=REPO_ROOT,
    )
    if args.workspace_root:
        config = _with_workspace(config, project_root)
    _configure_logging(config, args)
    return config


def _with_workspace(config: AppConfig, workspace_root: Path) -> AppConfig:
    """Point the shared workspace at ``workspace_root`` (keeps code paths intact)."""

    workspace = config.workspace.model_copy(update={"root": str(workspace_root)})
    status_dir = workspace_root / config.workspace.status_subdir
    persistence = config.persistence.model_copy(
        update={"sqlite_path": str(status_dir / "module2_state.db")}
    )
    return config.model_copy(update={"workspace": workspace, "persistence": persistence})


def _isolated_config(
    args: argparse.Namespace, workspace_root: Path, provider: str
) -> AppConfig:
    """Config for self tests: repo resources + a throwaway workspace."""

    config = load_config(
        args.config or default_config_path(),
        project_root=REPO_ROOT,
        env={
            "LLM_PROVIDER": provider,
            "MOCK_LLM_FIXTURE": "",
            "WORKSPACE_PATH": str(workspace_root),
            "SQLITE_PATH": str(workspace_root / "06_status" / "m2" / "module2_state.db"),
        },
    )
    _configure_logging(config, args)
    return config


def _print_json(payload: Any) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))


def _resolve_directory(value: str | None, *, prefix: str) -> Path:
    """Resolve (or create) a directory outside of the event loop."""

    path = Path(value).resolve() if value else Path(tempfile.mkdtemp(prefix=prefix))
    path.mkdir(parents=True, exist_ok=True)
    return path


def _summarise(outcomes: list[Any]) -> dict[str, Any]:
    return {
        "tasks": [
            {
                "task_id": outcome.task_id,
                "status": str(outcome.status),
                "attack_events": len(outcome.chain_ids),
                "alerts": len(outcome.alert_ids),
                "attackers": len(outcome.attacker_ids),
                "entities": outcome.entity_count,
                "candidates": outcome.candidate_count,
                "events": outcome.event_count,
                "severity": str(outcome.badge),
                "bundle": str(outcome.bundle_path) if outcome.bundle_path else None,
                "skipped_reason": outcome.skipped_reason,
                "errors": outcome.errors,
                "warnings": outcome.warnings[:5],
                "duration_ms": outcome.duration_ms,
            }
            for outcome in outcomes
        ],
        "processed": sum(1 for outcome in outcomes if str(outcome.status) == "completed"),
        "failed": sum(1 for outcome in outcomes if str(outcome.status) == "failed"),
    }


async def _run(args: argparse.Namespace) -> int:
    config = _load(args)
    ensure_workspace(config)
    pipeline = Module2Pipeline(config)
    with signal_cancellation() as token:
        try:
            outcomes = await pipeline.run_once(
                max_tasks=args.max_tasks,
                task_ids=args.task_id,
                force=args.force,
                retry_failed=args.retry_failed,
                token=token,
            )
        finally:
            await pipeline.aclose()
    _print_json(_summarise(outcomes))
    return 0 if all(str(outcome.status) != "failed" for outcome in outcomes) else 1


async def _watch(args: argparse.Namespace) -> int:
    config = _load(args)
    ensure_workspace(config)
    pipeline = Module2Pipeline(config)
    iterations = 0
    with signal_cancellation() as token:
        try:
            while not token.cancelled:
                outcomes = await pipeline.run_once(
                    force=args.force, retry_failed=args.retry_failed, token=token
                )
                if outcomes:
                    _print_json(_summarise(outcomes))
                iterations += 1
                if args.max_iterations and iterations >= args.max_iterations:
                    break
                if token.wait(args.interval):
                    break
        finally:
            await pipeline.aclose()
    return 0


async def _task(args: argparse.Namespace) -> int:
    config = _load(args)
    ensure_workspace(config)
    pipeline = Module2Pipeline(config)
    with signal_cancellation() as token:
        try:
            outcomes = await pipeline.run_once(
                task_ids=[args.task_id], force=args.force, token=token
            )
        finally:
            await pipeline.aclose()
    _print_json(_summarise(outcomes))
    return 0 if all(str(outcome.status) != "failed" for outcome in outcomes) else 1


def _status(args: argparse.Namespace) -> int:
    config = _load(args)
    store = TaskStatusStore(config)
    if args.task_id:
        record = store.load(args.task_id)
        _print_json(
            record.model_dump(mode="json")
            if record
            else {"task_id": args.task_id, "status": "unknown"}
        )
        return 0
    directory = config.status_dir
    records: list[dict[str, Any]] = []
    if directory.is_dir():
        for path in sorted(directory.glob("*.json")):
            record = store.load(path.stem)
            if record is None:
                continue
            records.append(
                {
                    "task_id": record.task_id,
                    "status": str(record.status),
                    "progress": record.progress,
                    "current_stage": record.current_stage,
                    "attack_events": record.attack_events,
                    "llm_calls": record.llm_calls,
                    "updated_at": record.updated_at.isoformat(),
                }
            )
    _print_json({"status_dir": str(directory), "tasks": records})
    return 0


def _registry(args: argparse.Namespace) -> int:
    config = _load(args)
    registry = ProcessedRegistry(config)
    try:
        if args.reset_task:
            registry.reset_task(args.reset_task)
        _print_json(registry.stats())
    finally:
        registry.close()
    return 0


def _providers(args: argparse.Namespace) -> int:
    config = _load(args)
    provider = create_llm_provider(config)
    _print_json(
        {
            "configured_provider": config.llm.provider,
            "supported_providers": list(SUPPORTED_PROVIDERS),
            "prompt_version": config.llm.prompt_version,
            "max_concurrency": config.llm.max_concurrency,
            "timeout_seconds": config.llm.timeout_seconds,
            "max_retries": config.llm.max_retries,
            "fail_open": config.llm.fail_open,
            "health": provider.health(),
        }
    )
    return 0


async def _selftest(args: argparse.Namespace) -> int:
    keep = bool(args.keep or args.dir)
    base_dir = _resolve_directory(args.dir, prefix="module2_selftest_")
    config = _isolated_config(args, base_dir / "workspace", args.provider)
    ensure_workspace(config)

    events = build_mixed_batch(task_id="task_selftest")[: args.events]
    write_batch(config.inbox_dir, events, task_id="task_selftest")
    logger.info(
        "synthetic batch written",
        extra={
            "task_id": "task_selftest",
            "stage": "selftest",
            "events": len(events),
            "inbox": str(config.inbox_dir),
        },
    )

    pipeline = Module2Pipeline(config)
    started = time.perf_counter()
    try:
        outcomes = await pipeline.run_once(max_tasks=1)
    finally:
        await pipeline.aclose()
        pipeline.registry.close()
    summary = _summarise(outcomes)
    summary["elapsed_seconds"] = round(time.perf_counter() - started, 3)
    summary["workspace"] = str(config.root_path)

    ok = bool(outcomes) and str(outcomes[0].status) == "completed"
    if ok and outcomes[0].bundle_path:
        done = outcomes[0].bundle_path / "DONE"
        summary["done_marker"] = done.is_file()
        ok = ok and done.is_file()
    _print_json(summary)
    if not keep:
        shutil.rmtree(base_dir, ignore_errors=True)
    return 0 if ok else 1


async def _sample_output(args: argparse.Namespace) -> int:
    out_dir = _resolve_directory(args.out, prefix="sample_output_")
    workspace_root = REPO_ROOT / f".{out_dir.name}_workspace"
    shutil.rmtree(workspace_root, ignore_errors=True)
    config = _isolated_config(args, workspace_root, "mock")
    ensure_workspace(config)
    events = build_mixed_batch(task_id="task_sample")[: args.events]
    write_batch(config.inbox_dir, events, task_id="task_sample")
    pipeline = Module2Pipeline(config)
    try:
        outcomes = await pipeline.run_once(max_tasks=1)
    finally:
        await pipeline.aclose()
        pipeline.registry.close()

    if not outcomes or outcomes[0].bundle_path is None:
        print("sample generation failed", file=sys.stderr)
        return 1
    shutil.rmtree(out_dir, ignore_errors=True)
    shutil.copytree(outcomes[0].bundle_path, out_dir)
    chains = json.loads((out_dir / "chains.json").read_text(encoding="utf-8"))
    alerts = json.loads((out_dir / "alerts.json").read_text(encoding="utf-8"))
    attackers = json.loads((out_dir / "attackers.json").read_text(encoding="utf-8"))
    report = json.loads((out_dir / "reports" / "report.json").read_text(encoding="utf-8"))

    # Flat convenience files for Module 3 front-end developers (spec §48).
    for name, payload in (
        ("attack_chain.json", chains[0] if chains else {}),
        ("alerts.json", alerts),
        ("attacker_profile.json", attackers[0] if attackers else {}),
        ("report.json", report),
    ):
        (out_dir / name).write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    shutil.rmtree(workspace_root, ignore_errors=True)
    _print_json(
        {
            "output": str(out_dir),
            "chains": len(chains),
            "alerts": len(alerts),
            "attackers": len(attackers),
            "entities": len(
                json.loads((out_dir / "entities.json").read_text(encoding="utf-8"))
            ),
            "report": "reports/report.json",
        }
    )
    return 0


def _validate_config(args: argparse.Namespace) -> int:
    reset_config_cache()
    try:
        config = get_config(args.config or default_config_path(), project_root=REPO_ROOT)
    except ConfigError as exc:
        print(f"invalid configuration: {exc}", file=sys.stderr)
        return 1
    try:
        kb = load_knowledge_base(config.attack_kb_path)
    except Exception as exc:
        print(f"invalid knowledge base: {exc}", file=sys.stderr)
        return 1
    _print_json(
        {
            "config_version": config.config_version,
            "project_root": str(config.root_path),
            "workspace": {
                "inbox": str(config.inbox_dir),
                "output": str(config.output_dir),
                "status": str(config.status_dir),
            },
            "correlation": {
                "window_seconds": config.correlation.correlation_window_seconds,
                "link_threshold": config.correlation.link_threshold,
            },
            "llm": {
                "provider": config.llm.provider,
                "model": config.llm.providers.deepseek.model,
                "timeout_seconds": config.llm.timeout_seconds,
                "max_concurrency": config.llm.max_concurrency,
            },
            "knowledge_base": knowledge_base_summary(kb),
            "sqlite": str(config.sqlite_path),
        }
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = args.command or "run"
    try:
        if command == "status":
            return _status(args)
        if command == "registry":
            return _registry(args)
        if command == "providers":
            return _providers(args)
        if command == "validate-config":
            return _validate_config(args)
        handlers = {
            "run": _run,
            "watch": _watch,
            "task": _task,
            "selftest": _selftest,
            "sample-output": _sample_output,
        }
        return asyncio.run(handlers[command](args))
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # pragma: no cover - interactive
        return 130


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
