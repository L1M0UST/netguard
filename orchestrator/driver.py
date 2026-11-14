"""整合流水线编排器（Orchestrator）。

职责：监视 M3 的 m3/READY/<task_id>/ 投递目录，串行驱动
  M1 降噪(m1.run) -> bridge 契约转换 -> M2 研判(backend.module2_chain.main)
  -> bundle 组装 -> 写 M3 消费目录 m2/READY/<task_id>/，
全程把 Status.v1 写到 m1/STATUS 与 m2/STATUS 供 M3 聚合进度。

模块本身无检测逻辑，只做进程编排、状态上报与原子投递。
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

M1_CONFIG_TEMPLATE = {
    # 演示配置：白名单降噪（TEST-NET-1 文档地址）；关键资产权重（M1 资产关键性加分演示）
    "whitelist_ips": ["192.0.2.100"], "whitelist_networks": [], "trusted_networks": [], "ioc_ips": [], "ioc_domains": [], "ioc_urls": [],
    "local_ioc": {"enabled": True},
    "session_window_seconds": 300, "max_session_duration_seconds": 3600,
    "scan_window_seconds": 60, "scan_min_sensitive_paths": 2,
    "source_activity_window_seconds": 300, "activity_window_seconds": 1800,
    "dedup_window_seconds": 60, "attack_campaign_window_seconds": 3600,
    "scan_min_unique_paths": 5, "suspicious_min_score": 45,
    "asset_ids": {"10.0.0.12": "asset-db-prod-01", "10.0.0.13": "asset-web-prod-01"},
    "asset_risk": {"asset-db-prod-01": 18, "asset-web-prod-01": 16},
    "shared_egress_ips": [],
    "schema_profile_sample_size": 200,
    "output": {"format": "parquet", "require_parquet": True, "batch_size": 1000, "batch_bytes": 8388608},
    "threatbook": {"enabled": False},
    "enable_l3_semantic_judge": True,
    "l3_max_ratio": 0.01,
    "llm": {
        "enabled": True,
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-flash",
        "api_key": "",           # 由 orchestrator 从 .env 注入
        "timeout_seconds": 120,
        "max_consecutive_failures": 5,
        # 云端可并发 8 路；本地 llama.cpp 另受 local_max_concurrency=4 限制。
        "max_concurrency": 8,
        "local_max_concurrency": 4,
        "cloud_enabled": True,
        # 默认双模型复核：本地垂域模型先判，云端模型对同一候选进行独立复核。
        # base_url 走环境变量 CQSEC_BASE_URL（llm/cqsec 客户端统一读取）。
        "cascade": {"enabled": True, "model": "cqsec", "mode": "review", "escalate_below": 0.5},
    },
}

SEVERITY_STOP = object()


def log(message: str) -> None:
    line = f"[{datetime.now().isoformat(timespec='seconds')}] {message}"
    print(line, flush=True)
    try:
        log_file = PROJECT_ROOT / "logs" / "orchestrator.log"
        log_file.parent.mkdir(exist_ok=True)
        with log_file.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")
    except OSError:
        pass


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_status(workspace: Path, module: str, task_id: str, state: str,
                 progress: int, message: str, detail: dict | None = None) -> None:
    """写 M3 契约的 Status.v1 到 <ws>/<module>/STATUS/<task>/status.json（原子）。

    detail 携带实时计数（如 processed_records/llm_done），随 module_statuses 透传到前端。
    """
    directory = workspace / module / "STATUS" / task_id
    directory.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "Status.v1",
        "task_id": task_id,
        "state": state,
        "progress": max(0, min(100, int(progress))),
        "message": message[:300],
        "updated_at": now_iso(),
    }
    if detail:
        payload["detail"] = detail
    tmp = directory / f"status.json.{uuid.uuid4().hex}.tmp"
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    # Windows 上 M3 会并发读取 status.json，os.replace 撞上读句柄会报 WinError 5；
    # 读方毫秒级关闭，短重试即可收敛。
    for attempt in range(6):
        try:
            os.replace(tmp, directory / "status.json")
            break
        except PermissionError:
            if attempt == 5:
                # 状态上报失败绝不让任务失败：仅记录日志并清理临时文件
                try:
                    tmp.unlink(missing_ok=True)
                except OSError:
                    pass
                log(f"状态上报失败（不影响任务）：{module}/{task_id}")
                return
            time.sleep(0.3 * (attempt + 1))


M2_STAGE_ZH = {
    "validation": "输入契约校验", "ingestion": "数据读取", "deduplication": "告警去重",
    "normalization": "字段归一化", "correlation": "攻击链关联（加权评分+并查集）",
    "technique_mapping": "ATT&CK 技术映射", "llm_analysis": "模型研判（Top-N 候选）",
    "evidence_validation": "反幻觉证据校验", "event_deduplication": "攻击事件指纹去重",
    "profiling": "攻击者画像提取", "entity_extraction": "威胁要素提取",
    "risk_scoring": "风险评分", "reporting": "风险报告生成", "bundle_write": "结果打包",
}


def _run_with_mirror(cmd: list[str], env: dict[str, str], workspace: Path, module: str,
                     task_id: str, budget: int, timeout: int = 7200) -> subprocess.CompletedProcess:
    """带实时状态镜像的子进程执行：轮询模块自己的状态文件，翻译成中文进度写回 M3 Status.v1。"""
    log(f"EXEC {' '.join(str(part) for part in cmd)}")
    process = subprocess.Popen([str(part) for part in cmd], cwd=str(PROJECT_ROOT), env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, encoding="utf-8", errors="replace")
    # 并发排空管道：轮询期间若不读 stdout/stderr，子进程日志一旦写满 ~64KB 管道缓冲
    # 就会永久阻塞（万级任务必现），必须由独立线程持续读走。
    stdout_buf: list[str] = []
    stderr_buf: list[str] = []

    def _drain(stream, buf: list[str]) -> None:
        try:
            for line in iter(stream.readline, ''):
                buf.append(line)
        except (OSError, ValueError):
            pass
        finally:
            try:
                stream.close()
            except (OSError, ValueError):
                pass

    drain_out = threading.Thread(target=_drain, args=(process.stdout, stdout_buf), daemon=True)
    drain_err = threading.Thread(target=_drain, args=(process.stderr, stderr_buf), daemon=True)
    drain_out.start()
    drain_err.start()
    last_message = {"m1": ("M1 解析与降噪分析中", 5), "m2": ("M2 关联研判中", 30)}[module]
    try:
        while process.poll() is None:
            write_status(workspace, module, task_id, "RUNNING", last_message[1], last_message[0])
            update = _read_module_progress(workspace, module, task_id, budget)
            if update:
                message, progress, detail = update
                write_status(workspace, module, task_id, "RUNNING", progress, message, detail)
                last_message = (message, progress)
            time.sleep(2)
        process.wait(timeout=60)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=30)
    finally:
        drain_out.join(timeout=5)
        drain_err.join(timeout=5)
    return subprocess.CompletedProcess(cmd, process.returncode or 0,
                                       ''.join(stdout_buf), ''.join(stderr_buf))


def _read_module_progress(workspace: Path, module: str, task_id: str, budget: int):
    """读取 M1/M2 自己写的状态文件，翻译为 (中文消息, 进度, detail)。无更新返回 None。"""
    if module == "m1":
        running_dir = workspace / "m1" / "running"
        files = sorted(running_dir.glob("*.status.json"), key=lambda p: p.stat().st_mtime) if running_dir.is_dir() else []
        if not files:
            return None
        try:
            data = json.loads(files[-1].read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        phase = data.get("phase")
        if phase == "l3_judge":
            done, total = int(data.get("l3_done", 0)), max(1, int(data.get("l3_total", 1)))
            detail = {"l3_done": done, "l3_total": total,
                      "local_hits": data.get("cascade_local_hits", 0), "escalations": data.get("escalations", 0)}
            return (f"模型语义研判中（{done}/{total}，本地判决 {detail['local_hits']}）",
                    60 + int(35 * done / total), detail)
        if data.get("processed_records"):
            processed = int(data["processed_records"])
            accepted = int(data.get("accepted_records", 0))
            dedup = int(data.get("filtered_duplicate", 0))
            total = data.get("total_records")
            creep = 5 + int(50 * (1 - 2.718281828 ** (-processed / 3000)))
            label = f"数据解析与降噪中（已处理 {processed}" + (f"/{total}" if total else "") + f" 条，降噪后 {accepted}，去重 {dedup}）"
            return (label, creep, {"processed": processed, "total": int(total) if total else None,
                                   "accepted": accepted, "duplicates": dedup})
        return None
    # M2：自己的任务状态 JSON（pipeline 每阶段更新）
    status_file = workspace / "06_status" / "m2" / f"task_{task_id}.json"
    if not status_file.is_file():
        return None
    try:
        data = json.loads(status_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    stage = str(data.get("current_stage") or "")
    zh = M2_STAGE_ZH.get(stage, stage)
    progress = int(float(data.get("progress") or 0))
    if stage == "llm_analysis":
        done = int(data.get("llm_calls") or 0)
        detail = {"llm_done": done, "llm_total": budget,
                  "candidates": data.get("attack_candidates")}
        return (f"模型研判中（{min(done, budget)}/{budget} 候选）", 30 + int(55 * min(done, budget) / max(1, budget)), detail)
    if stage == "correlation":
        return (f"攻击链关联中（{data.get('attack_candidates', 0)} 候选）", 32,
                {"candidates": data.get("attack_candidates")})
    if zh and progress:
        return (f"{zh}（M2 引擎）", min(95, max(31, progress)), {"stage": stage})
    return None


def _load_env(env_path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if env_path.is_file():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def ensure_m1_config(workspace: Path, env: dict[str, str], analysis_mode: str = "hybrid") -> Path:
    """生成 <ws>/m1/config.json：按任务策略配置本地、云端或双模型复核。

    DEEPSEEK_ENABLED=0（如余额耗尽）时关闭 M1 的 LLM 语义研判，管线以纯规则降级运行。
    """
    config = json.loads(json.dumps(M1_CONFIG_TEMPLATE))
    if analysis_mode not in {"local", "cloud", "hybrid"}:
        analysis_mode = "hybrid"
    provider_specs = [
        # Go, unlike the Zen free route, is available to a subscribed API key.
        ("opencode_go", "OPENCODE_API_KEY", "OPENCODE_GO_BASE_URL", "OPENCODE_GO_MODEL", "https://opencode.ai/zen/go/v1", "glm-5.3-flash", True),
        ("commandcode", "COMMANDCODE_API_KEY", "COMMANDCODE_BASE_URL", "COMMANDCODE_MODEL", "https://api.commandcode.ai/provider/v1", "z-ai/glm-5.3-flash", False),
        ("deepseek", "DEEPSEEK_API_KEY", "DEEPSEEK_BASE_URL", "DEEPSEEK_MODEL", "https://api.deepseek.com/v1", "deepseek-flash", False),
    ]
    providers = []
    for name, key_name, base_name, model_name, default_base, default_model, requires_session in provider_specs:
        key = env.get(key_name, "").strip()
        if not key or (name == "deepseek" and env.get("DEEPSEEK_ENABLED", "1") != "1"):
            continue
        providers.append({"name": name, "api_key": key, "base_url": (env.get(base_name) or default_base).rstrip("/"),
                          "model": env.get(model_name) or default_model, "requires_session": requires_session,
                          "user_agent": "NetGuard-Security-Research/1.0"})
    if providers:
        config["llm"].update({"providers": providers, "api_key": providers[0]["api_key"],
                              "base_url": providers[0]["base_url"], "model": providers[0]["model"]})
    else:
        config["llm"].update({"providers": [], "api_key": ""})
    cloud_available = bool(providers)
    config["llm"]["cloud_enabled"] = analysis_mode in {"cloud", "hybrid"} and cloud_available
    config["llm"]["enabled"] = config["llm"]["cloud_enabled"]
    cascade = config["llm"]["cascade"]
    cascade["enabled"] = analysis_mode in {"local", "hybrid"}
    cascade["mode"] = "local_only" if analysis_mode == "local" else "review" if analysis_mode == "hybrid" else "off"
    config["llm"]["analysis_mode"] = analysis_mode
    config_path = workspace / "m1" / "config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    return config_path


def _llm_budget() -> int:
    """从 config.yaml 读 M2 的 LLM 候选预算（缺省 60）。"""
    try:
        import yaml
        config = yaml.safe_load((PROJECT_ROOT / "config.yaml").read_text(encoding="utf-8"))
        return int((config.get("llm") or {}).get("max_candidates") or 60)
    except (OSError, ValueError, TypeError):
        return 60


def _run(cmd: list[str], env: dict[str, str], timeout: int = 7200) -> subprocess.CompletedProcess:
    log(f"EXEC {' '.join(str(part) for part in cmd)}")
    return subprocess.run([str(part) for part in cmd], cwd=str(PROJECT_ROOT), env=env,
                          capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout)


def find_m1_ready_dir(workspace: Path, task_id: str) -> Path | None:
    ready_root = workspace / "m1" / "ready" / f"batch-{task_id}"
    if not ready_root.is_dir():
        return None
    runs = sorted((p for p in ready_root.iterdir() if p.is_dir()),
                  key=lambda p: p.stat().st_mtime, reverse=True)
    return runs[0] if runs else None


def process_task(workspace: Path, task_id: str, env: dict[str, str], python_exe: str) -> dict:
    """处理一个 M3 投递任务的全流程。异常向上抛，由调用方统一标 FAILED。"""
    pipeline_started = time.monotonic()
    task_dir = workspace / "m3" / "READY" / task_id
    manifest = json.loads((task_dir / "manifest.json").read_text(encoding="utf-8"))
    sources = manifest.get("source_files") or []
    analysis_mode = str(manifest.get("analysis_mode") or "hybrid")
    if analysis_mode not in {"local", "cloud", "hybrid"}:
        analysis_mode = "hybrid"
    if not sources:
        raise ValueError("m3/READY 任务清单没有 source_files")

    # 0. 前置：M1 配置 + IOC 情报导出（失败不阻塞，M2 有占位数据兜底）
    ensure_m1_config(workspace, env, analysis_mode)
    log(f"M1 模型策略：{analysis_mode}")
    try:
        from bridge.export_intel import export_intel
        intel_stats = export_intel(workspace, PROJECT_ROOT / "data" / "threat_intel")
        log(f"情报导出: {json.dumps(intel_stats, ensure_ascii=False)}")
    except Exception as exc:  # noqa: BLE001
        log(f"情报导出跳过: {exc}")

    # 1. 把 M3 的无扩展名副本复制回 M1 的 incoming/（恢复原始文件名）
    incoming = workspace / "incoming"
    incoming.mkdir(parents=True, exist_ok=True)
    staged_names: list[str] = []
    for source in sources:
        source_name = source.get("filename") or f"{source['file_id']}.xlsx"
        target = incoming / source_name
        if target.exists():
            target = incoming / f"{task_id[:8]}-{source_name}"
        shutil.copyfile(task_dir / source["path"], target)
        staged_names.append(target.name)
        log(f"已投递输入文件 {target.name} ({source.get('size')} bytes)")

    # 2. M1：写任务 manifest 并调用 m1.run
    m1_task_id = task_id  # 直接用 M3 task_id，保证 batch-<task_id> 可定位
    m1_manifest_dir = workspace / "m1" / "manifests"
    m1_manifest_dir.mkdir(parents=True, exist_ok=True)
    m1_manifest = m1_manifest_dir / f"task-{task_id}.json"
    m1_manifest.write_text(json.dumps({
        "schema_version": "2.0", "task_id": m1_task_id,
        "input_files": [f"incoming/{name}" for name in staged_names],
        "options": {},
    }, ensure_ascii=False), encoding="utf-8")

    write_status(workspace, "m1", task_id, "RUNNING", 5, "M1 解析与降噪分析中")
    llm_budget = _llm_budget()
    result = _run_with_mirror([python_exe, "-m", "m1.run", "--workspace", str(workspace),
                               "--manifest", str(m1_manifest)], env, workspace, "m1", task_id, llm_budget)
    if result.returncode != 0:
        raise RuntimeError(f"M1 失败: {(result.stderr or result.stdout)[-800:]}")
    m1_ready_dir = find_m1_ready_dir(workspace, task_id)
    if m1_ready_dir is None:
        raise RuntimeError("M1 完成但找不到 ready 目录")
    batch_json = m1_ready_dir / "batch.json"
    m1_status = json.loads(batch_json.read_text(encoding="utf-8")).get("status", {})
    metrics = m1_status.get("metrics", {})
    m1_duration_seconds = time.monotonic() - pipeline_started
    log(f"M1 完成: {json.dumps(metrics, ensure_ascii=False)}")
    write_status(workspace, "m1", task_id, "COMPLETED", 100,
                 f"M1 完成：可疑会话 {metrics.get('suspicious_sessions', '?')}；信息级观察 {metrics.get('informational_sessions', 0)}",
                 {"session_risk_counts": metrics.get("session_risk_counts", {}),
                  "informational_sessions": metrics.get("informational_sessions", 0)})

    # 3. bridge：会话 -> 事件级契约 + evidence 索引
    #    M2 扫描器只认 task_ 前缀目录，且校验 manifest.task_id 与目录名一致，
    #    故 M2 侧任务名用 task_<hex>，bundle 组装时再映射回 M3 的 hex id。
    m2_task_id = f"task_{task_id}"
    write_status(workspace, "m2", task_id, "RUNNING", 10, "契约转换（会话展开+标签映射）")
    bridge_started = time.monotonic()
    from bridge.export_m2_batch import export_batch
    bridge_dir = workspace / "bridge" / task_id
    bridge_stats = export_batch(m1_ready_dir, workspace / "04_m2_inbox" / m2_task_id, m2_task_id,
                                evidence_out=bridge_dir / "evidence.parquet")
    bridge_duration_seconds = time.monotonic() - bridge_started
    log(f"bridge 完成: {json.dumps(bridge_stats, ensure_ascii=False)}")

    # 4. M2：关联研判（DeepSeek）
    write_status(workspace, "m2", task_id, "RUNNING", 30, "M2 关联研判中（ATT&CK+LLM）")
    m2_process_started = time.monotonic()
    # M2 uses the same audited cloud fallback chain as M1.  Do not remap one
    # arbitrary key into DEEPSEEK_*: that used to make the first failed vendor
    # bypass Command Code and DeepSeek entirely.
    m2_env = dict(env)
    cloud_names = []
    if env.get("OPENCODE_API_KEY"):
        cloud_names.append("OpenCode Go")
    if env.get("COMMANDCODE_API_KEY"):
        cloud_names.append("Command Code")
    if env.get("DEEPSEEK_API_KEY") and env.get("DEEPSEEK_ENABLED", "1") == "1":
        cloud_names.append("DeepSeek")
    if analysis_mode == "local":
        # A local-only acceptance run must not silently invoke a cloud model in M2.
        # M2 remains deterministic/evidence-based until a local M2 provider exists.
        m2_env["LLM_PROVIDER"] = "disabled"
        log("M2 本地模式：云端模型关闭，使用确定性关联与证据评分")
    elif cloud_names:
        m2_env["LLM_PROVIDER"] = "cloud_chain"
        log("M2 云端模型回退链：" + " → ".join(cloud_names))
    else:
        m2_env["LLM_PROVIDER"] = "disabled"
        log("M2 未配置云端模型：以规则引擎降级运行")
    result = _run_with_mirror([python_exe, "-m", "backend.module2_chain.main", "--config", "config.yaml",
                               "--workspace-root", str(workspace), "run"],
                              m2_env, workspace, "m2", task_id, llm_budget)
    log(f"M2 stdout 尾部: {(result.stdout or '')[-500:]}")
    if result.returncode != 0:
        raise RuntimeError(f"M2 失败: {(result.stderr or result.stdout)[-800:]}")
    m2_process_duration_seconds = time.monotonic() - m2_process_started
    m2_output = workspace / "05_m2_output" / m2_task_id
    if not (m2_output / "manifest.json").exists():
        raise RuntimeError(f"M2 完成但缺少输出包: {m2_output}")
    write_status(workspace, "m2", task_id, "RUNNING", 85, "M2 完成，组装结果包")

    # 5+6. bundle 组装；运营总结用"装配回调"基于加权后的真实分布生成（cqsec 本地模型，无云端额度）
    summarize = None
    if env.get("CQSEC_OPS_SUMMARY", "1") == "1":
        def summarize(sev_counts, events, chains, multistage, metrics, statistics):  # noqa: ANN001
            from llm.cqsec import build_ops_stats_text, ops_summary
            txt = build_ops_stats_text(sev_counts, events, chains, multistage, metrics, statistics)
            log("运营总结输入统计已按加权后真实分布生成")
            return ops_summary(txt)
    from bundle.assemble import assemble
    bundle_started = time.monotonic()
    bundle_stats = assemble(task_id, m2_output, bridge_dir / "evidence.parquet",
                            workspace / "m2" / "READY" / task_id,
                            m1_batch_json=batch_json, report_summary=None, summarize=summarize)
    bundle_duration_seconds = time.monotonic() - bundle_started
    # M2 自带的 duration_seconds 只覆盖其内部阶段。对外统一展示 M1+桥接+M2+结果装配
    # 的端到端时长，避免用户把单模块时长误当成整次分析耗时。
    total_duration_seconds = round(time.monotonic() - pipeline_started, 3)
    result_dir = workspace / "m2" / "READY" / task_id
    bundle_path = result_dir / "bundle.json"
    result_manifest_path = result_dir / "manifest.json"
    bundle_payload = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle_metrics = bundle_payload.setdefault("metrics", {})
    bundle_metrics["duration_seconds"] = total_duration_seconds
    bundle_metrics["m1_duration_seconds"] = round(m1_duration_seconds, 3)
    bundle_metrics["m2_duration_seconds"] = round(max(0.0, total_duration_seconds - m1_duration_seconds), 3)
    bundle_metrics["bridge_duration_seconds"] = round(bridge_duration_seconds, 3)
    bundle_metrics["m2_process_duration_seconds"] = round(m2_process_duration_seconds, 3)
    bundle_metrics["bundle_assembly_duration_seconds"] = round(bundle_duration_seconds, 3)
    bundle_metrics["orchestrator_overhead_seconds"] = round(max(
        0.0, total_duration_seconds - m1_duration_seconds - bridge_duration_seconds
        - m2_process_duration_seconds - bundle_duration_seconds), 3)
    bundle_metrics["duration_scope"] = "m1_m2_end_to_end"
    temp_bundle = bundle_path.with_suffix(".json.tmp")
    temp_bundle.write_text(json.dumps(bundle_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temp_bundle, bundle_path)
    result_manifest = json.loads(result_manifest_path.read_text(encoding="utf-8"))
    result_manifest["sha256"] = __import__("hashlib").sha256(bundle_path.read_bytes()).hexdigest()
    temp_manifest = result_manifest_path.with_suffix(".json.tmp")
    temp_manifest.write_text(json.dumps(result_manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temp_manifest, result_manifest_path)
    log(f"bundle 完成: {json.dumps({k: bundle_stats[k] for k in ('chains','alerts','severity_counts','multistage_chains') if k in bundle_stats}, ensure_ascii=False)}")
    write_status(workspace, "m2", task_id, "COMPLETED", 100,
                 f"M2 完成：攻击链 {bundle_stats['chains']} 条")
    return {"m1": metrics, "bridge": bridge_stats, "bundle": bundle_stats,
            "timings": {"m1_seconds": round(m1_duration_seconds, 3),
                        "bridge_seconds": round(bridge_duration_seconds, 3),
                        "m2_process_seconds": round(m2_process_duration_seconds, 3),
                        "bundle_assembly_seconds": round(bundle_duration_seconds, 3),
                        "orchestrator_overhead_seconds": bundle_metrics["orchestrator_overhead_seconds"],
                        "end_to_end_seconds": total_duration_seconds}}


def handle_task(workspace: Path, task_id: str, env: dict[str, str], python_exe: str) -> bool:
    marker_dir = workspace / "orchestrator"
    marker_dir.mkdir(parents=True, exist_ok=True)
    if (marker_dir / f"{task_id}.done").exists() or (marker_dir / f"{task_id}.running").exists():
        return False
    (marker_dir / f"{task_id}.running").write_text(now_iso(), encoding="utf-8")
    log(f"==== 开始处理任务 {task_id} ====")
    try:
        stats = process_task(workspace, task_id, env, python_exe)
        (marker_dir / f"{task_id}.done").write_text(json.dumps(stats, ensure_ascii=False), encoding="utf-8")
        log(f"==== 任务 {task_id} 成功 ====")
        return True
    except Exception as exc:  # noqa: BLE001
        error_text = f"{type(exc).__name__}: {exc}"
        log(f"任务 {task_id} 失败: {error_text}\n{traceback.format_exc()[-1500:]}")
        write_status(workspace, "m1", task_id, "FAILED", 100, f"失败: {error_text}")
        write_status(workspace, "m2", task_id, "FAILED", 100, f"失败: {error_text}")
        (marker_dir / f"{task_id}.failed").write_text(error_text, encoding="utf-8")
        return False
    finally:
        (marker_dir / f"{task_id}.running").unlink(missing_ok=True)


def watch(workspace: Path, env: dict[str, str], python_exe: str, interval: float = 3.0) -> None:
    log(f"orchestrator watch 启动，workspace={workspace}")
    while True:
        try:
            ready_root = workspace / "m3" / "READY"
            if ready_root.is_dir():
                for task_dir in sorted(ready_root.iterdir()):
                    if task_dir.is_dir() and (task_dir / "manifest.json").is_file():
                        handle_task(workspace, task_dir.name, env, python_exe)
        except Exception as exc:  # noqa: BLE001
            log(f"watch 循环异常: {exc}")
        time.sleep(interval)


def run_file(workspace: Path, file_path: Path, env: dict[str, str], python_exe: str,
             query: str = "", analysis_mode: str = "hybrid") -> str:
    """测试入口：不走 M3 上传，直接投递一个 m3/READY 任务并同步处理。返回 task_id。"""
    file_path = Path(file_path)
    if not file_path.is_file():
        raise FileNotFoundError(file_path)
    import hashlib
    task_id = uuid.uuid4().hex
    data = file_path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    file_id = digest[:32]
    task_dir = workspace / "m3" / "STAGING" / task_id
    task_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(file_path, task_dir / file_id)
    (task_dir / "manifest.json").write_text(json.dumps({
        "schema_version": "TaskManifest.v1", "task_id": task_id,
        "created_at": now_iso(),
        "source_files": [{"file_id": file_id, "filename": file_path.name,
                          "size": len(data), "sha256": digest, "path": file_id}],
        "user_prompt": query, "analysis_mode": analysis_mode, "versions": {},
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    target = workspace / "m3" / "READY" / task_id
    target.parent.mkdir(parents=True, exist_ok=True)
    os.replace(task_dir, target)
    handle_task(workspace, task_id, env, python_exe)
    return task_id


def main() -> int:
    parser = argparse.ArgumentParser(description="taishi_platform 流水线编排器")
    parser.add_argument("command", choices=["watch", "run-file", "run-task", "status"])
    parser.add_argument("--workspace", default=str(PROJECT_ROOT / "workspace"))
    parser.add_argument("--file", default=None, help="run-file: 输入文件路径")
    parser.add_argument("--task-id", default=None, help="run-task: 已投递任务ID")
    parser.add_argument("--interval", type=float, default=3.0)
    parser.add_argument("--analysis-mode", choices=("local", "cloud", "hybrid"), default="hybrid",
                        help="run-file: 选择本地、云端或本地+云端复核策略")
    args = parser.parse_args()

    workspace = Path(args.workspace).resolve()
    for sub in ("incoming", "m1", "04_m2_inbox", "05_m2_output", "06_status", "m2", "m3", "bridge", "orchestrator"):
        (workspace / sub).mkdir(parents=True, exist_ok=True)

    env = {**os.environ, **_load_env(PROJECT_ROOT / ".env")}
    if env.get("DEEPSEEK_ENABLED", "1") != "1" and not (env.get("OPENCODE_API_KEY") or env.get("COMMANDCODE_API_KEY")):
        # 仅当 DeepSeek 是唯一云端提供方且不可用时，M2 才切换到规则引擎。
        env["LLM_PROVIDER"] = "disabled"
        log("未配置可用的备用模型提供方：以纯规则降级模式运行")
    python_exe = sys.executable

    if args.command == "watch":
        watch(workspace, env, python_exe, args.interval)
    elif args.command == "run-file":
        if not args.file:
            parser.error("run-file 需要 --file")
        task_id = run_file(workspace, Path(args.file), env, python_exe,
                           analysis_mode=args.analysis_mode)
        print(json.dumps({"task_id": task_id}, ensure_ascii=False))
    elif args.command == "run-task":
        if not args.task_id:
            parser.error("run-task 需要 --task-id")
        handle_task(workspace, args.task_id, env, python_exe)
    elif args.command == "status":
        for marker in sorted((workspace / "orchestrator").glob("*.*")):
            print(marker.name, "->", marker.read_text(encoding="utf-8")[:200])
    return 0


if __name__ == "__main__":
    threading.excepthook = lambda args: log(f"线程异常: {args.exc}")
    raise SystemExit(main())
