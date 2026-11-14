"""M2 输出目录(chains/alerts/attackers/report/metrics) -> M3 AttackChainBundle.v1 组装器。

M3 的 Bundle 校验器（m3/workspace_io.py）要求：
- evidence[].event_id 唯一且非空；chains[].stages[].evidence_event_ids ⊆ evidence；
- alerts[].event_ids 非空且 ⊆ evidence；profiles[].evidence_refs 非空且 ⊆ evidence；
- report.recommended_actions[].source ∈ 固定枚举；versions 五键非空。
任一不满足整包拒绝 → M3 任务 failed。本组装器在写出前先用 M3 的 Bundle 模型自校验，
并原子投递（tmp → rename）到 workspace/m2/READY/<task_id>/。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import uuid
from collections import Counter
from pathlib import Path

from bridge.labels import severity_for

PROJECT_ROOT = Path(__file__).resolve().parents[1]

RECOMMENDATION_SOURCE_MAP = {
    "evidence_based": "rule_based",       # 基于已观测证据的处置（来自规则/技术命中）
    "general_recommendation": "knowledge_base",  # 处置知识库通用建议
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _blend_severity(m2_severity: str | None, m1_risk_level: str | None) -> str:
    """以可解释的 M2 综合风险等级为最终口径，M1 仅在 M2 缺失时兜底。

    旧实现简单取两者较高值，导致综合风险分 20～39（低危）的链被 M1 初筛
    全部抬成中/高危，页面与置信度卡片互相矛盾。M1 信号仍以 signal_severity
    单独保留，既不丢失规则强信号，也不污染最终风险等级分布。
    """
    raw = str(m2_severity or "").lower()
    if raw in SEVERITY_ORDER:
        return raw
    return severity_for(m1_risk_level)


def _load_json(path: Path, default):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _clamp01(value) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.5
    return min(1.0, max(0.0, number if number <= 1.0 else number / 100.0))


def _dominant_label(events: list[dict], event_ids: list[str]) -> str | None:
    labels = [events[eid]["attack_type"] for eid in event_ids
              if eid in events and events[eid].get("attack_type")]
    if not labels:
        return None
    return Counter(labels).most_common(1)[0][0]


def _m1_level_for(events: list[dict], event_ids: list[str]) -> str | None:
    """成员事件里最能代表威胁强度的一档（取最高分，非众数）。

    M1 的 risk_level 只用 >=75 high / >=45 medium 两档，会抹平 12 种规则分差异
    （命令注入 90、SQL 注入 85、XSS 65…全塌成 high/medium），导致危险等级占比只剩两档。
    这里按 M1 真实 risk_score 数值重建五档：>=90 critical、>=75 high、>=55 medium、
    >=45 low。无 risk_score 的旧数据回退到 risk_level。取最高分而非众数：一条链含 RCE
    事件就应按最危险成员定级。
    """
    scores = [events[eid].get("risk_score") for eid in event_ids
              if eid in events and isinstance(events[eid].get("risk_score"), (int, float))]
    if scores:
        score = max(scores)
        if score >= 90: return "critical"
        if score >= 75: return "high"
        if score >= 55: return "medium"
        if score >= 45: return "low"
        return None
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    levels = [events[eid].get("risk_level") for eid in event_ids
              if eid in events and events[eid].get("risk_level") in order]
    if not levels:
        return None
    return sorted(levels, key=lambda level: order[level])[0]


SEVERITY_ZH = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "提示"}


def _zh_title_and_desc(alert: dict, refs: list, label: str | None,
                       chain: dict | None, severity: str) -> tuple[str, str]:
    """中文告警标题与描述（展示层翻译：基于确定性标签/等级/方向构造，不虚构结论）。"""
    attacker = "、".join((alert.get("attacker_ips") or [])[:1]) or "未知来源"
    victim = "、".join((alert.get("victim_ips") or [])[:1])
    direction = f"{attacker} → {victim}" if victim else attacker
    technique = (alert.get("mitre_techniques") or [None])[0] or ((chain or {}).get("stages") or [{}])[0].get("technique")
    if label and label != "待研判":
        title = f"疑似{label}：{direction}"
    elif technique:
        title = f"可疑行为（{technique}）：{direction}"
    else:
        title = f"可疑行为（{SEVERITY_ZH.get(severity, severity)}）：{direction}"
    stage_count = len((chain or {}).get("stages") or [])
    desc = (f"经规则引擎与模型研判判定为「{label or '待研判'}」，风险等级 {SEVERITY_ZH.get(severity, severity)}；"
            f"关联攻击链 {stage_count} 个阶段，证据 {len(refs)} 条。")
    if label and label != "待研判":
        desc += f"主要类型为{label}，建议核实攻击来源并参考处置建议。"
    return title, desc


def _confidence_summary(risk: dict, validation: dict, penalties: list[dict],
                        llm_checked: bool = True) -> str:
    """置信度卡片的一句话总述：分数、依据强度、反幻觉结论。"""
    score = risk.get("score")
    parts = [f"综合风险分 {score}/100" if score is not None else "风险分未知"]
    if llm_checked:
        parts.append(f"LLM 结论反幻觉校验{'通过' if validation.get('valid') else '存在问题'}"
                     f"（有效证据 {validation.get('valid_evidence_count', '?')} 条）")
    else:
        parts.append("规则引擎产出，阶段证据引用已通过闭合校验")
    if validation.get("hallucination_detected"):
        parts.append("检测到模型幻觉，已扣减置信度")
    if penalties:
        parts.append(f"共 {len(penalties)} 项惩罚/提示")
    return "；".join(parts)


def _default_summary(sev_counts: dict, events: int, chains: int, multistage: int,
                     metrics: dict) -> str:
    """确定性运营总结（无 LLM 时兜底；数字全部来自加权后的真实分布）。"""
    sus = metrics.get("suspicious_count") or metrics.get("m2_events") or "—"
    raw = metrics.get("raw_count", "—")
    crit, high = sev_counts.get("critical", 0), sev_counts.get("high", 0)
    med, low = sev_counts.get("medium", 0), sev_counts.get("low", 0)
    tier = [f"{n} {c} 条" for n, c in (("严重", crit), ("高危", high), ("中危", med), ("低危", low)) if c]
    chain_note = (f"关联为 {chains} 条攻击链（其中 {multistage} 条为跨多战术的多阶段链）"
                  if multistage else f"关联为 {chains} 条攻击链（本批多为单事件独立成链，链数接近事件数属正常）")
    top = crit + high
    if top:
        prio = f"优先封禁高危及以上（合计 {top} 条）告警涉及的攻击源，并对失陷主机排查持久化与外联。"
        concl = "整体风险偏高，需尽快处置。"
    else:
        prio = "以中低危为主，建议持续监控并完善访问基线。"
        concl = "整体风险可控，保持监测即可。"
    return (f"【总体态势】本批次接入原始告警 {raw} 条，识别可疑事件 {sus} 条，"
            f"经降噪与研判确认攻击事件 {events} 条，{chain_note}。"
            f"【风险分级】{'、'.join(tier) if tier else '无'}。"
            f"【处置优先级】{prio}【结论】{concl}")


def assemble(task_id: str, m2_output: Path, evidence_path: Path, out_dir: Path,
             m1_batch_json: Path | None = None, report_summary: str | None = None,
             extra_metrics: dict | None = None,
             summarize=None) -> dict:
    m2_output, out_dir = Path(m2_output), Path(out_dir)
    # 证据索引：Parquet（首选，防杀毒隔离）或旧版 JSON（兼容历史产物）
    events: dict[str, dict] = {}
    labels: dict = {}
    if Path(evidence_path).with_suffix(".parquet").is_file():
        import pyarrow.parquet as pq
        rows = pq.read_table(Path(evidence_path).with_suffix(".parquet")).to_pylist()
        events = {row["event_id"]: row for row in rows if row.get("event_id")}
        labels_path = Path(evidence_path).parent / "labels.json"
        if labels_path.is_file():
            labels = _load_json(labels_path, {}) or {}
    else:
        evidence_doc = _load_json(evidence_path, {}) or {}
        events = {row["event_id"]: row for row in evidence_doc.get("events", []) if row.get("event_id")}

    chains_raw = _load_json(m2_output / "chains.json", [])
    alerts_raw = _load_json(m2_output / "alerts.json", [])
    profiles_raw = _load_json(m2_output / "attackers.json", [])
    report_raw = _load_json(m2_output / "reports" / "report.json", {}) or {}
    metrics_raw = _load_json(m2_output / "metrics.json", {}) or {}
    m1_status = {}
    if m1_batch_json:
        m1_status = (_load_json(m1_batch_json, {}) or {}).get("status", {}) or {}

    # ---- evidence ----
    evidence = []
    for eid, row in events.items():
        evidence.append({
            "event_id": eid,
            "summary": row.get("summary") or eid,
            "timestamp": row.get("timestamp"),
            "src_ip": row.get("src_ip"),
            "dst_ip": row.get("dst_ip"),
            "url_path": row.get("url_path"),
            "attack_type": row.get("attack_type"),
            "risk_level": row.get("risk_level"),
            "risk_score": row.get("risk_score"),
            "session_id": row.get("session_id"),
            "matched_rules": row.get("matched_rules") or [],
            "ioc_hits": row.get("ioc_hits") or [],
        })
    known_ids = set(events)

    # ---- chains ----
    chains: list[dict] = []
    chain_stage_evidence: dict[str, list[str]] = {}
    degraded = False
    llm_statuses: list[str] = []
    for chain in chains_raw:
        chain_id = chain.get("chain_id") or f"chain_{uuid.uuid4().hex[:20]}"
        meta = chain.get("llm_meta") or {}
        llm_statuses.append(str(meta.get("status") or "not_called"))
        # degraded 仅统计真实的 LLM 失败；预算外 not_called 是设计行为，不算降级
        if str(meta.get("status")) in ("failed", "error", "timeout"):
            degraded = True
        stages: list[dict] = []
        for stage in chain.get("stages") or []:
            refs = [r for r in (stage.get("evidence_event_ids") or []) if r in known_ids]
            if not refs:
                continue
            times = sorted(str(events[r].get("timestamp") or "") for r in refs if events[r].get("timestamp"))
            tactic = " ".join(x for x in (stage.get("tactic"), stage.get("tactic_name")) if x)
            technique = " ".join(x for x in (stage.get("technique"), stage.get("technique_name")) if x).strip()
            stage_id = f"{chain_id}-s{int(stage.get('stage_index') or len(stages) + 1):02d}"
            stages.append({
                "stage_id": stage_id,
                "tactic": tactic or "未知战术",
                "technique": technique or tactic or "未知技术",
                "evidence_event_ids": refs,
                "confidence": _clamp01(stage.get("confidence", 0.6)),
                "time_range": [times[0] if times else "", times[-1] if times else ""],
                "narrative": stage.get("narrative") or "",
                "source": stage.get("source") or "rule",
            })
        if not stages:
            continue
        stage_ids = [s["stage_id"] for s in stages]
        all_refs = [r for s in stages for r in s["evidence_event_ids"]]
        chain_stage_evidence[chain_id] = all_refs
        chain_label = _dominant_label(events, all_refs)
        # ---- Grounded Confidence 证据置信度卡片（候选②）----
        # 合并 M2 的 8 因子评分、反幻觉校验结果与惩罚明细，报告/问答/前端共用。
        risk = chain.get("risk_score") or {}
        validation = chain.get("evidence_validation") or {}
        penalties: list[dict] = []
        if validation.get("hallucination_detected"):
            penalties.append({
                "reason": "反幻觉校验发现模型引用了不存在的证据",
                "amount": validation.get("confidence_penalty"),
            })
        ISSUE_CN = {
            "insufficient_evidence": "有效证据不足以支撑该结论",
            "unknown_event": "引用了结果包中不存在的证据事件",
            "dropped_stage": "存在因证据缺失被剔除的阶段",
        }
        for issue in (validation.get("issues") or [])[:5]:
            text = issue if isinstance(issue, str) else json.dumps(issue, ensure_ascii=False)
            try:  # M2 的 issues 可能是 JSON 字符串（如 {"code":..,"message":..}），解析成可读文本
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    code = str(parsed.get("code") or "")
                    text = ISSUE_CN.get(code, "") or str(parsed.get("message") or text)
            except (ValueError, TypeError):
                pass
            penalties.append({"reason": str(text)[:160], "amount": None})
        if chain.get("llm_degraded") and (meta.get("status") or "") not in ("success", "not_called"):
            penalties.append({"reason": "LLM 研判失败，已降级为规则结论", "amount": None})
        confidence_card = {
            "score": risk.get("score"),
            "severity": severity_for(chain.get("severity")),
            "factors": risk.get("factors") or [],
            "rationale": risk.get("rationale") or [],
            "penalties": penalties,
            "evidence_validation": {
                "valid": validation.get("valid", True),
                "hallucination_detected": validation.get("hallucination_detected", False),
                "valid_evidence_count": validation.get("valid_evidence_count"),
                "dropped_stages": len(validation.get("dropped_stage_indexes") or []),
                "unknown_event_ids": len(validation.get("unknown_event_ids") or []),
                "llm_checked": "valid" in validation,
            },
            "summary": _confidence_summary(risk, validation, penalties,
                                           llm_checked="valid" in validation),
        }
        signal_severity = _m1_level_for(events, all_refs)
        chains.append({
            "schema_version": "AttackChain.v1",
            "chain_id": chain_id,
            "task_id": task_id,
            "severity": _blend_severity(chain.get("severity"), _m1_level_for(events, all_refs)),
            "signal_severity": signal_severity,
            "stages": stages,
            "edges": list(zip(stage_ids, stage_ids[1:])),
            "attacker_ips": chain.get("attacker_ips") or [],
            "victim_ips": chain.get("victim_ips") or [],
            "summary": chain.get("summary") or "",
            "risk_score": chain.get("risk_score"),
            "confidence": _clamp01(chain.get("confidence", 0.5)),
            "first_seen": chain.get("first_seen"),
            "last_seen": chain.get("last_seen"),
            "llm_meta": chain.get("llm_meta") or {},
            "confidence_card": confidence_card,
        })

    # ---- alerts ----
    alerts: list[dict] = []
    for alert in alerts_raw:
        refs = [r for r in (alert.get("evidence_event_ids") or []) if r in known_ids]
        if not refs:
            refs = chain_stage_evidence.get(alert.get("chain_id"), [])[:10]
        if not refs:
            continue
        member_chain = next((c for c in chains if c["chain_id"] == alert.get("chain_id")), None)
        rationale = ((member_chain or {}).get("risk_score") or {}).get("rationale") or []
        signal_severity = _m1_level_for(events, refs)
        severity = _blend_severity(alert.get("severity") or (member_chain or {}).get("severity"), signal_severity)
        label = _dominant_label(events, refs) or (member_chain or {}).get("stages", [{}])[0].get("technique")
        zh_title, zh_desc = _zh_title_and_desc(alert, refs, label, member_chain, severity)
        alerts.append({
            "schema_version": "CandidateAlert.v1",
            "alert_id": alert.get("alert_id") or f"alert_{uuid.uuid4().hex[:16]}",
            "title": zh_title,
            "title_en": alert.get("title") or "",
            "description": zh_desc,
            "severity": severity,
            "signal_severity": signal_severity,
            "confidence": _clamp01(alert.get("confidence", (member_chain or {}).get("confidence", 0.5))),
            "timestamp": alert.get("last_seen") or alert.get("first_seen"),
            "event_ids": refs,
            "attack_type": label,
            "mitre": (alert.get("mitre_techniques") or [None])[0]
                     or ((member_chain or {}).get("stages", [{}])[0].get("technique")),
            "tactic": (alert.get("mitre_tactics") or [None])[0],
            "technique": (alert.get("mitre_techniques") or [None])[0],
            "attacker_ips": alert.get("attacker_ips") or [],
            "victim_ips": alert.get("victim_ips") or [],
            "risk_reason": rationale[0] if rationale else (member_chain or {}).get("summary") or "",
            "chain_id": alert.get("chain_id"),
        })

    # ---- profiles ----
    profiles: list[dict] = []
    for profile in profiles_raw:
        refs = [r for r in (profile.get("evidence_event_ids") or []) if r in known_ids]
        if not refs:
            for cid in profile.get("chain_ids") or []:
                refs.extend(chain_stage_evidence.get(cid, []))
        refs = list(dict.fromkeys(refs))
        if not refs:
            continue
        profiles.append({
            "profile_id": profile.get("attacker_id") or f"profile_{uuid.uuid4().hex[:12]}",
            "attacker_ips": profile.get("attacker_ips") or [],
            "domains": profile.get("domains") or [],
            "usernames": profile.get("usernames") or [],
            "tools": profile.get("tools") or [],
            "techniques": profile.get("techniques") or [],
            "tactics": profile.get("tactics") or [],
            "target_assets": profile.get("target_assets") or [],
            "first_seen": profile.get("first_seen"),
            "last_seen": profile.get("last_seen"),
            "attack_count": profile.get("attack_count"),
            "severity_distribution": profile.get("severity_distribution") or {},
            "behavior_summary": profile.get("behavior_summary") or "",
            "attribution": profile.get("attribution") or "Not Determined",
            "attribution_confidence": profile.get("attribution_confidence", 0),
            "risk_score": profile.get("risk_score"),
            "max_severity": severity_for(profile.get("max_severity")),
            "observed_iocs": profile.get("observed_iocs") or [],
            "evidence_refs": refs,
            "chain_ids": [c for c in (profile.get("chain_ids") or []) if c in chain_stage_evidence],
            "notes": profile.get("notes") or [],
        })

    # ---- report ----
    recommendations = []
    for action in report_raw.get("recommendations") or []:
        source = RECOMMENDATION_SOURCE_MAP.get(
            action.get("recommendation_type") or "", "knowledge_base")
        recommendations.append({
            "id": action.get("mitigation_id") or f"act_{len(recommendations) + 1}",
            "title": action.get("title") or "",
            "text": action.get("description") or "",
            "source": source,
            "priority": action.get("priority"),
            "related_techniques": action.get("related_techniques") or [],
        })
    report = {
        "summary": report_summary or report_raw.get("overview") or "",
        "statistics": report_raw.get("statistics") or {},
        "highlights": report_raw.get("highlights") or [],
        "recommended_actions": recommendations,
        "generated_at": report_raw.get("generated_at"),
    }

    # ---- metrics / versions / degraded ----
    m1_metrics = m1_status.get("metrics", {}) or {}
    duration = 0.0
    raw_timings = metrics_raw.get("stage_timings")
    if isinstance(raw_timings, dict):
        for value in raw_timings.values():
            try:
                duration += float(value)
            except (TypeError, ValueError):
                pass
    elif isinstance(raw_timings, list):
        for entry in raw_timings:
            if isinstance(entry, dict):
                try:
                    # stage_timings 条目为毫秒（pipeline duration_ms），统一换算成秒
                    duration += float(entry.get("duration_ms") or 0) / 1000.0
                except (TypeError, ValueError):
                    pass
    if metrics_raw.get("total_duration_ms"):
        try:
            duration = max(duration, float(metrics_raw["total_duration_ms"]) / 1000.0)
        except (TypeError, ValueError):
            pass
    metrics = {
        "raw_count": m1_metrics.get("input_records"),
        "denoised_count": m1_metrics.get("normalized_records"),
        "suspicious_count": m1_metrics.get("suspicious_sessions"),
        "m2_events": metrics_raw.get("events_unique") or len(events),
        "attack_candidates": report_raw.get("statistics", {}).get("total_attack_candidates"),
        "attack_events": report_raw.get("statistics", {}).get("total_attack_events"),
        "llm_calls": report_raw.get("statistics", {}).get("llm_calls"),
        "llm_failures": report_raw.get("statistics", {}).get("llm_failures"),
        "llm_degraded_chains": report_raw.get("statistics", {}).get("llm_degraded_chains"),
        "events_per_second": metrics_raw.get("events_per_second"),
        "duration_seconds": round(duration, 3),
    }
    metrics = {k: v for k, v in metrics.items() if v is not None}
    metrics.update(extra_metrics or {})

    # ---- 最终等级分布：与可解释综合风险分同源；M1 初筛强度另存 signal_severity ----
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for a in alerts:
        key = a.get("severity", "info")
        if key not in sev_counts:
            key = "info"
        sev_counts[key] += 1
    chain_count = len(chains)
    confirmed_events = len(alerts)
    multistage_chains = sum(1 for c in chains if len(c.get("stages", [])) > 1)
    metrics["severity_counts"] = sev_counts
    metrics["chain_count"] = chain_count
    metrics["confirmed_events"] = confirmed_events
    metrics["multistage_chains"] = multistage_chains
    # 覆盖 report.statistics 的等级计数，保证叙事/表/PDF 三处同源且真实
    report["statistics"] = {**report["statistics"], **{
        f"{k}_count": v for k, v in sev_counts.items()},
        "chain_count": chain_count, "confirmed_events": confirmed_events,
        "multistage_chains": multistage_chains,
        # 单事件候选会各自成链，链数≈事件数属正常；如实标注避免把两数当两个独立大指标
        "events_vs_chains": ("本批攻击会话多为单事件、各自独立成链，故攻击链数接近攻击事件数"
                             if chain_count and abs(chain_count - confirmed_events) <= max(1, 0.05 * confirmed_events)
                             else "多条告警已被关联引擎串联为攻击链"),
    }
    # 运营总结：优先用回调（基于真实分布，可含 cqsec 本地模型，无云端额度）；否则确定性如实摘要
    narrative: str | None = None
    if summarize is not None:
        try:
            narrative = summarize(dict(sev_counts), confirmed_events, chain_count,
                                  multistage_chains, metrics, dict(report["statistics"]))
        except Exception:  # noqa: BLE001 - 总结失败回退确定性文案，不影响主流程
            narrative = None
    report["summary"] = (narrative or "").strip() or _default_summary(
        sev_counts, confirmed_events, chain_count, multistage_chains, metrics)

    m2_llm_meta = next((c.get("llm_meta") or {} for c in chains_raw if c.get("llm_meta")), {})
    versions = {
        "rule_version": str(m1_status.get("rule_version") or "m1-rules-1.3"),
        "model_version": str(m2_llm_meta.get("model") or m1_status.get("model_version") or "rule-only"),
        "prompt_version": str(m2_llm_meta.get("prompt_version") or "attack_analysis.v1"),
        "code_commit": "taishi-platform-dev-20260920",
        "threshold_version": "m2-link-0.55",
    }

    bundle = {
        "schema_version": "AttackChainBundle.v1",
        "task_id": task_id,
        "alerts": alerts,
        "chains": chains,
        "evidence": evidence,
        "profiles": profiles,
        "metrics": metrics,
        "report": report,
        "degraded": degraded
        or (not any(s in ("success", "failed") for s in llm_statuses)
            and str(m1_status.get("l3_status")) in ("failed", "partial_failure", "disabled")),
        # 全程无 LLM 参与（禁用/降级模式）或存在真实 LLM 失败时才标降级；
        # 预算内全部成功则视为正常智能模式。
        "versions": versions,
    }

    # ---- 用 M3 的校验器自校验（失败即抛错，不投递半成品）----
    sys.path.insert(0, str(PROJECT_ROOT))
    from m3.workspace_io import Bundle  # noqa: E402
    validated = Bundle.model_validate(bundle)

    # ---- 原子投递: <out>.tmp-xxx/ -> <out> ----
    out_dir = Path(out_dir)
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = out_dir.with_name(out_dir.name + ".tmp-" + uuid.uuid4().hex[:8])
    staging.mkdir(parents=True)
    payload = json.dumps(validated.model_dump(), ensure_ascii=False, indent=1).encode("utf-8")
    (staging / "bundle.json").write_bytes(payload)
    manifest = {
        "schema_version": "ResultManifest.v1",
        "task_id": task_id,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "producer": "taishi-bundle-1.0",
    }
    (staging / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2),
                                           encoding="utf-8")
    if out_dir.exists():
        import shutil as _shutil
        _shutil.rmtree(out_dir)  # Windows 上 os.replace 无法覆盖非空目录；M3 按 mtime 失效缓存
    # Windows 下新目录可能被杀毒/索引器短暂占用导致拒绝访问：重试兜底
    last_error: Exception | None = None
    for attempt in range(5):
        try:
            os.replace(staging, out_dir)
            last_error = None
            break
        except PermissionError as exc:
            last_error = exc
            time.sleep(0.8 * (attempt + 1))
    if last_error is not None:
        raise last_error

    return {
        "task_id": task_id,
        "alerts": len(alerts),
        "chains": len(chains),
        "profiles": len(profiles),
        "evidence": len(evidence),
        "severity_counts": dict(sev_counts),
        "multistage_chains": multistage_chains,
        "degraded": bundle["degraded"],
        "out_dir": str(out_dir),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Assemble M2 output into M3 AttackChainBundle.v1")
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--m2-output", required=True)
    parser.add_argument("--evidence", required=True, help="bridge 产出的 evidence 索引 JSON")
    parser.add_argument("--out", required=True, help="workspace/m2/READY/<task_id>")
    parser.add_argument("--m1-batch", default=None, help="M1 batch.json（用于版本与统计）")
    parser.add_argument("--report-summary", default=None, help="覆盖报告 summary（如 cqsec 运营总结）")
    args = parser.parse_args()
    stats = assemble(args.task_id, Path(args.m2_output), Path(args.evidence), Path(args.out),
                     Path(args.m1_batch) if args.m1_batch else None, args.report_summary)
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
