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
import math
import os
import re
import sys
import time
import uuid
from collections import Counter
from pathlib import Path

from bridge.labels import severity_for
from bundle.graph_builder import build_attack_graph

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


CAMPAIGN_GAP_SECONDS = 3600.0  # 同一攻击活动内两条链的最大时间间隔（秒）


def _parse_ts(value) -> float | None:
    if not value:
        return None
    try:
        from datetime import datetime

        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return None


def _freq_ranked(values, cap: int = 30) -> list[str]:
    """按出现频次降序去重（并列按字典序），供活动级攻击源/受害资产列表使用。"""
    counter = Counter(values)
    return [value for value, _ in sorted(counter.items(), key=lambda item: (-item[1], item[0]))][:cap]


def _build_campaigns(task_id: str, chains: list[dict]) -> list[dict]:
    """跨链攻击活动归并（可解释规则 + Union-Find）。

    两条链并入同一活动必须同时满足"证据相交"与"时间相容"：
    - 共享攻击源 IP；或
    - 共享受害资产 IP 且双方攻击源不同（疑似协同/分布式打击同一目标）。
    时间相容 = 时间区间重叠或间隔 ≤ CAMPAIGN_GAP_SECONDS。
    时间邻近只是相容条件、不是关联理由；每条归并边都落档可解释理由，
    攻击源缺失时不臆断协同。
    """
    n = len(chains)
    if n < 2:
        return []
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    starts: list[float] = []
    ends: list[float] = []
    for chain in chains:
        begin = _parse_ts(chain.get("first_seen"))
        finish = _parse_ts(chain.get("last_seen"))
        if begin is None:
            begin = finish if finish is not None else 0.0
        if finish is None:
            finish = begin
        starts.append(begin)
        ends.append(max(begin, finish))

    def time_compatible(i: int, j: int) -> bool:
        return max(starts[i], starts[j]) <= min(ends[i], ends[j]) + CAMPAIGN_GAP_SECONDS

    pair_reasons: dict[tuple[int, int], list[str]] = {}

    def add_reason(i: int, j: int, text: str) -> None:
        key = (min(i, j), max(i, j))
        bucket = pair_reasons.setdefault(key, [])
        if text not in bucket:
            bucket.append(text)

    def sweep(index: dict[str, list[int]], reason_for) -> None:
        """同一 IP 组内按首次时间排序、只连相邻项：O(k log k)，传递闭包仍成立。"""
        for key, members in index.items():
            if len(members) < 2:
                continue
            members = sorted(members, key=lambda idx: starts[idx])
            for pos in range(len(members) - 1):
                i, j = members[pos], members[pos + 1]
                if not time_compatible(i, j):
                    continue
                text = reason_for(key, i, j)
                if text:
                    add_reason(i, j, text)
                    union(i, j)

    attacker_index: dict[str, list[int]] = {}
    victim_index: dict[str, list[int]] = {}
    for idx, chain in enumerate(chains):
        for ip in chain.get("attacker_ips") or []:
            attacker_index.setdefault(ip, []).append(idx)
        for ip in chain.get("victim_ips") or []:
            victim_index.setdefault(ip, []).append(idx)

    def attacker_reason(key, i, j):
        return f"共享攻击源 {key}"

    def victim_reason(key, i, j):
        left, right = chains[i].get("attacker_ips"), chains[j].get("attacker_ips")
        if not left or not right:
            return None  # 攻击源缺失时不臆断协同
        if set(left) & set(right):
            return None  # 已由共享攻击源覆盖，不重复记理由
        return f"共享受害资产 {key}（来源不同、时间相容，疑似协同攻击）"

    sweep(attacker_index, attacker_reason)
    sweep(victim_index, victim_reason)

    groups: dict[int, list[int]] = {}
    for idx in range(n):
        groups.setdefault(find(idx), []).append(idx)

    campaigns: list[dict] = []
    for members in groups.values():
        if len(members) < 2:
            continue
        members.sort(key=lambda idx: starts[idx])
        member_chains = [chains[idx] for idx in members]
        reasons: list[str] = []
        for pos, i in enumerate(members):
            for j in members[pos + 1:]:
                for text in pair_reasons.get((min(i, j), max(i, j)), []):
                    if text not in reasons:
                        reasons.append(text)
        severity = min((c.get("severity", "info") for c in member_chains),
                       key=lambda sev: SEVERITY_ORDER.get(sev, 9))
        tactics: list[str] = []
        for chain in member_chains:
            for stage in chain.get("stages") or []:
                tactic = str(stage.get("tactic") or "")
                if tactic and tactic not in tactics:
                    tactics.append(tactic)
        last_times = [c.get("last_seen") for c in member_chains if c.get("last_seen")]
        campaigns.append({
            "schema_version": "AttackCampaign.v1",
            "campaign_id": "camp_" + hashlib.sha256(
                "|".join([task_id] + sorted(c["chain_id"] for c in member_chains)).encode("utf-8")
            ).hexdigest()[:16],
            "task_id": task_id,
            "attacker_ips": _freq_ranked(
                [ip for c in member_chains for ip in (c.get("attacker_ips") or [])]),
            "victim_ips": _freq_ranked(
                [ip for c in member_chains for ip in (c.get("victim_ips") or [])]),
            "chain_ids": [c["chain_id"] for c in member_chains],
            "chain_count": len(member_chains),
            "multistage_count": sum(1 for c in member_chains if len(c.get("stages") or []) > 1),
            "severity": severity,
            "first_seen": member_chains[0].get("first_seen"),
            "last_seen": max(last_times) if last_times else None,
            "top_tactics": tactics[:8],
            "reasons": reasons[:12],
            "members": [{
                "chain_id": c["chain_id"],
                "severity": c.get("severity", "info"),
                "risk_score": (c.get("risk_score") or {}).get("score"),
                "stage_count": len(c.get("stages") or []),
                "first_seen": c.get("first_seen"),
                "last_seen": c.get("last_seen"),
            } for c in member_chains],
        })
    campaigns.sort(key=lambda camp: (SEVERITY_ORDER.get(camp["severity"], 9), -camp["chain_count"]))
    return campaigns


SEVERITY_THREAT = {"critical": 1.0, "high": 0.85, "medium": 0.6, "low": 0.35, "info": 0.15}


def _build_victims(report_raw: dict, chains: list[dict], alerts: list[dict]) -> list[dict]:
    """高风险资产双榜单（确定性聚合，供报告层"高风险资产"维度使用）。

    对每个受害资产算两个 0~100 动态指数（相对化，避免整批分数低时无内容展示）：
    - freq_score  被多次攻击指数 = 100·ln(1+n)/ln(1+n_max)，n=命中告警数，榜一恒为 100；
    - threat_score 受高威胁攻击指数 = 0.40·最严等级权重 + 0.25·命中链最大风险分/100
      + 0.20·攻击类型多样性 + 0.15·攻击源多样性；命中多阶段链再 ×1.1（封顶 1.0）。
    展示名单用动态截断（相对榜一/占比），但**高危是硬指针**：最严等级为
    critical/high 的资产必须进入"受高威胁攻击"榜单，相对截断只负责在剩余
    名额里补足低危资产——绝不能因为整体分数低而漏掉被打进高危/Webshell/SQL
    注入/文件上传等危险行为的资产。
    每行带 in_threat_ranking / in_freq_ranking 两个旗标（榜单逻辑只在 assemble
    算一次，PDF 与页面按旗标取数，不重复实现截断规则）。
    """
    rows: list[dict] = []
    for v in report_raw.get("victims") or []:
        ip = str(v.get("victim_ip") or "").strip()
        if ip:
            rows.append({"victim_ip": ip, "m2_attack_count": int(v.get("attack_count") or 0),
                         "m2_tactics": [str(t) for t in (v.get("tactics") or [])][:6],
                         "m2_targeted_ports": list(v.get("targeted_ports") or [])[:8]})
    m2_by_ip = {row.pop("victim_ip"): row for row in rows}

    agg: dict[str, dict] = {}
    for chain in chains:
        risk_value = chain.get("risk_score")
        score = (risk_value or {}).get("score") if isinstance(risk_value, dict) else None
        try:
            score = float(score) if score is not None else None
        except (TypeError, ValueError):
            score = None
        multistage = len(chain.get("stages") or []) > 1
        for ip in chain.get("victim_ips") or []:
            entry = agg.setdefault(ip, {
                "victim_ip": ip, "alert_count": 0, "chain_count": 0,
                "max_severity": "info", "max_score": 0.0, "types": [], "attackers": [],
                "tactics": [], "techniques": [], "multistage": False,
                "first_seen": None, "last_seen": None})
            entry["chain_count"] += 1
            entry["multistage"] = entry["multistage"] or multistage
            severity = chain.get("severity", "info")
            if SEVERITY_ORDER.get(severity, 9) < SEVERITY_ORDER.get(entry["max_severity"], 9):
                entry["max_severity"] = severity
            if score is not None:
                entry["max_score"] = max(entry["max_score"], score)
            for ip_src in chain.get("attacker_ips") or []:
                if ip_src not in entry["attackers"]:
                    entry["attackers"].append(ip_src)
            for field, key in (("tactics", "tactic"), ("techniques", "technique")):
                for stage in chain.get("stages") or []:
                    value = str(stage.get(key) or "")
                    if value and value not in entry[field]:
                        entry[field].append(value)
            if chain.get("first_seen") and (not entry["first_seen"] or chain["first_seen"] < entry["first_seen"]):
                entry["first_seen"] = chain["first_seen"]
            if chain.get("last_seen") and (not entry["last_seen"] or chain["last_seen"] > entry["last_seen"]):
                entry["last_seen"] = chain["last_seen"]
    for alert in alerts:
        for ip in alert.get("victim_ips") or []:
            entry = agg.get(ip)
            if entry is None:  # 告警 victim 不在链集合里（旧包/单事件）也独立成行
                entry = agg.setdefault(ip, {
                    "victim_ip": ip, "alert_count": 0, "chain_count": 0,
                    "max_severity": "info", "max_score": 0.0, "types": [], "attackers": [],
                    "tactics": [], "techniques": [], "multistage": False,
                    "first_seen": None, "last_seen": None})
            entry["alert_count"] += 1
            atype = str(alert.get("attack_type") or "")
            if atype and atype not in entry["types"]:
                entry["types"].append(atype)
            severity = alert.get("severity", "info")
            if SEVERITY_ORDER.get(severity, 9) < SEVERITY_ORDER.get(entry["max_severity"], 9):
                entry["max_severity"] = severity
    if not agg:
        return []

    n_max = max(e["alert_count"] for e in agg.values()) or 1
    type_total = max(1, len({a.get("attack_type") for a in alerts if a.get("attack_type")}))
    for entry in agg.values():
        sev_w = SEVERITY_THREAT.get(entry["max_severity"], 0.15)
        threat = (0.40 * sev_w
                  + 0.25 * min(1.0, entry["max_score"] / 100.0)
                  + 0.20 * (len(entry["types"]) / type_total)
                  + 0.15 * (len(entry["attackers"]) / max(1, entry["chain_count"])))
        if entry["multistage"]:
            threat = min(1.0, threat * 1.1)
        entry["threat_score"] = round(threat * 100, 1)
        entry["freq_score"] = round(100 * (math_log_ratio(entry["alert_count"], n_max)), 1)
        m2 = m2_by_ip.get(entry["victim_ip"]) or {}
        entry["targeted_ports"] = m2.get("m2_targeted_ports") or []
        entry["tactics"] = (entry["tactics"] or m2.get("m2_tactics") or [])[:6]
        entry["techniques"] = entry["techniques"][:6]

    ranked = sorted(agg.values(), key=lambda e: (-e["threat_score"], e["victim_ip"]))
    # 受高威胁攻击榜：critical/high 硬指针全保留 + 相对线（榜一×0.6）补足，≤8 个
    threat_list: list[dict] = []
    for entry in ranked:
        if entry["max_severity"] in ("critical", "high"):
            threat_list.append(entry)
    soft_line = ranked[0]["threat_score"] * 0.6 if ranked else 0.0
    for entry in ranked:
        if len(threat_list) >= 8:
            break
        if entry in threat_list:
            continue
        if entry["threat_score"] >= soft_line:
            threat_list.append(entry)
    for entry in threat_list:
        entry["in_threat_ranking"] = True
    # 被多次攻击榜：count ≥ max(2, 榜一/3)；整体都只被打一次时退化为前 3（如实低频）
    freq_sorted = sorted(agg.values(), key=lambda e: (-e["alert_count"], -e["threat_score"], e["victim_ip"]))
    freq_line = max(2, -(-freq_sorted[0]["alert_count"] // 3))
    freq_list = [e for e in freq_sorted if e["alert_count"] >= freq_line][:8]
    if not freq_list:
        freq_list = freq_sorted[:3]
    for entry in freq_list:
        entry["in_freq_ranking"] = True

    ordered = [e for e in ranked if e.get("in_threat_ranking") or e.get("in_freq_ranking")]
    ordered += [e for e in ranked if e not in ordered][: max(0, 20 - len(ordered))]
    return ordered[:20]


def math_log_ratio(count: int, n_max: int) -> float:
    if count <= 0:
        return 0.0
    return math.log1p(count) / math.log1p(max(1, n_max))


def _narrative_numbers_ok(narrative: str, metrics: dict, statistics: dict,
                          extra: tuple = ()) -> bool:
    """运营总结数字对账：叙事里带量词的整数必须落在系统统计允许集内。

    大模型只负责文字组织，不负责产生统计值。ops_summary 虽被要求"原样引用数字"，
    这里再加一道确定性校验：叙事中任何「N 条/个/起/位/次」形式的数字都必须能在
    metrics/statistics/额外计数（证据/画像/告警总数）或 0~10 的小枚举（"前 3 条"之类）
    里找到，出现对不上的数字即判定为模型编造，回退确定性文案。
    """
    allowed: set[int] = set(range(0, 11))

    def collect(value) -> None:
        if isinstance(value, bool):
            return
        if isinstance(value, int):
            allowed.add(abs(value))
        elif isinstance(value, dict):
            for item in value.values():
                collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)

    collect(metrics)
    collect(statistics)
    allowed.update(abs(int(n)) for n in extra if isinstance(n, int))
    for match in re.finditer(r"\d+(?=\s*(?:条|个|起|位|次))", narrative):
        if int(match.group()) not in allowed:
            return False
    return True


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
            # 处理前原貌（上传文件中的原始日志行锚点；旧产物无这些键时为 None，前端自动隐藏）
            "source_row": row.get("source_row"),
            "source_file": row.get("source_file"),
            "request_body": row.get("request_body"),
            "user_agent": row.get("user_agent"),
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
            # 关联依据与缺失证据：M2 关联引擎的成对判定理由 + 链级不确定项，
            # 回答"这些告警为什么被归为一次攻击/还缺什么证据"。
            "correlation_score": _clamp01(chain.get("correlation_score") or 0.0),
            "correlation_reasons": [str(r) for r in (chain.get("correlation_reasons") or [])][:12],
            "uncertainties": [str(u) for u in (chain.get("uncertainties") or [])][:12],
        })

    # ---- campaigns：跨链攻击活动归并（同攻击者/同受害目标 + 时间相容才合并）----
    campaigns = _build_campaigns(task_id, chains)
    if campaigns:
        by_id = {chain["chain_id"]: chain for chain in chains}
        for campaign in campaigns:
            for member in campaign["members"]:
                chain = by_id.get(member["chain_id"])
                if chain is not None:
                    chain["campaign_id"] = campaign["campaign_id"]

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

    # ---- 高风险资产双榜单（确定性聚合，报告层"高风险资产"维度数据源）----
    victims = _build_victims(report_raw, chains, alerts)

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
    # M1 数据质量透出：过滤漏斗 + 坏行明细 + 语义研判覆盖。旧 batch 无 quality 块时
    # 回退从 metrics 取过滤计数，其余置空骨架，前端按缺省值展示。
    quality_raw = m1_status.get("quality") or {}
    metrics["quality"] = {
        "filtered": quality_raw.get("filtered") or {name: m1_metrics.get(f"filtered_{name}", 0) for name in ("empty", "meaningless", "duplicate", "whitelist", "parse_error")},
        "timestamp_parse_errors": quality_raw.get("timestamp_parse_errors") or 0,
        "parse_errors": quality_raw.get("parse_errors") or {"total": m1_metrics.get("filtered_parse_error", 0), "samples": []},
        "review_groups": quality_raw.get("review_groups"),
        "review_reduction_ratio": quality_raw.get("review_reduction_ratio"),
        "suspicious_ratio": quality_raw.get("suspicious_ratio"),
        "l3_session_coverage": quality_raw.get("l3_session_coverage"),
        "accuracy_status": quality_raw.get("accuracy_status"),
        "payload_similarity": quality_raw.get("payload_similarity") or {},
    }

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
    # 攻击类型分布：与 M3 页面/PDF/chat 同口径（Counter(alert.attack_type or technique)），
    # 一次计算三处同源：前端「主要威胁类型」chips、cqsec 运营总结输入、JSON 证据包。
    type_counts = Counter(
        (a.get("attack_type") or a.get("technique") or "未提供") for a in alerts)
    metrics["attack_types"] = dict(type_counts)
    metrics["severity_counts"] = sev_counts
    metrics["chain_count"] = chain_count
    metrics["confirmed_events"] = confirmed_events
    metrics["multistage_chains"] = multistage_chains
    metrics["campaign_count"] = len(campaigns)
    # 覆盖 report.statistics 的等级计数，保证叙事/表/PDF 三处同源且真实
    report["statistics"] = {**report["statistics"], **{
        f"{k}_count": v for k, v in sev_counts.items()},
        "chain_count": chain_count, "confirmed_events": confirmed_events,
        "multistage_chains": multistage_chains,
        "attack_type_counts": dict(type_counts),
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
        # 数字对账：叙事里出现系统统计之外的量词数字即判编造，回退确定性文案
        if narrative and not _narrative_numbers_ok(
                narrative, metrics, dict(report["statistics"]),
                extra=(len(evidence), len(profiles), len(alerts), len(victims))):
            import logging
            logging.getLogger("assemble").warning(
                "运营总结叙事包含与系统统计不一致的数字，已回退确定性文案")
            narrative = None
    report["summary"] = (narrative or "").strip() or _default_summary(
        sev_counts, confirmed_events, chain_count, multistage_chains, metrics)

    # ---- NetworkX 关联图：节点(IP/资产/链)+边(发起/命中/战役归并)+社区发现+布局坐标 ----
    try:
        graph = build_attack_graph(task_id, chains, campaigns)
    except Exception as exc:  # noqa: BLE001 - 出图失败不阻塞结果包，前端按缺省展示
        graph = None
        import logging

        logging.getLogger("assemble").warning("attack graph build failed: %s", exc)
    if graph is not None:
        metrics["graph_node_count"] = graph["stats"]["node_count"]
        metrics["graph_edge_count"] = graph["stats"]["edge_count"]
        metrics["graph_community_count"] = graph["stats"]["community_count"]

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
        "victims": victims,
        "campaigns": campaigns,
        "graph": graph,
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
        "victims": len(victims),
        "campaigns": len(campaigns),
        "evidence": len(evidence),
        "attack_type_counts": dict(type_counts),
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
