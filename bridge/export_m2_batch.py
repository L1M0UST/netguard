"""M1 SuspiciousEventBatch(2.0, 会话级) -> M2 SuspiciousEventBatch.v1(事件级) 契约转换。

解决矛盾点 #1/#8：
- M2 的 EventCore 必填 event.task_id / event.timestamp，M1 会话级行两者皆无，直连会 100% 被静默丢弃；
- 按 related_event_ids 将可疑会话展开回事件级（保留事件时间戳供 M2 时间衰减关联与证据链使用），
  会话级检测结论（规则/IOC/评分/标签）复制到成员事件上，session_id 原样传递（M2 同会话关联 +0.10）。
- 不把多个会话合并成一个事件：会破坏 M2 的时间窗关联，也让证据无法指向真实事件。

同时产出 evidence 索引（bundle 组装器用）与官方中文标签层（矛盾点 #5）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from bridge.labels import label_for

CONTRACT_VERSION = "1.0.0"

# M2 SuspiciousEvent.v1 契约列（扁平布局），顺序即 parquet 列顺序
CONTRACT_COLUMNS = [
    "event_id", "task_id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "payload_digest", "raw_ref", "source_file",
    "matched_rules", "ioc_hits", "score", "reason", "detector",
    "session_id", "emitted_at", "schema_version",
    # additive extras（契约允许增量字段，M2 会保留）
    "attack_type", "risk_level", "url_path", "review_group_id",
    # M1 L3 advisory evidence. M2 consumes it through explicit prompt/scoring
    # inputs; detection.reason remains the deterministic M1 explanation.
    "m1_semantic_verdict", "m1_semantic_confidence", "m1_semantic_summary",
    "m1_semantic_attack_type", "m1_semantic_reasoning", "m1_semantic_action", "m1_semantic_provider",
    "m1_semantic_model", "m1_model_agreement", "m1_evidence_reference",
]

EVIDENCE_COLUMNS = [
    "event_id", "session_id", "timestamp", "src_ip", "dst_ip", "url_path",
    "attack_type", "risk_level", "matched_rules", "ioc_hits", "summary",
    "m1_semantic_verdict", "m1_semantic_confidence", "m1_semantic_provider",
    "m1_semantic_attack_type",
]


def _iso(value) -> str | None:
    """统一为带时区的 ISO8601；naive 视为 UTC（与 M2 的假设一致）。"""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.isoformat()


def _payload_digest(detail: dict) -> str | None:
    parts = "|".join(str(detail.get(key) or "") for key in ("request_body", "message", "user_agent"))
    return hashlib.sha256(parts.encode("utf-8")).hexdigest()[:32] if parts.strip("|") else None


def _evidence_text(session: dict, label: str) -> str:
    parts = []
    for item in session.get("evidence") or []:
        if isinstance(item, dict) and item.get("name"):
            parts.append(f"{item.get('type', 'rule')}:{item['name']}")
    for match in session.get("ioc_matches") or []:
        if isinstance(match, dict) and match.get("value"):
            parts.append(f"ioc:{match['type']}:{match['value']}")
    if label and label != "待研判":
        parts.append(f"标签:{label}")
    return "; ".join(parts) or "M1 会话级初筛命中（无规则明细）"


def export_batch(m1_ready_dir: Path, out_dir: Path, task_id: str,
                 evidence_out: Path | None = None, limit: int | None = None) -> dict:
    """读取 M1 ready 批次，展开为 M2 事件级契约目录。返回统计 dict。"""
    # 复用 M1 自己的发布校验（READY.json / contract 2.0 / SHA-256）
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from m1.handoff import read_batch  # noqa: E402  延迟导入避免循环依赖

    batch = read_batch(Path(m1_ready_dir))
    m1_ready_dir = Path(m1_ready_dir)

    sessions_table = pq.read_table(m1_ready_dir / "suspicious_events.parquet")
    details_table = pq.read_table(m1_ready_dir / "event_details.parquet")
    sessions = sessions_table.to_pylist()
    details = {row["event_id"]: row for row in details_table.to_pylist()}
    judgement_path = m1_ready_dir / "semantic_judgements.parquet"
    judgements = (pq.read_table(judgement_path).to_pylist() if judgement_path.exists() else [])
    judgement_by_session = {str(row.get("session_id")): row for row in judgements if row.get("session_id")}

    now_iso = datetime.now(timezone.utc).isoformat()
    rows: list[dict] = []
    evidence_rows: list[dict] = []
    seen_event_ids: set[str] = set()
    missing_details = 0
    label_counts: dict[str, int] = {}

    for session in sessions:
        rule_hits = list(session.get("rule_hits") or [])
        ioc_matches = list(session.get("ioc_matches") or [])
        label = label_for(rule_hits, ioc_matches)
        label_counts[label] = label_counts.get(label, 0) + 1
        ioc_hits = [
            f"{m.get('type', 'unknown')}:{m.get('value', '')}"
            for m in ioc_matches if isinstance(m, dict) and m.get("value")
        ]
        reason = _evidence_text(session, label)
        session_id = session.get("session_id") or ""
        semantic = judgement_by_session.get(str(session_id), {})

        member_ids = list(session.get("related_event_ids") or [])
        if not member_ids:
            member_ids = [session.get("event_id")] if session.get("event_id") else []
        for member_id in member_ids:
            if not member_id or member_id in seen_event_ids:
                continue
            detail = details.get(member_id)
            if detail is None:
                missing_details += 1
                continue
            seen_event_ids.add(member_id)
            timestamp = _iso(detail.get("timestamp")) or _iso(session.get("first_seen")) or now_iso
            summary_payload = str(detail.get("request_body") or detail.get("message") or "")[:120]
            row = {
                "event_id": member_id,
                "task_id": task_id,
                "timestamp": timestamp,
                "src_ip": detail.get("src_ip") or session.get("src_ip"),
                "dst_ip": detail.get("dst_ip") or session.get("dst_ip"),
                "src_port": session.get("src_port"),
                "dst_port": session.get("dst_port"),
                "protocol": (session.get("protocol") or None),
                "payload_digest": _payload_digest(detail),
                "raw_ref": json.dumps(detail.get("raw_reference"), ensure_ascii=False)
                if isinstance(detail.get("raw_reference"), dict) else str(detail.get("raw_reference") or ""),
                "source_file": detail.get("source_file") or session.get("source_file"),
                "matched_rules": rule_hits,
                "ioc_hits": ioc_hits,
                "score": float(session.get("risk_score") or 0),
                "reason": reason,
                "detector": "m1-session",
                "session_id": session_id,
                "emitted_at": now_iso,
                "schema_version": CONTRACT_VERSION,
                "attack_type": label,
                "risk_level": session.get("risk_level"),
                "url_path": detail.get("url_path"),
                "review_group_id": session.get("review_group_id"),
                "m1_semantic_verdict": semantic.get("verdict"),
                "m1_semantic_confidence": semantic.get("confidence"),
                "m1_semantic_summary": str(semantic.get("summary") or "")[:300],
                "m1_semantic_attack_type": semantic.get("attack_type") or semantic.get("attack_label"),
                "m1_semantic_reasoning": json.dumps(semantic.get("reasoning") or [], ensure_ascii=False)[:1200],
                "m1_semantic_action": semantic.get("recommended_action"),
                "m1_semantic_provider": semantic.get("provider"),
                "m1_semantic_model": semantic.get("model"),
                "m1_model_agreement": semantic.get("model_agreement"),
                "m1_evidence_reference": json.dumps(semantic.get("evidence_reference") or {}, ensure_ascii=False),
            }
            rows.append(row)
            evidence_rows.append({
                "event_id": member_id,
                "session_id": session_id,
                "timestamp": timestamp,
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "url_path": detail.get("url_path"),
                "attack_type": label,
                "risk_level": session.get("risk_level"),
                "risk_score": session.get("risk_score"),
                "matched_rules": rule_hits,
                "ioc_hits": ioc_hits,
                "summary": f"{(timestamp or '')[:19]} {row['src_ip']} -> {row['dst_ip']} "
                           f"{detail.get('url_path') or ''} 载荷:{summary_payload or '(空)'} [{label}]",
                "m1_semantic_verdict": semantic.get("verdict"),
                "m1_semantic_confidence": semantic.get("confidence"),
                "m1_semantic_attack_type": semantic.get("attack_type") or semantic.get("attack_label"),
                "m1_semantic_provider": semantic.get("provider"),
            })
            if limit and len(rows) >= limit:
                break
        if limit and len(rows) >= limit:
            break

    # ---- 写 M2 inbox: batch_000001.parquet + manifest.json + READY（顺序不可颠倒）----
    out_dir = Path(out_dir)
    if out_dir.exists():
        for stale in ("READY", "PROCESSING", "DONE", "FAILED"):
            (out_dir / stale).unlink(missing_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    parquet_path = out_dir / "batch_000001.parquet"
    table = pa.table({name: pa.array([row.get(name) for row in rows]) for name in CONTRACT_COLUMNS})
    pq.write_table(table, parquet_path)

    manifest = {
        "schema_version": CONTRACT_VERSION,
        "task_id": task_id,
        "batch_id": f"batch-{task_id}",
        "producer": "module1",
        "created_at": now_iso,
        "event_count": len(rows),
        "files": [{
            "path": parquet_path.name,
            "sha256": hashlib.sha256(parquet_path.read_bytes()).hexdigest(),
            "size_bytes": parquet_path.stat().st_size,
            "row_count": len(rows),
            "schema_version": CONTRACT_VERSION,
        }],
        "metadata": {
            "m1_batch_id": batch.get("batch_id"),
            "m1_run_id": batch.get("run_id"),
            "consumption_key": batch.get("consumption_key"),
            "m1_ready_dir": str(m1_ready_dir),
            "bridge_version": "bridge-1.0",
            "semantic_judgements": len(judgements),
        },
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    if evidence_out is not None:
        # 注意：evidence 索引含真实攻击载荷样本，明文 JSON 会被 Windows Defender
        # 判为脚本威胁并隔离（导致下游 bundle 组装引用断裂）。改用 Parquet 二进制
        # 列式存储——信息不变，杀毒引擎不再误杀。
        evidence_out = Path(evidence_out).with_suffix(".parquet")
        evidence_out.parent.mkdir(parents=True, exist_ok=True)
        table = pa.table({name: pa.array([row.get(name) for row in evidence_rows])
                          for name in EVIDENCE_COLUMNS})
        pq.write_table(table, evidence_out)
        (evidence_out.parent / "labels.json").write_text(
            json.dumps({"task_id": task_id, "labels": label_counts}, ensure_ascii=False, indent=2),
            encoding="utf-8")

    (out_dir / "READY").write_text("", encoding="utf-8")  # M2 认领标记，最后创建

    return {
        "task_id": task_id,
        "m1_sessions": len(sessions),
        "events_written": len(rows),
        "missing_details": missing_details,
        "label_counts": label_counts,
        "out_dir": str(out_dir),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Bridge: M1 ready batch -> M2 inbox contract v1")
    parser.add_argument("--m1-ready", required=True, help="M1 ready/<batch_id>/<run_id> 目录")
    parser.add_argument("--out", required=True, help="M2 inbox 任务目录")
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--evidence-out", default=None, help="evidence 索引 JSON 输出路径")
    parser.add_argument("--limit", type=int, default=None, help="调试用：限制展开事件数")
    args = parser.parse_args()
    stats = export_batch(Path(args.m1_ready), Path(args.out), args.task_id,
                         Path(args.evidence_out) if args.evidence_out else None, args.limit)
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
