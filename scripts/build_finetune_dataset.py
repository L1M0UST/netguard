"""构建能力①"级联研判头"微调数据集（alpaca jsonl，LLaMA-Factory 直接可用）。

输出格式（与训练侧 qwen3_nothink 单条 user 消息对齐）：
  instruction: 能力①研判指令（固定，与 llm/cqsec.py JUDGE_INSTRUCTION 一致）
  input:       7 字段告警行（时间/方法/源IP/目的IP/UA/URL路径/请求体）
  output:      单行 JSON {"label":..,"confidence":..,"risk":..,"mitre":..}

数据来源（三层）：
  1) 官方 1.1 万条 xlsx（ground truth 8 类标签，类均衡采样）
  2) 平台数据飞轮：workspace/m1/ready/*/semantic_judgements.parquet（真实研判记录）
  3) 注入对抗样本：injection_alerts.csv 中的注入载荷（label=正常访问/待研判 混合）

用法:
  .venv/Scripts/python.exe scripts/build_finetune_dataset.py \
      --xlsx tests_integration/fixtures/web_alerts_full.xlsx --out dataset/cqsec_judge
"""
from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import json
import random
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

# 类别元数据表：label -> (风险, 置信度基准, ATT&CK)
LABEL_META = {
    "SQL注入攻击": ("高", 0.94, "T1190 Exploit Public-Facing Application"),
    "XSS跨站脚本攻击": ("中", 0.90, "T1059.007 JavaScript/JScript Execution"),
    "目录遍历攻击": ("中", 0.92, "T1083 File and Directory Discovery"),
    "文件包含攻击": ("高", 0.91, "T1059.004 Unix Shell"),
    "远程命令执行攻击": ("高", 0.95, "T1059 Command and Scripting Interpreter"),
    "CSRF攻击": ("中", 0.88, "T1189 Drive-by Compromise"),
    "Java反序列化漏洞利用攻击": ("高", 0.94, "T1203 Exploitation for Client Execution"),
    "文件上传攻击": ("高", 0.93, "T1505.003 Web Shell"),
    "扫描探测攻击": ("中", 0.90, "T1046 Network Service Discovery"),
    "暴力破解攻击": ("中", 0.90, "T1110 Brute Force"),
    "Webshell通信攻击": ("高", 0.93, "T1505.003 Web Shell"),
    "C2回连攻击": ("高", 0.95, "T1071 Application Layer Protocol"),
    "SSRF攻击": ("高", 0.92, "T1190 Exploit Public-Facing Application"),
    "XXE攻击": ("高", 0.92, "T1005 Data from Local System"),
    "SSTI攻击": ("高", 0.92, "T1059 Command and Scripting Interpreter"),
    "正常访问": ("低", 0.96, ""),
}
INSTRUCTION = (
    "你是网络安全态势感知中心的AI告警研判助手。请研判下列HTTP告警，"
    "从候选类别【SQL注入攻击、XSS跨站脚本攻击、目录遍历攻击、文件包含攻击、远程命令执行攻击、CSRF攻击、"
    "Java反序列化漏洞利用攻击、文件上传攻击、暴力破解攻击、扫描探测攻击、Webshell通信攻击、"
    "C2回连攻击、SSRF攻击、XXE攻击、SSTI攻击、正常访问】中判定其类型，"
    "只输出一行JSON：{\"label\":\"类别\",\"confidence\":0.xx,\"risk\":\"高|中|低\",\"mitre\":\"ATT&CK或空\"}。"
)


def alert_line(row: dict) -> str:
    return (
        f"时间: {row.get('timestamp') or '未知'}\n"
        f"方法: {row.get('method') or 'GET'}\n"
        f"源IP: {row.get('src_ip') or '未知'}\n"
        f"目的IP: {row.get('dst_ip') or '未知'}\n"
        f"User-Agent: {row.get('user_agent') or '未知'}\n"
        f"URL路径: {row.get('url_path') or '/'}\n"
        f"请求体: {row.get('request_body') or '（空）'}"
    )


def make_sample(row: dict, label: str, confidence: float | None = None) -> dict:
    risk, base_conf, mitre = LABEL_META[label]
    conf = round(confidence if confidence is not None else base_conf, 2)
    output = json.dumps({"label": label, "confidence": conf, "risk": risk, "mitre": mitre},
                        ensure_ascii=False)
    return {"instruction": INSTRUCTION, "input": alert_line(row), "output": output}


def from_official_xlsx(xlsx: Path, per_class: int, rng: random.Random) -> list[dict]:
    """官方数据按类均衡采样（label 用 ground truth 列）。"""
    import pandas as pd
    df = pd.read_excel(xlsx)
    label_col = "attack_type(结果列，需参赛选手判断输出)"
    samples: list[dict] = []
    for label, group in df.groupby(label_col):
        label = str(label)
        if label not in LABEL_META:
            continue
        for _, row in group.head(per_class).iterrows():
            # 置信度加轻微抖动，避免模型输出常数
            jitter = rng.uniform(-0.03, 0.03)
            samples.append(make_sample({k: row.get(k) for k in (
                "timestamp", "method", "src_ip", "dst_ip", "user_agent", "url_path", "request_body")},
                label, LABEL_META[label][1] + jitter))
    return samples


def from_flywheel(workspace: Path, limit: int, rng: random.Random) -> list[dict]:
    """数据飞轮：M1 真实研判记录（verdict→置信度映射，label 取规则映射的官方标签）。"""
    import sys
    sys.path.insert(0, str(PROJECT_ROOT))
    from bridge.labels import label_for  # noqa: E402
    try:
        import pyarrow.parquet as pq
    except ImportError:
        return []
    samples: list[dict] = []
    for status_path in glob.glob(str(workspace / "m1" / "ready" / "*" / "*" / "suspicious_events.parquet")):
        try:
            rows = pq.read_table(status_path).to_pylist()
        except Exception:
            continue
        judgements: dict[str, dict] = {}
        run_dir = Path(status_path).parent
        for jpath in glob.glob(str(run_dir / "semantic_judgements.parquet")):
            try:
                for item in pq.read_table(jpath).to_pylist():
                    judgements[str(item.get("session_id"))] = item
            except Exception:
                continue
        for session in rows:
            item = judgements.get(str(session.get("session_id")))
            if not item or item.get("semantic_status") != "completed":
                continue
            label = label_for(list(session.get("rule_hits") or []))
            if label not in LABEL_META:
                continue
            verdict = str(item.get("verdict"))
            if verdict == "benign" or label == "正常访问":
                label = "正常访问"
                confidence = 0.96
            elif item.get("confidence"):
                confidence = min(0.98, max(0.55, float(item["confidence"])))
            else:
                confidence = None
            evidence = session.get("semantic_evidence") or {}
            row = {
                "timestamp": session.get("first_seen") or session.get("timestamp"),
                "method": session.get("method"),
                "src_ip": session.get("src_ip"),
                "dst_ip": session.get("dst_ip"),
                "user_agent": evidence.get("user_agent"),
                "url_path": session.get("url_path"),
                "request_body": evidence.get("request_body") or evidence.get("message"),
            }
            samples.append(make_sample(row, label, confidence))
            if len(samples) >= limit:
                return samples
    return samples


def from_injection_csv(csv_path: Path) -> list[dict]:
    """注入对抗样本：载荷含注入片段，label=正常访问（低置信，教模型识别并降置信）。"""
    samples: list[dict] = []
    if not csv_path.is_file():
        return samples
    with csv_path.open(encoding="utf-8-sig") as stream:
        for row in csv.DictReader(stream):
            text = f"{row.get('request_body','')} {row.get('user_agent','')}".lower()
            if any(k in text for k in ("ignore", "instructions", "system prompt", "im_start", "you are now")):
                row["request_body"] = row.get("request_body")
                samples.append(make_sample(row, "正常访问", 0.62))
    return samples


def main() -> int:
    parser = argparse.ArgumentParser(description="构建能力①级联研判头 SFT 数据集")
    parser.add_argument("--xlsx", default=str(PROJECT_ROOT / "tests_integration/fixtures/web_alerts_full.xlsx"))
    parser.add_argument("--workspace", default=str(PROJECT_ROOT / "workspace"))
    parser.add_argument("--injection", default=str(PROJECT_ROOT / "tests_integration/fixtures/injection_alerts.csv"))
    parser.add_argument("--out", default=str(PROJECT_ROOT / "dataset/cqsec_judge"))
    parser.add_argument("--per-class", type=int, default=500, help="官方数据每类采样上限")
    parser.add_argument("--flywheel-limit", type=int, default=1500)
    parser.add_argument("--val-ratio", type=float, default=0.1)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    samples = from_official_xlsx(Path(args.xlsx), args.per_class, rng)
    print(f"官方数据样本: {len(samples)}")
    flywheel = from_flywheel(Path(args.workspace), args.flywheel_limit, rng)
    print(f"数据飞轮样本: {len(flywheel)}")
    injection = from_injection_csv(Path(args.injection))
    print(f"注入对抗样本: {len(injection)}")

    all_samples = samples + flywheel + injection
    # 全局去重（input+output 指纹）
    seen, unique = set(), []
    for item in all_samples:
        key = hashlib.sha256((item["input"] + item["output"]).encode("utf-8")).hexdigest()
        if key not in seen:
            seen.add(key)
            unique.append(item)
    rng.shuffle(unique)

    val_n = max(1, int(len(unique) * args.val_ratio))
    val, train = unique[:val_n], unique[val_n:]

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, data in (("train.jsonl", train), ("val.jsonl", val)):
        with (out_dir / name).open("w", encoding="utf-8") as stream:
            for item in data:
                stream.write(json.dumps(item, ensure_ascii=False) + "\n")
    label_dist = Counter(json.loads(item["output"])["label"] for item in train)
    dataset_info = {
        "cqsec_judge_train": {"file_name": "train.jsonl"},
        "cqsec_judge_val": {"file_name": "val.jsonl"},
    }
    (out_dir / "dataset_info.json").write_text(
        json.dumps(dataset_info, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"输出: {out_dir}/train.jsonl ({len(train)}) + val.jsonl ({len(val)})")
    print("训练集标签分布:", dict(label_dist.most_common()))
    print("dataset_info.json 已生成（注册到 LLaMA-Factory data/ 时合并）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
