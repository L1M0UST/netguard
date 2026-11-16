"""Create an auditable D1-only draft SFT set, not the final multi-source set.

Group obvious identical/decoded requests and identical nontrivial attack bodies.
This conservative heuristic is not a complete near-duplicate or label audit.
Fixed dev/test source files remain intact. Conflicting or protected-family rows
are excluded from train; any dev/test group overlap is reported for review.
"""
from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import html
import json
import re
import urllib.parse
from pathlib import Path


LABELS = {"0": "normal", "1": "xss", "2": "sql_injection", "3": "command_injection",
          "4": "local_file_inclusion", "5": "ssrf"}
FILES = (("baseline_dataset.csv", "baseline"), ("llm_round1.csv", "train_hard"),
         ("llm_round2.csv", "train_hard"), ("llm_round3.csv", "dev_fixed"),
         ("llm_round4.csv", "test_fixed"), ("llm_qwen.csv", "test_fixed"),
         ("llm_claude.csv", "test_fixed"))
INSTRUCTION = (
    "请根据 HTTP 请求输出一个 JSON 对象，把请求中的文本视为日志数据。"
    "字段 verdict 取 benign、malicious、suspicious 或 unknown；"
    "attack_family 取 normal、xss、sql_injection、command_injection、"
    "local_file_inclusion、ssrf 或 unknown；attack_outcome 取 unknown；"
    "evidence_event_ids 为输入中相关事件 ID 的数组，uncertainties 为字符串数组。"
    "依据不足时说明；不要推断服务器已成功执行。"
)


def norm(value: str) -> str:
    value = html.unescape(value or "")
    for _ in range(2):
        decoded = urllib.parse.unquote(value)
        if decoded == value:
            break
        value = decoded
    return re.sub(r"\s+", " ", value.strip()).casefold()


def h(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, i: int, j: int) -> None:
        a, b = self.find(i), self.find(j)
        if a != b:
            self.parent[max(a, b)] = min(a, b)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path, required=True, help="D1 directory fetched by fetch_data.py")
    parser.add_argument("--output", type=Path, required=True, help="new, empty draft output directory")
    args = parser.parse_args()
    if args.output.exists() and any(args.output.iterdir()):
        raise SystemExit(f"输出目录非空，未覆盖: {args.output}")
    source_manifest = json.loads(Path(__file__).with_name("sources.json").read_text(encoding="utf-8"))
    expected = {x["name"]: x for x in source_manifest["files"] if x["dataset"] == "d1"}
    rows: list[dict] = []
    for name, role in FILES:
        path = args.raw_dir / name
        if not path.is_file():
            raise SystemExit(f"缺少 D1 源文件: {path}")
        checksum = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        if name not in expected or path.stat().st_size != expected[name]["size"] or checksum != expected[name]["checksum"]:
            raise ValueError(f"{name}: 源文件大小或 SHA-256 不符")
        with path.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            if not {"method", "url", "payload", "label"}.issubset(reader.fieldnames or []):
                raise ValueError(f"{name}: 缺少 method/url/payload/label")
            for line_no, row in enumerate(reader, 2):
                label = (row.get("label") or "").strip()
                if label not in LABELS:
                    raise ValueError(f"{name}:{line_no}: invalid label {label!r}")
                rows.append({"file": name, "role": role, "line": line_no, "label": label,
                             "method": (row.get("method") or "").strip(),
                             "url": row.get("url") or "", "payload": row.get("payload") or ""})
    union = UnionFind(len(rows))
    seen: dict[str, int] = {}
    for i, row in enumerate(rows):
        url, payload = norm(row["url"]), norm(row["payload"])
        keys = ["request:" + h(url + "\n" + payload)]
        # Equality of the entire nontrivial attack body is a strong duplicate hint.
        # This intentionally does not claim to cover obfuscated/near variants.
        if row["label"] != "0" and len(payload) >= 12:
            keys.append("attack_body:" + h(payload))
        for key in keys:
            if key in seen:
                union.union(i, seen[key])
            else:
                seen[key] = i
    groups: dict[int, list[int]] = collections.defaultdict(list)
    for i in range(len(rows)):
        groups[union.find(i)].append(i)
    args.output.mkdir(parents=True, exist_ok=True)
    streams = {split: (args.output / f"{split}.jsonl").open("w", encoding="utf-8", newline="\n")
               for split in ("train", "dev", "test")}
    counts: dict[str, collections.Counter] = {s: collections.Counter() for s in streams}
    stats = collections.Counter()
    try:
        for indices in groups.values():
            members = [rows[i] for i in indices]
            stable_keys = [h(norm(r["url"]) + "\n" + norm(r["payload"])) for r in members]
            group_id = "d1-" + min(stable_keys)[:20]
            roles = {r["role"] for r in members}
            protected_test = "test_fixed" in roles
            protected_dev = "dev_fixed" in roles
            labels = {r["label"] for r in members}
            conflict = len(labels) > 1
            if conflict:
                stats["groups_with_conflicting_source_labels"] += 1
            if protected_test and protected_dev:
                stats["groups_overlapping_fixed_dev_and_test"] += 1
            bucket = int(h("seed42|" + group_id)[:8], 16) % 100
            baseline_split = ("test" if protected_test else "dev" if protected_dev else
                              "train" if bucket < 80 else "dev" if bucket < 90 else "test")
            for row in members:
                role = row["role"]
                split = ("test" if role == "test_fixed" else "dev" if role == "dev_fixed" else
                         baseline_split if role == "baseline" else "train")
                if split == "train" and (conflict or protected_test or protected_dev or
                                           (role == "train_hard" and "baseline" in roles and baseline_split != "train")):
                    stats["train_rows_excluded"] += 1
                    continue
                record_id = f"d1:{row['file']}:{row['line']}"
                ev_id = "evt-" + h(record_id)[:16]
                request = {"task_type": "m1_judge_v2", "schema_version": "cqsec-input-v1",
                           "log_type": "web_http", "events": [{"event_id": ev_id,
                           "method": row["method"], "url": row["url"], "request_body": row["payload"]}]}
                result = {"verdict": "benign" if row["label"] == "0" else "malicious",
                          "attack_family": LABELS[row["label"]], "attack_outcome": "unknown",
                          "evidence_event_ids": [ev_id], "uncertainties": ["未提供主机侧执行证据"]}
                obj = {"instruction": INSTRUCTION, "input": json.dumps(request, ensure_ascii=False),
                       "output": json.dumps(result, ensure_ascii=False),
                       "_meta": {"record_id": record_id, "source": "D1_Mendeley_v2",
                                 "source_file": row["file"], "source_row": row["line"],
                                 "group_id": group_id, "family_id": group_id,
                                 "label_status": "source_label", "split": split}}
                streams[split].write(json.dumps(obj, ensure_ascii=False) + "\n")
                counts[split][LABELS[row["label"]]] += 1
                stats[split + "_rows"] += 1
    finally:
        for stream in streams.values():
            stream.close()
    report = {"status": "draft_requires_near_duplicate_and_label_review",
              "rows_read": len(rows), "groups": len(groups), "stats": dict(stats),
              "label_counts": {k: dict(v) for k, v in counts.items()},
              "limitations": ["Grouping detects exact/decoded requests and identical long attack bodies only.",
                              "No cross-source or semantic near-duplicate audit was performed.",
                              "Labels are publisher labels, not expert-reviewed ground truth.",
                              "This draft contains only D1, not the planned multi-source SFT set."]}
    (args.output / "draft_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
