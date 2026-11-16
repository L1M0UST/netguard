"""Build grouped M1-compatible Web SFT data from competition and D1 sources.

Only source labels are used. Held-out samples never enter the training file.
The similarity audit is conservative and approximate, not a proof of no leakage.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import html
import importlib.util
import json
import random
import re
import sys
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / ".local_deps"))
sys.path.insert(0, str(HERE.parent.parent))
import pandas as pd
from datasketch import MinHash, MinHashLSH
from llm.cqsec import JUDGE_INSTRUCTION, fmt_alert

D1_LABELS = {
    "normal": "正常访问", "xss": "XSS跨站脚本攻击", "sql_injection": "SQL注入攻击",
    "command_injection": "远程命令执行攻击", "local_file_inclusion": "文件包含攻击", "ssrf": "SSRF攻击",
}
HIGH = {"SQL注入攻击", "远程命令执行攻击", "Java反序列化漏洞利用攻击", "文件上传攻击", "SSRF攻击"}
LABELS = set(D1_LABELS.values()) | {"目录遍历攻击", "CSRF攻击", "Java反序列化漏洞利用攻击", "文件上传攻击"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def norm(value: object) -> str:
    text = html.unescape(str(value or "")).strip().casefold()
    for _ in range(2):
        decoded = urllib.parse.unquote(text)
        if decoded == text:
            break
        text = decoded
    return re.sub(r"\s+", " ", text)


def url_path(value: object) -> str:
    raw = str(value or "")
    try:
        url = urllib.parse.urlsplit(raw)
        if url.scheme and url.netloc:
            return (url.path or "/") + ("?" + url.query if url.query else "")
    except ValueError:
        pass
    return raw


def canonical(alert: dict) -> str:
    return "\x1f".join((norm(alert.get("method")), norm(url_path(alert.get("url_path"))),
                         norm(alert.get("request_body"))))


def shape(alert: dict) -> str:
    return re.sub(r"\d{2,}", "<number>", canonical(alert))


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def features(alert: dict) -> frozenset[str]:
    result = set()
    for name, raw in (("url", url_path(alert.get("url_path"))), ("body", alert.get("request_body"))):
        text = norm(raw)
        if len(text) > 8192:
            return frozenset()
        words = re.findall(r"[a-z_]+|\d+|[^\w\s]", text)
        words = ["<number>" if w.isdigit() and len(w) >= 3 else w for w in words]
        result.update(name + ":" + " ".join(words[i:i+3]) for i in range(max(0, len(words)-2)))
    return frozenset(result)


def signature(values: frozenset[str]) -> MinHash:
    result = MinHash(num_perm=64, seed=42)
    result.update_batch([v.encode("utf-8") for v in values])
    return result


def read_jsonl(path: Path):
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def load_d0(path: Path, seed: int) -> list[dict]:
    df = pd.read_parquet(path).fillna("")
    required = {"timestamp", "user_agent", "method", "src_ip", "dst_ip", "url_path", "request_body", "attack_type"}
    if not required.issubset(df.columns):
        raise ValueError("competition parquet missing required fields")
    groups: dict[str, list[dict]] = collections.defaultdict(list)
    for i, row in enumerate(df.to_dict(orient="records")):
        label = str(row["attack_type"])
        if label not in LABELS:
            raise ValueError("unknown competition label: " + label)
        alert = {k: str(row[k]) for k in required if k != "attack_type"}
        group = "d0-" + digest(shape(alert))[:24]
        groups[group].append({"id": f"d0:{i}", "group": group, "source": "D0_competition", "label": label, "alert": alert})
    # Coalesce near-identical payload families before splitting. Assigning near
    # variants independently and removing them only afterward can leave some
    # classes with almost no usable training examples.
    parent = {key: key for key in groups}
    indices = {label: MinHashLSH(threshold=0.85, num_perm=64) for label in LABELS}
    seen_features: dict[str, frozenset[str]] = {}

    def find(key: str) -> str:
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    def union(a: str, b: str) -> None:
        a, b = find(a), find(b)
        if a != b:
            parent[max(a, b)] = min(a, b)

    for group in sorted(groups):
        labels = {r["label"] for r in groups[group]}
        if len(labels) != 1:
            raise ValueError("a competition request family has conflicting labels")
        label = next(iter(labels))
        feats = features(groups[group][0]["alert"])
        if len(feats) < 6:
            continue
        mh = signature(feats)
        for candidate in sorted(indices[label].query(mh))[:64]:
            other = seen_features[candidate]
            if len(feats & other) / len(feats | other) >= 0.85:
                union(group, candidate)
        indices[label].insert(group, mh)
        seen_features[group] = feats

    clustered: dict[str, list[dict]] = collections.defaultdict(list)
    for key, members in groups.items():
        clustered[find(key)].extend(members)
    for cluster, members in clustered.items():
        cluster_id = "d0family-" + digest(cluster)[:24]
        for row in members:
            row["group"] = cluster_id
    groups = clustered
    print("competition groups after near-family clustering:", len(groups), flush=True)

    per_label: dict[str, list[str]] = collections.defaultdict(list)
    for group, rows in groups.items():
        labels = {r["label"] for r in rows}
        if len(labels) != 1:
            raise ValueError("a competition request family has conflicting labels")
        per_label[next(iter(labels))].append(group)
    rng = random.Random(seed)
    out = []
    for label, keys in sorted(per_label.items()):
        keys.sort(); rng.shuffle(keys)
        keys.sort(key=lambda k: -len(groups[k]))
        count = sum(len(groups[k]) for k in keys)
        targets = {"train": count * 0.80, "dev": count * 0.10, "test": count * 0.10}
        assigned = {"train": 0, "test": 0, "dev": 0}
        for group in keys:
            split = max(("train", "dev", "test"), key=lambda s: targets[s] - assigned[s])
            assigned[split] += len(groups[group])
            for row in groups[group]:
                row["split"] = split
                out.append(row)
    return out


def load_d1(directory: Path) -> list[dict]:
    out = []
    for split in ("train", "dev", "test"):
        for record in read_jsonl(directory / f"{split}.jsonl"):
            data = json.loads(record["input"])
            event = (data.get("events") or [{}])[0]
            raw_label = json.loads(record["output"]).get("attack_family")
            if raw_label not in D1_LABELS:
                raise ValueError("unknown D1 label: " + str(raw_label))
            meta = record["_meta"]
            if meta.get("split") != split:
                raise ValueError("D1 metadata split mismatch")
            alert = {"timestamp": "", "method": event.get("method") or "", "src_ip": "", "dst_ip": "",
                     "user_agent": "", "url_path": event.get("url") or "", "request_body": event.get("request_body") or ""}
            out.append({"id": str(meta["record_id"]), "group": str(meta["group_id"]), "source": "D1_Mendeley_v2",
                        "source_file": str(meta.get("source_file", "")), "label": D1_LABELS[raw_label],
                        "split": split, "alert": alert})
    return out


def audit_overlap(rows: list[dict], candidate_split: str, protected_splits: set[str],
                  threshold: float = 0.85, cap: int = 64) -> dict:
    index = MinHashLSH(threshold=threshold, num_perm=64)
    protected: dict[str, tuple[frozenset[str], str]] = {}
    exact: set[str] = set()
    shape_keys: set[str] = set()
    stats = collections.Counter()
    for row in rows:
        if row["split"] not in protected_splits:
            continue
        alert = row["alert"]
        exact.add(digest(canonical(alert)))
        shape_keys.add(digest(shape(alert)))
        feats = features(alert)
        if len(feats) < 6:
            stats["protected_not_lsh_indexed"] += 1
            continue
        key = str(len(protected))
        protected[key] = (feats, row["split"])
        index.insert(key, signature(feats))
        stats["protected_lsh_indexed"] += 1
    flagged = set()
    for row in rows:
        if row["split"] != candidate_split:
            continue
        stats["candidate_seen"] += 1
        alert = row["alert"]
        if digest(canonical(alert)) in exact or digest(shape(alert)) in shape_keys:
            flagged.add(row["group"]); stats["exact_or_shape_matches"] += 1
            continue
        feats = features(alert)
        if len(feats) < 6:
            stats["candidate_not_lsh_queried"] += 1
            continue
        candidates = sorted(index.query(signature(feats)), key=int)
        if len(candidates) > cap:
            stats["candidate_list_capped"] += 1
        for key in candidates[:cap]:
            other, target_split = protected[key]
            if len(feats & other) / len(feats | other) >= threshold:
                flagged.add(row["group"])
                stats["near_matches_to_" + target_split] += 1
                break
        if stats["candidate_seen"] % 5000 == 0:
            print("audited", stats["candidate_seen"], candidate_split, "rows", flush=True)
    stats["flagged_candidate_groups"] = len(flagged)
    stats["excluded_rows"] = sum(r["split"] == candidate_split and r["group"] in flagged for r in rows)
    return {"candidate_split": candidate_split, "protected_splits": sorted(protected_splits),
            "stats": dict(stats), "flagged_groups": flagged, "threshold": threshold, "candidate_cap": cap}


def load_signatures(path: Path) -> dict:
    spec = importlib.util.spec_from_file_location("competition_evidence", path)
    if not spec or not spec.loader:
        raise ValueError("cannot load competition evidence patterns")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.SIGNATURES


def answer(row: dict, patterns: dict) -> str:
    label = row["label"]
    if label == "正常访问":
        risk = "低"
        why = "当前请求未见明确的攻击特征；仍应结合业务上下文判断。"
        action = "结合业务基线持续观察。"
    else:
        risk = "高" if label in HIGH else "中"
        text = norm(str(row["alert"].get("url_path") or "") + " " + str(row["alert"].get("request_body") or ""))
        found = []
        for pattern, _ in patterns.get(label, []):
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                fragment = re.sub(r"[\r\n]+", " ", match.group(0))[:48]
                if fragment and fragment not in found:
                    found.append(fragment)
            if len(found) == 2:
                break
        why = ("归一化请求中出现 " + "、".join("“" + x + "”" for x in found) + " 等可疑片段。") if found else "请求内容与该类攻击的可疑特征相符。"
        why += "仅凭请求不能确认漏洞存在或攻击成功。"
        action = "建议复核请求、响应及主机日志，确认影响后再处置。"
    return (f"【研判结论】攻击类型：{label}；风险等级：{risk}\n"
            f"【判定依据】{why}\n【ATT&CK映射】仅凭此请求不足以确认具体技术。\n"
            f"【处置建议】{action}")


def record(row: dict, patterns: dict) -> dict:
    meta = {"record_id": row["id"], "source": row["source"], "group_id": row["group"],
            "label_status": "source_label", "split": row["split"], "label": row["label"]}
    if row.get("source_file"):
        meta["source_file"] = row["source_file"]
    return {"instruction": JUDGE_INSTRUCTION, "input": fmt_alert(row["alert"]), "output": answer(row, patterns), "_meta": meta}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--d0", type=Path, required=True)
    ap.add_argument("--d1", type=Path, required=True)
    ap.add_argument("--signatures", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    rows = load_d0(args.d0, args.seed) + load_d1(args.d1)
    stats_before = collections.Counter((r["source"], r["split"], r["label"]) for r in rows)
    audit_dev = audit_overlap(rows, "dev", {"test"})
    flagged_dev = audit_dev.pop("flagged_groups")
    audit = audit_overlap(rows, "train", {"dev", "test"})
    flagged = audit.pop("flagged_groups")
    patterns = load_signatures(args.signatures)
    stats_after = collections.Counter()
    rng = random.Random(args.seed)
    for split in ("train", "dev", "test"):
        selected = [r for r in rows if r["split"] == split
                    and not (split == "train" and r["group"] in flagged)
                    and not (split == "dev" and r["group"] in flagged_dev)]
        rng.shuffle(selected)
        path = args.output / f"{split}.jsonl"
        with path.open("w", encoding="utf-8", newline="\n") as stream:
            for row in selected:
                stream.write(json.dumps(record(row, patterns), ensure_ascii=False) + "\n")
                stats_after[(row["source"], split, row["label"])] += 1
    info = {f"mist_web_{split}": {"file_name": f"{split}.jsonl", "formatting": "alpaca",
                "columns": {"prompt": "instruction", "query": "input", "response": "output"}}
            for split in ("train", "dev")}
    (args.output / "dataset_info.json").write_text(json.dumps(info, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    def nested(counts):
        result = {}
        for (source, split, label), count in sorted(counts.items()):
            result.setdefault(source, {}).setdefault(split, {})[label] = count
        return result
    report = {"seed": args.seed, "input_d0_sha256": sha256_file(args.d0),
              "input_d1_sha256": {s: sha256_file(args.d1 / f"{s}.jsonl") for s in ("train", "dev", "test")},
              "output_sha256": {s: sha256_file(args.output / f"{s}.jsonl") for s in ("train", "dev", "test")},
              "before": nested(stats_before), "after": nested(stats_after),
              "similarity_audit_train": audit, "similarity_audit_dev": audit_dev,
              "limitations": ["Source labels are not independently reviewed.", "MinHash/LSH may miss near duplicates and short/long samples are not exhaustively checked.",
                              "Competition holdout may have been seen by the previous 4B model.",
                              "Dev-vs-test near-duplicate audit is approximate, not exhaustive."]}
    (args.output / "data_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
