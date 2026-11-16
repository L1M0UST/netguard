"""Check prepared Alpaca JSONL, provenance, split leakage, and event references.

This is a structural check; it cannot prove label quality or detect all
semantic/near-duplicate leakage. Test data can stay outside the training host.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path
from typing import Any


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as stream:
        for lineno, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno} invalid JSON: {exc.msg}") from exc
            if not isinstance(item, dict):
                raise ValueError(f"{path}:{lineno} is not an object")
            yield lineno, item


def canonical_input(value: str) -> str:
    def strip_ids(item: Any) -> Any:
        if isinstance(item, dict):
            return {k: strip_ids(v) for k, v in item.items() if k not in {"event_id", "record_id", "session_id", "candidate_id"}}
        if isinstance(item, list):
            return [strip_ids(v) for v in item]
        return item
    try:
        return json.dumps(strip_ids(json.loads(value)), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    except json.JSONDecodeError:
        return value.strip()


def event_ids(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        if isinstance(value.get("event_id"), str) and value["event_id"]:
            found.add(value["event_id"])
        for child in value.values():
            found.update(event_ids(child))
    elif isinstance(value, list):
        for child in value:
            found.update(event_ids(child))
    return found


def check_file(path: Path, split: str, smoke: bool, registry: dict, report: dict) -> None:
    rows = 0
    task_counts: collections.Counter = collections.Counter()
    sources: collections.Counter = collections.Counter()
    for lineno, record in iter_jsonl(path):
        loc = f"{path}:{lineno}"
        for field in ("instruction", "input", "output"):
            if not isinstance(record.get(field), str) or not record[field].strip():
                raise ValueError(f"{loc}: {field} must be a nonempty string")
        meta = record.get("_meta")
        if not isinstance(meta, dict):
            raise ValueError(f"{loc}: missing _meta")
        for field in ("record_id", "source", "group_id", "label_status", "split"):
            if not isinstance(meta.get(field), str) or not meta[field].strip():
                raise ValueError(f"{loc}: missing _meta.{field}")
        if meta["split"] != split:
            raise ValueError(f"{loc}: _meta.split does not match {split}")
        valid_labels = {"source_label", "human_reviewed"} | ({"synthetic_smoke"} if smoke else set())
        if meta["label_status"] not in valid_labels:
            raise ValueError(f"{loc}: unapproved label_status {meta['label_status']}")
        record_id = meta["record_id"]
        if record_id in registry["records"]:
            raise ValueError(f"{loc}: duplicate record_id (also {registry['records'][record_id]})")
        registry["records"][record_id] = loc
        for key in ("group_id", "family_id"):
            identifier = meta.get(key)
            if identifier is None and key == "family_id":
                continue
            if not isinstance(identifier, str) or not identifier.strip():
                raise ValueError(f"{loc}: invalid {key}")
            old = registry[key].get(identifier)
            if old is not None and old != split:
                raise ValueError(f"{loc}: {key} spans {old} and {split}: {identifier}")
            registry[key][identifier] = split
        fingerprint = hashlib.sha256(
            (record["instruction"].strip() + "\n" + canonical_input(record["input"])).encode("utf-8")
        ).hexdigest()
        old = registry["inputs"].get(fingerprint)
        if old is not None and old != split:
            raise ValueError(f"{loc}: identical instruction/input occurs in {old} and {split}")
        registry["inputs"][fingerprint] = split
        try:
            inputs = json.loads(record["input"])
            output = json.loads(record["output"])
        except json.JSONDecodeError as exc:
            raise ValueError(f"{loc}: input/output must be JSON strings") from exc
        if not isinstance(inputs, dict) or not isinstance(output, dict):
            raise ValueError(f"{loc}: input/output JSON must be objects")
        if any(key in inputs for key in ("ground_truth", "true_label", "expected_answer", "answer_key")):
            raise ValueError(f"{loc}: top-level input contains a truth/answer field")
        if not isinstance(inputs.get("task_type"), str) or not inputs["task_type"]:
            raise ValueError(f"{loc}: missing input.task_type")
        stages = output.get("stages", [])
        if not isinstance(stages, list):
            raise ValueError(f"{loc}: output.stages must be a list")
        allowed_events = event_ids(inputs)
        top_refs = output.get("evidence_event_ids", [])
        if not isinstance(top_refs, list) or any(not isinstance(ref, str) for ref in top_refs):
            raise ValueError(f"{loc}: top-level evidence_event_ids must be a string list")
        if set(top_refs) - allowed_events:
            raise ValueError(f"{loc}: output references an event absent from input")
        for stage in stages:
            if not isinstance(stage, dict):
                raise ValueError(f"{loc}: each stage must be an object")
            refs = stage.get("evidence_event_ids", [])
            if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
                raise ValueError(f"{loc}: evidence_event_ids must be a string list")
            if set(refs) - allowed_events:
                raise ValueError(f"{loc}: a stage references an event absent from input")
        task_counts[inputs["task_type"]] += 1
        sources[meta["source"]] += 1
        rows += 1
    if not rows:
        raise ValueError(f"{path}: empty file")
    h = hashlib.sha256(path.read_bytes()).hexdigest()
    report[split] = {"rows": rows, "sha256": h, "task_counts": dict(task_counts), "sources": dict(sources)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--prefix", required=True, help="dataset registration prefix, e.g. cqsec_a")
    parser.add_argument("--test", type=Path, help="optional sealed test file (not registered for training)")
    parser.add_argument("--smoke", action="store_true", help="allow explicitly marked synthetic smoke examples")
    parser.add_argument("--register", action="store_true", help="write dataset_info.json after checks pass")
    args = parser.parse_args()
    if not args.prefix.replace("_", "").isalnum():
        parser.error("prefix must contain only letters, digits, or underscore")
    registry = {"records": {}, "group_id": {}, "family_id": {}, "inputs": {}}
    report = {}
    for split in ("train", "dev"):
        check_file(args.data_dir / f"{split}.jsonl", split, args.smoke, registry, report)
    if args.test:
        check_file(args.test, "test", args.smoke, registry, report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if not args.test:
        print("注意: 本次未检查封存测试集；不等于完成跨集泄漏审计。")
    if args.register:
        info = {
            f"{args.prefix}_{split}": {
                "file_name": f"{split}.jsonl",
                "formatting": "alpaca",
                "columns": {"prompt": "instruction", "query": "input", "response": "output"},
            }
            for split in ("train", "dev")
        }
        target = args.data_dir / "dataset_info.json"
        if target.exists():
            old = json.loads(target.read_text(encoding="utf-8"))
            if old != info:
                raise ValueError(f"{target} already exists with different contents; not overwritten")
        else:
            target.write_text(json.dumps(info, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"注册已就绪: {target}")
    print("结构校验通过。标签正确性、场景谱系和近重复仍须人工/专项审计。")


if __name__ == "__main__":
    main()
