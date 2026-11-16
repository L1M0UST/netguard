"""Copy a pilot set and select a reproducible, stratified small dev subset."""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import random
import shutil
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-dev", type=int, default=300)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if args.max_dev <= 0:
        parser.error("--max-dev must be positive")
    if args.output.exists() and any(args.output.iterdir()):
        raise SystemExit(f"输出目录非空，未覆盖: {args.output}")
    with (args.input / "dev.jsonl").open(encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream if line.strip()]
    if len(rows) < args.max_dev:
        raise ValueError(f"开发集只有 {len(rows)} 行，少于 {args.max_dev}")
    buckets = collections.defaultdict(list)
    for row in rows:
        label = json.loads(row["output"])["attack_family"]
        buckets[(row["_meta"].get("source_file", "unknown"), label)].append(row)
    rng = random.Random(args.seed)
    for bucket in buckets.values():
        rng.shuffle(bucket)
    selected = []
    while len(selected) < args.max_dev:
        progress = False
        for key in sorted(buckets):
            if buckets[key] and len(selected) < args.max_dev:
                selected.append(buckets[key].pop())
                progress = True
        if not progress:
            break
    rng.shuffle(selected)
    args.output.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.input / "train.jsonl", args.output / "train.jsonl")
    if (args.input / "test.jsonl").is_file():
        shutil.copyfile(args.input / "test.jsonl", args.output / "test.jsonl")
    (args.output / "dev.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in selected), encoding="utf-8")
    source_hash = hashlib.sha256((args.input / "dev.jsonl").read_bytes()).hexdigest()
    report = {"status": "pilot_only", "source_dev_rows": len(rows), "selected_dev_rows": len(selected),
              "source_dev_sha256": source_hash, "seed": args.seed,
              "strata": dict(collections.Counter(row["_meta"].get("source_file", "unknown") + "|" +
                                                  json.loads(row["output"])["attack_family"] for row in selected)),
              "note": "Small dev subset for training diagnostics; retain the full dev set for later evaluation."}
    (args.output / "subset_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
