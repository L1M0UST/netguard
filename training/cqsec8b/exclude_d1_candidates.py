"""Conservatively copy a D1 draft and exclude specified training groups.

This cannot establish clean data; it removes the supplied record IDs (for
example approximate-audit candidates or overlength samples) and their groups.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import shutil
from pathlib import Path


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--draft", type=Path, required=True)
    parser.add_argument("--flagged-ids", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() and any(args.output.iterdir()):
        raise SystemExit(f"输出目录非空，未覆盖: {args.output}")
    ids = {line.strip() for line in args.flagged_ids.read_text(encoding="utf-8").splitlines() if line.strip()}
    with (args.draft / "train.jsonl").open(encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream if line.strip()]
    available = {row["_meta"]["record_id"] for row in rows}
    missing = ids - available
    if missing:
        raise ValueError(f"flagged ID absent from train: {len(missing)}")
    groups = {row["_meta"]["group_id"] for row in rows if row["_meta"]["record_id"] in ids}
    args.output.mkdir(parents=True, exist_ok=True)
    kept, removed, labels = 0, 0, collections.Counter()
    with (args.output / "train.jsonl").open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            if row["_meta"]["group_id"] in groups:
                removed += 1
                continue
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
            labels[json.loads(row["output"])["attack_family"]] += 1
            kept += 1
    for split in ("dev", "test"):
        shutil.copyfile(args.draft / f"{split}.jsonl", args.output / f"{split}.jsonl")
    report = {"status": "pilot_only_training_exclusions_applied_not_formal_approval",
              "candidate_train_ids": len(ids), "candidate_groups": len(groups),
              "train_rows_removed": removed, "train_rows_kept": kept, "label_counts": dict(labels),
              "flagged_ids_sha256": sha(args.flagged_ids),
              "note": "All specified IDs were excluded conservatively; near-duplicate audit may miss variants or flag false positives."}
    (args.output / "filter_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
