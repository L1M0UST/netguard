"""Find approximate D1 train-versus-dev/test candidate overlaps.

Uses MinHash/LSH and verifies token-shingle Jaccard for returned candidates.
This is a bounded candidate generator, not proof of comprehensive deduplication.
"""
from __future__ import annotations

import argparse
import collections
import csv
import html
import json
import re
import urllib.parse
from pathlib import Path

from datasketch import MinHash, MinHashLSH


def tokens(row: dict) -> frozenset[str]:
    data = json.loads(row["input"])
    event = (data.get("events") or [{}])[0]
    output = set()
    for name, value in (("url", event.get("url") or ""), ("body", event.get("request_body") or "")):
        text = html.unescape(str(value))
        for _ in range(2):
            decoded = urllib.parse.unquote(text)
            if decoded == text:
                break
            text = decoded
        # Long fields are skipped rather than silently comparing truncated content.
        if len(text) > 8192:
            return frozenset()
        words = re.findall(r"[a-z_]+|\d+|[^\w\s]", text.casefold())
        words = ["<number>" if w.isdigit() and len(w) >= 3 else w for w in words]
        if len(words) >= 3:
            output.update(name + ":" + " ".join(words[i:i+3]) for i in range(len(words)-2))
    return frozenset(output)


def signature(features: frozenset[str], num_perm: int) -> MinHash:
    mh = MinHash(num_perm=num_perm, seed=42)
    mh.update_batch([item.encode("utf-8") for item in features])
    return mh


def read(path: Path):
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--threshold", type=float, default=0.85)
    parser.add_argument("--num-perm", type=int, default=64)
    parser.add_argument("--candidate-cap", type=int, default=64, help="max candidate comparisons per training row")
    args = parser.parse_args()
    if not 0.5 <= args.threshold <= 1 or args.num_perm < 16 or args.candidate_cap < 1:
        parser.error("invalid threshold, num-perm, or candidate cap")
    args.output.mkdir(parents=True, exist_ok=False)
    lsh = MinHashLSH(threshold=args.threshold, num_perm=args.num_perm)
    protected = {}
    counts = collections.Counter()
    for split in ("dev", "test"):
        for row in read(args.data_dir / f"{split}.jsonl"):
            features = tokens(row)
            if len(features) < 6:
                counts[split + "_not_indexed_short_or_long"] += 1
                continue
            key = str(len(protected))
            meta = row["_meta"]
            protected[key] = (features, meta["record_id"], split, meta["source_file"])
            lsh.insert(key, signature(features, args.num_perm))
            counts[split + "_indexed"] += 1
    flagged = set()
    comparisons = 0
    with (args.output / "candidate_pairs.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["train_record_id", "protected_record_id", "protected_split", "protected_file", "jaccard"])
        for row in read(args.data_dir / "train.jsonl"):
            counts["train_seen"] += 1
            features = tokens(row)
            if len(features) < 6:
                counts["train_not_queried_short_or_long"] += 1
                continue
            candidate_keys = sorted(lsh.query(signature(features, args.num_perm)), key=int)
            if len(candidate_keys) > args.candidate_cap:
                counts["train_candidate_list_capped"] += 1
            for key in candidate_keys[:args.candidate_cap]:
                other, record_id, split, filename = protected[key]
                comparisons += 1
                similarity = len(features & other) / len(features | other)
                if similarity >= args.threshold:
                    train_id = row["_meta"]["record_id"]
                    flagged.add(train_id)
                    counts["matching_pairs"] += 1
                    counts["pairs_to_" + split] += 1
                    writer.writerow([train_id, record_id, split, filename, f"{similarity:.4f}"])
            if counts["train_seen"] % 5000 == 0:
                print(f"checked {counts['train_seen']} train rows", flush=True)
    report = {"method": "decoded token-trigram shape MinHash/LSH; exact candidate Jaccard",
              "threshold": args.threshold, "num_perm": args.num_perm, "candidate_cap": args.candidate_cap,
              "counts": dict(counts), "candidate_comparisons": comparisons,
              "unique_train_rows_flagged": len(flagged),
              "limits": ["Approximate candidate search can miss near duplicates.",
                         "Numeric normalization may generate false positives; review candidates.",
                         "Short/long records and capped candidate lists were not exhaustively searched.",
                         "No cross-source audit outside D1 or semantic label review was performed."]}
    (args.output / "flagged_train_ids.txt").write_text("".join(x + "\n" for x in sorted(flagged)), encoding="utf-8")
    (args.output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
