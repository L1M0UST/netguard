"""Measure Qwen token lengths for the exact LlamaFactory qwen3_nothink format."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path


def percentile(values: list[int], p: float) -> int:
    values = sorted(values)
    return values[max(0, min(len(values)-1, math.ceil(p * len(values)) - 1))]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tokenizer", required=True)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--cutoff", type=int, default=2048)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.cutoff <= 0:
        parser.error("cutoff must be positive")
    if args.output.exists():
        raise SystemExit(f"报告已存在，未覆盖: {args.output}")
    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(args.tokenizer, local_files_only=True, trust_remote_code=False)
    report = {"tokenizer": args.tokenizer, "template": "LlamaFactory v0.9.4 qwen3_nothink",
              "cutoff_len": args.cutoff, "splits": {}}
    for split in ("train", "dev"):
        path = args.data_dir / f"{split}.jsonl"
        with path.open(encoding="utf-8") as stream:
            rows = [json.loads(line) for line in stream if line.strip()]
        if not rows:
            raise ValueError(f"empty dataset: {path}")
        totals, prompt_lens = [], []
        for start in range(0, len(rows), 64):
            batch = rows[start:start + 64]
            prompts = ["<|im_start|>user\n" + row["instruction"] + "\n" + row["input"] +
                       "<|im_end|>\n<|im_start|>assistant\n" for row in batch]
            full = [p + row["output"] + "<|im_end|>\n" for p, row in zip(prompts, batch)]
            prompt_ids = tokenizer(prompts, add_special_tokens=False)["input_ids"]
            full_ids = tokenizer(full, add_special_tokens=False)["input_ids"]
            prompt_lens.extend(len(x) for x in prompt_ids)
            totals.extend(len(x) for x in full_ids)
        report["splits"][split] = {
            "rows": len(rows), "file_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "mean_total_tokens": round(sum(totals) / len(totals), 1),
            "p50_total_tokens": percentile(totals, .50), "p95_total_tokens": percentile(totals, .95),
            "p99_total_tokens": percentile(totals, .99), "max_total_tokens": max(totals),
            "p95_prompt_tokens": percentile(prompt_lens, .95),
            "rows_over_cutoff": sum(length > args.cutoff for length in totals),
            "over_cutoff_records": [
                {"record_id": row.get("_meta", {}).get("record_id"),
                 "source_file": row.get("_meta", {}).get("source_file"),
                 "total_tokens": total, "prompt_tokens": prompt}
                for row, total, prompt in zip(rows, totals, prompt_lens) if total > args.cutoff
            ][:100],
        }
    report["note"] = "Counts full prompt and answer with the pinned tokenizer; above cutoff requires truncation/inspection."
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
