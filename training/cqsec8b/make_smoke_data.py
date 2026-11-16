"""Create clearly marked synthetic data for a five-step environment smoke run."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    for split in ("train", "dev"):
        target = args.output / f"{split}.jsonl"
        if target.exists():
            raise SystemExit(f"目标文件已存在，未覆盖: {target}")
    for split, count in (("train", 32), ("dev", 8)):
        target = args.output / f"{split}.jsonl"
        records = []
        for i in range(count):
            sample_id = f"smoke-{split}-{i:03d}"
            inp = {"task_type": "smoke_only", "events": [{"event_id": sample_id,
                   "message": f"合成的无真实安全事件的环境测试记录 {split}-{i:03d}"}]}
            out = {"verdict": "unknown", "evidence_event_ids": [sample_id],
                   "uncertainties": ["仅用于环境冒烟，不用于业务训练"]}
            records.append({"instruction": "读取演示输入并返回 JSON。此样本仅用于环境测试。",
                            "input": json.dumps(inp, ensure_ascii=False),
                            "output": json.dumps(out, ensure_ascii=False),
                            "_meta": {"record_id": sample_id, "source": "synthetic_smoke",
                                      "group_id": sample_id, "label_status": "synthetic_smoke",
                                      "split": split}})
        target.write_text("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in records), encoding="utf-8")
        print(f"created {target}: {count} synthetic examples")


if __name__ == "__main__":
    main()
