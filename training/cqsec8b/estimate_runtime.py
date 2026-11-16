"""Estimate training time from two actual LlamaFactory optimizer-step logs."""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path


def duration(value: str) -> float:
    text = str(value).strip()
    days = 0
    if "day" in text:
        first, text = text.split(",", 1)
        days = int(first.strip().split()[0])
    parts = [int(x) for x in text.strip().split(":")]
    if len(parts) != 3:
        raise ValueError(f"unexpected elapsed_time: {value}")
    return days * 86400 + parts[0] * 3600 + parts[1] * 60 + parts[2]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--samples", type=int, required=True)
    parser.add_argument("--epochs", type=float, default=1.0)
    parser.add_argument("--batch", type=int, default=1)
    parser.add_argument("--grad-accum", type=int, default=16)
    parser.add_argument("--gpus", type=int, default=1)
    parser.add_argument("--from-step", type=int, default=20)
    parser.add_argument("--to-step", type=int, default=40)
    args = parser.parse_args()
    if min(args.samples, args.batch, args.grad_accum, args.gpus) <= 0 or args.epochs <= 0:
        parser.error("samples, epochs, batch, grad-accum and gpus must be positive")
    logs = [json.loads(line) for line in args.log.read_text(encoding="utf-8").splitlines() if line.strip()]
    by_step = {x.get("current_steps"): x for x in logs if x.get("elapsed_time") is not None}
    if args.from_step not in by_step or args.to_step not in by_step or args.to_step <= args.from_step:
        raise SystemExit("训练日志中缺少指定的两个步骤；请查看实际 current_steps 后重新指定。")
    seconds = duration(by_step[args.to_step]["elapsed_time"]) - duration(by_step[args.from_step]["elapsed_time"])
    if seconds <= 0:
        raise SystemExit("两条日志的耗时无法用于估算。")
    per_step = seconds / (args.to_step - args.from_step)
    effective_batch = args.batch * args.grad_accum * args.gpus
    steps = math.ceil(args.samples * args.epochs / effective_batch)
    print(json.dumps({"measured_step_interval": [args.from_step, args.to_step], "seconds_per_step": per_step,
                      "samples": args.samples, "epochs": args.epochs, "effective_batch": effective_batch,
                      "estimated_optimizer_steps": steps, "estimated_training_hours": steps * per_step / 3600,
                      "excluded": "model loading, download, data preprocessing, evaluation, checkpoint saves, and variable sequence lengths"},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
