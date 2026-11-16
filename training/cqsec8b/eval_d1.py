"""Directly evaluate the D1 draft's m1_judge_v2 schema on a CUDA GPU.

This is a project-specific provisional check, not an official leaderboard.
Every record stays in the denominator, including invalid and too-long outputs.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import random
import time
from pathlib import Path


FAMILIES = ("normal", "xss", "sql_injection", "command_injection", "local_file_inclusion", "ssrf")


def build_prompt(tokenizer, request: str, template: str) -> str:
    if template == "lf_nothink":
        # LlamaFactory v0.9.4 qwen3_nothink: no default system or <think> prefix.
        return f"<|im_start|>user\n{request}<|im_end|>\n<|im_start|>assistant\n"
    return tokenizer.apply_chat_template([{"role": "user", "content": request}], tokenize=False,
                                         add_generation_prompt=True, enable_thinking=False)


def read_rows(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def sample_rows(rows: list[dict], limit: int, seed: int) -> list[dict]:
    if limit <= 0 or limit >= len(rows):
        return rows
    rng = random.Random(seed)
    buckets: dict[str, list[dict]] = collections.defaultdict(list)
    for row in rows:
        label = json.loads(row["output"]).get("attack_family")
        buckets[str(label)].append(row)
    for bucket in buckets.values():
        rng.shuffle(bucket)
    picked = []
    order = sorted(buckets)
    while len(picked) < limit:
        progress = False
        for label in order:
            if buckets[label] and len(picked) < limit:
                picked.append(buckets[label].pop())
                progress = True
        if not progress:
            break
    rng.shuffle(picked)
    return picked


def metrics(predictions: list[dict]) -> dict:
    class_metrics = {}
    for family in FAMILIES:
        tp = sum(p["truth"] == family and p["predicted_family"] == family for p in predictions)
        fp = sum(p["truth"] != family and p["predicted_family"] == family for p in predictions)
        fn = sum(p["truth"] == family and p["predicted_family"] != family for p in predictions)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        class_metrics[family] = {"support": tp + fn, "tp": tp, "fp": fp, "fn": fn,
                                 "precision": precision, "recall": recall, "f1": f1}
    normal = [p for p in predictions if p["truth"] == "normal"]
    attacks = [p for p in predictions if p["truth"] != "normal"]
    present = [family for family in FAMILIES if class_metrics[family]["support"] > 0]
    def rate(items: list[dict], predicate) -> float | None:
        return sum(bool(predicate(item)) for item in items) / len(items) if items else None
    return {
        "samples": len(predictions),
        "family_accuracy_all_samples": sum(p["truth"] == p["predicted_family"] for p in predictions) / max(1, len(predictions)),
        "macro_f1_present_classes": sum(class_metrics[x]["f1"] for x in present) / len(present) if present else None,
        "macro_f1_six_classes": sum(class_metrics[x]["f1"] for x in FAMILIES) / len(FAMILIES) if len(present) == len(FAMILIES) else None,
        "normal_flagged_malicious_rate": rate(normal, lambda p: p["verdict"] == "malicious"),
        "attack_predicted_benign_rate": rate(attacks, lambda p: p["verdict"] == "benign"),
        "normal_review_or_invalid_rate": rate(normal, lambda p: p["verdict"] not in {"benign", "malicious"}),
        "attack_review_or_invalid_rate": rate(attacks, lambda p: p["verdict"] not in {"benign", "malicious"}),
        "status_counts": dict(collections.Counter(p["status"] for p in predictions)),
        "per_class": class_metrics,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True, help="local, unquantized base model directory")
    parser.add_argument("--adapter", help="local adapter directory; omit for base comparison")
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--source-file", action="append", help="filter to this D1 source filename; repeatable")
    parser.add_argument("--output", type=Path, required=True, help="new, empty results directory")
    parser.add_argument("--max-samples", type=int, default=120, help="stratified sample; 0 means all")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-input-tokens", type=int, default=2048)
    parser.add_argument("--max-new-tokens", type=int, default=256)
    parser.add_argument("--template", choices=["lf_nothink", "qwen_official_nothink"], default="lf_nothink")
    args = parser.parse_args()
    if args.max_samples < 0 or args.max_input_tokens < 1 or args.max_new_tokens < 1:
        parser.error("sample/token limits must be nonnegative and token limits positive")
    args.output.mkdir(parents=True, exist_ok=False)
    rows = read_rows(args.data)
    if args.source_file:
        rows = [r for r in rows if r.get("_meta", {}).get("source_file") in args.source_file]
    rows = sample_rows(rows, args.max_samples, args.seed)
    if not rows:
        raise SystemExit("dataset is empty")
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    if not torch.cuda.is_available():
        raise SystemExit("CUDA GPU unavailable; no inference performed")
    tokenizer = AutoTokenizer.from_pretrained(args.model, local_files_only=True, trust_remote_code=False)
    quant = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True,
                               bnb_4bit_compute_dtype=torch.bfloat16)
    model = AutoModelForCausalLM.from_pretrained(args.model, local_files_only=True, trust_remote_code=False,
                                                  quantization_config=quant, device_map={"": 0})
    if args.adapter:
        from peft import PeftModel
        model = PeftModel.from_pretrained(model, args.adapter, is_trainable=False)
    model.eval()
    predictions = []
    started = time.monotonic()
    for i, row in enumerate(rows, 1):
        truth = json.loads(row["output"])["attack_family"]
        request = row["instruction"] + "\n" + row["input"]
        prompt = build_prompt(tokenizer, request, args.template)
        batch = tokenizer(prompt, return_tensors="pt", add_special_tokens=False)
        input_tokens = int(batch["input_ids"].shape[-1])
        result = {"record_id": row.get("_meta", {}).get("record_id"),
                  "source_file": row.get("_meta", {}).get("source_file"), "truth": truth,
                  "predicted_family": "invalid", "verdict": "invalid", "status": "invalid",
                  "input_tokens": input_tokens, "output_tokens": 0, "raw_output": ""}
        if input_tokens > args.max_input_tokens:
            result["status"] = "input_too_long"
        else:
            batch = {k: v.to("cuda:0") for k, v in batch.items()}
            try:
                with torch.inference_mode():
                    generated = model.generate(**batch, max_new_tokens=args.max_new_tokens,
                                               do_sample=False, pad_token_id=tokenizer.eos_token_id)
                new = generated[0, input_tokens:]
                text = tokenizer.decode(new, skip_special_tokens=True).strip()
                result["raw_output"] = text
                result["output_tokens"] = int(new.shape[0])
                obj = json.loads(text)
                if not isinstance(obj, dict) or obj.get("verdict") not in {"malicious", "benign", "suspicious", "unknown"}:
                    raise ValueError("invalid object or verdict")
                family = obj.get("attack_family")
                if not isinstance(family, str) or not family:
                    raise ValueError("invalid attack_family")
                result.update({"predicted_family": family, "verdict": obj["verdict"], "status": "ok"})
            except (ValueError, TypeError, RuntimeError) as exc:
                result["status"] = "inference_or_parse_error:" + type(exc).__name__
        predictions.append(result)
        if i % 10 == 0 or i == len(rows):
            print(f"evaluated {i}/{len(rows)}", flush=True)
    summary = metrics(predictions)
    by_source = {}
    for source in sorted({str(x.get("source_file") or "unknown") for x in predictions}):
        subset = [x for x in predictions if (x.get("source_file") or "unknown") == source]
        by_source[source] = metrics(subset)
    summary.update({"dataset_sha256": hashlib.sha256(args.data.read_bytes()).hexdigest(), "model": args.model,
                    "adapter": args.adapter, "seed": args.seed, "max_samples": args.max_samples,
                    "source_files": args.source_file, "by_source": by_source,
                    "template": args.template,
                    "max_input_tokens": args.max_input_tokens, "max_new_tokens": args.max_new_tokens,
                    "elapsed_seconds": time.monotonic() - started,
                    "note": "D1 draft labels; stratified sample if max_samples > 0; not official benchmark"})
    (args.output / "predictions.jsonl").write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in predictions), encoding="utf-8")
    (args.output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
