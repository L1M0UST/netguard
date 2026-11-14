"""Reproducible, label-isolated competition acceptance run.

The full pipeline only receives the input file. Ground-truth labels are opened
after M1/M2/bundle finish, and are used only for offline scoring.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import statistics
import sys
import time
import uuid
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

from bridge.labels import LABEL_NORMAL, LABEL_PENDING, label_for  # noqa: E402
from m1.handoff import read_batch  # noqa: E402
from m1.quality import read_rows  # noqa: E402
from m1.run import is_ground_truth_header  # noqa: E402
from orchestrator import driver  # noqa: E402


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def local_model_metadata(base_url: str) -> dict[str, Any]:
    """Capture non-secret model identity exposed by an OpenAI-compatible server."""
    endpoint = base_url.rstrip("/") + "/models"
    try:
        request = urllib.request.Request(endpoint, headers={"Accept": "application/json"})
        with urllib.request.urlopen(request, timeout=3) as response:
            payload = json.loads(response.read().decode("utf-8"))
        models = payload.get("data") or payload.get("models") or []
        if not models:
            return {"available": False, "endpoint": endpoint, "reason": "no_model_records"}
        model = models[0]
        metadata = model.get("meta") or model.get("details") or {}
        return {
            "available": True,
            "model_id": model.get("id") or model.get("name") or model.get("model"),
            "owned_by": model.get("owned_by"),
            "parameter_count": metadata.get("n_params") or metadata.get("parameter_count"),
            "quantization": metadata.get("ftype") or metadata.get("quantization_level"),
            "size_bytes": metadata.get("size") or model.get("size"),
        }
    except (OSError, TimeoutError, urllib.error.URLError, ValueError, json.JSONDecodeError) as exc:
        return {"available": False, "endpoint": endpoint, "reason": type(exc).__name__}


def normalized_label(value: Any) -> str:
    label = str(value or "").strip()
    aliases = {"normal": LABEL_NORMAL, "benign": LABEL_NORMAL, "正常": LABEL_NORMAL,
               "正常访问": LABEL_NORMAL}
    label = aliases.get(label.lower(), label)
    if not label:
        raise ValueError("ground-truth label column contains an empty value")
    return label


def read_ground_truth(path: Path) -> tuple[str, list[str]]:
    if path.suffix.lower() in {".xlsx", ".xlsm"}:
        from openpyxl import load_workbook

        workbook = load_workbook(path, read_only=True, data_only=True)
        try:
            rows = workbook.active.iter_rows(values_only=True)
            headers = [str(value or "") for value in next(rows, ())]
            label_indexes = [index for index, field in enumerate(headers)
                             if is_ground_truth_header(field)]
            if len(label_indexes) != 1:
                raise ValueError(f"expected exactly one ground-truth column, found: {label_indexes}")
            label_index = label_indexes[0]
            truth = [normalized_label(row[label_index] if label_index < len(row) else None)
                     for row in rows]
            return headers[label_index], truth
        finally:
            workbook.close()
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        fields = reader.fieldnames or []
        label_fields = [field for field in fields if is_ground_truth_header(field)]
        if len(label_fields) != 1:
            raise ValueError(f"expected exactly one ground-truth column, found: {label_fields}")
        truth = [normalized_label(row.get(label_fields[0])) for row in reader]
    return label_fields[0], truth


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def score_batch(input_path: Path, ready_dir: Path) -> dict[str, Any]:
    """Compare offline truth to M1 decisions, using row references (not model input)."""
    label_field, truth = read_ground_truth(input_path)
    batch = read_batch(ready_dir)
    details = list(read_rows(ready_dir, batch, "event_details"))
    sessions = list(read_rows(ready_dir, batch, "all_sessions"))
    suspicious_ids = {str(row.get("session_id")) for row in
                      read_rows(ready_dir, batch, "suspicious_events")}
    event_row = {
        str(row.get("event_id")): int(row.get("source_row")) - 1
        for row in details if row.get("event_id") and row.get("source_row") is not None
    }
    predictions = [LABEL_NORMAL] * len(truth)  # dropped/whitelisted/duplicate rows are no-alert
    alerts = [False] * len(truth)
    assigned: set[int] = set()
    for session in sessions:
        suspicious = str(session.get("session_id")) in suspicious_ids
        label = label_for(session.get("rule_hits") or [], session.get("ioc_matches") or [])
        prediction = (label if label != LABEL_PENDING else "未知攻击") if suspicious else LABEL_NORMAL
        for event_id in session.get("related_event_ids") or [session.get("event_id")]:
            index = event_row.get(str(event_id))
            if index is None or index < 0 or index >= len(truth):
                continue
            predictions[index] = prediction
            alerts[index] = suspicious
            assigned.add(index)

    expected_classes = sorted(set(truth))
    matrix: dict[str, dict[str, int]] = {label: {pred: 0 for pred in expected_classes}
                                         for label in expected_classes}
    for actual, predicted in zip(truth, predictions, strict=True):
        if predicted not in expected_classes:
            continue
        matrix[actual][predicted] += 1
    per_class: dict[str, dict[str, float | int | None]] = {}
    f1_values: list[float] = []
    for label in expected_classes:
        tp = matrix[label][label]
        fp = sum(matrix[actual][label] for actual in expected_classes if actual != label)
        fn = sum(matrix[label][pred] for pred in expected_classes if pred != label)
        precision = _ratio(tp, tp + fp)
        recall = _ratio(tp, tp + fn)
        f1 = (2 * precision * recall / (precision + recall)
              if precision is not None and recall is not None and precision + recall else 0.0)
        f1_values.append(f1)
        per_class[label] = {"support": sum(matrix[label].values()), "precision": precision,
                            "recall": recall, "f1": f1}

    positive_actual = [label != LABEL_NORMAL for label in truth]
    tp = sum(a and p for a, p in zip(positive_actual, alerts, strict=True))
    fp = sum((not a) and p for a, p in zip(positive_actual, alerts, strict=True))
    fn = sum(a and (not p) for a, p in zip(positive_actual, alerts, strict=True))
    tn = sum((not a) and (not p) for a, p in zip(positive_actual, alerts, strict=True))
    profile_files = sorted((ready_dir / "mapping_plans").glob("*.json"))
    excluded_columns: set[str] = set()
    for path in profile_files:
        plan = json.loads(path.read_text(encoding="utf-8"))
        excluded_columns.update(plan.get("excluded_ground_truth_fields") or [])
        profile = plan.get("profile") or {}
        mapping = plan.get("mapping") or {}
        if any(field in profile.get("fields", {}) or field in mapping for field in (label_field,)):
            raise AssertionError("ground-truth column leaked into an M1 mapping artifact")
    if label_field not in excluded_columns:
        raise AssertionError("M1 did not explicitly record exclusion of the truth column")

    return {
        "scope": "offline_labeled_dataset_m1_screening_only",
        "label_column": label_field,
        "rows": len(truth),
        "predicted_from_m1_rows": len(assigned),
        "rows_without_an_m1_event_after_filters": len(truth) - len(assigned),
        "classes": expected_classes,
        "multiclass_accuracy": _ratio(sum(pred == actual for pred, actual in zip(predictions, truth, strict=True)), len(truth)),
        "macro_f1": statistics.fmean(f1_values) if f1_values else None,
        "per_class": per_class,
        "confusion_matrix_actual_by_predicted": matrix,
        "binary_attack_detection": {
            "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
            "precision": _ratio(tp, tp + fp), "recall": _ratio(tp, tp + fn),
            "f1": (2 * tp / (2 * tp + fp + fn)) if 2 * tp + fp + fn else None,
            "false_positive_rate": _ratio(fp, fp + tn),
        },
        "unknown_attack_predictions": predictions.count("未知攻击"),
        "ground_truth_excluded_before_analysis": label_field in excluded_columns,
        "mapping_plan_files_checked": len(profile_files),
        "m1_rule_version": batch.get("status", {}).get("rule_version"),
        "m1_model_version": batch.get("status", {}).get("model_version"),
        "m1_llm_provider_calls": batch.get("status", {}).get("llm_provider_calls", {}),
        "m1_cascade": batch.get("status", {}).get("metrics", {}).get("cascade", {}),
    }


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    sorted_values = sorted(values)
    return sorted_values[max(0, math.ceil(fraction * len(sorted_values)) - 1)]


def _find_ready(workspace: Path, task_id: str) -> Path:
    root = workspace / "m1" / "ready" / f"batch-{task_id}"
    runs = sorted((path for path in root.iterdir() if path.is_dir()),
                  key=lambda path: path.stat().st_mtime, reverse=True)
    if not runs:
        raise FileNotFoundError(f"no M1 ready batch for task {task_id}")
    return runs[0]


def run_acceptance(input_path: Path, workspace: Path, repeat: int) -> dict[str, Any]:
    input_path = input_path.resolve()
    workspace = workspace.resolve()
    if repeat < 1 or repeat > 5:
        raise ValueError("repeat must be between 1 and 5")
    env = {**os.environ, **driver._load_env(PROJECT / ".env")}
    run_records: list[dict[str, Any]] = []
    first_score: dict[str, Any] | None = None
    for index in range(repeat):
        started = time.perf_counter()
        task_id = driver.run_file(workspace, input_path, env, sys.executable,
                                  analysis_mode="local")
        elapsed = round(time.perf_counter() - started, 3)
        marker_dir = workspace / "orchestrator"
        if not (marker_dir / f"{task_id}.done").is_file():
            failure = marker_dir / f"{task_id}.failed"
            detail = failure.read_text(encoding="utf-8") if failure.is_file() else "no completion marker"
            raise RuntimeError(f"full pipeline failed for {task_id}: {detail}")
        ready_dir = _find_ready(workspace, task_id)
        batch = read_batch(ready_dir)
        status = batch.get("status") or {}
        metrics = status.get("metrics") or {}
        bundle_path = workspace / "m2" / "READY" / task_id / "bundle.json"
        bundle = json.loads(bundle_path.read_text(encoding="utf-8")) if bundle_path.is_file() else {}
        if not bundle:
            raise RuntimeError(f"full pipeline completed without a bundle: {bundle_path}")
        done_path = marker_dir / f"{task_id}.done"
        done_record = json.loads(done_path.read_text(encoding="utf-8"))
        stage_timings = done_record.get("timings") or bundle.get("metrics", {})
        m2_metrics_path = workspace / "05_m2_output" / f"task_{task_id}" / "metrics.json"
        m2_metrics = json.loads(m2_metrics_path.read_text(encoding="utf-8")) if m2_metrics_path.is_file() else {}
        m2_stage_totals: dict[str, float] = {}
        for stage in m2_metrics.get("stage_timings", []):
            name = str(stage.get("stage") or "unknown")
            m2_stage_totals[name] = round(m2_stage_totals.get(name, 0.0) + float(stage.get("duration_ms") or 0.0) / 1000, 4)
        run_records.append({
            "task_id": task_id,
            "elapsed_seconds": elapsed,
            "input_rows": metrics.get("input_records"),
            "m1_normalized_rows": metrics.get("normalized_records"),
            "m1_suspicious_sessions": metrics.get("suspicious_sessions"),
            "m1_filter_counts": {key: metrics.get(key, 0) for key in
                                  ("filtered_empty", "filtered_meaningless", "filtered_duplicate", "filtered_whitelist")},
            "m1_duration_seconds": bundle.get("metrics", {}).get("m1_duration_seconds"),
            "m1_plus_bridge_m2_bundle_seconds": bundle.get("metrics", {}).get("duration_seconds", elapsed),
            "m2_duration_seconds": bundle.get("metrics", {}).get("m2_duration_seconds"),
            "stage_breakdown_seconds": {
                "m1_parse_screen_and_model": stage_timings.get("m1_seconds"),
                "bridge_export": stage_timings.get("bridge_seconds"),
                "m2_process_including_startup_and_output": stage_timings.get("m2_process_seconds"),
                "m2_internal_total": round(float(m2_metrics.get("total_duration_ms") or 0) / 1000, 3),
                "m2_internal_stages": m2_stage_totals,
                "bundle_assembly_and_summary": stage_timings.get("bundle_assembly_seconds"),
                "orchestrator_overhead": stage_timings.get("orchestrator_overhead_seconds"),
                "end_to_end": stage_timings.get("end_to_end_seconds", elapsed),
            },
            "m1_cascade": metrics.get("cascade", {}),
            "m1_model_version": status.get("model_version"),
            "m1_llm_provider_calls": status.get("llm_provider_calls", {}),
            "m2_chain_count": bundle.get("metrics", {}).get("chain_count", bundle.get("statistics", {}).get("chain_count")),
            "bundle_present": bool(bundle),
        })
        if first_score is None:
            first_score = score_batch(input_path, ready_dir)
    elapsed_values = [float(item["elapsed_seconds"]) for item in run_records]
    rows = int(run_records[0].get("input_rows") or 0)
    return {
        "schema_version": "NetGuardCompetitionAcceptance.v2",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "mode": "local_m1_and_deterministic_m2",
        "input_file": str(input_path),
        "input_sha256": sha256(input_path),
        "repetitions": repeat,
        "environment": {"python": sys.version, "platform": sys.platform,
                        "local_model_base_url": env.get("CQSEC_BASE_URL", "http://127.0.0.1:8008/v1"),
                        "local_model_runtime": local_model_metadata(env.get("CQSEC_BASE_URL", "http://127.0.0.1:8008/v1"))},
        "performance": {
            "input_rows": rows,
            "median_elapsed_seconds": statistics.median(elapsed_values),
            "p95_elapsed_seconds": percentile(elapsed_values, 0.95),
            "median_input_throughput_events_per_second":
                round(rows / statistics.median(elapsed_values), 2) if elapsed_values and statistics.median(elapsed_values) else None,
            "runs": run_records,
            "timing_note": "End-to-end includes M1, Bridge, M2 and bundle assembly; M2 duration includes Bridge/assembly overhead in the current public metric split.",
        },
        "quality": first_score,
        "data_provenance": {
            "fixture_generator": "scripts/build_test_suite.py" if "suite" in input_path.parts else None,
            "fixture_seed": 20260922 if "suite" in input_path.parts else None,
            "official_or_synthetic": ("synthetic deterministic acceptance fixture; not an official blind test or production sample"
                                       if "suite" in input_path.parts else
                                       "team-provided labeled workbook present in the project; official source and redistribution/license terms were not independently verified"),
            "truth_handling": "the analyzer receives the original file but M1 removes the ground-truth column before schema profiling/mapping; this script reads that column only after all analysis is complete",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="NetGuard competition acceptance run")
    parser.add_argument("--input", type=Path, default=PROJECT / "tests_integration" / "fixtures" / "suite" / "01_main_10k.csv")
    parser.add_argument("--workspace", type=Path, required=True, help="fresh or reusable isolated workspace")
    parser.add_argument("--repeat", type=int, default=3, help="1-5 full local-only repetitions; later runs may reuse local answer cache")
    parser.add_argument("--output", type=Path, required=True, help="new JSON evidence file (must not already exist)")
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(f"refusing to overwrite evidence file: {args.output}")
    result = run_acceptance(args.input, args.workspace, args.repeat)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(args.output.resolve()), "input_rows": result["performance"]["input_rows"],
                      "median_seconds": result["performance"]["median_elapsed_seconds"],
                      "p95_seconds": result["performance"]["p95_elapsed_seconds"],
                      "quality": result["quality"]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
