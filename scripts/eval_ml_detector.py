"""ML 检测器真实管线两臂对照（M1 初筛口径，含会话聚合）。

同一冻结测试 split 写 CSV 后，在两个隔离工作区各跑一次真实 M1 管线：
  baseline = ml_detector.enabled=false（纯规则）
  treatment = ml_detector.enabled=true（规则+ML 融合）
再用 competition_acceptance 的逐行预测口径打分对照：
  per-class P/R/F1、macro-F1、multiclass acc、二分类 FPR（融合口径），
  以及 ML 新增告警 precision（基线未告警而融合告警的行对照真值）。

用法：
  .venv/Scripts/python.exe scripts/eval_ml_detector.py \
      --input "E:/platform_taishi/赛题2：网络安全态势智能感知.xlsx" \
      --out docs/evidence/ml_detector_pipeline_eval.json
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "scripts"))

from competition_acceptance import _find_ready, m1_predictions, score_predictions  # noqa: E402
from m1.ml_split import (  # noqa: E402
    label_distribution, read_official_rows, split_rows, write_split_csv,
)

TASK_BASELINE = "ml_eval_base"
TASK_TREATMENT = "ml_eval_ml"


def run_arm(rows_csv: Path, workroot: Path, task_id: str, ml_enabled: bool) -> Path:
    """在隔离工作区跑一次真实 M1 管线，返回 ready 目录。"""
    from m1.run import process_task

    workspace = workroot / task_id
    shutil.rmtree(workspace, ignore_errors=True)
    (workspace / "m1").mkdir(parents=True)
    (workspace / "m1" / "config.json").write_text(json.dumps({
        "ml_detector": {"enabled": ml_enabled},
        "output": {"format": "parquet", "require_parquet": True},
    }), encoding="utf-8")
    (workspace / "incoming").mkdir()
    target = workspace / "incoming" / rows_csv.name
    shutil.copyfile(rows_csv, target)
    started = time.perf_counter()
    ready = process_task(workspace, {"task_id": task_id, "input_files": [f"incoming/{rows_csv.name}"]})
    elapsed = time.perf_counter() - started
    assert (ready / "READY.json").is_file()
    print(f"[arm] {task_id}: ml={'on ' if ml_enabled else 'off'} elapsed={elapsed:.1f}s ready={ready.name}")
    return ready


def ml_new_alert_report(truth: list[str], base_pred: list[str], base_alerts: list[bool],
                        ml_pred: list[str], ml_alerts: list[bool]) -> dict:
    from collections import Counter

    from bridge.labels import LABEL_NORMAL

    new_truth = Counter()
    type_hit = 0
    for actual, was_alert, is_alert, prediction in zip(truth, base_alerts, ml_alerts, ml_pred, strict=True):
        if is_alert and not was_alert:
            new_truth[actual] += 1
            if actual == prediction:
                type_hit += 1
    count = sum(new_truth.values())
    true_attack = sum(n for label, n in new_truth.items() if label != LABEL_NORMAL)
    return {
        "count": count,
        "true_attack_ratio": (true_attack / count) if count else None,
        "type_hit_ratio": (type_hit / count) if count else None,
        "by_truth_label": dict(new_truth),
        "note": "新增告警=纯规则未告警而规则+ML 告警的行（会话聚合口径）；true_attack_ratio 对真值统计",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Two-arm pipeline evaluation for the ML detector")
    parser.add_argument("--input", type=Path,
                        default=PROJECT.parent / "赛题2：网络安全态势智能感知.xlsx")
    parser.add_argument("--out", type=Path, default=PROJECT / "docs" / "evidence" / "ml_detector_pipeline_eval.json")
    parser.add_argument("--workroot", type=Path, default=PROJECT / ".test-workspaces" / "ml_eval")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if args.out.exists():
        raise FileExistsError(f"refusing to overwrite report: {args.out}")

    headers, rows = read_official_rows(args.input)
    splits, stats = split_rows(rows, seed=args.seed)
    test_rows = splits["test"]
    split_dir = args.workroot / "splits"
    test_csv = split_dir / "test.csv"
    write_split_csv(test_rows, headers, test_csv)
    print(f"[split] test={len(test_rows)} 行 | 分布 {label_distribution(test_rows, headers)}")

    base_ready = run_arm(test_csv, args.workroot, TASK_BASELINE, ml_enabled=False)
    ml_ready = run_arm(test_csv, args.workroot, TASK_TREATMENT, ml_enabled=True)

    base = m1_predictions(test_csv, base_ready)
    ml = m1_predictions(test_csv, ml_ready)
    base_metrics = score_predictions(base["truth"], base["predictions"], base["alerts"])
    ml_metrics = score_predictions(ml["truth"], ml["predictions"], ml["alerts"])
    ml_status = (ml["batch"].get("status") or {}).get("ml_detector") or {}

    rce = "远程命令执行攻击"
    report = {
        "schema_version": "NetGuardMLPipelineEval.v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "input": str(args.input),
        "seed": args.seed,
        "split": {**stats, "test_label_distribution": label_distribution(test_rows, headers)},
        "baseline_rules_only": base_metrics,
        "treatment_rules_plus_ml": ml_metrics,
        "delta": {
            "rce_recall": {k: (base_metrics["per_class"].get(rce) or {}).get(k) for k in ("support", "precision", "recall", "f1")},
            "rce_recall_treatment": {k: (ml_metrics["per_class"].get(rce) or {}).get(k) for k in ("precision", "recall", "f1")},
            "multiclass_accuracy": {k: v for k, v in (("baseline", base_metrics["multiclass_accuracy"]),
                                                       ("treatment", ml_metrics["multiclass_accuracy"]))},
            "macro_f1": {k: v for k, v in (("baseline", base_metrics["macro_f1"]),
                                            ("treatment", ml_metrics["macro_f1"]))},
            "binary_fpr": {k: v for k, v in (("baseline", base_metrics["binary_attack_detection"]["false_positive_rate"]),
                                              ("treatment", ml_metrics["binary_attack_detection"]["false_positive_rate"]))},
        },
        "ml_detector_status": ml_status,
        "ml_new_alerts": ml_new_alert_report(base["truth"], base["predictions"], base["alerts"],
                                             ml["predictions"], ml["alerts"]),
        "note": ("两臂均为真实 M1 管线（含会话聚合/频率加权/扫描检测）；llm 默认关闭，"
                 "分类指标只代表 M1 初筛。冻结口径与 scripts/train_ml_detector.py 一致（seed=%d）。" % args.seed),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")

    print("\n===== 真实管线两臂对照（冻结测试 split，含会话聚合） =====")
    print(f"[eval] baseline acc={base_metrics['multiclass_accuracy']:.4f} macroF1={base_metrics['macro_f1']:.4f} "
          f"FPR={base_metrics['binary_attack_detection']['false_positive_rate']:.4f}")
    print(f"[eval] treatment acc={ml_metrics['multiclass_accuracy']:.4f} macroF1={ml_metrics['macro_f1']:.4f} "
          f"FPR={ml_metrics['binary_attack_detection']['false_positive_rate']:.4f}")
    print(f"[eval] RCE recall: {(base_metrics['per_class'].get(rce) or {}).get('recall')} -> {(ml_metrics['per_class'].get(rce) or {}).get('recall')}")
    print(f"[eval] ML 新增告警 {report['ml_new_alerts']['count']} 行 | 真实攻击占比 {report['ml_new_alerts']['true_attack_ratio']} | "
          f"类型命中 {report['ml_new_alerts']['type_hit_ratio']}")
    print(f"[eval] ml_detector status: {ml_status.get('status')} calls={ml_status.get('calls')}")
    print(f"[eval] 报告已写: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
