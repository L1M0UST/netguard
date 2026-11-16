"""第二层 LightGBM 检测器训练（m1-ml-1.0）。

流程：请求指纹分组切分 60/20/20 → 原生 LightGBM 多分类训练（60%）→
校准集逐类阈值（20%，precision>=min_precision 下 F1 最大，无合格阈值则禁用该类）→
测试集冻结评估（20%，事件级闸门：真实规则引擎基线 vs 规则+ML 融合）。

闸门口径：
- 事件级：每行过 m1.run.enrich（真实规则引擎）得到基线命中；融合臂在基线命中之上
  并入 ML 命中（白名单类别中模型分数最高且 >= 阈值者）。会话聚合影响由
  scripts/eval_ml_detector.py 的真实管线两臂对照另行验证，不在此混评。
- 正常访问永不命中；待研判（如 ioc_match/prompt_injection 单独命中）计为"未知攻击"漏判。
- 模型分数经 class_weight 配平、未经概率校准；阈值不是概率。

用法：
  .venv/Scripts/python.exe scripts/train_ml_detector.py \
      --input "E:/platform_taishi/赛题2：网络安全态势智能感知.xlsx"
"""
from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "scripts"))

import numpy as np  # noqa: E402

from bridge.labels import LABEL_NORMAL, LABEL_PENDING, label_for  # noqa: E402
from m1.ml_detector import DEFAULT_MODEL_DIR, META_FILE, MODEL_FILE, ML_DETECTOR_VERSION  # noqa: E402
from m1.ml_features import FEATURE_NAMES, ML_RULE_BY_LABEL, extract_features  # noqa: E402
from m1.ml_split import (  # noqa: E402
    label_distribution, read_official_rows, split_rows, truth_of, write_split_csv,
)
from m1.run import enrich  # noqa: E402
from competition_acceptance import score_predictions  # noqa: E402

NORMAL_PRED = LABEL_NORMAL
UNKNOWN_PRED = "未知攻击"
THRESHOLD_GRID = [round(0.50 + 0.05 * step, 2) for step in range(10)] + [0.97, 0.98, 0.99]
# 校准预算阶梯：从 0.85 起逐级收紧，直到校准集融合 FPR 达标（留余量 0.7%，预算 1% 由测试集验证）
PRECISION_LADDER = [0.85, 0.90, 0.93, 0.95, 0.97, 0.99]
FPR_CALIB_TARGET = 0.007


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_matrix(rows: list[dict]) -> np.ndarray:
    return np.array([extract_features(row) for row in rows], dtype=np.float64)


def encode_labels(rows: list[dict], headers: list[str], classes: list[str]) -> tuple[np.ndarray, np.ndarray]:
    labels = [truth_of(row, headers) for row in rows]
    y = np.array([classes.index(label) for label in labels], dtype=np.int32)
    counts = Counter(labels)
    total = len(labels)
    weight = np.array([total / (len(classes) * counts[label]) for label in labels], dtype=np.float64)
    return y, weight


def decide(row_scores, classes: list[str], thresholds: dict[str, float]) -> tuple[str, float] | None:
    """与 m1.ml_detector.MLDetector._decide 同一决策规则。"""
    best_label, best_score = None, 0.0
    for index, label in enumerate(classes):
        threshold = thresholds.get(label)
        if threshold is None:
            continue
        score = float(row_scores[index])
        if score >= threshold and score > best_score:
            best_label, best_score = label, score
    return (best_label, best_score) if best_label else None


def calibrate(classes: list[str], truth: list[str], scores: np.ndarray,
              min_precision: float) -> tuple[dict[str, float], list[str], dict]:
    """校准集逐类阈值：precision >= min_precision 下 F1 最大；无合格阈值则禁用。"""
    thresholds: dict[str, float] = {}
    disabled: list[str] = []
    table: dict[str, dict] = {}
    for label in classes:
        if label == LABEL_NORMAL:
            continue
        col = scores[:, classes.index(label)]
        actual_pos = np.array([value == label for value in truth])
        best = None
        for threshold in THRESHOLD_GRID:
            predicted = col >= threshold
            tp = int(np.sum(predicted & actual_pos))
            fp = int(np.sum(predicted & ~actual_pos))
            fn = int(np.sum(~predicted & actual_pos))
            precision = tp / (tp + fp) if tp + fp else None
            recall = tp / (tp + fn) if tp + fn else None
            f1 = (2 * precision * recall / (precision + recall)
                  if precision is not None and recall is not None and precision + recall else 0.0)
            if precision is not None and precision >= min_precision:
                # 约束已把 precision 钉在地板上，选择标准改为"召回最大"（并列取更高 precision）
                if best is None or (recall or 0) > (best["recall"] or 0):
                    best = {"threshold": threshold, "precision": precision,
                            "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn}
        if best is None:
            disabled.append(label)
            table[label] = {"disabled": True, "reason": f"校准集上无 precision>={min_precision} 的阈值"}
            continue
        thresholds[label] = best["threshold"]
        table[label] = {"disabled": False, **best}
    return thresholds, disabled, table


def event_level_predictions(rows: list[dict], headers: list[str], classes: list[str],
                            thresholds: dict[str, float], booster=None) -> tuple[dict, dict, dict]:
    """事件级两臂预测：规则基线（真实 enrich）与规则+ML 融合。"""
    predictions_base: list[str] = []
    predictions_fused: list[str] = []
    alerts_base: list[bool] = []
    alerts_fused: list[bool] = []
    new_alert_truth: Counter[str] = Counter()
    ml_fired = 0

    base_hits_all: list[list[str]] = []
    for row in rows:
        probe = dict(row)
        enrich(probe, {})
        hits = list(probe.get("rule_hits") or [])
        base_hits_all.append(hits)
        alerts_base.append(bool(hits))
        if hits:
            label = label_for(hits)
            predictions_base.append(UNKNOWN_PRED if label == LABEL_PENDING else label)
        else:
            predictions_base.append(NORMAL_PRED)

    decisions: list[tuple[str, float] | None] = []
    if booster is not None and thresholds:
        scores = booster.predict(build_matrix(rows), num_iteration=booster.best_iteration)
        decisions = [decide(row_scores, classes, thresholds) for row_scores in scores]
    for row, hits, decision in zip(rows, base_hits_all, decisions, strict=True):
        fused_hits = set(hits)
        if decision is not None:
            ml_fired += 1
            fused_hits.add(ML_RULE_BY_LABEL[decision[0]])
        alerts_fused.append(bool(fused_hits))
        if fused_hits and not hits:
            new_alert_truth[truth_of(row, headers)] += 1
        if fused_hits:
            label = label_for(sorted(fused_hits))
            predictions_fused.append(UNKNOWN_PRED if label == LABEL_PENDING else label)
        else:
            predictions_fused.append(NORMAL_PRED)

    truth = [truth_of(row, headers) for row in rows]
    base_metrics = score_predictions(truth, predictions_base, alerts_base)
    fused_metrics = score_predictions(truth, predictions_fused, alerts_fused)
    new_alerts = sum(new_alert_truth.values())
    new_alert_true_attack = sum(count for label, count in new_alert_truth.items() if label != LABEL_NORMAL)
    ml_new = {
        "count": new_alerts,
        "true_attack_ratio": (new_alert_true_attack / new_alerts) if new_alerts else None,
        "by_truth_label": dict(new_alert_truth),
        "note": "新增告警=基线未命中而 ML 单独命中的行；true_attack_ratio 即 ML 新增告警 precision（按真值）",
    }
    return base_metrics, fused_metrics, {"ml_new_alerts": ml_new, "ml_fired": ml_fired}


def main() -> int:
    parser = argparse.ArgumentParser(description="Train the M1 LightGBM detector (m1-ml-1.0)")
    parser.add_argument("--input", type=Path,
                        default=PROJECT.parent / "赛题2：网络安全态势智能感知.xlsx")
    parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--rounds", type=int, default=600)
    parser.add_argument("--min-precision", type=float, default=0.85)
    parser.add_argument("--splits-dir", type=Path, default=None, help="可选：把三个 split 落盘为 CSV 供复用")
    args = parser.parse_args()

    started = time.perf_counter()
    headers, rows = read_official_rows(args.input)
    splits, split_stats = split_rows(rows, seed=args.seed)
    print(f"[split] 总行数 {split_stats['rows']} | 请求指纹组 {split_stats['groups']} | "
          f"重复组带来的重复行 {split_stats['duplicate_rows_from_repeated_groups']} | 单行组 {split_stats['singleton_groups']}")
    for name in ("train", "calib", "test"):
        dist = label_distribution(splits[name], headers)
        print(f"[split] {name}: {len(splits[name])} 行 | {dist}")
    if args.splits_dir:
        for name in ("train", "calib", "test"):
            write_split_csv(splits[name], headers, args.splits_dir / f"{name}.csv")
        print(f"[split] CSV 已落盘: {args.splits_dir}")

    classes = sorted({truth_of(row, headers) for row in rows})
    print(f"[train] 类别（索引顺序）: {classes}")

    y, weight = encode_labels(splits["train"], headers, classes)
    x_train = build_matrix(splits["train"])
    # 早停验证集取训练集尾部 10%（不触碰校准/测试集）
    cut = max(1, int(len(x_train) * 0.9))
    import lightgbm as lgb

    dtrain = lgb.Dataset(x_train[:cut], label=y[:cut], weight=weight[:cut],
                         feature_name=FEATURE_NAMES(), free_raw_data=False)
    dvalid = lgb.Dataset(x_train[cut:], label=y[cut:], weight=weight[cut:],
                         feature_name=FEATURE_NAMES(), reference=dtrain)
    params = {
        "objective": "multiclass", "num_class": len(classes),
        "metric": "multi_logloss", "learning_rate": 0.05,
        "num_leaves": 63, "min_data_in_leaf": 20,
        "feature_fraction": 0.9, "bagging_fraction": 0.8, "bagging_freq": 1,
        "seed": args.seed, "verbosity": -1, "first_metric_only": True,
    }
    booster = lgb.train(params, dtrain, num_boost_round=args.rounds,
                        valid_sets=[dvalid], valid_names=["train_tail"],
                        callbacks=[lgb.early_stopping(50, first_metric_only=True), lgb.log_evaluation(0)])
    print(f"[train] best_iteration={booster.best_iteration}")

    # ---- 校准集阈值（预算阶梯升级：直到校准集融合 FPR 达标；1% 预算由冻结测试集验证） ----
    calib_truth = [truth_of(row, headers) for row in splits["calib"]]
    calib_scores = booster.predict(build_matrix(splits["calib"]),
                                   num_iteration=booster.best_iteration)
    ladder = [p for p in PRECISION_LADDER if p >= args.min_precision] or [args.min_precision]
    thresholds: dict[str, float] = {}
    disabled: list[str] = []
    calib_table: dict = {}
    escalation: list[dict] = []
    for min_p in ladder:
        thresholds, disabled, calib_table = calibrate(classes, calib_truth, calib_scores, min_p)
        if not thresholds:
            escalation.append({"min_precision": min_p, "thresholds": {}, "disabled": disabled,
                               "calib_fused_fpr": None, "note": "全部类别禁用"})
            print(f"[calib] precision>={min_p}: 全部类别禁用")
            continue
        _, calib_fused, _ = event_level_predictions(splits["calib"], headers, classes,
                                                    thresholds, booster=booster)
        calib_fpr = calib_fused["binary_attack_detection"]["false_positive_rate"]
        escalation.append({"min_precision": min_p, "thresholds": dict(thresholds),
                           "disabled": list(disabled), "calib_fused_fpr": calib_fpr})
        print(f"[calib] precision>={min_p}: 阈值={thresholds} 禁用={disabled or '无'} "
              f"校准集融合FPR={calib_fpr:.4f}")
        if calib_fpr is not None and calib_fpr <= FPR_CALIB_TARGET:
            break
    if not thresholds:
        print("[gate] FAIL: 所有类别均无法满足 precision/FPR 约束；不落盘模型")
        return 2

    # ---- 测试集冻结闸门（事件级） ----
    base_metrics, fused_metrics, extra = event_level_predictions(
        splits["test"], headers, classes, thresholds, booster=booster)
    rce = "远程命令执行攻击"
    base_rce = base_metrics["per_class"].get(rce, {})
    fused_rce = fused_metrics["per_class"].get(rce, {})
    base_fpr = base_metrics["binary_attack_detection"]["false_positive_rate"]
    fused_fpr = fused_metrics["binary_attack_detection"]["false_positive_rate"]

    def _fmt(metrics: dict) -> str:
        return (f"acc={metrics['multiclass_accuracy']:.4f} macroF1={metrics['macro_f1']:.4f} "
                f"二分类 P={metrics['binary_attack_detection']['precision']:.4f} "
                f"R={metrics['binary_attack_detection']['recall']:.4f} "
                f"F1={metrics['binary_attack_detection']['f1']:.4f} FPR={metrics['binary_attack_detection']['false_positive_rate']:.4f}")

    print("\n===== 测试集闸门（冻结，事件级） =====")
    print(f"[gate] 规则基线: {_fmt(base_metrics)}")
    print(f"[gate] 规则+ML : {_fmt(fused_metrics)}")
    print(f"[gate] RCE recall: {base_rce.get('recall')} -> {fused_rce.get('recall')}")
    print(f"[gate] RCE support={base_rce.get('support')} precision {base_rce.get('precision')} -> {fused_rce.get('precision')}")
    print(f"[gate] FPR: {base_fpr} -> {fused_fpr} (预算 1%)")
    print(f"[gate] 未知攻击预测: {base_metrics['unknown_attack_predictions']} -> {fused_metrics['unknown_attack_predictions']}")
    print(f"[gate] ML 触发 {extra['ml_fired']} 行 | ML 新增告警 {extra['ml_new_alerts']['count']} 行 | "
          f"新增告警真实攻击占比 {extra['ml_new_alerts']['true_attack_ratio']}")
    print(f"[gate] 新增告警真值分布: {extra['ml_new_alerts']['by_truth_label']}")

    # ---- 落盘模型与 meta ----
    args.model_dir.mkdir(parents=True, exist_ok=True)
    model_path = args.model_dir / MODEL_FILE
    meta_path = args.model_dir / META_FILE
    booster.save_model(str(model_path), num_iteration=booster.best_iteration)
    meta = {
        "ml_version": ML_DETECTOR_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_input": str(args.input),
        "source_sha256": sha256(args.input),
        "group_key_fields": split_stats["group_key_fields"],
        "split": {**split_stats, "rows": {name: len(splits[name]) for name in ("train", "calib", "test")},
                  "label_distribution": {name: label_distribution(splits[name], headers)
                                         for name in ("train", "calib", "test")}},
        "classes": classes,
        "feature_names": FEATURE_NAMES(),
        "thresholds": thresholds,
        "disabled_classes": disabled,
        "min_precision": args.min_precision,
        "fpr_calib_target": FPR_CALIB_TARGET,
        "threshold_escalation": escalation,
        "calibration": calib_table,
        "params": {**params, "num_boost_round": args.rounds, "best_iteration": booster.best_iteration},
        "test_gate": {"baseline": base_metrics, "fused": fused_metrics, **extra},
        "decision_rule": "在白名单类别中取模型分数最高且 >= 阈值者；无则不命中；正常访问与禁用类永不命中",
        "note": ("模型分数经 class_weight 配平，未经概率校准，不解释为概率；"
                 "阈值经 precision 预算阶梯在校准集上选取（召回最大、precision>=阶梯值、"
                 "校准集融合 FPR<=0.007 即停），测试集冻结未参与任何选择。"),
    }
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")

    elapsed = time.perf_counter() - started
    rce_delta = (fused_rce.get("recall") or 0) - (base_rce.get("recall") or 0)
    macro_delta = (fused_metrics["macro_f1"] or 0) - (base_metrics["macro_f1"] or 0)
    verdict = "PASS" if (rce_delta >= 0.10 and (fused_fpr or 0) <= 0.01) else "REVIEW"
    print(f"\n[train] 闸门判定: {verdict} (RCE recall Δ={rce_delta:+.4f}, macro-F1 Δ={macro_delta:+.4f}, FPR={fused_fpr})")
    print(f"[train] 模型已写: {model_path}")
    print(f"[train] meta 已写: {meta_path}")
    print(f"[train] 总耗时 {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
