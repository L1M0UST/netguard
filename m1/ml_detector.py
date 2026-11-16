"""第二层传统机器学习检测器：LightGBM 原生 Booster 推理（m1-ml-1.0）。

- 训练产物：m1/model/ml_detector.txt（原生文本格式）+ ml_detector.meta.json；
- 推理只依赖 lightgbm + numpy，不引入 sklearn；
- 任何加载/校验/预测失败都 fail-open 降级为纯规则：不抛异常、零命中，但
  status/errors/detail 全程留痕（防"降级运行被误判为验收通过"）；
- 输出统称"模型分数"（class_weight 配平后未经概率校准，不作概率解释）。
"""
from __future__ import annotations

import json
import threading
from collections import Counter
from pathlib import Path

from m1.ml_features import FEATURE_NAMES, ML_RULE_BY_LABEL, RISK_ML

ML_DETECTOR_VERSION = "m1-ml-1.0"
DEFAULT_MODEL_DIR = Path(__file__).resolve().parent / "model"
MODEL_FILE = "ml_detector.txt"
META_FILE = "ml_detector.meta.json"
MAX_CONSECUTIVE_ERRORS = 3


class MLDetector:
    """懒加载的 LightGBM 多分类检测器；批量推理、阈值门控、证据回写。"""

    def __init__(self, model_dir: Path | str | None = None, enabled: bool = True):
        self.model_dir = Path(model_dir) if model_dir else DEFAULT_MODEL_DIR
        self.status = "disabled"
        self.detail = ""
        self.calls = 0
        self.errors = 0
        self.hits: Counter[str] = Counter()
        self._consecutive_errors = 0
        self._lock = threading.Lock()
        self.booster = None
        self.meta: dict = {}
        self.labels: list[str] = []      # 类别索引 -> 官方中文标签
        self.thresholds: dict[str, float] = {}  # 白名单类别 -> score 阈值
        if not enabled:
            self.detail = "config disabled"
            return
        model_path = self.model_dir / MODEL_FILE
        meta_path = self.model_dir / META_FILE
        if not model_path.is_file() or not meta_path.is_file():
            self.status = "missing"
            self.detail = f"model artifacts not found in {self.model_dir}"
            return
        try:
            import lightgbm as lgb  # 延迟导入：未安装时降级而非崩溃

            self.booster = lgb.Booster(model_file=str(model_path))
            self.meta = json.loads(meta_path.read_text(encoding="utf-8"))
            names = list(self.meta.get("feature_names") or [])
            if names != FEATURE_NAMES():
                raise ValueError("meta.feature_names 与 m1.ml_features.FEATURE_NAMES 不一致（特征漂移）")
            self.labels = [str(label) for label in self.meta.get("classes") or []]
            if not self.labels:
                raise ValueError("meta.classes 为空")
            self.thresholds = {str(label): float(value)
                               for label, value in (self.meta.get("thresholds") or {}).items()}
            if not self.thresholds:
                raise ValueError("meta.thresholds 为空（所有类别均未通过校准）")
            self.status = "ready"
        except Exception as exc:  # noqa: BLE001 — 任何加载失败都必须降级而非中断管线
            self.booster = None
            self.status = "error"
            self.detail = f"{type(exc).__name__}: {exc}"

    # ------------------------------------------------------------------ #
    def apply_batch(self, events: list[dict]) -> None:
        """对已带 _ml_features 的事件批量推理并回写命中；失败整批跳过（fail-open）。"""
        if self.status != "ready" or not events:
            return
        try:
            import numpy as np

            matrix = np.array([event["_ml_features"] for event in events], dtype=np.float64)
            if matrix.shape[1] != len(self.meta.get("feature_names") or []):
                raise ValueError("特征向量长度与 meta 不一致")
            scores = self.booster.predict(matrix)
        except Exception as exc:  # noqa: BLE001 — 预测阶段降级同样留痕
            with self._lock:
                self.errors += 1
                self._consecutive_errors += 1
                self.detail = f"predict failed: {type(exc).__name__}: {exc}"
                if self._consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                    self.status = "error"
            return
        with self._lock:
            self._consecutive_errors = 0
            self.calls += len(events)
        for event, row in zip(events, scores):
            decision = self._decide(row)
            if decision is not None:
                self._attach(event, *decision)

    # ------------------------------------------------------------------ #
    def _decide(self, row) -> tuple[str, float] | None:
        """白名单类别中取最高分且过阈值者；正常访问与禁用类永不命中。"""
        best_label, best_score = None, 0.0
        for index, label in enumerate(self.labels):
            threshold = self.thresholds.get(label)
            if threshold is None:
                continue
            score = float(row[index])
            if score >= threshold and score > best_score:
                best_label, best_score = label, score
        return (best_label, best_score) if best_label else None

    def _attach(self, event: dict, label: str, score: float) -> None:
        rule = ML_RULE_BY_LABEL[label]
        threshold = self.thresholds[label]
        event["rule_hits"] = sorted({*(event.get("rule_hits") or []), rule})
        evidence = event.setdefault("evidence", [])
        evidence.append({
            "type": "ml", "name": rule, "label": label,
            "score": round(score, 4), "threshold": threshold,
            "model_version": ML_DETECTOR_VERSION, "event_id": event.get("event_id"),
        })
        ml_risk = RISK_ML.get(rule, 45)
        if ml_risk > (event.get("risk_score") or 0):
            event["risk_score"] = ml_risk
            event["risk_level"] = "high" if ml_risk >= 75 else "medium" if ml_risk >= 45 else "low"
        components = event.get("score_components") or {}
        components["ml"] = max(int(components.get("ml") or 0), ml_risk)
        event["score_components"] = components
        with self._lock:
            self.hits[label] += 1

    # ------------------------------------------------------------------ #
    def snapshot(self) -> dict:
        """batch status 透出块；验收闸门断言 status=='ready' 且 calls>0。"""
        with self._lock:
            return {
                "status": self.status,
                "version": ML_DETECTOR_VERSION,
                "model_dir": str(self.model_dir),
                "classes": len(self.labels),
                "whitelist": sorted(self.thresholds),
                "calls": self.calls,
                "hits": dict(self.hits),
                "errors": self.errors,
                "detail": self.detail,
            }
