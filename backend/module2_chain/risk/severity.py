"""Severity classification from an explainable 0-100 risk score (M2-F14)."""

from __future__ import annotations

from backend.common.schemas.enums import Severity
from backend.module2_chain.app.config import SeverityThresholds


class SeverityClassifier:
    """Maps ``score -> severity`` using configured thresholds."""

    def __init__(self, thresholds: SeverityThresholds | None = None) -> None:
        self.thresholds = thresholds or SeverityThresholds()

    def threshold_for(self, severity: Severity) -> float:
        return {
            Severity.CRITICAL: self.thresholds.critical,
            Severity.HIGH: self.thresholds.high,
            Severity.MEDIUM: self.thresholds.medium,
            Severity.LOW: self.thresholds.low,
            Severity.INFO: 0.0,
        }[severity]

    def classify(self, score: float) -> Severity:
        if score >= self.thresholds.critical:
            return Severity.CRITICAL
        if score >= self.thresholds.high:
            return Severity.HIGH
        if score >= self.thresholds.medium:
            return Severity.MEDIUM
        if score >= self.thresholds.low:
            return Severity.LOW
        return Severity.INFO

    def describe(self, score: float) -> str:
        severity = self.classify(score)
        threshold = self.threshold_for(severity)
        return f"score {score:.1f} -> {severity.value} (threshold {threshold:.0f})"

    def thresholds_map(self) -> dict[str, float]:
        return {
            Severity.CRITICAL.value: self.thresholds.critical,
            Severity.HIGH.value: self.thresholds.high,
            Severity.MEDIUM.value: self.thresholds.medium,
            Severity.LOW.value: self.thresholds.low,
        }
