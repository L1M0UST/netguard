"""Confidence computation (M2-F15, spec §24).

``confidence`` is **not** the LLM's self-reported number.  It is a weighted
combination of evidence strength, rule score, correlation score, IOC support and
(only where available) the LLM's own confidence, then penalised by validation
problems and by LLM degradation.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from backend.common.schemas.attack import RiskFactor
from backend.module2_chain.app.config import AppConfig


def normalise_rule_score(value: float) -> float:
    """Normalise Module 1 detection scores regardless of their scale.

    Module 1 may emit 0-1, 0-10 or 0-100 scores; the scale is inferred from the
    magnitude, so no assumption about the upstream detector is baked in.
    """

    if value <= 0:
        return 0.0
    if value <= 1.0:
        return value
    if value <= 10.0:
        return value / 10.0
    return min(1.0, value / 100.0)


@dataclass(slots=True)
class ConfidenceResult:
    """Confidence value plus its explainable factors."""

    value: float
    factors: list[RiskFactor] = field(default_factory=list)
    penalty: float = 0.0
    degraded: bool = False

    def summary(self) -> dict[str, float]:
        return {factor.name: factor.contribution for factor in self.factors}


class ConfidenceCalculator:
    """Weighted, explainable confidence model."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.settings = config.risk
        self.weights = config.risk.confidence_weights
        self.evidence_settings = config.risk.evidence

    def compute(
        self,
        *,
        evidence_count: int,
        max_rule_score: float,
        correlation_score: float,
        ioc_score: float,
        llm_confidence: float | None,
        llm_degraded: bool,
        validation_penalty: float = 0.0,
        stage_count: int = 0,
        evidence_event_ids: list[str] | None = None,
    ) -> ConfidenceResult:
        del stage_count
        evidence_value = min(
            1.0,
            evidence_count / max(1, self.evidence_settings.max_events_for_full_score),
        )
        if evidence_count >= self.evidence_settings.min_events_for_high_confidence:
            evidence_value = min(1.0, evidence_value + 0.15)
        rule_value = normalise_rule_score(max_rule_score)
        correlation_value = max(0.0, min(1.0, correlation_score))
        ioc_value = max(0.0, min(1.0, ioc_score))
        llm_value = (
            0.0
            if (llm_degraded or llm_confidence is None)
            else max(0.0, min(1.0, llm_confidence))
        )

        components: list[tuple[str, float, float, str]] = [
            (
                "evidence",
                self.weights.evidence,
                evidence_value,
                f"{evidence_count} validated evidence event(s)",
            ),
            (
                "rule",
                self.weights.rule,
                rule_value,
                "Module 1 detection score of the correlated events",
            ),
            (
                "correlation",
                self.weights.correlation,
                correlation_value,
                "strength of the deterministic correlation",
            ),
            ("ioc", self.weights.ioc, ioc_value, "threat-intelligence support"),
            (
                "llm",
                self.weights.llm,
                llm_value,
                "semantic analysis confidence"
                if not llm_degraded
                else "LLM unavailable (weight redistributed)",
            ),
        ]
        if llm_degraded:
            components = [item for item in components if item[0] != "llm"]
        total_weight = sum(weight for _, weight, _, _ in components) or 1.0
        confidence = sum(weight * value for _, weight, value, _ in components) / total_weight

        penalty = max(0.0, min(0.9, validation_penalty))
        factors = [
            RiskFactor(
                name=name,
                weight=round(weight / total_weight, 4),
                value=round(value, 4),
                contribution=round(weight * value / total_weight, 4),
                description=description,
                evidence_event_ids=list(evidence_event_ids or [])[:10],
            )
            for name, weight, value, description in components
        ]
        if penalty > 0:
            factors.append(
                RiskFactor(
                    name="validation_penalty",
                    weight=0.0,
                    value=round(penalty, 4),
                    contribution=round(-penalty, 4),
                    description="evidence-validation problems reduced the confidence",
                )
            )
        final = max(0.0, min(1.0, round(confidence - penalty, 4)))
        return ConfidenceResult(value=final, factors=factors, penalty=penalty, degraded=llm_degraded)

    def meets_threshold(self, confidence: float) -> bool:
        return confidence >= self.settings.confidence_threshold
