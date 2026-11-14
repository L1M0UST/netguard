"""RiskScorer - deterministic, explainable severity (M2-F14, spec §23).

Severity is **never** taken from the LLM.  It is a weighted function of
ATT&CK tactics, evidence volume, threat intelligence, asset criticality, rule
scores, chain shape and (as one input among many) the validated LLM confidence.
Every factor is written into the report, so "why is this high?" is answerable.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field

from backend.common.schemas.attack import AttackCandidate, AttackChain, RiskFactor, RiskScore
from backend.common.schemas.suspicious_event import SuspiciousEvent
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.attack.knowledge import AttackKnowledgeBase, load_knowledge_base
from backend.module2_chain.llm.schemas import LLMAttackAnalysis
from backend.module2_chain.risk.assets import AssetInventory
from backend.module2_chain.risk.confidence import ConfidenceCalculator, normalise_rule_score
from backend.module2_chain.risk.severity import SeverityClassifier
from backend.module2_chain.schemas.internal import EvidenceValidationResult

logger = get_logger("risk.scorer")


@dataclass(slots=True)
class ScoringContext:
    """Everything the scorer needs, keeping the scoring function pure."""

    candidate: AttackCandidate
    events: list[SuspiciousEvent] = field(default_factory=list)
    analysis: LLMAttackAnalysis | None = None
    validation: EvidenceValidationResult | None = None
    asset_weights: dict[str, float] = field(default_factory=dict)
    ioc_hits: int = 0
    malicious_ioc_hits: int = 0


class RiskScorer:
    """Computes :class:`RiskScore` and the chain confidence."""

    def __init__(
        self,
        config: AppConfig,
        *,
        knowledge: AttackKnowledgeBase | None = None,
        inventory: AssetInventory | None = None,
    ) -> None:
        self.config = config
        self.settings = config.risk
        self.weights = config.risk.weights
        self.knowledge = knowledge or load_knowledge_base(config.attack_kb_path)
        self.inventory = inventory or AssetInventory(config)
        self.severity = SeverityClassifier(config.risk.severity_thresholds)
        self.confidence = ConfidenceCalculator(config)

    # ------------------------------------------------------------------ #
    def score(self, chain: AttackChain, context: ScoringContext) -> RiskScore:
        factors: list[RiskFactor] = []
        rationale: list[str] = []
        weights = self.weights

        # 1. ATT&CK tactic severity - the worst stage drives the score.
        tactic_values = [
            float(self.settings.tactic_severity.get(stage.tactic, 0.5)) for stage in chain.stages
        ]
        tactic_value = max(tactic_values) if tactic_values else 0.0
        worst_stage = None
        if chain.stages:
            worst_stage = max(
                chain.stages,
                key=lambda stage: self.settings.tactic_severity.get(stage.tactic, 0.5),
            )
            rationale.append(
                f"highest-impact tactic: {worst_stage.tactic} ({worst_stage.tactic_name or self.knowledge.tactic_name(worst_stage.tactic)})"
            )
        factors.append(
            RiskFactor(
                name="tactic_severity",
                weight=weights.tactic_severity,
                value=round(tactic_value, 4),
                contribution=round(weights.tactic_severity * tactic_value, 4),
                description="ATT&CK tactic impact of the most severe stage",
                evidence_event_ids=worst_stage.evidence_event_ids if worst_stage else [],
            )
        )

        # 2. Evidence strength.
        evidence_ids = chain.all_evidence_event_ids() or list(chain.event_ids)
        evidence_value = min(
            1.0,
            len(evidence_ids) / max(1, self.settings.evidence.max_events_for_full_score),
        )
        if len(evidence_ids) >= self.settings.evidence.min_events_for_high_confidence:
            evidence_value = min(1.0, evidence_value + 0.1)
            rationale.append(
                f"{len(evidence_ids)} independent evidence events support the chain"
            )
        factors.append(
            RiskFactor(
                name="evidence_strength",
                weight=weights.evidence_strength,
                value=round(evidence_value, 4),
                contribution=round(weights.evidence_strength * evidence_value, 4),
                description=f"{len(evidence_ids)} evidence event(s) back this chain",
                evidence_event_ids=evidence_ids[:10],
            )
        )

        # 3. Threat intelligence.
        ioc_value = 0.0
        if context.malicious_ioc_hits > 0:
            ioc_value = min(1.0, 0.6 + 0.2 * context.malicious_ioc_hits)
            rationale.append(
                f"{context.malicious_ioc_hits} malicious indicator(s) matched threat intelligence"
            )
        elif context.ioc_hits > 0:
            ioc_value = 0.3
        factors.append(
            RiskFactor(
                name="ioc",
                weight=weights.ioc,
                value=round(ioc_value, 4),
                contribution=round(weights.ioc * ioc_value, 4),
                description=(
                    f"{context.malicious_ioc_hits} malicious / {context.ioc_hits} total "
                    "threat-intelligence hit(s)"
                ),
            )
        )

        # 4. Asset criticality.
        asset_weight = self._asset_weight(chain, context)
        asset_value = min(1.0, max(0.0, (asset_weight - 1.0) / 2.0))
        if asset_weight > 1.5:
            rationale.append(f"victim asset criticality weight is {asset_weight:.2f}")
        factors.append(
            RiskFactor(
                name="asset_criticality",
                weight=weights.asset_criticality,
                value=round(asset_value, 4),
                contribution=round(weights.asset_criticality * asset_value, 4),
                description=f"victim asset weight {asset_weight:.2f}",
            )
        )

        # 5. Module 1 rule score.
        rule_value = normalise_rule_score(context.candidate.score_summary.max_score)
        factors.append(
            RiskFactor(
                name="rule_score",
                weight=weights.rule_score,
                value=round(rule_value, 4),
                contribution=round(weights.rule_score * rule_value, 4),
                description="normalised Module 1 detection score",
            )
        )

        # 6. Validated LLM confidence (one input among many).
        analysis = context.analysis
        llm_degraded = bool(analysis.degraded) if analysis is not None else True
        llm_value = 0.0
        if analysis is not None and not llm_degraded:
            llm_value = max(0.0, min(1.0, analysis.confidence))
        factors.append(
            RiskFactor(
                name="llm_confidence",
                weight=weights.llm_confidence,
                value=round(llm_value, 4),
                contribution=round(weights.llm_confidence * llm_value, 4),
                description=(
                    "LLM degraded - factor scored as zero"
                    if llm_degraded
                    else "validated LLM semantic confidence"
                ),
            )
        )

        # M1's structured assessment is an independent, capped supporting
        # signal.  A benign M1 answer never subtracts risk, and deterministic
        # rule/IOC factors above retain their own full evidence and weight.
        m1_rows = []
        for event in context.events:
            extras = event.model_extra or {}
            verdict = str(extras.get("m1_semantic_verdict") or "").lower()
            confidence = extras.get("m1_semantic_confidence")
            reference = extras.get("m1_evidence_reference")
            if (verdict not in {"malicious", "suspicious"}
                    or type(confidence) not in (int, float)
                    or not math.isfinite(float(confidence))):
                continue
            if isinstance(reference, str):
                try:
                    reference = json.loads(reference)
                except (TypeError, ValueError):
                    reference = {}
            if not isinstance(reference, dict) or reference.get("event_id") not in context.candidate.event_ids:
                continue
            m1_rows.append((max(0.0, min(1.0, float(confidence))), event.event.event_id))
        m1_value = min(0.6, max((item[0] for item in m1_rows), default=0.0) * 0.6)
        m1_evidence_ids = sorted({event_id for _, event_id in m1_rows})[:10]
        factors.append(
            RiskFactor(
                name="m1_semantic",
                weight=weights.m1_semantic,
                value=round(m1_value, 4),
                contribution=round(weights.m1_semantic * m1_value, 4),
                description=(
                    f"M1 malicious/suspicious assessment supported by {len(m1_rows)} evidence-bound event(s); "
                    "advisory only, capped at 0.60"
                ),
                evidence_event_ids=m1_evidence_ids,
            )
        )

        # 7. Chain length.
        chain_value = min(1.0, len(chain.stages) / 5.0)
        factors.append(
            RiskFactor(
                name="chain_length",
                weight=weights.chain_length,
                value=round(chain_value, 4),
                contribution=round(weights.chain_length * chain_value, 4),
                description=f"{len(chain.stages)} stage(s) in the chain",
            )
        )

        # 8. Multi-stage / multi-tactic bonus.
        tactic_set = {stage.tactic for stage in chain.stages}
        multi_value = 1.0 if len(tactic_set) >= 3 else (0.6 if len(tactic_set) == 2 else 0.0)
        if len(tactic_set) >= 3:
            rationale.append(f"{len(tactic_set)} distinct ATT&CK tactics observed")
        factors.append(
            RiskFactor(
                name="multi_stage",
                weight=weights.multi_stage,
                value=round(multi_value, 4),
                contribution=round(weights.multi_stage * multi_value, 4),
                description=f"{len(tactic_set)} distinct tactic(s)",
            )
        )

        total_weight = sum(factor.weight for factor in factors) or 1.0
        score = 100.0 * sum(factor.contribution for factor in factors) / total_weight
        validation = context.validation
        if validation is not None and validation.hallucination_detected:
            score = max(0.0, score - 5.0)
            rationale.append("score reduced by 5.0: the LLM produced unsupported claims")
        score = round(max(0.0, min(100.0, score)), 2)
        severity = self.severity.classify(score)
        rationale.append(self.severity.describe(score))

        logger.debug(
            "risk scored",
            extra={
                "task_id": chain.task_id,
                "candidate_id": context.candidate.candidate_id,
                "stage": "risk_scoring",
                "score": score,
                "severity": str(severity),
            },
        )
        return RiskScore(score=score, severity=severity, factors=factors, rationale=rationale)

    # ------------------------------------------------------------------ #
    def compute_confidence(
        self, chain: AttackChain, context: ScoringContext
    ) -> tuple[float, list[RiskFactor]]:
        validation = context.validation
        analysis = context.analysis
        result = self.confidence.compute(
            evidence_count=len(chain.all_evidence_event_ids() or chain.event_ids),
            max_rule_score=context.candidate.score_summary.max_score,
            correlation_score=context.candidate.correlation_score,
            ioc_score=(min(1.0, context.malicious_ioc_hits / 2.0) if context.ioc_hits else 0.0),
            llm_confidence=analysis.confidence if analysis else None,
            llm_degraded=bool(analysis.degraded) if analysis else True,
            validation_penalty=validation.confidence_penalty if validation else 0.0,
            stage_count=len(chain.stages),
            evidence_event_ids=chain.all_evidence_event_ids(),
        )
        return result.value, result.factors

    def apply(self, chain: AttackChain, context: ScoringContext) -> AttackChain:
        """Attach severity, risk score and confidence to a chain."""

        risk = self.score(chain, context)
        confidence, factors = self.compute_confidence(chain, context)
        return chain.model_copy(
            update={
                "severity": risk.severity,
                "risk_score": risk,
                "confidence": confidence,
                "confidence_factors": factors,
            }
        )

    # ------------------------------------------------------------------ #
    def _asset_weight(self, chain: AttackChain, context: ScoringContext) -> float:
        if context.asset_weights:
            return max(context.asset_weights.values())
        return self.inventory.max_weight_for(chain.victim_ips)
