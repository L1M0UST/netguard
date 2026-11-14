"""Rule-based fallback analyser (spec §19).

When the LLM times out, errors, returns malformed JSON or is not configured,
Module 2 must still produce an attack chain.  This analyser turns the
deterministic candidate techniques into a structured
:class:`LLMAttackAnalysis` - with ``degraded=True`` and the original error
recorded - so downstream stages stay identical.
"""

from __future__ import annotations

from typing import Any

from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.attack.knowledge import AttackKnowledgeBase, load_knowledge_base
from backend.module2_chain.llm.schemas import (
    AttackAnalysisRequest,
    LLMAttackAnalysis,
    LLMStage,
    LLMUsage,
)

logger = get_logger("llm.fallback")


class FallbackAttackAnalyzer:
    """Deterministic replacement for the LLM (`llm.fail_open: true`)."""

    name = "rule_based_fallback"
    model: str | None = None
    enabled = True

    def __init__(
        self, config: AppConfig, *, knowledge: AttackKnowledgeBase | None = None
    ) -> None:
        self.config = config
        self.knowledge = knowledge or load_knowledge_base(config.attack_kb_path)
        self.calls = 0

    # ------------------------------------------------------------------ #
    async def analyze_attack_scenario(
        self, request: AttackAnalysisRequest
    ) -> LLMAttackAnalysis:
        self.calls += 1
        metadata: dict[str, Any] = dict(request.metadata or {})
        techniques: list[dict[str, Any]] = list(metadata.get("candidate_techniques") or [])
        evidence_ids = list(request.evidence_event_ids)
        reason = str(metadata.get("llm_error") or "LLM analysis unavailable")

        stages = self._build_stages(techniques, evidence_ids)
        categories = [str(item) for item in (metadata.get("attack_categories") or [])]
        attacker_ips = [str(item) for item in (metadata.get("attacker_ips") or [])]
        victim_ips = [str(item) for item in (metadata.get("victim_ips") or [])]

        confidence = 0.0
        if techniques:
            confidence = min(
                0.65,
                0.35 + 0.4 * (sum(float(t.get("confidence") or 0.0) for t in techniques) / len(techniques)),
            )
        verdict = "attack" if len(evidence_ids) >= 3 and stages else "suspicious"
        if not stages:
            verdict = "unknown"

        analysis = LLMAttackAnalysis(
            candidate_id=request.candidate_id,
            verdict=verdict,  # type: ignore[arg-type]
            attack_summary=self._summary(attacker_ips, victim_ips, stages, categories),
            attacker_assessment=(
                f"Deterministic analysis: {', '.join(attacker_ips[:5]) or 'unknown source'}"
                f" generated {len(stages)} correlated stage(s)."
            ),
            victim_assessment=(
                f"Deterministic analysis: {len(victim_ips)} target(s) affected: "
                f"{', '.join(victim_ips[:5]) or 'unknown'}."
            ),
            stages=stages,
            threat_entities=[],
            uncertainties=[
                f"LLM reasoning was not available ({reason}); the chain below was "
                "derived from deterministic rules, threat intelligence and the "
                "candidate ATT&CK mapping.",
                *(
                    ["behaviour categories are inferred from rule names and may be incomplete"]
                    if categories
                    else []
                ),
            ],
            severity_hint=None,
            confidence=round(confidence, 4),
            prompt_version=request.prompt_version,
            provider=self.name,
            model=None,
            request_id=request.request_id,
            degraded=True,
            degraded_reason=reason,
            usage=LLMUsage(latency_ms=0.0, model=None),
        )
        logger.warning(
            "LLM degraded to the rule-based fallback analyser",
            extra={
                "task_id": request.task_id,
                "candidate_id": request.candidate_id,
                "stage": "llm_fallback",
                "reason": reason,
                "stages": len(stages),
            },
        )
        return analysis

    # ------------------------------------------------------------------ #
    def _build_stages(
        self, techniques: list[dict[str, Any]], evidence_ids: list[str]
    ) -> list[LLMStage]:
        if not techniques:
            return []
        evidence_set = set(evidence_ids)
        ordered = sorted(
            techniques,
            key=lambda item: (
                self.knowledge.tactic_rank(str(item.get("tactic") or "")),
                -float(item.get("confidence") or 0.0),
            ),
        )
        seen: set[tuple[str, str | None]] = set()
        stages: list[LLMStage] = []
        for item in ordered:
            tactic = str(item.get("tactic") or "").strip()
            technique = item.get("technique")
            technique_id = str(technique) if technique else None
            if not tactic or (tactic, technique_id) in seen:
                continue
            seen.add((tactic, technique_id))
            stage_evidence = [
                event_id
                for event_id in (item.get("evidence_event_ids") or [])
                if event_id in evidence_set
            ]
            if not stage_evidence and evidence_ids:
                stage_evidence = evidence_ids[:1]
            if not stage_evidence:
                continue
            narrative = str(item.get("reason") or "").strip() or (
                f"{item.get('tactic_name') or tactic} behaviour observed on the "
                "correlated evidence events."
            )
            stages.append(
                LLMStage(
                    stage_index=len(stages) + 1,
                    tactic=tactic,
                    technique=technique_id,
                    narrative=narrative,
                    evidence_event_ids=stage_evidence,
                    confidence=round(min(0.9, float(item.get("confidence") or 0.4)), 4),
                )
            )
            if len(stages) >= self.config.attack.max_stages_per_chain:
                break
        return stages

    @staticmethod
    def _summary(
        attacker_ips: list[str],
        victim_ips: list[str],
        stages: list[LLMStage],
        categories: list[str],
    ) -> str:
        tactic_names = [
            stage.tactic for stage in sorted(stages, key=lambda item: item.stage_index)
        ]
        return (
            "Rule-based attack chain: "
            f"{', '.join(attacker_ips[:3]) or 'unknown source'} targeted "
            f"{', '.join(victim_ips[:3]) or 'unknown destination'} across "
            f"{len(stages)} stage(s) [{', '.join(tactic_names) or 'none'}]"
            + (f"; behaviour categories: {', '.join(categories[:5])}" if categories else "")
            + "."
        )

    async def aclose(self) -> None:
        """Nothing to release."""

    def health(self) -> dict[str, object]:
        return {"provider": self.name, "enabled": True, "calls": self.calls}
