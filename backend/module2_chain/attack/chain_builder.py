"""AttackChain construction (M2-F12, spec §21, §22).

The chain is *not* a simple time sort:

1. validated LLM stages are used when they survive :class:`EvidenceValidator`;
2. otherwise the deterministic candidate techniques become the stages;
3. stages are de-duplicated by (tactic, technique), ordered by ATT&CK tactic
   progression and only then by time, and re-numbered so ``stage_index`` is
   strictly increasing;
4. **every** stage keeps its ``evidence_event_ids``.

An isolated suspicious event therefore produces a single-stage chain, never an
invented multi-step intrusion.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import UTC, datetime

from backend.common.schemas.attack import (
    AttackCandidate,
    AttackChain,
    CandidateTechnique,
    ChainStage,
    LLMMeta,
)
from backend.common.schemas.enums import Severity, TechniqueSource
from backend.common.schemas.suspicious_event import SuspiciousEvent
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.attack.knowledge import AttackKnowledgeBase, load_knowledge_base
from backend.module2_chain.llm.schemas import LLMAttackAnalysis, LLMCallRecord
from backend.module2_chain.schemas.internal import EvidenceValidationResult

logger = get_logger("attack.chain_builder")

CHAIN_PREFIX = "chain_"


class AttackChainBuilder:
    """Merges deterministic candidates and (validated) LLM reasoning into chains."""

    def __init__(
        self, config: AppConfig, *, knowledge: AttackKnowledgeBase | None = None
    ) -> None:
        self.config = config
        self.knowledge = knowledge or load_knowledge_base(config.attack_kb_path)
        self.max_stages = config.attack.max_stages_per_chain

    # ------------------------------------------------------------------ #
    def build(
        self,
        candidate: AttackCandidate,
        events: list[SuspiciousEvent],
        *,
        analysis: LLMAttackAnalysis | None = None,
        validation: EvidenceValidationResult | None = None,
        techniques: list[CandidateTechnique] | None = None,
        llm_record: LLMCallRecord | None = None,
    ) -> AttackChain:
        event_times = {
            event.event_id: _as_utc(event.event.timestamp) for event in events
        }
        candidate_techniques = techniques if techniques is not None else candidate.techniques

        use_llm = (
            analysis is not None
            and bool(analysis.stages)
            and not (validation is not None and validation.degraded_to_rules)
        )
        stages = (
            self._llm_stages(analysis, candidate_techniques, event_times)
            if use_llm and analysis is not None
            else self._rule_stages(candidate_techniques, event_times, events)
        )
        stages = self._finalise_stages(stages, event_times)
        if not stages:
            stages = self._single_stage_fallback(candidate, events)
        stages, single_event_note = self._collapse_single_evidence_stages(stages)

        mitigations: list[str] = []
        del mitigations
        summary = self._summary(candidate, stages, analysis if use_llm else None)
        tactics = [stage.tactic for stage in stages]
        uncertainties = list(analysis.uncertainties) if (analysis and use_llm) else []
        if single_event_note:
            uncertainties.append(single_event_note)
        if validation is not None:
            uncertainties.extend(
                issue.message
                for issue in validation.issues
                if issue.severity in {"error", "warning"}
            )
        if analysis is not None and analysis.degraded:
            uncertainties.append(
                analysis.degraded_reason
                or "LLM analysis was unavailable; the chain was built from deterministic rules"
            )

        degraded = bool(
            (analysis.degraded if analysis is not None else True)
            or (validation.degraded_to_rules if validation is not None else False)
        )
        chain = AttackChain(
            chain_id=self.chain_id(candidate, stages),
            task_id=candidate.task_id,
            stages=stages,
            severity=Severity.INFO,
            confidence=0.0,
            summary=summary,
            mitre_tactics=_dedupe(tactics),
            llm_meta=_llm_meta(llm_record, analysis, degraded),
            attacker_ips=list(candidate.attacker_ips),
            victim_ips=list(candidate.victim_ips),
            victim_ports=list(candidate.victim_ports),
            event_ids=list(candidate.event_ids),
            candidate_ids=[candidate.candidate_id],
            uncertainties=_dedupe(uncertainties),
            correlation_score=round(float(candidate.correlation_score or 0.0), 4),
            correlation_reasons=list(candidate.correlation_reasons or []),
            evidence_validation=(validation.model_dump(mode="json") if validation else {}),
            llm_degraded=degraded,
            first_seen=candidate.first_seen,
            last_seen=candidate.last_seen,
        )
        logger.info(
            "attack chain built",
            extra={
                "task_id": candidate.task_id,
                "candidate_id": candidate.candidate_id,
                "stage": "chain_building",
                "stages": len(stages),
                "llm_degraded": degraded,
            },
        )
        return chain

    # ------------------------------------------------------------------ #
    @staticmethod
    def chain_id(candidate: AttackCandidate, stages: list[ChainStage]) -> str:
        """Deterministic id - replaying the same input yields the same chain id."""

        payload = "|".join(
            [
                candidate.task_id,
                candidate.candidate_id,
                ",".join(f"{stage.tactic}:{stage.technique or ''}" for stage in stages),
                ",".join(sorted(candidate.event_ids)[:64]),
            ]
        )
        return f"{CHAIN_PREFIX}{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:20]}"

    # ------------------------------------------------------------------ #
    def _llm_stages(
        self,
        analysis: LLMAttackAnalysis,
        techniques: list[CandidateTechnique],
        event_times: dict[str, datetime],
    ) -> list[ChainStage]:
        rule_index = {
            (item.tactic_id, item.technique_id): item
            for item in techniques
        }
        stages: list[ChainStage] = []
        for stage in sorted(analysis.stages, key=lambda item: item.stage_index):
            matched = rule_index.get((stage.tactic, stage.technique))
            source = TechniqueSource.LLM
            if matched is not None or (stage.technique is None and any(
                item.tactic_id == stage.tactic for item in techniques
            )):
                source = TechniqueSource.MERGED
            narrative = stage.narrative or (
                matched.reason if matched else "LLM-identified stage of the attack chain."
            )
            stages.append(
                ChainStage(
                    stage_index=stage.stage_index,
                    tactic=stage.tactic,
                    technique=stage.technique,
                    narrative=narrative,
                    evidence_event_ids=_sorted_by_time(stage.evidence_event_ids, event_times),
                    confidence=round(
                        min(1.0, max(stage.confidence, matched.confidence if matched else 0.0)), 4
                    ),
                    tactic_name=self.knowledge.tactic_name(stage.tactic),
                    technique_name=(
                        matched.technique_name
                        if matched
                        else self._technique_name(stage.technique)
                    ),
                    source=source,
                )
            )
        return stages

    def _rule_stages(
        self,
        techniques: list[CandidateTechnique],
        event_times: dict[str, datetime],
        events: list[SuspiciousEvent],
    ) -> list[ChainStage]:
        if not techniques:
            return []
        rules_seen = _dedupe(
            [rule for event in events for rule in event.detection.matched_rules]
        )[:6]
        ordered = sorted(
            techniques,
            key=lambda item: (
                self.knowledge.tactic_rank(item.tactic_id),
                -item.confidence,
            ),
        )
        stages: list[ChainStage] = []
        for item in ordered:
            narrative = item.reason or (
                f"{item.tactic_name} behaviour inferred from "
                f"{', '.join(rules_seen) or 'the correlated events'}."
            )
            stages.append(
                ChainStage(
                    stage_index=len(stages) + 1,
                    tactic=item.tactic_id,
                    technique=item.technique_id,
                    narrative=narrative,
                    evidence_event_ids=_sorted_by_time(item.evidence_event_ids, event_times),
                    confidence=round(min(1.0, item.confidence), 4),
                    tactic_name=item.tactic_name,
                    technique_name=item.technique_name,
                    source=TechniqueSource.RULE,
                )
            )
        return stages

    def _single_stage_fallback(
        self, candidate: AttackCandidate, events: list[SuspiciousEvent]
    ) -> list[ChainStage]:
        evidence = [event.event.event_id for event in events] or list(candidate.event_ids)
        if not evidence:
            return []
        rationale = ", ".join(candidate.rule_hits[:3]) or "suspicious behaviour"
        return [
            ChainStage(
                stage_index=1,
                tactic="TA0007",
                technique=None,
                narrative=(
                    f"Single suspicious event group ({rationale}); insufficient evidence for a "
                    "multi-stage attack chain."
                ),
                evidence_event_ids=evidence[:5],
                confidence=0.25,
                tactic_name=self.knowledge.tactic_name("TA0007"),
                technique_name=None,
                source=TechniqueSource.RULE,
            )
        ]

    def _technique_name(self, technique_id: str | None) -> str | None:
        """Human readable technique name, or ``None`` when it is unknown."""

        if not technique_id:
            return None
        definition = self.knowledge.technique(technique_id)
        return definition.name if definition is not None else None

    # ------------------------------------------------------------------ #
    def _collapse_single_evidence_stages(
        self, stages: list[ChainStage]
    ) -> tuple[list[ChainStage], str | None]:
        """A stage must introduce new evidence; re-used evidence is inference, not progression.

        Spec §22: a single malicious-IP alert must not become a full attack chain.
        The same principle applies cumulatively: walking the stages in order, any
        stage whose evidence adds nothing beyond already-seen events is a candidate
        expansion (one observation dressed as several tactics) and is folded away.
        The surviving chain therefore has exactly one stage per new observation.
        """

        if len(stages) <= 1:
            return stages, None
        kept: list[ChainStage] = []
        seen: set[str] = set()
        folded: list[str] = []
        for stage in stages:
            ids = set(stage.evidence_event_ids)
            if not ids or ids.issubset(seen):
                folded.append(
                    f"{stage.tactic}/{stage.technique or '?'} (confidence {stage.confidence:.2f})"
                )
                continue
            seen |= ids
            kept.append(stage)
        if not folded:
            return stages, None
        kept = [
            stage.model_copy(update={"stage_index": index})
            for index, stage in enumerate(kept, start=1)
        ]
        preview = "; ".join(folded[:5]) + ("; ..." if len(folded) > 5 else "")
        note = (
            f"{len(folded)} of {len(stages)} proposed stages were folded: they cited no "
            f"evidence beyond earlier stages and represent inferred tactics, not observed "
            f"progression. Folded stages: {preview}."
        )
        return kept, note

    def _finalise_stages(
        self, stages: list[ChainStage], event_times: dict[str, datetime]
    ) -> list[ChainStage]:
        merged: dict[tuple[str, str | None], ChainStage] = {}
        for stage in stages:
            if not stage.evidence_event_ids:
                continue
            key = (stage.tactic, stage.technique)
            existing = merged.get(key)
            if existing is None:
                merged[key] = stage
            else:
                merged[key] = existing.model_copy(
                    update={
                        "evidence_event_ids": _dedupe(
                            [*existing.evidence_event_ids, *stage.evidence_event_ids]
                        ),
                        "confidence": max(existing.confidence, stage.confidence),
                        "narrative": existing.narrative or stage.narrative,
                    }
                )

        ordered = sorted(
            merged.values(),
            key=lambda stage: (
                self.knowledge.tactic_rank(stage.tactic),
                _first_time(stage.evidence_event_ids, event_times),
                stage.technique or "",
            ),
        )
        return [
            stage.model_copy(
                update={
                    "stage_index": index,
                    "tactic_name": stage.tactic_name or self.knowledge.tactic_name(stage.tactic),
                    "technique_name": stage.technique_name
                    or self._technique_name(stage.technique),
                    "evidence_event_ids": _sorted_by_time(stage.evidence_event_ids, event_times),
                }
            )
            for index, stage in enumerate(ordered[: self.max_stages], start=1)
        ]

    @staticmethod
    def _summary(
        candidate: AttackCandidate,
        stages: list[ChainStage],
        analysis: LLMAttackAnalysis | None,
    ) -> str:
        if analysis is not None and analysis.attack_summary:
            return analysis.attack_summary
        attackers = ", ".join(candidate.attacker_ips[:3]) or "unknown source"
        victims = ", ".join(candidate.victim_ips[:3]) or "unknown destination"
        tactic_names = [
            stage.tactic_name or stage.tactic
            for stage in sorted(stages, key=lambda item: item.stage_index)
        ]
        return (
            f"{attackers} targeted {victims} across {len(stages)} stage(s): "
            f"{' -> '.join(tactic_names)}. "
            f"Correlated from {len(candidate.event_ids)} suspicious event(s) "
            f"with {len(candidate.rule_hits)} rule signature(s)."
        )


def _llm_meta(
    record: LLMCallRecord | None,
    analysis: LLMAttackAnalysis | None,
    degraded: bool,
) -> LLMMeta:
    if record is None and analysis is None:
        return LLMMeta(provider="none", status="not_called", llm_degraded=True)
    if record is None:
        return LLMMeta(
            provider=(analysis.provider or "unknown") if analysis else "unknown",
            model=analysis.model if analysis else None,
            prompt_version=analysis.prompt_version if analysis else None,
            request_id=analysis.request_id if analysis else None,
            status="degraded" if degraded else "success",
            llm_degraded=degraded,
        )
    return LLMMeta(
        provider=record.provider,
        model=record.model,
        prompt_version=record.prompt_version,
        request_id=record.request_id,
        status=str(record.status),
        llm_degraded=degraded or record.fallback_used,
        latency_ms=record.latency_ms,
        input_tokens=record.input_tokens,
        output_tokens=record.output_tokens,
        retry_count=record.retry_count,
        error=record.error,
    )


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _first_time(event_ids: list[str], event_times: dict[str, datetime]) -> datetime:
    times = [event_times[event_id] for event_id in event_ids if event_id in event_times]
    if not times:
        return datetime.max.replace(tzinfo=UTC)
    return min(times)


def _sorted_by_time(event_ids: list[str], event_times: dict[str, datetime]) -> list[str]:
    return sorted(
        _dedupe(event_ids),
        key=lambda event_id: event_times.get(
            event_id, datetime.max.replace(tzinfo=UTC)
        ),
    )


def _dedupe(values: Sequence[str | None]) -> list[str]:
    seen: dict[str, None] = {}
    for value in values:
        if value:
            seen.setdefault(value, None)
    return list(seen)
