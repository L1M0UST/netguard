"""Evidence validation - the anti-hallucination gate (M2-F13, spec §20).

Every LLM claim is checked against the real, already-ingested events.  Invalid
material (unknown event ids, invented techniques, invented indicators) is
removed, confidence is penalised, and if nothing survives the chain degrades to
the deterministic rule result.
"""

from __future__ import annotations

from datetime import UTC, datetime

from backend.common.schemas.attack import AttackCandidate, CandidateTechnique
from backend.common.schemas.suspicious_event import SuspiciousEvent
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.attack.knowledge import AttackKnowledgeBase, load_knowledge_base
from backend.module2_chain.llm.schemas import LLMAttackAnalysis, LLMStage, LLMThreatEntity
from backend.module2_chain.schemas.internal import EvidenceIssue, EvidenceValidationResult

logger = get_logger("attack.evidence_validator")

_ADDRESS_ENTITY_TYPES = {"ip", "ipv6", "hostname", "domain", "url", "hash", "cve"}


class EvidenceValidator:
    """Validates LLM output against the ingested evidence."""

    def __init__(
        self, config: AppConfig, *, knowledge: AttackKnowledgeBase | None = None
    ) -> None:
        self.config = config
        self.settings = config.risk.evidence
        self.knowledge = knowledge or load_knowledge_base(config.attack_kb_path)
        self.allowed_tactics = set(self.knowledge.tactics) | set(self.knowledge.tactic_order)

    # ------------------------------------------------------------------ #
    def validate(
        self,
        candidate: AttackCandidate,
        analysis: LLMAttackAnalysis,
        events: list[SuspiciousEvent],
        candidate_techniques: list[CandidateTechnique] | None = None,
    ) -> tuple[LLMAttackAnalysis, EvidenceValidationResult]:
        event_index = {event.event_id: event for event in events}
        known_ids = set(event_index)
        allowed_techniques = {
            item.technique_id for item in (candidate_techniques or []) if item.technique_id
        }
        result = EvidenceValidationResult(candidate_id=candidate.candidate_id)

        stages, dropped = self._validate_stages(
            analysis, known_ids, allowed_techniques, event_index, result
        )
        entities = self._validate_entities(
            analysis, known_ids, event_index, candidate, result
        )
        self._validate_consistency(candidate, stages, event_index, result)
        self._validate_ordering(stages, event_index, result)
        self._validate_evidence_volume(candidate, stages, result)

        dropped_indexes = {stage.stage_index for stage in dropped}
        if dropped_indexes:
            result.dropped_stage_indexes = sorted(dropped_indexes)
        result.valid_evidence_count = len(
            {event_id for stage in stages for event_id in stage.evidence_event_ids}
        )

        if not stages and analysis.stages:
            result.degraded_to_rules = True
            result.notes.append(
                "all LLM stages were invalid; the deterministic rule result will be used"
            )

        penalty = min(
            self.settings.max_validation_penalty,
            self.settings.penalty_per_validation_issue * (result.error_count + 0.5 * result.warning_count),
        )
        if result.hallucination_detected:
            penalty += self.settings.llm_hallucination_penalty
        result.confidence_penalty = round(min(0.9, penalty), 4)
        result.valid = result.error_count == 0 and not result.degraded_to_rules

        sanitized = analysis.model_copy(
            update={
                "stages": _reindex(stages),
                "threat_entities": entities,
                "uncertainties": _dedupe(
                    [
                        *analysis.uncertainties,
                        *[issue.message for issue in result.issues if issue.severity != "info"],
                    ]
                ),
            }
        )

        logger.info(
            "evidence validation finished",
            extra={
                "task_id": candidate.task_id,
                "candidate_id": candidate.candidate_id,
                "stage": "evidence_validation",
                "valid": result.valid,
                "hallucination": result.hallucination_detected,
                "errors": result.error_count,
                "warnings": result.warning_count,
                "dropped_stages": len(result.dropped_stage_indexes),
                "penalty": result.confidence_penalty,
            },
        )
        return sanitized, result

    # ------------------------------------------------------------------ #
    def _validate_stages(
        self,
        analysis: LLMAttackAnalysis,
        known_ids: set[str],
        allowed_techniques: set[str],
        event_index: dict[str, SuspiciousEvent],
        result: EvidenceValidationResult,
    ) -> tuple[list[LLMStage], list[LLMStage]]:
        del event_index
        valid_stages: list[LLMStage] = []
        dropped: list[LLMStage] = []
        for stage in analysis.stages:
            unknown = [event_id for event_id in stage.evidence_event_ids if event_id not in known_ids]
            if unknown:
                result.hallucination_detected = True
                result.unknown_event_ids.extend(unknown)
                result.issues.append(
                    EvidenceIssue(
                        code="unknown_evidence_event_id",
                        message=(
                            f"stage {stage.stage_index} referenced {len(unknown)} event id(s) "
                            "that do not exist in the evidence set"
                        ),
                        severity="error",
                        stage_index=stage.stage_index,
                        event_id=unknown[0],
                        details={"unknown_event_ids": unknown[:10]},
                    )
                )
            evidence = [event_id for event_id in stage.evidence_event_ids if event_id in known_ids]
            if not evidence:
                result.issues.append(
                    EvidenceIssue(
                        code="stage_without_evidence",
                        message=f"stage {stage.stage_index} has no valid evidence event",
                        severity="error",
                        stage_index=stage.stage_index,
                    )
                )
                dropped.append(stage)
                continue

            tactic = stage.tactic
            if tactic not in self.allowed_tactics:
                result.hallucination_detected = True
                result.issues.append(
                    EvidenceIssue(
                        code="unknown_tactic",
                        message=f"stage {stage.stage_index} uses unknown tactic {tactic!r}",
                        severity="error",
                        stage_index=stage.stage_index,
                        field="tactic",
                    )
                )
                dropped.append(stage)
                continue

            technique = stage.technique
            if technique and technique not in self.knowledge.technique_ids():
                # Not even a real ATT&CK technique: clear hallucination.
                result.hallucination_detected = True
                result.issues.append(
                    EvidenceIssue(
                        code="unknown_technique",
                        message=f"stage {stage.stage_index} uses unknown technique {technique!r}",
                        severity="error",
                        stage_index=stage.stage_index,
                        field="technique",
                    )
                )
                technique = None
            elif technique and allowed_techniques and technique not in allowed_techniques:
                # Real technique, but outside the candidate set the rules proposed.
                result.hallucination_detected = True
                result.issues.append(
                    EvidenceIssue(
                        code="technique_outside_candidate_set",
                        message=(
                            f"stage {stage.stage_index} uses technique {technique} which is not "
                            "part of the candidate technique set"
                        ),
                        severity="error",
                        stage_index=stage.stage_index,
                        field="technique",
                    )
                )
                technique = None

            valid_stages.append(
                stage.model_copy(update={"evidence_event_ids": evidence, "technique": technique})
            )
        return valid_stages, dropped

    def _validate_entities(
        self,
        analysis: LLMAttackAnalysis,
        known_ids: set[str],
        event_index: dict[str, SuspiciousEvent],
        candidate: AttackCandidate,
        result: EvidenceValidationResult,
    ) -> list[LLMThreatEntity]:
        observed = _observed_indicators(event_index)
        observed.update(_normalise_set(candidate.attacker_ips))
        observed.update(_normalise_set(candidate.victim_ips))
        observed.update(_normalise_set(candidate.ioc_hits))

        entities: list[LLMThreatEntity] = []
        for entity in analysis.threat_entities:
            evidence = [
                event_id for event_id in entity.evidence_event_ids if event_id in known_ids
            ]
            if entity.evidence_event_ids and not evidence:
                result.hallucination_detected = True
                result.issues.append(
                    EvidenceIssue(
                        code="entity_without_evidence",
                        message=(
                            f"threat entity {entity.value!r} references event ids that do not exist"
                        ),
                        severity="error",
                        event_id=entity.evidence_event_ids[0],
                        field="threat_entities",
                    )
                )
                continue
            if (
                entity.entity_type.lower() in _ADDRESS_ENTITY_TYPES
                and _normalise(entity.value) not in observed
            ):
                result.hallucination_detected = True
                result.issues.append(
                    EvidenceIssue(
                        code="indicator_not_observed",
                        message=(
                            f"threat entity {entity.value!r} was not observed in any "
                            "evidence event"
                        ),
                        severity="warning",
                        field="threat_entities",
                    )
                )
                continue
            entities.append(entity.model_copy(update={"evidence_event_ids": evidence}))
        return entities

    def _validate_consistency(
        self,
        candidate: AttackCandidate,
        stages: list[LLMStage],
        event_index: dict[str, SuspiciousEvent],
        result: EvidenceValidationResult,
    ) -> None:
        evidence_ids = {event_id for stage in stages for event_id in stage.evidence_event_ids}
        evidence_events = [event_index[event_id] for event_id in evidence_ids if event_id in event_index]
        if not evidence_events:
            return
        observed_sources = {
            _normalise(event.event.src_ip) for event in evidence_events if event.event.src_ip
        }
        observed_destinations = {
            _normalise(event.event.dst_ip) for event in evidence_events if event.event.dst_ip
        }
        if candidate.attacker_ips and not (observed_sources & _normalise_set(candidate.attacker_ips)):
            result.issues.append(
                EvidenceIssue(
                    code="attacker_not_in_evidence",
                    message=(
                        "none of the correlated attacker IPs appear as the source of the "
                        "validated evidence events"
                    ),
                    severity="warning",
                    field="attacker_ips",
                )
            )
        if candidate.victim_ips and not (
            observed_destinations & _normalise_set(candidate.victim_ips)
        ):
            result.issues.append(
                EvidenceIssue(
                    code="victim_not_in_evidence",
                    message=(
                        "none of the correlated victim IPs appear as the destination of the "
                        "validated evidence events"
                    ),
                    severity="warning",
                    field="victim_ips",
                )
            )

    def _validate_ordering(
        self,
        stages: list[LLMStage],
        event_index: dict[str, SuspiciousEvent],
        result: EvidenceValidationResult,
    ) -> None:
        previous: datetime | None = None
        previous_index: int | None = None
        for stage in sorted(stages, key=lambda item: item.stage_index):
            timestamps = [
                _as_utc(event_index[event_id].event.timestamp)
                for event_id in stage.evidence_event_ids
                if event_id in event_index
            ]
            if not timestamps:
                continue
            earliest = min(timestamps)
            if previous is not None and earliest < previous:
                result.issues.append(
                    EvidenceIssue(
                        code="stage_time_regression",
                        message=(
                            f"stage {stage.stage_index} happens before stage {previous_index} "
                            "in time; verify the narrative ordering"
                        ),
                        severity="warning",
                        stage_index=stage.stage_index,
                        details={"previous_stage": previous_index},
                    )
                )
            previous = max(previous, earliest) if previous else earliest
            previous_index = stage.stage_index

    def _validate_evidence_volume(
        self,
        candidate: AttackCandidate,
        stages: list[LLMStage],
        result: EvidenceValidationResult,
    ) -> None:
        minimum = self.config.correlation.min_evidence_count
        evidence_ids = {event_id for stage in stages for event_id in stage.evidence_event_ids}
        if len(evidence_ids) < minimum:
            result.issues.append(
                EvidenceIssue(
                    code="insufficient_evidence",
                    message=(
                        f"only {len(evidence_ids)} valid evidence event(s) survived validation; "
                        f"the configured minimum is {minimum}"
                    ),
                    severity="info",
                    details={"candidate_events": len(candidate.event_ids)},
                )
            )
        if len(stages) > 1 and len(evidence_ids) < len(stages):
            result.issues.append(
                EvidenceIssue(
                    code="stages_share_scarce_evidence",
                    message=(
                        f"{len(stages)} stages are supported by only {len(evidence_ids)} "
                        "evidence event(s)"
                    ),
                    severity="warning",
                )
            )


def _reindex(stages: list[LLMStage]) -> list[LLMStage]:
    return [
        stage.model_copy(update={"stage_index": index})
        for index, stage in enumerate(stages, start=1)
    ]


def _dedupe(values: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for value in values:
        if value:
            seen.setdefault(value, None)
    return list(seen)


def _normalise(value: str | None) -> str:
    return (value or "").strip().lower()


def _normalise_set(values: list[str]) -> set[str]:
    return {_normalise(value) for value in values if value}


def _observed_indicators(event_index: dict[str, SuspiciousEvent]) -> set[str]:
    observed: set[str] = set()
    for event in event_index.values():
        core = event.event
        if core.src_ip:
            observed.add(_normalise(core.src_ip))
        if core.dst_ip:
            observed.add(_normalise(core.dst_ip))
        for hit in event.detection.ioc_hits:
            observed.add(_normalise(hit))
    return observed


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)
