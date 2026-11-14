"""Deterministic ATT&CK candidate mapping (M2-F9, M2-F10).

Rules, behaviour categories, ports, protocols and IOC hits are mapped onto a
*candidate* tactic/technique set **before** the LLM is involved.  The LLM only
re-ranks and narrates this set - it may never invent a technique outside it
(enforced later by the evidence validator).
"""

from __future__ import annotations

from backend.common.schemas.attack import AttackCandidate, CandidateTechnique
from backend.common.schemas.enums import TechniqueSource
from backend.common.schemas.suspicious_event import SuspiciousEvent
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.attack.knowledge import (
    AttackKnowledgeBase,
    TechniqueDef,
    TechniqueMatch,
    TechniqueSignals,
    keyword_hit,
    load_knowledge_base,
    normalise_text,
)

logger = get_logger("attack.technique_mapper")

MAX_EVIDENCE_PER_TECHNIQUE = 20


class AttackTechniqueMapper:
    """Maps one correlated candidate onto candidate ATT&CK techniques."""

    def __init__(
        self, config: AppConfig, *, knowledge: AttackKnowledgeBase | None = None
    ) -> None:
        self.config = config
        self.settings = config.attack
        self.knowledge = knowledge or load_knowledge_base(config.attack_kb_path)

    # ------------------------------------------------------------------ #
    def signals(
        self, candidate: AttackCandidate, events: list[SuspiciousEvent]
    ) -> TechniqueSignals:
        rules: dict[str, None] = {}
        detectors: dict[str, None] = {}
        reasons: dict[str, None] = {}
        iocs: dict[str, None] = {}
        ports: dict[int, None] = {}
        protocols: dict[str, None] = {}
        for event in events:
            for rule in event.detection.matched_rules:
                if rule:
                    rules.setdefault(rule, None)
            if event.detection.detector:
                detectors.setdefault(event.detection.detector, None)
            if event.detection.reason:
                reasons.setdefault(event.detection.reason, None)
            for hit in event.detection.ioc_hits:
                if hit:
                    iocs.setdefault(hit, None)
            if event.event.dst_port is not None:
                ports.setdefault(int(event.event.dst_port), None)
            if event.event.protocol:
                protocols.setdefault(event.event.protocol.lower(), None)
        for rule in candidate.rule_hits:
            rules.setdefault(rule, None)
        for hit in candidate.ioc_hits:
            iocs.setdefault(hit, None)
        for port in candidate.victim_ports:
            ports.setdefault(int(port), None)
        for protocol in candidate.protocols:
            protocols.setdefault(protocol.lower(), None)

        categories: list[str] = list(candidate.attack_categories)
        if not categories:
            categories = self.knowledge.classify_category(
                " | ".join([*rules, *reasons]), detectors=list(detectors)
            )
        return TechniqueSignals(
            rules=list(rules),
            detectors=list(detectors),
            reasons=list(reasons),
            ports=sorted(ports),
            protocols=sorted(protocols),
            ioc_hits=list(iocs),
            categories=categories,
            max_score=candidate.score_summary.max_score,
        )

    # ------------------------------------------------------------------ #
    def map_candidate(
        self, candidate: AttackCandidate, events: list[SuspiciousEvent]
    ) -> tuple[list[CandidateTechnique], TechniqueSignals]:
        signals = self.signals(candidate, events)
        matches = self.knowledge.match_techniques(
            signals,
            min_confidence=self.settings.min_technique_confidence,
            max_results=self.settings.max_candidate_techniques,
        )
        if not matches:
            matches = self._category_fallback(candidate, signals)

        mapped: list[CandidateTechnique] = []
        for match in matches:
            mapped.append(
                CandidateTechnique(
                    tactic_id=match.tactic_id,
                    tactic_name=match.tactic_name,
                    technique_id=match.technique.id or None,
                    technique_name=match.technique.name,
                    confidence=match.confidence,
                    evidence_event_ids=self._evidence_for(match, events),
                    reason=match.reason,
                    source=TechniqueSource.RULE,
                    matched_rules=list(signals.rules)[:10],
                )
            )
        logger.debug(
            "mapped candidate techniques",
            extra={
                "task_id": candidate.task_id,
                "candidate_id": candidate.candidate_id,
                "stage": "technique_mapping",
                "techniques": len(mapped),
                "categories": ",".join(signals.categories[:5]),
            },
        )
        return mapped, signals

    def map_candidates(
        self,
        candidates: list[AttackCandidate],
        events_by_candidate: dict[str, list[SuspiciousEvent]],
    ) -> dict[str, list[CandidateTechnique]]:
        return {
            candidate.candidate_id: self.map_candidate(
                candidate, events_by_candidate.get(candidate.candidate_id, [])
            )[0]
            for candidate in candidates
        }

    # ------------------------------------------------------------------ #
    def _category_fallback(
        self, candidate: AttackCandidate, signals: TechniqueSignals
    ) -> list[TechniqueMatch]:
        """Last resort: derive one tactic-level candidate per behaviour category."""

        matches: list[TechniqueMatch] = []
        for category in signals.categories[: self.settings.max_candidate_techniques]:
            tactic_id = self.knowledge.category_tactic(category)
            if not tactic_id:
                continue
            definition = self.knowledge.categories.get(category)
            matches.append(
                TechniqueMatch(
                    technique=TechniqueDef(
                        id="",
                        name=definition.label if definition else category,
                        tactic=tactic_id,
                        base_confidence=0.3,
                    ),
                    tactic_id=tactic_id,
                    tactic_name=self.knowledge.tactic_name(tactic_id),
                    confidence=0.3,
                    reason=(
                        f"behaviour category {category} observed, but no rule signature "
                        "matched a specific technique"
                    ),
                    matched_rules=list(signals.rules)[:10],
                    matched_signals=[f"category:{category}"],
                )
            )
        if not matches and candidate.event_ids:
            matches.append(
                TechniqueMatch(
                    technique=TechniqueDef(
                        id="", name="Unclassified", tactic="TA0007", base_confidence=0.2
                    ),
                    tactic_id="TA0007",
                    tactic_name=self.knowledge.tactic_name("TA0007"),
                    confidence=0.2,
                    reason="events are suspicious but no ATT&CK signature matched",
                    matched_rules=list(signals.rules)[:10],
                    matched_signals=["fallback"],
                )
            )
        return matches

    def _evidence_for(
        self, match: TechniqueMatch, events: list[SuspiciousEvent]
    ) -> list[str]:
        """Attribute the technique to the events that actually carry its signals."""

        technique = match.technique
        keywords = [normalise_text(keyword) for keyword in technique.keywords]
        categories = {item.lower() for item in technique.categories}
        matched_ids: list[str] = []
        for event in events:
            haystack = normalise_text(
                " | ".join(
                    [
                        *event.detection.matched_rules,
                        event.detection.reason or "",
                        event.detection.detector or "",
                    ]
                )
            )
            if keywords and any(keyword_hit(keyword, haystack) for keyword in keywords):
                matched_ids.append(event.event.event_id)
                continue
            if categories:
                event_categories = {
                    item.lower()
                    for item in self.knowledge.classify_category(
                        " | ".join([*event.detection.matched_rules, event.detection.reason or ""]),
                        detectors=[event.detection.detector or ""],
                    )
                }
                if categories & event_categories:
                    matched_ids.append(event.event.event_id)
        if not matched_ids and events:
            # Keep the strongest evidence rather than emitting an evidence-free stage.
            ranked = sorted(
                events, key=lambda item: (-float(item.detection.score or 0.0), item.event.timestamp)
            )
            matched_ids = [event.event.event_id for event in ranked[:3]]
        return matched_ids[:MAX_EVIDENCE_PER_TECHNIQUE]
