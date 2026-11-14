"""Attacker profiling (M2-F18, spec §26).

A profile is strictly **evidence bounded**: it aggregates what the chains and
events actually show.  Attribution (group name, nationality, identity) is never
invented - it stays ``Not Determined`` unless explicit evidence exists.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from datetime import datetime

from backend.common.schemas.attack import AttackChain
from backend.common.schemas.enums import Severity
from backend.common.schemas.profile import UNKNOWN_ATTRIBUTION, AttackerProfile
from backend.common.schemas.suspicious_event import SuspiciousEvent
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.attack.knowledge import AttackKnowledgeBase, load_knowledge_base
from backend.module2_chain.entities.patterns import (
    extract_domains,
    extract_tools,
    extract_usernames,
)

logger = get_logger("profiling.attacker_profiler")

ATTACKER_PREFIX = "attacker_"
UNKNOWN_ATTACKER_KEY = "unknown"


class AttackerProfiler:
    """Aggregates chains into :class:`AttackerProfile` objects."""

    def __init__(
        self, config: AppConfig, *, knowledge: AttackKnowledgeBase | None = None
    ) -> None:
        self.config = config
        self.knowledge = knowledge or load_knowledge_base(config.attack_kb_path)

    def profile(
        self,
        task_id: str,
        chains: list[AttackChain],
        events_by_id: dict[str, SuspiciousEvent],
    ) -> list[AttackerProfile]:
        grouped: dict[str, list[AttackChain]] = {}
        order: list[str] = []
        for chain in chains:
            key = chain.attacker_ips[0] if chain.attacker_ips else UNKNOWN_ATTACKER_KEY
            if key not in grouped:
                grouped[key] = []
                order.append(key)
            grouped[key].append(chain)

        profiles = [
            self._build_profile(task_id, key, grouped[key], events_by_id) for key in order
        ]
        profiles.sort(
            key=lambda profile: (-profile.risk_score, -profile.attack_count, profile.attacker_id)
        )
        logger.info(
            "attacker profiling finished",
            extra={
                "task_id": task_id,
                "stage": "profiling",
                "profiles": len(profiles),
                "chains": len(chains),
            },
        )
        return profiles

    def _build_profile(
        self,
        task_id: str,
        key: str,
        chains: list[AttackChain],
        events_by_id: dict[str, SuspiciousEvent],
    ) -> AttackerProfile:
        attacker_ips: dict[str, None] = {}
        target_assets: dict[str, None] = {}
        target_ports: dict[int, None] = {}
        techniques: dict[str, None] = {}
        tactics: dict[str, None] = {}
        chain_ids: dict[str, None] = {}
        evidence: dict[str, None] = {}
        iocs: dict[str, None] = {}
        domains: dict[str, None] = {}
        usernames: dict[str, None] = {}
        tools: dict[str, None] = {}
        severity_distribution: Counter[str] = Counter()
        first_seen: datetime | None = None
        last_seen: datetime | None = None
        confidence_num = 0.0
        confidence_den = 0.0
        degraded = False
        max_severity = Severity.INFO
        risk_score = 0.0

        for chain in chains:
            chain_ids.setdefault(chain.chain_id, None)
            for ip in chain.attacker_ips:
                attacker_ips.setdefault(ip, None)
            for ip in chain.victim_ips:
                target_assets.setdefault(ip, None)
            for port in chain.victim_ports:
                target_ports.setdefault(int(port), None)
            for stage in chain.stages:
                if stage.technique:
                    techniques.setdefault(stage.technique, None)
                tactics.setdefault(stage.tactic, None)
            for event_id in chain.all_evidence_event_ids() or chain.event_ids:
                evidence.setdefault(event_id, None)
            severity_distribution[chain.severity.value] += 1
            if chain.severity.rank > max_severity.rank:
                max_severity = chain.severity
            risk_score = max(risk_score, chain.risk_score.score)
            degraded = degraded or chain.llm_degraded
            weight = max(1.0, float(len(chain.event_ids)))
            confidence_num += chain.confidence * weight
            confidence_den += weight
            if chain.first_seen is not None:
                first_seen = (
                    min(first_seen, chain.first_seen) if first_seen else chain.first_seen
                )
            if chain.last_seen is not None:
                last_seen = max(last_seen, chain.last_seen) if last_seen else chain.last_seen

        for event_id in evidence:
            event = events_by_id.get(event_id)
            if event is None:
                continue
            for hit in event.detection.ioc_hits:
                iocs.setdefault(hit, None)
                for domain in extract_domains(hit):
                    domains.setdefault(domain, None)
            text = " | ".join(
                [
                    *event.detection.matched_rules,
                    event.detection.reason or "",
                    event.detection.detector or "",
                ]
            )
            for username in extract_usernames(text):
                usernames.setdefault(username, None)
            for tool in extract_tools(text):
                tools.setdefault(tool, None)

        confidence = (confidence_num / confidence_den) if confidence_den else 0.0
        return AttackerProfile(
            attacker_id=self.attacker_id(key),
            task_id=task_id,
            attacker_ips=sorted(attacker_ips),
            domains=sorted(domains),
            usernames=sorted(usernames),
            tools=sorted(tools),
            techniques=sorted(techniques),
            tactics=sorted(tactics, key=self.knowledge.tactic_rank),
            target_assets=sorted(target_assets),
            target_ports=sorted(target_ports),
            first_seen=first_seen,
            last_seen=last_seen,
            attack_count=len(chains),
            severity_distribution=dict(severity_distribution),
            behavior_summary=self._behaviour_summary(
                key, len(chains), target_assets, tactics, techniques, first_seen, last_seen
            ),
            confidence=round(min(1.0, confidence), 4),
            evidence_event_ids=sorted(evidence),
            chain_ids=list(chain_ids),
            observed_iocs=sorted(iocs),
            max_severity=max_severity,
            risk_score=round(risk_score, 2),
            attribution=UNKNOWN_ATTRIBUTION,
            attribution_confidence=0.0,
            attribution_evidence_event_ids=[],
            llm_degraded=degraded,
            notes=[
                "Attribution (group, identity, country) is intentionally left "
                "undetermined: no supporting evidence was available.",
            ],
        )

    @staticmethod
    def attacker_id(key: str) -> str:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return f"{ATTACKER_PREFIX}{digest[:12]}"

    def _behaviour_summary(
        self,
        key: str,
        chain_count: int,
        target_assets: dict[str, None],
        tactics: dict[str, None],
        techniques: dict[str, None],
        first_seen: datetime | None,
        last_seen: datetime | None,
    ) -> str:
        source = (
            "an unidentified source" if key == UNKNOWN_ATTACKER_KEY else f"source {key}"
        )
        tactic_names = [
            self.knowledge.tactic_name(tactic)
            for tactic in sorted(tactics, key=self.knowledge.tactic_rank)
        ]
        parts = [
            f"{source} was linked to {chain_count} attack chain(s) against "
            f"{len(target_assets)} target asset(s).",
        ]
        if tactic_names:
            parts.append(f"Observed progress: {' -> '.join(tactic_names)}.")
        if techniques:
            suffix = " ..." if len(techniques) > 8 else ""
            parts.append(
                f"ATT&CK techniques: {', '.join(sorted(techniques)[:8])}{suffix}."
            )
        if first_seen and last_seen:
            parts.append(
                f"Activity window: {first_seen.isoformat()} to {last_seen.isoformat()}."
            )
        return " ".join(parts)
