"""Build :class:`AttackCandidate` objects from correlated event groups.

``AttackCandidate`` is the unit that later stages (threat intel, ATT&CK mapping,
the LLM) work on.  Building it is pure bookkeeping over Module 1 fields - no
new semantics are invented here.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from datetime import UTC, datetime

from backend.common.schemas.attack import AttackCandidate, ScoreSummary
from backend.common.schemas.suspicious_event import SuspiciousEvent
from backend.module2_chain.attack.knowledge import AttackKnowledgeBase
from backend.module2_chain.correlation.features import EventFeatures

CANDIDATE_PREFIX = "cand_"


def candidate_id_for(task_id: str, event_ids: list[str]) -> str:
    """Deterministic candidate id (stable across replays => idempotent runs)."""

    digest = hashlib.sha256(
        "|".join([task_id, *sorted(event_ids)]).encode("utf-8")
    ).hexdigest()
    return f"{CANDIDATE_PREFIX}{digest[:16]}"


def _percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = quantile * (len(ordered) - 1)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


class CandidateBuilder:
    """Turns a set of suspicious events into one attack candidate."""

    def __init__(self, knowledge: AttackKnowledgeBase | None = None) -> None:
        self.knowledge = knowledge

    def build(
        self,
        task_id: str,
        events: list[SuspiciousEvent],
        *,
        features: list[EventFeatures] | None = None,
        correlation_score: float = 0.0,
        correlation_reasons: list[str] | None = None,
        cluster_keys: list[str] | None = None,
    ) -> AttackCandidate:
        if not events:
            raise ValueError("cannot build an attack candidate from zero events")

        ordered = sorted(events, key=lambda item: (item.event.timestamp, item.event.event_id))
        event_ids = [event.event.event_id for event in ordered]
        scores = [float(event.detection.score or 0.0) for event in ordered]

        attacker_ips = _ranked_values(
            [event.event.src_ip for event in ordered if event.event.src_ip]
        )
        victim_ips = _ranked_values([event.event.dst_ip for event in ordered if event.event.dst_ip])
        victim_ports = sorted(
            {int(event.event.dst_port) for event in ordered if event.event.dst_port is not None}
        )
        protocols = sorted({(event.event.protocol or "").lower() for event in ordered if event.event.protocol})
        rule_hits = sorted({rule for event in ordered for rule in event.detection.matched_rules})
        ioc_hits = sorted({hit for event in ordered for hit in event.detection.ioc_hits})
        session_ids = sorted({event.session_id for event in ordered if event.session_id})

        categories: list[str] = []
        if features:
            counter: Counter[str] = Counter()
            for feature in features:
                counter.update(feature.categories)
            categories = [key for key, _ in counter.most_common()]
        elif self.knowledge is not None:
            categories = self.knowledge.classify_category(
                " | ".join([*rule_hits, *[event.detection.reason or "" for event in ordered]]),
                detectors=[event.detection.detector or "" for event in ordered],
            )

        first_seen = ordered[0].event.timestamp
        last_seen = ordered[-1].event.timestamp
        if first_seen.tzinfo is None:
            first_seen = first_seen.replace(tzinfo=UTC)
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=UTC)

        score_summary = ScoreSummary(
            event_count=len(ordered),
            max_score=max(scores) if scores else 0.0,
            mean_score=(sum(scores) / len(scores)) if scores else 0.0,
            sum_score=sum(scores),
            p95_score=_percentile(scores, 0.95),
        )

        return AttackCandidate(
            candidate_id=candidate_id_for(task_id, event_ids),
            task_id=task_id,
            attacker_ips=attacker_ips,
            victim_ips=victim_ips,
            victim_ports=victim_ports,
            event_ids=event_ids,
            first_seen=_ensure_utc(first_seen),
            last_seen=_ensure_utc(last_seen),
            protocols=protocols,
            rule_hits=rule_hits,
            ioc_hits=ioc_hits,
            score_summary=score_summary,
            session_ids=session_ids,
            attack_categories=categories,
            cluster_keys=sorted(cluster_keys or []),
            correlation_score=round(float(correlation_score), 4),
            correlation_reasons=list(correlation_reasons or []),
        )


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _ranked_values(values: list[str]) -> list[str]:
    """Unique values ordered by descending frequency, then lexicographically."""

    counter: Counter[str] = Counter(values)
    return [value for value, _ in sorted(counter.items(), key=lambda item: (-item[1], item[0]))]
