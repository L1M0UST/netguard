"""CorrelationEngine - combines temporal, entity and behaviour correlation.

Complexity is kept near-linear in practice:

* events are time-sorted and only compared inside an ``max_gap_seconds`` window;
* pairing is *blocked* by attacker IP and by victim IP, so unrelated events are
  never compared at all;
* pairs that are already in the same group are skipped.

All thresholds come from ``config.yaml``; nothing here is hard-coded.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from backend.common.schemas.attack import AttackCandidate
from backend.common.schemas.suspicious_event import SuspiciousEvent
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.attack.candidate_builder import CandidateBuilder
from backend.module2_chain.attack.knowledge import AttackKnowledgeBase, load_knowledge_base
from backend.module2_chain.correlation.behavior import BehaviorCorrelator
from backend.module2_chain.correlation.entity import EntityCorrelator
from backend.module2_chain.correlation.features import EventFeatures, build_features
from backend.module2_chain.correlation.temporal import TemporalCorrelator
from backend.module2_chain.correlation.union_find import UnionFind

logger = get_logger("correlation.engine")

MAX_LINK_REASONS_PER_PAIR = 3
MAX_GROUP_REASONS = 12


@dataclass(slots=True)
class LinkDecision:
    """Whether two events belong to the same attack, and why."""

    linked: bool
    score: float
    components: dict[str, float] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)
    veto: str | None = None


@dataclass(slots=True)
class CandidateGroup:
    """A correlated group of events before it becomes an ``AttackCandidate``."""

    group_id: str
    event_indexes: list[int]
    event_ids: list[str]
    correlation_score: float
    reasons: list[str] = field(default_factory=list)
    cluster_keys: list[str] = field(default_factory=list)


class CorrelationEngine:
    """Deterministic, LLM-free grouping of suspicious events (M2-F4..F7)."""

    def __init__(
        self,
        config: AppConfig,
        *,
        knowledge: AttackKnowledgeBase | None = None,
        builder: CandidateBuilder | None = None,
        temporal: TemporalCorrelator | None = None,
        entity: EntityCorrelator | None = None,
        behavior: BehaviorCorrelator | None = None,
    ) -> None:
        self.config = config
        settings = config.correlation
        self.knowledge = knowledge or load_knowledge_base(config.attack_kb_path)
        self.builder = builder or CandidateBuilder(self.knowledge)
        self.temporal = temporal or TemporalCorrelator(
            window_seconds=settings.correlation_window_seconds,
            max_gap_seconds=settings.max_gap_seconds,
        )
        self.entity = entity or EntityCorrelator(settings.entity)
        self.behavior = behavior or BehaviorCorrelator(settings.behavior)
        self.weights = settings.weights
        self.link_threshold = settings.link_threshold
        self.max_pairs_examined = 2_000_000
        self.pairs_examined = 0
        self.pairs_truncated = False

    # ------------------------------------------------------------------ #
    # Pairwise decision
    # ------------------------------------------------------------------ #
    def link_decision(self, left: EventFeatures, right: EventFeatures) -> LinkDecision:
        time_score = self.temporal.score(left, right)
        if time_score <= 0.0:
            return LinkDecision(linked=False, score=0.0, veto="outside correlation window")

        entity_components = self.entity.components(left, right)
        behavior_components = self.behavior.components(left, right)
        behavior_score = behavior_components["behavior"]
        ioc_overlap = behavior_components["ioc_overlap"]

        if (
            not self.entity.attacker_compatible(left, right)
            and self.config.correlation.entity.same_attacker_required
            and ioc_overlap <= 0.0
        ):
            return LinkDecision(
                linked=False,
                score=0.0,
                veto="different attackers without a shared IOC",
            )

        score = (
            self.weights.time * time_score
            + self.weights.attacker * entity_components["attacker"]
            + self.weights.victim * entity_components["victim"]
            + self.weights.port * entity_components["port"]
            + self.weights.protocol * entity_components["protocol"]
            + self.weights.behavior * behavior_score
        )
        if ioc_overlap > 0.0:
            score += self.config.correlation.entity.shared_ioc_bonus
        if self.entity.session_score(left, right) > 0.0:
            score += 0.1

        components = {
            "time": round(time_score, 4),
            **{key: round(value, 4) for key, value in entity_components.items()},
            **{key: round(value, 4) for key, value in behavior_components.items()},
        }
        score = round(min(1.0, score), 4)
        if score < self.link_threshold:
            return LinkDecision(
                linked=False,
                score=score,
                components=components,
                veto="below link_threshold",
            )

        # Behaviour first: IOC/category evidence is the most informative reason.
        reasons = [
            *self.behavior.describe(left, right),
            *self.entity.describe(left, right),
            *self.temporal_reasons(left, right),
        ]
        return LinkDecision(
            linked=True,
            score=score,
            components=components,
            reasons=reasons[:MAX_LINK_REASONS_PER_PAIR],
        )

    def temporal_reasons(self, left: EventFeatures, right: EventFeatures) -> list[str]:
        described = self.temporal.describe(left, right)
        return [described] if described else []

    # ------------------------------------------------------------------ #
    # Grouping
    # ------------------------------------------------------------------ #
    def correlate_groups(self, events: list[SuspiciousEvent]) -> list[CandidateGroup]:
        if not events:
            return []

        settings = self.config.correlation
        features = build_features(
            events,
            knowledge=self.knowledge,
            attacker_prefix=settings.entity.attacker_subnet_prefix_v4,
            victim_prefix=settings.entity.victim_subnet_prefix_v4,
        )
        order = sorted(range(len(features)), key=lambda index: features[index].timestamp)
        union_find = UnionFind(len(features))
        linked_pairs: list[tuple[int, int, float, list[str]]] = []
        self.pairs_examined = 0
        self.pairs_truncated = False

        attacker_blocks: dict[str, list[int]] = defaultdict(list)
        victim_blocks: dict[str, list[int]] = defaultdict(list)
        for index in order:
            feature = features[index]
            attacker_blocks[feature.attacker_key].append(index)
            victim_blocks[feature.victim_key].append(index)

        for block_name, blocks in (("attacker", attacker_blocks), ("victim", victim_blocks)):
            for key, members in blocks.items():
                if len(members) < 2:
                    continue
                self._link_block(
                    block_name, key, members, features, union_find, linked_pairs
                )

        groups: list[CandidateGroup] = []
        for root, members in union_find.groups().items():
            if len(members) < settings.min_events_per_candidate:
                continue
            ordered_members = sorted(members, key=lambda index: features[index].timestamp)
            if len(ordered_members) > settings.max_events_per_candidate:
                logger.warning(
                    "candidate exceeds correlation.max_events_per_candidate; truncating",
                    extra={
                        "task_id": events[ordered_members[0]].event.task_id,
                        "stage": "correlation",
                        "size": len(ordered_members),
                        "limit": settings.max_events_per_candidate,
                    },
                )
                ordered_members = ordered_members[: settings.max_events_per_candidate]
            groups.append(
                self._make_group(root, ordered_members, features, linked_pairs)
            )

        groups.sort(key=lambda group: features[group.event_indexes[0]].timestamp)
        logger.info(
            "correlation finished",
            extra={
                "task_id": events[0].event.task_id,
                "stage": "correlation",
                "events": len(events),
                "candidates": len(groups),
                "pairs_examined": self.pairs_examined,
                "pairs_truncated": self.pairs_truncated,
            },
        )
        return groups

    def _link_block(
        self,
        block_name: str,
        key: str,
        members: list[int],
        features: list[EventFeatures],
        union_find: UnionFind,
        linked_pairs: list[tuple[int, int, float, list[str]]],
    ) -> None:
        for position, left_index in enumerate(members):
            left = features[left_index]
            for right_index in members[position + 1 :]:
                right = features[right_index]
                if right.timestamp - left.timestamp > self.temporal.max_gap_seconds:
                    break
                if union_find.connected(left_index, right_index):
                    continue
                if self.pairs_examined >= self.max_pairs_examined:
                    self.pairs_truncated = True
                    return
                self.pairs_examined += 1
                decision = self.link_decision(left, right)
                if not decision.linked:
                    continue
                if union_find.union(left_index, right_index):
                    linked_pairs.append(
                        (
                            left_index,
                            right_index,
                            decision.score,
                            [
                                f"{block_name} block {key}",
                                *decision.reasons,
                            ][:MAX_LINK_REASONS_PER_PAIR],
                        )
                    )

    def _make_group(
        self,
        root: int,
        members: list[int],
        features: list[EventFeatures],
        linked_pairs: list[tuple[int, int, float, list[str]]],
    ) -> CandidateGroup:
        member_set = set(members)
        scores: list[float] = []
        reasons: list[str] = []
        for left_index, right_index, score, pair_reasons in linked_pairs:
            if left_index in member_set and right_index in member_set:
                scores.append(score)
                reasons.extend(pair_reasons)
        cluster_keys: dict[str, None] = {}
        for index in members:
            feature = features[index]
            if feature.attacker_key:
                cluster_keys.setdefault(f"attacker:{feature.attacker_key}", None)
            if feature.victim_key:
                cluster_keys.setdefault(f"victim:{feature.victim_key}", None)
            for category in feature.categories:
                cluster_keys.setdefault(f"category:{category}", None)
        event_ids = [features[index].event_id for index in members]
        return CandidateGroup(
            group_id=f"grp_{root}",
            event_indexes=list(members),
            event_ids=event_ids,
            correlation_score=round(sum(scores) / len(scores), 4) if scores else 0.0,
            reasons=_dedupe(reasons)[:MAX_GROUP_REASONS],
            cluster_keys=list(cluster_keys),
        )

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def correlate(self, events: list[SuspiciousEvent]) -> list[AttackCandidate]:
        """Correlate events into :class:`AttackCandidate` objects (M2-F4..F7)."""

        if not events:
            return []
        features = build_features(
            events,
            knowledge=self.knowledge,
            attacker_prefix=self.config.correlation.entity.attacker_subnet_prefix_v4,
            victim_prefix=self.config.correlation.entity.victim_subnet_prefix_v4,
        )
        groups = self.correlate_groups(events)
        by_id = {feature.index: event for feature, event in zip(features, events, strict=False)}
        candidates: list[AttackCandidate] = []
        for group in groups:
            group_events = [by_id[index] for index in group.event_indexes if index in by_id]
            if not group_events:
                continue
            candidates.append(
                self.builder.build(
                    group_events[0].event.task_id,
                    group_events,
                    features=[features[index] for index in group.event_indexes],
                    correlation_score=group.correlation_score,
                    correlation_reasons=group.reasons,
                    cluster_keys=group.cluster_keys,
                )
            )
        return candidates


def _dedupe(values: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for value in values:
        if value:
            seen.setdefault(value, None)
    return list(seen)
