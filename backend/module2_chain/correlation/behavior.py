"""Behavioural correlation (rule type, attack category, IOC, session)."""

from __future__ import annotations

from dataclasses import dataclass, field

from backend.module2_chain.app.config import BehaviorCorrelationSettings
from backend.module2_chain.correlation.features import EventFeatures


@dataclass(slots=True)
class BehaviorCorrelator:
    """Scores whether two events look like parts of the same attack behaviour."""

    settings: BehaviorCorrelationSettings = field(default_factory=BehaviorCorrelationSettings)
    name: str = "behavior"

    # ------------------------------------------------------------------ #
    def rule_similarity(self, left: EventFeatures, right: EventFeatures) -> float:
        """Jaccard similarity of matched-rule sets, with a text fallback."""

        left_rules = {rule.lower() for rule in left.rules}
        right_rules = {rule.lower() for rule in right.rules}
        if left_rules and right_rules:
            union = left_rules | right_rules
            if union:
                return len(left_rules & right_rules) / len(union)
        if left.rule_text and right.rule_text:
            left_tokens = set(left.rule_text.split())
            right_tokens = set(right.rule_text.split())
            union = left_tokens | right_tokens
            if union:
                return 0.5 * len(left_tokens & right_tokens) / len(union)
        return 0.0

    def category_affinity(self, left: EventFeatures, right: EventFeatures) -> float:
        """How naturally two behaviour categories follow each other."""

        if not left.categories or not right.categories:
            return 0.0
        best = 0.0
        for left_category in left.categories:
            for right_category in right.categories:
                if left_category == right_category:
                    best = max(best, 0.8)
                    continue
                affinity = self.settings.category_affinity.get(
                    f"{left_category}:{right_category}"
                ) or self.settings.category_affinity.get(f"{right_category}:{left_category}")
                if affinity:
                    best = max(best, float(affinity))
        return best

    def ioc_overlap(self, left: EventFeatures, right: EventFeatures) -> float:
        if not left.ioc_hits or not right.ioc_hits:
            return 0.0
        shared = set(left.ioc_hits) & set(right.ioc_hits)
        if not shared:
            return 0.0
        union = set(left.ioc_hits) | set(right.ioc_hits)
        return len(shared) / len(union) if union else 0.0

    def score(self, left: EventFeatures, right: EventFeatures) -> float:
        rule = self.rule_similarity(left, right)
        if rule < self.settings.rule_similarity_threshold:
            rule = 0.0
        behaviour = max(
            rule,
            self.category_affinity(left, right),
            self.ioc_overlap(left, right),
        )
        if left.session_id and left.session_id == right.session_id:
            behaviour = min(1.0, behaviour + 0.3)
        return behaviour

    def components(self, left: EventFeatures, right: EventFeatures) -> dict[str, float]:
        rule = self.rule_similarity(left, right)
        if rule < self.settings.rule_similarity_threshold:
            rule = 0.0
        return {
            "behavior": self.score(left, right),
            "rule_similarity": rule,
            "category_affinity": self.category_affinity(left, right),
            "ioc_overlap": self.ioc_overlap(left, right),
        }

    def describe(self, left: EventFeatures, right: EventFeatures) -> list[str]:
        # Rare, high-signal reasons first: a shared IOC or session is much more
        # informative than a generic rule-name similarity.
        reasons: list[str] = []
        if left.session_id and left.session_id == right.session_id:
            reasons.append(f"same session {left.session_id}")
        if self.ioc_overlap(left, right) > 0.0:
            shared = sorted(set(left.ioc_hits) & set(right.ioc_hits))
            reasons.append("shared IOC " + ", ".join(shared[:3]))
        affinity = self.category_affinity(left, right)
        rule = self.rule_similarity(left, right)
        if affinity > 0.0:
            reasons.append(
                "behaviour categories {} -> {} (affinity={:.2f})".format(
                    "/".join(left.categories[:2]) or "unknown",
                    "/".join(right.categories[:2]) or "unknown",
                    affinity,
                )
            )
        if rule >= self.settings.rule_similarity_threshold:
            reasons.append(f"similar rule hits (similarity={rule:.2f})")
        return reasons
