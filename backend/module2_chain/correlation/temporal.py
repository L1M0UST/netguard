"""Temporal correlation (M2-F4).

Two events are temporally compatible when their gap is inside
``correlation_window_seconds``; between the window and ``max_gap_seconds`` the
score decays linearly so that a slow, multi-stage intrusion still clusters.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from backend.module2_chain.correlation.features import EventFeatures


@dataclass(slots=True)
class TemporalCorrelator:
    window_seconds: float = 300.0
    max_gap_seconds: float = 600.0
    name: str = "temporal"
    reasons: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.max_gap_seconds < self.window_seconds:
            self.max_gap_seconds = self.window_seconds

    def score_gap(self, gap_seconds: float) -> float:
        gap = abs(gap_seconds)
        if gap <= self.window_seconds:
            return 1.0
        if gap >= self.max_gap_seconds:
            return 0.0
        span = self.max_gap_seconds - self.window_seconds
        return max(0.0, 1.0 - (gap - self.window_seconds) / span)

    def score(self, left: EventFeatures, right: EventFeatures) -> float:
        return self.score_gap(right.timestamp - left.timestamp)

    def components(self, left: EventFeatures, right: EventFeatures) -> dict[str, float]:
        return {"time": self.score(left, right)}

    def is_within_hard_limit(self, left: EventFeatures, right: EventFeatures) -> bool:
        """Cheap pre-filter used to bound the pair loop."""

        return abs(right.timestamp - left.timestamp) <= self.max_gap_seconds

    def describe(self, left: EventFeatures, right: EventFeatures) -> str | None:
        gap = abs(right.timestamp - left.timestamp)
        if gap <= self.window_seconds:
            return f"events occur within {int(gap)}s (inside the correlation window)"
        if gap < self.max_gap_seconds:
            return f"events are {int(gap)}s apart (inside the extended gap limit)"
        return None
