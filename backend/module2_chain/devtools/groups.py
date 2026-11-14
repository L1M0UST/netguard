"""Synthetic *multi-group* batches.

``build_mixed_batch`` produces one group per scenario (8 groups).  Fixture
generation and load tests need many independent attack groups, so this module
gives every group its own attacker address: correlation then yields exactly one
candidate per group, which makes the fixtures predictable.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from backend.common.schemas.suspicious_event import SuspiciousEvent
from backend.module2_chain.devtools.synthetic import BASE_TIME, SCENARIOS, build_events


def attacker_for_group(index: int) -> str:
    """Deterministic, unique attacker address per group."""

    third = index // 250
    fourth = (index % 250) + 1
    return f"198.18.{third}.{fourth}"


def build_grouped_batch(
    *,
    task_id: str,
    groups: int = 8,
    seed: int = 7,
    start: datetime = BASE_TIME,
    group_offset: int = 0,
) -> list[SuspiciousEvent]:
    """Build ``groups`` independent attack groups (one attacker each)."""

    scenarios = list(SCENARIOS)
    events: list[SuspiciousEvent] = []
    counter = [0]
    for index in range(groups):
        scenario = scenarios[index % len(scenarios)]
        produced = build_events(
            scenario,
            task_id=task_id,
            attacker=attacker_for_group(index + group_offset),
            start=start + timedelta(minutes=index),
            seed=seed + index,
            event_counter=counter,
        )
        events.extend(produced.events)
    events.sort(key=lambda event: event.event.timestamp)
    return events


def build_large_grouped_batch(
    *,
    task_id: str,
    groups: int = 100,
    seed: int = 23,
) -> list[SuspiciousEvent]:
    """Convenience wrapper used by the fixture generator (100 groups)."""

    return build_grouped_batch(task_id=task_id, groups=groups, seed=seed)
