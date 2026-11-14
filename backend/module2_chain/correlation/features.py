"""Lightweight, hashable event features used by the pairwise correlators.

Correlation runs over *features* rather than pydantic models: an O(n) pre-pass
beats attribute lookups inside the pair loop by a wide margin, which matters
when Module 2 has to correlate tens of thousands of suspicious events.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from backend.common.schemas.suspicious_event import SuspiciousEvent
from backend.module2_chain.attack.knowledge import AttackKnowledgeBase, normalise_text


def normalise_ip(value: str | None) -> str | None:
    """Normalise an IP literal (IPv4-mapped IPv6 -> IPv4, strip zone/space)."""

    if not value:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    try:
        parsed = ipaddress.ip_address(candidate.split("%")[0])
    except ValueError:
        return candidate.lower()
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return str(parsed.ipv4_mapped)
    return str(parsed)


def subnet_key(value: str | None, *, v4_prefix: int = 24, v6_prefix: int = 64) -> str:
    """Return the subnet grouping key of an address (``""`` when unusable)."""

    normalised = normalise_ip(value)
    if not normalised:
        return ""
    try:
        parsed = ipaddress.ip_address(normalised)
    except ValueError:
        return normalised
    if isinstance(parsed, ipaddress.IPv4Address):
        if v4_prefix >= 32:
            return str(parsed)
        network = ipaddress.ip_network(f"{parsed}/{v4_prefix}", strict=False)
        return str(network.network_address)
    network6 = ipaddress.ip_network(f"{parsed}/{v6_prefix}", strict=False)
    return str(network6.network_address)


@dataclass(slots=True, frozen=True)
class EventFeatures:
    """Pre-computed correlation features of a single suspicious event."""

    index: int
    event_id: str
    timestamp: float
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    protocol: str | None
    session_id: str | None
    score: float
    rules: tuple[str, ...]
    rule_text: str
    detectors: tuple[str, ...]
    reason_text: str
    ioc_hits: tuple[str, ...]
    categories: tuple[str, ...]
    attacker_key: str
    victim_key: str
    attacker_subnet: str
    victim_subnet: str


def build_features(
    events: list[SuspiciousEvent],
    *,
    knowledge: AttackKnowledgeBase | None = None,
    attacker_prefix: int = 32,
    victim_prefix: int = 24,
) -> list[EventFeatures]:
    """Convert suspicious events into correlation features."""

    features: list[EventFeatures] = []
    for index, event in enumerate(events):
        core = event.event
        detection = event.detection
        rules = tuple(rule for rule in detection.matched_rules if rule)
        detectors = tuple(filter(None, [detection.detector or ""]))
        reason_text = normalise_text(detection.reason or "")
        rule_text = normalise_text(" | ".join((*rules, detection.reason or "", *detectors)))
        categories: tuple[str, ...] = ()
        if knowledge is not None:
            categories = tuple(
                knowledge.classify_category(
                    " | ".join((*rules, detection.reason or "")),
                    detectors=list(detectors),
                )
            )
        src_ip = normalise_ip(core.src_ip)
        dst_ip = normalise_ip(core.dst_ip)
        features.append(
            EventFeatures(
                index=index,
                event_id=core.event_id,
                timestamp=core.timestamp.timestamp(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=core.dst_port,
                protocol=(core.protocol or "").lower() or None,
                session_id=event.session_id,
                score=float(detection.score or 0.0),
                rules=rules,
                rule_text=rule_text,
                detectors=detectors,
                reason_text=reason_text,
                ioc_hits=tuple(hit for hit in detection.ioc_hits if hit),
                categories=categories,
                attacker_key=src_ip or "",
                victim_key=dst_ip or "",
                attacker_subnet=subnet_key(src_ip, v4_prefix=attacker_prefix),
                victim_subnet=subnet_key(dst_ip, v4_prefix=victim_prefix),
            )
        )
    return features
