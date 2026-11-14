"""Attacker/victim/port/protocol correlation (M2-F5, M2-F6).

Same ``src_ip`` alone is *not* enough to merge events: the victim, the port and
the protocol all contribute.  Incompatible attackers veto a link (unless they
share an IOC), which is what keeps two different attackers on the same victim
as two separate incidents.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from backend.module2_chain.app.config import EntityCorrelationSettings
from backend.module2_chain.correlation.features import EventFeatures

_COMMON_SERVICE_CLASSES: tuple[frozenset[int], ...] = (
    frozenset({80, 443, 8000, 8080, 8443, 8888}),
    frozenset({20, 21, 22, 23, 25, 110, 143, 465, 587, 993, 995}),
    frozenset({135, 137, 138, 139, 445}),
    frozenset({1433, 1521, 3306, 5432, 6379, 27017}),
    frozenset({389, 636, 88, 464}),
    frozenset({3389, 5900, 5985, 5986}),
)


@dataclass(slots=True)
class EntityCorrelator:
    """Scores entity compatibility of two events."""

    settings: EntityCorrelationSettings = field(default_factory=EntityCorrelationSettings)
    name: str = "entity"

    # ------------------------------------------------------------------ #
    # Attackers
    # ------------------------------------------------------------------ #
    def attacker_score(self, left: EventFeatures, right: EventFeatures) -> float:
        if not left.attacker_key or not right.attacker_key:
            # Unknown attacker: never use it as a positive signal.
            return 0.0
        if left.attacker_key == right.attacker_key:
            return 1.0
        if (
            self.settings.attacker_subnet_prefix_v4 < 32
            and left.attacker_subnet
            and left.attacker_subnet == right.attacker_subnet
        ):
            return 0.5
        return 0.0

    def attacker_compatible(self, left: EventFeatures, right: EventFeatures) -> bool:
        if self.attacker_score(left, right) > 0.0:
            return True
        # Unknown attacker on either side: defer to the victim/time/behaviour terms.
        return not (left.attacker_key and right.attacker_key)

    # ------------------------------------------------------------------ #
    # Victims
    # ------------------------------------------------------------------ #
    def victim_score(self, left: EventFeatures, right: EventFeatures) -> float:
        if not left.victim_key or not right.victim_key:
            return 0.0
        if left.victim_key == right.victim_key:
            return 1.0
        if (
            self.settings.victim_subnet_prefix_v4 < 32
            and left.victim_subnet
            and left.victim_subnet == right.victim_subnet
        ):
            return 0.6
        return 0.0

    # ------------------------------------------------------------------ #
    # Ports / protocols
    # ------------------------------------------------------------------ #
    def port_score(self, left: EventFeatures, right: EventFeatures) -> float:
        if left.dst_port is None or right.dst_port is None:
            return 0.0
        if left.dst_port == right.dst_port:
            return 1.0
        for service_class in _COMMON_SERVICE_CLASSES:
            if left.dst_port in service_class and right.dst_port in service_class:
                return 0.5
        return 0.0

    def protocol_score(self, left: EventFeatures, right: EventFeatures) -> float:
        if not left.protocol or not right.protocol:
            return 0.0
        return 1.0 if left.protocol == right.protocol else 0.0

    def session_score(self, left: EventFeatures, right: EventFeatures) -> float:
        if not left.session_id or not right.session_id:
            return 0.0
        return 1.0 if left.session_id == right.session_id else 0.0

    # ------------------------------------------------------------------ #
    def components(self, left: EventFeatures, right: EventFeatures) -> dict[str, float]:
        return {
            "attacker": self.attacker_score(left, right),
            "victim": self.victim_score(left, right),
            "port": self.port_score(left, right),
            "protocol": self.protocol_score(left, right),
        }

    def describe(self, left: EventFeatures, right: EventFeatures) -> list[str]:
        reasons: list[str] = []
        if self.attacker_score(left, right) >= 1.0:
            reasons.append(f"identical attacker {left.attacker_key}")
        elif self.attacker_score(left, right) > 0.0:
            reasons.append(f"attackers inside the same subnet ({left.attacker_key}/{right.attacker_key})")
        if self.victim_score(left, right) >= 1.0:
            reasons.append(f"identical victim {left.victim_key}")
        elif self.victim_score(left, right) > 0.0:
            reasons.append(f"victims inside the same subnet ({left.victim_key}/{right.victim_key})")
        if self.port_score(left, right) >= 1.0:
            reasons.append(f"same destination port {left.dst_port}")
        if self.session_score(left, right) > 0.0:
            reasons.append(f"same Module 1 session {left.session_id}")
        return reasons
