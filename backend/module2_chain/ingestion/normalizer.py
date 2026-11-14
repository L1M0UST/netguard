"""Event normalisation.

Module 1 already normalises the wire format; Module 2 only canonicalises what it
needs for correlation (IP representation, protocol casing, identifier hygiene)
and never changes the *meaning* of a field.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from backend.common.schemas.suspicious_event import SuspiciousEvent
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.correlation.features import normalise_ip
from backend.module2_chain.schemas.internal import ValidationIssue

logger = get_logger("ingestion.normalizer")


@dataclass(slots=True)
class NormalizationResult:
    """Normalised events plus what actually changed."""

    events: list[SuspiciousEvent] = field(default_factory=list)
    ip_changes: int = 0
    protocol_changes: int = 0
    issues: list[ValidationIssue] = field(default_factory=list)


class EventNormalizer:
    """Canonicalises IP literals, protocols and identifier whitespace."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def normalize(self, events: list[SuspiciousEvent]) -> NormalizationResult:
        result = NormalizationResult()
        for event in events:
            core = event.event
            src = normalise_ip(core.src_ip)
            dst = normalise_ip(core.dst_ip)
            protocol = (core.protocol or "").strip().lower() or None
            changed_ip = src != core.src_ip or dst != core.dst_ip
            changed_protocol = protocol != core.protocol
            normalized = event.model_copy(
                update={
                    "event": core.model_copy(
                        update={
                            "event_id": core.event_id.strip(),
                            "src_ip": src,
                            "dst_ip": dst,
                            "protocol": protocol,
                            "payload_digest": (core.payload_digest or "").strip() or None,
                            "source_file": (core.source_file or "").strip() or None,
                        }
                    ),
                    "detection": event.detection.model_copy(
                        update={
                            "matched_rules": [
                                rule.strip()
                                for rule in event.detection.matched_rules
                                if rule and rule.strip()
                            ],
                            "ioc_hits": [
                                hit.strip()
                                for hit in event.detection.ioc_hits
                                if hit and hit.strip()
                            ],
                            "detector": (event.detection.detector or "").strip() or None,
                        }
                    ),
                    "session_id": (event.session_id or "").strip() or None,
                }
            )
            if changed_ip:
                result.ip_changes += 1
            if changed_protocol:
                result.protocol_changes += 1
            result.events.append(normalized)
        logger.debug(
            "event normalisation finished",
            extra={
                "task_id": events[0].event.task_id if events else None,
                "stage": "normalization",
                "events": len(result.events),
                "ip_changes": result.ip_changes,
                "protocol_changes": result.protocol_changes,
            },
        )
        return result
