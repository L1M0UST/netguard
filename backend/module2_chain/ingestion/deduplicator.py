"""Event de-duplication (M2-F3).

Two deterministic passes:

1. **identity** - the same ``event_id`` must never be analysed twice (Module 1
   may legitimately re-emit a batch);
2. **content** - the same observable (source, destination, port, protocol,
   payload digest, rule signature) inside one time bucket is one fact, however
   many times a sensor reported it.
"""

from __future__ import annotations

import hashlib

from backend.common.schemas.suspicious_event import SuspiciousEvent
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.schemas.internal import DeduplicationResult

logger = get_logger("ingestion.deduplicator")

MAX_REPORTED_DUPLICATES = 200


class EventDeduplicator:
    """Collapses duplicate suspicious events."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.settings = config.dedup

    def content_key(self, event: SuspiciousEvent) -> str:
        bucket_seconds = self.settings.content_hash_time_bucket_seconds
        bucket = int(event.event.timestamp.timestamp() // bucket_seconds)
        payload = "|".join(
            [
                (event.event.src_ip or "").lower(),
                (event.event.dst_ip or "").lower(),
                str(event.event.dst_port or ""),
                (event.event.protocol or "").lower(),
                event.event.payload_digest or "",
                event.rule_signature,
                str(bucket),
            ]
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def deduplicate(self, events: list[SuspiciousEvent]) -> DeduplicationResult:
        result = DeduplicationResult(input_count=len(events))
        if not events:
            return result

        seen_ids: dict[str, int] = {}
        seen_content: dict[str, int] = {}
        kept: list[SuspiciousEvent] = []

        for event in events:
            event_id = event.event.event_id
            if self.settings.by_event_id and event_id in seen_ids:
                result.duplicate_event_id_count += 1
                if len(result.duplicate_event_ids) < MAX_REPORTED_DUPLICATES:
                    result.duplicate_event_ids.append(event_id)
                continue
            if self.settings.content_hash:
                key = self.content_key(event)
                existing_index = seen_content.get(key)
                if existing_index is not None:
                    result.content_duplicate_count += 1
                    current = kept[existing_index]
                    if float(event.detection.score or 0.0) > float(
                        current.detection.score or 0.0
                    ):
                        kept[existing_index] = event
                    continue
                seen_content[key] = len(kept)
            seen_ids[event_id] = len(kept)
            kept.append(event)

        result.events = kept
        logger.info(
            "event de-duplication finished",
            extra={
                "task_id": events[0].event.task_id,
                "stage": "deduplication",
                "input": result.input_count,
                "output": result.output_count,
                "duplicate_event_ids": result.duplicate_event_id_count,
                "content_duplicates": result.content_duplicate_count,
            },
        )
        return result
