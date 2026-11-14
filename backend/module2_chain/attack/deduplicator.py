"""Attack event deduplication (M2-F17).

Chains sharing a fingerprint describe the same attack: they are merged into one
chain (union of stages/evidence, worst severity wins) and the merged-away ids are
recorded in ``deduplicated_from`` so nothing is silently lost.
"""

from __future__ import annotations

from backend.common.schemas.attack import AttackChain, ChainStage
from backend.common.schemas.enums import Severity
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger

logger = get_logger("attack.deduplicator")


class AttackDeduplicator:
    """Merges attack chains by fingerprint."""

    def __init__(self, config: AppConfig, *, bucket_seconds: float | None = None) -> None:
        self.config = config
        self.bucket_seconds = bucket_seconds

    def deduplicate(
        self, chains: list[AttackChain]
    ) -> tuple[list[AttackChain], list[AttackChain]]:
        """Return ``(unique_chains, merged_away_chains)``."""

        grouped: dict[str, list[AttackChain]] = {}
        order: list[str] = []
        for chain in chains:
            key = chain.fingerprint or chain.chain_id
            if key not in grouped:
                grouped[key] = []
                order.append(key)
            grouped[key].append(chain)

        unique: list[AttackChain] = []
        merged_away: list[AttackChain] = []
        for key in order:
            group = grouped[key]
            if len(group) == 1:
                unique.append(group[0])
                continue
            primary = self._pick_primary(group)
            unique.append(self._merge(primary, group))
            merged_away.extend(chain for chain in group if chain is not primary)
            logger.info(
                "merged duplicate attack chains",
                extra={
                    "task_id": primary.task_id,
                    "stage": "event_deduplication",
                    "fingerprint": key,
                    "merged": len(group),
                    "kept_chain": primary.chain_id,
                },
            )
        return unique, merged_away

    # ------------------------------------------------------------------ #
    @staticmethod
    def _pick_primary(group: list[AttackChain]) -> AttackChain:
        return sorted(
            group,
            key=lambda chain: (
                -chain.severity.rank,
                -len(chain.stages),
                -len(chain.event_ids),
                chain.chain_id,
            ),
        )[0]

    def _merge(self, primary: AttackChain, group: list[AttackChain]) -> AttackChain:
        stage_map: dict[tuple[str, str | None], ChainStage] = {}
        for chain in sorted(group, key=lambda item: (-item.severity.rank, item.chain_id)):
            for stage in sorted(chain.stages, key=lambda item: item.stage_index):
                key = (stage.tactic, stage.technique)
                existing = stage_map.get(key)
                if existing is None:
                    stage_map[key] = stage
                else:
                    stage_map[key] = existing.model_copy(
                        update={
                            "evidence_event_ids": _dedupe(
                                [*existing.evidence_event_ids, *stage.evidence_event_ids]
                            ),
                            "confidence": max(existing.confidence, stage.confidence),
                            "narrative": existing.narrative or stage.narrative,
                        }
                    )

        stages = [
            stage.model_copy(update={"stage_index": index})
            for index, stage in enumerate(
                sorted(stage_map.values(), key=lambda item: item.stage_index), start=1
            )
        ]
        event_ids = _dedupe([event_id for chain in group for event_id in chain.event_ids])
        attacker_ips = _dedupe([ip for chain in group for ip in chain.attacker_ips])
        victim_ips = _dedupe([ip for chain in group for ip in chain.victim_ips])
        victim_ports = sorted({port for chain in group for port in chain.victim_ports})
        severity = max((chain.severity for chain in group), key=lambda item: item.rank)
        confidence = max(chain.confidence for chain in group)
        merged_ids = [chain.chain_id for chain in group if chain.chain_id != primary.chain_id]
        first_seen = min(
            (chain.first_seen for chain in group if chain.first_seen), default=primary.first_seen
        )
        last_seen = max(
            (chain.last_seen for chain in group if chain.last_seen), default=primary.last_seen
        )
        return primary.model_copy(
            update={
                "stages": stages,
                "event_ids": event_ids,
                "attacker_ips": attacker_ips,
                "victim_ips": victim_ips,
                "victim_ports": victim_ports,
                "severity": severity,
                "confidence": confidence,
                "mitre_tactics": [stage.tactic for stage in stages],
                "candidate_ids": _dedupe(
                    [candidate_id for chain in group for candidate_id in chain.candidate_ids]
                ),
                "deduplicated_from": _dedupe(
                    [*primary.deduplicated_from, *merged_ids]
                ),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "summary": primary.summary or max((chain.summary for chain in group), key=len),
            }
        )


def _dedupe(values: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for value in values:
        if value:
            seen.setdefault(value, None)
    return list(seen)


__all__ = ["AttackDeduplicator", "Severity"]
