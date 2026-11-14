"""Threat entity extraction (spec §27).

Entities come from three evidence-bounded sources:

1. network facts of the evidence events (IP / port / protocol),
2. indicators and text patterns found in the detection metadata (CVE, hash,
   domain, tool, username),
3. *validated* LLM entities (already filtered by ``EvidenceValidator``).
"""

from __future__ import annotations

import hashlib

from backend.common.schemas.attack import AttackChain
from backend.common.schemas.entity import ThreatEntity
from backend.common.schemas.enums import EntityRole, EntityType
from backend.common.schemas.suspicious_event import SuspiciousEvent
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.entities.patterns import (
    extract_cves,
    extract_domains,
    extract_hashes,
    extract_tools,
    extract_usernames,
)
from backend.module2_chain.llm.schemas import LLMThreatEntity
from backend.module2_chain.threat_intel.base import classify_indicator

logger = get_logger("entities.extractor")

ENTITY_PREFIX = "ent_"

_ENTITY_TYPE_MAP: dict[str, EntityType] = {
    "ip": EntityType.IP,
    "ipv6": EntityType.IPV6,
    "domain": EntityType.DOMAIN,
    "url": EntityType.URL,
    "hash": EntityType.HASH,
    "cve": EntityType.CVE,
    "port": EntityType.PORT,
    "protocol": EntityType.PROTOCOL,
    "username": EntityType.USERNAME,
    "hostname": EntityType.HOSTNAME,
    "malware": EntityType.MALWARE,
    "tool": EntityType.TOOL,
    "technique": EntityType.TECHNIQUE,
    "asset": EntityType.ASSET,
}

_ROLE_MAP: dict[str, EntityRole] = {
    "attacker": EntityRole.ATTACKER,
    "victim": EntityRole.VICTIM,
    "target": EntityRole.TARGET,
    "infrastructure": EntityRole.INFRASTRUCTURE,
    "tool": EntityRole.TOOL,
    "indicator": EntityRole.INDICATOR,
    "unknown": EntityRole.UNKNOWN,
}


class ThreatEntityExtractor:
    """Extracts :class:`ThreatEntity` objects with an evidence trail."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def extract(
        self,
        task_id: str,
        chains: list[AttackChain],
        events_by_id: dict[str, SuspiciousEvent],
        *,
        llm_entities: dict[str, list[LLMThreatEntity]] | None = None,
    ) -> tuple[list[ThreatEntity], dict[str, list[str]]]:
        """Return ``(entities, chain_id -> entity_ids)``."""

        collected: dict[tuple[str, str, str], ThreatEntity] = {}
        chain_entities: dict[str, list[str]] = {}
        for chain in chains:
            evidence_ids = chain.all_evidence_event_ids() or list(chain.event_ids)
            events = [
                events_by_id[event_id] for event_id in evidence_ids if event_id in events_by_id
            ]
            self._from_chain(chain, events, collected, task_id)
            for llm_entity in (llm_entities or {}).get(chain.chain_id, []):
                self._from_llm(chain, llm_entity, collected, task_id)
            entity_ids = [
                entity.entity_id
                for entity in collected.values()
                if chain.chain_id in entity.chain_ids
            ]
            chain_entities[chain.chain_id] = sorted(set(entity_ids))

        entities = sorted(
            collected.values(),
            key=lambda entity: (str(entity.entity_type), entity.value),
        )
        logger.info(
            "threat entity extraction finished",
            extra={
                "task_id": task_id,
                "stage": "entity_extraction",
                "entities": len(entities),
                "chains": len(chains),
            },
        )
        return entities, chain_entities

    def _from_chain(
        self,
        chain: AttackChain,
        events: list[SuspiciousEvent],
        collected: dict[tuple[str, str, str], ThreatEntity],
        task_id: str,
    ) -> None:
        for ip in chain.attacker_ips:
            self._add(
                collected,
                chain,
                task_id,
                entity_type=_ip_type(ip),
                value=ip,
                role=EntityRole.ATTACKER,
                confidence=0.95,
                evidence_event_ids=[
                    event.event.event_id for event in events if event.event.src_ip == ip
                ],
                tags=["correlated-attacker"],
            )
        for ip in chain.victim_ips:
            self._add(
                collected,
                chain,
                task_id,
                entity_type=_ip_type(ip),
                value=ip,
                role=EntityRole.VICTIM,
                confidence=0.9,
                evidence_event_ids=[
                    event.event.event_id for event in events if event.event.dst_ip == ip
                ],
                tags=["correlated-victim"],
            )
        for port in chain.victim_ports:
            self._add(
                collected,
                chain,
                task_id,
                entity_type=EntityType.PORT,
                value=str(port),
                role=EntityRole.TARGET,
                confidence=0.8,
                evidence_event_ids=[
                    event.event.event_id for event in events if event.event.dst_port == port
                ],
            )
        for stage in chain.stages:
            if stage.technique:
                self._add(
                    collected,
                    chain,
                    task_id,
                    entity_type=EntityType.TECHNIQUE,
                    value=stage.technique,
                    role=EntityRole.UNKNOWN,
                    confidence=stage.confidence,
                    evidence_event_ids=stage.evidence_event_ids,
                    tags=[stage.tactic],
                )

        for event in events:
            text = " | ".join(
                [
                    *event.detection.matched_rules,
                    event.detection.reason or "",
                    event.detection.detector or "",
                ]
            )
            for indicator in event.detection.ioc_hits:
                indicator_type = classify_indicator(indicator)
                entity_type = (
                    _ENTITY_TYPE_MAP.get(str(indicator_type), EntityType.DOMAIN)
                    if indicator_type
                    else EntityType.DOMAIN
                )
                self._add(
                    collected,
                    chain,
                    task_id,
                    entity_type=entity_type,
                    value=indicator,
                    role=EntityRole.INDICATOR,
                    confidence=0.85,
                    evidence_event_ids=[event.event.event_id],
                    tags=["ioc-hit"],
                )
            for cve in extract_cves(text):
                self._add(
                    collected,
                    chain,
                    task_id,
                    entity_type=EntityType.CVE,
                    value=cve,
                    role=EntityRole.INDICATOR,
                    confidence=0.7,
                    evidence_event_ids=[event.event.event_id],
                )
            for digest in extract_hashes(text):
                self._add(
                    collected,
                    chain,
                    task_id,
                    entity_type=EntityType.HASH,
                    value=digest,
                    role=EntityRole.INDICATOR,
                    confidence=0.6,
                    evidence_event_ids=[event.event.event_id],
                )
            for domain in extract_domains(text):
                self._add(
                    collected,
                    chain,
                    task_id,
                    entity_type=EntityType.DOMAIN,
                    value=domain,
                    role=EntityRole.INFRASTRUCTURE,
                    confidence=0.55,
                    evidence_event_ids=[event.event.event_id],
                )
            for username in extract_usernames(text):
                self._add(
                    collected,
                    chain,
                    task_id,
                    entity_type=EntityType.USERNAME,
                    value=username,
                    role=EntityRole.UNKNOWN,
                    confidence=0.5,
                    evidence_event_ids=[event.event.event_id],
                )
            for tool in extract_tools(text):
                self._add(
                    collected,
                    chain,
                    task_id,
                    entity_type=EntityType.TOOL,
                    value=tool,
                    role=EntityRole.TOOL,
                    confidence=0.6,
                    evidence_event_ids=[event.event.event_id],
                )
            if event.event.protocol:
                self._add(
                    collected,
                    chain,
                    task_id,
                    entity_type=EntityType.PROTOCOL,
                    value=event.event.protocol.lower(),
                    role=EntityRole.UNKNOWN,
                    confidence=0.7,
                    evidence_event_ids=[event.event.event_id],
                )

    def _from_llm(
        self,
        chain: AttackChain,
        entity: LLMThreatEntity,
        collected: dict[tuple[str, str, str], ThreatEntity],
        task_id: str,
    ) -> None:
        entity_type = _ENTITY_TYPE_MAP.get(entity.entity_type.strip().lower())
        if entity_type is None:
            return
        role = _ROLE_MAP.get(entity.role.strip().lower(), EntityRole.UNKNOWN)
        self._add(
            collected,
            chain,
            task_id,
            entity_type=entity_type,
            value=entity.value,
            role=role,
            confidence=min(0.9, entity.confidence),
            evidence_event_ids=entity.evidence_event_ids,
            tags=["llm-proposed"],
        )

    @staticmethod
    def _add(
        collected: dict[tuple[str, str, str], ThreatEntity],
        chain: AttackChain,
        task_id: str,
        *,
        entity_type: EntityType,
        value: str,
        role: EntityRole,
        confidence: float,
        evidence_event_ids: list[str],
        tags: list[str] | None = None,
    ) -> None:
        if not value:
            return
        key = (str(entity_type), value.lower(), str(role))
        entity = collected.get(key)
        if entity is None:
            collected[key] = ThreatEntity(
                entity_id=entity_id_for(str(entity_type), value, str(role)),
                entity_type=entity_type,
                value=value,
                role=role,
                confidence=round(min(1.0, confidence), 4),
                evidence_event_ids=sorted(set(evidence_event_ids)),
                chain_ids=[chain.chain_id],
                task_id=task_id,
                first_seen=chain.first_seen,
                last_seen=chain.last_seen,
                tags=list(tags or []),
            )
            return
        entity.evidence_event_ids = sorted(set(entity.evidence_event_ids) | set(evidence_event_ids))
        if chain.chain_id not in entity.chain_ids:
            entity.chain_ids.append(chain.chain_id)
        entity.confidence = round(max(entity.confidence, min(1.0, confidence)), 4)
        entity.tags = sorted(set(entity.tags) | set(tags or []))


def entity_id_for(entity_type: str, value: str, role: str) -> str:
    digest = hashlib.sha256(f"{entity_type}|{value.lower()}|{role}".encode()).hexdigest()
    return f"{ENTITY_PREFIX}{digest[:16]}"


def _ip_type(value: str) -> EntityType:
    return EntityType.IPV6 if ":" in value else EntityType.IP
