"""Alert construction from attack chains (Module 2 -> Module 3)."""

from __future__ import annotations

import hashlib

from backend.common.schemas.alert import Alert
from backend.common.schemas.attack import AttackChain
from backend.common.schemas.enums import Severity
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger

logger = get_logger("reporting.alert_builder")

ALERT_PREFIX = "alert_"

_TACTIC_TITLES: dict[str, str] = {
    "TA0043": "Reconnaissance activity",
    "TA0042": "Attack infrastructure preparation",
    "TA0001": "Initial access attempt",
    "TA0002": "Code execution observed",
    "TA0003": "Persistence established",
    "TA0004": "Privilege escalation",
    "TA0005": "Defence evasion",
    "TA0006": "Credential access attempt",
    "TA0007": "Discovery activity",
    "TA0008": "Lateral movement",
    "TA0009": "Data collection",
    "TA0011": "Command and control",
    "TA0010": "Data exfiltration",
    "TA0040": "Destructive impact",
}


class AlertBuilder:
    """Builds one actionable alert per (deduplicated) attack chain."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def build(self, chain: AttackChain) -> Alert:
        tactics = [stage.tactic for stage in chain.stages]
        worst_tactic = ""
        if chain.stages:
            worst_tactic = chain.stages[0].tactic
        title = self._title(chain, worst_tactic)
        alert = Alert(
            alert_id=self.alert_id(chain.chain_id),
            task_id=chain.task_id,
            chain_id=chain.chain_id,
            title=title,
            description=chain.summary,
            severity=chain.severity,
            confidence=chain.confidence,
            risk_score=chain.risk_score.score,
            first_seen=chain.first_seen,
            last_seen=chain.last_seen,
            attacker_ips=list(chain.attacker_ips),
            victim_ips=list(chain.victim_ips),
            mitre_tactics=_dedupe(tactics),
            mitre_techniques=[
                stage.technique for stage in chain.stages if stage.technique
            ],
            evidence_event_ids=chain.all_evidence_event_ids() or list(chain.event_ids),
            fingerprint=chain.fingerprint,
            llm_degraded=chain.llm_degraded,
            risk_factors=[factor.model_dump(mode="json") for factor in chain.risk_score.factors],
            tags=self._tags(chain),
        )
        logger.debug(
            "alert built",
            extra={
                "task_id": chain.task_id,
                "alert_id": alert.alert_id,
                "stage": "report_generation",
                "severity": str(alert.severity),
            },
        )
        return alert

    def build_many(self, chains: list[AttackChain]) -> list[Alert]:
        alerts = [self.build(chain) for chain in chains]
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        alerts.sort(key=lambda alert: (order[alert.severity], -alert.risk_score, alert.alert_id))
        return alerts

    @staticmethod
    def alert_id(chain_id: str) -> str:
        digest = hashlib.sha256(chain_id.encode("utf-8")).hexdigest()
        return f"{ALERT_PREFIX}{digest[:16]}"

    def _title(self, chain: AttackChain, worst_tactic: str) -> str:
        base = _TACTIC_TITLES.get(worst_tactic, "Suspicious attack activity")
        attackers = ", ".join(chain.attacker_ips[:2]) or "unknown source"
        victims = ", ".join(chain.victim_ips[:2]) or "unknown target"
        stage_count = len(chain.stages)
        if stage_count > 1:
            return f"{base}: {attackers} -> {victims} ({stage_count} stages)"
        return f"{base}: {attackers} -> {victims}"

    @staticmethod
    def _tags(chain: AttackChain) -> list[str]:
        tags = {"module2", f"severity:{chain.severity.value}"}
        if chain.llm_degraded:
            tags.add("llm-degraded")
        if chain.deduplicated_from:
            tags.add("deduplicated")
        for stage in chain.stages:
            tags.add(f"tactic:{stage.tactic}")
            if stage.technique:
                tags.add(f"technique:{stage.technique}")
        return sorted(tags)


def _dedupe(values: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for value in values:
        if value:
            seen.setdefault(value, None)
    return list(seen)
