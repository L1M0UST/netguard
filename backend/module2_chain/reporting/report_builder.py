"""RiskEventReport assembly (M2-F19, spec §28)."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any

from backend.common.schemas.alert import Alert
from backend.common.schemas.attack import AttackChain
from backend.common.schemas.entity import ThreatEntity
from backend.common.schemas.enums import Severity
from backend.common.schemas.profile import AttackerProfile
from backend.common.schemas.report import (
    EvidenceSummary,
    Mitigation,
    ReportAttackerSummary,
    ReportAttackEvent,
    ReportHighlight,
    ReportStatistics,
    ReportVictimSummary,
    RiskEventReport,
)
from backend.common.schemas.version import (
    ALERT_SCHEMA_VERSION,
    ATTACK_CHAIN_SCHEMA_VERSION,
    ATTACKER_PROFILE_SCHEMA_VERSION,
    RISK_EVENT_REPORT_SCHEMA_VERSION,
    SUSPICIOUS_EVENT_BATCH_SCHEMA_VERSION,
    THREAT_ENTITY_SCHEMA_VERSION,
)
from backend.module2_chain.app.config import AppConfig
from backend.module2_chain.app.logging import get_logger
from backend.module2_chain.reporting.atomic_io import atomic_write_json
from backend.module2_chain.reporting.mitigations import MitigationLibrary

logger = get_logger("reporting.report_builder")

MAX_REPORT_ENTITIES = 200
MAX_HIGHLIGHTS = 5

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class ReportBuilder:
    """Builds the Module 3 facing :class:`RiskEventReport`."""

    def __init__(
        self, config: AppConfig, *, mitigations: MitigationLibrary | None = None
    ) -> None:
        self.config = config
        self.mitigations = mitigations or MitigationLibrary(config)

    def build(
        self,
        *,
        task_id: str,
        chains: list[AttackChain],
        alerts: list[Alert],
        profiles: list[AttackerProfile],
        entities: list[ThreatEntity],
        evidence_summary: EvidenceSummary,
        total_suspicious_events: int,
        deduplicated_events: int,
        candidate_count: int,
        metrics: dict[str, Any] | None = None,
        llm_meta: dict[str, Any] | None = None,
        warnings: list[str] | None = None,
    ) -> RiskEventReport:
        alerts_by_chain = {alert.chain_id: alert for alert in alerts}
        statistics = self._statistics(
            chains=chains,
            chains_profiles=profiles,
            entities=entities,
            alerts=alerts,
            total_suspicious_events=total_suspicious_events,
            deduplicated_events=deduplicated_events,
            candidate_count=candidate_count,
            metrics=metrics or {},
        )
        report = RiskEventReport(
            report_id=f"report_{task_id}",
            task_id=task_id,
            overview=self._overview(task_id, chains, statistics, profiles, warnings or []),
            statistics=statistics,
            attack_events=[self._attack_event(chain, alerts_by_chain.get(chain.chain_id)) for chain in chains],
            attackers=[self._attacker(profile) for profile in profiles],
            victims=self._victims(chains),
            threat_entities=[
                entity.model_dump(mode="json") for entity in entities[:MAX_REPORT_ENTITIES]
            ],
            highlights=self._highlights(chains),
            recommendations=self.mitigations.for_chains(chains),
            evidence_summary=evidence_summary,
            llm_meta=llm_meta or {},
            metrics=metrics or {},
            data_contract={
                "suspicious_event_batch": SUSPICIOUS_EVENT_BATCH_SCHEMA_VERSION,
                "attack_chain": ATTACK_CHAIN_SCHEMA_VERSION,
                "alert": ALERT_SCHEMA_VERSION,
                "attacker_profile": ATTACKER_PROFILE_SCHEMA_VERSION,
                "threat_entity": THREAT_ENTITY_SCHEMA_VERSION,
                "risk_event_report": RISK_EVENT_REPORT_SCHEMA_VERSION,
                "producer": "module2_chain",
                "transport": "shared_workspace",
            },
        )
        logger.info(
            "risk event report built",
            extra={
                "task_id": task_id,
                "stage": "report_generation",
                "attack_events": len(report.attack_events),
                "recommendations": len(report.recommendations),
            },
        )
        return report

    def write(self, report: RiskEventReport, path: Any) -> Any:
        return atomic_write_json(path, report.model_dump(mode="json"))

    # ------------------------------------------------------------------ #
    def _statistics(
        self,
        *,
        chains: list[AttackChain],
        chains_profiles: list[AttackerProfile],
        entities: list[ThreatEntity],
        alerts: list[Alert],
        total_suspicious_events: int,
        deduplicated_events: int,
        candidate_count: int,
        metrics: dict[str, Any],
    ) -> ReportStatistics:
        severity_counts: Counter[str] = Counter(chain.severity.value for chain in chains)
        victims: dict[str, None] = {}
        techniques: dict[str, None] = {}
        tactics: dict[str, None] = {}
        for chain in chains:
            for victim in chain.victim_ips:
                victims.setdefault(victim, None)
            for stage in chain.stages:
                tactics.setdefault(stage.tactic, None)
                if stage.technique:
                    techniques.setdefault(stage.technique, None)
        return ReportStatistics(
            total_suspicious_events=total_suspicious_events,
            deduplicated_events=deduplicated_events,
            total_attack_candidates=candidate_count,
            total_attack_events=len(chains),
            critical_count=severity_counts[Severity.CRITICAL.value],
            high_count=severity_counts[Severity.HIGH.value],
            medium_count=severity_counts[Severity.MEDIUM.value],
            low_count=severity_counts[Severity.LOW.value],
            info_count=severity_counts[Severity.INFO.value],
            attacker_count=len(chains_profiles),
            victim_count=len(victims),
            technique_count=len(techniques),
            tactic_count=len(tactics),
            entity_count=len(entities),
            ioc_hit_count=sum(len(chain.evidence_validation.get("ioc_hits", [])) for chain in chains),
            llm_calls=int(metrics.get("llm_calls") or 0),
            llm_failures=int(metrics.get("llm_failures") or 0),
            llm_degraded_chains=sum(1 for chain in chains if chain.llm_degraded),
        )

    def _overview(
        self,
        task_id: str,
        chains: list[AttackChain],
        statistics: ReportStatistics,
        profiles: list[AttackerProfile],
        warnings: list[str],
    ) -> str:
        if not chains:
            return (
                f"Task {task_id}: {statistics.total_suspicious_events} suspicious event(s) were "
                "correlated but no attack event met the reporting criteria. "
                "No actionable attack chain was produced."
            )
        worst = max(chains, key=lambda chain: chain.risk_score.score)
        attackers = ", ".join(worst.attacker_ips[:3]) or "unknown source"
        victims = ", ".join(worst.victim_ips[:3]) or "unknown target"
        parts = [
            (
                f"Task {task_id}: {statistics.total_suspicious_events} suspicious event(s) "
                f"correlated into {statistics.total_attack_candidates} candidate group(s) and "
                f"{statistics.total_attack_events} attack event(s)."
            ),
            (
                f"Severity distribution: critical={statistics.critical_count}, "
                f"high={statistics.high_count}, medium={statistics.medium_count}, "
                f"low={statistics.low_count}, info={statistics.info_count}."
            ),
            (
                f"Highest risk event: {worst.chain_id} ({worst.severity.value}, "
                f"score {worst.risk_score.score:.1f}) from {attackers} targeting {victims} "
                f"across {len(worst.stages)} stage(s)."
            ),
            f"{statistics.attacker_count} attacker profile(s) and {statistics.entity_count} threat entity/entities were derived from evidence.",
        ]
        if statistics.llm_degraded_chains:
            parts.append(
                f"{statistics.llm_degraded_chains} chain(s) were produced with the deterministic "
                "fallback analyser because the LLM was unavailable."
            )
        if warnings:
            parts.append("Warnings: " + "; ".join(warnings[:3]))
        if profiles and profiles[0].attribution == "Not Determined":
            parts.append(
                "Attribution (threat group / identity) was not determined: no supporting "
                "evidence was available."
            )
        return " ".join(parts)

    @staticmethod
    def _attack_event(chain: AttackChain, alert: Alert | None) -> ReportAttackEvent:
        return ReportAttackEvent(
            chain_id=chain.chain_id,
            alert_id=alert.alert_id if alert else None,
            title=alert.title if alert else chain.chain_id,
            summary=chain.summary,
            severity=chain.severity,
            confidence=chain.confidence,
            risk_score=chain.risk_score.score,
            attacker_ips=list(chain.attacker_ips),
            victim_ips=list(chain.victim_ips),
            victim_ports=list(chain.victim_ports),
            mitre_tactics=list(chain.mitre_tactics),
            mitre_techniques=[stage.technique for stage in chain.stages if stage.technique],
            stage_count=len(chain.stages),
            evidence_event_ids=chain.all_evidence_event_ids() or list(chain.event_ids),
            first_seen=chain.first_seen,
            last_seen=chain.last_seen,
            llm_degraded=chain.llm_degraded,
            risk_factors=[factor.model_dump(mode="json") for factor in chain.risk_score.factors],
            uncertainties=list(chain.uncertainties[:10]),
        )

    @staticmethod
    def _attacker(profile: AttackerProfile) -> ReportAttackerSummary:
        return ReportAttackerSummary(
            attacker_id=profile.attacker_id,
            attacker_ips=list(profile.attacker_ips),
            attack_count=profile.attack_count,
            max_severity=profile.max_severity,
            risk_score=profile.risk_score,
            techniques=list(profile.techniques),
            target_assets=list(profile.target_assets),
            behavior_summary=profile.behavior_summary,
            confidence=profile.confidence,
            attribution=profile.attribution,
            evidence_event_ids=list(profile.evidence_event_ids[:50]),
        )

    @staticmethod
    def _victims(chains: list[AttackChain]) -> list[ReportVictimSummary]:
        grouped: dict[str, dict[str, Any]] = {}
        for chain in chains:
            for victim in chain.victim_ips:
                entry = grouped.setdefault(
                    victim,
                    {
                        "attack_count": 0,
                        "max_severity": Severity.INFO,
                        "tactics": set(),
                        "techniques": set(),
                        "ports": set(),
                        "first_seen": chain.first_seen,
                        "last_seen": chain.last_seen,
                        "evidence": set(),
                    },
                )
                entry["attack_count"] += 1
                if chain.severity.rank > entry["max_severity"].rank:
                    entry["max_severity"] = chain.severity
                for stage in chain.stages:
                    entry["tactics"].add(stage.tactic)
                    if stage.technique:
                        entry["techniques"].add(stage.technique)
                for port in chain.victim_ports:
                    entry["ports"].add(port)
                if chain.first_seen and (
                    entry["first_seen"] is None or chain.first_seen < entry["first_seen"]
                ):
                    entry["first_seen"] = chain.first_seen
                if chain.last_seen and (
                    entry["last_seen"] is None or chain.last_seen > entry["last_seen"]
                ):
                    entry["last_seen"] = chain.last_seen
                entry["evidence"].update(chain.all_evidence_event_ids()[:50])

        summaries = [
            ReportVictimSummary(
                victim_ip=victim,
                attack_count=entry["attack_count"],
                max_severity=entry["max_severity"],
                tactics=sorted(entry["tactics"]),
                techniques=sorted(entry["techniques"]),
                targeted_ports=sorted(entry["ports"]),
                first_seen=entry["first_seen"],
                last_seen=entry["last_seen"],
                evidence_event_ids=sorted(entry["evidence"])[:50],
            )
            for victim, entry in grouped.items()
        ]
        summaries.sort(key=lambda item: (-item.attack_count, item.victim_ip))
        return summaries

    @staticmethod
    def _highlights(chains: list[AttackChain]) -> list[ReportHighlight]:
        ranked = sorted(
            chains,
            key=lambda chain: (
                _SEVERITY_ORDER[chain.severity],
                -chain.risk_score.score,
                -chain.confidence,
            ),
        )[:MAX_HIGHLIGHTS]
        highlights: list[ReportHighlight] = []
        for index, chain in enumerate(ranked, start=1):
            attackers = ", ".join(chain.attacker_ips[:2]) or "unknown source"
            victims = ", ".join(chain.victim_ips[:2]) or "unknown target"
            highlights.append(
                ReportHighlight(
                    highlight_id=f"hl_{chain.chain_id}_{index}",
                    title=(
                        f"{chain.severity.value.upper()} attack: {attackers} -> {victims} "
                        f"({len(chain.stages)} stage(s))"
                    ),
                    description=chain.summary,
                    severity=chain.severity,
                    chain_id=chain.chain_id,
                    evidence_event_ids=chain.all_evidence_event_ids()[:10],
                )
            )
        return highlights


def empty_statistics() -> ReportStatistics:
    return ReportStatistics()


def generated_at() -> datetime:
    return datetime.now(UTC)


__all__ = ["Mitigation", "ReportBuilder", "empty_statistics", "generated_at"]
