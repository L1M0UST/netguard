"""Attacker profiling, threat-entity extraction, alerts and report tests."""

from __future__ import annotations

from datetime import timedelta

from backend.common.schemas.enums import EntityRole, EntityType, MitigationKind
from backend.module2_chain.attack.chain_builder import AttackChainBuilder
from backend.module2_chain.attack.fingerprint import AttackFingerprintBuilder
from backend.module2_chain.attack.knowledge import load_knowledge_base
from backend.module2_chain.attack.technique_mapper import AttackTechniqueMapper
from backend.module2_chain.correlation.engine import CorrelationEngine
from backend.module2_chain.entities.extractor import ThreatEntityExtractor
from backend.module2_chain.profiling.attacker_profiler import AttackerProfiler
from backend.module2_chain.reporting.alert_builder import AlertBuilder
from backend.module2_chain.reporting.mitigations import MitigationLibrary
from backend.module2_chain.reporting.report_builder import ReportBuilder
from backend.module2_chain.risk.scorer import RiskScorer, ScoringContext
from backend.module2_chain.tests.conftest import BASE_TIME, make_event


def _chains(config, event_groups):
    knowledge = load_knowledge_base(config.attack_kb_path)
    engine = CorrelationEngine(config, knowledge=knowledge)
    mapper = AttackTechniqueMapper(config, knowledge=knowledge)
    builder = AttackChainBuilder(config, knowledge=knowledge)
    scorer = RiskScorer(config, knowledge=knowledge)
    fingerprints = AttackFingerprintBuilder(config)
    chains = []
    for events in event_groups:
        candidate = engine.correlate(events)[0]
        techniques, _ = mapper.map_candidate(candidate, events)
        candidate = candidate.model_copy(update={"techniques": techniques})
        chain = builder.build(candidate, events, techniques=techniques)
        chain = scorer.apply(
            chain,
            ScoringContext(
                candidate=candidate,
                events=events,
                ioc_hits=len(candidate.ioc_hits),
                malicious_ioc_hits=1 if candidate.ioc_hits else 0,
            ),
        )
        chains.append(fingerprints.apply(chain))
    return chains


def test_profiler_groups_chains_by_attacker(config) -> None:
    groups = [
        [
            make_event("evt_1", rules=["l1_port_scan_sweep"], reason="port scan"),
            make_event("evt_2", dst_port=443, rules=["l1_port_scan_sweep"]),
        ],
        [
            make_event(
                "evt_3",
                rules=["l1_smb_psexec_lateral"],
                reason="psexec lateral movement",
                timestamp=BASE_TIME + timedelta(hours=4),
            ),
            make_event(
                "evt_4",
                dst_port=135,
                rules=["l1_smb_psexec_lateral"],
                timestamp=BASE_TIME + timedelta(hours=4, seconds=30),
            ),
        ],
        [
            make_event(
                "evt_5",
                src_ip="192.0.2.9",
                dst_ip="10.0.0.50",
                rules=["l1_ransomware_encryption"],
                reason="ransomware encryption",
                score=99.0,
            )
        ],
    ]
    chains = _chains(config, groups)
    events_by_id = {
        event.event.event_id: event for group in groups for event in group
    }
    profiles = AttackerProfiler(config).profile("task_test", chains, events_by_id)
    assert len(profiles) == 2
    first = max(profiles, key=lambda profile: profile.attack_count)
    assert first.attack_count == 2
    assert first.attacker_ips == ["10.0.0.8"]
    assert first.techniques
    assert first.evidence_event_ids
    assert first.severity_distribution
    assert first.behavior_summary
    assert 0.0 <= first.confidence <= 1.0


def test_profiler_never_invents_attribution(config) -> None:
    groups = [[make_event("evt_1", rules=["l1_port_scan_sweep"])]]
    chains = _chains(config, groups)
    events_by_id = {"evt_1": groups[0][0]}
    profile = AttackerProfiler(config).profile("task_test", chains, events_by_id)[0]
    assert profile.attribution == "Not Determined"
    assert profile.attribution_confidence == 0.0
    assert profile.attribution_evidence_event_ids == []
    assert any("Attribution" in note for note in profile.notes)


def test_profiler_extracts_tools_usernames_and_domains(config) -> None:
    groups = [
        [
            make_event(
                "evt_1",
                rules=["l1_suspicious_powershell", "l1_c2_beacon_periodic"],
                reason="mimikatz executed by user=administrator to evil-c2.example.com",
                ioc_hits=["evil-c2.example.com"],
            )
        ]
    ]
    chains = _chains(config, groups)
    events_by_id = {"evt_1": groups[0][0]}
    profile = AttackerProfiler(config).profile("task_test", chains, events_by_id)[0]
    assert "mimikatz" in profile.tools
    assert "administrator" in profile.usernames
    assert "evil-c2.example.com" in profile.domains
    assert "evil-c2.example.com" in profile.observed_iocs


def test_entity_extraction_is_evidence_bound(config) -> None:
    groups = [
        [
            make_event(
                "evt_1",
                rules=["l1_exploit_cve_2021_44228"],
                reason="CVE-2021-44228 exploitation user=admin",
                ioc_hits=["CVE-2021-44228"],
                dst_port=8080,
            ),
            make_event(
                "evt_2",
                rules=["l1_exploit_cve_2021_44228"],
                dst_port=8080,
                timestamp=BASE_TIME + timedelta(seconds=20),
            ),
        ]
    ]
    chains = _chains(config, groups)
    events_by_id = {event.event.event_id: event for event in groups[0]}
    entities, chain_entities = ThreatEntityExtractor(config).extract(
        "task_test", chains, events_by_id
    )
    by_type: dict[EntityType, set[str]] = {}
    for entity in entities:
        by_type.setdefault(entity.entity_type, set()).add(entity.value)
        assert entity.evidence_event_ids
    assert "10.0.0.8" in by_type[EntityType.IP]
    assert "8080" in by_type[EntityType.PORT]
    assert "tcp" in by_type[EntityType.PROTOCOL]
    assert "CVE-2021-44228" in by_type[EntityType.CVE]
    assert "admin" in by_type[EntityType.USERNAME]
    attackers = [
        entity
        for entity in entities
        if entity.entity_type is EntityType.IP and entity.role is EntityRole.ATTACKER
    ]
    assert attackers
    assert chain_entities[chains[0].chain_id]


def test_entities_from_llm_are_merged(config) -> None:
    from backend.module2_chain.llm.schemas import LLMThreatEntity

    groups = [[make_event("evt_1", rules=["l1_port_scan_sweep"])]]
    chains = _chains(config, groups)
    events_by_id = {"evt_1": groups[0][0]}
    llm_entities = {
        chains[0].chain_id: [
            LLMThreatEntity(
                entity_type="tool",
                value="nmap",
                role="tool",
                confidence=0.7,
                evidence_event_ids=["evt_1"],
            )
        ]
    }
    entities, _ = ThreatEntityExtractor(config).extract(
        "task_test", chains, events_by_id, llm_entities=llm_entities
    )
    assert any(entity.value == "nmap" for entity in entities)
    assert all("llm-proposed" in entity.tags for entity in entities if entity.value == "nmap")


def test_alerts_are_derived_from_chains(config) -> None:
    groups = [
        [
            make_event(
                "evt_1",
                rules=["l1_ransomware_encryption"],
                reason="ransomware encryption",
                score=99.0,
            )
        ]
    ]
    chains = _chains(config, groups)
    alerts = AlertBuilder(config).build_many(chains)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.chain_id == chains[0].chain_id
    assert alert.evidence_event_ids
    assert alert.severity is chains[0].severity
    assert alert.risk_factors
    assert "module2" in alert.tags
    assert alert.fingerprint == chains[0].fingerprint


def test_mitigations_are_evidence_based_when_supported(config) -> None:
    groups = [
        [
            make_event(
                "evt_1",
                rules=["l1_exploit_cve_2021_44228"],
                reason="CVE-2021-44228 exploitation attempt",
                ioc_hits=["CVE-2021-44228"],
                score=95.0,
            )
        ]
    ]
    chains = _chains(config, groups)
    chains[0] = chains[0].model_copy(
        update={
            "evidence_validation": {
                **chains[0].evidence_validation,
                "rules": ["l1_exploit_cve_2021_44228"],
                "malicious_ioc_hits": 1,
            }
        }
    )
    mitigations = MitigationLibrary(config).for_chains(chains)
    assert mitigations
    kinds = {mitigation.recommendation_type for mitigation in mitigations}
    assert MitigationKind.EVIDENCE_BASED in kinds
    assert any("CVE-2021-44228" in mitigation.title for mitigation in mitigations)
    for mitigation in mitigations:
        assert mitigation.evidence_event_ids
        assert mitigation.priority in {"low", "medium", "high", "critical"}


def test_report_statistics_and_highlights(config) -> None:
    groups = [
        [
            make_event("evt_1", rules=["l1_port_scan_sweep"], reason="nmap port scan"),
            make_event("evt_2", dst_port=443, rules=["l1_port_scan_sweep"]),
        ],
        [
            make_event(
                "evt_3",
                src_ip="192.0.2.9",
                dst_ip="10.0.0.50",
                rules=["l1_ransomware_encryption"],
                reason="ransomware encryption",
                score=99.0,
            )
        ],
    ]
    chains = _chains(config, groups)
    events_by_id = {event.event.event_id: event for group in groups for event in group}
    profiles = AttackerProfiler(config).profile("task_test", chains, events_by_id)
    entities, _ = ThreatEntityExtractor(config).extract(
        "task_test", chains, events_by_id
    )
    alerts = AlertBuilder(config).build_many(chains)
    from backend.common.schemas.report import EvidenceSummary

    report = ReportBuilder(config).build(
        task_id="task_test",
        chains=chains,
        alerts=alerts,
        profiles=profiles,
        entities=entities,
        evidence_summary=EvidenceSummary(
            total_input_events=3, unique_events=3, events_in_chains=3, candidate_count=2
        ),
        total_suspicious_events=3,
        deduplicated_events=0,
        candidate_count=2,
        metrics={"llm_calls": 2, "llm_failures": 0},
    )
    assert report.statistics.total_attack_events == len(chains)
    assert report.statistics.attacker_count == len(profiles)
    assert report.statistics.technique_count >= 1
    severity_total = (
        report.statistics.critical_count
        + report.statistics.high_count
        + report.statistics.medium_count
        + report.statistics.low_count
        + report.statistics.info_count
    )
    assert severity_total == len(chains)
    assert report.highlights
    assert report.attack_events
    assert report.victims
    assert report.data_contract["producer"] == "module2_chain"
    assert report.data_contract["transport"] == "shared_workspace"
    assert "Not Determined" in report.overview or report.statistics.attacker_count >= 1


def test_empty_report_is_still_valid(config) -> None:
    from backend.common.schemas.report import EvidenceSummary

    report = ReportBuilder(config).build(
        task_id="task_empty",
        chains=[],
        alerts=[],
        profiles=[],
        entities=[],
        evidence_summary=EvidenceSummary(),
        total_suspicious_events=0,
        deduplicated_events=0,
        candidate_count=0,
    )
    assert report.statistics.total_attack_events == 0
    assert report.attack_events == []
    assert "no attack event" in report.overview
