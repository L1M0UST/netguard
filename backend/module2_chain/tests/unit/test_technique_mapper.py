"""ATT&CK candidate mapping tests (M2-F9, M2-F10)."""

from __future__ import annotations

from backend.module2_chain.attack.knowledge import load_knowledge_base
from backend.module2_chain.attack.technique_mapper import AttackTechniqueMapper
from backend.module2_chain.correlation.engine import CorrelationEngine
from backend.module2_chain.tests.conftest import make_event


def _candidate(config, events):
    engine = CorrelationEngine(config, knowledge=load_knowledge_base(config.attack_kb_path))
    return engine.correlate(events)[0]


def test_scanning_maps_to_reconnaissance_and_discovery(config) -> None:
    events = [
        make_event("evt_1", rules=["l1_port_scan_sweep"], reason="nmap port scan"),
        make_event("evt_2", dst_port=443, rules=["l1_service_discovery"], reason="service scan"),
    ]
    candidate = _candidate(config, events)
    mapper = AttackTechniqueMapper(config, knowledge=load_knowledge_base(config.attack_kb_path))
    techniques, signals = mapper.map_candidate(candidate, events)
    tactics = {item.tactic_id for item in techniques}
    assert {"TA0043", "TA0007"} & tactics
    assert any(item.technique_id in {"T1595", "T1046"} for item in techniques)
    assert signals.categories
    assert all(item.evidence_event_ids for item in techniques)


def test_brute_force_maps_to_credential_access(config) -> None:
    events = [
        make_event(
            f"evt_{index}",
            dst_port=22,
            rules=["l1_brute_force_ssh"],
            reason="repeated failed login attempts user=admin",
        )
        for index in range(3)
    ]
    candidate = _candidate(config, events)
    mapper = AttackTechniqueMapper(config, knowledge=load_knowledge_base(config.attack_kb_path))
    techniques, _ = mapper.map_candidate(candidate, events)
    assert any(item.technique_id == "T1110" for item in techniques)
    assert any(item.tactic_id == "TA0006" for item in techniques)


def test_exploitation_maps_to_initial_access_with_cve(config) -> None:
    events = [
        make_event(
            "evt_1",
            dst_port=8080,
            rules=["l1_exploit_cve_2021_44228"],
            reason="CVE-2021-44228 exploitation attempt",
            ioc_hits=["CVE-2021-44228"],
            score=95.0,
        )
    ]
    candidate = _candidate(config, events)
    mapper = AttackTechniqueMapper(config, knowledge=load_knowledge_base(config.attack_kb_path))
    techniques, _ = mapper.map_candidate(candidate, events)
    assert any(item.technique_id == "T1190" for item in techniques)
    assert any(item.tactic_id == "TA0001" for item in techniques)


def test_impact_scenario_maps_to_impact_tactic(config) -> None:
    events = [
        make_event(
            "evt_1",
            rules=["l1_ransomware_encryption"],
            reason="mass file encryption and ransom note creation",
            dst_port=445,
            score=99.0,
        )
    ]
    candidate = _candidate(config, events)
    mapper = AttackTechniqueMapper(config, knowledge=load_knowledge_base(config.attack_kb_path))
    techniques, _ = mapper.map_candidate(candidate, events)
    assert any(item.tactic_id == "TA0040" for item in techniques)
    assert any(item.technique_id == "T1486" for item in techniques)


def test_unmatched_behaviour_falls_back_to_a_tactic_level_candidate(config) -> None:
    events = [make_event("evt_1", rules=["l1_totally_unknown_rule"], reason="unknown", score=10.0)]
    candidate = _candidate(config, events)
    mapper = AttackTechniqueMapper(config, knowledge=load_knowledge_base(config.attack_kb_path))
    techniques, _ = mapper.map_candidate(candidate, events)
    assert techniques
    assert all(item.evidence_event_ids for item in techniques)


def test_knowledge_base_covers_all_required_tactics(config) -> None:
    kb = load_knowledge_base(config.attack_kb_path)
    required = {
        "TA0043",
        "TA0042",
        "TA0001",
        "TA0002",
        "TA0003",
        "TA0004",
        "TA0005",
        "TA0006",
        "TA0007",
        "TA0008",
        "TA0009",
        "TA0011",
        "TA0010",
        "TA0040",
    }
    assert required <= set(kb.tactics)
    assert required <= set(kb.tactic_order)
    assert len(kb.techniques) >= 20
    assert kb.tactic_rank("TA0001") < kb.tactic_rank("TA0040")


def test_technique_evidence_points_at_real_events(config) -> None:
    events = [
        make_event("evt_1", rules=["l1_port_scan_sweep"], reason="port scan"),
        make_event(
            "evt_2",
            dst_port=445,
            rules=["l1_smb_psexec_lateral"],
            reason="psexec lateral movement over smb",
        ),
    ]
    candidate = _candidate(config, events)
    mapper = AttackTechniqueMapper(config, knowledge=load_knowledge_base(config.attack_kb_path))
    techniques, _ = mapper.map_candidate(candidate, events)
    known_ids = {event.event_id for event in events}
    for item in techniques:
        assert set(item.evidence_event_ids) <= known_ids
