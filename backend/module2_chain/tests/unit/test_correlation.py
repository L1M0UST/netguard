"""Correlation engine tests (M2-F4..F7, spec §8/§9)."""

from __future__ import annotations

from datetime import timedelta

from backend.module2_chain.attack.knowledge import load_knowledge_base
from backend.module2_chain.correlation.behavior import BehaviorCorrelator
from backend.module2_chain.correlation.engine import CorrelationEngine
from backend.module2_chain.correlation.entity import EntityCorrelator
from backend.module2_chain.correlation.features import build_features, subnet_key
from backend.module2_chain.correlation.temporal import TemporalCorrelator
from backend.module2_chain.tests.conftest import BASE_TIME


def _engine(config) -> CorrelationEngine:
    return CorrelationEngine(config, knowledge=load_knowledge_base(config.attack_kb_path))


def test_single_suspicious_event_becomes_a_single_event_candidate(config, event_factory) -> None:
    events = [event_factory("evt_1")]
    candidates = _engine(config).correlate(events)
    assert len(candidates) == 1
    assert candidates[0].event_ids == ["evt_1"]
    assert candidates[0].score_summary.event_count == 1
    assert candidates[0].attacker_ips == ["10.0.0.8"]


def test_empty_input_returns_no_candidates(config) -> None:
    assert _engine(config).correlate([]) == []


def test_scan_and_exploit_by_same_attacker_form_one_candidate(config, event_factory) -> None:
    events = [
        event_factory("evt_1", dst_ip="10.0.0.12", dst_port=80),
        event_factory("evt_2", dst_ip="10.0.0.13", dst_port=443),
        event_factory(
            "evt_3",
            dst_ip="10.0.0.12",
            dst_port=8080,
            timestamp=BASE_TIME + timedelta(seconds=60),
            rules=["l1_exploit_cve_2021_44228"],
            reason="CVE-2021-44228 exploitation attempt",
        ),
    ]
    candidates = _engine(config).correlate(events)
    assert len(candidates) == 1
    assert set(candidates[0].event_ids) == {"evt_1", "evt_2", "evt_3"}
    assert candidates[0].victim_ips == ["10.0.0.12", "10.0.0.13"]
    assert candidates[0].victim_ports == [80, 443, 8080]
    assert candidates[0].correlation_score > 0
    assert candidates[0].correlation_reasons


def test_different_attackers_stay_separate(config, event_factory) -> None:
    events = [
        event_factory("evt_1", src_ip="10.0.0.8", dst_ip="10.0.0.12"),
        event_factory("evt_2", src_ip="10.0.0.9", dst_ip="10.0.0.12"),
        event_factory("evt_3", src_ip="10.0.0.9", dst_ip="10.0.0.12", dst_port=445),
    ]
    candidates = _engine(config).correlate(events)
    assert len(candidates) == 2
    by_attacker = {candidate.attacker_ips[0]: candidate for candidate in candidates}
    assert set(by_attacker) == {"10.0.0.8", "10.0.0.9"}
    assert set(by_attacker["10.0.0.9"].event_ids) == {"evt_2", "evt_3"}


def test_multiple_victims_of_one_attacker_stay_together(config, event_factory) -> None:
    events = [
        event_factory(f"evt_{index}", dst_ip=f"10.0.0.{20 + index}", dst_port=22)
        for index in range(5)
    ]
    candidates = _engine(config).correlate(events)
    assert len(candidates) == 1
    assert len(candidates[0].victim_ips) == 5


def test_time_window_boundary_is_enforced(config, event_factory) -> None:
    window = config.correlation.correlation_window_seconds
    max_gap = config.correlation.max_gap_seconds
    inside = [
        event_factory("evt_1"),
        event_factory("evt_2", timestamp=BASE_TIME + timedelta(seconds=window)),
    ]
    assert len(_engine(config).correlate(inside)) == 1

    outside = [
        event_factory("evt_1"),
        event_factory("evt_2", timestamp=BASE_TIME + timedelta(seconds=max_gap + 1)),
    ]
    assert len(_engine(config).correlate(outside)) == 2

    decaying = [
        event_factory("evt_1"),
        event_factory("evt_2", timestamp=BASE_TIME + timedelta(seconds=window + 60)),
    ]
    decision = _engine(config).link_decision(
        *build_features(decaying, knowledge=load_knowledge_base(config.attack_kb_path))
    )
    assert 0.0 < decision.components["time"] < 1.0


def test_same_ip_different_attack_outside_window_splits(config, event_factory) -> None:
    events = [
        event_factory("evt_1", dst_port=22, rules=["l1_brute_force_ssh"], reason="failed login"),
        event_factory(
            "evt_2",
            dst_port=445,
            rules=["l1_smb_psexec_lateral"],
            reason="psexec lateral movement",
            timestamp=BASE_TIME + timedelta(hours=3),
        ),
    ]
    candidates = _engine(config).correlate(events)
    assert len(candidates) == 2


def test_same_campaign_from_two_addresses_links_via_ioc(config, event_factory) -> None:
    events = [
        event_factory("evt_1", src_ip="203.0.113.45", ioc_hits=["evil-c2.example.com"]),
        event_factory(
            "evt_2",
            src_ip="203.0.113.46",
            dst_port=443,
            timestamp=BASE_TIME + timedelta(seconds=30),
            ioc_hits=["evil-c2.example.com"],
        ),
    ]
    candidates = _engine(config).correlate(events)
    assert len(candidates) == 1
    assert "shared IOC" in " ".join(candidates[0].correlation_reasons)


def test_subnet_grouping_can_link_neighbouring_attackers(config, event_factory) -> None:
    correlation = config.correlation.model_copy(
        update={
            "entity": config.correlation.entity.model_copy(
                update={"attacker_subnet_prefix_v4": 24}
            )
        }
    )
    relaxed = config.model_copy(update={"correlation": correlation})
    events = [
        event_factory("evt_1", src_ip="10.0.0.8", dst_port=22),
        event_factory(
            "evt_2",
            src_ip="10.0.0.9",
            dst_port=22,
            timestamp=BASE_TIME + timedelta(seconds=20),
        ),
    ]
    assert len(_engine(relaxed).correlate(events)) == 1
    assert subnet_key("10.0.0.8", v4_prefix=24) == subnet_key("10.0.0.9", v4_prefix=24)


def test_candidate_ids_are_deterministic(config, event_factory) -> None:
    events = [event_factory("evt_2"), event_factory("evt_1")]
    first = _engine(config).correlate(events)
    second = _engine(config).correlate(list(reversed(events)))
    assert [candidate.candidate_id for candidate in first] == [
        candidate.candidate_id for candidate in second
    ]


def test_temporal_correlator_scores(config) -> None:
    correlator = TemporalCorrelator(
        window_seconds=config.correlation.correlation_window_seconds,
        max_gap_seconds=config.correlation.max_gap_seconds,
    )
    assert correlator.score_gap(0) == 1.0
    assert correlator.score_gap(correlator.window_seconds) == 1.0
    assert 0.0 < correlator.score_gap(correlator.window_seconds + 1) < 1.0
    assert correlator.score_gap(correlator.max_gap_seconds + 1) == 0.0


def test_entity_correlator_components(config, event_factory) -> None:
    correlator = EntityCorrelator(config.correlation.entity)
    features = build_features(
        [
            event_factory("evt_1", dst_port=443),
            event_factory("evt_2", dst_port=8443),
            event_factory("evt_3", src_ip="10.0.0.99", dst_ip="10.0.9.9", dst_port=25),
        ]
    )
    same_service_class = correlator.components(features[0], features[1])
    assert same_service_class["port"] == 0.5
    assert same_service_class["attacker"] == 1.0
    unrelated = correlator.components(features[0], features[2])
    assert unrelated["attacker"] == 0.0
    assert not correlator.attacker_compatible(features[0], features[2])


def test_behavior_correlator_rule_similarity(config, event_factory) -> None:
    correlator = BehaviorCorrelator(config.correlation.behavior)
    features = build_features(
        [
            event_factory("evt_1", rules=["l1_port_scan_sweep"]),
            event_factory("evt_2", rules=["l1_port_scan_sweep"]),
            event_factory("evt_3", rules=["l1_ransomware_encryption"]),
        ],
        knowledge=load_knowledge_base(config.attack_kb_path),
    )
    assert correlator.rule_similarity(features[0], features[1]) == 1.0
    assert correlator.category_affinity(features[0], features[1]) == 0.8
    assert correlator.category_affinity(features[1], features[2]) == 0.0


def test_link_decision_reports_veto_reasons(config, event_factory) -> None:
    engine = _engine(config)
    features = build_features(
        [
            event_factory("evt_1", src_ip="10.0.0.8"),
            event_factory("evt_2", src_ip="192.0.2.7", dst_ip="10.9.9.9"),
        ]
    )
    decision = engine.link_decision(features[0], features[1])
    assert not decision.linked
    assert decision.veto


def test_attack_categories_are_attached(config, event_factory) -> None:
    events = [
        event_factory(
            "evt_1", rules=["l1_brute_force_ssh"], reason="repeated failed login attempts"
        )
    ]
    candidate = _engine(config).correlate(events)[0]
    assert "brute_force" in candidate.attack_categories
