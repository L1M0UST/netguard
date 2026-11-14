"""Contract tests for the shared schemas (v1 additive-only)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from backend.common.schemas import (
    Alert,
    AttackCandidate,
    AttackChain,
    AttackerProfile,
    ChainStage,
    Severity,
    SuspiciousEvent,
    ThreatEntity,
)
from backend.common.schemas.version import (
    ATTACK_CHAIN_SCHEMA_VERSION,
    SUPPORTED_SUSPICIOUS_EVENT_BATCH_VERSIONS,
    SUSPICIOUS_EVENT_BATCH_SCHEMA_VERSION,
)


def _flat_event_row() -> dict[str, object]:
    return {
        "event.event_id": "evt_1",
        "event.task_id": "task_1",
        "event.timestamp": datetime(2024, 5, 1, 12, 0, tzinfo=UTC),
        "event.src_ip": "10.0.0.8",
        "event.dst_ip": "10.0.0.12",
        "event.src_port": 50000,
        "event.dst_port": 80,
        "event.protocol": "TCP",
        "event.payload_digest": "deadbeef",
        "event.raw_ref": "raw/1",
        "event.source_file": "capture.pcap",
        "detection.matched_rules": ["l1_port_scan"],
        "detection.ioc_hits": [],
        "detection.score": 55.0,
        "detection.reason": "scan",
        "detection.detector": "scan_detector",
        "session_id": "sess_1",
        "emitted_at": datetime(2024, 5, 1, 12, 0, tzinfo=UTC),
    }


def test_flat_and_nested_layouts_produce_the_same_event() -> None:
    from_flat = SuspiciousEvent.from_flat_dict(_flat_event_row())
    nested = SuspiciousEvent.model_validate(
        {
            "event": {
                "event_id": "evt_1",
                "task_id": "task_1",
                "timestamp": "2024-05-01T12:00:00+00:00",
                "src_ip": "10.0.0.8",
                "dst_ip": "10.0.0.12",
                "src_port": 50000,
                "dst_port": 80,
                "protocol": "TCP",
                "payload_digest": "deadbeef",
                "raw_ref": "raw/1",
                "source_file": "capture.pcap",
            },
            "detection": {
                "matched_rules": ["l1_port_scan"],
                "ioc_hits": [],
                "score": 55.0,
                "reason": "scan",
                "detector": "scan_detector",
            },
            "session_id": "sess_1",
            "emitted_at": "2024-05-01T12:00:00+00:00",
        }
    )
    assert from_flat.event.event_id == nested.event.event_id
    assert from_flat.detection.matched_rules == nested.detection.matched_rules
    assert nested.protocol == "tcp"
    assert from_flat.rule_signature == nested.rule_signature


def test_flat_round_trip_is_lossless() -> None:
    event = SuspiciousEvent.from_flat_dict(_flat_event_row())
    again = SuspiciousEvent.from_flat_dict(event.to_flat_dict())
    assert again.model_dump() == event.model_dump()


def test_suspicious_event_accepts_additive_fields_only() -> None:
    row = _flat_event_row()
    row["event.new_field_added_in_v1"] = "allowed"
    event = SuspiciousEvent.from_flat_dict(row)
    assert event.event.model_extra is not None
    assert event.event.model_extra["new_field_added_in_v1"] == "allowed"


def test_batch_contract_versions_are_stable() -> None:
    assert SUSPICIOUS_EVENT_BATCH_SCHEMA_VERSION == "1.0.0"
    assert "1.0.0" in SUPPORTED_SUSPICIOUS_EVENT_BATCH_VERSIONS
    assert ATTACK_CHAIN_SCHEMA_VERSION == "1.0.0"


def test_attack_chain_requires_strictly_increasing_stages() -> None:
    chain = AttackChain(
        chain_id="chain_1",
        task_id="task_1",
        stages=[
            ChainStage(stage_index=1, tactic="TA0043", evidence_event_ids=["evt_1"]),
            ChainStage(stage_index=2, tactic="TA0001", evidence_event_ids=["evt_2"]),
        ],
        severity=Severity.HIGH,
        mitre_tactics=["TA0043", "TA0001"],
    )
    indexes = [stage.stage_index for stage in chain.stages]
    assert indexes == sorted(indexes)
    assert chain.all_evidence_event_ids() == ["evt_1", "evt_2"]
    assert chain.tactic_ids == ["TA0043", "TA0001"]


def test_stage_index_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        ChainStage(stage_index=0, tactic="TA0043")


def test_confidence_and_score_ranges_are_enforced() -> None:
    with pytest.raises(ValidationError):
        AttackChain(chain_id="c", task_id="t", confidence=1.5)
    with pytest.raises(ValidationError):
        ThreatEntity(entity_id="e", entity_type="ip", value="1.2.3.4", confidence=-0.1)


def test_candidate_and_profile_defaults_are_evidence_bounded() -> None:
    candidate = AttackCandidate(
        candidate_id="cand_1", task_id="task_1", first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
    )
    assert candidate.event_ids == []
    assert candidate.threat_intel == []
    profile = AttackerProfile(attacker_id="attacker_1", task_id="task_1")
    assert profile.attribution == "Not Determined"
    assert profile.severity_distribution == {}
    alert = Alert(alert_id="a1", task_id="t", chain_id="c", title="t")
    assert alert.source == "module2_chain"
