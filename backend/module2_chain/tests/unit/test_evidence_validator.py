"""Evidence validation tests (M2-F13, spec §20)."""

from __future__ import annotations

from datetime import timedelta

from backend.module2_chain.attack.evidence_validator import EvidenceValidator
from backend.module2_chain.attack.knowledge import load_knowledge_base
from backend.module2_chain.attack.technique_mapper import AttackTechniqueMapper
from backend.module2_chain.correlation.engine import CorrelationEngine
from backend.module2_chain.llm.schemas import (
    LLMAttackAnalysis,
    LLMStage,
    LLMThreatEntity,
)
from backend.module2_chain.tests.conftest import BASE_TIME, make_event


def _setup(config, events, analysis: LLMAttackAnalysis):
    knowledge = load_knowledge_base(config.attack_kb_path)
    candidate = CorrelationEngine(config, knowledge=knowledge).correlate(events)[0]
    techniques, _ = AttackTechniqueMapper(config, knowledge=knowledge).map_candidate(
        candidate, events
    )
    candidate = candidate.model_copy(update={"techniques": techniques})
    validator = EvidenceValidator(config, knowledge=knowledge)
    return validator.validate(candidate, analysis, events, techniques)


def _analysis(stages: list[LLMStage], **kwargs) -> LLMAttackAnalysis:
    return LLMAttackAnalysis(
        candidate_id="cand_1",
        verdict="attack",
        attack_summary="summary",
        stages=stages,
        confidence=0.8,
        **kwargs,
    )


def test_valid_analysis_passes_through_unchanged(config) -> None:
    events = [
        make_event("evt_1", rules=["l1_port_scan_sweep"], reason="port scan"),
        make_event("evt_2", dst_port=443, rules=["l1_port_scan_sweep"]),
    ]
    analysis = _analysis(
        [
            LLMStage(
                stage_index=1,
                tactic="TA0043",
                technique="T1595",
                narrative="scan",
                evidence_event_ids=["evt_1", "evt_2"],
                confidence=0.8,
            )
        ]
    )
    sanitized, result = _setup(config, events, analysis)
    assert result.valid
    assert not result.hallucination_detected
    assert sanitized.stages[0].evidence_event_ids == ["evt_1", "evt_2"]
    assert result.confidence_penalty == 0.0


def test_unknown_event_ids_are_removed_and_flagged(config) -> None:
    events = [make_event("evt_1", rules=["l1_port_scan_sweep"])]
    analysis = _analysis(
        [
            LLMStage(
                stage_index=1,
                tactic="TA0043",
                technique="T1595",
                evidence_event_ids=["evt_ghost", "evt_1"],
                confidence=0.9,
            )
        ]
    )
    sanitized, result = _setup(config, events, analysis)
    assert result.hallucination_detected
    assert result.unknown_event_ids == ["evt_ghost"]
    assert sanitized.stages[0].evidence_event_ids == ["evt_1"]
    assert any(issue.code == "unknown_evidence_event_id" for issue in result.issues)
    assert result.confidence_penalty > 0


def test_stage_without_any_valid_evidence_is_dropped(config) -> None:
    events = [make_event("evt_1", rules=["l1_port_scan_sweep"])]
    analysis = _analysis(
        [
            LLMStage(
                stage_index=1,
                tactic="TA0043",
                technique="T1595",
                evidence_event_ids=["evt_ghost"],
                confidence=0.9,
            )
        ]
    )
    sanitized, result = _setup(config, events, analysis)
    assert sanitized.stages == []
    assert result.degraded_to_rules is True
    assert not result.valid
    assert 1 in result.dropped_stage_indexes


def test_unknown_tactic_drops_the_stage(config) -> None:
    events = [make_event("evt_1", rules=["l1_port_scan_sweep"])]
    analysis = _analysis(
        [
            LLMStage(
                stage_index=1,
                tactic="TA9999",
                technique=None,
                evidence_event_ids=["evt_1"],
                confidence=0.9,
            )
        ]
    )
    sanitized, result = _setup(config, events, analysis)
    assert sanitized.stages == []
    assert any(issue.code == "unknown_tactic" for issue in result.issues)
    assert result.hallucination_detected


def test_technique_outside_the_candidate_set_is_removed(config) -> None:
    events = [make_event("evt_1", rules=["l1_port_scan_sweep"], reason="port scan")]
    analysis = _analysis(
        [
            LLMStage(
                stage_index=1,
                tactic="TA0043",
                technique="T1486",
                evidence_event_ids=["evt_1"],
                confidence=0.9,
            )
        ]
    )
    sanitized, result = _setup(config, events, analysis)
    assert any(issue.code == "technique_outside_candidate_set" for issue in result.issues)
    assert sanitized.stages[0].technique is None
    assert sanitized.stages[0].tactic == "TA0043"


def test_unknown_technique_is_removed(config) -> None:
    events = [make_event("evt_1", rules=["l1_port_scan_sweep"])]
    analysis = _analysis(
        [
            LLMStage(
                stage_index=1,
                tactic="TA0043",
                technique="T9999",
                evidence_event_ids=["evt_1"],
                confidence=0.9,
            )
        ]
    )
    sanitized, result = _setup(config, events, analysis)
    assert result.hallucination_detected
    assert any(issue.code == "unknown_technique" for issue in result.issues)
    assert sanitized.stages[0].technique is None


def test_invented_threat_entities_are_removed(config) -> None:
    events = [make_event("evt_1", rules=["l1_port_scan_sweep"])]
    analysis = _analysis(
        [
            LLMStage(
                stage_index=1,
                tactic="TA0043",
                technique="T1595",
                evidence_event_ids=["evt_1"],
                confidence=0.9,
            )
        ],
        threat_entities=[
            LLMThreatEntity(
                entity_type="ip",
                value="203.0.113.250",
                role="infrastructure",
                confidence=0.9,
                evidence_event_ids=["evt_1"],
            ),
            LLMThreatEntity(
                entity_type="ip",
                value="10.0.0.8",
                role="attacker",
                confidence=0.9,
                evidence_event_ids=["evt_1"],
            ),
        ],
    )
    sanitized, result = _setup(config, events, analysis)
    values = {entity.value for entity in sanitized.threat_entities}
    assert "203.0.113.250" not in values
    assert "10.0.0.8" in values
    assert any(issue.code == "indicator_not_observed" for issue in result.issues)


def test_entity_with_unknown_evidence_is_removed(config) -> None:
    events = [make_event("evt_1", rules=["l1_port_scan_sweep"])]
    analysis = _analysis(
        [],
        threat_entities=[
            LLMThreatEntity(
                entity_type="ip",
                value="10.0.0.8",
                role="attacker",
                evidence_event_ids=["evt_ghost"],
            )
        ],
    )
    sanitized, result = _setup(config, events, analysis)
    assert sanitized.threat_entities == []
    assert any(issue.code == "entity_without_evidence" for issue in result.issues)


def test_stage_time_regression_is_reported(config) -> None:
    events = [
        make_event("evt_1", timestamp=BASE_TIME),
        make_event("evt_2", timestamp=BASE_TIME + timedelta(minutes=5)),
    ]
    analysis = _analysis(
        [
            LLMStage(
                stage_index=1,
                tactic="TA0043",
                technique="T1595",
                evidence_event_ids=["evt_2"],
                confidence=0.7,
            ),
            LLMStage(
                stage_index=2,
                tactic="TA0001",
                technique="T1190",
                evidence_event_ids=["evt_1"],
                confidence=0.7,
            ),
        ]
    )
    _, result = _setup(config, events, analysis)
    assert any(issue.code == "stage_time_regression" for issue in result.issues)
    assert result.warning_count >= 1


def test_insufficient_evidence_is_reported_as_info(config) -> None:
    events = [make_event("evt_1", rules=["l1_port_scan_sweep"])]
    analysis = _analysis(
        [
            LLMStage(
                stage_index=1,
                tactic="TA0043",
                technique="T1595",
                evidence_event_ids=["evt_1"],
                confidence=0.7,
            )
        ]
    )
    _, result = _setup(config, events, analysis)
    assert any(issue.code == "insufficient_evidence" for issue in result.issues)


def test_uncertainties_gain_the_validation_issues(config) -> None:
    events = [make_event("evt_1", rules=["l1_port_scan_sweep"])]
    analysis = _analysis(
        [
            LLMStage(
                stage_index=1,
                tactic="TA0043",
                technique="T1595",
                evidence_event_ids=["evt_ghost", "evt_1"],
                confidence=0.9,
            )
        ]
    )
    sanitized, _ = _setup(config, events, analysis)
    assert sanitized.uncertainties
