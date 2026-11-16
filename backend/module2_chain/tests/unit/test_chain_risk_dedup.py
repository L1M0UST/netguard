"""Attack chain, risk scoring, confidence, fingerprint and dedup tests."""

from __future__ import annotations

from datetime import timedelta

from backend.common.schemas.attack import ChainStage
from backend.common.schemas.enums import Severity, TechniqueSource
from backend.module2_chain.attack.chain_builder import AttackChainBuilder
from backend.module2_chain.attack.deduplicator import AttackDeduplicator
from backend.module2_chain.attack.fingerprint import AttackFingerprintBuilder
from backend.module2_chain.attack.knowledge import load_knowledge_base
from backend.module2_chain.attack.technique_mapper import AttackTechniqueMapper
from backend.module2_chain.correlation.engine import CorrelationEngine
from backend.module2_chain.llm.schemas import LLMAttackAnalysis, LLMStage
from backend.module2_chain.risk.confidence import ConfidenceCalculator, normalise_rule_score
from backend.module2_chain.risk.scorer import RiskScorer, ScoringContext
from backend.module2_chain.schemas.internal import EvidenceValidationResult
from backend.module2_chain.tests.conftest import BASE_TIME, make_event


def _build(
    config,
    events,
    *,
    analysis: LLMAttackAnalysis | None = None,
    validation: EvidenceValidationResult | None = None,
    malicious_ioc: int = 0,
):
    knowledge = load_knowledge_base(config.attack_kb_path)
    candidate = CorrelationEngine(config, knowledge=knowledge).correlate(events)[0]
    techniques, _ = AttackTechniqueMapper(config, knowledge=knowledge).map_candidate(
        candidate, events
    )
    candidate = candidate.model_copy(
        update={
            "techniques": techniques,
            "correlation_score": 0.8,
        }
    )
    chain = AttackChainBuilder(config, knowledge=knowledge).build(
        candidate,
        events,
        analysis=analysis,
        validation=validation,
        techniques=techniques,
    )
    chain = AttackFingerprintBuilder(config).apply(chain)
    context = ScoringContext(
        candidate=candidate,
        events=events,
        analysis=analysis,
        validation=validation,
        ioc_hits=malicious_ioc,
        malicious_ioc_hits=malicious_ioc,
    )
    chain = RiskScorer(config, knowledge=knowledge).apply(chain, context)
    return chain, candidate


def test_rule_based_chain_is_evidence_bound(config) -> None:
    events = [
        make_event("evt_1", rules=["l1_port_scan_sweep"], reason="nmap port scan"),
        make_event(
            "evt_2",
            dst_port=8080,
            rules=["l1_exploit_cve_2021_44228"],
            reason="CVE-2021-44228 exploitation",
            timestamp=BASE_TIME + timedelta(seconds=45),
            score=95.0,
        ),
    ]
    chain, _ = _build(config, events)
    assert chain.stages
    indexes = [stage.stage_index for stage in chain.stages]
    assert indexes == list(range(1, len(indexes) + 1))
    known = {event.event_id for event in events}
    for stage in chain.stages:
        assert stage.evidence_event_ids
        assert set(stage.evidence_event_ids) <= known
        assert stage.narrative
    assert chain.mitre_tactics
    assert chain.summary
    assert chain.llm_degraded is True  # no LLM analysis was supplied
    assert chain.llm_meta.status == "not_called"


def test_single_event_yields_a_single_stage(config) -> None:
    events = [make_event("evt_1", rules=["l1_port_scan_sweep"])]
    chain, _ = _build(config, events)
    assert len(chain.stages) == 1
    assert chain.stages[0].evidence_event_ids == ["evt_1"]
    assert chain.severity in {Severity.INFO, Severity.LOW, Severity.MEDIUM}


def test_llm_analysis_is_used_when_validated(config) -> None:
    events = [
        make_event("evt_1", rules=["l1_port_scan_sweep"], reason="nmap port scan"),
        make_event(
            "evt_2",
            dst_port=8080,
            rules=["l1_exploit_cve_2021_44228"],
            reason="exploitation attempt",
            timestamp=BASE_TIME + timedelta(seconds=30),
        ),
    ]
    analysis = LLMAttackAnalysis(
        candidate_id="candidate",
        verdict="attack",
        attack_summary="LLM narrative summary",
        stages=[
            LLMStage(
                stage_index=1,
                tactic="TA0043",
                technique="T1595",
                narrative="Reconnaissance first",
                evidence_event_ids=["evt_1"],
                confidence=0.85,
            ),
            LLMStage(
                stage_index=2,
                tactic="TA0001",
                technique="T1190",
                narrative="Then exploitation",
                evidence_event_ids=["evt_2"],
                confidence=0.9,
            ),
        ],
        confidence=0.88,
    )
    chain, _ = _build(config, events, analysis=analysis)
    assert chain.summary == "LLM narrative summary"
    assert [stage.narrative for stage in chain.stages] == [
        "Reconnaissance first",
        "Then exploitation",
    ]
    assert chain.llm_degraded is False
    assert chain.stages[0].source in {TechniqueSource.LLM, TechniqueSource.MERGED}


def test_degraded_analysis_falls_back_to_rule_stages(config) -> None:
    events = [make_event("evt_1", rules=["l1_port_scan_sweep"], reason="port scan")]
    analysis = LLMAttackAnalysis(
        candidate_id="candidate",
        verdict="unknown",
        attack_summary="",
        stages=[],
        degraded=True,
        degraded_reason="LLM timeout",
    )
    chain, _ = _build(config, events, analysis=analysis)
    assert chain.llm_degraded is True
    assert chain.stages
    assert any("LLM timeout" in item for item in chain.uncertainties)


def test_risk_score_is_explainable_and_bounded(config) -> None:
    events = [
        make_event("evt_1", rules=["l1_ransomware_encryption"], reason="ransomware", score=99.0),
        make_event(
            "evt_2",
            rules=["l1_data_exfil_upload"],
            reason="exfiltration upload",
            timestamp=BASE_TIME + timedelta(seconds=20),
            score=95.0,
        ),
    ]
    chain, _ = _build(config, events, malicious_ioc=1)
    assert 0.0 <= chain.risk_score.score <= 100.0
    factor_names = {factor.name for factor in chain.risk_score.factors}
    assert {
        "tactic_severity",
        "evidence_strength",
        "ioc",
        "asset_criticality",
        "rule_score",
        "llm_confidence",
        "chain_length",
        "multi_stage",
    } <= factor_names
    assert chain.risk_score.rationale
    assert any("malicious indicator" in item for item in chain.risk_score.rationale)
    # 共享证据折叠上线后，两条事件不再撑起虚胖多阶段，chain_length/multi_stage
    # 贡献下降——量纲收紧，strong 信号（IOC+高规则分）仍应守住中危及以上。
    assert chain.severity.rank >= Severity.MEDIUM.rank


def test_m1_semantic_is_evidence_bound_and_cannot_remove_rule_facts(config) -> None:
    base = make_event("evt_semantic", rules=["l1_exploit_cve_2021_44228"], score=90.0)
    assessed = base.model_copy(update={
        "m1_semantic_verdict": "malicious",
        "m1_semantic_confidence": 0.8,
        "m1_evidence_reference": '{"event_id":"evt_semantic","batch_id":"batch_test"}',
    })
    chain, _ = _build(config, [assessed])
    factors = {factor.name: factor for factor in chain.risk_score.factors}
    assert factors["m1_semantic"].value == 0.48
    assert factors["m1_semantic"].evidence_event_ids == ["evt_semantic"]
    assert factors["rule_score"].value == normalise_rule_score(90.0)

    unreferenced = base.model_copy(update={
        "m1_semantic_verdict": "malicious",
        "m1_semantic_confidence": 1.0,
        "m1_evidence_reference": '{"event_id":"not-in-chain","batch_id":"batch_test"}',
    })
    unsupported_chain, _ = _build(config, [unreferenced])
    unsupported = {factor.name: factor for factor in unsupported_chain.risk_score.factors}
    assert unsupported["m1_semantic"].value == 0.0
    assert unsupported["rule_score"].value == factors["rule_score"].value


def test_scanning_only_chain_scores_lower_than_impact(config) -> None:
    scanning = _build(config, [make_event("evt_1", rules=["l1_port_scan_sweep"])])[0]
    impact = _build(
        config,
        [
            make_event(
                "evt_1",
                rules=["l1_ransomware_encryption"],
                reason="ransomware encryption",
                score=99.0,
            )
        ],
    )[0]
    assert impact.risk_score.score > scanning.risk_score.score
    assert impact.severity.rank >= scanning.severity.rank


def test_confidence_is_not_the_llm_number_alone(config) -> None:
    events = [
        make_event(f"evt_{index}", rules=["l1_port_scan_sweep"], score=20.0)
        for index in range(3)
    ]
    analysis = LLMAttackAnalysis(
        candidate_id="candidate",
        verdict="suspicious",
        confidence=0.99,
        stages=[
            LLMStage(
                stage_index=1,
                tactic="TA0043",
                technique="T1595",
                narrative="scan",
                evidence_event_ids=["evt_0"],
                confidence=0.99,
            )
        ],
    )
    confident_chain, _ = _build(config, events, analysis=analysis)
    low_llm_chain, _ = _build(
        config,
        events,
        analysis=analysis.model_copy(update={"confidence": 0.05}),
    )
    assert confident_chain.confidence != analysis.confidence
    assert confident_chain.confidence > low_llm_chain.confidence
    assert confident_chain.confidence_factors


def test_llm_degradation_removes_the_llm_factor(config) -> None:
    events = [make_event("evt_1", rules=["l1_port_scan_sweep"])]
    degraded = LLMAttackAnalysis(
        candidate_id="candidate", verdict="unknown", stages=[], degraded=True
    )
    chain, _ = _build(config, events, analysis=degraded)
    factor_names = {factor.name for factor in chain.confidence_factors}
    assert "llm" not in factor_names
    assert chain.llm_degraded is True


def test_validation_penalty_reduces_confidence(config) -> None:
    events = [make_event("evt_1", rules=["l1_port_scan_sweep"])]
    clean, _ = _build(config, events)
    penalised, _ = _build(
        config,
        events,
        validation=EvidenceValidationResult(
            candidate_id="candidate",
            valid=False,
            hallucination_detected=True,
            confidence_penalty=0.3,
        ),
    )
    assert penalised.confidence < clean.confidence
    assert any(factor.name == "validation_penalty" for factor in penalised.confidence_factors)


def test_asset_criticality_factor_respects_zero_weight(config, event_factory) -> None:
    """2026-11-15 拍板：asset_criticality 权重置 0（赛题数据源全内网，无重要性事实不加分）。

    因子仍被记录（功能保留、实战接 CMDB 后权重 0→0.12 一键恢复），但不再影响总分。
    """
    events = [make_event("evt_1", rules=["l1_exploit_cve_2021_44228"], score=90.0)]
    knowledge = load_knowledge_base(config.attack_kb_path)
    chain, candidate = _build(config, events)
    scorer = RiskScorer(config, knowledge=knowledge)
    plain = scorer.score(chain, ScoringContext(candidate=candidate, asset_weights={"x": 1.0}))
    critical = scorer.score(chain, ScoringContext(candidate=candidate, asset_weights={"x": 3.0}))
    assert critical.score == plain.score
    asset_factor = next(f for f in critical.factors if f.name == "asset_criticality")
    assert asset_factor.weight == 0.0
    assert asset_factor.contribution == 0.0


def test_rule_score_normalisation() -> None:
    assert normalise_rule_score(0.5) == 0.5
    assert normalise_rule_score(5.0) == 0.5
    assert normalise_rule_score(50.0) == 0.5
    assert normalise_rule_score(0) == 0.0
    assert normalise_rule_score(-1) == 0.0


def test_confidence_calculator_respects_the_threshold(config) -> None:
    calculator = ConfidenceCalculator(config)
    strong = calculator.compute(
        evidence_count=6,
        max_rule_score=90.0,
        correlation_score=0.9,
        ioc_score=1.0,
        llm_confidence=0.9,
        llm_degraded=False,
    )
    weak = calculator.compute(
        evidence_count=1,
        max_rule_score=5.0,
        correlation_score=0.0,
        ioc_score=0.0,
        llm_confidence=0.1,
        llm_degraded=False,
    )
    assert strong.value > weak.value
    assert calculator.meets_threshold(strong.value)
    assert not calculator.meets_threshold(weak.value)


def test_fingerprint_is_stable_and_discriminating(config) -> None:
    events = [make_event("evt_1", rules=["l1_port_scan_sweep"])]
    first, _ = _build(config, events)
    second, _ = _build(config, events)
    assert first.fingerprint == second.fingerprint
    assert first.fingerprint is not None
    assert first.fingerprint.startswith("af_")

    other_attacker = [make_event("evt_1", src_ip="10.0.0.99", rules=["l1_port_scan_sweep"])]
    third, _ = _build(config, other_attacker)
    assert third.fingerprint != first.fingerprint


def test_fingerprint_components_are_human_readable(config) -> None:
    events = [make_event("evt_1", rules=["l1_port_scan_sweep"])]
    chain, _ = _build(config, events)
    components = AttackFingerprintBuilder(config).components(chain)
    assert components["attackers"] == "10.0.0.8"
    assert "time_bucket" in components


def test_chain_ids_are_deterministic(config) -> None:
    events = [make_event("evt_1", rules=["l1_port_scan_sweep"])]
    first, _ = _build(config, events)
    second, _ = _build(config, events)
    assert first.chain_id == second.chain_id
    assert first.chain_id.startswith("chain_")


def test_deduplicator_merges_equal_fingerprints(config) -> None:
    events = [make_event("evt_1", rules=["l1_port_scan_sweep"])]
    first, _ = _build(config, events)
    second, _ = _build(config, events)
    assert first.fingerprint == second.fingerprint
    # Two *different* candidates can describe the same attack; that is the case
    # the fingerprint deduplication exists for.
    second = second.model_copy(update={"chain_id": "chain_from_another_candidate"})
    unique, merged = AttackDeduplicator(config).deduplicate([first, second])
    assert len(unique) == 1
    assert len(merged) == 1
    assert unique[0].deduplicated_from == ["chain_from_another_candidate"]


def test_identical_chain_ids_collapse_without_duplication(config) -> None:
    events = [make_event("evt_1", rules=["l1_port_scan_sweep"])]
    first, _ = _build(config, events)
    second, _ = _build(config, events)
    assert first.chain_id == second.chain_id
    unique, merged = AttackDeduplicator(config).deduplicate([first, second])
    assert len(unique) == 1
    assert len(merged) == 1
    assert unique[0].chain_id == first.chain_id


def test_deduplicator_keeps_distinct_fingerprints(config) -> None:
    scan, _ = _build(config, [make_event("evt_1", rules=["l1_port_scan_sweep"])])
    ransom, _ = _build(
        config,
        [
            make_event(
                "evt_2",
                src_ip="192.0.2.5",
                rules=["l1_ransomware_encryption"],
                reason="ransomware encryption",
                score=99.0,
            )
        ],
    )
    unique, merged = AttackDeduplicator(config).deduplicate([scan, ransom])
    assert len(unique) == 2
    assert merged == []


def test_deduplicator_union_of_evidence_and_severity(config) -> None:
    events = [
        make_event("evt_1", rules=["l1_port_scan_sweep"]),
        make_event("evt_2", rules=["l1_port_scan_sweep"], dst_port=443),
    ]
    first, _ = _build(config, events[:1])
    second, _ = _build(config, events)
    first = first.model_copy(update={"severity": Severity.LOW, "confidence": 0.4})
    second = second.model_copy(update={"severity": Severity.CRITICAL, "confidence": 0.9})
    second = second.model_copy(
        update={"fingerprint": first.fingerprint, "chain_id": "chain_other"}
    )
    unique, _ = AttackDeduplicator(config).deduplicate([first, second])
    merged = unique[0]
    assert merged.severity is Severity.CRITICAL
    assert merged.confidence == 0.9
    assert "evt_1" in merged.event_ids and "evt_2" in merged.event_ids


def test_correlation_evidence_reaches_the_chain_and_survives_merge(config) -> None:
    """边证据验收：关联理由必须随链输出，且指纹合并后只增不减。"""

    events = [make_event("evt_1", rules=["l1_port_scan_sweep"]), make_event("evt_2", rules=["l1_port_scan_sweep"], dst_port=443)]
    chain, candidate = _build(config, events)
    # _build 里 candidate 已带 correlation_score=0.8；关联理由来自 CorrelationEngine
    assert chain.correlation_score == 0.8
    assert chain.correlation_reasons, "chain must carry the pairwise correlation reasons"

    second = chain.model_copy(update={"chain_id": "chain_from_another_candidate"})
    unique, _ = AttackDeduplicator(config).deduplicate([chain, second])
    merged = unique[0]
    assert merged.correlation_score == 0.8
    assert set(chain.correlation_reasons) <= set(merged.correlation_reasons)


# ---- _collapse_single_evidence_stages：共享证据的候选展开阶段折叠 ----


def _stage(tactic: str, technique: str, ids, confidence: float) -> ChainStage:
    return ChainStage(
        stage_index=1,
        tactic=tactic,
        technique=technique,
        narrative="",
        evidence_event_ids=list(ids),
        confidence=confidence,
    )


def _collapse_builder(config):
    return AttackChainBuilder(config, knowledge=load_knowledge_base(config.attack_kb_path))


def test_collapse_folds_stages_sharing_the_same_multi_evidence(config) -> None:
    """全部阶段引用同一组（多条）证据=候选展开虚胖，折叠为首个引入证据的阶段。"""
    builder = _collapse_builder(config)
    stages = [
        _stage("TA0001", "T1190", ["evt_a", "evt_b"], 0.8),
        _stage("TA0002", "T1203", ["evt_b", "evt_a"], 0.5),
        _stage("TA0010", "T1041", ["evt_a", "evt_b"], 0.6),
    ]
    kept, note = builder._collapse_single_evidence_stages(stages)
    assert len(kept) == 1
    assert kept[0].technique == "T1190"
    assert kept[0].stage_index == 1
    assert note is not None and "2 of 3 proposed stages were folded" in note


def test_collapse_folds_group_shared_evidence(config) -> None:
    """分组共享形态（A 撑 4 阶段+B 撑 3 阶段，无新证据的阶段）：折叠为 2 个观察阶段。"""
    builder = _collapse_builder(config)
    stages = [
        _stage("TA0001", "T1190", ["evt_a"], 0.7),
        _stage("TA0002", "T1203", ["evt_a"], 0.5),
        _stage("TA0004", "T1068", ["evt_a"], 0.5),
        _stage("TA0003", "T1505", ["evt_a"], 0.4),
        _stage("TA0010", "T1041", ["evt_b"], 0.6),
        _stage("TA0010", "T1048", ["evt_b"], 0.5),
        _stage("TA0011", "T1071", ["evt_b"], 0.4),
    ]
    kept, note = builder._collapse_single_evidence_stages(stages)
    assert len(kept) == 2
    assert [s.technique for s in kept] == ["T1190", "T1041"]
    assert [s.stage_index for s in kept] == [1, 2]
    assert note is not None and "5 of 7 proposed stages were folded" in note


def test_collapse_folds_single_evidence_stages(config) -> None:
    """单条证据被多阶段共享：原行为回归。"""
    builder = _collapse_builder(config)
    stages = [
        _stage("TA0001", "T1190", ["evt_a"], 0.7),
        _stage("TA0002", "T1203", ["evt_a"], 0.4),
    ]
    kept, note = builder._collapse_single_evidence_stages(stages)
    assert len(kept) == 1 and kept[0].technique == "T1190"
    assert note is not None and "1 of 2 proposed stages were folded" in note


def test_collapse_keeps_stages_with_distinct_evidence(config) -> None:
    """各阶段证据集不同=真实战术推进，不折叠。"""
    builder = _collapse_builder(config)
    stages = [
        _stage("TA0001", "T1190", ["evt_a"], 0.7),
        _stage("TA0002", "T1203", ["evt_b"], 0.4),
    ]
    kept, note = builder._collapse_single_evidence_stages(stages)
    assert len(kept) == 2 and note is None


def test_collapse_keeps_partially_overlapping_evidence(config) -> None:
    """部分阶段有专属证据（S1{a} vs S2{a,b}）=推进补强，不折叠。"""
    builder = _collapse_builder(config)
    stages = [
        _stage("TA0001", "T1190", ["evt_a"], 0.7),
        _stage("TA0002", "T1203", ["evt_a", "evt_b"], 0.4),
    ]
    kept, note = builder._collapse_single_evidence_stages(stages)
    assert len(kept) == 2 and note is None


def test_collapse_renumbers_and_never_returns_empty(config) -> None:
    """极端情形：全部阶段共用已见证据且首阶段无证据时，仍至少保留一个阶段。"""
    builder = _collapse_builder(config)
    stages = [
        _stage("TA0001", "T1190", [], 0.9),
        _stage("TA0002", "T1203", ["evt_a"], 0.4),
        _stage("TA0010", "T1041", ["evt_a"], 0.3),
    ]
    kept, note = builder._collapse_single_evidence_stages(stages)
    assert len(kept) == 1 and kept[0].stage_index == 1
    assert note is not None
