"""整合层测试：bridge 契约转换 / 标签映射 / bundle 组装。

bridge 测试使用 he-l 仓库内的真实 M1 审计批次作为 fixture（不存在则跳过）；
bundle 测试用合成 M2 输出，全部可离线运行。

运行:  .venv/Scripts/python.exe -m unittest tests_integration.test_pipeline -v
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from bridge.labels import LABEL_PENDING, label_for, severity_for  # noqa: E402

REAL_M1_BATCH = Path(
    r"E:\platform_taishi\he-l\he-l\work\quality-audit"
    r"\92b7616ad5a04b88b4884a2f8ad4ff48\m1\ready"
    r"\batch-quality-audit\310911345d5c44bf93384512bc819959")


class LabelMappingTest(unittest.TestCase):
    def test_rule_to_official_label(self):
        self.assertEqual(label_for(["sql_injection"]), "SQL注入攻击")
        self.assertEqual(label_for(["path_traversal"]), "目录遍历攻击")
        self.assertEqual(label_for(["command_injection"]), "远程命令执行攻击")
        self.assertEqual(label_for(["multi_path_scan"]), "扫描探测攻击")

    def test_priority_when_multiple_rules(self):
        # 命令注入优先级高于 XSS
        self.assertEqual(label_for(["xss", "command_injection"]), "远程命令执行攻击")

    def test_no_rule_means_pending(self):
        self.assertEqual(label_for([]), LABEL_PENDING)
        self.assertEqual(label_for(None, ioc_matches=[{"type": "ip", "value": "1.2.3.4"}]),
                         LABEL_PENDING)

    def test_severity_map(self):
        self.assertEqual(severity_for("high"), "high")
        self.assertEqual(severity_for("critical"), "critical")
        self.assertEqual(severity_for(None), "info")
        self.assertEqual(severity_for("weird"), "info")


@unittest.skipUnless(REAL_M1_BATCH.is_dir(), "真实 M1 审计批次 fixture 不存在")
class BridgeExportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from bridge.export_m2_batch import export_batch
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out_dir = Path(cls.tmp.name) / "task_test"
        cls.evidence = Path(cls.tmp.name) / "evidence.parquet"
        cls.stats = export_batch(REAL_M1_BATCH, cls.out_dir, "task_test",
                                 evidence_out=cls.evidence, limit=500)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_writes_contract_layout(self):
        for name in ("batch_000001.parquet", "manifest.json", "READY"):
            self.assertTrue((self.out_dir / name).is_file(), name)

    def test_manifest_fields(self):
        manifest = json.loads((self.out_dir / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], "1.0.0")
        self.assertEqual(manifest["task_id"], "task_test")
        self.assertEqual(manifest["event_count"], manifest["files"][0]["row_count"])
        payload = (self.out_dir / "batch_000001.parquet").read_bytes()
        self.assertEqual(hashlib.sha256(payload).hexdigest(), manifest["files"][0]["sha256"])

    def test_rows_pass_m2_pydantic_contract(self):
        import pyarrow.parquet as pq
        from backend.common.schemas.suspicious_event import SuspiciousEvent
        rows = pq.read_table(self.out_dir / "batch_000001.parquet").to_pylist()
        self.assertTrue(rows)
        for row in rows:
            event = SuspiciousEvent.model_validate({
                "event": {k: row.get(k) for k in (
                    "event_id", "task_id", "timestamp", "src_ip", "dst_ip", "src_port",
                    "dst_port", "protocol", "payload_digest", "raw_ref", "source_file")},
                "detection": {k: row.get(k) for k in (
                    "matched_rules", "ioc_hits", "score", "reason", "detector")},
                "session_id": row.get("session_id"),
                "emitted_at": row.get("emitted_at"),
                "schema_version": row.get("schema_version"),
                "attack_type": row.get("attack_type"),
                "risk_level": row.get("risk_level"),
                "url_path": row.get("url_path"),
                "review_group_id": row.get("review_group_id"),
            })
            self.assertTrue(event.event.task_id)
            self.assertIsNotNone(event.event.timestamp)

    def test_evidence_index_consistent(self):
        import pyarrow.parquet as pq
        # 9.23 起 evidence 索引为 Parquet 二进制（防 Defender 拦截明文 JSON），字段含 event_id/summary
        doc_rows = pq.read_table(self.evidence).to_pylist()
        rows = pq.read_table(self.out_dir / "batch_000001.parquet").to_pylist()
        self.assertEqual({r["event_id"] for r in doc_rows}, {r["event_id"] for r in rows})
        self.assertTrue(all(e.get("summary") for e in doc_rows))


class BundleAssembleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        # 合成 evidence 索引
        events = [{"event_id": f"ev-{i}", "session_id": "s1", "timestamp": f"2025-10-21T19:2{i}:00+00:00",
                   "src_ip": "10.25.73.34", "dst_ip": "10.60.33.18", "url_path": "/API/uSerS",
                   "attack_type": "SQL注入攻击", "risk_level": "high",
                   "matched_rules": ["sql_injection"], "ioc_hits": [],
                   "summary": f"证据 {i}"} for i in range(1, 4)]
        (base / "evidence.json").write_text(
            json.dumps({"task_id": "t1", "labels": {}, "events": events}, ensure_ascii=False),
            encoding="utf-8")
        # 合成 M2 输出
        out = base / "m2out"
        (out / "reports").mkdir(parents=True)
        chain = {"chain_id": "chain_abc", "task_id": "t1", "severity": "high",
                 "confidence": 0.8, "summary": "SQL 注入攻击链",
                 "attacker_ips": ["10.25.73.34"], "victim_ips": ["10.60.33.18"],
                 "risk_score": {"score": 78, "rationale": ["多阶段注入"]},
                 "llm_meta": {"model": "deepseek-v4-pro", "prompt_version": "attack_analysis.v1"},
                 "llm_degraded": False,
                 "stages": [
                     {"stage_index": 1, "tactic": "TA0001", "tactic_name": "Initial Access",
                      "technique": "T1190", "technique_name": "Exploit Public-Facing App",
                      "narrative": "注入探测", "evidence_event_ids": ["ev-1"], "confidence": 0.7,
                      "source": "rule"},
                     {"stage_index": 2, "tactic": "TA0006", "tactic_name": "Impact",
                      "technique": "T1041", "technique_name": "Exfiltration",
                      "narrative": "数据外传", "evidence_event_ids": ["ev-2", "ev-3"],
                      "confidence": 0.9, "source": "llm"}]}
        (out / "chains.json").write_text(json.dumps([chain], ensure_ascii=False), encoding="utf-8")
        alert = {"alert_id": "alert_001", "chain_id": "chain_abc", "task_id": "t1",
                 "title": "SQL 注入", "description": "检测到注入", "severity": "high",
                 "confidence": 0.8, "evidence_event_ids": ["ev-1", "ev-2"],
                 "attacker_ips": ["10.25.73.34"], "victim_ips": ["10.60.33.18"],
                 "mitre_tactics": ["TA0001"], "mitre_techniques": ["T1190"],
                 "first_seen": "2025-10-21T19:21:00+00:00", "last_seen": "2025-10-21T19:22:00+00:00"}
        (out / "alerts.json").write_text(json.dumps([alert], ensure_ascii=False), encoding="utf-8")
        profile = {"attacker_id": "attacker_01", "attacker_ips": ["10.25.73.34"],
                   "evidence_event_ids": ["ev-1"], "chain_ids": ["chain_abc"],
                   "attack_count": 2, "attribution": "Not Determined",
                   "attribution_confidence": 0, "max_severity": "high",
                   "behavior_summary": "多阶段注入", "risk_score": 78,
                   "first_seen": "2025-10-21T19:21:00+00:00", "last_seen": "2025-10-21T19:23:00+00:00"}
        (out / "attackers.json").write_text(json.dumps([profile], ensure_ascii=False), encoding="utf-8")
        report = {"report_id": "r1", "task_id": "t1", "overview": "总体风险中高",
                  "statistics": {"total_attack_events": 1, "high_count": 1},
                  "recommendations": [{"mitigation_id": "m1", "title": "参数化查询",
                                       "description": "使用预编译语句",
                                       "recommendation_type": "evidence_based",
                                       "priority": "high", "related_techniques": ["T1190"]}]}
        (out / "reports" / "report.json").write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
        (out / "metrics.json").write_text(json.dumps({"stage_timings": {"correlation": 0.5, "llm": 1.2}}),
                                          encoding="utf-8")
        self.base, self.out = base, out

    def tearDown(self):
        self.tmp.cleanup()

    def test_assemble_produces_valid_bundle(self):
        from bundle.assemble import assemble
        from m3.workspace_io import Bundle
        stats = assemble("t1", self.out, self.base / "evidence.json",
                         self.base / "m2_ready" / "t1")
        self.assertEqual(stats["chains"], 1)
        self.assertEqual(stats["alerts"], 1)
        payload = (self.base / "m2_ready" / "t1" / "bundle.json").read_bytes()
        manifest = json.loads((self.base / "m2_ready" / "t1" / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(hashlib.sha256(payload).hexdigest(), manifest["sha256"])
        bundle = Bundle.model_validate_json(payload)
        self.assertEqual(bundle.chains[0].edges, [("chain_abc-s01", "chain_abc-s02")])
        self.assertEqual(bundle.alerts[0]["attack_type"], "SQL注入攻击")
        self.assertEqual(bundle.report["recommended_actions"][0]["source"], "rule_based")
        data = json.loads(payload)
        # 攻击类型分布：metrics 与 report.statistics 同源（页面 chips / cqsec 运营总结输入）
        self.assertEqual(data["metrics"]["attack_types"], {"SQL注入攻击": 1})
        self.assertEqual(data["report"]["statistics"]["attack_type_counts"], {"SQL注入攻击": 1})
        self.assertEqual(stats["attack_type_counts"], {"SQL注入攻击": 1})
        # 高风险资产双榜单：本地聚合（victim 10.60.33.18 被 1 条 high 链/1 条告警命中）
        # critical/high 是硬指针 → 必须进"受高威胁攻击"榜，不受相对截断影响
        self.assertEqual(stats["victims"], 1)
        victim = data["victims"][0]
        self.assertEqual(victim["victim_ip"], "10.60.33.18")
        self.assertEqual(victim["alert_count"], 1)
        self.assertEqual(victim["chain_count"], 1)
        self.assertEqual(victim["max_severity"], "high")
        self.assertGreater(victim["threat_score"], 0)
        self.assertGreater(victim["freq_score"], 0)
        self.assertTrue(victim["in_threat_ranking"])
        self.assertTrue(victim["in_freq_ranking"])


    def test_campaign_grouping_and_correlation_passthrough(self):
        """跨链活动归并 + 关联依据/缺失证据透出（第四方面验收：逐边可解释）。"""
        from bundle.assemble import assemble
        from m3.workspace_io import Bundle
        # 在同一任务里放两条链：同攻击源、间隔 2 分钟 -> 必须归并为一个攻击活动
        chain_a = {"chain_id": "chain_aaa", "task_id": "t1", "severity": "high",
                   "confidence": 0.8, "summary": "注入探测",
                   "attacker_ips": ["10.25.73.34"], "victim_ips": ["10.60.33.18"],
                   "risk_score": {"score": 78, "rationale": ["注入"]},
                   "correlation_score": 0.75,
                   "correlation_reasons": ["identical attacker 10.25.73.34",
                                           "events occur within 30s (inside the correlation window)"],
                   "uncertainties": ["模型提出了多个阶段，但仅有一条证据事件支持"],
                   "llm_meta": {"model": "m", "prompt_version": "v"},
                   "stages": [{"stage_index": 1, "tactic": "TA0001", "tactic_name": "Initial Access",
                               "technique": "T1190", "technique_name": "Exploit",
                               "narrative": "探测", "evidence_event_ids": ["ev-1"],
                               "confidence": 0.7, "source": "rule"}],
                   "first_seen": "2025-10-21T19:21:00+00:00",
                   "last_seen": "2025-10-21T19:22:00+00:00"}
        chain_b = dict(chain_a, chain_id="chain_bbb", severity="medium", confidence=0.6,
                       victim_ips=["10.60.33.99"],
                       stages=[{"stage_index": 1, "tactic": "TA0002", "tactic_name": "Execution",
                                "technique": "T1059", "technique_name": "Command Interpreter",
                                "narrative": "执行", "evidence_event_ids": ["ev-2"],
                                "confidence": 0.6, "source": "rule"}],
                       first_seen="2025-10-21T19:24:00+00:00",
                       last_seen="2025-10-21T19:25:00+00:00")
        (self.out / "chains.json").write_text(json.dumps([chain_a, chain_b], ensure_ascii=False),
                                              encoding="utf-8")
        out = self.base / "m2_ready" / "t1c"
        stats = assemble("t1", self.out, self.base / "evidence.json", out)
        payload = (out / "bundle.json").read_bytes()
        bundle = Bundle.model_validate_json(payload)  # extra 字段必须能过 M3 校验器
        data = json.loads(payload)
        # 1) 关联依据与不确定项逐字透出
        chain = data["chains"][0]
        self.assertEqual(chain["correlation_score"], 0.75)
        self.assertIn("identical attacker 10.25.73.34", chain["correlation_reasons"])
        self.assertTrue(chain["uncertainties"])
        # 2) 战役归并：2 条链 -> 1 个活动，理由与 campaign_id 双向挂接
        self.assertEqual(stats["campaigns"], 1)
        campaign = data["campaigns"][0]
        self.assertEqual(campaign["chain_count"], 2)
        self.assertTrue(any("共享攻击源 10.25.73.34" in r for r in campaign["reasons"]))
        ids = {c["chain_id"] for c in data["chains"]}
        self.assertTrue(all(c["campaign_id"] == campaign["campaign_id"] for c in data["chains"]))
        self.assertEqual(ids, set(campaign["chain_ids"]))
        self.assertEqual(data["metrics"]["campaign_count"], 1)
        # 3) 任务列表瘦身剥离 campaigns 由 m3/test_campaign_slim.py 覆盖（避免此处引入 m3_services）

    def test_victim_ranking_hard_pointer(self):
        """高危硬指针：整体分数低时，critical/high 资产也不能被相对截断挤出榜单。"""
        from bundle.assemble import _build_victims
        chains = [{"chain_id": "chain_high", "severity": "high", "risk_score": {"score": 88},
                   "attacker_ips": ["10.0.0.1"], "victim_ips": ["10.9.9.9"],
                   "stages": [{"tactic": "TA0001", "technique": "T1190"}]}]
        for i in range(1, 11):  # 10 个纯低危受害资产，威胁指数与高危资产差距悬殊
            chains.append({"chain_id": f"chain_low_{i}", "severity": "low", "risk_score": {"score": 22},
                           "attacker_ips": [f"10.1.0.{i}"], "victim_ips": [f"10.8.0.{i}"],
                           "stages": [{"tactic": "TA0007", "technique": "T1046"}]})
        rows = _build_victims({}, chains, [])
        threat_rows = [r for r in rows if r.get("in_threat_ranking")]
        ips = {r["victim_ip"] for r in threat_rows}
        self.assertIn("10.9.9.9", ips)          # 硬指针：high 资产强制在榜
        self.assertLessEqual(len(threat_rows), 8)  # 相对截断只影响软名额
        # 高危资产的威胁指数必须高于所有低危资产（权重结构保证）
        high_row = next(r for r in rows if r["victim_ip"] == "10.9.9.9")
        for row in threat_rows:
            if row["victim_ip"] != "10.9.9.9":
                self.assertGreaterEqual(high_row["threat_score"], row["threat_score"])

    def test_reference_closure_enforced(self):
        """引用不闭合的链阶段必须被剔除而不是产出非法包。"""
        from bundle.assemble import assemble
        from m3.workspace_io import Bundle
        evidence = json.loads((self.base / "evidence.json").read_text(encoding="utf-8"))
        evidence["events"] = evidence["events"][:1]  # 只保留 ev-1
        (self.base / "evidence2.json").write_text(json.dumps(evidence, ensure_ascii=False),
                                                  encoding="utf-8")
        assemble("t1", self.out, self.base / "evidence2.json", self.base / "m2_ready" / "t1b")
        payload = (self.base / "m2_ready" / "t1b" / "bundle.json").read_bytes()
        bundle = Bundle.model_validate_json(payload)  # 校验器必须通过
        self.assertEqual(len(bundle.chains[0].stages), 1)  # ev-2/ev-3 不存在 -> 阶段2被剔除


if __name__ == "__main__":
    unittest.main()


class GraphBuilderTest(unittest.TestCase):
    """NetworkX 关联图：节点/边/社区/坐标（第四方面"图遍历、社区发现"真实实现）。"""

    def setUp(self):
        self.chains = [
            {"chain_id": "chain_a", "severity": "high", "risk_score": {"score": 80},
             "attacker_ips": ["1.1.1.1"], "victim_ips": ["10.0.0.1"],
             "campaign_id": "camp_x", "stages": [{}, {}],
             "first_seen": "2026-01-01T08:00:00+00:00", "last_seen": "2026-01-01T08:05:00+00:00"},
            {"chain_id": "chain_b", "severity": "medium", "risk_score": {"score": 50},
             "attacker_ips": ["1.1.1.1"], "victim_ips": ["10.0.0.2"],
             "campaign_id": "camp_x", "stages": [{}],
             "first_seen": "2026-01-01T08:30:00+00:00", "last_seen": "2026-01-01T08:31:00+00:00"},
            {"chain_id": "chain_c", "severity": "critical", "risk_score": {"score": 95},
             "attacker_ips": ["2.2.2.2"], "victim_ips": ["10.0.0.1"], "stages": [{}],
             "first_seen": "2026-01-01T09:00:00+00:00", "last_seen": "2026-01-01T09:01:00+00:00"},
        ]
        self.campaigns = [{"campaign_id": "camp_x",
                           "members": [{"chain_id": "chain_a", "first_seen": "2026-01-01T08:00:00+00:00",
                                        "last_seen": "2026-01-01T08:05:00+00:00"},
                                       {"chain_id": "chain_b", "first_seen": "2026-01-01T08:30:00+00:00",
                                        "last_seen": "2026-01-01T08:31:00+00:00"}],
                           "reasons": ["共享攻击源 1.1.1.1"]}]

    def test_graph_structure_and_layout(self):
        from bundle.graph_builder import build_attack_graph
        g = build_attack_graph("t", self.chains, self.campaigns)
        self.assertEqual(g["schema_version"], "AttackGraph.v1")
        self.assertEqual(g["stats"]["node_count"], 7)   # 3 链 + 4 个 IP
        self.assertGreaterEqual(g["stats"]["edge_count"], 7)
        self.assertGreaterEqual(g["stats"]["community_count"], 1)
        self.assertEqual(g["stats"]["component_count"], 1)
        types = {n["type"] for n in g["nodes"]}
        self.assertEqual(types, {"chain", "ip"})
        for n in g["nodes"]:
            self.assertTrue(0 <= n["x"] <= g["canvas"]["width"])
            self.assertTrue(0 <= n["y"] <= g["canvas"]["height"])
        edge_types = {e["type"] for e in g["edges"]}
        self.assertEqual(edge_types, {"launches", "targets", "campaign"})
        campaign_edge = next(e for e in g["edges"] if e["type"] == "campaign")
        self.assertIn("共享攻击源", campaign_edge["reason"])
        self.assertIn("1.1.1.1", [i["ip"] for i in g["stats"]["top_ips"]])

    def test_graph_truncation_keeps_top_risk(self):
        from bundle.graph_builder import CHAINS_PER_CAMPAIGN, build_attack_graph
        many = []
        for i in range(CHAINS_PER_CAMPAIGN + 3):
            many.append({"chain_id": f"chain_m{i}", "severity": "low", "risk_score": {"score": 10 + i},
                         "attacker_ips": ["9.9.9.9"], "victim_ips": ["10.9.0.9"],
                         "campaign_id": "camp_big", "stages": [{}],
                         "first_seen": "2026-01-01T10:00:00+00:00", "last_seen": "2026-01-01T10:01:00+00:00"})
        members = [{"chain_id": c["chain_id"], "first_seen": c["first_seen"], "last_seen": c["last_seen"]}
                   for c in many]
        campaigns = [{"campaign_id": "camp_big", "members": members, "reasons": ["共享攻击源 9.9.9.9"]}]
        g = build_attack_graph("t2", many, campaigns)
        chain_ids = {n["chain_id"] for n in g["nodes"] if n["type"] == "chain"}
        self.assertEqual(len(chain_ids), CHAINS_PER_CAMPAIGN)
        self.assertTrue(g["stats"]["truncated"])
        self.assertTrue(all(n["risk_score"] >= 10 + 3 for n in g["nodes"] if n["type"] == "chain"))

    def test_assemble_attaches_graph(self):
        """assemble 把图挂进 bundle，且 M3 校验器放行（最小夹具）。"""
        import tempfile
        from bundle.assemble import assemble
        from m3.workspace_io import Bundle
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            events = [{"event_id": f"ev-{i}", "session_id": "s1",
                       "timestamp": f"2025-10-21T19:2{i}:00+00:00", "src_ip": "10.25.73.34",
                       "dst_ip": "10.60.33.18", "url_path": "/a", "attack_type": "SQL注入攻击",
                       "risk_level": "high", "matched_rules": ["sql_injection"], "ioc_hits": [],
                       "summary": f"证据 {i}"} for i in (1, 2, 3)]
            (root / "evidence.json").write_text(
                json.dumps({"task_id": "t1", "labels": {}, "events": events}, ensure_ascii=False),
                encoding="utf-8")
            out = root / "m2out"
            (out / "reports").mkdir(parents=True)
            base_chain = {"task_id": "t1", "severity": "high", "confidence": 0.8,
                          "attacker_ips": ["10.25.73.34"], "victim_ips": ["10.60.33.18"],
                          "risk_score": {"score": 78, "rationale": ["注入"]},
                          "llm_meta": {"model": "m", "prompt_version": "v"},
                          "stages": [{"stage_index": 1, "tactic": "TA0001", "tactic_name": "IA",
                                      "technique": "T1190", "technique_name": "Exploit",
                                      "narrative": "n", "confidence": 0.7, "source": "rule"}]}
            chains = [
                dict(base_chain, chain_id="chain_g1", summary="s1",
                     stages=[dict(base_chain["stages"][0], evidence_event_ids=["ev-1"])],
                     first_seen="2025-10-21T19:21:00+00:00", last_seen="2025-10-21T19:22:00+00:00"),
                dict(base_chain, chain_id="chain_g2", severity="medium", summary="s2",
                     stages=[dict(base_chain["stages"][0], evidence_event_ids=["ev-2"])],
                     first_seen="2025-10-21T19:24:00+00:00", last_seen="2025-10-21T19:25:00+00:00"),
            ]
            (out / "chains.json").write_text(json.dumps(chains, ensure_ascii=False), encoding="utf-8")
            stats = assemble("t1", out, root / "evidence.json", root / "ready")
            data = json.loads((root / "ready" / "bundle.json").read_bytes())
            self.assertIsNotNone(data.get("graph"))
            self.assertEqual(data["graph"]["schema_version"], "AttackGraph.v1")
            self.assertGreater(data["metrics"]["graph_node_count"], 0)
            Bundle.model_validate_json((root / "ready" / "bundle.json").read_bytes())
            del stats

