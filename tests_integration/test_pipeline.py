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
        cls.evidence = Path(cls.tmp.name) / "evidence.json"
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
        doc = json.loads(self.evidence.read_text(encoding="utf-8"))
        rows = pq.read_table(self.out_dir / "batch_000001.parquet").to_pylist()
        self.assertEqual({r["event_id"] for r in doc["events"]}, {r["event_id"] for r in rows})
        self.assertTrue(all(e.get("summary") for e in doc["events"]))


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
