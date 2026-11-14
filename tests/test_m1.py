import json
import unittest
from contextlib import contextmanager
import shutil
from unittest.mock import patch
from m1.run import l3_candidates, semantic_judge, write_events
from m1.run import normalized, aggregate, is_whitelisted, parse_ethernet_packet, read_records
from pathlib import Path
from uuid import uuid4

from m1.run import LLMClient, get_mapping_plan, ThreatBookClient, build_attack_campaigns, dedup_key, enrich, mapping_for, process, schema_profile


@contextmanager
def test_workspace():
    root = Path(__file__).parent / ".test-workspaces" / str(uuid4())
    root.mkdir(parents=True)
    try:
        yield root
    finally:
        shutil.rmtree(root)


class M1IntegrationTest(unittest.TestCase):
    def test_json_and_jsonl_parsers_and_icmp_ports(self):
        import struct
        with test_workspace() as root:
            rows = [{'src_ip': '10.0.0.1'}, {'dst_ip': '10.0.0.2'}]
            for fmt in ('json', 'jsonl'):
                path = root / ('events.' + fmt)
                path.write_text(json.dumps(rows) if fmt == 'json' else '\n'.join(json.dumps(row) for row in rows), encoding='utf-8')
                self.assertEqual(list(read_records(path, fmt)), rows)
        packet = bytearray(38)
        packet[12:14] = b'\x08\x00'
        packet[14] = 0x45
        packet[23] = 1
        packet[26:30] = bytes([10,0,0,1])
        packet[30:34] = bytes([10,0,0,2])
        packet[34:38] = struct.pack('>HH', 8, 123)
        self.assertIsNone(parse_ethernet_packet(packet)['src_port'])

    def test_l3_receives_bounded_evidence_and_rejects_nan(self):
        llm = LLMClient({'max_concurrency': 1})
        event = {'session_id': 's', 'event_id': 'e', 'batch_id': 'b', 'semantic_evidence': {'request_body': 'id=1 or 1=1'}}
        response = {'verdict': 'suspicious', 'confidence': 0.7, 'recommended_action': 'review', 'reasoning': ['payload evidence']}
        with patch.object(llm, 'ask_json', return_value=response) as ask:
            self.assertEqual(len(semantic_judge([event], llm)), 1)
            self.assertEqual(ask.call_args.args[1]['session']['semantic_evidence']['request_body'], 'id=1 or 1=1')
        with patch.object(llm, 'ask_json', return_value={**response, 'confidence': float('nan')}):
            self.assertEqual(semantic_judge([event], llm), [])

    def test_duty_regressions(self):
        config = {'ioc_ips': ['10.0.0.8'], 'ioc_domains': ['BAD.EXAMPLE'], 'ioc_urls': ['https://bad.example/a']}
        self.assertIn('ioc_match', enrich({'dst_ip': '10.0.0.8'}, config)['rule_hits'])
        self.assertIn('ioc_match', enrich({'url_path': 'https://bad.example/x'}, config)['rule_hits'])
        self.assertNotIn('ioc_match', enrich({'url_path': 'https://good.example/?q=https://bad.example/a'}, config)['rule_hits'])
        self.assertNotIn('file_upload', enrich({'request_body': 'multipart/form-data; filename=holiday.jpg'}, config)['rule_hits'])
        self.assertTrue(is_whitelisted({'src_ip': '10.0.0.1'}, {'whitelist_ips': [], 'trusted_networks': ['invalid', '10.0.0.0/24']}))
        row = {'timestamp': '2026-01-01T00:00:00+00:00', 'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.8', 'user_agent': 'browser'}
        plan = {key: key for key in row}
        a = normalized(row, plan, 'b', 'f', 1)
        b = normalized({**row, 'user_agent': 'sqlmap'}, plan, 'b', 'f', 2)
        self.assertNotEqual(a['fingerprint'], b['fingerprint'])
        self.assertFalse(a['data_quality']['timestamp_parse_error'])
        for event in (a,b): enrich(event, config)
        b['timestamp'] = '2026-01-01T00:10:00+00:00'
        self.assertEqual(len(aggregate([a,b], 300, 21600)), 2)
        b['timestamp'] = '2026-01-01T00:01:00+00:00'
        self.assertEqual(len(aggregate([a,b], 300, 21600)), 1)

    def test_l3_ratio_bounds(self):
        rows = [{'risk_level': 'high', 'risk_score': 90}] * 100
        for ratio in (-0.01, 0.1, float('nan'), float('inf')):
            with self.assertRaises(ValueError):
                l3_candidates(rows, 100, {'enable_l3_semantic_judge': True, 'l3_max_ratio': ratio})
        self.assertEqual(len(l3_candidates(rows, 100, {'enable_l3_semantic_judge': True})), 1)

    def test_parquet_batches_preserve_nested_late_values(self):
        import pyarrow.parquet as pq
        with test_workspace() as root:
            rows = [{'event_id': 'a', 'src_port': None, 'rule_hits': [], 'evidence': []},
                    {'event_id': 'b', 'src_port': 443, 'rule_hits': ['ioc_match'], 'evidence': [{'type': 'ioc', 'judgments': ['botnet']}]}]
            filename = write_events(root, 'sample', iter(rows), {'format': 'parquet', 'batch_size': 1})
            result = pq.read_table(root / filename).to_pylist()
            self.assertEqual(result[1]['src_port'], 443)
            self.assertEqual(result[1]['evidence'][0]['judgments'], ['botnet'])
            self.assertEqual(pq.ParquetFile(root / filename).num_row_groups, 2)

    def test_l3_consecutive_failure_resets(self):
        llm = LLMClient({'max_concurrency': 1, 'max_consecutive_failures': 2})
        rows = [{'session_id': str(i), 'event_id': str(i), 'batch_id': 'b'} for i in range(5)]
        good = {'verdict': 'unknown', 'confidence': 0.1, 'recommended_action': 'review', 'reasoning': []}
        with patch.object(llm, 'ask_json', side_effect=[RuntimeError(), good, RuntimeError(), good, good]) as ask:
            self.assertEqual(len(semantic_judge(rows, llm)), 3)
            self.assertEqual(ask.call_count, 5)

    def test_l3_stop_collects_inflight_result(self):
        import threading
        llm = LLMClient({'max_concurrency': 2, 'max_consecutive_failures': 1})
        barrier = threading.Barrier(2)
        def reply(system, payload):
            barrier.wait(timeout=3)
            if payload['session']['session_id'] == '0':
                raise RuntimeError('failed')
            return {'verdict': 'unknown', 'confidence': 0.1, 'recommended_action': 'review', 'reasoning': []}
        rows = [{'session_id': str(i), 'event_id': str(i), 'batch_id': 'b'} for i in range(6)]
        with patch.object(llm, 'ask_json', side_effect=reply) as ask:
            result = semantic_judge(rows, llm)
            self.assertTrue(any(row['session_id'] == '1' for row in result))
            self.assertLessEqual(ask.call_count, 3)

    def test_streamed_details_and_nested_attack_output(self):
        import pyarrow.parquet as pq
        with test_workspace() as root:
            (root / 'm1').mkdir()
            (root / 'm1/config.json').write_text(json.dumps({'output': {'format': 'parquet', 'batch_size': 1}}))
            (root / 'alerts.csv').write_text('Source IP,URL,Payload\n10.0.0.1,/a,id=1 or 1=1\n10.0.0.2,/b,test\n')
            manifest = root / 'manifest.json'
            manifest.write_text(json.dumps({'task_id': 'nested', 'input_files': ['alerts.csv']}))
            ready = process(root, manifest)
            details = pq.read_table(ready / 'event_details.parquet').to_pylist()
            sessions = pq.read_table(ready / 'all_sessions.parquet').to_pylist()
            self.assertEqual(len(details), 2)
            self.assertEqual(details[0]['request_body'], 'id=1 or 1=1')
            self.assertNotIn('request_body', sessions[0])
            self.assertEqual({row['event_id'] for row in details}, {row['event_id'] for row in sessions})
            suspicious = pq.read_table(ready / 'suspicious_events.parquet').to_pylist()
            self.assertIn('sql_injection', suspicious[0]['rule_hits'])
            self.assertEqual(pq.ParquetFile(ready / 'event_details.parquet').num_row_groups, 2)

    def test_ambiguous_address_and_protocol_values(self):
        row = {"address": "10.0.0.1", "transport": "TCP", "clientCount": 42}
        plan, _ = mapping_for(list(row), schema_profile([row]))
        self.assertEqual(plan, {"transport": "protocol"})
        row["otherTransport"] = "UDP"
        self.assertNotIn("protocol", mapping_for(list(row), schema_profile([row]))[0].values())

    def test_mapping_cache_ignores_counts_order_nulls_but_checks_types(self):
        with test_workspace() as root:
            llm = LLMClient({"enabled": True, "model": "fake", "api_key": "test"})
            row = {"address": "10.0.0.1", "transport": "TCP"}
            with patch.object(llm, "ask_json", return_value={"mapping": [{"source": "address", "target": "dst_ip", "confidence": 0.9}]}) as ask:
                first = get_mapping_plan(Path(root), list(row), "csv", schema_profile([row] * 100), llm)
                second = get_mapping_plan(Path(root), list(reversed(row)), "csv", schema_profile([row] * 200 + [dict.fromkeys(row)]), llm)
                self.assertTrue(second[1])
                self.assertEqual(first[0], second[0])
                self.assertEqual(ask.call_count, 1)
                payload = ask.call_args.args[1]
                self.assertLessEqual(len(payload["unresolved_fields"]["address"]["samples"]), 3)
                changed = {"address": "not an IP", "transport": "TCP"}
                self.assertFalse(get_mapping_plan(Path(root), list(row), "csv", schema_profile([changed]), llm)[1])

    def test_independent_mapping_model_and_programmatic_full_scan(self):
        with test_workspace() as root_text:
            root = Path(root_text)
            (root / "m1").mkdir()
            (root / "incoming").mkdir()
            (root / "m1/config.json").write_text(json.dumps({"mapping_llm": {"enabled": True, "model": "small-mapper", "api_key": "test"}, "llm": {"enabled": False}}))
            (root / "incoming/data.csv").write_text("mystery,URL\n" + "10.0.0.1,/index\n" * 10001)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"task_id": "mapping-test", "input_files": ["incoming/data.csv"], "options": {"profile_sample_size": 10000}}))
            with patch.object(LLMClient, "ask_json", return_value={"mapping": [{"source": "mystery", "target": "src_ip", "confidence": 0.95}]}) as ask:
                ready = process(root, manifest)
                self.assertEqual(ask.call_count, 1)
                ready = process(root, manifest)
                self.assertEqual(ask.call_count, 1)
            status = json.loads((ready / "status.json").read_text())
            batch = json.loads((ready / "batch.json").read_text())
            self.assertEqual(status["metrics"]["input_records"], 10001)
            self.assertEqual(status["llm_mapping_calls"], 0)
            self.assertEqual(batch["mapping_plans"]["incoming/data.csv"]["sample_size_used"], 500)
            self.assertTrue(batch["mapping_plans"]["incoming/data.csv"]["reused"])

    def test_schema_mapping_uses_sample_types_before_llm(self):
        rows = [{"EventTime": "2026-01-01T00:00:00+00:00", "clientAddress": "10.0.0.2", "serverAddress": "10.0.0.8", "payloadText": "x"}]
        profile = schema_profile(rows)
        plan, decisions = mapping_for(list(rows[0]), profile)
        self.assertEqual(plan["EventTime"], "timestamp")
        self.assertEqual(plan["clientAddress"], "src_ip")
        self.assertEqual(plan["serverAddress"], "dst_ip")
        self.assertTrue(all(item["source_type"].startswith("rule") for item in decisions))

    def test_competition_ground_truth_column_never_enters_mapping_or_model(self):
        label_header = "attack_type(结果列，需参赛选手判断输出)"
        row = {
            "timestamp": "2025-10-20 02:47:34", "user_agent": "browser", "method": "GET",
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "url_path": "/profile",
            "request_body": "title=hello", label_header: "正常访问",
        }
        profile = schema_profile([row])
        self.assertNotIn(label_header, profile["fields"])
        plan, _ = mapping_for(list(row), profile)
        self.assertNotIn(label_header, plan)
        self.assertNotIn("attack_type", plan.values())

        with test_workspace() as root:
            llm = LLMClient({"enabled": True, "model": "fake", "api_key": "test"})
            with patch.object(llm, "ask_json", side_effect=AssertionError("label or mapping prompt leaked")):
                frozen, _, _, _ = get_mapping_plan(Path(root), list(row), "xlsx", profile, llm)
            self.assertNotIn(label_header, frozen)
            parsed = normalized(row, {**frozen, label_header: "attack_type"}, "b", "f", 1)
            self.assertNotIn("attack_type", parsed)

    def test_attack_campaign_groups_source_activity_and_marks_scan(self):
        events = [
            {"session_id": "a", "event_id": "a", "src_ip": "10.0.0.2", "dst_ip": "10.0.0.8", "timestamp": "2026-01-01T00:00:00+00:00", "url_path": "/one", "rule_hits": ["scanner"], "risk_score": 45, "event_count": 1},
            {"session_id": "b", "event_id": "b", "src_ip": "10.0.0.2", "dst_ip": "10.0.0.9", "timestamp": "2026-01-01T00:05:00+00:00", "url_path": "/two", "rule_hits": ["scanner"], "risk_score": 45, "event_count": 1},
            {"session_id": "c", "event_id": "c", "src_ip": "10.0.0.2", "dst_ip": "10.0.0.9", "timestamp": "2026-01-01T00:10:00+00:00", "url_path": "/three", "rule_hits": ["scanner"], "risk_score": 45, "event_count": 1},
        ]
        campaigns = build_attack_campaigns(events, 86400, 3)
        self.assertEqual(len(campaigns), 2)
        self.assertTrue(all(row['target_count'] == 1 for row in campaigns))
        self.assertTrue(all('multi_path_scan' not in row['behavior_tags'] for row in campaigns))

    def test_extended_web_attack_rules(self):
        config = {"ioc_ips": [], "ioc_domains": [], "ioc_urls": []}
        cases = {
            "java_deserialization": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",
            "file_inclusion": "page=phar://malicious/shell.php",
            "command_injection": "domain=test.com&$(whoami)",
            "file_upload": "Content-Disposition: form-data; name=file; filename=shell.php",
        }
        for rule, body in cases.items():
            event = {"src_ip": "10.0.0.2", "domain": None, "url_path": "/api/transfer", "request_body": body, "message": "", "user_agent": ""}
            self.assertIn(rule, enrich(event, config)["rule_hits"])

    def test_dedup_uses_time_bucket(self):
        base = {"fingerprint": "same", "timestamp": "2026-01-01T00:00:10+00:00"}
        later = {"fingerprint": "same", "timestamp": "2026-01-01T00:02:10+00:00"}
        self.assertNotEqual(dedup_key(base, 60), dedup_key(later, 60))

    def test_threatbook_evidence_is_added_for_malicious_ip(self):
        class FakeThreatBook:
            def lookup_ip(self, value):
                return {"matched": value == "8.8.8.8", "judgments": ["botnet"], "severity": "high", "threat_type": "botnet"}
        event = {"src_ip": "8.8.8.8", "domain": None, "url_path": "/", "request_body": "", "message": "", "user_agent": ""}
        result = enrich(event, {"ioc_ips": [], "ioc_domains": [], "ioc_urls": []}, FakeThreatBook())
        self.assertIn("ioc_match", result["rule_hits"])
        self.assertEqual(result["evidence"][-1]["source"], "threatbook")

    def test_threatbook_response_requires_explicit_malicious_verdict(self):
        benign = ThreatBookClient._verdict({"data": {"is_malicious": False, "judgments": ["unknown"]}})
        malicious = ThreatBookClient._verdict({"data": {"is_malicious": True, "judgments": ["botnet"]}})
        self.assertFalse(benign["matched"])
        self.assertTrue(malicious["matched"])

    def test_manual_ioc_config_without_download(self):
        from m1.run import load_config
        with test_workspace() as root:
            (root / "m1").mkdir()
            (root / "m1/config.json").write_text(json.dumps({"ioc_ips": ["203.0.113.10"]}))
            loaded = load_config(root)
            with patch("m1.run.urlopen", side_effect=AssertionError("unexpected network request")):
                event = enrich({"src_ip": "203.0.113.10"}, loaded)
            self.assertIn("ioc_match", event["rule_hits"])
            self.assertEqual(event["ioc_matches"][0]["source"], "configured")

    def test_csv_dedup_rule_and_session(self):
        root = Path(__file__).parent / ".test-workspaces" / str(uuid4())
        try:
            (root / "incoming").mkdir(parents=True); (root / "manifests").mkdir()
            (root / "incoming" / "alerts.csv").write_text(
                "Time,Source IP,Destination,Method,URL,Payload\n"
                "2026-01-01T00:00:00+00:00,10.0.0.2,10.0.0.8,GET,/x?q=1%20or%201=1,\n"
                "2026-01-01T00:00:01+00:00,10.0.0.2,10.0.0.8,GET,/x?q=1%20or%201=1,\n", encoding="utf-8")
            manifest = root / "manifests" / "t.json"
            manifest.write_text(json.dumps({"task_id": "t", "batch_id": "b", "input_files": ["incoming/alerts.csv"]}), encoding="utf-8")
            ready = process(root, manifest)
            events = [json.loads(line) for line in (ready / "suspicious_events.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(events), 1)
            self.assertIn("sql_injection", events[0]["rule_hits"])
            self.assertEqual(events[0]["risk_level"], "high")
            self.assertTrue((ready / "all_sessions.jsonl").exists())
            self.assertNotIn("request_body", events[0])
            details = [json.loads(line) for line in (ready / "event_details.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(details[0]["request_body"], "")
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_xlsx_workbook_is_ingested(self):
        from openpyxl import Workbook
        root = Path(__file__).parent / ".test-workspaces" / str(uuid4())
        try:
            (root / "incoming").mkdir(parents=True); (root / "manifests").mkdir()
            workbook = Workbook()
            sheet = workbook.active
            sheet.title = "alerts"
            sheet.append(["时间", "源IP", "目的IP", "请求体"])
            sheet.append(["2026-01-01T00:00:00+00:00", "10.0.0.2", "10.0.0.8", "id=1 or 1=1"])
            workbook.create_sheet("empty")
            workbook.save(root / "incoming" / "alerts.xlsx")
            manifest = root / "manifests" / "t.json"
            manifest.write_text(json.dumps({"task_id": "t", "batch_id": "b", "input_files": ["incoming/alerts.xlsx"]}), encoding="utf-8")
            ready = process(root, manifest)
            events = [json.loads(line) for line in (ready / "suspicious_events.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(events), 1)
            self.assertIn("sql_injection", events[0]["rule_hits"])
            batch = json.loads((ready / "batch.json").read_text(encoding="utf-8"))
            self.assertEqual(batch["mapping_plans"]["incoming/alerts.xlsx"]["format"], "xlsx")
            self.assertTrue((ready / "mapping_plans").is_dir())
            self.assertTrue(list((ready / "mapping_plans").glob("*.json")))
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__": unittest.main()
