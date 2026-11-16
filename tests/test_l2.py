import json
import unittest
from datetime import datetime, timezone, timedelta
from tests.test_m1 import test_workspace
from m1.run import aggregate, apply_contextual_scores, build_activity_groups, build_attack_campaigns, is_suspicious, process, load_config
from m1.l2 import detect_scans
from m1.handoff import iter_suspicious


class L2Test(unittest.TestCase):
    def event(self, i, **changes):
        event = dict(event_id=str(i), src_ip='10.0.0.1', dst_ip='10.0.0.2', src_port=1000+i,
            dst_port=80, protocol='HTTP', domain='a.example', url_path='/products/'+str(i),
            timestamp=(datetime(2026,1,1,tzinfo=timezone.utc)+timedelta(seconds=i)).isoformat(),
            rule_hits=[], evidence=[], risk_score=15)
        event.update(changes)
        return event

    def sessions(self, rows, config=None):
        return apply_contextual_scores(aggregate(rows, 300, 3600), config or {})

    def test_scan_and_browsing_and_slow_probes(self):
        paths = ['/.env', '/.git/config', '/wp-admin', '/actuator/health', '/server-status']
        for step, expected in [(1, True), (120, False)]:
            rows = [self.event(i*step, url_path=path) for i, path in enumerate(paths)]
            detect_scans(rows, {})
            self.assertEqual(all('multi_path_scan' in row['rule_hits'] for row in rows), expected)
        rows = [self.event(i, url_path=path) for i, path in enumerate(['/home', '/about', '/contact', '/cart', '/help'])]
        detect_scans(rows, {})
        self.assertTrue(all(not row['rule_hits'] for row in rows))
        rows = [self.event(i, url_path='/.env' if i < 5 else '/.git/config') for i in range(10)]
        detect_scans(rows, {})
        self.assertTrue(all(not row['rule_hits'] for row in rows))

    def test_shared_exit_scan_does_not_pool_connections(self):
        rows = [self.event(i, url_path=path) for i, path in enumerate(['/.env', '/.git/config', '/wp-admin', '/actuator/health', '/server-status'])]
        detect_scans(rows, {'shared_egress_ips': ['10.0.0.1']})
        self.assertTrue(all(not row['rule_hits'] for row in rows))
        for row in rows: row['src_port'] = 9000
        detect_scans(rows, {'shared_egress_ips': ['10.0.0.1']})
        self.assertTrue(all('multi_path_scan' in row['rule_hits'] for row in rows))

    def test_normal_frequency_and_asset_not_attack(self):
        rows = [self.event(i, src_port=1000) for i in range(20)]
        sessions = self.sessions(rows, {'asset_risk': {'10.0.0.2':20}})
        self.assertFalse(is_suspicious(sessions[0], {}))
        self.assertEqual(sessions[0]['risk_score'], 15)
        sessions = self.sessions([self.event(i) for i in range(20)], {'asset_risk': {'10.0.0.2':20}})
        self.assertTrue(all(not is_suspicious(row,{}) for row in sessions))

    def test_session_cap_and_invalid_window(self):
        sessions = self.sessions([self.event(i*240, src_port=1000) for i in range(100)])
        self.assertGreater(len(sessions), 1)
        self.assertEqual(sum(s['event_count'] for s in sessions),100)
        for s in sessions:
            self.assertLess((datetime.fromisoformat(s['last_seen'])-datetime.fromisoformat(s['first_seen'])).total_seconds(),3600)
        with self.assertRaises(ValueError): aggregate([],0,3600)

    def test_time_boundaries_and_separation(self):
        for start, end in [(1799,1801),(86399,86401)]:
            sessions = self.sessions([self.event(start, rule_hits=['xss']),self.event(end,rule_hits=['xss','ioc_match'])])
            self.assertEqual(len(build_activity_groups(sessions,1800)),1)
            self.assertEqual(len(build_attack_campaigns(sessions,3600,5)),1)
        sessions = self.sessions([self.event(0,rule_hits=['xss']),self.event(3601,rule_hits=['xss'])])
        self.assertEqual(len(build_attack_campaigns(sessions,3600,5)),2)
        sessions = self.sessions([self.event(i,rule_hits=['xss']) for i in range(3)], {'shared_egress_ips':['10.0.0.1']})
        self.assertEqual(len(build_attack_campaigns(sessions,3600,5)),3)
        self.assertEqual(build_activity_groups(sessions,1800),[])
        sessions = self.sessions([self.event(0,rule_hits=['xss']),self.event(1,dst_ip='10.0.0.3',rule_hits=['xss']),self.event(2,protocol='TLS',rule_hits=['xss'])])
        self.assertEqual(len(build_attack_campaigns(sessions,3600,5)),3)

    def test_all_paths_and_overlap_counts(self):
        rows = [self.event(0,src_port=1,url_path='/unrelated',rule_hits=['xss']),
                self.event(1,src_port=1,rule_hits=['xss']),self.event(2,src_port=2,rule_hits=['sql_injection'])]
        groups = build_activity_groups(self.sessions(rows))
        self.assertEqual(len(groups),1)
        self.assertEqual(groups[0]['route_template'],'/products/{id}')
        self.assertEqual(groups[0]['session_count'],2)

    def test_pipeline_unsigned_scan_and_parquet_evidence(self):
        with test_workspace() as root:
            (root/'m1').mkdir(exist_ok=True)
            (root/'m1/config.json').write_text(json.dumps({'output':{'format':'parquet'},'enable_l3_semantic_judge':False,'ml_detector':{'enabled':False}}))
            rows = [self.event(i,url_path=path) for i,path in enumerate(['/.env','/.git/config','/wp-admin','/actuator/health','/server-status'])]
            (root/'data.json').write_text(json.dumps(rows))
            manifest = root/'manifest.json'
            manifest.write_text(json.dumps({'task_id':'scan','input_files':['data.json']}))
            ready = process(root,manifest)
            sessions = list(iter_suspicious(ready))
            self.assertEqual(len(sessions),5)
            self.assertTrue(all('multi_path_scan' in s['rule_hits'] for s in sessions))
            self.assertEqual(sessions[0]['evidence'][0]['window_seconds'],60)
            status = json.loads((ready/'status.json').read_text())
            self.assertEqual(status['llm_calls'],0)
            self.assertTrue(status['l2_policy']['behavior_detection_before_filter'])

    def test_legacy_window_alias(self):
        with test_workspace() as root:
            (root/'m1').mkdir(exist_ok=True)
            config = root/'m1/config.json'
            config.write_text(json.dumps({'campaign_window_seconds':123}))
            self.assertEqual(load_config(root)['attack_campaign_window_seconds'],123)
            config.write_text(json.dumps({'campaign_window_seconds':123,'attack_campaign_window_seconds':456}))
            self.assertEqual(load_config(root)['attack_campaign_window_seconds'],456)

