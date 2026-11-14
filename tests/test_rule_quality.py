import unittest
from datetime import datetime, timezone, timedelta
from m1.run import enrich, apply_contextual_scores, build_attack_campaigns, l3_candidates, build_activity_groups, LLMClient, L3_PROMPT_VERSION
from unittest.mock import patch
from urllib.error import HTTPError


class RuleQualityTest(unittest.TestCase):
    def test_retry_is_bounded_and_only_transient(self):
        client = LLMClient({})
        def fail(cause):
            error = RuntimeError('request failed')
            error.__cause__ = cause
            return error
        with patch.object(client, '_ask_once', side_effect=[fail(TimeoutError()), {'ok': True}]) as request, patch('m1.run.time.sleep'):
            self.assertEqual(client.ask_json('', {'prompt_version': L3_PROMPT_VERSION}), {'ok': True})
            self.assertEqual(request.call_count, 2)
        for cause in (HTTPError('https://test', 401, 'denied', {}, None), TimeoutError()):
            with patch.object(client, '_ask_once', side_effect=fail(cause)) as request, patch('m1.run.time.sleep'):
                with self.assertRaises(RuntimeError): client.ask_json('', {'prompt_version': L3_PROMPT_VERSION})
                self.assertEqual(request.call_count, 1 if isinstance(cause, HTTPError) else 2)
        with patch.object(client, '_ask_once', side_effect=fail(TimeoutError())) as request:
            with self.assertRaises(RuntimeError): client.ask_json('', {'prompt_version': 'mapping'})
            self.assertEqual(request.call_count, 1)

    def test_activity_groups_keep_victim_and_domain_boundaries(self):
        base = {'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2', 'protocol': 'HTTP', 'domain': 'a.example', 'rule_hits': ['sql_injection'], 'timestamp': '2026-01-01T00:01:00+00:00', 'first_seen': '2026-01-01T00:01:00+00:00', 'last_seen': '2026-01-01T00:01:00+00:00', 'event_count': 1, 'risk_score': 85}
        rows = [dict(base, session_id='a', url_path='/users/123?q=1'), dict(base, session_id='b', url_path='/users/456?q=2'), dict(base, session_id='c', url_path='/users/789', domain='b.example')]
        groups = build_activity_groups(rows)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]['related_session_ids'], ['a', 'b'])
        self.assertEqual(groups[0]['route_template'], '/users/{id}')
    def test_l1_false_positive_and_evasion_cases(self):
        config = {'ioc_ips': [], 'ioc_domains': [], 'ioc_urls': []}
        cases = [
            ({'request_body': 'help -- verbose'}, 'sql_injection', False),
            ({'request_body': 'id=1 or 1=1'}, 'sql_injection', True),
            ({'request_body': r'..\windows\win.ini'}, 'path_traversal', True),
            ({'request_body': '%2e%2e%5cwindows'}, 'path_traversal', True),
            ({'request_body': 'a'*21000, 'user_agent': 'sqlmap'}, 'scanner', True),
            ({'method': 'POST', 'url_path': '/transfer', 'request_body': 'amount=100&to=alice&csrf_token=valid'}, 'csrf', False),
            ({'method': 'POST', 'url_path': '/transfer', 'request_body': 'amount=100&to=alice'}, 'csrf', False),
            ({'method': 'POST', 'request_body': 'csrf_token=none'}, 'csrf', True),
        ]
        for event, rule, expected in cases:
            with self.subTest(rule=rule, event=repr(event)[:100]):
                self.assertEqual(rule in enrich(event, config)['rule_hits'], expected)

    def sessions(self, seconds):
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        return [{'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2', 'timestamp': (start + timedelta(seconds=i*seconds)).isoformat(), 'risk_score': 15, 'score_components': {}} for i in range(10)]

    def test_activity_window_and_shared_egress(self):
        separated = apply_contextual_scores(self.sessions(86400), {})
        self.assertTrue(all(row['score_components']['source_activity'] == 0 for row in separated))
        burst = apply_contextual_scores([dict(row, rule_hits=['scanner']) for row in self.sessions(1)], {})
        self.assertEqual(burst[-1]['source_session_count'], 10)
        self.assertEqual(burst[-1]['score_components']['source_activity'], 10)
        shared = apply_contextual_scores([dict(row, rule_hits=['scanner']) for row in self.sessions(1)], {'shared_egress_ips': ['10.0.0.1']})
        self.assertEqual(shared[-1]['score_components']['source_activity'], 2)

    def test_campaign_uses_session_path_set_and_end(self):
        event = dict(self.sessions(1)[0], session_id='s', paths=['/a','/b','/c','/d','/e'], paths_count=5, last_seen='2026-01-01T00:04:00+00:00', rule_hits=['scanner'])
        result = build_attack_campaigns([event], 86400, 5)[0]
        self.assertEqual(result['unique_path_count'], 5)
        self.assertNotIn('multi_path_scan', result['behavior_tags'])
        self.assertEqual(result['ended_at'], event['last_seen'])

    def test_candidate_budget_and_diversity(self):
        rows = [{'session_id': str(i), 'risk_level': 'high', 'risk_score': 100, 'rule_hits': ['sql_injection']} for i in range(20)]
        rows.append({'session_id': 'x', 'risk_level': 'medium', 'risk_score': 65, 'rule_hits': ['xss']})
        selected = l3_candidates(rows, 400, {'enable_l3_semantic_judge': True})
        self.assertEqual(len(selected), 4)
        self.assertIn('x', [row['session_id'] for row in selected])
        self.assertEqual(len({row['session_id'] for row in selected}), 4)
