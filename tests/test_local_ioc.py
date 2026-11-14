import io
import sqlite3
import unittest
from contextlib import closing
from unittest.mock import patch

from m1.local_ioc import LocalIOC, parse_feed, update
from m1.run import enrich, process
from m1.handoff import iter_suspicious
from tests.test_m1 import test_workspace


class LocalIOCTest(unittest.TestCase):
    def refresh(self, root):
        responses = []
        for body in (b'{"cidr":"10.0.0.0/24"}\n{"timestamp":1}',
                     b'{"cidr":"2001:db8::/32"}', b'https://phish.example/login\n'):
            response = io.BytesIO(body)
            response.headers = {}
            responses.append(response)
        with patch('m1.local_ioc.urlopen', side_effect=responses):
            return update(root)

    def test_validation(self):
        self.assertEqual(parse_feed('{"cidr":"10.0.0.0/24"}\n{"timestamp":1}', 'cidr'), ['10.0.0.0/24'])
        for text, kind in [('<html>unavailable</html>', 'url'), ('{"cidr":"invalid"}', 'cidr'), ('', 'url')]:
            with self.assertRaises(ValueError): parse_feed(text, kind)

    def test_index_expiry_and_failed_refresh(self):
        with test_workspace() as root:
            self.refresh(root)
            local = LocalIOC(root)
            self.assertEqual(local.count, 3)
            matches = local.match({'src_ip': '10.0.0.255', 'dst_ip': '2001:db8::1', 'url_path': 'https://phish.example/login'})
            self.assertEqual(len(matches), 3)
            self.assertEqual(local.match({'src_ip': '10.0.1.0', 'url_path': 'https://phish.example/other'}), [])
            event = enrich({'src_ip': '10.0.0.2'}, {'_local_ioc': local})
            self.assertIn('ioc_match', event['rule_hits'])
            self.assertEqual(event['ioc_matches'][0]['source'], 'spamhaus_drop_v4')
            with patch('m1.local_ioc.urlopen', side_effect=TimeoutError):
                report = update(root)
            self.assertTrue(all(s['status'] == 'failed_kept_previous' for s in report['sources']))
            self.assertEqual(LocalIOC(root).count, 3)
            with closing(sqlite3.connect(root / 'm1/local_ioc/ioc.sqlite3')) as conn:
                conn.execute("UPDATE indicators SET expires_at='2000-01-01T00:00:00+00:00'")
                conn.commit()
            expired = LocalIOC(root)
            self.assertEqual((expired.count, expired.expired), (0, 3))
            self.assertEqual(expired.match({'src_ip': '10.0.0.2'}), [])

    def test_pipeline_parquet_provenance(self):
        import json
        from tests.test_handoff import HandoffTest
        with test_workspace() as root:
            manifest = HandoffTest().prepare(root)
            config_path = root / 'm1/config.json'
            config = json.loads(config_path.read_text())
            config['ioc_ips'] = []
            config['local_ioc'] = {'enabled': True}
            config_path.write_text(json.dumps(config))
            self.refresh(root)
            process(root, manifest)
            ready = next((root / 'm1/ready/b').glob('*/READY.json')).parent
            sessions = list(iter_suspicious(ready))
            self.assertTrue(sessions)
            for session in sessions:
                match = session['ioc_matches'][0]
                self.assertEqual(match['source'], 'spamhaus_drop_v4')
                self.assertTrue(match['fetched_at'])
                self.assertTrue(match['expires_at'])


if __name__ == '__main__':
    unittest.main()
