import json
import unittest
from unittest.mock import patch
from tests.test_m1 import test_workspace
from m1.run import process
from m1.handoff import read_batch, iter_suspicious


class HandoffTest(unittest.TestCase):
    def prepare(self, root, empty=False):
        (root / 'm1').mkdir(exist_ok=True)
        (root / 'm1/config.json').write_text(json.dumps({'output': {'format': 'parquet', 'batch_size': 1}, 'ioc_ips': ['10.0.0.2'], 'asset_ids': {'10.0.0.2': 'asset-2'}, 'shared_egress_ips': ['10.0.0.1'], 'ml_detector': {'enabled': False}}))
        (root / 'data.csv').write_text('Time,Source IP,Destination,URL,Payload\n' + ('' if empty else '2026-01-01T00:00:00Z,10.0.0.1,10.0.0.2,https://a.example/x,id=1 or 1=1\n2026-01-01T00:01:00Z,10.0.0.1,10.0.0.2,https://b.example/y,test\n'))
        manifest = root / 'manifest.json'
        manifest.write_text(json.dumps({'task_id': 't', 'batch_id': 'b', 'input_files': ['data.csv']}))
        return manifest

    def test_published_batch_rerun_and_contract(self):
        with test_workspace() as root:
            manifest = self.prepare(root)
            first = process(root, manifest)
            old = (first / 'batch.json').read_bytes()
            second = process(root, manifest)
            self.assertNotEqual(first, second)
            self.assertEqual((first / 'batch.json').read_bytes(), old)
            batch = read_batch(second)
            rows = list(iter_suspicious(second))
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row['event_count'], 2)
            self.assertLess(row['first_seen'], row['last_seen'])
            self.assertEqual(row['victim_asset_id'], 'asset-2')
            self.assertEqual(row['domains'], ['a.example', 'b.example'])
            self.assertEqual(row['semantic_status'], 'disabled')
            self.assertTrue(row['source_identity_shared'])
            self.assertEqual(row['ioc_matches'][0]['matched_field'], 'dst_ip')
            self.assertEqual(row['session_fingerprint'], list(iter_suspicious(first))[0]['session_fingerprint'])
            self.assertNotEqual(batch['consumption_key'], read_batch(first)['consumption_key'])
            with (second / batch['artifacts']['suspicious_events']).open('ab') as stream:
                stream.write(b'corrupt')
            with self.assertRaises(Exception): read_batch(second)

    def test_empty_batch_and_failed_publication(self):
        with test_workspace() as root:
            manifest = self.prepare(root, empty=True)
            ready = process(root, manifest)
            self.assertEqual(list(iter_suspicious(ready)), [])
            before = list((root / 'm1/ready/b').iterdir())
            with patch('m1.run.write_events', side_effect=RuntimeError('simulated failure')):
                with self.assertRaises(RuntimeError): process(root, manifest)
            self.assertEqual(list((root / 'm1/ready/b').iterdir()), before)
            self.assertEqual(read_batch(ready)['artifact_metadata']['suspicious_events']['rows'], 0)


if __name__ == '__main__': unittest.main()
