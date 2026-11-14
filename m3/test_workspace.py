import json
import hashlib
import tempfile
import unittest
from pathlib import Path
from workspace_io import Workspace, atomic_json
from demo_bundle import produce

class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.ws=Workspace(self.root)

    def test_atomic_task_with_checksum(self):
        (self.root/'input').write_bytes(b'test')
        manifest=self.ws.publish({'task_id':'task-1','created_at':'2026-09-17','query':''},[{'file_id':'input','sha256':hashlib.sha256(b'test').hexdigest()}],self.root)
        self.assertTrue((self.root/'m3/READY/task-1/manifest.json').exists())
        self.assertFalse((self.root/'m3/STAGING/task-1').exists())
        self.assertEqual(manifest['schema_version'],'TaskManifest.v1')

    def test_tampered_bundle_rejected(self):
        produce(self.root,'task-1')
        self.assertEqual(self.ws.read_bundle('task-1')['task_id'],'task-1')
        (self.root/'m2/READY/task-1/bundle.json').write_text('{}')
        with self.assertRaisesRegex(ValueError,'checksum'):
            self.ws.read_bundle('task-1')

    def test_missing_evidence_rejected(self):
        produce(self.root,'task-1')
        directory=self.root/'m2/READY/task-1'
        bundle=json.loads((directory/'bundle.json').read_text(encoding='utf-8'))
        bundle['evidence']=[]
        atomic_json(directory/'bundle.json',bundle)
        atomic_json(directory/'manifest.json',{'task_id':'task-1','schema_version':'ResultManifest.v1','sha256':hashlib.sha256((directory/'bundle.json').read_bytes()).hexdigest()})
        with self.assertRaises(ValueError):
            self.ws.read_bundle('task-1')

    def test_staging_invisible_and_path_rejected(self):
        (self.root/'m2/STAGING/task-1').mkdir(parents=True)
        self.assertIsNone(self.ws.read_bundle('task-1'))
        with self.assertRaises(ValueError):
            self.ws.read_bundle('../escape')

if __name__=='__main__':
    unittest.main()
