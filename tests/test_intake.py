import json
import unittest
from tests.test_m1 import test_workspace
from m1.intake import scan


class IntakeTest(unittest.TestCase):
    def test_stability_idempotency_and_numbering(self):
        with test_workspace() as root:
            (root/'incoming').mkdir()
            source=root/'incoming/web_alerts.xlsx'
            source.write_bytes(b'example')
            first,created=scan(root,{})
            self.assertEqual(created,[])
            _,created=scan(root,first)
            self.assertEqual(created[0].name,'excel-001.json')
            task=json.loads(created[0].read_text(encoding='utf-8'))
            self.assertEqual(task['input_files'],['incoming/web_alerts.xlsx'])
            self.assertEqual(scan(root,first)[1],[])
            second=root/'incoming/another.xlsx'
            second.write_bytes(b'example2')
            state,_=scan(root,{})
            second.write_bytes(b'changed-more-data')
            state,created=scan(root,state)
            self.assertEqual(created,[])
            _,created=scan(root,state)
            self.assertEqual(created[0].name,'excel-002.json')

    def test_ignores_temporary_and_empty_files(self):
        with test_workspace() as root:
            (root/'incoming').mkdir()
            for name,data in [('~$sheet.xlsx',b'x'),('sheet.xlsx.part',b'x'),('empty.csv',b'')]:
                (root/'incoming'/name).write_bytes(data)
            state,_=scan(root,{})
            self.assertEqual(scan(root,state)[1],[])
