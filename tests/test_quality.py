import csv
import unittest
from pathlib import Path
from unittest.mock import patch
from tests.test_m1 import test_workspace
from m1.quality import review_groups, sample, evaluate
from m1.run import l3_candidates
from m1.similarity import payload_features, session_features, clusters
from collections import Counter


class QualityTest(unittest.TestCase):
    def rows(self):
        return [dict(session_id=str(i), rule_hits=['xss'], protocol='HTTP',method='GET',url_path='/users/'+str(i),
            dst_ip='10.0.0.'+str(i),src_ip='10.1.0.1',risk_score=65,risk_level='medium',event_count=1) for i in range(5)]

    def test_groups_conserve_members_and_do_not_assert_identity(self):
        rows = self.rows()
        for row in rows: row['_payload']=payload_features({'request_body':'<script>alert(1)</script>'})
        groups = review_groups(rows)
        self.assertEqual(len(groups),1)
        self.assertEqual(groups[0]['session_count'],5)
        self.assertEqual(groups[0]['target_count'],5)
        self.assertEqual(groups[0]['correlation_status'],'review_pattern_only')
        self.assertEqual(set(groups[0]['related_session_ids']),{r['session_id'] for r in rows})
        rows[0]['ioc_matches']=[{'type':'ip','value':'203.0.113.1'}]
        self.assertEqual(len(review_groups(rows)),2)

    def test_l3_pattern_diversity_and_cap(self):
        rows=self.rows()
        rows.append(dict(rows[0],session_id='other',url_path='/different'))
        selected=l3_candidates(rows,200,{'enable_l3_semantic_judge':True,'l3_max_ratio':0.01})
        self.assertEqual(len(selected),2)
        self.assertIn('other',[r['session_id'] for r in selected])
        self.assertEqual(l3_candidates(rows,99,{'enable_l3_semantic_judge':True}),[])

    def test_sampling_labels_and_validation(self):
        rows=self.rows()
        def read(directory,batch,name): return iter(rows[:2] if name=='suspicious_events' else rows)
        with test_workspace() as root, patch('m1.quality.read_batch',return_value={'consumption_key':'b:r'}), patch('m1.quality.read_rows',side_effect=read):
            file=root/'labels.csv'
            report=sample(root,file,100)
            self.assertEqual(report['sampled'],5)
            self.assertIsNone(evaluate(root,file)['accuracy'])
            with file.open(encoding='utf-8-sig',newline='') as stream:
                data=list(csv.DictReader(stream))
            for row in data: row['label']='malicious' if row['session_id'] in ('0','2') else 'benign'
            with file.open('w',encoding='utf-8-sig',newline='') as stream:
                writer=csv.DictWriter(stream,fieldnames=data[0].keys()); writer.writeheader();writer.writerows(data)
            result=evaluate(root,file)
            self.assertEqual(result['confusion'],{'TP':1,'FP':1,'TN':2,'FN':1})
            self.assertEqual(result['recall'],0.5)
            with self.assertRaises(FileExistsError): sample(root,file)
