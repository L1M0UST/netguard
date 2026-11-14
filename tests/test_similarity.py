import unittest
from collections import Counter
from m1.similarity import payload_features, session_features, clusters
from m1.quality import review_groups
from m1.run import l3_candidates, lightweight_record


class SimilarityTest(unittest.TestCase):
    def row(self, i, payload, url='/login'):
        return dict(session_id=str(i),request_body=payload,url_path=url,rule_hits=['sql_injection'],
            risk_score=85,risk_level='high',event_count=1,src_ip='a',dst_ip='b',
            _payload=payload_features({'request_body':payload,'url_path':url}))

    def test_query_and_payload_semantics_remain_distinct(self):
        rows=[self.row(1,'', '/login?q=1%20or%201=1'),self.row(2,'','/login?q=normal')]
        self.assertEqual(len(review_groups(rows)),2)
        rows=[self.row(1,'x=1 or 1=1'),self.row(2,'x=1 or 1=0')]
        self.assertEqual(len(review_groups(rows)),2)
        self.assertNotIn('_payload',lightweight_record(rows[0]))

    def test_whitespace_and_missing_evidence(self):
        rows=[self.row(1,'a = 1'),self.row(2,'a  =  1')]
        self.assertEqual(len(review_groups(rows)),1)
        for row in rows:row.pop('_payload')
        self.assertEqual(len(review_groups(rows)),2)

    def test_long_and_mixed_payloads_use_full_digests(self):
        a,b=self.row(1,'a'*5000+'x'),self.row(2,'a'*5000+'y')
        self.assertFalse(a['_payload']['approximate'])
        self.assertEqual(len(review_groups([a,b])),2)
        mixed=session_features([a,b])
        self.assertFalse(mixed['approximate'])
        self.assertNotEqual(mixed['digest'],a['_payload']['digest'])

    def test_lsh_is_verified_and_comparisons_bounded(self):
        rows=[self.row(i,str(i)) for i in range(100)]
        for i,row in enumerate(rows):
            row['_payload'].update(tokens=frozenset(range(i*10,i*10+10)),signature=1,approximate=True)
        stats=Counter()
        self.assertEqual(len(clusters(rows,stats)),100)
        self.assertLessEqual(stats['candidate_comparisons'],100*64)
        rows=rows[:2]
        rows[0]['_payload']['tokens']=frozenset(range(100))
        rows[1]['_payload']['tokens']=frozenset(range(99))
        stats=Counter()
        self.assertEqual(len(clusters(rows,stats)),1)
        self.assertEqual(stats['approximate_assignments'],1)

    def test_l3_uses_payload_groups(self):
        rows=[self.row(1,'x=1 or 1=1'),self.row(2,'x=1 or 1=1'),self.row(3,'union select password from users')]
        review_groups(rows)
        selected=l3_candidates(rows,200,{'enable_l3_semantic_judge':True,'l3_max_ratio':.01})
        self.assertEqual(len({r['review_group_id'] for r in selected}),2)
