import csv
import json
from pathlib import Path
import tempfile
import unittest

from tools.catalog import ROOT
from tools.compare_iris import path_delta,summarize
from tools.review_labels import analyze


class ImprovementTests(unittest.TestCase):
    def test_path_narrowing_does_not_assume_subset_or_improvement(self):
        delta=path_delta(['a.java','b.java'],['b.java','c.java','d.java'])
        self.assertEqual(delta['removed_paths'],['a.java'])
        self.assertEqual(delta['added_paths'],['c.java','d.java'])
        row=dict(eligible=True,original_count=2,normalized_count=3,iris_annotated_paths=[],missing_iris_annotated_paths=[],context_files=[],**delta)
        self.assertEqual(summarize([row])['reduction_percent'],-50)

    def test_saved_comparison_preserves_annotations_and_flags_context_loss(self):
        r=json.loads((ROOT/'data/iris-comparison.json').read_text())
        self.assertEqual(r['primary'],summarize([c for c in r['cases'] if c['batch']=='pilot']))
        self.assertEqual(r['expanded'],summarize(r['cases']))
        self.assertEqual((r['primary']['cves'],r['primary']['original_paths'],r['primary']['normalized_paths']),(9,60,33))
        self.assertEqual((r['expanded']['cves'],r['expanded']['original_paths'],r['expanded']['normalized_paths']),(10,62,35))
        self.assertEqual(r['expanded']['missing_iris_annotated_paths'],0)
        c=next(c for c in r['cases'] if c['cve_id']=='CVE-2019-10392')
        context=c['context_files'][0]
        self.assertIn(context['path'],c['removed_paths'])
        self.assertEqual(context['before_blob'],context['after_blob'])
        self.assertEqual(context['matching_issue_ids'],['SECURITY-1534'])

    def forms(self,path,rows):
        fields=['review_id','sample_id','reviewer_decision','reviewer_name','review_date','reason','evidence_checked','review_status']
        with path.open('w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)

    def test_blank_review_has_no_agreement_percentage(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'form.csv';self.forms(p,[dict(review_id='R1',sample_id='s1',review_status='PENDING')])
            r=analyze({'samples':[dict(review_id='R1',sample_id='s1',baseline_ai_label='UNCONFIRMED')]},[p])
            self.assertEqual(r['status'],'PENDING');self.assertIsNone(r['agreement_rate'])

    def test_review_agreement_disagreement_and_duplicate_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'form.csv'
            rows=[dict(review_id='R'+str(i),sample_id='s'+str(i),reviewer_decision=decision,reviewer_name='Reviewer A',review_date='2026-11-25',reason='Scoped code inspection',evidence_checked='source',review_status='COMPLETED') for i,decision in [(1,'VULNERABLE'),(2,'UNCONFIRMED')]]
            self.forms(p,rows);copy=Path(tmp)/'copy.csv';copy.write_bytes(p.read_bytes())
            ref={'samples':[dict(review_id='R'+str(i),sample_id='s'+str(i),baseline_ai_label='VULNERABLE') for i in [1,2]]}
            r=analyze(ref,[p,copy]);self.assertEqual(r['valid_samples'],2);self.assertEqual(r['agreement_rate'],0.5)
            self.assertEqual(r['disagreement_count'],1)

    def test_ai_or_unfinished_form_is_not_human_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'form.csv';self.forms(p,[dict(review_id='R1',sample_id='s1',reviewer_decision='VULNERABLE',reviewer_name='AI',review_date='2026-11-25',reason='r',evidence_checked='e',review_status='COMPLETED')])
            r=analyze({'samples':[dict(review_id='R1',sample_id='s1',baseline_ai_label='VULNERABLE')]},[p])
            self.assertEqual(r['valid_samples'],0);self.assertIsNone(r['agreement_rate'])
