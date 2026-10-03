"""Validate scoring and the evaluation harness, not a tuned accuracy target."""
import json
from pathlib import Path
import tempfile
import unittest
from evaluation.run import metrics,load_dataset,run_stage,DATASET


class EvaluationTests(unittest.TestCase):
    def test_metrics_and_zero_denominators(self):
        result=metrics([(True,True),(True,False),(False,True),(False,False)])
        self.assertEqual([result[k] for k in ('TP','FP','TN','FN')],[1,1,1,1])
        self.assertEqual(result['precision'],.5);self.assertEqual(result['recall'],.5);self.assertEqual(result['f1'],.5)
        empty=metrics([])
        self.assertIsNone(empty['precision']);self.assertIsNone(empty['recall']);self.assertIsNone(empty['f1'])
        self.assertEqual(metrics([(True,False)])['f1'],0)
        self.assertIsNone(metrics([(False,False)])['precision'])

    def test_ground_truth_frozen_balanced_and_explicit(self):
        rows,digest=load_dataset()
        self.assertEqual(digest,'73c72c4db254ac9f52071915f5e8a56d111c7d0933ebc1e6ad363c4e25b3a2d1')
        self.assertEqual(len(rows),54)
        for category in {r['category'] for r in rows}:
            group=[r for r in rows if r['category']==category]
            self.assertEqual(sum(r['expected'] for r in group),3)
            self.assertEqual(sum(not r['expected'] for r in group),3)
            self.assertTrue(any(r['variant']=='protected' for r in group))
        self.assertTrue(all(r['ground_truth'] and r['future_improvement'] for r in rows))

    def test_dataset_rejects_traversal_duplicates_and_nonboolean_labels(self):
        base=json.loads(DATASET.read_text())
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'bad.json'
            for value in ('../outside.py','/absolute.py','a\\b.py'):
                data=json.loads(json.dumps(base));data['fixtures'][0]['path']=value;path.write_text(json.dumps(data))
                with self.assertRaises(ValueError):load_dataset(path)
            base['fixtures'][0]['expected']='true';path.write_text(json.dumps(base))
            with self.assertRaises(ValueError):load_dataset(path)

    def test_real_worker_isolated_nonexecution_cleanup_and_category_scoring(self):
        rows,_=load_dataset()
        selected=[dict(r) for r in rows if r['id'] in ('sql_concat','sql_bound')]
        with tempfile.TemporaryDirectory() as directory:
            marker=Path(directory)/'never-execute'
            selected[0]['source']='from pathlib import Path\nPath('+repr(str(marker))+').write_text("executed")\n'+selected[0]['source']
            result=run_stage(selected)
            self.assertFalse(marker.exists());self.assertTrue(result['valid_run']);self.assertTrue(result['archive_cleaned'])
            self.assertEqual(result['ai_reviews'],0)
            self.assertEqual([result['overall'][k] for k in ('TP','FP','TN','FN')],[1,0,1,0])
            self.assertEqual(result['unscored_findings'],[])

    def test_saved_results_recalculate_without_hiding_failures(self):
        artifact=DATASET.with_name('results.json')
        data=json.loads(artifact.read_text());rows,digest=load_dataset()
        self.assertEqual(data['dataset_sha256'],digest)
        for stage in data['stages']:
            self.assertEqual({c['id'] for c in stage['cases']},{r['id'] for r in rows})
            self.assertEqual(stage['overall'],metrics([(c['expected'],c['detected']) for c in stage['cases']]))
            self.assertEqual(sum(stage['overall'][k] for k in ('TP','FP','TN','FN')),len(rows))
            self.assertTrue(stage['valid_run'])
            self.assertEqual(stage['ai_reviews'],0)
