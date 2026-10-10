"""Malformed persistence fixtures use disposable SQLite only."""
import json
from pathlib import Path
import tempfile
import unittest
from app import create_app
from database import get_db
from analysis.finding_engine import Finding,save_finding
from analysis.management import compare_scans
from analysis.stored_data import StoredDataError,object_json,logical_fingerprint


class StoredDataTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.app=create_app({'TESTING':True,'DATABASE':str(Path(self.temp.name)/'test.sqlite3'),'REPORTS_DIR':str(Path(self.temp.name)/'reports'),'LLM_ENABLED':False})
        self.addCleanup(self.app.extensions['scan_manager'].shutdown)
        self.client=self.app.test_client();self.client.get('/')
        with self.client.session_transaction() as session:self.csrf=session['csrf_token']
        with self.app.app_context():
            db=get_db()
            with db:
                self.a=db.execute("INSERT INTO scans(scan_type,target,status,assessment_risk) VALUES ('Website','https://fixture.invalid/','Completed',17)").lastrowid
                self.b=db.execute("INSERT INTO scans(scan_type,target,status,assessment_risk) VALUES ('Website','https://fixture.invalid/','Completed',17)").lastrowid
            self.ids=[]
            for sid in (self.a,self.b):
                self.ids.append(save_finding(db,sid,Finding(title='Keep this finding',severity='Critical',confidence='High',category='Audit',source='Website',location='https://fixture.invalid/',description='Fixture',evidence='Fixture',impact='Fixture',recommendation='Review',status='Open')))
            with db:self.mid=db.execute("INSERT INTO scan_modules(scan_id,name,status,data_json) VALUES (?,'HTTP','Completed','{}')",(self.a,)).lastrowid

    def set_module(self,raw):
        with self.app.app_context():
            db=get_db()
            with db:db.execute('UPDATE scan_modules SET data_json=? WHERE id=?',(raw,self.mid))

    def set_solution(self,raw,fid=None):
        with self.app.app_context():
            db=get_db()
            with db:db.execute('INSERT OR REPLACE INTO finding_solutions VALUES (?,?)',(fid or self.ids[0],raw))

    def snapshot(self):
        with self.app.app_context():
            db=get_db()
            return {t:[tuple(r) for r in db.execute('SELECT * FROM '+t+' ORDER BY 1')] for t in ('scans','findings','scan_modules','finding_solutions','scan_comparisons')}

    def post(self):
        return self.client.post('/comparisons',data={'csrf_token':self.csrf,'baseline':self.a,'current':self.b})

    def test_invalid_json_and_top_level_types_module_are_unavailable(self):
        for raw in ('{bad','[]','null','true','7','"PRIVATE-CORRUPT-RECORD"','{"x":NaN}',b'\xff'):
            with self.subTest(raw=raw):
                self.set_module(raw);before=self.snapshot()
                r=self.client.get('/scans/'+str(self.a));text=r.get_data(as_text=True)
                self.assertEqual(r.status_code,200)
                self.assertIn('Observations unavailable',text);self.assertIn('Coverage cannot be verified',text)
                self.assertIn('Keep this finding',text);self.assertIn('17/100',text)
                self.assertNotIn('PRIVATE-CORRUPT-RECORD',text)
                self.assertEqual(self.snapshot(),before)

    def test_module_empty_and_unknown_observation_keys_remain_valid(self):
        for raw in ('{}','{"status_code":200,"headers":{}}','{"future_field":["<script>fixture</script>"]}'):
            self.set_module(raw);before=self.snapshot();r=self.client.get('/scans/'+str(self.a))
            self.assertEqual(r.status_code,200);self.assertNotIn(b'Observations unavailable',r.data)
            self.assertNotIn(b'<script>fixture</script>',r.data);self.assertEqual(self.snapshot(),before)

    def test_one_invalid_module_does_not_hide_other_observations(self):
        with self.app.app_context():
            db=get_db()
            with db:db.execute("INSERT INTO scan_modules(scan_id,name,status,data_json) VALUES (?,'DNS','Completed',?)",(self.a,'{"note":"Valid observation retained"}'))
        self.set_module('{bad');r=self.client.get('/scans/'+str(self.a))
        self.assertIn(b'Valid observation retained',r.data);self.assertIn(b'Observations unavailable',r.data)

    def test_invalid_solution_json_and_nested_types_reject_creation(self):
        cases=['{bad','[]','null','3','true','"PRIVATE-CORRUPT-RECORD"']
        cases += [json.dumps({'finding_context':v}) for v in (None,[],1,'x')]
        cases += [json.dumps({'finding_context':{'analysis':v}}) for v in (None,[],False,'x')]
        cases += [json.dumps({'finding_context':{'analysis':{'logical_fingerprint':v}}}) for v in ([],{},True,42,'','not-a-fingerprint')]
        for raw in cases:
            with self.subTest(raw=raw):
                self.set_solution(raw);before=self.snapshot();r=self.post()
                self.assertEqual(r.status_code,400);self.assertIn(b'Comparison unavailable',r.data)
                self.assertNotIn(b'PRIVATE-CORRUPT-RECORD',r.data);self.assertEqual(self.snapshot(),before)
                self.assertNotIn(b'Detection changes</h1>',r.data)

    def test_bad_current_snapshot_rejected_without_discarding_finding(self):
        self.set_solution('[]',self.ids[1]);before=self.snapshot()
        self.assertEqual(self.post().status_code,400);self.assertEqual(self.snapshot(),before)

    def test_corrupt_module_does_not_create_comparison_with_false_coverage(self):
        self.set_module('{bad');before=self.snapshot()
        self.assertEqual(self.post().status_code,400);self.assertEqual(self.snapshot(),before)

    def test_failed_refresh_retains_previous_saved_comparison(self):
        self.assertEqual(self.post().status_code,303)
        self.set_solution('[]');before=self.snapshot()
        self.assertEqual(self.post().status_code,400);self.assertEqual(self.snapshot(),before)
        with self.app.app_context():cid=get_db().execute('SELECT id FROM scan_comparisons').fetchone()[0]
        self.assertEqual(self.client.get('/comparisons/'+str(cid)).status_code,200)

    def test_missing_legacy_fields_preserve_matching_not_empty_results(self):
        for raw in ('{}','{"finding_context":{}}','{"finding_context":{"analysis":{}}}','{"finding_context":{"analysis":{"logical_fingerprint":null}}}'):
            self.set_solution(raw)
            self.assertEqual(self.post().status_code,303)
            with self.app.app_context():
                db=get_db();result=json.loads(db.execute('SELECT summary_json FROM scan_comparisons').fetchone()[0])
                self.assertEqual(len(result['unchanged']),1);self.assertEqual(result['resolved'],[]);self.assertEqual(result['new'],[])
                self.assertTrue(any('legacy' in s for s in result['limitations']))
                self.assertEqual(result['current_risk'],17)

    def test_valid_logical_identity_and_missing_snapshot_preserve_records(self):
        for fid in self.ids:self.set_solution(json.dumps({'finding_context':{'analysis':{'logical_fingerprint':'a'*64}}}),fid)
        self.assertEqual(self.post().status_code,303)
        with self.app.app_context():
            db=get_db();result=compare_scans(db,self.a,self.b)
            self.assertEqual(result['unchanged'][0]['fingerprint'],'a'*64)
            self.assertEqual(len(result['unchanged']),1)
        for path in ('/','/scans','/findings','/risk-trends'):
            self.assertEqual(self.client.get(path).status_code,200)

    def test_deep_invalid_json_and_wrong_identity_cannot_escape_validation(self):
        for raw in ('['*1500+'0'+']'*1500,'{"x":Infinity}',None):
            with self.assertRaises(StoredDataError):object_json(raw)
        with self.assertRaises(StoredDataError):logical_fingerprint('{"finding_context":[]}')
