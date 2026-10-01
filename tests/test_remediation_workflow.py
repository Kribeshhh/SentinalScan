"""Scan -> redacted context -> checked draft -> PR -> merged rescan -> verification."""
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch
from app import create_app
from database import get_db
from analysis.fix_validation import validate_fix
from analysis.source_context import mask_source
from analysis.remediation_workflow import assess_rescan
from integrations.github import GitHubClient,GitHubError

OLD='value = eval(raw)\n'
NEW='import json\nvalue = json.loads(raw)\n'
TOKEN='ghp_'+'fakeValue456'*4
REPO={'owner':'lab','name':'repo','full_name':'lab/repo','url':'https://github.com/lab/repo','private':True,'default_branch':'main','size_kib':1,'language':'Python'}


class WorkflowGitHub:
    merged=False
    source=OLD
    def __init__(self,token=None): pass
    def identity(self): return 'lab'
    def repositories(self,*args): return [REPO]
    def repository(self,*args): return REPO
    def branches(self,*args): return ['main']
    def commit(self,*args): return ('b' if self.merged else 'a')*40
    def archive(self,name,sha,destination):
        with zipfile.ZipFile(destination,'w') as z:
            z.writestr('snapshot/code.py',self.source)
    def source_file(self,*args): return OLD,'c'*40
    def publish_fix(self,draft): return 'https://github.com/lab/repo/pull/7'
    def pull_status(self,draft): return {'state':'Merged' if self.merged else 'Open','merge_commit':'b'*40 if self.merged else None}
    def includes_commit(self,*args): return self.merged


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        WorkflowGitHub.merged=False;WorkflowGitHub.source=OLD
        self.temp=tempfile.TemporaryDirectory()
        self.config={'TESTING':True,'DATABASE':str(Path(self.temp.name)/'db'),'GITHUB_CLIENT_FACTORY':WorkflowGitHub}
        self.app=create_app(self.config);self.client=self.app.test_client();self.client.get('/')
        with self.client.session_transaction() as s:self.csrf=s['csrf_token']

    def tearDown(self):
        self.app.extensions['scan_manager'].shutdown();self.temp.cleanup()

    def post(self,path,**data):
        return self.client.post(path,data={'csrf_token':self.csrf,**data},follow_redirects=False)

    def scan(self):
        response=self.post('/repository-scan',action='start',repository='lab/repo',branch='main',authorized='yes')
        self.assertEqual(response.status_code,303)
        self.app.extensions['scan_manager'].executor.submit(lambda:None).result(timeout=10)
        return int(response.headers['Location'].rsplit('/',1)[1])

    def setup_draft(self):
        self.scan()
        with self.app.app_context():
            self.id=get_db().execute('SELECT id FROM findings').fetchone()[0]
        self.url=f'/findings/{self.id}'
        self.assertEqual(self.post(self.url+'/edit',action='load').status_code,303)

    def test_complete_workflow_persists_and_verifies_merge(self):
        self.setup_draft()
        page=self.client.get(self.url).get_data(as_text=True)
        self.assertIn('Remediation workflow',page)
        with self.app.app_context():
            db=get_db();context=db.execute('SELECT * FROM finding_context').fetchone()
            self.assertIn('eval(raw)',context['excerpt']);self.assertEqual(context['commit_sha'],'a'*40)
        self.post(self.url+'/edit',action='save',version='1',content=NEW)
        with self.app.app_context():
            check=json.loads(get_db().execute('SELECT data_json FROM draft_checks').fetchone()[0])
            self.assertEqual(check['syntax'],'Passed');self.assertEqual(check['rule'],'No longer detected')
            self.assertEqual(check['behavior'],'Not tested')
        self.post('/repository-scan',action='connect',github_token=TOKEN)
        self.post(self.url+'/publish',version='2',reviewed='yes')
        self.post(self.url+'/pull-request/refresh')
        with self.app.app_context():self.assertEqual(get_db().execute('SELECT state FROM pull_request_tracking').fetchone()[0],'Open')
        WorkflowGitHub.merged=True;WorkflowGitHub.source=NEW
        response=self.post(self.url+'/rescan',authorized='yes')
        self.assertEqual(response.status_code,303)
        scan_id=int(response.headers['Location'].rsplit('/',1)[1])
        self.app.extensions['scan_manager'].executor.submit(lambda:None).result(timeout=10)
        self.assertIn(self.url+'#remediation-workflow',self.client.get(f'/scans/{scan_id}').get_data(as_text=True))
        with patch.object(WorkflowGitHub,'includes_commit',return_value=False):
            self.post(self.url+'/verify',scan_id=scan_id,resolve='yes')
        with self.app.app_context():
            self.assertEqual(get_db().execute('SELECT result FROM remediation_verifications').fetchone()[0],'Inconclusive')
            self.assertEqual(get_db().execute('SELECT status FROM findings WHERE id=?',(self.id,)).fetchone()[0],'Open')
        self.post(self.url+'/verify',scan_id=scan_id)
        with self.app.app_context():
            self.assertEqual(get_db().execute('SELECT status FROM findings WHERE id=?',(self.id,)).fetchone()[0],'Open')
        self.post(self.url+'/verify',scan_id=scan_id,resolve='yes')
        with self.app.app_context():
            db=get_db();v=db.execute('SELECT * FROM remediation_verifications').fetchone()
            self.assertEqual(v['result'],'Not detected');self.assertEqual(v['merge_commit'],'b'*40)
            self.assertEqual(db.execute('SELECT status FROM findings WHERE id=?',(self.id,)).fetchone()[0],'Resolved')
            self.assertNotIn(TOKEN,'\n'.join(db.iterdump()))
        restarted=create_app(self.config)
        try:
            page=restarted.test_client().get(self.url).get_data(as_text=True)
            self.assertIn('Not detected',page);self.assertIn('Merged',page);self.assertIn('No longer detected',page)
        finally: restarted.extensions['scan_manager'].shutdown()

    def test_validation_blocks_syntax_and_remaining_rule(self):
        self.setup_draft();self.post('/repository-scan',action='connect',github_token=TOKEN)
        self.post(self.url+'/edit',action='save',version='1',content='value = eval(raw + "x")\n')
        with patch.object(WorkflowGitHub,'publish_fix') as publish:
            self.post(self.url+'/publish',version='2',reviewed='yes');publish.assert_not_called()
        self.post(self.url+'/edit',action='save',version='2',content='value = (')
        with self.app.app_context():
            check=json.loads(get_db().execute('SELECT data_json FROM draft_checks WHERE version=3').fetchone()[0])
            self.assertEqual(check['syntax'],'Failed');self.assertFalse(check['can_publish'])
        self.assertEqual(self.client.post(self.url+'/verify',data={'scan_id':1}).status_code,400)
        self.assertEqual(self.post(self.url+'/rescan',authorized='no').status_code,400)
        self.assertEqual(self.post(self.url+'/validate',version='1').status_code,400)

    def test_verification_requires_coverage_and_counts_ignored_recurrence(self):
        self.setup_draft();WorkflowGitHub.source='\n\n'+OLD
        second=self.scan()
        with self.app.app_context():
            db=get_db();f=db.execute('SELECT * FROM findings WHERE id=?',(self.id,)).fetchone()
            scan=db.execute('SELECT * FROM scans WHERE id=?',(second,)).fetchone()
            with db:db.execute("UPDATE findings SET status='Ignored' WHERE scan_id=?",(second,))
            self.assertEqual(assess_rescan(db,f,scan)[0],'Still detected')
            with db:db.execute("UPDATE scan_modules SET status='Partial' WHERE scan_id=? AND name='Python'",(second,))
            self.assertEqual(assess_rescan(db,f,scan)[0],'Inconclusive')
            with db:
                db.execute("UPDATE scan_modules SET status='Completed' WHERE scan_id=?",(second,))
                db.execute('DELETE FROM scan_files WHERE scan_id=?',(second,))
            self.assertEqual(assess_rescan(db,f,scan)[0],'Inconclusive')
            with self.assertRaises(ValueError):assess_rescan(db,f,db.execute('SELECT * FROM scans WHERE id=?',(f['scan_id'],)).fetchone())

    def test_retained_context_masks_multiline_keys_preserves_lines(self):
        source='first\n-----BEGIN PRIVATE KEY-----\nSENSITIVEKEYVALUE\n-----END PRIVATE KEY-----\npassword="RealCredential987"\nlast\n'
        masked=mask_source(source)
        self.assertNotIn('SENSITIVEKEYVALUE',masked);self.assertNotIn('RealCredential987',masked)
        self.assertEqual(source.count('\n'),masked.count('\n'))
        self.assertEqual(masked.splitlines()[5],'last')

    def test_github_tracking_validates_identity_and_ancestry(self):
        github=GitHubClient()
        draft={'repository':'lab/repo','pr_url':'https://github.com/lab/repo/pull/7','base_branch':'main','head_branch':'fix'}
        response={'base':{'ref':'main','repo':{'full_name':'lab/repo'}},'head':{'ref':'fix'},'merged':True,'merge_commit_sha':'b'*40}
        with patch.object(github,'api',return_value=response):self.assertEqual(github.pull_status(draft)['state'],'Merged')
        response['base']['ref']='other'
        with patch.object(github,'api',return_value=response):
            with self.assertRaises(GitHubError):github.pull_status(draft)
        for status,wanted in [('ahead',True),('identical',True),('behind',False),('diverged',False)]:
            with patch.object(github,'api',return_value={'status':status}):self.assertEqual(github.includes_commit('lab/repo','a'*40,'b'*40),wanted)
