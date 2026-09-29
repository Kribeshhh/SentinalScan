"""Real SQLite editor workflow; GitHub writes are isolated behind a simulated API."""
import base64
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from app import create_app
from database import get_db
from analysis.finding_engine import Finding,save_finding
from analysis.remediation import source_diff
from integrations.github import GitHubClient,GitHubError

SHA='a'*40
BLOB='b'*40
OLD='result = eval(user_input)\n'
NEW='result = int(user_input)\n'


class Fixture:
    def __init__(self,token=None): pass
    def source_file(self,*args): return OLD,BLOB
    def publish_fix(self,draft): return 'https://github.com/test/repo/pull/1'


class RemediationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.config={'TESTING':True,'DATABASE':str(Path(self.temp.name)/'db.sqlite3'),'GITHUB_CLIENT_FACTORY':Fixture}
        self.app=create_app(self.config);self.client=self.app.test_client();self.client.get('/')
        with self.client.session_transaction() as s: self.csrf=s['csrf_token']
        with self.app.app_context():
            db=get_db()
            with db:
                repo=db.execute("INSERT INTO repositories(name,location,owner,branch,commit_sha) VALUES ('repo','https://github.com/test/repo','test','main',?)",(SHA,)).lastrowid
                scan=db.execute("INSERT INTO scans(scan_type,target,status,repository_id) VALUES ('Repository','test/repo','Completed',?)",(repo,)).lastrowid
            save_finding(db,scan,Finding(title='Unsafe eval',severity='High',confidence='High',category='Code',source='Repository',location='test/repo/app.py:1',description='Review',evidence='eval(user_input)',impact='Execution',recommendation='Parse the value.'))
            self.finding=db.execute('SELECT id FROM findings').fetchone()[0]
        self.url=f'/findings/{self.finding}/edit'

    def tearDown(self):
        self.app.extensions['scan_manager'].shutdown();self.temp.cleanup()

    def post(self,**data):
        return self.client.post(self.url,data={'csrf_token':self.csrf,**data})

    def load(self):
        self.assertEqual(self.post(action='load').status_code,303)

    def draft(self):
        with self.app.app_context():
            return dict(get_db().execute('SELECT * FROM remediation_drafts').fetchone())

    def connect(self):
        with self.client.session_transaction() as s:
            s['github_connected']=True
            s['github_credential']=self.app.extensions['github_credentials'].put('test-credential')

    def publish(self,version='2',reviewed='yes'):
        return self.client.post(f'/findings/{self.finding}/publish',data={'csrf_token':self.csrf,'version':version,'reviewed':reviewed},follow_redirects=True)

    def test_editor_preview_save_publish_and_persistence(self):
        self.assertIn('Edit source',self.client.get(f'/findings/{self.finding}').get_data(as_text=True))
        self.assertEqual(self.client.get(self.url).status_code,200)
        self.load()
        preview=self.post(action='preview',version='1',content=NEW)
        self.assertIn('+result = int(user_input)',preview.get_data(as_text=True))
        self.assertEqual(self.draft()['edited'],OLD)
        self.assertEqual(self.post(action='save',version='1',content=NEW).status_code,303)
        self.assertEqual(self.post(action='save',version='1',content='stale').status_code,400)
        patch_response=self.client.get(f'/findings/{self.finding}/patch')
        self.assertIn('+result = int(user_input)',patch_response.get_data(as_text=True))
        self.assertIn('attachment',patch_response.headers['Content-Disposition'])
        self.connect()
        self.assertEqual(self.publish(reviewed='no').status_code,400)
        self.assertEqual(self.publish(version='1').status_code,400)
        self.assertIn('View pull request',self.publish().get_data(as_text=True))
        self.assertEqual(self.draft()['state'],'Published')
        self.assertEqual(self.post(action='save',version='2',content=OLD).status_code,400)
        with self.app.app_context():
            self.assertEqual(get_db().execute('SELECT status FROM findings').fetchone()[0],'Open')
        restarted=create_app(self.config)
        try:
            page=restarted.test_client().get(self.url).get_data(as_text=True)
            self.assertIn('View pull request',page)
            self.assertIn('+result = int(user_input)',page)
        finally: restarted.extensions['scan_manager'].shutdown()

    def test_csrf_secrets_xss_limits_and_paths(self):
        self.assertEqual(self.client.post(self.url,data={'action':'load'}).status_code,400)
        self.load()
        secret='ghp_'+'xY72aBc9'*5
        response=self.post(action='save',version='1',content='token = "'+secret+'"')
        self.assertEqual(response.status_code,400);self.assertNotIn(secret,response.get_data(as_text=True))
        self.assertEqual(self.draft()['edited'],OLD)
        response=self.post(action='preview',version='1',content='</textarea><script>alert(1)</script>')
        self.assertNotIn('<script>alert(1)</script>',response.get_data(as_text=True))
        self.assertEqual(self.post(action='save',version='1',content='x'*48001).status_code,400)
        with self.app.app_context():
            db=get_db()
            with db: db.execute("UPDATE findings SET location='test/repo/../outside.py:1'")
        self.assertEqual(self.client.get(self.url).status_code,400)
        self.assertEqual(self.client.get('/findings/99999/edit').status_code,404)

    def test_load_secret_block_and_publication_retry(self):
        with patch.object(Fixture,'source_file',return_value=('password = "RealExposedValue123"',BLOB)):
            self.assertEqual(self.post(action='load').status_code,400)
        self.load();self.post(action='save',version='1',content=NEW)
        self.assertIn('Connect GitHub before publishing',self.publish().get_data(as_text=True))
        self.connect()
        with patch.object(Fixture,'publish_fix',side_effect=GitHubError('Write permission required.')):
            self.assertIn('Write permission required',self.publish().get_data(as_text=True))
        self.assertEqual(self.draft()['state'],'Retry')
        self.assertEqual(self.post(action='save',version='2',content=OLD).status_code,400)
        self.publish();self.assertEqual(self.draft()['state'],'Published')


class GitHubPublicationTests(unittest.TestCase):
    def draft(self):
        return dict(repository='test/repo',head_branch='sentinelscan/fix-1-test',base_branch='main',
            commit_sha=SHA,original=OLD,edited=NEW,path='app.py',blob_sha=BLOB,finding_id=1)

    def test_create_and_retry_reuse_branch_and_commit(self):
        client=GitHubClient(token='test');state={'branch':False,'content':OLD,'pull':False};writes=[]
        def api(path,method='GET',payload=None):
            if method!='GET': writes.append((path,method,payload))
            if '/pulls?' in path: return [{'number':12}] if state['pull'] else []
            if '/branches/' in path: return {'commit':{'sha':SHA}}
            if '/git/ref/heads/' in path:
                if not state['branch']: raise GitHubError('Missing',404)
                return {'object':{'sha':SHA}}
            if path.endswith('/git/refs'): state['branch']=True;return {}
            if '/contents/' in path:
                if method=='PUT': state['content']=base64.b64decode(payload['content']).decode();return {}
                return {'type':'file','encoding':'base64','path':'app.py','size':len(state['content']),
                    'content':base64.b64encode(state['content'].encode()).decode(),'sha':BLOB}
            if path.endswith('/pulls'):
                if not state['pull']:
                    state['pull']=True
                    raise GitHubError('Response lost')
            raise AssertionError(path)
        with patch.object(client,'api',side_effect=api):
            with self.assertRaises(GitHubError): client.publish_fix(self.draft())
            self.assertEqual(client.publish_fix(self.draft()),'https://github.com/test/repo/pull/12')
        self.assertEqual([item[1] for item in writes],['POST','PUT','POST'])
        self.assertEqual(writes[1][2]['branch'],'sentinelscan/fix-1-test')

    def test_changed_base_has_no_writes(self):
        client=GitHubClient(token='test')
        with patch.object(client,'api',return_value=[]) as api,patch.object(client,'commit',return_value='c'*40):
            with self.assertRaisesRegex(GitHubError,'branch has changed'): client.publish_fix(self.draft())
            self.assertEqual(api.call_count,1)

    def test_source_file_bounds_and_encoding(self):
        client=GitHubClient()
        with patch.object(client,'api',return_value={'type':'file','path':'app.py','encoding':'base64','size':5,'sha':BLOB,'content':'!!!!'}):
            with self.assertRaises(GitHubError): client.source_file('test/repo','app.py',SHA)
        self.assertIn('No newline at end of file',source_diff('old','new','app.py'))
