"""Static fixtures are only read and zipped, never imported, built or executed."""
from pathlib import Path
import json
import os
import stat
import tempfile
import unittest
import zipfile
from unittest.mock import patch
from app import create_app
from database import get_db
from integrations.github import GitHubClient,GitHubError
from integrations.network import RemoteError
from scanner.repository_safety import extract_archive,ArchiveError,MAX_FILE
from scanner.source_scanner import analyze_directory,MODULES
from scanner.sast import dependency_scanner
from analysis.redaction import scrub

FIXTURES=Path(__file__).parent/'fixtures'/'sast_lab'
REPO={'owner':'authorized-lab','name':'source-fixture','full_name':'authorized-lab/source-fixture','url':'https://github.com/authorized-lab/source-fixture','private':True,'default_branch':'main','size_kib':5,'language':'Python'}
SHA='a'*40
FAKE_AUTH='ghp_'+'9aB2cD3eF4gH5jK6mN7pQ8rS9tU0vW1xY2zA'


def fixture_zip(destination):
    with zipfile.ZipFile(destination,'w') as bundle:
        for path in sorted(FIXTURES.iterdir()):
            if path.is_file():
                bundle.write(path,'snapshot/'+path.name)
        bundle.writestr('snapshot/.env.production','DATABASE_PASSWORD=LocalDatabaseCredential-39-not-valid\n')
        bundle.writestr('snapshot/credentials.txt','GITHUB_TOKEN="'+FAKE_AUTH+'"\n')
        bundle.writestr('snapshot/node_modules/ignored.js','eval(user)')
        bundle.writestr('snapshot/binary.py',b'\x00binary')


class FixtureGitHub:
    """Network boundary fixture only; all scanner modules analyze actual source files."""
    token_seen=None
    archive_path=None
    def __init__(self,token=None):
        type(self).token_seen=token
    def identity(self):
        return 'authorized-lab'
    def repositories(self,owner='',page=1):
        return [REPO]
    def repository(self,name):
        if name!=REPO['full_name']:
            raise GitHubError('Repository is not accessible.')
        return REPO
    def branches(self,name,page=1):
        return ['main','feature/lab']
    def commit(self,name,branch):
        if branch not in ('main','feature/lab'):
            raise GitHubError('Branch is not accessible.')
        return SHA
    def archive(self,name,sha,destination):
        type(self).archive_path=destination
        fixture_zip(destination)


class SourceScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.app=create_app({'TESTING':True,'DATABASE':str(Path(self.temp.name)/'test.sqlite3'),'GITHUB_CLIENT_FACTORY':FixtureGitHub})
        self.client=self.app.test_client();self.client.get('/repository-scan')
        with self.client.session_transaction() as session:
            self.csrf=session['csrf_token']

    def tearDown(self):
        self.app.extensions['scan_manager'].shutdown();self.temp.cleanup()

    def test_optional_tool_failure_preserves_custom_scan(self):
        from scanner.engines.process import ToolFailure
        self.app.config.update(SEMGREP_ENABLED=True,CODEQL_ENABLED=True)
        with patch('scanner.engines.external.executable',return_value='/trusted/tool'),patch('scanner.engines.external.run_tool',side_effect=ToolFailure('Analysis timed out.')):
            response=self.client.post('/repository-scan',data={'csrf_token':self.csrf,'action':'start','repository':REPO['full_name'],'branch':'main','authorized':'yes'})
            self.assertEqual(response.status_code,303)
            self.app.extensions['scan_manager'].shutdown()
        with self.app.app_context():
            db=get_db()
            self.assertEqual(db.execute('SELECT status FROM scans').fetchone()[0],'Completed')
            self.assertGreater(db.execute('SELECT count(*) FROM findings').fetchone()[0],0)
            for engine in ('Semgrep','CodeQL'):
                self.assertEqual(db.execute('SELECT status FROM scan_modules WHERE name=?',(engine,)).fetchone()[0],'Failed')

    def test_repository_pipeline_and_secret_redaction(self):
        response=self.client.post('/repository-scan',data={'csrf_token':self.csrf,'action':'start','repository':REPO['full_name'],'branch':'feature/lab','authorized':'yes'})
        self.assertEqual(response.status_code,303)
        self.app.extensions['scan_manager'].shutdown()
        self.assertFalse(FixtureGitHub.archive_path.exists())
        self.assertFalse(FixtureGitHub.archive_path.parent.exists())
        with self.app.app_context():
            db=get_db();scan=db.execute('SELECT * FROM scans').fetchone()
            self.assertEqual(scan['scan_type'],'Repository');self.assertEqual(scan['status'],'Completed');self.assertEqual(scan['progress'],100)
            rows=db.execute('SELECT * FROM scan_modules').fetchall()
            self.assertTrue(all(row['status']==('Skipped' if row['name'] in ('Semgrep','CodeQL') else 'Completed') for row in rows),[(row['name'],row['error']) for row in rows])
            titles=[row[0] for row in db.execute('SELECT title FROM findings')]
            for title in ('Dynamic Python code execution','Potential shell command injection','Potential SQL injection in constructed query','Potential unsafe deserialization','Weak hash algorithm usage','Dynamic JavaScript code execution','Potential unsafe DOM HTML assignment','Dynamic Java process execution','Potential SQL injection in Java query','Potential unsafe Java deserialization','Weak Java cryptographic algorithm','Password form uses GET','Debug or development mode configured','GitHub token'):
                self.assertIn(title,titles)
            dump='\n'.join(db.iterdump())
            for secret in (FAKE_AUTH,'LocalLabCredential-83-not-valid','LocalFixtureSigningKey-47-not-valid','LocalDatabaseCredential-39-not-valid'):
                self.assertNotIn(secret,dump)
            self.assertIn('[REDACTED]',dump)
            repo=db.execute('SELECT * FROM repositories').fetchone()
            self.assertEqual(repo['branch'],'feature/lab');self.assertEqual(repo['commit_sha'],SHA)
            self.assertIn('Python',json.loads(repo['languages_json']))
            self.assertEqual(len(json.loads(repo['dependencies_json'])),6)
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(),[])
            finding_id=db.execute('SELECT id FROM findings LIMIT 1').fetchone()[0]
        for url in (response.headers['Location'],'/','/findings?source=Repository',f'/findings/{finding_id}',response.headers['Location']+'/status'):
            page=self.client.get(url)
            self.assertEqual(page.status_code,200)
            self.assertNotIn(FAKE_AUTH,page.get_data(as_text=True))

    def test_github_connection_keeps_token_server_side(self):
        with patch.dict(os.environ,{'SENTINELSCAN_GITHUB_TOKEN':FAKE_AUTH}):
            response=self.client.post('/repository-scan',data={'csrf_token':self.csrf,'action':'connect'},follow_redirects=True)
            self.assertEqual(response.status_code,200);self.assertIn('Connected to GitHub',response.get_data(as_text=True))
            self.assertEqual(FixtureGitHub.token_seen,FAKE_AUTH)
            self.assertNotIn(FAKE_AUTH,response.get_data(as_text=True))
            self.assertNotIn(FAKE_AUTH,str(response.headers))
            with self.client.session_transaction() as session:
                self.assertNotIn(FAKE_AUTH,str(dict(session)))
                self.assertTrue(session['github_connected'])
            selection=self.client.get('/repository-scan?repo='+REPO['full_name'])
            self.assertIn('feature/lab',selection.get_data(as_text=True))
            self.assertNotIn(FAKE_AUTH,selection.get_data(as_text=True))
            self.client.post('/repository-scan',data={'csrf_token':self.csrf,'action':'disconnect'})
            with self.client.session_transaction() as session:
                self.assertNotIn('github_connected',session)

    def test_submission_validation_and_csrf(self):
        data={'action':'start','repository':REPO['full_name'],'branch':'main','authorized':'yes'}
        self.assertEqual(self.client.post('/repository-scan',data=data).status_code,400)
        data['csrf_token']=self.csrf;data['authorized']='no'
        self.assertEqual(self.client.post('/repository-scan',data=data).status_code,400)
        data['authorized']='yes';data['repository']='https://attacker.invalid/repository'
        self.assertEqual(self.client.post('/repository-scan',data=data).status_code,400)
        self.assertEqual(self.client.get('/repository-scan?page=-1').status_code,400)
        with self.app.app_context():
            self.assertEqual(get_db().execute('SELECT COUNT(*) FROM scans').fetchone()[0],0)

    def test_context_reduces_code_false_positives(self):
        from scanner.sast import python_scanner,javascript_scanner,java_scanner
        root=Path(self.temp.name)/'safe';root.mkdir()
        (root/'safe.py').write_text("import yaml\n# eval(user)\ns='os.system(user)'\ncursor.execute('SELECT ?',(user,))\nyaml.load(data, Loader=yaml.SafeLoader)\n")
        (root/'safe.js').write_text("// eval(user)\nconst x='node.innerHTML = user'; node.innerHTML='Static'; node.innerHTML=DOMPurify.sanitize(user); document.write('Static');")
        (root/'Safe.java').write_text('class Safe { void x() { String s="Runtime.getRuntime().exec(user)"; stmt.executeQuery("SELECT 1"); }}')
        ctx=analyze_directory(root,['safe.py','safe.js','Safe.java'],'authorized/safe')
        for module in (python_scanner,javascript_scanner,java_scanner):
            module.run(ctx)
        self.assertEqual(ctx['findings'],[])

    def test_dependency_vulnerability_and_outage(self):
        ctx=analyze_directory(FIXTURES,[p.name for p in FIXTURES.iterdir() if p.is_file()],REPO['full_name'],True)
        advisory={'vulns':[{'id':'GHSA-test-advisory','summary':'Test advisory response','database_specific':{'severity':'HIGH'},'affected':[{'package':{'name':'Flask','ecosystem':'PyPI'},'ranges':[{'type':'ECOSYSTEM','events':[{'introduced':'0'},{'fixed':'1.0'}]}]}]}]}
        with patch('scanner.sast.dependency_scanner.query',return_value=advisory):
            data=dependency_scanner.run(ctx)
        self.assertEqual(data['queried_packages'],3)
        self.assertTrue(any(f.category=='Dependency' and f.severity=='High' for f in ctx['findings']))
        self.assertTrue(any(d['lookup']=='Unresolved version' for d in data['dependencies']))
        ctx=analyze_directory(FIXTURES,[p.name for p in FIXTURES.iterdir() if p.is_file()],REPO['full_name'],True)
        with patch('scanner.sast.dependency_scanner.query',side_effect=RemoteError('OSV unavailable')):
            data=dependency_scanner.run(ctx)
        self.assertEqual(data['lookup_failures'],3);self.assertEqual(ctx['findings'],[])

    def test_osv_failure_does_not_fail_repository(self):
        with patch('scanner.sast.dependency_scanner.query',side_effect=RemoteError('OSV unavailable')):
            self.client.post('/repository-scan',data={'csrf_token':self.csrf,'action':'start','repository':REPO['full_name'],'branch':'main','authorized':'yes','osv':'yes'})
            self.app.extensions['scan_manager'].shutdown()
        with self.app.app_context():
            db=get_db()
            self.assertEqual(db.execute('SELECT status FROM scans').fetchone()[0],'Completed')
            self.assertEqual(db.execute("SELECT status FROM scan_modules WHERE name='Dependencies'").fetchone()[0],'Partial')
            self.assertGreater(db.execute('SELECT COUNT(*) FROM findings').fetchone()[0],0)

    def test_secret_placeholders_and_export_redaction(self):
        from scanner.sast.secret_scanner import run
        root=Path(self.temp.name)/'secrets';root.mkdir()
        (root/'settings.py').write_text("API_KEY='YOUR_API_KEY'\nPASSWORD='changeme'\nSECRET_KEY='<API_KEY>'\n")
        ctx=analyze_directory(root,['settings.py'],'authorized/fixture');run(ctx)
        self.assertEqual(ctx['findings'],[])
        data=scrub({'evidence':'token='+FAKE_AUTH,'description':'password="AnyRealCandidate-4839"'})
        self.assertNotIn(FAKE_AUTH,json.dumps(data));self.assertNotIn('AnyRealCandidate-4839',json.dumps(data))


class ArchiveSafetyTests(unittest.TestCase):
    def test_reject_malicious_archives_and_skip_exclusions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for index,name in enumerate(('../escape.py','root/../../escape.py','/absolute.py','root/evil\\name.py','root/C:evil.py')):
                archive=root/f'{index}.zip'
                with zipfile.ZipFile(archive,'w') as bundle:
                    bundle.writestr(name,'print(1)')
                with self.subTest(name=name),self.assertRaises(ArchiveError):
                    extract_archive(archive,root/f'out{index}')
            archive=root/'symlink.zip'
            info=zipfile.ZipInfo('root/link.py');info.create_system=3;info.external_attr=(stat.S_IFLNK|0o777)<<16
            with zipfile.ZipFile(archive,'w') as bundle:
                bundle.writestr(info,'/etc/passwd')
            with self.assertRaises(ArchiveError):
                extract_archive(archive,root/'links')
            archive=root/'fixture.zip';fixture_zip(archive)
            with zipfile.ZipFile(archive,'a') as bundle:
                bundle.writestr('snapshot/large.py',b'A'*(MAX_FILE+1))
            paths,stats=extract_archive(archive,root/'valid')
            self.assertNotIn('node_modules/ignored.js',paths);self.assertEqual(stats['excluded'],1)
            self.assertEqual(stats['oversized_files'],1);self.assertEqual(stats['binary_files'],1)

    def test_reject_duplicate_paths_and_zip_bomb(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);archive=root/'duplicate.zip'
            with zipfile.ZipFile(archive,'w') as bundle:
                bundle.writestr('repo/a.py','pass');bundle.writestr('repo/A.py','pass')
            with self.assertRaises(ArchiveError):
                extract_archive(archive,root/'out')
            archive=root/'bomb.zip'
            with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED) as bundle:
                bundle.writestr('repo/huge.py',b'A'*(2*1024*1024))
            with self.assertRaises(ArchiveError):
                extract_archive(archive,root/'bomb')


class GitHubTransportTests(unittest.TestCase):
    def test_authenticated_owner_listing_includes_private_and_preserves_pagination(self):
        rows=[dict(REPO, full_name='another/repo'+str(i)) for i in range(30)]
        with patch('integrations.github.request', return_value=(200,{},json.dumps(rows).encode())) as remote:
            github=GitHubClient(FAKE_AUTH)
            self.assertEqual(github.repositories('authorized-lab'), [])
            self.assertTrue(github.has_more_repositories)
            self.assertTrue(remote.call_args.args[1].startswith('/user/repos?'))
            self.assertEqual(remote.call_args.kwargs['headers']['Authorization'], 'Bearer '+FAKE_AUTH)
        with patch('integrations.github.request', return_value=(200,{},json.dumps([REPO]).encode())) as remote:
            results=github.repositories('AUTHORIZED-LAB',2)
            self.assertEqual(results[0]['full_name'],REPO['full_name'])
            self.assertTrue(results[0]['private'])
            self.assertFalse(github.has_more_repositories)
            self.assertIn('page=2',remote.call_args.args[1])
        with patch('integrations.github.request', return_value=(200,{},b'[]')) as remote:
            GitHubClient().repositories('authorized-lab')
            self.assertTrue(remote.call_args.args[1].startswith('/users/authorized-lab/repos?'))

    def test_access_errors_distinguish_sso_and_rate_limits_without_leaking(self):
        from integrations.github import access_error
        self.assertIn('SSO authorization',access_error(403,{'X-GitHub-SSO':'required; url='+FAKE_AUTH}))
        self.assertIn('rate limit',access_error(403,{'X-RateLimit-Remaining':'0'}))
        self.assertIn('Contents: read',access_error(404,{}))
        self.assertNotIn(FAKE_AUTH,access_error(403,{'X-GitHub-SSO':'required; url='+FAKE_AUTH}))

    def test_token_never_forwarded_to_archive_host(self):
        with tempfile.TemporaryDirectory() as directory:
            responses=[(302,{'Location':'https://codeload.github.com/authorized-lab/source-fixture/legacy.zip/'+SHA},b''),(200,{},b'archive')]
            with patch('integrations.github.request',side_effect=responses) as remote:
                GitHubClient(FAKE_AUTH).archive(REPO['full_name'],SHA,Path(directory)/'archive.zip')
            self.assertEqual(remote.call_args_list[0].kwargs['headers']['Authorization'],'Bearer '+FAKE_AUTH)
            self.assertNotIn('Authorization',remote.call_args_list[1].kwargs.get('headers',{}))
            self.assertNotIn(FAKE_AUTH,str(remote.call_args_list[1]))
            self.assertNotIn(FAKE_AUTH,repr(GitHubClient(FAKE_AUTH)))

    def test_bad_redirects_and_errors_do_not_leak(self):
        with tempfile.TemporaryDirectory() as directory:
            for url in ('https://attacker.invalid/archive','http://codeload.github.com/authorized-lab/source-fixture/archive','https://codeload.github.com/other/repo/archive'):
                with patch('integrations.github.request',return_value=(302,{'Location':url},b'')),self.assertRaises(GitHubError):
                    GitHubClient(FAKE_AUTH).archive(REPO['full_name'],SHA,Path(directory)/'archive.zip')
        with patch('integrations.github.request',return_value=(401,{},FAKE_AUTH.encode())):
            with self.assertRaises(GitHubError) as error:
                GitHubClient(FAKE_AUTH).identity()
        self.assertNotIn(FAKE_AUTH,str(error.exception))

    def test_authentication_errors_are_fixed_messages(self):
        for status in (401,403,404,429,500):
            with patch('integrations.github.request',return_value=(status,{},FAKE_AUTH.encode())):
                with self.assertRaises(GitHubError) as error:
                    GitHubClient(FAKE_AUTH).repository(REPO['full_name'])
                self.assertNotIn(FAKE_AUTH,str(error.exception))


class NonExecutionTests(unittest.TestCase):
    def test_build_hooks_are_only_read_as_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);archive=root/'untrusted.zip';marker=root/'SHOULD_NOT_EXIST'
            with zipfile.ZipFile(archive,'w') as bundle:
                bundle.writestr('root/setup.py',f'from pathlib import Path\nPath({str(marker)!r}).touch()\n')
                bundle.writestr('root/Makefile','all:\n\ttouch SHOULD_NOT_EXIST\n')
                bundle.writestr('root/install.sh','touch SHOULD_NOT_EXIST\n')
                bundle.writestr('root/package.json','{"scripts":{"install":"touch SHOULD_NOT_EXIST"}}')
            paths,_=extract_archive(archive,root/'source')
            ctx=analyze_directory(root/'source',paths,'authorized/nonexecution')
            with patch('subprocess.run',side_effect=AssertionError('Repository code must not execute')),patch('os.system',side_effect=AssertionError('Repository code must not execute')):
                for _,module in MODULES:
                    module(ctx)
            self.assertFalse(marker.exists())
