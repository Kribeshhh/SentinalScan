"""Adversarial regression checks; every write uses isolated temporary storage."""
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from app import create_app
from config import secret_key
from database import get_db
from analysis.finding_engine import Finding, save_finding
from scanner.http_scanner import Client
from scanner.port_scanner import run as port_scan
from scanner.repository_safety import extract_archive, ArchiveError
from scanner.target import validate_target
from scanner.website_scanner import QueueFull
from scanner import source_scanner
from reports.report_generator import generate_report
from test_source_scanner import FixtureGitHub, REPO


class HardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.app = create_app({'TESTING': True, 'DATABASE': str(self.root/'test.sqlite3'),
                              'REPORTS_DIR': str(self.root/'reports'), 'GITHUB_CLIENT_FACTORY': FixtureGitHub})
        self.client = self.app.test_client()
        self.client.get('/')
        with self.client.session_transaction() as session:
            self.csrf = session['csrf_token']

    def tearDown(self):
        self.app.extensions['scan_manager'].shutdown()
        self.temp.cleanup()

    def seed(self):
        with self.app.app_context():
            db = get_db()
            scan = db.execute("INSERT INTO scans(scan_type,target,status,assessment_risk) VALUES ('Website','http://localhost/','Completed',17)").lastrowid
            db.commit()
            finding = Finding(title='Test finding', severity='Critical', confidence='High', category='Test',
                              source='Website', location='http://localhost/', description='Test description',
                              evidence='Test evidence', impact='Test impact', recommendation='Test recommendation')
            return scan, save_finding(db, scan, finding)

    def test_id_bounds_upload_rejection_and_request_limits(self):
        huge = str(2**80)
        for path in ('/findings/'+huge, '/scans/'+huge, '/reports/'+huge+'/view', '/comparisons/'+huge):
            self.assertEqual(self.client.get(path).status_code, 404)
        for path in ('/findings?scan_id='+huge, '/reports?scan_id='+huge, '/risk-trends?scan_id='+huge):
            self.assertEqual(self.client.get(path).status_code, 400)
        self.assertEqual(self.client.post('/reports/generate', data={'csrf_token': self.csrf, 'scan_id': huge, 'format': 'JSON'}).status_code, 400)
        self.assertEqual(self.client.post('/website-scan', data={'csrf_token': self.csrf, 'upload': (io.BytesIO(b'not executed'), 'run.py')}).status_code, 400)
        self.assertEqual(self.client.post('/website-scan', data=b'x'*1048577, content_type='application/x-www-form-urlencoded').status_code, 413)
        self.assertFalse(self.app.debug)
        self.assertIn('camera=()', self.client.get('/').headers['Permissions-Policy'])

    def test_safe_error_response_and_logs(self):
        def fail():
            raise RuntimeError('password=PrivateErrorPayload-1298')
        with patch.dict(self.app.view_functions, {'dashboard': fail}), self.assertLogs(self.app.logger, level='ERROR') as recorded:
            response = self.client.get('/')
        self.assertEqual(response.status_code, 500)
        self.assertIn('RuntimeError', str(recorded.output))
        for content in (response.get_data(as_text=True), str(recorded.output)):
            self.assertNotIn('PrivateErrorPayload', content)
            self.assertNotIn('Traceback', content)

    def test_dast_persistence_masks_credentials_and_form_errors(self):
        scan, _ = self.seed()
        with self.app.app_context():
            finding = Finding(title='Credential test', severity='Low', confidence='High', category='Test', source='Website',
                              location='https://user:URLCredential-1209@localhost/', description='Test',
                              evidence='Authorization: Bearer OpaqueCredential-9182; password="AssignedCredential-8971"',
                              impact='Test', recommendation='Test')
            save_finding(get_db(), scan, finding)
            report_id = generate_report(scan, 'JSON')
            stored = str([tuple(row) for row in get_db().execute('SELECT * FROM findings')])
        with self.client.get(f'/reports/{report_id}/download') as response:
            exported = response.get_data(as_text=True)
        for content in (stored, exported):
            for secret in ('URLCredential-1209', 'OpaqueCredential-9182', 'AssignedCredential-8971'):
                self.assertNotIn(secret, content)
        response = self.client.post('/website-scan', data={'csrf_token': self.csrf, 'authorized': 'yes', 'action': 'start',
                                  'url': 'https://name:URLCredential-1209@localhost/'})
        self.assertEqual(response.status_code, 400)
        self.assertNotIn('URLCredential-1209', response.get_data(as_text=True))

    def test_session_key_symlink_short_key_and_permissions(self):
        with patch.dict(os.environ, {}, clear=True):
            folder = self.root/'keys'; folder.mkdir()
            key = secret_key(folder)
            self.assertEqual(secret_key(folder), key)
            self.assertEqual((folder/'.secret_key').stat().st_mode & 0o777, 0o600)
            (folder/'.secret_key').unlink()
            outside = self.root/'outside'; outside.write_text('a'*64)
            (folder/'.secret_key').symlink_to(outside)
            with self.assertRaises(OSError):
                secret_key(folder)
            (folder/'.secret_key').unlink(); (folder/'.secret_key').write_text('short')
            with self.assertRaises(RuntimeError):
                secret_key(folder)

    def test_archive_rejects_preexisting_destination(self):
        archive = self.root/'snapshot.zip'
        with zipfile.ZipFile(archive, 'w') as bundle:
            bundle.writestr('root/nested/file.py', 'eval(untrusted)')
        outside = self.root/'outside'; outside.mkdir()
        destination = self.root/'destination'; destination.mkdir()
        (destination/'nested').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ArchiveError):
            extract_archive(archive, destination)
        self.assertFalse((outside/'file.py').exists())

    def test_malformed_nmap_falls_back_without_shell(self):
        target = validate_target('http://127.0.0.1:5001/', True)
        with patch('scanner.port_scanner.shutil.which', return_value='/usr/local/bin/nmap'), \
             patch('scanner.port_scanner.run_tool') as process, \
             patch('scanner.port_scanner.connect_ip', side_effect=OSError):
            process.return_value = b'<nmaprun><host><ports><port portid="80"/></ports></host></nmaprun>'
            result = port_scan({'target': target, 'client': Client(target)})
        self.assertEqual(result['method'], 'TCP connect fallback')
        self.assertFalse(process.call_args.kwargs.get('shell', False))
        self.assertIn('127.0.0.1', process.call_args.args[0])

    def test_repository_module_failure_cleanup_and_queue_limit(self):
        def broken(ctx):
            raise RuntimeError('secret=FailureCredential-9817')
        modules = [(name, broken if name == 'Python' else fn) for name, fn in source_scanner.MODULES]
        with patch.object(source_scanner, 'MODULES', modules):
            response = self.client.post('/repository-scan', data={'csrf_token': self.csrf, 'action': 'start',
                                        'repository': REPO['full_name'], 'branch': 'main', 'authorized': 'yes'})
            self.assertEqual(response.status_code, 303)
            self.app.extensions['scan_manager'].executor.submit(lambda: None).result(timeout=10)
        with self.app.app_context():
            db = get_db()
            self.assertEqual(db.execute('SELECT status FROM scans').fetchone()[0], 'Completed')
            states = dict(db.execute('SELECT name,status FROM scan_modules'))
            self.assertEqual(states['Python'], 'Failed')
            self.assertEqual(states['JavaScript'], 'Completed')
            self.assertEqual(states['Dependencies'], 'Completed')
            self.assertNotIn('FailureCredential', str([tuple(row) for row in db.execute('SELECT * FROM scan_modules')]))
        self.assertFalse(FixtureGitHub.archive_path.parent.exists())
        manager = self.app.extensions['scan_manager']
        for _ in range(4):
            manager.slots.acquire()
        try:
            with self.assertRaises(QueueFull):
                manager.submit(validate_target('http://127.0.0.1/', True), [])
        finally:
            for _ in range(4):
                manager.slots.release()

    def test_retrieval_failure_cleans_temporary_files(self):
        def bad_archive(client, name, sha, destination):
            FixtureGitHub.archive_path = destination
            destination.write_bytes(b'not a zip')
        with patch.object(FixtureGitHub, 'archive', bad_archive):
            self.client.post('/repository-scan', data={'csrf_token': self.csrf, 'action': 'start',
                             'repository': REPO['full_name'], 'branch': 'main', 'authorized': 'yes'})
            self.app.extensions['scan_manager'].executor.submit(lambda: None).result(timeout=10)
        self.assertFalse(FixtureGitHub.archive_path.parent.exists())
        with self.app.app_context():
            self.assertEqual(get_db().execute('SELECT status FROM scans').fetchone()[0], 'Failed')

    def test_dashboard_trend_and_report_selection(self):
        scan, _ = self.seed()
        page = self.client.get('/').get_data(as_text=True)
        self.assertIn('SentinelScan Risk Score', page)
        self.assertIn('Not CVSS'.lower(), page.lower())
        self.assertIn(f'Scan {scan} · 17/100', page)
        page = self.client.get(f'/reports?scan_id={scan}').get_data(as_text=True)
        self.assertIn(f'value="{scan}" selected', page)
