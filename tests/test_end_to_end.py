"""Final HTTP workflow against a real Flask subprocess and an authorized loopback lab.
Only the GitHub network boundary is simulated; repository analyzers inspect real files.
"""
from contextlib import closing
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import build_opener, HTTPCookieProcessor
from werkzeug.serving import make_server, WSGIRequestHandler
from examples.lab_app import app as lab_app
from test_source_scanner import REPO, FAKE_AUTH

ROOT = Path(__file__).resolve().parents[1]


class Quiet(WSGIRequestHandler):
    def log(self, *args, **kwargs):
        pass


class EndToEndTests(unittest.TestCase):
    def test_full_http_workflow_and_process_restart(self):
        lab = make_server('127.0.0.1', 0, lab_app, threaded=True, request_handler=Quiet)
        thread = threading.Thread(target=lab.serve_forever, daemon=True)
        thread.start()
        process = None
        try:
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                with socket.socket() as probe:
                    probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
                base = f'http://127.0.0.1:{port}'
                opener = build_opener(HTTPCookieProcessor(CookieJar()))
                config = {'REPORTS_DIR': str(root/'reports'), 'SCANNER_CLIENT_OPTIONS': {'interval': 0, 'timeout': 1}}
                script = (f"import sys; sys.path.insert(0, {str(ROOT/'tests')!r}); "
                          "from test_source_scanner import FixtureGitHub; from app import create_app, PrivateRequestHandler; "
                          "from unittest.mock import patch; patch('scanner.port_scanner.shutil.which', return_value=None).start(); "
                          f"config={config!r}; config['GITHUB_CLIENT_FACTORY']=FixtureGitHub; "
                          f"create_app(config).run(host='127.0.0.1',port={port},request_handler=PrivateRequestHandler)")
                def get(path):
                    with opener.open(base+path, timeout=5) as response:
                        return response.read().decode()
                def start():
                    child = subprocess.Popen([sys.executable, '-c', script], cwd=ROOT,
                                             env=dict(os.environ, SENTINELSCAN_DATA_DIR=folder),
                                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    try:
                        for _ in range(100):
                            if child.poll() is not None:
                                self.fail('Application exited at startup')
                            try:
                                get('/'); return child
                            except URLError:
                                time.sleep(.05)
                        self.fail('Application did not start')
                    except BaseException:
                        child.terminate(); child.wait(timeout=5); raise
                def stop(child):
                    child.terminate(); child.wait(timeout=5)
                process = start()
                def post(path, **data):
                    form = get('/website-scan')
                    csrf = re.search(r'name="csrf_token" value="([^"]+)"', form).group(1)
                    with opener.open(base+path, urlencode(dict(data, csrf_token=csrf)).encode(), timeout=10) as response:
                        return response.url, response.read().decode()
                def wait_scan(url):
                    scan_id = int(url.rsplit('/', 1)[1])
                    for _ in range(200):
                        status = json.loads(get(f'/scans/{scan_id}/status'))['status']
                        if status in ('Completed', 'Failed'):
                            self.assertEqual(status, 'Completed'); return scan_id
                        time.sleep(.05)
                    self.fail('Scan did not finish')
                target = f'http://127.0.0.1:{lab.server_port}/?q=hello'
                first = wait_scan(post('/website-scan', action='start', url=target, authorized='yes', allow_private='yes')[0])
                with closing(sqlite3.connect(root/'sentinelscan.sqlite3')) as db:
                    rows = db.execute('SELECT severity,status FROM findings WHERE scan_id=?', (first,)).fetchall()
                    self.assertTrue(rows)
                    points = sum({'Critical':10,'High':7,'Medium':4,'Low':1,'Informational':0}[severity] for severity,status in rows)
                    self.assertEqual(db.execute('SELECT risk_score FROM scans WHERE id=?', (first,)).fetchone()[0], round(100*points/(points+50)))
                    finding = db.execute('SELECT id FROM findings WHERE scan_id=? LIMIT 1', (first,)).fetchone()[0]
                self.assertIn('Finding status updated.', post(f'/findings/{finding}/status', status='Resolved')[1])
                repository = wait_scan(post('/repository-scan', action='start', repository=REPO['full_name'], branch='main', authorized='yes')[0])
                self.assertIn('Dynamic Python code execution', get(f'/scans/{repository}'))
                self.assertNotIn(FAKE_AUTH, get(f'/scans/{repository}'))
                for output_format in ('HTML','JSON','CSV'):
                    self.assertIn('Report generated.', post('/reports/generate', scan_id=repository, format=output_format)[1])
                second = wait_scan(post('/website-scan', action='start', url=target, authorized='yes', allow_private='yes')[0])
                comparison_url, comparison_page = post('/comparisons', baseline=first, current=second)
                self.assertIn('UNCHANGED', comparison_page)
                self.assertIn('Risk change', comparison_page)
                with closing(sqlite3.connect(root/'sentinelscan.sqlite3')) as db:
                    tables = ('scans','findings','repositories','reports','scan_comparisons')
                    counts = {table: db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0] for table in tables}
                    self.assertEqual(counts['scans'], 3); self.assertEqual(counts['reports'], 3)
                    reports = db.execute('SELECT id FROM reports').fetchall()
                stop(process); process = None
                process = start()
                with closing(sqlite3.connect(root/'sentinelscan.sqlite3')) as db:
                    self.assertEqual(counts, {table: db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0] for table in tables})
                    self.assertEqual(db.execute('SELECT status FROM findings WHERE id=?', (finding,)).fetchone()[0], 'Resolved')
                    self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
                for report_id, in reports:
                    content = get(f'/reports/{report_id}/download')
                    self.assertTrue(content); self.assertNotIn(FAKE_AUTH, content)
                self.assertIn('UNCHANGED', get(comparison_url.removeprefix(base)))
                self.assertIn('SentinelScan Risk Score', get('/'))
        finally:
            if process is not None:
                process.terminate(); process.wait(timeout=5)
            lab.shutdown(); lab.server_close(); thread.join()
