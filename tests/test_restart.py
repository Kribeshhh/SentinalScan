"""Verify persistence across actual HTTP server process restarts."""
import os
import json
import re
from http.cookiejar import CookieJar
from urllib.parse import urlencode
from contextlib import closing
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.error import URLError
from urllib.request import urlopen, build_opener, HTTPCookieProcessor

ROOT = Path(__file__).resolve().parents[1]


class ProcessRestartTests(unittest.TestCase):
    def test_restart_retains_records(self):
        with tempfile.TemporaryDirectory() as directory:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            env = dict(os.environ, SENTINELSCAN_DATA_DIR=directory)
            command = [sys.executable, "-c", f"from app import create_app, PrivateRequestHandler; create_app({{'REPORTS_DIR': {str(Path(directory) / "reports")!r}}}).run(host='127.0.0.1', port={port}, request_handler=PrivateRequestHandler)"]
            def start():
                process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    for _ in range(100):
                        if process.poll() is not None:
                            self.fail("Test server exited before startup")
                        try:
                            with urlopen(f"http://127.0.0.1:{port}/", timeout=1) as response:
                                self.assertEqual(response.status, 200)
                            return process
                        except URLError:
                            time.sleep(.05)
                    self.fail("Test server startup timed out")
                except BaseException:
                    stop(process)
                    raise
            def stop(process):
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            process = start()
            try:
                with closing(sqlite3.connect(Path(directory) / "sentinelscan.sqlite3")) as db:
                    db.execute("INSERT INTO repositories(name,location) VALUES (?,?)", ("restart-check", "test-only"))
                    scan_id = db.execute("INSERT INTO scans(scan_type,target,status) VALUES ('Website','http://restart.test/','Completed')").lastrowid
                    finding_id = db.execute("""INSERT INTO findings(scan_id,title,severity,confidence,category,source,location,description,evidence,impact,recommendation,fingerprint)
                        VALUES (?,'Restart test','Low','High','Test','Website','http://restart.test/','Test description','Test evidence','Test impact','Test recommendation','restart-test')""", (scan_id,)).lastrowid
                    db.commit()
                opener = build_opener(HTTPCookieProcessor(CookieJar()))
                base = f"http://127.0.0.1:{port}"
                with opener.open(f"{base}/findings/{finding_id}") as response:
                    csrf = re.search(r'name="csrf_token" value="([^"]+)"', response.read().decode()).group(1)
                with opener.open(f"{base}/findings/{finding_id}/status", urlencode({'csrf_token': csrf, 'status': 'Resolved'}).encode()) as response:
                    self.assertEqual(response.status, 200)
                with opener.open(f"{base}/reports/generate", urlencode({'csrf_token': csrf, 'scan_id': scan_id, 'format': 'JSON'}).encode()) as response:
                    self.assertEqual(response.status, 200)
                with closing(sqlite3.connect(Path(directory) / "sentinelscan.sqlite3")) as db:
                    report_id = db.execute('SELECT id FROM reports').fetchone()[0]
                before = (Path(directory) / ".secret_key").read_bytes()
            finally:
                stop(process)
            process = start()
            try:
                with closing(sqlite3.connect(Path(directory) / "sentinelscan.sqlite3")) as db:
                    self.assertEqual(db.execute("SELECT name FROM repositories").fetchone()[0], "restart-check")
                    self.assertEqual(db.execute('SELECT status FROM findings WHERE id=?', (finding_id,)).fetchone()[0], 'Resolved')
                with urlopen(f"{base}/reports/{report_id}/download") as response:
                    report = json.load(response)
                    self.assertEqual(report['findings'][0]['status'], 'Resolved')
                self.assertEqual(before, (Path(directory) / ".secret_key").read_bytes())
            finally:
                stop(process)


if __name__ == "__main__":
    unittest.main()
