"""Single-worker, bounded in-process job queue with durable scan/module records."""
from concurrent.futures import ThreadPoolExecutor
import json
import sqlite3
import threading
from datetime import datetime, timezone
from database import get_db
from analysis.finding_engine import save_finding
from analysis.redaction import scrub
from analysis.risk_engine import calculate_risk
from scanner import dns_scanner, port_scanner, header_scanner, cookie_scanner, tls_scanner, technology_scanner, directory_scanner, cors_scanner, xss_scanner, sqli_scanner, disclosure_scanner
from scanner.http_scanner import Client, observation, RequestFailure, ScanLimit
from scanner.common import SkipModule


def http_run(ctx):
    response = ctx['client'].get(ctx['target'].url)
    ctx['response'] = response
    return observation(response)


MODULES = [('DNS',dns_scanner.run), ('Ports',port_scanner.run), ('HTTP',http_run),
           ('Security headers',header_scanner.run), ('Cookies',cookie_scanner.run),
           ('TLS',tls_scanner.run), ('Technologies',technology_scanner.run),
           ('Resources',directory_scanner.run), ('CORS',cors_scanner.run),
           ('Reflected XSS',xss_scanner.run), ('SQL injection',sqli_scanner.run),
           ('Information disclosure',disclosure_scanner.run)]


class QueueFull(ValueError):
    pass


def now():
    return datetime.now(timezone.utc).isoformat()


class ScanManager:
    def __init__(self, app):
        self.app = app
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='sentinelscan')
        self.slots = threading.BoundedSemaphore(4)
        with app.app_context():
            db = get_db()
            with db:
                db.execute("UPDATE scan_modules SET status='Failed', error='Interrupted by application restart.' WHERE scan_id IN (SELECT id FROM scans WHERE status IN ('Queued','Running')) AND status IN ('Queued','Running')")
                db.execute("UPDATE scans SET status='Failed', error='Interrupted by application restart. Start a new scan to retry.', completed_at=? WHERE status IN ('Queued','Running')", (now(),))

    def submit(self, target, paths):
        if not self.slots.acquire(blocking=False):
            raise QueueFull('The scan queue is full. Wait for a scan to finish and retry.')
        try:
            db = get_db()
            with db:
                result = db.execute("INSERT INTO scans(scan_type,target,status,options_json) VALUES ('Website',?,'Queued',?)", (target.display, json.dumps({'private_lab':target.allow_private,'paths':paths,'authorized':True,'request_limit':60,'response_byte_limit':262144,'scan_seconds':150,'http_concurrency':1,'minimum_request_interval_seconds':.2})))
                scan_id = result.lastrowid
                db.executemany("INSERT INTO scan_modules(scan_id,name) VALUES (?,?)", [(scan_id,name) for name,_ in MODULES])
            self.executor.submit(self.run, scan_id, target, paths)
            return scan_id
        except Exception:
            self.slots.release()
            raise

    def run(self, scan_id, target, paths):
        try:
            with self.app.app_context():
                db = get_db()
                try:
                    with db:
                        db.execute("UPDATE scans SET status='Running', started_at=? WHERE id=?",(now(),scan_id))
                    options = self.app.config.get('SCANNER_CLIENT_OPTIONS', {})
                    ctx = {'target':target,'paths':paths,'client':Client(target, **options),'findings':[]}
                    for index,(name, module) in enumerate(MODULES):
                        with db:
                            db.execute("UPDATE scan_modules SET status='Running' WHERE scan_id=? AND name=?", (scan_id,name))
                        start = len(ctx['findings'])
                        data, error, status = {}, None, 'Completed'
                        try:
                            ctx['client'].remaining()
                            data = module(ctx)
                        except SkipModule as exc:
                            status, error = 'Skipped', str(exc)
                        except (RequestFailure, ScanLimit) as exc:
                            status, error = 'Failed', str(exc)
                        except Exception:
                            status, error = 'Failed', 'Module could not complete; other checks continue.'
                        # Retain verified evidence collected before an individual module failed.
                        for finding in ctx['findings'][start:]:
                            try:
                                save_finding(db, scan_id, finding)
                            except sqlite3.IntegrityError:
                                pass  # Per-scan fingerprints deduplicate repeated evidence.
                        with db:
                            db.execute("UPDATE scan_modules SET status=?,data_json=?,error=? WHERE scan_id=? AND name=?", (status,json.dumps(scrub(data)),scrub(error),scan_id,name))
                            rows = db.execute("SELECT severity,status FROM findings WHERE scan_id=?", (scan_id,)).fetchall()
                            db.execute("UPDATE scans SET progress=?,risk_score=? WHERE id=?",(round((index+1)*100/len(MODULES)),calculate_risk(rows),scan_id))
                    all_rows = [dict(row, status='Open') for row in db.execute('SELECT severity FROM findings WHERE scan_id=?',(scan_id,))]
                    with db:
                        db.execute('UPDATE scans SET assessment_risk=? WHERE id=?',(calculate_risk(all_rows),scan_id))
                    completed = ctx.get('response') is not None
                    message = None if completed else 'The baseline HTTP request failed. Partial observations and any TLS findings are retained.'
                    with db:
                        db.execute("UPDATE scans SET status=?, completed_at=?,error=? WHERE id=?", ('Completed' if completed else 'Failed', now(),message,scan_id))
                except Exception:
                    db.rollback()
                    with db:
                        db.execute("UPDATE scans SET status='Failed',error='Scan could not finish. Partial results are retained.',completed_at=? WHERE id=?",(now(),scan_id))
                        db.execute("UPDATE scan_modules SET status='Failed',error='Scan interrupted.' WHERE scan_id=? AND status IN ('Queued','Running')",(scan_id,))
        finally:
            self.slots.release()

    def submit_repository(self, github, metadata, branch, sha, osv_enabled):
        from scanner.source_scanner import MODULE_NAMES
        if not self.slots.acquire(blocking=False):
            raise QueueFull('The scan queue is full. Wait for a scan to finish and retry.')
        try:
            db = get_db()
            safe = scrub(metadata)
            with db:
                repo_id = db.execute("INSERT INTO repositories(name,location,owner,url,branch,commit_sha) VALUES (?,?,?,?,?,?)",
                    (safe['name'],safe['url'],safe['owner'],safe['url'],scrub(branch),sha)).lastrowid
                scan_id = db.execute("INSERT INTO scans(scan_type,target,status,repository_id,options_json) VALUES ('Repository',?,'Queued',?,?)",
                    (safe['full_name']+' @ '+scrub(branch),repo_id,json.dumps({'branch':scrub(branch),'commit':sha,'osv_enabled':osv_enabled,'authorized':True}))).lastrowid
                db.execute('UPDATE repositories SET scan_id=? WHERE id=?',(scan_id,repo_id))
                db.executemany('INSERT INTO scan_modules(scan_id,name) VALUES (?,?)',[(scan_id,name) for name in MODULE_NAMES])
            self.executor.submit(self.run_repository,scan_id,github,metadata,branch,sha,osv_enabled)
            return scan_id
        except Exception:
            self.slots.release()
            raise

    def run_repository(self, *args):
        from scanner.source_scanner import run_repository
        try:
            run_repository(self.app,*args)
        finally:
            self.slots.release()

    def shutdown(self):
        self.executor.shutdown(wait=True)
