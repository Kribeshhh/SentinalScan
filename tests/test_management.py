"""End-to-end management tests use real scanner output and isolated SQLite/report directories."""
import csv
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from flask import Flask,make_response
from werkzeug.serving import make_server,WSGIRequestHandler
from app import create_app
from database import get_db
from analysis.management import compare_scans,comparison_fingerprint,risk_trend
from reports.report_generator import generate_report
from test_source_scanner import FixtureGitHub,REPO,FAKE_AUTH


class Quiet(WSGIRequestHandler):
    def log(self,*args,**kwargs):
        pass


class ManagementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mode=0
        lab=Flask('management-test-lab')
        @lab.get('/')
        def index():
            response=make_response('<html><body>Authorized management test lab</body></html>')
            if cls.mode:
                response.headers['Content-Security-Policy']="default-src 'self'; frame-ancestors 'none'"
                response.set_cookie('new_lab_cookie','COOKIE_VALUE_NOT_FOR_REPORTS')
            return response
        cls.server=make_server('127.0.0.1',0,lab,threaded=True,request_handler=Quiet)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.target=f'http://127.0.0.1:{cls.server.server_port}/'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.config={'TESTING':True,'DATABASE':str(Path(self.temp.name)/'test.sqlite3'),'REPORTS_DIR':str(Path(self.temp.name)/'reports'),'SCANNER_CLIENT_OPTIONS':{'interval':0,'timeout':1},'GITHUB_CLIENT_FACTORY':FixtureGitHub}
        self.app=create_app(self.config);self.client=self.app.test_client();self.client.get('/')
        with self.client.session_transaction() as session:
            self.csrf=session['csrf_token']

    def tearDown(self):
        self.app.extensions['scan_manager'].shutdown();self.temp.cleanup()

    def website(self,mode=0):
        type(self).mode=mode
        with patch('scanner.port_scanner.shutil.which',return_value=None):
            response=self.client.post('/website-scan',data={'csrf_token':self.csrf,'action':'start','url':self.target,'authorized':'yes','allow_private':'yes','paths':'/robots.txt'})
            self.assertEqual(response.status_code,303)
            self.app.extensions['scan_manager'].executor.submit(lambda:None).result(timeout=10)
        return int(response.headers['Location'].rsplit('/',1)[1])

    def repository(self):
        response=self.client.post('/repository-scan',data={'csrf_token':self.csrf,'action':'start','repository':REPO['full_name'],'branch':'main','authorized':'yes'})
        self.assertEqual(response.status_code,303)
        self.app.extensions['scan_manager'].executor.submit(lambda:None).result(timeout=10)
        return int(response.headers['Location'].rsplit('/',1)[1])

    def test_real_scans_comparison_status_and_trends(self):
        previous=self.website(0);current=self.website(1)
        response=self.client.post('/comparisons',data={'csrf_token':self.csrf,'baseline':previous,'current':current})
        self.assertEqual(response.status_code,303)
        with self.app.app_context():
            db=get_db();comparison=json.loads(db.execute('SELECT summary_json FROM scan_comparisons').fetchone()[0])
            self.assertTrue(comparison['new']);self.assertTrue(comparison['resolved']);self.assertTrue(comparison['unchanged'])
            self.assertIn('Missing Content-Security-Policy',[item['finding']['title'] for item in comparison['resolved']])
            self.assertTrue(any('Cookie missing' in item['finding']['title'] for item in comparison['new']))
            self.assertIn('Missing Referrer-Policy',[item['finding']['title'] for item in comparison['unchanged']])
            finding=db.execute("SELECT id FROM findings WHERE scan_id=? AND severity='Low' LIMIT 1",(current,)).fetchone()[0]
            assessment=db.execute('SELECT assessment_risk FROM scans WHERE id=?',(current,)).fetchone()[0]
            before=db.execute('SELECT risk_score FROM scans WHERE id=?',(current,)).fetchone()[0]
        self.assertEqual(self.client.post(f'/findings/{finding}/status',data={'csrf_token':self.csrf,'status':'Resolved'}).status_code,303)
        with self.app.app_context():
            db=get_db();scan=db.execute('SELECT * FROM scans WHERE id=?',(current,)).fetchone()
            self.assertEqual(scan['assessment_risk'],assessment);self.assertLess(scan['risk_score'],before)
            self.assertEqual(len(risk_trend(db,current)),2)
            self.assertEqual(compare_scans(db,previous,current)['current_risk'],scan['risk_score'])
        for url in (response.headers['Location'],'/comparisons','/scans',f'/risk-trends?scan_id={current}'):
            self.assertEqual(self.client.get(url).status_code,200)
        self.assertIn('<svg',self.client.get('/risk-trends').get_data(as_text=True))

    def test_website_repository_reports_redaction_and_downloads(self):
        website=self.website();repository=self.repository()
        for scan_id in (website,repository):
            for output_format in ('HTML','JSON','CSV'):
                response=self.client.post('/reports/generate',data={'csrf_token':self.csrf,'scan_id':scan_id,'format':output_format})
                self.assertEqual(response.status_code,303)
                with self.app.app_context():
                    row=get_db().execute('SELECT * FROM reports ORDER BY id DESC LIMIT 1').fetchone()
                    report_id=row['id'];filename=row['file_path']
                self.assertRegex(filename,r'^report-[a-f0-9]{32}\.(html|json|csv)$')
                with self.client.get(f'/reports/{report_id}/download') as downloaded:
                    self.assertEqual(downloaded.status_code,200);self.assertIn('attachment',downloaded.headers['Content-Disposition'])
                    content=downloaded.get_data(as_text=True)
                for secret in (FAKE_AUTH,'COOKIE_VALUE_NOT_FOR_REPORTS','LocalLabCredential-83-not-valid','LocalFixtureSigningKey-47-not-valid'):
                    self.assertNotIn(secret,content)
                if output_format=='JSON':
                    report=json.loads(content)
                    self.assertEqual(report['scan']['id'],scan_id);self.assertTrue(report['findings'])
                    if scan_id==repository:
                        self.assertTrue(report['repository']['languages']);self.assertTrue(report['repository']['dependencies'])
                    else:
                        self.assertIn('Ports',[m['name'] for m in report['modules']])
                elif output_format=='CSV':
                    rows=list(csv.DictReader(io.StringIO(content)))
                    self.assertTrue(any(row['record_type']=='finding' for row in rows));self.assertTrue(any(row['record_type']=='module' for row in rows))
                    self.assertIn('confidence',rows[0])
                else:
                    self.assertIn('Executive summary',content);self.assertIn('Limitations',content)
                    with self.client.get(f'/reports/{report_id}/view') as viewed:
                        self.assertEqual(viewed.status_code,200);self.assertIn('sandbox',viewed.headers['Content-Security-Policy'])
        self.assertEqual(self.client.get('/reports').status_code,200)

    def test_filtering_search_and_history_counts(self):
        scan_id=self.website(1)
        with self.app.app_context():
            count=get_db().execute('SELECT COUNT(*) FROM findings WHERE scan_id=?',(scan_id,)).fetchone()[0]
        self.assertIn(str(count),self.client.get('/scans').get_data(as_text=True))
        result=self.client.get(f'/findings?scan_id={scan_id}&severity=Low&confidence=High&source=Website&status=Open&category=Cookie+Security&q=Cookie+missing').get_data(as_text=True)
        self.assertIn('Cookie missing Secure',result);self.assertNotIn('Missing Referrer-Policy</a>',result)
        self.assertIn('No matching findings',self.client.get('/findings?q=%25').get_data(as_text=True))
        for query in ('confidence=Unknown','scan_id=bad','category=Unknown','q='+'a'*201):
            self.assertEqual(self.client.get('/findings?'+query).status_code,400)

    def test_comparison_rejects_wrong_target_running_and_reverse(self):
        previous=self.website();current=self.website(1);repo=self.repository()
        with self.app.app_context():
            db=get_db()
            for ids in ((previous,repo),(current,previous),(current,current),(1,999999)):
                with self.assertRaises(ValueError):
                    compare_scans(db,*ids)
            db.execute("UPDATE scans SET status='Running' WHERE id=?",(current,));db.commit()
            with self.assertRaises(ValueError):
                compare_scans(db,previous,current)
        self.assertEqual(self.client.post('/comparisons',data={'baseline':previous,'current':current}).status_code,400)
        self.assertEqual(self.client.post('/reports/generate',data={'csrf_token':self.csrf,'scan_id':current,'format':'HTML'}).status_code,400)

    def test_source_fingerprint_ignores_ids_and_line_shifts(self):
        first={'source':'Repository','category':'Code Security','title':'Dynamic execution','location':'owner/repo/app.py:12','id':1}
        later=dict(first,id=200,location='owner/repo/app.py:48')
        self.assertEqual(comparison_fingerprint(first),comparison_fingerprint(later))
        self.assertNotEqual(comparison_fingerprint(first),comparison_fingerprint(dict(later,title='Different issue')))

    def test_report_snapshot_persistence_and_path_security(self):
        scan_id=self.website()
        with self.app.app_context():
            report_id=generate_report(scan_id,'JSON')
            finding=get_db().execute('SELECT id FROM findings LIMIT 1').fetchone()[0]
        self.client.post(f'/findings/{finding}/status',data={'csrf_token':self.csrf,'status':'Ignored'})
        restarted=create_app(self.config)
        try:
            with restarted.app_context():
                db=get_db();self.assertEqual(db.execute('SELECT status FROM findings WHERE id=?',(finding,)).fetchone()[0],'Ignored')
            with restarted.test_client().get(f'/reports/{report_id}/download') as response:
                self.assertEqual(response.status_code,200)
                report=json.loads(response.get_data(as_text=True))
                self.assertEqual(next(f for f in report['findings'] if f['id']==finding)['status'],'Open')
        finally:
            restarted.extensions['scan_manager'].shutdown()
        outside=Path(self.temp.name)/'outside.txt';outside.write_text('must not be served')
        with self.app.app_context():
            db=get_db()
            bad=db.execute("INSERT INTO reports(scan_id,format,file_path) VALUES (?,'JSON','../outside.txt')",(scan_id,)).lastrowid
            name='report-'+'a'*32+'.json'
            (Path(self.config['REPORTS_DIR'])/name).symlink_to(outside)
            link=db.execute("INSERT INTO reports(scan_id,format,file_path) VALUES (?,'JSON',?)",(scan_id,name)).lastrowid
            db.commit()
        for report in (bad,link,999999):
            self.assertEqual(self.client.get(f'/reports/{report}/download').status_code,404)
        self.assertEqual(self.client.get('/reports/../../outside.txt/download').status_code,404)

    def test_csv_formula_html_escaping_and_legacy_secret_masking(self):
        scan_id=self.website()
        with self.app.app_context():
            db=get_db()
            db.execute("UPDATE findings SET title=?,evidence=? WHERE scan_id=?",('=HYPERLINK("https://invalid") <script>alert(1)</script>','password="LegacyCredential-890123"',scan_id))
            db.execute("INSERT INTO scan_modules(scan_id,name,status,data_json) VALUES (?,'Legacy','Completed',?)",(scan_id,json.dumps({'api_key':'UnstructuredSecret-67890'})))
            db.commit();csv_id=generate_report(scan_id,'CSV');html_id=generate_report(scan_id,'HTML')
        with self.client.get(f'/reports/{csv_id}/download') as response:
            content=response.get_data(as_text=True)
            rows=list(csv.DictReader(io.StringIO(content)))
            self.assertTrue(next(row for row in rows if row['record_type']=='finding')['title'].startswith("'="))
            self.assertNotIn('LegacyCredential-890123',content);self.assertNotIn('UnstructuredSecret-67890',content)
        with self.client.get(f'/reports/{html_id}/download') as response:
            content=response.get_data(as_text=True)
            self.assertNotIn('<script>alert(1)</script>',content);self.assertIn('&lt;script&gt;',content)
