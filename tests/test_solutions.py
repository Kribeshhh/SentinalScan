"""Solutions remain contextual, escaped and available for historical findings."""
import ast
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest
from app import create_app
from analysis.finding_engine import Finding, save_finding
from analysis.solution_engine import solution_for
from database import get_db
from reports.report_generator import report_data, csv_document


def finding(title,category='Injection',source='Repository',location='owner/repo/app.py:3',evidence='Static analysis'):
    return dict(title=title,category=category,source=source,location=location,evidence=evidence)


class SolutionEngineTests(unittest.TestCase):
    def test_all_static_scanner_rules_have_guidance(self):
        for path in Path('scanner').rglob('*.py'):
            for call in ast.walk(ast.parse(path.read_text())):
                if not isinstance(call,ast.Call) or not isinstance(call.func,ast.Name): continue
                if call.func.id=='issue' and len(call.args)>4:
                    title,category=call.args[1],call.args[3];source='Website'
                elif call.func.id=='add' and len(call.args)>6:
                    title,category=call.args[3],call.args[4];source='Repository'
                else: continue
                if not all(isinstance(v,ast.Constant) and isinstance(v.value,str) for v in (title,category)): continue
                evidence='Parsed security setting session_cookie_secure is disabled.' if title.value=='Security control disabled in configuration' else ''
                result=solution_for(finding(title.value,category.value,source,evidence=evidence))
                with self.subTest(title=title.value):
                    self.assertTrue(result['matched']);self.assertTrue(result['examples'])
                    self.assertTrue(result['notes']);self.assertTrue(result['verification'])
                    for item in result['examples']:
                        if item['language'].startswith('Python'): ast.parse(item['code'])

    def test_language_context_dynamic_rules_and_unknown_fallback(self):
        java=solution_for(finding('Potential SQL injection in Java query',location='o/r/Test.java:20'))
        self.assertIn('PreparedStatement',java['examples'][0]['code'])
        python=solution_for(finding('Potential SQL injection in constructed query'))
        self.assertIn('(username,)',python['examples'][0]['code'])
        for title,category in [('Missing Content-Security-Policy','Security Headers'),('Cookie missing Secure: session','Cookie Security'),('Hardcoded credential','Secret Exposure'),('Vulnerable dependency: fake (FAKE-1)','Dependency')]:
            self.assertTrue(solution_for(finding(title,category))['matched'])
        fallback=solution_for(finding('Future rule','Future category'))
        self.assertFalse(fallback['matched']);self.assertEqual(fallback['examples'],[])

    def test_untrusted_evidence_is_never_inserted_into_examples(self):
        value='<script>alert(1)</script> ghp_'+'Ab98'*10
        result=solution_for(finding('Potential SQL Injection',source='Website',location=value,evidence=value))
        self.assertNotIn(value,json.dumps(result))
        self.assertTrue(any('DAST' in note for note in result['notes']))
        self.assertNotIn('99.99.99',json.dumps(solution_for(finding('Vulnerable dependency: package','Dependency'))))


class SolutionIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.app=create_app({'TESTING':True,'DATABASE':str(Path(self.temp.name)/'test.db'),'REPORTS_DIR':str(Path(self.temp.name)/'reports')})
        self.client=self.app.test_client()
        with self.app.app_context():
            db=get_db()
            with db:
                self.scan=db.execute("INSERT INTO scans(scan_type,target,status) VALUES ('Website','https://example.com','Completed')").lastrowid
            self.id=save_finding(db,self.scan,Finding(title='Potential SQL Injection',category='SQL Injection',source='Website',location='https://example.com',severity='Medium',confidence='Medium',description='Test finding',evidence='<script>alert(1)</script>',impact='Data exposure',recommendation='Use bound parameters.'))

    def tearDown(self):
        self.app.extensions['scan_manager'].shutdown();self.temp.cleanup()

    def test_historical_finding_page_and_scan_link(self):
        page=self.client.get(f'/findings/{self.id}').get_data(as_text=True)
        self.assertIn('Code solution',page);self.assertIn('Copy code',page)
        self.assertIn('SELECT id FROM users',page)
        self.assertNotIn('<script>alert(1)</script>',page)
        page=self.client.get(f'/scans/{self.scan}').get_data(as_text=True)
        self.assertIn('#code-solution',page)

    def test_reports_include_machine_readable_and_rendered_solution(self):
        with self.app.app_context():
            data=report_data(get_db(),self.scan)
            code=data['findings'][0]['solution']['examples'][0]['code']
            self.assertIn('(username,)',code)
            row=next(row for row in csv.DictReader(io.StringIO(csv_document(data))) if row['record_type']=='finding')
            self.assertEqual(json.loads(row['details_json'])['solution']['examples'][0]['code'],code)
        self.client.get('/')
        with self.client.session_transaction() as session: csrf=session['csrf_token']
        for fmt in ('HTML','JSON','CSV'):
            response=self.client.post('/reports/generate',data={'csrf_token':csrf,'scan_id':self.scan,'format':fmt})
            self.assertEqual(response.status_code,303)
            with self.app.app_context():
                report=get_db().execute('SELECT id FROM reports ORDER BY id DESC').fetchone()[0]
            response=self.client.get(f'/reports/{report}/download')
            self.assertEqual(response.status_code,200)
            self.assertIn('SELECT id FROM users',response.get_data(as_text=True))
            response.close()
