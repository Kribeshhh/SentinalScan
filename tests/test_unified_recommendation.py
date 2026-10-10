"""One final recommendation across detail/editor and report consumers."""
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest
from bs4 import BeautifulSoup
from flask import render_template
from app import create_app
from database import get_db
from analysis.finding_engine import Finding,save_finding
from analysis.solution_engine import solution_for
from analysis.recommendation_composer import compose,final_solution
from analysis.llm_review import prepare,process
from analysis.ai_grounding import ACTION
from reports.report_generator import report_data,csv_document
from tests import test_source_accuracy
from tests.test_llm_review import response
from tests.test_llm_sast_dast import configuration


class ComposerTests(unittest.TestCase):
    def setUp(self):
        fixture=test_source_accuracy.SourceAccuracyTests();self.source=fixture.sql();self.finding=fixture.finding(self.source)
        self.base=solution_for(self.finding,self.source)
        snippet=self.base['before'];payload=prepare(self.finding,dict(excerpt=snippet,start_line=6,detected_line=6),solution=self.base)
        answer=response(original_code=snippet,suggested_code=self.base['examples'][0]['code'],remediation=ACTION)
        self.review=process(self.finding,payload,answer,self.source)

    def test_source_fix_off_on_and_dedup(self):
        off=compose(self.finding,self.base,self.review,False)
        on=compose(self.finding,self.base,self.review,True)
        self.assertFalse(off['ai_assisted']);self.assertTrue(on['ai_assisted']);self.assertEqual(on['validation_status'],'Passed')
        self.assertEqual(len(on['examples']),1);self.assertEqual(on['examples'][0]['code'].strip(),off['examples'][0]['code'].strip())
        self.assertEqual(on['what_to_change'],ACTION)
        self.assertNotIn('ai_assisted',self.base)

    def test_failed_unvalidated_and_malformed_review_fall_back(self):
        for review in (None,{},dict(self.review,validation={'status':'Failed'}),dict(self.review,validation={'status':'Not Available'}),dict(self.review,recommendation={'bad':'shape'})):
            result=compose(self.finding,self.base,review,True)
            self.assertFalse(result['ai_assisted']);self.assertEqual(result['examples'],self.base['examples'])

    def test_secret_yaml_and_false_positive_keep_safe_policy(self):
        f=dict(self.finding,category='Secret Exposure',location='o/r/settings.yaml:2',title='Potential embedded credential')
        base=solution_for(f,'service:\n password: "SuperSensitive987"')
        from analysis.ai_grounding import statements
        policy=statements(f);reply=response(reason=policy['reason'][0])
        reply['recommendation'].update(what_to_change=policy['what_to_change'][0],why=policy['why'][0])
        review=process(f,prepare(f,None),reply)
        result=compose(f,base,review,True)
        self.assertEqual(result['examples'],[]);self.assertNotIn('SuperSensitive987',json.dumps(result))
        self.assertTrue(any('rotate' in action.lower() for action in result['additional_actions']))
        dismissed=compose(dict(self.finding,status='False Positive'),solution_for(dict(self.finding,status='False Positive')),self.review,True)
        self.assertFalse(dismissed['ai_assisted']);self.assertFalse(dismissed['examples'])

    def test_website_backend_code_never_composes(self):
        f=dict(self.finding,source='Website',location='https://example.test',category='SQL Injection')
        result=compose(f,solution_for(f),self.review,True)
        self.assertFalse(result['ai_assisted']);self.assertEqual(result['example_type'],'illustrative');self.assertIn('Pseudocode',result['examples'][0]['language'])
        self.assertIn('backend implementation',result['unavailable'])
        self.assertEqual(result['validation_message'],'Requires implementation and re-scan.')


class UnifiedPageTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.app=create_app(dict(TESTING=True,DATABASE=str(Path(self.tmp.name)/'test.db'),REPORTS_DIR=str(Path(self.tmp.name)/'reports'),LLM_ENABLED=False))
        self.client=self.app.test_client();self.client.get('/')
        with self.client.session_transaction() as session:self.csrf=session['csrf_token']
        fixture=ComposerTests();fixture.setUp();self.repo_review=fixture.review
        self.ids={};self.scans={}
        with self.app.app_context():
            db=get_db()
            for source in ('Repository','Website'):
                with db:scan=db.execute("INSERT INTO scans(scan_type,target,status) VALUES (?,?,'Completed')",(source,'o/r' if source=='Repository' else 'https://example.test')).lastrowid
                f=dict(fixture.finding) if source=='Repository' else dict(title='Missing X-Content-Type-Options',category='Security Headers',source='Website',location='https://example.test',evidence='Header absent')
                f.update(severity='Low',confidence='High',description='Fixture finding',impact='Review exposure',recommendation='Base guidance')
                fid=save_finding(db,scan,Finding(**f));base=solution_for(f,fixture.source if source=='Repository' else None)
                with db:db.execute('INSERT OR REPLACE INTO finding_solutions VALUES (?,?)',(fid,json.dumps(base)))
                self.ids[source]=fid;self.scans[source]=scan
    def tearDown(self):self.app.extensions['scan_manager'].shutdown();self.tmp.cleanup()
    def save_review(self,source):
        with self.app.app_context():
            db=get_db();fid=self.ids[source];f=db.execute('SELECT * FROM findings WHERE id=?',(fid,)).fetchone()
            review=self.repo_review if source=='Repository' else process(f,{},configuration())
            with db:db.execute('INSERT OR REPLACE INTO ai_reviews(finding_id,data_json) VALUES (?,?)',(fid,json.dumps(review)))
    def page(self,source):
        response=self.client.get(f'/findings/{self.ids[source]}');self.assertEqual(response.status_code,200)
        soup=BeautifulSoup(response.data,'html.parser');section=soup.select_one('#recommendation')
        self.assertEqual(len(soup.select('#recommendation')),1)
        text=section.get_text();self.assertNotIn('Scanner Guidance',text);self.assertNotIn('AI-Assisted Suggested Fix',text)
        self.assertIn('Fix Confidence:',text)
        return section

    def refine_website(self):
        from analysis.llm_review import refine_finding
        with self.app.app_context():
            db=get_db()
            refine_finding(db,db.execute('SELECT * FROM findings WHERE id=?',(self.ids['Website'],)).fetchone(),self.app.config)
        return self.client.get(f'/findings/{self.ids["Website"]}')

    def test_five_required_display_states(self):
        for source in self.ids:
            self.save_review(source)
            self.app.config['LLM_ENABLED']=False
            section=self.page(source);self.assertNotIn('AI-assisted recommendation',section.get_text());self.assertIsNone(section.select_one('#ai-review'))
            self.app.config['LLM_ENABLED']=True
            section=self.page(source);self.assertIn('AI-assisted recommendation',section.get_text())
            self.assertEqual(len(section.select('button[data-copy-solution]')),2 if source=='Repository' else 1)
            if source=='Website':self.assertIn('Example Secure Pattern',section.get_text());self.assertNotIn('Suggested Source Fix',section.get_text())
        with self.app.app_context():
            db=get_db()
            with db:db.execute('DELETE FROM ai_reviews')
        def fail(*_):raise TimeoutError('private-provider-error')
        self.app.config['LLM_REVIEW_PROVIDER']=fail
        response=self.refine_website()
        self.assertIn(b'Recommended Fix',response.data);self.assertNotIn(b'private-provider-error',response.data)
        self.assertNotIn('AI-assisted recommendation',self.page('Website').get_text())

    def test_reports_export_final_only_and_respect_disabled(self):
        self.save_review('Repository');self.app.config['LLM_ENABLED']=True
        with self.app.app_context():
            data=report_data(get_db(),self.scans['Repository']);f=data['findings'][0]
            self.assertEqual(f['recommendation'],ACTION)
            self.assertTrue(f['solution']['ai_assisted']);self.assertNotIn('original_code',json.dumps(data))
            html=render_template('report_document.html',report=data)
            self.assertEqual(html.count(ACTION),1)
            self.assertIn('Recommendation Source: AI-assisted',html)
            row=next(row for row in csv.DictReader(io.StringIO(csv_document(data))) if row['record_type']=='finding')
            self.assertEqual(row['recommendation'],f['recommendation'])
            self.assertTrue(json.loads(row['details_json'])['solution']['ai_assisted'])
            self.app.config['LLM_ENABLED']=False
            self.assertFalse(report_data(get_db(),self.scans['Repository'])['findings'][0]['solution']['ai_assisted'])

    def test_failed_refresh_uses_base_without_deleting_previous_review(self):
        self.save_review('Website');self.app.config['LLM_ENABLED']=True
        with self.app.app_context():previous=get_db().execute('SELECT data_json FROM ai_reviews').fetchone()[0]
        def fail(*_):raise TimeoutError()
        self.app.config['LLM_REVIEW_PROVIDER']=fail
        self.refine_website()
        self.assertNotIn('AI-assisted recommendation',self.page('Website').get_text())
        with self.app.app_context():
            self.assertEqual(previous,get_db().execute('SELECT data_json FROM ai_reviews').fetchone()[0])
            self.assertFalse(report_data(get_db(),self.scans['Website'])['findings'][0]['solution']['ai_assisted'])
        self.app.config['LLM_REVIEW_PROVIDER']=lambda *_:configuration()
        self.refine_website()
        self.assertIn('AI-assisted recommendation',self.page('Website').get_text())

    def test_composed_text_escaped_and_does_not_change_detection(self):
        self.save_review('Repository');self.app.config['LLM_ENABLED']=True
        with self.app.app_context():
            db=get_db();row=db.execute('SELECT data_json FROM ai_reviews').fetchone();review=json.loads(row[0]);review['recommendation']['what_to_change']='<script>bad()</script>'
            with db:db.execute('UPDATE ai_reviews SET data_json=?',(json.dumps(review),))
            before=tuple(db.execute('SELECT * FROM findings WHERE id=?',(self.ids['Repository'],)).fetchone())
        section=self.page('Repository');self.assertIsNone(section.find('script'));self.assertNotIn('<script>bad()</script>',section.get_text());self.assertNotIn('AI-assisted recommendation',section.get_text())
        with self.app.app_context():self.assertEqual(before,tuple(get_db().execute('SELECT * FROM findings WHERE id=?',(self.ids['Repository'],)).fetchone()))

class ExamplePatternTests(unittest.TestCase):
    def compose(self,title,category='Injection',path='app.py',source='Repository',evidence='',**extra):
        f=dict(title=title,category=category,location='o/r/'+path+':2',source=source,evidence=evidence,status='Open',**extra)
        return compose(f,solution_for(f))

    def test_unknown_source_gets_example_not_replacement(self):
        result=self.compose('Potential SQL injection in constructed query')
        self.assertEqual(result['example_type'],'illustrative')
        self.assertEqual(result['examples'][0]['kind'],'Example Secure Pattern')
        self.assertIn('Pseudocode',result['examples'][0]['language'])
        self.assertFalse(result['exact']);self.assertFalse(result['source_matched'])
        self.assertEqual(result['validation_status'],'Not Available');self.assertEqual(result['fix_confidence'],'Low')
        self.assertIsNone(result.get('before'));self.assertIn('not detected',result['examples'][0]['note'])
        command=self.compose('Potential shell command injection')
        self.assertIn('shell=False',command['examples'][0]['code'])

    def test_dependency_recorded_fixed_release_and_unknown_placeholder(self):
        data={'package':'sanitize-html','ecosystem':'npm','version':'1.0.0','id':'GHSA-fixture','affected':[{'ranges':[{'type':'SEMVER','events':[{'introduced':'0'},{'fixed':'1.11.4'}]}]}]}
        result=self.compose('Vulnerable dependency: sanitize-html','Dependency','package.json',evidence=json.dumps(data))
        self.assertEqual(json.loads(result['examples'][0]['code'])['dependencies']['sanitize-html'],'1.11.4')
        self.assertIn('this advisory only',result['examples'][0]['note'])
        data.pop('affected')
        unknown=self.compose('Vulnerable dependency: sanitize-html','Dependency','package.json',evidence=json.dumps(data))
        self.assertIn('<verified-safe-version>',unknown['examples'][0]['code'])
        self.assertNotIn('1.11.4',json.dumps(unknown));self.assertIn('Placeholder only',unknown['examples'][0]['note'])
        data.update(ecosystem='PyPI',package='example-library')
        self.assertEqual(self.compose('Vulnerable dependency','Dependency','requirements.txt',evidence=json.dumps(data))['examples'][0]['code'],'example-library==<verified-safe-version>')

    def test_overlapping_ranges_do_not_claim_fixed_release(self):
        data={'package':'example','ecosystem':'npm','version':'1.0.0','affected':[{'ranges':[{'type':'SEMVER','events':[{'introduced':'0'},{'fixed':'2.0.0'}]},{'type':'SEMVER','events':[{'introduced':'1.0.0'}]}]}]}
        result=self.compose('Vulnerable dependency','Dependency','package.json',evidence=json.dumps(data))
        self.assertIn('<verified-safe-version>',result['examples'][0]['code'])

    def test_website_generic_secret_redaction_and_operational_fallback(self):
        result=self.compose('Potential SQL Injection',source='Website')
        self.assertEqual(result['example_type'],'illustrative')
        self.assertIn('Pseudocode',result['examples'][0]['language'])
        self.assertNotIn('sqlite',json.dumps(result).lower());self.assertNotIn('flask',json.dumps(result).lower())
        secret=self.compose('Potential embedded credential','Secret Exposure',evidence='password="PrivateFixture987"')
        self.assertIn('os.environ',secret['examples'][0]['code']);self.assertNotIn('PrivateFixture987',json.dumps(secret))
        self.assertTrue(any('rotate' in n for n in secret['notes']))
        self.assertFalse(self.compose('TLS certificate expires soon','TLS',source='Website')['examples'])
        self.assertFalse(self.compose('Future rule','Future category')['examples'])
