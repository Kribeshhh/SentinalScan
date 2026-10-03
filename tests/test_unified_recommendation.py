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
from reports.report_generator import report_data,csv_document
from tests import test_source_accuracy
from tests.test_llm_review import response
from tests.test_llm_sast_dast import configuration


class ComposerTests(unittest.TestCase):
    def setUp(self):
        fixture=test_source_accuracy.SourceAccuracyTests();self.source=fixture.sql();self.finding=fixture.finding(self.source)
        self.base=solution_for(self.finding,self.source)
        snippet=self.base['before'];payload=prepare(self.finding,dict(excerpt=snippet,start_line=6,detected_line=6),solution=self.base)
        answer=response(original_code=snippet,suggested_code=self.base['examples'][0]['code'],remediation='Bind email at the existing SQLite execute call.')
        answer['recommendation'].update(why='Binding email separately prevents it from changing the SQL structure.',additional_actions=['Test ordinary emails and quote characters using the same SQLite connection.'])
        self.review=process(self.finding,payload,answer,self.source)

    def test_source_fix_off_on_and_dedup(self):
        off=compose(self.finding,self.base,self.review,False)
        on=compose(self.finding,self.base,self.review,True)
        self.assertFalse(off['ai_assisted']);self.assertTrue(on['ai_assisted']);self.assertEqual(on['validation_status'],'Passed')
        self.assertEqual(len(on['examples']),1);self.assertEqual(on['examples'][0]['code'].strip(),off['examples'][0]['code'].strip())
        self.assertEqual(on['what_to_change'],'Bind email at the existing SQLite execute call.')
        self.assertNotIn('ai_assisted',self.base)

    def test_failed_unvalidated_and_malformed_review_fall_back(self):
        for review in (None,{},dict(self.review,validation={'status':'Failed'}),dict(self.review,validation={'status':'Not Available'}),dict(self.review,recommendation={'bad':'shape'})):
            result=compose(self.finding,self.base,review,True)
            self.assertFalse(result['ai_assisted']);self.assertEqual(result['examples'],self.base['examples'])

    def test_secret_yaml_and_false_positive_keep_safe_policy(self):
        f=dict(self.finding,category='Secret Exposure',location='o/r/settings.yaml:2',title='Potential embedded credential')
        base=solution_for(f,'service:\n password: "SuperSensitive987"')
        review=process(f,prepare(f,None),response(remediation='Load credentials securely at runtime.'))
        result=compose(f,base,review,True)
        self.assertEqual(result['examples'],[]);self.assertNotIn('SuperSensitive987',json.dumps(result))
        self.assertTrue(any('rotate' in action.lower() for action in result['additional_actions']))
        dismissed=compose(dict(self.finding,status='False Positive'),solution_for(dict(self.finding,status='False Positive')),self.review,True)
        self.assertFalse(dismissed['ai_assisted']);self.assertFalse(dismissed['examples'])

    def test_website_backend_code_never_composes(self):
        f=dict(self.finding,source='Website',location='https://example.test',category='SQL Injection')
        result=compose(f,solution_for(f),self.review,True)
        self.assertFalse(result['ai_assisted']);self.assertFalse(result['examples'])
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

    def test_five_required_display_states(self):
        for source in self.ids:
            self.save_review(source)
            self.app.config['LLM_ENABLED']=False
            section=self.page(source);self.assertNotIn('AI-assisted recommendation',section.get_text());self.assertIsNone(section.select_one('#ai-review'))
            self.app.config['LLM_ENABLED']=True
            section=self.page(source);self.assertIn('AI-assisted recommendation',section.get_text())
            self.assertEqual(len(section.select('button[data-copy-solution]')),1)
            if source=='Website':self.assertIn('Configuration Example',section.get_text());self.assertNotIn('Suggested Source Fix',section.get_text())
        with self.app.app_context():
            db=get_db()
            with db:db.execute('DELETE FROM ai_reviews')
        def fail(*_):raise TimeoutError('private-provider-error')
        self.app.config['LLM_REVIEW_PROVIDER']=fail
        response=self.client.post(f'/findings/{self.ids["Website"]}/ai-review',data={'csrf_token':self.csrf,'share_context':'yes'},follow_redirects=True)
        self.assertIn(b'Deterministic guidance remains',response.data);self.assertNotIn(b'private-provider-error',response.data)
        self.assertNotIn('AI-assisted recommendation',self.page('Website').get_text())

    def test_reports_export_final_only_and_respect_disabled(self):
        self.save_review('Repository');self.app.config['LLM_ENABLED']=True
        with self.app.app_context():
            data=report_data(get_db(),self.scans['Repository']);f=data['findings'][0]
            self.assertEqual(f['recommendation'],'Bind email at the existing SQLite execute call.')
            self.assertTrue(f['solution']['ai_assisted']);self.assertNotIn('original_code',json.dumps(data))
            html=render_template('report_document.html',report=data)
            self.assertEqual(html.count('Bind email at the existing SQLite execute call.'),1)
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
        self.client.post(f'/findings/{self.ids["Website"]}/ai-review',data={'csrf_token':self.csrf,'share_context':'yes'})
        self.assertNotIn('AI-assisted recommendation',self.page('Website').get_text())
        with self.app.app_context():
            self.assertEqual(previous,get_db().execute('SELECT data_json FROM ai_reviews').fetchone()[0])
            self.assertFalse(report_data(get_db(),self.scans['Website'])['findings'][0]['solution']['ai_assisted'])
        self.app.config['LLM_REVIEW_PROVIDER']=lambda *_:configuration()
        self.client.post(f'/findings/{self.ids["Website"]}/ai-review',data={'csrf_token':self.csrf,'share_context':'yes'})
        self.assertIn('AI-assisted recommendation',self.page('Website').get_text())

    def test_composed_text_escaped_and_does_not_change_detection(self):
        self.save_review('Repository');self.app.config['LLM_ENABLED']=True
        with self.app.app_context():
            db=get_db();row=db.execute('SELECT data_json FROM ai_reviews').fetchone();review=json.loads(row[0]);review['recommendation']['what_to_change']='<script>bad()</script>'
            with db:db.execute('UPDATE ai_reviews SET data_json=?',(json.dumps(review),))
            before=tuple(db.execute('SELECT * FROM findings WHERE id=?',(self.ids['Repository'],)).fetchone())
        section=self.page('Repository');self.assertIsNone(section.find('script'));self.assertIn('<script>bad()</script>',section.get_text())
        with self.app.app_context():self.assertEqual(before,tuple(get_db().execute('SELECT * FROM findings WHERE id=?',(self.ids['Repository'],)).fetchone()))
