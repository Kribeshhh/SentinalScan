"""Recommendation policy and rendered structure, with isolated finding records."""
import json
from pathlib import Path
import tempfile
import unittest
from bs4 import BeautifulSoup
from app import create_app
from database import get_db
from analysis.finding_engine import Finding,save_finding
from analysis.solution_engine import solution_for
from analysis.recommendation import recommendation_for,source_metadata


def finding(title='Hardcoded credential',category='Secret Exposure',file='settings.json',**extra):
    return dict(title=title,category=category,source='Repository',location='owner/repo/'+file+':2',evidence='Pattern detected; value [REDACTED].',**extra)


class RecommendationPolicyTests(unittest.TestCase):
    def test_secret_language_and_runtime_uncertainty(self):
        for extension in ('json','yaml','yml','env','properties','js','jsx'):
            with self.subTest(extension=extension):
                result=solution_for(finding(file='config.'+extension))
                self.assertEqual(result['examples'],[])
                self.assertIn('runtime',result['action'])
                self.assertTrue(any('rotate' in n for n in result['notes']))
        for extension,label in [('py','Python'),('java','Java'),('cjs','JavaScript / Node.js')]:
            result=solution_for(finding(file='config.'+extension))
            self.assertEqual(result['examples'],[])
            self.assertEqual(result['kind'],'Remediation guidance')
            self.assertEqual(result['fix_confidence'],'Low')

    def test_unknown_database_and_command_do_not_invent_replacement(self):
        for title in ('Potential SQL injection in constructed query','Potential shell command injection','Dynamic Java process execution'):
            result=solution_for(finding(title,'Injection','app.py'))
            self.assertEqual(result['examples'],[]);self.assertFalse(result['exact'])
            self.assertIn('manual review required',result['unavailable'])
        result=solution_for(finding('Potential SQL injection in constructed query','Injection','app.py'), 'import psycopg\ncursor.execute(query)')
        self.assertNotIn('sqlite',json.dumps(result).lower())

    def test_checksum_does_not_get_password_recipe(self):
        result=solution_for(finding('Weak hash algorithm usage','Cryptography','app.py',severity='Low'))
        self.assertEqual(result['examples'],[])
        self.assertIn('checksum may need no change',result['action'])
        result=solution_for(dict(finding('Weak hash algorithm usage','Cryptography','app.py',severity='High'),evidence='security-sensitive naming/context detected'))
        self.assertIn('password-hashing',result['action'])

    def test_source_match_and_context_metadata(self):
        f=finding('Potential unsafe DOM HTML assignment','Injection','app.js')
        result=solution_for(f,'function show(value) {\n  node.innerHTML = value;\n}')
        self.assertEqual(result['metadata']['function'],'show')
        self.assertEqual(result['kind'],'Suggested Source Fix')
        self.assertTrue(result['exact']);self.assertEqual(result['fix_confidence'],'Medium')
        self.assertIn('plain text',result['action']);self.assertIn('intentional HTML',result['action'])
        self.assertEqual(source_metadata(f)['function'],'Could not be determined statically')

    def test_old_snapshot_policy_and_unknown_rule(self):
        old={'examples':[{'language':'Python','code':'import os\n'}],'exact':False,'context':'   2 > password: [REDACTED]'}
        result=recommendation_for(finding(),old)
        self.assertEqual(result['examples'],[]);self.assertEqual(result['context'],old['context'])
        result=solution_for(finding('Future rule','Future category',recommendation='Inspect custom authorization.'))
        self.assertEqual(result['action'],'Inspect custom authorization.')


class FindingQualityPageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.app=create_app({'TESTING':True,'DATABASE':str(Path(self.temp.name)/'quality.db')})
        self.client=self.app.test_client()
        with self.app.app_context():
            db=get_db()
            with db:self.scan=db.execute("INSERT INTO scans(scan_type,target,status) VALUES ('Repository','owner/repo','Completed')").lastrowid

    def tearDown(self):
        self.app.extensions['scan_manager'].shutdown();self.temp.cleanup()

    def page(self,f,solution=None):
        with self.app.app_context():
            db=get_db();fid=save_finding(db,self.scan,Finding(**dict(f,severity='Medium',confidence='High',description='Static analysis',impact='Potential data exposure',recommendation='Review affected code.')))
            if solution:
                with db:db.execute('INSERT INTO finding_solutions VALUES (?,?)',(fid,json.dumps(solution)))
        response=self.client.get('/findings/'+str(fid));self.assertEqual(response.status_code,200)
        return BeautifulSoup(response.data,'html.parser'),response.get_data(as_text=True)

    def test_solution_is_inside_recommendation_once_and_escaped(self):
        f=finding('Potential unsafe DOM HTML assignment','Injection','app.js')
        solution=solution_for(f,'function show(value) {\n node.innerHTML = value;\n // <script>alert(1)</script>\n}')
        soup,html=self.page(f,solution)
        recommendation=soup.select_one('#recommendation')
        self.assertEqual(len(soup.select('#recommendation')),1)
        self.assertIn('Recommended Code',recommendation.get_text())
        self.assertTrue(recommendation.select('pre code'))
        self.assertEqual(len(recommendation.select('.detected-line')),1)
        self.assertNotIn('<script>alert(1)</script>',html)
        self.assertIn('&lt;script&gt;',html)
        self.assertNotIn('Code solution',[h.get_text() for h in soup.select('h2')])
        self.assertIn('Fingerprint',soup.select_one('details.technical-details').get_text())
        self.assertIn('Detection Confidence',html);self.assertIn('Fix Confidence: Medium',html)
        self.assertFalse(soup.select('a[href$="/edit"]'))

    def test_unknown_solution_and_redacted_historical_secret(self):
        soup,html=self.page(finding(),{'examples':[{'language':'Python','code':'credential = "should-not-display"'}],'exact':False,'context':'   2 > password: [REDACTED]'})
        self.assertIn('[REDACTED]',html);self.assertNotIn('should-not-display',html)
        self.assertIn('manual review required',soup.select_one('#recommendation').get_text())
        self.assertFalse(soup.select_one('#recommendation').select('button[data-copy-solution]'))
        soup,html=self.page(finding('Future rule','Future category'))
        self.assertIn('Review affected code.',html)

    def test_structured_flow_and_unknown_source_are_honest(self):
        f=finding('Potential SQL injection in constructed query','Injection','app.py')
        f['evidence']='Dynamic value; original input source unknown → query → SQL execute. No protection recognized for this operation; static analysis does not prove exploitability.'
        soup,html=self.page(f)
        self.assertIn('Input source could not be determined statically.',html)
        self.assertIn('Dynamically constructed SQL reaches',html)
        self.assertIn('No parameterized query was recognized',html)
        self.assertIn('Not recorded',html)

    def test_static_validation_label_is_inside_recommendation(self):
        f=finding('Potential unsafe DOM HTML assignment','Injection','app.js')
        solution=solution_for(f,'function render(value) {\n view.innerHTML = value;\n}')
        soup,html=self.page(f,solution)
        recommendation=soup.select_one('#recommendation')
        self.assertIn('Static validation passed',recommendation.get_text())
        self.assertNotIn('Vulnerability fixed',html)
        self.assertIn('Illustrative Secure Example · JavaScript · option B',recommendation.get_text())

    def test_action_precedes_collapsed_evidence_and_checklist(self):
        f=finding('Potential unsafe DOM HTML assignment','Injection','app.js')
        solution=solution_for(f,'function render(value) {\n view.innerHTML = value;\n}')
        soup,html=self.page(f,solution)
        self.assertLess(html.index('id="recommendation"'),html.index('id="technical-details"'))
        self.assertIsNone(soup.select_one('.fix-summary').find_parent('details'))
        self.assertIsNone(soup.select_one('.fix-checks').find_parent('details'))
        self.assertFalse(soup.select_one('#technical-details').has_attr('open'))
        self.assertTrue(soup.select_one('#technical-details .current-source'))
        self.assertTrue(soup.select_one('.primary-fix.suggested-fix'))
        checklist=soup.find('h3',string='Validation and follow-up').find_parent('details')
        self.assertFalse(checklist.has_attr('open'))

    def test_secret_rotation_not_hidden_in_disclosure(self):
        soup,_=self.page(finding())
        notes=soup.select_one('#recommendation .solution-notes')
        self.assertIn('rotate',notes.get_text())
        self.assertIsNone(notes.find_parent('details'))

    def test_dependency_example_inside_existing_card_for_historical_snapshot(self):
        f=finding('Vulnerable dependency: sanitize-html','Dependency','package.json')
        f['evidence']=json.dumps({'package':'sanitize-html','ecosystem':'npm','version':'1.0.0','id':'GHSA-example'})
        soup,html=self.page(f,{'examples':[],'exact':False,'matched':True,'action':'Upgrade after checking compatibility.'})
        self.assertEqual(len(soup.select('#recommendation')),1)
        primary=soup.select_one('#recommendation .primary-fix')
        self.assertIn('Example Secure Pattern',primary.get_text())
        self.assertIn('not the repository',primary.get_text())
        self.assertIn('<verified-safe-version>',primary.get_text())
        self.assertNotIn('Replace your code',primary.get_text())
        self.assertIn('&lt;verified-safe-version&gt;',html)
        self.assertIn('Fix Confidence: Low',soup.select_one('#recommendation').get_text())

    def test_actual_source_and_validated_fix_render_together(self):
        f=finding('Potential unsafe DOM HTML assignment','Injection','app.js')
        s=solution_for(f,'function show(value) {\n node.innerHTML = value;\n}')
        soup,_=self.page(f,s)
        pair=soup.select_one('#recommendation .code-comparison')
        self.assertIsNotNone(pair);self.assertIsNone(pair.find_parent('details'))
        self.assertEqual(pair.select_one('.current-code code').get_text(),s['before'])
        self.assertIn('textContent',pair.select_one('.primary-fix code').get_text())
        self.assertIn('Current Code',pair.get_text());self.assertIn('Recommended Code',pair.get_text())
        self.assertEqual(len(pair.select('[data-copy-solution]')),2)
        self.assertEqual(len(soup.select('#recommendation')),1)
        self.assertFalse(soup.select_one('a[href$="/edit"]'))

    def test_dependency_pair_requires_retained_entry_and_supported_fixed_version(self):
        f=finding('Vulnerable dependency: sanitize-html','Dependency','package.json')
        f['evidence']=json.dumps({'package':'sanitize-html','ecosystem':'npm','version':'1.10.0','affected':[{'ranges':[{'type':'SEMVER','events':[{'introduced':'0'},{'fixed':'1.11.4'}]}]}]})
        source='{\n "dependencies": {"sanitize-html": "1.10.0"}\n}'
        soup,_=self.page(f,solution_for(f,source))
        self.assertEqual(soup.select_one('.current-code code').get_text(),'"sanitize-html": "1.10.0"')
        self.assertIn('"sanitize-html": "1.11.4"',soup.select_one('.primary-fix code').get_text())
        from analysis.recommendation_composer import compose
        self.assertIsNone(compose(f,solution_for(f))['code_pair'])
        data=json.loads(f['evidence']);data['affected']=[];f['evidence']=json.dumps(data)
        result=compose(f,solution_for(f,source))
        self.assertIsNone(result['code_pair']);self.assertIn('<verified-safe-version>',result['examples'][0]['code'])

    def test_no_pair_for_website_unmatched_source_or_secret(self):
        from analysis.recommendation_composer import compose
        f=finding('Potential SQL Injection','SQL Injection','app.py')
        for source in ('Website','Repository'):
            row=dict(f,source=source)
            result=compose(row,solution_for(row))
            self.assertIsNone(result['code_pair']);self.assertEqual(result['example_type'],'illustrative')
        secret=finding(file='settings.py')
        secret['evidence']='password="PrivateFixture987"'
        soup,html=self.page(secret,solution_for(secret,'password="PrivateFixture987"'))
        self.assertIsNone(soup.select_one('.code-comparison'));self.assertNotIn('PrivateFixture987',html)

    def test_dependency_pair_reads_retained_line_without_reconstructing_old_code(self):
        from analysis.recommendation_composer import compose
        f=finding('Vulnerable dependency: sanitize-html','Dependency','package.json')
        f['evidence']=json.dumps({'package':'sanitize-html','ecosystem':'npm','version':'1.10.0','affected':[{'ranges':[{'type':'SEMVER','events':[{'introduced':'0'},{'fixed':'1.11.4'}]}]}]})
        base=solution_for(f)
        base['context']=' 145 > "sanitize-html": "1.10.0",'
        result=compose(f,base)
        self.assertEqual(result['code_pair']['current'],'"sanitize-html": "1.10.0"')
        self.assertEqual(result['code_pair']['recommended'],'"sanitize-html": "1.11.4"')
        for context in (' 145 > "sanitize-html": "0.0.1",',' 145 > "sanitize-html": "1.10…',base['context']+'\n'+base['context']):
            base['context']=context;self.assertIsNone(compose(f,base)['code_pair'])
