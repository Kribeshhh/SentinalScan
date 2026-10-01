import json
import tempfile
import unittest
from pathlib import Path
from analysis.solution_engine import solution_for
from analysis.dependency_solution import package_line
from scanner.sast.secret_scanner import run
from scanner.source_scanner import analyze_directory

class SourceGuidanceTests(unittest.TestCase):
    def test_translation_prose_is_not_a_credential_but_typed_tokens_still_are(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'i18n').mkdir()
            token='ghp_'+'AbCd1234'*5
            (root/'i18n/en.json').write_text(json.dumps({'PASSWORD':'Choose a strong password','Change password into something':'Translated challenge text','token':token}))
            (root/'config.py').write_text('db_password = "RealCredential987"\npassword_hint = "Choose a strong password"\n')
            ctx=analyze_directory(root,['i18n/en.json','config.py'],'owner/repo');run(ctx)
            self.assertEqual(len(ctx['findings']),2)
            self.assertEqual({f.title for f in ctx['findings']},{'GitHub token','Hardcoded credential'})
            self.assertTrue(all(token not in f.evidence for f in ctx['findings']))

    def finding(self,fixed=True):
        return dict(title='Vulnerable dependency: library (GHSA-example)',category='Dependency',source='Repository',severity='Critical',location='owner/repo/package.json:1',
            evidence=json.dumps({'package':'library','version':'1.0.0','ecosystem':'npm','id':'GHSA-example','description':'Known advisory',
            'affected':[{'ranges':[{'type':'SEMVER','events':[{'introduced':'0'},{'fixed':'2.0.0'}] if fixed else [{'introduced':'0'},{'last_affected':'1.0.0'}]}]}]}))

    def test_dependency_actual_entry_and_advisory_candidate(self):
        source='{\n "name": "app",\n "dependencies": {\n  "library": "1.0.0"\n }\n}\n'
        result=solution_for(self.finding(),source)
        self.assertIn('4 >',result['context'])
        self.assertEqual(result['before'],'"library": "1.0.0"')
        self.assertEqual(result['examples'][0]['code'],'"library": "2.0.0"\n')
        self.assertIn('THIS advisory only',' '.join(result['notes']))
        self.assertIn('Critical',' '.join(result['notes']))
        self.assertEqual(package_line(source,'library','1.0.0')[0],4)

    def test_no_fixed_release_does_not_invent_code(self):
        result=solution_for(self.finding(False),'{"dependencies":{"library":"1.0.0"}}')
        self.assertEqual(result['examples'],[])
        self.assertIn('No fixed release',result['action'])
        self.assertNotIn('checklist',json.dumps(result))
        ambiguous='{"dependencies":{"library":"1.0.0"},"devDependencies":{"library":"1.0.0"}}'
        self.assertIsNone(package_line(ambiguous,'library','1.0.0'))
