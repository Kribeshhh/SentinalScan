"""Phase 3 fixtures are untrusted text; no repository or credential execution."""
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from app import create_app
from database import get_db
from analysis.correlation import persist_candidates,review
from analysis.management import compare_scans
from scanner.source_scanner import analyze_directory
from scanner.sast import python_scanner,secret_scanner,dependency_scanner
from scanner.sast.security_context import ContextRetriever
from scanner.engines.sarif import import_results


class Phase3Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def context(self,files):
        for path,source in files.items():
            file=self.root/path;file.parent.mkdir(parents=True,exist_ok=True);file.write_text(source)
        return analyze_directory(self.root,list(files),'lab/evidence',True)

    def app(self):
        app=create_app({'TESTING':True,'DATABASE':str(self.root/'test.sqlite3')})
        self.addCleanup(app.extensions['scan_manager'].shutdown)
        return app

    def test_secret_real_placeholder_env_docs_and_redaction(self):
        value='AKIA'+'A1B2C3D4E5F6G7H8'
        ctx=self.context({'credentials.txt':'AWS_ACCESS_KEY_ID='+value+'\npassword="RealCredential-93823"',
                          'examples/example.txt':'password="dummy-password-123"\ntoken="$AUTH_TOKEN"',
                          'docs/note.md':'password="UncertainDocumentation-12345"',
                          'examples/settings.py':'password="UncertainCredential-93824"'})
        secret_scanner.run(ctx)
        self.assertEqual(len(ctx['findings']),4)
        self.assertEqual(next(f for f in ctx['findings'] if 'settings.py' in f.location).confidence,'Low')
        self.assertNotIn(value,str(ctx['findings']));self.assertNotIn('RealCredential-93823',str(ctx['findings']))
        doc=next(f for f in ctx['findings'] if 'note.md' in f.location)
        self.assertEqual(doc.confidence,'Low')
        self.assertNotIn('UncertainDocumentation-12345',str(doc))

    def test_new_manifests_lockfiles_unknown_and_bounds(self):
        lock={'lockfileVersion':3,'packages':{'':{'name':'app'},'node_modules/example-lib':{'version':'1.2.3'},'node_modules/other':{'version':'2.3.4'}}}
        ctx=self.context({'pyproject.toml':'[project]\ndependencies=["flask==2.0.0", "requests>=2"]',
                          'package-lock.json':json.dumps(lock),'yarn.lock':'unsupported here'})
        rows,errors,capped=dependency_scanner.manifests(ctx)
        self.assertFalse(errors);self.assertFalse(capped)
        self.assertEqual(len(rows),4)
        self.assertFalse(next(r for r in rows if r['package']=='requests')['exact'])
        self.assertEqual(ctx['_unsupported_manifests'],['yarn.lock'])
        self.assertEqual(next(r for r in rows if r['package']=='example-lib')['version_evidence'],'lockfile')
        ctx=self.context({'package-lock.json':json.dumps({'lockfileVersion':99})})
        self.assertEqual(dependency_scanner.manifests(ctx)[1],['package-lock.json'])

    def test_osv_positive_negative_unknown_and_dependency_dedup(self):
        ctx=self.context({'package.json':'{"dependencies":{"example-lib":"1.2.3","unknown":"^2"}}',
            'package-lock.json':json.dumps({'lockfileVersion':2,'packages':{'node_modules/example-lib':{'version':'1.2.3'},'node_modules/clean':{'version':'1.0.0'}}})})
        def query(name,version,ecosystem):
            return {'vulns':[{'id':'OSV-FIXTURE-1','affected':[{'package':{'name':name,'ecosystem':ecosystem}}]}]} if name=='example-lib' else {'vulns':[]}
        with patch.object(dependency_scanner,'query',side_effect=query) as lookup:result=dependency_scanner.run(ctx)
        self.assertEqual(lookup.call_count,2);self.assertEqual(len(ctx['findings']),1)
        info=json.loads(ctx['findings'][0].context_json)['analysis']['dependency']
        self.assertEqual(len(info['occurrences']),2);self.assertEqual(info['reachability'],'Not assessed')
        self.assertIn('No known advisory',next(r for r in result['dependencies'] if r['package']=='clean')['assessment'])
        self.assertEqual(next(r for r in result['dependencies'] if r['package']=='unknown')['lookup'],'Unresolved version')

    def candidates(self,source):
        ctx=self.context({'a.py':source});python_scanner.run(ctx)
        return ctx

    def external(self,ctx,line=3,engine='Semgrep',cwe='89'):
        doc={'version':'2.1.0','runs':[{'tool':{'driver':{'rules':[{'id':'sql-test','properties':{'tags':['CWE-'+cwe]}}]}},
            'results':[{'ruleId':'sql-test','locations':[{'physicalLocation':{'artifactLocation':{'uri':'a.py'},'region':{'startLine':line}}}]}]}]}
        import_results(json.dumps(doc).encode(),ctx,engine)

    def test_three_engines_one_finding_provenance_report_and_escaping(self):
        ctx=self.candidates('from flask import request\nq="SELECT "+request.args.get("q")\ncursor.execute(q)')
        self.external(ctx);self.external(ctx,engine='CodeQL')
        app=self.app()
        with app.app_context():
            db=get_db();sid=db.execute("INSERT INTO scans(scan_type,target,status) VALUES ('Repository','lab/evidence','Completed')").lastrowid
            persist_candidates(db,sid,ctx,ctx['findings'])
            self.assertEqual(db.execute('SELECT count(*) FROM findings').fetchone()[0],1)
            fid=db.execute('SELECT id FROM findings').fetchone()[0]
            snapshot=json.loads(db.execute('SELECT data_json FROM finding_solutions').fetchone()[0])
            a=snapshot['finding_context']['analysis']
            self.assertEqual({p['engine'] for p in a['detected_by']},{'python-ast','Semgrep','CodeQL'})
            self.assertEqual(a['verification_status'],'Strongly Supported')
            from reports.report_generator import report_data
            self.assertEqual(len(report_data(db,sid)['findings']),1)
        page=app.test_client().get('/findings/'+str(fid)).get_data(as_text=True)
        self.assertIn('Detected by:',page);self.assertIn('Strongly Supported',page)
        self.assertIn('Semgrep',page);self.assertIn('CodeQL',page)

    def test_unrelated_same_cwe_and_ambiguous_same_line_not_merged(self):
        ctx=self.candidates('q="SELECT "+request.args.get("q")\ncursor.execute(q)\nother.execute(q)')
        self.external(ctx,line=2)
        app=self.app()
        with app.app_context():
            db=get_db();sid=db.execute("INSERT INTO scans(scan_type,target,status) VALUES ('Repository','lab/evidence','Completed')").lastrowid
            persist_candidates(db,sid,ctx,ctx['findings'])
            self.assertEqual(db.execute('SELECT count(*) FROM findings').fetchone()[0],2)
        ambiguous=self.candidates('q="SELECT "+request.args.get("q")\ncursor.execute(q); other.execute(q)')
        _,key=review(ambiguous,ambiguous['findings'][0]);self.assertIsNone(key)

    def test_line_movement_and_function_identity(self):
        source='def route():\n q="SELECT "+request.args.get("q")\n cursor.execute(q)'
        a=self.candidates(source);first,_=review(a,a['findings'][0])
        b=self.candidates('\n\n'+source);second,_=review(b,b['findings'][0])
        get=lambda f:json.loads(f.context_json)['analysis']['logical_fingerprint']
        self.assertEqual(get(first),get(second))
        c=self.candidates(source.replace('route','other_route'));third,_=review(c,c['findings'][0])
        self.assertNotEqual(get(first),get(third))
        app=self.app()
        with app.app_context():
            db=get_db()
            ids=[]
            for ctx in (a,b):
                sid=db.execute("INSERT INTO scans(scan_type,target,status) VALUES ('Repository','lab/evidence','Completed')").lastrowid
                # Recreate sources for a realistic per-scan snapshot.
                (self.root/'a.py').write_text(source if not ids else '\n\n'+source)
                persist_candidates(db,sid,ctx,ctx['findings']);ids.append(sid)
            result=compare_scans(db,*ids)
            self.assertEqual(len(result['unchanged']),1);self.assertEqual(result['new'],[])

    def test_context_bounded_redacted_and_related_functions(self):
        source='''password="FixtureCredential-984723"
def build(value):
 return "SELECT "+value
def search(value):
 cursor.execute(build(value))
def route():
 search(request.args.get("q"))
'''
        ctx=self.context({'a.py':source,'unrelated.py':'private_data="DoNotRetrieveThis"'})
        secret_scanner.run(ctx);python_scanner.run(ctx)
        candidate=next(f for f in ctx['findings'] if f.category=='Injection')
        finding,_=review(ctx,candidate)
        package=json.loads(finding.context_json)['analysis']['evidence_package']
        self.assertTrue(package['available']);self.assertIn('build',package['related_functions'])
        self.assertEqual(package['related_files'],['a.py'])
        self.assertLessEqual(sum(len(s['text']) for s in package['snippets']),3600)
        self.assertNotIn('FixtureCredential-984723',finding.context_json)
        self.assertNotIn('DoNotRetrieveThis',finding.context_json)
        r=ContextRetriever(ctx);r.end=0
        self.assertFalse(r.retrieve({'file':'a.py','start_line':1})['available'])
        self.assertFalse(r.retrieve({'file':'../not-vetted','start_line':1})['available'])
        (self.root/'a.py').unlink()
        self.assertFalse(ContextRetriever(ctx).retrieve({'file':'a.py','start_line':1})['available'])

    def test_missing_evidence_downgrades_high_and_manual_rejection(self):
        ctx=self.candidates('cursor.execute("SELECT "+request.args.get("q"))')
        ctx['paths']=[]
        f,_=review(ctx,ctx['findings'][0]);a=json.loads(f.context_json)['analysis']
        self.assertEqual(f.confidence,'Medium');self.assertEqual(a['verification_status'],'Needs Review')
        rejected,_=review(ctx,replace(ctx['findings'][0],status='False Positive'))
        self.assertEqual(json.loads(rejected.context_json)['analysis']['verification_status'],'Rejected / False Positive')
