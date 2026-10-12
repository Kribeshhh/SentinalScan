"""Phase24: static text only, synthetic credentials, isolated persistence."""
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import Mock, patch
from bs4 import BeautifulSoup
from scanner.source_scanner import analyze_directory, run_repository, MODULE_NAMES
from scanner.sast import python_scanner, config_scanner
from analysis.finding_engine import Finding, save_finding
from analysis.solution_engine import solution_for
from analysis.recommendation_composer import compose, final_solution
from database import get_db
from reports.report_generator import generate_report, open_report
from tests import test_unified_recommendation as unified


class Parsing24Tests(unittest.TestCase):
    def run_files(self, module, files):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for path, content in files.items():
                p=root/path;p.parent.mkdir(parents=True,exist_ok=True)
                p.write_bytes(content if isinstance(content,bytes) else content.encode())
            ctx=analyze_directory(root,list(files),'fixture/coverage')
            data=module.run(ctx)
            return data,ctx['findings']

    def test_python_legacy_invalid_encoding_and_valid(self):
        data,found=self.run_files(python_scanner,{'valid.py':'import os\nos.remove("NEVER_EXECUTE")',
            'legacy.py':'print "masked-only"\n','invalid.py':'def incomplete(',
            'bad.py':b'\xff','future.py':'type Alias[T = int] =\n'})
        self.assertEqual(data['parsed_files'],1)
        self.assertEqual(len(data['unparsed_files']),4)
        self.assertEqual(len(data['parse_errors']),4)
        self.assertIn('Legacy Python print syntax',data['parse_errors'][0]['reason'])
        self.assertEqual(data['parse_errors'][0]['line'],1)
        self.assertEqual(data['parse_errors'][2]['category'],'EncodingError')
        other,_=self.run_files(python_scanner,{'old.py':'exec "example"'})
        self.assertNotIn('print syntax',other['parse_errors'][0]['reason'])
        self.assertNotIn('masked-only',json.dumps(data))
        self.assertTrue(all(d['status']=='Not parsed' and 'Not established' in d['other_engine_assessment'] for d in data['parse_errors']))

    def test_python_read_and_recursion_errors_are_safe(self):
        for error in (OSError('PRIVATE_CONTENT'),RecursionError('PRIVATE_CONTENT')):
            with patch.object(Path,'read_text',side_effect=error):
                data=python_scanner.run(analyze_directory(Path('/unused'),['a.py'],'fixture/r'))
            self.assertEqual(data['parsed_files'],0);self.assertEqual(data['unparsed_files'],['a.py'])
            self.assertNotIn('PRIVATE_CONTENT',json.dumps(data))

    def test_jsonc_comments_strings_and_trailing_commas(self):
        text='/* intro */\n{"url":"https://host/x//y", "quote":"a\\\"/*b", // line\n"items":[1,2,],"debug":false,}'
        parsed=config_scanner.json_configuration(text,'tsconfig.app.json')
        self.assertEqual(parsed['url'],'https://host/x//y');self.assertEqual(parsed['quote'],'a"/*b')
        self.assertEqual(parsed['items'],[1,2])
        data,found=self.run_files(config_scanner,{'frontend/tsconfig.json':text})
        self.assertEqual(data['parsed_files'],1);self.assertEqual(data['unparsed_files'],[]);self.assertEqual(found,[])

    def test_jsonc_malformed_not_silently_repaired(self):
        for text in ('/* unfinished','{"a":,}','[,]', '{,}', '{"a": [1,,]}','{"a": undefined}', '{"a":"//unterminated}'):
            with self.subTest(text=text):
                data,_=self.run_files(config_scanner,{'tsconfig.json':text})
                self.assertEqual(data['parsed_files'],0);self.assertEqual(data['unparsed_files'],['tsconfig.json'])
                self.assertEqual(data['parse_errors'][0]['category'],'JSONDecodeError')

    def test_jsonc_scope_and_yaml_json_regression(self):
        files={'regular.json':'{"url":"//host","debug":false}', 'config.yml':'debug: true',
               'tsconfig.build.json':'// debug:true\n{"debug":false,}',
               'jsconfig.json':'{"debug":true,}', 'package.json':'// unsupported\n{"debug":true}'}
        data,found=self.run_files(config_scanner,files)
        self.assertEqual(data['configuration_files'],5);self.assertEqual(data['parsed_files'],4)
        self.assertEqual(data['unparsed_files'],['package.json'])
        self.assertEqual(len(found),2);self.assertTrue(all(f.severity=='Medium' and f.confidence=='High' for f in found))
        self.assertEqual({f.location for f in found},{'fixture/coverage/config.yml:1','fixture/coverage/jsconfig.json:1'})

    def test_config_encoding_and_yaml_diagnostics_redacted(self):
        data,_=self.run_files(config_scanner,{'a.json':b'\xff','a.yml':'value: [\n','tsconfig.json':'/* hi */\n{"secret": PRIVATE_CONTENT}'})
        self.assertEqual(data['parsed_files'],0);self.assertEqual(len(data['parse_errors']),3)
        self.assertNotIn('PRIVATE_CONTENT',json.dumps(data))
        self.assertEqual(data['parse_errors'][-1]['line'],2)


class Presentation24Tests(unittest.TestCase):
    setUp=unified.UnifiedPageTests.setUp
    tearDown=unified.UnifiedPageTests.tearDown

    def secret(self):
        f=Finding(title='Potential embedded credential',category='Secret Exposure',source='Repository',
            location='fixture/repo/data/static/users.yml:149',severity='High',confidence='Medium',
            description='Candidate credential',evidence='[REDACTED]',impact='Access if real.',recommendation='Remove and rotate if real.')
        db=get_db();fid=save_finding(db,self.scans['Repository'],f)
        return db,dict(db.execute('SELECT * FROM findings WHERE id=?',(fid,)).fetchone())

    def test_yaml_history_single_ui_and_exports_no_ai_get(self):
        provider=Mock(side_effect=AssertionError('No inference on render'))
        self.app.config.update(LLM_ENABLED=True,LLM_REVIEW_PROVIDER=provider)
        with self.app.app_context():
            db,f=self.secret();before='\n'.join(db.iterdump())
            solution=final_solution(db,f)
            e=solution['examples'][0]
            self.assertEqual(e['vulnerable_code'],'database:\n  password: "[REDACTED]"')
            self.assertIn('not a verified replacement for YAML',e['note'])
            self.assertEqual(solution['example_type'],'illustrative');self.assertEqual(solution['validation_status'],'Not Available')
            self.assertEqual(solution['fix_confidence'],'Low');self.assertIsNone(solution['code_pair'])
            self.assertEqual(before,'\n'.join(db.iterdump()))
            for fmt in ('HTML','JSON','CSV'):
                rid=generate_report(self.scans['Repository'],fmt)
                row=db.execute('SELECT * FROM reports WHERE id=?',(rid,)).fetchone()
                with open_report(row) as handle: body=handle.read().decode()
                if fmt=='JSON': examples=next(r for r in json.loads(body)['findings'] if r['id']==f['id'])['solution']['examples']
                elif fmt=='CSV': examples=json.loads(next(r for r in csv.DictReader(io.StringIO(body)) if r['id']==str(f['id']))['details_json'])['solution']['examples']
                else:
                    self.assertIn('Vulnerable Example',body);self.assertIn('Safer Example',body);continue
                self.assertEqual(examples,solution['examples'])
        page=self.client.get('/findings/'+str(f['id']));self.assertEqual(page.status_code,200)
        soup=BeautifulSoup(page.data,'html.parser');self.assertEqual(len(soup.select('#recommendation')),1)
        self.assertIn('Vulnerable Example',soup.get_text());self.assertIn('Safer Example',soup.get_text())
        self.assertIn('[REDACTED]',soup.get_text());self.assertNotIn('Improve with AI',soup.get_text());provider.assert_not_called()

    def test_fallback_examples_sql_dom_secret_and_header(self):
        cases=[('Potential SQL injection in constructed query','SQL Injection','a.py','Repository','Pseudocode'),
               ('Potential unsafe DOM HTML insertion','DOM XSS','a.js','Repository','JavaScript'),
               ('Hardcoded credential','Secret Exposure','a.py','Repository','Python'),
               ('Potential embedded credential','Secret Exposure','a.yaml','Repository','Python')]
        for title,cat,path,source,language in cases:
            f=dict(title=title,category=cat,source=source,location='o/r/'+path+':1',evidence='Recorded indicator',recommendation='Review evidence.')
            base=solution_for(f);result=compose(f,base,{'unexpected':'bad'},True)
            self.assertFalse(result['ai_assisted']);self.assertIn(language,result['examples'][0]['language'])
            self.assertTrue(result['examples'][0]['vulnerable_code']);self.assertIsNone(result['code_pair'])
            self.assertEqual(result['validation_status'],'Not Available')
        f=dict(title='Missing X-Content-Type-Options header',category='Security Headers',source='Website',location='https://fixture.test/',evidence='Missing',recommendation='Set nosniff.')
        r=compose(f,solution_for(f));self.assertIn('nosniff',json.dumps(r));self.assertNotIn('Flask',json.dumps(r['examples']))

    def test_dismissed_and_unknown_language_not_invented(self):
        with self.app.app_context():
            _,f=self.secret()
            for changes in ({'status':'False Positive'},{'location':'o/r/unknown.dat:1'}):
                altered=dict(f,**changes);r=compose(altered,solution_for(altered));self.assertFalse(r['examples'])

    def test_worker_partial_persistence_and_cleanup(self):
        class Archive:
            destination=None
            def archive(self,repo,sha,destination):
                self.destination=destination
                with zipfile.ZipFile(destination,'w') as z:
                    z.writestr('snapshot/good.py','x = 1\n')
                    z.writestr('snapshot/old.py','print "example"\n')
                    z.writestr('snapshot/frontend/tsconfig.json','/* valid JSONC */ {"files":[],}')
                    z.writestr('snapshot/bad.json','{"debug": }')
        archive=Archive()
        with self.app.app_context():
            db=get_db()
            with db:
                sid=db.execute("INSERT INTO scans(scan_type,target,status) VALUES ('Repository','fixture/coverage','Queued')").lastrowid
                db.executemany('INSERT INTO scan_modules(scan_id,name) VALUES (?,?)',[(sid,n) for n in MODULE_NAMES])
        run_repository(self.app,sid,archive,{'full_name':'fixture/coverage'},'main','a'*40,False)
        with self.app.app_context():
            db=get_db()
            for name in ('Python','Configuration'):
                row=db.execute('SELECT * FROM scan_modules WHERE scan_id=? AND name=?',(sid,name)).fetchone()
                self.assertEqual(row['status'],'Partial');data=json.loads(row['data_json'])
                self.assertEqual(data['parsed_files'],1);self.assertEqual(len(data['parse_errors']),1)
            self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0],'ok')
        self.assertFalse(archive.destination.parent.exists())
        self.assertEqual(self.client.get('/scans/'+str(sid)).status_code,200)

    def test_example_html_escaping_and_csv_formula_boundary(self):
        from flask import render_template
        from reports.report_generator import report_data, csv_document
        with self.app.app_context():
            db,f=self.secret()
            with db:db.execute('UPDATE findings SET title=? WHERE id=?',('=1+1',f['id']))
            hostile={'language':'YAML','code':'<script>never_execute()</script>',
                     'vulnerable_code':'<img src=x onerror=never_execute()>',
                     'vulnerable_language':'YAML','note':'Illustrative only.'}
            with patch('analysis.recommendation.example_secure_pattern',return_value=hostile):
                data=report_data(db,self.scans['Repository'])
                item=next(x for x in data['findings'] if x['id']==f['id'])
                rendered=render_template('_solution.html',solution=item['solution'],finding=item)
                exported=render_template('report_document.html',report=data)
                for html in (rendered,exported):
                    self.assertNotIn('<script>never_execute()',html)
                    self.assertNotIn('<img src=x',html)
                    self.assertIn('&lt;img',html);self.assertIn('&lt;script',html)
                rows=list(csv.DictReader(io.StringIO(csv_document(data))))
                row=next(r for r in rows if r['id']==str(f['id']))
                self.assertEqual(row['title'],"'=1+1")
                self.assertEqual(json.loads(row['details_json'])['solution']['examples'][0]['vulnerable_code'],hostile['vulnerable_code'])

    def test_secret_source_not_stored_in_illustrations_or_ai_context(self):
        from analysis.llm_review import prepare
        with self.app.app_context():
            db,f=self.secret()
            synthetic='OnlySyntheticMaterial9382'
            source='database:\n  password: "'+synthetic+'"\n'
            base=solution_for(f,source)
            with db:db.execute('INSERT INTO finding_solutions VALUES (?,?)',(f['id'],json.dumps(base)))
            result=final_solution(db,f)
            payload=prepare(f,None,solution=base)
            for value in (json.dumps(result),json.dumps(payload),'\n'.join(db.iterdump())):
                self.assertNotIn(synthetic,value)
            self.assertEqual(result['examples'][0]['vulnerable_code'],'database:\n  password: "[REDACTED]"')
            self.assertFalse(result['source_matched']);self.assertFalse(result['exact'])
