"""Repository inputs are fixture text; none are imported, compiled or executed."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scanner.source_scanner import analyze_directory
from scanner.sast.registry import ANALYZERS, analyzer_for
from scanner.sast.project_index import build_index


class RepositoryFoundationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def context(self, files):
        for path, source in files.items():
            (self.root/path).write_text(source)
        return analyze_directory(self.root,list(files),'lab/foundation')

    def scan(self, path, source):
        ctx = self.context({path:source})
        analyzer_for(path).run(ctx)
        return ctx['findings']

    def test_registry_and_unsupported_language(self):
        self.assertEqual([a.language for a in ANALYZERS],['Python','JavaScript','Java'])
        self.assertIsNone(analyzer_for('code.rb'))
        for path,source in [('a.py','x=1'),('a.js','const x=1;'),('A.java','class A {}')]:
            self.assertIsNotNone(analyzer_for(path).parse(source))

    def test_structured_flow_and_coordinates_all_languages(self):
        cases=[('a.py','from flask import request\ndef route():\n user=request.args.get("x")\n query="SELECT "+user\n cursor.execute(query)', 'Python','route','python.sql.constructed'),
            ('a.js','function render(){const user=location.hash; document.write(user);}', 'JavaScript','render','javascript.document.write'),
            ('A.java','class A {void run(HttpServletRequest request){String user=request.getParameter("x"); stmt.executeQuery("SELECT "+user);}}','Java','run','java.sql.constructed')]
        for path,source,language,function,rule in cases:
            with self.subTest(language=language):
                f=self.scan(path,source)[0];data=json.loads(f.context_json)['analysis']
                self.assertEqual(data['language'],language)
                self.assertEqual(data['function'],function)
                self.assertEqual(data['rule_id'],rule)
                self.assertTrue(data['source']);self.assertTrue(data['sink'])
                self.assertIn('user',data['data_flow'])
                self.assertGreaterEqual(data['end_line'],data['start_line'])
                self.assertEqual(data['verification_status'],'Not verified')
                self.assertIsNone(data['suggested_code'])

    def test_function_names_comments_and_safe_apis_are_not_findings(self):
        cases=[('a.py','# cursor.execute(request.args)\ntext="os.system(user)"\ncursor.execute(query_object)\nimport subprocess\nsubprocess.run(command)\ncursor.execute("SELECT ?",(user,))'),
            ('a.js','// eval(user)\nconst text="document.write(user)"; function eval(x){return x;} eval(user);'),
            ('A.java','class A {void run(){stmt.executeQuery(queryObject); connection.prepareStatement("SELECT ?"); helper.exec("fixed");}}')]
        for path,source in cases:
            with self.subTest(path=path): self.assertEqual(self.scan(path,source),[])

    def test_protection_is_sink_specific_in_structured_evidence(self):
        self.assertEqual(self.scan('a.js','const value=DOMPurify.sanitize(location.hash); document.write(value);'),[])
        f=self.scan('a.js','const value=DOMPurify.sanitize(location.hash); eval(value);')[0]
        self.assertIn('not applicable',json.loads(f.context_json)['analysis']['sanitizers'][0])
        self.assertEqual(self.scan('a.py','import subprocess\nsubprocess.run(["echo",request.args.get("x")],shell=False)'),[])

    def test_index_scopes_imports_and_no_literal_arguments(self):
        secret='FixtureLiteral-MustNotBeIndexed-2738'
        ctx=self.context({'a.py':'from flask import request as r\nclass View:\n def route(self):\n  helper("'+secret+'")',
                          'a.js':'import express from "express"; function route(){ helper("'+secret+'"); }',
                          'A.java':'import org.springframework.Controller; class A {void run(){helper("'+secret+'");}}'})
        index=build_index(ctx)
        self.assertEqual(set(index['languages']),{'Python','JavaScript','Java'})
        self.assertNotIn(secret,json.dumps(index))
        self.assertIn('flask',index['framework_indicators'])
        self.assertTrue(any(r.get('scope')=='View.route' and r['kind']=='call' for r in index['records']))
        self.assertTrue(all(r['resolved'] is False for r in index['records'] if r['kind']=='call'))

    def test_index_limits_parse_failure_and_deadline(self):
        ctx=self.context({'bad.py':'def :','a.py':'\n'.join('f()' for _ in range(130))})
        index=build_index(ctx)
        self.assertEqual(index['unparsed_files'],['bad.py']);self.assertTrue(index['truncated'])
        self.assertEqual(len(index['records']),100)
        with patch('scanner.sast.project_index.MAX_RECORDS',3):
            self.assertEqual(len(build_index(ctx)['records']),3)
        ctx['deadline']=0
        with self.assertRaises(TimeoutError): build_index(ctx)

    def test_evidence_persists_through_source_retention_and_reports(self):
        from app import create_app
        from database import get_db
        from analysis.finding_engine import save_finding
        from analysis.source_context import retain_context
        from reports.report_generator import report_data
        source='from flask import request\nq="SELECT "+request.args.get("x")\ncursor.execute(q)'
        finding=self.scan('a.py',source)[0]
        app=create_app({'TESTING':True,'DATABASE':str(self.root/'test.sqlite3')})
        self.addCleanup(app.extensions['scan_manager'].shutdown)
        with app.app_context():
            db=get_db()
            sid=db.execute("INSERT INTO scans(scan_type,target,status) VALUES ('Repository','lab/foundation','Completed')").lastrowid
            fid=save_finding(db,sid,finding)
            retain_context(db,sid,self.root,['a.py'],'lab/foundation','a'*40)
            stored=json.loads(db.execute('SELECT data_json FROM finding_solutions WHERE finding_id=?',(fid,)).fetchone()[0])
            self.assertEqual(stored['finding_context']['analysis']['rule_id'],'python.sql.constructed')
            self.assertEqual(db.execute('SELECT fingerprint FROM findings WHERE id=?',(fid,)).fetchone()[0],finding.fingerprint)
            report=report_data(db,sid)
            self.assertEqual(report['findings'][0]['solution']['finding_context']['analysis']['rule_id'],'python.sql.constructed')
        self.assertEqual(app.test_client().get('/').status_code,200)
        self.assertEqual(app.test_client().get('/website-scan').status_code,200)
