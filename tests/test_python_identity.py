"""D05 identity regressions. Fixtures are parsed, never imported or executed."""
import json
from pathlib import Path
import tempfile
import unittest
from scanner.source_scanner import analyze_directory
from scanner.sast import python_scanner

SQL = 'Potential SQL injection in constructed query'
DB = 'from flask import request\nimport sqlite3\nconn=sqlite3.connect(":memory:")\ncursor=conn.cursor()\n'
DISPLAY = 'class Display:\n def execute(self,value):\n  print(value)\ndisplay=Display()\n'


def scan(source):
    with tempfile.TemporaryDirectory() as td:
        root=Path(td);(root/'case.py').write_text(source)
        ctx=analyze_directory(root,['case.py'],'lab/identity')
        python_scanner.run(ctx)
        return ctx['findings']


class IdentityTests(unittest.TestCase):
    def test_original_d05_display_and_imported_source(self):
        for prefix in ('','from flask import request\n'):
            self.assertEqual(scan(prefix+DISPLAY+'display.execute("SELECT "+request.args.get("q"))'),[])

    def test_original_d05_local_request_is_not_framework_source(self):
        for prefix in ('','from flask import request\n'):
            findings=scan(prefix+'class Local:\n args={"q":"1"}\nrequest=Local()\neval(request.args.get("q"))')
            self.assertEqual(len(findings),1)  # generic eval remains reviewable
            self.assertEqual(findings[0].confidence,'Medium')
            self.assertEqual(json.loads(findings[0].context_json)['analysis']['source'],[])
            self.assertNotIn('Recognized input',findings[0].evidence)

    def test_database_bound_query_positive_and_parameterized_negative(self):
        findings=scan(DB+'cursor.execute("SELECT "+request.args.get("q"))')
        self.assertEqual([(f.title,f.confidence) for f in findings],[(SQL,'High')])
        detail=json.loads(findings[0].context_json)['analysis']
        self.assertEqual(detail['start_line'],5);self.assertEqual(detail['sink'],'SQL execute')
        self.assertEqual(detail['source'],['flask.request.args'])
        self.assertEqual(scan(DB+'cursor.execute("SELECT ?",(request.args.get("q"),))'),[])

    def test_import_aliases_and_supported_drivers(self):
        for module in ('sqlite3','psycopg','psycopg2','pymysql','mysql.connector'):
            for declaration in (f'import {module} as db\nc=db.connect("fixture")',f'from {module} import connect as open_db\nc=open_db("fixture")'):
                with self.subTest(module=module,declaration=declaration):
                    findings=scan('from flask import request as req\n'+declaration+'\ncur=c.cursor()\ncur.execute("SELECT "+req.form["q"])')
                    self.assertEqual(findings[0].confidence,'High')
        self.assertEqual(scan('from django.db import connection\nfrom flask import request\ncursor=connection.cursor()\ncursor.execute("SELECT "+request.args["q"])')[0].confidence,'High')

    def test_receiver_alias_and_bounded_helper(self):
        findings=scan(DB+'def query(c,v):\n c.execute("SELECT "+v)\nalias=cursor\nquery(alias,request.args["q"])')
        self.assertEqual(len(findings),1);self.assertEqual(findings[0].confidence,'High')
        self.assertIn('query',json.loads(findings[0].context_json)['analysis']['calls'])
        self.assertEqual(scan('from flask import request\n'+DISPLAY+'alias=display.execute\nalias("SELECT "+request.args["q"])'),[])

    def test_unknown_receiver_has_low_confidence_and_explicit_uncertainty(self):
        for source in ('request.args["q"]','unknown'):
            finding=scan('from flask import request\ncursor.execute("SELECT "+'+source+')')[0]
            self.assertEqual(finding.confidence,'Low')
            detail=json.loads(finding.context_json)['analysis']
            self.assertEqual(detail['sink'],'Unresolved receiver method execute')
            self.assertEqual(detail['reachability'],'Potential pattern')

    def test_unimported_or_relative_request_is_unknown(self):
        for prefix in ('','from .flask import request\n','from . import flask\n'):
            for call in ('request.args["q"]','flask.request.get_json()'):
                finding=scan(prefix+'eval('+call+')')[0]
                self.assertEqual(json.loads(finding.context_json)['analysis']['source'],[])
                self.assertNotEqual(finding.confidence,'High')

    def test_framework_aliases(self):
        for source in ('import flask as f\nr=f.request\neval(r.get_json())','from flask import request as r\na=r\neval(a.args["q"])'):
            self.assertEqual(scan(source)[0].confidence,'High')

    def test_scope_parameters_rebinding_and_import_shadow(self):
        for body in ('def route(request):\n eval(request.args["q"])', 'def route():\n eval(request.args["q"])\n request=unknown', 'def route():\n eval(request.args["q"])\n import local as request', 'request=unknown\neval(request.args["q"])'):
            findings=scan('from flask import request\n'+body)
            self.assertTrue(findings)
            self.assertTrue(all(not json.loads(f.context_json)['analysis']['source'] for f in findings))

    def test_branch_receiver_identity_is_not_invented(self):
        findings=scan(DB+DISPLAY+'if flag:\n cursor=display\ncursor.execute("SELECT "+request.args["q"])')
        self.assertEqual(findings[0].confidence,'Low')

    def test_inherited_dynamic_and_rebound_method_stay_unknown(self):
        for source in ('class Display(Base):\n pass\ndisplay=Display()\n', 'class Display:\n def __getattr__(self,k):\n  return unknown\ndisplay=Display()\n', DISPLAY+'display.execute=unknown\n'):
            finding=scan('from flask import request\n'+source+'display.execute("SELECT "+request.args["q"])')[0]
            self.assertEqual(finding.confidence,'Low')

    def test_local_request_mutation_does_not_turn_eval_safe(self):
        findings=scan('class Local:\n args={"q":"1"}\nrequest=Local()\nrequest.args["q"]=input()\neval(request.args.get("q"))')
        self.assertEqual(len(findings),1)
        self.assertNotEqual(findings[0].confidence,'High')

    def test_attribute_and_exception_shadowing(self):
        for source in ('from flask import request\nrequest.args=unknown\neval(request.args["q"])', 'from flask import request\ntry:\n pass\nexcept Exception as request:\n eval(request.args["q"])'):
            finding=scan(source)[0]
            self.assertFalse(json.loads(finding.context_json)['analysis']['source'])
        finding=scan(DB+'cursor.execute=unknown\ncursor.execute("SELECT "+request.args["q"])')[0]
        self.assertEqual(finding.confidence,'Low')

    def test_database_import_shadow_and_request_branch_are_uncertain(self):
        findings=scan('from flask import request\nimport sqlite3\ndef route(sqlite3):\n cursor=sqlite3.connect("fixture").cursor()\n cursor.execute("SELECT "+request.args["q"])')
        self.assertEqual(findings[0].confidence,'Low')
        finding=scan('from flask import request\nif flag:\n request=unknown\neval(request.args["q"])')[0]
        self.assertFalse(json.loads(finding.context_json)['analysis']['source'])
        self.assertNotEqual(finding.confidence,'High')
