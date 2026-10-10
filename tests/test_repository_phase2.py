"""Bounded static flow and optional engine contracts; scanned fixtures never execute."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from scanner.source_scanner import analyze_directory
from scanner.sast import python_scanner
from scanner.engines import external
from scanner.engines.process import ToolFailure,run_tool
from scanner.engines.sarif import import_results


def sarif(path='a.py',flow=False):
    def location(line):
        return {'physicalLocation':{'artifactLocation':{'uri':path},'region':{'startLine':line,'endLine':line}}}
    item={'ruleId':'python/sql-injection','level':'error','message':{'text':'SECRET-RAW-TOOL-MESSAGE'},'locations':[location(3)]}
    if flow:item['codeFlows']=[{'threadFlows':[{'locations':[{'location':location(1)},{'location':location(3)}]}]}]
    return json.dumps({'version':'2.1.0','runs':[{'tool':{'driver':{'rules':[{'id':'python/sql-injection','properties':{'tags':['external/cwe/cwe-089'],'security-severity':'9.1'}}]}},'results':[item]}]}).encode()


class FlowTests(unittest.TestCase):
    def scan(self,source):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'a.py';path.write_text(source)
            ctx=analyze_directory(path.parent,['a.py'],'lab/flow')
            data=python_scanner.run(ctx)
            return ctx['findings'],data

    def test_cross_function_source_to_sink_and_returned_query(self):
        source='''from flask import request
import sqlite3
cursor=sqlite3.connect(':memory:').cursor()
def build_query(value):
 return "SELECT "+value
def search(value):
 query=build_query(value)
 cursor.execute(query)
def route():
 username=request.args.get("q")
 search(username)
'''
        findings,_=self.scan(source)
        self.assertEqual(len(findings),1)
        self.assertEqual(findings[0].confidence,'High')
        data=json.loads(findings[0].context_json)['analysis']
        self.assertIn('search',data['calls']);self.assertIn('build_query',data['calls'])
        self.assertTrue(data['source']);self.assertEqual(data['sink'],'SQL execute')
        self.assertIn('Static source-to-sink',data['reachability'])
        self.assertIn('build_query() return',findings[0].evidence)

    def test_returned_input_alias_and_transform(self):
        findings,_=self.scan('''from flask import request
import sqlite3
cursor=sqlite3.connect(':memory:').cursor()
def read():
 return request.args.get("q")
def build(x):
 return "SELECT "+x
alias=read
value=alias()
q=build(value)
cursor.execute(q)
''')
        self.assertEqual(len(findings),1);self.assertEqual(findings[0].confidence,'High')

    def test_safe_constant_parameterization_and_sink_specific_protection(self):
        for source in ['''def query(x):
 return "SELECT ?"
cursor.execute(query(request.args.get("q")),(request.args.get("q"),))''',
                       '''import subprocess
def execute(value):
 subprocess.run(["echo",value],shell=False)
execute(request.args.get("q"))''',
                       '''def fixed(value):
 return "1"
eval(fixed(request.args.get("q")))''']:
            with self.subTest(source=source):self.assertEqual(self.scan(source)[0],[])
        findings,_=self.scan('''def escape_html(value):
 return value
value=escape_html(request.args.get("q"))
eval(value)''')
        self.assertTrue(findings)

    def test_recursion_is_bounded_and_uncertain(self):
        findings,data=self.scan('''from flask import request
import sqlite3
cursor=sqlite3.connect(':memory:').cursor()
def cycle(x):
 return cycle(x)
cursor.execute(cycle(request.args.get("q")))''')
        self.assertEqual(data['flow_limited_files'],['a.py'])
        self.assertEqual(findings[0].confidence,'Medium')
        self.assertEqual(json.loads(findings[0].context_json)['analysis']['reachability'],'Potential pattern')

    def test_unknown_call_does_not_prove_sanitization(self):
        findings,_=self.scan('from flask import request\nimport sqlite3\ncursor=sqlite3.connect(":memory:").cursor()\nq=validate_username(request.args.get("q"))\ncursor.execute(q)')
        self.assertEqual(findings[0].confidence,'Medium')
        self.assertIn('Potential pattern',findings[0].context_json)

    def test_numeric_sql_protection_survives_supported_helper_only(self):
        source='def numeric(x):\n return int(x)\nq="SELECT "+str(numeric(request.args.get("q")))\ncursor.execute(q)'
        self.assertEqual(self.scan(source)[0],[])
        findings,_=self.scan('q="SELECT "+unknown_transform(int(request.args.get("q")))\ncursor.execute(q)')
        self.assertTrue(findings)

    def test_dead_code_and_function_shadowing(self):
        self.assertEqual(self.scan('if False:\n eval(request.args.get("q"))')[0],[])
        findings,_=self.scan('''def helper(x):
 return request.args.get("q")
def route(helper):
 cursor.execute(helper("fixed"))''')
        self.assertEqual(findings,[])
        findings,_=self.scan('''def f():
 return "constant"
 eval(request.args.get("q"))''')
        self.assertEqual(findings,[])


class ExternalEngineTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);(self.root/'a.py').write_text('x=input()\nq=x\ncursor.execute(q)')
        self.ctx=analyze_directory(self.root,['a.py'],'lab/tools')
        self.ctx['engine_config']={'SEMGREP_ENABLED':True,'CODEQL_ENABLED':True}

    def test_both_disabled_and_unavailable(self):
        with patch('scanner.engines.external.shutil.which',return_value=None):
            for fn in (external.semgrep,external.codeql):
                self.assertEqual(fn(self.ctx)['status'],'Skipped')
        self.ctx['engine_config']={}
        with patch('scanner.engines.external.run_tool') as run:
            self.assertEqual(external.semgrep(self.ctx)['status'],'Skipped')
            self.assertEqual(external.codeql(self.ctx)['status'],'Skipped');run.assert_not_called()

    def test_valid_semgrep_and_codeql_paths_normalized_without_messages(self):
        for engine in ('Semgrep','CodeQL'):
            with self.subTest(engine=engine):
                self.ctx['findings']=[]
                result=import_results(sarif(flow=True),self.ctx,engine)
                self.assertEqual(result['status'],'Completed')
                finding=self.ctx['findings'][0];data=json.loads(finding.context_json)['analysis']
                self.assertEqual(data['engine'],engine);self.assertEqual(data['cwe'],'CWE-89')
                self.assertEqual(finding.severity,'Critical');self.assertEqual(finding.confidence,'Medium')
                self.assertEqual(len(data['data_flow']),2)
                self.assertNotIn('SECRET-RAW',str(finding))
                self.assertEqual(data['verification_status'],'Not verified')

    def test_path_traversal_remote_uri_and_malformed_output(self):
        for path in ('../outside.py','https://example.test/a.py','missing.py','%2e%2e/outside.py'):
            result=import_results(sarif(path),self.ctx,'Semgrep')
            self.assertEqual(result['rejected_results'],1)
        self.assertEqual(self.ctx['findings'],[])
        for body in (b'not json',b'[]',b'{"version":"2.1.0","runs":[{"results":null}]}'):
            with self.assertRaises(ToolFailure):import_results(body,self.ctx,'CodeQL')

    def test_semgrep_command_uses_trusted_rules_no_remote_auto_or_build(self):
        with patch('scanner.engines.external.executable',return_value='/trusted/semgrep'),patch('scanner.engines.external.run_tool',return_value=sarif()) as run:
            self.assertEqual(external.semgrep(self.ctx)['status'],'Completed')
            args=run.call_args.args[0]
            self.assertIn('--metrics=off',args);self.assertIn('--disable-version-check',args)
            self.assertNotIn('--autofix',args);self.assertNotIn('auto',args)
            self.assertNotIn('--allow-local-builds',args)
            self.assertFalse(Path(args[args.index('--config')+1]).is_relative_to(self.root))

    def test_codeql_create_analyze_safe_no_build(self):
        with patch('scanner.engines.external.executable',return_value='/trusted/codeql'),patch('scanner.engines.external.run_tool',side_effect=[b'',sarif(flow=True)]) as run:
            self.assertEqual(external.codeql(self.ctx)['status'],'Completed')
            create=run.call_args_list[0].args[0];analyze=run.call_args_list[1].args[0]
            self.assertIn('--build-mode=none',create)
            self.assertIn('codeql/python-queries',analyze)
            self.assertFalse(any(arg.startswith('--command') or arg=='--download' for arg in create+analyze))

    def test_tool_failure_timeout_and_bad_output_graceful(self):
        for fn in (external.semgrep,external.codeql):
            for response in (ToolFailure('Analysis timed out.'),ToolFailure('Tool failed.'),b'not json'):
                with self.subTest(fn=fn.__name__,response=response):
                    effects=[response] if fn==external.semgrep or isinstance(response,Exception) else [b'',response]
                    with patch('scanner.engines.external.executable',return_value='/trusted/tool'),patch('scanner.engines.external.run_tool',side_effect=effects):
                        self.assertEqual(fn(self.ctx)['status'],'Failed')
        self.assertEqual(self.ctx['findings'],[])

    def test_codeql_java_only_skipped_and_repo_executable_rejected(self):
        self.ctx['paths']=['A.java']
        self.assertEqual(external.codeql(self.ctx)['status'],'Skipped')
        with patch('scanner.engines.external.shutil.which',return_value=str(self.root/'codeql')):
            with self.assertRaises(ToolFailure):external.executable({},'CODEQL',self.root)

    def test_runner_scrubs_environment_and_enforces_timeout_output(self):
        output=self.root/'env.json'
        # This is a trusted test helper, not scanned repository code.
        script='import json,os,pathlib;pathlib.Path("env.json").write_text(json.dumps(dict(os.environ)))'
        with patch.dict(os.environ,{'GITHUB_TOKEN':'PRIVATE-TEST-TOKEN','PYTHONPATH':'/untrusted','SEMGREP_APP_TOKEN':'SECRET'}):
            data=run_tool([sys.executable,'-I','-c',script],self.root,3,output)
        self.assertNotIn('PRIVATE-TEST-TOKEN',data.decode());self.assertNotIn('SECRET',data.decode())
        self.assertNotIn('PYTHONPATH',json.loads(data))
        with self.assertRaisesRegex(ToolFailure,'timed out'):
            run_tool([sys.executable,'-I','-c','import time;time.sleep(2)'],self.root,.1)
        with patch('scanner.engines.process.OUTPUT_LIMIT',200):
            with self.assertRaisesRegex(ToolFailure,'output limit'):
                run_tool([sys.executable,'-I','-c','print("x"*2000)'],self.root,3)


@unittest.skipUnless(os.environ.get('SENTINELSCAN_TEST_SEMGREP'), 'Optional live Semgrep binary not configured')
class LiveSemgrepTests(unittest.TestCase):
    def test_bundled_rules_vulnerable_safe_and_protected(self):
        samples=[
            ('sql.py','from flask import request\nq="SELECT "+request.args.get("q")\ncursor.execute(q)',1),
            ('bound.py','from flask import request\ncursor.execute("SELECT ?",(request.args.get("q"),))',0),
            ('constant.py','cursor.execute("SELECT 1")',0),
            ('numeric.py','from flask import request\ncursor.execute("SELECT "+str(int(request.args.get("q"))))',0),
            ('shell.py','import subprocess\nfrom flask import request\nsubprocess.run(request.args.get("q"),shell=True)',1),
            ('safe_shell.py','import subprocess\nfrom flask import request\nsubprocess.run(["echo",request.args.get("q")],shell=False)',0),
            ('dom.js','const x=location.hash; document.body.innerHTML=x;',1),
            ('safe_dom.js','const x=DOMPurify.sanitize(location.hash); document.body.innerHTML=x;',0),
        ]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for path,source,_ in samples:(root/path).write_text(source)
            ctx=analyze_directory(root,[s[0] for s in samples],'lab/live-semgrep')
            ctx['engine_config']={'SEMGREP_ENABLED':True,'SEMGREP_BINARY':os.environ['SENTINELSCAN_TEST_SEMGREP']}
            result=external.semgrep(ctx)
            self.assertEqual(result['status'],'Completed',result)
            for path,_,expected in samples:
                with self.subTest(path=path):
                    self.assertEqual(sum(f.location.startswith('lab/live-semgrep/'+path+':') for f in ctx['findings']),expected)
            for f in ctx['findings']:
                data=json.loads(f.context_json)['analysis']
                self.assertTrue(data['rule_id'].startswith('sentinelscan.'))
                self.assertTrue(data['cwe'])
