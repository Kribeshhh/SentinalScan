"""Phase23: inert source fixtures and isolated process/storage regressions."""
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from scanner.source_scanner import analyze_directory
from scanner.sast import javascript_scanner
from scanner.engines import external
from scanner.engines.process import run_tool, ToolFailure
from scanner import port_scanner
from scanner.target import validate_target


class Quality23Tests(unittest.TestCase):
    def js(self,source):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/'a.js').write_text(source)
            ctx=analyze_directory(root,['a.js'],'lab/quality');javascript_scanner.run(ctx);return ctx['findings']

    def test_dom_original_direct_decoded_alias_and_location(self):
        for source in ['node.insertAdjacentHTML("beforeend", location.hash);',
            'const content=decodeURIComponent(location.hash.slice(1));\nnode.insertAdjacentHTML("beforeend", content);',
            'const a=location.search; const b=a;\nnode.insertAdjacentHTML("afterbegin", b);']:
            with self.subTest(source=source):
                found=self.js(source);self.assertEqual(len(found),1)
                self.assertTrue(found[0].location.endswith(':'+str(source.count('\n')+1)))
                self.assertIn('Browser/HTTP input',found[0].evidence)
                self.assertEqual(found[0].severity,'Medium')

    def test_dom_safe_and_sanitized(self):
        for source in ['node.insertAdjacentHTML("beforeend","<b>constant</b>");',
            'node.textContent=location.hash;',
            'const safe=DOMPurify.sanitize(location.hash); node.insertAdjacentHTML("beforeend",safe);',
            'node.insertAdjacentHTML(location.hash,"constant");']:
            with self.subTest(source=source):self.assertEqual(self.js(source),[])

    def test_dom_unknown_transform_is_not_sanitizer(self):
        f=self.js('node.insertAdjacentHTML("beforeend", unknown(location.hash));')
        self.assertEqual(len(f),1)
        unknown=self.js('node.insertAdjacentHTML("beforeend", unknown());')
        self.assertEqual(len(unknown),1);self.assertEqual(unknown[0].confidence,'Medium')
        self.assertTrue(self.js('const DOMPurify={sanitize:x=>x}; node.insertAdjacentHTML("beforeend",DOMPurify.sanitize(location.hash));'))

    @unittest.skipUnless(os.environ.get('SENTINELSCAN_TEST_SEMGREP'),'Semgrep opt-in')
    def test_real_semgrep_receiver_and_dom(self):
        cases={
            'display.py':('class Printer:\n def execute(self,value):\n  print(value)\nfrom flask import request\nPrinter().execute("SELECT "+request.args.get("q"))',False),
            'rebound.py':('class Printer:\n def execute(self,value):\n  print(value)\nimport sqlite3\nfrom flask import request\nPrinter=sqlite3.connect\nPrinter(":memory:").execute("SELECT "+request.args.get("q"))',True),
            'wrapper.py':('class Printer:\n def execute(self,value):\n  print(value)\n  db.execute(value)\nfrom flask import request\nPrinter().execute("SELECT "+request.args.get("q"))',True),
            'sql.py':('import sqlite3 as sql\nfrom flask import request\ndb=sql.connect(":memory:")\ncursor=db.cursor()\ncursor.execute("SELECT "+request.args.get("q"))',True),
            'bound.py':('import sqlite3\nfrom flask import request\ndb=sqlite3.connect(":memory:")\ndb.execute("SELECT ?",(request.args.get("q"),))',False),
            'dom.js':('const v=decodeURIComponent(location.hash.slice(1)); document.body.insertAdjacentHTML("beforeend",v);',True),
            'safe.js':('document.body.insertAdjacentHTML("beforeend",DOMPurify.sanitize(location.hash));',False),
            'constant.js':('document.body.insertAdjacentHTML("beforeend","ok");',False)}
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for p,(s,_) in cases.items():(root/p).write_text(s)
            ctx=analyze_directory(root,list(cases),'lab/quality');ctx['engine_config']={'SEMGREP_ENABLED':True,'SEMGREP_BINARY':os.environ['SENTINELSCAN_TEST_SEMGREP']}
            self.assertEqual(external.semgrep(ctx)['status'],'Completed')
            # Both engines must resolve the same parsed operation for correlation.
            from analysis.correlation import review
            external_dom=next(f for f in ctx['findings'] if '/dom.js:' in f.location)
            javascript_scanner.run(ctx)
            builtin_dom=next(f for f in ctx['findings'] if '/dom.js:' in f.location and f.title=='Potential unsafe DOM HTML insertion')
            self.assertEqual(review(ctx,external_dom)[1],review(ctx,builtin_dom)[1])
            self.assertIsNotNone(review(ctx,builtin_dom)[1])
            for p,(_,expected) in cases.items():
                with self.subTest(path=p):self.assertEqual(any('/'+p+':' in f.location for f in ctx['findings']),expected)

    def test_nmap_success_and_arguments_cleanup(self):
        captured=[]
        def tool(args,work,seconds,output):
            captured.append((args,work,seconds));return b'<nmaprun><host><ports><port portid="80" protocol="tcp"><state state="open"/><service name="http"/></port></ports></host></nmaprun>'
        with patch('scanner.port_scanner.shutil.which',return_value='/trusted/nmap'),patch('scanner.port_scanner.run_tool',side_effect=tool):
            r=port_scanner.run({'target':validate_target('http://127.0.0.1/',True),'client':SimpleNamespace(end=time.monotonic()+30)})
        self.assertEqual(r['open_ports'][0]['port'],80);args,work,seconds=captured[0]
        self.assertEqual(args[-1],'127.0.0.1');self.assertLessEqual(seconds,18);self.assertFalse(Path(work).exists())
        self.assertEqual(r['tested_ports'],[80,443,8000,8080,8443])

    def test_nmap_failure_and_missing_fallback(self):
        for failure in [ToolFailure('timeout'),ToolFailure('nonzero'),ToolFailure('output'),OSError('missing'),None]:
            with self.subTest(failure=failure),patch('scanner.port_scanner.shutil.which',return_value='/trusted/nmap' if failure else None),patch('scanner.port_scanner.run_tool',side_effect=failure),patch('scanner.port_scanner.connect_ip',side_effect=OSError()):
                r=port_scanner.run({'target':validate_target('http://127.0.0.1/',True),'client':SimpleNamespace(end=time.monotonic()+30,remaining=lambda:1)})
                self.assertEqual(r['method'],'TCP connect fallback');self.assertTrue(r['warning'])

    def test_real_process_sanitization_and_limits(self):
        with tempfile.TemporaryDirectory() as td,patch.dict(os.environ,{'PHASE23_SENTINEL':'not-a-credential'}):
            result=Path(td)/'out'
            code='import os,pathlib,sys;pathlib.Path(sys.argv[1]).write_text(str("PHASE23_SENTINEL" in os.environ))'
            self.assertEqual(run_tool([sys.executable,'-c',code,str(result)],td,3,output=result),b'False')
            for code in ['raise SystemExit(2)','import time;time.sleep(3)','import sys;sys.stdout.write("x"*4096)']:
                with self.subTest(code=code),patch('scanner.engines.process.OUTPUT_LIMIT',1024),self.assertRaises(ToolFailure):
                    run_tool([sys.executable,'-c',code],td,.3)

    def test_new_database_private_existing_untouched(self):
        from app import create_app
        from database import get_db
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);existing=root/'existing';existing.touch();existing.chmod(0o644)
            for path,mode in [(root/'new',0o600),(existing,0o644)]:
                app=create_app({'TESTING':True,'DATABASE':str(path),'LLM_ENABLED':False})
                try:
                    with app.app_context():self.assertEqual(get_db().execute('PRAGMA integrity_check').fetchone()[0],'ok')
                    self.assertEqual(path.stat().st_mode & 0o777,mode)
                finally:app.extensions['scan_manager'].shutdown()

    def test_no_code_guidance_and_website_instructions(self):
        from analysis.solution_engine import solution_for
        f=dict(title='Server or framework version disclosed',category='Information Disclosure',source='Website',location='http://localhost/',recommendation='Minimize banners while keeping software patched.',status='Open',evidence='Server version disclosed')
        r=solution_for(f);self.assertEqual(r['examples'],[]);self.assertNotIn('merge the example',r['action']);self.assertIn('patched',r['action'])
        f.update(title='Missing X-Content-Type-Options',category='Security Headers')
        r=solution_for(f);self.assertTrue(r['examples']);self.assertIn('header',r['action'])
        page=(Path(__file__).resolve().parents[1]/'templates/website_scan.html').read_text()
        self.assertNotIn('placeholder="http://localhost:5001/?',page);self.assertIn('unsafe request replay',page)

    def test_no_code_ai_composition_and_invalid_fallback(self):
        from analysis.solution_engine import solution_for
        from analysis.ai_grounding import statements
        from analysis.llm_review import process,prepare
        from analysis.recommendation_composer import compose
        from tests.test_llm_review import response
        f=dict(title='Server or framework version disclosed',category='Information Disclosure',source='Website',location='http://localhost/',recommendation='Minimize banners.',status='Open',severity='Informational',confidence='High',evidence='Version banner')
        base=solution_for(f);policy=statements(f)
        answer=response(reason=policy['reason'][0],remediation=base['action'])
        answer['recommendation']['why']=policy['why'][0]
        reviewed=process(f,prepare(f,None),answer)
        for enabled,review in [(False,None),(True,reviewed),(True,{'broken':'answer'})]:
            with self.subTest(enabled=enabled,review=bool(review)):
                final=compose(f,base,review,enabled)
                self.assertEqual(final['examples'],[])
                self.assertNotIn('merge the example',final['action'])
                self.assertIn('patched',final['action'])
        self.assertTrue(compose(f,base,reviewed,True)['ai_assisted'])

    def test_timeout_reaps_child(self):
        with tempfile.TemporaryDirectory() as td:
            pid=Path(td)/'pid'
            with self.assertRaises(ToolFailure):
                run_tool([sys.executable,'-c','import os,sys,time;open(sys.argv[1],"w").write(str(os.getpid()));time.sleep(10)',str(pid)],td,.5)
            self.assertTrue(pid.exists())
            with self.assertRaises(ProcessLookupError):os.kill(int(pid.read_text()),0)
