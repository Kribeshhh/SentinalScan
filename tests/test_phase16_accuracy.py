"""Controlled inert regressions for the Phase 16 audit defects."""
import json
import tempfile
import unittest
from pathlib import Path
from scanner.source_scanner import analyze_directory
from scanner.sast import python_scanner, javascript_scanner, html_scanner, secret_scanner
from analysis.correlation import review


class RepositoryAccuracyCorrections(unittest.TestCase):
    def scan(self, source, path='a.py', module=python_scanner):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/path).write_text(source)
            ctx=analyze_directory(root,[path],'audit/fixture');module.run(ctx)
            return ctx['findings'], [review(ctx,f) for f in ctx['findings']]

    def test_distinct_same_line_occurrences(self):
        for prefix in ('', 'from flask import request\n'):
            findings, reviewed=self.scan(prefix+'eval(request.args.get("x")); eval(request.args.get("y"))\n')
            self.assertEqual(len(findings),2)
            self.assertEqual(len({f.fingerprint for f in findings}),2)
            self.assertEqual(len({key for f,key in reviewed}),2)
            self.assertTrue(all(f.location.endswith(':2' if prefix else ':1') for f in findings))
            self.assertEqual([f.confidence for f in findings],['High' if prefix else 'Medium']*2)
            self.assertIn('eval',findings[0].evidence)
        findings,_=self.scan('eval("1"); eval("2")')
        self.assertEqual(findings,[])

    def test_identical_same_line_and_javascript_occurrences(self):
        for source,path,module in [('eval(value); eval(value)','a.py',python_scanner),('eval(location.hash); eval(location.hash);','a.js',javascript_scanner)]:
            findings, reviewed=self.scan(source,path,module)
            self.assertEqual(len({f.fingerprint for f in findings}),2)
            self.assertEqual(len({key for f,key in reviewed}),2)

    def test_repeated_analysis_keeps_same_operation_identity(self):
        findings,_=self.scan('def helper(x):\n eval(x)\nhelper(a)\nhelper(b)')
        self.assertEqual(len(findings),1)
        analysis=json.loads(findings[0].context_json)['analysis']
        self.assertNotIn('occurrence_column',analysis)

    def test_html_comment_location(self):
        findings,_=self.scan('<p>hi</p>\n<!-- disable authentication -->','index.html',html_scanner)
        self.assertEqual([(f.location,f.severity,f.confidence) for f in findings],[('audit/fixture/index.html:2','Low','Low')])
        source='<script>const example="<!-- disable authentication -->";</script>\n<!-- public -->\n<!-- disable authentication -->\n<p>hi</p>\n<!-- disable authentication -->'
        findings,_=self.scan(source,'index.html',html_scanner)
        self.assertEqual([f.location for f in findings],['audit/fixture/index.html:3','audit/fixture/index.html:5'])
        self.assertEqual(self.scan('<!-- public layout section -->','index.html',html_scanner)[0],[])

    def test_documentation_phrase_not_credential(self):
        source='The UI renders this phrase:\npassword="Choose a memorable passphrase for your account"'
        self.assertEqual(self.scan(source,'guide.md',secret_scanner)[0],[])
        findings,_=self.scan('password="Choose a memorable passphrase for your account"','a.py',secret_scanner)
        self.assertEqual(len(findings),1)  # Actual source assignments still reviewed.
        findings,_=self.scan('password="SyntheticFixture-Credential-93284"','guide.md',secret_scanner)
        self.assertEqual(len(findings),1)
        self.assertNotIn('SyntheticFixture-Credential-93284',findings[0].evidence)
        self.assertEqual((findings[0].severity,findings[0].confidence),('High','Low'))

    def test_unknown_custom_constant_is_not_invented_credential(self):
        # D09 is intentionally unresolved: the fixture contract supplies knowledge
        # absent from source. Do not hardcode its custom name or value as a secret.
        for source in ('connection_material="OrionService-884932-Auth"', 'display_material="OrionService-884932-Label"'):
            self.assertEqual(self.scan(source,'a.py',secret_scanner)[0],[])
        self.assertEqual(len(self.scan('password="SyntheticFixture-93284-Auth"','a.py',secret_scanner)[0]),1)

    def test_same_line_persistence(self):
        from app import create_app
        from database import get_db
        from analysis.correlation import persist_candidates
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/'a.py').write_text('eval(value); eval(value)')
            ctx=analyze_directory(root,['a.py'],'audit/fixture');python_scanner.run(ctx)
            app=create_app({'TESTING':True,'DATABASE':str(root/'test.sqlite3'),'REPORTS_DIR':str(root/'reports'),'LLM_ENABLED':False})
            try:
                with app.app_context():
                    db=get_db()
                    sid=db.execute("INSERT INTO scans(scan_type,target,status) VALUES ('Repository','audit/fixture','Completed')").lastrowid
                    persist_candidates(db,sid,ctx,ctx['findings'])
                    persist_candidates(db,sid,ctx,ctx['findings'])
                    rows=db.execute('SELECT location,severity,confidence,fingerprint FROM findings WHERE scan_id=?',(sid,)).fetchall()
                    self.assertEqual(len(rows),2)
                    self.assertEqual(len({r['fingerprint'] for r in rows}),2)
                    self.assertEqual({r['location'] for r in rows},{'audit/fixture/a.py:1'})
            finally:
                app.extensions['scan_manager'].shutdown()


class WebsiteAccuracyCorrections(unittest.TestCase):
    def response(self, body, status=200, headers=()):
        from scanner.http_scanner import Response
        return Response('https://localhost/?q=fixture',status,[('Content-Type','text/html'),*headers],body.encode(),False,[])

    def run_module(self, module, base, reply=None, paths=None):
        from unittest.mock import Mock
        from scanner.target import validate_target
        client=Mock()
        from scanner.xss_scanner import parameter_urls
        # Synthetic response fixture; explicitly reviewed query mutation.
        client.parameter_urls.side_effect=lambda url, fn: parameter_urls(url, fn, {base.url:[0]})
        if callable(reply): client.get.side_effect=reply
        else: client.get.return_value=reply
        ctx=dict(target=validate_target('https://localhost/?q=fixture',True),response=base,client=client,findings=[],paths=paths or [])
        result=module.run(ctx)
        return ctx['findings'],result

    def test_framing_policy_semantics(self):
        from scanner import header_scanner as module
        for csp,xfo,expected in [("frame-ancestors *",'',False),("frame-ancestors *",'DENY',False),("frame-ancestors https:",'',False),("frame-ancestors",'',False),("frame-ancestors 'none'",'',True),("frame-ancestors 'self'",'',True),("frame-ancestors https://trusted.invalid",'',True),("frame-ancestors https://*.trusted.invalid",'',True),("frame-ancestors *; frame-ancestors 'none'",'',False),("frame-ancestors *; default-src 'none'",'',False),('', 'DENY',True),('', 'ALLOWALL',False)]:
            with self.subTest(csp=csp,xfo=xfo):
                findings,result=self.run_module(module,self.response('body',headers=[('Content-Security-Policy',csp),('X-Frame-Options',xfo)]))
                selected=[f for f in findings if f.title=='Missing or invalid framing protection']
                self.assertEqual(bool(selected),not expected)
                self.assertEqual(result['framing_protection'],expected)
                if selected:self.assertEqual((selected[0].severity,selected[0].confidence),('Low','High'))

    def test_inert_script_reflection(self):
        from scanner import xss_scanner as module
        from urllib.parse import parse_qs, urlsplit
        for kind,expected in [('',True),('module',True),('text/javascript',True),('application/json',False),('application/ld+json',False),('importmap',False),('text/plain',False)]:
            def reply(url):
                marker=parse_qs(urlsplit(url).query)['q'][0]
                return self.response('<script type="'+kind+'">"'+marker+'"</script>')
            findings,result=self.run_module(module,self.response('baseline'),reply)
            self.assertEqual(bool(findings),expected,kind)
            self.assertTrue(result['parameters'][0]['reflected'])
            if findings:self.assertEqual((findings[0].severity,findings[0].confidence),('Low','Low'))

    def test_error_signature_context(self):
        from scanner import sqli_scanner, disclosure_scanner
        for body,expected in [('Database error: sqlite3.OperationalError: fixture',True),('sqlite3.OperationalError: fixture',True),('<pre>sqlite3.OperationalError: fixture</pre>',True),('Documentation: sqlite3.OperationalError is a Python exception.',False),('<p>Documentation: <code>sqlite3.OperationalError</code> is an exception.</p>',False),('generic error',False)]:
            findings,_=self.run_module(sqli_scanner,self.response('baseline'),self.response(body))
            self.assertEqual(bool(findings),expected,body)
            if findings:self.assertEqual((findings[0].severity,findings[0].confidence),('Medium','Medium'))
        for body,expected in [('Internal error: Traceback (most recent call last)',True),('Traceback (most recent call last)',True),('<pre>Traceback (most recent call last)\n  File "a.py"</pre>',True),('Tutorial: Traceback (most recent call last)',False),('<p>Tutorial: <code>Traceback (most recent call last)</code></p>',False),('generic error',False)]:
            findings,_=self.run_module(disclosure_scanner,self.response(body))
            self.assertEqual(bool(findings),expected,body)
            if findings:self.assertEqual((findings[0].severity,findings[0].confidence),('Low','High'))
        self.assertEqual(self.run_module(sqli_scanner,self.response('sqlite3.OperationalError'),self.response('sqlite3.OperationalError'))[0],[])

    def test_directory_listing_survives_length_similarity(self):
        from scanner import directory_scanner as module
        missing='<html><title>not found</title><p>no</p></html>'
        listing='<html><title>Index of /uploads</title></html>'
        for base_body,result_body,status,expected in [('x'*45,'<title>Index of /uploads</title>',200,True),(missing,listing,200,True),(missing,missing,200,False),(listing,listing,200,False),(missing,listing,403,False),(missing,'<html><title>ordinary</title></html>',200,False)]:
            def reply(url,**kwargs):
                return self.response(base_body if 'sentinelscan-not-found-' in url else result_body,status=200 if 'sentinelscan-not-found-' in url else status)
            findings,result=self.run_module(module,self.response('base'),reply,paths=['/uploads'])
            self.assertEqual(bool(findings),expected)
            if expected:
                self.assertFalse(result['resources'][0]['possible_soft_404'])
                self.assertEqual((findings[0].severity,findings[0].confidence),('Low','High'))
