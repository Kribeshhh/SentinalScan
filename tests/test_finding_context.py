"""Context reflects observed source/responses and survives sanitized persistence."""
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
from analysis.finding_context import repository_context, website_context
from analysis.finding_engine import Finding, sanitize_finding
from analysis.solution_engine import solution_for
from scanner.http_scanner import Response
from scanner import cors_scanner, cookie_scanner, sqli_scanner


class FindingContextTests(unittest.TestCase):
    def response(self,status=200,headers=None,body=b'',url='https://example.test/?q=privatevalue'):
        return Response(url,status,headers or [],body,False,[])

    def test_source_categories_keep_actual_context_and_unknowns(self):
        for title,category,code in [
            ('Potential SQL injection in constructed query','Injection','cursor.execute(query)'),
            ('Potential shell command injection','Injection','os.system(command)'),
            ('Dynamic Python code execution','Injection','eval(expression)'),
            ('Potential DOM HTML injection','Injection','node.innerHTML = input'),
            ('Potential embedded credential','Secret Exposure','password = "S3nsitiveValue987"'),
            ('Weak hash algorithm','Cryptography','hashlib.md5(value)')]:
            js='DOM' in title
            source='function show() {\n'+code+'\n}' if js else 'def run():\n    '+code+'\n'
            f=dict(title=title,category=category,source='Repository',location='o/r/app.'+('js' if js else 'py')+':2',evidence='Static pattern',recommendation='Review the operation.')
            solution=solution_for(f,source);c=solution['finding_context']
            self.assertEqual(c['line'],2);self.assertEqual(c['function'],'show' if js else 'run')
            self.assertTrue(c['snippet']);self.assertIsNone(c['input_source']);self.assertIsNone(c['database'])
            self.assertNotIn('S3nsitiveValue987',json.dumps(c))
            for key in ('what_to_change','suggested_code_or_config','example_type','why','additional_actions','fix_confidence','validation_status'):self.assertIn(key,solution)

    def test_flow_and_missing_source_are_honest(self):
        c=repository_context(dict(location='o/r/app.py:9',evidence='Recognized input request.args → query → SQL execute. No protection recognized for this operation.'))
        self.assertEqual(c['input_source'],'request.args');self.assertEqual(c['sink'],'SQL execute')
        self.assertEqual(c['simple_flow'],['query']);self.assertIsNone(c['snippet']);self.assertIsNone(c['function'])
        self.assertIn('not proof',c['protection'])

    def test_headers_and_queries_exclude_credentials(self):
        r=self.response(headers=[('Authorization','Bearer private-auth'),('Set-Cookie','sid=private-cookie'),('Content-Security-Policy',"script-src 'nonce-private-nonce'"),('Server','example')])
        data=json.dumps(website_context({'response':r}))
        for value in ('private-auth','private-cookie','private-nonce','privatevalue'):self.assertNotIn(value,data)
        self.assertIn('[REDACTED]',data)

    def test_cookie_and_cors_attach_actual_observations(self):
        r=self.response(headers=[('Set-Cookie','sid=opaque-cookie-value')]);ctx={'response':r,'target':SimpleNamespace(url=r.url),'findings':[]}
        cookie_scanner.run(ctx)
        c=json.loads(ctx['findings'][0].context_json)
        self.assertFalse(c['observations']['cookie_attributes']['httponly']);self.assertNotIn('opaque-cookie-value',json.dumps(c))
        probe=self.response(202,[('Access-Control-Allow-Origin','https://sentinelscan-probe.invalid'),('Access-Control-Allow-Credentials','true')])
        ctx['client']=Mock();ctx['client'].get.return_value=probe;ctx['findings']=[]
        cors_scanner.run(ctx);c=json.loads(ctx['findings'][0].context_json)
        self.assertEqual(c['http_status'],202);self.assertEqual(c['observations']['cors']['request_origin'],'https://sentinelscan-probe.invalid')

    def test_sql_probe_status_not_baseline_and_no_body(self):
        r=self.response();probe=self.response(500,body=b'sqlite3.OperationalError password=NotForStorage987')
        ctx={'response':r,'target':SimpleNamespace(url=r.url),'findings':[],'client':Mock()};ctx['client'].get.return_value=probe
        sqli_scanner.run(ctx);c=json.loads(ctx['findings'][0].context_json)
        self.assertEqual(c['http_status'],500);self.assertEqual(c['observations']['baseline_status'],200)
        self.assertNotIn('NotForStorage987',json.dumps(c));self.assertIsNone(c['response_snippet'])

    def test_structured_redaction_preserves_json_and_identity(self):
        f=Finding(title='Test',severity='Low',confidence='High',category='Test',source='Repository',location='o/r/app.py:1',description='Test',evidence='Test',impact='Test',recommendation='Review',context_json=json.dumps({'snippet':'password="known-value"','nested':{'authorization':'opaque'}}))
        clean=sanitize_finding(f,['known-value']);c=json.loads(clean.context_json)
        self.assertNotIn('known-value',json.dumps(c));self.assertNotIn('opaque',json.dumps(c));self.assertEqual(f.fingerprint,clean.fingerprint)

    def test_website_categories_never_guess_backend(self):
        for title,category in [('Missing Content-Security-Policy','Security Headers'),('Cookie missing HttpOnly: sid','Cookie Security'),('Potential unsafe credentialed CORS','CORS'),('Potential Reflected XSS','Reflected XSS'),('Potential SQL Injection','SQL Injection'),('TLS certificate validation failed','TLS'),('Exposed Git metadata','Information Disclosure'),('Server technology disclosure','Information Disclosure')]:
            s=solution_for(dict(title=title,category=category,source='Website',location='https://example.test',evidence='Observed',recommendation='Review observed control.'))
            self.assertIn(s['example_type'],('configuration','none'));self.assertFalse(s['source_matched'])
            self.assertEqual(s['validation_status'],'Not Available');self.assertIsNone(s['finding_context']['http_status'])
            self.assertNotIn('sqlite3',json.dumps(s['examples']))
