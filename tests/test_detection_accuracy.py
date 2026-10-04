"""Accuracy examples are parsed as text only, never executed."""
from pathlib import Path
import tempfile
import unittest
from scanner.source_scanner import analyze_directory
from scanner.sast import python_scanner, javascript_scanner, java_scanner, secret_scanner


class DetectionAccuracyTests(unittest.TestCase):
    def scan(self, source, language='py'):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path='Example.'+language
            (root/path).write_text(source)
            ctx=analyze_directory(root,[path],'lab/accuracy')
            {'py':python_scanner,'js':javascript_scanner,'java':java_scanner,'txt':secret_scanner}[language].run(ctx)
            return ctx['findings']

    def test_flask_sources_and_alias_chain(self):
        for source in ('request.args.get("u")','request.form["u"]','request.values.get("u")','request.json["u"]','request.get_json()["u"]','request.headers.get("u")','request.cookies.get("u")'):
            with self.subTest(source=source):
                findings=self.scan('from flask import request\ndef route():\n    username='+source+'\n    name=username\n    query="SELECT * FROM users WHERE name="+name\n    cursor.execute(query)')
                self.assertEqual(len(findings),1);self.assertEqual(findings[0].confidence,'High')
                self.assertIn('username → name → query',findings[0].evidence)

    def test_python_sql_protection_and_static_values(self):
        for source in ('cursor.execute("SELECT ?", (request.args.get("u"),))', 'q="SELECT "+"1"\ncursor.execute(q)', 'cursor.execute(query_object)'):
            self.assertEqual(self.scan(source),[])
        for source in ('q=f"SELECT {user_id}"\ncursor.execute(q)', 'q="SELECT {}".format(user_id)\ncursor.execute(q)', 'q="SELECT "+user_id\ncursor.execute(q,(other,))'):
            findings=self.scan(source);self.assertEqual(len(findings),1);self.assertEqual(findings[0].confidence,'Medium')

    def test_python_command_and_eval(self):
        for sink in ('os.system(value)','os.popen(value)','subprocess.run(value,shell=True)','subprocess.call(value,shell=True)','subprocess.Popen(value,shell=True)','eval(value)','exec(value)'):
            with self.subTest(sink=sink):
                findings=self.scan('import os, subprocess\nvalue=request.args.get("x")\n'+sink)
                self.assertEqual(len(findings),1);self.assertEqual(findings[0].confidence,'High')
                self.assertEqual(self.scan('import os, subprocess\nvalue="date"\n'+sink),[])
        self.assertEqual(self.scan('import subprocess\nsubprocess.run(["echo",request.args.get("x")],shell=False)'),[])

    def test_python_order_scope_branches_import_alias(self):
        cases=[('x=request.args.get("x")\neval(x)\nx="1"',1),('x=request.args.get("x")\nx="1"\neval(x)',0),('def a():\n x="1"\ndef b():\n eval(x)',1),('x=request.args.get("x")\nif flag:\n x="1"\neval(x)',1),('import os as system\nfor i in items:\n pass\nsystem.system(request.args.get("x"))',1)]
        for source,count in cases:self.assertEqual(len(self.scan(source)),count)

    def test_python_deserialization_and_crypto(self):
        self.assertEqual(self.scan('import yaml\nyaml.load(request.get_json(),Loader=yaml.SafeLoader)\nyaml.safe_load(data)'),[])
        findings=self.scan('import pickle\npickle.loads(request.args.get("x"))');self.assertEqual(findings[0].confidence,'High')
        findings=self.scan('import pickle\npickle.loads(data)');self.assertEqual(findings[0].confidence,'Low')
        findings=self.scan('import hashlib\nchecksum=hashlib.md5(file_contents)\npassword_hash=hashlib.md5(password.encode())')
        self.assertEqual([(f.severity,f.confidence) for f in findings],[('Informational','Low'),('High','Medium')])
        self.assertEqual(self.scan('import hashlib\nhashlib.sha256(data)'),[])

    def test_javascript_html_protection_aliases_and_sources(self):
        for sink in ('node.innerHTML = value','node.outerHTML = value','document.write(value)'):
            for source,expected in [('const value="hello";',0),('const value=DOMPurify.sanitize(userInput);',0),('const clean=DOMPurify.sanitize(userInput); const value=clean;',0),('const value=userInput;',1),('const value=location.hash;',1)]:
                with self.subTest(sink=sink,source=source):
                    findings=self.scan(source+sink,'js');self.assertEqual(len(findings),expected)
                    if 'location.hash' in source:self.assertEqual(findings[0].confidence,'High')

    def test_javascript_execution_sanitizer_is_sink_specific(self):
        for sink in ('eval(value)','Function(value)','new Function(value)'):
            self.assertEqual(self.scan('const value="return 1";'+sink,'js'),[])
            findings=self.scan('const value=location.hash;'+sink,'js');self.assertEqual(findings[0].confidence,'High')
            self.assertEqual(len(self.scan('const value=DOMPurify.sanitize(userInput);'+sink,'js')),1)

    def test_javascript_order_and_scope(self):
        for source,count in [('let x=userInput; eval(x); x="1";',1),('let x=userInput; x="1"; eval(x);',0),('function a(){const x="1";} function b(){eval(x);}',1),('let x="1"; function f(x){eval(x);}',1),('let x=userInput; if(flag){x="1";} eval(x);',1),('let clean=DOMPurify.sanitize(userInput);clean=location.hash;node.innerHTML=clean;',1)]:
            self.assertEqual(len(self.scan(source,'js')),count,source)

    def java(self,body):return self.scan('class Example { void run(HttpServletRequest request, String unknown) throws Exception {'+body+'}}','java')

    def test_java_process_and_sql(self):
        for sink in ('Runtime.getRuntime().exec(value);','new ProcessBuilder(value);','stmt.executeQuery("SELECT "+value);','connection.prepareStatement("SELECT "+value);'):
            with self.subTest(sink=sink):
                self.assertEqual(self.java('String value="date";'+sink),[])
                findings=self.java('String value=request.getParameter("x");'+sink)
                self.assertEqual(len(findings),1);self.assertEqual(findings[0].confidence,'High')
                findings=self.java('String value=unknown;'+sink);self.assertEqual(findings[0].confidence,'Medium')
        self.assertEqual(self.java('PreparedStatement s=connection.prepareStatement("SELECT ?");s.setString(1,unknown);s.executeQuery();'),[])
        self.assertEqual(self.java('stmt.executeQuery(String.format("SELECT %s","1"));'),[])

    def test_java_deserialization_and_crypto(self):
        findings=self.java('ObjectInputStream s=new ObjectInputStream(request.getInputStream());s.readObject();')
        self.assertEqual(findings[0].confidence,'High')
        findings=self.java('ObjectInputStream s=new ObjectInputStream(stream);s.readObject();')
        self.assertEqual(findings[0].confidence,'Low')
        findings=self.java('MessageDigest checksum=MessageDigest.getInstance("MD5");MessageDigest passwordHash=MessageDigest.getInstance("SHA-1");')
        self.assertEqual([f.severity for f in findings],['Informational','High'])
        self.assertEqual(self.java('MessageDigest.getInstance("SHA-256");Cipher.getInstance("AES/GCM/NoPadding");mapper.readValue(json,Data.class);'),[])

    def test_secret_placeholders_and_masking(self):
        for value in ('your-api-key-here','replace-me','example-token','dummy-password','test-secret','changeme'):
            self.assertEqual(self.scan('password="'+value+'"','txt'),[])
        secret='LocalCredential-731-OnlyFixture'
        findings=self.scan('password="'+secret+'"','txt')
        self.assertTrue(findings);self.assertNotIn(secret,str(findings))
        findings=self.scan('SECRET_KEY="'+secret+'"')
        # Secret detection is a separate module from language code analysis.
        self.assertEqual(findings,[])
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'settings.py').write_text('SECRET_KEY="'+secret+'"')
            ctx=analyze_directory(root,['settings.py'],'lab/accuracy');secret_scanner.run(ctx)
            self.assertEqual(len(ctx['findings']),1);self.assertNotIn(secret,str(ctx['findings']))
