"""Phase 21: inert parsed source and real optional Semgrep; no fixture execution."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from scanner.source_scanner import analyze_directory
from scanner.sast import python_scanner, java_scanner, secret_scanner
from scanner.engines import external


class RepositoryAccuracy21Tests(unittest.TestCase):
    def scan(self, source, module=python_scanner, path='sample.py'):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);f=root/path;f.parent.mkdir(parents=True,exist_ok=True);f.write_text(source)
            ctx=analyze_directory(root,[path],'lab/phase21');module.run(ctx)
            return ctx['findings']

    def test_original_quoted_and_dangerous_execution(self):
        prefix='import os, shlex\nfrom flask import request\n'
        self.assertEqual(self.scan(prefix+'os.system("echo "+shlex.quote(request.args.get("msg")))'),[])
        for command in ('request.args.get("msg")','"echo "+request.args.get("msg")',
                        '"sh -c "+shlex.quote(request.args.get("msg"))',
                        ''''echo "'+shlex.quote(request.args.get("msg"))+'"' '''):
            self.assertTrue(self.scan(prefix+'os.system('+command+')'))
        self.assertEqual(self.scan('example="os.system(user_input)"\n# os.system(user_input)'),[])

    def test_quote_identity_shadowing(self):
        for prefix in ('', 'import shlex\nshlex=other\n'):
            self.assertTrue(self.scan(prefix+'import os\nos.system("echo "+shlex.quote(value))'))
        self.assertEqual(self.scan('import os\nfrom shlex import quote as q\nos.system("echo "+q(value))'),[])

    def test_checksum_unknown_and_explicit_nonsecurity(self):
        original='import hashlib\nchecksum=hashlib.md5(public_file_bytes).hexdigest()'
        f=self.scan(original);self.assertEqual([(x.severity,x.confidence) for x in f],[('Informational','Low')])
        self.assertEqual(self.scan('import hashlib\nchecksum=hashlib.md5(public_file_bytes,usedforsecurity=False).hexdigest()'),[])
        self.assertEqual(self.scan('import hashlib\nchecksum=hashlib.new("md5",public_file_bytes,usedforsecurity=False)'),[])
        self.assertTrue(self.scan('import hashlib\npassword_hash=hashlib.md5(password.encode(),usedforsecurity=False)'))
        self.assertTrue(self.scan('import hashlib\nchecksum=hashlib.md5(password.encode())'))
        self.assertTrue(self.scan('import hashlib\nchecksum=hashlib.md5(data,usedforsecurity=unknown)'))

    def test_java_unknown_hash_and_security_positive(self):
        f=self.scan('class Checksum { void run() throws Exception { MessageDigest checksum=MessageDigest.getInstance("MD5"); } }',java_scanner,'a.java')
        self.assertEqual([(x.severity,x.confidence) for x in f],[('Informational','Low')])
        for code in ('MessageDigest passwordHash=MessageDigest.getInstance("SHA-1");','Cipher c=Cipher.getInstance("DES");'):
            f=self.scan('class A { void run() throws Exception { '+code+' } }',java_scanner,'a.java')
            self.assertTrue(f);self.assertNotEqual(f[0].severity,'Informational')
        self.assertEqual(self.scan('class A { void run() { java.util.zip.CRC32 c=new java.util.zip.CRC32(); c.update(data); } }',java_scanner,'a.java'),[])

    def test_custom_name_without_evidence_is_not_guessed(self):
        fixtures=json.loads(Path('evaluation/fixtures.json').read_text())['fixtures']
        original=next(f['source'] for f in fixtures if f['id']=='secret_custom_name')
        self.assertEqual(self.scan(original,secret_scanner),[]) # Known unresolved FN; do not relabel.
        for value in ('123e4567-e89b-12d3-a456-426614174000','a'*32,'U29tZSBwdWJsaWMgZGF0YQ==','PublicIdentifier-83642'):
            self.assertEqual(self.scan('material='+repr(value),secret_scanner),[])

    def test_custom_names_known_auth_sink_and_alias(self):
        value='SyntheticNonfunctional-'+str(73129)
        source='import psycopg2 as db\nmaterial='+repr(value)+'\nalias=material\ndb.connect(password=alias)'
        f=self.scan(source,secret_scanner)
        self.assertEqual(len(f),1);self.assertTrue(f[0].location.endswith(':2'))
        self.assertEqual((f[0].severity,f[0].confidence),('High','Medium'))
        self.assertNotIn(value,str(f));self.assertIn('[REDACTED]',f[0].evidence)
        self.assertTrue(self.scan('from requests.auth import HTTPBasicAuth as Auth\nAuth("user",'+repr(value)+')',secret_scanner))

    def test_secret_identity_scope_and_reassignment(self):
        literal=repr('SyntheticNonfunctional-'+str(83519))
        for source in ('material='+literal+'\nunknown.connect(password=material)',
                       'import psycopg2 as db\nmaterial='+literal+'\ndb=other\ndb.connect(password=material)',
                       'import psycopg2 as db\nmaterial='+literal+'\nmaterial=env\ndb.connect(password=material)',
                       'import psycopg2 as db\ndef f(db):\n material='+literal+'\n db.connect(password=material)',
                       'import psycopg2 as db\nmaterial='+literal+'\nif flag:\n material=env\ndb.connect(password=material)'):
            self.assertEqual(self.scan(source,secret_scanner),[])
        self.assertTrue(self.scan('import psycopg2 as db\ndef f():\n material='+literal+'\n db.connect(password=material)',secret_scanner))

    def test_named_secret_dedup_documentation_and_placeholders(self):
        literal=repr('SyntheticNonfunctional-'+str(73129))
        source='import psycopg2\npassword='+literal+'\npsycopg2.connect(password=password)\npsycopg2.connect(password=password)'
        self.assertEqual(len(self.scan(source,secret_scanner)),1)
        self.assertEqual(self.scan('import psycopg2\nmaterial="replace-me"\npsycopg2.connect(password=material)',secret_scanner),[])
        source='import psycopg2\nmaterial='+literal+'\npsycopg2.connect(password=material)'
        f=self.scan(source,secret_scanner,'fixtures/a.py');self.assertEqual(f[0].confidence,'Low')
        self.assertEqual(self.scan('```python\n'+source+'\n```',secret_scanner,'guide.md'),[])

    @unittest.skipUnless(os.environ.get('SENTINELSCAN_TEST_SEMGREP'),'Existing Semgrep opt-in required')
    def test_semgrep_allowlist_and_nonterminating_reassigned_guards(self):
        prefix='from flask import request\nname=request.args.get("order")\n'
        sink='cursor.execute("SELECT x FROM places ORDER BY "+name)'
        cases={
            'safe.py':(prefix+'if name not in ("name","city"):\n raise ValueError()\n'+sink,False),
            'vulnerable.py':(prefix+sink,True),
            'not_exit.py':(prefix+'if name not in ("name","city"):\n print("bad")\n'+sink,True),
            'reassigned.py':(prefix+'if name not in ("name","city"):\n raise ValueError()\nname=request.args.get("new")\n'+sink,True),
            'dynamic_choices.py':(prefix+'if name not in ("name",other):\n raise ValueError()\n'+sink,True),
            'conditional.py':(prefix+'if flag:\n if name not in ("name","city"):\n  raise ValueError()\n'+sink,True),
            'suppressed.py':(prefix+'with suppress(ValueError):\n if name not in ("name","city"):\n  raise ValueError()\n'+sink,True),
            'caught_group.py':(prefix+'try:\n if name not in ("name","city"):\n  raise ValueError()\nexcept* ValueError:\n pass\n'+sink,True),
            'caught.py':(prefix+'try:\n if name not in ("name","city"):\n  raise ValueError()\nexcept ValueError:\n pass\n'+sink,True),
        }
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for path,(source,_) in cases.items():(root/path).write_text(source)
            ctx=analyze_directory(root,list(cases),'lab/phase21');ctx['engine_config']={'SEMGREP_ENABLED':True,'SEMGREP_BINARY':os.environ['SENTINELSCAN_TEST_SEMGREP']}
            result=external.semgrep(ctx);self.assertEqual(result['status'],'Completed')
            for path,(_,expected) in cases.items():
                with self.subTest(path=path):self.assertEqual(any('/'+path+':' in f.location for f in ctx['findings']),expected)

    def test_worker_persistence_reports_ai_redaction_and_single_finding(self):
        from app import create_app
        from database import get_db
        from scanner.source_scanner import run_repository,MODULE_NAMES
        from reports.report_generator import generate_report,open_report
        from analysis.llm_review import prepare
        import zipfile
        value='SyntheticNonfunctional-'+str(92641)
        source='import psycopg2\nmaterial='+repr(value)+'\npsycopg2.connect(password=material)\npsycopg2.connect(password=material)'
        class Archive:
            def archive(self,repository,commit,destination):
                with zipfile.ZipFile(destination,'w') as z:z.writestr('snapshot/source.py',source)
        with tempfile.TemporaryDirectory() as td:
            app=create_app({'TESTING':True,'DATABASE':str(Path(td)/'db.sqlite3'),'REPORTS_DIR':str(Path(td)/'reports'),
                            'LLM_ENABLED':False,'SEMGREP_ENABLED':False,'CODEQL_ENABLED':False})
            try:
                with app.app_context():
                    db=get_db()
                    with db:
                        sid=db.execute("INSERT INTO scans(scan_type,target,status) VALUES ('Repository','lab/phase21','Queued')").lastrowid
                        db.execute('INSERT INTO repositories(name,location,scan_id) VALUES (?,?,?)',('phase21','lab/phase21',sid))
                        db.executemany('INSERT INTO scan_modules(scan_id,name) VALUES (?,?)',[(sid,n) for n in MODULE_NAMES])
                run_repository(app,sid,Archive(),{'full_name':'lab/phase21'},'main','a'*40,False)
                with app.app_context():
                    db=get_db();self.assertEqual(db.execute('SELECT status FROM scans').fetchone()[0],'Completed')
                    findings=db.execute("SELECT * FROM findings WHERE category='Secret Exposure'").fetchall()
                    self.assertEqual(len(findings),1);finding=dict(findings[0]);self.assertTrue(finding['location'].endswith('source.py:2'))
                    self.assertNotIn(value,'\n'.join(db.iterdump()))
                    self.assertNotIn(value,json.dumps(prepare(finding,None)))
                    for fmt in ('HTML','JSON','CSV'):
                        rid=generate_report(sid,fmt);row=db.execute('SELECT * FROM reports WHERE id=?',(rid,)).fetchone()
                        with open_report(row) as report:self.assertNotIn(value,report.read().decode())
                page=app.test_client().get('/findings/'+str(finding['id']))
                self.assertEqual(page.status_code,200);self.assertNotIn(value,page.get_data(as_text=True))
            finally:app.extensions['scan_manager'].shutdown()
