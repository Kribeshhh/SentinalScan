import ipaddress
import json
from contextlib import closing
from pathlib import Path
import sqlite3
import ssl
import tempfile
import threading
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from werkzeug.serving import make_server, WSGIRequestHandler
from app import create_app
from database import get_db
from examples.lab_app import app as lab_app
from scanner.target import validate_target, TargetError
from scanner.http_scanner import Client, ScanLimit
from scanner.directory_scanner import paths_from_text
from scanner.website_scanner import MODULES
from scanner import tls_scanner


class QuietHandler(WSGIRequestHandler):
    def log(self, *args, **kwargs):
        pass


class WebsiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = make_server('127.0.0.1', 0, lab_app, threaded=True, request_handler=QuietHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f'http://localhost:{cls.server.server_port}/?q=hello'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.app = create_app({'TESTING':True, 'DATABASE':str(Path(self.directory.name)/'scan.sqlite3'), 'SCANNER_CLIENT_OPTIONS':{'interval':0,'timeout':1}})
        self.client = self.app.test_client()
        self.client.get('/website-scan')
        with self.client.session_transaction() as session:
            self.token = session['csrf_token']

    def tearDown(self):
        self.app.extensions['scan_manager'].shutdown()
        self.directory.cleanup()

    def submit(self, url=None):
        return self.client.post('/website-scan', data={'csrf_token':self.token,'url':url or self.url,'authorized':'yes','allow_private':'yes','action':'start','paths':'/.env\n/.git/HEAD'})

    def test_localhost_real_assessment_pipeline(self):
        with patch('scanner.port_scanner.shutil.which', return_value=None):
            response = self.submit()
            self.assertEqual(response.status_code,303)
            self.app.extensions['scan_manager'].shutdown()
        with self.app.app_context():
            db = get_db()
            scan = db.execute('SELECT * FROM scans').fetchone()
            self.assertEqual(scan['status'],'Completed')
            self.assertEqual(scan['progress'],100)
            self.assertNotIn('hello',scan['target'])
            modules = db.execute('SELECT * FROM scan_modules').fetchall()
            self.assertEqual(len(modules),len(MODULES))
            self.assertTrue(all(m['status']=='Completed' for m in modules), [(m['name'],m['error']) for m in modules])
            titles = [r[0] for r in db.execute('SELECT title FROM findings')]
            for expected in ('Potential Reflected XSS','Potential SQL Injection','Potential unsafe credentialed CORS','Exposed Git metadata','Potential exposed environment configuration'):
                self.assertIn(expected,titles)
            for row in db.execute('SELECT f.category,s.data_json FROM findings f JOIN finding_solutions s ON s.finding_id=f.id'):
                solution=json.loads(row['data_json']);context=solution['finding_context']
                self.assertEqual(context['kind'],'dast')
                self.assertTrue(context['affected_url'])
                self.assertIn(context['http_method'],('GET',None))
                self.assertEqual(solution['example_type'] in ('configuration','none'),True)
                self.assertNotIn('Python',json.dumps(solution['examples']))
            self.assertGreater(scan['risk_score'],0)
            dump = '\n'.join(db.iterdump())
            self.assertNotIn('LAB_COOKIE_VALUE_MUST_NOT_BE_STORED',dump)
            self.assertNotIn('APP_MODE=educational',dump)
            self.assertIn('TCP connect fallback',dump)
            finding_id = db.execute('SELECT id FROM findings LIMIT 1').fetchone()[0]
        self.assertEqual(self.client.get(response.headers['Location']).status_code,200)
        self.assertEqual(self.client.get(response.headers['Location']+'/status').json['status'],'Completed')
        self.assertEqual(self.client.get(f'/findings/{finding_id}').status_code,200)
        self.assertIn('Potential SQL Injection', self.client.get('/findings').get_data(as_text=True))

    def test_validation_and_authorization(self):
        for url in ('file:///etc/passwd','ftp://example.com','http://user:pass@localhost','http://169.254.169.254/','http://100.100.100.200/','http://0.0.0.0/','http://[ff02::1]/','http://[fe80::1]/','http://[fd00:ec2::254]/','http://127.1/','http://localhost:99999/','http://localhost:0/','http://localhost\\@example.com','http://localhost/\r\nheader'):
            with self.subTest(url=url), self.assertRaises(TargetError):
                validate_target(url,True)
        with self.assertRaises(TargetError):
            validate_target(self.url)
        self.assertEqual(validate_target('http://[::1]/',True).addresses,('::1',))
        self.assertEqual(validate_target('http://192.168.1.2/',True).addresses,('192.168.1.2',))
        self.assertEqual(self.client.post('/website-scan',data={'url':self.url,'action':'start'}).status_code,400)
        self.assertEqual(self.client.post('/website-scan',data={'csrf_token':self.token,'url':self.url,'action':'start','allow_private':'yes'}).status_code,400)
        with self.assertRaises(ValueError):
            paths_from_text('//external.test/path')
        with self.assertRaises(ValueError):
            paths_from_text('/../private')

    def test_pinning_redirect_and_limits(self):
        target = validate_target(self.url,True)
        with patch('socket.getaddrinfo',side_effect=AssertionError('Unexpected DNS re-resolution')):
            response = Client(target,interval=0).get(self.url)
        self.assertEqual(response.status,200)
        url = self.url.split('/?')[0] + '/redirect-external'
        response = Client(target,interval=0).get(url)
        self.assertEqual(response.status,302)
        self.assertFalse(response.redirects[0]['followed'])
        client = Client(target,interval=0,max_requests=1,max_bytes=50)
        response = client.get(self.url)
        self.assertEqual(len(response.body),50)
        self.assertTrue(response.truncated)
        with self.assertRaises(ScanLimit):
            client.get(self.url)

    def test_one_module_failure_does_not_abort_scan(self):
        replacement = [(name, (lambda ctx: (_ for _ in ()).throw(RuntimeError('private detail'))) if name=='Ports' else module) for name,module in MODULES]
        with patch('scanner.website_scanner.MODULES',replacement):
            self.submit()
            self.app.extensions['scan_manager'].shutdown()
        with self.app.app_context():
            db=get_db()
            self.assertEqual(db.execute('SELECT status FROM scans').fetchone()[0],'Completed')
            self.assertEqual(db.execute("SELECT status FROM scan_modules WHERE name='Ports'").fetchone()[0],'Failed')
            self.assertEqual(db.execute("SELECT status FROM scan_modules WHERE name='HTTP'").fetchone()[0],'Completed')
            self.assertNotIn('private detail','\n'.join(db.iterdump()))

    def test_https_valid_and_untrusted_certificate(self):
        key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1))
                .not_valid_after(datetime.now(timezone.utc)+timedelta(days=60))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
                .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(key,hashes.SHA256()))
        certpath=Path(self.directory.name)/'cert.pem'; keypath=Path(self.directory.name)/'key.pem'
        certpath.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        keypath.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(certpath,keypath)
        server=make_server('127.0.0.1',0,lab_app,threaded=True,ssl_context=context,request_handler=QuietHandler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            url=f'https://localhost:{server.server_port}/?q=hello'
            target=validate_target(url,True)
            client=Client(target,cafile=str(certpath),interval=0)
            response=client.get(url)
            ctx={'target':target,'client':client,'response':response,'findings':[]}
            data=tls_scanner.run(ctx)
            self.assertTrue(data['verified']);self.assertTrue(data['available'])
            self.app.config['SCANNER_CLIENT_OPTIONS']={'cafile':str(certpath),'interval':0,'timeout':1}
            with patch('scanner.port_scanner.shutil.which',return_value=None):
                self.submit(url)
                self.app.extensions['scan_manager'].shutdown()
            with self.app.app_context():
                self.assertEqual(get_db().execute('SELECT status FROM scans').fetchone()[0],'Completed')
                self.assertIn('Missing or disabled HSTS',[r[0] for r in get_db().execute('SELECT title FROM findings')])
            ctx={'target':target,'client':Client(target,interval=0),'findings':[]}
            data=tls_scanner.run(ctx)
            self.assertFalse(data['verified'])
            self.assertIn('TLS certificate validation failed',[f.title for f in ctx['findings']])
            finding=next(f for f in ctx['findings'] if f.title=='TLS certificate validation failed')
            self.assertFalse(json.loads(finding.context_json)['observations']['tls']['verified'])
        finally:
            server.shutdown();server.server_close();thread.join()

    def test_migration_preserves_existing_related_records(self):
        path=Path(self.directory.name)/'old.sqlite3'
        with closing(sqlite3.connect(path)) as db:
            db.executescript("""CREATE TABLE scans(id INTEGER PRIMARY KEY,scan_type TEXT,target TEXT,status TEXT CHECK(status IN ('Pending','Running','Completed','Failed')),repository_id INTEGER,created_at TEXT,completed_at TEXT);
                INSERT INTO scans VALUES(42,'Website','http://localhost','Completed',NULL,'2026-01-01',NULL);
                CREATE TABLE migration_child(scan_id INTEGER REFERENCES scans(id));
                INSERT INTO migration_child VALUES(42);""")
        migrated=create_app({'TESTING':True,'DATABASE':str(path)})
        try:
            with migrated.app_context():
                db=get_db()
                self.assertEqual(db.execute('SELECT id FROM scans').fetchone()[0],42)
                self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(),[])
                self.assertEqual(db.execute('SELECT scan_id FROM migration_child').fetchone()[0],42)
                db.execute("INSERT INTO scans(scan_type,target,status) VALUES('Website','http://localhost','Queued')")
                db.commit()
        finally:
            migrated.extensions['scan_manager'].shutdown()

    def test_plain_text_reflection_is_not_xss_or_sqli(self):
        from scanner import xss_scanner, sqli_scanner
        url = self.url.replace('/?','/safe?')
        target = validate_target(url,True)
        client = Client(target,interval=0)
        ctx = {'target':target,'client':client,'response':client.get(url),'findings':[]}
        observations = xss_scanner.run(ctx)
        self.assertTrue(observations['parameters'][0]['reflected'])
        self.assertEqual(observations['parameters'][0]['contexts'],['HTML text'])
        sqli_scanner.run(ctx)
        self.assertEqual(ctx['findings'],[])

    def test_mixed_dns_answers_rejected_before_connection(self):
        import dns.resolver
        def resolve(host, record, **kwargs):
            if record == 'A':
                return ['93.184.216.34','127.0.0.1']
            raise dns.resolver.NoAnswer()
        with patch('dns.resolver.Resolver.resolve',side_effect=resolve):
            with self.assertRaises(TargetError):
                validate_target('https://authorized.example/')
        def metadata(host, record, **kwargs):
            if record == 'A':
                return ['169.254.169.254']
            raise dns.resolver.NoAnswer()
        with patch('dns.resolver.Resolver.resolve',side_effect=metadata):
            with self.assertRaises(TargetError):
                validate_target('https://authorized.example/',True)

    def test_restart_marks_interrupted_jobs_failed(self):
        with self.app.app_context():
            db=get_db()
            scan_id=db.execute("INSERT INTO scans(scan_type,target,status) VALUES('Website','http://localhost','Running')").lastrowid
            db.execute("INSERT INTO scan_modules(scan_id,name,status) VALUES(?,'HTTP','Running')",(scan_id,))
            db.commit()
        restarted=create_app({'TESTING':True,'DATABASE':self.app.config['DATABASE']})
        try:
            with restarted.app_context():
                self.assertEqual(get_db().execute('SELECT status FROM scans WHERE id=?',(scan_id,)).fetchone()[0],'Failed')
                self.assertEqual(get_db().execute('SELECT status FROM scan_modules WHERE scan_id=?',(scan_id,)).fetchone()[0],'Failed')
        finally:
            restarted.extensions['scan_manager'].shutdown()
