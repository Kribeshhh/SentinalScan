"""P8 S2: no unreviewed query replay, including before active probes."""
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit,parse_qsl
from scanner.target import validate_target,TargetError
from scanner.http_scanner import Client,Response,ScanLimit,RequestFailure
from scanner.common import SkipModule
from scanner.xss_scanner import parameter_urls
from scanner import xss_scanner,sqli_scanner,cors_scanner


class ReplayTests(unittest.TestCase):
    def test_original_both_modules_no_requests(self):
        for query in ('action=fixture-noop&q=hello','q=hello&action=fixture-noop',
                      'action=fixture-noop&q=x&cmd=fixture-noop','q=x&q=y','q=',
                      'q=a%26action%3Dfixture-noop','q=%E9%9B%AA','arbitrary=anything'):
            u='http://127.0.0.1/?'+query
            for module in (xss_scanner,sqli_scanner,cors_scanner):
                client=Client(validate_target(u,True),interval=0)
                ctx=dict(target=client.target,response=Response(u,200,[('Content-Type','text/html')],b'baseline',False,[]),client=client,findings=[])
                with self.subTest(query=query,module=module.__name__),patch('scanner.http_scanner.connect_ip') as connect:
                    with self.assertRaises(SkipModule):module.run(ctx)
                    connect.assert_not_called();self.assertEqual(client.count,0)
                    self.assertEqual(ctx['findings'],[])

    def test_unreviewed_baseline_blocked_before_socket(self):
        u='http://127.0.0.1/?action=fixture-noop&q=hello'
        client=Client(validate_target(u,True))
        with patch('scanner.http_scanner.connect_ip') as connect:
            with self.assertRaises(SkipModule):client.get(u)
            connect.assert_not_called()
        self.assertEqual(client.count,0)

    def test_review_preserves_unrelated_bytes_and_duplicate_positions(self):
        u='http://127.0.0.1/?action=fixture-noop&q=&q=a%20b&name=%E9%9B%AA&blank'
        probes=list(parameter_urls(u,lambda value:value+"'",{u:[1,2,3,4]}))
        self.assertEqual(len(probes),4)
        for index,(_,probe,_) in zip((1,2,3,4),probes):
            old=urlsplit(u).query.split('&');new=urlsplit(probe).query.split('&')
            self.assertEqual(len(old),len(new))
            for i in range(len(old)):
                if i!=index:self.assertEqual(old[i],new[i])
            self.assertEqual(parse_qsl(urlsplit(probe).query,keep_blank_values=True)[index][1],parse_qsl(urlsplit(u).query,keep_blank_values=True)[index][1]+"'")
        # Approval of a different value, path, origin or parameter order does not transfer.
        for changed in (u.replace('fixture-noop','other'),u.replace('/?','/other?'),u.replace('127.0.0.1','localhost')):
            with self.assertRaises(SkipModule):list(parameter_urls(changed,str,{u:[1]}))

    def test_names_do_not_confer_safety_and_reviews_are_bounded(self):
        u='http://127.0.0.1/?action=fixture-noop&q=hello'
        with self.assertRaises(SkipModule):list(parameter_urls(u,str))
        self.assertEqual(len(list(parameter_urls(u,str,{u:[0]}))),1) # Explicit inert fixture review, not name-based approval.
        for positions in ([True],[-1],[99],[],['1']):
            with self.assertRaises(SkipModule):list(parameter_urls(u,str,{u:positions}))
        many='http://127.0.0.1/?'+'&'.join('q='+str(i) for i in range(9))
        self.assertEqual(len(list(parameter_urls(many,str,{many:list(range(9))}))),5)

    def test_review_never_bypasses_origin_ssrf_or_deadline(self):
        u='http://127.0.0.1/?q=x';other='http://localhost/?q=x'
        client=Client(validate_target(u,True),reviewed_queries={other:[0]},interval=0)
        with self.assertRaises(RequestFailure):client.get(other)
        with self.assertRaises(TargetError):validate_target('http://169.254.169.254/?q=x',True)
        client=Client(validate_target(u,True),reviewed_queries={u:[0]},deadline=0)
        with self.assertRaises(ScanLimit):client.get(u)


class LocalReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.requests=[]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                cls.requests.append(self.path)
                if self.path=='/redirect':
                    self.send_response(302);self.send_header('Location','/?action=fixture-noop&q=hello');self.end_headers();return
                q=dict(parse_qsl(urlsplit(self.path).query,keep_blank_values=True)).get('q','')
                body=('plain text' if self.path.startswith('/safe') else 'sqlite3.OperationalError: unrecognized token:' if "'" in q else '<script>let q="'+q+'";</script>').encode()
                self.send_response(200);self.send_header('Content-Type','text/html');self.end_headers();self.wfile.write(body)
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.base=f'http://127.0.0.1:{cls.server.server_port}'
    @classmethod
    def tearDownClass(cls):cls.server.shutdown();cls.server.server_close();cls.thread.join()
    def setUp(self):self.requests.clear()

    def test_unreviewed_same_origin_query_redirect_not_followed(self):
        u=self.base+'/redirect';client=Client(validate_target(u,True),interval=0)
        result=client.get(u)
        self.assertEqual(self.requests,['/redirect']);self.assertFalse(result.redirects[0]['followed'])
        self.assertIn('Query replay safety',result.redirects[0]['reason'])

    def test_reviewed_inert_detection_and_safe_negative(self):
        for path,positive in (('/',True),('/safe',False)):
            u=self.base+path+'?q=hello';client=Client(validate_target(u,True),interval=0,reviewed_queries={u:[0]})
            ctx=dict(target=client.target,client=client,response=client.get(u),findings=[])
            xss_scanner.run(ctx);sqli_scanner.run(ctx)
            self.assertEqual(bool(ctx['findings']),positive)
            if positive:self.assertEqual({f.title for f in ctx['findings']},{'Potential Reflected XSS','Potential SQL Injection'})
            self.assertEqual(client.count,3)

    def test_reviewed_request_count_and_size_limits(self):
        u=self.base+'/?q=hello';client=Client(validate_target(u,True),interval=0,reviewed_queries={u:[0]},max_requests=1,max_bytes=4)
        self.assertTrue(client.get(u).truncated)
        with self.assertRaises(ScanLimit):client.get(u)
        self.assertEqual(len(self.requests),1)

    def test_blocked_scan_records_skipped_http_and_no_false_clean_result(self):
        from app import create_app
        from database import get_db
        with tempfile.TemporaryDirectory() as td:
            app=create_app({'TESTING':True,'DATABASE':str(Path(td)/'db.sqlite3'),'LLM_ENABLED':False})
            try:
                u=self.base+'/?action=fixture-noop&q=hello'
                with app.app_context(),patch('scanner.port_scanner.shutil.which',return_value=None):
                    sid=app.extensions['scan_manager'].submit(validate_target(u,True),[])
                    # Keep external port inventory disabled until the worker finishes.
                    app.extensions['scan_manager'].shutdown()
                with app.app_context():
                    db=get_db();module=db.execute("SELECT * FROM scan_modules WHERE scan_id=? AND name='HTTP'",(sid,)).fetchone()
                    self.assertEqual(module['status'],'Skipped');self.assertIn('Query replay safety',module['error'])
                    self.assertEqual(db.execute('SELECT status FROM scans WHERE id=?',(sid,)).fetchone()[0],'Failed')
                self.assertEqual(self.requests,[])
            finally:app.extensions['scan_manager'].shutdown()
