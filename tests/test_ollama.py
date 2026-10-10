"""Ollama-only boundary tests: synthetic context, no model download or real inference."""
import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from integrations.llm import review, available_model
from integrations.ollama import endpoint, request
from integrations.network import RemoteError, ResponseTooLarge
from tests.ollama_fixtures import envelope, transport
from tests.test_llm_review import response

CONFIG = {'LLM_ENABLED': True, 'OLLAMA_MODEL': 'fixture'}


class OllamaTests(unittest.TestCase):
    def test_loopback_only_no_dns_endpoint(self):
        for url in ('http://127.0.0.1:11434','http://localhost:11434','http://[::1]:11434'):
            self.assertEqual(endpoint(url)[1],11434)
        for url in ('https://example.com','http://example.com','http://10.0.0.1',
                    'http://127.0.0.1.evil.test','http://user@127.0.0.1',
                    'http://127.0.0.1/api','http://127.0.0.1?x=1',
                    'http://127.0.0.1#x','http://[::1%lo0]', 'http://127.0.0.1:0',
                    'http://127.0.0.1:65536','http://127.0.0.1\n'):
            with self.subTest(url=url), self.assertRaises(ValueError):endpoint(url)

    def test_model_missing_or_service_unavailable(self):
        for status, raw in ((200,b'{"models":[]}'),(503,b'private-body'),(200,b'bad'),(200,b'[]')):
            with patch('integrations.llm.request',return_value=(status,{},raw)) as send:
                with self.assertRaises(ValueError):review({},CONFIG)
                self.assertEqual(send.call_count,1)
        with patch('integrations.llm.request',side_effect=RemoteError('unavailable')):
            with self.assertRaises(RemoteError):review({},CONFIG)

    def test_cloud_aliases_and_missing_local_metadata_rejected(self):
        for detail in ({'remote_host':'https://cloud.invalid','details':{'format':'gguf'}},
                       {'remote_model':'remote','details':{'format':'gguf'}}, {}, []):
            with patch('integrations.llm.request',side_effect=[
                (200,{},b'{"models":[{"name":"fixture"}]}'),(200,{},json.dumps(detail).encode())]) as send:
                with self.assertRaises(ValueError):review({},CONFIG)
                self.assertEqual(send.call_count,2)

    def test_disabled_and_size_limits_before_network(self):
        with patch('integrations.llm.request') as send:
            for payload,config in (({},dict(CONFIG,LLM_ENABLED=False)),({},dict(CONFIG,OLLAMA_MODEL='')),({'snippet':'x'*48001},CONFIG)):
                with self.assertRaises(ValueError):review(payload,config)
            send.assert_not_called()

    def test_realistic_envelope_and_exact_selected_model(self):
        with patch('integrations.llm.request',side_effect=transport(200,envelope(json.dumps(response())))) as send:
            self.assertEqual(review({'snippet':'safe'},CONFIG),response())
            self.assertEqual([c.args[1] for c in send.call_args_list],['/api/tags','/api/show','/api/chat'])
            body=json.loads(send.call_args.kwargs['body'])
            self.assertEqual(body['model'],'fixture');self.assertFalse(body['stream'])
            self.assertEqual(body['options']['num_predict'],3000)
            self.assertNotIn('tools',body);self.assertNotIn('Authorization',str(send.call_args))
        with patch('integrations.llm.request',return_value=(200,{},b'{"models":[{"name":"different"}]}')):
            with self.assertRaises(ValueError):available_model(CONFIG)

    def test_incomplete_tool_nonobject_and_invalid_responses(self):
        for data in ([], {'done':False}, {'done':True,'done_reason':'length'},
                     {'done':True,'done_reason':'stop','message':{'role':'assistant','content':'[]'}},
                     {'done':True,'done_reason':'stop','message':{'role':'assistant','content':'bad'}},
                     {'done':True,'done_reason':'stop','message':{'role':'assistant','tool_calls':[{}],'content':'{}'}}):
            with patch('integrations.llm.request',side_effect=transport(200,json.dumps(data).encode())):
                with self.assertRaises(ValueError):review({},CONFIG)

    def test_local_http_limits_redirect_and_deadline(self):
        class Handler(BaseHTTPRequestHandler):
            mode='ok'
            def log_message(self,*args):pass
            def do_GET(self):
                if self.mode=='slow':time.sleep(.3)
                self.send_response(302 if self.mode=='redirect' else 200)
                self.send_header('Location','https://example.invalid/')
                self.end_headers()
                try:self.wfile.write(b'{"models":[]}')
                except OSError:pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        base='http://127.0.0.1:'+str(server.server_port)
        try:
            self.assertEqual(request(base,'/api/tags')[0],200)
            with self.assertRaises(ResponseTooLarge):request(base,'/api/tags',limit=4)
            Handler.mode='redirect';self.assertEqual(request(base,'/api/tags')[0],302)
            Handler.mode='slow'
            with self.assertRaises(RemoteError):request(base,'/api/tags',seconds=.05)
            with self.assertRaises(ValueError):request(base,'/api/pull',method='POST')
            with self.assertRaises(ValueError):request(base,'/api/chat',method='POST',body=b'x'*65537)
        finally:server.shutdown();server.server_close();thread.join()
