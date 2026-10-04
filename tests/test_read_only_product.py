"""The recommendation viewer has no edit/publication execution surface."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from app import create_app
from database import get_db
from integrations.github import GitHubClient

class ReadOnlyProductTests(unittest.TestCase):
    def test_removed_routes_and_preserved_historical_tables(self):
        with tempfile.TemporaryDirectory() as directory:
            app=create_app({'TESTING':True,'DATABASE':str(Path(directory)/'db')})
            try:
                client=app.test_client();client.get('/')
                with client.session_transaction() as session: csrf=session['csrf_token']
                for suffix in ('edit','publish','patch','validate','pull-request/refresh','rescan','verify'):
                    with self.subTest(route=suffix):
                        self.assertEqual(client.get('/findings/1/'+suffix).status_code,404)
                        self.assertEqual(client.post('/findings/1/'+suffix,data={'csrf_token':csrf}).status_code,404)
                with app.app_context():
                    tables={r[0] for r in get_db().execute("SELECT name FROM sqlite_master WHERE type='table'")}
                    self.assertTrue({'remediation_drafts','draft_checks','pull_request_tracking','remediation_verifications'}.issubset(tables))
                for path in ('/','/website-scan','/repository-scan','/findings','/scans','/comparisons','/risk-trends','/reports'):
                    response=client.get(path)
                    self.assertEqual(response.status_code,200,path)
                    self.assertNotIn(b'Review / Edit Fix',response.data)
            finally: app.extensions['scan_manager'].shutdown()

    def test_github_client_is_read_only(self):
        client=GitHubClient()
        for name in ('publish_fix','pull_status','includes_commit'):
            self.assertFalse(hasattr(client,name))
        with patch('integrations.github.request',return_value=(200,{},b'{"login":"fixture"}')) as request:
            self.assertEqual(client.identity(),'fixture')
            self.assertNotIn('body',request.call_args.kwargs)
            self.assertEqual(request.call_args.kwargs.get('method','GET'),'GET')
            with self.assertRaises(TypeError):client.api('/repos/fixture/repo',method='PUT',payload={})
            self.assertEqual(request.call_count,1)
