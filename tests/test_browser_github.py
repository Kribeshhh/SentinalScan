"""Browser credential entry never returns or persists the token outside server memory."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from app import create_app
from database import get_db
from integrations.credentials import CredentialStore
from integrations.github import GitHubError
from test_source_scanner import FixtureGitHub, FAKE_AUTH, REPO


class BrowserGitHubTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.config = {'TESTING': True, 'DATABASE': str(Path(self.temp.name)/'test.sqlite3'), 'GITHUB_CLIENT_FACTORY': FixtureGitHub}
        self.app = create_app(self.config)
        self.client = self.app.test_client()
        self.client.get('/repository-scan')
        with self.client.session_transaction() as session:
            self.csrf = session['csrf_token']

    def tearDown(self):
        self.app.extensions['scan_manager'].shutdown()
        self.temp.cleanup()

    def connect(self, **kwargs):
        return self.client.post('/repository-scan', data={'csrf_token': self.csrf, 'action': 'connect', 'github_token': FAKE_AUTH}, **kwargs)

    def test_browser_connect_scan_disconnect_without_environment(self):
        with patch.dict(os.environ, {'SENTINELSCAN_GITHUB_TOKEN': ''}):
            response = self.connect(follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn('Connected to GitHub', response.get_data(as_text=True))
            self.assertEqual(FixtureGitHub.token_seen, FAKE_AUTH)
            self.assertNotIn(FAKE_AUTH, response.get_data(as_text=True)+str(response.headers))
            with self.client.session_transaction() as session:
                self.assertNotIn(FAKE_AUTH, str(dict(session)))
                handle = session['github_credential']
            store = self.app.extensions['github_credentials']
            self.assertEqual(store.get(handle), FAKE_AUTH)
            self.assertNotIn(FAKE_AUTH, repr(store))
            response = self.client.post('/repository-scan', data={'csrf_token': self.csrf, 'action': 'start',
                                        'repository': REPO['full_name'], 'branch': 'main', 'authorized': 'yes'})
            self.assertEqual(response.status_code, 303)
            self.assertEqual(FixtureGitHub.token_seen, FAKE_AUTH)
            self.app.extensions['scan_manager'].executor.submit(lambda: None).result(timeout=10)
            with self.app.app_context():
                self.assertEqual(get_db().execute('SELECT status FROM scans').fetchone()[0], 'Completed')
                self.assertNotIn(FAKE_AUTH, '\n'.join(get_db().iterdump()))
            self.client.post('/repository-scan', data={'csrf_token': self.csrf, 'action': 'disconnect'})
            self.assertIsNone(store.get(handle))
            with self.client.session_transaction() as session:
                self.assertNotIn('github_credential', session)
                self.assertNotIn('github_connected', session)

    def test_invalid_or_rejected_token_is_not_retained_or_echoed(self):
        class Rejected(FixtureGitHub):
            def identity(self):
                raise GitHubError('GitHub authorization failed. Check your token.')
        with patch.dict(self.app.config, {'GITHUB_CLIENT_FACTORY': Rejected}):
            response = self.connect()
            self.assertEqual(response.status_code, 400)
            self.assertNotIn(FAKE_AUTH, response.get_data(as_text=True))
            self.assertIn('type="password"', response.get_data(as_text=True))
            with self.client.session_transaction() as session:
                self.assertNotIn('github_credential', session)
        for token in ('short', 'a'*256, 'token with spaces and control\r\n'):
            response = self.client.post('/repository-scan', data={'csrf_token': self.csrf,'action':'connect','github_token':token})
            self.assertEqual(response.status_code, 400)
            self.assertNotIn('value="'+token+'"', response.get_data(as_text=True))

    def test_csrf_remote_http_and_browser_isolation(self):
        response = self.client.post('/repository-scan', data={'action':'connect','github_token':FAKE_AUTH})
        self.assertEqual(response.status_code, 400)
        response = self.connect(environ_overrides={'REMOTE_ADDR':'192.168.1.10'})
        self.assertEqual(response.status_code, 400)
        self.assertIn('localhost or HTTPS', response.get_data(as_text=True))
        self.assertEqual(self.connect().status_code, 303)
        other = self.app.test_client()
        page = other.get('/repository-scan').get_data(as_text=True)
        self.assertNotIn('Connected to GitHub', page)
        self.assertNotIn(FAKE_AUTH, page)
        self.assertIn('Connected to GitHub', self.client.get('/repository-scan').get_data(as_text=True))

    def test_restart_expires_connection_even_with_signed_session_cookie(self):
        self.connect()
        with self.client.session_transaction() as session:
            saved = dict(session)
        restarted = create_app(self.config)
        try:
            fresh = restarted.test_client()
            with fresh.session_transaction() as session:
                session.update(saved)
            page = fresh.get('/repository-scan').get_data(as_text=True)
            self.assertIn('connection cleared', page)
            self.assertNotIn('Connected to GitHub', page)
            self.assertNotIn(FAKE_AUTH, page)
            with fresh.session_transaction() as session:
                self.assertNotIn('github_credential', session)
        finally:
            restarted.extensions['scan_manager'].shutdown()

    def test_store_is_bounded_and_reconnect_rotates_handle(self):
        store = CredentialStore(capacity=1)
        first = store.put('one'); second = store.put('two')
        self.assertIsNone(store.get(first)); self.assertEqual(store.get(second), 'two')
        self.connect()
        with self.client.session_transaction() as session:
            old = session['github_credential']
        self.connect()
        self.assertIsNone(self.app.extensions['github_credentials'].get(old))
