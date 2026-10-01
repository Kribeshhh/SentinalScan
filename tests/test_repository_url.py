"""URL input is canonicalized before reaching the fixed-host GitHub client."""
import unittest
from unittest.mock import patch
import test_browser_github
from test_source_scanner import FixtureGitHub,REPO
from integrations.github import repository_input,GitHubError
from database import get_db


class RepositoryURLTests(unittest.TestCase):
    def test_url_validation(self):
        for value in ('owner/repo','https://github.com/owner/repo',' https://github.com/owner/repo/ ',
                      'https://github.com/owner/repo.git','https://github.com/owner/repo.git/'):
            self.assertEqual(repository_input(value),'owner/repo')
        for value in ('http://github.com/owner/repo','https://github.com.evil.test/owner/repo',
                      'https://user:password@github.com/owner/repo','https://github.com:443/owner/repo',
                      'https://github.com/owner/repo/tree/main','https://github.com/owner/repo?token=hidden',
                      'https://github.com/owner/repo#readme','git@github.com:owner/repo.git',
                      'https://127.0.0.1/owner/repo','https://github.com/owner/%2e%2e','https://github.com/owner/repo\nextra'):
            with self.subTest(value=value),self.assertRaises(GitHubError):repository_input(value)

    def test_open_url_and_scan_with_existing_authorization(self):
        fixture=test_browser_github.BrowserGitHubTests();fixture.setUp()
        try:
            client=fixture.client
            url='https://github.com/'+REPO['full_name']+'.git'
            response=client.post('/repository-scan',data={'csrf_token':fixture.csrf,'action':'open','repository_url':url})
            self.assertEqual(response.status_code,303)
            self.assertNotIn('https',response.headers['Location'])
            page=client.get(response.headers['Location'])
            self.assertEqual(page.status_code,200)
            self.assertIn('Start repository analysis',page.get_data(as_text=True))
            self.assertEqual(client.post('/repository-scan',data={'action':'open','repository_url':url}).status_code,400)
            with patch.object(FixtureGitHub,'repository') as remote:
                rejected=client.post('/repository-scan',data={'csrf_token':fixture.csrf,'action':'open','repository_url':'https://password@github.com/a/b'})
                self.assertEqual(rejected.status_code,400);remote.assert_not_called()
                self.assertNotIn('password@',rejected.get_data(as_text=True))
            fixture.connect()
            response=client.post('/repository-scan',data={'csrf_token':fixture.csrf,'action':'start','repository':url,'branch':'main','authorized':'yes'})
            self.assertEqual(response.status_code,303)
            fixture.app.extensions['scan_manager'].executor.submit(lambda:None).result(timeout=10)
            with fixture.app.app_context():
                self.assertEqual(get_db().execute('SELECT status FROM scans').fetchone()[0],'Completed')
        finally:fixture.tearDown()
