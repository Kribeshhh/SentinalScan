"""Read-only GitHub source boundary and shared suggestion diff validation."""
import unittest
from unittest.mock import patch
from integrations.github import GitHubClient, GitHubError
from analysis.remediation import source_diff
SHA="a"*40
BLOB="b"*40

class SourceReadTests(unittest.TestCase):
    def test_source_file_bounds_and_encoding(self):
        client=GitHubClient()
        with patch.object(client,'api',return_value={'type':'file','path':'app.py','encoding':'base64','size':5,'sha':BLOB,'content':'!!!!'}):
            with self.assertRaises(GitHubError): client.source_file('test/repo','app.py',SHA)
        self.assertIn('No newline at end of file',source_diff('old','new','app.py'))
