"""Larger real-world archives remain bounded and errors remain actionable."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from integrations.github import GitHubClient,GitHubError
from integrations.network import ResponseTooLarge,RemoteError
from scanner.repository_safety import MAX_ARCHIVE,MAX_TOTAL,ArchiveError,extract_archive

class ArchiveLimitsTests(unittest.TestCase):
    def test_download_limit_and_deadline_and_safe_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            destination=Path(directory)/'repo.zip'
            with patch('integrations.github.request',return_value=(200,{},b'archive')) as request:
                GitHubClient().archive('owner/repo','a'*40,destination)
                self.assertEqual(request.call_args.kwargs['limit'],MAX_ARCHIVE)
                self.assertEqual(request.call_args.kwargs['seconds'],120)
            for error,message in [(ResponseTooLarge('private signed url'),'64 MiB'),(RemoteError('private signed url'),'retry')]:
                with patch('integrations.github.request',side_effect=error),self.assertRaises(GitHubError) as caught:
                    GitHubClient().archive('owner/repo','a'*40,destination)
                self.assertIn(message,str(caught.exception));self.assertNotIn('private signed',str(caught.exception))

    def test_oversized_archive_still_rejected(self):
        self.assertEqual(MAX_TOTAL,128*1024*1024)
        with tempfile.TemporaryDirectory() as directory:
            archive=Path(directory)/'large.zip'
            with archive.open('wb') as file:file.truncate(MAX_ARCHIVE+1)
            with self.assertRaisesRegex(ArchiveError,'64 MiB'):
                extract_archive(archive,Path(directory)/'output')
            self.assertFalse((Path(directory)/'output').exists())
