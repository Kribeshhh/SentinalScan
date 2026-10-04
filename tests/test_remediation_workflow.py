"""Retained source redaction independent of the retired publication workflow."""
import unittest
from analysis.source_context import mask_source

class ContextRedactionTests(unittest.TestCase):
    def test_retained_context_masks_multiline_keys_preserves_lines(self):
        source='first\n-----BEGIN PRIVATE KEY-----\nSENSITIVEKEYVALUE\n-----END PRIVATE KEY-----\npassword="RealCredential987"\nlast\n'
        masked=mask_source(source)
        self.assertNotIn('SENSITIVEKEYVALUE',masked);self.assertNotIn('RealCredential987',masked)
        self.assertEqual(source.count('\n'),masked.count('\n'))
        self.assertEqual(masked.splitlines()[5],'last')
