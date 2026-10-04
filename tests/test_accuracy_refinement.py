"""Parsed-only development regressions, separate from the frozen evaluation set."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from scanner.source_scanner import analyze_directory
from scanner.sast import python_scanner, javascript_scanner, config_scanner, secret_scanner


class AccuracyRefinementTests(unittest.TestCase):
    def scan(self, source, path='example.py', module=python_scanner):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/path).write_text(source)
            ctx=analyze_directory(root,[path],'lab/refinement');module.run(ctx)
            return ctx['findings']

    def test_holdout_identity(self):
        self.assertEqual(hashlib.sha256(Path('evaluation/accuracy_holdout_v1.json').read_bytes()).hexdigest(),
            '9fabe35ae18ac86e7ca97f9714b49f59ff626880dafc51685203e547ed999bb1')

    def test_constant_dispatch_and_shadowing(self):
        for body in ('getattr(os,"system")(request.args["cmd"])',
                     'op=getattr(os,"system")\nop(request.args["cmd"])'):
            self.assertEqual(len(self.scan('import os\n'+body)),1)
        self.assertEqual(self.scan('import os\ngetattr(os,"system")("date")'),[])
        self.assertEqual(self.scan('import os\ndef getattr(a,b):\n return print\ngetattr(os,"system")(request.args["cmd"])'),[])
        self.assertEqual(self.scan('import os\nop=getattr(os,"system")\nop=print\nop(request.args["cmd"])'),[])

    def test_allowlist_requires_termination_and_is_sink_specific(self):
        prefix='def route():\n name=request.args["col"]\n if name not in ("id","label"):\n  '
        self.assertEqual(self.scan(prefix+'raise ValueError()\n cursor.execute("SELECT "+name+" FROM records")'),[])
        self.assertTrue(self.scan(prefix+'print("invalid")\n cursor.execute("SELECT "+name+" FROM records")'))
        self.assertTrue(self.scan(prefix+'return\n name=request.args["other"]\n cursor.execute("SELECT "+name)'))
        self.assertTrue(self.scan(prefix+'return\n eval(name)'))
        self.assertTrue(self.scan('def route():\n name=request.args["col"]\n if name not in ("id", dangerous):\n  return\n cursor.execute("SELECT "+name)'))

    def test_guard_helper_preserves_rejected_return_path(self):
        code='def choose(value):\n if value not in ("id", "name"):\n  return value\n return value\ncursor.execute("SELECT " + choose(request.args["field"]))'
        self.assertTrue(self.scan(code))

    def test_quoting_is_one_complete_posix_argument(self):
        prefix='import shlex, os\nvalue=request.args["x"]\n'
        self.assertEqual(self.scan(prefix+'os.system("/usr/bin/printf -- " + shlex.quote(value))'),[])
        for expression in ('"/usr/bin/printf \\\"" + shlex.quote(value) + "\\\""',
                           'shlex.quote(value)', '"/usr/bin/printf -- " + shlex.quote(value).strip("\\\"")',
                           '"/usr/bin/printf -- " + shlex.quote(value) + value'):
            self.assertTrue(self.scan(prefix+'os.system('+expression+')'),expression)
        self.assertTrue(self.scan(prefix+'safe=shlex.quote(value)\neval(safe)'))
        self.assertTrue(self.scan(prefix+'os.system("/bin/sh -c " + shlex.quote(value))'))

    def test_requests_identity_and_false_literal(self):
        self.assertTrue(self.scan('from requests import get as fetch\nfetch(url,verify=False)'))
        for source in ('client.get(url,verify=False)', 'import requests\nrequests.get(url,verify=True)',
                       'import requests\nrequests=client\nrequests.get(url,verify=False)'):
            self.assertEqual(self.scan(source),[])

    def test_computed_dom_and_sanitization(self):
        for prop in ('"inner"+"HTML"','key'):
            self.assertTrue(self.scan('const key="innerHTML"; el['+prop+']=location.hash;', 'example.js',javascript_scanner))
        for code in ('const key="textContent";el[key]=location.hash;',
                     'const key="innerHTML";el[key]=DOMPurify.sanitize(location.hash);'):
            self.assertEqual(self.scan(code,'example.js',javascript_scanner),[])

    def test_documentation_prose_is_not_a_spaced_password(self):
        self.assertEqual(self.scan('password="Type your password to continue"','guide.md',secret_scanner),[])
        self.assertTrue(self.scan('password="violet cedar glacier silver"','example.py',secret_scanner))
        result=self.scan('password="violet cedar glacier silver"','guide.md',secret_scanner)
        self.assertTrue(result);self.assertNotIn('violet cedar glacier silver',str(result))

    def test_config_variants_and_safe_configuration(self):
        self.assertTrue(self.scan('DEBUG=True','settings_local.py',config_scanner))
        self.assertEqual(self.scan('DEBUG=False','settings_local.py',config_scanner),[])
        self.assertEqual(self.scan('DEBUG=True','algorithm.py',config_scanner),[])
