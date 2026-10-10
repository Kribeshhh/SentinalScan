"""Trusted pack configuration and SARIF execution-status regressions."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scanner.engines import external
from scanner.engines.process import ToolFailure
from scanner.engines.sarif import import_results
from scanner.source_scanner import analyze_directory
from tests.test_repository_phase2 import sarif


class CodeQLRepairTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name).resolve();self.root=self.base/'repo';self.root.mkdir()
        (self.root/'a.py').write_text('value=input()\nquery=value\ncursor.execute(query)')
        self.ctx=analyze_directory(self.root,['a.py'],'lab/codeql')
        self.packs=[self.base/'python-pack',self.base/'js-pack']
        for p in self.packs:p.mkdir()
        self.search=os.pathsep.join(map(str,self.packs))
        self.ctx['engine_config']={'CODEQL_ENABLED':True,'CODEQL_SEARCH_PATH':self.search}

    def test_multiple_trusted_pack_directories_and_single_compatibility(self):
        self.assertEqual(external.codeql_search_path(self.ctx['engine_config'],self.root),self.search)
        self.assertEqual(external.codeql_search_path({'CODEQL_SEARCH_PATH':str(self.packs[0])},self.root),str(self.packs[0]))
        self.assertEqual(external.codeql_search_path({},self.root),'')

    def test_invalid_missing_relative_and_repository_pack_paths(self):
        link=self.base/'link';link.symlink_to(self.root,target_is_directory=True)
        for value in (None,[],'.',str(self.root),str(link),str(self.base/'missing'),self.search+os.pathsep,os.pathsep+self.search,'bad\npath',os.pathsep.join([str(self.base)]*17)):
            with self.subTest(value=value),self.assertRaises(ToolFailure):
                external.codeql_search_path({'CODEQL_SEARCH_PATH':value},self.root)

    def test_mixed_language_arguments_isolation_cleanup(self):
        (self.root/'b.js').write_text('const value=location.hash;\nconsole.log(value);')
        self.ctx['paths'].append('b.js')
        with patch.object(external,'executable',return_value='/trusted/codeql'),patch.object(external,'run_tool',side_effect=[b'',sarif(),b'',sarif()]) as run:
            result=external.codeql(self.ctx)
        self.assertEqual(result['status'],'Completed')
        self.assertEqual([r['language'] for r in result['languages']],['python','javascript'])
        self.assertEqual(run.call_count,4)
        for call in run.call_args_list:
            args,work,seconds=call.args[:3]
            self.assertGreater(seconds,0);self.assertLessEqual(seconds,120)
            self.assertFalse(Path(work).exists())
            self.assertFalse(any(a.startswith(('--command','--download')) for a in args))
            if 'analyze' in args:self.assertIn('--search-path='+self.search,args)
            else:self.assertIn('--build-mode=none',args)
        self.assertIn('codeql/python-queries',run.call_args_list[1].args[0])
        self.assertIn('codeql/javascript-queries',run.call_args_list[3].args[0])

    def test_missing_configured_pack_stops_before_execution(self):
        self.ctx['engine_config']['CODEQL_SEARCH_PATH']=str(self.base/'missing')
        with patch.object(external,'executable',return_value='/trusted/codeql'),patch.object(external,'run_tool') as run:
            self.assertEqual(external.codeql(self.ctx)['status'],'Failed');run.assert_not_called()

    def test_failure_timeout_and_malformed_output_preserved(self):
        for effects in ([ToolFailure('Analysis timed out.')],[b'',ToolFailure('Tool failed; raw diagnostics are omitted to protect source data.')],[b'',b'not json']):
            with self.subTest(effects=effects),patch.object(external,'executable',return_value='/trusted/codeql'),patch.object(external,'run_tool',side_effect=effects) as run:
                result=external.codeql(self.ctx)
                self.assertEqual(result['status'],'Failed')
                self.assertTrue(all(not Path(c.args[1]).exists() for c in run.call_args_list))
        self.assertEqual(self.ctx['findings'],[])

    def test_mixed_one_language_failure_is_partial_and_retains_results(self):
        (self.root/'b.js').write_text('const x=1;');self.ctx['paths'].append('b.js')
        with patch.object(external,'executable',return_value='/trusted/codeql'),patch.object(external,'run_tool',side_effect=[b'',sarif(),ToolFailure('Analysis timed out.')]):
            result=external.codeql(self.ctx)
        self.assertEqual(result['status'],'Partial');self.assertEqual(len(self.ctx['findings']),1)
        self.assertEqual([r['status'] for r in result['languages']],['Completed','Failed'])

    def document(self,invocations):
        doc=json.loads(sarif());doc['runs'][0]['invocations']=invocations
        return json.dumps(doc).encode()

    def test_informational_execution_and_configuration_notifications_complete(self):
        payload=self.document([{'executionSuccessful':True,'toolExecutionNotifications':[{'level':'note','message':{'text':'DO-NOT-PERSIST'}},{'level':'none'}],'toolConfigurationNotifications':[{'level':'note'}]}])
        result=import_results(payload,self.ctx,'CodeQL')
        self.assertEqual(result['status'],'Completed');self.assertEqual(result['candidates'],1)
        finding=self.ctx['findings'][0]
        self.assertEqual(finding.severity,'Critical');self.assertTrue(finding.location.endswith('a.py:3'))
        self.assertNotIn('DO-NOT-PERSIST',str(finding))

    def test_warning_error_missing_level_and_failed_invocation_are_partial(self):
        for invocation in ({'executionSuccessful':False},{'toolExecutionNotifications':[{'level':'warning'}]},{'toolExecutionNotifications':[{'level':'error'}]},{'toolConfigurationNotifications':[{'level':'error'}]},{'toolExecutionNotifications':[{}]}):
            with self.subTest(invocation=invocation):
                self.ctx['findings']=[]
                result=import_results(self.document([invocation]),self.ctx,'CodeQL')
                self.assertEqual(result['status'],'Partial');self.assertEqual(result['candidates'],1)

    def test_malformed_invocation_metadata_is_rejected(self):
        for value in (None,{},[None],[{'executionSuccessful':'true'}],[{'toolExecutionNotifications':{}}],[{'toolExecutionNotifications':[None]}],[{'toolExecutionNotifications':[{'level':'success'}]}]):
            with self.subTest(value=value),self.assertRaises(ToolFailure):
                import_results(self.document(value),self.ctx,'CodeQL')
        self.assertEqual(self.ctx['findings'],[])
