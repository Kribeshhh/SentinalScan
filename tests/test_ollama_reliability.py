"""Phase 19: generation constraints never replace independent validation."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from app import create_app
from database import get_db
from analysis.finding_engine import Finding, save_finding
from analysis.llm_review import validate_response, refine_scan
from integrations.llm import SCHEMA, consistent_schema, ProviderUnavailable, review
from tests.test_llm_sast_dast import configuration
from tests.ollama_fixtures import transport, envelope


class ContractTests(unittest.TestCase):
    def test_original_phase18_inconsistencies_still_rejected(self):
        for original, code in [('', 'node.textContent=input;'), ('password="[REDACTED]"', ''),
                               ('node.innerHTML=input;', 'Replace this with textContent.')]:
            value=configuration();value['original_code']=original
            value['recommendation'].update(example_type='none',suggested_code_or_config=code)
            with self.subTest(original=original,code=code), self.assertRaises(ValueError):
                validate_response(value)

    def test_guidance_schema_cannot_emit_code_or_source(self):
        for category in ('Injection','Secret Exposure'):
            schema=consistent_schema({'source_type':'Repository','category':category,'snippet':'x'},SCHEMA)
            props=schema['properties']
            self.assertEqual(props['original_code'],{'const':''})
            self.assertEqual(props['recommendation']['properties']['suggested_code_or_config'],{'const':''})
            self.assertEqual(props['recommendation']['properties']['example_type'],{'const':'none'})
        self.assertNotIn('const',SCHEMA['properties']['original_code'])

    def test_configuration_and_source_are_consistent_alternatives(self):
        schema=consistent_schema({'source_type':'Website','category':'Security Headers'},SCHEMA)
        self.assertEqual(schema['properties']['original_code'],{'const':''})
        choices=schema['properties']['recommendation']['anyOf']
        self.assertEqual(choices[0]['properties']['suggested_code_or_config'],{'const':''})
        self.assertEqual(choices[1]['properties']['example_type'],{'const':'configuration'})
        self.assertEqual(choices[1]['properties']['suggested_code_or_config']['minLength'],1)
        source=consistent_schema({'source_type':'Repository','snippet':'node.innerHTML=input;',
                                  'source_replacement_available':True},SCHEMA)
        self.assertEqual(source['anyOf'][1]['properties']['original_code'],{'const':'node.innerHTML=input;'})
        self.assertEqual(source['anyOf'][1]['properties']['recommendation']['properties']['example_type'],{'const':'source_specific'})
        # Mock providers can ignore schemas: independent checks must still reject.
        bad=configuration();bad['original_code']='invented';
        with self.assertRaises(ValueError):validate_response(bad)

    def test_native_request_preserves_bounds_and_rejects_http_outage(self):
        with patch('integrations.llm.request',side_effect=transport(200,envelope(json.dumps(configuration())))) as send:
            review({'source_type':'Repository'},dict(LLM_ENABLED=True,OLLAMA_MODEL='fixture'))
        body=json.loads(send.call_args.kwargs['body'])
        self.assertEqual(body['keep_alive'],'60s')
        self.assertEqual(body['options']['num_predict'],3000)
        self.assertEqual(send.call_args.kwargs['seconds'],20)
        self.assertEqual(body['format']['properties']['original_code'],{'const':''})
        with patch('integrations.llm.request',side_effect=transport(503,b'{}')):
            with self.assertRaises(ProviderUnavailable):review({},dict(LLM_ENABLED=True,OLLAMA_MODEL='fixture'))

    def test_specific_options_first_without_forcing_assessment(self):
        from analysis.ai_grounding import prompt_statements, statements
        from tests.test_llm_sast_dast import website
        payload={'supported_statements':prompt_statements(website())}
        before=deepcopy(payload)
        self.assertEqual(payload['supported_statements']['reason'],list(reversed(statements(website())['reason'])))
        with patch('integrations.llm.request',side_effect=transport(200,envelope(json.dumps(configuration())))) as send:
            review(payload,dict(LLM_ENABLED=True,OLLAMA_MODEL='fixture'))
        body=json.loads(send.call_args.kwargs['body'])
        self.assertEqual(body['format']['properties']['reason']['enum'],payload['supported_statements']['reason'])
        self.assertIn('needs_review',body['format']['properties']['assessment']['enum'])
        self.assertEqual(payload,before)


class CompletionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.app=create_app({'TESTING':True,'DATABASE':str(Path(self.tmp.name)/'db.sqlite3'),
                             'LLM_ENABLED':True,'OLLAMA_MODEL':'fixture'})
        self.ctx=self.app.app_context();self.ctx.push();self.db=get_db()
        with self.db:self.sid=self.db.execute("INSERT INTO scans(scan_type,target,status) VALUES ('Website','http://fixture/','Completed')").lastrowid

    def tearDown(self):
        self.app.extensions['scan_manager'].shutdown();self.ctx.pop();self.tmp.cleanup()

    def add(self,n=2):
        for i in range(n):
            save_finding(self.db,self.sid,Finding(title='Missing X-Content-Type-Options',severity='Low',confidence='High',category='Security Headers',source='Website',location=f'http://fixture/{i}',description='Header absent',evidence='Header absent',impact='MIME sniffing',recommendation='Set nosniff.'))

    def test_rejected_first_finding_does_not_starve_second(self):
        self.add();bad=configuration();bad['recommendation']['example_type']='none'
        original=[tuple(r) for r in self.db.execute('SELECT * FROM findings')]
        with patch.dict(self.app.config,LLM_REVIEW_PROVIDER=unittest.mock.Mock(side_effect=[bad,configuration()])):
            refine_scan(self.app,self.sid)
            self.assertEqual(self.app.config['LLM_REVIEW_PROVIDER'].call_count,2)
        self.assertEqual(self.db.execute('SELECT count(*) FROM ai_reviews').fetchone()[0],1)
        self.assertEqual(original,[tuple(r) for r in self.db.execute('SELECT * FROM findings')])
        flags=[json.loads(r[0])['_ai_review_failed'] for r in self.db.execute('SELECT data_json FROM finding_solutions ORDER BY finding_id')]
        self.assertEqual(flags,[True,False])

    def test_provider_outage_stops_without_retry(self):
        self.add()
        for failure in (ProviderUnavailable('Unavailable'),RuntimeError('transport failure')):
            provider=unittest.mock.Mock(side_effect=failure)
            with patch.dict(self.app.config,LLM_REVIEW_PROVIDER=provider):refine_scan(self.app,self.sid)
            self.assertEqual(provider.call_count,1)
        self.assertEqual(self.db.execute('SELECT count(*) FROM ai_reviews').fetchone()[0],0)

    def test_candidate_cap_even_when_every_answer_is_rejected(self):
        self.add(22);provider=unittest.mock.Mock(side_effect=ValueError('Invalid response'))
        with patch.dict(self.app.config,LLM_REVIEW_PROVIDER=provider):refine_scan(self.app,self.sid)
        self.assertEqual(provider.call_count,20)

    def test_global_budget_stops_before_next_finding(self):
        self.add();provider=unittest.mock.Mock(return_value=configuration())
        with patch.dict(self.app.config,LLM_REVIEW_PROVIDER=provider), patch('time.monotonic',side_effect=[0,61]):
            refine_scan(self.app,self.sid)
        provider.assert_not_called()
