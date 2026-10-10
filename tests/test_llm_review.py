from tests.ollama_fixtures import transport, envelope
"""Provider boundary fixtures only: no paid requests or repository execution."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from bs4 import BeautifulSoup
from app import create_app
from database import get_db
from analysis.finding_engine import Finding,save_finding
from analysis.llm_review import prepare,process,validate_response
from analysis.ai_grounding import EXPLANATION, IMPACT, ACTION, FOLLOWUP
from integrations.llm import review


def response(**changes):
    original=changes.pop('original_code','');code=changes.pop('suggested_code','')
    remediation=changes.pop('remediation',ACTION)
    result=dict(assessment='likely_valid',reason=EXPLANATION,
        recommendation=dict(what_to_change=remediation,suggested_code_or_config=code,
                            example_type='source_specific' if code else 'none',why=IMPACT,additional_actions=[FOLLOWUP]),
        original_code=original,fix_confidence='medium')
    result.update(changes);return result


def finding(**changes):
    result=dict(title='Potential unsafe DOM HTML assignment',category='Injection',source='Repository',location='owner/repo/ui.js:2',evidence='Recognized input → input → innerHTML')
    result.update(changes);return result


class LLMUnitTests(unittest.TestCase):
    def test_request_redacted_before_provider_and_bounded(self):
        pat='ghp_'+'aB39'*10;key='provider-credential-4482'
        context=dict(excerpt='// '+pat+' '+key+'\nconst password="anyvalue";\nnode.innerHTML=input;',start_line=1,detected_line=3)
        payload=prepare(finding(evidence='Bearer '+pat),context,(pat,key))
        wire=json.dumps(payload)
        for secret in (pat,key,'anyvalue'):self.assertNotIn(secret,wire)
        self.assertNotIn('owner/repo',wire)
        self.assertEqual(prepare(finding(),dict(context,excerpt='a'*8000))['snippet'],'')

    def test_secret_finding_payload_is_synthetic_only(self):
        payload=prepare(finding(category='Secret Exposure',evidence='SuperSecret',title='SuperSecret'),dict(excerpt='custom="SuperSecret"',start_line=1,detected_line=1))
        self.assertNotIn('SuperSecret',json.dumps(payload));self.assertEqual(payload['snippet'],'password = "[REDACTED]"')
        from analysis.ai_grounding import statements
        policy=statements(finding(category='Secret Exposure'))
        reply=response(original_code=payload['snippet'],suggested_code='password="fake"',reason=policy['reason'][0])
        reply['recommendation'].update(what_to_change=policy['what_to_change'][0],why=policy['why'][0])
        result=process(finding(category='Secret Exposure'),payload,reply)
        self.assertEqual(result['suggested_code'],'')

    def test_strict_schema_and_limits(self):
        for data in (None,[],{},response(assessment='approved'),response(extra='bad'),response(reason=3),response(reason=''),response(suggested_code='x'),response(reason='x'*3001)):
            with self.subTest(data=type(data)),self.assertRaises(ValueError):validate_response(data)

    def test_good_patch_requires_full_source_and_recheck(self):
        source='function show(input) {\nnode.innerHTML=input;\n}\n'
        payload=prepare(finding(),dict(excerpt='node.innerHTML=input;',start_line=2,detected_line=2))
        answer=response(original_code=payload['snippet'],suggested_code='node.textContent=input;')
        unavailable=process(finding(),payload,answer)
        self.assertEqual(unavailable['validation']['status'],'Not Available')
        result=process(finding(),payload,answer,source)
        self.assertEqual(result['validation']['status'],'Passed');self.assertIn('+node.textContent=input;',result['diff'])
        self.assertIn('No code was applied',result['note'])

    def test_bad_generated_code_and_source_mismatch(self):
        original='function show(input) {\nnode.innerHTML=input;\n}\n'
        payload=prepare(finding(),dict(excerpt='node.innerHTML=input;',start_line=2,detected_line=2))
        for code in ('node.innerHTML=input;','node.textContent = ;','node.textContent=input;eval(input);'):
            result=process(finding(),payload,response(original_code=payload['snippet'],suggested_code=code),original)
            self.assertNotEqual(result['validation']['status'],'Passed')
        result=process(finding(),payload,response(original_code='unrelated',suggested_code='safe'))
        self.assertEqual(result['validation']['status'],'Failed');self.assertEqual(result['suggested_code'],'')

    def test_transport_schema_refusal_timeout_and_missing_model(self):
        config={'LLM_ENABLED':True,'OLLAMA_MODEL':'test-model'}
        raw=envelope(json.dumps(response()))
        with patch('integrations.llm.request',side_effect=transport(200,raw)) as send:
            self.assertEqual(review({'snippet':'safe'},config),response())
            body=json.loads(send.call_args.kwargs['body'])
            self.assertFalse(body['stream']);self.assertFalse(body['format']['additionalProperties'])
            self.assertNotIn('Authorization',json.dumps(body));self.assertNotIn('tools',body)
        for raw in (b'bad',json.dumps({'done':True,'done_reason':'length','message':{}}).encode(),json.dumps({'done':True,'done_reason':'stop','message':{'role':'assistant','content':''}}).encode()):
            with patch('integrations.llm.request',side_effect=transport(200,raw)),self.assertRaises((ValueError,KeyError)):review({},config)
        with patch('integrations.llm.request',side_effect=TimeoutError()),self.assertRaises(TimeoutError):review({},config)
        with patch('integrations.llm.request') as send,self.assertRaises(ValueError):review({},dict(config,OLLAMA_MODEL=''))
        send.assert_not_called()


class LLMRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.calls=[]
        def provider(payload,config):self.calls.append(payload);return response()
        self.app=create_app({'TESTING':True,'DATABASE':str(Path(self.tmp.name)/'test.db'),'LLM_ENABLED':True,'LLM_REVIEW_PROVIDER':provider})
        self.client=self.app.test_client()
        with self.app.app_context():
            db=get_db()
            with db:scan=db.execute("INSERT INTO scans(scan_type,target,status) VALUES ('Repository','o/r','Completed')").lastrowid
            self.id=save_finding(db,scan,Finding(**finding(),severity='High',confidence='High',description='Scanner evidence',impact='Review',recommendation='Use safe DOM'))
            with db:db.execute('INSERT INTO finding_context VALUES (?,?,?,?,?,?)',(self.id,'ui.js','a'*40,2,2,'node.innerHTML=input;'))
        self.client.get('/')
        with self.client.session_transaction() as session:self.csrf=session['csrf_token']

    def tearDown(self):self.app.extensions['scan_manager'].shutdown();self.tmp.cleanup()

    def submit(self):
        from analysis.llm_review import refine_finding
        with self.app.app_context():
            db=get_db()
            refine_finding(db,db.execute('SELECT * FROM findings WHERE id=?',(self.id,)).fetchone(),self.app.config)
        return self.client.get(f'/findings/{self.id}')

    def test_enabled_persists_separate_review_and_escapes_inside_recommendation(self):
        page=self.submit();self.assertEqual(page.status_code,200)
        self.assertEqual(len(self.calls),1)
        soup=BeautifulSoup(page.data,'html.parser')
        self.assertIsNone(soup.select_one('#recommendation #ai-review'));self.assertNotIn('Improve with AI',soup.get_text())
        self.assertIn('AI-assisted recommendation',page.get_data(as_text=True));self.assertNotIn('<script>bad()</script>',page.get_data(as_text=True))
        with self.app.app_context():
            db=get_db();self.assertEqual(db.execute('SELECT status FROM findings').fetchone()[0],'Open')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM ai_reviews').fetchone()[0],1)
        self.client.get(f'/findings/{self.id}');self.assertEqual(len(self.calls),1)

    def test_disabled_and_removed_route_preserve_csrf(self):
        self.assertEqual(self.client.post(f'/findings/{self.id}/ai-review').status_code,400)
        self.assertEqual(self.client.post(f'/findings/{self.id}/ai-review',data={'csrf_token':self.csrf}).status_code,404)
        self.app.config['LLM_ENABLED']=False
        self.assertEqual(self.submit().status_code,200);self.assertEqual(self.calls,[])
        self.assertEqual(self.client.get(f'/findings/{self.id}').status_code,200)

    def test_outage_and_invalid_output_keep_finding(self):
        for provider in (lambda *_:None,lambda *_:response(assessment='invalid')):
            self.app.config['LLM_REVIEW_PROVIDER']=provider
            page=self.submit();self.assertEqual(page.status_code,200);self.assertIn(b'Recommended Fix',page.data);self.assertNotIn(b'AI Assisted',page.data)
        def fail(*_):raise TimeoutError('sensitive error body')
        self.app.config['LLM_REVIEW_PROVIDER']=fail
        page=self.submit();self.assertNotIn(b'sensitive error body',page.data)
        with self.app.app_context():
            self.assertEqual(get_db().execute('SELECT COUNT(*) FROM findings').fetchone()[0],1)
            self.assertEqual(get_db().execute('SELECT COUNT(*) FROM ai_reviews').fetchone()[0],0)

    def test_likely_false_positive_never_triages(self):
        self.app.config['LLM_REVIEW_PROVIDER']=lambda *_:response(assessment='likely_false_positive')
        self.submit()
        with self.app.app_context():self.assertEqual(get_db().execute('SELECT status FROM findings').fetchone()[0],'Open')

class LLMPipelineTests(unittest.TestCase):
    def test_repository_pipeline_never_depends_on_provider(self):
        from tests.test_source_scanner import FixtureGitHub,REPO
        for enabled in (False,True):
            with self.subTest(enabled=enabled),tempfile.TemporaryDirectory() as directory:
                def unavailable(*_):raise AssertionError('Scan workers must never call AI')
                app=create_app({'TESTING':True,'DATABASE':str(Path(directory)/'scan.db'),'GITHUB_CLIENT_FACTORY':FixtureGitHub,'LLM_ENABLED':enabled,'LLM_REVIEW_PROVIDER':unavailable})
                client=app.test_client();client.get('/')
                with client.session_transaction() as session:csrf=session['csrf_token']
                page=client.post('/repository-scan',data={'csrf_token':csrf,'action':'start','repository':REPO['full_name'],'branch':'main','authorized':'yes'})
                self.assertEqual(page.status_code,303);app.extensions['scan_manager'].shutdown()
                with app.app_context():
                    self.assertEqual(get_db().execute('SELECT status FROM scans').fetchone()[0],'Completed')
                    self.assertGreater(get_db().execute('SELECT COUNT(*) FROM findings').fetchone()[0],0)
                    self.assertEqual(get_db().execute('SELECT COUNT(*) FROM ai_reviews').fetchone()[0],0)

    def test_removing_another_occurrence_cannot_validate_original(self):
        original='function show(input) {\nnode.innerHTML=input;\nother.innerHTML=input;\n}\n'
        payload=prepare(finding(),dict(excerpt='node.innerHTML=input;\nother.innerHTML=input;',start_line=2,detected_line=2))
        code='node.innerHTML=input;\nother.textContent=input;'
        result=process(finding(),payload,response(original_code=payload['snippet'],suggested_code=code),original)
        self.assertEqual(result['validation']['status'],'Failed')

    def test_completed_repository_automatically_refines_without_changing_detection(self):
        from tests.test_source_scanner import FixtureGitHub, REPO
        from tests.test_repository_phase4 import Provider, answer
        for enabled in (False, True):
            with self.subTest(enabled=enabled), tempfile.TemporaryDirectory() as directory:
                class GroundedProvider(Provider):
                    def review_finding(self,payload,config,**kwargs):
                        value=super().review_finding(payload,config,**kwargs)
                        policy=payload['supported_statements']
                        value['reason']=policy['reason'][0]
                        value['recommendation'].update(what_to_change=policy['what_to_change'][0],why=policy['why'][0])
                        return value
                provider=GroundedProvider(*[answer() for _ in range(40)])
                calls=[]
                def legacy(payload,config):
                    calls.append(payload)
                    value=response();policy=payload['supported_statements']
                    value['reason']=policy['reason'][0]
                    value['recommendation'].update(what_to_change=policy['what_to_change'][0],why=policy['why'][0])
                    return value
                app=create_app(dict(TESTING=True,DATABASE=str(Path(directory)/'scan.db'),GITHUB_CLIENT_FACTORY=FixtureGitHub,
                    LLM_ENABLED=enabled,LLM_EVIDENCE_PROVIDER=provider,LLM_REVIEW_PROVIDER=legacy))
                client=app.test_client();client.get('/')
                with client.session_transaction() as session:csrf=session['csrf_token']
                result=client.post('/repository-scan',data=dict(csrf_token=csrf,action='start',repository=REPO['full_name'],branch='main',authorized='yes'))
                self.assertEqual(result.status_code,303)
                app.extensions['scan_manager'].shutdown()
                with app.app_context():
                    db=get_db()
                    self.assertEqual(db.execute('SELECT status FROM scans').fetchone()[0],'Completed')
                    rows=[tuple(row) for row in db.execute('SELECT title,severity,confidence,evidence,fingerprint,status FROM findings ORDER BY id')]
                    if not enabled:baseline=rows
                    else:
                        self.assertEqual(rows,baseline)
                        self.assertGreater(db.execute('SELECT COUNT(*) FROM ai_reviews').fetchone()[0],0)
                    self.assertEqual(bool(provider.calls or calls),enabled)
                    for payload, *_ in provider.calls:
                        self.assertIn('evidence_package',payload)

    def test_refinement_budget_failure_and_saved_reviews_are_bounded(self):
        from analysis.llm_review import refine_scan
        with tempfile.TemporaryDirectory() as directory:
            calls=[]
            def provider(payload,config):calls.append(payload);return response()
            app=create_app(dict(TESTING=True,DATABASE=str(Path(directory)/'scan.db'),LLM_ENABLED=True,LLM_REVIEW_PROVIDER=provider))
            with app.app_context():
                db=get_db()
                with db:scan=db.execute("INSERT INTO scans(scan_type,target,status) VALUES ('Repository','o/r','Completed')").lastrowid
                for n in range(25):
                    save_finding(db,scan,Finding(**finding(location=f'o/r/ui.js:{n+1}'),severity='Low',confidence='Low',description='Candidate',impact='Review',recommendation='Use safe text.'))
            refine_scan(app,scan)
            self.assertEqual(len(calls),20)
            def fail(*_):calls.append('failure');raise TimeoutError('private-body')
            app.config['LLM_REVIEW_PROVIDER']=fail
            refine_scan(app,scan)
            self.assertEqual(len(calls),21)  # Saved reviews skipped, one outage stops remaining calls.
            with app.app_context():
                self.assertEqual(get_db().execute('SELECT COUNT(*) FROM ai_reviews').fetchone()[0],20)
                self.assertEqual(get_db().execute('SELECT status FROM scans').fetchone()[0],'Completed')
            app.extensions['scan_manager'].shutdown()
