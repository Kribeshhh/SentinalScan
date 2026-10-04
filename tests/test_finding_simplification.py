"""Progressive disclosure and optional enhancement, isolated from user history."""
from copy import deepcopy
import json
import unittest
from unittest.mock import Mock
from bs4 import BeautifulSoup
from flask import render_template
from database import get_db
from analysis.finding_engine import Finding,save_finding
from analysis.solution_engine import solution_for
from analysis.recommendation_composer import compose
from analysis.recommendation import brief,presentation_summary
from tests import test_unified_recommendation as unified


class SimplifiedFindingTests(unittest.TestCase):
    setUp=unified.UnifiedPageTests.setUp
    tearDown=unified.UnifiedPageTests.tearDown
    save_review=unified.UnifiedPageTests.save_review

    def page(self,source='Repository'):
        response=self.client.get('/findings/'+str(self.ids[source]))
        self.assertEqual(response.status_code,200)
        return BeautifulSoup(response.data,'html.parser')

    def primary(self,soup):
        copy=BeautifulSoup(str(soup),'html.parser')
        for node in copy.select('details'):node.decompose()
        return copy

    def test_minimal_primary_and_single_disclosure_preserves_information(self):
        soup=self.page();visible=self.primary(soup)
        self.assertEqual(len(soup.select('#recommendation')),1)
        self.assertEqual(len(soup.select('#technical-details')),1)
        self.assertFalse(soup.select_one('#technical-details').has_attr('open'))
        self.assertIn('Detection Confidence:',visible.get_text())
        self.assertIn('Fix Confidence:',visible.get_text())
        self.assertTrue(visible.select_one('.finding-header .badge-low'))
        self.assertTrue(visible.select_one('.finding-address').get_text().strip())
        self.assertTrue(visible.select_one('.primary-fix code'))
        self.assertNotIn('Fingerprint',visible.get_text())
        self.assertIn('Fingerprint',soup.select_one('#technical-details').get_text())
        self.assertTrue(soup.select_one('#technical-details .current-source'))
        self.assertFalse(visible.select('h3'))
        self.assertFalse(visible.select_one('a[href$="/edit"]'))

    def test_ai_contributes_once_and_get_never_calls_provider(self):
        self.save_review('Repository');self.app.config['LLM_ENABLED']=True
        provider=Mock(side_effect=AssertionError('GET must not call AI'))
        self.app.config['LLM_REVIEW_PROVIDER']=provider
        soup=self.page();visible=self.primary(soup)
        self.assertEqual(len(visible.select('.ai-enhanced')),1)
        self.assertEqual(visible.get_text().count('Bind email at the existing SQLite execute call.'),1)
        self.assertEqual(len(visible.select('.primary-fix code')),1)
        self.assertEqual(len(soup.select('#ai-review form')),0)
        self.assertIn('AI review details',soup.select_one('#technical-details').get_text())
        self.assertNotIn('AI review details',visible.get_text())
        self.assertNotIn('Improve with AI',soup.get_text())
        provider.assert_not_called()

    def test_disabled_failure_and_csrf_keep_base(self):
        self.save_review('Website')
        self.assertFalse(self.page('Website').select('.ai-enhanced'))
        self.app.config['LLM_ENABLED']=True
        provider=Mock(side_effect=TimeoutError('private-provider-body'))
        self.app.config['LLM_REVIEW_PROVIDER']=provider
        url='/findings/'+str(self.ids['Website'])+'/ai-review'
        self.assertEqual(self.client.post(url,data={'share_context':'yes'}).status_code,400)
        self.assertEqual(self.client.post(url,data={'csrf_token':self.csrf}).status_code,404)
        provider.assert_not_called()
        unified.UnifiedPageTests.refine_website(self)
        soup=self.page('Website');self.assertFalse(soup.select('.ai-enhanced'))
        self.assertTrue(soup.select_one('.fix-summary').get_text().strip())
        self.assertNotIn('private-provider-body',str(soup))

    def test_secret_guidance_visible_context_redacted_no_invented_code(self):
        with self.app.app_context():
            db=get_db();f=dict(title='Potential embedded credential',category='Secret Exposure',source='Repository',location='o/r/users.yml:2',severity='High',confidence='Medium',description='Credential candidate',impact='If real, access may be exposed.',evidence='Value: [REDACTED]',recommendation='Use runtime secret configuration.')
            fid=save_finding(db,self.scans['Repository'],Finding(**f))
            solution=solution_for(f,'users:\n password: "SyntheticSensitive987"')
            with db:db.execute('INSERT INTO finding_solutions VALUES (?,?)',(fid,json.dumps(solution)))
            self.ids['Repository']=fid
        soup=self.page();visible=self.primary(soup)
        self.assertIn('rotate',visible.get_text());self.assertIn('history',visible.get_text())
        self.assertNotIn('SyntheticSensitive987',str(soup))
        self.assertFalse(visible.select('pre code'))
        self.assertNotIn('unavailable',visible.select_one('.fix-summary').get_text().lower())
        self.assertIn('manual review required',soup.select_one('#technical-details').get_text())

    def test_website_source_fix_is_not_fabricated(self):
        with self.app.app_context():
            db=get_db();f=dict(title='Potential SQL Injection',category='SQL Injection',source='Website',location='https://example.test/search?id=1',severity='Medium',confidence='Low',description='A SQL error appeared in the probe response.',impact='Review the server handler.',evidence='Observed probe difference',recommendation='Review server query construction.')
            self.ids['Website']=save_finding(db,self.scans['Website'],Finding(**f))
        soup=self.page('Website');visible=self.primary(soup)
        self.assertIn('Recommended Fix',visible.get_text())
        self.assertNotIn('cursor.execute',str(soup));self.assertIn('Pseudocode',visible.get_text());self.assertIn('Example Secure Pattern',visible.get_text())
        self.assertIn('backend',soup.select_one('#technical-details').get_text())
        self.assertFalse(visible.select('a[href$="/edit"]'))

    def test_empty_optional_subsections_omitted(self):
        empty=dict(action='Review the affected handler.',examples=[],finding_context={'missing':None},additional_actions=[],source_type='Website',fix_confidence='Low')
        with self.app.test_request_context():
            soup=BeautifulSoup(render_template('_solution.html',solution=empty,finding_id=1),'html.parser')
        self.assertFalse(soup.select('#technical-details h3'))
        self.assertTrue(soup.select_one('#technical-details'))

    def test_noop_and_generic_ai_do_not_replace_useful_base(self):
        fixture=unified.ComposerTests();fixture.setUp()
        review=deepcopy(fixture.review)
        review['recommendation'].update(what_to_change=fixture.base['action'],why=fixture.base['why'],additional_actions=[])
        self.assertFalse(compose(fixture.finding,fixture.base,review,True)['ai_assisted'])
        review['recommendation']['what_to_change']='Review the code.'
        result=compose(fixture.finding,fixture.base,review,True)
        self.assertFalse(result['ai_assisted']);self.assertEqual(result['action'],fixture.base['action'])
        self.assertEqual(result['examples'],fixture.base['examples'])

    def test_summary_is_bounded_without_modifying_full_text(self):
        text='Observed response differs. Review its handler. Confirm deployment. Fourth sentence.'
        self.assertNotIn('Fourth',brief(text));self.assertIn('Fourth',text)
        self.assertLessEqual(len(brief('long '*1000)),421)

    def test_dismissed_secret_has_no_primary_rotation_action(self):
        result=presentation_summary({'description':'Reviewed candidate.'},{'dismissed':True,'action':'No fix required.'},{'category':'Secret Exposure','impact':''})
        self.assertEqual(result['essential'],[])
