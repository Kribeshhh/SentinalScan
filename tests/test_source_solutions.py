import unittest
from analysis.solution_engine import solution_for
from integrations.github import GitHubError


class SourceSolutionTests(unittest.TestCase):
    def finding(self,line=2):
        return dict(title='Potential unsafe DOM HTML assignment',category='Injection',source='Repository',location=f'owner/repo/app.js:{line}',evidence='assignment to innerHTML')

    def test_exact_statement_preserves_names_and_surrounding_source(self):
        source='const label = "é";\ndocument.getElementById("result").innerHTML = user.name;\nrun();\n'
        result=solution_for(self.finding(),source)
        self.assertTrue(result['exact'])
        self.assertEqual(result['before'],'document.getElementById("result").innerHTML = user.name')
        self.assertEqual(result['examples'][0]['code'],'document.getElementById("result").textContent = user.name\n')
        self.assertIn('DOMPurify.sanitize(user.name',result['examples'][1]['code'])
        self.assertIn('runtime behavior has not been verified',result['source_status'])
        self.assertIn('2 >',result['context'])

    def test_bracket_multiline_and_outerhtml(self):
        source='// example\nnode["innerHTML"] =\n  content;'
        r=solution_for(self.finding(),source)
        self.assertTrue(r['exact']);self.assertIn('node["textContent"]',r['examples'][0]['code'])
        r=solution_for(self.finding(),'// example\nnode.outerHTML = content;')
        self.assertTrue(r['exact']);self.assertEqual(len(r['examples']),1)
        self.assertNotIn('textContent',r['examples'][0]['code'])

    def test_ambiguity_bad_syntax_wrong_line_and_augmented_assignment(self):
        for source in ['// example\na.innerHTML=x; b.innerHTML=y;', '// example\na.innerHTML = ;', '// example\na.textContent=x;', '// example\na.innerHTML += x;']:
            self.assertFalse(solution_for(self.finding(),source)['exact'])
        self.assertFalse(solution_for(self.finding(99),'const x=1;')['exact'])

    def test_secrets_are_not_shown_and_generic_is_labeled(self):
        with self.assertRaises(GitHubError):
            solution_for(self.finding(),'const password = "liveSensitive123";\na.innerHTML=x;')
        r=solution_for(self.finding())
        self.assertFalse(r['exact']);self.assertIn('not retrieved source',r['before_label'])
        self.assertEqual(r['examples'],[])
        self.assertIn('manual review',r['unavailable'])

    def test_candidates_remove_target_detection_without_touching_other_statement(self):
        from scanner.sast.javascript_scanner import analyze
        source='// display\nnode.innerHTML = userInput;\nother.innerHTML = otherInput;\n'
        r=solution_for(self.finding(),source)
        for candidate in r['examples']:
            updated=source.replace(r['before'],candidate['code'].rstrip('\n'),1)
            ctx={'findings':[],'repository':'owner/repo','capped':False}
            self.assertTrue(analyze(ctx,'app.js',updated))
            self.assertEqual([f.location for f in ctx['findings']],['owner/repo/app.js:3'])
