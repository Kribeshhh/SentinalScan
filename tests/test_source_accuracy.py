"""Source transformations are inspected and rescanned, never executed."""
import ast
import unittest
from analysis.solution_engine import solution_for
from analysis.source_validation import validate_candidate


class SourceAccuracyTests(unittest.TestCase):
    def sql(self,driver='sqlite3',name='email'):
        return f'''import {driver}
connection = {driver}.connect(database)
cur = connection.cursor()
{name} = request.args.get("email")
query = "SELECT id FROM accounts WHERE email='" + {name} + "'"
cur.execute(query)
keep_this()
'''

    def finding(self,source,title='Potential SQL injection in constructed query',category='Injection',filename='app.py',needle='cur.execute'):
        line=next(i for i,s in enumerate(source.splitlines(),1) if needle in s)
        return dict(title=title,category=category,source='Repository',location=f'owner/repo/{filename}:{line}',evidence='Recognized input request.args → query → SQL execute')

    def test_sqlite_and_psycopg_actual_names_and_static_recheck(self):
        for driver in ('sqlite3','psycopg','psycopg2'):
            source=self.sql(driver,'customer_email');f=self.finding(source)
            result=solution_for(f,source)
            self.assertTrue(result['exact']);self.assertEqual(result['kind'],'Suggested Source Fix')
            candidate=result['examples'][0]
            self.assertIn('customer_email',candidate['code']);self.assertNotIn('username',candidate['code'])
            self.assertIn('SELECT id FROM accounts WHERE email=',candidate['code'])
            self.assertIn('?' if driver=='sqlite3' else '%s',candidate['code'])
            edited=source.replace(result['before'],candidate['code'].rstrip('\n'),1)
            ast.parse(edited)
            self.assertEqual(candidate['validation']['status'],'Passed')
            self.assertEqual(validate_candidate(f,source,edited)['status'],'Passed')
            self.assertEqual(edited.splitlines()[:5],source.splitlines()[:5]);self.assertTrue(edited.endswith('keep_this()\n'))
            self.assertEqual(result['fix_confidence'],'Medium')

    def test_sql_fstring_and_import_alias(self):
        source=self.sql().replace('import sqlite3','import sqlite3 as db').replace('sqlite3.connect','db.connect').replace('"SELECT id FROM accounts WHERE email=\'" + email + "\'"','f"SELECT id FROM accounts WHERE email=\'{email}\'"')
        result=solution_for(self.finding(source),source)
        self.assertTrue(result['exact']);self.assertIn('(email,)',result['examples'][0]['code'])

    def test_uncertain_sql_rebindings_unknown_orm_and_query_shapes(self):
        cases=[self.sql().replace('sqlite3','sqlalchemy'), self.sql().replace('sqlite3','unknown_driver'),
            self.sql().replace('cur.execute(query)','email = another\ncur.execute(query)'),
            self.sql().replace('cur.execute(query)','cur = another\ncur.execute(query)'),
            self.sql().replace('email=','email LIKE '),
            self.sql().replace('cur.execute(query)','cur.execute(query, existing_params)'),
            self.sql().replace('cur.execute(query)','if allowed:\n cur.execute(query)'),
            self.sql().replace('SELECT id FROM accounts WHERE email=', 'SELECT id FROM ')]
        for source in cases:
            with self.subTest(source=source):
                result=solution_for(self.finding(source),source)
                self.assertFalse(result['exact']);self.assertEqual(result['examples'],[])

    def test_wrong_finding_type_or_language_cannot_get_sql_patch(self):
        source=self.sql()
        for title,file in [('Dynamic Python code execution','app.py'),('Potential SQL injection in constructed query','data.json')]:
            result=solution_for(self.finding(source,title=title,filename=file),source)
            self.assertFalse(result['exact']);self.assertEqual(result['examples'],[])

    def test_dynamic_commands_and_execution_stay_guidance(self):
        for title,line in [('Potential shell command injection','os.system(command)'),('Dynamic Python code execution','eval(expression)')]:
            source='import os\n'+line
            result=solution_for(self.finding(source,title=title,needle=line),source)
            self.assertEqual(result['examples'],[]);self.assertIn('manual review',result['unavailable'])

    def test_dom_candidate_validation_and_dependency_labels(self):
        for prefix,expected in [('', 'Illustrative Secure Example'),('import DOMPurify from "dompurify";\n','Suggested Source Fix')]:
            source=prefix+'function show(value) {\n view.innerHTML = value;\n other.innerHTML = otherValue;\n}\n'
            f=self.finding(source,'Potential unsafe DOM HTML assignment','Injection','ui.js','view.innerHTML')
            result=solution_for(f,source)
            self.assertTrue(result['exact'])
            self.assertEqual(result['examples'][1]['kind'],expected)
            for candidate in result['examples']:
                self.assertEqual(candidate['validation']['status'],'Passed')
                edited=source.replace(result['before'],candidate['code'].rstrip('\n'),1)
                self.assertIn('other.innerHTML = otherValue;',edited)
                self.assertIn('view.',candidate['code']);self.assertIn('value',candidate['code'])

    def test_validation_rejects_wrong_target_syntax_and_new_findings(self):
        source=self.sql();f=self.finding(source)
        self.assertNotEqual(validate_candidate(f,source,source)['status'],'Passed')
        self.assertNotEqual(validate_candidate(f,source,'this is not python (')['status'],'Passed')
        fixed=source.replace('cur.execute(query)','cur.execute("SELECT id FROM accounts WHERE email=?",(email,))')
        self.assertNotEqual(validate_candidate(f,source,fixed+'eval(request.args.get("x"))\n')['status'],'Passed')
        self.assertNotEqual(validate_candidate(dict(f,title='Other rule'),source,fixed)['status'],'Passed')

    def test_validation_never_exposes_secret(self):
        source=self.sql();secret='LocalFixtureCredential-9371'
        result=validate_candidate(self.finding(source),source,source+'\npassword="'+secret+'"')
        self.assertNotEqual(result['status'],'Passed');self.assertNotIn(secret,str(result))

    def test_secret_uses_actual_assignment_name_without_exposing_value(self):
        secret='LocalFixtureCredential-2841'
        source='def settings():\n    admin_password = "'+secret+'"\n'
        f=self.finding(source,'Hardcoded credential','Secret Exposure','settings.py','admin_password')
        result=solution_for(f,source)
        self.assertNotIn(secret,str(result));self.assertIn('[REDACTED]',result['context'])
        self.assertFalse(result['exact']);self.assertEqual(result['kind'],'Illustrative Secure Example')
        self.assertIn('admin_password = os.environ',result['examples'][0]['code'])
        self.assertTrue(any('rotate or revoke' in n for n in result['notes']))
        self.assertNotIn('validation',result['examples'][0])
        for suffix in ('json','yaml','properties','java','js'):
            other=dict(f,location='o/r/config.'+suffix+':2')
            self.assertEqual(solution_for(other,source)['examples'],[])

    def test_snapshot_normalization_preserves_validated_candidate(self):
        from analysis.recommendation import recommendation_for
        source=self.sql();f=self.finding(source)
        solution=solution_for(f,source)
        again=recommendation_for(f,solution)
        self.assertEqual(again['examples'],solution['examples'])
        self.assertTrue(again['source_aware'])
        self.assertEqual(again['examples'][0]['validation']['status'],'Passed')

    def test_sql_preserves_captured_alias_not_later_binding(self):
        source=self.sql().replace('query =', 'saved_email = email\nemail = other_email\nquery =').replace('+ email +', '+ saved_email +')
        result=solution_for(self.finding(source),source)
        self.assertTrue(result['exact'])
        self.assertIn('(saved_email,)',result['examples'][0]['code'])
        self.assertNotIn('other_email',result['examples'][0]['code'])
