import os,sys,json,tempfile,time,unittest
from pathlib import Path
sys.path.insert(0,str(Path.cwd()));sys.path.insert(0,str(Path.cwd()/'tests'))
with tempfile.TemporaryDirectory(prefix='phase22-focused-') as td:
 os.environ.update(SENTINELSCAN_DATA_DIR=td,SENTINELSCAN_LLM_ENABLED='false',SENTINELSCAN_TEST_SEMGREP='/opt/homebrew/bin/semgrep');os.environ.pop('SENTINELSCAN_GITHUB_TOKEN',None)
 names=['test_replay_safety','test_website_scanner','test_source_scanner','test_ollama_reliability','test_phase21_accuracy','test_hardening','test_end_to_end']
 suite=unittest.TestLoader().loadTestsFromNames(names);start=time.monotonic()
 with open('docs/audit/PHASE_22_FOCUSED.log','w') as out:r=unittest.TextTestRunner(stream=out,verbosity=2).run(suite)
 Path('docs/audit/PHASE_22_FOCUSED.json').write_text(json.dumps(dict(command='.venv/bin/python -B /tmp/phase22_focused.py',modules=names,tests=r.testsRun,failures=len(r.failures),errors=len(r.errors),skipped=len(r.skipped),seconds=time.monotonic()-start,exit=0 if r.wasSuccessful() else 1),indent=2))
