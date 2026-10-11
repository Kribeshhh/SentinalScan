import os,subprocess,tempfile,time,json
from pathlib import Path
with tempfile.TemporaryDirectory(prefix='phase18-tests-') as td:
 env=os.environ.copy();env.update(SENTINELSCAN_DATA_DIR=td,SENTINELSCAN_LLM_ENABLED='false',SENTINELSCAN_TEST_SEMGREP='/opt/homebrew/bin/semgrep');env.pop('SENTINELSCAN_GITHUB_TOKEN',None)
 cmd=['.venv/bin/python','-B','-m','unittest','discover','-s','tests','-v'];start=time.monotonic()
 with open('docs/audit/PHASE_20_TESTS.log','w') as out:r=subprocess.run(cmd,env=env,stdout=out,stderr=subprocess.STDOUT)
 Path('docs/audit/PHASE_20_TESTS.json').write_text(json.dumps({'command':cmd,'exit':r.returncode,'seconds':round(time.monotonic()-start,3)},indent=2))
 print(r.returncode,round(time.monotonic()-start,3))
