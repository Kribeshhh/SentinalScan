import os,tempfile,subprocess,time,json,sys
from pathlib import Path
with tempfile.TemporaryDirectory() as td:
 env=dict(os.environ,SENTINELSCAN_DATA_DIR=td,SENTINELSCAN_LLM_ENABLED='false',SENTINELSCAN_TEST_SEMGREP='/opt/homebrew/bin/semgrep');env.pop('SENTINELSCAN_GITHUB_TOKEN',None)
 cmd=['.venv/bin/python','-B','-m','unittest','discover','-s','tests']+([] if '--full' in sys.argv else ['-p','test_phase23_quality.py'])+['-v']
 name='TESTS' if '--full' in sys.argv else 'FOCUSED';start=time.monotonic()
 with open('docs/fixes/PHASE_23_'+name+'.log','w') as f:r=subprocess.run(cmd,env=env,stdout=f,stderr=subprocess.STDOUT)
 Path('docs/fixes/PHASE_23_'+name+'.json').write_text(json.dumps(dict(command=cmd,exit=r.returncode,seconds=time.monotonic()-start)));print(r.returncode)
