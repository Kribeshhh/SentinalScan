import tempfile,os,subprocess,sys,time,json
from pathlib import Path
with tempfile.TemporaryDirectory(prefix='phase22-data-') as td:
 env=os.environ.copy();env.update(SENTINELSCAN_DATA_DIR=td,SENTINELSCAN_LLM_ENABLED='false',SENTINELSCAN_TEST_SEMGREP='/opt/homebrew/bin/semgrep');env.pop('SENTINELSCAN_GITHUB_TOKEN',None)
 focused='--full' not in sys.argv;cmd=['.venv/bin/python','-B','-m','unittest','discover','-s','tests']+(['-p','test_phase22_accuracy.py'] if focused else [])+['-v']
 name='PHASE_22_FOCUSED' if focused else 'PHASE_22_TESTS';start=time.monotonic()
 with open('docs/audit/'+name+'.log','w') as f:r=subprocess.run(cmd,env=env,stdout=f,stderr=subprocess.STDOUT)
 Path('docs/audit/'+name+'.json').write_text(json.dumps(dict(command=cmd,exit=r.returncode,seconds=time.monotonic()-start),indent=2));print(r.returncode)
