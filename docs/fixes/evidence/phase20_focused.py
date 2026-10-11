import os, tempfile, subprocess, time, json
from pathlib import Path
with tempfile.TemporaryDirectory(prefix='phase20-focused-') as td:
    env=os.environ.copy();env.update(SENTINELSCAN_DATA_DIR=td,SENTINELSCAN_LLM_ENABLED='false');env.pop('SENTINELSCAN_GITHUB_TOKEN',None)
    cmd=['.venv/bin/python','-B','-m','unittest','discover','-s','tests','-p','test_replay_safety.py','-v']
    start=time.monotonic()
    with open('docs/audit/PHASE_20_FOCUSED.log','w') as f:
        r=subprocess.run(cmd,env=env,stdout=f,stderr=subprocess.STDOUT)
    Path('docs/audit/PHASE_20_FOCUSED.json').write_text(json.dumps(dict(command=cmd,exit=r.returncode,seconds=round(time.monotonic()-start,3)),indent=2))
    print(r.returncode)
