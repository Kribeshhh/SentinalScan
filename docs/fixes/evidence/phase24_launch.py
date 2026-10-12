import tempfile,subprocess,os
with tempfile.TemporaryDirectory(prefix='phase24-data-') as td:
 env=os.environ.copy();env['SENTINELSCAN_DATA_DIR']=td;env['SENTINELSCAN_LLM_ENABLED']='false';env['PYTHONPATH']='/tmp/phase24-hook'
 env.pop('SENTINELSCAN_CODEQL_SEARCH_PATH',None);env.pop('SENTINELSCAN_GITHUB_TOKEN',None)
 p=subprocess.run(['/bin/zsh','./run-local.sh'],env=env,timeout=250)
 raise SystemExit(p.returncode)
