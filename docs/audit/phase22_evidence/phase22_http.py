import os,subprocess,tempfile,signal,time,urllib.request,json,re,sqlite3
from pathlib import Path
result={'method':'Actual run-local.sh with temporary Flask.run port=0 wrapper; all serving behavior retained','production_code_changed':False}
with tempfile.TemporaryDirectory(prefix='phase22-http-') as td:
 hook=Path(td)/'hook';hook.mkdir()
 (hook/'sitecustomize.py').write_text('import flask\n_original=flask.Flask.run\ndef _run(self,*args,**kwargs):\n kwargs["port"]=0\n return _original(self,*args,**kwargs)\nflask.Flask.run=_run\n')
 env=os.environ.copy();env.update(SENTINELSCAN_DATA_DIR=str(Path(td)/'data'),SENTINELSCAN_LLM_ENABLED='false',PYTHONDONTWRITEBYTECODE='1',PYTHONPATH=str(hook));env.pop('SENTINELSCAN_GITHUB_TOKEN',None)
 log=Path(td)/'server.log'
 with log.open('w') as output:
  p=subprocess.Popen(['/bin/zsh','./run-local.sh'],env=env,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
  try:
   for _ in range(80):
    match=re.search(r'Running on (http://127.0.0.1:\d+)',log.read_text())
    if match or p.poll() is not None:break
    time.sleep(.1)
   if match:
    with urllib.request.urlopen(match.group(1)+'/',timeout=3) as response:result.update(http=response.status,brand=b'SentinelScan' in response.read(),headers={k:response.headers.get(k) for k in ('Content-Security-Policy','X-Frame-Options','X-Content-Type-Options')})
   result['alive']=p.poll() is None
  finally:
   if p.poll() is None:os.killpg(p.pid,signal.SIGTERM)
   p.wait(timeout=5)
 result['log']=log.read_text()
 database=Path(td)/'data/sentinelscan.sqlite3'
 if database.exists():
  with sqlite3.connect(database.as_uri()+'?mode=ro',uri=True) as db:result['database']={'tables':[r[0] for r in db.execute("select name from sqlite_master where type='table'")],'version':db.execute('pragma user_version').fetchone()[0],'integrity':db.execute('pragma quick_check').fetchone()[0],'scans':db.execute('select count(*) from scans').fetchone()[0]}
 result['status']='PASS' if result.get('http')==200 and result.get('brand') and result['database']['integrity']=='ok' else 'FAIL'
Path('docs/audit/PHASE_22_HTTP.json').write_text(json.dumps(result,indent=2));print(result['status'])
