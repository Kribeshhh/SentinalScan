import os,sys,tempfile,json,threading,stat
from pathlib import Path
from unittest.mock import patch
sys.path[:0]=[str(Path.cwd()),str(Path.cwd()/'tests')]
rows=[]
from scanner.target import validate_target,TargetError
for address in ('127.0.0.1','10.1.2.3','192.168.1.1','[::1]','[fd12::1]','169.254.169.254','100.100.100.200','[fd00:ec2::254]','0.0.0.0','224.0.0.1','[::ffff:127.0.0.1]'):
 for allow in (False,True):
  try:validate_target('http://'+address+'/',allow);accepted=True
  except TargetError:accepted=False
  rows.append(dict(case='address policy',address=address,allow_private=allow,accepted=accepted))
with tempfile.TemporaryDirectory(prefix='phase08-') as td:
 os.environ.update(SENTINELSCAN_DATA_DIR=td,SENTINELSCAN_LLM_ENABLED='false')
 from app import create_app
 from database import get_db
 from scanner.website_scanner import QueueFull
 app=create_app(dict(TESTING=True,REPORTS_DIR=str(Path(td)/'reports')));manager=app.extensions['scan_manager'];gate=threading.Event();started=threading.Event();active=[];max_active=[0]
 def worker(*args):
  active.append(1);max_active[0]=max(max_active[0],len(active));started.set()
  try:gate.wait(3)
  finally:active.pop();manager.slots.release()
 try:
  with patch.object(manager,'run',side_effect=worker),app.app_context():
   ids=[manager.submit(validate_target('http://127.0.0.1/',True),[]) for _ in range(4)]
   started.wait(1)
   try:manager.submit(validate_target('http://127.0.0.1/',True),[]);rejected=False
   except QueueFull:rejected=True
   rows.append(dict(case='actual queue admission',accepted=len(ids),fifth_rejected=rejected,persisted=get_db().execute('select count(*) from scans').fetchone()[0]))
   gate.set();manager.executor.submit(lambda:None).result(timeout=5)
  rows.append(dict(case='single worker',maximum_active=max_active[0]))
  client=app.test_client();r=client.get('/');headers={k:r.headers.get(k) for k in ('Content-Security-Policy','X-Content-Type-Options','X-Frame-Options','Referrer-Policy','Cache-Control')}
  with client.session_transaction() as s:csrf=s['csrf_token']
  rows.append(dict(case='headers',headers=headers))
  rows.append(dict(case='CSRF and Host',missing=client.post('/reports/generate').status_code,wrong=client.post('/reports/generate',data={'csrf_token':'wrong'}).status_code,host=client.get('/',headers={'Host':'foreign.invalid'}).status_code,cancel=client.post('/scans/1/cancel',data={'csrf_token':csrf}).status_code))
  rows.append(dict(case='fresh directory permissions',directory=oct(Path(td).stat().st_mode&0o777),database=oct(Path(app.config['DATABASE']).stat().st_mode&0o777),key=oct((Path(td)/'.secret_key').stat().st_mode&0o777)))
 finally:gate.set();manager.shutdown()
 # Existing data directory permissions are not tightened by settings().
 old=Path(td)/'existing';old.mkdir(mode=0o755);old.chmod(0o755)
 os.environ['SENTINELSCAN_DATA_DIR']=str(old)
 app2=create_app(dict(TESTING=True))
 try:rows.append(dict(case='existing directory permissions',directory=oct(old.stat().st_mode&0o777),database=oct(Path(app2.config['DATABASE']).stat().st_mode&0o777)))
 finally:app2.extensions['scan_manager'].shutdown()
Path('docs/audit/PHASE_22_SECURITY.json').write_text(json.dumps(rows,indent=2));print(json.dumps(rows,indent=2))
