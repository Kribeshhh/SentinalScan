import os,sys,tempfile,json,time,zipfile,hashlib,secrets
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path.cwd()))
OUT=Path('docs/audit/PHASE_22_LIVE.json')
before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('.').rglob('*') if p.is_file() and p.suffix in ('.py','.html','.js','.css','.sh') and not any(x in p.parts for x in ('.venv','.git','data','reports_output','docs'))}
Path('/tmp/phase22-live-before.json').write_text(json.dumps(before))
with tempfile.TemporaryDirectory(prefix='phase22-live-') as td:
 os.environ['SENTINELSCAN_DATA_DIR']=td;os.environ['SENTINELSCAN_LLM_ENABLED']='false';os.environ.pop('SENTINELSCAN_GITHUB_TOKEN',None)
 from app import create_app
 from database import get_db
 from integrations import llm
 from analysis import llm_review,evidence_review
 from analysis.recommendation_composer import final_solution
 from analysis.remediation_workflow import finding_solution
 from analysis.finding_engine import Finding,save_finding
 from analysis.llm_review import clean
 from tests.test_llm_sast_dast import website
 real_request=llm.request
 marker='AuditOnly-'+secrets.token_hex(15)
 evidence={'model':'qwen2.5-coder:3b','endpoint':'http://127.0.0.1:11434','cases':[]}
 try:
  status,_,raw=real_request(evidence['endpoint'],'/api/tags',seconds=5)
  inventory=json.loads(raw);evidence['inventory']={'status':status,'body':inventory}
  if status!=200 or not any(m.get('name')==evidence['model'] for m in inventory.get('models',[])):raise ValueError('Model unavailable')
 except Exception as exc:
  evidence.update(status='NOT TESTED',reason=type(exc).__name__);OUT.write_text(json.dumps(evidence,indent=2));print('Live Ollama NOT TESTED');sys.exit(0)
 def sanitized(x):
  if isinstance(x,dict):return {k:sanitized(v) for k,v in x.items()}
  if isinstance(x,list):return [sanitized(v) for v in x]
  return clean(x,(marker,)) if isinstance(x,str) else x
 for name,files in [('sql',{'app.py':'from flask import request\nimport sqlite3\ndef search():\n db=sqlite3.connect(":memory:")\n return db.execute("SELECT * FROM users WHERE name="+request.args.get("q"))\n'}),('reflected_xss',None),('secret',{'settings.py':'password = "'+marker+'"\n'}),('headers',None),('no_code_banner',None)]:
  row={'case':name,'requests':[],'validation_errors':[]};evidence['cases'].append(row)
  app=create_app({'TESTING':True,'DATABASE':str(Path(td)/(name+'.sqlite3')),'LLM_ENABLED':True,'OLLAMA_MODEL':evidence['model'],'OLLAMA_BASE_URL':evidence['endpoint'],'SEMGREP_ENABLED':False,'CODEQL_ENABLED':False})
  def trace(base,path,**kw):
   r={'path':path,'method':kw.get('method','GET')};row['requests'].append(r);start=time.monotonic()
   if kw.get('body'):
    body=kw['body'].decode();r['synthetic_secret_absent']=marker not in body
    if path=='/api/chat':
     assert marker not in body,'Secret redaction failed before transport'
     r['request_sha256']=hashlib.sha256(kw['body']).hexdigest();r['bytes']=len(kw['body'])
     r['context']=sanitized(json.loads(json.loads(body)['messages'][1]['content']))
   try:
    status,h,raw=real_request(base,path,**kw);r['http']=status
    if path=='/api/chat':r['response']=sanitized(json.loads(raw))
    return status,h,raw
   except Exception as exc:r['error']=type(exc).__name__;raise
   finally:r['seconds']=round(time.monotonic()-start,3)
  originals={k:getattr(m,k) for m,k in [(evidence_review,'run_review'),(llm_review,'process')]}
  def wrap(key):
   def run(*a,**kw):
    try:return originals[key](*a,**kw)
    except Exception as exc:row['validation_errors'].append({'stage':key,'type':type(exc).__name__,'message':clean(str(exc),(marker,))});raise
   return run
  class Archive:
   def archive(self,repo,sha,dest):
    with zipfile.ZipFile(dest,'w') as z:
     for p,s in files.items():z.writestr('fixture/'+p,s)
  start=time.monotonic()
  with patch.object(llm,'request',side_effect=trace),patch.object(evidence_review,'run_review',side_effect=wrap('run_review')),patch.object(llm_review,'process',side_effect=wrap('process')):
   if files:
    with app.app_context():
     sid=app.extensions['scan_manager'].submit_repository(Archive(),{'name':name,'owner':'audit','full_name':'audit/'+name,'url':'https://github.com/audit/'+name},'fixture','a'*40,False)
    app.extensions['scan_manager'].shutdown()
   else:
    # Real existing header rule with a controlled HTTP observation; no public DAST.
    from scanner import header_scanner
    from types import SimpleNamespace
    from scanner.target import validate_target
    with app.app_context():
     db=get_db()
     with db:sid=db.execute("INSERT INTO scans(scan_type,target,status) VALUES ('Website','http://127.0.0.1/','Completed')").lastrowid
     from scanner.http_scanner import Response
     ctx={'target':validate_target('http://127.0.0.1/',True),'response':Response('http://127.0.0.1/',200,[('Content-Type','text/html')],b'<html>Fixture</html>',False,[]),'findings':[]}
     if name=='headers':
      header_scanner.run(ctx)
      selected=[f for f in ctx['findings'] if 'X-Content-Type-Options' in f.title]
     elif name=='reflected_xss':
      from scanner import xss_scanner
      from scanner.http_scanner import Client
      from urllib.parse import urlsplit,parse_qs
      url='http://127.0.0.1/?q=hello'
      ctx['target']=validate_target(url,True);ctx['response']=Response(url,200,[('Content-Type','text/html')],b'<html>inert fixture baseline</html>',False,[])
      ctx['client']=Client(ctx['target'],reviewed_queries={url:[0]})
      def inert_response(probe):
       value=parse_qs(urlsplit(probe).query)['q'][0]
       return Response(probe,200,[('Content-Type','text/html')],('<script>var q="'+value+'";</script>').encode(),False,[])
      with patch.object(ctx['client'],'get',side_effect=inert_response):xss_scanner.run(ctx)
      selected=ctx['findings']
     else:
      from scanner import disclosure_scanner
      ctx['response']=Response('http://127.0.0.1/',200,[('Content-Type','text/html'),('Server','FixtureServer/1.2.3')],b'<html>fixture</html>',False,[])
      disclosure_scanner.run(ctx);selected=ctx['findings']
     for f in selected:save_finding(db,sid,f)
    app.extensions['scan_manager'].on_complete(sid,())
    app.extensions['scan_manager'].shutdown()
  with app.app_context():
   db=get_db();row['scan']=dict(db.execute('SELECT id,status FROM scans WHERE id=?',(sid,)).fetchone());row['findings']=[]
   for f in db.execute('SELECT * FROM findings WHERE scan_id=?',(sid,)).fetchall():
    final=final_solution(db,f);base=finding_solution(db,f);ai=db.execute('SELECT data_json FROM ai_reviews WHERE finding_id=?',(f['id'],)).fetchone()
    html=app.test_client().get('/findings/'+str(f['id']))
    row['findings'].append(sanitized({'id':f['id'],'title':f['title'],'severity':f['severity'],'confidence':f['confidence'],'location':f['location'],'evidence':f['evidence'],'base':base,'ai_saved':bool(ai),'ai_review':json.loads(ai[0]) if ai else None,'final':final,'ui_status':html.status_code,'single_recommendation':html.get_data(as_text=True).count('id="recommendation"'),'ai_indicator':'AI Assisted' in html.get_data(as_text=True),'secret_absent_ui':marker not in html.get_data(as_text=True)}))
   row['scan_ui_status']=app.test_client().get('/scans/'+str(sid)).status_code
   row['integrity']=db.execute('PRAGMA integrity_check').fetchone()[0]
  row['seconds']=round(time.monotonic()-start,3)
  OUT.write_text(json.dumps(evidence,indent=2)+'\n')
  print(name,'findings',len(row['findings']),'chat',sum(r['path']=='/api/chat' for r in row['requests']),'AI',[f['final']['ai_assisted'] for f in row['findings']],'errors',row['validation_errors'],flush=True)
