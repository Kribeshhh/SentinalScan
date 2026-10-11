import json,time,tempfile,zipfile,os,sys
from pathlib import Path
from unittest.mock import patch

def verify(app):
 from scanner.source_scanner import run_repository,MODULE_NAMES
 from scanner.engines import external
 from scanner.engines.process import run_tool
 from database import get_db
 base=json.load(open('docs/fixes/PHASE_14_BEFORE.json'));fixtures=base['fixtures']
 evidence={'launcher':'/bin/zsh ./run-local.sh -> .venv python3 -u app.py -> create_app().run (serving replaced by temporary test hook)','config':{k:app.config[k] for k in ('CODEQL_ENABLED','CODEQL_BINARY','CODEQL_SEARCH_PATH','SEMGREP_ENABLED','LLM_ENABLED')},'interpreter':sys.executable,'runs':[]}
 assert app.config['CODEQL_ENABLED'] and not app.config['LLM_ENABLED']
 assert Path(app.config['DATABASE']).is_relative_to(Path(os.environ['SENTINELSCAN_DATA_DIR']))
 class Archive:
  destination=None
  def __init__(self,files):self.files=files
  def archive(self,repository,commit,destination):
   self.destination=destination
   with zipfile.ZipFile(destination,'w') as z:
    for p,src in self.files.items():z.writestr('fixture/'+p,src)
 try:
  for language in ('python','javascript','mixed'):
   files=fixtures[language] if language!='mixed' else {**fixtures['python'],**fixtures['javascript']}
   archive=Archive(files);calls=[];raw=[];imported=[]
   def traced(args,work,seconds,output=None):
    row={'args':args,'work':str(work),'budget':seconds};calls.append(row);start=time.monotonic()
    try:
     payload=run_tool(args,work,seconds,output);row['status']='Completed'
     if 'create' in args:row['database_created']=Path(args[3]).is_dir()
     if output and 'analyze' in args:
      doc=json.loads(payload)
      row['invocations']=[{'success':i.get('executionSuccessful'),'levels':[n.get('level') for n in i.get('toolExecutionNotifications',[])]} for r in doc['runs'] for i in r.get('invocations',[])]
      raw.extend({'rule':r['ruleId'],'locations':r['locations']} for run in doc['runs'] for r in run['results'])
     return payload
    except Exception as e:row['error']=str(e);raise
    finally:row['seconds']=round(time.monotonic()-start,3)
   original_import=external.import_results
   def import_trace(payload,ctx,engine):
    before=len(ctx['findings']);result=original_import(payload,ctx,engine)
    if engine=='CodeQL':
     imported.extend({'title':f.title,'location':f.location,'severity':f.severity,'confidence':f.confidence} for f in ctx['findings'][before:])
    return result
   with app.app_context():
    db=get_db()
    with db:
     sid=db.execute("INSERT INTO scans(scan_type,target,status) VALUES ('Repository',?,'Queued')",('audit/'+language,)).lastrowid
     db.execute('INSERT INTO repositories(name,location,scan_id) VALUES (?,?,?)',(language,'audit/'+language,sid))
     db.executemany('INSERT INTO scan_modules(scan_id,name) VALUES (?,?)',[(sid,n) for n in MODULE_NAMES])
   start=time.monotonic()
   with patch.object(external,'run_tool',side_effect=traced),patch.object(external,'import_results',side_effect=import_trace):run_repository(app,sid,archive,{'full_name':'audit/'+language},'fixture','a'*40,False)
   with app.app_context():
    db=get_db();coverage=dict(db.execute("SELECT status,error,data_json FROM scan_modules WHERE scan_id=? AND name='CodeQL'",(sid,)).fetchone())
    coverage['data']=json.loads(coverage.pop('data_json'));saved=[]
    for r in db.execute('SELECT f.*,s.data_json FROM findings f JOIN finding_solutions s ON f.id=s.finding_id WHERE scan_id=?',(sid,)):
     a=json.loads(r['data_json']).get('finding_context',{}).get('analysis',{})
     engines=[p['engine'] for p in a.get('detected_by',[])]
     if a.get('engine')=='CodeQL' or 'CodeQL' in engines:saved.append({'title':r['title'],'location':r['location'],'severity':r['severity'],'confidence':r['confidence'],'analysis':a})
    scan_status=db.execute('SELECT status FROM scans WHERE id=?',(sid,)).fetchone()[0]
   row={'language':language,'seconds':round(time.monotonic()-start,3),'scan_status':scan_status,'coverage':coverage,'saved':saved,'imported_codeql':imported,'raw_result_locations':raw,'commands':calls,'cleaned':all(not Path(r['work']).exists() for r in calls) and not archive.destination.parent.exists()}
   evidence['runs'].append(row)
   print(language,coverage['status'],'saved',len(saved),'cleaned',row['cleaned'],flush=True)
   assert coverage['status']=='Completed',row
   assert len(saved)==(2 if language=='mixed' else 1),row
   assert all('positive.' in r['location'] and r['severity']==('High' if '.py:' in r['location'] else 'Medium') for r in saved),row
   assert len(imported)==len(saved) and all(f['severity']=='High' and f['confidence']=='Medium' for f in imported),row
   assert row['cleaned']
   for r in raw:
    physical=r['locations'][0]['physicalLocation'];path=physical['artifactLocation']['uri'];line=physical['region']['startLine']
    assert path=='positive.py' and line==7 or path=='positive.js' and line==2,(path,line)
 finally:
  app.extensions['scan_manager'].shutdown()
  Path('docs/audit/PHASE_22_CODEQL.json').write_text(json.dumps(evidence,indent=2)+'\n')
