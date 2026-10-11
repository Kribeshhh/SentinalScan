import os,sys,tempfile,json,time
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path.cwd()))
with tempfile.TemporaryDirectory(prefix='phase22-failure-') as td:
 os.environ['SENTINELSCAN_DATA_DIR']=td;os.environ['SENTINELSCAN_LLM_ENABLED']='false';os.environ.pop('SENTINELSCAN_GITHUB_TOKEN',None)
 from app import create_app
 from database import get_db
 from analysis.finding_engine import Finding,save_finding
 from analysis.llm_review import refine_finding
 from analysis.recommendation_composer import final_solution
 from tests.test_llm_sast_dast import website,configuration
 from tests.ollama_fixtures import transport,envelope
 from integrations.network import RemoteError
 from integrations import llm
 app=create_app({'TESTING':True,'DATABASE':str(Path(td)/'test.sqlite3'),'LLM_ENABLED':True,'OLLAMA_MODEL':'qwen2.5-coder:3b','OLLAMA_BASE_URL':'http://127.0.0.1:11434'})
 results=[]
 try:
  for case in ['unavailable','missing_model','timeout','invalid_output','unsafe','unsupported']:
   with app.app_context():
    db=get_db()
    with db:sid=db.execute("INSERT INTO scans(scan_type,target,status) VALUES ('Website','http://127.0.0.1/','Completed')").lastrowid
    f=website();f.pop('id',None);f.pop('created_at',None)
    f.update(description='Observed missing header on controlled HTML response.',impact='Browser sniffing protection is absent.');fields=Finding.__dataclass_fields__;save_finding(db,sid,Finding(**{k:v for k,v in f.items() if k in fields}))
    f=db.execute('SELECT * FROM findings WHERE scan_id=?',(sid,)).fetchone();before=dict(f)
    config=dict(app.config);config['OLLAMA_MODEL']='fixture' if case!='missing_model' else 'phase22-not-installed-fixture'
    calls=[];real=llm.request
    def native(*a,**kw):
     result=real(*a,**kw);calls.append({'path':a[1],'http':result[0]});return result
    if case in ('unavailable','timeout'):side=RemoteError('Local Ollama service unavailable or timed out')
    elif case=='missing_model':side=native
    elif case=='invalid_output':side=transport(200,b'not-json')
    else:
     answer=configuration()
     if case=='unsafe':answer['recommendation']['suggested_code_or_config']='X-Content-Type-Options: disabled'
     else:answer['recommendation']['what_to_change']='Install imaginary-package 99.99.99 and disable authentication.'
     side=transport(200,envelope(json.dumps(answer)))
    with patch('integrations.llm.request',side_effect=side) as send:accepted=refine_finding(db,f,config)
    final=final_solution(db,f);page=app.test_client().get('/findings/'+str(f['id']))
    result={'case':case,'mode':'real inventory with absent model' if case=='missing_model' else 'mock failure','request_calls':send.call_count,'native_calls':calls,'accepted':accepted,'ai_assisted':final['ai_assisted'],'ai_rows':db.execute('SELECT count(*) FROM ai_reviews WHERE finding_id=?',(f['id'],)).fetchone()[0],'scan_status':db.execute('SELECT status FROM scans WHERE id=?',(sid,)).fetchone()[0],'finding_unchanged':before==dict(db.execute('SELECT * FROM findings WHERE id=?',(f['id'],)).fetchone()),'http':page.status_code,'single_recommendation':page.get_data(as_text=True).count('id="recommendation"'),'base_saved':bool(db.execute('SELECT 1 FROM finding_solutions WHERE finding_id=?',(f['id'],)).fetchone())}
    assert not accepted and not final['ai_assisted'] and result['finding_unchanged'] and page.status_code==200 and result['base_saved']
    results.append(result)
 finally:app.extensions['scan_manager'].shutdown()
 Path('docs/audit/PHASE_22_FAILURES.json').write_text(json.dumps(results,indent=2)+'\n')
 print('PASS',len(results),'failure cases')
