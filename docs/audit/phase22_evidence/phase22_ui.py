import os,sys,tempfile,json
from pathlib import Path
sys.path[:0]=[str(Path.cwd()),str(Path.cwd()/'tests')]
from unittest.mock import patch
from bs4 import BeautifulSoup
rows=[]
with tempfile.TemporaryDirectory(prefix='phase06-matrix-') as td:
 os.environ.update(SENTINELSCAN_DATA_DIR=td,SENTINELSCAN_LLM_ENABLED='false')
 from app import create_app
 from database import get_db
 app=create_app(dict(TESTING=True,REPORTS_DIR=str(Path(td)/'reports')));c=app.test_client()
 def check(path,expected=200,**kw):
  r=c.get(path,**kw);rows.append(dict(method='GET',path=path,expected=expected,actual=r.status_code,passed=r.status_code==expected));return r
 for p in ('/','/website-scan','/repository-scan','/scans','/findings','/reports','/comparisons','/risk-trends','/static/js/app.js','/static/css/style.css'):check(p)
 empty=BeautifulSoup(c.get('/').data,'html.parser');assert 'No scans recorded' in empty.get_text();assert not empty.select('.chart-point')
 nav=[]
 for a in empty.select('nav a[href]'):
  p=a['href'];nav.append(dict(path=p,status=c.get(p).status_code))
 with c.session_transaction() as s:csrf=s['csrf_token']
 for p in ('/scans/99999','/scans/99999/status','/findings/99999','/comparisons/99999','/reports/99999/download','/missing','/findings/1/edit'):check(p,404)
 for p in ('/scans?page=bad','/findings?severity=Wrong','/reports?scan_id=bad','/risk-trends?scan_id=bad'):check(p,400)
 for p,data in [('/website-scan',dict(action='start',url='file:///tmp/test',authorized='yes')),('/repository-scan',dict(action='start',repository='not a repo',authorized='yes')),('/comparisons',dict(baseline='bad',current='1')),('/reports/generate',dict(scan_id='1',format='PDF'))]:
  r=c.post(p,data=dict(data,csrf_token=csrf));rows.append(dict(method='POST',path=p,expected=400,actual=r.status_code,passed=r.status_code==400))
 states=[]
 with app.app_context():
  db=get_db()
  for status,progress in [('Queued',0),('Running',42),('Completed',100),('Failed',100)]:
   with db:
    sid=db.execute('insert into scans(scan_type,target,status,progress,error) values (?,?,?,?,?)',('Repository','audit/fixture @ main',status,progress,'Fixture failure' if status=='Failed' else None)).lastrowid
    db.execute('insert into scan_modules(scan_id,name,status,error) values (?,?,?,?)',(sid,'Fixture module','Partial','Fixture coverage incomplete'))
   page=check('/scans/'+str(sid));soup=BeautifulSoup(page.data,'html.parser');api=check('/scans/'+str(sid)+'/status').get_json()
   states.append(dict(status=status,api=api,polling_markup=bool(soup.select('[data-scan-status-url]')),progress_element=bool(soup.select('#scan-progress')),coverage_warning='module(s) failed' in soup.get_text(),failed_warning='Zero findings do not indicate a clean assessment' in soup.get_text()))
  # Dashboard must reflect actual persisted rows, including the state fixtures.
  soup=BeautifulSoup(c.get('/').data,'html.parser')
  metrics=[x.get_text(' ',strip=True) for x in soup.select('.metric')]
  dashboard_count=db.execute('select count(*) from scans').fetchone()[0]
 with patch('app.risk_trend',side_effect=RuntimeError('PRIVATE_AUDIT_ERROR')):
  r=check('/',500);assert b'PRIVATE_AUDIT_ERROR' not in r.data
 app.extensions['scan_manager'].shutdown()
Path('docs/audit/PHASE_22_UI.json').write_text(json.dumps(dict(routes=rows,states=states,navigation=nav,empty_state=True,dashboard_rows=dashboard_count,dashboard_metrics=metrics),indent=2))
print(json.dumps(dict(route_checks=len(rows),failed=[x for x in rows if not x['passed']],states=states,navigation=nav,dashboard_metrics=metrics),indent=2))
