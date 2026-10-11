import os,sys,tempfile,json,sqlite3,threading,time,csv,io
from pathlib import Path
from unittest.mock import patch
sys.path[:0]=[str(Path.cwd()),str(Path.cwd()/'tests')]
results=[]
def record(name,expected,actual,passed):results.append(dict(case=name,expected=expected,actual=actual,status='PASS' if passed else 'FAIL'))
with tempfile.TemporaryDirectory(prefix='phase07-matrix-') as td:
 os.environ.update(SENTINELSCAN_DATA_DIR=td,SENTINELSCAN_LLM_ENABLED='false')
 from app import create_app
 from database import get_db
 from analysis.finding_engine import Finding,save_finding
 from analysis.risk_engine import calculate_risk
 from analysis.management import compare_scans,scan_metrics
 from reports.report_generator import generate_report,report_data
 app=create_app(dict(TESTING=True,REPORTS_DIR=str(Path(td)/'reports')));client=app.test_client();client.get('/')
 with client.session_transaction() as session:csrf=session['csrf_token']
 with app.app_context():
  db=get_db();tables=[r[0] for r in db.execute("select name from sqlite_master where type='table'")]
  record('schema','14 tables, version4, foreign keys ON, WAL',[len(tables),db.execute('pragma user_version').fetchone()[0],db.execute('pragma foreign_keys').fetchone()[0],db.execute('pragma journal_mode').fetchone()[0]],len(tables)==14)
  record('connection reuse','same object in app context',get_db() is db,get_db() is db)
  try:
   with db:
    db.execute("insert into scans(scan_type,target) values ('Website','rollback-fixture')")
    raise RuntimeError()
  except RuntimeError:pass
  count=db.execute("select count(*) from scans where target='rollback-fixture'").fetchone()[0];record('rollback','zero uncommitted rows',count,count==0)
  with db:
   sid=db.execute("insert into scans(scan_type,target,status,assessment_risk) values ('Website','https://audit.invalid/','Completed',31)").lastrowid
  for i,severity in enumerate(('Critical','High','Medium','Low','Informational')):
   save_finding(db,sid,Finding(title=f'Fixture {severity} <script>x</script>',severity=severity,confidence='High',category='Audit',source='Website',location=f'https://audit.invalid/{i}',description='Unicode café नमस्ते',evidence='password="SyntheticCredential-93283"',impact='Review',recommendation='Use reviewed guidance'))
  metrics=scan_metrics(db,db.execute('select * from scans where id=?',(sid,)).fetchone());record('severity distribution','one each, count5, risk31',dict(counts=metrics['counts'],count=metrics['finding_count'],risk=metrics['risk_score']),metrics['finding_count']==5 and metrics['risk_score']==31 and all(x==1 for x in metrics['counts'].values()))
  for status in ('Completed','Failed'):
   with db:empty=db.execute('insert into scans(scan_type,target,status) values (?,?,?)',('Website','https://empty.invalid/'+status,status)).lastrowid
   for fmt in ('HTML','JSON','CSV'):
    rid=generate_report(empty,fmt);r=client.get(f'/reports/{rid}/download');record('empty '+status+' '+fmt,'200 nonempty report',r.status_code,r.status_code==200 and bool(r.data));r.close()
  for fmt in ('HTML','JSON','CSV'):
   rid=generate_report(sid,fmt);r=client.get(f'/reports/{rid}/download');content=r.get_data(as_text=True);ok='SyntheticCredential-93283' not in content
   if fmt=='JSON':ok=ok and len(json.loads(content)['findings'])==5 and json.loads(content)['scan']['risk_score']==31
   if fmt=='HTML':ok=ok and '<script>x</script>' not in content and '&lt;script&gt;' in content
   if fmt=='CSV':ok=ok and len([x for x in csv.DictReader(io.StringIO(content)) if x['record_type']=='finding'])==5
   record('populated '+fmt,'5 saved findings, masked secret, format-safe output',dict(status=r.status_code,redacted='SyntheticCredential-93283' not in content),ok);r.close()
  # Two connections: stable WAL read snapshot while another writer commits.
  other=sqlite3.connect(app.config['DATABASE'],timeout=1);other.execute('pragma foreign_keys=ON')
  db.execute('BEGIN');before=db.execute('select count(*) from scans').fetchone()[0]
  with other:other.execute("insert into scans(scan_type,target,status) values ('Repository','audit/concurrent','Completed')")
  during=db.execute('select count(*) from scans').fetchone()[0];db.commit();after=db.execute('select count(*) from scans').fetchone()[0]
  record('WAL snapshot','reader stable until commit then sees writer',[before,during,after],before==during and after==before+1)
  db.execute('BEGIN IMMEDIATE');other.execute('pragma busy_timeout=50');start=time.monotonic()
  try:
   other.execute("insert into scans(scan_type,target) values ('Website','locked')");locked=False
  except sqlite3.OperationalError:locked=True
  elapsed=time.monotonic()-start;db.rollback();other.rollback();other.close();record('writer contention','second writer bounded lock failure',dict(locked=locked,seconds=round(elapsed,3)),locked)
  # Report file cleanup when metadata registration fails (temporary trigger only).
  directory=Path(td)/'reports';before=set(directory.iterdir())
  db.execute("CREATE TEMP TRIGGER reject_report BEFORE INSERT ON reports BEGIN SELECT RAISE(ABORT,'audit failure'); END;")
  try:generate_report(sid,'JSON');failed=False
  except sqlite3.IntegrityError:failed=True
  db.execute('DROP TRIGGER reject_report');db.commit()
  record('report metadata failure cleanup','exception and no orphan new file',dict(failed=failed,no_new_file=set(directory.iterdir())==before),failed and set(directory.iterdir())==before)
  # Invalid persisted JSON does not come from a normal successful serializer.
  with db:mid=db.execute("insert into scan_modules(scan_id,name,status,data_json) values (?,'Malformed','Completed','{bad')",(sid,)).lastrowid
  before=set(directory.iterdir());r=client.post('/reports/generate',data=dict(csrf_token=csrf,scan_id=sid,format='JSON'))
  record('malformed module report','controlled rejection, no output file',dict(http=r.status_code,no_new_file=set(directory.iterdir())==before),r.status_code==400 and set(directory.iterdir())==before)
  record('malformed module scan display','graceful record-level display',client.get(f'/scans/{sid}').status_code,client.get(f'/scans/{sid}').status_code==200)
  with db:db.execute('delete from scan_modules where id=?',(mid,));later=db.execute("insert into scans(scan_type,target,status) values ('Website','https://audit.invalid/','Completed')").lastrowid
  comparison=compare_scans(db,sid,later);record('absent findings comparison','5 resolved groups with no-proof warning',dict(resolved=len(comparison['resolved']),warning=comparison['limitations'][0]),len(comparison['resolved'])==5 and 'not proof' in comparison['limitations'][0])
  fid=db.execute('select id from findings where scan_id=? limit 1',(sid,)).fetchone()[0]
  with db:db.execute('insert or replace into finding_solutions values (?,?)',(fid,'[]'))
  r=client.post('/comparisons',data=dict(csrf_token=csrf,baseline=sid,current=later));record('malformed solution comparison','controlled validation response (400)',r.status_code,r.status_code==400)
  with db:db.execute('delete from finding_solutions where finding_id=?',(fid,))
  record('integrity','ok, no foreign key violations',[db.execute('pragma integrity_check').fetchone()[0],len(db.execute('pragma foreign_key_check').fetchall())],db.execute('pragma integrity_check').fetchone()[0]=='ok' and not db.execute('pragma foreign_key_check').fetchall())
 # Closed request connection is not reusable.
 try:db.execute('select 1');closed=False
 except sqlite3.ProgrammingError:closed=True
 record('connection teardown','connection closed',closed,closed)
 for name,rows,expected in [('empty',[],0),('all severities',[dict(severity=x,status='Open') for x in ('Critical','High','Medium','Low','Informational')],31),('ignored',[dict(severity='Critical',status=x) for x in ('Resolved','Ignored','False Positive')],0),('rounding tie',[dict(severity='Low',status='Open')]*30,38),('large',[dict(severity='Critical',status='Open')]*10000,100)]:
  actual=calculate_risk(rows);record('risk '+name,expected,actual,actual==expected)
 app.extensions['scan_manager'].shutdown()
Path('docs/audit/PHASE_22_DATABASE.json').write_text(json.dumps(results,indent=2));print(json.dumps(results,indent=2))
