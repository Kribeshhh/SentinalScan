"""Immutable, redacted report snapshots generated only from persisted scan records."""
import csv
from datetime import datetime,timezone
import io
import json
import os
from pathlib import Path
import re
import stat
import uuid
from flask import current_app,render_template
from analysis.management import scan_metrics
from analysis.redaction import scrub
from analysis.solution_engine import solution_for
from database import get_db

FORMATS=('HTML','JSON','CSV')
LIMITATIONS=[
 'This report is a snapshot at generation time. Later triage changes require a new report.',
 'Security checks are bounded and heuristic. Findings require review; absence does not establish security.',
 'Open-finding risk reflects triage at report generation. Assessment risk represents all detections at scan completion.',
 'Failed, skipped or partial modules reduce coverage. Review module status and observations.',
 'Detected secrets are redacted. No original source files or raw response bodies are included.',
]


def report_data(db,scan_id):
    scan=db.execute('SELECT * FROM scans WHERE id=?',(scan_id,)).fetchone()
    if not scan:
        raise ValueError('Select an existing scan.')
    if scan['status'] not in ('Completed','Failed'):
        raise ValueError('Wait for the scan to finish before generating a report.')
    findings=[dict(row) for row in db.execute('SELECT * FROM findings WHERE scan_id=? ORDER BY id',(scan_id,))]
    for finding in findings:
        from analysis.recommendation_composer import final_solution
        finding['solution']=final_solution(db,finding)
        finding['recommendation']=finding['solution']['what_to_change']
    modules=[]
    for row in db.execute('SELECT * FROM scan_modules WHERE scan_id=? ORDER BY id',(scan_id,)):
        module=dict(row);module['observations']=json.loads(module.pop('data_json'));modules.append(module)
    repository=None
    if scan['repository_id']:
        row=db.execute('SELECT * FROM repositories WHERE id=?',(scan['repository_id'],)).fetchone()
        if row:
            repository=dict(row)
            repository['languages']=json.loads(repository.pop('languages_json'))
            repository['dependencies']=json.loads(repository.pop('dependencies_json'))
    scan_data=scan_metrics(db,scan)
    scan_data['options']=json.loads(scan_data.pop('options_json'))
    return scrub({'schema_version':1,'platform':'SentinelScan','generated_at':datetime.now(timezone.utc).isoformat(),
        'scan':scan_data,'statistics':scan_data['counts'],'findings':findings,'modules':modules,'repository':repository,
        'limitations':LIMITATIONS+(['DAST: no authenticated crawling, JavaScript execution or exhaustive TLS enumeration. Open ports and technologies are observations, not automatic vulnerabilities.'] if scan['scan_type']=='Website' else ['SAST: static syntax/context heuristics; no code execution, complete taint analysis or transitive dependency resolution. Secret detection can miss unknown formats.'])})


def csv_safe(value):
    text='' if value is None else str(value)
    stripped=text.lstrip(' \t\r\n\ufeff')
    return "'"+text if stripped.startswith(('=','+','-','@')) or text.startswith(('\t','\r','\n')) else text


def csv_document(data):
    output=io.StringIO(newline='')
    fields=['record_type','scan_id','target','scan_type','scan_date','duration_seconds','risk_score','assessment_risk','id','title','severity','confidence','category','source','location','description','evidence','impact','recommendation','status','created_at','fingerprint','details_json']
    writer=csv.DictWriter(output,fieldnames=fields);writer.writeheader()
    scan=data['scan']
    common={key:scan.get(key) for key in ('target','scan_type','duration_seconds','risk_score','assessment_risk')}
    common.update(scan_id=scan['id'],scan_date=scan['created_at'])
    def emit(kind,values):
        row=dict(common,record_type=kind);row.update(values)
        writer.writerow({key:csv_safe(row.get(key)) for key in fields})
    emit('scan',{'status':scan['status'],'details_json':json.dumps({'scan':scan,'statistics':data['statistics'],'generated_at':data['generated_at'],'limitations':data['limitations']},ensure_ascii=False)})
    if data['repository']:
        emit('repository',{'details_json':json.dumps(data['repository'],ensure_ascii=False)})
    for module in data['modules']:
        emit('module',{'title':module['name'],'status':module['status'],'details_json':json.dumps(module,ensure_ascii=False)})
    for finding in data['findings']:
        emit('finding',dict(finding,details_json=json.dumps({'solution':finding.get('solution')},ensure_ascii=False)))
    return output.getvalue()


def generate_report(scan_id,output_format):
    if output_format not in FORMATS:
        raise ValueError('Choose HTML, JSON or CSV.')
    db=get_db()
    # One read transaction provides a consistent snapshot during concurrent triage.
    with db:
        db.execute('BEGIN')
        data=report_data(db,scan_id)
    if output_format=='JSON':
        content=json.dumps(data,ensure_ascii=False,indent=2)
    elif output_format=='CSV':
        content=csv_document(data)
    else:
        content=render_template('report_document.html',report=data)
    root=Path(current_app.config['REPORTS_DIR']).resolve();root.mkdir(mode=0o700,parents=True,exist_ok=True)
    filename='report-'+uuid.uuid4().hex+'.'+output_format.lower()
    path=root/filename
    created=False
    try:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        created=True
        with os.fdopen(fd,'w',encoding='utf-8',newline='') as handle:
            handle.write(content)
        with db:
            report_id=db.execute('INSERT INTO reports(scan_id,format,file_path) VALUES (?,?,?)',(scan_id,output_format,filename)).lastrowid
    except Exception:
        if created:
            path.unlink(missing_ok=True)
        raise
    return report_id


def open_report(row):
    filename=row['file_path']
    if not re.fullmatch(r'report-[a-f0-9]{32}\.(html|json|csv)',filename) or filename.rsplit('.',1)[1]!=row['format'].lower():
        raise FileNotFoundError('Report file unavailable')
    root=Path(current_app.config['REPORTS_DIR']).resolve()
    # Resolve by server-generated basename, refuse symlinks and non-regular files.
    directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
    try:
        fd=os.open(filename,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd);raise FileNotFoundError('Report file unavailable')
        return os.fdopen(fd,'rb')
    finally:
        os.close(directory)
