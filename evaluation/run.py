"""Run actual repository workers on a frozen synthetic archive; emit scored evidence."""
import argparse
import hashlib
from importlib.metadata import version
import json
from pathlib import Path, PurePosixPath
import platform
import sys
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parents[1]
DATASET=Path(__file__).with_name('fixtures.json')
REPOSITORY='evaluation/controlled-fixtures'


def metrics(labels):
    counts={key:0 for key in ('TP','FP','TN','FN')}
    for expected,detected in labels:
        counts['TP' if expected and detected else 'FN' if expected else 'FP' if detected else 'TN']+=1
    tp,fp,fn=counts['TP'],counts['FP'],counts['FN']
    # None means undefined, not a perfect result or a crash.
    precision=tp/(tp+fp) if tp+fp else None
    recall=tp/(tp+fn) if tp+fn else None
    f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None
    return dict(counts,precision=precision,recall=recall,f1=f1)


def load_dataset(path=DATASET):
    raw=Path(path).read_bytes();data=json.loads(raw);seen=set();paths=set()
    for row in data['fixtures']:
        if type(row['expected']) is not bool or row['variant'] not in ('vulnerable','safe','protected'):
            raise ValueError('Invalid fixture ground truth')
        path=PurePosixPath(row['path'])
        if path.is_absolute() or '..' in path.parts or '\\' in row['path'] or not row['ground_truth'] or not row['source']:
            raise ValueError('Invalid fixture path or rationale')
        if row['id'] in seen or row['path'] in paths:raise ValueError('Duplicate fixture identity')
        seen.add(row['id']);paths.add(row['path'])
    return data['fixtures'],hashlib.sha256(raw).hexdigest()


def classification(finding,analysis):
    title=finding['title'];cwe=analysis.get('cwe')
    if analysis.get('file','').endswith('.java') and (cwe in ('CWE-89','CWE-78','CWE-502','CWE-328') or 'Java' in title):return 'Java Security'
    if 'SQL injection' in title or cwe=='CWE-89':return 'SQL Injection'
    if 'shell command' in title or 'subprocess shell' in title or cwe=='CWE-78':return 'Command Injection'
    if 'code execution' in title or cwe=='CWE-95':return 'Dynamic Code Execution'
    if 'DOM HTML' in title or 'document.write' in title or cwe=='CWE-79':return 'DOM XSS'
    if finding['category']=='Secret Exposure':return 'Secrets'
    if finding['category']=='Deserialization' or cwe=='CWE-502':return 'Deserialization'
    if finding['category']=='Cryptography':return 'Weak Cryptography'
    if finding['category']=='Configuration':return 'Configuration'
    return None


def run_stage(fixtures,semgrep=None):
    from app import create_app
    from database import get_db
    from scanner.source_scanner import run_repository,MODULE_NAMES
    class Archive:
        destination=None
        def archive(self,repository,commit,destination):
            self.destination=destination
            with zipfile.ZipFile(destination,'w') as bundle:
                for row in fixtures:bundle.writestr('snapshot/'+row['path'],row['source'])
    archive=Archive()
    with tempfile.TemporaryDirectory(prefix='sentinelscan-evaluation-') as directory:
        app=create_app({'TESTING':True,'DATABASE':str(Path(directory)/'evaluation.sqlite3'),
            'LLM_ENABLED':False,'SEMGREP_ENABLED':bool(semgrep),'SEMGREP_BINARY':semgrep or 'semgrep',
            'CODEQL_ENABLED':False,'REPORTS_DIR':str(Path(directory)/'reports')})
        try:
            with app.app_context():
                db=get_db()
                with db:
                    sid=db.execute("INSERT INTO scans(scan_type,target,status) VALUES ('Repository',?,'Queued')",(REPOSITORY,)).lastrowid
                    db.execute('INSERT INTO repositories(name,location,scan_id) VALUES (?,?,?)',('controlled-fixtures',REPOSITORY,sid))
                    db.executemany('INSERT INTO scan_modules(scan_id,name) VALUES (?,?)',[(sid,n) for n in MODULE_NAMES])
            run_repository(app,sid,archive,{'full_name':REPOSITORY},'fixed-dataset','a'*40,False)
            with app.app_context():
                db=get_db();scan=dict(db.execute('SELECT * FROM scans WHERE id=?',(sid,)).fetchone())
                coverage=[dict(row) for row in db.execute('SELECT name,status,error,data_json FROM scan_modules WHERE scan_id=?',(sid,))]
                saved=[]
                for row in db.execute('SELECT f.*,s.data_json FROM findings f LEFT JOIN finding_solutions s ON f.id=s.finding_id WHERE f.scan_id=?',(sid,)):
                    analysis=json.loads(row['data_json'] or '{}').get('finding_context',{}).get('analysis',{})
                    saved.append({'file':analysis.get('file'),'title':row['title'],'severity':row['severity'],
                        'confidence':row['confidence'],'category':classification(row,analysis),
                        'engines':[item['engine'] for item in analysis.get('detected_by',[])],
                        'rule':analysis.get('rule_id')})
                ai_count=db.execute('SELECT count(*) FROM ai_reviews').fetchone()[0]
            cleaned=archive.destination is not None and not archive.destination.parent.exists()
        finally:app.extensions['scan_manager'].shutdown()
    cases=[]
    for row in fixtures:
        matches=[f for f in saved if f['file']==row['path'] and f['category']==row['category']]
        detected=bool(matches)
        cases.append({'id':row['id'],'path':row['path'],'category':row['category'],'expected':row['expected'],
            'detected':detected,'outcome':'TP' if row['expected'] and detected else 'FN' if row['expected'] else 'FP' if detected else 'TN',
            'findings':matches,'ground_truth':row['ground_truth'],'future_improvement':row['future_improvement']})
    unscored=[f for f in saved if not any(f['file']==row['path'] and f['category']==row['category'] for row in fixtures)]
    result={'stage':'custom-plus-semgrep' if semgrep else 'custom-with-dataflow',
        'scan_status':scan['status'],'coverage':[{k:v for k,v in row.items() if k!='data_json'} for row in coverage],
        'coverage_details':{row['name']:json.loads(row['data_json']) for row in coverage},
        'archive_cleaned':cleaned,'ai_reviews':ai_count,'final_finding_count':len(saved),'unscored_findings':unscored,
        'overall':metrics([(c['expected'],c['detected']) for c in cases]),
        'categories':{category:metrics([(c['expected'],c['detected']) for c in cases if c['category']==category]) for category in sorted({c['category'] for c in cases})},
        'cases':cases}
    required=[row for row in coverage if row['name'] not in ('Semgrep','CodeQL') or row['name']=='Semgrep' and semgrep]
    result['valid_run']=scan['status']=='Completed' and cleaned and all(row['status']=='Completed' for row in required)
    return result


def code_digest():
    paths=sorted(set(list((ROOT/'scanner').rglob('*.py'))+list((ROOT/'analysis').glob('*.py'))+[ROOT/'scanner/engines/semgrep_rules.yml']))
    h=hashlib.sha256()
    for path in paths:h.update(path.relative_to(ROOT).as_posix().encode()+b'\0'+path.read_bytes()+b'\0')
    return h.hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'evaluation/results.json')
    parser.add_argument('--dataset',type=Path,default=DATASET)
    parser.add_argument('--semgrep',help='Trusted installed Semgrep binary; adds a real second stage')
    args=parser.parse_args();fixtures,digest=load_dataset(args.dataset)
    stages=[run_stage(fixtures)]
    tool_version=None
    if args.semgrep:
        from scanner.engines.process import run_tool
        with tempfile.TemporaryDirectory() as directory:
            # Trusted helper captures version only under the same process/output
            # limits; scanner diagnostics themselves remain discarded.
            helper='import subprocess,sys; f=open("version.txt","wb"); subprocess.run(sys.argv[1:],stdout=f,check=True)'
            tool_version=run_tool([sys.executable,'-I','-c',helper,str(Path(args.semgrep).resolve()),'--version'],
                                  Path(directory),15,Path(directory)/'version.txt').decode().strip()[:100]
        stages.append(run_stage(fixtures,str(Path(args.semgrep).resolve())))
    result={'dataset_sha256':digest,'scanner_sha256':code_digest(),'fixture_count':len(fixtures),
        'python':platform.python_version(),'packages':{name:version(name) for name in ('Flask','tree-sitter','tree-sitter-javascript','tree-sitter-java')},
        'semgrep_version':tool_version,'codeql':'Not evaluated: unavailable; no accuracy claim.',
        'llm':'Not evaluated: no live provider. Mocked behavior tests are not accuracy metrics.',
        'unit':'One category-presence decision per fixture. All confidences count; duplicates count once.',
        'stages':stages}
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(result,indent=2)+'\n')
    for stage in stages:print(stage['stage'],json.dumps(stage['overall']),'valid_run='+str(stage['valid_run']))
    if not all(stage['valid_run'] for stage in stages):raise SystemExit(2)


if __name__=='__main__':main()
