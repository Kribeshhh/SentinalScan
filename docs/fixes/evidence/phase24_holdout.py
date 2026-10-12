import os,sys,tempfile,json,hashlib,time
from pathlib import Path
sys.path.insert(0,str(Path.cwd()))
p=Path('docs/audit/PHASE_22_HOLDOUT.json');raw=p.read_bytes();digest=hashlib.sha256(raw).hexdigest();assert digest==json.load(open('docs/audit/PHASE_22_HOLDOUT_FREEZE.json'))['sha256']
cases=json.loads(raw)['cases'];fixtures=[]
for c in cases:
 for name,source in c['files'].items():
  fixtures.append(dict(id=c['id']+'/'+name,path=c['id']+'/'+name,source=source.replace('P22_SYNTHETIC_MATERIAL','AuditOnly-'+hashlib.sha256(c['id'].encode()).hexdigest()[:24]),category=c['category'],expected=c['expected'] is True,variant='vulnerable' if c['expected'] else 'safe',ground_truth=c['rationale'],future_improvement='Not tuned during audit'))
with tempfile.TemporaryDirectory(prefix='phase22-holdout-') as td:
 os.environ.update(SENTINELSCAN_DATA_DIR=td,SENTINELSCAN_LLM_ENABLED='false');os.environ.pop('SENTINELSCAN_GITHUB_TOKEN',None)
 from evaluation.run import run_stage,metrics
 stages=[]
 for tool in (None,'/opt/homebrew/bin/semgrep'):
  start=time.monotonic();r=run_stage(fixtures,tool);scored=[];ambiguous=[]
  for c in cases:
   matches=[f for row in r['cases'] if row['id'].startswith(c['id']+'/') for f in row['findings']]
   found=bool(matches);expected=c['expected']
   row=dict(id=c['id'],category=c['category'],expected=expected,detected=found,findings=matches,rationale=c['rationale'])
   if expected is None:ambiguous.append(row)
   else:
    row['outcome']='TP' if expected and found else 'FN' if expected else 'FP' if found else 'TN';scored.append(row)
  stages.append(dict(stage=r['stage'],seconds=time.monotonic()-start,valid_run=r['valid_run'],coverage=r['coverage'],coverage_details=r['coverage_details'],archive_cleaned=r['archive_cleaned'],metrics=metrics([(c['expected'],c['detected']) for c in scored]),categories={cat:metrics([(c['expected'],c['detected']) for c in scored if c['category']==cat]) for cat in sorted({c['category'] for c in scored})},cases=scored,ambiguous=ambiguous,unscored=r['unscored_findings']))
 Path('docs/fixes/PHASE_24_HOLDOUT_RESULTS.json').write_text(json.dumps(dict(dataset_sha256=digest,stages=stages),indent=2))
 print([(s['stage'],s['metrics'],s['valid_run']) for s in stages])
