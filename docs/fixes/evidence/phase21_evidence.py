"""Offline persisted benchmark evidence; original source restored in subprocess memory only."""
import os,sys,tempfile,json,subprocess
from pathlib import Path
sys.path.insert(0,str(Path.cwd()))
with tempfile.TemporaryDirectory(prefix='phase21-evidence-') as td:
 os.environ['SENTINELSCAN_DATA_DIR']=td;os.environ['SENTINELSCAN_LLM_ENABLED']='false'
 from evaluation.run import load_dataset,run_stage
 from scanner import source_scanner
 from scanner.sast import python_scanner,secret_scanner
 from scanner.engines import external
 before='--before' in sys.argv
 if before:
  # These three files were unchanged relative to HEAD at Phase 21 start.
  for module in (python_scanner,secret_scanner):
   path=str(Path(module.__file__).relative_to(Path.cwd()))
   source=subprocess.check_output(['git','show','HEAD:'+path],text=True)
   exec(compile(source,path,'exec'),module.__dict__)
  source_scanner.MODULES=[(n,python_scanner.run if n=='Python' else secret_scanner.run if n=='Secrets' else f) for n,f in source_scanner.MODULES]
  rules=subprocess.check_output(['git','show','HEAD:scanner/engines/semgrep_rules.yml'],text=True)
  Path(td,'semgrep_rules.yml').write_text(rules);external.__file__=str(Path(td,'external.py'))
 from analysis import correlation
 fixtures,digest=load_dataset();saved=[];original=correlation.save_finding
 def capture(db,sid,finding,*a,**kw):
  result=original(db,sid,finding,*a,**kw)
  analysis=json.loads(finding.context_json).get('analysis',{})
  saved.append(dict(title=finding.title,location=finding.location,severity=finding.severity,confidence=finding.confidence,
    evidence=finding.evidence,fingerprint=finding.fingerprint,engine=analysis.get('engine'),detected_by=analysis.get('detected_by'),rule_id=analysis.get('rule_id')))
  return result
 correlation.save_finding=capture
 stages=[]
 for tool in (None,'/opt/homebrew/bin/semgrep'):
  saved.clear();result=run_stage(fixtures,tool);result['persisted_evidence']=saved.copy();stages.append(result)
 name='BEFORE' if before else 'AFTER'
 Path('docs/fixes/PHASE_21_'+name+'_EVIDENCE.json').write_text(json.dumps(dict(dataset_sha256=digest,stages=stages),indent=2))
 print(name,[(s['overall'],s['valid_run'],len(s['persisted_evidence'])) for s in stages])
