import os,sys,tempfile,json,time,subprocess
from pathlib import Path
sys.path.insert(0,str(Path.cwd()))
from scanner.source_scanner import analyze_directory
from scanner.engines import external
from scanner.engines.process import run_tool
from unittest.mock import patch
fixtures=json.loads(Path('docs/fixes/PHASE_14_BEFORE.json').read_text())['fixtures']
rows=[]
for language in ('python','javascript'):
 with tempfile.TemporaryDirectory(prefix='phase22-semgrep-') as td:
  root=Path(td);files=fixtures[language]
  for p,source in files.items():(root/p).write_text(source)
  ctx=analyze_directory(root,list(files),'audit/'+language);ctx['engine_config']={'SEMGREP_ENABLED':True,'SEMGREP_BINARY':'/opt/homebrew/bin/semgrep'}
  calls=[]
  def trace(args,work,seconds,output=None):
   calls.append({'args':args,'work':str(work),'seconds_limit':seconds});return run_tool(args,work,seconds,output)
  start=time.monotonic()
  with patch.object(external,'run_tool',side_effect=trace):out=external.semgrep(ctx)
  rows.append({'language':language,'seconds':round(time.monotonic()-start,3),'result':out,'findings':[{'title':f.title,'location':f.location,'severity':f.severity,'confidence':f.confidence,'evidence':f.evidence} for f in ctx['findings']],'commands':calls,'cleaned':all(not Path(c['work']).exists() for c in calls)})
  assert out['status']=='Completed' and len(ctx['findings'])==1
  assert ctx['findings'][0].location.endswith('positive.py:7' if language=='python' else 'positive.js:2')
result={'version':subprocess.check_output(['/opt/homebrew/bin/semgrep','--version'],text=True).strip(),'runs':rows}
Path('docs/audit/PHASE_22_SEMGREP.json').write_text(json.dumps(result,indent=2));print([(r['language'],r['result'],r['cleaned']) for r in rows])
