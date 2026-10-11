import os,sys,json,hashlib,subprocess,tempfile,sqlite3,platform,importlib.metadata as m,importlib.util
from pathlib import Path
root=Path.cwd();docs=['CLAUDE.md',*['context/'+p+'.md' for p in ('project-overview','architecture','ui-context','code-standards','ai-workflow-rules','progress-tracker')],'AGENTS.md','docs/POST_FIX_VERIFICATION.md','docs/PHASE_18_LIVE_OLLAMA_VERIFICATION.md',*['docs/fixes/'+p for p in ('PHASE_19_OLLAMA_RELIABILITY.md','PHASE_20_WEBSITE_REPLAY_SAFETY.md','PHASE_21_REPOSITORY_ACCURACY.md')]]
files={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for d in ('scanner','analysis','integrations','templates','static','tests','evaluation') for p in Path(d).rglob('*') if p.is_file() and '__pycache__' not in p.parts}
for p in Path('.').iterdir():
 if p.is_file() and p.suffix in ('.py','.sh','.txt'):files[str(p)]=hashlib.sha256(p.read_bytes()).hexdigest()
d=dict(cwd=str(root),branch=subprocess.check_output(['git','branch','--show-current'],text=True).strip(),commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),git_status=subprocess.check_output(['git','status','--short'],text=True),python=sys.version,interpreter=sys.executable,sqlite=sqlite3.sqlite_version,dependencies={p.metadata['Name']:p.version for p in m.distributions()},documents={p:hashlib.sha256(Path(p).read_bytes()).hexdigest() if Path(p).exists() else 'MISSING' for p in docs},protected_files=files,browser_packages={p:bool(importlib.util.find_spec(p)) for p in ('playwright','selenium')})
with tempfile.TemporaryDirectory(prefix='phase22-baseline-') as td:
 os.environ['SENTINELSCAN_DATA_DIR']=td
 sys.path.insert(0,str(root));from config import settings
 c=settings();d['config']={k:c[k] for k in ('DEBUG','SEMGREP_ENABLED','SEMGREP_BINARY','CODEQL_ENABLED','CODEQL_BINARY','CODEQL_SEARCH_PATH','LLM_ENABLED','OLLAMA_BASE_URL','OLLAMA_MODEL','SESSION_COOKIE_HTTPONLY','SESSION_COOKIE_SAMESITE','SESSION_COOKIE_SECURE','MAX_CONTENT_LENGTH','TRUSTED_HOSTS')}
Path('docs/audit/PHASE_22_BASELINE.json').write_text(json.dumps(d,indent=2));print('Baseline captured; protected files',len(files))
