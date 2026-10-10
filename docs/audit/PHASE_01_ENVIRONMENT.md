# Phase 01 — Project structure, environment and startup audit

Date: 2026-10-08. Scope: environment/startup only; no application changes, dependency installs, scanner execution or paid services.

## Location and command convention

All commands below ran from `/Users/kribeshthapa/Developer/Vibe code/SentinalScan` unless specified. The supplied Desktop location no longer exists. Commands used the existing `.venv/bin/python` directly; the existing launcher activates that same environment internally. Temporary databases were used for application startup. The user database was opened read-only, never passed to the app factory (startup can mark interrupted scans Failed).

## Check results

| Check | Status | Exact command / evidence |
|---|---|---|
| Supplied working directory | FAIL | `ls -ld '/Users/kribeshthapa/Desktop/Vibe code/SentinalScan'` — No such file or directory. |
| Actual project directory | PASS | `mdfind 'kMDItemFSName == "SentinalScan" || kMDItemFSName == "SentinelScan"'` — found the Developer path above. |
| Required documentation | PASS | `cat CLAUDE.md context/project-overview.md context/architecture.md context/ui-context.md context/code-standards.md context/ai-workflow-rules.md context/progress-tracker.md AGENTS.md` — all eight exist and were read, in requested order. No missing documents. |
| Modular architecture | PASS | `ls -d */`; `rg --files scanner tests`; `cat requirements.txt config.py run-local.sh`; `sed -n '1,240p' database.py`; `tail -20 app.py` — Flask factory/routes; scanner/SAST/engines; analysis; integrations; reports; Jinja/static; tests/evaluation; SQLite. No frontend build required. |
| Python interpreter | PASS | `.venv/bin/python -B -c 'import sys,platform; print(sys.executable); print(sys.version); print("prefix:",sys.prefix); print("base:",sys.base_prefix); print(platform.platform())'` — Python 3.13.5, macOS arm64, environment prefix at actual root, Homebrew Python 3.13 base. |
| Virtual environment | PASS | `cat .venv/pyvenv.cfg`; `ls -l .venv/bin/python*`; interpreter command above — valid symlinks, isolated site packages, current Developer path. |
| Installed dependencies | PASS | `.venv/bin/python -B -m pip check` — No broken requirements found. Driver A checks every requirements constraint against installed metadata; all 11 satisfy. |
| Application imports | PASS | Driver A — 73 application modules imported successfully; no missing dependency or broken import encountered. External process wrapper excluded from bulk import, inspected separately. |
| Tests present / syntax | PASS | Driver A — all 33 top-level `tests/test*.py` modules compile successfully without execution. This is not a test-suite pass. |
| Launcher syntax | PASS | `/bin/zsh -n run-local.sh` — exit 0. Executable launcher activates `.venv` then invokes `python3 -u app.py`. |
| Existing launcher startup | PASS | Driver B invokes `/bin/zsh ./run-local.sh` with isolated data and AI disabled. HTTP 200 at `http://127.0.0.1:5000/`, body contains SentinelScan, process alive, debug off. Audit-owned process group terminated afterward. |
| Port availability observation | PARTIAL | `lsof -nP -iTCP:5000 -sTCP:LISTEN` also shows ControlCe PID 1065 on wildcard IPv4/IPv6. This did **not** prevent the verified loopback launcher startup; no port-conflict failure was reproduced. No user process was stopped. |
| Semgrep / CodeQL flags | PASS | `rg -n 'SEMGREP|CODEQL' config.py`; `cat run-local.sh`; `cat scanner/engines/external.py`; Driver A executable checks — defaults disabled; launcher explicitly enables both and sets `/opt/homebrew/bin/semgrep` and `/opt/homebrew/bin/codeql`; both executable paths exist. Missing/disabled tools have explicit skipped states. |
| External engine operation / packs | NOT TESTED | No Semgrep or CodeQL scan/version/database/query-pack command executed. Executable availability alone does not establish working engine coverage. |
| Fresh SQLite initialization | PASS | Driver A — 14 tables, schema version 4, WAL, foreign keys enabled. Required scans/findings/repositories/reports/scan_comparisons present. |
| Existing SQLite health | PASS | Driver A read-only URI — quick_check `ok`, schema 4, 33 scans, 1,336 findings, zero foreign-key violations. |
| Restart persistence | PASS | Driver A recreates Flask factory against temporary SQLite; completed fixture record remains. Existing historical-database migrations were not replayed. |
| Page and actual HTTP startup | PASS | Driver A — six primary GET pages return 200; separate ephemeral loopback HTTP server serves SentinelScan with 200. No remote lookup requested. |
| Environment/config defaults | PASS | Driver A presence-only check found no inherited SENTINELSCAN_/LLM_ variables; no credential values printed. AI explicitly disabled for startup. Config debug false, trusted hosts loopback, HttpOnly/Lax cookies, 1 MiB request cap. Secret generated server-side or supplied via environment; existing key mode 0600. |
| Local HTTP security posture | PARTIAL | Driver A — CSP, nosniff, DENY, no-store present; untrusted Host returns 400. Secure cookie false for local HTTP by design (`SENTINELSCAN_HTTPS=1` enables it). This local workspace is not authenticated multi-user hosting. No full security/CSRF test in this phase. |
| Local data permissions | PARTIAL | Driver A stat — data directory 0755, SQLite 0644, secret file 0600. Database mode permits other local accounts to read it if parent-directory traversal allows; effective ACL/access not tested. No permissions changed. |
| Source and user DB preservation | PASS | Driver A SHA-256 comparison — protected application Python/HTML/CSS/JS, requirements, launcher and user SQLite unchanged. `git status --short` baseline had only untracked run-local.sh; audit adds documentation only. |
| Full test suite / scanner accuracy | SKIPPED | No `unittest discover` execution in this environment-only phase. No website, repository, engine, LLM, GitHub, report generation or accuracy tests run. Historical 243-test result in tracker is not a result of this audit. |
| Architecture/documentation consistency | PARTIAL | `rg -n 'editor/PR|Current|Phase 7 in progress' context/*.md AGENTS.md`; `head -2 static/css/style.css`; static inspection described below. |

## Actual architecture and remaining inconsistencies

- `app.py` owns the Flask factory and local entry point; `repository_routes.py` and `management_routes.py` register supporting routes. `database.py` initializes compatible SQLite schema. Website/repository scan orchestration is separate from SAST rules and optional external engines. Automatic optional AI is a completion callback, not required for startup. Reports and recommendation presentation remain separate modules.
- `AGENTS.md:308` still asks to preserve reviewed editor/PR controls, conflicting with its current recommendation-only scope at the top. The progress tracker retains “Phase 7 in progress” before its later completion statement. `context/ui-context.md` lists old CSS token values (e.g. background #0b1017 versus actual #101214), repeats “fix confidence,” and retains workflow language. These are documentation ambiguities; no UI/code edits made.
- Launcher is untracked and machine-specific: zsh plus absolute Homebrew tool paths. It forces both optional engines on, whereas normal configuration defaults them off. Activation failure is not explicitly checked before `python3`; current environment activation succeeded. README documents direct `python3 app.py` startup and opt-in engines. These invocation differences should not be mistaken for identical configurations.
- `database.py` retains an interrupted-publication comment although the current product is recommendation-only. Historical workflow tables are explicitly retained for compatibility and are not themselves an architectural defect.
- `settings()` creates the data directory/secret before `create_app(test_config)` overrides apply. For safe tests, the environment data-directory override is necessary as well as any test configuration. ScanManager initialization can update interrupted scans; this audit deliberately avoided normal-user-DB startup.
- No reproduced broken import, missing required package, or Flask startup error. Runtime scanner quality, external service availability and external query packs remain unverified.

## Reproducible audit commands and raw evidence

Driver A was saved as `/tmp/sentinel_phase01.py` and executed with:

```sh
.venv/bin/python -B /tmp/sentinel_phase01.py > /tmp/sentinel_phase01.log 2>&1
cat /tmp/sentinel_phase01.log
```

Exact driver body (no credentials):

```python
import os,sys,tempfile,pathlib,importlib,importlib.metadata,sqlite3,subprocess,json,hashlib,threading,urllib.request
root=pathlib.Path.cwd();sys.path.insert(0,str(root))
def emit(k,v): print(k+': '+json.dumps(v,default=str),flush=True)
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
protected={str(p):digest(p) for p in root.rglob('*') if p.is_file() and '.venv' not in p.parts and '.git' not in p.parts and (p.suffix in ('.py','.html','.css','.js') or p.name in ('requirements.txt','run-local.sh','sentinelscan.sqlite3'))}
emit('environment presence only',{k:bool(os.environ.get(k)) for k in sorted(set(k for k in os.environ if k.startswith(('SENTINELSCAN_','LLM_'))) )})
from packaging.requirements import Requirement
for line in (root/'requirements.txt').read_text().splitlines():
 if line.strip() and not line.startswith('#'):
  r=Requirement(line);v=importlib.metadata.version(r.name);emit('dependency',{'name':r.name,'version':v,'satisfies':v in r.specifier})
modules=['app','config','database','management_routes','repository_routes']
for folder in ('scanner','analysis','integrations','reports'):
 for p in (root/folder).rglob('*.py'):
  if p.name=='limit_exec.py':continue
  modules.append('.'.join(p.relative_to(root).with_suffix('').parts).removesuffix('.__init__'))
for m in sorted(set(modules)):importlib.import_module(m)
emit('imports passed',len(set(modules)))
tests=list((root/'tests').glob('test*.py'))
for p in tests:compile(p.read_text(),str(p),'exec')
emit('test modules syntax checked, not executed',len(tests))
dbpath=root/'data/sentinelscan.sqlite3'
with sqlite3.connect(dbpath.as_uri()+'?mode=ro',uri=True) as db:
 emit('existing DB',{'quick_check':db.execute('pragma quick_check').fetchone()[0],'version':db.execute('pragma user_version').fetchone()[0],'scans':db.execute('select count(*) from scans').fetchone()[0],'findings':db.execute('select count(*) from findings').fetchone()[0],'foreign_key_violations':len(db.execute('pragma foreign_key_check').fetchall())})
emit('permissions',{str(p.relative_to(root)):oct(p.stat().st_mode&0o777) for p in (root/'data',dbpath,root/'data/.secret_key')})
with tempfile.TemporaryDirectory(prefix='sentinel-phase01-') as td:
 os.environ['SENTINELSCAN_DATA_DIR']=td;os.environ['SENTINELSCAN_LLM_ENABLED']='false';os.environ['PYTHONDONTWRITEBYTECODE']='1'
 # Both names disabled defensively; config.py actually uses SENTINELSCAN_LLM_ENABLED.
 os.environ['LLM_ENABLED']='false'
 from config import settings
 c=settings();emit('safe config',{k:c.get(k) for k in ('DEBUG','LLM_ENABLED','SEMGREP_ENABLED','CODEQL_ENABLED','SESSION_COOKIE_HTTPONLY','SESSION_COOKIE_SAMESITE','SESSION_COOKIE_SECURE','TRUSTED_HOSTS','MAX_CONTENT_LENGTH')})
 for name in ('semgrep','codeql'):emit('external executable',{'name':name,'exists_and_executable':os.access('/opt/homebrew/bin/'+name,os.X_OK)})
 try:
  p=subprocess.run(['/bin/zsh','./run-local.sh'],env=os.environ.copy(),text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=12)
  emit('launcher',{'returncode':p.returncode,'output':p.stdout})
 except subprocess.TimeoutExpired:emit('launcher','still running after 12 seconds; subprocess terminated by timeout')
 from app import create_app
 from database import get_db
 app=create_app({'TESTING':True,'REPORTS_DIR':pathlib.Path(td)/'reports'})
 with app.app_context():
  db=get_db();emit('initialized tables',[r[0] for r in db.execute("select name from sqlite_master where type='table' order by name")]);emit('sqlite pragmas',{'foreign_keys':db.execute('pragma foreign_keys').fetchone()[0],'journal_mode':db.execute('pragma journal_mode').fetchone()[0],'user_version':db.execute('pragma user_version').fetchone()[0]})
  db.execute("insert into scans(scan_type,target,status) values(?,?,?)",('Repository','audit/local-fixture','Completed'));db.commit()
 client=app.test_client()
 for url in ('/','/website-scan','/repository-scan','/scans','/findings','/reports'):
  response=client.get(url);emit('local route',{'path':url,'status':response.status_code})
 emit('security headers',{k:response.headers.get(k) for k in ('Content-Security-Policy','X-Content-Type-Options','X-Frame-Options','Cache-Control')})
 emit('untrusted host status',client.get('/',headers={'Host':'untrusted.invalid'}).status_code)
 app2=create_app({'TESTING':True,'REPORTS_DIR':pathlib.Path(td)/'reports'})
 with app2.app_context():emit('restart persisted completed fixture',get_db().execute("select count(*) from scans where target=? and status='Completed'",('audit/local-fixture',)).fetchone()[0])
 from werkzeug.serving import make_server
 server=make_server('127.0.0.1',0,app2);t=threading.Thread(target=server.serve_forever);t.start()
 try:
  with urllib.request.urlopen('http://127.0.0.1:'+str(server.server_port)+'/',timeout=5) as response:emit('actual loopback HTTP',{'status':response.status,'body_contains_SentinelScan':b'SentinelScan' in response.read()})
 finally:server.shutdown();t.join();server.server_close()
emit('protected files unchanged',all(pathlib.Path(p).exists() and digest(pathlib.Path(p))==h for p,h in protected.items()))
```

Driver A output:

```text
environment presence only: {}
dependency: {"name": "Flask", "version": "3.1.3", "satisfies": true}
dependency: {"name": "dnspython", "version": "2.8.0", "satisfies": true}
dependency: {"name": "beautifulsoup4", "version": "4.15.0", "satisfies": true}
dependency: {"name": "cryptography", "version": "50.0.2", "satisfies": true}
dependency: {"name": "tree-sitter", "version": "0.25.2", "satisfies": true}
dependency: {"name": "tree-sitter-javascript", "version": "0.25.0", "satisfies": true}
dependency: {"name": "tree-sitter-java", "version": "0.23.5", "satisfies": true}
dependency: {"name": "packaging", "version": "26.3", "satisfies": true}
dependency: {"name": "defusedxml", "version": "0.7.1", "satisfies": true}
dependency: {"name": "PyYAML", "version": "6.0.3", "satisfies": true}
dependency: {"name": "cvss", "version": "3.6", "satisfies": true}
imports passed: 73
test modules syntax checked, not executed: 33
existing DB: {"quick_check": "ok", "version": 4, "scans": 33, "findings": 1336, "foreign_key_violations": 0}
permissions: {"data": "0o755", "data/sentinelscan.sqlite3": "0o644", "data/.secret_key": "0o600"}
safe config: {"DEBUG": false, "LLM_ENABLED": false, "SEMGREP_ENABLED": false, "CODEQL_ENABLED": false, "SESSION_COOKIE_HTTPONLY": true, "SESSION_COOKIE_SAMESITE": "Lax", "SESSION_COOKIE_SECURE": false, "TRUSTED_HOSTS": ["localhost", "127.0.0.1", "[::1]"], "MAX_CONTENT_LENGTH": 1048576}
external executable: {"name": "semgrep", "exists_and_executable": true}
external executable: {"name": "codeql", "exists_and_executable": true}
launcher: "still running after 12 seconds; subprocess terminated by timeout"
initialized tables: ["ai_reviews", "draft_checks", "finding_context", "finding_solutions", "findings", "pull_request_tracking", "remediation_drafts", "remediation_verifications", "reports", "repositories", "scan_comparisons", "scan_files", "scan_modules", "scans"]
sqlite pragmas: {"foreign_keys": 1, "journal_mode": "wal", "user_version": 4}
local route: {"path": "/", "status": 200}
local route: {"path": "/website-scan", "status": 200}
local route: {"path": "/repository-scan", "status": 200}
local route: {"path": "/scans", "status": 200}
local route: {"path": "/findings", "status": 200}
local route: {"path": "/reports", "status": 200}
security headers: {"Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Cache-Control": "no-store"}
untrusted host status: 400
restart persisted completed fixture: 1
127.0.0.1 - - [08/Oct/2026 13:00:05] "GET / HTTP/1.1" 200 -
actual loopback HTTP: {"status": 200, "body_contains_SentinelScan": true}
protected files unchanged: true
```

The initial 12-second launcher observation ended by timeout because a server is a long-running process; it was not a demonstrated startup failure. A second 30-second observation captured the normal running message. Driver B then verified HTTP while the launcher was running, resolving that ambiguity:

```sh
.venv/bin/python -B /tmp/sentinel_launcher01.py > /tmp/sentinel_launcher01.log 2>&1
cat /tmp/sentinel_launcher01.log
```

```python
import os,subprocess,tempfile,signal,time,urllib.request
with tempfile.TemporaryDirectory(prefix='sentinel-launch-audit-') as td:
 env=os.environ.copy();env.update(SENTINELSCAN_DATA_DIR=td,SENTINELSCAN_LLM_ENABLED='false',PYTHONDONTWRITEBYTECODE='1')
 p=subprocess.Popen(['/bin/zsh','./run-local.sh'],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,start_new_session=True)
 try:
  for attempt in range(20):
   try:
    with urllib.request.urlopen('http://127.0.0.1:5000/',timeout=1) as r:
     body=r.read()
     if b'SentinelScan' in body:
      print('LAUNCHER HTTP',r.status,'SentinelScan body confirmed');break
   except Exception:pass
   time.sleep(.5)
  else:print('LAUNCHER HTTP not verified')
  print('LAUNCHER alive:',p.poll() is None)
 finally:
  if p.poll() is None:os.killpg(p.pid,signal.SIGTERM)
  out,_=p.communicate(timeout=5);print(out)
```

```text
LAUNCHER HTTP 200 SentinelScan body confirmed
LAUNCHER alive: True
 * Serving Flask app 'app'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
127.0.0.1 - - [08/Oct/2026 13:01:18] Request completed: 200

```

## Conclusion

**Works:** valid Python/venv, all declared dependency constraints and 73 imports, existing launcher/dashboard, primary pages, safe temporary schema initialization and persistence, existing database integrity.

**Fails:** the supplied Desktop working-directory path is stale. No application startup failure reproduced at the actual Developer path.

**Blockers:** none for Phase 2 when using the actual project path and isolated test data. Local data permissions, launcher portability/configuration differences and stale documentation are recorded limitations, not corrected in this testing-only task.

**Phase 2:** can proceed when requested. No Phase 2 checks started. This audit does not certify scanner accuracy or optional engine/provider operation.
