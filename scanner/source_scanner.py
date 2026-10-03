"""Repository SAST orchestration using the existing queue, schema and finding contract."""
from dataclasses import replace
from datetime import datetime,timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import time
from analysis.redaction import scrub,redact_text
from analysis.finding_engine import save_finding
from analysis.risk_engine import calculate_risk
from database import get_db
from integrations.github import GitHubError
from scanner.repository_safety import extract_archive,ArchiveError
from scanner.sast import secret_scanner,python_scanner,javascript_scanner,java_scanner,html_scanner,config_scanner,dependency_scanner

from scanner.sast.registry import ANALYZERS
from scanner.sast.project_index import build_index
from scanner.engines.external import semgrep,codeql

MODULES=[('Secrets',secret_scanner.run)]+[(adapter.language,adapter.run) for adapter in ANALYZERS]+[('HTML',html_scanner.run),('Configuration',config_scanner.run),('Dependencies',dependency_scanner.run),('Semgrep',semgrep),('CodeQL',codeql)]
MODULE_NAMES=['Repository retrieval']+[name for name,_ in MODULES]


def now():
    return datetime.now(timezone.utc).isoformat()


def analyze_directory(root,paths,repository,osv_enabled=False):
    """For isolated tests/offline integrations: inspect already-vetted files, never execute them."""
    ctx={'root':Path(root),'paths':paths,'repository':repository,'osv_enabled':osv_enabled,'findings':[],
         'secrets':set(),'dependencies':[],'capped':False,'deadline':time.monotonic()+180}
    return ctx


def run_repository(app,scan_id,github,metadata,branch,sha,osv_enabled):
    with app.app_context():
        db=get_db()
        try:
            with db:
                db.execute("UPDATE scans SET status='Running',started_at=? WHERE id=?",(now(),scan_id))
                db.execute("UPDATE scan_modules SET status='Running' WHERE scan_id=? AND name='Repository retrieval'",(scan_id,))
            with tempfile.TemporaryDirectory(prefix='sentinelscan-repository-') as directory:
                archive=Path(directory)/'snapshot.zip';root=Path(directory)/'source'
                github.archive(metadata['full_name'],sha,archive)
                paths,inventory=extract_archive(archive,root)
                ctx=analyze_directory(root,paths,metadata['full_name'],osv_enabled)
                ctx['engine_config']={key:app.config.get(key) for key in ('SEMGREP_ENABLED','SEMGREP_BINARY','CODEQL_ENABLED','CODEQL_BINARY','CODEQL_SEARCH_PATH')}
                languages={}
                names={'.py':'Python','.js':'JavaScript','.jsx':'JavaScript','.mjs':'JavaScript','.cjs':'JavaScript','.java':'Java','.html':'HTML','.htm':'HTML'}
                for path in paths:
                    name=names.get(Path(path).suffix,'Configuration / other text')
                    languages[name]=languages.get(name,0)+1
                with db:
                    db.execute("UPDATE scan_modules SET status='Completed',data_json=? WHERE scan_id=? AND name='Repository retrieval'",(json.dumps(scrub({'repository':metadata,'branch':branch,'commit':sha,'inventory':inventory,'languages':languages,'project_index':build_index(ctx)})),scan_id))
                    db.execute('UPDATE scans SET progress=12 WHERE id=?',(scan_id,))
                    db.execute('UPDATE repositories SET languages_json=? WHERE scan_id=?',(json.dumps(languages),scan_id))
                for index,(name,module) in enumerate(MODULES,2):
                    with db:
                        db.execute("UPDATE scan_modules SET status='Running' WHERE scan_id=? AND name=?",(scan_id,name))
                    start=len(ctx['findings']);status='Completed';error=None;data={}
                    try:
                        if time.monotonic()>ctx['deadline']:
                            raise TimeoutError()
                        data=module(ctx)
                        if data.get('status') in ('Skipped','Partial','Failed'):
                            status=data['status'];error=data.get('note')
                        if data.get('unsupported_manifests') or data.get('inventory_capped') or data.get('flow_limited_files') or data.get('unparsed_files') or data.get('unparsed_manifests') or data.get('unparsed_inline_scripts') or data.get('lookup_failures'):
                            status='Partial';error='Some files or lookups could not be assessed; review the coverage details.'
                    except Exception:
                        status='Failed';error='Module could not complete safely; other checks continue.'
                    from analysis.correlation import persist_candidates
                    persist_candidates(db,scan_id,ctx,ctx['findings'][start:])
                    with db:
                        db.execute('UPDATE scan_modules SET status=?,data_json=?,error=? WHERE scan_id=? AND name=?',(status,json.dumps(scrub(data,ctx['secrets'])),error,scan_id,name))
                        rows=db.execute('SELECT severity,status FROM findings WHERE scan_id=?',(scan_id,)).fetchall()
                        db.execute('UPDATE scans SET progress=?,risk_score=? WHERE id=?',(round(index/len(MODULE_NAMES)*100),calculate_risk(rows),scan_id))
                all_rows = [dict(row, status='Open') for row in db.execute('SELECT severity FROM findings WHERE scan_id=?',(scan_id,))]
                from analysis.source_context import retain_context
                retain_context(db,scan_id,root,paths,metadata['full_name'],sha,ctx['secrets'])
                with db:
                    db.execute('UPDATE scans SET assessment_risk=? WHERE id=?',(calculate_risk(all_rows),scan_id))
                with db:
                    db.execute('UPDATE repositories SET dependencies_json=?,scanned_at=? WHERE scan_id=?',(json.dumps(scrub(ctx['dependencies'],ctx['secrets'])),now(),scan_id))
                    db.execute("UPDATE scans SET status='Completed',completed_at=?,error=? WHERE id=?",(now(),'Finding limit reached; results are incomplete.' if ctx['capped'] else None,scan_id))
            # Temporary archive and all source files have been removed before job completion returns.
        except Exception as exc:
            db.rollback()
            message=str(exc) if isinstance(exc,(ArchiveError,GitHubError)) else 'Repository analysis could not finish safely. Partial results are retained.'
            with db:
                db.execute("UPDATE scans SET status='Failed',error=?,completed_at=? WHERE id=?",(redact_text(message),now(),scan_id))
                db.execute("UPDATE scan_modules SET status='Failed',error='Repository analysis interrupted.' WHERE scan_id=? AND status IN ('Queued','Running')",(scan_id,))
