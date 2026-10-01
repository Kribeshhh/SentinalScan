"""Persist validation and conservative, coverage-aware rescan verification."""
import json
import re
from analysis.fix_validation import validate_fix
from analysis.management import target_identity,comparison_fingerprint
from analysis.risk_engine import calculate_risk


def check_draft(db,draft):
    finding=db.execute('SELECT * FROM findings WHERE id=?',(draft['finding_id'],)).fetchone()
    result=validate_fix(finding,draft)
    with db:
        db.execute('INSERT OR REPLACE INTO draft_checks(draft_id,version,data_json) VALUES (?,?,?)',
            (draft['id'],draft['version'],json.dumps(result)))
    return result


def workflow_data(db,finding):
    draft=db.execute('SELECT * FROM remediation_drafts WHERE finding_id=?',(finding['id'],)).fetchone()
    check=tracking=None
    if draft:
        row=db.execute('SELECT data_json FROM draft_checks WHERE draft_id=? AND version=?',(draft['id'],draft['version'])).fetchone()
        check=json.loads(row[0]) if row else None
        tracking=db.execute('SELECT * FROM pull_request_tracking WHERE draft_id=?',(draft['id'],)).fetchone()
    baseline=db.execute('SELECT * FROM scans WHERE id=?',(finding['scan_id'],)).fetchone()
    candidates=[]
    for row in db.execute("SELECT * FROM scans WHERE id>? AND scan_type=? ORDER BY id DESC LIMIT 200",(finding['scan_id'],finding['source'])):
        if target_identity(db,row)==target_identity(db,baseline): candidates.append(row)
    history=db.execute('SELECT * FROM remediation_verifications WHERE finding_id=? ORDER BY checked_at DESC LIMIT 10',(finding['id'],)).fetchall()
    return dict(draft=draft,check=check,tracking=tracking,candidates=candidates,history=history)


def assess_rescan(db,finding,scan):
    baseline=db.execute('SELECT * FROM scans WHERE id=?',(finding['scan_id'],)).fetchone()
    if scan is None or scan['id']<=baseline['id'] or target_identity(db,scan)!=target_identity(db,baseline):
        raise ValueError('Select a later scan of the same target and branch.')
    if scan['status']!='Completed' or scan['error']:
        return 'Inconclusive','The scan is incomplete, failed, or capped. No resolution is inferred.'
    before_options=json.loads(baseline['options_json']);after_options=json.loads(scan['options_json'])
    if finding['source']=='Website' and not set(before_options.get('paths',[])).issubset(after_options.get('paths',[])):
        return 'Inconclusive','The later website scan did not include all previously requested paths.'
    if finding['category']=='Dependency' and not after_options.get('osv_enabled'):
        return 'Inconclusive','Dependency vulnerability lookup was disabled in the later scan.'
    modules=db.execute('SELECT name,status FROM scan_modules WHERE scan_id=?',(scan['id'],)).fetchall()
    prior={r[0] for r in db.execute('SELECT name FROM scan_modules WHERE scan_id=?',(baseline['id'],))}
    if not prior or not modules or not prior.issubset({r['name'] for r in modules}) or any(r['status']!='Completed' for r in modules):
        return 'Inconclusive','Module coverage is incomplete or changed. A missing finding is not sufficient evidence of a fix.'
    if finding['source']=='Repository':
        repo=db.execute('SELECT * FROM repositories WHERE id=?',(baseline['repository_id'],)).fetchone()
        prefix=repo['owner']+'/'+repo['name']+'/'
        location=re.sub(r':\d+$','',finding['location'])
        path=location[len(prefix):] if location.startswith(prefix) else ''
        if not db.execute('SELECT 1 FROM scan_files WHERE scan_id=? AND path=?',(scan['id'],path)).fetchone():
            return 'Inconclusive','The affected file was not analyzed in this scan (removed, renamed, excluded, or no retained coverage record).'
    fingerprint=comparison_fingerprint(finding)
    for row in db.execute('SELECT * FROM findings WHERE scan_id=?',(scan['id'],)):
        if comparison_fingerprint(row)==fingerprint:
            return 'Still detected','The same rule still detects a finding at this location, ignoring line shifts and triage status.'
    return 'Not detected','The later scan completed its recorded modules and no longer detects this rule at the affected location. Application behavior is not verified.'


def save_verification(db,finding,scan,result,message,merge_commit=None,resolve=False):
    with db:
        db.execute('''INSERT INTO remediation_verifications(finding_id,scan_id,result,message,merge_commit)
            VALUES (?,?,?,?,?) ON CONFLICT(finding_id,scan_id) DO UPDATE SET result=excluded.result,
            message=excluded.message,merge_commit=excluded.merge_commit,checked_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')''',
            (finding['id'],scan['id'],result,message,merge_commit))
        if resolve and result=='Not detected':
            db.execute("UPDATE findings SET status='Resolved' WHERE id=? AND status='Open'",(finding['id'],))
            rows=db.execute('SELECT severity,status FROM findings WHERE scan_id=?',(finding['scan_id'],)).fetchall()
            db.execute('UPDATE scans SET risk_score=? WHERE id=?',(calculate_risk(rows),finding['scan_id']))


def finding_solution(db,finding,draft=None):
    from analysis.solution_engine import solution_for
    saved=db.execute('SELECT data_json FROM finding_solutions WHERE finding_id=?',(finding['id'],)).fetchone()
    if saved and not draft:
        snapshot=json.loads(saved[0])
        if finding['status']=='False Positive' or snapshot.get('summary')=='This finding is marked False Positive.':
            current=solution_for(finding)
            current.update(context=snapshot.get('context'),source_status=snapshot.get('source_status'))
            return current
        return snapshot
    solution=solution_for(finding,draft['original'] if draft else None)
    if not draft:
        row=db.execute('SELECT * FROM finding_context WHERE finding_id=?',(finding['id'],)).fetchone()
        if row:
            solution['context']='\n'.join(f'{row["start_line"]+i:>4} {">" if row["start_line"]+i==row["detected_line"] else " "} {line}' for i,line in enumerate(row['excerpt'].splitlines()))
            solution['source_status']='Redacted source context retained from scanned commit '+row['commit_sha']+'. Long lines may be truncated. A new scan prepares supported source-matched candidates automatically.'
    return solution
