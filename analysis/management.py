"""Database-backed scan metrics, target identity and comparison snapshots."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from analysis.risk_engine import calculate_risk,SEVERITY_WEIGHTS
from analysis.redaction import scrub


def duration(scan):
    if not scan.get('started_at') or not scan.get('completed_at'):
        return None
    try:
        return max(0,round((datetime.fromisoformat(scan['completed_at'].replace('Z','+00:00'))-datetime.fromisoformat(scan['started_at'].replace('Z','+00:00'))).total_seconds(),2))
    except (ValueError,TypeError):
        return None


def scan_metrics(db,scan):
    data=dict(scan)
    findings=[dict(row) for row in db.execute('SELECT * FROM findings WHERE scan_id=? ORDER BY id',(data['id'],))]
    counts=Counter(f['severity'] for f in findings)
    data.update(duration_seconds=duration(data),finding_count=len(findings),counts={s:counts[s] for s in SEVERITY_WEIGHTS},risk_score=calculate_risk(findings))
    return data


def target_identity(db,scan):
    if scan['scan_type']=='Repository':
        repo=db.execute('SELECT * FROM repositories WHERE id=?',(scan['repository_id'],)).fetchone()
        if repo and repo['owner'] and repo['branch']:
            return ('Repository',repo['owner'].lower()+'/'+repo['name'].lower(),repo['branch'])
        return ('Repository',scan['target'])
    p=urlsplit(scan['target'])
    try:
        port=p.port
    except ValueError:
        return ('Website',scan['target'])
    host=(p.hostname or '').lower()
    if ':' in host:
        host='['+host+']'
    if port and port != (443 if p.scheme.lower()=='https' else 80):
        host+=':'+str(port)
    query=urlencode(sorted((key,'[redacted]') for key,_ in parse_qsl(p.query,keep_blank_values=True)))
    return ('Website',urlunsplit((p.scheme.lower(),host,p.path or '/',query,'')))


def comparison_fingerprint(finding):
    location=finding['location']
    if finding['source']=='Repository':
        location=re.sub(r':\d+(?::\d+)?$','',location)
    parts=[finding['source'],finding['category'].strip(),finding['title'].strip(),location]
    return hashlib.sha256(json.dumps(parts,ensure_ascii=False).encode()).hexdigest()


def compare_scans(db,baseline_id,current_id):
    previous=db.execute('SELECT * FROM scans WHERE id=?',(baseline_id,)).fetchone()
    current=db.execute('SELECT * FROM scans WHERE id=?',(current_id,)).fetchone()
    if previous is None or current is None:
        raise ValueError('Select two existing scans.')
    if baseline_id==current_id:
        raise ValueError('Select two different scans.')
    if previous['status']!='Completed' or current['status']!='Completed':
        raise ValueError('Only completed scans can be compared; review partial module coverage as well.')
    if target_identity(db,previous)!=target_identity(db,current):
        raise ValueError('Scans must assess the same target. Repository comparisons also require the same branch.')
    if (previous['created_at'],previous['id']) >= (current['created_at'],current['id']):
        raise ValueError('The baseline must be older than the current scan.')
    loaded={}
    for scan_id in (baseline_id,current_id):
        loaded[scan_id]=[]
        for row in db.execute('SELECT * FROM findings WHERE scan_id=? ORDER BY id',(scan_id,)):
            finding=dict(row)
            saved=db.execute('SELECT data_json FROM finding_solutions WHERE finding_id=?',(finding['id'],)).fetchone()
            logical=json.loads(saved[0]).get('finding_context',{}).get('analysis',{}).get('logical_fingerprint') if saved else None
            loaded[scan_id].append((finding,logical))
    # Preserve legacy matching for any rule/file family with missing new evidence.
    legacy_families={comparison_fingerprint(f) for rows in loaded.values() for f,logical in rows if not logical}
    def groups(scan_id):
        result={}
        for finding,logical in loaded[scan_id]:
            legacy=comparison_fingerprint(finding)
            key=logical if logical and legacy not in legacy_families else legacy
            result.setdefault(key,[]).append(finding)
        return result
    old,new=groups(baseline_id),groups(current_id)
    def group(key,rows):
        return {'fingerprint':key,'finding':rows[0],'occurrences':len(rows),'finding_ids':[r['id'] for r in rows]}
    a,b=scan_metrics(db,previous),scan_metrics(db,current)
    warnings=['RESOLVED means absent from the later scan, not proof of remediation. All triage statuses participate in detection matching.',
              'New supported repository findings use semantic operation/scope identities without line numbers. Families missing that evidence use legacy title/file grouping; repeated identical operations may remain one comparison group.',
              'Website query values are redacted; target identity compares scheme, host, port, path and query parameter names.']
    for scan in (previous,current):
        modules=db.execute('SELECT name,status FROM scan_modules WHERE scan_id=?',(scan['id'],)).fetchall()
        if not modules or any(row['status']!='Completed' for row in modules):
            warnings.append(f"Scan {scan['id']} has missing, failed, partial or skipped module coverage. Absence can reflect incomplete coverage.")
    if previous['options_json']!=current['options_json']:
        warnings.append('Scan options or repository commits differ. Review scope and coverage before interpreting changes.')
    return scrub({'schema_version':1,'generated_at':datetime.now(timezone.utc).isoformat(),'baseline':a,'current':b,
        'previous_risk':a['risk_score'],'current_risk':b['risk_score'],'risk_change':b['risk_score']-a['risk_score'],
        'new':[group(k,new[k]) for k in sorted(new.keys()-old.keys())],
        'resolved':[group(k,old[k]) for k in sorted(old.keys()-new.keys())],
        'unchanged':[dict(group(k,new[k]),previous=old[k][0],previous_occurrences=len(old[k])) for k in sorted(new.keys()&old.keys())],
        'limitations':warnings})


def risk_trend(db,scan_id=None):
    rows=db.execute("SELECT * FROM scans WHERE status='Completed' ORDER BY created_at DESC,id DESC").fetchall()
    if scan_id is not None:
        reference=db.execute('SELECT * FROM scans WHERE id=?',(scan_id,)).fetchone()
        if not reference:
            raise ValueError('Unknown scan for risk trend.')
        identity=target_identity(db,reference)
        rows=[row for row in rows if target_identity(db,row)==identity]
    rows=list(reversed(rows[:40]))
    points=[]
    for index,row in enumerate(rows):
        score=row['assessment_risk']
        if score is None:
            continue
        points.append({'id':row['id'],'target':row['target'],'created_at':row['created_at'],'score':score,
                       'x':50+index*700/max(1,len(rows)-1),'y':180-score*1.4})
    return scrub(points)
