"""Read retained deterministic recommendation snapshots, including historical context."""
import json


def finding_solution(db,finding,draft=None):
    from analysis.solution_engine import solution_for
    saved=db.execute('SELECT data_json FROM finding_solutions WHERE finding_id=?',(finding['id'],)).fetchone()
    if saved and not draft:
        snapshot=json.loads(saved[0])
        if finding['status']=='False Positive' or snapshot.get('summary')=='This finding is marked False Positive.':
            current=solution_for(finding)
            current.update(context=snapshot.get('context'),source_status=snapshot.get('source_status'),finding_context=snapshot.get('finding_context',current.get('finding_context')))
            return current
        from analysis.recommendation import recommendation_for
        return recommendation_for(finding,snapshot)
    solution=solution_for(finding,draft['original'] if draft else None)
    if not draft:
        row=db.execute('SELECT * FROM finding_context WHERE finding_id=?',(finding['id'],)).fetchone()
        if row:
            solution['context']='\n'.join(f'{row["start_line"]+i:>4} {">" if row["start_line"]+i==row["detected_line"] else " "} {line}' for i,line in enumerate(row['excerpt'].splitlines()))
            solution['source_status']='Redacted source context retained from scanned commit '+row['commit_sha']+'. Long lines may be truncated. A new scan prepares supported source-matched candidates automatically.'
    return solution
