"""Explicit GitHub status refresh, authorized rescan and finding verification."""
import json
from flask import abort,request,session,redirect,url_for,flash
from database import get_db
from repository_routes import client
from integrations.github import GitHubError
from analysis.validation import record_id
from analysis.remediation_workflow import check_draft,assess_rescan,save_verification
from scanner.website_scanner import QueueFull


def register_workflow(app):
    def records(finding_id):
        db=get_db()
        finding=db.execute('SELECT * FROM findings WHERE id=?',(finding_id,)).fetchone()
        if not finding: abort(404)
        draft=db.execute('SELECT * FROM remediation_drafts WHERE finding_id=?',(finding_id,)).fetchone()
        return db,finding,draft

    def back(finding_id): return redirect(url_for('finding_detail',finding_id=finding_id)+'#remediation-workflow',code=303)

    def refresh(db,draft,github):
        if not draft or not draft['pr_url']: raise GitHubError('Create a pull request before checking its status.')
        state=github.pull_status(draft)
        with db:
            db.execute('''INSERT INTO pull_request_tracking(draft_id,state,merge_commit) VALUES (?,?,?)
                ON CONFLICT(draft_id) DO UPDATE SET state=excluded.state,merge_commit=excluded.merge_commit,
                checked_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')''',(draft['id'],state['state'],state['merge_commit']))
        return state

    @app.post('/findings/<int:finding_id>/validate')
    def validate_finding_fix(finding_id):
        db,finding,draft=records(finding_id)
        if not draft: abort(404)
        if request.form.get('version')!=str(draft['version']): abort(400)
        try:
            check_draft(db,draft);flash('Saved draft checked. Review the validation results below.')
        except GitHubError as exc: flash(str(exc))
        return back(finding_id)

    @app.post('/findings/<int:finding_id>/pull-request/refresh')
    def refresh_finding_pr(finding_id):
        db,finding,draft=records(finding_id)
        try:
            refresh(db,draft,client(bool(session.get('github_connected'))))
            flash('Pull request status refreshed from GitHub.')
        except GitHubError as exc: flash(str(exc))
        return back(finding_id)

    @app.post('/findings/<int:finding_id>/rescan')
    def rescan_finding(finding_id):
        db,finding,draft=records(finding_id)
        if request.form.get('authorized')!='yes': abort(400)
        try:
            github=client(bool(session.get('github_connected')))
            state=refresh(db,draft,github)
            if state['state']!='Merged': raise GitHubError('Merge the reviewed pull request on GitHub before starting a verification scan.')
            metadata=github.repository(draft['repository']);sha=github.commit(draft['repository'],draft['base_branch'])
            if not github.includes_commit(draft['repository'],state['merge_commit'],sha):
                raise GitHubError('The branch no longer contains the merge commit. Review its history before verifying.')
            scan_id=app.extensions['scan_manager'].submit_repository(github,metadata,draft['base_branch'],sha,request.form.get('osv')=='yes')
            scan=db.execute('SELECT * FROM scans WHERE id=?',(scan_id,)).fetchone()
            save_verification(db,finding,scan,'Pending','Verification scan requested; check after completion.',state['merge_commit'])
            flash('Verification scan started. After it completes, return to this finding and verify against the new scan.')
            return redirect(url_for('scan_detail',scan_id=scan_id),code=303)
        except (GitHubError,QueueFull) as exc: flash(str(exc))
        return back(finding_id)

    @app.post('/findings/<int:finding_id>/verify')
    def verify_finding(finding_id):
        db,finding,draft=records(finding_id)
        try:
            scan_id=record_id(request.form.get('scan_id',''))
        except ValueError: abort(400)
        scan=db.execute('SELECT * FROM scans WHERE id=?',(scan_id,)).fetchone()
        try:
            result,message=assess_rescan(db,finding,scan)
            merged=None
            if draft and draft['pr_url']:
                github=client(bool(session.get('github_connected')))
                state=refresh(db,draft,github)
                if state['state']!='Merged':
                    result='Inconclusive';message='The linked pull request is not merged. Its remediation cannot yet be verified.'
                elif result!='Inconclusive':
                    repo=db.execute('SELECT commit_sha FROM repositories WHERE id=?',(scan['repository_id'],)).fetchone()
                    if not repo or not github.includes_commit(draft['repository'],state['merge_commit'],repo['commit_sha']):
                        result='Inconclusive';message='This scan does not include the pull request merge commit.'
                    else: merged=state['merge_commit']
            save_verification(db,finding,scan,result,message,merged,request.form.get('resolve')=='yes')
            flash('Verification: '+result+'. '+message)
        except ValueError as exc:
            flash(str(exc) if isinstance(exc,GitHubError) else 'Select a later scan of the same target and branch.')
        return back(finding_id)
