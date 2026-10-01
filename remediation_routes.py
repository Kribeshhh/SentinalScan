"""Finding-to-source editor and explicit reviewed pull-request publication."""
import secrets
from flask import abort, flash, redirect, render_template, request, session, url_for, Response
from database import get_db
from integrations.github import GitHubError
from repository_routes import client
from analysis.remediation import coordinates, source_diff, validate_content
from analysis.solution_engine import solution_for
from analysis.remediation_workflow import check_draft,workflow_data,finding_solution


def register_remediation(app):
    @app.route('/findings/<int:finding_id>/edit',methods=['GET','POST'])
    def edit_finding(finding_id):
        db=get_db();error=None;context=None;draft=None;preview=None;content=''
        try:
            context=coordinates(db,finding_id)
            if context is None:
                abort(404)
            draft=db.execute('SELECT * FROM remediation_drafts WHERE finding_id=?',(finding_id,)).fetchone()
            if request.method=='POST':
                action=request.form.get('action')
                if action=='load' and not draft:
                    original,blob=client(bool(session.get('github_connected'))).source_file(context['repository'],context['path'],context['commit_sha'])
                    validate_content(original)
                    with db:
                        db.execute('''INSERT OR IGNORE INTO remediation_drafts
                            (finding_id,repository,path,base_branch,commit_sha,blob_sha,original,edited,head_branch)
                            VALUES (?,?,?,?,?,?,?,?,?)''',(finding_id,context['repository'],context['path'],context['base_branch'],context['commit_sha'],blob,
                            original,original,'sentinelscan/fix-'+str(finding_id)+'-'+secrets.token_hex(8)))
                    return redirect(url_for('edit_finding',finding_id=finding_id),code=303)
                if not draft or action not in ('preview','save'):
                    abort(400)
                if draft['state']!='Draft':
                    raise GitHubError('This draft is locked after publication starts. Retry publication or review its pull request.')
                content=request.form.get('content','').replace('\r\n','\n')
                # Browsers normalize textarea newlines. Preserve the source file convention.
                if '\r\n' in draft['original'] and '\n' not in draft['original'].replace('\r\n',''):
                    content=content.replace('\n','\r\n')
                validate_content(content)
                version=request.form.get('version','')
                if version!=str(draft['version']):
                    raise GitHubError('This draft changed in another tab. Reload before editing again.')
                preview=source_diff(draft['original'],content,draft['path'])
                if action=='save':
                    with db:
                        changed=db.execute("""UPDATE remediation_drafts SET edited=?,version=version+1,
                            updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=? AND version=? AND state='Draft'""",
                            (content,draft['id'],draft['version'])).rowcount
                    if not changed:
                        raise GitHubError('This draft changed in another tab. Reload before editing again.')
                    flash('Draft saved. Review the saved diff below, then create a pull request.')
                    saved=db.execute('SELECT * FROM remediation_drafts WHERE id=?',(draft['id'],)).fetchone()
                    check_draft(db,saved)
                    return redirect(url_for('edit_finding',finding_id=finding_id),code=303)
            elif draft:
                content=draft['edited']
        except GitHubError as exc:
            error=str(exc)
            # Never echo submitted secrets back into HTML.
            content=draft['edited'] if draft else ''
        diff=source_diff(draft['original'],draft['edited'],draft['path']) if draft else ''
        return render_template('finding_editor.html',title='Edit finding source',context=context,draft=draft,
            content=content,error=error,diff=diff,preview=preview,finding_id=finding_id,
            solution=finding_solution(db,context['finding'],draft) if context else None,
            workflow=workflow_data(db,context['finding']) if context else None),400 if error else 200

    @app.post('/findings/<int:finding_id>/publish')
    def publish_finding(finding_id):
        db=get_db()
        draft=db.execute('SELECT * FROM remediation_drafts WHERE finding_id=?',(finding_id,)).fetchone()
        if not draft:
            abort(404)
        if draft['state']=='Published':
            return redirect(url_for('edit_finding',finding_id=finding_id),code=303)
        if request.form.get('reviewed')!='yes' or request.form.get('version')!=str(draft['version']):
            abort(400)
        if draft['original']==draft['edited']:
            flash('Make and save a change before creating a pull request.')
            return redirect(url_for('edit_finding',finding_id=finding_id),code=303)
        try:
            if not session.get('github_connected'):
                raise GitHubError('Connect GitHub before publishing. Your token needs Contents and Pull requests: read and write for this repository.')
            github=client(True)
            validate_content(draft['original']);validate_content(draft['edited'])
            validation=check_draft(db,draft)
            if not validation['can_publish']:
                raise GitHubError('Publication blocked by validation. Fix syntax errors, remaining detections or new high-severity findings and save again.')
            with db:
                claimed=db.execute("UPDATE remediation_drafts SET state='Publishing' WHERE id=? AND version=? AND state IN ('Draft','Retry')",(draft['id'],draft['version'])).rowcount
            if not claimed:
                flash('Publication is already in progress. Reload shortly to see its result.')
                return redirect(url_for('edit_finding',finding_id=finding_id),code=303)
            try:
                pr_url=github.publish_fix(draft)
                with db:
                    db.execute("UPDATE remediation_drafts SET state='Published',pr_url=?,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?",(pr_url,draft['id']))
                flash('Pull request created. Review and test it on GitHub, then re-scan after merging.')
            except Exception:
                with db:
                    db.execute("UPDATE remediation_drafts SET state='Retry' WHERE id=?",(draft['id'],))
                raise
        except GitHubError as exc:
            flash(str(exc))
        except Exception:
            flash('Publication could not finish. The draft is saved; retry to recover using the same branch. A branch or commit may already exist on GitHub.')
        return redirect(url_for('edit_finding',finding_id=finding_id),code=303)

    @app.get('/findings/<int:finding_id>/patch')
    def finding_patch(finding_id):
        draft=get_db().execute('SELECT * FROM remediation_drafts WHERE finding_id=?',(finding_id,)).fetchone()
        if not draft:
            abort(404)
        return Response(source_diff(draft['original'],draft['edited'],draft['path']),mimetype='text/plain',
            headers={'Content-Disposition':f'attachment; filename="sentinelscan-finding-{finding_id}.patch"'})
