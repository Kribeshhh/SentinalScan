"""Server-rendered GitHub connection/repository workflow; session-scoped tokens remain in server memory."""
import os
import ipaddress
import re
from flask import request,session,render_template,redirect,url_for,current_app,flash
from integrations.github import GitHubClient,GitHubError,repository_name,branch_name
from scanner.website_scanner import QueueFull
from analysis.redaction import redact_text
from integrations.credentials import CredentialStore


def stored_token():
    handle = session.get('github_credential')
    if handle:
        return current_app.extensions['github_credentials'].get(handle)
    return os.environ.get('SENTINELSCAN_GITHUB_TOKEN')


def clear_connection():
    current_app.extensions['github_credentials'].remove(session.pop('github_credential', None))
    session.pop('github_connected', None)
    session.pop('github_login', None)


def client(connected):
    token = stored_token() if connected else None
    if connected and not token:
        raise GitHubError('Your GitHub connection expired. Paste your token below to reconnect.')
    factory = current_app.config.get('GITHUB_CLIENT_FACTORY', GitHubClient)
    return factory(token=token)


def connect():
    token = request.form.get('github_token', '').strip()
    if token:
        try:
            local = ipaddress.ip_address(request.remote_addr or '').is_loopback
        except ValueError:
            local = False
        if not request.is_secure and not local:
            raise GitHubError('Token entry requires localhost or HTTPS.')
        if not re.fullmatch(r'[A-Za-z0-9_]{20,255}', token):
            raise GitHubError('Paste a valid GitHub personal access token without spaces.')
    else:
        token = os.environ.get('SENTINELSCAN_GITHUB_TOKEN')
        if not token:
            raise GitHubError('Paste your GitHub personal access token to connect.')
    factory = current_app.config.get('GITHUB_CLIENT_FACTORY', GitHubClient)
    login = factory(token=token).identity()  # Verify before retaining the credential.
    clear_connection()
    session['github_credential'] = current_app.extensions['github_credentials'].put(token)
    session['github_connected'] = True
    session['github_login'] = redact_text(login, (token,))


def register_routes(app):
    app.extensions['github_credentials'] = CredentialStore()
    @app.route('/repository-scan',methods=['GET','POST'])
    def repository_scan():
        error=None;repositories=[];branches=[];selected=None
        owner=request.args.get('owner','').strip()
        repo=request.args.get('repo','').strip()
        try:
            page=int(request.args.get('page','1'));branch_page=int(request.args.get('branch_page','1'))
            if not 1<=page<=1000 or not 1<=branch_page<=1000:
                raise ValueError()
        except ValueError:
            page=branch_page=1;error='Invalid repository or branch page.'
        connected=bool(session.get('github_connected'))
        if connected and not stored_token():
            clear_connection()
            connected=False
            flash('GitHub connection cleared after a restart or session eviction. Paste your token to reconnect.')
        if request.method=='POST':
            try:
                action=request.form.get('action')
                if action=='connect':
                    connect()
                    flash('GitHub connection verified. The access token stays on the server.')
                    return redirect(url_for('repository_scan'),code=303)
                if action=='disconnect':
                    clear_connection()
                    flash('GitHub disconnected for this browser. Already-authorized scans may finish.')
                    return redirect(url_for('repository_scan'),code=303)
                if action!='start' or request.form.get('authorized')!='yes':
                    raise GitHubError('Confirm authorization before starting repository analysis.')
                repo=repository_name(request.form.get('repository',''))
                branch=branch_name(request.form.get('branch',''))
                github=client(connected)
                metadata=github.repository(repo)  # Recheck access at submission, including private repositories.
                sha=github.commit(repo,branch)
                scan_id=app.extensions['scan_manager'].submit_repository(github,metadata,branch,sha,request.form.get('osv')=='yes')
                return redirect(url_for('scan_detail',scan_id=scan_id),code=303)
            except (GitHubError,QueueFull) as exc:
                error=str(exc)
        if not error:
            try:
                github=client(connected)
                if repo:
                    selected=github.repository(repository_name(repo))
                    branches=github.branches(selected['full_name'],branch_page)
                elif owner or connected:
                    repositories=github.repositories(owner,page)
            except GitHubError as exc:
                error=str(exc)
        return render_template('repository_scan.html',title='Repository Scan',connected=connected,
            token_configured=bool(os.environ.get('SENTINELSCAN_GITHUB_TOKEN')),login=session.get('github_login',''),
            repositories=repositories,branches=branches,selected=selected,owner=redact_text(owner),
            page=page,branch_page=branch_page,error=error),400 if error else 200
