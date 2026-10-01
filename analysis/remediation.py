"""Bounded source editing, immutable scan coordinates and reviewable diffs."""
import difflib
import re
from analysis.redaction import redact_text
from integrations.github import GitHubError, repository_name, branch_name

MAX_SOURCE_BYTES = 524288


def validate_path(path):
    if (not isinstance(path, str) or not path or len(path)>400 or path.startswith('/')
            or '\\' in path or any(ord(c)<32 or ord(c)==127 for c in path)
            or any(part in ('', '.', '..', '.git') for part in path.split('/'))):
        raise GitHubError('This finding does not identify an editable source file.')
    if path.startswith('.github/workflows/'):
        raise GitHubError('Workflow files must be edited on GitHub with separate workflow authorization.')
    return path


def validate_content(content):
    if len(content.encode('utf-8'))>MAX_SOURCE_BYTES or any(ord(c)<32 and c not in '\r\n\t' for c in content):
        raise GitHubError('The editor supports regular UTF-8 source files up to 512 KiB.')
    if redact_text(content)!=content or '[REDACTED]' in content:
        raise GitHubError('This file contains a possible secret or masked content. Edit it securely in your local checkout and rotate exposed credentials. SentinelScan will not store or publish it through this editor.')
    return content


def coordinates(db, finding_id):
    row=db.execute('''SELECT f.*,r.owner,r.name AS repo_name,r.branch,r.commit_sha
        FROM findings f JOIN scans s ON s.id=f.scan_id
        LEFT JOIN repositories r ON r.id=s.repository_id WHERE f.id=?''',(finding_id,)).fetchone()
    if row is None:
        return None
    if row['source']!='Repository' or not row['owner'] or not row['commit_sha']:
        raise GitHubError('Code editing is available for repository findings with a saved commit. Website findings do not identify an editable source file.')
    name=repository_name(row['owner']+'/'+row['repo_name'])
    prefix=name+'/'
    if not row['location'].startswith(prefix):
        raise GitHubError('This finding does not identify an editable source file.')
    location=row['location'][len(prefix):]
    match=re.fullmatch(r'(.+):([0-9]+)',location)
    path=validate_path(match[1] if match else location)
    if not re.fullmatch('[a-fA-F0-9]{40,64}',row['commit_sha']):
        raise GitHubError('This scan does not have a valid source commit. Run a new repository scan.')
    return dict(finding=row,repository=name,path=path,line=int(match[2]) if match else 1,
                base_branch=branch_name(row['branch']),commit_sha=row['commit_sha'])


def source_diff(original,edited,path):
    # Explicit no-newline markers keep downloaded patches applicable to files without final LF.
    lines=difflib.unified_diff(original.splitlines(keepends=True),edited.splitlines(keepends=True),
                               fromfile='a/'+path,tofile='b/'+path)
    return ''.join(line if line.endswith('\n') else line+'\n\\ No newline at end of file\n' for line in lines)
