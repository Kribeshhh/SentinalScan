import hashlib
import re
import secrets
from urllib.parse import urlsplit, urlunsplit
from scanner.common import baseline, issue
from scanner.http_scanner import RequestFailure
from scanner.target import safe_url

DEFAULT_PATHS = ['/admin','/login','/dashboard','/api','/robots.txt','/uploads','/backup','/.git','/.git/HEAD','/.env']


def paths_from_text(text):
    paths = text.split() if text.strip() else DEFAULT_PATHS.copy()
    if len(paths) > 15:
        raise ValueError('Use at most 15 resource paths.')
    for path in paths:
        if len(path) > 120 or not re.fullmatch(r'/[a-zA-Z0-9_./-]*', path) or path.startswith('//') or '..' in path:
            raise ValueError('Paths must start with one slash and contain only letters, numbers, dots, slashes, underscores or hyphens; traversal is blocked.')
    return list(dict.fromkeys(paths))


def run(ctx):
    response = baseline(ctx)
    origin = urlsplit(response.url)
    def url(path):
        return urlunsplit((origin.scheme, origin.netloc, path, '', ''))
    random_path = '/sentinelscan-not-found-' + secrets.token_hex(10)
    missing = ctx['client'].get(url(random_path), redirects=False)
    missing_hash = hashlib.sha256(missing.body).digest()
    rows = []
    for path in ctx['paths']:
        try:
            result = ctx['client'].get(url(path), redirects=False)
        except RequestFailure:
            rows.append({'path':path,'error':'Request unavailable'})
            continue
        soft = result.status == missing.status and (hashlib.sha256(result.body).digest() == missing_hash or (result.html and missing.html and abs(len(result.body)-len(missing.body)) < 80))
        row = {'path':path,'status':result.status,'bytes':len(result.body),'truncated':result.truncated,'possible_soft_404':soft,'content_type':result.header('Content-Type')[:120]}
        rows.append(row)
        if result.status != 200 or soft:
            continue
        if path == '/.git/HEAD' and re.fullmatch(r'ref: refs/heads/[\w./-]+\s*', result.text):
            issue(ctx,'Exposed Git metadata','Medium','Information Disclosure','The Git HEAD resource contains a branch reference; no repository contents were downloaded.','Block access to .git paths and remove repository metadata from the served directory.','High', location=safe_url(result.url),response=result)
        if path == '/.env' and not result.html and len(re.findall(r'(?m)^[A-Z_][A-Z0-9_]{2,}\s*=', result.text)) >= 2:
            issue(ctx,'Potential exposed environment configuration','High','Information Disclosure','The /.env resource contains multiple environment-style assignments. Keys and values are not retained.','Remove configuration files from the web root, block access, and investigate whether secrets require rotation.','Medium',location=safe_url(result.url),response=result)
        if result.html and re.search(r'<title>\s*Index of\s*/', result.text, re.I):
            issue(ctx,'Directory listing enabled','Low','Information Disclosure','An HTML directory-index title was observed. Entry names are not retained.','Disable directory indexing and restrict access to intended public resources.','High',location=safe_url(result.url),response=result)
    return {'resources':rows, 'soft_404_baseline_status':missing.status, 'note':'HTTP 200/401/403 alone is not treated as a vulnerability. Soft-404 filtering is heuristic.'}
