"""GitHub REST access. An access token is sent only to api.github.com in a header."""
import json
import base64
import re
from urllib.parse import quote, urlsplit
from integrations.network import request, RemoteError, ResponseTooLarge
from analysis.redaction import redact_text


class GitHubError(ValueError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def access_error(status, headers):
    """Diagnose known access failures without exposing GitHub bodies or signed URLs."""
    headers={key.lower():value for key,value in headers.items()}
    if status==401:
        return 'GitHub rejected the token. It may be expired or revoked; disconnect and connect with a valid token.'
    if status==429 or status==403 and headers.get('x-ratelimit-remaining')=='0':
        return 'GitHub rate limit reached. Wait before retrying.'
    if status==403 and 'required' in headers.get('x-github-sso','').lower():
        return 'The organization requires SSO authorization for this token. Authorize it in GitHub token settings, then retry.'
    if status in (403,404):
        return ('GitHub could not grant access to this repository or branch. Check the owner/name, token resource owner, '
                'selected repositories and Contents: read permission. Organization approval or SSO may also be required. '
                'Connecting your account alone does not grant repository access.')
    return 'GitHub could not complete this request. Try again later.'


def repository_name(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}',value) or value.split('/')[1] in ('.','..'):
        raise GitHubError('Enter a GitHub repository as owner/name.')
    if redact_text(value) != value:
        raise GitHubError('Repository identifiers that resemble credentials are not accepted.')
    return value


def repository_input(value):
    """Accept repository identifiers or HTTPS GitHub root URLs, never arbitrary hosts."""
    message='Enter owner/repository or an HTTPS GitHub repository URL, such as https://github.com/owner/repository. Use the repository root URL; select its branch below.'
    if not isinstance(value,str) or len(value)>512:
        raise GitHubError(message)
    value=value.strip()
    if any(ord(c)<33 for c in value):
        raise GitHubError(message)
    if '://' not in value:
        return repository_name(value)
    try:
        url=urlsplit(value)
        if (url.scheme!='https' or url.netloc.lower()!='github.com' or
            url.query or url.fragment or '?' in value or '#' in value):
            raise ValueError()
        path=url.path
        if path.endswith('/'): path=path[:-1]
        if path.endswith('.git'): path=path[:-4]
        if not path.startswith('/'): raise ValueError()
        return repository_name(path[1:])
    except ValueError:
        raise GitHubError(message) from None


def branch_name(value):
    if not isinstance(value,str) or not 1<=len(value)<=240 or any(ord(c)<33 for c in value) or any(c in value for c in ('..','@{','\\','~','^',':','?','*','[')):
        raise GitHubError('Invalid branch name.')
    if redact_text(value) != value:
        raise GitHubError('Branch identifiers that resemble credentials are not accepted.')
    return value


class GitHubClient:
    def __init__(self, token=None):
        self._token=token

    def __repr__(self):
        return '<GitHubClient credentials withheld>'

    def api(self,path):
        headers={'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'}
        if self._token:
            headers['Authorization']='Bearer '+self._token
        try:
            status, received, body=request('api.github.com',path,headers=headers)
        except RemoteError as exc:
            raise GitHubError(str(exc)) from None
        if status not in (200,201):
            message=access_error(status, received)
            raise GitHubError(message,status)
        try:
            return json.loads(body)
        except (ValueError,UnicodeError):
            raise GitHubError('GitHub returned an invalid response.') from None

    def identity(self):
        return str(self.api('/user')['login'])[:100]

    def source_file(self,name,path,ref):
        from analysis.remediation import validate_path, validate_content
        validate_path(path)
        data=self.api('/repos/'+repository_name(name)+'/contents/'+quote(path,safe='/')+'?ref='+quote(ref,safe=''))
        try:
            if not isinstance(data,dict) or data.get('type')!='file' or data.get('encoding')!='base64' or data.get('path')!=path or data.get('size',999999)>524288:
                raise ValueError()
            content=base64.b64decode(''.join(data['content'].split()),validate=True).decode('utf-8')
            sha=data['sha']
            if not re.fullmatch('[a-f0-9]{40,64}',sha):
                raise ValueError()
        except (ValueError,KeyError,UnicodeError,TypeError):
            raise GitHubError('Source preview supports regular UTF-8 source files up to 512 KiB.') from None
        validate_content(content)
        return content,sha

    def repositories(self,owner='',page=1):
        if not 1<=page<=1000:
            raise GitHubError('Invalid repository page.')
        if owner and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}',owner):
            raise GitHubError('Enter a valid GitHub owner.')
        if self._token:
            # /users/{owner}/repos exposes public repositories even with a token.
            path=f'/user/repos?per_page=30&page={page}&sort=updated&affiliation=owner,collaborator,organization_member'
        else:
            if not owner:
                raise GitHubError('Enter a valid GitHub owner to browse public repositories.')
            path=f'/users/{owner}/repos?per_page=30&page={page}&sort=updated'
        rows=self.api(path)
        self.has_more_repositories=len(rows)==30
        results=[self.metadata(row) for row in rows]
        return [row for row in results if not self._token or not owner or row['owner'].lower()==owner.lower()]

    @staticmethod
    def metadata(row):
        full=repository_name(row['full_name'])
        owner,name=full.split('/')
        return {'owner':owner,'name':name,'full_name':full,'url':'https://github.com/'+full,
                'private':bool(row.get('private')),'default_branch':str(row.get('default_branch','main'))[:240],
                'size_kib':int(row.get('size',0)),'language':str(row.get('language') or 'Unknown')[:50]}

    def repository(self,name):
        return self.metadata(self.api('/repos/'+repository_name(name)))

    def branches(self,name,page=1):
        if not 1<=page<=1000:
            raise GitHubError('Invalid branch page.')
        rows=self.api('/repos/'+repository_name(name)+f'/branches?per_page=30&page={page}')
        return [branch_name(row['name']) for row in rows]

    def commit(self,name,branch):
        data=self.api('/repos/'+repository_name(name)+'/branches/'+quote(branch_name(branch),safe=''))
        sha=data['commit']['sha']
        if not re.fullmatch('[a-fA-F0-9]{40,64}',sha):
            raise GitHubError('GitHub returned an invalid commit identifier.')
        return sha

    def archive(self,name,sha,destination):
        name=repository_name(name)
        if not re.fullmatch('[a-fA-F0-9]{40,64}',sha):
            raise GitHubError('Invalid commit identifier.')
        headers={'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'}
        if self._token:
            headers['Authorization']='Bearer '+self._token
        try:
            status,received,body=request('api.github.com','/repos/'+name+'/zipball/'+sha,headers=headers,limit=64*1024*1024,seconds=120)
            if status in (301,302,303,307,308):
                location=next((v for k,v in received.items() if k.lower()=='location'),'')
                parsed=urlsplit(location)
                if parsed.scheme!='https' or parsed.hostname!='codeload.github.com' or parsed.port not in (None,443) or parsed.username is not None or not parsed.path.startswith('/'+name+'/'):
                    raise GitHubError('GitHub archive redirect was outside the permitted download scope.')
                # No Authorization header, cookies or proxy configuration on the download request.
                status,_,body=request('codeload.github.com',parsed.path+('?' + parsed.query if parsed.query else ''),limit=64*1024*1024,seconds=120)
            if status!=200:
                raise GitHubError(access_error(status, {})+' Repository download requires Contents: read access.')
            destination.write_bytes(body)
        except ResponseTooLarge:
            raise GitHubError('Repository archive exceeds the 64 MiB download limit. Scan a smaller source-only repository.') from None
        except (RemoteError,ValueError) as exc:
            if isinstance(exc,GitHubError):
                raise
            raise GitHubError('Repository download could not complete. Check the network connection and retry; the download deadline is 120 seconds.') from None
