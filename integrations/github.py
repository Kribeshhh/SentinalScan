"""GitHub REST access. An access token is sent only to api.github.com in a header."""
import json
import re
from urllib.parse import quote, urlsplit
from integrations.network import request, RemoteError
from analysis.redaction import redact_text


class GitHubError(ValueError):
    pass


def repository_name(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}',value) or value.split('/')[1] in ('.','..'):
        raise GitHubError('Enter a GitHub repository as owner/name.')
    if redact_text(value) != value:
        raise GitHubError('Repository identifiers that resemble credentials are not accepted.')
    return value


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
        messages={401:'GitHub authorization failed. Check the server-side token.',403:'GitHub denied this request or its rate limit was reached.',404:'Repository or branch is unavailable to this GitHub identity.',429:'GitHub rate limit reached. Try again later.'}
        if status!=200:
            raise GitHubError(messages.get(status,'GitHub could not complete this request.'))
        try:
            return json.loads(body)
        except (ValueError,UnicodeError):
            raise GitHubError('GitHub returned an invalid response.') from None

    def identity(self):
        return str(self.api('/user')['login'])[:100]

    def repositories(self,owner='',page=1):
        if not 1<=page<=1000:
            raise GitHubError('Invalid repository page.')
        if self._token and not owner:
            path=f'/user/repos?per_page=30&page={page}&sort=updated&affiliation=owner,collaborator,organization_member'
        else:
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}',owner):
                raise GitHubError('Enter a valid GitHub owner to browse public repositories.')
            path=f'/users/{owner}/repos?per_page=30&page={page}&sort=updated'
        return [self.metadata(row) for row in self.api(path)]

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
            status,received,body=request('api.github.com','/repos/'+name+'/zipball/'+sha,headers=headers,limit=20*1024*1024,seconds=30)
            if status in (301,302,303,307,308):
                location=next((v for k,v in received.items() if k.lower()=='location'),'')
                parsed=urlsplit(location)
                if parsed.scheme!='https' or parsed.hostname!='codeload.github.com' or parsed.port not in (None,443) or parsed.username is not None or not parsed.path.startswith('/'+name+'/'):
                    raise GitHubError('GitHub archive redirect was outside the permitted download scope.')
                # No Authorization header, cookies or proxy configuration on the download request.
                status,_,body=request('codeload.github.com',parsed.path+('?' + parsed.query if parsed.query else ''),limit=20*1024*1024,seconds=30)
            if status!=200:
                raise GitHubError('Repository archive could not be retrieved; verify access and retry.')
            destination.write_bytes(body)
        except (RemoteError,ValueError) as exc:
            if isinstance(exc,GitHubError):
                raise
            raise GitHubError('Repository download failed or exceeded the download limit.') from None
