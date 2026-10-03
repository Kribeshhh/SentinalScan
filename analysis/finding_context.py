"""Bounded, redacted observation context; unknown facts stay unknown."""
import re
from pathlib import PurePosixPath
from analysis.redaction import scrub
from analysis.recommendation import source_metadata


def repository_context(finding, source=None):
    from analysis.source_context import mask_source
    f=dict(finding); metadata=source_metadata(f,source)
    language={'.py':'Python','.js':'JavaScript','.jsx':'JavaScript','.mjs':'JavaScript','.cjs':'JavaScript','.java':'Java'}.get(PurePosixPath(metadata['file']).suffix)
    parts=f.get('evidence','').split(' → ')
    flow=len(parts)>1 and parts[0].startswith(('Recognized input ', 'Dynamic value;'))
    line=metadata['line']; snippet=None
    if source is not None and line:
        lines=mask_source(source).splitlines()
        snippet='\n'.join(f'{i+1}: {lines[i][:700]}' for i in range(max(0,line-4),min(len(lines),line+3)))
    return scrub(dict(kind='sast',language=language,file=metadata['file'],line=line,
        function=None if metadata['function']=='Could not be determined statically' else metadata['function'],
        input_source=parts[0].removeprefix('Recognized input ') if flow and parts[0].startswith('Recognized input ') else None,
        sink=parts[-1].split('. No protection recognized')[0] if flow else None,
        simple_flow=parts[1:-1] if flow else [],
        protection='No protection recognized by this rule; not proof that none exists.' if flow and 'No protection recognized' in f.get('evidence','') else None,
        framework=None,database=None,snippet=snippet,scanner_evidence=f.get('evidence','')))


def website_context(ctx, response=None, observations=None):
    from scanner.target import safe_url
    response=response if response is not None else ctx.get('response')
    headers={}
    allowed={'content-type','content-security-policy','x-content-type-options','x-frame-options','referrer-policy','permissions-policy','strict-transport-security','access-control-allow-origin','access-control-allow-credentials','access-control-allow-methods','access-control-allow-headers','server','x-powered-by'}
    if response:
        for key,value in response.headers:
            if key.lower() in allowed:
                headers[key.lower()]=re.sub(r"nonce-[^\s;']+",'nonce-[REDACTED]',value[:1000])
    return scrub(dict(kind='dast',affected_url=safe_url(response.url if response else ctx['target'].url),
        http_method='GET' if response else None,http_status=response.status if response else None,
        response_headers=headers,observations=observations or {},response_snippet=None,
        body_policy='Response bodies and cookie values are not retained in finding context.'))
