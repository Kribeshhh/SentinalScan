"""Explicit, bounded review with redaction before provider request construction."""
import json
import re
from pathlib import PurePosixPath
from analysis.redaction import redact_text
from analysis.source_context import mask_source
from analysis.source_validation import validate_candidate
from analysis.remediation import source_diff
from integrations.llm import FIELDS


def clean(value,known=()):
    value=mask_source(str(value),known)
    # Do not apply placeholder/entropy exceptions at the external-data boundary.
    value=re.sub(r'''(?im)(\b(?:password|passwd|secret|token|api[_-]?key|authorization|credential)[\w.-]*["']?\s*[:=]\s*)["'][^"'\r\n]*["']''',r'\1"[REDACTED]"',value)
    value=re.sub(r'\bsk-[A-Za-z0-9_-]{12,}\b','[REDACTED]',value)
    return redact_text(value,known)


def prepare(finding,context,known=()):
    f=dict(finding)
    suffix=PurePosixPath(re.sub(r':\d+$','',f['location'])).suffix.lower()
    language={'.py':'Python','.java':'Java','.js':'JavaScript','.jsx':'JavaScript','.cjs':'JavaScript','.mjs':'JavaScript','.json':'JSON','.yaml':'YAML','.yml':'YAML'}.get(suffix,'Unknown')
    if f['category']=='Secret Exposure':
        return dict(category='Secret Exposure',language=language,title='Potential hardcoded credential',evidence='Credential pattern detected. Value withheld; validity not tested.',snippet='password = "[REDACTED]"',start_line=0)
    snippet=clean(context['excerpt'],known) if context else ''
    # Truncating source makes replacement mapping ambiguous: omit instead.
    if len(snippet)>7000 or len(snippet.splitlines())>21:snippet=''
    return dict(category=clean(f['category'],known)[:100],title=clean(f['title'],known)[:200],language=language,
        evidence=clean(f['evidence'],known)[:3000],snippet=snippet,start_line=context['start_line'] if context and snippet else 0,
        detected_line=context['detected_line'] if context and snippet else 0,
        scope='One retained excerpt; unknown framework/source/sanitization details must remain unknown.')


def validate_response(data):
    if not isinstance(data,dict) or set(data)!=set(FIELDS):raise ValueError('Invalid structure')
    for key,value in data.items():
        if not isinstance(value,str) or len(value)>(8000 if key in ('original_code','suggested_code') else 3000):raise ValueError('Invalid field')
        if any(ord(c)<32 and c not in '\n\r\t' for c in value):raise ValueError('Invalid characters')
    if data['assessment'] not in ('likely_valid','needs_review','likely_false_positive') or data['fix_confidence'] not in ('high','medium','low'):raise ValueError('Invalid enum')
    if not data['reason'].strip() or not data['remediation'].strip():raise ValueError('Empty explanation')
    if bool(data['original_code'])!=bool(data['suggested_code']):raise ValueError('Incomplete replacement')
    return dict(data)


def process(finding,payload,response,original=None,known=()):
    data=validate_response(response)
    data={key:clean(value,known) for key,value in data.items()}
    data.update(validation={'status':'Not Available'},diff='',note='AI output may be wrong. Review it alongside scanner evidence. No code was applied.')
    if finding['category']=='Secret Exposure':
        data.update(original_code='',suggested_code='',note='Secret values are withheld. Rotate/revoke real credentials and review runtime configuration manually.')
        return data
    if not data['suggested_code']:return data
    snippet=payload['snippet'];start=payload['start_line']
    if not snippet or response['original_code']!=snippet or data['original_code']!=snippet or '[REDACTED]' in data['original_code']+data['suggested_code']:
        data.update(original_code='',suggested_code='',note='AI code was withheld because it did not match the supplied source or contained redacted data.')
        data['validation']={'status':'Failed'};return data
    data['diff']=source_diff(snippet,data['suggested_code'],'reviewed-snippet')
    if original is None:
        data['note']='Static validation not available: load the pinned source in the existing editor, then request review again. This diff covers only the excerpt.'
        return data
    lines=original.splitlines(keepends=True);count=len(snippet.splitlines())
    span=''.join(lines[start-1:start-1+count])
    if start<1 or span.rstrip('\r\n')!=snippet.rstrip('\r\n'):
        data['note']='Source context does not match the pinned file; no validated replacement is available.'
        return data
    replacement=data['suggested_code'].rstrip('\r\n')+ ('\r\n' if span.endswith('\r\n') else '\n' if span.endswith('\n') else '')
    edited=''.join(lines[:start-1])+replacement+''.join(lines[start-1+count:])
    result=validate_candidate(finding,original,edited)
    data['validation']=dict(result,status='Passed' if result['status']=='Passed' else 'Failed' if result['status']=='Not passed' else 'Not Available')
    data['diff']=clean(source_diff(original,edited,'reviewed-source'),known)
    return data
