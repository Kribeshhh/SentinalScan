from analysis.finding_engine import Finding
from dataclasses import replace
import json
from scanner.sast.evidence import normalized
import time


def check_budget(ctx):
    if time.monotonic() > ctx['deadline']:
        raise TimeoutError('Source analysis budget reached')


def add(ctx,path,line,title,category,evidence,recommendation,severity='Medium',confidence='Medium',impact=None,semantic=None):
    if len(ctx['findings'])>=1500:
        ctx['capped']=True
        return
    finding=Finding(title=title,severity=severity,confidence=confidence,category=category,source='Repository',
        location=ctx['repository']+'/'+path+(':'+str(line) if line else ''),
        description=title+' was identified by static analysis. Review the surrounding code and data flow before treating it as exploitable.',
        evidence=evidence,recommendation=recommendation,
        impact=impact or 'If reachable with untrusted or sensitive data, this pattern can compromise confidentiality or integrity. Static analysis does not establish runtime reachability.')
    from analysis.finding_context import repository_context
    context=repository_context(vars(finding))
    context["analysis"]=normalized(finding,ctx["repository"],path,line,semantic)
    # Only disambiguate colliding semantic occurrences. Ordinary/legacy finding
    # fingerprints and display locations stay unchanged. Re-analysis of the same
    # AST operation still deduplicates.
    if semantic is not None:
        for index, prior in enumerate(ctx['findings']):
            if (prior.source, prior.category, prior.title, prior.location) != (finding.source, finding.category, finding.title, finding.location):
                continue
            previous = json.loads(prior.context_json)
            detail = previous.get('analysis', {})
            column = detail.get('start_column')
            if type(column) is int and (column != semantic.start_column or 'occurrence_column' in detail):
                detail['occurrence_column'] = column
                context['analysis']['occurrence_column'] = semantic.start_column
                ctx['findings'][index] = replace(prior, context_json=json.dumps(previous))
    ctx["findings"].append(replace(finding,context_json=json.dumps(context)))


def files(ctx,suffixes):
    for path in ctx['paths']:
        check_budget(ctx)
        if any(path.lower().endswith(suffix) for suffix in suffixes):
            yield path,(ctx['root']/path).read_text(encoding='utf-8-sig')


def parse_diagnostic(path, error):
    """Safe structural diagnostics only: exception text may contain credentials."""
    category = type(error).__name__
    reason = 'Unsupported or malformed syntax; this file was not assessed by this parser.'
    if isinstance(error, SyntaxError) and "Missing parentheses in call to 'print'" in error.msg:
        reason = 'Legacy Python print syntax is unsupported by the Python 3 AST parser; no automatic conversion was attempted.'
    elif isinstance(error, UnicodeError):
        category = 'EncodingError'
        reason = 'File is not supported UTF-8 text.'
    elif isinstance(error, OSError):
        category = 'ReadError'
        reason = 'File could not be read safely.'
    elif isinstance(error, RecursionError):
        reason = 'Parser nesting limit reached.'
    mark = getattr(error, 'problem_mark', None)
    line = getattr(error, 'lineno', None)
    column = getattr(error, 'offset', getattr(error, 'colno', None))
    if mark is not None:
        line, column = mark.line + 1, mark.column + 1
    return {'path': path, 'category': category, 'line': line, 'column': column,
            'status': 'Not parsed', 'reason': reason,
            'other_engine_assessment': 'Not established per file; consult separate engine coverage. Enabled or zero findings does not prove assessment.'}
