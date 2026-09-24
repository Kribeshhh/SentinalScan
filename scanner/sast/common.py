from analysis.finding_engine import Finding
import time


def check_budget(ctx):
    if time.monotonic() > ctx['deadline']:
        raise TimeoutError('Source analysis budget reached')


def add(ctx,path,line,title,category,evidence,recommendation,severity='Medium',confidence='Medium',impact=None):
    if len(ctx['findings'])>=1500:
        ctx['capped']=True
        return
    ctx['findings'].append(Finding(title=title,severity=severity,confidence=confidence,category=category,source='Repository',
        location=ctx['repository']+'/'+path+(':'+str(line) if line else ''),
        description=title+' was identified by static analysis. Review the surrounding code and data flow before treating it as exploitable.',
        evidence=evidence,recommendation=recommendation,
        impact=impact or 'If reachable with untrusted or sensitive data, this pattern can compromise confidentiality or integrity. Static analysis does not establish runtime reachability.'))


def files(ctx,suffixes):
    for path in ctx['paths']:
        check_budget(ctx)
        if any(path.lower().endswith(suffix) for suffix in suffixes):
            yield path,(ctx['root']/path).read_text(encoding='utf-8-sig')
