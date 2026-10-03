import json
from analysis.finding_context import website_context
from analysis.finding_engine import Finding
from scanner.target import safe_url


class SkipModule(Exception):
    pass


def issue(ctx, title, severity, category, evidence, recommendation, confidence='Medium', location=None, description=None, impact=None, response=None, observations=None):
    context=website_context(ctx,response,observations)
    context['scanner_evidence']=evidence
    finding = Finding(title=title, severity=severity, confidence=confidence, category=category,
        source='Website', location=location or safe_url(ctx['target'].url),
        description=description or title + ' was observed during a bounded website assessment.',
        evidence=evidence, impact=impact or 'This condition may weaken application security; validate its effect in the application context.',
        recommendation=recommendation, context_json=json.dumps(context))
    ctx['findings'].append(finding)


def baseline(ctx):
    if ctx.get('response') is None:
        raise SkipModule('No usable HTTP response; prerequisite request failed.')
    return ctx['response']
