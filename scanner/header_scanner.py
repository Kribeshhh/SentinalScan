import re
from scanner.common import baseline, issue


def framing_protected(csp, frame):
    policies = []
    for policy in csp.split(','):
        for directive in policy.split(';'):
            tokens = directive.strip().lower().split()
            if not tokens or tokens[0] != 'frame-ancestors':
                continue
            sources = tokens[1:]
            # The first occurrence of a directive wins. An enforced CSP framing
            # directive supersedes XFO; bare wildcards/schemes do not constrain it.
            restrictive = bool(sources) and all(
                source in ("'self'", "'none'") or re.fullmatch(
                    r'(?:https?://)?(?:\*\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::(?:[0-9]+|\*))?(?:/[^\s;]*)?', source)
                for source in sources)
            policies.append(restrictive)
            break
    return any(policies) if policies else frame in ('DENY', 'SAMEORIGIN')


def run(ctx):
    response = baseline(ctx)
    if not response.html:
        return {'note':'HTML-specific headers not assessed for non-HTML content.'}
    checks = [
        ('Content-Security-Policy','Low','Define a restrictive CSP appropriate to the application.'),
        ('X-Content-Type-Options','Low','Set X-Content-Type-Options: nosniff.'),
        ('Referrer-Policy','Low','Use strict-origin-when-cross-origin or a stricter referrer policy.'),
        ('Permissions-Policy','Informational','Restrict browser capabilities not needed by the application.'),
    ]
    checked = {}
    for header, severity, recommendation in checks:
        value = response.header(header)
        checked[header] = bool(value)
        if not value:
            issue(ctx, 'Missing ' + header, severity, 'Security Headers', header + ' was absent on the HTML response.', recommendation, 'High')
    csp = response.header('Content-Security-Policy').lower()
    if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
        issue(ctx,'Permissive Content-Security-Policy','Low','Security Headers','CSP contains unsafe-inline or unsafe-eval; effective policy requires manual review.','Use nonces or hashes and remove unnecessary unsafe execution sources.','Low')
    if response.header('X-Content-Type-Options') and response.header('X-Content-Type-Options').lower().strip() != 'nosniff':
        issue(ctx,'Invalid MIME sniffing protection','Low','Security Headers','X-Content-Type-Options is not nosniff.','Set X-Content-Type-Options: nosniff.','High')
    frame = response.header('X-Frame-Options').upper().strip()
    protected = framing_protected(csp, frame)
    if not protected:
        issue(ctx,'Missing or invalid framing protection','Low','Security Headers','No restrictive framing policy was observed; an enforced CSP frame-ancestors directive takes precedence over X-Frame-Options.','Set CSP frame-ancestors and optionally X-Frame-Options to restrict embedding.','High')
    if response.header('Referrer-Policy').lower().strip() == 'unsafe-url':
        issue(ctx,'Permissive Referrer-Policy','Low','Security Headers','Referrer-Policy uses unsafe-url.','Use strict-origin-when-cross-origin or no-referrer.','High')
    if response.url.startswith('https:'):
        import re
        hsts = response.header('Strict-Transport-Security')
        match = re.search(r'(?i)max-age\s*=\s*(\d+)', hsts)
        if not match or int(match.group(1)) == 0:
            issue(ctx,'Missing or disabled HSTS','Low','Security Headers','HTTPS response lacks an active HSTS max-age.','Enable HSTS after confirming HTTPS works for the intended scope.','High')
    return {'headers_present':checked, 'framing_protection':protected, 'hsts_applicable':response.url.startswith('https:')}
