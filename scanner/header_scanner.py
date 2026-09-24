from scanner.common import baseline, issue


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
    if frame not in ('DENY','SAMEORIGIN') and 'frame-ancestors' not in csp:
        issue(ctx,'Missing or invalid framing protection','Low','Security Headers','Neither a valid X-Frame-Options value nor CSP frame-ancestors was observed.','Set CSP frame-ancestors and optionally X-Frame-Options to restrict embedding.','High')
    if response.header('Referrer-Policy').lower().strip() == 'unsafe-url':
        issue(ctx,'Permissive Referrer-Policy','Low','Security Headers','Referrer-Policy uses unsafe-url.','Use strict-origin-when-cross-origin or no-referrer.','High')
    if response.url.startswith('https:'):
        import re
        hsts = response.header('Strict-Transport-Security')
        match = re.search(r'(?i)max-age\s*=\s*(\d+)', hsts)
        if not match or int(match.group(1)) == 0:
            issue(ctx,'Missing or disabled HSTS','Low','Security Headers','HTTPS response lacks an active HSTS max-age.','Enable HSTS after confirming HTTPS works for the intended scope.','High')
    return {'headers_present':checked, 'framing_protection':frame in ('DENY','SAMEORIGIN') or 'frame-ancestors' in csp, 'hsts_applicable':response.url.startswith('https:')}
