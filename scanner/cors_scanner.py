from scanner.common import baseline, issue


def run(ctx):
    response = baseline(ctx)
    origin = 'https://sentinelscan-probe.invalid'
    probe = ctx['client'].get(response.url, headers={'Origin':origin})
    allow = probe.header('Access-Control-Allow-Origin').strip()
    credentials = probe.header('Access-Control-Allow-Credentials').lower().strip()
    observation={'request_origin':origin,'allow_origin':allow[:200],'allow_credentials':credentials[:30]}
    if allow == origin and credentials == 'true':
        issue(ctx,'Potential unsafe credentialed CORS','Medium','CORS','The response allowed the untrusted test Origin and credentials. No authenticated data was requested.','Use an explicit allowlist of trusted origins and enable credentials only when required.','Medium',response=probe,observations={'cors':observation})
    elif allow == origin:
        issue(ctx,'Potential arbitrary CORS origin reflection','Low','CORS','The response reflected the untrusted test Origin without credentials.','Confirm that cross-origin public access is intended; otherwise use a strict origin allowlist.','Low',response=probe,observations={'cors':observation})
    elif allow == '*' and credentials == 'true':
        issue(ctx,'Incompatible wildcard credentialed CORS','Informational','CORS','ACAO is * and ACAC is true. Browsers reject this combination for credentialed reads.','Use an explicit trusted origin for credentialed responses or remove credential support.','High',response=probe,observations={'cors':observation})
    return {'test_origin':origin, 'allow_origin':allow[:200], 'allow_credentials':credentials[:30], 'allow_methods':probe.header('Access-Control-Allow-Methods')[:300], 'allow_headers':probe.header('Access-Control-Allow-Headers')[:300], 'note':'GET response inspection only; no authentication or preflight enumeration.'}
