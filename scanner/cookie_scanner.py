from http.cookies import SimpleCookie
from scanner.common import baseline, issue


def run(ctx):
    response = baseline(ctx)
    inventory = []
    malformed = 0
    for name, value in response.headers:
        if name.lower() != 'set-cookie':
            continue
        cookie = SimpleCookie()
        try:
            cookie.load(value)
        except Exception:
            malformed += 1
            continue
        if not cookie:
            malformed += 1
        for key, morsel in cookie.items():
            # Names and attribute flags only; values never leave transient memory.
            attributes = {'name':key, 'secure':bool(morsel['secure']), 'httponly':bool(morsel['httponly']), 'samesite':morsel['samesite'] if morsel['samesite'].lower() in ('strict','lax','none') else 'Missing/invalid'}
            inventory.append(attributes)
            for attribute, ok in [('Secure', attributes['secure']), ('HttpOnly', attributes['httponly']), ('SameSite', morsel['samesite'].lower() in ('strict','lax','none'))]:
                if not ok:
                    issue(ctx, 'Cookie missing ' + attribute + ': ' + key, 'Low', 'Cookie Security', 'Cookie name: ' + key + '; missing or invalid ' + attribute + '. Value omitted.', 'Set appropriate cookie attributes; verify whether this cookie carries authentication or other sensitive state.', 'High',observations={'cookie_attributes':attributes})
            if morsel['samesite'].lower() == 'none' and not attributes['secure']:
                issue(ctx,'SameSite=None cookie without Secure: ' + key,'Low','Cookie Security','SameSite=None requires Secure; cookie value omitted.','Set Secure for SameSite=None cookies or choose Lax/Strict.','High',observations={'cookie_attributes':attributes})
    return {'cookies':inventory, 'unparsed_headers':malformed, 'note':'Only cookies on the final baseline response are assessed. Cookie values are never stored.'}
