import secrets
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from bs4 import BeautifulSoup
from scanner.common import baseline, issue
from scanner.target import safe_url


def parameter_urls(url, value_function, reviewed_queries=None):
    """Only operator-reviewed full query URLs permit explicitly reviewed positions.

    A review covers replay of the WHOLE endpoint/query and mutation of these positions.
    Parameter names and private-address opt-in confer no safety approval.
    """
    from scanner.common import SkipModule
    p = urlsplit(url)
    if not p.query:
        return
    reviews = reviewed_queries or {}
    if url not in reviews:
        raise SkipModule('Query replay safety: this full URL has not been reviewed as inert; active requests skipped.')
    positions = reviews[url]
    raw = p.query.split('&')
    if not isinstance(positions, (list, tuple)) or any(type(i) is not int or i < 0 or i >= len(raw) for i in positions):
        raise SkipModule('Query replay safety: invalid trusted review configuration.')
    if not positions:
        raise SkipModule('Query replay safety: no parameter positions reviewed for mutation.')
    for index in list(dict.fromkeys(positions))[:5]:
        pair = parse_qsl(raw[index], keep_blank_values=True)
        if len(pair) != 1:
            raise SkipModule('Query replay safety: ambiguous query component.')
        name, value = pair[0]
        replacement = value_function(value)
        changed = raw.copy()
        # Preserve every unrelated byte, duplicate, blank and original name encoding.
        from urllib.parse import quote_plus
        changed[index] = raw[index].split('=', 1)[0] + '=' + quote_plus(replacement)
        yield name, urlunsplit((p.scheme, p.netloc, p.path, '&'.join(changed), '')), replacement


def run(ctx):
    response = baseline(ctx)
    observations = []
    for name, url, marker in ctx['client'].parameter_urls(response.url, lambda _: 'ssprobe' + secrets.token_hex(10)):
        probe = ctx['client'].get(url)
        if marker not in probe.text:
            observations.append({'parameter':name,'reflected':False})
            continue
        contexts = set()
        if probe.html:
            soup = BeautifulSoup(probe.text,'html.parser')
            for tag in soup.find_all(True):
                if tag.find_parent('template') is not None:
                    continue
                if tag.name == 'script' and marker in tag.get_text():
                    script_type = str(tag.get('type', '')).strip().lower().split(';', 1)[0]
                    executable = script_type in ('', 'module', 'text/javascript', 'application/javascript',
                        'text/ecmascript', 'application/ecmascript', 'application/x-javascript')
                    contexts.add('script text' if executable else 'inert script data')
                for attr, value in tag.attrs.items():
                    if marker in str(value):
                        contexts.add('event-handler attribute' if attr.lower().startswith('on') else 'HTML attribute')
            if not contexts:
                contexts.add('HTML text')
        else:
            contexts.add('non-HTML response')
        observations.append({'parameter':name, 'reflected':True,'contexts':sorted(contexts)})
        if contexts & {'script text','event-handler attribute'}:
            issue(ctx,'Potential Reflected XSS','Low','Reflected XSS',f'A harmless alphanumeric marker for parameter {name} appeared in: {", ".join(sorted(contexts))}. No script execution or escaping bypass was demonstrated.','Review contextual output encoding and avoid interpolation into JavaScript or event handlers.','Low',location=safe_url(response.url) + ' [parameter: ' + name + ']',response=probe,observations={'parameter':name,'reflection_contexts':sorted(contexts)})
    return {'parameters':observations,'note':'Harmless markers only. Reflection in ordinary text/attributes is recorded without a vulnerability claim. JavaScript is not executed.'}
