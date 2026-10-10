import secrets
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from bs4 import BeautifulSoup
from scanner.common import baseline, issue
from scanner.target import safe_url


def parameter_urls(url, value_function):
    p = urlsplit(url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    for index, (name, value) in enumerate(pairs[:5]):
        # Avoid replaying obvious state-changing query parameters.
        if name.lower() in ('delete','remove','logout','action','command','cmd','execute','token','password','secret','api_key','key'):
            continue
        changed = pairs.copy()
        changed[index] = (name, value_function(value))
        yield name, urlunsplit((p.scheme,p.netloc,p.path,urlencode(changed),'')), changed[index][1]


def run(ctx):
    response = baseline(ctx)
    observations = []
    for name, url, marker in parameter_urls(response.url, lambda _: 'ssprobe' + secrets.token_hex(10)):
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
