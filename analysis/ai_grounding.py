"""Closed, deterministic grounding policy for optional recommendation refinement.

This is a validator for the existing AI pipeline, not a detector or truth oracle.
Unverifiable free-form claims fail closed. Raw evidence is never an allowlist of
instructions. The model may select approved statements and propose checked code.
"""
import re

EXPLANATION = 'The scanner reported a potential issue; exploitability has not been verified.'
IMPACT = 'If the reported condition is reachable, it may affect application security. Review the recorded evidence and deployment context.'
ACTION = 'Review the affected operation and apply the deterministic recommendation after checking the recorded evidence.'
FOLLOWUP = 'Test intended behavior and re-scan after implementing the change.'
UNCERTAINTY = 'The available context does not establish runtime reachability or existing protections.'


def statements(finding):
    """Reconstruct support from deterministic policy, never from model-supplied lists.

    Do not whitelist raw descriptions, recommendations, headers or snippets: they
    can contain instructions, quotes of unsafe code, or attacker-authored text.
    """
    from analysis.solution_engine import solution_for
    f = dict(finding)
    # Unknown rule fallback can echo an untrusted recommendation. Exclude it.
    base = solution_for(dict(f, recommendation='Review the recorded evidence.'))
    result = {'reason': [EXPLANATION, UNCERTAINTY], 'why': [IMPACT],
              'what_to_change': [ACTION], 'additional_actions': [FOLLOWUP]}
    for field, key in (('what_to_change', 'action'), ('why', 'why')):
        text = base.get(key)
        if isinstance(text, str) and text.strip() and len(text) <= 2000 and 'could not be established' not in text:
            result[field].append(text)
    title = f.get('title', '').lower()
    category = f.get('category')
    if 'dom html' in title:
        result['reason'].append('The scanner identified a dynamic HTML assignment. Static evidence alone does not prove script execution.')
        result['what_to_change'].append('Use text rendering when markup is not required; otherwise review an appropriate HTML sanitizer for the actual application.')
    if 'sql injection' in title:
        result['reason'].append('The scanner reported a potential SQL injection indicator. Query construction and input handling require review; exploitation was not verified.')
        result['why'].append('When untrusted values become SQL syntax, query behavior may change. Bound parameters keep values separate from SQL structure.')
    if 'shell' in title or 'process execution' in title:
        result['reason'].append('The scanner reported potentially unsafe process execution. The intended command and input trust boundary need review.')
    if category == 'Dependency':
        result['reason'].append('The scanner matched a declared dependency to recorded advisory data. Installed versions and runtime reachability were not verified.')
    if category == 'Security Headers' and 'x-content-type-options' in title:
        result['reason'].append('The scanner reported a missing X-Content-Type-Options header on the inspected response.')
        result['what_to_change'].append('Set X-Content-Type-Options to nosniff at the response-producing layer and verify the deployed response.')
        result['why'].append('The nosniff policy limits MIME sniffing; it does not establish that an attack occurred.')
    if category == 'Secret Exposure':
        # No raw finding metadata or values enter allowed statements for secrets.
        result = {'reason': ['A credential pattern was detected; its validity was not tested.'],
                  'why': ['A real exposed credential could permit unauthorized access.'],
                  'what_to_change': ['Remove the embedded credential, rotate or revoke it if real, and use protected runtime configuration.'],
                  'additional_actions': [FOLLOWUP]}
    return {k: list(dict.fromkeys(v)) for k, v in result.items()}



def prompt_statements(finding, known=()):
    # Redact BEFORE serialization, including advisory-derived version strings.
    from analysis.llm_review import clean
    return {key: [clean(value, known) for value in reversed(values)]
            for key, values in statements(finding).items()}


def validate_grounding(finding, payload, answer):
    """Unsupported claims, including clever paraphrases, are not promoted.

    Exact approved statements avoid pretending a blacklist can verify arbitrary
    natural language. A model confidence score and a second model are not evidence.
    """
    support = statements(finding)
    rec = answer['recommendation']
    for key, value in (('reason', answer['reason']), ('why', rec['why']),
                       ('what_to_change', rec['what_to_change'])):
        if value.strip() not in support[key]:
            raise ValueError('AI statement is not grounded in deterministic guidance')
    if any(v.strip() not in support['additional_actions'] for v in rec['additional_actions']):
        raise ValueError('Unsupported AI follow-up')
    if finding['category'] == 'Secret Exposure':
        return  # process() removes all secret code before storage.
    code = rec['suggested_code_or_config']
    if code and finding['source']=='Website' and finding['category'] in ('TLS','Transport Security'):
        title=finding['title'].lower()
        if not any(term in title for term in ('protocol','tls version','ssl version')):
            raise ValueError('TLS configuration cannot repair this observed condition')
    if code and finding['source'] == 'Website' and finding['category'] == 'Security Headers':
        title = finding['title'].lower()
        names = {line.partition(':')[0].strip().lower() for line in code.splitlines() if line.strip()}
        required = next((h for h in ('x-content-type-options', 'content-security-policy', 'x-frame-options',
                                     'strict-transport-security', 'referrer-policy', 'permissions-policy') if h in title), None)
        if required is None or names != {required}:
            raise ValueError('Configuration does not match the affected header')
    if not code or rec['example_type'] == 'source_specific' or finding['source'] == 'Website':
        return
    # No free-form illustrative programs: keep the existing deterministic pattern.
    # Source-specific proposals still pass the shared parse/rule/diff validator.
    raise ValueError('Unvalidated repository example; retain deterministic pattern')


def header_example(code, category):
    """Small safe-value subset. Unsupported valid configurations also fall back.

    This is not deployment validation. Deliberately no arbitrary CSP origins,
    cipher strings, nginx applications, permissive CORS or real cookie values.
    """
    if not code:
        return True
    lines = [line.strip() for line in code.splitlines() if line.strip()]
    if not lines or len(lines) > 8:
        return False
    if category in ('TLS', 'Transport Security'):
        return len(set(lines)) == len(lines) and all(line in {
            'ssl_protocols TLSv1.2 TLSv1.3;', 'ssl_protocols TLSv1.3;',
            'ssl_session_tickets off;', 'ssl_prefer_server_ciphers on;'
        } for line in lines)
    allowed = {
        'Security Headers': {
            'x-content-type-options': {'nosniff'},
            'x-frame-options': {'DENY', 'SAMEORIGIN'},
            'referrer-policy': {'no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'},
            'content-security-policy': {"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"},
            'permissions-policy': {'camera=(), microphone=(), geolocation=()'},
            'strict-transport-security': {'max-age=31536000'},
        },
        'CORS': {'access-control-allow-origin': {'https://trusted.example'},
                 'access-control-allow-credentials': {'true'},
                 'access-control-allow-methods': {'GET, HEAD'},
                 'access-control-allow-headers': {'Content-Type'}, 'vary': {'Origin'}},
    }
    seen = set()
    for line in lines:
        name, sep, value = line.partition(':')
        name, value = name.lower(), value.strip()
        if not sep or name in seen:
            return False
        seen.add(name)
        if category == 'Cookie Security':
            if name != 'set-cookie' or not re.fullmatch(
                r'[A-Za-z0-9_-]+=\[REDACTED\]; (?:Path=/; )?Secure; HttpOnly; SameSite=(?:Lax|Strict)', value):
                # Accept the other common order without loosening attributes.
                if name != 'set-cookie' or not re.fullmatch(
                    r'[A-Za-z0-9_-]+=\[REDACTED\]; HttpOnly; Secure; SameSite=(?:Lax|Strict)', value):
                    return False
        elif value not in allowed.get(category, {}).get(name, set()):
            return False
    if category == 'CORS':
        return {'access-control-allow-origin', 'vary'} <= seen
    return category in ('Security Headers', 'Cookie Security')
