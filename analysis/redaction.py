"""Persist redacted evidence rather than relying on a particular UI/export to hide secrets."""
import re

TOKEN_PATTERNS=[
    ('GitHub token',r'\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{30,255})\b'),
    ('AWS access key',r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    ('Google API key',r'\bAIza[A-Za-z0-9_-]{30,50}\b'),
    ('Stripe secret key',r'\bsk_live_[A-Za-z0-9]{16,200}\b'),
    ('JWT',r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'),
    ('Private key',r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----'),
]
ASSIGNMENT=re.compile(r'''(?im)(?:["']?)([\w.-]{0,80}(?:password|passwd|api[_-]?key|access[_-]?token|auth[_-]?token|secret|credential|database[_-]?url|db[_-]?url|aws[_-]?access[_-]?key[_-]?id)[\w.-]{0,80})(?:["']?)\s*[:=]\s*(?:["']([^"'\r\n]{4,500})["']|([^\s,;#\r\n]{4,500}))''')
PLACEHOLDERS={'example','changeme','change_me','your_api_key','your_secret','your_token','your_password','password','secret','test','testing','dummy','placeholder','redacted','none','null','true','false'}


def plausible(value):
    lowered=value.lower().strip()
    placeholder=re.fullmatch(r'(?:replace[-_ ]?me|(?:your|example|dummy|test)[-_ ](?:api[-_ ]?key|token|password|secret)(?:[-_ ]here)?)',lowered)
    return (not placeholder and len(value)>=6 and lowered not in PLACEHOLDERS and not any(t in lowered for t in ('your_','your-','example','changeme','placeholder','${','{{','process.env','os.environ','os.getenv','getenv(', 'system.getenv'))
            and not value.startswith(('<','[redacted','*','env(','getenv(','config(')) and len(set(value))>2)


def redact_text(text,known=()):
    result=str(text)
    for value in sorted(set(known),key=len,reverse=True):
        if value:
            result=result.replace(value,'[REDACTED]')
    # Mask URL userinfo and HTTP credentials even when no typed-token pattern matches.
    result = re.sub(r'(?i)(https?://)[^/\s@]+@', r'\1[REDACTED]@', result)
    result = re.sub(r'(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{4,}', r'\1 [REDACTED]', result)
    for _,pattern in TOKEN_PATTERNS:
        result=re.sub(pattern,'[REDACTED]',result)
    def assignment(match):
        value=match.group(2) or match.group(3)
        return match.group(0).replace(value,'[REDACTED]') if plausible(value) else match.group(0)
    return ASSIGNMENT.sub(assignment,result)


def scrub(value,known=()):
    if isinstance(value,str):
        return redact_text(value,known)
    if isinstance(value,dict):
        def protected(key,item):
            if isinstance(item,str) and re.search(r'(?i)(?:^|[_ .-])(?:password|passwd|token|secret|api_key|private_key|authorization|set-cookie)(?:$|[_ .-])',str(key)):
                return '[REDACTED]'
            return scrub(item,known)
        return {redact_text(k,known):protected(k,v) for k,v in value.items()}
    if isinstance(value,(list,tuple)):
        return [scrub(item,known) for item in value]
    return value
