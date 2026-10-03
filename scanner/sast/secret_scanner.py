import ast
import re
from pathlib import PurePosixPath
from analysis.redaction import TOKEN_PATTERNS, ASSIGNMENT, plausible
from scanner.sast.common import add, check_budget


def credential_assignment(path,key,value):
    # Translated UI/challenge prose is data, not an authentication setting. Typed
    # tokens and private keys are still detected in these files by TOKEN_PATTERNS.
    if path.lower().endswith('.json') and any(part.lower() in ('i18n','locales','translations') for part in path.split('/')):
        return False
    key=re.sub(r'([a-z])([A-Z])',r'\1_\2',key).lower()
    if not re.fullmatch(r'(?:[a-z0-9]+[_.-])*(?:password|passwd|secret(?:[_-]?key)?|token|api[_-]?key|access[_-]?token|auth[_-]?token|credential|database[_-]?url|db[_-]?url|aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key)',key):
        return False
    if re.fullmatch(r'\$[A-Za-z_][A-Za-z0-9_]*',value.strip()):return False
    if re.fullmatch(r'(?i)(?:dummy|test|sample|fake)[_-](?:password|token|secret|key)(?:[_-]\d+)?',value.strip()):return False
    return plausible(value)


def run(ctx):
    detected=0
    for path in ctx['paths']:
        check_budget(ctx)
        text=(ctx['root']/path).read_text(encoding='utf-8-sig')
        docs=PurePosixPath(path).suffix.lower() in ('.md','.rst') or any(part.lower() in ('docs','examples','fixtures') for part in PurePosixPath(path).parts)
        matches=[]
        for label,pattern in TOKEN_PATTERNS:
            for match in re.finditer(pattern,text):
                if label=='Private key' or plausible(match.group()):
                    matches.append((text.count('\n',0,match.start())+1,label,match.group(),'High'))
        if path.endswith('.py'):
            try:
                tree=ast.parse(text)
                for node in ast.walk(tree):
                    if isinstance(node,(ast.Assign,ast.AnnAssign)) and isinstance(node.value,ast.Constant) and isinstance(node.value.value,str):
                        targets=node.targets if isinstance(node,ast.Assign) else [node.target]
                        names=' '.join(t.id if isinstance(t,ast.Name) else t.attr if isinstance(t,ast.Attribute) else '' for t in targets)
                        value=node.value.value
                        if any(credential_assignment(path,name,value) for name in names.split()):
                            matches.append((node.lineno,'Hardcoded credential',value,'Low' if docs else 'Medium'))
            except (SyntaxError,ValueError,RecursionError):
                pass
        else:
            for match in ASSIGNMENT.finditer(text):
                value=match.group(2) or match.group(3)
                if credential_assignment(path,match.group(1),value):
                    # Skip obvious unquoted code identifiers; .env/properties commonly use unquoted values.
                    config=path.rsplit('/',1)[-1].startswith('.env') or path.endswith(('.properties','.yml','.yaml','.ini','.cfg','.conf'))
                    if not match.group(2) and not config and re.fullmatch(r'[A-Za-z_$][\w.$]*(?:\([^)]*\))?',value):
                        continue
                    matches.append((text.count('\n',0,match.start())+1,'Potential embedded credential',value,'Low' if docs else 'Medium'))
        seen=set()
        for line,label,value,confidence in matches:
            ctx['secrets'].add(value)
            if (line,value) in seen:
                continue
            seen.add((line,value));detected+=1
            add(ctx,path,line,label,'Secret Exposure',f'{label} pattern detected. Value: [REDACTED]. No validity check or authentication attempt was made.',
                'Remove the credential from source and history, rotate it if real, and load it from a secret manager or environment.',
                severity='High',confidence=confidence,impact='If this is a valid credential, repository readers may be able to access the associated service or data.')
    return {'potential_secrets':detected,'values_retained':False,'note':'Candidates are not tested against services. Placeholders are suppressed. False positives remain possible.'}
