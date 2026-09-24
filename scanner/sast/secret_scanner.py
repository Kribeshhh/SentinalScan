import ast
import re
from analysis.redaction import TOKEN_PATTERNS, ASSIGNMENT, plausible
from scanner.sast.common import add, check_budget


def run(ctx):
    detected=0
    for path in ctx['paths']:
        check_budget(ctx)
        text=(ctx['root']/path).read_text(encoding='utf-8-sig')
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
                        if re.search(r'password|passwd|secret|token|api_?key|credential|database_url|db_url',names,re.I) and plausible(value):
                            matches.append((node.lineno,'Hardcoded credential',value,'Medium'))
            except (SyntaxError,ValueError,RecursionError):
                pass
        else:
            for match in ASSIGNMENT.finditer(text):
                value=match.group(2) or match.group(3)
                if plausible(value):
                    # Skip obvious unquoted code identifiers; .env/properties commonly use unquoted values.
                    config=path.rsplit('/',1)[-1].startswith('.env') or path.endswith(('.properties','.yml','.yaml','.ini','.cfg','.conf'))
                    if not match.group(2) and not config and re.fullmatch(r'[A-Za-z_$][\w.$]*(?:\([^)]*\))?',value):
                        continue
                    matches.append((text.count('\n',0,match.start())+1,'Potential embedded credential',value,'Medium'))
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
