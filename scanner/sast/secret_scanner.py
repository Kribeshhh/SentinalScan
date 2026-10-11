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
    # Only recognizable instructional prose in documentation is suppressed;
    # spaced passphrases in source/configuration remain credential candidates.
    if PurePosixPath(path).suffix.lower() in ('.md', '.rst') and re.fullmatch(
        r'(?i)(?:enter|type|choose) (?:your |the |an? )?(?:account )?(?:memorable |strong |secure )?(?:password|passphrase)(?: for your account| to [a-z ]+)?[.!]?', value.strip()):
        return False
    return plausible(value)


def credential_uses(tree, ctx):
    """Bounded straight-line Python literal flow to imported credential APIs.

    No entropy guesses, execution, or cross-file identity inference. Branches and
    complex control flow invalidate tracked values rather than inventing flow.
    Values remain transient and are added to the existing redaction set by run().
    """
    matches=[]
    database={'psycopg.connect','psycopg2.connect','pymysql.connect','mysql.connector.connect'}
    def block(nodes, imports=None):
        identities=dict(imports or {}); literals={}
        def identity(node):
            if isinstance(node,ast.Name):return identities.get(node.id,'')
            if isinstance(node,ast.Attribute):return identity(node.value)+'.'+node.attr
            return ''
        def value(node):
            if isinstance(node,ast.Constant) and isinstance(node.value,str):return node.value,node.lineno
            if isinstance(node,ast.Name):return literals.get(node.id)
            return None
        def inspect(node):
            if node is None or isinstance(node,(ast.Lambda,ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):return
            if isinstance(node,ast.Call):
                fn=identity(node.func);candidates=[]
                if fn in database:
                    candidates=[k.value for k in node.keywords if k.arg in ('password','passwd')]
                elif fn=='requests.auth.HTTPBasicAuth' and len(node.args)==2:
                    candidates=[node.args[1]]
                for candidate in candidates:
                    resolved=value(candidate)
                    if resolved and credential_assignment('source.py','password',resolved[0]):
                        matches.append((resolved[1],'Hardcoded credential',resolved[0]))
            for child in ast.iter_child_nodes(node):inspect(child)
        for node in nodes:
            check_budget(ctx)
            if isinstance(node,(ast.Import,ast.ImportFrom)):
                for alias in node.names:
                    key=alias.asname or (alias.name.split('.')[0] if isinstance(node,ast.Import) else alias.name)
                    identities[key]=(alias.name if alias.asname else alias.name.split('.')[0]) if isinstance(node,ast.Import) else '.'*node.level+(node.module or '')+'.'+alias.name
                    literals.pop(key,None)
            elif isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                # Local stores/parameters shadow outer imports even before assignment.
                shadow={n.id for n in ast.walk(node) if isinstance(n,ast.Name) and isinstance(n.ctx,(ast.Store,ast.Del))}
                shadow.update(n.arg for n in ast.walk(node) if isinstance(n,ast.arg))
                shadow.update(n.name for n in ast.walk(node) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)))
                for child in ast.walk(node):
                    if isinstance(child,(ast.Import,ast.ImportFrom)):
                        shadow.update(a.asname or (a.name.split('.')[0] if isinstance(child,ast.Import) else a.name) for a in child.names)
                block(node.body,{k:v for k,v in identities.items() if k not in shadow})
                identities.pop(node.name,None);literals.pop(node.name,None)
            elif isinstance(node,(ast.Assign,ast.AnnAssign)):
                inspect(node.value);resolved=value(node.value)
                for target in node.targets if isinstance(node,ast.Assign) else [node.target]:
                    for child in ast.walk(target):
                        if isinstance(child,ast.Name):
                            identities.pop(child.id,None);literals.pop(child.id,None)
                    if isinstance(target,ast.Name) and resolved:literals[target.id]=resolved
            elif isinstance(node,ast.Expr):inspect(node.value)
            elif isinstance(node,(ast.Return,ast.Raise)):
                inspect(node.value if isinstance(node,ast.Return) else node.exc);break
            else:
                # No claim about assignments surviving loops, exceptions, dynamic
                # attribute writes or other unmodeled scope/control-flow constructs.
                literals.clear();identities.clear()
    block(tree.body)
    return matches


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
                matches.extend((line,label,value,'Low' if docs else 'Medium') for line,label,value in credential_uses(tree,ctx))
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
                    if not match.group(2) and not config and re.fullmatch(r'[A-Za-z_$][\w.$]*(?:\([^)]*\))?[)\]}]*',value):
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
