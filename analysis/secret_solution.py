"""Read only assignment names; never include a secret literal in a recommendation."""
import ast
import re
from pathlib import PurePosixPath
from analysis.source_context import mask_source


def secret_context(finding,source,result):
    match=re.search(r':(\d+)$',finding['location'])
    if not match:return
    line=int(match[1]);lines=mask_source(source).splitlines()
    result['context']='\n'.join(f'{n:>4} {">" if n==line else " "} {lines[n-1][:1000]}' for n in range(max(1,line-3),min(len(lines),line+3)+1))
    result['source_status']='Redacted context from scanned source. No secret value is included in the recommendation.'
    if PurePosixPath(finding['location'][:match.start()]).suffix.lower()!='.py':return
    try:tree=ast.parse(source)
    except (SyntaxError,ValueError,RecursionError):return
    assignments=[n for n in ast.walk(tree) if isinstance(n,ast.Assign) and n.lineno==line and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and isinstance(n.value,ast.Constant) and isinstance(n.value.value,str)]
    if len(assignments)!=1:return
    name=assignments[0].targets[0].id
    result['assignment_name']=name
    result['secret_example']={'language':'Python · runtime configuration example','kind':'Illustrative Secure Example',
        'code':'import os\n\n'+name+' = os.environ['+repr(name.upper())+']\n'}
