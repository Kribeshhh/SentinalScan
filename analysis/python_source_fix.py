"""Conservative SQL parameterization for directly established Python DB-API cursors."""
import ast
import re
from analysis.source_validation import validate_candidate


def sql_candidate(finding,source):
    if finding['title']!='Potential SQL injection in constructed query':return None
    try:tree=ast.parse(source);line=int(finding['location'].rsplit(':',1)[1])
    except (SyntaxError,ValueError):return None
    calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and n.lineno==line and isinstance(n.func,ast.Attribute) and n.func.attr=='execute']
    if len(calls)!=1:return None
    call=calls[0]
    if len(call.args)!=1 or call.keywords or not isinstance(call.func.value,ast.Name):return None
    # Only straight-line preceding statements in the containing function/module.
    parents={child:node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    statement=call
    while statement in parents and not isinstance(parents[statement],(ast.Module,ast.FunctionDef,ast.AsyncFunctionDef)):
        if isinstance(parents[statement],(ast.If,ast.For,ast.While,ast.Try,ast.With,ast.Lambda,ast.ClassDef)):return None
        statement=parents[statement]
    scope=parents.get(statement)
    if not isinstance(scope,(ast.Module,ast.FunctionDef,ast.AsyncFunctionDef)):return None
    imports={}
    # Import names are accepted only when not shadowed/rebound elsewhere.
    for node in tree.body:
        if isinstance(node,ast.Import):
            for alias in node.names:
                if alias.name in ('sqlite3','psycopg','psycopg2'):imports[alias.asname or alias.name]=alias.name
    if not imports:return None
    for node in ast.walk(tree):
        if isinstance(node,ast.Name) and isinstance(node.ctx,ast.Store) and node.id in imports:return None
        if isinstance(node,ast.arg) and node.arg in imports:return None
    env={};bindings={}
    def parts(node,seen=()):
        if isinstance(node,ast.Constant) and isinstance(node.value,str):return [node.value]
        if isinstance(node,ast.Name):
            # Preserve the value variable as written; expanding aliases against
            # later bindings can change the captured query's meaning.
            return [node]
        if isinstance(node,ast.BinOp) and isinstance(node.op,ast.Add):
            left,right=parts(node.left,seen),parts(node.right,seen)
            return left+right if left is not None and right is not None else None
        if isinstance(node,ast.JoinedStr):
            chunks=[]
            for value in node.values:
                if isinstance(value,ast.Constant):chunks.append(value.value)
                elif isinstance(value,ast.FormattedValue) and value.conversion==-1 and value.format_spec is None and isinstance(value.value,ast.Name):chunks.append(value.value)
                else:return None
            return chunks
        return None
    for node in scope.body:
        if node is statement:break
        if isinstance(node,(ast.Import,ast.ImportFrom)):
            if isinstance(node,ast.Import):
                for alias in node.names:
                    if alias.name in ('sqlite3','psycopg','psycopg2'):imports[alias.asname or alias.name]=alias.name
            continue
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and isinstance(scope,ast.Module):continue
        if not isinstance(node,ast.Assign) or len(node.targets)!=1 or not isinstance(node.targets[0],ast.Name):return None
        name=node.targets[0].id;value=node.value;binding=None
        if name in imports:return None
        if isinstance(value,ast.Call) and isinstance(value.func,ast.Attribute) and isinstance(value.func.value,ast.Name):
            receiver=value.func.value.id
            if value.func.attr=='connect' and receiver in imports and not any(k.arg is None or 'factory' in k.arg for k in value.keywords):binding=(imports[receiver],'connection')
            elif value.func.attr=='cursor' and bindings.get(receiver,(None,None))[1]=='connection' and not value.args and not value.keywords:binding=(bindings[receiver][0],'cursor')
        elif isinstance(value,ast.Name):binding=bindings.get(value.id)
        if binding:bindings[name]=binding
        else:bindings.pop(name,None)
        # Keep request/unknown values as names, never substitute their expressions.
        if isinstance(value,(ast.Constant,ast.BinOp,ast.JoinedStr,ast.Name)):
            env[name]=value
        else:env.pop(name,None)
    if isinstance(call.args[0],ast.Name):
        index=scope.body.index(statement)
        previous=scope.body[index-1] if index else None
        if not isinstance(previous,ast.Assign) or len(previous.targets)!=1 or not isinstance(previous.targets[0],ast.Name) or previous.targets[0].id!=call.args[0].id:return None
    binding=bindings.get(call.func.value.id)
    if not binding or binding[1] not in ('connection','cursor'):return None
    expression=env.get(call.args[0].id) if isinstance(call.args[0],ast.Name) else call.args[0]
    chunks=parts(expression)
    if not chunks or sum(isinstance(c,ast.Name) for c in chunks)!=1:return None
    index=next(i for i,c in enumerate(chunks) if isinstance(c,ast.Name))
    prefix=''.join(chunks[:index]);suffix=''.join(chunks[index+1:]);value=chunks[index].id
    # Restrict to a single SELECT equality value, never identifiers/LIKE/list syntax.
    if not re.fullmatch(r'\s*SELECT\s+[^;\'"%?]+\s+WHERE\s+[A-Za-z_][\w.]*\s*=\s*\x27?',prefix,re.I):return None
    quoted=prefix.endswith("'")
    if (quoted and suffix.strip()!="'") or (not quoted and suffix.strip()!=''):return None
    query=(prefix[:-1] if quoted else prefix)+('?' if binding[0]=='sqlite3' else '%s')
    receiver=call.func.value.id
    replacement=f'{receiver}.execute({query!r}, ({value},))'
    lines=source.encode().splitlines(keepends=True)
    start=sum(map(len,lines[:call.lineno-1]))+call.col_offset
    end=sum(map(len,lines[:call.end_lineno-1]))+call.end_col_offset
    raw=source.encode();before=raw[start:end].decode();edited=(raw[:start]+replacement.encode()+raw[end:]).decode()
    validation=validate_candidate(finding,source,edited)
    if validation['status']!='Passed':return None
    return dict(before=before,before_label='Actual database call to replace',exact=True,source_aware=True,
        examples=[dict(language='Python / '+binding[0],code=replacement+'\n',kind='Suggested Source Fix',validation=validation)],
        action='Replace only the database call shown below. Keep the existing query structure and bind the original value separately.',
        why='The detected DB-API driver receives SQL and the value separately, preventing the value from becoming SQL syntax.',
        fix_confidence='Medium',fix_reason='Driver construction and the query were matched in this file. Static checks passed; runtime types and application behavior still require testing.',
        notes=['The original query assignment is left unchanged to avoid altering other uses. Review whether it can be removed after this call is updated.', 'Test the query with ordinary and special-character values using the same database driver. No runtime query was executed by SentinelScan.'],
        source_status='Matched a direct '+binding[0]+' connection/cursor and a single SELECT equality query in scanned source. Static validation passed; runtime behavior has not been verified.')
