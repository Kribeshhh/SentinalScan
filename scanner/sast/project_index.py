"""Bounded declaration/import/call inventory, not a resolved inter-file call graph."""
import ast
import time
from analysis.redaction import scrub
from scanner.sast.registry import analyzer_for
from scanner.sast.common import check_budget
from scanner.sast.evidence import bounded

MAX_RECORDS = 5000
MAX_PER_FILE = 100


def python_name(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute):
        base = python_name(node.value)
        return base + '.' + node.attr if base else node.attr
    return '<unresolved>'


def records(tree, language):
    stack = [(tree, None)]
    while stack:
        node, scope = stack.pop()
        item = None
        if language == 'Python':
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                item = {'kind':'class' if isinstance(node, ast.ClassDef) else 'function', 'name':node.name,
                        'line':node.lineno, 'end_line':node.end_lineno, 'scope':scope}
                scope = (scope + '.' if scope else '') + node.name
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                item = {'kind':'import', 'names':[{'name':a.name, 'alias':a.asname} for a in node.names][:20],
                        'module':getattr(node,'module',None), 'line':node.lineno, 'scope':scope}
            elif isinstance(node, ast.Call):
                item = {'kind':'call', 'name':python_name(node.func), 'line':node.lineno, 'scope':scope, 'resolved':False}
            children = list(ast.iter_child_nodes(node))
        else:
            kind = node.type
            if kind in ('class_declaration','function_declaration','function_expression','arrow_function',
                        'method_definition','method_declaration','constructor_declaration'):
                name = node.child_by_field_name('name')
                name = name.text.decode('utf-8') if name else '<anonymous>'
                item = {'kind':'class' if kind=='class_declaration' else 'function', 'name':name,
                        'line':node.start_point.row+1, 'end_line':node.end_point.row+1, 'scope':scope}
                scope = (scope + '.' if scope else '') + name
            elif kind in ('import_statement','import_declaration'):
                # Identifiers / import path only; never arbitrary source expressions.
                names = []
                pending = list(node.named_children)
                while pending:
                    child = pending.pop()
                    if child.type in ('identifier','string_fragment'): names.append(child.text.decode('utf-8')[:160])
                    else: pending.extend(child.named_children)
                item = {'kind':'import', 'names':names[:20], 'line':node.start_point.row+1, 'scope':scope}
            elif kind in ('call_expression','method_invocation','object_creation_expression','new_expression'):
                name = node.child_by_field_name('name') or node.child_by_field_name('function') or node.child_by_field_name('type') or node.child_by_field_name('constructor')
                # Avoid retaining calls/arguments hidden in member expressions.
                if name and name.type not in ('identifier','type_identifier'):
                    name = name.child_by_field_name('property')
                item = {'kind':'call', 'name':name.text.decode('utf-8')[:160] if name and name.type in ('identifier','property_identifier','type_identifier') else '<unresolved>',
                        'line':node.start_point.row+1, 'scope':scope, 'resolved':False}
            children = node.named_children
        if item: yield item
        stack.extend((child,scope) for child in reversed(children))


def build_index(ctx):
    result = {'schema_version':1, 'files':[], 'languages':{}, 'records':[], 'unparsed_files':[],
              'framework_indicators':[], 'truncated':False,
              'note':'Declarations and syntactic calls only; imports do not prove framework use or resolved call relationships.'}
    end = min(ctx['deadline'], time.monotonic()+10)
    for path in ctx['paths']:
        check_budget(ctx)
        adapter = analyzer_for(path)
        if not adapter: continue
        result['files'].append({'file':path,'language':adapter.language})
        result['languages'][adapter.language] = result['languages'].get(adapter.language,0)+1
        if time.monotonic()>end or len(result['records'])>=MAX_RECORDS:
            result['truncated']=True
            continue
        try:
            tree = adapter.parse((ctx['root']/path).read_text(encoding='utf-8-sig'))
            for index,item in enumerate(records(tree,adapter.language)):
                if index>=MAX_PER_FILE or len(result['records'])>=MAX_RECORDS or time.monotonic()>end:
                    result['truncated']=True;break
                check_budget(ctx)
                result['records'].append(bounded(dict(item,file=path)))
                if item['kind']=='import':
                    labels = str(item.get('module') or '') + ' ' + str(item.get('names',[]))
                    for framework in ('flask','django','express','spring'):
                        if framework in labels.lower() and framework not in result['framework_indicators']:
                            result['framework_indicators'].append(framework)
        except (SyntaxError,ValueError,RecursionError):
            result['unparsed_files'].append(path)
    return scrub(result,ctx.get('secrets',()))
