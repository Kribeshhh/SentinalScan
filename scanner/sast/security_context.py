"""Bounded, redacted context and source anchors. No source execution or LLM calls."""
import ast
import hashlib
import json
import time
from pathlib import Path
from analysis.source_context import mask_source
from scanner.sast.registry import analyzer_for

OPERATIONS={
    'CWE-89':{'execute','executemany','executescript','raw','executeQuery','executeUpdate','prepareStatement'},
    'CWE-78':{'system','popen','run','call','Popen','check_call','check_output','exec','ProcessBuilder'},
    'CWE-79':{'innerHTML','outerHTML','write'},
    'CWE-95':{'eval','exec','Function'},
    'CWE-502':{'load','loads','readObject'},
}


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class ContextRetriever:
    def __init__(self,ctx):
        self.ctx=ctx;self.cache={};self.bytes=0;self.end=min(ctx['deadline'],time.monotonic()+12)

    def file(self,path):
        if path in self.cache:return self.cache[path]
        if path not in self.ctx['paths'] or len(self.cache)>=40 or time.monotonic()>self.end:return None
        target=self.ctx['root']/path
        if target.is_symlink() or not target.resolve().is_relative_to(self.ctx['root'].resolve()):return None
        try:
            size=target.stat().st_size
            if size>512*1024 or self.bytes+size>4*1024*1024:return None
            self.bytes+=size
            source=target.read_text(encoding='utf-8-sig')
        except (OSError,UnicodeError):
            # Optional enrichment must not discard a detected finding when a
            # vetted file disappears or becomes unreadable.
            return None
        lines=mask_source(source,self.ctx.get('secrets',())).splitlines()
        adapter=analyzer_for(path);operations=[];functions=[]
        try:
            tree=adapter.parse(source) if adapter else None
            stack=[(tree,None)] if tree is not None else []
            while stack:
                if time.monotonic()>self.end:break
                node,scope=stack.pop()
                if len(operations)+len(functions)>=4000:break
                if isinstance(node,ast.AST):
                    if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                        scope=(scope+'.' if scope else '')+node.name
                        if not isinstance(node,ast.ClassDef):functions.append((scope,node.lineno,node.end_lineno))
                    if isinstance(node,ast.Call):
                        name=node.func.attr if isinstance(node.func,ast.Attribute) else node.func.id if isinstance(node.func,ast.Name) else None
                        # Redact before hashing; never retain a digest of a raw credential.
                        signature=mask_source(ast.dump(node,include_attributes=False),self.ctx.get('secrets',()))
                        operations.append({'name':name,'start':node.lineno,'end':node.end_lineno,'scope':scope,
                                           'signature':digest(signature)})
                    children=list(ast.iter_child_nodes(node))
                else:
                    if node.type in ('function_declaration','function_expression','arrow_function','method_definition','method_declaration','constructor_declaration','class_declaration'):
                        name=node.child_by_field_name('name')
                        label=name.text.decode('utf-8') if name else '<anonymous>'
                        scope=(scope+'.' if scope else '')+label
                        if node.type!='class_declaration':functions.append((scope,node.start_point.row+1,node.end_point.row+1))
                    if node.type in ('call_expression','new_expression','method_invocation','object_creation_expression','assignment_expression'):
                        name=node.child_by_field_name('name') or node.child_by_field_name('function') or node.child_by_field_name('constructor') or node.child_by_field_name('type') or node.child_by_field_name('left')
                        if name and name.type in ('member_expression','subscript_expression'):name=name.child_by_field_name('property') or name.child_by_field_name('index')
                        label=name.text.decode('utf-8').strip('"\'') if name else None
                        # Token boundaries, comments and whitespace handled by the actual parser.
                        tokens=[];pending=[node]
                        while pending:
                            part=pending.pop()
                            if part.type=='comment':continue
                            if not part.children:tokens.append((part.type,part.text.decode('utf-8')))
                            else:pending.extend(reversed(part.children))
                        signature=mask_source(json.dumps(tokens),self.ctx.get('secrets',()))
                        operations.append({'name':label,'start':node.start_point.row+1,'end':node.end_point.row+1,'scope':scope,'signature':digest(signature)})
                    children=node.named_children
                stack.extend((child,scope) for child in reversed(children))
        except (SyntaxError,ValueError,RecursionError):pass
        data={'lines':lines,'operations':operations,'functions':functions}
        self.cache[path]=data
        return data

    def retrieve(self,analysis):
        path=analysis.get('file');line=analysis.get('start_line')
        empty={'available':False,'snippets':[],'related_functions':[],'related_files':[],
               'note':'Context unavailable, unsupported or budget exhausted.'}
        if not isinstance(path,str) or type(line) is not int:return empty
        data=self.file(path)
        if not data or not 1<=line<=len(data['lines']):return empty
        matching=[op for op in data['operations'] if op['start']<=line<=op['end'] and op['name'] in OPERATIONS.get(analysis.get('cwe'),set())]
        anchor=matching[0] if len(matching)==1 else None
        functions=[fn for fn in data['functions'] if fn[1]<=line<=fn[2]]
        function=min(functions,key=lambda fn:fn[2]-fn[1]) if functions else None
        name=function[0] if function else None
        budget=3600;snippets=[]
        def excerpt(start,end,label):
            nonlocal budget
            if budget<=0:return
            text='\n'.join(f'{i}: {data["lines"][i-1][:300]}' for i in range(max(1,start),min(len(data['lines']),end)+1))
            text=text[:min(budget,1800)];budget-=len(text)
            snippets.append({'file':path,'role':label,'start_line':max(1,start),'text':text})
        excerpt(max(line-4,function[1] if function else 1),min(line+5,function[2] if function else line+5),'affected operation')
        related=[]
        if name:
            # One hop of syntactic callers/callees in the same file only; not resolved dispatch.
            calls=[op for op in data['operations'] if op['scope']==name]
            callees={op['name'] for op in calls}
            related=[fn for fn in data['functions'] if fn[0].split('.')[-1] in callees and fn[0]!=name][:2]
            caller_scopes={op['scope'] for op in data['operations'] if op['name']==name.split('.')[-1]}
            related+= [fn for fn in data['functions'] if fn[0] in caller_scopes and fn not in related and fn[0]!=name][:2]
        for label,start,end in related[:3]:excerpt(start,min(start+7,end),'syntactically related function')
        return {'available':True,'anchor':anchor,'function':name,'snippets':snippets,
                'related_functions':[fn[0] for fn in related[:3]],'related_files':[path],
                'limits':{'files':1,'depth':1,'characters':3600},
                'note':'Redacted excerpts, not full functions; relationships are syntactic and may be unresolved. No unrelated configuration is inferred.'}
