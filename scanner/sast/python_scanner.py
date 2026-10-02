"""Order-sensitive intraprocedural AST checks. Source is never executed."""
import ast
from dataclasses import replace
from scanner.sast.common import add,files,check_budget
from scanner.sast.flow import Value,UNKNOWN,combine,merge_environments,confidence,evidence,sensitive_name


class Analyzer:
    def __init__(self,ctx,path):self.ctx=ctx;self.path=path;self.env={};self.aliases={};self.target=''

    def name(self,node):
        if isinstance(node,ast.Name):return self.aliases.get(node.id,node.id if node.id not in self.env else '')
        if isinstance(node,ast.Attribute):return self.name(node.value)+'.'+node.attr
        return ''

    def report(self,node,title,category,value,sink,severity='Medium',recommendation='Replace dynamic execution with explicit parsing or constrained data formats.',level=None):
        detail=evidence(value,sink)
        if category=='Cryptography':
            detail=sink+(': security-sensitive naming/context detected; confirm actual use.' if severity=='High' else ': weak hash detected; checksum-only use may be acceptable. Purpose requires review.')
        add(self.ctx,self.path,node.lineno,title,category,detail,recommendation,severity,level or confidence(value))

    def expr(self,node):
        if node is None:return UNKNOWN
        if isinstance(node,ast.Constant):return Value(static=True,literal=node.value)
        if isinstance(node,ast.Name):return self.env.get(node.id,Value(sensitive=sensitive_name(node.id)))
        if isinstance(node,ast.Lambda):
            self.function(node);return UNKNOWN
        if isinstance(node,(ast.Attribute,ast.Subscript)):
            label=self.name(node)
            if any(label==prefix or label.startswith(prefix+'.') for prefix in ('request.args','request.form','request.values','request.json','request.headers','request.cookies','flask.request.args','flask.request.form','flask.request.values','flask.request.json','flask.request.headers','flask.request.cookies')):
                return Value(sources=(label,))
            return self.expr(node.value)
        if isinstance(node,ast.NamedExpr):
            value=self.expr(node.value);self.assign(node.target,value);return value
        if isinstance(node,ast.Call):
            fn=self.name(node.func)
            receiver=self.expr(node.func.value) if isinstance(node.func,ast.Attribute) else UNKNOWN
            args=[self.expr(a) for a in node.args];keywords={k.arg:self.expr(k.value) for k in node.keywords}
            first=args[0] if args else UNKNOWN
            source=receiver.sources or ((fn,) if fn in ('request.get_json','flask.request.get_json','input','builtins.input') else ())
            result=replace(combine([receiver,*args]),static=False,literal=None)
            if source:result=replace(result,sources=source)
            if fn in ('str','bytes') and args:return first
            if fn in ('int','float') and args:
                # Numeric conversion constrains SQL/shell metacharacters, but is not a generic sanitizer.
                return replace(first,static=False,sources=(),constructed=False)
            if isinstance(node.func,ast.Attribute) and node.func.attr in ('format','join'):
                result=combine([receiver,*args,*keywords.values()],constructed=True)
            if fn in ('eval','exec','builtins.eval','builtins.exec') and args and not first.static:
                self.report(node,'Dynamic Python code execution','Code Security',first,fn,'High' if first.sources else 'Medium')
            if fn in ('os.system','os.popen') and args and not first.static:
                self.report(node,'Potential shell command injection','Injection',first,fn,'High','Use a fixed executable and an argument list with shell=False; validate allowed arguments.')
            shell=keywords.get('shell',Value(static=True,literal=False))
            if fn in ('subprocess.run','subprocess.call','subprocess.Popen','subprocess.check_call','subprocess.check_output') and args and not first.static and shell.literal is True:
                self.report(node,'Unsafe subprocess shell invocation','Injection',first,fn+'(shell=True)','High','Use an argument array and shell=False.')
            if isinstance(node.func,ast.Attribute) and node.func.attr in ('execute','executemany','executescript','raw') and args and not first.static and (first.constructed or first.sources):
                self.report(node,'Potential SQL injection in constructed query','Injection',first,'SQL '+node.func.attr,'High','Use database-bound parameters instead of concatenation or interpolation.')
            unsafe=fn in ('pickle.load','pickle.loads','dill.load','dill.loads','marshal.loads','marshal.load')
            if fn=='yaml.load':
                loaders=[k.value for k in node.keywords if k.arg=='Loader']+node.args[1:2]
                unsafe=not any(self.name(loader) in ('yaml.SafeLoader','yaml.CSafeLoader','yaml.BaseLoader') for loader in loaders)
            if unsafe:self.report(node,'Potential unsafe deserialization','Deserialization',first,fn,'High' if first.sources else 'Medium','Use a data-only format or safe loader; never deserialize untrusted object graphs.', 'High' if first.sources else 'Low')
            weak=fn in ('hashlib.md5','hashlib.sha1')
            factory=fn=='hashlib.new' and str(first.literal).lower() in ('md5','sha1')
            if weak or factory:
                data=first if weak else (args[1] if len(args)>1 else UNKNOWN)
                sensitive=data.sensitive or sensitive_name(self.target)
                self.report(node,'Weak hash algorithm usage' if weak else 'Weak hash algorithm selection','Cryptography',data,fn,
                    'High' if sensitive else 'Low','Use dedicated password hashing for credentials; checksum-only use may be acceptable. Review the purpose before changing algorithms.',
                    ('High' if data.sources else 'Medium') if sensitive else 'Low')
            return result
        if isinstance(node,(ast.BinOp,ast.JoinedStr)):
            children=[self.expr(n) for n in ast.iter_child_nodes(node) if not isinstance(n,ast.operator)]
            return combine(children,constructed=True)
        if isinstance(node,(ast.List,ast.Tuple,ast.Set)):
            return combine([self.expr(n) for n in node.elts]) if node.elts else Value(static=True)
        if isinstance(node,ast.Dict):return combine([self.expr(n) for n in node.values])
        return combine([self.expr(n) for n in ast.iter_child_nodes(node)])

    def assign(self,target,value):
        if isinstance(target,ast.Name):
            self.env[target.id]=value.assigned(target.id);self.aliases.pop(target.id,None)
        elif isinstance(target,(ast.Tuple,ast.List)):
            for item in target.elts:self.assign(item,UNKNOWN)

    def function(self,node):
        saved=self.env,self.aliases,self.target
        self.env=self.env.copy();self.aliases=self.aliases.copy();self.target=''
        # Local names shadow outer variables even before their first assignment.
        def locals_in(nodes):
            for n in nodes:
                if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef,ast.Lambda)):
                    if hasattr(n,'name'):yield n.name
                    continue
                if isinstance(n,ast.Name) and isinstance(n.ctx,ast.Store):yield n.id
                yield from locals_in(ast.iter_child_nodes(n))
        body=[node.body] if isinstance(node,ast.Lambda) else node.body
        params=node.args.posonlyargs+node.args.args+node.args.kwonlyargs
        for arg in params+([node.args.vararg] if node.args.vararg else [])+([node.args.kwarg] if node.args.kwarg else []):
            self.env[arg.arg]=Value(sensitive=sensitive_name(arg.arg));self.aliases.pop(arg.arg,None)
        for name in locals_in(body):self.env[name]=UNKNOWN;self.aliases.pop(name,None)
        if isinstance(node,ast.Lambda):self.expr(node.body)
        else:self.block(body)
        self.env,self.aliases,self.target=saved

    def block(self,nodes):
        for node in nodes:
            if 'deadline' in self.ctx:check_budget(self.ctx)
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                self.function(node);self.env[node.name]=UNKNOWN;self.aliases.pop(node.name,None)
            elif isinstance(node,ast.ClassDef):
                saved=self.env,self.aliases;self.env=self.env.copy();self.aliases=self.aliases.copy();self.block(node.body);self.env,self.aliases=saved
            elif isinstance(node,(ast.Import,ast.ImportFrom)):
                for alias in node.names:
                    key=alias.asname or (alias.name.split('.')[0] if isinstance(node,ast.Import) else alias.name)
                    self.aliases[key]=(alias.name if alias.asname else alias.name.split('.')[0]) if isinstance(node,ast.Import) else (node.module or '')+'.'+alias.name
                    self.env.pop(key,None)
            elif isinstance(node,(ast.Assign,ast.AnnAssign,ast.AugAssign)):
                targets=node.targets if isinstance(node,ast.Assign) else [node.target]
                self.target=' '.join(t.id for t in targets if isinstance(t,ast.Name))
                value=self.expr(node.value)
                if isinstance(node,ast.AugAssign):value=combine([self.expr(node.target),value],constructed=True)
                for target in targets:self.assign(target,value)
                self.target=''
            elif isinstance(node,ast.If):
                self.expr(node.test);before=self.env.copy();aliases=self.aliases.copy()
                self.block(node.body);left=self.env.copy();left_alias=self.aliases.copy()
                self.env=before.copy();self.aliases=aliases.copy();self.block(node.orelse)
                self.env=merge_environments(before,left,self.env)
                self.aliases={k:v for k,v in self.aliases.items() if left_alias.get(k)==v}
            elif isinstance(node,(ast.For,ast.AsyncFor,ast.While,ast.Try)):
                before=self.env.copy();before_aliases=self.aliases.copy()
                if hasattr(node,'iter'):self.assign(node.target,self.expr(node.iter))
                if hasattr(node,'test'):self.expr(node.test)
                self.block(node.body)
                branches=[before,self.env.copy()];branch_aliases=[before_aliases,self.aliases.copy()]
                for handler in getattr(node,'handlers',[]):
                    self.env=before.copy();self.aliases=before_aliases.copy();self.block(handler.body);branches.append(self.env.copy());branch_aliases.append(self.aliases.copy())
                self.env=merge_environments(before,*branches)
                self.aliases={k:v for k,v in before_aliases.items() if all(b.get(k)==v for b in branch_aliases)}
                self.block(getattr(node,'orelse',[]));self.block(getattr(node,'finalbody',[]))
            elif isinstance(node,(ast.With,ast.AsyncWith)):
                for item in node.items:
                    value=self.expr(item.context_expr)
                    if item.optional_vars:self.assign(item.optional_vars,value)
                self.block(node.body)
            else:self.expr(node)


def run(ctx):
    count=0;errors=[]
    for path,source in files(ctx,('.py',)):
        try:tree=ast.parse(source);Analyzer(ctx,path).block(tree.body)
        except (SyntaxError,ValueError,RecursionError):errors.append(path);continue
        count+=1
    return {'parsed_files':count,'unparsed_files':errors[:100],'note':'Statement-order local flow, aliases and Flask input sources. Branches merge conservatively; no interprocedural analysis or execution.'}
