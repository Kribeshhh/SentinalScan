"""Order-sensitive intraprocedural AST checks. Source is never executed."""
import ast
import re
from dataclasses import replace
from scanner.sast.common import add,files,check_budget
from scanner.sast.evidence import semantic
from scanner.sast.flow import Value,UNKNOWN,combine,merge_environments,confidence,evidence,sensitive_name


class Analyzer:
    def __init__(self,ctx,path):self.ctx=ctx;self.path=path;self.env={};self.aliases={};self.target='';self.function_name=None;self.functions={};self.global_env={};self.global_aliases={};self.active=[];self.expansions=0;self.returns=[];self.limited=False;self.class_depth=0;self.local_classes={};self.mutated_attributes=set()

    def prepare(self,tree):
        # Only unambiguous plain module functions; no dispatch, decorators or closures.
        # Attribute rebinding/dynamic lookup makes local receiver identity uncertain.
        self.mutated_attributes={n.attr for n in ast.walk(tree) if isinstance(n,ast.Attribute) and isinstance(n.ctx,(ast.Store,ast.Del))}
        if any(isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in ('setattr','delattr') for n in ast.walk(tree)):
            self.mutated_attributes.update(('execute','executemany','executescript','raw'))
        definitions={}
        for node in tree.body:
            if isinstance(node,ast.FunctionDef):definitions.setdefault(node.name,[]).append(node)
        for name,nodes in list(definitions.items())[:100]:
            node=nodes[0]
            if len(nodes)==1 and not node.decorator_list and not node.args.vararg and not node.args.kwarg:
                self.functions[name]=node
                self.env[name]=Value(callable_name=name)
        self.global_env=self.env.copy()

    def invoke(self,name,args,keywords):
        if name in self.active or len(self.active)>=4 or self.expansions>=100:
            self.limited=True
            return replace(combine(args),static=False,uncertain=True,callable_name=None)
        node=self.functions[name]
        params=node.args.posonlyargs+node.args.args
        if len(args)>len(params) or None in keywords:
            return replace(combine(args),static=False,uncertain=True,callable_name=None)
        supplied={p.arg:v for p,v in zip(params,args)}
        if any(key in supplied for key in keywords):return replace(combine(args),static=False,uncertain=True)
        if any(key not in {p.arg for p in params+node.args.kwonlyargs} for key in keywords):
            return replace(combine([*args,*keywords.values()]),static=False,uncertain=True)
        supplied.update(keywords)
        defaults=dict(zip([p.arg for p in params][-len(node.args.defaults):],node.args.defaults)) if node.args.defaults else {}
        defaults.update({p.arg:v for p,v in zip(node.args.kwonlyargs,node.args.kw_defaults) if v is not None})
        if any(p.arg in keywords for p in node.args.posonlyargs) or any(p.arg not in supplied and p.arg not in defaults for p in params+node.args.kwonlyargs):
            return replace(combine([*args,*keywords.values()]),static=False,uncertain=True)

        saved=self.env,self.aliases,self.target,self.function_name,self.returns
        self.env=self.global_env.copy();self.aliases=self.global_aliases.copy();self.target='';self.function_name=name;self.returns=[]
        self.active.append(name);self.expansions+=1
        try:
            # A local declaration shadows a module helper even before assignment.
            def bind_locals(nodes):
                for child in nodes:
                    if isinstance(child,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef,ast.Lambda)):
                        if hasattr(child,'name'):self.env[child.name]=UNKNOWN;self.aliases.pop(child.name,None)
                        continue
                    if isinstance(child,(ast.Import,ast.ImportFrom)):
                        for alias in child.names:
                            key=alias.asname or (alias.name.split('.')[0] if isinstance(child,ast.Import) else alias.name)
                            self.env[key]=UNKNOWN;self.aliases.pop(key,None)
                    if isinstance(child,ast.Name) and isinstance(child.ctx,ast.Store):
                        self.env[child.id]=UNKNOWN;self.aliases.pop(child.id,None)
                    bind_locals(ast.iter_child_nodes(child))
            bind_locals(node.body)
            for param in params+node.args.kwonlyargs:
                value=supplied.get(param.arg)
                if value is None:value=self.expr(defaults[param.arg]) if param.arg in defaults else UNKNOWN
                self.env[param.arg]=replace(value.assigned(name+'('+param.arg+')'),calls=(value.calls+(name,))[-6:])
                self.aliases.pop(param.arg,None)
            self.block(node.body)
            result=(self.returns[0] if len(self.returns)==1 else combine(self.returns,preserve_html=True)) if self.returns else UNKNOWN
            # A function with a possible fallthrough cannot be called a constant sanitizer.
            if not node.body or not isinstance(node.body[-1],ast.Return):
                result=replace(result,static=False,uncertain=True)
            return replace(result,trace=(result.trace+(name+'() return',))[-8:],calls=(result.calls+(name,))[-6:])
        finally:
            self.active.pop()
            self.env,self.aliases,self.target,self.function_name,self.returns=saved

    def name(self,node):
        if isinstance(node,ast.Name):
            if node.id in self.aliases:return self.aliases[node.id]
            if node.id not in self.env:return node.id
            value=self.env[node.id]
            return value.identity or (value.callable_name if value.callable_name not in self.functions else '') or ''
        if isinstance(node,ast.Attribute):return self.name(node.value)+'.'+node.attr
        if isinstance(node,ast.Call) and self.name(node.func) in ('getattr','builtins.getattr') and len(node.args)==2 and not node.keywords:
            attr=node.args[1]
            value=attr.value if isinstance(attr,ast.Constant) else self.env.get(attr.id,UNKNOWN).literal if isinstance(attr,ast.Name) else None
            if isinstance(value,str) and value.isidentifier():return self.name(node.args[0])+'.'+value
        return ''

    def report(self,node,title,category,value,sink,severity='Medium',recommendation='Replace dynamic execution with explicit parsing or constrained data formats.',level=None):
        detail=evidence(value,sink)
        if category=='Cryptography':
            detail=sink+(': security-sensitive naming/context detected; confirm actual use.' if severity=='High' else ': weak hash detected; checksum-only use may be acceptable. Purpose requires review.')
        add(self.ctx,self.path,node.lineno,title,category,detail,recommendation,severity,level or confidence(value),semantic=semantic(node,value,sink,"Python",self.function_name))

    def expr(self,node):
        if node is None:return UNKNOWN
        if isinstance(node,ast.Constant):return Value(static=True,literal=node.value)
        if isinstance(node,ast.Name):return self.env.get(node.id,Value(identity=self.aliases.get(node.id),sensitive=sensitive_name(node.id)))
        if isinstance(node,ast.Lambda):
            self.function(node);return UNKNOWN
        if isinstance(node,(ast.Attribute,ast.Subscript)):
            receiver=self.expr(node.value)
            if isinstance(node,ast.Subscript):
                self.expr(node.slice)
                return replace(receiver,identity=None,callable_name=None)
            if node.attr in self.mutated_attributes:return replace(receiver,identity=None,callable_name=None,uncertain=True)
            label=(receiver.identity+'.'+node.attr) if receiver.identity else ''
            if label in ('flask.request.args','flask.request.form','flask.request.values','flask.request.json','flask.request.headers','flask.request.cookies'):
                return Value(sources=(label,))
            return replace(receiver,identity=label or None,callable_name=None)
        if isinstance(node,ast.NamedExpr):
            value=self.expr(node.value);self.assign(node.target,value);return value
        if isinstance(node,ast.Call):
            fn=self.name(node.func)
            receiver=self.expr(node.func.value) if isinstance(node.func,ast.Attribute) else UNKNOWN
            args=[self.expr(a) for a in node.args];keywords={k.arg:self.expr(k.value) for k in node.keywords}
            callable_value=self.env.get(node.func.id,UNKNOWN) if isinstance(node.func,ast.Name) else UNKNOWN
            if callable_value.callable_name in self.functions:
                if any(isinstance(arg,ast.Starred) for arg in node.args):
                    return replace(combine(args),static=False,uncertain=True)
                return self.invoke(callable_value.callable_name,args,keywords)
            first=args[0] if args else UNKNOWN
            if fn.startswith('class:'):
                return Value(identity=fn.replace('class:', 'local:', 1) if fn in self.local_classes else None)
            if fn in ('sqlite3.connect','psycopg.connect','psycopg2.connect','pymysql.connect','mysql.connector.connect') and self.expr(node.func).identity==fn:
                return Value(identity='db:connection')
            if fn=='django.db.connection.cursor' and self.expr(node.func).identity==fn:
                return Value(identity='db:cursor')
            if receiver.identity=='db:connection' and isinstance(node.func,ast.Attribute) and node.func.attr=='cursor':
                return Value(identity='db:cursor')
            if fn in ('getattr','builtins.getattr') and self.name(node):
                return Value(callable_name=self.name(node))
            source=receiver.sources or ((fn,) if fn in ('input','builtins.input') or fn=='flask.request.get_json' and self.expr(node.func).identity==fn else ())
            result=replace(combine([receiver,*args]),static=False,literal=None)
            if source:result=replace(result,sources=source)
            if fn in ('str','bytes') and args:return first
            if fn in ('int','float') and args:
                # Numeric conversion constrains SQL/shell metacharacters, but is not a generic sanitizer.
                return replace(first,static=False,constructed=False,protections=("sql-value",))
            if fn=='shlex.quote' and self.expr(node.func).identity==fn and len(args)==1 and not keywords:
                return replace(first,static=False,literal=None,protections=('posix-quoted-argument',))
            if isinstance(node.func,ast.Attribute) and node.func.attr in ('format','join'):
                result=combine([receiver,*args,*keywords.values()],constructed=True)
            if fn in ('eval','exec','builtins.eval','builtins.exec') and args and not first.static:
                self.report(node,'Dynamic Python code execution','Code Security',first,fn,'High' if first.sources else 'Medium')
            if fn in ('os.system','os.popen') and args and not first.static and 'fixed-posix-command' not in first.protections:
                self.report(node,'Potential shell command injection','Injection',first,fn,'High','Use a fixed executable and an argument list with shell=False; validate allowed arguments.')
            shell=keywords.get('shell',Value(static=True,literal=False))
            if fn in ('subprocess.run','subprocess.call','subprocess.Popen','subprocess.check_call','subprocess.check_output') and args and not first.static and shell.literal is True and 'fixed-posix-command' not in first.protections:
                self.report(node,'Unsafe subprocess shell invocation','Injection',first,fn+'(shell=True)','High','Use an argument array and shell=False.')
            method=node.func.attr if isinstance(node.func,ast.Attribute) else fn.rsplit('.',1)[-1] if '.' in fn else ''
            sink_identity=(receiver.identity or fn.rsplit('.',1)[0]) if method not in self.mutated_attributes else ''
            if method in ('execute','executemany','executescript','raw') and not (method in self.local_classes.get(sink_identity.replace('local:','class:',1),()) and method not in self.mutated_attributes) and args and not first.static and (first.constructed or first.sources) and 'sql-value' not in first.protections:
                self.report(node,'Potential SQL injection in constructed query','Injection',replace(first,uncertain=True) if sink_identity not in ('db:connection','db:cursor') else first,
                    ('SQL ' if sink_identity in ('db:connection','db:cursor') else 'Unresolved receiver method ')+method,'High',
                    'Use database-bound parameters instead of concatenation or interpolation.',
                    level=confidence(first) if sink_identity in ('db:connection','db:cursor') else 'Low')
            if fn in ('requests.get','requests.post','requests.put','requests.patch','requests.delete','requests.head','requests.options','requests.request') and any(v=='requests' or v==fn for v in self.aliases.values()) and keywords.get('verify',UNKNOWN).literal is False:
                add(self.ctx,self.path,node.lineno,'Security control disabled in configuration','Configuration','An imported requests API explicitly disables TLS certificate verification.',
                    'Enable TLS certificate verification. Configure a trusted CA bundle when required instead of verify=False.','Medium','High')
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
                # Explicit hashlib non-security intent, not a checksum variable name.
                nonsecurity = (self.expr(node.func).identity == fn and keywords.get('usedforsecurity', UNKNOWN).literal is False and not sensitive)
                if not nonsecurity:self.report(node,'Weak hash algorithm usage' if weak else 'Weak hash algorithm selection','Cryptography',data,fn,
                    'High' if sensitive else 'Informational','Use dedicated password hashing for credentials; checksum-only use may be acceptable. Review the purpose before changing algorithms.',
                    ('High' if data.sources else 'Medium') if sensitive else 'Low')
            if not source and fn not in ('str','bytes') and not (isinstance(node.func,ast.Attribute) and node.func.attr in ('format','join')):
                result=replace(result,uncertain=True,protections=(),trace=(result.trace+((fn or '<unresolved call>')+'() transformation',))[-8:])
            elif source:
                # A transformed tainted receiver is still tainted; a previously
                # recognized quoting/allowlist protection must not survive it.
                result=replace(result,protections=())
            return result
        if isinstance(node,(ast.BinOp,ast.JoinedStr)):
            children=[self.expr(n) for n in ast.iter_child_nodes(node) if not isinstance(n,ast.operator)]
            result=combine(children,constructed=True)
            if isinstance(node,ast.BinOp) and isinstance(node.op,ast.Add) and len(children)==2:
                left,right=children
                if isinstance(left.literal,str) and isinstance(right.literal,str) and len(left.literal)+len(right.literal)<=1000:
                    result=replace(result,literal=left.literal+right.literal)
                # POSIX quoting only protects a complete argument after a fixed
                # executable, not interpolation inside quotes or executable choice.
                prefix=left.literal
                safe=left.static and isinstance(prefix,str) and prefix.split(' ',1)[0] in ('echo','/bin/echo','/usr/bin/echo','/usr/bin/printf') and re.fullmatch(r'[A-Za-z0-9_./-]+(?: +[A-Za-z0-9_./-]+)* +',prefix)
                protections=set(result.protections)-{'posix-quoted-argument','fixed-posix-command'}
                if safe and 'posix-quoted-argument' in right.protections:protections.add('fixed-posix-command')
                result=replace(result,protections=tuple(sorted(protections)))
            else:
                result=replace(result,protections=tuple(p for p in result.protections if p not in ('posix-quoted-argument','fixed-posix-command')))
            return result
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
        saved=self.env,self.aliases,self.target,self.function_name
        self.function_name=getattr(node,"name","<lambda>")
        saved_returns=self.returns;self.returns=[]
        self.env=self.env.copy();self.aliases=self.aliases.copy();self.target=''
        # Local names shadow outer variables even before their first assignment.
        def locals_in(nodes):
            for n in nodes:
                if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef,ast.Lambda)):
                    if hasattr(n,'name'):yield n.name
                    continue
                if isinstance(n,(ast.Import,ast.ImportFrom)):
                    for alias in n.names:yield alias.asname or (alias.name.split('.')[0] if isinstance(n,ast.Import) else alias.name)
                if isinstance(n,ast.Name) and isinstance(n.ctx,ast.Store):yield n.id
                yield from locals_in(ast.iter_child_nodes(n))
        body=[node.body] if isinstance(node,ast.Lambda) else node.body
        params=node.args.posonlyargs+node.args.args+node.args.kwonlyargs
        for arg in params+([node.args.vararg] if node.args.vararg else [])+([node.args.kwarg] if node.args.kwarg else []):
            self.env[arg.arg]=Value(sensitive=sensitive_name(arg.arg));self.aliases.pop(arg.arg,None)
        for name in locals_in(body):self.env[name]=UNKNOWN;self.aliases.pop(name,None)
        if isinstance(node,ast.Lambda):self.expr(node.body)
        else:self.block(body)
        self.env,self.aliases,self.target,self.function_name=saved
        self.returns=saved_returns

    def block(self,nodes):
        for node in nodes:
            if 'deadline' in self.ctx:check_budget(self.ctx)
            if self.function_name is None and not self.class_depth:
                self.global_env=self.env.copy();self.global_aliases=self.aliases.copy()
            if isinstance(node,ast.Return):
                self.returns.append(self.expr(node.value));break
            if isinstance(node,ast.Raise):
                self.expr(node.exc);break
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                self.function(node);self.env[node.name]=Value(callable_name=node.name) if self.functions.get(node.name) is node else UNKNOWN;self.aliases.pop(node.name,None)
            elif isinstance(node,ast.ClassDef):
                saved=self.env,self.aliases;self.env=self.env.copy();self.aliases=self.aliases.copy();self.class_depth+=1;self.block(node.body);self.class_depth-=1
                # Plain local classes cannot inherit database methods. Dynamic
                # dispatch, decorators, bases and attribute writes stay unresolved.
                identity='class:'+str(node.lineno)
                if not node.bases and not node.keywords and not node.decorator_list and not any(isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and (n.name.startswith('__') or n.decorator_list) for n in node.body):
                    rebound={t.id for t in ast.walk(node) if isinstance(t,ast.Name) and isinstance(t.ctx,ast.Store)}
                    self.local_classes[identity]={n.name for n in node.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name not in rebound}
                self.env,self.aliases=saved
                self.env[node.name]=Value(identity=identity);self.aliases.pop(node.name,None)
            elif isinstance(node,(ast.Import,ast.ImportFrom)):
                for alias in node.names:
                    key=alias.asname or (alias.name.split('.')[0] if isinstance(node,ast.Import) else alias.name)
                    self.aliases[key]=(alias.name if alias.asname else alias.name.split('.')[0]) if isinstance(node,ast.Import) else ('.'*node.level)+(node.module or '')+'.'+alias.name
                    self.env.pop(key,None)
            elif isinstance(node,(ast.Assign,ast.AnnAssign,ast.AugAssign)):
                targets=node.targets if isinstance(node,ast.Assign) else [node.target]
                self.target=' '.join(t.id for t in targets if isinstance(t,ast.Name))
                value=self.expr(node.value)
                if isinstance(node,ast.AugAssign):value=combine([self.expr(node.target),value],constructed=True)
                for target in targets:self.assign(target,value)
                self.target=''
            elif isinstance(node,ast.If):
                if isinstance(node.test,ast.Constant):
                    self.block(node.body if node.test.value else node.orelse);continue
                guard=node.test
                if (isinstance(guard,ast.Compare) and isinstance(guard.left,ast.Name) and len(guard.ops)==1 and isinstance(guard.ops[0],ast.NotIn)
                    and isinstance(guard.comparators[0],(ast.Tuple,ast.List,ast.Set)) and not node.orelse and len(node.body)==1
                    and (isinstance(node.body[0],ast.Raise) or isinstance(node.body[0],ast.Return) and self.function_name is not None)):
                    choices=guard.comparators[0].elts
                    if 0<len(choices)<=32 and all(isinstance(x,ast.Constant) and isinstance(x.value,str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',x.value) for x in choices):
                        self.expr(guard)
                        before_exit=self.env.copy();before_aliases=self.aliases.copy()
                        exit_value=self.expr(node.body[0].exc if isinstance(node.body[0],ast.Raise) else node.body[0].value)
                        if isinstance(node.body[0],ast.Return):self.returns.append(exit_value)
                        self.env=before_exit;self.aliases=before_aliases
                        old=self.env.get(guard.left.id,UNKNOWN)
                        self.env[guard.left.id]=replace(old,protections=tuple(set(old.protections)|{'sql-value'}))
                        continue
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
                    self.env=before.copy();self.aliases=before_aliases.copy()
                    if handler.name:self.env[handler.name]=UNKNOWN;self.aliases.pop(handler.name,None)
                    self.block(handler.body);branches.append(self.env.copy());branch_aliases.append(self.aliases.copy())
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
    count=0;errors=[];limited=[];start=len(ctx['findings'])
    for path,source in files(ctx,('.py',)):
        try:
            tree=ast.parse(source);analyzer=Analyzer(ctx,path);analyzer.prepare(tree);analyzer.block(tree.body)
            if analyzer.limited:limited.append(path)
        except (SyntaxError,ValueError,RecursionError):errors.append(path);continue
        count+=1
    # Keep the strongest supported path per existing fingerprint, not duplicate call-site findings.
    unique={}
    rank={'Low':0,'Medium':1,'High':2}
    for finding in ctx['findings'][start:]:
        prior=unique.get(finding.fingerprint)
        if prior is None or rank[finding.confidence]>rank[prior.confidence]:unique[finding.fingerprint]=finding
    ctx['findings'][start:]=list(unique.values())
    return {'flow_limited_files':limited,'parsed_files':count,'unparsed_files':errors[:100],'note':'Statement-order local flow, aliases and Flask input sources. Branches merge conservatively; bounded plain same-file function calls (depth 4, 100 expansions/file); no execution or runtime reachability proof.'}
