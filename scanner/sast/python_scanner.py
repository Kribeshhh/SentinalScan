"""Python AST checks with import aliases and local assignment context; no evaluation/imports."""
import ast
from scanner.sast.common import add,files


def run(ctx):
    count=0;errors=[]
    for path,text in files(ctx,('.py',)):
        try:
            tree=ast.parse(text)
        except (SyntaxError,ValueError,RecursionError):
            errors.append(path);continue
        count+=1;aliases={};values={}
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):
                for alias in node.names:
                    aliases[alias.asname or alias.name.split('.')[0]]=alias.name
            elif isinstance(node,ast.ImportFrom):
                for alias in node.names:
                    aliases[alias.asname or alias.name]=(node.module or '')+'.'+alias.name
            elif isinstance(node,ast.Assign):
                for target in node.targets:
                    if isinstance(target,ast.Name):
                        values[target.id]=node.value
        def name(node):
            if isinstance(node,ast.Name):
                return aliases.get(node.id,node.id)
            if isinstance(node,ast.Attribute):
                return name(node.value)+'.'+node.attr
            return ''
        def resolve(node):
            return values.get(node.id,node) if isinstance(node,ast.Name) else node
        def literal(node):
            node=resolve(node)
            return isinstance(node,ast.Constant) and isinstance(node.value,(str,bytes))
        def constructed(node):
            node=resolve(node)
            return isinstance(node,(ast.JoinedStr,ast.BinOp)) or (isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr in ('format','join'))
        for node in ast.walk(tree):
            if not isinstance(node,ast.Call):
                continue
            function=name(node.func);first=node.args[0] if node.args else None
            if function in ('eval','exec','builtins.eval','builtins.exec') and first is not None and not literal(first):
                add(ctx,path,node.lineno,'Dynamic Python code execution','Code Security','AST call to '+function+' with a nonliteral argument.','Replace dynamic execution with explicit parsing, dispatch tables or constrained data formats.')
            if function in ('os.system','os.popen') and first is not None and not literal(first):
                add(ctx,path,node.lineno,'Potential shell command injection','Injection','AST shell invocation with a nonliteral command.','Use a fixed executable and an argument list with shell=False; validate allowed arguments.','High')
            if function.startswith('subprocess.') and any(k.arg=='shell' and isinstance(k.value,ast.Constant) and k.value.value is True for k in node.keywords) and first is not None and not literal(first):
                add(ctx,path,node.lineno,'Unsafe subprocess shell invocation','Injection','subprocess call uses shell=True with a dynamic command.','Use an argument array and shell=False.','High')
            if isinstance(node.func,ast.Attribute) and node.func.attr in ('execute','executemany','executescript','raw') and first is not None and constructed(first):
                add(ctx,path,node.lineno,'Potential SQL injection in constructed query','Injection','Query-like method receives an interpolated or concatenated argument (including a locally assigned expression).','Use database-bound parameters instead of concatenation or interpolation.','High','Medium')
            unsafe=function in ('pickle.load','pickle.loads','dill.load','dill.loads','marshal.loads','marshal.load')
            if function=='yaml.load':
                loaders=[k.value for k in node.keywords if k.arg=='Loader']+node.args[1:2]
                unsafe=not any(name(loader) in ('yaml.SafeLoader','yaml.CSafeLoader','yaml.BaseLoader') for loader in loaders)
            if unsafe:
                add(ctx,path,node.lineno,'Potential unsafe deserialization','Deserialization','AST call to '+function+'; trust of serialized input is not established.','Use a data-only format or safe loader; never deserialize untrusted object graphs.','Medium','Medium')
            if function in ('hashlib.md5','hashlib.sha1'):
                add(ctx,path,node.lineno,'Weak hash algorithm usage','Cryptography','AST call to '+function+'. Security-sensitive use has not been established.','Use modern hashes for security, and a dedicated password hashing function for passwords.','Low','Medium')
            if function.endswith('.new') and first is not None and isinstance(resolve(first),ast.Constant) and str(resolve(first).value).lower() in ('md5','sha1'):
                add(ctx,path,node.lineno,'Weak hash algorithm selection','Cryptography','A weak hash name is passed to an algorithm factory.','Use a modern cryptographic algorithm for security-sensitive operations.','Low','Low')
    return {'parsed_files':count,'unparsed_files':errors[:100],'note':'AST and one-step assignment/import-alias context; no interprocedural taint analysis. Unparseable files are excluded from code rules.'}
