import ast
import json
import re
import yaml
from pathlib import PurePosixPath
from scanner.sast.common import add, check_budget, parse_diagnostic


def flatten(value):
    seen=set();stack=[('',value,0)];count=0
    while stack and count<5000:
        prefix,node,depth=stack.pop();count+=1
        if depth>20:
            continue
        if isinstance(node,(dict,list)):
            if id(node) in seen:
                continue
            seen.add(id(node))
        if isinstance(node,dict):
            stack.extend((prefix+'.'+str(k),v,depth+1) for k,v in node.items())
        elif isinstance(node,list):
            if '*' in node:
                yield prefix,'*'
        else:
            yield prefix,node


def json_configuration(text, name):
    """JSONC only for TypeScript/JavaScript project configuration, never JS evaluation.

    Replace comments/commas with spaces to preserve parser line/column positions.
    Quoted strings (including escaped quotes and URL slashes) remain byte-for-byte.
    """
    if not re.fullmatch(r'(?:tsconfig|jsconfig)(?:\.[A-Za-z0-9_-]+)*\.json', name):
        return json.loads(text)
    chars = list(text); i = 0; quoted = False
    while i < len(text):
        char = text[i]
        if quoted:
            if char == '\\': i += 2; continue
            if char == '"': quoted = False
        elif char == '"': quoted = True
        elif text.startswith('//', i):
            end = text.find('\n', i)
            if end < 0: end = len(text)
            for j in range(i, end):
                if text[j] not in '\r\n': chars[j] = ' '
            i = end; continue
        elif text.startswith('/*', i):
            end = text.find('*/', i + 2)
            if end < 0: raise json.JSONDecodeError('Unterminated JSONC comment', text, i)
            for j in range(i, end + 2):
                if text[j] not in '\r\n': chars[j] = ' '
            i = end + 2; continue
        i += 1
    stripped = ''.join(chars); i = 0; quoted = False
    while i < len(stripped):
        char = stripped[i]
        if quoted:
            if char == '\\': i += 2; continue
            if char == '"': quoted = False
        elif char == '"': quoted = True
        elif char == ',':
            end = i + 1
            while end < len(stripped) and stripped[end].isspace(): end += 1
            # A preceding value is required: reject [,] and {,}, not turn them empty.
            previous = i - 1
            while previous >= 0 and stripped[previous].isspace(): previous -= 1
            if end < len(stripped) and stripped[end] in ']}' and previous >= 0 and stripped[previous] not in '[{,:':
                chars[i] = ' '
        i += 1
    return json.loads(''.join(chars))


def run(ctx):
    count=0;errors=[];diagnostics=[]
    for path in ctx['paths']:
        check_budget(ctx)
        name=PurePosixPath(path).name
        python_config=name in ('config.py','settings.py') or bool(re.fullmatch(r'(?:config|settings)_[A-Za-z0-9_]+\.py',name))
        if not (name.startswith('.env') or path.endswith(('.json','.yaml','.yml','.properties','.ini','.cfg','.conf')) or python_config):
            continue
        count+=1;entries=[]
        try:
            text=(ctx['root']/path).read_text(encoding='utf-8-sig')
            if path.endswith('.py'):
                for node in ast.walk(ast.parse(text)):
                    if isinstance(node,(ast.Assign,ast.AnnAssign)):
                        targets=node.targets if isinstance(node,ast.Assign) else [node.target]
                        try:
                            value=ast.literal_eval(node.value)
                        except (ValueError,TypeError):
                            continue
                        entries.extend((t.id,value,node.lineno) for t in targets if isinstance(t,ast.Name))
            elif path.endswith('.json'):
                entries=[(key,value,1) for key,value in flatten(json_configuration(text,name))]
            elif path.endswith(('.yaml','.yml')):
                aliases=0
                for index,event in enumerate(yaml.parse(text)):
                    aliases+=isinstance(event,yaml.AliasEvent)
                    if index>10000 or aliases>20:
                        raise ValueError('Configuration structure limit exceeded')
                entries=[(key,value,1) for key,value in flatten(yaml.safe_load(text))]
            else:
                for line_number,line in enumerate(text.splitlines(),1):
                    match=re.match(r'\s*([\w.-]+)\s*[:=]\s*([^#\r\n]+)',line)
                    if match:
                        entries.append((match.group(1),match.group(2).strip().strip('"\''),line_number))
        except (ValueError,TypeError,SyntaxError,RecursionError,yaml.YAMLError,OSError) as error:
            errors.append(path);diagnostics.append(parse_diagnostic(path,error));continue
        for key,value,line in entries:
            normalized=key.lower().strip('.').replace('-','_')
            leaf=normalized.split('.')[-1]
            enabled=value is True or str(value).lower() in ('true','1','yes','on','development')
            disabled=value is False or str(value).lower() in ('false','0','no','off')
            if (leaf in ('debug','flask_debug','debug_mode') and enabled) or (leaf in ('flask_env','node_env') and str(value).lower()=='development'):
                add(ctx,path,line,'Debug or development mode configured','Configuration','A parsed configuration field enables debug/development behavior.','Disable debug/development mode in production and separate environment-specific configuration.','Medium','High')
            if disabled and (leaf in ('session_cookie_secure','session_cookie_httponly','csrf_enabled','wtf_csrf_enabled','verify_ssl','ssl_verify','check_hostname') or normalized.endswith('server.ssl.enabled')):
                add(ctx,path,line,'Security control disabled in configuration','Configuration','Parsed security setting '+key+' is disabled.','Enable the relevant cookie, CSRF or TLS verification protection outside an isolated test environment.','Medium','High')
            if leaf=='allowed_hosts' and (value=='*' or isinstance(value,list) and '*' in value):
                add(ctx,path,line,'Wildcard allowed hosts configuration','Configuration','ALLOWED_HOSTS accepts arbitrary hostnames.','Allow only the deployment hostnames that the application serves.','Low','High')
    return {'configuration_files':count,'parsed_files':count-len(errors),'parse_errors':diagnostics[:100],'unparsed_files':errors[:100],'note':'Literal configuration inspection only; environment overrides and runtime behavior are not evaluated. JSON/YAML locations are file-level line 1.'}
