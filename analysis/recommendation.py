"""Presentation policy for recommendations, including historical solution snapshots."""
import ast
import re
from pathlib import PurePosixPath
from analysis.redaction import scrub

UNAVAILABLE='Source-specific code solution unavailable — manual review required.'


def source_metadata(finding, source=None):
    location=finding['location'];match=re.search(r':(\d+)$',location)
    path=location[:match.start()] if match else location
    parts=path.split('/',2)
    result={'file':parts[2] if len(parts)==3 else path,'line':int(match[1]) if match else None,'function':'Could not be determined statically'}
    if source is None or not match:return result
    line=result['line'];suffix=PurePosixPath(path).suffix.lower()
    try:
        if suffix=='.py':
            nodes=[n for n in ast.walk(ast.parse(source)) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.lineno<=line<=getattr(n,'end_lineno',n.lineno)]
            if nodes:result['function']=min(nodes,key=lambda n:n.end_lineno-n.lineno).name
        elif suffix in ('.js','.jsx','.mjs','.cjs','.java'):
            from scanner.sast.javascript_scanner import parse_source,walk,text
            import tree_sitter_java,tree_sitter_javascript
            root=parse_source(tree_sitter_java if suffix=='.java' else tree_sitter_javascript,source)
            if root and not root.has_error:
                nodes=[n for n in walk(root) if n.type in ('function_declaration','function_expression','method_definition','method_declaration','constructor_declaration','arrow_function') and n.start_point.row+1<=line<=n.end_point.row+1]
                if nodes:
                    node=min(nodes,key=lambda n:n.end_byte-n.start_byte)
                    name=node.child_by_field_name('name')
                    result['function']=text(name) if name else 'Anonymous function'
    except (SyntaxError,ValueError,RecursionError):pass
    return scrub(result)


def recommendation_for(finding, solution):
    """Reuse candidates; remove unsupported assumptions even from older snapshots."""
    f=dict(finding);s=dict(solution);s['examples']=list(s.get('examples',[]));s['notes']=list(s.get('notes',[]))
    title=f['title'].lower();category=f['category'];repo=f['source']=='Repository'
    suffix=PurePosixPath(re.sub(r':\d+$','',f['location'])).suffix.lower()
    s.setdefault('metadata',source_metadata(f))
    if not s.get('matched'):
        s['action']=f.get('recommendation') or 'Review the affected component and its security requirements before changing code.'
    if s.get('action','').startswith('Replace the vulnerable operation'):
        s['action']=s.get('summary') or f.get('recommendation','Review the affected operation.')
    s.setdefault('why','This reduces exposure at the affected operation. Verify the application behavior and the relevant security control after changing it.')
    if 'dynamic python' in title or 'dynamic javascript' in title:
        s['why']='Parsing a defined data format avoids treating input as executable code. The example only fits data input; expression evaluators and command dispatch need their own constrained design.'
    elif 'deserialization' in title:
        s['why']='Data-only parsing avoids reconstructing arbitrary executable object graphs. Validate the schema and resource limits, and update both producers and consumers.'
    def guidance(action,why):
        s.update(examples=[],before=None,exact=False,action=action,why=why)
    if repo and 'sql injection' in title and not s.get('source_aware'):
        guidance('Use the parameterized-query API provided by the database library used by this application. Keep SQL structure separate from values; use an allowlist for dynamic identifiers.',
                 'Binding values prevents those values from being interpreted as SQL syntax. The database driver and placeholder syntax could not be established reliably.')
    elif repo and ('shell' in title or 'process execution' in title):
        guidance('Review the intended command and shell features. Where behavior permits, use a fixed executable, separate arguments and an allowlist; avoid passing untrusted values to a shell.',
                 'Separating validated arguments from shell syntax reduces command injection risk. Arbitrary shell pipelines cannot safely be replaced without understanding their behavior.')
    elif repo and ('dynamic python' in title or 'dynamic javascript' in title):
        guidance('Source-specific replacement unavailable. Manual refactoring is required because SentinelScan cannot determine the intended dynamic behavior safely.',
                 'Removing dynamic execution requires knowing whether the input represents data, expressions or commands. A generic JSON parser is not a behavior-preserving replacement.')
    elif repo and suffix=='.java' and 'deserialization' in title:
        guidance('Review the expected input format and trust boundary. Replace object deserialization with a bounded data-only format only after defining the schema and updating producers and consumers.',
                 'A made-up data class or library dependency cannot safely replace the actual Java object protocol.')
    elif repo and category=='Cryptography':
        password=f.get('severity')=='High' and bool(re.search(r'password|credential|security-sensitive naming',f.get('evidence',''),re.I))
        if password:
            guidance('Confirm that this operation stores passwords. If so, use a maintained password-hashing library with salts and a work factor, and plan migration and verification of existing hashes.',
                     'Password hashing is deliberately expensive and salted, making offline guessing harder. A fast general-purpose digest is unsuitable for password storage.')
        else:
            guidance('Determine whether this is an ordinary checksum or a security control. A non-security checksum may need no change. For security-sensitive digests or encryption, choose a suitable modern primitive and review compatibility.',
                     'Checksum compatibility, password storage and authenticated encryption have different requirements. Replacing an algorithm without knowing its purpose can break the application.')
    elif repo and category=='Secret Exposure':
        s.update(before=None,exact=False,action='Remove the hardcoded credential and load its replacement securely at runtime.',
                 why='Keeping credentials outside tracked source prevents repository readers from obtaining them directly. Runtime access still needs protection.')
        s['notes']=['If this was a real credential, rotate or revoke it.', 'Review and remove exposed credentials from repository history when appropriate.', 'Supply the replacement through a secret manager or protected runtime environment.', 'Do not commit the replacement secret or expose it to browser JavaScript.']
        s['examples']=[s['secret_example']] if s.get('secret_example') else []
        if s.get('assignment_name'):
            s['action']='Remove the hardcoded value assigned to '+s['assignment_name']+' and configure its replacement at runtime.'
            s['notes'].append('The environment variable name in this example is proposed, not detected configuration. Set it securely before startup. Import placement and os name binding require review; this is not a validated full-file patch.')
        s['fix_reason']='The correct secret-loading mechanism depends on how this file is consumed. Environment substitution is not automatically supported by JSON, YAML or browser JavaScript.'
    elif repo and ('dom html' in title or 'document.write' in title):
        if not s.get('exact'):s['examples']=[]
        s['action']='First determine whether plain text or rendered HTML is intended. Use textContent for plain text; use a maintained sanitizer with an explicit policy for intentional HTML.'
        s['why']='Text insertion does not interpret markup. Sanitization removes disallowed markup when HTML rendering is required; the two choices have different behavior.'
    source_matched=bool(s.get('exact') or (category=='Dependency' and s.get('before') and s.get('before_label','').startswith('Actual dependency entry')))
    if repo:
        # A language inferred only by catalogue defaults is not repository evidence.
        s['examples']=[e for e in s['examples'] if not (e['language'].startswith('Python') and suffix!='.py')]
        if not source_matched:s['before']=None
    if not s['examples']:
        s['exact']=False
        if not source_matched:s['before']=None
    if f.get('status')=='False Positive':
        s.update(examples=[],before=None,exact=False,action='No fix is recommended for a finding marked False Positive.',notes=[],verification=[],why='Review the detection before making an unrelated code change.')
    s['source_matched']=source_matched
    s['kind']='Suggested Source Fix' if source_matched and s['examples'] else 'Illustrative Secure Example' if s['examples'] else 'Remediation guidance'
    s['fix_confidence']='Medium' if s['examples'] else 'Low'
    s.setdefault('fix_reason','The candidate matches scanned source but runtime behavior and dependencies need review.' if source_matched and s['examples'] else 'This is an illustrative example, not a source-specific replacement.' if s['examples'] else 'Insufficient source or framework context to safely generate replacement code.')
    s['unavailable']=None if source_matched and s['examples'] else UNAVAILABLE
    if not s['examples']:
        s['notes']=[note for note in s['notes'] if not note.startswith('Illustrative solution:')]
    if not s['notes'] and f.get('status')!='False Positive':
        s['notes']=['Review the intended behavior, define the accepted input and test the refactored operation before deployment.']
    s['dismissed']=f.get('status')=='False Positive'
    if s['dismissed']:
        s['unavailable']=None
        s['fix_reason']='No replacement is proposed while this detection is marked False Positive.'
    return scrub(s)


def finding_presentation(finding,solution):
    f=dict(finding);title=f['title'].lower();detail=f['description']
    rules=[('sql injection','Dynamically constructed SQL reaches a database execution operation. Review how the query is constructed and whether values are bound separately.'),
           ('shell','A dynamic command reaches a shell execution operation.'),('process execution','A dynamic value reaches a process creation operation; this alone does not establish shell injection.'),
           ('dynamic python','A dynamic value reaches Python code execution.'),('dynamic javascript','A dynamic value reaches JavaScript code compilation or execution.'),
           ('dom html','A dynamic value reaches an HTML assignment without a recognized HTML sanitizer.'),('document.write','A dynamic value reaches document.write without a recognized HTML sanitizer.'),
           ('deserialization','An object deserialization operation was detected. Its safety depends on the input trust boundary and loader controls.')]
    if f['source']=='Repository':
        for key,description in rules:
            if key in title:detail=description;break
        if f['category']=='Secret Exposure':detail='A credential-like literal or token pattern was detected in repository content. The value is redacted and has not been tested for validity.'
        elif f['category']=='Cryptography':detail='A weak cryptographic algorithm was selected. Its security significance depends on whether it is used as a checksum or a security control.'
    evidence=f['evidence'];parts=evidence.split(' → ')
    flow=len(parts)>1 and ('Recognized input ' in parts[0] or 'Dynamic value;' in parts[0])
    context=[]
    for line in (solution.get('context') or '').splitlines()[:15]:
        match=re.match(r'^\s*(\d+) ([> ]) (.*)$',line)
        if match:context.append(dict(number=int(match[1]),highlight=match[2]=='>',code=match[3][:1000]))
    structured=None
    if flow:
        structured={'source':parts[0].replace('Recognized input ','') if parts[0].startswith('Recognized input ') else 'Input source could not be determined statically.',
            'flow':' → '.join(parts[1:-1]) or 'No intermediate variable was recorded.',
            'operation':parts[-1].split('. No protection recognized')[0],
            'protection':'No parameterized query was recognized for the constructed SQL.' if 'sql injection' in title else 'No protection was recognized for this operation.',
            'source_line':'Not recorded'}
    return scrub(dict(description=detail,evidence=structured,context=context,metadata=solution.get('metadata') or source_metadata(f)))
