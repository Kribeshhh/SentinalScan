"""Validate one bounded source candidate without running repository code."""
import ast
import difflib
from collections import Counter
from pathlib import Path
import tempfile
import time
from analysis.remediation import validate_content
from scanner.sast import python_scanner,javascript_scanner,java_scanner,secret_scanner


def validate_candidate(finding,original,edited):
    result={'status':'Unavailable','syntax':'Unavailable','rule':'Unavailable','regressions':'Unavailable','behavior':'Not tested'}
    try:
        validate_content(original);validate_content(edited)
        suffix=Path(finding['location'].rsplit(':',1)[0]).suffix.lower()
        module={'.py':python_scanner,'.js':javascript_scanner,'.jsx':javascript_scanner,'.mjs':javascript_scanner,'.cjs':javascript_scanner,'.java':java_scanner}.get(suffix)
        if module is None:return result
        parsed_original=None
        for source in (original,edited):
            if suffix=='.py':root=ast.parse(source)
            else:
                import tree_sitter_java,tree_sitter_javascript
                root=javascript_scanner.parse_source(tree_sitter_java if suffix=='.java' else tree_sitter_javascript,source)
                if root is None or root.has_error:raise SyntaxError()
            if parsed_original is None:parsed_original=root
        result['syntax']='Passed'
        def inspect(source):
            with tempfile.TemporaryDirectory(prefix='sentinelscan-candidate-') as directory:
                path=Path(directory)/('candidate'+suffix);path.write_text(source);path.chmod(0o600)
                ctx=dict(root=Path(directory),paths=[path.name],repository='candidate/source',findings=[],secrets=set(),dependencies=[],osv_enabled=False,capped=False,deadline=time.monotonic()+5)
                data=module.run(ctx);secret_scanner.run(ctx)
                if ctx['capped'] or data.get('unparsed_files'):raise ValueError()
                return ctx['findings']
        before,after=inspect(original),inspect(edited)
        target=lambda f:f.title==finding['title'] and f.category==finding['category']
        line=int(finding['location'].rsplit(':',1)[1])
        reproduced=any(target(f) and f.location.endswith(':'+str(line)) for f in before)
        if suffix=='.py':
            ends=[getattr(n,'end_lineno',line) for n in ast.walk(parsed_original) if isinstance(n,ast.Call) and n.lineno==line]
        else:
            ends=[n.end_point.row+1 for n in javascript_scanner.walk(parsed_original) if n.type in ('assignment_expression','call_expression','new_expression','method_invocation','object_creation_expression') and n.start_point.row+1==line]
        end_line=max(ends,default=line)
        changes=[(a,b,c,d) for tag,a,b,c,d in difflib.SequenceMatcher(None,original.splitlines(),edited.splitlines(),autojunk=False).get_opcodes() if tag!='equal' and a<end_line and b>line-1]
        target_changed=bool(changes)
        target_survives=any(target(f) and any(c<int(f.location.rsplit(':',1)[1])<=d for a,b,c,d in changes) for f in after)
        removed=target_changed and not target_survives and sum(target(f) for f in before)-sum(target(f) for f in after)==1
        result['rule']='Target pattern removed' if reproduced and removed else 'Unverified'
        key=lambda f:(f.title,f.category,f.severity,f.confidence)
        new=Counter(map(key,after))-Counter(map(key,before))
        result['regressions']='No new findings in checked modules' if not new else 'New finding detected'
        if reproduced and removed and not new:result['status']='Passed'
        else:result['status']='Not passed'
    except SyntaxError:
        result.update(status='Not passed',syntax='Failed')
    except Exception:
        # Never include parser payloads or source/credentials in diagnostics.
        result['status']='Unavailable'
    return result
