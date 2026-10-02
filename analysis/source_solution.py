"""Build narrowly scoped replacement candidates against pinned, validated source."""
import re
from pathlib import PurePosixPath
from analysis.remediation import validate_content


def enrich_source_solution(result,finding,source):
    validate_content(source)
    match=re.search(r':([0-9]+)$',finding['location'])
    if not match:
        result['source_status']='File loaded; the finding has no precise line. Review the full file in the editor.'
        return
    line=int(match[1]);lines=source.splitlines()
    if not 1<=line<=len(lines):
        result['source_status']='The recorded line is outside this file. No exact replacement is proposed.'
        return
    lo=max(1,line-3);hi=min(len(lines),line+3)
    result['context']='\n'.join(f'{n:>4} {">" if n==line else " "} {lines[n-1]}' for n in range(lo,hi+1))
    result['source_status']='Scanned source loaded. The marked line is the detection location; surrounding lines are context, not a replacement range.'
    suffix=PurePosixPath(finding['location'][:match.start()]).suffix.lower()
    if suffix=='.py':
        from analysis.python_source_fix import sql_candidate
        candidate=sql_candidate(finding,source)
        if candidate:result.update(candidate)
        return
    if finding['title']!='Potential unsafe DOM HTML assignment' or suffix not in ('.js','.jsx','.mjs','.cjs'):
        return
    from scanner.sast.javascript_scanner import parse_source,walk,text
    import tree_sitter_javascript
    root=parse_source(tree_sitter_javascript,source)
    if root is None or root.has_error:
        result['source_status']='Source could not be parsed reliably. Review the context manually.'
        return
    matches=[]
    for node in walk(root):
        if node.type!='assignment_expression' or node.start_point.row+1!=line: continue
        left=node.child_by_field_name('left');right=node.child_by_field_name('right')
        if not left or not right or left.type not in ('member_expression','subscript_expression'): continue
        prop=left.child_by_field_name('property') or left.child_by_field_name('index')
        if text(prop).strip('"\'') not in ('innerHTML','outerHTML'): continue
        if node.child_by_field_name('operator') and text(node.child_by_field_name('operator'))!='=': continue
        matches.append((node,left,right,prop))
    if len(matches)!=1:
        result['source_status']='No unique matching assignment at the recorded line. No exact replacement is proposed.'
        return
    node,left,right,prop=matches[0]
    raw=source.encode('utf-8')
    before=raw[node.start_byte:node.end_byte].decode('utf-8')
    if text(right).startswith('DOMPurify.sanitize('):
        result['source_status']='The scanned statement already uses DOMPurify.sanitize. Review sanitizer configuration before proposing another change.'
        return
    candidates=[]
    if text(prop).strip('"\'')=='innerHTML':
        token='"textContent"' if left.type=='subscript_expression' else 'textContent'
        replacement=(raw[node.start_byte:prop.start_byte]+token.encode()+raw[prop.end_byte:node.end_byte]).decode()
        candidates.append({'language':'JavaScript · option A: plain text only','code':replacement+'\n'})
    replacement=(raw[node.start_byte:right.start_byte]+b'DOMPurify.sanitize('+raw[right.start_byte:right.end_byte]+b', {USE_PROFILES: {html: true}})'+raw[right.end_byte:node.end_byte]).decode()
    candidates.append({'language':'JavaScript · option B: intentional HTML','code':replacement+'\n'})
    from analysis.source_validation import validate_candidate
    purifier_imported=any(n.type=='import_statement' and re.match(r'''^import\s+DOMPurify\s+from\s+['"]dompurify['"]''',text(n)) for n in root.named_children)
    for candidate in candidates:
        candidate['kind']='Illustrative Secure Example' if 'DOMPurify.sanitize(' in candidate['code'] and not purifier_imported else 'Suggested Source Fix'
        updated=(raw[:node.start_byte]+candidate['code'].rstrip('\n').encode()+raw[node.end_byte:]).decode()
        checked=parse_source(tree_sitter_javascript,updated)
        if checked is None or checked.has_error:
            result['source_status']='Candidate failed full-file JavaScript syntax validation. No exact replacement is proposed.'
            return
        candidate['validation']=validate_candidate(finding,source,updated)
        if candidate['validation']['status']!='Passed':
            result['source_status']='The candidate could not pass the relevant static rule and regression checks. Manual review is required.'
            return
    result.update(before=before,before_label=f'Actual assignment to replace · lines {line}–{node.end_point.row+1}',
        examples=candidates,exact=True,action='Replace only the assignment shown below with ONE option. Keep surrounding statements and the existing semicolon.',
        source_status='Matched the recorded assignment in scanned source. Both the original and candidate full files parse successfully; runtime behavior has not been verified.')
    result['notes']=[
        'Choose plain text only when markup should not render. This changes formatting and replaces the element’s children.',
        'For intentional HTML, install/import a maintained DOMPurify version as DOMPurify before using the sanitizer option. No dependency is installed automatically. Review allowed markup and URL behavior for your application.',
        'These candidates assume an ordinary HTML element, not a script/style element or a framework-specific object. outerHTML replaces the element itself; its references/listeners may need updating.',
        'A syntax check is not proof of security or functional correctness. Review data flow and test before committing.'
    ]
    result['verification']=[
        'Check normal text/formatting, DOM structure, event listeners and accessibility after the replacement.',
        'In an isolated test, confirm untrusted HTML such as <img src=x onerror=alert(1)> cannot execute script.',
        'Run application tests and re-scan the changed commit. Do not mark the finding resolved based on syntax validation alone.'
    ]
