"""Run existing static rules on draft text in isolated temporary files; no execution."""
import ast
from collections import Counter
import json
from pathlib import Path
import tempfile
import time
from analysis.remediation import validate_content
from scanner.sast import python_scanner,javascript_scanner,java_scanner,html_scanner,config_scanner


def validate_fix(finding,draft):
    result={'syntax':'Unavailable','rule':'Unavailable','regressions':'Unavailable',
            'behavior':'Not tested','can_publish':True,'notes':[]}
    validate_content(draft['original']);validate_content(draft['edited'])
    suffix=Path(draft['path']).suffix.lower()
    module={'.py':python_scanner,'.js':javascript_scanner,'.jsx':javascript_scanner,
        '.mjs':javascript_scanner,'.cjs':javascript_scanner,'.java':java_scanner,
        '.html':html_scanner,'.htm':html_scanner}.get(suffix)
    if finding['category']=='Configuration' and suffix not in ('.html','.htm'):
        module=config_scanner
    if module is None or finding['category'] in ('Secret Exposure','Dependency'):
        result['notes'].append('This rule requires a full scan or additional context; local validation is unavailable.')
        return result
    try:
        if suffix=='.py': ast.parse(draft['edited']);result['syntax']='Passed'
        elif suffix in ('.js','.jsx','.mjs','.cjs','.java'):
            import tree_sitter_java,tree_sitter_javascript
            root=javascript_scanner.parse_source(tree_sitter_java if suffix=='.java' else tree_sitter_javascript,draft['edited'])
            if root is None or root.has_error: raise SyntaxError()
            result['syntax']='Passed'
        elif suffix=='.json': json.loads(draft['edited']);result['syntax']='Passed'
        else: result['notes'].append('No strict syntax validator is available for this format.')
    except (SyntaxError,ValueError,RecursionError):
        result.update(syntax='Failed',can_publish=False)
        result['notes'].append('The edited file cannot be parsed. No source text or parser error payload is logged.')
        return result
    def inspect(source):
        with tempfile.TemporaryDirectory(prefix='sentinelscan-fix-') as directory:
            # Use a fixed basename, never a browser-supplied filesystem path.
            name='candidate'+suffix;path=Path(directory)/name
            path.write_text(source,encoding='utf-8');path.chmod(0o600)
            ctx={'root':Path(directory),'paths':[name],'repository':'draft/source','findings':[],
                 'secrets':set(),'dependencies':[],'osv_enabled':False,'capped':False,'deadline':time.monotonic()+5}
            data=module.run(ctx)
            if ctx['capped'] or any(data.get(key) for key in ('unparsed_files','unparsed_inline_scripts')): raise ValueError()
            return ctx['findings']
    try:
        before=inspect(draft['original']);after=inspect(draft['edited'])
        target=lambda f:f.title==finding['title'] and f.category==finding['category']
        if not any(target(f) for f in before):
            result['notes'].append('The original detection could not be reproduced with the current single-file rule; do not treat its absence as a verified fix.')
        elif any(target(f) for f in after):
            result.update(rule='Still detected',can_publish=False)
            result['notes'].append('The same rule still fires in this file; multiple occurrences require review.')
        else: result['rule']='No longer detected'
        counts=Counter((f.title,f.category) for f in before if f.severity in ('Critical','High'))
        new_counts=Counter((f.title,f.category) for f in after if f.severity in ('Critical','High'))
        result['regressions']='New high-severity finding' if new_counts-counts else 'No new high-severity findings in this module'
        if new_counts-counts: result['can_publish']=False
    except Exception:
        result['notes'].append('Static recheck could not complete; full-scan verification is required.')
        result['rule']='Unavailable'
    result['notes'].append('Only the relevant static module was checked. Application tests and other modules were not run.')
    return result
