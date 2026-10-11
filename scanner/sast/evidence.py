"""Versioned semantic evidence; no source literals or runtime-proof claims."""
from dataclasses import dataclass, asdict
from pathlib import PurePosixPath
from analysis.redaction import scrub

# Stable IDs are independent of display wording and existing finding fingerprints.
RULES = {
    'Potential SQL injection in constructed query': ('python.sql.constructed', 'CWE-89', 'A03:2021'),
    'Potential SQL injection in Java query': ('java.sql.constructed', 'CWE-89', 'A03:2021'),
    'Potential shell command injection': ('python.shell.dynamic', 'CWE-78', 'A03:2021'),
    'Unsafe subprocess shell invocation': ('python.subprocess.shell', 'CWE-78', 'A03:2021'),
    'Dynamic Python code execution': ('python.code.dynamic', 'CWE-95', 'A03:2021'),
    'Dynamic JavaScript code execution': ('javascript.code.dynamic', 'CWE-95', 'A03:2021'),
    'Potential unsafe DOM HTML insertion': ('javascript.dom.insertion', 'CWE-79', 'A03:2021'),
    'Potential unsafe DOM HTML assignment': ('javascript.dom.html', 'CWE-79', 'A03:2021'),
    'Potential unsafe document.write': ('javascript.document.write', 'CWE-79', 'A03:2021'),
    'Dynamic Java process execution': ('java.process.dynamic', 'CWE-78', 'A03:2021'),
    'Potential unsafe deserialization': ('python.deserialize.unsafe', 'CWE-502', 'A08:2021'),
    'Potential unsafe Java deserialization': ('java.deserialize.unsafe', 'CWE-502', 'A08:2021'),
    'Weak hash algorithm usage': ('python.hash.weak', 'CWE-328', 'A02:2021'),
    'Weak hash algorithm selection': ('python.hash.selection', 'CWE-328', 'A02:2021'),
    'Weak Java cryptographic algorithm': ('java.crypto.weak', None, 'A02:2021'),
}


@dataclass(frozen=True)
class SemanticEvidence:
    engine: str
    language: str
    end_line: int
    function: str | None
    sources: tuple
    sink: str
    data_flow: tuple
    sanitizers: tuple
    constructed: bool
    calls: tuple
    uncertain: bool
    start_column: int


def semantic(node, value, sink, language, function=None, offset=0):
    """Only abstract labels enter the envelope; never Value.literal or node text."""
    if language == 'Python':
        end = getattr(node, 'end_lineno', node.lineno)
    else:
        end = node.end_point.row + 1
        parent = node.parent
        while parent is not None:
            if parent.type in ('function_declaration', 'function_expression', 'method_definition',
                               'method_declaration', 'constructor_declaration', 'arrow_function'):
                name = parent.child_by_field_name('name')
                function = name.text.decode('utf-8', errors='replace') if name else '<anonymous>'
                break
            parent = parent.parent
    return SemanticEvidence('python-ast' if language == 'Python' else 'tree-sitter',
        language, end + offset, function, value.sources, sink,
        value.trace, ('HTML protection recognized; not applicable to this sink',) if value.html_safe else (),
        value.constructed, value.calls, value.uncertain,
        node.col_offset if language == "Python" else node.start_point.column)


def bounded(value):
    if isinstance(value, str): return value[:512]
    if isinstance(value, (list, tuple)): return [bounded(item) for item in value[:20]]
    if isinstance(value, dict): return {key:bounded(item) for key,item in value.items()}
    return value


def normalized(finding, repository, path, line, detail=None):
    rule, cwe, owasp = RULES.get(finding.title, (None, None, None))
    data = asdict(detail) if detail else {}
    language = data.get('language') or {'.py':'Python', '.js':'JavaScript', '.jsx':'JavaScript',
        '.mjs':'JavaScript', '.cjs':'JavaScript', '.java':'Java', '.html':'HTML', '.htm':'HTML'}.get(PurePosixPath(path).suffix.lower())
    engine = data.get('engine') or {'Secret Exposure':'secret-patterns', 'Configuration':'configuration',
        'Dependency':'dependency-advisory'}.get(finding.category, 'markup')
    return scrub(bounded(dict(schema_version=1, title=finding.title, category=finding.category,
        cwe=cwe, owasp=[owasp] if owasp else [], severity=finding.severity, confidence=finding.confidence,
        repository=repository, file=path, start_line=line or None, end_line=data.get('end_line',line or None),
        start_column=data.get('start_column'), language=language, function=data.get('function'), source=list(data.get('sources',())),
        sink=data.get('sink'), data_flow=list(data.get('data_flow',())), sanitizers=list(data.get('sanitizers',())),
        engine=engine, rule_id=rule, evidence=finding.evidence[:2000], description=finding.description,
        impact=finding.impact, recommendation=finding.recommendation[:2000], suggested_code=None,
        verification_status='Not verified', evidence_kind='semantic candidate' if detail else 'static observation',
        constructed=data.get('constructed'), calls=list(data.get('calls',())),
        reachability='Potential pattern' if not data.get('sources') or data.get('uncertain') else 'Static source-to-sink evidence; runtime reachability not proven',
        flow_scope='bounded same-file calls' if data.get('calls') else 'local; call targets and runtime reachability not proven')))
