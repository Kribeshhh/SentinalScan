"""Small language adapter registry. Existing module run(ctx) APIs stay compatible."""
from dataclasses import dataclass
from importlib import import_module
from pathlib import PurePosixPath
import ast


@dataclass(frozen=True)
class LanguageAnalyzer:
    language: str
    suffixes: tuple
    module: str
    grammar: str | None = None

    def supports(self, path):
        return PurePosixPath(path).suffix.lower() in self.suffixes

    def parse(self, source):
        if self.language == 'Python':
            return ast.parse(source)
        from scanner.sast.javascript_scanner import parse_source
        root = parse_source(import_module(self.grammar), source)
        if root is None or root.has_error:
            raise ValueError('Unsupported or invalid syntax')
        return root

    def run(self, ctx):
        return import_module(self.module).run(ctx)


ANALYZERS = (
    LanguageAnalyzer('Python', ('.py',), 'scanner.sast.python_scanner'),
    LanguageAnalyzer('JavaScript', ('.js','.jsx','.mjs','.cjs'), 'scanner.sast.javascript_scanner', 'tree_sitter_javascript'),
    LanguageAnalyzer('Java', ('.java',), 'scanner.sast.java_scanner', 'tree_sitter_java'),
)


def analyzer_for(path):
    return next((item for item in ANALYZERS if item.supports(path)), None)
