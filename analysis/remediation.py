"""Bounded source validation and comparison for recommendation advice."""
import difflib
from analysis.redaction import redact_text
from integrations.github import GitHubError

MAX_SOURCE_BYTES = 524288


def validate_path(path):
    if (not isinstance(path, str) or not path or len(path)>400 or path.startswith('/')
            or '\\' in path or any(ord(c)<32 or ord(c)==127 for c in path)
            or any(part in ('', '.', '..', '.git') for part in path.split('/'))):
        raise GitHubError('This finding does not identify an readable source file.')
    if path.startswith('.github/workflows/'):
        raise GitHubError('Workflow files are outside this source preview scope.')
    return path


def validate_content(content):
    if len(content.encode('utf-8'))>MAX_SOURCE_BYTES or any(ord(c)<32 and c not in '\r\n\t' for c in content):
        raise GitHubError('Source preview supports regular UTF-8 source files up to 512 KiB.')
    if redact_text(content)!=content or '[REDACTED]' in content:
        raise GitHubError('This file contains a possible secret or masked content. Edit it securely in your local checkout and rotate exposed credentials. SentinelScan does not retain secret-bearing full source.')
    return content


def source_diff(original,edited,path):
    # Explicit no-newline markers keep downloaded patches applicable to files without final LF.
    lines=difflib.unified_diff(original.splitlines(keepends=True),edited.splitlines(keepends=True),
                               fromfile='a/'+path,tofile='b/'+path)
    return ''.join(line if line.endswith('\n') else line+'\n\\ No newline at end of file\n' for line in lines)
