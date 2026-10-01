"""Retain bounded redacted excerpts and file hashes, never a full source checkout."""
import hashlib
import re
from pathlib import Path
from analysis.redaction import TOKEN_PATTERNS, redact_text


def mask_source(source,known=()):
    # Keep line coordinates even when a private key spans several lines.
    def mask(value): return '[REDACTED]'+'\n'*value.count('\n')
    for value in sorted(set(known),key=len,reverse=True):
        if value: source=source.replace(value,mask(value))
    for _,pattern in TOKEN_PATTERNS:
        source=re.sub(pattern,lambda m:mask(m.group()),source)
    return '\n'.join(redact_text(line) for line in source.split('\n'))


def retain_context(db,scan_id,root,paths,repository,commit,known=()):
    grouped={};budget=1024*1024
    for finding in db.execute('SELECT id,location FROM findings WHERE scan_id=?',(scan_id,)):
        location=finding['location'];prefix=repository+'/'
        if not location.startswith(prefix): continue
        match=re.fullmatch(r'(.+):([0-9]+)',location[len(prefix):])
        if match and match[1] in paths:
            grouped.setdefault(match[1],[]).append((finding['id'],int(match[2])))
    with db:
        for path in paths:
            raw=(Path(root)/path).read_bytes()
            db.execute('INSERT OR REPLACE INTO scan_files VALUES (?,?,?)',(scan_id,path,hashlib.sha256(raw).hexdigest()))
            if path not in grouped or budget <= 0: continue
            lines=mask_source(raw.decode('utf-8-sig'),known).splitlines()
            for finding_id,line in grouped[path]:
                if not 1<=line<=len(lines): continue
                first=max(1,line-3);last=min(len(lines),line+3)
                excerpt='\n'.join(text[:1000] for text in lines[first-1:last])
                size=len(excerpt.encode())
                if size>budget: continue
                budget-=size
                db.execute('INSERT OR REPLACE INTO finding_context VALUES (?,?,?,?,?,?)',
                    (finding_id,path,commit,first,line,excerpt))
