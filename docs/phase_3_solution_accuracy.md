# Phase 3: source-aware solution accuracy

## Implemented scope

The existing solution catalogue, source capture, JavaScript candidate builder,
Recommendation presentation and reviewed remediation workflow are extended.
No new vulnerability categories, external exploitation, repository execution,
automatic GitHub writes or merges are introduced. Solution format version is 4.

### Python SQL

`analysis/python_source_fix.py` recognizes direct SQLite (`sqlite3`) and PostgreSQL
(`psycopg`/`psycopg2`) connection/cursor construction, including module import aliases.
It accepts a deliberately narrow straight-line SELECT equality query constructed
with concatenation or an unformatted f-string and one value variable. The query
may be passed inline or assigned immediately before the execution statement.

The replacement changes only the actual execute call. It preserves the receiver,
table/column/query text and value variable, using `?` for SQLite and `%s` for psycopg.
Value-variable aliases are not expanded against later bindings. The old query
assignment is left intact to avoid changing other uses; the recommendation asks the
reviewer whether that assignment can subsequently be removed.

Unrecognized drivers, SQLAlchemy/Django ORM/JDBC APIs, custom connection factories,
complex control flow, existing parameter arguments, LIKE, dynamic identifiers,
multiple dynamic values, ambiguous calls and intervening assignments receive
manual-review guidance. The generator does not infer a database from a filename
or arbitrary cursor name. Driver identification is static source evidence, not a
runtime connection test. Monkey-patching and cross-function mutation are outside
this local model.

### JavaScript DOM

The existing AST-matched assignment candidates retain actual DOM receiver/value
expressions and surrounding source. Plain-text and intentional-HTML alternatives
remain separate. A DOMPurify candidate is labelled **Illustrative Secure Example**
unless the parsed module contains an explicit default DOMPurify import from
`dompurify`; even that import does not prove installation or runtime availability.
The application is never assumed to want textContent unconditionally. Missing or
ambiguous DOM source falls back to guidance rather than unrelated variable names.

### Secrets, dynamic execution and other uncertain cases

Secret source is redacted before constructing display context. A uniquely matched
Python literal assignment can show an **illustrative** runtime-loading example
using the actual assigned variable. Its environment-variable name is explicitly
proposed, not claimed to exist; import placement, binding and application startup
must be reviewed. This is not a statically validated full-file patch.

Unknown assignment names, JSON/YAML/.env/properties and ambiguous Java/JavaScript
configuration receive guidance rather than unrelated Python or generic-variable
code. Rotation/revocation remains mandatory guidance if the exposed credential
was real. Credentials are never tested and their values never enter examples.
Existing editor restrictions for secret-containing files remain unchanged.

Arbitrary shell logic and eval/exec receive guidance because the intended behavior
cannot safely be reconstructed. Java deserialization no longer invents Jackson
classes or dependencies. Weak cryptography retains the Phase 2 distinction between
checksums, password hashing and encryption; no speculative algorithm substitution
is generated.

## Static validation

`analysis/source_validation.py` validates every new source-matched SQL/DOM candidate:

1. Validate source size/content and parse original and edited files.
2. Re-run the relevant language scanner and the secret detector on isolated
   temporary source files. Never import, execute or build the source.
3. Reproduce the original rule at the recorded line and verify exactly one
   occurrence is removed. Unrelated existing occurrences may remain.
4. Compare finding counts by title/category/severity/confidence and reject a
   candidate introducing new findings in the checked modules.

Only a passing candidate receives **Static validation passed** inside
Recommendation. Runtime behavior is explicitly **Not tested**. This is not
“Vulnerability fixed.” Other language/configuration/dependency modules and
application tests are not covered by this local validation.

The checks are scoped to a bounded AST-matched replacement, not arbitrary draft
verification. The existing draft validation and explicit reviewed publication flow
remain separate and unchanged. Candidates cannot resolve findings or publish PRs.

Per-file limits remain in force. Scan-time source-candidate preparation admits at
most 40 findings and starts no more candidate work after a 20-second preparation
budget; an in-progress bounded check may finish afterward. Later findings retain
redacted context and guidance. A focused editor request can prepare a candidate.

## Confidence and persistence

Generated candidates have Medium fix confidence: source structure and static
checks are established, but application behavior/types/dependencies are untested.
Uncertain cases prefer Low confidence and guidance. Detection confidence is not
changed. No High confidence is claimed from parsing alone.

New scans save redacted solution snapshots, including candidate-specific validation
and labels. Historical snapshots lacking full source are not magically revalidated.
Loading a pinned source file through the existing editor can regenerate supported
candidates. The source-aware SQL marker survives recommendation normalization.
Fingerprint, triage, comparison and source editor/diff/PR review are preserved.

## Verification

Run `python3 -m unittest discover -s tests -q` with project requirements installed.
`tests/test_source_accuracy.py` covers actual variable/query names, driver-specific
placeholders, import aliases, f-strings, rebinding hazards, uncertain APIs/query
shapes, unchanged surrounding code, parsing, target-rule rechecks, regression
rejection, secret redaction, DOM dependency labels and snapshot normalization.
The finding page test verifies the validation label remains inside Recommendation.
Existing pipeline/report/editor/remediation and Phase 1/2 tests are also run.

Verification result: **124 tests passed, 0 failed**. `git diff --check` passed.

Phase 3 stops here; no next phase is started automatically.
