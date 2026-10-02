# Phase 2: finding quality and integrated recommendations

## Finding layout

Finding details now show severity and detection confidence, category/source, file,
line and function (when recorded), description, evidence and impact. One
**Recommendation** section contains:

1. What to do.
2. A bounded, redacted actual-source excerpt with the detected line highlighted.
3. Suggested Code Solution: either a **Suggested Source Fix**, an **Illustrative
   Secure Example**, or explicit manual-review guidance.
4. Why this change helps.
5. Additional actions, including application/security verification.
6. **Fix Confidence**, separate from detection confidence, with an explanation.

The fingerprint is in collapsed Technical details. Finding status updates remain
available. The old `#code-solution` anchor is preserved inside Recommendation so
existing scan-history links still work; it is not a duplicate section.

## Architecture

- `analysis/solution_engine.py` retains the existing catalogue and source/dependency
  candidate builders. Its public `solution_for()` adds source metadata and applies
  `analysis/recommendation.py` policy. Solution format version is now 3.
- `recommendation_for()` normalizes both new solutions and historical SQLite
  snapshots. Unsupported language/technology assumptions are removed at display
  time; scan history, original evidence and comparison fingerprints are not rewritten.
- `source_metadata()` uses Python AST or existing Tree-sitter parsing to identify an
  enclosing function when full scanned source is available. Unknown names and
  source lines are explicitly reported as unknown/not recorded, never fabricated.
- `finding_presentation()` derives specific descriptions and structured evidence
  from existing recorded flow. It does not infer request arguments or input line
  numbers absent from the evidence. The sink location remains the recorded line.
- `templates/_solution.html` is the reusable Recommendation partial, nested inside
  finding details and also used by the existing editor. `finding_detail.html`
  presents the metadata/evidence and demotes the fingerprint.
- Existing report JSON/CSV/HTML generation continues using `solution_for()` and
  therefore inherits the conservative solution policy. No report/database schema
  migration, external lookup or GitHub write is introduced.

## Context and safe fallbacks

SQL driver identity is not reliably retained by the current detector. Repository
SQL findings therefore explain bound parameters and require manual review rather
than inventing SQLite/JDBC replacements. Arbitrary dynamic shell/process commands
also receive guidance until behavior-preserving replacements can be established.

Python, Java and CommonJS secret examples match their source language and are
explicitly illustrative. JSON/YAML/properties/.env and ambiguous browser/server JS
receive guidance: those formats cannot be assumed to interpolate environment
variables or safely hold browser-visible credentials. Rotation/revocation, history
review, runtime secret storage and avoiding new commits of secrets are included.

Existing source-matched DOM candidates are preserved. Plain text and intentional
HTML are separate choices, with dependency and runtime caveats; textContent is
not applied automatically. Dependency candidates retain their actual manifest
entry and advisory-provided version, while explaining compatibility/other-advisory
limitations. Checksum findings receive contextual review, not password-hashing
recipes; password-sensitive findings discuss password hashing and migration.

Fix confidence is currently Medium for reviewed source candidates/illustrations,
and Low when source-specific code cannot be determined. No result claims High
confidence solely because it parses. This is independent of detection confidence.

## Security and compatibility

All repository strings use Jinja autoescaping. Source rows are limited to 15 rows
and 1,000 characters per row on the finding page; marked rows use CSS, not trusted
HTML. Existing secret masking remains in place, and recommendation data is scrubbed
before use. No repository code is executed. Source editor loading, draft saving,
diff/validation, reviewed PR creation and rescan verification are preserved.

Old snapshots may lack function names or precise source/input metadata. A new scan
captures available metadata; old data is not silently rewritten. Guidance and
examples are not verified runtime fixes. No custom validators, SQL-driver inference,
LLM integration or Phase 3 work is included.

## Tests

Run `python3 -m unittest discover -s tests -q` with the installed requirements.

New `tests/test_finding_quality.py` checks recommendation nesting and uniqueness,
source highlighting, HTML escaping, language selection, source-vs-example labels,
unknown-driver/command fallback, checksum context, old snapshot normalization,
secret redaction, unknown rules and honest evidence. Existing solution tests were
updated to assert guidance rather than require invented SQL examples. Existing
source-candidate, report and remediation editor/workflow tests remain in the suite.

Verification: 112 tests passed, 0 failed (including eight new Phase 2 test methods).
