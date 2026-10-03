# Phase 1: deterministic SAST and DAST finding context

This phase prepares existing findings for better recommendations. No LLM integration
or AI requests were added. The previously implemented optional AI layer remains
unchanged; deterministic scanning and recommendations work without it.

## Storage and architecture

The common finding fields, detection severity/confidence, triage status and
fingerprint are unchanged. `Finding.context_json` is an optional transient JSON
object, not a new database column. `save_finding` sanitizes its values individually
and stores observation context under `finding_context` in the existing
`finding_solutions.data_json` snapshot. No migration is needed. Repository source
capture enriches that snapshot after static analysis. Historical snapshots are
normalized on read; absent observations are marked unknown, never reconstructed
from a live request. Findings, JSON/CSV/HTML reports and Recommendation share the
same normalized snapshot. Source editor, comparison and reviewed PR flows remain.

## Repository context

Context records file, detected line, supported source language, enclosing
function/method when the existing parser can identify it, a bounded redacted source
window, scanner evidence, and recorded source/flow/sink/protection information.
Flow fields come only from detector evidence; arbitrary variable names are not
promoted to request sources. Unknown source, function, framework or database stays
null. A missing recognized sanitizer is not proof that no protection exists.

Database identity is retained when the existing source-specific SQL builder has
established a supported direct SQLite/psycopg/psycopg2 connection/cursor and query.
It is not inferred merely from a module import or filename. Framework inference is
not implemented. Snippets are at most seven lines, 700 characters per line; existing
source capture and solution preparation budgets still apply.

## Website context

Each finding captures the triggering response's redacted URL, GET method, status,
allowlisted relevant headers and scanner evidence. CORS includes the test Origin
and observed policy; cookies include only names and attribute flags. SQL error and
reflection checks retain parameter names, signatures/context labels and actual
probe status. Resource checks retain the resource response, not the home page.
TLS findings retain verification/handshake observations available at detection.
An HTTP response, if present, is separate from the TLS handshake observations.

Authorization and Set-Cookie headers are excluded. URL query values are masked.
CSP nonces are masked. Bodies and cookie values are omitted entirely; the response
snippet field is null with an explicit omission policy. Thus verbose errors,
resource bodies and reflected credentials cannot enter the new context through
raw response excerpts. Relevant signature names remain in evidence.

## Recommendation contract

Existing fields remain for compatibility, with these normalized fields:

- `what_to_change`: deterministic guidance.
- `suggested_code_or_config`: list of existing example/candidate objects.
- `example_type`: `source_specific`, `illustrative`, `configuration` or `none`.
- `why`: rationale.
- `additional_actions`: application notes and verification steps.
- `fix_confidence`: separate from detection confidence.
- `validation_status`: `Passed`, `Failed` or `Not Available`.

All examples must have passed existing static validation for the aggregate status
to be Passed. HTTP configuration is not marked statically validated. Website
suggestions never fabricate backend code: header/cookie configuration examples or
remediation guidance replace generic Python/database implementations. Configuration
examples need compatibility testing (especially CSP and SameSite). Source candidates
continue through the existing source matching and static validation workflow.

## Redaction and limitations

Known detected secrets and existing credential/token/private-key patterns are masked
before snapshot persistence. JSON values are sanitized before serialization to avoid
corrupting JSON. Jinja escaping remains enabled; context is displayed in a collapsed
section inside Recommendation and reports. No source is executed or automatically
modified. Detection confidence is evidence about a security pattern; fix confidence
is confidence in remediation suitability, never proof of runtime correctness.

Redaction is pattern-based and cannot recognize every unlabeled sensitive value.
Retained source remains limited and should be treated as sensitive local data.
No cross-function taint analysis, runtime verification, backend inference, full
response capture or historical backfill is introduced. Re-scan to collect context
missing from old records. No existing finding is deleted or reclassified.

## Verification

Run `python3 -m unittest discover -s tests -q` with requirements installed.
`tests/test_finding_context.py` covers representative source categories, unknown
facts, structured flow, redaction, recommendation fields, cookie/CORS observations,
probe status and website backend neutrality. Existing local website integration
checks persist and inspect context for real lab findings; TLS tests inspect retained
verification state. Source accuracy tests assert recognized drivers and validation.
Existing report, editor, optional AI mock and regression tests remain included.

Phase ends here. Do not start the next phase automatically.

## Completed verification and changed files

Verified with `/tmp/sentinelscan-verify-venv/bin/python`:
- Targeted context suite: 7 passed, 0 failed.
- Complete project suite: 143 passed, 0 failed.
- `git diff --check`: passed.
- No live AI API or remote-target scan was performed; integration uses local labs
  and existing provider mocks. The user's stored scan data was not rewritten.

Added: `analysis/finding_context.py`, `tests/test_finding_context.py`, and this document.

Modified:
- `AGENTS.md`
- `analysis/finding_engine.py`, `analysis/recommendation.py`,
  `analysis/remediation_workflow.py`, `analysis/solution_engine.py`,
  `analysis/source_context.py`
- `scanner/common.py`, `scanner/cookie_scanner.py`, `scanner/cors_scanner.py`,
  `scanner/directory_scanner.py`, `scanner/source_scanner.py`,
  `scanner/sqli_scanner.py`, `scanner/tls_scanner.py`, `scanner/xss_scanner.py`
- `reports/report_generator.py`
- `templates/_solution.html`, `templates/report_document.html`
- `tests/test_foundation.py`, `tests/test_solutions.py`,
  `tests/test_source_accuracy.py`, `tests/test_website_scanner.py`
