# Phase 3: unified Recommendation for SAST and DAST

> Current policy: [Final simplification (2026-10-04)](#final-simplification-2026-10-04)
> and the subsequent updates govern the current application. Sections before that
> heading record the historical phase, including its removed manual AI controls;
> they are not active instructions to restore that workflow.

Scanner guidance and AI review remain separate internally. One composition layer
now produces the user-facing Recommendation on finding details, in the existing
source editor, and in newly generated HTML/JSON/CSV reports. No scanner, provider
API, detection rule, fingerprint, status or risk-scoring behavior is replaced.

## Composition

`analysis/recommendation_composer.py` supplies `compose` and `final_solution`.
`finding_solution` remains the deterministic source used when preparing AI requests;
AI output is never fed back as the next request's base recommendation.

The final structure includes `what_to_change`, `suggested_code_or_config`,
`example_type`, `why`, `additional_actions`, `fix_confidence`, `validation_status`
and `ai_assisted`. Existing aliases remain for compatibility with solution consumers.
The composer copies its inputs; it does not rewrite scanner findings or AI reviews.

Selection rules:

- AI disabled: use deterministic guidance, even if a saved review exists. No empty
  AI panel, AI requirement, or disabled-AI warning appears.
- Enabled but no valid review: use deterministic guidance.
- Valid guidance-only enhancement: improve the action/rationale while retaining
  useful deterministic code and essential application/security actions.
- Eligible AI example: replace the base examples with one selected example, never
  append a second copy of substantially identical code. Equal snippets differing
  only in trailing whitespace are deduplicated. Different deterministic alternatives
  may remain when they have meaningfully different behavior.
- Failed/malformed AI result, failed static checks, or unvalidated source-specific
  AI code: retain the deterministic recommendation. No fabricated validation pass.
- Explicitly triaged False Positive: preserve the deterministic no-fix policy.

A failed refresh records a small `_ai_review_failed` presentation flag in the
existing solution snapshot. The previous AI record is retained internally, but
pages/editor/reports use deterministic output until another review succeeds.
This requires no migration. The flag is stripped from composed report output.
Reports already generated remain immutable snapshots.

## One UI

The existing Recommendation section now contains one What to change, Current Code
when available, chosen Suggested Code Solution / Illustrative Secure Example /
Configuration Example / Suggested Solution, rationale, additional actions, Fix
Confidence, and validation. The small **AI-assisted recommendation** indicator
appears only when eligible AI content contributed.

No separate Scanner Guidance, AI Explanation or AI-Assisted Suggested Fix panel is
rendered. The optional consent form is collapsed under Improve with AI. The old
`#code-solution` and `#ai-review` navigation anchors remain where applicable. The
source editor no longer repeats the original scanner recommendation above the
composed section. Review/Edit continues through the existing manual workflow.

Detection Confidence remains beside the finding severity/status metadata.
Fix Confidence belongs to remediation. Model confidence is advisory and cannot
upgrade static validation or prove runtime correctness. The existing redaction and
Jinja escaping protect context, code and prose; raw model HTML is not rendered.

## Repository and website behavior

Source-specific repository AI code is selected only after the existing static
validator passed it against matched local source. The exact supplied excerpt is
shown as Current Code. These checks do not test runtime behavior or semantic
compatibility. Unsupported or unvalidated candidates leave deterministic guidance
or validated deterministic code intact. Illustrative examples are labelled as such.

Secret findings preserve redacted source and mandatory rotation/revocation, history
review and runtime storage guidance. AI cannot introduce a code recipe into a secret
finding. A YAML credential does not become a fabricated Python implementation.

Website output cannot be a Suggested Source Fix. Only supported configuration
examples are eligible; backend source remains unknown. Website SQL-error findings
receive guidance and an explicit backend-source-unavailable message. Validation is
**Requires implementation and re-scan**, not Passed. Header/cookie/CORS/TLS examples
remain advisory, with the Phase 2 configuration grammar restrictions.

## Reports

`report_data` reads the same composer as the UI. The exported finding recommendation
text is the chosen final action, and `solution` contains the composed final data,
including `ai_assisted` and Recommendation Source. HTML shows one recommendation;
CSV's recommendation column agrees with its structured solution JSON. No raw AI
review envelope, prompts, original_code provider field or provider response is
exported. Existing solution field aliases are retained for machine compatibility.
No finding record is overwritten with the exported text. Newly generated reports
respect the current AI-enabled setting and failed-refresh state.

## Five rendered examples

Open [the read-only rendered preview](phase_3_recommendation_examples.html).
It was generated from actual Jinja finding-page output using temporary SQLite test
fixtures, not user scan results. AI responses were mocked; controls are inactive.

1. Repository, AI OFF: matched SQLite call with deterministic bound-value solution.
2. Repository, AI ON: one selected SQLite solution with improved context-specific
   wording and the AI-assisted indicator; no duplicate deterministic code example.
3. Website, AI OFF: deterministic `X-Content-Type-Options: nosniff` configuration.
4. Website, AI ON: one configuration example with enhanced rationale/actions and
   the AI-assisted indicator; no invented backend code.
5. AI failure after a prior enhancement: one deterministic website recommendation;
   the old review remains stored internally and the indicator is absent.

The preview does not claim that a real provider generated these suggestions.

## Files changed in this phase

Added:
- `analysis/recommendation_composer.py`
- `tests/test_unified_recommendation.py`
- `docs/phase_3_unified_recommendation.md`
- `docs/phase_3_recommendation_examples.html`

Modified:
- `app.py`, `remediation_routes.py`, `llm_routes.py`
- `reports/report_generator.py`
- `templates/_solution.html`, `templates/_ai_review.html`,
  `templates/finding_editor.html`, `templates/report_document.html`
- `tests/test_llm_review.py`, `tests/test_solutions.py`
- `README.md`, `AGENTS.md`

Earlier Phase 1/2 changes are preserved. No live server restart, user-database
modification, live AI request, repository publication or website modification was
performed during this phase.

## Verification and limits

Using `/tmp/sentinelscan-verify-venv/bin/python`:

- Full project suite: **162 tests passed, 0 failed**.
- Focused unified-recommendation suite: **8 passed, 0 failed**.
- `git diff --check`: passed.

Tests verify disabled/enabled/failure rendering, failed refresh and recovery,
deduplication, source validation fallback, website backend rejection, secret/YAML
policy, confidence/indicator placement, escaped model text, unchanged findings,
and final HTML/JSON/CSV recommendation consistency. Existing scanner, provider-mock,
editor, persistence and reporting suites continue to run.

No live model quality or provider availability is established by mocked tests.
Missing historical source/context requires a new scan or loading pinned source.
Static validation is not a guaranteed fix. Redaction remains pattern-based and may
miss unknown unlabeled sensitive formats; sharing context still requires consent.
This phase does not automate application, publication, merging or resolution.

Stop here; Phase 4 is not started.

## Final simplification (2026-10-04)

This section supersedes the historical manual activation and expanded UI above.
The previous partial task had added concise finding summaries, a single collapsed
Technical Details container, and rejection of generic/no-op AI wording. These were
kept. The extra `analysis/finding_ui.py` helper was consolidated into existing
`analysis/recommendation.py`; its duplicate imports were removed. The obsolete
`llm_routes.py` and `_ai_review.html` were removed after migrating callers/tests.
The existing AI orchestration moved into `analysis.llm_review.refine_finding`;
`refine_scan` invokes it from the existing ScanManager completion callback. No new
provider, detector, queue, table, recommendation engine or dependency was introduced.
Pre-existing repository accuracy changes in the working tree were preserved, not
reverted or extended. No new accuracy claim is made.

### Automatic refinement and fallback

Detection finishes and persists its findings/context first. With LLM_ENABLED and
provider configuration available, at most 20 stored candidates per new scan are
refined in severity order. A 60-second between-review budget and first-error stop
bound optional work; the current provider review retains its transport bounds and
may finish after that budget. No automatic retries or bulk historical processing.
The existing single-worker queue serializes this work; it can delay the next scan.
AI is disabled by default. Enabling it authorizes this external redacted-context
processing for new scans. Missing configuration skips refinement entirely.

Pages, editor and report rendering only read the same final composer; they never
make model requests. Base guidance is immediately usable, and refreshing after
refinement shows accepted contributions. Older saved reviews remain compatible;
rescan to obtain new context/refinement. No manual AI button or route remains.
The AI Assisted badge appears only for an accepted contribution. Failed, malformed,
generic/no-op or unvalidated source code falls back to deterministic output. AI
cannot alter the finding, severity, detection confidence, fingerprint, risk or triage.
A failed generated-code check remains visible; secret rotation/history guidance is
not hidden. Review/Edit → draft → diff → explicit publication → PR is preserved.

### Context audit

Repository `retain_context` already saves multi-line source anchors and structured
analysis/evidence packages in `finding_solutions`, not merely a one-line message.
The package carries source/sink/flow, known function/framework labels, protections,
provenance and bounded affected/related excerpts. `prepare_evidence` preserves its
allowlisted fields for both existing review passes. Legacy `prepare` retains the
stored excerpt and known repository context. No new flow engine or expanded source
collection was needed. The new callback reads these snapshots after capture completes.
Pinned draft source is only used locally by the unchanged static validator; it is
never included as a whole-file payload. Without it, AI source code cannot be labelled
validated or replace the base. Unknown APIs/frameworks remain unknown.

Website `issue` → `website_context` → `save_finding` already retains the actual
triggering response status/URL and safe headers, parameter, CORS/cookie/TLS details,
reflection context or new database signatures. SQL comparisons retain baseline and
probe status; raw bodies, auth and cookie values stay excluded. `prepare` uses the
same whitelist. No backend source is invented. Existing relevant context already
survives to the composer and Technical Details, so no detector handoff was rewritten.
Tests inspect automatic provider payloads and immutable detection after both scans.

### Website scanner audit

All checks below are retained. The sole change in `scanner/website_scanner.py` is
shared completion orchestration for optional recommendation refinement. No website
check, network transport, DNS safety rule, category or detection threshold changed.

| Component | Current implementation | Library/tool | Decision | Reason |
|---|---|---|---|---|
| URL/target validation | Normalize HTTP(S), IDNA, ports, fragment removal; reject credentials/ambiguous hosts | urllib.parse, ipaddress, dnspython | KEEP | Small validation policy is necessary |
| Authorization | Explicit checkbox and CSRF on scan POST, private-lab opt-in | Flask, hmac | KEEP | Target permission and local scope remain explicit |
| SSRF protection | Validate all addresses, pin connections, restrict redirects, block metadata/special ranges | ipaddress, socket, HTTP client | KEEP | Preserves target boundary across requests |
| DNS | Bounded A/AAAA/CNAME lookups with system resolver fallback; retain pinned inventory | dnspython, system resolver | KEEP | Handles resolver failures without bypassing address checks |
| Ports | Restricted TCP/version-light inventory; bounded fallback if unavailable | Nmap, defusedxml, socket | KEEP | Appropriate optional mature tool; open ports alone are not vulnerabilities |
| HTTP | GET only, pinned IP/Host/SNI, verified TLS, redirect/request/byte/time limits | http.client, socket, ssl | KEEP | Custom wrapper enforces scope and resource controls |
| Headers | HTML header presence/value and conservative CSP/framing/HSTS checks | Existing response parser + small custom policy | KEEP | Small, understandable checks; CSP is not exhaustively evaluated |
| Cookies | Attribute flags only; omit cookie values | http.cookies.SimpleCookie | KEEP | Established parser; sensitive-state relevance needs review |
| TLS | Verified handshake, certificate trust/expiry, negotiated protocol/cipher | ssl, cryptography.x509 | KEEP | Appropriate libraries; not full protocol/cipher enumeration |
| Technologies | Passive header/cookie-name/asset/generator indicators | BeautifulSoup, re | KEEP | Inventory only; framework heuristics explicitly uncertain |
| Resources | Bounded paths, random missing-page comparison, Git/env/index signatures | hashlib, re, existing HTTP client | KEEP | 200/401/403 alone never establishes vulnerability; soft-404 heuristic remains |
| CORS | One untrusted Origin GET and policy comparison | Existing HTTP client + custom policy | KEEP | No authenticated exploitation claim; wildcard+credentials is informational |
| XSS | Harmless random markers, at most five eligible query parameters, context inspection | secrets, urllib.parse, BeautifulSoup | KEEP | Low-confidence candidates only; no JS execution/bypass proof |
| SQL injection | One quote per eligible parameter, compare new DB-error signatures | re, existing HTTP client | KEEP | Status/length alone is insufficient; no extraction/time-delay payloads |
| Disclosure | Error/version/source-map signatures; reuse SQL error matcher | re, shared SQL signatures | KEEP | Shared matching avoids a duplicate engine; indicators remain qualified |

### Verification and limitations

Tests use temporary SQLite databases, mocked providers/GitHub and local HTTP/TLS
labs. Provider schema, secret redaction, both review passes, unsafe generated code,
source matching, failure fallback, report consistency and reviewed remediation
remain covered. Live model quality, CodeQL and remote target availability are not
established by these tests. SAST/DAST false positives and blind spots remain as
previously documented. Automatic caps can leave findings with deterministic guidance;
static validity never proves runtime safety or a guaranteed fix.

Final verification: **242 tests passed, 0 failed, 0 skipped** in 49.787 seconds.
Command: `SENTINELSCAN_TEST_SEMGREP=/tmp/sentinelscan-semgrep-verify/bin/semgrep
/tmp/sentinelscan-verify-venv/bin/python -m unittest discover -s tests -v`
(with a temporary pycache prefix). Includes real Semgrep 1.179.0, local HTTP/TLS,
Flask-process restart/persistence, reports/downloads, comparisons and remediation.
AI providers, GitHub and CodeQL are mocked; no live AI quality or production accuracy
is claimed. Browser checks used labelled isolated fixtures at desktop and 390px: one
recommendation, no manual AI control, working disclosure and no horizontal overflow.
User scan history was not used by the tests.

### Consolidation file inventory

Modified application files: `app.py`, `analysis/llm_review.py`,
`analysis/recommendation.py`, `analysis/recommendation_composer.py`,
`scanner/website_scanner.py` (completion callback only), `static/css/style.css`,
`templates/finding_detail.html`, `templates/_solution.html`.
Kept the partial task's new `templates/_finding_technical.html` and
`tests/test_finding_simplification.py`; each has one responsibility, not a second
recommendation implementation. Removed unused earlier-layout CSS selectors.

Updated tests: `tests/test_llm_review.py`, `tests/test_llm_sast_dast.py`,
`tests/test_unified_recommendation.py`, `tests/test_final_validation.py`,
`tests/test_repository_phase4.py`, `tests/test_finding_quality.py`,
`tests/test_solutions.py`, `tests/test_finding_simplification.py`.

Updated documentation: `AGENTS.md`, `README.md`, `context/architecture.md`,
`context/ui-context.md`, `context/progress-tracker.md`, this document,
`docs/phase_2_finding_quality.md`, `docs/phase_2_llm_integration.md`,
`docs/phase_4_llm_and_validation.md`, `docs/phase_4_validation.md`,
`docs/repository_upgrade_phase_4.md`. Historical phase records explicitly link to
this superseding activation policy rather than erasing their historical results.

Removed: `llm_routes.py`, `templates/_ai_review.html`, and the partial task's
untracked `analysis/finding_ui.py` (merged into existing recommendation policy).
No database, report, secret/configuration or user source file was removed.

Final `git diff --check` passed. Pre-task hashes confirm all protected scanner,
risk, finding and correlation files unchanged except the documented shared queue
callback in `scanner/website_scanner.py`. The local app was restarted on port 5001
with no active scans; its 1,247 findings remain intact. The iCloud-offloaded SQLite
file initially returned an I/O error; reading its bytes hydrated it without replacing
or resetting the database. Browser verification of the live finding confirms one
recommendation, one Technical Details container and no manual AI button. Isolated
preview tab/server were closed. Server-memory GitHub connections clear on restart.

## Illustrative fallback examples (2026-10-04)

The final composer retains exact source-specific fixes unchanged. When no usable
code is available, it can add one short **Example Secure Pattern** inside the same
card, using the existing recommendation policy and dependency builder. This is
illustrative, has Low fix confidence and Not Available static validation, and is
never a replacement span or an automatically applied edit. Unknown SQL APIs use
pseudocode; DAST never infers a backend framework. Supported dependency ecosystems
(npm/PyPI) use recorded package names and fixed releases only where the retained
ranges exclude the candidate. Missing/unsupported/overlapping range information
uses `<verified-safe-version>`; this placeholder is not an installable version.
Even an advisory-listed release needs other-advisory and compatibility review.
Python credential examples contain only proposed runtime names, never secrets.
Operational, unknown and dismissed findings may remain text-only. Existing
illustrative/configuration snippets use the same label; source-specific labels
and validation remain intact. UI/editor/new reports share the final composition;
historical snapshots need no database rewrite. No scanner or AI workflow changed.

Illustrative fallback verification: 247 tests passed, 0 failed, 0 skipped in
19.946 seconds, including real Semgrep and mocked provider boundaries. Existing
no-example assertions were migrated to check labelled pseudocode/manifest examples.
Tests cover exact fix preservation, missing versions, overlapping advisory ranges,
historical snapshot UI, report consistency, redaction and operational text-only
fallbacks. Live finding 1247 verified visually; no scanner/AI transport changes.

Current/recommended code display: the existing Recommended Fix card now pairs
retained actual source with a statically validated source replacement, or a complete
matched dependency entry with an advisory-supported fixed release. Historical
dependency snippets may supply a unique complete recorded entry; advisory metadata
alone never supplies Current Code. Missing, truncated or ambiguous current entries
retain Example Secure Pattern. Website/secret findings never get fabricated pairs.
Desktop uses two columns; mobile stacks them. Each block has its own copy control.
Source context remains in Technical Details without a duplicate Current Code label.
No detector, source capture, AI workflow or publication behavior changed.

Paired-display verification: 251 tests passed; `git diff --check` passed. Live
finding 1247 shows retained sanitize-html 1.4.2 beside advisory candidate 1.11.4.
Browser layout checks: desktop two columns, 390px single column without overflow.
No scanner changes or new AI calls. Existing local app restarted on port 5001.
