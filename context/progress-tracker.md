# Progress Tracker

Update after every meaningful implementation change. Last updated: 2026-10-04.

## Current Phase

Maintenance. Prior requested scanner upgrade phases and accuracy/readability work
are complete. Six-file context adoption is complete. Final simplification replaces the earlier UI-only task.

## Current Goal

Final product polish complete: read-only recommendations and consistent responsive
Flask/Jinja UI. Scanner and automatic AI recommendation architecture preserved.

## Completed

- Existing Flask/SQLite foundation, website DAST and GitHub repository SAST.
- Finding management, history, comparison, trends and HTML/JSON/CSV reports.
- Source context, unified Recommendation, static fix validation, editor/diff/PR flow.
- Optional automatic AI refinement after new scans when enabled/configured; optional bounded local Semgrep/CodeQL adapters.
- Scanner evidence/correlation and frozen evaluation harness.
- Accuracy/readability maintenance: action-first responsive findings, collapsed
  detail, constant dispatch/computed property handling and narrow protection checks.
- Added populated `CLAUDE.md` and six context documents; connected `AGENTS.md`.
  Adapted generic TypeScript/Next.js/npm examples to the existing Python stack.

## Verification Baseline (historical, not rerun for context adoption)

Latest implementation run: 230 tests passed, 0 failed, including real Semgrep.
Original 54-case authored set after maintenance: custom TP26/FP4/TN23/FN1,
F1 91.23%; custom + Semgrep TP26/FP5/TN22/FN1, F1 89.66%. These are not
production accuracy estimates. The separate 26-case set is now consumed, not a
fresh future holdout. Details: `docs/accuracy_and_finding_readability.md`.
Context-adoption verification at that time checked file completeness, links and whitespace only.

## Completed final simplification (historical)

Kept the concise partial UI and generic/no-op AI fallback. Consolidated the new
display helper into existing recommendation policy, removed the manual AI route and
consent partial, and migrated review orchestration into the existing AI module.
The scan completion hook refines persisted candidates with bounded context and
deterministic fallback. Website checks and repository rules remain unchanged.
Focused verification: 59 tests passed, then 26 automatic/provider tests passed.
Full suite: **242 passed, 0 failed, 0 skipped** (49.787s), with real Semgrep 1.179.0;
AI/GitHub/CodeQL mocked. Desktop and 390px browser checks passed with isolated
fixtures: one recommendation, no AI button, working details and no page overflow.
Final simplification is complete; no new phase started.

## Open Questions / Known Limits

- No outstanding decision blocks adoption of these context files.
- Known detection false positives and blind spots remain; see accuracy documentation.
- CodeQL live accuracy and live LLM quality have not been measured.
- Multi-user access control/deployment would require a separate specification.

## Architecture Decisions

- Keep Flask/Jinja/SQLite/vanilla JavaScript; no frontend build system.
- Deterministic detection remains independent of optional AI review.
- Preserve the detailed maintenance constraints in `AGENTS.md`; the context files
  are a concise current map, not replacements for subsystem security requirements.

## Session Notes

Default entry point is `python3 app.py` on port 5000. The last session started the
app on 5001 because macOS Control Center occupied 5000; verify live state before
assuming that process persists. An offloaded local database was hydrated by a
read and reopened successfully; do not replace history to work around I/O errors.
Downloads template originals were left unchanged. No application code or database
changes were needed for this documentation task.

Final checks: `git diff --check` passed; protected scanner hashes match apart from
the shared completion hook. Local server restarted on 5001, 1,247 findings retained.
Live page shows the simplified UI. Temporary preview closed. No live AI was called.

## Current small maintenance request: illustrative fallback

Implemented examples in the existing composer/policy and dependency builder; exact
fixes remain unchanged. Recorded dependency versions or explicit placeholders,
backend-neutral website pseudocode and safe Python patterns are clearly labelled.
No scanners or AI workflow changed. Verification complete: **247 tests passed,
0 failed, 0 skipped** (19.946s), including real Semgrep; providers remain mocked.
Live finding 1247 displays the recorded sanitize-html 1.11.4 advisory example,
labelled illustrative and unvalidated. `git diff --check` passed. Server restarted
on 5001 with no active scans; all 1,247 findings retained. Task complete.

## Current/recommended code display

Added the requested paired display in the existing card using retained source and
validated replacement/advisory evidence; existing illustrative fallback remains.
Added matched/missing/ambiguous dependency and source/UI tests. Complete suite:
**251 passed, 0 failed, 0 skipped** in 20.428s (real Semgrep, mocked AI/GitHub).

Paired-display verification: 251 tests passed; `git diff --check` passed. Live
finding 1247 shows retained sanitize-html 1.4.2 beside advisory candidate 1.11.4.
Browser layout checks: desktop two columns, 390px single column without overflow.
No scanner changes or new AI calls. Existing local app restarted on port 5001.


## Final documentation cleanup and verification (2026-10-04)

Complete. Audited AGENTS.md, CLAUDE.md, README.md, SECURITY.md, all six context
files, and the phase/maintenance documentation for obsolete AI activation rules.
Corrected three active AGENTS rules and the overview/completed-feature summaries:
operator-enabled/configured AI refines persisted findings through the bounded scan
completion hook, followed by one final Recommendation for UI/reports. No manual
AI route/button or page-triggered provider request remains. Clarified historical
phase notices without rewriting their implementation/test records. Documentation
verification guidance now honors explicit requests to run the complete suite.

No source, scanner, UI, database, report, remediation or test changes. A before/after
SHA-256 check of source/tests/templates/styles found no changes during this task.
No remaining activation inconsistency was found against app.py wiring and the
existing refine_scan/refine_finding implementation.

Verification used the project's existing .venv (Python 3.13.5):

```sh
PYTHONPYCACHEPREFIX=/tmp/sentinelscan-doc-audit-pycache SENTINELSCAN_TEST_SEMGREP=/tmp/sentinelscan-semgrep-verify/bin/semgrep .venv/bin/python -m unittest discover -s tests -v
```

**251 tests passed, 0 failed, 0 skipped in 21.167 seconds.** Optional installed
Semgrep executed; AI/GitHub boundaries remained mocked. Full log:
`/tmp/sentinelscan-doc-audit-tests.log`. `git diff --check` passed. No further work
or phase started.


## Final product polish — in progress

Phase 1 complete: removed edit/publish/patch/validation/PR tracking and verification
routes, editor templates and JavaScript, GitHub write methods and publication-only
helpers. Historical tables remain; startup no longer mutates their publication state.
Recommendation snapshots, source validation and redacted diffs remain shared advice
utilities. Existing historical draft source can still be read by the unchanged AI
validator; no drafts can be created or changed. Removed 10 execution-only tests,
retained source retrieval/diff and redaction tests, and added 2 read-only regressions.
241 regression tests passed (1 optional Semgrep skipped); 2 new boundary tests passed.
Phase 2: shared charcoal/emerald tokens, controls, cards, typography and table/code
styles refined. Read-only/page smoke tests: 2 passed. No detection changes.

Phase 3 complete: grouped sidebar and risk-first overview with existing metrics and
recent scans. Foundation tests: 7 passed. Phase 4 complete: website/repository forms
use clearer steps and expandable scope; existing module status drives progress.
Repository and website focused suites passed (source suite 16 tests, website 9).
Phase 5 complete: triage tables show confidence/location/scan, paired code uses shared
framed panels; recommendation ends without edit actions. Finding suites: 32 passed.
Phase 6 complete: history/comparison/trend/report tables are keyboard scrollable;
comparison labels qualify not-detected results; HTML reports display code pairs.
Management and unified recommendation suites passed (7 and 12 tests respectively).
Phase 7 in progress: browser verified 1440px desktop and 390px mobile code pairing,
no page overflow on finding 1247, collapsed details, keyboard Escape closes sidebar.
Preview uses an isolated copy of existing scan data, with AI disabled.

Final verification: **243 tests passed, 0 failed, 0 skipped in 19.959 seconds**
using the existing .venv and installed optional Semgrep. AI/GitHub/CodeQL mocked;
local HTTP/TLS labs and temporary SQLite databases exercised real application flows.
Command: `SENTINELSCAN_TEST_SEMGREP=/tmp/sentinelscan-semgrep-verify/bin/semgrep .venv/bin/python -m unittest discover -s tests -v`.
Log: `/tmp/sentinel-polish-final.log`. Count: prior 251 minus 10 removed execution-only
tests plus 2 new read-only boundary tests = 243. Unrelated tests retained.

Browser QA: all nine main pages plus finding 1247 at 390px have no horizontal page
overflow; code pairs stack. Desktop at 1440px uses two panels; 1024px also has no
overflow. Mobile sidebar opens and Escape closes; Technical Details toggles and
starts collapsed. Wide data tables intentionally scroll inside focusable regions.
Protected file hash audit confirms all scanner, risk, comparison, recommendation
generation, source-candidate and LLM modules unchanged. Only execution-only helper
removal and read-only GitHub adapter changes within analysis/integrations occurred.
No new dependency, analytics, migrations or product feature. Historical report files
are intentionally unchanged; newly generated reports use the updated presentation.
Final product-polish work is complete.

Idle local app restarted on port 5001. Live finding 1247 confirmed paired code,
collapsed Technical Details and no edit links. Isolated preview stopped.
