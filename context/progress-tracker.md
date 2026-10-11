# Progress Tracker

Update after every meaningful implementation change. Last updated: 2026-10-09.

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


## Phase 01 environment audit — 2026-10-08

Complete; see `docs/audit/PHASE_01_ENVIRONMENT.md` for commands and evidence.
Existing .venv Python 3.13.5, all 11 dependency constraints, 73 application imports,
launcher HTTP 200, six primary pages, temporary SQLite initialization/persistence
and read-only user-database integrity passed. Supplied Desktop path is stale; actual
project is under Developer/Vibe code/SentinalScan. Documentation/permissions/launcher
portability limitations recorded. No source changes, installs, scanner runs or paid
services; full test suite intentionally not run in this environment-only phase.
Phase 2 can proceed when requested using the actual path and isolated test data.


## Phase 02 external-engine audit — 2026-10-08

Audit complete: `docs/audit/PHASE_02_EXTERNAL_ENGINES.md` and its evidence JSON.
Semgrep 1.179.0: installed, launcher-enabled, rules valid, real Python/JS positives
imported and negatives unflagged. CodeQL 2.27.2: installed and launcher-enabled;
cached Python 1.8.12 / JavaScript 2.4.7 query packs are not resolved under current
private-HOME/empty-search-path settings. Both databases created; default analysis
failed at pack resolution. Temporary exact-pack search-path overrides ran queries
and imported expected positives with no negative findings. Adapter status remained
Partial because informational SARIF notifications trigger its existing policy.
32 existing focused tests passed, 0 failed/skipped; failure mocks and real bounded
helper checks passed. Engine workspaces cleaned up. No application/integration/rule/
pack/config changes or installations, no public repository or paid-provider calls.
Full project suite not rerun; this phase was external-engine verification only.


## Phase 03 website-scanner audit — 2026-10-08

Complete: `docs/audit/PHASE_03_WEBSITE_SCANNER.md` and evidence JSON. All 12
website modules plus validation/transport inspected. 20 selected existing tests
passed; 66 module characterization cases and 13 local transport/safety cases matched
observed expectations. Live loopback HTTP/TLS, Nmap 7.991 and TCP fallback exercised.
Reproduced noisy XSS/SQL/disclosure indicators, wildcard framing protection miss
and similar-length soft-404 suppression of a directory listing. Coverage gaps and
minimal fixes documented only. No source/config/detection changes, external scans,
installs or paid services; user SQLite untouched. Full suite not rerun. Phase 3 stopped.


## Phase 04 repository-scanner audit — 2026-10-08

Complete: `docs/audit/PHASE_04_REPOSITORY_SCANNER.md` plus evidence JSON.
84 selected existing tests passed (5.625s), no failures/skips. Frozen 54-case
worker/persistence evaluation: custom TP26/FP4/TN23/FN1; +Semgrep TP26/FP5/TN22/FN1.
59 supplemental observations and mocked-transport real route/ZIP/worker/persistence
flow completed; redaction, restart persistence, cleanup and nonexecution verified.
Observed false source/sink identity claims, HTML comment line-1 error, same-line
occurrence collapse, and prior known protected/secret/checksum accuracy limits.
No scanner/rule/architecture/configuration changes; no live GitHub/OSV/provider use.
Full suite not rerun; no next phase started.


## Phase 05 AI-remediation audit — 2026-10-08

Complete: `docs/audit/PHASE_05_AI_REMEDIATION.md` and evidence JSON.
89 existing focused tests passed, zero failures/errors/skips (5.849s); 10 additional
observations verify configuration, persisted failure fallback and semantic gaps.
Automatic mocked repository/website review, redaction, strict schema, static-code
checks and unified display work. Unsupported package/framework claims, invalid
header values and agreeing irrelevant two-pass guidance can still be selected.
New AI source-specific fixes lack a full original without historical draft data and
safely fall back. Real provider/model quality NOT TESTED; no paid/external calls,
application changes or installs. Full suite not rerun. Phase 5 stopped.


## Phase 06 frontend/backend workflow audit — 2026-10-08

Complete: `docs/audit/PHASE_06_UI_BACKEND.md` and evidence JSON.
89 focused existing tests passed, zero failures/errors/skips (10.521s); 34 additional
route checks matched expected statuses, eight navigation links returned 200.
Local website and mocked-GitHub worker workflows, findings, comparison, risk SVG,
reports/downloads, restart persistence and four persisted UI states verified.
No new backend/template failures reproduced. Browser JS, clipboard, focus and
responsive visual behavior NOT TESTED: no project Playwright/Selenium; Safari driver
exists but isolated automation unverified. No screenshots, application changes,
installs, live provider calls or user-data changes. Full suite not run. Phase 6 stopped.


## Phase 07 database/risk/report audit — 2026-10-08

Complete: `docs/audit/PHASE_07_DATABASE_REPORTS.md` and evidence JSON.
43 focused existing tests passed, no failures/errors/skips (9.286s). Supplemental
27 checks:25 pass,2 malformed-data failures (module JSON breaks scan detail;
non-object solution snapshot breaks comparison). Temporary SQLite schema/FKs/WAL,
rollback/close, risk formula, severity counts, empty/failed/populated HTML/JSON/CSV,
WAL reader consistency, writer contention and report failure cleanup exercised.
RESOLVED comparison is absence only, not remediation proof. No application/schema/
formula changes or user history access/reset. Full suite not rerun. Phase7 stopped.


## Phase 08 application-security audit — 2026-10-08

Complete: `docs/audit/PHASE_08_SECURITY.md` and evidence JSON.
95 selected methods: initial93 pass/1 harness-blocked DNS test/1 optional Semgrep
skip; unchanged DNS test rerun with socket guard passed. Final distinct94 pass,
1 skip, no unresolved test failure. Literal-address, CSRF/headers/Host, actual
four-job/one-worker queue and temporary permission observations recorded.
Conditional existing-directory disclosure/query replay risks distinguished from
confirmed exploits; prior malformed-JSON/AI accuracy defects retained. No reproduced
SSRF/traversal/shell/CSRF bypass or real-key leak. Cancellation not implemented.
No controls/application/user data changed, no public attacks or paid calls.
Full suite not run. Phase8 stopped.


## Phase 09 complete-suite/accuracy audit — 2026-10-08

Complete: `docs/audit/PHASE_09_TESTS_ACCURACY.md` and evidence JSON.
243 existing tests discovered/executed/passed; 0 failures/errors/skips, 22.642s
unittest time (23.129s process wall), exit0. Optional live Semgrep test included.
Coverage NOT TESTED: coverage module absent; nothing installed. Frozen54 repository
cases: built-in TP26/FP4/TN23/FN1 (precision86.67%, recall96.30%); +Semgrep
TP26/FP5/TN22/FN1 (83.87%,96.30%). CodeQL not benchmarked, not absent.
Twelve controlled website module cases: TP4/FP3/TN4/FN1 (57.14%,80.00%);
diagnostic indicator sample only. No universal accuracy claim. No exact duplicated
test bodies or observed flake in this single run; stale stub/harness wording and
coverage gaps documented. No application/test changes, installs, public scans, paid
calls or user-history reset. Phase9 stopped.


## Phase 10 final audit consolidation — 2026-10-08

Complete: `docs/COMPLETE_TEST_AUDIT.md` consolidates all nine completed audit
phases, module statuses, commands/results, confirmed defect reproductions, gaps,
ranked issues and demo gates. Phase9 baseline remains 243 passed, zero failures/
errors/skips; no tests, scans or provider calls rerun during consolidation.
Core local workflows work; accuracy, AI semantic advice, default CodeQL pack
resolution and malformed-data robustness remain limited. Restricted supervised
local demo/controlled lab use is conditional; academic presentation is viable with
explicit limitations; production deployment is not ready. Top priorities: unsupported
AI advice, action-query replay, source/sink identity, CodeQL configuration/status,
and malformed saved JSON. No application/configuration/test/data changes or fixes.
Awaiting user approval for remediation; audit stopped after Phase10.


## Phase 11 Ollama migration — 2026-10-09

Complete: `docs/fixes/PHASE_11_OLLAMA_MIGRATION.md`. Ollama-only local native
transport replaces cloud API/key/provider configuration. Existing automatic
review, schemas/redaction/static validation, deterministic fallback, single final
recommendation and historical review rows retained. No detectors, routes, UI,
database schema, requirements or user-history changes. Runtime endpoints restricted
to loopback; selected model must exist locally; size/time/response guards tested.
Ollama0.40.1 installed/running, inventory empty. Live synthetic missing-model
request safely rejected; successful real inference NOT TESTED (no model installed).
No downloads/installs. Adapted45 tests and new7 boundary tests pass; complete suite
250 passed, zero failures/errors/skips in19.626s, exit0 (wall20.098s), optional
installed Semgrep included. Mocked inference does not establish model quality;
previous semantic/source-context audit limitations remain. Phase11 stopped.


## Approved qwen2.5-coder:3b setup — 2026-10-09

Downloaded only the approved1.9GB model; checksum/list verified. Existing launcher
now enables it with environment-overridable local settings; active server not
restarted, application defaults unchanged. Synthetic website/repository completion
hooks reached Ollama but rejected responses; deterministic fallback, immutable
findings/scan rows and one UI recommendation verified in temporary DBs. Additional
website example violated configuration grammar; one request timed out. Redacted
secret example also rejected. No accepted quality improvement demonstrated.
No validation weakening, detector changes or additional models/features. Launcher
syntax/config inheritance and diff checks pass; full suite not rerun for this
launcher-only follow-up. Details in Phase11 migration document. Scope stopped.

## Phase 12 Ollama remediation grounding — 2026-10-09 (complete)

D03/D04 reproduced before edits with controlled responses; evidence retained in
`docs/fixes/PHASE_12_BEFORE.json`. Existing AI pipeline now uses bounded deterministic
statement choices, independent local checks before persistence/composition, affected
header/safe-value validation and supported source replacements through the existing
static validator. Unknown prose/examples fall back; no detector or UI architecture
change. Final focused run: 80 passed, zero failures/errors/skips, 6.208s, exit 0. Complete
suite: 266 discovered/executed/passed, zero failures/errors/skips, 20.095s, exit 0;
16 new Phase 12 methods. Installed optional Semgrep included. Tests use mocked
Ollama and temporary SQLite; no live model calls, downloads or user-history writes.
Closed grounded selection intentionally rejects arbitrary paraphrases/novel code;
it is not model training or proof of real-model quality. Existing one-recommendation
UI/reports and immutable detector rows verified. Old unsupported AI content is
suppressed on read without rewriting history. Full evidence, before/after, fixture
changes and limitations: `docs/fixes/PHASE_12_OLLAMA_REMEDIATION.md` and adjacent
log/JSON. `git diff --check` passed. Phase 12 complete; awaiting approval, no further
phase or unrelated audit fixes started.


## Phase 13 SAST identity — 2026-10-09 (complete)

Reproduced original D05 fixtures from the Phase04 evidence bundle. The unrelated
Display.execute SQL false positive is suppressed. The exact Local request eval
fixture already had unknown source/Medium confidence before this phase; it remains
reviewable and is not misreported as a new fix. Existing Python AST now preserves
supported import/receiver identity, rejects bare/relative/shadowed framework-source
claims, recognizes bounded DB constructors/cursors and makes unresolved SQL receivers
Low confidence with uncertain sink evidence. No new scanners/dependencies, UI,
recommendation/AI or database changes. Existing histories preserved.

Added 14 identity regression methods. Updated explicit imports/cursor construction
in earlier High-confidence positive fixtures, preserving assertions. Final full
suite: 280 discovered/executed/passed, zero failures/errors/skips, 23.324s, exit 0.
Focused: 41 passed, zero failures/errors/skips, 2.833s, exit 0. Installed Semgrep
included; provider calls mocked and databases isolated. Frozen 54-case repository
benchmark unchanged: built-in TP26 FP4 TN23 FN1 (precision86.67%, recall96.30%);
built-in+Semgrep TP26 FP5 TN22 FN1 (83.87%,96.30%). Separate four-case SQL identity
regression set: before TP1 FP2 TN1 FN0; after TP1 FP0 TN3 FN0. Small samples do not
establish universal accuracy. CodeQL not benchmarked. Known dynamic/cross-file and
constant-attribute limitations remain. `git diff --check` passes. Full report and
reproducible evidence: `docs/fixes/PHASE_13_SAST_IDENTITY.md` and adjacent JSON/logs.
Phase 13 stopped; awaiting approval before any further phase.


## Phase 14 CodeQL integration repair — 2026-10-09 (complete)

D01 reproduced: private-HOME empty search path cannot find installed packs; DB
creation succeeds but analysis fails. D02 reproduced: successful analysis imports
one finding but informational notifications made it Partial. Existing adapter now
validates multiple trusted absolute pack directories; run-local.sh supplies pinned
installed Python1.8.12 and JavaScript2.4.7 packs for CodeQL2.27.2, with operator
override. SARIF note/none notifications no longer imply failure; warnings/errors,
failed execution and malformed output preserve conservative reporting. Process
supervisor/resource controls unchanged. No pack download, install or user DB edit.

Actual run-local.sh -> app.py configuration verified with a temporary serving-boundary
hook, then real isolated CodeQL in the existing repository worker on controlled ZIPs:
Python Completed/1 import, JavaScript Completed/1 import, mixed Completed/2 imports.
Expected lines py:7/js:2, High/Medium severity/confidence on raw CodeQL imports;
existing correlation retains custom JS Medium severity with CodeQL provenance.
Both safe counterparts unreported by CodeQL; all engine/archive cleanup assertions
passed. Isolated resolver discovers 45 Python/89 JS queries; missing packs still fail.
No live HTTP/browser test claimed and no existing server restarted. Fixture sources
never executed, AI disabled, query/extraction bounds preserved.

Final full suite: 289 discovered/executed/passed, zero failures/errors/skips, 23.663s,
exit0. Focused:25 passed, zero failures/errors/skips,2.876s,exit0. Installed Semgrep
included, live CodeQL recorded separately. Launcher syntax and git diff checks pass.
Report/evidence: docs/fixes/PHASE_14_CODEQL.md and adjacent JSON/logs. Pinned pack
paths must be updated/overridden after installation changes. Existing resource,
correlation and accuracy limitations remain. Phase14 stopped; no later phase begun.


## Phase 15 malformed stored data — 2026-10-09 (complete)

Reproduced D13 ({bad module data) and D14 ([] finding-solution snapshot used during
comparison) as HTTP500 in isolated SQLite. Scan detail now returns200 with explicit
unavailable observations, retaining other modules/findings/recorded status/risk.
Comparison creation returns400 on malformed present snapshot/context/analysis/
identity or module observations; rollback preserves any previous saved comparison.
Absent optional legacy identity fields keep existing warned matching. No corrupted
record is discarded as an empty/secure scan or saved as a false resolved result.
No database schema/migration, report generator, triage, risk formula or scanner changes.

Ten new regression methods cover invalid syntax/types/UTF-8/nonfinite/deep input,
nested identity validation, legacy missing fields, valid matches, escaped output,
unchanged records, and failed refresh preservation. Full suite:299 passed, zero
failures/errors/skips,21.456s,exit0. Focused robustness/management/foundation:24 passed,
zero failures/errors/skips,3.375s,exit0. Existing reports/history/triage tests pass.
Temporary SQLite/data/report directories only; mocked AI, installed Semgrep included,
no installs/public scanning/paid calls/user-history edits. git diff --check passes.
Details/evidence: docs/fixes/PHASE_15_DATA_ROBUSTNESS.md and adjacent JSON/logs.
Scope is the two audited read paths, not comprehensive corruption recovery or all
JSON consumers. Phase15 stopped; awaiting approval before further work.


## Phase 16 — Scanner accuracy corrections (2026-10-10)

Completed the authorized bounded correction/verification scope. D06/D07/D10/D12
original fixtures pass: same-line semantic occurrences persist separately, HTML
comments use real line positions, unrestricted framing is flagged, and distinct
index signatures survive length-only soft-404 filtering. D11 original inert JSON /
SQL documentation / traceback tutorial cases pass, with broader documentary error
ambiguity retained. D08 PARTIAL: narrow instructional documentation FP removed;
bare-shell, checksum and Semgrep allowlist cases remain. D09 FAIL/unresolved: custom
untyped constant lacks credential-use evidence; no speculative rule added.

Final suite:310 passed,0 failed/errors/skips,22.487s,exit0. Focused:37 passed,1.327s.
First full run:308/309; old same-line ambiguity assertion updated to check both
precise columns and genuinely ambiguous missing-column evidence. No test deleted.
Frozen54 repository TP/FP/TN/FN built-in26/4/23/1→26/3/24/1; with Semgrep26/5/22/1→
26/4/23/1. Website12 diagnostic cases4/3/4/1→5/0/7/0. Small known development fixtures,
not universal accuracy; no dataset relabeling. Native CodeQL/AI not invoked.
Temporary data only; no user history/schema/UI/remediation changes, new engines,
public scans or installs. Historical findings need a new scan; collision/line identity
changes documented. Report: docs/fixes/PHASE_16_SCANNER_ACCURACY.md; adjacent JSON/logs
retain exact reproduction helpers, results and hashes. Stopped after Phase16.

## Phase 17 — Final post-fix verification (2026-10-10)

Completed testing/reporting only; no production or test code changed (148 protected
file hashes unchanged). Complete existing suite:310 passed,0 failed/errors/skipped,
23.121s,exit0. Native Semgrep Python/JS and actual-launcher CodeQL Python/JS/mixed
complete and import expected positives, no fixture-negative hits, cleanup verified.
D01–D07,D10,D12–D14 original cases pass; D11 original cases pass with broader limits.
D08 PARTIAL (remaining protected/checksum cases); D09 unresolved FAIL. Mocked D03/D04
validation/fallback passes. P8 S2 action-query replay remains confirmed with mocks;
no destructive/public requests. Frozen54 repository built-in26/3/24/1 and combined
Semgrep26/4/23/1; website12 diagnostic cases5/0/7/0. Small known datasets only.

Route matrix34 expected outcomes; database/report matrix27/27. Actual launcher HTTP
passes with temporary ephemeral-port override; default5000 occupied and left alone.
New temporary SQLite14tables/v4 integrityok. Browser and live AI NOT TESTED. Existing
user history not reset; its full live integrity not claimed. Documentation ambiguities
and conditional security limitations recorded. Supervised local demo conditional;
academic presentation ready with disclosures; production not ready.
Report: docs/POST_FIX_VERIFICATION.md; reproducible helpers/results in
 docs/audit/PHASE_17_VERIFICATION.json and adjacent PHASE_17 evidence. Phase17 stopped.

## Phase 18 — Live Ollama verification (2026-10-10)

Verification only; local qwen2.5-coder:3b inventory/inference and actual launcher
configuration confirmed at 127.0.0.1:11434. Three temporary repository scans exercised
the automatic callback; an existing header rule used a controlled response and the
same completion hook. Four primary cases: SQL timeout; XSS/header inconsistent
example type; secret unexpected source field. Separate SQL repeat returned HTTP200
but inconsistent example type. Total5chat attempts,4HTTP200,1timeout,0accepted live
reviews; all retain deterministic recommendations. No claim of useful live AI fix.
Six failure scenarios pass (missing model real inventory, remaining failure mocks).
Complete requested unittest command:310passed,0failed/errors/skipped,21.697s,exit0.
SQLite/finding/scan template responses pass; browser behavior not tested. Synthetic
credential absent before transport/UI. No user data, production code, models or
validators changed. Report: docs/PHASE_18_LIVE_OLLAMA_VERIFICATION.md; adjacent
PHASE_18 evidence records requests, validation, fallback and repeat separately.
Phase18 complete, overallPARTIAL; fixes await approval.

## Phase 19 — Ollama reliability fixes (2026-10-10)

Completed bounded fixes in existing generation/queue paths. Native schemas couple
example type/code/original; missing pinned originals and secrets use guidance only.
Independent structure/grounding/static validation and composer unchanged. Specific
supported statements precede generic prompt choices without forcing assessment.
Individual rejected answers continue to the next candidate; provider/transport/
storage failures stop. Existing20candidate/60second-between-review bounds preserved.
Cold/warm pairs:16.235/6.178s and18.350/6.372s; keep_alive60s replaces0, with explicit
memory-residency trade-off. Timeout20s/token cap3000 unchanged; no inference retries.

Final real qwen2.5-coder:3b run:SQL/XSS/secret/header,7native HTTP200calls,4grounded
reviews saved,0contract errors. Header AI refinement selected;3Needs Review repository
assessments retain deterministic output. No claim of validated generated source fixes.
Queue reproduction1call/0saved before→2calls/1saved after. Full suite319passed,
0failures/errors/skips,21.265s,exit0;9new tests, existing tests unchanged. Intermediate
order-equality failure corrected in production prompt preparation, not weakened tests.
Only3existing Python files changed relative to Phase18; detectors/UI/database/history
untouched. Report:docs/fixes/PHASE_19_OLLAMA_RELIABILITY.md and adjacent evidence.
Phase19 stopped; no further phase started.

## Phase 20 — website query replay safety (2026-10-10)

Completed requested P8 S2 correction. Before: both XSS and SQL probes preserved
`action=fixture-noop` while mutating q (one request each). After: unreviewed full
query URLs are blocked before HTTP; both probes and CORS are Skipped with zero
requests. Baseline/redirect paths share the guard. Reviewed inert local fixtures
retain XSS/SQL indicators, safe negatives, encoding and existing transport limits.
Production changes limited to `scanner/http_scanner.py`, `scanner/xss_scanner.py`
and `scanner/sqli_scanner.py`; no user data/schema/UI/AI/repository changes this phase.
Full suite: 328 passed, 0 failed, 0 errors, 0 skipped, 21.732s (22.227s process wall).
Independent replay suite: 9 passed, 0 failed/errors/skipped, 0.604s.
Existing fixture tests explicitly authorize only their inert query URLs; assertions
were retained. One new asynchronous mock-lifetime failure was corrected in test
setup; the complete suite was rerun successfully. Queryless GET side effects and
incorrect operator review remain limitations, not proven-safe behavior.
Report: `docs/fixes/PHASE_20_WEBSITE_REPLAY_SAFETY.md`; logs and command metadata:
`docs/audit/PHASE_20_{TESTS,FOCUSED}.{log,json}`. No Phase 21 started.

## Phase 21 — repository accuracy improvement (2026-10-11)

Completed scoped implementation and verification, **D08/D09 overall PARTIAL**.
Reproduced the unchanged frozen 54-case baseline: built-in26/3/24/1 and combined
Semgrep26/4/23/1 (TP/FP/TN/FN). After: both26/2/25/1. Precision89.66%→92.86% built-in,
86.67%→92.86% combined; recall96.30% unchanged. `cmd_quoted` and combined
`sql_allowlist` now TN. Original ambiguous Python/Java checksum observations remain
FP; original custom constant without use context remains FN. No relabeling.

Added bounded imported-API credential-use detection and explicit hashlib nonsecurity
intent handling; tightened shlex identity and fixed documentary closing-delimiter
reference false positive. No Java/correlation/AI/DAST/Phase20/schema/UI changes.
New10-method regression suite passes independently (2.129s). Complete338 tests pass,
0 failures/errors/skips (22.865s; process23.190s); no existing tests weakened/edited.
Real Semgrep1.179.0 and CodeQL2.27.2 run: CodeQL Python/JS/mixed complete, import1/1/2
findings, temporary cleanup passes. Reports/database/source/AI payload redact the
new synthetic credential. GitHub boundaries and unrelated AI use fixtures/mocks;
no live provider, public scan, package installation or user-history changes.
Initial Semgrep sanitizer caught-exception and suppressed-exception regressions failed and were corrected
before the final successful suite. Report/evidence:
`docs/fixes/PHASE_21_REPOSITORY_ACCURACY.md`, Phase21 BEFORE/AFTER benchmark files,
focused/full logs, `docs/audit/PHASE_21_CODEQL.json`. Phase22 not started.

## Phase 22 — final readiness audit (2026-10-11)

Completed verification/reporting only. Full existing suite: **338 passed, 0 failed,
0 errors, 0 skipped**, 23.044s unittest / 23.477s process, exit0. Focused repeat:
63 passed in8.208s. Protected163 application/template/test/evaluation file hashes
unchanged from pre-audit baseline; no detection, AI, UI, schema or user-history edits.

Original54 benchmark unchanged: both built-in and +Semgrep TP26/FP2/TN25/FN1,
precision92.86%, recall96.30%, F1 94.55%. Separately frozen holdout28 scored
(14positive/14negative)+3ambiguous: built-in12/0/14/2 (100%,85.71%,92.31%);
+Semgrep12/1/13/2 (92.31%,85.71%,88.89%). Missing insertAdjacentHTML and HMAC-MD5
policy coverage; external Semgrep local execute method false positive. No tuning,
relabeling or universal-accuracy claim. D08/D09 remain partial. Known12-case DAST
indicator replay5/0/7/0, not independent accuracy. Phase20 replay regressions pass.

Real Semgrep Python/JS and actual-launcher CodeQL Python/JS/mixed complete and
import1/1/2 CodeQL candidates with cleanup. Local Ollama qwen2.5-coder:3b:
7 real chat requests,5 accepted/saved reviews,3 AI contributions selected,
2 deterministic recommendations retained; all five UI pages have one recommendation.
Six failure/fallback checks pass (mostly mocks; missing-model inventory real).
34 HTTP/template route checks,8 navigation URLs,27 database/report checks pass;
real local website and mocked-GitHub end-to-end/restart workflows pass. Browser
rendering/JS/accessibility, live GitHub/private access and CodeQL holdout accuracy
NOT TESTED. Current no-auth/shared-storage deployment limits, Nmap isolation gap,
query-form prerequisite wording and generic no-code advice remain documented.

Verdict: **conditionally ready for supervised local academic demo; not ready for
shared private or public production deployment**. Read all conditions and ranked
issues A22-01–09 in `docs/audit/PHASE_22_FINAL_READINESS_AUDIT.md`. Non-sensitive
logs, JSON and reproduction helpers are under docs/audit. No fixes implemented;
Phase22 ends here pending approval. Earlier dated audit states remain historical.

## Phase 23 — focused quality improvements (2026-10-11, completed)

Implemented insertAdjacentHTML flow checks and existing correlation operation;
Semgrep DOM sink plus narrow print-only SQL receiver exclusion/reassignment guard;
Nmap shared bounded runner/private XML; queryless website instructions; no-code
recommendation normalization;0600 creation of new SQLite files only. Existing
permissions/data, replay policy, Ollama settings and frozen labels untouched.

Final full suite **349 passed,0 failures/errors/skips**,29.863s unittest/30.328s
process,exit0. New11 tests pass independently in3.080s. First full run had an old
Nmap mock-boundary error, corrected without removing assertions; initial log retained.
Real Semgrep SQL/DOM/allowlist tests pass. Real actual-launcher CodeQL Python/JS/mixed
Completed, imports1/1/2, cleanup passes. AI validation/fallback/single recommendation
and Phase20 safety covered by full suite; AI mocked, no new live-model claim.

Original54 unchanged: both engines26/2/25/1, P92.86/R96.30/F1 94.55%. Consumed
Phase22holdout28: built-in12/0/14/2→13/0/14/1; combined12/1/13/2→13/0/14/1.
After P100/R92.86/F1 96.30% for both. DOM missed case nowTP with one correlated
finding; combined local display FP nowTN. Labels/scoring/3ambiguous cases unchanged.
Original checksum FPs/context-free secret FN and holdout HMAC policy FN remain.
No universal accuracy claim. Holdout is development/regression data, not independent.

Report: `docs/fixes/PHASE_23_QUALITY_IMPROVEMENTS.md`; results/logs/hashes and helpers
under docs/fixes. Suitable for supervised local academic demonstration with stated
limits. Unknown receiver/transformations remain qualified; existing storage permissions
require operator review. No source execution, public scans, package installs,
hosting/auth features, user-history edits or commit/push. Phase23 stops here.
