# Phase 17 — Final post-fix verification

Date: 2026-10-10. Scope: verification after Phases 11–16, not implementation.

## Executive result

**PARTIAL overall.** All 310 existing automated tests pass. The original CodeQL
pack-discovery/notification, AI grounding, Python identity, same-line deduplication,
HTML location, framing, diagnostic website examples, directory listing and malformed
SQLite-record cases now behave as documented below. Live installed Semgrep and
CodeQL executed against controlled positive and negative fixtures. Remaining known
accuracy defects and the website probe replay risk prevent an unconditional clean
bill of health. Passing regression assertions includes assertions of conservative
limitations; it does not mean every benchmark label is detected correctly.

No production application or test code was changed in Phase 17. SHA-256 comparison
of 148 pre-existing code/template/script/requirements files found zero changes.
Previous phases' uncommitted changes were preserved. Tests used temporary databases,
local fixtures and mocked providers. No packages/query packs were installed, no paid
AI calls were made, and no public targets were scanned. User scan history was not
reset or used as a test database. Its individual records were not freshly audited.

## Evidence and reproducibility

Project: `/Users/kribeshthapa/Developer/Vibe code/SentinalScan`.
Interpreter: existing `.venv/bin/python`, Python 3.13.5 on macOS arm64.
Read CLAUDE.md, the six context documents in prescribed order, AGENTS.md,
COMPLETE_TEST_AUDIT.md, original Phase 01–09 audit reports and completed Phase 11–16
fix reports. No required document was missing. Historical reports remain unchanged.

[Verification manifest](audit/PHASE_17_VERIFICATION.json) contains document hashes,
protected code hashes and the exact temporary helper scripts, including their
fixtures and environment isolation. To reproduce, restore the scripts under the
recorded `/tmp` paths and run from the project root. Helpers are verification
artifacts, not production modules. They set temporary data directories before
application imports. Paths in recorded subprocess commands refer to temporary
locations that were subsequently cleaned up.

| Exact command | Exit | Evidence / result |
|---|---:|---|
| `.venv/bin/python -B /tmp/phase17_run.py --full` | 0 | [Full test log](audit/PHASE_17_TESTS.log) |
| `.venv/bin/python -B /tmp/phase17_launch.py` | 0 | [CodeQL](audit/PHASE_17_CODEQL.json), [log](audit/PHASE_17_CODEQL.log) |
| `.venv/bin/python -B /tmp/phase17_semgrep.py` | 0 | [Semgrep](audit/PHASE_17_SEMGREP.json), [log](audit/PHASE_17_SEMGREP.log) |
| `.venv/bin/python -B /tmp/phase13_bench.py --output docs/audit/PHASE_17_REPOSITORY.json --semgrep /opt/homebrew/bin/semgrep` | 0 | [Repository benchmark](audit/PHASE_17_REPOSITORY.json) |
| `.venv/bin/python -B /tmp/phase17_website.py` | 0 | [Website benchmark](audit/PHASE_17_WEBSITE.json) |
| `.venv/bin/python -B /tmp/phase17_remaining.py` | 0 | [AI](audit/PHASE_17_AI.json), [D06–D09/D12](audit/PHASE_17_D06_D09_D12.json), [replay](audit/PHASE_17_REPLAY.json) |
| `.venv/bin/python -B /tmp/phase13_repro.py docs/audit/PHASE_17_D05.json` | 0 | [D05](audit/PHASE_17_D05.json) |
| `.venv/bin/python -B /tmp/phase15_repro.py docs/audit/PHASE_17_D13_D14.json` | 0 | [D13/D14](audit/PHASE_17_D13_D14.json) |
| `.venv/bin/python -B /tmp/phase17_ui.py` | 0 | [Route matrix](audit/PHASE_17_UI.json) |
| `.venv/bin/python -B /tmp/phase17_database.py` | 0 | [Database/report matrix](audit/PHASE_17_DATABASE.json) |
| `.venv/bin/python -B /tmp/phase17_security.py` | 0 | [Security probes](audit/PHASE_17_SECURITY.json) |
| `.venv/bin/python -B /tmp/phase17_startup.py` | 0 | [Default port preflight](audit/PHASE_17_STARTUP.json); occupied port, serving skipped |
| `.venv/bin/python -B /tmp/phase17_http.py` | 0 | [Actual launcher HTTP](audit/PHASE_17_HTTP.json) |
| `.venv/bin/python -m pip check` | 0 | `No broken requirements found.` |
| `/bin/zsh -n run-local.sh` | 0 | Launcher syntax valid |

### Complete automated suite: PASS

310 discovered and executed; **310 passed, 0 failed, 0 errors, 0 skipped**.
Unittest time **23.121 seconds**, wrapper time 23.122 seconds, exit 0. Discovery is
`unittest.defaultTestLoader.discover('tests')`; all regression files are included.
Installed Semgrep was enabled for its opt-in tests. Supplemental audit matrices and
benchmarks below are not added to the 310-test total. No tests were deleted, weakened
or rewritten during this phase.

## Original defects: before versus now

“Before” refers to the original audit reproductions, not inferred production incidents.
PASS is bounded to the original failing case plus the regression suite.

| ID | Before | Current result and evidence | Status |
|---|---|---|---|
| D01 | Isolated CodeQL could not resolve installed packs | Real launcher supplies trusted installed pack paths; Python, JS and mixed database creation/analyze/import complete | PASS |
| D02 | Informational SARIF notifications made success Partial | Real successful Python run includes `none`/`note` notifications and remains Completed; genuine failure regressions pass | PASS |
| D03 | Unsupported package/framework/exploit or unsafe AI prose accepted | Original imaginary package/version/Django claim rejected; unsafe agreeing reviews rejected on first provider response; deterministic fallback retained | PASS, mocked AI |
| D04 | Invalid security-header advice accepted | Original `X-Content-Type-Options: unsafe-value` rejected; valid `nosniff` example accepted without claiming static validation | PASS, mocked AI |
| D05 | Display.execute treated as SQL; local request treated as Flask | Display fixture has no finding; local request fixture retains generic eval warning, Medium confidence, original source unknown. Genuine SQL/source positives and shadowing negatives pass | PASS for identity defect |
| D06 | Two distinct same-line operations merged | Original two eval calls produce two saved findings and distinct fingerprints, both line 1; positive/negative collision regressions pass | PASS |
| D07 | HTML comment reported on wrong line | Original comment now line 2; multiline and script/non-comment regression cases pass | PASS |
| D08 | Protected/documentary code false positives | Original narrow instructional secret example now has no finding; shell quoting, checksum and external allowlist cases remain benchmark false positives | PARTIAL |
| D09 | Custom-named credential omitted | Original untyped custom constant still produces no finding; frozen `secret_custom_name` remains FN | FAIL / unresolved |
| D10 | `frame-ancestors *` accepted | Original wildcard now flagged; restricted framing negative remains clean | PASS |
| D11 | Inert JSON script, SQL documentation and traceback tutorial flagged | All three original diagnostic negatives now clean; true script/SQL error/runtime trace positives remain detected. Broader documentary ambiguity is not solved universally | PASS for original cases; broader coverage PARTIAL |
| D12 | Length-based soft-404 hid directory listing | Original directory signature retained, Low severity/High confidence, soft404 false; safe soft-404 regression passes | PASS |
| D13 | Invalid module JSON caused HTTP 500 | Original malformed module JSON now HTTP 200 with unavailable/error state; valid records preserved | PASS |
| D14 | Wrong-type comparison snapshot caused HTTP 500 | Original malformed/wrong-type solution snapshot now HTTP 400; no fabricated empty/resolved comparison; valid comparisons and previous snapshot preservation pass | PASS |

D06 original bare-request fixture appropriately has Medium severity/confidence, not
an invented trusted Flask source. D05 does not establish general constant propagation.
D13/D14 regressions cover invalid syntax, wrong types, missing fields and valid
records. They do not constitute recovery from arbitrary SQLite corruption.

## Website probe replay safety: FAIL (P8 S2 persists)

Original safe reproduction: `http://127.0.0.1/?action=fixture-noop&q=hello`.
The helper avoids selecting `action` as the mutated parameter but retains it when
probing `q`. Both existing XSS and SQL-indicator modules pass a URL containing the
original action to the mocked request client. [Exact evidence](audit/PHASE_17_REPLAY.json).

Zero real network requests were made in this reproduction. This confirms request
construction/replay, not destructive exploitation. A GET endpoint with side effects
could repeat its action even when another parameter is probed. Existing request,
rate, byte and timeout bounds do not remove this risk. Use only reviewed inert lab
endpoints for a supervised demonstration. No security control was changed here.

## Accuracy benchmarks

Precision = TP/(TP+FP); recall = TP/(TP+FN). One labeled decision per case.
Frozen repository dataset: 54 cases (27 positive, 27 negative), SHA-256
`73c72c4db254ac9f52071915f5e8a56d111c7d0933ebc1e6ad363c4e25b3a2d1`.
All reported candidates, including Informational findings, count; no relabeling.

| Dataset/engine | Before corrections TP/FP/TN/FN | Phase 17 TP/FP/TN/FN | Precision now | Recall now |
|---|---|---|---:|---:|
| Repository built-in, 54 | 26/4/23/1 | 26/3/24/1 | 89.66% | 96.30% |
| Repository built-in + Semgrep, 54 | 26/5/22/1 | 26/4/23/1 | 86.67% | 96.30% |
| Website diagnostic responses, 12 (5 positive/7 negative) | 4/3/4/1 | 5/0/7/0 | 100% | 100% |

Repository before precision: 86.67% built-in, 83.87% combined; recall 96.30% both.
Website before precision 57.14%, recall 80%. Current results match Phase 16.
Remaining built-in FP: `cmd_quoted`, `crypto_checksum`, `java_checksum`; additional
Semgrep FP: `sql_allowlist`; FN: `secret_custom_name`. `secret_doc` now TN.

These are small known development/diagnostic datasets, not independent holdouts,
whole-repository truth or exploitability measurements. Website cases use controlled
responses; separate suite tests use loopback servers. D12 is separately reproduced.
No universal accuracy claim follows. No standalone CodeQL accuracy percentage is
computed: the benchmark does not enable CodeQL. Its old “unavailable” wording must
not be interpreted as absence of the now-verified installed CLI. Native engine
positive/negative smoke tests below are separate evidence.

## External engines

| Engine | Installed | Enabled in tested config | Invoked | Completed | Results imported |
|---|---|---|---|---|---|
| Semgrep 1.179.0 | PASS | PASS | PASS, Python/JS | PASS | PASS |
| CodeQL 2.27.2 | PASS | PASS, actual launcher | PASS, Python/JS/mixed | PASS | PASS, persisted with provenance |

Semgrep executable resolves to
`/opt/homebrew/Cellar/semgrep/1.179.0/libexec/bin/semgrep`.
Bundled rules used without installation. Python positive: `positive.py:7`, High
severity/Low confidence; JS: `positive.js:2`, Medium/Low. The adapter conservatively
reports Low confidence because these Semgrep outputs supply no path. Negative
parameterized SQL and textContent fixtures produce no candidate. Individual runs
1.986s/1.254s, one imported candidate each, zero rejected records, Completed, tool
temporary directories removed. Full suite also verifies bundled-rule safe patterns.

CodeQL launcher binary `/opt/homebrew/bin/codeql` resolves to
`/opt/homebrew/Caskroom/codeql/2.27.2/codeql/codeql`. Trusted search path:

- `/Users/kribeshthapa/.codeql/packages/codeql/python-queries/1.8.12`
- `/Users/kribeshthapa/.codeql/packages/codeql/javascript-queries/2.4.7`

The actual `/bin/zsh ./run-local.sh` launches the existing venv/app factory with
CodeQL and Semgrep enabled. A temporary test hook replaces serving with the fixture
worker, not engine execution. Repository retrieval supplies local controlled ZIPs;
real `run_tool`, database creation, query analysis, SARIF parsing, correlation and
SQLite saving execute. AI is explicitly disabled for this audit. Python completes
in 14.212s (1 saved finding), JS 21.904s (1), mixed 31.317s (2). Original positive
locations: Python line 7 (`py/sql-injection`), JS line 2 (`js/xss`). Raw CodeQL imports
are High severity/Medium confidence. Correlated JS representative severity is Medium,
with CodeQL provenance retained, not a parser failure. No negative fixture findings.
Every tool work directory and repository extraction is cleaned up.

Commands, budgets, raw locations and notifications are in the CodeQL JSON. Existing
mocked missing-pack, timeout, malformed-output and actual-failure regressions pass.
Trusted configured discovery works; empty configuration is not claimed to discover
packs automatically. Isolation remains environment/resource/process controls, not
an OS network/filesystem sandbox. No downloaded source was run as an application.

## AI validation and fallback: PASS with mocks; live provider NOT TESTED

Original D03/D04 and safe-header control reproduced independently; complete suite
covers correct, unsupported, malformed, malicious and contradictory outputs, redaction,
timeouts/API failure and saved fallback. Native Ollama response contracts are mocked.
Automatic finding → evidence → deterministic recommendation → optional refinement →
one saved recommendation remains the tested path. No manual button or second pipeline.

Rejected AI prose does not replace the deterministic recommendation. A safe header
example is displayed as illustrative with Static Validation **Not Available**, not
Passed. Source-specific acceptance remains subject to existing static checks. These
checks reject unsupported claims conservatively; they do not prove all generated
advice factually correct. No real model quality, latency or provider availability was
verified; paid calls were not used. Direct config defaults AI off; the approved launcher
defaults it on with `qwen2.5-coder:3b`. Audit helpers override it off except mocked tests.

## Startup, workflows, database and reports

| Check | Result | Evidence / limits |
|---|---|---|
| Dependencies/imports | PASS | pip check; suite imports existing application |
| Default port 5000 launcher serving | SKIPPED | Port occupied; existing process not stopped |
| Actual launcher HTTP on ephemeral loopback port | PASS | Temporary Flask.run port-only override; HTTP 200, debug off, CSP/frame/nosniff headers |
| New isolated SQLite initialization | PASS | 14 tables, schema version 4, integrity `ok`, zero initial scans |
| Website/repository workflow and restart | PASS | Existing `test_full_http_workflow_and_process_restart`: fixture submissions, results, triage, reports, process restart persistence |
| Route/template states | PASS | 34 expected route outcomes, 8 navigation destinations; empty/populated/loading/failed/invalid/error cases |
| Database/report matrix | PASS | 27/27 checks; transactions, FK/WAL, teardown, saved evidence/recommendations, history, malformed records |
| Triage/comparison/trends/risk | PASS | Existing management tests; risk empty=0, mixed=31, ignored=0, rounding=38, large=100; NEW/RESOLVED/UNCHANGED cases |
| HTML/JSON/CSV/downloads | PASS | Populated 5-row fixture output, escaped/masked values; six empty Completed/Failed format cases; safe downloads and metadata-failure cleanup |
| Concurrent SQLite access | PASS for bounded fixture | WAL reader snapshot 3/3/4; writer lock timeout exercised; not a load test |
| Existing user data | PARTIAL | Not overwritten; isolated preservation/restart passed. No exhaustive live-history integrity audit |
| Browser rendering/JS/mobile/clipboard/focus | NOT TESTED | No available configured isolated browser automation; Playwright/Selenium absent; no screenshot verification |

Expected sanitized HTTP 500 from an injected internal-error test is intentional, not
a newly discovered application failure. Invalid inputs/missing routes remain 400/404.
Comparison RESOLVED means absent from the compared snapshot, not proof of remediation.
Jinja response checks do not establish real browser rendering or JavaScript behavior.

## Security and failure handling: PARTIAL

Existing tests pass for target validation, mixed DNS rejection, pinning/redirect
restrictions, private-target opt-in, metadata rejection, ZIP/path/size controls,
parameterized SQLite use, CSRF, host checks, HTML escaping, headers, redaction,
subprocess argument/environment/output handling, timeout failures and bounded scans.
Fresh probes exercise 22 literal-address decisions without connections, four accepted
queue jobs with fifth rejected and one worker, missing/wrong CSRF 400 and wrong host
400. Cancellation route returns 404: cancellation remains unsupported. Restart
interruption handling passes; this is not interactive cancellation.

Remaining qualifications from the original audit:

- P8 S2 replay is still confirmed as described above.
- P8 S1 permissions remain conditional: newly created data directory 0700, database
  0644, key 0600; an existing 0755 directory remains 0755 with database 0644.
  Actual cross-account access is NOT TESTED; confidentiality depends on parent access.
- Earlier Nmap environment/output isolation and segmented timeout-budget limitations
  were not repaired in this phase. No fresh live Nmap execution/stress exploit test.
- Local development server/access assumptions, untested load/deployment controls and
  browser behavior do not support production readiness.

## Documentation consistency: PARTIAL

Current README/AGENTS architecture describes automatic optional Ollama and one final
recommendation. Completed fix reports accurately retain D08/D09 limitations. Original
audits are historical evidence, not claims those defects still all fail.

Some older lower AGENTS remediation-editor/PR wording is superseded by its explicit
archival notice; context/ui-context.md retains earlier color/workflow descriptions
alongside later superseding polish guidance. “AI disabled by default” requires the
config-versus-launcher distinction above. The frozen evaluation helper's CodeQL
“unavailable” wording also needs that qualification. No removed editor/manual AI
feature was reinstated. This reporting phase records these ambiguities rather than
performing unrelated documentation or source cleanup.

## Remaining defects, gaps and readiness

Confirmed unresolved: D08 residual false positives, D09 custom credential false
negative, P8 S2 request replay. Conditional P8 S1 permissions risk remains. Broader
source identity, runtime reachability, documentary error interpretation, cross-file
analysis and generated-fix correctness remain bounded by existing implementations.
Historical persisted findings are not automatically rescanned or rewritten.

NOT TESTED: live Ollama quality/availability, actual browser behavior, public/private
GitHub service access with real credentials, production deployment/load, exhaustive
user-history integrity and real destructive effects of replay. These are not implied
by successful mocked/local fixtures. No accuracy percentage is assigned to untested
areas or standalone CodeQL coverage.

| Intended use | Readiness | Basis |
|---|---|---|
| Supervised local demo | PARTIAL / conditional | Working startup, workflows and reports; use isolated reviewed inert lab fixtures, disclose D08/D09 and replay, verify chosen browser manually and select an available port |
| Academic presentation | PASS with explicit limitations | Reproducible evidence, bounded metrics, transparent remaining defects; present as a capstone assessment tool, not a validated universal detector |
| Production deployment | FAIL / not ready | Unresolved safety/accuracy issues, local development deployment assumptions and unverified operational/browser/provider behavior |

Phase 17 ends with verification and reporting only. No fixes implemented.
