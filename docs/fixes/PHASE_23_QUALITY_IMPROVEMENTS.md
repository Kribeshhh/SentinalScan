# Phase 23 — Scanner accuracy, reliability and quality improvements

Date: 2026-10-11. **Completed scoped implementation and verification.** Local academic project only; no authentication, hosting, multi-user features or Phase24 work.

## 1. Executive summary

Corrected the original DOM insertion miss and Semgrep print-only receiver false positive, reused the bounded process runner for Nmap, clarified query safety and no-code actions, and restricted newly created SQLite files without changing existing permissions or user history. Full suite **349 passed /0 failures /0 errors /0 skipped**. Both frozen datasets reran without changes to labels/scoring. CodeQL Python/JS/mixed real local analysis completed. AI tests use mocks; Ollama model, prompts and budgets unchanged.

## 2. Confirmed defects and root causes

| Issue | Root cause | Result |
|---|---|---|
| A22-03 DOM insertion | Existing TreeFlow already carries decoded/aliased input, but JS inspect lacked insertAdjacentHTML; parsed correlation whitelist lacked its operation |PASS original case and targeted safe/unsafe regressions|
| A22-05 Semgrep SQL | Any execute receiver matched, including direct local print-only constructor |PASS original; deliberately narrow exclusion, broader identity remains limited|
| A22-07 Nmap | subprocess.run inherited environment and captured output without byte bound |PASS bounded runner/fallback tests|
| A22-08 query instructions | Form placeholder suggested query URL without explaining trusted-review prerequisite |PASS text/template checks; no safety-policy changes|
| A22-09 no-code action | Catalogue example removed by presentation policy but its merge-example action survived |PASS policy normalizes obsolete no-code action; AI/fallback composition tested|
| A22-02 new DB permissions | SQLite creation followed ambient umask |PASS new0600; existing0644 deliberately unchanged; existing installations still need operator review|

Before evidence: Phase22 audit, frozen predictions, live banner final recommendation and permission/process evidence. Initial working tree and targeted pre-edit source copies were inspected/preserved. Phase23 uses those recorded pre-fix outcomes rather than claiming a second full historical audit. New focused tests initially exposed two test/policy mismatches described below; final fixtures exercise actual behavior.

## 3. Exact modified files

Production (8):

- `scanner/sast/javascript_scanner.py`: inspect second argument of insertAdjacentHTML using existing local flow.
- `scanner/sast/evidence.py`: stable `javascript.dom.insertion` /CWE-79 mapping.
- `scanner/sast/security_context.py`: existing parsed operation whitelist includes insertion for correlation.
- `scanner/engines/semgrep_rules.yml`: DOM insertion sink and narrow SQL exclusion/reassignment guard.
- `scanner/port_scanner.py`: existing run_tool, private temporary XML and safe fallback.
- `database.py`: atomic exclusive0600 creation for new disk databases; in-memory special case preserved.
- `analysis/recommendation.py`: no-code normalization after examples are filtered, including historical snapshots.
- `templates/website_scan.html`: queryless placeholder and concise safety explanation.

Tests: new `tests/test_phase23_quality.py` (11 methods with multiple subcases); existing `tests/test_hardening.py` changes only the Nmap mock boundary/return shape, preserving malformed XML, fallback, no-shell and pinned-address assertions. No assertions removed/weakened. No existing source scanner, risk, schema, provider, report or replay tests changed.

Docs: this report, affected context architecture/UI/AI rules/progress tracker and AGENTS; new Phase23 logs, results and reproduction helpers. Existing dirty changes from prior phases preserved; no commit/push. `analysis/solution_engine.py` was briefly considered for wording correction, then restored byte-for-byte to its pre-phase state: normalization belongs after filtering in the shared policy.

## 4. DOM detection and correlation

Direct, decoded and assigned-alias location input reaches the new HTML argument check. Constant HTML and textContent remain negative. Existing DOMPurify recognition excludes supported sanitized values; a local shadowed DOMPurify object does not establish safety in built-in flow. Unknown transformations do not become sanitizers. Unknown origin uses existing Medium heuristic confidence; source-backed local flow retains existing High confidence and explicit no-exploit-proof evidence. Method/receiver runtime identity is not proven.

The position argument does not taint constant HTML. Line/column and parsed operation metadata are retained. Original holdout line2 now has one final merged finding with tree-sitter+Semgrep provenance, not two separate findings. No broad correlation algorithm change; distinct operations remain distinct. Dynamic bracket-method resolution, method-binding aliases and whole-program sanitization are not newly supported.

## 5. Semgrep SQL correction

Retain generic SQL candidates for unresolved receivers rather than globally suppress execute. Exclude only the recognized direct construction of a local class whose execute body is print-only. A wrapper that also calls database execute remains positive. Constructor reassignment re-enables candidate reporting. Real tests verify imported sqlite alias/cursor, unsafe construction, safe binding and the original unrelated Printer. Existing Phase21 allowlist/caught-exception/suppressed-exception/reassignment tests pass.

This is a narrow syntactic correction, not a general Python symbol resolver: arbitrary application methods, assigned receiver objects, dynamic class changes, decorators, metaclasses and monkey-patching are not fully resolved. Unknown receiver candidates keep qualified external evidence. No claim of universal false-positive removal.

## 6. Nmap hardening

Existing `run_tool` now executes Nmap with explicit arguments, sanitized environment/private HOME, no shell, bounded combined stdout/stderr and result-file size (6MiB), workspace limits, bounded duration and process-group cleanup. XML is written inside a temporary directory, returned only after bounded execution, and parsed with existing defusedxml. Trusted executable discovery, port list, TCP connect/version-light flags and at-most18s duration remain unchanged. Missing executable, tool failure, malformed XML or timeout falls back to the same bounded TCP inventory with a fixed warning.

Tests: mocked Nmap success/arguments/XML/fallback; actual trusted Python subprocess fixtures verify absent synthetic environment variable, nonzero exit, timeout, oversized output and killed/reaped child PID. No untrusted source or public scan. Live Nmap service-detection accuracy NOT TESTED; this phase verifies transport/resource behavior. The shared runner is not a full OS filesystem/network sandbox. Existing timeout across the fallback and per-scan budgets still applies.

## 7. Website instructions

Placeholder now `http://localhost:5001/`. Help explains authorized inert labs, trusted review of query-bearing URLs, unsafe replay prevention and that skipped checks do not imply security. No fields, routes, operator approval editor or CSS redesign. Phase20 Client/probe files hash unchanged; all nine replay regressions pass in the full suite. Actual browser layout/assistive technology NOT TESTED; HTTP/template workflows pass.

## 8. Recommendation quality and AI

Normalize no-code actions only after unsupported examples are removed. The original banner now says to minimize server/framework version banners, keep software patched and verify deployed headers. Other affected configuration/operational guidance uses the finding recommendation or available summary instead of asking to merge a missing example. Actual header examples remain intact. False-positive dismissal and existing secret guidance are preserved.

Policy applies to saved historical snapshots when read; no bulk database rewrite. Existing grounded AI statements reconstruct the updated deterministic guidance. New tests exercise AI-off, accepted mock AI, malformed saved AI and deterministic fallback; full suite exercises invalid live-response contracts and one final UI/report recommendation. No validator relaxed; no real Ollama inference in Phase23, no model/settings change. Advice and illustrative examples still require developer review, not a guarantee or automatic fix. Remaining wording elsewhere may still be generic; no unsupported source patch was fabricated.

## 9. Database permissions

For a new file only, os.open(O_CREAT|O_EXCL|O_WRONLY,0600) creates it before SQLite connection. Existing path wins without chmod/chown; ordinary SQLite setup, WAL and schema initialization continue. `:memory:` remains special. Regression verifies new0600, existing0644 unchanged, integrity ok. Existing new data-directory0700 behavior retained; pre-existing directory permissions untouched. No ownership changes, migration, scan-history deletion or user DB opening for tests.

Existing installations with shared-readable storage remain a conditional risk. Local operator recommendation: inspect ownership and parent-directory access before voluntarily restricting one's own data directory/backups. This phase does not silently change those files. Permission behavior verified on current macOS; no cross-account/ACL or Windows guarantee.

## 10. Regression/integration results

| Check | Result / evidence |
|---|---|
| Full suite |349 passed,0 failures/errors/skips;29.863s unittest,30.328s process;exit0; PHASE_23_TESTS.log/json|
| New focused suite |11 passed,0 failures/errors/skips;3.080s unittest,3.409s process;exit0; PHASE_23_FOCUSED.log/json|
| Semgrep |Real installed1.179.0; rules compile/execute; SQL/DOM fixtures, Phase21 guards and both benchmarks pass expected scoped behavior|
| CodeQL |Real installed2.27.2 through actual run-local.sh config, cached Python1.8.12/JS2.4.7 packs; table below|
| AI |Mocked enabled/disabled/invalid/outage/grounding/fallback; live quality NOT TESTED this phase|
| Replay safety |All existing9 tests pass; policy files unchanged|
| Existing workflows |Full suite includes local HTTP website/repository fixture scans, restart, risk, triage, persistence, correlation, secrets, reports and UI templates|
| Whitespace/diff |git diff --check exit0|

| CodeQL fixture | Status | Imported candidates | Duration | Temporary cleanup |
|---|---|---:|---:|---|
| python | Completed | 1 | 14.536s | True |
| javascript | Completed | 1 | 23.918s | True |
| mixed | Completed | 2 | 38.276s | True |

Real engine smoke uses controlled inert archives, never executes repository applications, and tests negative counterparts as well as positive pyline7/jsline2. Native commands/provenance in PHASE_23_CODEQL.json. No query-pack download, sandbox bypass or unauthorized GitHub access.

Initial failures were not hidden: first new no-code test showed that catalogue-level correction ran too early; moved correction after presentation filtering. One new unknown-flow test initially expected Low instead of the unchanged existing Medium convention; corrected that new expectation, not an existing assertion. The first full run347 methods had one error because the old Nmap mock targeted removed subprocess.run; retained in PHASE_23_INITIAL_TESTS.log. Mock now targets run_tool while preserving assertions. Added correlation and process-reaping checks before final349 run. Final full suite was rerun after all code/test changes.

## 11. Benchmarks — unchanged labels and scoring

Phase22 holdout is now **consumed regression/development data**, not independent evidence after tuning.28 scored +3 separately ambiguous; original54 unchanged. Per-case outcomes, valid coverage and unscored findings remain recorded. Source dataset hashes unchanged; no cases deleted or relabeled.

| Dataset/engine | Before TP/FP/TN/FN | After TP/FP/TN/FN | Precision before→after | Recall before→after | F1 before→after |
|---|---|---|---|---|---|
| Original54 built-in |26/2/25/1|26/2/25/1|92.86→92.86%|96.30→96.30%|94.55→94.55%|
| Original54 +Semgrep |26/2/25/1|26/2/25/1|92.86→92.86%|96.30→96.30%|94.55→94.55%|
| Phase22holdout built-in |12/0/14/2|13/0/14/1|100→100%|85.71→92.86%|92.31→96.30%|
| Phase22holdout +Semgrep |12/1/13/2|13/0/14/1|92.31→100%|85.71→92.86%|88.89→96.30%|

Per-case changes only: dom_adjacent FN→TP both; sql_local_display FP→TN combined. Combined DOM case has one correlated finding. All required benchmark modules complete; optional CodeQL disabled for this benchmark, verified separately with no accuracy percentage. Historical evaluator metadata saying CodeQL unavailable means not evaluated in that run, not uninstalled here.

Evidence: PHASE_23_BENCHMARK.json, PHASE_23_HOLDOUT_RESULTS.json and PHASE_23_CASE_CHANGES.json. Before records retained under docs/audit/PHASE_22_*.json. PrecisionTP/(TP+FP), recallTP/(TP+FN), F1=2TP/(2TP+FP+FN). These small known fixtures do not estimate universal accuracy.

## 12. Remaining uncertainty

Original54 still has informationalLow Python/Java checksum false positives and a context-free custom-secret false negative. Holdout still misses the HMAC-MD5 weak-primitive policy case (not proof of a practical forgery); its three uncertain cases remain separate. No crypto/secret rules changed. Names and entropy alone do not establish purpose. Semgrep and built-in JS retain bounded local-analysis limitations; no DOM/browser execution or full runtime identity proof. No broad production features are appropriate to this local academic scope.

## 13. Reproduction and preservation

Use existing .venv, temporary storage, AI disabled, and optional real Semgrep flag. Exact commands/exit codes in result JSON. Helpers archived under docs/fixes/evidence/phase23_*:

```text
.venv/bin/python -B /tmp/phase23_tests.py
.venv/bin/python -B /tmp/phase23_tests.py --full
.venv/bin/python -B /tmp/phase23_holdout.py
.venv/bin/python -B /tmp/phase13_bench.py --output docs/fixes/PHASE_23_BENCHMARK.json --semgrep /opt/homebrew/bin/semgrep
.venv/bin/python -B /tmp/phase23_launch.py
```

Full wrapper executes `.venv/bin/python -B -m unittest discover -s tests -v` in an isolated data environment with SENTINELSCAN_TEST_SEMGREP=/opt/homebrew/bin/semgrep. Launcher helper expects its sitecustomize hook under /tmp/phase23-hook and verifier at /tmp/phase23_launcher_verify.py; serving alone is replaced by fixture verification. No user's running server was restarted. New rescans/startup are needed to use changed code in an already-running app.

PHASE_23_HASHES.json includes exact changed code/test hashes and unchanged replay/provider/dataset hashes. Existing Git dirtiness recorded in PHASE_23_GIT_BEFORE.txt. User data, immutable history/report evidence, configuration secrets and historical audits unchanged. No packages installed or commits made.

## 14. Local academic readiness and next steps

Suitable for a supervised local academic demonstration with qualified evidence, declared limitations and deterministic fallback. Demonstrate the corrected cases and remaining uncertain cases honestly. No production-hosting work recommended or implemented in this phase. Optional future accuracy work should collect supported use-context and a fresh independently labeled dataset before extending rules; this consumed holdout cannot serve as independent generalization evidence. No claim of99% or universal safety.

Phase23 complete. Stop pending approval; no Phase24 started.
