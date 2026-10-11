# Phase 21 — Repository scanner accuracy improvements

Completed 2026-10-11. **PARTIAL for D08/D09 overall**, with verified narrow fixes.
No website/Phase 20 changes, new engines, UI, schema, providers or dependencies.
User history was not used for tests or rewritten. Existing unrelated working-tree
changes were preserved. No repository source was executed, no public repository
was scanned, and no live Ollama/provider call or credential authentication occurred.

## Executive result and original reproductions

The frozen 54-case benchmark was rerun **before implementation**, reproducing the
Phase 17 results. Labels, source and scoring were unchanged. There are 27 positive
and 27 negative cases, SHA-256
`73c72c4db254ac9f52071915f5e8a56d111c7d0933ebc1e6ad363c4e25b3a2d1`.
All confidences, including informational observations, count. Duplicates count once
per labeled category/case. No samples were relabeled or removed.

| Case | Root cause / source evidence | Before → after | Status |
|---|---|---|---|
| `cmd_quoted` | Fixed `echo ` + imported `shlex.quote(request input)` was excluded from the narrow approved executable prefixes, despite occupying one complete POSIX argument | FP → TN, both stages | PASS for this case |
| `sql_allowlist` | Bundled Semgrep taint rule recognized numeric sanitizers, but not a terminating literal-identifier membership guard; adapter/correlation were not the cause | Combined FP → TN; built-in remains TN | PASS for supported guard |
| `crypto_checksum` | MD5 purpose is unknown from the source; benchmark's non-adversarial purpose exists only in its label | Informational/Low FP remains | PARTIAL: explicit non-security API intent now handled; original remains unresolved |
| `java_checksum` | MessageDigest MD5 selection has no subsequent usage/security context; existing Informational/Low observation counted as FP | FP remains | PARTIAL / original unresolved; no speculative Java suppression |
| `secret_custom_name` | One custom-named 24-character constant; no credential format or use in source. Label alone calls it an authentication credential | FN remains | PARTIAL: contextual API-use cases improved; original unresolved |

The original custom literal is not reproduced in this report. Promoting every
opaque constant to a credential or treating `checksum` as proof of non-security use
would invent evidence. Existing assertions for uncertain informational crypto remain.
Neither Java's class/variable name nor an unused-looking digest establishes its
purpose across a real application. No broad filename or checksum-name exception was
introduced. Original D08/D09 are **not claimed fully fixed**.

## Implemented corrections

### Python shell and crypto — existing AST analyzer

- Add fixed `echo` to the existing narrow POSIX command-prefix set. Quoting must
  produce one complete argument, not the executable, an interpreter program, nested
  quoted interpolation or a subsequently modified value.
- Require imported `shlex.quote` identity; unrelated or rebound names cannot confer
  protection. Existing command positives, sh/`-c`, transformed quoting and added raw
  input remain findings. Static strings/documentary comments are not execution.
- Respect literal `usedforsecurity=False` on identified hashlib MD5/SHA1/new calls
  only when known sensitive input/target context does not contradict that intent.
  Password/auth/signature-sensitive context retains the weak-hash finding even with
  that flag. Missing/dynamic flags preserve existing observations. This is API intent,
  not proof of downstream use; no global weak-hash suppression.

### Semgrep SQL — existing bundled rule

The existing taint rule now recognizes the checked variable after a guard of the
form `if value not in ("name", "city"): raise ValueError()` with exactly two literal
identifier-shaped choices. The sanitizer has side effects only on that variable.
It does not discard SQL findings in the adapter or correlate them away.

A caught exception can resume without satisfying the guard. An early proposed rule
failed the new caught-exception regression; the final sanitizer excludes matched
try/except and synchronous/asynchronous context-manager regions. A final-review
suppressing-context-manager regression also initially failed and was corrected. Tests preserve findings for nonterminating guards, conditional
checks, reassignment, dynamic choices, caught exception groups and suppressed exceptions. Larger/dynamic sets,
unsupported control flow and alternate patterns can still require manual review.
This is narrow support, not a general path-feasibility proof.

### Secrets — existing dedicated scanner

Add bounded straight-line Python AST literal/alias tracking at recognized imported
credential APIs: psycopg/psycopg2/pymysql/mysql.connector `connect` password/passwd
keywords and requests.auth.HTTPBasicAuth's password argument. Credential detection
therefore no longer depends solely on the assignment's name. Record the original
literal's line; repeated uses and named-rule overlap deduplicate via the existing
(line, value) mechanism. Candidates remain High severity/Medium confidence (Low in
existing documentation/fixture contexts), never a claim of valid credentials.

Shadowed/reassigned imports or values invalidate identity; uncertain control flow
clears tracking. Function-local bindings are isolated. No global literal propagation
into functions, cross-file credential analysis, heap modeling, value execution,
entropy-only detector or whole-program rewrite was added. Existing placeholder and
typed-token checks remain. Values enter the existing known-secret redaction set
before source retention, persistence, reports and AI packaging.

Also correct a narrow documentary false positive: unquoted references such as
`password=material)` were previously treated as a credential because the closing
code delimiter prevented the existing identifier exclusion from matching. Code
reference exclusion now permits trailing closing delimiters. Quoted candidates and
unquoted configuration values retain their existing handling.

## Exact changed files for Phase 21

Production:

1. `scanner/sast/python_scanner.py` — shell identity/prefix and explicit non-security hash intent.
2. `scanner/sast/secret_scanner.py` — bounded credential-use context and closing-delimiter reference correction.
3. `scanner/engines/semgrep_rules.yml` — precise SQL guard sanitizer with exception-catching/suppressing-context exclusion.

Tests: new `tests/test_phase21_accuracy.py` (10 methods, multiple cases/subtests).
No existing tests were deleted, weakened or edited during Phase 21.

Documentation: this report, `context/architecture.md`, `context/ai-workflow-rules.md`,
`context/progress-tracker.md`, `AGENTS.md`; new Phase 21 evidence/log/helper files.
No modifications to correlation, Java scanner, CodeQL adapter, GitHub retrieval,
website modules, Phase 20 replay policy, AI flow, risk, UI, reports or schema.

## Benchmark before / after

| Engine / metric | Before | After |
|---|---:|---:|
| Built-in TP | 26 | 26 |
| Built-in FP | 3 | 2 |
| Built-in TN | 24 | 25 |
| Built-in FN | 1 | 1 |
| Built-in precision | 89.66% | 92.86% |
| Built-in recall | 96.30% | 96.30% |
| Built-in + Semgrep TP | 26 | 26 |
| Built-in + Semgrep FP | 4 | 2 |
| Built-in + Semgrep TN | 23 | 25 |
| Built-in + Semgrep FN | 1 | 1 |
| Combined precision | 86.67% | 92.86% |
| Combined recall | 96.30% | 96.30% |

Precision = TP/(TP+FP); recall = TP/(TP+FN). Both runs have Completed required
modules and cleaned temporary archives. Evidence:
`PHASE_21_BEFORE.json`, `PHASE_21_AFTER.json`, and corresponding
`PHASE_21_BEFORE_EVIDENCE.json` / `PHASE_21_AFTER_EVIDENCE.json` include per-case
findings, coverage, provenance and captured persistence evidence. The supplemental
before evidence reloads the original three scanner/rule files from unchanged-at-start
HEAD into an isolated subprocess, not the working tree. Its counts match the original
pre-edit benchmark. Synthetic secret source values are not copied into evidence.

This known development dataset was used for tuning, not independent validation.
No new holdout or universal accuracy claim. New contextual-secret tests improve
supported behavior, but **do not improve recall on the unchanged opaque-constant
fixture**. No standalone CodeQL percentage is calculated. The unchanged evaluation
helper's historical “CodeQL unavailable” string means not evaluated by that benchmark;
it is superseded for installation/execution by the fresh smoke results below.

## Regression and integration verification

| Check | Result | Evidence / limits |
|---|---|---|
| Full suite | PASS | 338 passed, 0 failed, 0 errors, 0 skipped; 22.865s unittest, 23.190s process wall; exit 0 |
| Independent Phase 21 tests | PASS | 10 passed, 0 failed/errors/skipped; 2.129s unittest, 2.385s wall; exit 0 |
| Shell positives/negatives/identity | PASS | Quoted echo clean; unquoted source/interpreter/nested quotes remain findings; aliases work, shadowed names do not sanitize |
| Crypto | PARTIAL | Explicit nonsecurity API case clean; password/weak cipher positives retained; two original unknown-purpose checksum observations retained |
| Credential usage | PASS within scope | Custom-name/alias/known API detected; location line 2, one finding, High/Medium; unknown/reassigned/shadowed references and benign UUID/checksum/public constants not guessed |
| Credential privacy | PASS | Temporary full worker/database dump, HTML/JSON/CSV exports, finding page and actual AI prepare payload contain no synthetic credential value |
| Semgrep | PASS, installed/enabled/invoked/completed/imported | Installed 1.179.0; actual bundled rule runs, SQL positives/guards and unchanged benchmark Python/JS cases; rule validation succeeds |
| CodeQL | PASS, installed/enabled/invoked/completed/imported | Actual launcher config, Python/JS/mixed local ZIP fixtures; details below |
| GitHub retrieval / language / persistence | PASS with fixtures/mocks | Existing route/archive/branch/commit validation and actual local extraction/scanner worker tests; no live GitHub credentials/repository access |
| Normalization/correlation/provenance | PASS for suite/fixtures | Existing distinct-operation/provenance tests, unchanged worker benchmark and external imports; no correlation code change |
| Risk/reports/recommendations/AI fallback | PASS with mocks | Full suite; existing single-final-recommendation and mocked Ollama contracts preserved; no live AI quality assessment |
| Website replay safety | PASS in full regression suite | Existing 9 Phase 20 tests unchanged; no website modifications |

The new tests also retain the original unresolved cases explicitly, document Low
confidence for fixture credential context, exercise safe placeholder/documentation
cases and prevent duplicate credentials from repeated uses. Regression pass counts
are not an accuracy percentage; some assertions intentionally preserve uncertainty.

### Real CodeQL smoke

Existing CLI 2.27.2, launcher `/opt/homebrew/bin/codeql`, trusted packs Python 1.8.12
and JavaScript 2.4.7 under the installed user's `.codeql/packages/codeql` directories.
The actual `/bin/zsh ./run-local.sh` configuration supplies both paths. A temporary
hook replaces Flask serving with the verification worker; extraction, CodeQL CLI,
SARIF import, correlation and SQLite persistence are real. AI is forced off.

| Fixture | Status | Imported / saved | Duration | Cleanup |
|---|---|---:|---:|---|
| Python | Completed | 1 / 1 | 14.494s | PASS |
| JavaScript | Completed | 1 / 1 | 22.176s | PASS |
| Mixed | Completed | 2 / 2 | 31.382s | PASS |

Positive Python SQL location line 7; JavaScript XSS line 2. Parameterized SQL and
textContent negative fixtures produce no imported result. Raw imports High/Medium;
JS representative remains Medium after existing correlation, with CodeQL provenance
retained. No source executed as an application, pack installation or sandbox bypass.
Evidence: `../audit/PHASE_21_CODEQL.json`, `PHASE_21_CODEQL.log`; command exit 0.

## Reproducible commands

Project root: `/Users/kribeshthapa/Developer/Vibe code/SentinalScan`.
Existing virtual environment Python 3.13.5. Wrappers use temporary data directories,
AI disabled, and no inherited GitHub token in tests/launcher.

```sh
.venv/bin/python -B /tmp/phase13_bench.py --output docs/fixes/PHASE_21_BEFORE.json --semgrep /opt/homebrew/bin/semgrep
.venv/bin/python -B /tmp/phase13_bench.py --output docs/fixes/PHASE_21_AFTER.json --semgrep /opt/homebrew/bin/semgrep
.venv/bin/python -B /tmp/phase21_evidence.py --before
.venv/bin/python -B /tmp/phase21_evidence.py
/opt/homebrew/bin/semgrep --validate --config scanner/engines/semgrep_rules.yml --metrics off --disable-version-check
.venv/bin/python -B /tmp/phase21_tests.py
.venv/bin/python -B /tmp/phase21_tests.py --full
.venv/bin/python -B /tmp/phase21_launch.py
```

Test wrapper executes the required `.venv/bin/python -B -m unittest discover -s tests -v`,
with `-p test_phase21_accuracy.py` for the independent run. Existing Semgrep opt-in is
`SENTINELSCAN_TEST_SEMGREP=/opt/homebrew/bin/semgrep`. Logs and exact timing/exit metadata:
`PHASE_21_{TESTS,FOCUSED}.{log,json}`. Script copies are in `evidence/phase21_*.py`;
restore the recorded temporary hook paths for launcher reproduction. Original
benchmark wrapper is archived as `phase21_bench.py`. `PHASE_21_HASHES.json` records
final production/test/dataset and unchanged Phase 20 file hashes.

## Remaining limitations / recommended next steps

- D08 remains partial: original Python/Java checksum purpose cannot be verified from
  provided snippets. Preserve their informational uncertainty until supported usage
  evidence justifies removing or elevating them. Do not hide them from scoring.
- D09 remains partial: an untyped custom constant with no usage cannot be reliably
  distinguished from a public identifier. Supported API usage now helps; cross-file,
  runtime/rebound APIs, complex control flow, classes and other languages remain gaps.
- POSIX command reasoning assumes standard shell/echo semantics; dynamic shell
  overrides, argument-level effects and platform behavior are not proven safe.
- Semgrep support is intentionally narrow and uses the engine's existing local flow
  model, not whole-program feasibility or runtime exploit verification.
- Redaction, static validation and plausible-secret rules are bounded heuristics;
  no candidate is authenticated. Framework/import identity may differ at runtime.
- Future accuracy work should collect independently labeled use-context examples
  and a new holdout rather than change frozen labels or suppress uncertain categories.
  These are recommendations only; no further phase implemented.

Phase 21 ends here. No Phase 22, OpenAnt, model or architectural changes.
