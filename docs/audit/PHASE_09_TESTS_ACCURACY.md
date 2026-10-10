# Phase 09 — Existing test suite and controlled scanner accuracy

Date: 2026-10-08. Scope: verification only. **Suite PASS; scanner accuracy PARTIAL.**
No application, scanner, rule, test, schema, UI, or configuration changes. No installs,
paid calls, public repository scans, or downloaded-source execution. Test databases
and evaluation archives were temporary; user scan history was not reset or overwritten.

## Context and method

Read CLAUDE.md, then context/project-overview.md, architecture.md, ui-context.md,
code-standards.md, ai-workflow-rules.md, progress-tracker.md, and AGENTS.md.
Reviewed all eight previous phase reports in docs/audit/. No required document missing.
Inspected README testing instructions, existing tests and evaluation/run.py.

Actual working directory for commands:
`/Users/kribeshthapa/Developer/Vibe code/SentinalScan`.
The earlier Desktop location is not the current project root.
Interpreter: `.venv/bin/python`, Python 3.13.5. Framework: standard-library unittest.
README/context document `python3 -m unittest discover -s tests -v`; this audit uses
its virtual-environment equivalent with `-B` to avoid bytecode writes.

Complete raw test output, per-case benchmark results, runtime versions, hashes,
module coverage, and reproduction helpers are in
[PHASE_09_TESTS_ACCURACY.evidence.json](PHASE_09_TESTS_ACCURACY.evidence.json).
The helper sources are audit evidence, not new project tests or detection features.

## Commands, environment, and execution results

Commands executed from the working directory above:

| Check | Exact command | Exit | Time | Result |
|---|---|---:|---|---|
| Coverage availability | `.venv/bin/python -B -c "import importlib.util; print('coverage_installed', bool(importlib.util.find_spec('coverage')))"` | 0 | Not timed | `coverage_installed False` |
| Isolated execution helper | `.venv/bin/python -B /tmp/phase09_run.py` | 0 | Child times below | PASS |
| Complete existing suite (helper child) | `.venv/bin/python -B -m unittest discover -s tests -v` | 0 | 22.642s unittest; 23.129s process wall | PASS |
| Existing repository evaluation (helper child) | `.venv/bin/python -B -m evaluation.run --output /tmp/phase09_repository.json --semgrep /opt/homebrew/bin/semgrep` | 0 | 4.923s process wall | Valid completed stages, accuracy PARTIAL |
| Controlled website diagnostic matrix | `.venv/bin/python -B /tmp/phase09_website.py` | 0 | Not timed | Executed; accuracy PARTIAL |

The helper sets a temporary SENTINELSCAN_DATA_DIR, LLM_ENABLED=false,
SEMGREP_ENABLED=false, CODEQL_ENABLED=false (all with SENTINELSCAN_ prefix),
PYTHONDONTWRITEBYTECODE=1 and SENTINELSCAN_TEST_SEMGREP=/opt/homebrew/bin/semgrep.
It removes inherited SENTINELSCAN_LLM_API_KEY and SENTINELSCAN_GITHUB_TOKEN.
Individual tests deliberately override settings with mock providers and fixtures.
The benchmark explicitly enables Semgrep for its second stage only.
No new blanket socket/DNS guard was applied: Phase 8 showed such a guard interfered
with an existing DNS mock. This suite uses its existing local servers/mocks and the
installed optional Semgrep integration. No real LLM provider was used.

To reproduce the helpers, extract `reproduction_scripts` from the evidence JSON
into /tmp under their recorded names, then run the commands above from the project
root. The suite log contains every executed test identity and its result.

## Complete automated suite

| Measure | Observed |
|---|---:|
| Test modules (`tests/test*.py`) | 33 |
| Declared test methods / discovered and executed test cases | 243 / 243 |
| Passed | 243 |
| Failed | 0 |
| Errors | 0 |
| Skipped | 0 |
| unittest execution time | 22.642 seconds |
| Whole suite process wall time | 23.129 seconds |
| Exit code | 0 |

Final output:

```text
Ran 243 tests in 22.642s

OK
```

Counts are test cases, not individual assertions/subtests. Static AST inventory
found 243 declared methods, matching the 243 successful test-log entries; no
repeated executed identities. No existing tests were deleted, weakened or edited.
The optional installed-Semgrep test ran rather than being skipped.

**Code coverage: NOT TESTED.** The coverage module is not installed. No tool was
installed and no line/branch percentage is inferred from passing tests or scanner
module status. The benchmark's `coverage` fields describe assessment modules,
not Python code coverage.

## Repository accuracy — existing labeled dataset

54 controlled fixtures: 27 positive, 27 negative; nine categories with three
positives and three negatives each. Existing evaluation uses a synthetic archive,
actual repository worker, temporary SQLite persistence and saved finding matching.
One category-presence decision per fixture; all confidences count and duplicates
count once. This is not per-line or per-occurrence accuracy. No unscored findings
were recorded. Both stages completed, cleaned their archives and saved zero AI reviews.

| Stage | N | TP | FP | TN | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|---:|
| Built-in/custom with local data flow | 54 | 26 | 4 | 23 | 1 | 86.67% | 96.30% |
| Built-in/custom + Semgrep 1.179.0 | 54 | 26 | 5 | 22 | 1 | 83.87% | 96.30% |
| Semgrep independently | — | — | — | — | — | N/A | N/A |
| CodeQL | — | — | — | — | — | N/A | N/A |

The combined row is **not Semgrep-only accuracy**. Semgrep adds one false positive
on this dataset and no newly detected positive; findings preserve engine attribution
in evidence. An independent engine benchmark was not run. CodeQL is installed per
Phase 2 but disabled by this evaluation harness and not invoked here. Its raw JSON
hardcodes “unavailable”; that is stale harness wording, not evidence of absence.
Phase 2's isolated query-pack resolution problem remains outside this phase's
changes. Mocked CodeQL test success does not verify a native analysis run.

| Category (6 cases each) | Built-in TP/FP/TN/FN | Combined TP/FP/TN/FN |
|---|---|---|
| Command Injection | 3/1/2/0 | 3/1/2/0 |
| Configuration | 3/0/3/0 | 3/0/3/0 |
| DOM XSS | 3/0/3/0 | 3/0/3/0 |
| Deserialization | 3/0/3/0 | 3/0/3/0 |
| Dynamic Code Execution | 3/0/3/0 | 3/0/3/0 |
| Java Security | 3/1/2/0 | 3/1/2/0 |
| SQL Injection | 3/0/3/0 | 3/1/2/0 |
| Secrets | 2/1/2/1 | 2/1/2/1 |
| Weak Cryptography | 3/1/2/0 | 3/1/2/0 |

Observed mismatches (ground-truth rationale and returned finding titles in evidence):

- `cmd_quoted`: FP; quoted input in the controlled shell-command fixture.
- `secret_custom_name`: FN; credential under an unrecognized custom name.
- `secret_doc`: FP; documentation rather than an active credential.
- `crypto_checksum` and `java_checksum`: FP; non-security checksum uses. Low-confidence
  or Informational findings still count under the benchmark's declared policy.
- `sql_allowlist`: additional FP in the Semgrep-enabled stage; protected allowlist case.

These are the existing frozen development fixtures, not an independent holdout.
Small balanced category samples, narrow syntax and title/CWE category mapping limit
interpretation. Passing dataset-validation tests does not mean the detector has no
errors: tests can assert a benchmark's known imperfect outcomes.

## Website accuracy — controlled diagnostic response fixtures

12 authored cases (5 positive, 7 negative), three per family. Existing website
modules consume synthetic Response objects and a mocked HTTP client. No live target,
exploit execution or network delivery is needed. Ground truth distinguishes runtime
errors from tutorial text and executable script context from inert JSON script data.
These are module-level diagnostic examples informed by Phase 3 findings, not a full
DAST endpoint benchmark. “Positive” refers to the supported indicator/policy check,
not proof of exploitability.

| Family | N | TP | FP | TN | FN | Precision | Recall |
| Disclosure | 3 | 1 | 1 | 1 | 0 | 50.00% | 100.00% |
| Framing protection | 3 | 1 | 0 | 1 | 1 | 100.00% | 50.00% |
| SQL indicators | 3 | 1 | 1 | 1 | 0 | 50.00% | 100.00% |
| XSS indicators | 3 | 1 | 1 | 1 | 0 | 50.00% | 100.00% |
| Total built-in website modules | 12 | 4 | 3 | 4 | 1 | 57.14% | 80.00% |

| Fixture | Expected detection | Actual | Outcome |
| missing framing | True | True | TP |
| restricted framing | False | False | TN |
| wildcard framing | True | False | FN |
| reflection script | True | True | TP |
| reflection text | False | False | TN |
| reflection json | False | True | FP |
| SQL new error | True | True | TP |
| SQL neutral | False | False | TN |
| SQL documentation | False | True | FP |
| disclosure runtime | True | True | TP |
| disclosure neutral | False | False | TN |
| disclosure tutorial | False | True | FP |

The framing wildcard is missed. Inert application/json script content is treated
as an XSS indicator; SQL exception documentation and traceback tutorial text produce
false indicators. These diagnostic results reproduce earlier accuracy limitations.
Semgrep and CodeQL are repository engines, not website benchmark stages (N/A).

## Interpretation, test quality and gaps

Precision = TP/(TP+FP); recall = TP/(TP+FN). Undefined denominators must yield N/A,
not zero or 100%. All measured rows above have defined denominators. Unmeasured
engine rows have N/A metrics, not implied zero detections. Repository and website
percentages use different fixture populations and must not be averaged or ranked
as real-world scanner accuracy. No universal or “99%” accuracy claim is supported.

- **Flakiness:** none observed in this single full run. Repeated randomized/order,
  load and multi-platform runs were not performed; absence of flakes is not proven.
  The Phase 8 DNS failure was caused by the audit guard and passed unchanged with
  the corrected harness; it is not evidence of an application flake.
- **Duplication:** static comparison of AST method bodies (ignoring locations) found
  no exact duplicate test bodies; executed identities were unique. Tests overlap
  intentionally in redaction, lifecycle and fallback coverage. Semantic redundancy
  has not been exhaustively established; no tests are recommended for deletion.
- **Stale wording:** test_llm_review.py's unavailable-provider stub says “Scan workers
  must never call AI”; the current completion hook may call optional AI and catches
  provider failure. Its assertions test survival/fallback, not non-invocation.
  The similar “Scan called AI” stub in test_llm_sast_dast.py also tests fallback.
  Adjacent automatic-refinement tests explicitly verify invocation. No tests changed.
- **Misleading scope if overinterpreted:** test_browser_github.py uses Flask's test
  client; it is not browser automation. The evaluation CodeQL availability string
  is stale as noted above. No whole test was proven obsolete.
- **Confirmed gaps from earlier audits:** malformed module JSON / non-object solution
  snapshots causing route errors, incorrect source/sink receiver identity, same-line
  finding collapse and HTML line accuracy need explicit regressions. Existing suite
  passes without disproving those separately reproduced defects.
- **AI quality:** mock responses exercise structure/redaction/fallback, not factual
  correctness or real-provider quality. Unsupported package/framework claims and
  unsafe header suggestions documented in Phase 5 are not resolved by this run.
- **Benchmark coverage:** no scored dependency-advisory corpus, cross-file flow,
  broad framework/library variants, sanitizer equivalence, full large repositories,
  confidence calibration or severity calibration. Website scored cases omit DNS,
  TLS, cookies, CORS, Nmap, transport limits, technology and exposed-resource accuracy;
  functional safety tests/prior Phase 3 checks are separate evidence.
- **Unverified environments:** browser JavaScript, clipboard/responsive appearance,
  installed default CodeQL pack execution, real provider calls and production-scale
  concurrency are not established by this full suite. Code coverage is NOT TESTED.

Minimal future test improvements (not implemented): encode prior audit defects as
labeled regressions, retain protected examples, create an independent held-out
corpus, and separate native engine availability from mocked integration success.

## Outcome

All 243 existing automated tests pass. Controlled accuracy evaluation still shows
false positives/negatives, and the complete suite does not cover every earlier audit
defect. Only this report/evidence and the existing progress tracker were updated.
No production code or security controls changed. Phase 9 complete; stopped.
