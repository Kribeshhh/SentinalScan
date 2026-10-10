# Phase 13 — Python SAST source/sink identity

Date: 2026-10-09. Scope: D05 in the existing Python AST/local-flow engine only.
No new scanner, dependency, schema, UI, AI, external-engine rule, or website change.
Scanned fixtures were treated as text; none were executed. Existing user history
was not rewritten. Historical findings require a new scan to reflect this change.

## Reproduction and before/after

The exact two `unrelated` fixtures were extracted from
`docs/audit/PHASE_04_REPOSITORY_SCANNER.evidence.json`, script `phase04_cases.py`.
Results: `PHASE_13_D05_BEFORE.json` and `PHASE_13_D05_AFTER.json`.

| Case | Before this change | After |
| --- | --- | --- |
| Local `Display.execute("SELECT "+request.args.get("q"))` | SQL candidate, High confidence, incorrectly recognized unimported request | No SQL candidate |
| Same Display with an actual Flask request import | SQL candidate, High confidence | No SQL candidate |
| Local `request=Local()` followed by `eval(request.args.get("q"))` | Generic eval candidate, Medium, **source already unknown** in this checkout | Generic eval candidate, Medium, source still unknown |
| Imported Flask input concatenated into an established SQLite cursor query | SQL candidate, High | SQL candidate, High |
| Same SQLite cursor with a fixed parameterized query | No SQL candidate | No SQL candidate |
| Constructed query passed to an unresolved receiver | Could claim SQL sink and High/Medium confidence | Low-confidence potential candidate; evidence says `Unresolved receiver method execute`, reachability `Potential pattern` |

The historical audit's local-request diagnosis does not exactly reproduce against
the pre-change checkout: it already retained unknown source for that particular
fixture. We do not claim its generic eval warning was fixed or removed. The analyzer
still cannot prove a class dictionary read constant, and deliberately retains a
reviewable eval warning. No constant-container propagation was added to hide it.

## Implementation

- `scanner/sast/flow.py`: immutable abstract values carry optional symbol identity.
  Assignment/aliases and supported bounded helper calls preserve it. Unequal branch
  values lose identity through the existing conservative merge.
- `scanner/sast/python_scanner.py`: recognize Flask request sources from absolute
  import identity, including module/object aliases. Bare names, relative imports,
  local assignment, parameter/import shadowing and ambiguous branches do not establish
  framework identity. Exception bindings and observed attribute writes stay unknown.
- Establish DB connection/cursor identity for imported `sqlite3`, `psycopg`,
  `psycopg2`, `pymysql`, `mysql.connector` connect calls and Django connection cursors.
  Existing supported SQL operations keep their rule/title/category/fingerprint.
- Suppress SQL name matching for explicitly declared ordinary methods on simple
  local classes. Inheritance, decorators, special dispatch, metaclass keywords,
  class-member rebinding and observed attribute mutation prevent that suppression.
  Their method bodies are still visited by existing analysis.
- Unknown receivers remain potential candidates when the existing query-shape rule
  matches, with Low confidence and explicit uncertain sink evidence. Rule severity
  remains unchanged; Low confidence is not a safety verdict.
- Existing safe parameterized/numeric/allowlisted cases and bounded recursion limits
  remain. No recommendation, correlation, import execution or runtime engine added.

## Regression tests

`tests/test_python_identity.py` adds 14 methods with vulnerable, safe, protected and
unknown cases: original D05, imported/aliased Flask, DB families, Django, SQL parameter
binding, helpers and receiver aliases, unknown sinks, relative/unimported requests,
parameter/local-import shadowing, branches, inherited/dynamic methods, mutations,
exception aliases and DB import shadowing. Checks include normalized source, sink,
line, confidence and reachability, not just finding counts.

Existing positive fixtures in `test_detection_accuracy.py`,
`test_repository_phase2.py` and `test_repository_phase3.py` now explicitly establish
Flask/database imports and cursors where they assert known High-confidence flow.
The correlation fixture's mocked external location moves from line 3 to line 5
with its actual SQL call. Assertions were preserved; no tests were removed. Dedicated
new unknown-identity tests guard against restoring the old name-only inference.
An initial full run exposed these incomplete positive fixtures (20 failed subtest/
assertion entries, 2 errors); corrected fixture setup and final results are below.

## Frozen repository benchmark

Unchanged `evaluation/fixtures.json`, 54 labeled examples (27 positive, 27 negative),
actual isolated repository worker, persisted/normalized results, AI disabled.
`evaluation.run` category scoring counts a candidate regardless of confidence; these
numbers do not measure source identity, exploitability or fix quality.

| Engine stage | Run | TP | FP | TN | FN | Precision | Recall |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Built-in with data flow | Before | 26 | 4 | 23 | 1 | 86.67% | 96.30% |
| Built-in with data flow | After | 26 | 4 | 23 | 1 | 86.67% | 96.30% |
| Built-in + installed Semgrep | Before | 26 | 5 | 22 | 1 | 83.87% | 96.30% |
| Built-in + installed Semgrep | After | 26 | 5 | 22 | 1 | 83.87% | 96.30% |

Both stages report `valid_run=true`. Evidence JSON contains fixture/scanner hashes,
engine versions, saved results, coverage and cleanup. CodeQL is **not benchmarked**;
the harness's older “unavailable” description is not a fresh installation check.
The existing 4 built-in FPs / 1 FN are not resolved by this identity-only change.

Supplemental SQL identity set (4 cases, 1 positive / 3 negative), separate from the
frozen benchmark: before TP=1 FP=2 TN=1 FN=0, precision 33.33%, recall 100%; after
TP=1 FP=0 TN=3 FN=0, precision/recall 100%. `PHASE_13_TARGETED.json` preserves exact
cases/results. This tiny regression set specifically measures Display suppression;
it is **not** a claim of general accuracy. Baseline uses the trusted original scanner
module from Git HEAD, not execution of scanned fixture source.

## Commands and evidence

Working directory: `/Users/kribeshthapa/Developer/Vibe code/SentinalScan`.
Interpreter: existing `.venv/bin/python`. No package/model installation or live AI.
The environment wrapper selects a temporary `SENTINELSCAN_DATA_DIR` **before** app
imports, disables AI and removes the GitHub token. Tests use mocks/local fixtures.

```sh
.venv/bin/python -B /tmp/phase13_repro.py docs/fixes/PHASE_13_D05_BEFORE.json
.venv/bin/python -B /tmp/phase13_bench.py --output docs/fixes/PHASE_13_BENCHMARK_BEFORE.json --semgrep /opt/homebrew/bin/semgrep
# After implementation:
.venv/bin/python -B /tmp/phase13_repro.py docs/fixes/PHASE_13_D05_AFTER.json
.venv/bin/python -B /tmp/phase13_targeted.py
.venv/bin/python -B /tmp/phase13_bench.py --output docs/fixes/PHASE_13_BENCHMARK_AFTER.json --semgrep /opt/homebrew/bin/semgrep
SENTINELSCAN_TEST_SEMGREP=/opt/homebrew/bin/semgrep .venv/bin/python -B -m unittest tests.test_python_identity tests.test_detection_accuracy tests.test_repository_phase2 -v
.venv/bin/python -B /tmp/phase13_run.py --full
git diff --check
```

Temporary script bodies, commands and final test summaries are retained in
`PHASE_13_VERIFICATION.json` for reproducibility; restore its `scripts` to `/tmp`
when repeating commands. The full wrapper uses unittest discovery over `tests`.
Final complete suite: **280 discovered/executed/passed, 0 failures, 0 errors, 0 skips,
23.324 seconds, exit 0**. Focused suite: **41 passed, 0 failures/errors/skips,
2.833 seconds, exit 0**, including installed Semgrep. Counts/timings are also in that
JSON and the adjacent `PHASE_13_TESTS.log` and
`PHASE_13_FOCUSED.log`. All final commands exit 0.

## Limitations and remaining risk

This is bounded static identity inference, not a Python type checker. Cross-file
module resolution, dependency shadow packages, monkeypatches via arbitrary calls,
complex inheritance/descriptors, object state/mutable containers, decorators,
global changes after function definition, reflection and runtime reachability remain
unsupported or conservative. Attribute-write detection is file-wide and may reduce
confidence for unrelated objects with the same attribute name. Unknown SQL-method
candidates can still be false positives; local eval may still be reported for
constant attributes not resolved by this engine. Recognized DB identity does not
verify each driver API signature or determine schema/query correctness. JavaScript,
Java, Semgrep and CodeQL identity behavior is unchanged. No universal accuracy claim.

Phase 13 complete after the recorded verification. No later phase started.
