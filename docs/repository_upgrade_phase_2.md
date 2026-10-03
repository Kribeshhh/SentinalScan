# Repository upgrade Phase 2 — bounded flow and optional engines

## Scope and inspection

Phase 1's registry, normalized evidence and retained snapshots remain in place.
Python already had local AST flow, JavaScript/Java Tree-sitter flow, and source
retention/report compatibility. No implementation blocker was found. Neither
external binary was initially installed. Semgrep was installed in an isolated
**test** environment for real verification; CodeQL remains unverified live.
No LLM integration or repository execution was added.

## Flow, sources, sinks and protections

The immutable abstract `Value` carries static/dynamic state, recognized sources,
assignment trace, construction state, HTML protection, SQL-value protection,
callable identity, bounded call labels and uncertainty. Literal values remain
transient; persisted evidence contains labels, not source literals.

Existing Python sources include recognized Flask request fields and input calls;
JavaScript recognizes browser/HTTP input; Java recognizes supported Servlet inputs.
Existing sinks include constructed SQL arguments, dynamic shell/code execution,
unsafe DOM insertion and object deserialization. The scanner checks the argument
construction/flow, not the occurrence of a function name in a comment or string.

Python now follows plain, unambiguous module-level helper calls within one file.
It binds parameters to abstract arguments, follows aliases and returned values,
and appends helper/return labels to evidence. This handles route → search → query
builder → SQL sink without executing any function. Unknown call transformations
retain possible flow but add uncertainty; an unknown `validate_*` helper is not
assumed to sanitize. Explicit numeric conversion protects an SQL value through
supported concatenation/helper returns; an unknown transform removes that guarantee.
Parameterized SQL and subprocess argument arrays with shell=False remain protected
examples. DOMPurify protection remains HTML-specific, never a generic eval sanitizer.

A recognized source reaching a supported sink through supported operations can
have High detection confidence. Unknown transformations or exhausted analysis limits
reduce confidence. Normalized context distinguishes **Potential pattern** from
**Static source-to-sink evidence; runtime reachability not proven**. Neither is a
claim that an application route is deployed, authorized, feasible or exploitable.

Limits: at most 100 registered module functions, 100 call expansions per file,
4 nested expansions; recursion stops immediately. Trace/call labels remain bounded.
Timeout checks and vetted file limits still apply. Truncated call analysis is
recorded as `flow_limited_files`, making module coverage Partial. Duplicate findings
at one existing fingerprint keep the strongest supported path rather than creating
one finding per call site.

JavaScript/Java retain existing intraprocedural analysis. Custom interprocedural
analysis does not resolve class dispatch, decorators, async functions, closures,
varargs, arbitrary imports or cross-file calls. Missing/unsupported call bindings
stay uncertain. Functions are also inspected as potential patterns with unknown
parameters; an uncalled function can still produce a review candidate. Straight-line
code after return and literal false branches are skipped, but general path feasibility
and exception/loop behavior are not solved. There is no whole-program call graph.

## Semgrep

Optional `Semgrep` module, disabled by default. It uses only the bundled
`scanner/engines/semgrep_rules.yml`: Flask SQL argument taint, explicit shell=True
command taint, and browser-input-to-DOM HTML taint with relevant numeric/HTML
sanitizers. No registry auto-configuration, remote rule download, autofix, build,
credential validation or Pro engine is requested. Semgrep's local scan flags disable
metrics, version checks and machine-path rule-ID rewriting.

Results are SARIF candidates. External rule messages/snippets are deliberately not
retained. The importer records engine, stable rule ID, location/span, CWE tags,
severity, conservative confidence and available path coordinates. Semgrep CE 1.179.0
returned candidates without SARIF flow paths in the live fixtures; those correctly
remain Low confidence, regardless of the tool's own precision label.

[Semgrep CLI reference](https://docs.semgrep.dev/cli-reference) documents local scan,
SARIF, taint trace and privacy-related flags. The bundled rules are a small reviewed
starting set, not comprehensive framework coverage or a claim of CE inter-file flow.

## CodeQL

Optional `CodeQL` module, disabled by default. The adapter supports **Python and
JavaScript** only, using explicit `--build-mode=none`. Java/compiled build workflows
are skipped; there is no fallback to autobuild, repository commands, dependency
installation or arbitrary scripts. A supported recent CLI and locally installed
`codeql/python-queries` / `codeql/javascript-queries` packs and dependencies are
required. Missing packs, extraction failure, query failure or timeouts are recorded;
custom findings survive. The adapter never requests automatic pack downloads.

[CodeQL database creation](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/database-create)
documents no-build extraction (the build-mode option requires CLI 2.16.4 or newer).
[Database analysis](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/database-analyze)
documents local pack resolution, SARIF, query timeout and memory/thread controls.

CodeQL SARIF `codeFlows` become bounded file/line paths. Endpoints are labelled
engine-reported, not independently confirmed sources or sinks. Paths without enough
validated coordinates remain Low confidence; complete reported paths receive Medium,
never automatic High. CodeQL was not installed in this environment, so database
creation and queries have **not** been validated against a live CodeQL installation.
Controlled adapter tests cover the command sequence, valid paths and failure modes.

## Configuration

Both engines work independently of each other and of the existing optional AI layer.
Enable only tools installed by the operator; ordinary scanning requires neither.

```sh
export SENTINELSCAN_SEMGREP_ENABLED=true
export SENTINELSCAN_SEMGREP_BINARY=/absolute/path/to/semgrep
export SENTINELSCAN_CODEQL_ENABLED=true
export SENTINELSCAN_CODEQL_BINARY=/absolute/path/to/codeql
# Optional: one absolute directory containing trusted, installed CodeQL packs.
export SENTINELSCAN_CODEQL_SEARCH_PATH=/absolute/path/to/codeql-packs
python3 app.py
```

Omit either enabled setting or set it to false to disable that engine. Binary
settings default to `semgrep` and `codeql` on PATH. Query packs must be outside the
scanned repository. Private HOME isolation means packs installed only in the user's
usual home cache may need an explicit search path. The temporary Semgrep verification
installation is not a permanent project dependency; requirements.txt is unchanged.
Review the external tools' distribution/licensing terms when installing them.

## Execution and import security

Tools receive vetted source in the existing isolated extraction directory. They run
with argument arrays, stdin closed, private working directories and HOME, and an
allowlisted environment. GitHub PATs, AI keys, PYTHONPATH and tool account tokens
are not inherited. Logs are discarded instead of persisted. Tool executables inside
the scanned repository are rejected. No `shell=True` is used.

Semgrep has a 30-second wall budget, one job, 512 MB tool memory setting and a
5-second rule/file timeout. CodeQL has a shared 120-second extraction/query budget,
one thread, 1,024 MB memory hint and 30-second query timeout. Both remain inside the
existing repository deadline. A separate trusted launcher sets CPU (150 seconds),
per-file output (64 MiB) and core-dump limits without threaded `preexec_fn`; Linux
also gets a 4 GiB address-space bound. macOS relies on tool memory controls rather
than JVM-incompatible address-space limits. Unsupported platforms/tool versions fail
without interrupting custom scanning.

The supervisor bounds stdout/stderr and result files to 6 MiB, monitors its workspace
at 512 MiB/20,000 files and kills the process group on failure/timeout/completion.
Disk monitoring is cooperative and can overshoot between checks; it is not a hard
filesystem quota. Temporary outputs/databases are removed. Trusted external tools
are not OS-sandboxed or network-isolated; disabling telemetry/build flags does not
replace keeping those tools patched and trusted.

SARIF is untrusted. Invalid schema, rule IDs, spans, traversal paths, remote URIs
and files outside the vetted inventory are rejected. Path traces retain at most 20
coordinates. At most 1,500 candidates per run are imported within the existing
finding cap. Raw messages/snippets and SARIF file contents are not copied into
findings. All retained fields still cross central redaction before persistence.

## Coverage, confidence and compatibility

Engine modules report Completed, Partial, Failed or Skipped independently; a missing
optional tool never fails a successful custom scan. Failed/partial coverage remains
visible in scan details and reports. Engines disabled in both scans do not prevent
custom-rule rescan verification. A previously active engine, or an engine-owned
finding, still requires completed coverage; skipped analysis cannot establish a fix.

External candidates keep engine-specific identities. Duplicate results within an
engine/rule/location are suppressed. Cross-tool agreement is **not** automatically
merged or promoted: different engines can describe different weaknesses on one line.
This can leave related candidates requiring human triage and can increase aggregate
risk; correlation and cross-engine deduplication are explicit limitations, not proof
of extra vulnerabilities. Severity is separate from confidence. SARIF security scores
map to severity; path availability only affects confidence.

No finding columns, historic records, triage statuses, dashboard queries, website
checks or report formats were migrated. Existing snapshots retain the normalized
analysis envelope. External findings use manual-review guidance; custom remediation
validation does not pretend to reproduce an external engine's rule.

## Files and verification

Added: `scanner/engines/{__init__,external,process,limit_exec,sarif}.py`,
`scanner/engines/semgrep_rules.yml`, `tests/test_repository_phase2.py`, this document.
Updated: configuration, repository orchestration, abstract flow/normalized evidence,
Python analyzer, remediation rescan coverage, integration tests, README and AGENTS.

```sh
python3 -m unittest discover -s tests -v
# Include the opt-in real Semgrep positive/safe/protected fixture test:
SENTINELSCAN_TEST_SEMGREP=/absolute/path/to/semgrep \
  python3 -m unittest discover -s tests -v
```

Tests use temporary databases and source fixtures, never the user's scan history.
The live Semgrep case scans eight files as data (SQL, bound SQL, constant SQL,
numeric protection, shell command, safe argv, DOM insertion and sanitized DOM).
CodeQL valid/unavailable/failed/malformed/timeout behavior is mocked. The subprocess
supervisor itself is exercised with trusted test helpers for environment isolation,
timeouts and output limits. Other tests cover direct/multi-variable/cross-function/
returned flow, recursion, safe constants, shadowing, dead code, retained custom results
when engines fail, reports and optional coverage during remediation verification.

Initial full-suite execution exposed two rescan-coverage regressions caused by newly
Skipped optional modules. Coverage policy was corrected, with an additional regression
test preserving the requirement for previously active engines. Final results follow.

This phase stops here. No LLM work or subsequent phase is started.

### Final results

- Focused Phase 2 suite: **16 passed, 0 failed**, including live Semgrep.
- Complete suite after the coverage regression fix: **197 passed, 0 failed,
  0 skipped**, 15.717 seconds, with the opt-in Semgrep test enabled.
- Live engine: Semgrep **1.179.0**, eight controlled source fixtures, expected three
  positive findings and five safe/protected negatives. These sources were parsed,
  never executed.
- CodeQL: valid SARIF and command/failure behavior tested with mocks; **no live
  database/query execution**. Availability is reported honestly rather than treated
  as a passing live test.
- Full-suite log: `/tmp/sentinelscan-repository-phase2-tests.log`.
- Interpreter: `/tmp/sentinelscan-verify-venv/bin/python`; isolated Semgrep binary:
  `/tmp/sentinelscan-semgrep-verify/bin/semgrep`. No user database was modified.
