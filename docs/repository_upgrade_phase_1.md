# Repository scanner upgrade — Phase 1

## Migration analysis and scope

This extends the existing application. The cancelled website DAST accuracy phase
was not implemented. Website modules, database columns, dashboard queries, finding
fingerprints, GitHub authentication and reviewed publication remain unchanged.

Previously, the repository worker downloaded a pinned commit, extracted vetted
files into a temporary directory, ran secrets/Python/JavaScript/Java/HTML/configuration/
dependency modules, persisted findings, and retained redacted source/remediation
snapshots. Python already used AST; JavaScript and Java already used Tree-sitter.
There was no isolated-regex SQL/command detector to replace in these languages.
Their existing local abstract-value analysis remains the detection authority.

The new flow is extraction → language registry and bounded project inventory →
existing language-aware checks → structured candidate evidence → existing Finding
and JSON persistence → existing recommendations/reports. No new service or engine
is required. No major architectural decision required clarification.

## Common analyzer interface and project structure

`scanner/sast/registry.py` provides `supports(path)`, `parse(source)` and `run(ctx)`
through three explicit adapters. Python parsing uses `ast.parse`; JavaScript and
Java use their respective Tree-sitter grammars. Unsupported languages are not
passed to Python AST. Existing module entry points remain compatible with focused
validation and inline JavaScript analysis.

The project index is stored inside the existing Repository retrieval module JSON.
It records supported files/languages, declaration ranges, enclosing scopes,
imports/aliases where available, syntactic calls and import-based framework
indicators. Calls are explicitly unresolved. There is no inferred inter-file taint
or claim that importing a framework proves its use. Import expressions and function
arguments are not retained. Python aliases are recorded; JavaScript/Java import
identifiers are inventory, not fully resolved bindings.

Index limits: 10 seconds within the existing scan deadline, 100 records per file,
5,000 total records, bounded label strings and the existing vetted-file limits.
Truncation and unparsed files are explicit. Invalid syntax does not generate a
regex fallback vulnerability. Parsers are used again by detection rather than
caching whole repository ASTs. This trades bounded extra parsing for simplicity and
lower retained memory. The time limit is cooperative; an individual parse uses the
existing parser/file bounds and can finish after the inventory deadline.

## Normalized findings

`scanner/sast/evidence.py` defines an immutable semantic evidence envelope emitted
at the actual rule match. It never reconstructs flow by parsing an explanation.
`common.add` attaches a versioned `analysis` object to the existing finding context:

- Title, category, severity and detection confidence.
- Repository, file, start/end line, language and enclosing function when known.
- Stable rule ID, engine, applicable CWE and version-labelled OWASP 2021 mapping.
- Recognized input sources, sink, local variable trace, construction evidence and
  recognized protection that is inapplicable to the reported sink.
- Evidence, description, impact and recommendation.
- Suggested code defaults to null; verification status is **Not verified**.

Unknown sources, functions and mappings remain empty/null. Nonsemantic secret,
configuration, dependency and markup observations have no invented source/sink
flow; rules without an explicit mapping have null rule IDs. Existing remediation
owns generated code and its separate validation. No static candidate is declared
exploitable or fixed by this envelope. OWASP mappings are broad classification,
not an assertion that every mapped candidate is an exploitable vulnerability.

Persistence reuses `Finding.context_json` and `finding_solutions.data_json`.
Source retention explicitly preserves the envelope while adding redacted context
and checked remediation. Existing report composition includes this context. No
schema migration, historical finding rewrite, triage change or fingerprint change
is performed. Older scans remain readable without these optional fields.

## Regex migration

| Class | Existing use | Decision |
| --- | --- | --- |
| A — Keep | Typed secret tokens, private-key markers, placeholder recognition | Appropriate candidate discovery; never authenticate credentials. |
| A — Keep | Paths, extensions, coordinate validation and exact dependency version syntax | Metadata, not complex vulnerability conclusions. |
| A — Keep | Literal configuration keys/values, Gradle dependency coordinates | Bounded configuration/manifest evidence; not runtime evaluation. |
| B — Candidate-only | Generic credential assignments, sensitive HTML comments | Heuristic findings requiring review; do not prove live credentials or bypasses. |
| B — Candidate-only | Sensitive variable names and framework/source receiver-name indicators | Context hints; unknown origin/purpose remains qualified. |
| C — Replace eventually | Name-based source/sink/API identity assumptions | Extend semantic symbol/type resolution before stronger claims; do not add broad regex detections. |

SQL, shell/code execution and DOM rules already inspect calls, assignments,
expressions and local abstract values. A string or comment mentioning a dangerous
function is not evidence. `cursor.execute(query_object)` is not a constructed-query
finding. Constant SQL and bound parameters remain safe examples; interpolated SQL
is not made safe merely by supplying an additional parameter argument.
`subprocess.run(command)` alone is not shell injection; the shell rule requires
explicit `shell=True` and a dynamic argument. HTML sanitization does not make eval
safe; its presence is retained as inapplicable protection in structured evidence.

## Security boundaries

Repository code is untrusted and is never executed, imported, compiled or built.
Archive traversal, symlink/special-file, duplicate-path and compression checks are
unchanged. Limits remain 64 MiB compressed, 128 MiB expanded, 512 KiB per analyzed
file and 2,000 analyzable files, with generated/vendor exclusions and temporary
workspace cleanup. Existing worker and parser deadlines remain active.

Normalized evidence contains abstract labels, not literal values. Central
redaction runs before persistence/reporting, including known discovered secrets.
The index retains only bounded structural metadata, never call arguments or full
source files. No credentials or GitHub PATs enter the index or evidence through
an integration payload. No Semgrep, CodeQL, new AI analysis, auto-apply or automatic
GitHub publication is added.

## Files changed

New: `scanner/sast/registry.py`, `scanner/sast/project_index.py`,
`scanner/sast/evidence.py`, `tests/test_repository_foundation.py`, this document.

Updated: `scanner/source_scanner.py`, `scanner/sast/common.py`,
`scanner/sast/python_scanner.py`, `scanner/sast/javascript_scanner.py`,
`scanner/sast/java_scanner.py`, `analysis/source_context.py`, `AGENTS.md`.

## Verification

Run with the project's installed requirements:

```sh
python3 -m unittest discover -s tests -p test_repository_foundation.py -v
python3 -m unittest discover -s tests -p test_detection_accuracy.py -v
python3 -m unittest discover -s tests -v
```

New tests cover all three adapters, explicit semantic coordinates/flow, harmless
function names/comments, protected APIs, sink-specific sanitization, index scopes,
no literal argument retention, caps/deadlines, malformed syntax, persistence through
source retention, report compatibility and dashboard/website route availability.
Existing tests supply vulnerable/safe/protected examples for the supported sink
families and real local DAST/repository pipeline fixtures. Fixtures are parsed as
data; external GitHub/provider/advisory boundaries are mocked. User scan history
is not touched. Final suite results are recorded below after execution.

## Limitations and Phase 2 prerequisites

No interprocedural return-value summaries, inter-file taint, heap model, complete
type resolution, path feasibility or full sanitizer semantics are introduced.
Local analysis can propagate uncertainty through calls but does not establish
callee behavior. Receiver names, unknown dynamic arguments, Java process arguments
and security-sensitive names remain potential false-positive sources. Nested
shadowing and unsupported syntax remain coverage limitations. The index is
structural inventory, not proof of reachability or a compiler call graph.

Before a later phase, agree on the specific rules/languages and resolution scope,
retain vulnerable/safe/protected fixtures, and define evidence and coverage contracts
for any added engine. Do not infer measured real-world precision from passing tests.
This phase stops here; Phase 2 requires a new request.

### Final execution results

- Existing detection-accuracy suite: **11 passed, 0 failed**.
- New repository foundation suite: **7 passed, 0 failed**.
- Complete project suite: **179 passed, 0 failed** (12.688 seconds).
- The first new-suite run exposed missing sanitizer provenance in an eval finding;
  evidence capture was corrected and the focused/full suites then passed.
- Verification interpreter: `/tmp/sentinelscan-verify-venv/bin/python`.
- Full output: `/tmp/sentinelscan-repository-phase1-tests.log`.
- No live GitHub, AI provider, production repository execution or user DB mutation
  was used for this verification. No new AI behavior was implemented.
