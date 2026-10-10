# Phase 04 — Existing GitHub repository scanner accuracy and reliability audit

2026-10-08. **Audit only; no scanner, rule, architecture, application, configuration or dependency changes.** Actual project: `/Users/kribeshthapa/Developer/Vibe code/SentinalScan`; existing `.venv/bin/python` 3.13.5 used. All repository inputs are authored local fixture text or frozen local evaluation fixtures. GitHub/OSV requests mocked; no public repository, credential validation or live provider accessed. Source was never executed, imported, installed or built.

Required context read in order: CLAUDE.md; context/project-overview.md, architecture.md, ui-context.md, code-standards.md, ai-workflow-rules.md, progress-tracker.md; AGENTS.md; earlier Phase 01/02/03 audit reports. All present. Current recommendation-only scope and data-preservation instructions remain in force.

## Summary and interpretation

- **84 selected existing tests passed, 0 failed, 0 skipped, 5.625 s.** Includes live installed Semgrep, parser rules, mock CodeQL import, archive limits, GitHub URL/access, nonexecution, dependency and correlation contracts.
- Frozen 54-case set executed through actual `run_repository`, ZIP extraction, modules, correlation and SQLite persistence twice: custom only and custom + Semgrep. Both required-module runs valid; archives removed; no AI reviews.
- 59 supplemental observations: 45 authored source cases, 3 mocked dependency outcomes, 3 commit-SHA checks, 8 language dispatch checks. Source examples include positive/safe pairs for all implemented category families; exact finding evidence and source are preserved in the evidence artifact.
- Additional URL → actual GitHubClient with mocked transport → local ZIP → worker → SQLite → app recreation succeeded, with redacted data and nonexecution marker intact.
- **Overall PARTIAL:** runtime contracts pass, but concrete false positives, one frozen-set false negative, a location defect and same-line finding loss remain. Passing tests do not imply universal accuracy.

## Workflow verification matrix

| Area | Status | Evidence / limits |
|---|---|---|
| GitHub URL input | PASS | Existing RepositoryURLTests accepts owner/repo, HTTPS root, trailing slash and .git; rejects lookalike hosts, userinfo, non-HTTPS, explicit port, tree URLs, query/fragment, SCP and encoded traversal. POST open/start exercises CSRF and canonicalization. |
| Repository / branch | PASS | Existing fixture listing, private-repo access/pagination and branch-selection tests; pipeline submits `feature/lab` and observes `/branches/feature%2Flab`. Branch-access errors remain distinct from identity success. Real GitHub permissions not tested. |
| Commit resolution | PASS | GitHubClient API boundary mocked, 40/64 hex SHA accepted, malformed SHA rejected; worker archive request uses resolved 40-character commit, not mutable branch. Branch/commit retained in repository and scan options. |
| Download | PASS tested contracts | Exact pipeline request to `/zipball/<sha>` uses 64 MiB and 120 s. Existing tests reject unsafe redirects, prevent PAT forwarding to codeload, and sanitize size/network failures. No live download. |
| Extraction | PASS tested controls | Rejects traversal, symlinks/special/encrypted members, duplicate/case-collision paths, oversized archive and zip-bomb ratios; excludes dependency/build directories, binary and unsupported files. Private new destination, exclusive writes. Controlled pipeline reports 3 analyzed files, 1 excluded, 1 binary, 1 unsupported. |
| File/language discovery | PASS supported dispatch / PARTIAL scope | Registry: Python .py; JS .js/.jsx/.mjs/.cjs; Java .java. Uppercase .PY recognized. .ts and .rb unsupported; not mislabeled as JS. HTML inspected separately with inline JS. Recognition is suffix-based, not content/type inference. |
| Python AST | PARTIAL accuracy | Positive/safe SQL, shell, eval, deserialization and crypto pairs; multiline SQL sink line 5 correct. Order/reassignment/guards/helper flow tested. Unrelated execute method produces false SQL finding. |
| JS / Java Tree-sitter | PASS sampled rules / PARTIAL scope | Positive/safe dynamic execution, DOM sinks, Java SQL/process/deserialization/crypto cases; syntax errors reported as unparsed. No Java compilation or JS execution. Not all syntactic/API variants covered. |
| Context/local flow | PARTIAL | Source, sink, function and path recorded for Python route, JS render and Java f. Scope/reassignment/helper/guard tests pass. Name-based source/sink inference produces erroneous support claims for unrelated objects. Inter-file/type-complete flow not claimed. |
| Secrets/redaction | PARTIAL detection, PASS sampled masking | Synthetic credential detected, environment lookup/placeholder suppressed; typed-token and documentation tests pass contracts. User-like custom credential names can be missed, documentation prose can be flagged. Secret literal absent from persisted pipeline dump. |
| Configuration | PASS sampled literal checks | Debug, disabled control, wildcard-host positives/safe cases; existing config format tests. JSON/YAML intentionally use file-level line 1, not precise key line; runtime overrides not evaluated. |
| Dependencies | PASS mocked contract / PARTIAL external validity | Exact vulnerable, safe and unresolved versions; only exact versions queried. Mock OSV advisory, alias/occurrence dedup, unknown severity and outage handling. No real advisory freshness, package installation, reachability or transitive resolution assessed. |
| Semgrep / CodeQL imports | PASS tested normalization/correlation; live CodeQL limitation retained | Live Semgrep included in frozen evaluation. Mock three-engine same-operation test persists one finding with provenance. Invalid/path-escaping SARIF rejected. Phase 02 demonstrated default CodeQL pack-resolution failure; not fixed or rerun here. |
| Deduplication | PARTIAL | Exact duplicate and cross-engine semantic correlation tests pass; distinct operations on separate lines retained. Two same-title eval calls on one line reduce to one raw/persisted finding through fingerprint dedup. |
| Coordinates / severity / confidence | PARTIAL | All supplemental positive sink lines match except HTML comment (expected 2, actual 1). Wrong receiver SQL gets High confidence and Strongly Supported even though fixture method only prints. Confidence labels remain heuristic. |
| Persistence / status | PASS tested lifecycle / PARTIAL meaning | Submission 303; scan Completed/100%; branch/SHA/status/findings survive new app instance; archive removed; source never executed. Existing engine-failure test preserves custom results with failed module states. Completed does not mean every optional module succeeded. |

## Frozen evaluation — observed, not a production benchmark

Category-presence per fixture; all confidences and informational findings count; duplicates count once. The authored dataset has been used previously in development, so it is not an independent holdout. Scores should not be generalized to unfamiliar repositories. Tests assert fixture identity; no labels/baselines overwritten.

Dataset SHA-256: `73c72c4db254ac9f52071915f5e8a56d111c7d0933ebc1e6ad363c4e25b3a2d1`.
Scanner digest (existing harness): `9f171d1c3dad52747307ae402fdfb5fc236f806209e101c49f1da3a83e7f59d6`.

| Stage | TP | FP | TN | FN | Stored findings | Elapsed | Required coverage |
|---|---:|---:|---:|---:|---:|---:|---|
| custom-with-dataflow | 26 | 4 | 23 | 1 | 30 | 0.411 s | valid=True |
| custom-plus-semgrep | 26 | 5 | 22 | 1 | 31 | 1.765 s | valid=True |

| Category | Custom TP/FP/TN/FN | +Semgrep TP/FP/TN/FN |
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

Both stages have zero unscored findings and zero AI reviews. Required custom modules Completed; optional CodeQL Skipped by this evaluation. Phase 02 remains the evidence for real CodeQL operation and unresolved default configuration, rather than describing CodeQL as uninstalled.

## Confirmed false positives, false negatives and evidence defects

| ID | Evidence | Observed problem | Priority |
|---|---|---|---|
| R1 | Supplemental `unrelated execute method FP` | A locally defined Display.execute only prints its argument. Scanner sees constructed input to `.execute`, labels SQL injection High/High and review calls it Strongly Supported. Method name is not sufficient database identity. | High |
| R2 | Supplemental `unrelated request object source FP` | Local `request=Local()` with constant dictionary value is treated as Flask-style request input. Static-safe eval gets a finding; reviewed confidence Medium/Likely. Source identity inference is too broad. | High |
| R3 | Pipeline a.py line 1 has two eval calls on different request arguments | Python module already collapses them to one candidate because title/source/category/location fingerprints lack column/operation identity. One saved finding cannot represent both occurrences separately. | Medium |
| R4 | Supplemental HTML comment on line 2 | Finding points to line 1. html_scanner hardcodes comment location; this is a location defect, not a missing detection. | Medium |
| R5 | Frozen `cmd_quoted` | Protected POSIX quoted argument still generates shell-injection High/High. Narrow allowed fixed executable handling does not cover this fixture. | Medium |
| R6 | Frozen `sql_allowlist` with Semgrep | Custom scanner suppresses bounded allowlisted identifier; Semgrep taint rule still flags it High/Low. Adds noise without increasing TP on this set. | Medium |
| R7 | Frozen `secret_doc` | Documentation prose counted as a credential, High severity/Low confidence. | Medium |
| R8 | Frozen `secret_custom_name` | Credential under custom name missed without usage context. This is an explicit fixture truth, not evidence of a validated live secret. | Medium / bounded detection limit |
| R9 | Frozen Python/Java checksum cases | Non-security MD5/SHA-1 usage still emits Informational/Low candidates; scored as false positives by fixture truth. Low-severity review signal should not be presented as proven security impact. | Low |

No failures in the 84 selected unittest methods. The accuracy defects above are not hidden by the green regression result. Strongly Supported describes existing static evidence rules, not a proof of a vulnerable application; R1 demonstrates why the distinction matters.

## Supplemental detection matrix

Known positive/safe examples are stored in the evidence JSON as inert source strings. For positives, line expectation refers to the sink's starting line, not necessarily every line in a multiline call. Raw candidate confidence and reviewed confidence are recorded separately. API/language checks follow the source/dependency cases in the evidence artifact.

| Case | Expected | Actual | Outcome | Expected line / observed locations |
|---|---|---|---|---|
| python sql positive | finding | finding | TP | 5 / audit/fixture/a.py:5 |
| python sql safe | no target finding | none | TN | None / — |
| python shell positive | finding | finding | TP | 3 / audit/fixture/a.py:3 |
| python shell safe | no target finding | none | TN | None / — |
| python eval positive | finding | finding | TP | 2 / audit/fixture/a.py:2 |
| python eval safe | no target finding | none | TN | None / — |
| python deserialize positive | finding | finding | TP | 2 / audit/fixture/a.py:2 |
| python deserialize safe | no target finding | none | TN | None / — |
| python hash positive | finding | finding | TP | 2 / audit/fixture/a.py:2 |
| python hash safe | no target finding | none | TN | None / — |
| javascript eval positive | finding | finding | TP | 2 / audit/fixture/a.js:2 |
| javascript eval safe | no target finding | none | TN | None / — |
| javascript DOM positive | finding | finding | TP | 3 / audit/fixture/a.js:3 |
| javascript DOM safe | no target finding | none | TN | None / — |
| javascript write positive | finding | finding | TP | 1 / audit/fixture/a.js:1 |
| javascript write safe | no target finding | none | TN | None / — |
| java sql positive | finding | finding | TP | 3 / audit/fixture/A.java:3 |
| java sql safe | no target finding | none | TN | None / — |
| java process positive | finding | finding | TP | 2 / audit/fixture/A.java:2 |
| java process safe | no target finding | none | TN | None / — |
| java deserialize positive | finding | finding | TP | 3 / audit/fixture/A.java:3 |
| java deserialize safe | no target finding | none | TN | None / — |
| java crypto positive | finding | finding | TP | 1 / audit/fixture/A.java:1 |
| java crypto safe | no target finding | none | TN | None / — |
| secret positive | finding | finding | TP | 1 / audit/fixture/settings.py:1 |
| secret safe | no target finding | none | TN | None / — |
| config debug positive | finding | finding | TP | 1 / audit/fixture/settings.py:1 |
| config debug safe | no target finding | none | TN | None / — |
| config control positive | finding | finding | TP | 1 / audit/fixture/settings.py:1 |
| config control safe | no target finding | none | TN | None / — |
| config hosts positive | finding | finding | TP | 1 / audit/fixture/settings.py:1 |
| config hosts safe | no target finding | none | TN | None / — |
| html password positive | finding | finding | TP | 1 / audit/fixture/index.html:1 |
| html password safe | no target finding | none | TN | None / — |
| html transport positive | finding | finding | TP | 1 / audit/fixture/index.html:1, audit/fixture/index.html:2 |
| html transport safe | no target finding | none | TN | None / — |
| html comment positive | finding | finding | TP | 2 / audit/fixture/index.html:1 |
| html comment safe | no target finding | none | TN | None / — |
| unrelated execute method FP | no target finding | finding | FP | None / audit/fixture/a.py:5 |
| unrelated request object source FP | no target finding | finding | FP | None / audit/fixture/a.py:4 |
| cross function safe scope | no target finding | none | TN | None / — |
| reassigned safe value | no target finding | none | TN | None / — |
| python malformed | no target finding | none | TN | None / — |
| javascript malformed | no target finding | none | TN | None / — |
| java malformed | no target finding | none | TN | None / — |
| dependency 1.0.0 | finding | finding | PASS | — / audit/dep/requirements.txt:1 |
| dependency 2.0.0 | no target finding | none | PASS | — / — |
| dependency ^1.0.0 | no target finding | none | PASS | — / — |

The three malformed-language examples correctly produce no finding **and** explicit unparsed-file observations; they are not clean-assessment evidence. Dependency `^1.0.0` label is a scenario name: its requirements fixture uses `>=1`, correctly makes zero advisory queries and records unresolved version. Unknown advisory severity remains Informational. Secret literals in this artifact are synthetic test strings, not discovered user credentials.

## End-to-end saved-result evidence

The audit used the real route, GitHubClient JSON parsing, commit path construction, zip extraction, worker, normalization and SQLite. Only transport responses were replaced by authorized local metadata/ZIP bytes. Key observations:

```json
{
  "submission_status": 303,
  "calls": [
    {
      "host": "api.github.com",
      "path": "/repos/audit/fixture",
      "limit": null,
      "seconds": null
    },
    {
      "host": "api.github.com",
      "path": "/repos/audit/fixture/branches/feature%2Flab",
      "limit": null,
      "seconds": null
    },
    {
      "host": "api.github.com",
      "path": "/repos/audit/fixture/zipball/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "limit": 67108864,
      "seconds": 120
    }
  ],
  "redacted": true,
  "restarted_same_findings": true,
  "source_not_executed": true,
  "archive_cleanup": true,
  "same_line_raw_candidates": 1,
  "same_line_saved_candidates": 1
}
```

Scan status Completed, progress 100; branch `feature/lab`, SHA `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` stored. Python inventory has 3 files; unsupported TypeScript and excluded node_modules do not silently become JavaScript findings. AST evidence for two same-line calls is intentionally tested as a limitation, not a deduplication success. Creating the second app used the same temporary data directory, never user history.

## Commands, timings and reproduction

```sh
.venv/bin/python -B /tmp/phase04_existing.py > /tmp/phase04_existing.log 2>&1
.venv/bin/python -B /tmp/phase04_cases.py > /tmp/phase04_cases.log 2>&1
.venv/bin/python -B /tmp/phase04_pipeline.py
```

[Full evidence and exact helper source](PHASE_04_REPOSITORY_SCANNER.evidence.json). From project root, recreate helpers without modifying source:

```sh
.venv/bin/python -B - <<'PYREPRO'
import json
from pathlib import Path
data=json.loads(Path('docs/audit/PHASE_04_REPOSITORY_SCANNER.evidence.json').read_text())
for name,source in data['scripts'].items():
    Path('/tmp',name).write_text(source)
PYREPRO
```

`phase04_existing.py` sets temporary SENTINELSCAN_DATA_DIR and disables AI, enables the installed Semgrep test binary, then runs these existing suites:

- test_repository_url, test_browser_github, test_source_scanner, test_archive_limits
- test_detection_accuracy, test_repository_foundation, test_repository_phase2
- test_repository_phase3, test_accuracy_refinement, test_evaluation

It then calls the unchanged evaluation `load_dataset` and `run_stage` twice and saves only `/tmp/phase04_evaluation.json`, preserving evaluation/results.json and frozen labels. Full unittest log and per-stage coverage are embedded in the evidence artifact. Supplemental case durations are recorded per source case. Pipeline helper completed in approximately 0.4 s. Full project suite was not run; these are focused Phase 4 tests.

## Safety, reliability and missing coverage

- Inspected extraction bounds: 64 MiB compressed, 128 MiB total declared expanded size, 512 KiB per retained file, 2,000 analyzable files, 5,000 ZIP entries, compression-ratio guard, private new destination. Bounds are not a guarantee against every ZIP/library flaw.
- Inspected analysis bounds: 180-second context deadline, 1,500 finding cap, Python helper depth 4/100 expansions per file; tree-sitter local flow and bounded context retrieval. Some counters describe skipped/unparsed data, not full repository coverage.
- Existing tests cover build hooks as text, invalid ZIP paths/types, masked credentials, OSV outage and query deduplication, engine failures, semantic correlation across three engines, distinct anchors/scopes and line movement. No downloaded code executed.
- **NOT TESTED live:** GitHub authorization/branch mutation races, network downloads or OSV advisory accuracy/freshness. Those boundaries are mocked; no real token used.
- **NOT TESTED here:** real CodeQL rerun; rely on Phase 02 default-pack failure/exact-pack success and Partial-notification finding. Mock CodeQL results verify ingestion, not CodeQL detection accuracy.
- **PARTIAL coverage:** extension dispatch, named APIs and local flow do not establish arbitrary dynamic dispatch, inter-file taint, full framework identity, runtime dependency versions, sanitizer correctness or exploitability. Unsupported languages/formats and parser failures remain relevant even if scan status says Completed.
- **Coarse locations:** JSON/YAML configuration and some manifests intentionally report line 1. This is not precise key/dependency anchoring. HTML comments also report line 1 but can be misleading when presented as exact.
- **Dependency limits:** exact versions only, 50 query identities, stop after three remote failures, bounded advisories; no full resolver/transitive install or real reachability. Safe fixture means no advisory returned, not certified safe software.
- Potential duplicates may remain when anchors are ambiguous; intentionally conservative cross-engine correlation avoids merging merely by CWE. Conversely, same-line within-engine fingerprints lose distinct occurrences (R3).

## Prioritized minimal recommendations — no implementation

1. **High:** constrain source/sink support claims by resolved receiver/import identity where already available. An arbitrary execute method or shadowed request object must not earn database/Flask certainty. Add R1/R2 negative regressions before changing rules.
2. **Medium:** preserve distinct same-line occurrences using source span/column identity while planning compatibility with existing fingerprints; this needs deliberate testing, not an unreviewed migration.
3. **Medium:** correct HTML comment line anchoring and label intentionally file-level locations as approximate.
4. **Medium:** add narrow protected-case regressions for quoted commands and allowlists across custom/Semgrep evidence, without treating all quoting/sanitizers as universally safe.
5. **Medium:** keep secret heuristics bounded and uncertain; reduce obvious documentation noise without claiming to find arbitrary custom-named credentials. Preserve pre-persistence masking.
6. **Medium:** separately address the already-observed CodeQL pack visibility and informational Partial status from Phase 02 before presenting optional coverage as complete.
7. **Low:** distinguish harmless checksum review signals and unsupported/unparsed coverage from actionable high-risk findings. Do not equate engine agreement or scan completion with validation.

No fixes applied. Only audit artifacts and the observed-status progress entry were written. No next phase started.
