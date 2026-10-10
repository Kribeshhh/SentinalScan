# Phase 07 — Database, risk and reports audit

2026-10-08. **Overall PARTIAL: normal persisted workflows pass; two malformed-data robustness failures reproduced.** Audit only. No application/schema/risk-formula changes, real-history reset, dependency installs, public scanning or paid API calls.

Project root: `/Users/kribeshthapa/Developer/Vibe code/SentinalScan`. Existing `.venv/bin/python` used. Required context documents, CLAUDE.md and AGENTS.md reviewed; prior Phase 01–06 results reviewed. All required documents present. Previous scanner/AI accuracy limitations remain applicable: correct storage/reporting does not make a finding or suggested fix factually correct.

## Commands and results

```sh
.venv/bin/python -B /tmp/phase07_tests.py > /tmp/phase07_tests.log 2>&1
.venv/bin/python -B /tmp/phase07_matrix.py > /tmp/phase07_matrix.log 2>&1
cat /tmp/phase07_tests_summary.json
cat /tmp/phase07_matrix.json
git diff --check
```

**43 existing tests passed; 0 failures, errors or skips; 9.286 seconds.** Focused suites: test_foundation, test_management, test_restart, test_end_to_end, test_unified_recommendation, test_llm_review; additionally test_website_scanner.WebsiteTests.test_migration_preserves_existing_related_records. Full project suite not rerun.

**27 supplemental checks: 25 PASS, 2 FAIL** against the explicitly stated expected behaviors below. Failing robustness checks are not masked by the green existing suite. Helpers return recorded observations; their process exit code alone is not an all-checks-pass claim.

[Exact helper source, existing test names/log and expected/actual observations](PHASE_07_DATABASE_REPORTS.evidence.json). Recreate helpers:

```sh
.venv/bin/python -B - <<'PYREPRO'
import json
from pathlib import Path
bundle=json.loads(Path('docs/audit/PHASE_07_DATABASE_REPORTS.evidence.json').read_text())
for name,source in bundle['scripts'].items():
    Path('/tmp',name).write_text(source)
PYREPRO
```

Both helpers set SENTINELSCAN_DATA_DIR to a temporary directory before app creation. Existing tests additionally use temporary DATABASE/REPORTS_DIR overrides. AI off by default; enabled tests use mocks. External transport is blocked in the selected-suite runner; its existing end-to-end subprocess uses local lab and fixture GitHub. No user database opened by an app instance. A temporary connection-local trigger simulates report metadata failure; it is removed before cleanup and is not a project schema change.

## Requested verification matrix

| Check | Expected | Actual / evidence | Result |
|---|---|---|---|
| SQLite initialization/schema | Required tables, v4, FK enforcement and WAL | Fresh DB: 14 tables, version4, foreign_keys1, wal; existing migration test retains related records | PASS |
| Connections/transactions | Per-context connection reuse/close; rollback atomic | Same get_db object within context; closed afterward; raised exception leaves zero inserted rows; WAL reader snapshot stable | PASS sampled |
| Save website scans | Worker writes status/findings/modules | Management/EndToEnd local lab completes and records findings/risk | PASS |
| Save repository scans | Controlled GitHub source persists without execution | FixtureGitHub worker stores source findings and repository metadata; process restart retains records | PASS mocked remote |
| Findings/evidence | Enum/FK/unique/source validation, evidence retained/redacted | Foundation constraints reject invalid severity/foreign key/duplicate; fixture synthetic credential removed before reports; Unicode and HTML special characters handled | PASS sampled |
| Recommendations/AI | Base/review separate, final composition consistent | Unified/LLM tests persist ai_reviews and base solutions, disabled/failure fallback, unchanged findings and consistent exports | PASS mocked; semantic limits Phase05 |
| History | Stored records survive restart and paginate | Foundation 27 records show 25/2 pages; EndToEnd verifies counts after subprocess restart | PASS |
| Comparison | Same target/branch, ordered completed scans; meaningful change groups | Management local scans produce NEW/RESOLVED/UNCHANGED; wrong/reversed/running targets rejected; supplemental absent findings yields 5 resolved groups and explicit warning | PASS valid data / FAIL malformed snapshot |
| Risk formula | Weighted Open findings, bounded normalization | All weights/statuses, mixed31, empty0, rounding38 and large100 checked | PASS |
| Severity/dashboard totals | Counts reflect stored rows, no placeholders | One per severity gives counts1 each, finding_count5/risk31; Foundation dashboard shows17 for oneCritical and changes after triage | PASS sampled |
| Supported reports | HTML/JSON/CSV render/download | Existing worker results + supplemental populated/empty/failed reports; all formats successful. PDF unsupported by generator | PASS supported formats |
| Report consistency | Counts/IDs/risk and final recommendation match snapshot | JSON5 findings/risk31, CSV5 finding rows, unified export agrees with selected action; immutable older report retains original status after triage/restart | PASS |
| Escaping/redaction | No executable HTML, sensitive literals or CSV formulas | HTML escaped, JSON/CSV parse, synthetic secrets absent; existing formula injection and legacy secret tests pass | PASS sampled |
| Empty/failed/malformed data | Empty/failed export supported; malformed data controlled | Six empty Completed/Failed exports200; invalid module JSON report400/no file, scan view500; non-object solution comparison500 | PARTIAL |
| Files/concurrency | Secure registered paths, failure cleanup, bounded contention | Report failure leaves no new file; traversal/symlink tests pass; WAL snapshot3→3→4; second writer lock fails ~0.059s with audit50ms timeout | PASS sampled / PARTIAL scope |

## Risk interpretation

Inspected analysis/risk_engine.py and documented dashboard formula:

`points = 10×Critical + 7×High + 4×Medium + 1×Low + 0×Informational`, counting **Open only**.

`score = round(100 × points / (points + 50))` using Python rounding. Empty yields0; oneCritical17; all five severities total22points yields31; 30Low gives37.5 rounded38; 10,000Critical rounds100. Resolved, Ignored and False Positive contribute0. Invalid severity cannot normally enter via Finding/SQLite constraints; calculate_risk itself expects a validated contract, not arbitrary input.

Current/open risk changes after triage. assessment_risk is a stored completion-time all-detections value and feeds historical charts; existing tests verify it remains unchanged. Overall dashboard counts repeated findings across scans separately, as documented. This is not CVSS, probability, unique-asset risk or proof of remediation. Float behavior beyond tested practical sizes and every rounding boundary was not exhaustively enumerated.

## Supplemental expected versus actual evidence

| Case | Expected | Actual | Status |
|---|---|---|---|
| schema | 14 tables, version4, foreign keys ON, WAL | [14, 4, 1, "wal"] | PASS |
| connection reuse | same object in app context | true | PASS |
| rollback | zero uncommitted rows | 0 | PASS |
| severity distribution | one each, count5, risk31 | {"counts": {"Critical": 1, "High": 1, "Medium": 1, "Low": 1, "Informational": 1}, "count": 5, "risk": 31} | PASS |
| empty Completed HTML | 200 nonempty report | 200 | PASS |
| empty Completed JSON | 200 nonempty report | 200 | PASS |
| empty Completed CSV | 200 nonempty report | 200 | PASS |
| empty Failed HTML | 200 nonempty report | 200 | PASS |
| empty Failed JSON | 200 nonempty report | 200 | PASS |
| empty Failed CSV | 200 nonempty report | 200 | PASS |
| populated HTML | 5 saved findings, masked secret, format-safe output | {"status": 200, "redacted": true} | PASS |
| populated JSON | 5 saved findings, masked secret, format-safe output | {"status": 200, "redacted": true} | PASS |
| populated CSV | 5 saved findings, masked secret, format-safe output | {"status": 200, "redacted": true} | PASS |
| WAL snapshot | reader stable until commit then sees writer | [3, 3, 4] | PASS |
| writer contention | second writer bounded lock failure | {"locked": true, "seconds": 0.059} | PASS |
| report metadata failure cleanup | exception and no orphan new file | {"failed": true, "no_new_file": true} | PASS |
| malformed module report | controlled rejection, no output file | {"http": 400, "no_new_file": true} | PASS |
| malformed module scan display | graceful record-level display | 500 | FAIL |
| absent findings comparison | 5 resolved groups with no-proof warning | {"resolved": 5, "warning": "RESOLVED means absent from the later scan, not proof of remediation. All triage statuses participate in detection matching."} | PASS |
| malformed solution comparison | controlled validation response (400) | 500 | FAIL |
| integrity | ok, no foreign key violations | ["ok", 0] | PASS |
| connection teardown | connection closed | true | PASS |
| risk empty | 0 | 0 | PASS |
| risk all severities | 31 | 31 | PASS |
| risk ignored | 0 | 0 | PASS |
| risk rounding tie | 38 | 38 | PASS |
| risk large | 100 | 100 | PASS |

## Defects and minimal suggested fixes — not implemented

### D1: malformed module JSON breaks entire scan detail (Medium)

Reproduction in disposable database: insert scan_modules.data_json=`{bad` for an existing completed scan; GET `/scans/<id>`. Expected: a controlled record-level unavailable observation or validation response. Actual: HTTP500; app.py scan_detail calls json.loads without a record-level guard. Error handler remains sanitized; no private data exposed. Report generation for the same input returns400 because JSONDecodeError is a ValueError, and no file is created.

Minimal suggestion: validate/decode persisted module JSON at consumption boundaries, preserve the scan and explicitly mark unreadable observations unavailable. Do not silently replace corrupted observations with successful empty coverage. Add this regression before any fix.

### D2: non-object solution snapshot breaks comparison (Medium)

Reproduction: two completed same-target scans, with an existing baseline finding; set that finding_solutions.data_json to `[]`; POST `/comparisons` with valid CSRF/baseline/current. Expected: controlled400 or explicit safe legacy fallback with warning. Actual: HTTP500. compare_scans assumes json.loads(...).get exists and raises AttributeError. Invalid JSON strings are also not independently validated by schema; not every shape was tested.

Minimal suggestion: type-check saved snapshot and nested context/analysis before reading logical_fingerprint. For invalid data, reject comparison clearly or use documented legacy grouping with an explicit coverage warning. Do not fabricate RESOLVED claims from discarded records.

These malformed records were deliberately injected through temporary SQL; the audit did not observe ordinary scanner serialization producing them. They are corruption/legacy-data robustness defects, not a demonstrated remote injection vector.

## Transactions, reports and cleanup boundaries

- get_db enables foreign keys and WAL, uses sqlite3.Row and 10-second busy timeout; teardown closes the context connection. Independent connection read snapshot held at3 rows while writer committed row4; fresh transaction then saw4.
- Contention used a second connection with **audit-only50ms timeout**, producing OperationalError in approximately0.059s while the first held BEGIN IMMEDIATE. This verifies contention behavior, not the production10-second timeout duration or application throughput under load.
- generate_report starts a read transaction before composing the report, releases it before filesystem output, writes an exclusive UUID filename with0600 creation mode, then registers metadata. Temporary trigger made metadata INSERT fail: written file removed, exception retained. This is ordinary exception cleanup; power loss/process kill between file creation and registration was NOT TESTED and no crash-atomic filesystem/DB guarantee is claimed.
- Path guards use validated basename/extension, directory-relative O_NOFOLLOW opening and regular-file checks. Existing tests reject traversal/symlink rows. PDF remains allowed in historical schema for compatibility, but FORMATS supports HTML/JSON/CSV only; PDF generation not implemented and not counted as a failed supported format.
- Recommendation and AI rows are saved components; final recommendation is composed at export time. Immutable report bytes remain unchanged after later triage/configuration changes. Phase05's unsupported AI advice can still enter a correctly persisted/exported recommendation; this phase does not establish model accuracy.
- Temporary audit directories/servers are cleaned by helper contexts/test teardown. Saved report files intentionally persist with their records during tests; generated application reports are not temporary files to delete. Abrupt crash recovery, concurrent multi-process migration, sustained load, disk-full failure and all malformed repository/options/AI JSON permutations NOT TESTED.
- ScanManager startup recovery can mark active scans Failed; tests used disposable DBs only. No user history was reset or migrated by this audit.

## Comparison qualification

RESOLVED means a comparison group is absent in the later scan. It does **not** update triage automatically or prove that code was fixed. Incomplete coverage, different scan options, missing logical evidence and legacy title/file grouping can change matches. The controlled five-group disappearance test retained the explicit no-proof warning. Earlier same-line/identity limitations remain; cross-engine accuracy was not re-evaluated here.

## Conclusion

Normal SQLite initialization, persistence, risk calculation and supported exports pass sampled checks. Two malformed-data cases fail gracefully only at the generic500 boundary rather than preserving an informative record-level workflow. No schema, formula or application fixes applied. Audit artifacts and progress status only updated; Phase7 stops here.
