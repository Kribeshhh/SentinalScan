# Phase 15 — Stored-data robustness

2026-10-09. D13/D14 only; read-only validation at existing consumption boundaries.
No schema/migration, scanner, risk formula, triage, AI or report generator changes.
No user database/history was opened, reset or rewritten by verification.

## Context and reproduction

Reviewed CLAUDE.md, six context documents in order, AGENTS.md, the complete audit,
Phase07 database/report audit and its evidence JSON, and previous Phase11–14 fix
reports. Inspected scan-detail rendering, comparison creation/transaction/matching,
finding-solution storage, templates and report consumption. Used the existing
`.venv/bin/python` in `/Users/kribeshthapa/Developer/Vibe code/SentinalScan`.

The reproduction helper sets SENTINELSCAN_DATA_DIR before importing the app and
creates a disposable SQLite database and reports directory. It inserts two compatible
Completed website scans and a real finding row via `save_finding`. These are explicitly
authored test records, not fake results added to the user's workspace.

| Defect | Temporary persisted input and route | Before | After |
| --- | --- | --- | --- |
| D13 | `scan_modules.data_json = '{bad'`; GET `/scans/<id>` | HTTP500, JSONDecodeError | HTTP200, explicit module observations unavailable; scan/findings retained |
| D14 | Existing finding's `finding_solutions.data_json = '[]'`; valid-CSRF POST `/comparisons` | HTTP500, AttributeError | HTTP400, explicit comparison unavailable; no new/refreshed snapshot |

Exact observations: `PHASE_15_BEFORE.json`, `PHASE_15_AFTER.json`. D14's confirmed
corrupt input is the **finding solution snapshot used to obtain comparison identity**,
not `scan_comparisons.summary_json`. That distinction matters when reproducing it.

## Root causes and changes

### D13 — scan module observations

`app.py` decoded stored JSON without catching decode failures, then formatted it
for the template. It also accepted arbitrary top-level JSON types as observations.

`analysis/stored_data.py` now supplies `object_json`: accept a decoded JSON object,
reject invalid syntax, scalar/list/null values, non-finite constants and excessive
nesting that raises RecursionError. Raise a dedicated sanitized `StoredDataError`
without exposing stored contents or parser exception text.

The scan-detail route catches that error per module. Its view model marks the
observations unavailable, omits the malformed payload and includes it in the coverage
warning count. The existing module disclosure displays **Unavailable**, an explicit
warning, and the original recorded module status. Other module observations and all
findings remain visible. The database's module/scan status is not rewritten. Risk
continues to be calculated from the original findings.

Module observations have heterogeneous scanner-specific fields and no shared required
keys, so `{}` remains valid (including queued/legacy modules). Unknown object keys
are retained and escaped for display. Validation does not infer secure coverage from
an empty object, inspect arbitrary scanner semantics, or fabricate missing fields.

### D14 — comparison identity metadata

`compare_scans` chained `.get()` calls after decoding `finding_solutions.data_json`.
A list/null/scalar at the top or nested context caused AttributeError; a non-scalar
fingerprint could also fail during grouping or supply an invalid identity.

`logical_fingerprint` now requires an object snapshot, and object-valued
`finding_context` and `analysis` when present. A non-null logical fingerprint must
match the existing generated format: 64 lowercase hexadecimal characters. Missing
optional context/analysis/fingerprint and an explicitly null fingerprint retain the
existing legacy matching behavior and its existing limitations warning. Present
malformed objects/identities are rejected, never silently discarded as no findings.
No finding rows are removed from the comparison input.

Comparison creation also validates any present module observations before returning
a comparison. Corrupt observations therefore cannot masquerade as complete coverage
and produce a saved change summary. Missing/partial module coverage still uses the
existing qualified comparison behavior when the stored data itself is valid.

`management_routes.py` catches the dedicated error and returns HTTP400 with a fixed
message: comparison unavailable; nothing was saved/refreshed; records unchanged.
The existing `BEGIN IMMEDIATE`/transaction context rolls back on rejection, preserving
a prior valid comparison snapshot. No results page with fabricated NEW/RESOLVED groups
is rendered for a rejected request. Valid matching and no-proof-of-remediation wording
remain unchanged.

## Changed files

- Added `analysis/stored_data.py`: focused stored-object/identity validators.
- Changed `app.py`: module-level read failure handling and warning count.
- Changed `templates/scan_detail.html`: unavailable observation display only.
- Changed `analysis/management.py`: validated snapshot identity/module reads.
- Changed `management_routes.py`: explicit sanitized HTTP400 comparison error.
- Added `tests/test_data_robustness.py`: ten regression methods with subcases.
- Documentation: this report/evidence, architecture note and progress tracker.

`database.py`, risk calculations, reports, scanners and finding/AI recommendation
pipelines are unchanged. There are no schema changes, migrations or repair writes.

## Verification

```sh
.venv/bin/python -B /tmp/phase15_repro.py docs/fixes/PHASE_15_BEFORE.json
# After the fix:
.venv/bin/python -B /tmp/phase15_repro.py docs/fixes/PHASE_15_AFTER.json
.venv/bin/python -B /tmp/phase15_focused.py
.venv/bin/python -B /tmp/phase15_run.py --full
git diff --check
```

The complete runner uses `unittest` discovery over `tests`, temporary data before
application imports, disabled/mocked AI, and the existing installed Semgrep test.
No paid services, new dependencies, public scans or live LLM calls. Phase14's live
CodeQL fixture verification is not rerun for this database-only change.

**Complete suite: 299 discovered/executed/passed, 0 failures, 0 errors, 0 skips,
21.456 seconds, exit0.** Full log: `PHASE_15_TESTS.log`. Focused regression/management/
foundation results: **24 passed, 0 failures/errors/skips, 3.375 seconds, exit0**,
recorded in `PHASE_15_FOCUSED.log` and `PHASE_15_VERIFICATION.json`.
The verification JSON retains exact helper sources, final counts and hashes; restore
its scripts to the documented temporary paths to repeat the commands. The pre-edit
HTTP500 observations are historical; repeating the helper on fixed code yields 200/400.

Coverage includes:

- Malformed JSON, invalid UTF-8 BLOB, arrays, null, numbers, booleans, strings,
  non-finite constants and deeply nested input.
- Malformed present context/analysis fields and logical fingerprint types/format.
- Safe missing legacy metadata and valid logical identity; unchanged matching/risk.
- Invalid baseline and current snapshots; corrupt module blocks comparison creation.
- Failed refresh preserves an existing saved comparison and its readable details.
- Per-module failures retain other observations and Critical finding/risk17 display.
- Stored raw payload does not leak into page/error output; valid special characters
  are escaped. Database table snapshots remain identical before/after rejected reads.
- Existing management/foundation/full suites cover normal NEW/RESOLVED/UNCHANGED,
  triage, risk totals/trends, history/restart, reports/export/download and persistence.

## Limits

This is validation of the two affected read paths, not a complete schema validator
or database recovery tool. Well-formed but factually wrong observations cannot be
identified here. No corrupted record is repaired/deleted automatically. Other JSON
consumers, including arbitrary damage to already-saved comparison summary JSON,
are not comprehensively hardened by this scope. Existing report rejection behavior
is preserved rather than changed. Coverage status and an absent comparison finding
still do not establish security or verified remediation.

Phase15 complete after verification. Stop and await approval; no next phase begun.
