# Phase 24 — Repository coverage and code examples

Date: 2026-10-11. Scoped implementation and verification complete. No Phase25 work.

## 1. Executive summary

Verified the exact three reported files against saved scan38 content hashes and its pinned commit. The Python files contain unsupported legacy print syntax; retain Partial with safe structural explanations. The TypeScript configuration contains a valid leading JSONC comment; the existing config parser now accepts scoped comments/trailing commas. The existing single recommendation can show deterministic illustrative vulnerable/safer pairs, including masked YAML credentials and explicitly cross-language runtime-loading guidance. No new engine, provider, schema, route or workflow.

**361 tests passed, 0 failures, 0 errors, 0 skipped**, including12 new focused methods. Original54 and consumed holdout28 benchmarks unchanged. Real Semgrep and CodeQL smoke verification passed. AI is mocked; no live model-quality claim. User scan history only queried read-only for snapshot identity; no mutation, startup against user data or historical report rewrite.

## 2. Original Python Partial issue

User-observed scan coverage is confirmed in scan38: parsed_files1, unparsed_files2. Saved repository commit is `86bc7dc4840cd35dfb6cd43ae139ebc5d844dbcd`. Retrieved only the three requested files from `https://raw.githubusercontent.com/vulnerable-apps/juice-shop/<commit>/<path>` with15s timeout/512KiB read bound, no token; analyzed as text, never executed. Each retrieved SHA-256 equals the corresponding read-only scan_files record. This is exact snapshot evidence, not an assumption about today's master branch or a synthetic substitute.

| Exact file | Parser before/after | Line/column | Result |
|---|---|---|---|
|test/files/decrypt.py|Python3 ast.parse SyntaxError: legacy print statement|9 /2|Still not parsed; Partial retained|
|test/files/decrypt_bruteforce.py|Python3 ast.parse SyntaxError: legacy print statement|15 /2|Still not parsed; Partial retained|

No safe Python2 support exists in the current Python3 AST path. Conversion could change semantics; neither conversion nor a second parser/scanner was added. Parsed coverage on these two is0/2 before and after. Historical whole-module1 parsed/2 unparsed is unchanged; the third file/full repository was not rescanned in this investigation.

## 3. Original Configuration Partial issue

Saved scan38 records192 configuration files with frontend/tsconfig.json unparsed. Exact matched file begins with a block comment, producing JSONDecodeError at1:1 under json.loads. After preprocessing, this same436-byte file parses with zero configuration findings. No trailing comma is present in the original file; trailing-comma support is verified separately on synthetic fixtures.

Before/after for exact affected file: **0/1 →1/1 parsed**, unparsed1→0. Do not present this as an observed full192-file rescan: it was not rerun. Existing historical records remain unchanged; new scans record new diagnostics and coverage.

## 4. Root-cause evidence

`PHASE_24_ORIGINAL_PARSING.json` records paths, bytes, hashes, saved-hash equality, original errors and new module output. Python errors now say legacy print syntax is unsupported, without copying source or exception messages. Configuration parses its relevant JSONC subset. Scan38 recorded Semgrep and CodeQL Completed globally; this does **not** prove successful per-file analysis of either legacy Python file. Diagnostics explicitly say other-engine assessment is not established and refer to separate engine coverage.

## 5. Exact changed files

Production six:
- scanner/sast/common.py: shared fixed-message parse_diagnostic, no raw source/error serialization.
- scanner/sast/python_scanner.py: per-file read/parse failures with sanitized diagnostics; retain counts/unparsed/flow behavior.
- scanner/sast/config_scanner.py: scoped JSONC preprocessing, safe read/parse errors, explicit parsed count.
- analysis/recommendation.py: extend existing illustrative policy with optional vulnerable_code/language; YAML secret teaching example.
- templates/_solution.html: supporting vulnerable/safer blocks in existing card, existing copy controls and example-type label.
- templates/report_document.html: equivalent escaped illustrative pair in HTML exports.

Tests: new tests/test_phase24_coverage.py; two obsolete no-YAML-code expectations in test_finding_simplification.py and test_unified_recommendation.py now assert the requested masked illustrative pair, no source-specific pair, Not Available validation, rotation and no secret disclosure. No detection, privacy or existing validation assertion weakened/deleted.

Docs: this report, evidence/logs, AGENTS.md and relevant architecture/UI/AI/progress context files. Baseline Git state and protected hashes: PHASE_24_BASELINE.json; final inventory/hashes: PHASE_24_HASHES.json. No commit/push, dependency installation or database migration.

## 6. Parsing improvements and limits

Existing parser only: JSONC is enabled for tsconfig.json/jsconfig.json and dotted project variants (e.g. tsconfig.app.json). Comment spans and trailing commas become spaces, preserving newlines/columns and string contents including URLs, escaped quotes, // and /* inside strings. Ordinary .json remains strict; no JSON5/unquoted keys/arbitrary JavaScript, compilation, inheritance resolution or config execution. YAML safe loading/alias limits and file/discovery/deadline limits are unchanged.

Malformed comments, empty comma entries, consecutive commas, undefined values, invalid UTF-8 and unreadable files stay unparsed. Python read errors no longer abort the whole module; other files continue. parse_errors is bounded to100 like unparsed_files, while counts cover all attempted files. Diagnostics contain path/category/line/column/disposition/fixed reason; unavailable positions are null. No error text containing source/credentials is exposed. Existing worker marks nonempty unparsed_files Partial. Configuration finding locations remain honest file-level line1, not newly precise field locations.

## 7. Coverage verification

| Fixture | Expected / actual | Status |
|---|---|---|
|Python3 inert text plus legacy/invalid/encoding/unsupported examples|1 parsed,4 unparsed; structural diagnostics; no execution|PASS|
|Python read/nesting failure|0 parsed; failure category; private error text absent|PASS|
|JSONC strings/comments/trailing commas|parsed, preserved strings, no comment-generated debug finding|PASS|
|Malformed JSONC|remains unparsed, no silently repaired empty entries|PASS|
|JSON/YAML/config scope mix|5 attempted,4 parsed,1 ordinary-JSON failure;2 intended configuration findings Medium/High, correct file-level line1|PASS|
|Temporary full repository worker|Python1parsed/1unparsed and Config1parsed/1unparsed both Partial; scan readable, DB integrity ok, cleanup true|PASS|
|Exact original files|2 legacy failures retained; tsconfig succeeds|PASS within scoped support|

## 8. Recommendation architecture

Reuse example_secure_pattern called by existing compose only when no usable example survives. No changes to recommendation_composer, Ollama transport, prompts, schema, grounding validator, completion callback or DB schema. Optional vulnerable_code/vulnerable_language live in the existing example dictionary alongside safer code/language/note. Existing final_solution serves UI/new reports. JSON includes full final solution; CSV already carries it in details_json. No second recommendation or endpoint.

Historical findings derive the safe example at read time without persisting changes or invoking a provider. The dedicated source-specific code_pair policy is unchanged. Source-specific examples still need pinned context and existing checks. AI secret output remains guidance-only; deterministic supporting illustrations are separate from accepting model-generated secret code.

## 9. Vulnerable versus safer examples

| Finding | Supporting pattern | Qualification |
|---|---|---|
|YAML credential|database/password with literal [REDACTED]; Python os.environ runtime loading|Illustrative, cross-language; not retained YAML, no interpolation claim, no verified replacement|
|Python credential|masked credential assignment → existing environment-loading example|Illustrative; provision runtime value; rotate/revoke if real|
|Unknown SQL API|concatenation → existing query/parameters pseudocode|No invented driver or placeholder syntax; identifiers separately allowlisted|
|DOM HTML insertion|innerHTML user input → textContent teaching example|Plain text only; intentional HTML needs supported sanitization; not exact detected source|
|Missing nosniff header|Existing neutral nosniff configuration guidance retained|No invented Flask/server identity or backend source|

Illustrative examples carry Low fix confidence and Not Available static validation, not a guarantee. Unknown/dismissed findings remain text-only where unsupported. Exact supported current/recommended pairs remain unchanged and covered by existing tests. Actual secret source is deliberately not copied into the illustrative vulnerable example.

## 10. Secret-redaction verification

Synthetic secret is absent from saved solution, SQLite dump, final composition and prepared AI payload. Existing raw-source/redaction tests also pass. YAML uses only [REDACTED]. No credentials authenticate or enter report evidence. No raw original secret from user data was read or printed. Error handling tests pass private marker messages to read/parse failures and assert they are absent in diagnostics. Source-file hashes, not content, are retained as investigation evidence.

## 11. Ollama and fallback

Full existing mocked enabled/disabled/outage/malformed/unsafe-source/grounding/native-contract suites pass. New malformed review retains deterministic illustrative content; historical page/report reads assert provider never called. Existing accepted review tests retain one final recommendation and source-specific validation. **Real Ollama inference NOT TESTED in Phase24**; no provider settings/budgets/model changed. This verifies contracts/fallback, not live semantic accuracy.

## 12. UI, reports and persistence

Flask/Jinja tests: one Recommended Fix, one existing Technical Details container, masked Vulnerable Example and Safer Example / Example Secure Pattern, visible qualification/confidence/validation. Reuse escaped code blocks, indentation, overflow rules and existing clipboard controls. No new CSS/JavaScript, manual AI button or edit/push workflow. Browser layout/clipboard/responsiveness execution **NOT TESTED**; CSS mechanisms retained, template behavior tested.

HTML/JSON/CSV generated from the same final_solution; JSON and CSV nested examples equal the UI composition. HTML escapes script/image markup in both new fields. CSV retains formula escaping (fixture title =1+1 is prefixed) and valid JSON in details_json. Temporary SQLite integrity/worker persistence/cleanup pass. Rendering alone leaves dump unchanged. Saved historical reports not regenerated/overwritten. No report schema/column changes; CSV pair is nested data, not new flat columns.

## 13. Tests and real-engine verification

| Run | Passed | Failed/errors/skipped | Timing | Exit |
|---|---:|---|---|---:|
|Complete|361|0/0/0|25.694s unittest;26.025s process|0|
|Focused Phase24|12|0/0/0|0.457s unittest;0.698s process|0|

Full command: `.venv/bin/python -B -m unittest discover -s tests -v`.
Focused adds `-p test_phase24_coverage.py`. Wrapper uses temporary SENTINELSCAN_DATA_DIR, AI off, existing Semgrep opt-in. No dependencies installed. Original baseline349 +12 new methods=361, no duplicated imported test classes in final count. Existing extraction, secrets, AI, SQLite/restart, risk, reports, workflow and all9 Phase20 replay tests pass. Protected replay/provider/evaluator/database hashes remain unchanged.

Initial full run349 had2 failures solely for obsolete assertions requiring no YAML example. Their replacements strengthen the new qualification/privacy requirements; originals and output retained as PHASE_24_INITIAL_TESTS.log/json. Initial focused discovery also included4 imported existing class methods; switched to module import, final count12 unique new methods. Those intermediate counts are not final evidence.

Semgrep1.179.0: actual binary /opt/homebrew/bin/semgrep; bundled validation0 errors/3rules; real Python/JS positive/negative integration and both benchmark stages pass. CodeQL2.27.2: actual run-local.sh configuration with installed Python1.8.12/JS2.4.7 packs, serving replaced only by temporary verification hook. Real download substitute is inert local ZIP, worker/extraction/CLI/results/SQLite all real:

|CodeQL fixture|Status|Imported|Time|Temporary cleanup|
|---|---|---:|---:|---|
|Python|Completed|1|13.121s|True|
|JavaScript|Completed|1|21.991s|True|
|Mixed|Completed|2|34.454s|True|

Positive pyline7/jsline2, expected severity/confidence/provenance checked, negative counterparts have no imported finding. No query packs downloaded, no sandbox bypass or scanned application execution. PHASE_24_CODEQL.json/log contains exact arguments/outcomes. Optional engine smoke is not a complete accuracy benchmark.

Reproduction from project root with existing .venv:

```text
.venv/bin/python -B /tmp/phase24_tests.py
.venv/bin/python -B /tmp/phase24_tests.py --full
.venv/bin/python -B /tmp/phase13_bench.py --output docs/fixes/PHASE_24_BENCHMARK.json --semgrep /opt/homebrew/bin/semgrep
.venv/bin/python -B /tmp/phase24_holdout.py
.venv/bin/python -B /tmp/phase24_launch.py
/opt/homebrew/bin/semgrep --validate --config scanner/engines/semgrep_rules.yml --metrics off --disable-version-check
git diff --check
```

Helpers archived in docs/fixes/evidence/phase24_*.py. Launcher reproduction expects /tmp/phase24-hook/sitecustomize.py and /tmp/phase24_launcher_verify.py; restore archived copies. Existing benchmark helper archived as phase24_bench.py. All final commands exit0, diff check passes. Existing user's running Flask process was not restarted; restart it and create a new scan to obtain new coverage diagnostics. Existing findings derive examples on render with updated process code.

## 14. Benchmarks (unchanged labels/scoring)

Both datasets are consumed development/regression fixtures, not independent real-world accuracy estimates. Original54=27positive/27negative; holdout28=14positive/14negative plus3 separately ambiguous. Built-in and combined results unchanged from Phase23:

|Dataset / both engine stages|Before → after TP/FP/TN/FN|Precision|Recall|F1|
|---|---|---:|---:|---:|
|Original54|26/2/25/1 →26/2/25/1|92.86%|96.30%|94.55%|
|Consumed Phase22 holdout28|13/0/14/1 →13/0/14/1|100%|92.86%|96.30%|

Both runs valid with completed required modules, cleaned archives and unchanged dataset hashes. All confidence levels counted, category scoring/dedup unchanged; no labels removed. Raw cases/metrics in PHASE_24_BENCHMARK.json and PHASE_24_HOLDOUT_RESULTS.json. No regression and no measured detection-accuracy gain claimed from parser/UI changes. Original opaque credential FN and2 informational checksum FPs, holdout HMAC-MD5 policy FN remain.

## 15. Limitations and assessment

Python2 files remain unparsed; no full legacy analysis. UTF-8-only vetted inventory may exclude other encodings before these modules. JSONC support intentionally does not resolve inherited config/runtime behavior; JSON/YAML findings retain file-level locations. No full192-file rescanning claim. Per-file external-engine coverage cannot be inferred from global completion. Illustrations are teaching material, not validated patches or inferred application architecture; unrecognized languages stay limited. Existing bounded SAST/DAST heuristics/unknown-flow limitations remain. Live GitHub authentication, browser behavior and real Ollama quality not retested.

Suitable for a supervised college live demonstration with these limitations explained. Restart updated app and rescan for diagnostics; no guarantee of finding every vulnerability or producing a secure runnable patch. Existing local-only assumptions remain; not a public production-readiness claim.

## 16. Future recommendations (not implemented)

If broader legacy support is later requested, evaluate existing engines against versioned known legacy fixtures and retain explicit per-file coverage provenance. For more exact remediation, collect verified application-loader/database context before replacing pseudocode or YAML illustrations. Use fresh independently labeled fixtures for future accuracy claims. No further phase or feature has begun.

Phase24 complete. Stop pending approval.
