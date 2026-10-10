# Phase 16 — Scanner accuracy corrections

Completed 2026-10-10. Scope: D06–D12 only. Existing engines/categories and
conservative probes remain; no source execution, public scanning, paid calls,
installation, database migration, UI or recommendation redesign. Tests use temporary
SQLite/data directories. Existing user history and historical findings are unchanged.

Read CLAUDE.md, required context documents in order, AGENTS.md, complete audit,
Phase03/04/09 reports and evidence, previous fix reports and applicable detector
subsystem documentation. Used the existing Developer checkout and `.venv/bin/python`.

## Per-defect result

PASS below refers to reproduced cases, not universal detector accuracy.

| Defect | Status | Before → after / remaining issue |
| --- | --- | --- |
| D06 same-line collapse | PASS | Original two eval calls: 1 raw / 1 persisted → 2 raw / 2 persisted. Python/JavaScript identical calls also remain distinct; repeated analysis of one operation still deduplicates. |
| D07 HTML comment location | PASS | Original comment on line2 reported line1 → line2. Repeated comments on different lines and script text masquerading as a comment tested. |
| D08 protected/documentary noise | PARTIAL | `secret_doc` instructional phrase: FP → TN. `cmd_quoted`, `crypto_checksum`, `java_checksum` remain FP under frozen labels; Semgrep `sql_allowlist` remains FP. See limitations, not claimed fixed. |
| D09 custom-named credential | FAIL / unresolved | Original positive `secret_custom_name` still undetected. Its credential meaning exists only in the fixture contract, not in source, use sites or a typed format. No speculative name/value/entropy rule added. |
| D10 wildcard framing | PASS | `frame-ancestors *` now yields existing Low/High-confidence framing finding. XFO cannot override an enforced wildcard CSP. Restricted origins/self/none and first-duplicate-directive behavior tested. |
| D11 inert/prose indicators | PASS for original fixtures; broader context PARTIAL | JSON script remains a reflection observation without XSS finding; original SQL documentation and traceback tutorial no longer produce findings. Genuine tested script/event/error conditions retained. Complete quoted error blocks remain ambiguous. |
| D12 listing soft-404 | PASS | Original 45-byte missing page and similar-length directory-index response: 0 → 1 listing finding (Low/High). Identical responses and matching baseline listing signatures remain filtered. |

## Changes and compatibility

- `scanner/sast/evidence.py`: retain parser byte-column in semantic evidence.
- `scanner/sast/common.py`, `analysis/finding_engine.py`: add column to fingerprint
  identity **only for colliding semantic findings** sharing source/category/title/
  location. Ordinary findings preserve the old fingerprint. Display stays file:line.
- `scanner/sast/security_context.py`, `analysis/correlation.py`: match precise parser
  operations by line/column, and include column in within-scan correlation keys.
  External evidence without columns stays ambiguous when several operations match;
  no guessed association. Existing logical comparison grouping still retains counts.
- `scanner/sast/html_scanner.py`: standard-library HTMLParser comment callbacks supply
  actual opening line instead of constant1. No markup or JavaScript execution.
- `scanner/sast/secret_scanner.py`: narrowly extend existing Markdown/RST instructional
  phrase exclusion for “Choose a memorable passphrase for your account”. Typed
  credentials and ordinary credential literals in documentation remain candidates;
  source/configuration passphrases are not excluded by this documentation filter.
- `scanner/header_scanner.py`: inspect actual frame-ancestors sources, reject unrestricted
  wildcard/scheme-only/empty values as adequate protection, honor directive precedence.
- `scanner/xss_scanner.py`: executable script MIME/module contexts distinguished from
  inert data scripts; template contents do not count as executed reflection.
- `scanner/sqli_scanner.py`, `scanner/disclosure_scanner.py`: preserve surrounding
  inline prose when extracting error text; exclude script/style data and explicitly
  labeled documentation/tutorial/example text on the same line as the signature.
  Do not suppress the entire response or require every error to begin at column0:
  runtime errors below prose or with an error prefix are still detectable.
- `scanner/directory_scanner.py`: a directory-index signature absent from the missing
  page outweighs length-only soft-404 similarity. Exact-body matching stays intact.
- `tests/test_phase16_accuracy.py`: 11 regression methods with positive/negative
  subcases and isolated persistence. `tests/test_repository_phase3.py`: old ambiguity
  assertion now verifies distinct precise anchors AND ambiguity without columns.

No migration rewrites legacy same-line collapsed records. Re-scan for corrected
results. Colliding new occurrences have new fingerprints, and corrected HTML lines
change their location-based fingerprints. Cross-version comparisons/triage therefore
need review; no automatic resolution or repair of historical data is implied.

## Reproduction and tests

Original source/response fixtures come from Phase04 pipeline/comment examples,
Phase03 resource case, and unchanged Phase09 response/54-repository datasets.
Fresh `PHASE_16_REPRO_BEFORE.json` and `PHASE_16_REPRO_AFTER.json` include count,
location, severity/confidence, masked evidence and original D06 SQLite count.
Before reproduction uses a disposable import overlay: copy current scanner/analysis
packages and restore only Phase16 files from the pre-Phase16 HEAD versions. Other
approved fixes remain; no working file or user database is reset. The frozen repository
and website BEFORE benchmarks were also run before production edits.

Commands from `/Users/kribeshthapa/Developer/Vibe code/SentinalScan`:

```sh
.venv/bin/python -B /tmp/phase16_reproduce.py
.venv/bin/python -B /tmp/phase16_focused.py
.venv/bin/python -B /tmp/phase16_run.py --full
.venv/bin/python -B /tmp/phase13_bench.py --output docs/fixes/PHASE_16_BENCHMARK_BEFORE.json --semgrep /opt/homebrew/bin/semgrep
.venv/bin/python -B /tmp/phase13_bench.py --output docs/fixes/PHASE_16_BENCHMARK_AFTER.json --semgrep /opt/homebrew/bin/semgrep
.venv/bin/python -B /tmp/phase09_website.py
# The website helper writes /tmp/phase09_website.json; copied separately as BEFORE/AFTER.
git diff --check
```

Focused tests were run after each correction (3, 4, 6, 7, 9, 10 methods as added),
then expanded persistence and existing detector suites: **37 passed**, 0 failed/errors/
skipped, 1.327s, exit0. Final full suite: **310 passed, 0 failed, 0 errors, 0 skipped, 22.487s, exit0**,
recorded in the verification JSON and `PHASE_16_TESTS.log`. The first full run was 308/309 with one obsolete expected-
ambiguity assertion failing; retained in `PHASE_16_TESTS_INITIAL.log`. It was replaced
with stronger precise/ambiguous coverage, not deleted. No tests were weakened to
hide retained benchmark errors.

Exact helper sources, commands, final results and hashes are retained in
`PHASE_16_VERIFICATION.json`; they can be restored into /tmp for reproduction.
Suite includes existing transport/safety, report, risk, persistence, AI fallback and
installed Semgrep tests. No live provider or native CodeQL run was made in this phase;
CodeQL contract regressions are part of the full suite, not an accuracy measurement.

## Frozen controlled benchmark comparison

One category-presence decision per labeled case; all confidence levels and
Informational observations count. No fixture/ground-truth changes.

| Dataset / engine | N | Before TP/FP/TN/FN | After TP/FP/TN/FN | Precision before → after | Recall before → after |
| --- | ---: | --- | --- | --- | --- |
| Repository built-in | 54 (27 positive/27 negative) | 26/4/23/1 | 26/3/24/1 | 86.67% → 89.66% | 96.30% → 96.30% |
| Repository built-in + installed Semgrep | 54 | 26/5/22/1 | 26/4/23/1 | 83.87% → 86.67% | 96.30% → 96.30% |
| Website built-in response indicators | 12 (5 positive/7 negative) | 4/3/4/1 | 5/0/7/0 | 57.14% → 100% | 80% → 100% |

Precision = TP/(TP+FP); recall = TP/(TP+FN). All these denominators are defined.
Standalone Semgrep and CodeQL accuracy: N/A, not measured by this existing harness.
The repository harness's legacy CodeQL “unavailable” string does not override the
successful Phase14 installation/execution evidence; CodeQL is disabled in this
benchmark. D06 occurrence counts and D07 line precision are separate regressions,
not measured by category-presence metrics. D12 is outside the 12-case website set.
These are small, previously known development fixtures, not independent holdouts
or real-world/universal accuracy estimates. Website success does not prove execution
or exploitability, nor establish complete DAST coverage.

## Unresolved cases and limitations

1. D08 bare `echo` + shlex.quote has POSIX-only ground truth; source supplies no target
   platform guarantee. Existing absolute POSIX command handling remains; no universal
   shell sanitizer inference added. Existing protected and unsafe quoting tests pass.
2. D08 Python/Java checksum contracts assert non-security use absent from source.
   Removing findings because a variable is named checksum could hide security uses.
   Existing Informational/Low observations remain counted as FP, not hidden from metrics.
3. D08 Semgrep rejecting-allowlist guard is still flagged. Proving domination, mutation
   and exception behavior across the independent engine safely needs additional modeling;
   no broad pattern-not or unverified sanitizer suppresses those results here.
4. D09 an arbitrary name plus untyped literal cannot establish credential identity.
   Detecting it would require reliable credential-use evidence absent from the original
   fixture. It remains a measured FN; its fixture name/value is not special-cased.
5. D11 only explicit prose and inert-script distinctions are corrected. A tutorial
   reproducing a complete standalone stack trace can still look like a real error;
   errors labeled as tutorial prose may be suppressed. These remain indicators.
6. D06 semantic parser columns address Python/JS/Java candidates, not every unpositioned
   external/secret/markup observation. External same-line results lacking columns may
   remain duplicated or ambiguous; no claims of global deduplication accuracy.
7. CSP handling is a bounded inspection, not a complete browser policy evaluator.
   Directory listing remains a title signature, not proof of accessible file contents.

Phase16 ends here. Unresolved limitations are documented rather than forcing
speculative broad rules. No further phase or fixes started.
