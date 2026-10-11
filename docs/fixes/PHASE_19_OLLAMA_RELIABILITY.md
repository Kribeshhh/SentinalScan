# Phase 19 — Ollama recommendation reliability

Date: 2026-10-10. Existing Ollama pipeline only. No detector, schema migration,
UI, provider, user history, or scanner algorithm changes. No downloaded models.

## Root causes and bounded corrections

1. Phase 18 exposed a generation schema that validated fields independently: it
   allowed `example_type=none` alongside nonempty code/original source. Prompts alone
   did not prevent these combinations. The existing independent validator correctly
   rejected them, but the model repeatedly produced them.
2. The model copied source despite a guidance-only task, including redacted secret
   source. Fresh scans generally lack a full pinned original needed for patch
   validation. A snippet is not sufficient authority to generate a validated patch.
3. The model selected generic supported statements before specific ones. They were
   valid guidance but often less useful than the existing deterministic recommendation.
4. `refine_scan` stopped whenever `refine_finding` returned false, conflating a single
   rejected answer with an unavailable provider. One malformed answer starved later
   candidates. The original stop predicate was reinstated in a temporary function
   clone to reproduce this: two findings, first invalid/second valid, one call and
   zero saved reviews before; two calls and one saved review after. No production
   rollback was used. [Queue reproduction](PHASE_19_QUEUE.json).
5. `keep_alive=0` repeatedly unloaded the model. Measurements below support keeping
   it resident briefly without raising inference timeouts or output limits.

### Generation contract

The existing native `/api/chat` format schema now contains mutually consistent
alternatives using `const` and `anyOf`:

- Guidance: type `none`, empty code and empty original_code.
- Website configuration: type `configuration`, nonempty code, empty original_code.
- Repository replacement: only requested when a pinned original is locally available;
  type `source_specific`, nonempty code and original_code fixed to the supplied snippet.
- Secret findings always use guidance-only mode. Unverified false-positive prose
  remains prohibited; the schema now constrains its list to empty as validation already did.

These are generation constraints, not authorization to accept a fix. No invalid model
code is repaired, trimmed into correctness or given invented source. The independent
structure, grounding, header grammar, source matching and static validators are
unchanged. Configuration examples remain illustrative; source code must still meet
all existing checks. Mock providers ignoring the schema still fail those checks.

The native schema uses Ollama's documented JSON Schema `format` support:
[official structured output documentation](https://github.com/ollama/ollama/blob/main/docs/capabilities/structured-outputs.mdx).
The installed model/service exercised guidance and configuration alternatives live.
Full-source replacement alternatives are regression-tested; no new full-source capture
or historical source record was created to force a live patch acceptance.

Specific already-supported statements now precede generic choices at prompt
preparation. The content/allowlist does not change; the schema and prepared context
remain identical in option order. No assessment is forced to likely_valid, and
uncertainty does not become evidence of exploitability.

### Queue behavior

The same callback keeps its boolean-compatible refine_finding API, with an optional
internal outcome record. Individual invalid response ValueErrors retain fallback and
allow the next candidate. Native model/inventory/configuration or non-200 HTTP failures
raise ProviderUnavailable; transport, storage and unexpected runtime errors stop the
pass. No retry or new worker. Malformed model content is an individual rejection.

The existing 20-candidate cap and 60-second **between-review** deadline remain.
An already-started two-pass review can finish after that deadline, as before; this
is not a strict total wall-clock limit. Deadline exhaustion stops before the next
finding. Tests exercise successful continuation, outage stop, all-invalid candidate
cap and deadline expiry. Scan status and finding severity/confidence remain unchanged.

## Latency investigation

Model `qwen2.5-coder:3b`; endpoint `http://127.0.0.1:11434`; existing local installation.
Two cold/warm pairs used the same redacted SQL payload and original output schema,
not public source. Cold calls retained the model for 60s; following warm calls used
keep_alive=0 to unload before the next cold measurement. No daemon was terminated.
[Raw timings and Ollama counters](PHASE_19_LATENCY_BEFORE.json).

| Trial | Wall seconds | Model load seconds | Prompt evaluation seconds | Output tokens |
|---|---:|---:|---:|---:|
| Cold 1 | 16.235 | 7.223 | 3.021 | 217 |
| Warm 1 | 6.178 | 0.009 | 0.049 | 217 |
| Cold 2 | 18.350 | 9.206 | 3.030 | 217 |
| Warm 2 | 6.372 | 0.003 | 0.056 | 217 |

Each diagnostic prompt had 6,126 characters / 1,248 evaluated prompt tokens;
request body 8,406–8,410 bytes. Output cap remained 3,000 tokens. The repeated warm
mean was 6.275s versus cold 17.293s in this small sample. These are single diagnostic
inferences, not whole two-pass reviews or a universal performance promise.

Smallest applied resource change: **keep_alive=60s instead of 0**. The 20-second HTTP
request deadline, 3,000 output-token ceiling, request/body bounds and scan budget
remain unchanged. Warm reuse reduces repeated loading, at the cost of retaining model
memory for up to the configured idle interval (and longer while actively reused).
An idle model is left to Ollama to unload; no explicit stop affects other users.
No increase in time/token limits was required by these measurements. Cold requests
can still timeout on a busy machine. Token-limit truncation still causes rejection;
this phase does not claim a calibrated worst-case latency guarantee.

## Real workflow verification

Temporary fixture databases, real built-in static scanning of inert ZIP source,
real ScanManager completion callbacks, native local Ollama HTTP and existing
validators/composer were used. GitHub archive retrieval alone was substituted with
local ZIP creation. SQL, DOM XSS and synthetic hardcoded credential repositories
were not executed. Semgrep, CodeQL and OSV were disabled in these focused AI cases.
The header case uses the existing header rule on a controlled HTML response and
calls the same completion hook; it is not a full DAST network scan.

The final run is recorded in [release live evidence](PHASE_19_RELEASE_LIVE.json)
and [log](PHASE_19_RELEASE_LIVE.log). Every real request records HTTP status, duration,
sanitized output/context and a request hash. The synthetic secret is asserted absent
before transport. Earlier development runs remain separately named; they are not
pooled into an acceptance percentage.

| Finding | Native chat calls / seconds | Grounded review saved | Selected AI contribution | Final result |
|---|---|---|---|---|
| sql | 2 / 13.675, 7.555 | Yes | No | Needs Review; deterministic guidance retained |
| xss | 2 / 6.559, 6.646 | Yes | No | Needs Review; deterministic guidance retained |
| secret | 2 / 4.587, 5.21 | Yes | No | Needs Review; deterministic guidance retained |
| headers | 1 / 5.966 | Yes | Yes | AI header configuration |

Final run: **7/7 native chat requests HTTP 200; 4/4 valid grounded reviews saved;
1/4 AI contributions selected for display; 3/4 appropriately retain deterministic
guidance because repository assessments remain Needs Review.** Before: zero accepted
reviews in the four primary Phase 18 cases. This fixes contract rejection; it does
not turn uncertainty into an approved patch.

Acceptance has two separate meanings: a structurally valid, grounded **review saved**
to ai_reviews and an **AI contribution selected** for final display. The unchanged
composer may retain deterministic guidance for uncertain/disputed repository reviews.
Do not equate persistence, schema validity or two-model agreement with a secure fix.
No source-specific generated patch was validated in these fresh-source cases.

Quality: SQL advice separates values from SQL structure; DOM advice distinguishes
plain text from intentional sanitized HTML; secrets require removal and rotation if
real; nosniff guidance targets the actual missing header. No new framework, source
file, package version or verified-exploitation claim was introduced. The model selects
from grounded statements; it is not freely inventing new remediation knowledge.

For each fixture the scan/finding routes return HTTP 200, one recommendation element
is rendered, the isolated SQLite integrity check is `ok`, and the credential value
is absent from transport and UI. Source examples remain deterministic when no safe
AI patch is available. Real browser/clipboard/layout behavior was not retested.

## Regressions and evidence

Added `tests/test_ollama_reliability.py` (9 tests): original inconsistent tuples,
guidance-only empty fields, configuration/source alternatives, unchanged native
resource limits and outage classification, prepared option order/immutability,
rejection continuation, provider stop, candidate cap and scan deadline.

The original Phase 18 inconsistent outputs still fail independent validation; the
new generation schema prevents those combinations rather than relaxing the validator.
Existing unsafe-header, malicious/unsupported prose, secret, malformed-output,
source mismatch, fallback, disabled AI, persistence and UI tests remain intact.

Exact full-suite child command:

```sh
.venv/bin/python -B -m unittest discover -s tests -v
```

Executed by `/tmp/phase19_tests.py` with a temporary data directory, live AI disabled
and the existing installed Semgrep opt-in enabled. **319 passed, 0 failures,
0 errors, 0 skipped; 21.265s test time, exit 0** (21.734s wrapper wall time).
[Full log](../audit/PHASE_19_TESTS.log), [command/timing](../audit/PHASE_19_TESTS.json).
No existing test was deleted, weakened or edited in Phase 19.

One intermediate run passed 318 tests before the final ordering test was added.
A subsequent 319-test run failed the existing schema/context order equality test.
Ordering was moved to prompt preparation, preserving that original assertion; the
final full run passed. [Intermediate failure log](PHASE_19_INTERMEDIATE_TESTS.log).
A temporary live-helper indentation error was corrected before its first successful
run; it was not an application error.

Commands: `.venv/bin/python -B /tmp/phase19_latency.py` (four measurements),
`.venv/bin/python -B /tmp/phase19_queue.py` (before/after stop predicate),
`.venv/bin/python -B /tmp/phase19_live.py` (fixture live run),
`.venv/bin/python -B /tmp/phase19_tests.py` (full suite), `git diff --check`.
Reproducible helpers and file-change evidence: [manifest](PHASE_19_EVIDENCE.json).
No secrets or user prompts were captured; only authored fixtures and redacted output.

## Changed files

- `integrations/llm.py`: request-specific consistent schema, instructions, explicit
  provider-unavailable error and 60s keep_alive.
- `analysis/ai_grounding.py`: order specific supported prompt options first; validator
  and underlying statements unchanged.
- `analysis/llm_review.py`: local source-availability signal and bounded per-finding
  rejection/outage distinction.
- `tests/test_ollama_reliability.py`: new regressions; existing test files unchanged.
- `AGENTS.md`, `context/architecture.md`, `context/ai-workflow-rules.md`,
  `context/progress-tracker.md`: active policy/status; this report and adjacent evidence.

No recommendation composer, scanner/detection, database, UI or dependency change.
No user scan history touched; historical reviews/reports remain unchanged.

## Limitations and stopping point

The model may remain uncertain, choose generic guidance or fail its deadline. Those
cases must retain deterministic output. New source patches still require pinned
originals and supported static validation; no guarantee of runtime security or
behavior preservation. Guidance quality depends on scanner evidence and deterministic
catalogue quality. All local tests use a small known fixture set, not a model accuracy
benchmark. Real GitHub service/private repository access and production deployment
were not retested. Existing unrelated audit defects remain outside Phase 19.

Phase 19 only. No subsequent phase or additional fix started.
