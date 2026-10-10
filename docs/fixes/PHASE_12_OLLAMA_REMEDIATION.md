# Phase 12 — Ollama remediation workflow and grounding

Date: 2026-10-09. Scope: the existing optional remediation workflow only.
Detectors, severity, confidence, fingerprints, risk, database schema, UI routes,
queue architecture, reports implementation and user history are unchanged. No model
installation, live inference, public scan or paid-provider request was made.

## Reproduced defects before editing

Read CLAUDE.md, the six context files in order, AGENTS.md, the complete audit,
Phase 05 and its evidence JSON, Phase 11, and applicable recommendation/evidence
validation documentation. Historical activation instructions remain historical.

`PYTHONPATH=. .venv/bin/python -B /tmp/phase12_before.py` used authored fixtures
and a temporary data directory. Exit 0. Results retained in
[PHASE_12_BEFORE.json](PHASE_12_BEFORE.json):

| Audit defect | Observed before | Required/observed after |
|---|---|---|
| D03: invented package/framework/exploitability | `imaginary-package 99.99.99`, Django and exploitable claims accepted and composed as AI-assisted | Unknown prose rejected before saving; old unsupported reviews no longer promoted on read |
| D03: two agreeing harmful reviews | Disabling authentication selected as remediation for a DOM sink | Rejected independently in either pass; analyst failure stops before forwarding to skeptic |
| D04: unsafe header value | `X-Content-Type-Options: unsafe-value` selected as an example | Rejected; `nosniff` positive control accepted as an illustrative configuration, not a validated deployment |

The original Phase 05 audit artifacts are unchanged. Their findings describe the
old implementation, not a real-model hallucination rate. Regression tests reproduce
these failure inputs against the new boundary.

## Workflow retained

Scanner saves finding and evidence → deterministic base → minimized, redacted
context → optional existing Ollama review → deterministic validation → separately
saved accepted review → one final recommendation → human implementation/review.

The existing `refine_scan` completion callback and `refine_finding` remain the only
orchestration path. Repository evidence retains analyst/skeptic passes; website
and legacy records retain single-pass compatibility. Neither detection nor page or
report GETs invoke a model. AI remains optional. Failures preserve Completed scan
state, scanner records and deterministic guidance. A failed refresh preserves old
AI rows internally but suppresses their contribution until a successful review.

## Conservative factual validation

A keyword blacklist cannot establish whether arbitrary model prose is true.
Accordingly, **the model now selects grounded statements rather than inventing
free-form explanations**. This is an intentional restriction, not a claim of general
natural-language fact checking or new model intelligence.

`analysis/ai_grounding.py` reconstructs bounded allowed reasons, impacts, actions
and follow-ups from the existing deterministic policy. Context-specific explanations
qualify SQL/DOM/dependency/header observations as scanner reports, not verified
exploitation. Missing context remains uncertainty. Secret choices include rotation
or revocation and never real values. Unknown rule recommendations cannot whitelist
arbitrary finding prose. Raw evidence, source snippets, headers and a model-supplied
`supported_statements` list never authorize advice.

Existing preparation adds these redacted choices beside the allowlisted context.
The native Ollama schema uses per-request enums to make correct selection easier
for the small local model. The ordinary local validator independently rebuilds the
choices; schema compliance and model confidence are not trusted. Additional clauses,
paraphrases, invented paths/lines/frameworks, package releases not in deterministic
advisory guidance, contradictory claims and weakening advice are rejected. This
also rejects some correct unsupported paraphrases. No blacklist or second-model
agreement can bypass the contract. Nonempty free-form false-positive indicators
are withheld until they can be deterministically supported; disagreement/uncertainty
still keeps base guidance without modifying triage.

Versions are permitted only within the deterministic advisory statement reconstructed
for that finding; changing a recorded candidate version or replaying that statement
against missing advisory data fails validation. An advisory-listed release is not
claimed universally safe, compatible or proven reachable. Existing advisory/parser
limitations remain; no dependency scanner was changed.

Both live processing and saved-review composition apply the policy. Rejected old
prose is not leaked back through the collapsed review details. The database is not
rewritten, and previously generated immutable report files remain unchanged.

## Context and code policy

- Repository context retains language, snippet, function, file, framework/database
  when recorded, source/sink/flow/protections and analyzer evidence. The legacy
  path now uses the retained context row's file path when snapshot metadata lacks
  it; evidence-v1 carries the available context fields and affected excerpt file.
  Missing values stay null. No whole-file or repository expansion occurs.
- Website context retains the existing allowlisted endpoint, method, response status,
  headers and TLS/cookie/CORS/probe observations. Raw bodies and credentials remain
  excluded. Backend source is unknown.
- Redaction happens before serialization, including statement choices and both
  review passes. The existing context, request size, time and candidate limits stay.
- Website header values have a deliberately small safe subset; duplicate headers,
  invalid/unsafe values, wildcard credentialed CORS, real cookie values, weak TLS
  directives and unrelated header fixes fail. A protocol example cannot repair a
  certificate-expiry finding. Unsupported but potentially valid configurations also
  fall back. Accepted examples still require adaptation and deployment testing.
- Source-specific proposals must match the original snippet and pinned file, parse,
  reproduce/remove the target occurrence and introduce no new findings through the
  existing validator. They must additionally match an existing statically checked
  deterministic replacement; arbitrary new APIs and merely illustrative library
  examples are not promoted. A terminal JavaScript/Java semicolon may differ, but
  unrelated source or replacement content cannot. No repository code is executed.
- Unknown database APIs force full deterministic fallback even if the surrounding
  prose is grounded. Missing full pinned source remains Not Available. Historical
  drafts may supply it; this phase does not add source capture/drafts/editing.
- Unvalidated repository illustrations from the model are rejected. The existing
  deterministic Example Secure Pattern remains available instead.
- Fix confidence is capped at Medium, or Low when the model/detection says Low;
  neither it nor two-pass agreement establishes factual correctness or fix safety.

## UI and storage

No template or stylesheet was changed. Existing finding explanation/Why it matters,
one Recommended Fix, Current/Recommended Code pair when established, otherwise
Example Secure Pattern, confidence and collapsed technical details remain. Accepted
prose flows into the existing action/reason/why fields; no second recommendation,
manual button, new route or additional persistent model was introduced. New reports
use the same composer, so rejected prose is absent there too. Model-generated notes
cannot inject arbitrary historical prose into collapsed details.

## Regression coverage and results

New `tests/test_ai_grounding.py` covers:

- D03 fabricated facts and unsafe agreement; D04 unsafe values and a good header.
- Bad/duplicate/unrelated headers, unsafe CSP/HSTS/referrer/cookie/CORS/TLS examples.
- Unknown framework/file/line/version, confirmed-exploitation and guaranteed-fix
  claims, security-weakening instructions, appended and Unicode-obfuscated advice.
- Prompt/evidence attempts to whitelist unsafe instructions.
- Advisory-supported release versus fabricated/current/missing releases.
- Arbitrary repository examples/APIs versus a matched statically checked DOM fix.
- Missing original, unknown SQL API, safe secret guidance and pre-request redaction.
- Missing/extra/malformed/contradictory response fields.
- Native mocked Ollama success, persistence, preserved finding rows, one UI result,
  report parity, subsequent failure fallback and retained historical AI data.
- Disabled AI, timeout, malformed JSON, rate limiting, available context and native
  schema constraints.

Existing AI tests use grounded fixtures instead of arbitrary free-form mock prose.
Tests for single recommendation, immutable findings, exact source validation,
redaction, failure recovery, escaping and no provider calls on GET remain. Historical
unsupported prose now expects suppression rather than display. No test was deleted,
no detector fixture/benchmark label changed and no static validator was weakened.

Verification uses the project's existing `.venv/bin/python` (Python 3.13.5).
The runner sets a temporary `SENTINELSCAN_DATA_DIR` before application imports,
disables AI by default and removes inherited GitHub credentials in its own process.
Individual tests enable mocked Ollama. The existing opt-in real Semgrep fixture uses
`SENTINELSCAN_TEST_SEMGREP=/opt/homebrew/bin/semgrep`. No tools were installed.

```sh
.venv/bin/python -B /tmp/phase12_run.py          # focused AI/validation suites
.venv/bin/python -B /tmp/phase12_run.py --full   # unittest discover('tests')
git diff --check
```

The complete runner source and final counts are retained in
[PHASE_12_TESTS.evidence.json](PHASE_12_TESTS.evidence.json); extract its `runner`
field to `/tmp/phase12_run.py` to reproduce. Full output:
[PHASE_12_TESTS.log](PHASE_12_TESTS.log).

| Run | Discovered/executed | Passed | Failed | Errors | Skipped | Time | Exit |
|---|---:|---:|---:|---:|---:|---:|---:|
| Focused | 80 | 80 | 0 | 0 | 0 | 6.208s | 0 |
| Complete existing suite plus Phase 12 tests | 266 | 266 | 0 | 0 | 0 | 20.095s | 0 |

16 new Phase 12 test methods; previous Phase 11 baseline was 250. The counts are
regression methods, not detection accuracy or a measured live-model success rate.
The complete run includes installed Semgrep, local HTTP/TLS fixtures, Flask restart,
SQLite persistence, AI failure cases and report consumers. `git diff --check` passed.
Mocked Ollama workflow: PASS for the tested contracts. Real Ollama quality: NOT TESTED.
Browser automation was not rerun; Flask/Jinja/HTML assertions verified the existing
presentation and no template/style files changed.

An intermediate full run found one stale hardcoded expectation for an old mock SQL
action in the UI test. Its fixture was migrated to a grounded statement; the test
still asserts exactly one visible action and no provider invocation during GET.
Earlier focused iterations found a semicolon-format mismatch in the supported-code
check and a safe disputed-review metadata suppression; both were corrected and
covered before the final run. The initial missing-new-test-module invocation was
an in-progress harness error, not a production failure.

## Limitations and remaining risks

- Mocked success verifies the application contract, not qwen2.5-coder:3b's actual
  response quality, latency or acceptance rate. No real Ollama call in this phase.
  Phase 11 live failures remain historical observations; no new success is invented.
- Conservative selection improves rejection reliability at the cost of creative
  advice. Many useful paraphrases, novel fixes, frameworks, configuration grammars
  and false-positive explanations deliberately fall back. This is not training or
  fine-tuning the model and does not expand detection coverage.
- Policy depends on deterministic catalogue/advisory quality and scanner context.
  A false scanner finding can still lead to an inappropriate deterministic action.
  Human review of source, intended behavior and deployment is required.
- Static checks do not prove runtime security, behavior preservation, compatibility
  or complete vulnerability removal. A missing finding is not proof of remediation.
- New scans generally lack a full retained pinned original for new AI source patches;
  safe fallback remains, while existing deterministic source solutions can still
  be shown. No new storage or source-fetch workflow was added.
- Existing first-failure stop, 20-candidate and between-review 60-second budget remain;
  not every finding receives AI. No retries or model downloads were added.
- Pattern-based redaction cannot guarantee recognition of every unlabeled secret.
  Local Ollama remains operator-trusted; unknown secret formats and local access
  controls are not solved by this phase.
- Other audit defects (detector accuracy, CodeQL packs, malformed stored JSON,
  conditional action-query replay and filesystem permissions) remain out of scope.

Phase 12 only. No further phase or unrelated fix started.
