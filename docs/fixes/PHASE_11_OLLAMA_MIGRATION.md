# Phase 11 — Ollama-only AI migration

Date: 2026-10-09. Implementation and verification complete. Successful live inference
is **NOT TESTED: the running local service has no installed models**. No software or
models installed/downloaded; no cloud provider requests, user-history reset, detector
changes, new route, UI button or database model.

## Architecture before and after

Previously, `integrations/llm.py` called the fixed cloud Chat Completions endpoint
with an environment API key/model. `OpenAIProvider` wrapped that transport for the
repository analyst/skeptic protocol; website/legacy reviews used its single-pass
function. Evidence preparation, redaction, static validation, fallback and final
composition were already shared.

Now Ollama is the only supported provider. The flow remains:

`scan → deterministic findings/evidence → base recommendation → optional local Ollama review → existing validation → one final recommendation`.

`integrations/llm.py` calls the native Ollama APIs. `OllamaProvider` supplies the same
analyst/skeptic prompts/schema. Website and legacy single-pass reviews use the same
local transport. No parallel pipeline or manual trigger exists. Trusted mock provider
hooks remain available for tests; they are not an environment-selectable provider.
AI cannot change scanner findings, severity, detection confidence, evidence, status
or risk. Shared validators still check the exact structured response and applicable
source/code constraints before saving an accepted review. Failed/unavailable reviews
retain deterministic recommendations.

Historical `ai_reviews`, deterministic snapshots, historical draft-source compatibility
and existing report bytes remain untouched. Model labels for new reviews use the
configured Ollama name. No schema migration or bulk history rewrite occurred.

## Configuration and startup

AI remains disabled by default; no default model is hardcoded.

```sh
# If the installed Ollama service is not already running:
ollama serve
# In another terminal, inspect existing models:
ollama list
```

Copy an exact installed model name, including its tag. The selected model must support
structured JSON output. Configure the Flask process environment:

```sh
export SENTINELSCAN_LLM_ENABLED=true
export SENTINELSCAN_OLLAMA_BASE_URL=http://127.0.0.1:11434
export SENTINELSCAN_OLLAMA_MODEL='EXACT_NAME_FROM_OLLAMA_LIST'
.venv/bin/python app.py
```

The model string above is a placeholder, not a recommendation or installed model.
If the list is empty, leave AI disabled until an operator chooses and approves a
model installation. This application never calls pull/install/create endpoints.
Restart Flask after configuring it and perform a new authorized scan; page GETs and
old records do not initiate inference. Use `SENTINELSCAN_LLM_ENABLED=false` to disable.
No provider API key is required. Old cloud provider/key/model environment settings
are no longer consumed. GitHub token configuration is unrelated and unchanged.

## Local transport and safeguards

- Native GET `/api/tags` confirms exact model availability before each inference.
  POST `/api/show` checks local metadata. Remote-host/remote-model metadata, names
  containing `cloud`, and missing/non-GGUF format are conservatively rejected.
- POST `/api/chat` supplies JSON schema in `format`, `stream=false`, `think=false`,
  temperature 0, maximum 3,000 predicted tokens and keep_alive=0. It requires a
  finished assistant response with `done_reason=stop`, no tool calls and JSON object
  content. Shared strict nested schema and code validation remain authoritative.
- Base URL is trusted server configuration only. It accepts HTTP literal loopback
  addresses or localhost mapped directly to 127.0.0.1. No remote host, credentials,
  URL path/query/fragment, scoped IP, proxy or redirect following. Only the three
  fixed API method/path pairs are permitted. Remote deployments are not supported.
- Separate loopback HTTP client avoids weakening existing public-service SSRF rules.
  GitHub/OSV continue to use the original HTTPS infrastructure; the cloud origin was
  removed from its allowlist. Shared safe network exception types are reused.
- Connection timeout: at most 3 seconds. Inventory/metadata response deadline: 5
  seconds each; chat response deadline: 20 seconds. A timer interrupts the socket
  across response reads, including slow trickles. These are per-request budgets;
  one review may include three requests and repository review two passes.
- Context JSON max 48,000 bytes; complete request max 65,536 bytes; each response max
  65,536 bytes. Oversize, malformed, HTTP-error, missing-model and timeout outcomes
  fail safely with fixed messages. No retries, automatic downloads, prompt logging
  or raw response/error body logging. No authorization header or provider credentials.
- Existing allowlisted evidence preparation/redaction occurs BEFORE serialization
  at this boundary, for both scans and both review passes. Local inference is not a
  reason to bypass redaction. Caller-provided known GitHub secrets remain masked.

Official API references checked during implementation:
[Chat API](https://docs.ollama.com/api/chat) and
[model inventory API](https://docs.ollama.com/api/tags).

## Files changed

Runtime:

- `config.py`: replaces provider/key/model settings with Ollama base URL/model.
- `integrations/ollama.py` (new): bounded loopback HTTP and endpoint restrictions.
- `integrations/llm.py`: native inventory/metadata/chat envelope and response handling;
  existing schema/prompts retained.
- `integrations/evidence_provider.py`: sole Ollama adapter, no cloud provider selector.
- `integrations/network.py`: obsolete cloud destination removed; GitHub/OSV unchanged.
- `analysis/llm_review.py`: configured-model readiness, saved model label and removal
  of obsolete provider-key handling; existing review orchestration unchanged.

Tests: adapted `test_llm_review.py`, `test_llm_sast_dast.py`,
`test_repository_phase4.py`, `test_final_validation.py` to native envelopes and model
availability; added `ollama_fixtures.py` and seven `test_ollama.py` methods. Existing
security, fallback, single-recommendation and immutable-finding assertions retained.

Documentation: README, AGENTS, overview/architecture/AI-workflow context, tracker and
this report. Three earlier provider documents explicitly marked historical and
superseded; past audit reports/evidence retained as historical facts.

No scanner, risk, recommendation composer, source validator, template, database,
requirements or launcher changes. No removed supported tests or weakened assertions.

## Verification results

All commands used the existing project venv in
`/Users/kribeshthapa/Developer/Vibe code/SentinalScan`.

| Check | Result |
|---|---|
| `command -v ollama` | `/usr/local/bin/ollama` |
| `ollama --version` | 0.40.1 |
| Native local GET /api/tags | HTTP200, `{"models":[]}` |
| Live synthetic missing-model request through migrated review | Rejected before /api/chat: Selected Ollama model is not installed |
| Successful real-model synthetic inference | NOT TESTED; no installed model, no download approved/performed |
| Adapted focused AI tests | 45 passed, 0 failed/errors/skips, 4.642s |
| New Ollama boundary tests | 7 passed, 0 failed/errors/skips, 0.523s |
| Complete existing suite plus new tests | **250 passed, 0 failed/errors/skips, 19.626s**, exit0; wall20.098s |
| Active runtime/test/README obsolete provider search | No cloud API/key/model/provider references remain |
| `git diff --check` | PASS |

Full-suite child command:

```sh
.venv/bin/python -B -m unittest discover -s tests -v
```

The audit runner set a temporary SENTINELSCAN_DATA_DIR before imports, disabled live
AI and runtime external engines by default, and set
SENTINELSCAN_TEST_SEMGREP=/opt/homebrew/bin/semgrep for the existing opt-in test.
Tests explicitly enable mock AI where needed; local fixture servers exercise transport.
No user database was opened by an app instance. Full test output is retained alongside
this report in `PHASE_11_OLLAMA_TESTS.log`.

Coverage includes enabled/disabled, inventory available/missing, service failures,
exact-model selection, remote alias/endpoint rejection, strict native completion,
malformed JSON, HTTP failures, timeouts, oversized data, local redirect non-following,
secret/prompt separation, persisted deterministic fallback, historical review retention,
one displayed recommendation and unchanged detection rows. Positive mocked inference
is separate from the real missing-model check; neither proves local model quality.

## Remaining limitations

Provider migration does not resolve audit findings about semantic hallucinations,
unsupported advice, DAST configuration semantics, receiver identity, CodeQL setup,
malformed stored JSON, or missing full originals for new AI source patches. Local
models can still produce incorrect or unsafe advice. Existing static validation and
human review remain necessary; no guaranteed fix or runtime security claim is made.

Some local models may not support the requested structured output or thinking option;
those errors fall back. Cold loading or slow inference can exceed the deliberately
bounded timeout. The existing 20-candidate/60-second-between-review policy remains,
so not every finding gets AI. A timed-out HTTP connection does not prove the daemon
has stopped all model computation. Loopback and metadata checks assume an operator-
trusted local Ollama service, not a sandbox against a malicious daemon or proxy.
Historical cloud reviews remain readable and are not regenerated automatically.

Phase 11 stopped after implementation, tests and documentation. No model chosen,
installed or downloaded; no next phase or unrelated audit fix started.

## Approved model setup follow-up — 2026-10-09

After explicit user approval, downloaded **only qwen2.5-coder:3b** with
`ollama pull qwen2.5-coder:3b` (exit0, checksum verification successful).
`ollama list`: model f72c60cabf62, 1.9GB, Q4_K_M / 3.1B. No other model
or application feature installed. This supersedes the earlier empty-inventory
observation; it does not change the historical migration test results above.

The existing `run-local.sh` now defaults the enabled flag to true, loopback URL
to http://127.0.0.1:11434 and model to qwen2.5-coder:3b. Explicit environment
overrides remain honored. Application config.py defaults remain disabled/model-empty
for direct app startup. Restart via `./run-local.sh` to use the configured model;
an already-running server was not restarted. No existing history was processed.

Validation: launcher shell syntax and instrumented environment inheritance passed;
`git diff --check` passed. No Python or detection code changed in this follow-up,
so the complete suite was not rerun (previous result:250 passes).

Live local tests used synthetic fixtures and temporary SQLite via existing refine_scan:

- Website: native API200 in16.18s, overall16.33s; review rejected, base retained.
- Repository evidence review: first native API200 in13.51s, overall13.54s; review
  rejected before second pass, base retained.
- Both cases: finding/scan rows unchanged, page200, exactly one recommendation.
- Diagnostic website request: one response timed out under the existing20s limit.
  Another returned valid JSON but supplied application assignment code instead of
  plain HTTP header configuration; existing validator correctly rejected it.
- Synthetic secret example: secret removed before request; response rejected by
  existing validation in10.76s. No real secret/source data used.

**Installation/configuration succeeded; useful accepted AI refinement was not
demonstrated in these examples.** The small model can violate the required output
contract despite native structured JSON. Validation was not weakened, prompts and
transport were not changed, and no alternative model was downloaded. Existing
deterministic fallback remains the working behavior when this happens. This is
not a model-accuracy benchmark or a promise of better recommendations.

Machine: Apple M2/8GiB RAM. Available disk was about3.4GiB after testing (varies
with swap). Tests used only the approved local model; no cloud calls. Follow-up
stopped within download/configuration/synthetic-test scope.
