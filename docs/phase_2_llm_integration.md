> Historical provider implementation/configuration: superseded on 2026-10-09 by
> [Phase 11 Ollama migration](fixes/PHASE_11_OLLAMA_MIGRATION.md). Cloud credentials,
> endpoints and alternative adapters below are archival, not current setup instructions.
> Shared evidence, validation and recommendation contracts remain applicable.

# Phase 2: optional LLM assistance for SAST and DAST

> Current activation/UI policy: the 2026-10-04 final simplification supersedes
> the manual Improve with AI workflow described in this historical phase record.
> Manual activation/consent instructions and old route references below are archival,
> not current setup requirements. Enabled/configured AI now refines persisted findings
> through the bounded new-scan completion hook; page/report GETs never call providers.
> See [current behavior and audit](phase_3_unified_recommendation.md#final-simplification-2026-10-04).

## Roles and user control

Deterministic SAST and DAST detect findings. The existing optional LLM reviews one
stored finding and improves its explanation/recommendation only after the user
checks the context-sharing box and selects **Improve with AI** inside Recommendation.
Opening a finding or running either scanner never calls AI. AI cannot change a
finding's status, severity, evidence, fingerprint or risk; it cannot write code,
publish GitHub changes, resolve findings or merge PRs.

The previous provider transport, configuration, POST route, CSRF protection,
per-process review lock, SQLite `ai_reviews`, static validation and diff workflow
are reused. No database migration or new dependency is required. Phase 1 context
and deterministic recommendations are preserved. Saved older AI reviews still
render through their original display fields.

## Configuration

Use the existing server environment variables and restart Flask:

```ini
SENTINELSCAN_LLM_ENABLED=false
SENTINELSCAN_LLM_MODEL=<your structured-output-capable model>
SENTINELSCAN_LLM_API_KEY=<your provider API key>
```

Set ENABLED to true to offer new AI requests. No model is selected automatically.
Keep the real key in the server environment/secret manager, never in a repository,
browser form or chat. A GitHub PAT is not an LLM key. Missing/invalid credentials,
missing model, timeout, rate limiting, refusal, invalid JSON, malformed schema and
provider failures show a generic message and preserve deterministic guidance and
any previous saved review. AI is not a scan-worker dependency.

## Context and privacy

`llm_routes.py` reads the existing normalized solution snapshot and passes it to
`analysis.llm_review.prepare`. Only explicitly selected fields are included:

- Both: source type, category/title, severity, detection confidence, scanner
  evidence and base recommendation.
- Repository: supported language, relative file, function, known framework/database,
  recorded source/sink/flow/protection, one redacted retained source excerpt and up
  to two existing suggested examples. Unknown facts stay null. The full original
  draft is used locally only, never included in the request.
- Website: redacted affected URL, recorded method/status, allowlisted response
  headers, cookie names/attribute flags, selected TLS/CORS observations, reflected
  parameter/context or database-error signature names. Phase 1 intentionally omits
  response bodies; the response snippet remains null. No HTML pages are sent.

Existing masking utilities run before provider request construction and before
length truncation. Known GitHub/provider credentials, detected secret patterns,
private keys, credential assignments, authentication/cookie header lines and URL
query values are redacted. URLs lose userinfo and fragments. Authorization and
Set-Cookie headers and cookie value fields are excluded from website payloads.
Secret findings use fixed evidence and a synthetic `password = "[REDACTED]"` only,
never the original secret evidence or suggested code.

Source excerpts over 21 lines or 7,000 characters are omitted, not truncated into
misleading replacement spans. Evidence is capped at 3,000 characters, base guidance
at 2,000, metadata at 1,000, headers at 700, observation values at 300 and flow at 12
bounded entries. Only selected fields are sent, not arbitrary snapshot JSON.

## Prompt injection and response structure

The system instruction declares repository/website content untrusted, prohibits
following its instructions, revealing credentials or reconstructing redacted
values, and limits analysis to the supplied finding. Scanned text is user-message
data, never system instructions. No tools, browsing or remote writes are provided.
Prompt injection can still affect advisory prose; these boundaries do not prove
model correctness.

The provider uses strict JSON Schema, followed by independent local checks of exact
keys, nested types, enums, sizes, control characters and code/type consistency:

```json
{
  "assessment": "needs_review",
  "reason": "The recorded evidence needs application-context review.",
  "recommendation": {
    "what_to_change": "Review the affected security control.",
    "suggested_code_or_config": "",
    "example_type": "none",
    "why": "The implementation was not established.",
    "additional_actions": ["Test intended behavior and re-scan."]
  },
  "original_code": "",
  "fix_confidence": "low"
}
```

Assessments: likely_valid / needs_review / likely_false_positive. Example types:
source_specific / illustrative / configuration / none. Fix confidence:
high / medium / low. This is a model claim, separate from detection confidence and
local validation. Unexpected fields such as status/severity changes are rejected.

The existing fixed OpenAI Chat Completions endpoint, TLS checks, response bound,
no-redirect/no-POST-retry policy, store=false and completion budget remain.
Schema reference: [OpenAI Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs).

## Source-aware behavior and validation

For a repository source-specific suggestion, original_code must match the supplied
excerpt exactly. If a pinned full source draft exists locally, the same existing
static candidate validator parses the edit, checks the target rule and checks for
new findings. Otherwise validation is Not Available, not an invented pass. SQL
source-specific code is withheld unless Phase 1 established a supported database
API (sqlite3, psycopg or psycopg2). Illustrations are not validated source patches.

Example exercised by the existing tests: `node.innerHTML=input;` can receive a
suggested `node.textContent=input;` replacement against the supplied function. This
is appropriate only when plain-text rendering is intended; application behavior
and user intent still need human review.

Website fixes cannot be source_specific. SQL/XSS indicators receive guidance, not
fabricated database calls or backend handlers. Configuration code is restricted to
plain HTTP header lines for security headers/cookies/CORS, or a small set of
illustrative nginx TLS directives. Cookie values must be placeholders. For example,
a missing MIME-sniffing protection header can receive:

```http
X-Content-Type-Options: nosniff
```

This is labelled Configuration, with Static Validation: Not Available. Grammar
acceptance is not a deployment/security validation. Unsupported examples reject the
review and retain deterministic guidance. Arbitrary provider/framework config
formats are deliberately outside this phase's supported examples.

## UI, persistence and limitations

The Recommendation section displays scanner guidance first, then AI assessment,
explanation, **AI-Assisted Suggested Fix**, example type, rationale/actions, model
fix confidence and static validation. Text/code/diffs are escaped; no model HTML or
Markdown is trusted. Website findings do not display source-editor instructions.
AI reviews are separate from deterministic report data. Nothing is auto-applied.

Redaction cannot recognize every unusual unlabeled sensitive value. Share context
only when external processing is appropriate. Historical findings may lack context;
re-scan to capture it. Framework inference, runtime tests, semantic equivalence and
model accuracy are not established by these checks. Live provider credentials,
account/model compatibility, latency and generated answer quality require operator
verification; tests use mocks and local labs only.

## Files and verification

Modified: `analysis/llm_review.py`, `integrations/llm.py`, `llm_routes.py`,
`templates/_ai_review.html`, `tests/test_llm_review.py`, `README.md`, `AGENTS.md`.
Added: `tests/test_llm_sast_dast.py`, `docs/phase_2_llm_integration.md`.
`config.py`, scan workers and the database schema require no Phase 2 changes.

Run `python3 -m unittest discover -s tests -q` for the complete suite and
`python3 -m unittest discover -s tests -p 'test_llm*.py' -v` for AI tests.
Tests cover disabled/enabled behavior, CSRF/consent, unchanged findings/risk, SAST
and DAST pipeline isolation, source validation, website configuration, backend
rejection, unknown database fallback, nested schema rejection, redaction before
request construction, prompt injection placement, invalid keys/rate limits/server
errors/timeouts, and preservation of previous reviews.

Stop after Phase 2. Do not start Phase 3 automatically.

Completed verification using `/tmp/sentinelscan-verify-venv/bin/python`:
**154 project tests passed, 0 failed**; **23 AI tests passed, 0 failed**.
`git diff --check` passed. Provider calls were mocked; website integration used the
local fixture server. No real LLM request, user-database migration, external scan,
GitHub publication or website modification was performed.
