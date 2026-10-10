> Historical provider implementation/configuration: superseded on 2026-10-09 by
> [Phase 11 Ollama migration](fixes/PHASE_11_OLLAMA_MIGRATION.md). Cloud credentials,
> endpoints and alternative adapters below are archival, not current setup instructions.
> Shared evidence, validation and recommendation contracts remain applicable.

# Phase 4: optional LLM review and validation

> Current activation/UI policy: the 2026-10-04 final simplification supersedes
> the manual Improve with AI workflow described in this historical phase record.
> Manual activation/consent instructions and old route references below are archival,
> not current setup requirements. Enabled/configured AI now refines persisted findings
> through the bounded new-scan completion hook; page/report GETs never call providers.
> See [current behavior and audit](phase_3_unified_recommendation.md#final-simplification-2026-10-04).

## What detects findings

The existing deterministic SAST modules remain the only candidate detectors.
Repository scans never call the LLM, whether AI is enabled or disabled. AI is an
optional, explicit review of one already stored repository finding, inside its
Recommendation section. It cannot delete, suppress, resolve or alter that finding,
its severity, fingerprint, scanner evidence or detection confidence.

The flow is: deterministic finding → bounded redacted context → explicit AI review
→ structured response validation → optional local source validation → displayed
explanation/code/diff → human review in the existing editor/draft/PR workflow.
Nothing is automatically applied, published or merged.

## Enable and use

AI defaults to disabled. Set environment variables in the Flask server process:

```ini
SENTINELSCAN_LLM_ENABLED=true
SENTINELSCAN_LLM_MODEL=<a model in your account supporting Chat Completions JSON Schema>
SENTINELSCAN_LLM_API_KEY=<your provider API key>
```

The angle-bracket values are placeholders. Provide the real API key through your
server environment/secret manager, not a committed file, browser form, GitHub PAT,
chat or shell command that records it in history. No dotenv loading is added.
Restart Flask after changing configuration. Set `SENTINELSCAN_LLM_ENABLED=false`
to disable new AI requests. Previously saved reviews remain visible and labelled.

Open a repository finding, expand/read Recommendation, select the explicit
context-sharing checkbox and choose **Request AI review**. The fixed provider is
OpenAI at `https://api.openai.com/v1/chat/completions`. No model is chosen implicitly;
missing key/model fails gracefully. Model/account compatibility and provider usage
charges remain the operator's responsibility.

To validate a code suggestion against a full file, first load the pinned scanned
file in the existing source editor, then request review. Only its small excerpt
is sent externally; the saved original is used locally for validation. Without a
saved full source, guidance/code can still appear with **Not Available** validation
and a clearly identified excerpt-only diff. Secret-bearing files retain the
existing editor prohibition and receive guidance only.

## Request boundary and redaction

`analysis/llm_review.py` explicitly whitelists category, title, language, recorded
evidence and one `finding_context` excerpt. It sends no repo archive, unrelated
file, GitHub credential, session cookie, filesystem path, application configuration
or complete draft. Excerpts exceeding 21 lines or 7,000 characters are omitted;
evidence is capped at 3,000 characters and title/category are bounded.

Redaction occurs before request JSON construction and before length truncation.
Existing source masking, typed-token/private-key patterns, credential assignments,
URL/HTTP authentication redaction and exact removal of known server API/GitHub
credentials apply. Secret findings use only a synthetic `password = "[REDACTED]"`
example and fixed evidence, never their original literal or arbitrary evidence.
The API key is used only as the provider authorization header, never prompt data.

Redaction is defense in depth, not a proof that every unknown secret format can be
recognized. Review retained context before sharing confidential source. Already
detected source secrets are masked at scan persistence; newly discovered or
unusual sensitive material should be handled manually with AI disabled.

The system instruction treats source/evidence as untrusted data and prohibits
following embedded instructions, fetching files/URLs, reconstructing secrets or
calling tools. No tools are provided. Prompt injection remains a limitation of
AI interpretation; output still requires validation and human review.

## Structured output and transport

`integrations/llm.py` uses strict JSON Schema with assessment, reason, remediation,
original_code, suggested_code and fix_confidence. Assessment is one of
`likely_valid`, `needs_review`, `likely_false_positive`. Confidence is high/medium/low.
Local validation independently enforces exact keys, types, enums, field lengths,
nonempty explanations and paired code fields. Refusal, incomplete output, non-JSON,
extra fields and oversized responses are rejected.

Transport reuses fixed-origin HTTPS with verified TLS, public DNS validation,
connection/read budgets, no redirect following, no POST retries and a 64 KiB
response limit. Provider request budget is 20 seconds for the HTTP response phase;
DNS/TCP/TLS have their existing independent bounds. Completion output is capped at
3,000 tokens; `store` is false. Provider data-handling policies still apply.

API schema implementation reference:
[OpenAI Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs).

## Static validation and display

The model must return the exact supplied excerpt as original_code. Replacement
mismatch, redacted placeholders or untrusted credential-like generated content
prevent validated patch presentation. Suggestions never choose filesystem paths.

When full pinned source is locally available and matches the excerpt, the replacement
is spliced only into that range and passed through the same
`analysis/source_validation.validate_candidate` function as deterministic source
suggestions. It parses original/edited source, reproduces the target rule, checks
that the target statement changed and its detection disappeared, and checks new
findings in the relevant language module and secret detector. Removing a different
occurrence cannot validate the original. Multiline statements are accounted for.

The UI displays **AI-Assisted Suggested Fix**, AI confidence and Static Validation:
Passed / Failed / Not Available. Passed means local static checks passed, never
“Vulnerability fixed.” AI confidence is a model claim, not scanner confidence or
validation status. Bad code stays visibly unvalidated and is never applied.

Model text/code/diffs use Jinja escaping, not rendered Markdown or trusted HTML.
The scanner recommendation remains above the optional review. All editor saves,
diff review, explicit publication approval, PR creation and no-auto-merge behavior
remain unchanged. Stored review code cannot directly enter the publishing route.

## Persistence and failure behavior

`ai_reviews` is an additive SQLite table keyed by finding ID, with reviewed JSON
and a timestamp; it stores no API key/request body. One review per finding is
retained. Failures preserve the previous review and show a fixed, sanitized message.
No exception payload, provider error body, request content or credentials are logged.
One review at a time per Flask process is allowed; no background scan dependency
or new frontend/build dependency is introduced. Reports remain deterministic;
AI reviews are currently shown only in finding/editor Recommendation.

## Testing and limitations

Run `python3 -m unittest discover -s tests -q`.
The AI tests mock the provider/HTTP boundary. They cover enabled review, disabled
requests, complete repository pipelines with AI both enabled and disabled, provider
outage, timeout, missing API key, refusal, invalid/oversized structure, redaction
before the request, secret-only synthetic context, HTML escaping, unchanged finding
status, code/source mismatch, invalid syntax/new findings and wrong-occurrence fixes.
The full existing DAST, SAST, reporting and remediation suite also runs.

Verification result: **136 tests passed, 0 failed**, including **12 AI-focused
test methods**. `git diff --check` also passed.

No live paid model request is used for testing. Provider account access, model
quality and real-world latency are unverified. Seven-line retained excerpts may
omit important framework/data-flow context. Validation requires a matching full
source draft and supports the existing Python/JavaScript/Java rule modules; it does
not execute application tests, prove semantic equivalence or assess all security
properties. No AI-generated fix is guaranteed correct.

Phase 4 stops here.
