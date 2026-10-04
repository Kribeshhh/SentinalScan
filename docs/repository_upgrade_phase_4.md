# Repository scanner upgrade — Phase 4: LLM evidence review

> Current activation/UI policy: the 2026-10-04 final simplification supersedes
> the manual Improve with AI workflow described in this historical phase record.
> Manual activation/consent instructions and old route references below are archival,
> not current setup requirements. Enabled/configured AI now refines persisted findings
> through the bounded new-scan completion hook; page/report GETs never call providers.
> See [current behavior and audit](phase_3_unified_recommendation.md#final-simplification-2026-10-04).

## Detection and authority

The pipeline remains **static analysis → candidate → Phase 3 evidence/context →
optional analyst → optional skeptical reviewer → static code validation → one
Recommendation → human review**. Neither scan worker calls AI. Opening a finding
never calls AI. The user must enable AI and explicitly submit Improve with AI with
CSRF protection and context-sharing consent for an existing finding.

The model does not scan the repository, delete findings, change severity/detection
confidence/risk/status, resolve issues, edit files, publish commits or merge PRs.
Deterministic evidence and AI reviews remain separately stored. Existing editor,
diff, explicit publication and human review requirements remain in force.

## Configuration and provider boundary

Existing environment configuration is reused:

```ini
SENTINELSCAN_LLM_ENABLED=false
SENTINELSCAN_LLM_PROVIDER=openai
SENTINELSCAN_LLM_MODEL=<your configured structured-output-capable model>
SENTINELSCAN_LLM_API_KEY=<provided through your server secret environment>
```

Enable explicitly and restart the application to use changed server configuration.
Do not commit keys or paste them into source, logs, chat or test fixtures. No default
model or new dependency is introduced. The shipped adapter uses the existing fixed
OpenAI HTTPS transport. Unknown provider names fail safely; this is not a claim that
other vendor endpoints have already been implemented.

`integrations/evidence_provider.py` defines the small `LLMProvider.review_finding`
interface and `OpenAIProvider` adapter. An alternative trusted server adapter can be
injected as `LLM_EVIDENCE_PROVIDER` with the same method; scanner/correlation logic
has no provider dependency. Repository content cannot select adapters/endpoints.
The existing single-pass `LLM_REVIEW_PROVIDER` hook remains for legacy/DAST review.

No redirects, tools, repository execution, automatic retries or network credential
validation are added. Each provider call retains the 64 KiB response limit,
3,000-completion-token cap and 20-second HTTP response budget, plus the existing
independent DNS/connection/TLS bounds. Two sequential passes can cost more and take
longer than one; the existing per-process review lock covers both calls.

## Evidence-only request construction

For a Phase 3 repository finding, `analysis/evidence_review.prepare_evidence` uses
an explicit allowlist of its saved evidence package: source/sink/flow, protections,
function/framework when known, related function/file labels, up to three analyzer
provenance records and four source excerpts. It adds bounded finding metadata,
deterministic guidance and an established database label if already recorded.
It never sends the full repository, editor draft or arbitrary snapshot fields.

Limits: at most 3,600 excerpt characters, 1,800 per excerpt, 10 bounded entries per
flow/protection list, three provenance records, 2,000 characters of base guidance,
and 16,000 characters of redacted serialized input. Oversized excerpts are omitted.
The separate replacement snippet duplicates only the affected excerpt, at most
21 lines; the total request bound includes this duplication. Numbered related
excerpts cannot be selected as replacement spans. Locally pinned full source is
used only by static validation, never sent externally.

Redaction happens on individual values before JSON request construction or clipping:
known server/GitHub credentials, existing detected-secret masking, token/private-key
patterns, credential assignments, Authorization/cookie values and URL credentials
are removed. Secret findings use fixed evidence and `password = "[REDACTED]"` only.
Pass 1 output is independently validated and redacted before constructing pass 2.
Only its assessment, reason, support flag and false-positive indicators are forwarded;
its code and recommendation are not forwarded. This adds at most roughly 7 KiB of
bounded assessment text to pass 2. No prompts or raw provider bodies are persisted.

Redaction cannot guarantee recognition of every unknown, unlabeled sensitive value.
The user must decide whether external processing of even redacted proprietary
context is appropriate. Both trusted system prompts explicitly classify repository
content and prior model assessments as untrusted data, prohibit embedded instructions,
credential disclosure and reconstruction of `[REDACTED]`, and provide no tools.
These boundaries reduce exposure; they do not prove immunity to prompt injection.

## Two-pass decisions

1. **Security analyst:** assess source/sink, supplied flow, protections, impact and
   context-appropriate remediation. Missing evidence must remain unknown.
2. **Skeptical reviewer:** independently try to disprove the candidate using
   sanitization, validation, parameterization, escaping, framework protections,
   safe APIs, unreachable/test/demo code and incomplete or incorrect flow assumptions.

Both passes require the existing strict recommendation JSON plus a boolean
`evidence_supported` and at most eight `false_positive_indicators`. Exact keys,
field types/lengths, enums and recommendation/code consistency are checked locally,
independent of the provider's JSON Schema enforcement. Contradictory likely-valid
without support, or likely-false-positive with support, is rejected.

Assessment disagreement or differing support flags becomes **Needs Review**.
Missing source context prevents a final likely-valid claim even when both models
agree. Needs Review and Likely False Positive retain deterministic guidance and
withhold AI code; they do not triage or erase the finding. Agreement is advisory.
For an agreed supported assessment, the skeptical pass supplies the final proposed
remediation. Fix confidence is capped by the weaker model pass and recorded
scanner detection confidence; engine counts never increase it. This conservative
cap is a presentation policy, not a calibrated probability. Severity is unchanged.

Failure of either pass, invalid JSON, missing key/model, timeout, refusal or rate
limit falls back to deterministic guidance. No partial analyst result is promoted.
A prior review stays stored but is not used after a failed refresh until a later
successful review. Scanning remains fully functional with AI disabled/unavailable.

## Unified remediation and validation

One existing Recommendation is composed for findings, the editor and new reports.
An AI-assisted indicator appears only when eligible AI content improves that final
recommendation. A compact collapsed AI evidence review inside Recommendation shows
both assessments, reasons, false-positive indicators and any disagreement. It does
not contain a second competing recommendation or another code solution.

Code must use the exact eligible snippet. Source-specific suggestions pass through
the existing `analysis.llm_review.process` and `validate_candidate` path: match the
pinned local source, parse, reproduce/remove the relevant deterministic finding,
check new findings, then produce a diff. Without pinned source or supported rules,
validation is Not Available. Failed or unvalidated AI source code cannot replace
validated deterministic output. SQL patches still require a recorded supported
actual database API; imports alone do not justify placeholder syntax. Static checks
do not execute tests or prove runtime behavior, API semantics or a guaranteed fix.

HTML uses escaped text, not model HTML/Markdown. JSON/CSV carry bounded review
summaries through the existing composed solution; raw envelopes/prompts remain out.
False Positive manual triage still preserves the existing no-fix policy.

## Compatibility and documented fallback

New repository snapshots with Phase 3 evidence receive two-pass review. Historical
repository snapshots without that package retain the prior bounded, single-pass
review; re-scan to capture the richer evidence. Website DAST also retains the existing
single-pass interface, source restrictions and configuration-only examples. Neither
fallback sends entire files or invents backend source. No DAST scanner is rebuilt.
This phase adds no database migration and does not rewrite scan history or old reports.

## Verification

Run with project requirements installed:

```sh
python3 -m unittest discover -s tests -p test_repository_phase4.py -v
python3 -m unittest discover -s tests -v
# Optional installed real Semgrep fixture:
SENTINELSCAN_TEST_SEMGREP=/absolute/path/to/semgrep python3 -m unittest discover -s tests -v
```

The new suite covers agreement, disagreement, needs-review/likely-false-positive,
confidence capping, disabled mode, malformed responses, timeouts, redaction,
prompt-injection placement, missing context, actual source replacements and invalid
code, single Recommendation, reports, immutable detection and failed-refresh fallback.
Existing suites cover missing keys, malformed transport JSON, rate limits, DAST
backend restrictions, optional AI pipeline isolation and regression behavior.
All provider responses are controlled fixtures; no paid/live LLM request is made.
Real model quality, account access, billing and adversarial robustness are unverified.

Final verification on 2026-10-03: **214 tests passed, 0 failed, 0 skipped** in
16.785 seconds using the isolated Python 3.14 verification environment. This includes
all **9 new Phase 4 tests**, existing mocked AI/DAST/SAST tests, and the live
Semgrep 1.179.0 fixture. `git diff --check` passed. Two initial route-fixture setup
errors (a missing test solution snapshot) were corrected before the passing runs.
No user scan database, live server, external target, paid LLM account or GitHub
repository was changed by testing. CodeQL and OSV remain fixture-tested here.

## Files

Added `analysis/evidence_review.py`, `integrations/evidence_provider.py`,
`templates/_evidence_review.html`, `tests/test_repository_phase4.py` and this document.
Updated provider transport, route/configuration, recommendation composer, finding/
report/consent templates, README and AGENTS. Stop after Phase 4.
