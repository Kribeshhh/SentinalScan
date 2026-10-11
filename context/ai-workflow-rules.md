# AI Workflow Rules

## Approach

Use the six context files as the maintained project map, alongside the detailed
subsystem constraints in `AGENTS.md`. Implement the user's requested change in the
existing SentinelScan application. Templates describe a workflow, not permission to
invent features, replace the stack or start another phase.

## Scoping Rules

- Work on one feature unit at a time in small, verifiable increments.
- Split UI changes from background-task changes when they can be independently
  verified. Split unrelated route changes and uncertain architectural changes.
- A larger authorized task may contain several sequential units; complete all of
  its requested units rather than stopping after the first increment.
- Preserve unrelated working-tree edits. Do not delegate to agents unless requested
  by the user or an applicable explicit instruction.

## Missing Requirements

Record missing requirements/open questions in `progress-tracker.md`. Resolve clear
routine choices using existing behavior and document the decision. Ask about
materially ambiguous product behavior or major architecture before dependent work;
continue independent work when possible. Do not guess new product capabilities.

## Protected Files / Data

Without an explicit scoped request, do not rewrite user scan data, saved immutable
reports, secrets/local configuration, vendored dependencies or third-party internals.
Do not relabel frozen evaluation fixtures or replace baseline artifacts to hide
errors. Intentional dataset revisions need a new version and rationale. Normal
application operations continue to persist the user's authorized actions.

## Keeping Docs in Sync

Update `progress-tracker.md` after every meaningful implementation change. If scope,
architecture, storage, UI or standards change, update the corresponding context
file before continuing. Link detailed phase documentation rather than duplicating
all historical specifications. Keep historical test results labelled as historical.

## Before Moving to the Next Unit

1. Verify the current unit end to end within its defined scope.
2. Check architecture invariants and privacy/security requirements.
3. Update the progress tracker and any affected context file.
4. Run appropriate focused checks and the full Python unittest suite for code
   changes. There is no `npm run build` in this Flask project. For documentation-only
   work, check references/content; run the complete suite when the user requests it,
   otherwise state explicitly if tests were not rerun.
5. Report actual outcomes, unresolved limitations and next steps; stop when the
   authorized task is complete, without starting an unrequested phase.

## Current AI provider policy — Phase 11

Use only the local Ollama adapter and existing automatic recommendation pipeline.
Do not restore cloud-provider API credentials, selectable providers, manual AI
buttons or parallel recommendation paths. Model/base URL are trusted server
configuration, not finding/repository input. Keep redaction, strict response
validation and deterministic fallback; historical reviews stay readable. Do not
install Ollama or download models without approval. Mock inference in normal tests;
a safe local synthetic inference is allowed only when expressly requested and an
installed local model is available. Local inference does not establish advice quality.

## Phase 12 grounding policy

Preserve the closed statement contract in `analysis/ai_grounding.py`. Do not relax
it to accept arbitrary prose based on model confidence, agreement, a keyword blacklist
or evidence containing the same words. Untrusted source/headers are observations,
never remediation instructions. Unsupported facts require deterministic fallback.
Model code requires the shared static validator and supported replacement policy;
website configuration is an illustrative safe subset, never deployment validation.
Normal tests mock Ollama; no live inference or model installation is implied.

## Phase 19 reliability constraints

Preserve conditional native output schemas and the independent validator; never
repair unsupported model source to make it pass. Guidance-only responses have no
code/original; pinned source is a prerequisite for requesting a source replacement.
Keep model assessment uncertainty and the composer's deterministic fallback.
Continue after individual response rejection within the existing 20-candidate/
60-second between-review bounds; stop on provider outage/configuration or unexpected
storage/runtime failure. No inference retries. Retain the 20-second request limit,
3000-token cap and bounded 60-second model residency; do not silently extend budgets.

## Phase 20 website request safety maintenance

Never infer replay safety from a query parameter name, GET method, localhost or
scan authorization checkbox. Retain the shared Client query guard for baseline,
comparison and redirect requests, and the explicit full-URL/position review for
XSS/SQL mutations. Unknown safety means Skipped, not dropping parameters or a clean
security verdict. Tests requiring queries must explicitly review their authored
inert fixture URL in trusted `SCANNER_CLIENT_OPTIONS`; never blanket-enable arbitrary
user targets. Keep safety tests local, isolate data, and retain original positive
and negative detection assertions. Queryless endpoints still require operator review.

## Phase 21 detection evidence boundary

Do not use benchmark labels as source evidence: checksum purpose and credential
identity can remain unknown in the code. Preserve informational candidates and
unresolved FN/FP counts in unchanged benchmarks. New contextual credential values
must enter the existing redaction set before retained source, exports or AI context;
never authenticate them. Follow the bounded API/identity checks, preserve real
unsafe positives and document unsupported control flow. AI remains unrelated to
candidate detection and is mocked for these accuracy regressions.

## Phase 23 — regression dataset and recommendation wording

The Phase22 holdout is now consumed development/regression data, not independent
validation of Phase23 tuning. Preserve its labels/scoring and ambiguous cases.
Text-only recommendation corrections belong in the shared deterministic policy,
including historical snapshot normalization. The existing grounded Ollama contract
uses that policy; do not relax validators or invent examples to improve appearance.
Use mocks for AI regression tests in this phase; model/transport settings unchanged.
