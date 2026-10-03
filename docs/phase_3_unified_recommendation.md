# Phase 3: unified Recommendation for SAST and DAST

Scanner guidance and AI review remain separate internally. One composition layer
now produces the user-facing Recommendation on finding details, in the existing
source editor, and in newly generated HTML/JSON/CSV reports. No scanner, provider
API, detection rule, fingerprint, status or risk-scoring behavior is replaced.

## Composition

`analysis/recommendation_composer.py` supplies `compose` and `final_solution`.
`finding_solution` remains the deterministic source used when preparing AI requests;
AI output is never fed back as the next request's base recommendation.

The final structure includes `what_to_change`, `suggested_code_or_config`,
`example_type`, `why`, `additional_actions`, `fix_confidence`, `validation_status`
and `ai_assisted`. Existing aliases remain for compatibility with solution consumers.
The composer copies its inputs; it does not rewrite scanner findings or AI reviews.

Selection rules:

- AI disabled: use deterministic guidance, even if a saved review exists. No empty
  AI panel, AI requirement, or disabled-AI warning appears.
- Enabled but no valid review: use deterministic guidance.
- Valid guidance-only enhancement: improve the action/rationale while retaining
  useful deterministic code and essential application/security actions.
- Eligible AI example: replace the base examples with one selected example, never
  append a second copy of substantially identical code. Equal snippets differing
  only in trailing whitespace are deduplicated. Different deterministic alternatives
  may remain when they have meaningfully different behavior.
- Failed/malformed AI result, failed static checks, or unvalidated source-specific
  AI code: retain the deterministic recommendation. No fabricated validation pass.
- Explicitly triaged False Positive: preserve the deterministic no-fix policy.

A failed refresh records a small `_ai_review_failed` presentation flag in the
existing solution snapshot. The previous AI record is retained internally, but
pages/editor/reports use deterministic output until another review succeeds.
This requires no migration. The flag is stripped from composed report output.
Reports already generated remain immutable snapshots.

## One UI

The existing Recommendation section now contains one What to change, Current Code
when available, chosen Suggested Code Solution / Illustrative Secure Example /
Configuration Example / Suggested Solution, rationale, additional actions, Fix
Confidence, and validation. The small **AI-assisted recommendation** indicator
appears only when eligible AI content contributed.

No separate Scanner Guidance, AI Explanation or AI-Assisted Suggested Fix panel is
rendered. The optional consent form is collapsed under Improve with AI. The old
`#code-solution` and `#ai-review` navigation anchors remain where applicable. The
source editor no longer repeats the original scanner recommendation above the
composed section. Review/Edit continues through the existing manual workflow.

Detection Confidence remains beside the finding severity/status metadata.
Fix Confidence belongs to remediation. Model confidence is advisory and cannot
upgrade static validation or prove runtime correctness. The existing redaction and
Jinja escaping protect context, code and prose; raw model HTML is not rendered.

## Repository and website behavior

Source-specific repository AI code is selected only after the existing static
validator passed it against matched local source. The exact supplied excerpt is
shown as Current Code. These checks do not test runtime behavior or semantic
compatibility. Unsupported or unvalidated candidates leave deterministic guidance
or validated deterministic code intact. Illustrative examples are labelled as such.

Secret findings preserve redacted source and mandatory rotation/revocation, history
review and runtime storage guidance. AI cannot introduce a code recipe into a secret
finding. A YAML credential does not become a fabricated Python implementation.

Website output cannot be a Suggested Source Fix. Only supported configuration
examples are eligible; backend source remains unknown. Website SQL-error findings
receive guidance and an explicit backend-source-unavailable message. Validation is
**Requires implementation and re-scan**, not Passed. Header/cookie/CORS/TLS examples
remain advisory, with the Phase 2 configuration grammar restrictions.

## Reports

`report_data` reads the same composer as the UI. The exported finding recommendation
text is the chosen final action, and `solution` contains the composed final data,
including `ai_assisted` and Recommendation Source. HTML shows one recommendation;
CSV's recommendation column agrees with its structured solution JSON. No raw AI
review envelope, prompts, original_code provider field or provider response is
exported. Existing solution field aliases are retained for machine compatibility.
No finding record is overwritten with the exported text. Newly generated reports
respect the current AI-enabled setting and failed-refresh state.

## Five rendered examples

Open [the read-only rendered preview](phase_3_recommendation_examples.html).
It was generated from actual Jinja finding-page output using temporary SQLite test
fixtures, not user scan results. AI responses were mocked; controls are inactive.

1. Repository, AI OFF: matched SQLite call with deterministic bound-value solution.
2. Repository, AI ON: one selected SQLite solution with improved context-specific
   wording and the AI-assisted indicator; no duplicate deterministic code example.
3. Website, AI OFF: deterministic `X-Content-Type-Options: nosniff` configuration.
4. Website, AI ON: one configuration example with enhanced rationale/actions and
   the AI-assisted indicator; no invented backend code.
5. AI failure after a prior enhancement: one deterministic website recommendation;
   the old review remains stored internally and the indicator is absent.

The preview does not claim that a real provider generated these suggestions.

## Files changed in this phase

Added:
- `analysis/recommendation_composer.py`
- `tests/test_unified_recommendation.py`
- `docs/phase_3_unified_recommendation.md`
- `docs/phase_3_recommendation_examples.html`

Modified:
- `app.py`, `remediation_routes.py`, `llm_routes.py`
- `reports/report_generator.py`
- `templates/_solution.html`, `templates/_ai_review.html`,
  `templates/finding_editor.html`, `templates/report_document.html`
- `tests/test_llm_review.py`, `tests/test_solutions.py`
- `README.md`, `AGENTS.md`

Earlier Phase 1/2 changes are preserved. No live server restart, user-database
modification, live AI request, repository publication or website modification was
performed during this phase.

## Verification and limits

Using `/tmp/sentinelscan-verify-venv/bin/python`:

- Full project suite: **162 tests passed, 0 failed**.
- Focused unified-recommendation suite: **8 passed, 0 failed**.
- `git diff --check`: passed.

Tests verify disabled/enabled/failure rendering, failed refresh and recovery,
deduplication, source validation fallback, website backend rejection, secret/YAML
policy, confidence/indicator placement, escaped model text, unchanged findings,
and final HTML/JSON/CSV recommendation consistency. Existing scanner, provider-mock,
editor, persistence and reporting suites continue to run.

No live model quality or provider availability is established by mocked tests.
Missing historical source/context requires a new scan or loading pinned source.
Static validation is not a guaranteed fix. Redaction remains pattern-based and may
miss unknown unlabeled sensitive formats; sharing context still requires consent.
This phase does not automate application, publication, merging or resolution.

Stop here; Phase 4 is not started.
