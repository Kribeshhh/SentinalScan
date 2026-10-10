# Phase 05 — Existing AI-assisted remediation audit

Date: 2026-10-08. **Overall: PARTIAL. Mocked pipeline works; recommendation factual/semantic accuracy is not enforced. Real provider call NOT TESTED.** No paid requests, application changes, additional pipeline, routes, models, buttons or dependency installation. Temporary SQLite and authored fixtures only; no user scan data was passed to an application instance.

Working directory: `/Users/kribeshthapa/Developer/Vibe code/SentinalScan`. Interpreter: existing `.venv/bin/python` (Python 3.13.5, verified in Phase 01). Supplied historical Desktop path is stale.

## Documents and implementation inspected

Required guidance exists: CLAUDE.md, then context/project-overview.md, architecture.md, ui-context.md, code-standards.md, ai-workflow-rules.md and progress-tracker.md; AGENTS.md. Reviewed prior Phase 01–04 audit reports, current architecture, and historical/current policy distinctions in phase_4_llm_and_validation.md and phase_3_unified_recommendation.md. Earlier scanner accuracy and CodeQL limitations remain unchanged.

Inspected config.py, app.py, scanner/website_scanner.py ScanManager completion wiring, analysis/llm_review.py, evidence_review.py, recommendation_composer.py, integrations/llm.py, evidence_provider.py, network.py, templates/_solution.html, and the eight existing test modules listed below. Existing tests exercise shared source validation, deterministic solution policy, SQLite and report consumers.

## Actual flow and storage

Scan workers persist findings and deterministic context/solutions. The shared ScanManager Future completion callback invokes refine_scan after worker return. Enabled/configured refinement reads saved candidates and their base recommendation. Repository evidence packages use analyst and skeptic passes; legacy repository records and DAST use the existing single-pass path. Strict local schema validation, output redaction and applicable static validation run before ai_reviews persistence. final_solution composes deterministic snapshots with eligible saved AI review data for the finding page and new reports.

**One final recommendation is composed from saved components, not stored as an immutable final-recommendation row.** findings remain unchanged; ai_reviews stores the accepted review, finding_solutions stores the base/failure flag. Disabling AI hides its contribution without deleting the saved review. Existing generated reports remain immutable. This is the established architecture, not a missing new database model.

The callback runs when a worker finishes, including Failed scans with retained findings; refine_scan does not require status Completed. It processes at most 20 not-yet-reviewed, non-False-Positive findings in severity order and stops on the first failure. The 60-second limit is checked between findings, not preemptively within a two-pass review. Existing queue worker availability can be delayed by refinement. These are inspected boundaries, not stress-tested latency guarantees.

## Verification matrix

PASS means the sampled behavior/contract worked, not guaranteed model quality.

| Requested check | Result | Evidence |
|---|---|---|
| 1. Enabled/disabled | PASS | LLMUnit/Route/Pipeline and WebsitePipelineAIIsolation tests: both scanners complete with AI off/on; disabled makes no provider calls; enabling uses saved evidence; detector rows unchanged. Environment probes verify false default and synthetic enabled override. |
| 2. Environment API configuration | PASS supported setup / PARTIAL consistency | config.py reads SENTINELSCAN_LLM_ENABLED/PROVIDER/MODEL/API_KEY; no UI key input; synthetic key loaded without printing it. Missing key rejected before transport. Fixed HTTPS OpenAI origin, verified TLS, bounded body, no tools, store=false, POST no retry. LLM_PROVIDER is checked by evidence provider_for but single-pass review always selects OpenAI regardless of that selector. |
| 3. Automatic invocation | PASS | test_completed_repository_automatically_refines_without_changing_detection and test_website_completion_refines_actual_probe_context_automatically exercise actual submission/worker/completion. Website provider asserts durable Completed status. Page GETs make no calls; removed manual route 404 (400 without CSRF). |
| 4. Structured parsing | PASS sampled adversarial cases | Exact top-level/nested keys, enums, field types/lengths, nonempty explanations, source/code consistency; non-JSON/refusal/truncated answers rejected. Two-pass support contradictions and malformed second pass rejected. |
| 5. One final fix | PASS UI contract | UnifiedPageTests and EvidenceRouteTests assert one recommendation section, escaped content, no competing AI panel; selected AI code replaces rather than appends. Distinct deterministic alternatives may remain collapsed. |
| 6. Relevant/factual explanation | FAIL adversarial contract | Probe: unsupported Django/exploitability claim accepted for missing-header evidence. Two passes agreeing on disabling authentication for a DOM sink still compose AI-assisted guidance. Schema/role agreement cannot establish factual truth. |
| 7. Current/Recommended Code | PASS conditional | Finding-quality and source-accuracy tests verify retained actual source plus validated replacement; dependency pair requires complete retained entry and supported release. Website, secrets and unavailable source do not get fabricated Current Code. |
| 8. Example Secure Pattern | PASS deterministic policy / PARTIAL AI quality | Unknown source uses labelled examples, backend-neutral pseudocode or operational text; paired source remains distinct. Supplemental unsupported header value passes allowed-header grammar and is shown as an example, not validated code. |
| 9. No fabrication | PARTIAL / FAIL for AI prose | No scanner findings created or modified by AI; source mismatch rejected and unknown SQL driver withheld. Deterministic dependency tests reject invented/overlapping fixed releases. But AI prose inventing imaginary-package 99.99.99 is saved and shown on the page without advisory support. |
| 10. Secret redaction | PASS sampled boundaries / PARTIAL generality | Known provider/PAT values, assignments, auth/cookies, query values, raw bodies, unrelated fields excluded before wire; secret finding uses synthetic redacted assignment; analyst text redacted before skeptic. Tests check DB, page, reports and logs. Unknown secret formats are not proven detectable. |
| 11. Unavailable fallback | PASS | Timeout/invalid-response tests retain detector records/base advice; prior AI record retained but failure flag suppresses contribution. No scan failure due to provider failure. |
| 12. API failures | PASS mocked | Additional persisted probes: 401, 429, 500, malformed JSON and TimeoutError each produce one attempted request, false review result, deterministic composition, prior review retained, scan still Completed. No retry/backoff is claimed. |
| 13. Storage and display | PASS tested components / PARTIAL interpretation | Reviews stored separately, HTML escaped, final UI and HTML/JSON/CSV use same composition, old reviews readable. Fabricated prose also persists/renders, showing storage safety is not semantic correctness. No separate immutable final row by design. |

## Test execution and exact evidence

Commands from project root:

```sh
.venv/bin/python -B /tmp/phase05_tests.py > /tmp/phase05_tests.log 2>&1
.venv/bin/python -B /tmp/phase05_probes.py
cat /tmp/phase05_tests_summary.json
git diff --check
```

**89 existing test methods passed, 0 failures, 0 errors, 0 skips; 5.849 seconds** (driver elapsed 5.850 seconds). This was the focused suite, not the complete project suite:

- tests.test_llm_review
- tests.test_llm_sast_dast
- tests.test_repository_phase4
- tests.test_unified_recommendation
- tests.test_final_validation
- tests.test_finding_quality
- tests.test_source_accuracy
- tests.test_solutions

The runner creates a temporary SENTINELSCAN_DATA_DIR before importing app/test modules, disables AI by default, removes inherited provider/GitHub credentials within its process, and blocks integrations.network._request_once. Test fixtures explicitly enable mock providers; actual website integration targets the authorized loopback lab. Repository source remains inert. No live external/provider request was needed.

The supplemental helper produced 10 observations (including deliberately undesirable results), **not 10 passing accuracy tests**. No prompts or actual credentials were printed. Synthetic configuration markers are fixture data. Complete test names/log, observed booleans and exact helper sources are in [the evidence artifact](PHASE_05_AI_REMEDIATION.evidence.json).

Recreate helpers from the artifact:

```sh
.venv/bin/python -B - <<'PYREPRO'
import json
from pathlib import Path
bundle=json.loads(Path('docs/audit/PHASE_05_AI_REMEDIATION.evidence.json').read_text())
for name,source in bundle['scripts'].items():
    Path('/tmp',name).write_text(source)
PYREPRO
```

## Issues and limitations

1. **High — semantic/factual advice is not verified.** A valid mocked response describing a missing header recommended upgrading an invented package to 99.99.99 and asserted Django/exploitability without supporting context. refine_finding returned true; ai_reviews saved it; final_solution marked AI-assisted; finding page contained the version. Original finding remained unchanged. A separate two-pass DOM example recommended disabling authentication; agreeing analyst/skeptic fixtures passed and their unsupported action was selected. These demonstrate missing enforcement, not the frequency of hallucination by any real model.
2. **Medium — website grammar is not security validation.** X-Content-Type-Options: unsafe-value passed process/compose because the header name and nonempty value satisfy website_example. It appeared in final examples with Not Available validation. Existing UI correctly avoids a validation-pass claim, but an invalid solution still receives AI-assisted presentation. Other header/TLS semantics were not exhaustively fuzzed.
3. **Medium — new AI source patches lack full pinned originals for static validation.** refine_finding reads full original only from historical remediation_drafts. Current recommendation-only workflow creates no new drafts. Supplemental valid DOM replacement without original yields Not Available and AI contribution false. This safe fallback means new scans generally cannot promote AI source-specific code; deterministic source solutions can still be prepared during scanning. Direct tests passing a full original verify the validator, not availability of that source in new production records. One note still refers to the removed editor.
4. **Low — provider selector inconsistency.** provider_for rejects unsupported providers for evidence-v1, while the legacy/DAST path directly calls fixed OpenAI review and does not inspect LLM_PROVIDER. This was code-inspected, not a real provider call. Endpoint cannot be redirected by repository content.
5. **Bounded coverage and visibility.** 20-finding cap, first-error stop, no retry and between-review deadline leave some findings deterministic. Failed scans can still have retained findings reviewed. Completion status does not expose per-provider success; AI Assisted only means an accepted contribution. These policies should not be described as every finding receiving AI or semantic validation.
6. **Human review remains essential.** Syntax/target-rule/new-finding checks cover existing static modules, not runtime behavior, semantic equivalence, dependency compatibility, exploitability or all new vulnerabilities. Prompt-injection placement tests prove separation of data/instructions, not resistance of a real model. Mock relevance fixtures cannot measure provider judgment or real-world accuracy.

Recommended minimal follow-up, **not implemented**: reject unsupported package/framework/security claims where structured evidence can establish a contradiction; validate allowed website configuration values before selecting examples; clarify unavailable new-source AI validation and remove obsolete editor advice in a separately authorized task; align provider-selector behavior. Do not treat reviewer agreement as factual corroboration.

## Mocked versus real provider conclusion

- **Mocked pipeline: PASS for invocation, schema, privacy samples, persistence, UI composition and failure fallback; PARTIAL overall because semantic/factual quality probes fail.** Existing green tests do not contradict those audit findings.
- **Real provider: NOT TESTED.** Account/key validity, selected model support, actual response quality, latency, billing and provider-side data handling were not verified. No paid calls authorized or made.
- Only audit documentation/evidence and the progress tracker were written. No scanner, recommendation architecture, LLM implementation, UI, database model or application code changed. Phase 5 stops here.
