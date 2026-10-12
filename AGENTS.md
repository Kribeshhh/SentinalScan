# Current provider policy — Ollama only (2026-10-09)

Phase 11 replaces the cloud transport with native loopback Ollama. Use
SENTINELSCAN_LLM_ENABLED, SENTINELSCAN_OLLAMA_BASE_URL and SENTINELSCAN_OLLAMA_MODEL;
no provider key or selectable cloud adapter remains. Preserve automatic refinement,
existing validation/composition, deterministic fallback and all historical reviews.
Do not add routes/buttons/models, change detectors or silently download a model.
Older provider descriptions are historical; see docs/fixes/PHASE_11_OLLAMA_MIGRATION.md.

# SentinelScan maintenance

## Current product scope — recommendation-only (2026-10-04)

The final UI polish removes source editing, drafts, patch download, GitHub writes,
PR publication/tracking and workflow verification routes. Do not restore them.
GitHub is read-only for access, browsing, source retrieval and scanning. Preserve
recommendation generation, source validation, code pairs, examples, automatic AI,
triage and ordinary scan comparison. Historical workflow tables stay for safe
compatibility; the unchanged AI validator may read historical source, never write
new drafts. Older phase descriptions of editor/PR behavior are archival.

## Current maintenance policy — final simplification (2026-10-04)

This is the active AI activation policy; older phase records describe historical workflows.
Keep deterministic repository detection and website checks unchanged. AI is optional,
disabled by default, and automatically refines persisted candidates after a new scan
when explicitly enabled in server configuration. There is no Improve with AI button
or manual AI route. Page/report GETs never call providers. Reuse `refine_finding` /
`refine_scan` in `analysis/llm_review.py` and the existing recommendation composer,
whitelists, two-pass review and static validator; do not add a parallel workflow.
The existing scan queue invokes the completion hook after durable scan results.
Bound each scan to 20 candidate reviews, prioritized by severity, and a 60-second
between-review budget; an in-flight bounded review can finish after that budget.
Stop on first provider failure; individual invalid responses retain fallback and may proceed to the next candidate within the same limits. All remaining findings keep deterministic guidance.
Use mocked AI in normal tests; explicitly authorized synthetic local Ollama checks
may use an already-installed local model. Never install/download models implicitly. Optional local processing permission
comes from the operator's enabled configuration; preserve pre-request redaction,
unknown context, no tools, structured validation and human review outside SentinelScan.
A source fix without pinned local source stays unvalidated and cannot replace the
base fix. Show one Recommended Fix, an AI Assisted indicator only when contributed,
and one Technical Details container. Keep security actions/warnings visible.
See `docs/phase_3_unified_recommendation.md` for the current audit and behavior.


## Required project context

Before implementation or architectural decisions, read these files in order:

1. `context/project-overview.md`
2. `context/architecture.md`
3. `context/ui-context.md`
4. `context/code-standards.md`
5. `context/ai-workflow-rules.md`
6. `context/progress-tracker.md`

Update the progress tracker after meaningful implementation changes. Update affected
context documents when scope, architecture, storage, UI or standards change before
continuing. `CLAUDE.md` provides the same entry point for other assistants. These
files complement the detailed rules below; they do not replace security invariants.


Work in this existing Flask/SQLite application. Preserve DAST, repository scanning,
GitHub access, reports, comparison, status persistence and reviewed remediation.
Do not rebuild the project or start another phase without the user's request.

## Repository detection

- Read `docs/phase_1_detection_accuracy.md` before modifying SAST rules.
- Python uses AST; JavaScript and Java use Tree-sitter. Never execute, import,
  build, install dependencies from, or test credentials found in scanned code.
- Keep analysis bounded by existing scan/file limits and deadline checks.
- Preserve finding titles/categories unless migrating fingerprints, solutions,
  comparison and remediation validation deliberately together.
- Track local values in statement order and isolate function scopes. Preserve
  uncertainty through branches; never present heuristic flow as proven exploitation.
- Protections are sink-specific: HTML sanitization is not protection for eval.
- Redact candidate secrets before persistence, UI, reports or diagnostics.
- Every detection change needs vulnerable and safe examples, plus a protected
  example where applicable. Fixtures must remain data, never executed.
- Run `python3 -m unittest discover -s tests -v` using an environment with
  `requirements.txt` installed. Tests use temporary databases; do not overwrite
  the user's scan history or create an app instance against their DB during tests.

Phase 1 improves existing detection accuracy only. No LLM, new scanning engine,
automatic exploitation, or automatic GitHub changes are part of this work.

## Finding recommendations (Phase 2)

- Read `docs/phase_2_finding_quality.md` before changing finding presentation.
- Recommendation is the main remediation area. Keep code inside it; do not add a
  separate duplicate Code solution section. Preserve existing fragment links.
- Reuse solution builders and normalize historical snapshots with the same policy.
- Distinguish retrieved source, source-matched candidates and illustrative examples.
  Never guess a database driver, source language, input line or enclosing function.
- Detection confidence and fix confidence are separate. Syntax validity alone is
  not proof of a correct fix. Use explicit manual-review guidance when uncertain.
- Preserve redaction, Jinja escaping, recommendation viewer and static validation and fingerprints.
- Run finding-quality tests and the full existing suite after presentation changes.
- Phase 2 is complete; do not begin Phase 3 without the user's request.

## Source-aware solutions (Phase 3)

- Read `docs/phase_3_solution_accuracy.md` before changing candidate generation.
- Preserve actual source names and replacement spans. Driver/library imports alone
  do not justify a patch; establish the specific API and supported query shape.
- Every source-matched candidate must parse, reproduce/remove the target pattern,
  and introduce no new findings in its checked modules before labelling it
  “Static validation passed.” Never say “Vulnerability fixed” from static checks.
- Sanitizer imports and runtime dependencies must be distinguished from optional
  illustrative installation/use. Do not invent APIs, data schemas or command intent.
- Secret-derived examples may use assignment names but never literal values.
  Keep secret-bearing full files out of editor drafts and GitHub publication.
- Keep candidate preparation bounded and preserve guidance/context on fallback.
- Run source-accuracy tests plus the full suite. Stop at Phase 3 unless requested.

## Optional AI review (Phase 4)

- Read `docs/phase_4_llm_and_validation.md` before modifying this layer.
- Deterministic SAST owns detection and never requires AI. When the operator enables
  and configures AI, the existing queue completion hook automatically refines stored
  findings after new scans. Detection logic and page/report GETs never call providers.
- Construct provider payloads only through the bounded whitelist and redaction
  boundary. Never send full repositories, GitHub PATs, secrets or unrelated files.
- Treat source and model output as untrusted. Validate exact response structure;
  escape all output. Never log provider bodies, prompts or credentials.
- AI assessments cannot change finding status, severity, evidence or fingerprints.
- Route code through the existing static candidate validator against matched pinned
  source. Missing context means Not Available, never an invented validation pass.
- Preserve human review before external implementation. No automatic apply or merge.
- Test enabled/disabled/outage/invalid response/redaction/bad-code cases and the full
  suite. Mock provider calls unless live use is explicitly authorized.
- Phase 4 is optional and complete; stop unless the user requests further work.

## Finding context preparation (new Phase 1)

- Read `docs/phase_1_finding_context.md` before changing SAST/DAST context.
- Reuse `finding_solutions` snapshots; context_json is transient, not a findings
  column. Preserve fingerprints, triage and historical compatibility.
- Capture the response that triggered the finding, including probe/resource status;
  never substitute baseline metadata. Exclude raw bodies, cookie values and auth.
- Keep unknown source/framework/database facts unknown. Use existing matched source
  validation for database identity, not speculative import or filename inference.
- Normalize new and historical recommendations alike. Website observations cannot
  justify fabricated backend code. Keep fix and detection confidence separate.
- Redact context field values before JSON serialization and before persistence.
- This phase adds no AI integration or API calls. Preserve the existing optional
  layer without enabling it. Run context tests and the full regression suite.
- Stop after this phase; do not begin Phase 2 without a new user request.


## Optional SAST/DAST AI assistance (new Phase 2)

- Read `docs/phase_2_llm_integration.md` before changing AI payloads or output.
- Reuse `analysis.llm_review.refine_scan` / `refine_finding` through the existing
  completion hook for both sources when AI is enabled/configured. Keep deterministic
  fallback. There is no manual AI route or consent form; page GETs never call AI.
- Pass Phase 1 context through the bounded whitelist; never forward arbitrary
  snapshot JSON, full drafts, raw response bodies, credentials or cookie values.
- Scanned content is untrusted data, never system instructions. Keep provider tools
  disabled and validate exact nested response structure independently of schema.
- Website output cannot be source_specific or fabricated backend code. Unsupported
  configuration grammar falls back to deterministic guidance. Configuration grammar
  acceptance is not static validation or proof of a deployed fix.
- Preserve legacy saved reviews and separate AI persistence. AI never changes
  findings, severity, risk or triage and never publishes/merges code automatically.
- Run both AI suites and the complete project suite with mocked providers/local labs.
- Phase 2 ends here; do not start Phase 3 automatically.

## Unified Recommendation (new Phase 3)

- Read `docs/phase_3_unified_recommendation.md` before changing final presentation.
- Keep scanner guidance and AI records separate internally; use final_solution for
  finding/report presentation and finding_solution for deterministic AI input.
- Render one Recommendation. Never append a separate AI recommendation or duplicate
  a deterministic and AI copy of the same code. Use a small contribution indicator.
- AI disabled or invalid/failed/unvalidated source candidates fall back to the base.
  After a failed refresh, preserve old AI data internally but show deterministic
  guidance until success. Keep the presentation flag out of exported final data.
- Preserve secret-remediation actions, source-specific validation, website backend
  neutrality, escaping, triage and human review before external implementation.
- Reports use the same final composition, never raw AI envelopes/prompts/responses.
  Preserve immutable older reports and clearly labelled example types/confidences.
- Test the five requested display states, failure recovery, reports, deduplication,
  secret handling and the full suite. Fixture previews must be labelled and isolated
  from user scan data. Do not call a live AI provider for render verification.
- Stop after Phase 3; do not start Phase 4 automatically.

## Final validation (new Phase 4)

- Read `docs/phase_4_validation.md` before changing validation claims or test coverage.
- Source-specific candidate validation must parse, reproduce/check the original
  rule and inspect new findings. Never promote unavailable/failed checks to Passed.
- Invalid AI code stays out of final examples. Show the explicit failed-code warning
  inside the one Recommendation and reports; preserve valid deterministic guidance.
  A rejected AI alternative does not invalidate a separately checked base candidate.
- Website validation means implementation/deployment and re-scan, never auto-editing
  or claiming a validated backend fix. Preserve human approval and no-auto-merge.
- Test vulnerable, safe/protected, privacy and failure cases using isolated fixtures;
  never run scanned source or expose real credentials. Mock provider/GitHub boundaries.
- Preserve documented false-positive candidates and blind spots honestly. Do not
  weaken tests or claim measured real-world accuracy from fixture pass counts.
- Run the full suite, not just new tests. The completed final-phase baseline is 172
  passing methods; future edits must report their own actual verification results.
- This final phase is complete. Stop unless the user requests further changes.

## Repository scanner upgrade — Phase 1

- Read `docs/repository_upgrade_phase_1.md` before extending this foundation.
- Do not execute scanned repositories, import their modules, compile/build them or
  install their dependencies. Keep extraction limits, exclusions and cleanup.
- Regex alone cannot establish complex vulnerabilities. Use semantic evidence from
  Python AST or the appropriate language's Tree-sitter grammar; keep unknowns explicit.
- Register language adapters through `scanner/sast/registry.py`. Keep project indexing
  bounded and descriptive; unresolved calls are not proven inter-file data flow.
- Emit normalized source/sink/flow metadata at the rule match; preserve it through
  retained remediation snapshots. Do not change fingerprints or require DB migration.
- Preserve website scanning and dashboard/report compatibility. Existing optional AI
  must remain optional; this upgrade adds no AI/third-party engine or auto-remediation.
- Ask before making unclear major architectural decisions. Document every
  implementation phase, its tests and limitations. Use isolated test databases.
- Run the complete suite and stop after this phase. Do not start Phase 2 automatically.

## Repository scanner upgrade — Phase 2

- Read `docs/repository_upgrade_phase_2.md` before changing flow or external engines.
- Python helper expansion is same-file, plain-function and bounded (depth 4, 100
  expansions/file). Preserve unknown/limited flow and sink-specific protections.
  Never equate a static trace with feasible runtime reachability.
- Semgrep/CodeQL are optional and disabled by default. Use trusted local rules/packs,
  vetted files, private tool environments, bounded subprocesses and validated SARIF.
  No repository builds, dependency installation, downloaded rule auto-config or autofix.
- CodeQL is limited to Python/JavaScript no-build extraction. Record unavailable,
  skipped, partial and failed coverage; keep custom scanning functional.
- Preserve structured evidence, redaction, website scanning, report/dashboard
  compatibility and human review. Do not infer correctness from tool agreement.
- Rescan verification may ignore engines skipped in both scans, but never ignore
  missing coverage from a previously active engine or an engine-owned finding.
- Run the complete suite. Live Semgrep testing is opt-in via
  SENTINELSCAN_TEST_SEMGREP; distinguish real execution from mocked CodeQL results.
- Document every phase and ask about unclear major architectural decisions.
  Stop at Phase 2; do not add new LLM analysis or start another phase automatically.

## Repository scanner upgrade — Phase 3

- Read `docs/repository_upgrade_phase_3.md` before changing correlation/evidence.
- Keep secrets in the dedicated module; never authenticate discovered credentials.
  Retain typed detection and redact before source anchors, evidence, UI and reports.
- Correlate only unambiguous parsed operation + scope + file + CWE + occurrence,
  across distinct engines. CWE or tool agreement alone is insufficient.
- Preserve engine provenance, existing finding fingerprints and triage. Use optional
  logical fingerprints for new comparison evidence; retain historical fallback.
- Keep context retrieval bounded, redacted and syntactic. Missing callers, validators,
  configuration or framework knowledge stays unknown. No whole-repository payloads.
- Dependency versions/advisories do not prove reachable vulnerable functionality.
  Unsupported/dynamic manifests and partial inventory must remain visible.
- Evidence review states qualify support; never call an automated finding absolutely
  confirmed. Preserve website scanning, dashboard/report and remediation compatibility.
- Run focused and complete tests with isolated databases. Document results honestly.
  Stop at Phase 3; do not add LLM calls or begin the next phase automatically.

## Repository scanner upgrade — Phase 4

- Read `docs/repository_upgrade_phase_4.md` before changing evidence review.
- Static analysis owns detection. Operator-enabled/configured AI automatically reviews
  persisted findings through the scan completion hook, within its existing limits.
  Do not call providers from detection logic or page GETs, or restore manual AI controls.
- New repository reviews use the allowlisted Phase 3 package, never full source,
  arbitrary snapshot JSON or a whole repository. Redact before requests/truncation
  and before forwarding the analyst assessment to the skeptical reviewer.
- Keep the provider protocol separate from scanner logic. No repository-selected
  endpoints/adapters, tools, automatic retries or credential validation.
- Validate both structured responses. Disagreement becomes Needs Review; failure
  of either pass falls back. Model agreement never proves a vulnerability.
- Preserve scanner severity/confidence/risk/status and human review outside SentinelScan.
  Cap advisory fix confidence conservatively; do not turn agreement into a score.
- Compose one Recommendation. Evidence assessments can be shown in a compact
  collapsed detail, never as duplicate recommendations or competing code blocks.
- Use existing exact-source static validation. Missing context/API/pinned source
  cannot create a validated patch; DAST cannot invent backend implementations.
- Keep historical/DAST single-pass compatibility documented. No database rewrite.
- Test with isolated databases and mocked providers, including both passes, privacy,
  failures, disagreements, code validation and reports, then run the full suite.
- Stop after Phase 4; do not begin another phase automatically.

## Repository scanner upgrade — Phase 5 (final)

- Read `docs/scanner_accuracy.md` and `docs/repository_upgrade_phase_5.md` before
  changing evaluation or making accuracy claims. Regression pass counts are not
  precision/recall; preserve known errors and distinguish mocks from live tools.
- `evaluation/fixtures.json` is a frozen, labeled, authored challenge set, not an
  independent production benchmark. Its SHA is asserted. Never execute fixture
  source, install its dependencies or authenticate synthetic secret candidates.
- Do not tune detection and then silently relabel or replace hard benchmark cases.
  Deliberate dataset revisions require a new version/rationale; future tuning needs
  a separate holdout. Record code/dataset hashes and actual engine versions.
- Score actual persisted findings by declared category per fixture, count duplicates
  once, keep all confidence levels and retain unscored findings/coverage metadata.
  Incomplete required modules invalidate a run. Zero denominators are undefined.
- Keep AI accuracy separate. Mock review results test contracts, not model quality.
  No live AI evaluation without authorization. No fabricated no-data-flow baseline.
- Use temporary databases and archives, preserve the user's history, and run the
  complete suite. Baseline: 219 passing tests with optional real Semgrep enabled;
  benchmark: TP18 FP5 TN22 FN9, F1 72%, not a security certification.
- This is the final requested phase. Stop unless the user requests further work.

## Accuracy and readability maintenance

- Read `docs/accuracy_and_finding_readability.md` before extending these rules/UI.
- Preserve the original benchmark and results. The 26-case accuracy_holdout_v1 is
  frozen and now consumed; use a fresh separately versioned set for future tuning.
- Guard refinement must retain rejected helper returns. SQL allowlists are not eval
  protections. POSIX quoting is not safe inside other quotes or interpreter commands.
- Keep informational observations in evaluation; do not improve scores by hiding
  low-confidence findings. Historical severity/triage must not be silently rewritten.
- Keep one action-first Recommendation. Secret rotation, validation failures and
  source/fix distinctions stay visible; collapse supporting detail, not essential warnings.
- Verify mobile and desktop layouts with isolated fixture data, preserving escaping,
  status forms, anchors and reviewed editor/PR controls. Run the full test suite.

## Illustrative fallback policy

The latest user request permits short Example Secure Patterns when exact fixes are
unavailable, superseding older guidance-only rules for these illustrative cases.
Use the existing composer/policy and dependency builder; never change detectors.
Keep examples distinct from source-specific fixes and unvalidated. Never invent
package versions, backend frameworks or original source; use advisory-supported
versions or explicit placeholders and backend-neutral pseudocode. Keep operational
recommendations text-only when no useful safe example exists.

## Phase 12 — current Ollama recommendation validation

Read `docs/fixes/PHASE_12_OLLAMA_REMEDIATION.md` before changing AI validation.
Keep the existing automatic flow and single recommendation. The model selects
from locally reconstructed grounded statements; free-form factual claims are
rejected, including unverified false-positive explanations. Do not whitelist raw
scanner evidence as instructions. Schema enums assist generation but do not replace
local validation. Website values and affected-header checks, source matching and
supported static replacements are mandatory. Revalidate saved AI at composition;
never rewrite history to remove a rejected contribution. No confidence or two-pass
agreement can substitute for evidence. No new detector, route, database or UI feature.

## Phase 19 — native response reliability

Use the existing request-specific conditional schema. Guidance-only mode requires
empty code and original_code; no pinned original means no requested source patch.
The shared independent response/grounding/static validators remain authoritative,
even if a provider ignores its schema. Do not repair unsafe or unsupported code.
Keep assessments independent; accepted review storage is not necessarily an accepted
UI contribution. The existing composer may withhold uncertain/disputed reviews.
ProviderUnavailable distinguishes model/configuration/HTTP outages from an individual
ValueError response rejection. Unexpected transport/storage errors stop the callback.
No retries, new queue, providers or detector changes. Request timeout/token bounds
remain20s/3000; model keep_alive60s trades short-lived memory for measured warm latency.
See docs/fixes/PHASE_19_OLLAMA_RELIABILITY.md.

## Phase 20 — website query replay safety

Preserve the shared HTTP Client guard and exact full-URL/position review in the
existing probe helper. No parameter-name, HTTP-method or private-lab assumption may
approve replay. Unknown queries are skipped before HTTP; do not strip parameters
and scan a semantically different request. Explicit trusted review configuration
is for endpoints whose baseline repetition and selected mutations are known inert.
Keep SSRF/origin/budget checks independent. Read
`docs/fixes/PHASE_20_WEBSITE_REPLAY_SAFETY.md` before changing this policy.

## Phase 21 — repository accuracy constraints

Read `docs/fixes/PHASE_21_REPOSITORY_ACCURACY.md` before changing these rules.
POSIX quoting requires imported shlex identity and a complete argument at the
existing narrow command shape; it is not protection inside an interpreter program.
Checksum names do not establish non-security use. Credential names/entropy alone
must not invent custom-secret identity: use supported API context, keep uncertainty
and redact values before persistence. Preserve the frozen 54-case dataset and all
confidence levels in scoring. Semgrep allowlist protection must not survive caught or suppressed
exceptions, nonterminating/conditional guards or reassignment. D08/D09 are partial,
not fully fixed; do not rewrite historical findings or claim universal accuracy.

## Phase 23 — scoped quality maintenance

Use the existing DOM flow and parsed correlation operations for insertAdjacentHTML;
inspect its HTML argument, not position. Constants and recognized sanitization are
not findings; unknown transformations are not automatically sanitizers. Semgrep's
local print-only constructor exclusion is narrow, not universal receiver resolution.
Keep unknown SQL receivers qualified and preserve Phase21 allowlist regressions.
Nmap now uses run_tool; maintain sanitized environment, bounded output, private XML,
process-group cleanup and unchanged ports/fallback. New DB files use0600; never
silently change permissions/ownership of existing user storage. Keep no-code wording
in the shared recommendation policy and preserve one final recommendation.
Phase22 holdout is consumed; report unchanged-label metrics without generalization.

## Phase 24 — honest parser coverage and code examples

Preserve unparsed_files and bounded sanitized parse_errors; never expose exception
messages containing source or secrets. Python2 print syntax stays unsupported and
Partial; no conversion/execution. Config JSONC preprocessing is scoped to tsconfig/
jsconfig project filenames and must preserve quoted strings and diagnostic positions.
Malformed JSONC remains Partial. Do not claim another engine assessed a file merely
because it was enabled or reported zero findings.
Use existing example_secure_pattern/composer for masked illustrative vulnerable and
safer examples; source pairs still require the existing evidence/validation policy.
YAML does not imply interpolation support or a Python backend. Label cross-language
runtime illustrations, retain secret rotation and one recommendation, and apply the
same examples/escaping to new reports. No historical rewrites or inference on GET.
