# SentinelScan maintenance

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
- Preserve redaction, Jinja escaping, source editor/diff/PR workflow and fingerprints.
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
- Deterministic SAST owns detection. Never call AI from a scanner or require it for
  ordinary scans. AI requests require enabled configuration and an explicit action.
- Construct provider payloads only through the bounded whitelist and redaction
  boundary. Never send full repositories, GitHub PATs, secrets or unrelated files.
- Treat source and model output as untrusted. Validate exact response structure;
  escape all output. Never log provider bodies, prompts or credentials.
- AI assessments cannot change finding status, severity, evidence or fingerprints.
- Route code through the existing static candidate validator against matched pinned
  source. Missing context means Not Available, never an invented validation pass.
- Preserve explicit human diff/draft/PR approval. No automatic apply or merge.
- Test enabled/disabled/outage/invalid response/redaction/bad-code cases and the full
  suite. Mock provider calls unless live use is explicitly authorized.
- Phase 4 is optional and complete; stop unless the user requests further work.
