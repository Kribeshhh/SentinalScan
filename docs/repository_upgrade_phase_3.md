# Repository upgrade Phase 3 — specialized scanners, correlation and evidence

## Architecture and scope

The existing Secrets module remains logically separate from code analysis. This
phase improves it instead of adding another secret binary: typed rules already
cover GitHub/access tokens, AWS access keys, API keys, JWTs, private keys and
credential assignments. No credential is tested against a service. The external
Semgrep/CodeQL adapters and custom AST/Tree-sitter analyzers remain intact.
No new LLM call, automatic remediation or repository execution is added.

Candidates now pass through bounded source-context retrieval and evidence review
before incremental persistence. Correlated candidates update one existing finding's
snapshot; they do not create extra dashboard vulnerabilities. Findings still use
the existing schema, status workflow, recommendation composition and report formats.
No historical rows or triage decisions are rewritten.

## Secret scanning

Generic candidates reject obvious test/dummy labels and environment references
such as `$AUTH_TOKEN`. AWS secret-access-key assignment names are recognized.
Generic credentials in documentation/example/fixture paths receive Low confidence;
a real-looking value is not silently dismissed merely because it appears in docs.
Typed token and private-key patterns remain checked in documentation and examples.
Existing placeholder and localization safeguards remain in place.

All detected values are held only transiently in the scan's known-secret set and
are replaced with `[REDACTED]` before findings, retained context and reports. No
external login, API-key validation or authentication request is performed. A typed
pattern is evidence of a possible credential, not proof that it is active. Unknown
secret formats and values resembling placeholders remain detection limitations.

## Dependency evidence

Existing requirements.txt, package.json, pom.xml and build.gradle readers remain.
New support:

- **pyproject.toml:** static PEP 621 project dependencies and optional groups;
  ranges are inventory, not guessed exact versions. Dynamic/Poetry declarations
  are explicitly limited, not interpreted by executing build metadata.
- **package-lock.json / npm-shrinkwrap.json:** npm lockfile versions 1, 2 and 3;
  bounded nested v1 dependencies or v2/v3 package entries. Links and root workspace
  entries do not masquerade as published versioned packages.

Yarn, pnpm, Ruby, Go, Poetry and uv lock/manifests are reported as unsupported when
present in the vetted inventory. Their relevant filenames are retained for coverage
reporting; they are not claimed as successfully parsed. Malformed and unknown npm
lock versions are unparsed. Inventory remains capped at 500 dependency records;
additional parser/depth limits are recorded and module coverage becomes Partial.

Exact declared/locked versions can be queried against the existing opt-in OSV
endpoint. A returned advisory must name the matching ecosystem/package. No advisory
returned means **no known advisory returned for this version**, not "secure".
Unresolved versions, disabled lookup, timeouts and unsupported formats remain unknown.
Findings explicitly say **functionality reachability not assessed**.

Repeated matching package/advisory occurrences in manifests and lockfiles within
one project directory become one finding. Up to 20 affected path/version occurrences
are retained in structured evidence; different project directories stay separate.
The inventory still shows declared versus locked versions. Dependency filenames
and package/advisory identity remain compatible with existing guidance.

Format references: [npm lockfile specification](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/)
and [pyproject specification](https://packaging.python.org/en/latest/specifications/pyproject-toml/).
No package installation, lockfile regeneration, transitive resolution or application
reachability analysis is performed.

## Correlation decisions for presentation

`analysis/correlation.py` makes conservative, explainable decisions:

1. Parse the vetted affected file with the language adapter.
2. Find exactly one supported operation at the reported location for its CWE.
3. Construct an identity from repository, file, enclosing scope, CWE, operation
   name and normalized parsed operation. Source is redacted before hashing.
4. Within a scan, also require the same operation occurrence/range.
5. Merge evidence from different engines into the first representative finding.
   Preserve its fingerprint, severity and confidence; agreement alone does not
   increase confidence or claim a confirmed vulnerability.

Supported anchors cover SQL calls, shell/process calls, dynamic code execution,
DOM insertion and deserialization. Python uses AST structure; JavaScript/Java use
parsed tokens with comments/formatting excluded. Unsupported or ambiguous cases
remain separate candidates. Two operations on one line are intentionally ambiguous.
Two sinks on different lines, different files/functions, different CWEs, or different
parsed expressions are not merged. Separate rules from one engine are not merged
merely because they share a sink. At most three engine evidence records are retained,
covering custom, Semgrep and CodeQL in this phase.

The evidence package includes **Detected by** entries with engine, rule, original
confidence, scanner evidence and available source/sink/flow. A Semgrep or CodeQL
label is not proof of correctness. Repository module statuses remain independent
and visible even when their candidates correlate into one finding.

## Stable comparison identity

The existing findings table fingerprint is unchanged. A new optional
`logical_fingerprint` in the evidence JSON omits line numbers and uses parsed
operation plus scope, so adding blank lines does not alone create a new issue.
Scan comparison uses these identities when available. Rule/file families missing
new evidence fall back to legacy comparison; historical reports remain readable.

Identical repeated operations in one scope can still be one comparison group with
an occurrence count. Changing source expressions, helper names or scope can change
identity; this is not a perfect code-movement tracker. Conservative correlation can
leave related findings separate when evidence is missing or anchors are ambiguous.

## Context retrieval and verification states

`scanner/sast/security_context.py` retrieves only the affected excerpt and up to
three syntactically related same-file functions (one hop of callers/callees).
It does not collect the repository or infer unrelated configuration. External calls,
unknown validators and framework identity remain unknown rather than guessed.

Limits:

- One file per evidence package, depth one, at most 3,600 excerpt characters.
- At most 1,800 characters per snippet and 300 characters per source line.
- At most 40 cached files / 4 MiB source per scan, 4,000 structural records per file.
- A 12-second cooperative retrieval budget within the repository deadline.
- Existing 512 KiB vetted-file bound, path membership, symlink and traversal checks.

Packages record source, sink, flow, recognized sanitizers, unknown validators,
framework when available, related functions/files and qualified reachability.
Excerpts are redacted before retention. Exhausted/missing context is explicitly
unavailable; it is not a complete-function or complete-call-graph claim.

Review states are separate from Open/Resolved/Ignored/False Positive triage:

- **Strongly Supported:** custom semantic source/sink evidence plus available source
  context and a qualified supported static trace.
- **Likely:** useful context and supporting evidence, without the stronger trace.
- **Needs Review:** missing/weak context or evidence.
- **Rejected / False Positive:** explicit existing False Positive triage, not an
  automatic dismissal by a scanner.

Missing evidence downgrades unsupported High confidence. These states never mean
"100% Confirmed" or prove runtime exploitability. The finding page and HTML reports
show review state and engine provenance; JSON/CSV retain structured evidence through
existing solution snapshots. There is no new duplicate recommendation page.

## Changed files

Added: `analysis/correlation.py`, `scanner/sast/security_context.py`,
`scanner/sast/dependency_manifests.py`, `tests/test_repository_phase3.py`, this doc.
Updated: repository orchestration/extraction, secret and dependency modules,
comparison, finding/report presentation, README and AGENTS.

## Verification

Focused fixtures cover real-looking secrets, placeholders/environment references,
documentation confidence and redaction; positive/negative/unknown dependency evidence;
new manifests/unsupported formats; custom/Semgrep/CodeQL correlation; unrelated and
ambiguous sinks; line movement; evidence packages; context limits; missing evidence;
confidence adjustment and manual false-positive status. OSV and external engine
results are controlled fixtures, never credential validation or remote target scans.

Run with installed project requirements:

```sh
python3 -m unittest discover -s tests -p test_repository_phase3.py -v
python3 -m unittest discover -s tests -v
# Optional existing live Semgrep fixture:
SENTINELSCAN_TEST_SEMGREP=/absolute/path/to/semgrep python3 -m unittest discover -s tests -v
```

Final verification (2026-10-03): **205 tests passed, 0 failed, 0 skipped** in
16.275 seconds, including all eight Phase 3 test methods and the live Semgrep
1.179.0 vulnerable/safe/protected fixture. Python 3.14 used the installed project
requirements in an isolated verification environment. `git diff --check` passed.
CodeQL and OSV responses were fixtures; no live CodeQL installation, production
repository scan, credential validation or live LLM request was part of verification.
Existing AI disabled/enabled/failure/privacy regressions ran with mocked providers.

The final checks also cover unavailable source files falling back to unavailable
context, and Low confidence for generic credentials in Python example files. One
intermediate new fixture failed because its value began with `Example`, correctly
triggering placeholder suppression; the fixture was corrected to exercise the
intended non-placeholder case before the final complete passing run.

Tests used temporary databases and did not modify existing scan history. New evidence
and correlation apply to new scans; older records retain their original results.
Source relationships remain bounded and syntactic, unsupported lockfile formats
remain visible limitations, and static support never proves runtime exploitability.
Stop after Phase 3; no new LLM analysis or subsequent phase is included.
