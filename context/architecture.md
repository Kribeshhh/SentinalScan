# Architecture Context

## Stack

| Layer | Technology | Role |
| --- | --- | --- |
| Application | Python 3.11+, Flask | Local routes, validation and orchestration |
| UI | Jinja HTML, CSS, vanilla JavaScript | Server-rendered responsive workspace |
| Persistence | SQLite | Scans, findings, triage, snapshots and workflow records |
| Source analysis | Python AST, JavaScript/Java Tree-sitter | Bounded static detection |
| Optional engines | Trusted local Semgrep/CodeQL | Additional bounded evidence |
| Integrations | GitHub API, optional local Ollama | Read-only source access, optional refinement |

No React, TypeScript, Node.js dependency or frontend build step.

## System Boundaries

- `app.py`, `*_routes.py`: HTTP/UI entry points and workflow coordination.
- `config.py`, `database.py`: configuration, connections and compatible migrations.
- `scanner/`: website/repository workers and network/extraction safeguards.
- `scanner/sast/`: language registry, static flow, indexing and specialized checks.
- `scanner/engines/`: bounded process execution and external evidence normalization.
- `analysis/`: findings, risk, correlation, context, recommendations and validation.
- `integrations/`: GitHub and optional provider boundaries.
- `reports/`: generation and safe exports; `templates/`, `static/`: presentation.
- `tests/`, `evaluation/`: isolated regressions and frozen labeled evaluation data.

## Storage Model

SQLite defaults to `data/sentinelscan.sqlite3`; configuration supports a data directory
override. It stores scans/modules, findings, repositories, comparisons, report
metadata, bounded redacted source context/solution snapshots, separate AI reviews,
historical source drafts/checks and PR records retained for compatibility only. Reports are files under
`reports_output/`, accessed by registered report IDs, not arbitrary filenames.
Repository archives/extracted files are temporary and bounded. Secret-bearing full
files must not enter stored full-source context. Preserve existing schema and
immutable reports; never reset the user's database during development/testing.

## Auth and Access Model

The app is a local workspace bound to loopback, not a multi-tenant authenticated
service. Flask sessions and CSRF protect forms; GitHub authorizes repository access.
Browser-supplied PATs stay in session-scoped server memory, not SQLite or browser
session payloads. Environment credentials are server-side configuration. Do not
invent account ownership or deployed access controls that do not exist.

## Invariants

1. Deterministic workers own scan work. Optional AI refines stored findings through
   the existing queue completion callback; it is never required for detection.
2. Never execute/import/build scanned repositories or authenticate discovered secrets.
3. Redact before persistence, diagnostics, reports and any AI payload construction.
4. Unknown flow/framework facts remain unknown; severity, detection confidence and
   fix confidence are distinct. Static validation is not proof of runtime safety.
5. Preserve fingerprints, triage, history and human review outside SentinelScan.
6. Tests and previews use temporary databases, never the user's history.
7. Use the applicable detailed rules/docs referenced in `AGENTS.md` for each subsystem.

## Final recommendation handoff

`ScanManager` finishes/persists either scan, then calls `analysis.llm_review.refine_scan`
on its existing executor. No new queue, detection engine, table or AI route exists.
Enabled/configured AI uses the former review orchestration, now `refine_finding`.
It reads deterministic `finding_solution`, retained context and existing local draft
for validation only; allowlisted redacted snippets/flow or HTTP observations reach
the loopback-only Ollama provider. AI records remain separate. `final_solution` composes one result for
finding/new reports. Failure, missing context or invalid code retains the base.
No page GET sends context. Older records are not bulk processed on startup; rescan
to collect/refine new context. Existing saved reviews retain read compatibility.
The automatic pass is bounded to 20 candidates and a 60-second between-review budget,
with first-failure stop. Detection completes before refinement; refreshing later can
show the persisted enhancement. Runtime validation and human review remain required.

Website checks are intentionally retained: dnspython + system resolver; validated
pinned IPs with socket/http.client/ssl; optional Nmap and TCP fallback; cryptography
certificate parsing; BeautifulSoup passive HTML parsing; small custom header, cookie,
CORS, reflection, SQL-error and resource checks. See the audit table in
`docs/phase_3_unified_recommendation.md`. No website detection or repository analysis
was changed in this simplification.

## Recommendation-only product boundary

Editor/publication and workflow routes/templates are removed. GitHubClient exposes
GET-only API operations; it cannot create branches, commits or PRs. Shared source
validation/redacted diff helpers and finding_solution are retained for advice. No
new drafts/checks/tracking/verification writes occur; historical tables remain and
the existing AI validator can read old draft source for compatibility. No destructive
migration or change to detectors, risk, comparison or AI orchestration was made.

## Ollama provider migration — 2026-10-09

Ollama is the only runtime LLM provider. `integrations/llm.py` uses the native
/api/tags, /api/show and /api/chat APIs through `integrations/ollama.py`; the shared
public HTTPS client remains reserved for GitHub/OSV. Loopback addresses only, no
DNS/proxy/redirect forwarding or provider credentials. Local model metadata is
checked before each inference; missing/remote models fail safely. Configuration:
SENTINELSCAN_LLM_ENABLED (default false), SENTINELSCAN_OLLAMA_BASE_URL (default
http://127.0.0.1:11434), SENTINELSCAN_OLLAMA_MODEL (default empty). No model downloads.
Existing completion hooks, analyst/skeptic schemas, redaction, static validation,
composition and historical ai_reviews remain. Transport replacement does not fix
semantic hallucination or unavailable pinned originals. See docs/fixes/PHASE_11_OLLAMA_MIGRATION.md.

## Phase 12 recommendation grounding — 2026-10-09

The existing Ollama handoff now supplies bounded `supported_statements`, generated
from deterministic recommendation policy, alongside the existing redacted evidence.
The native response schema constrains prose to those choices; the local validator
independently reconstructs them before persistence and final composition. It never
trusts a model-supplied allowlist or treats two-pass agreement as factual verification.
Unsupported free-form claims and false-positive rationales fall back. This is a
conservative selection/refinement contract, not unrestricted AI explanation generation.
Website examples require a small safe-value grammar and the affected header; source
proposals need the existing pinned-source checks plus a supported deterministic
replacement. Unknown source/API or unverified examples retain the base recommendation.
No new route, pipeline, schema, detector, UI panel or provider. Historical reviews
remain stored, but unsupported content is no longer promoted when read. Immutable
old report files are unchanged. See docs/fixes/PHASE_12_OLLAMA_REMEDIATION.md.

## Python identity checks — Phase 13 (2026-10-09)

Existing AST abstract values retain supported import/receiver identities. Flask
sources require absolute import identity; recognized database constructors/cursors
support SQL confidence. Unresolved receivers keep Low-confidence heuristic candidates
with explicitly uncertain sinks. Ordinary explicitly declared local methods are not
SQL sinks solely because of their names; dynamic/inherited/rebound identities stay
unknown. Scope aliases and conservative branch merging remain bounded; scanned code
is never executed. No engine, schema or recommendation architecture change. See
`docs/fixes/PHASE_13_SAST_IDENTITY.md` for supported cases and limitations.


## CodeQL pack resolution and coverage — Phase 14 (2026-10-09)

The existing CODEQL_SEARCH_PATH setting accepts a validated OS-path-separated list
of absolute trusted installed pack directories outside scanned source. The local
launcher supplies pinned Python1.8.12/JavaScript2.4.7 directories for CLI2.27.2;
operators can override it when installations change. Private subprocess HOME and
all existing execution/resource limits remain. SARIF note/none diagnostics permit
Completed status; warnings/errors/unsuccessful invocations remain Partial, while
execution failure, timeout and malformed SARIF remain Failed. No download, build,
new scanner or database change. See docs/fixes/PHASE_14_CODEQL.md.

## Stored data validation — Phase 15 (2026-10-09)

Scan detail validates module JSON objects per record and displays malformed
observations as unavailable without rewriting stored status or hiding findings.
Comparison creation validates finding-solution context/analysis/identity and present
module observations; malformed data returns a controlled error and leaves existing
comparison snapshots unchanged. Absent optional legacy metadata still uses existing
qualified matching. No schema, risk, triage or report changes. See
`docs/fixes/PHASE_15_DATA_ROBUSTNESS.md` for scope and verification.


### Phase 16 occurrence and conservative detection corrections

Semantic evidence retains parser byte columns. Only colliding same-line semantic
findings add a column discriminator to their existing fingerprint; ordinary and
historical identities remain unchanged. Parsed correlation uses precise columns
when present and leaves unknown external anchors ambiguous. Display locations stay
file:line; no schema migration or historical rewrite. HTML comments now carry their
actual opening line. New scans are required to observe corrected results.
Website indicators distinguish inert script data, explicitly labeled explanatory
prose and unrestricted framing, and retain distinct directory-index signatures
against length-only soft-404s. These remain bounded heuristics. D08 is partial and
D09 arbitrary credential detection remains unresolved; see the Phase16 fix report.
