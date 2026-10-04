# Architecture Context

## Stack

| Layer | Technology | Role |
| --- | --- | --- |
| Application | Python 3.11+, Flask | Local routes, validation and orchestration |
| UI | Jinja HTML, CSS, vanilla JavaScript | Server-rendered responsive workspace |
| Persistence | SQLite | Scans, findings, triage, snapshots and workflow records |
| Source analysis | Python AST, JavaScript/Java Tree-sitter | Bounded static detection |
| Optional engines | Trusted local Semgrep/CodeQL | Additional bounded evidence |
| Integrations | GitHub API, optional LLM provider | Read-only source access, optional refinement |

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
on its existing executor. No new queue, provider, engine, table or AI route exists.
Enabled/configured AI uses the former review orchestration, now `refine_finding`.
It reads deterministic `finding_solution`, retained context and existing local draft
for validation only; allowlisted redacted snippets/flow or HTTP observations reach
the provider. AI records remain separate. `final_solution` composes one result for
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
