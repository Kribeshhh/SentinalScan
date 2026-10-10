# SentinelScan — Complete Test Audit

**Audit date:** 2026-10-08. **Phase 10: consolidation only.**

## Executive summary

SentinelScan is a functioning local Flask/SQLite capstone application, with bounded
website assessment, repository static analysis, persisted vulnerability management,
optional external engines, optional automatic AI assistance, and HTML/JSON/CSV exports.
It is currently **conditionally ready for a supervised local demonstration and an
honest academic presentation, not ready for production deployment or autonomous
security decisions**.

The existing environment starts successfully. All **243 existing automated tests
passed** in Phase 9. That result coexists with confirmed detection errors, unsupported
AI advice, a default CodeQL configuration failure, and two malformed-data page
failures. The tests do not cover or reject every defect reproduced by the audit.
No universal accuracy, exploitability, guaranteed remediation or security certification
is supported by these results.

All nine requested audit phases completed. A completed audit phase does not mean
all its checks passed. This document consolidates their recorded evidence; **no
suite, scan, external tool or provider was rerun in Phase 10**. No application,
configuration, test, database or security-control changes were made. Proposed fixes
below are pending user approval.

## Evidence and status conventions

Required reading completed: CLAUDE.md; context/project-overview.md, architecture.md,
ui-context.md, code-standards.md, ai-workflow-rules.md, progress-tracker.md in that
order; AGENTS.md; all reports below. No required document/report is missing.

| Source | Completed scope | Principal evidence |
|---|---|---|
| [P1: Environment](audit/PHASE_01_ENVIRONMENT.md) | Structure, dependencies, startup, SQLite | Launcher HTTP 200, 73 imports, all 11 requirements satisfied |
| [P2: External engines](audit/PHASE_02_EXTERNAL_ENGINES.md) | Semgrep/CodeQL native and mocked checks | Real positive/negative fixtures, pack failures and diagnostic overrides |
| [P3: Website](audit/PHASE_03_WEBSITE_SCANNER.md) | All 12 existing website modules | Local HTTP/TLS/Nmap and mocked module cases |
| [P4: Repository](audit/PHASE_04_REPOSITORY_SCANNER.md) | URL through persisted findings | Controlled ZIP/transport, language rules, frozen evaluation |
| [P5: AI](audit/PHASE_05_AI_REMEDIATION.md) | Optional refinement and fallback | Mocked schemas/providers, semantic counterexamples |
| [P6: UI/backend](audit/PHASE_06_UI_BACKEND.md) | Routes/templates/workflows | Flask/local HTTP; 34 route checks, eight navigation links |
| [P7: Database/reports](audit/PHASE_07_DATABASE_REPORTS.md) | Persistence, risk, exports | Temporary SQLite; 25/27 supplemental checks passed |
| [P8: Security](audit/PHASE_08_SECURITY.md) | Safety boundaries and failures | Isolated mocks, 22 address-policy cases, real gated queue |
| [P9: Tests/accuracy](audit/PHASE_09_TESTS_ACCURACY.md) | Complete suite and labeled benchmarks | 243 tests, 54 repository fixtures, 12 website cases |

P2–P9 each have an adjacent `.evidence.json` containing raw observations and helper
sources; P1 embeds its commands/helpers/output. These are the reproduction authority.
No phase was omitted; individual unverified capabilities are explicitly marked below.

**PASS** means sampled supported behavior worked. **FAIL** means an expected
behavior was contradicted. **PARTIAL** means working behavior has confirmed limits
or incomplete coverage. **SKIPPED** means deliberately excluded/unsupported in the
stated context. **NOT TESTED** means no applicable verification evidence. Statuses
are scoped to the evidence, not universal claims about a module.

## Feature inventory and verification matrix

| Module/feature | Status | What is established / boundary | Source |
|---|---|---|---|
| Python, venv, dependencies, imports | PASS | Python 3.13.5, Flask 3.1.3, valid venv, no broken required imports | P1 |
| Flask launcher/local dashboard | PASS | Existing launcher served HTTP 200, debug off | P1 |
| Startup portability/config consistency | PARTIAL | Old Desktop path missing; machine-specific launcher forces optional engines on | P1 |
| Website URL/target validation | PASS | Sample schemes, IP policies, fragments, unsafe targets rejected/normalized | P3/P8 |
| DNS inventory/address pinning | PASS | Mock resolution/fallback and unsafe-answer rejection; live public DNS NOT TESTED | P3/P8 |
| HTTP transport | PASS | Local redirects, TLS verification, failures and reduced safety limits | P3 |
| Security headers | PARTIAL | Known positive/negative checks; wildcard frame-ancestors false negative | P3/P9 |
| Cookie flags | PASS | Secure/HttpOnly/SameSite cases and malformed cookie handling | P3 |
| TLS assessment | PARTIAL | Trusted/untrusted local certs; expiry/weak mocks; no exhaustive protocol/chain audit | P3 |
| Ports/services | PASS | Nmap 7.991 loopback inventory and TCP fallback; not a port vulnerability claim | P3 |
| Technology observations | PASS | Sample nginx/jQuery/WordPress markers; identification not independently proven | P3 |
| CORS | PASS | Supported GET-only origin tests; no authenticated read/preflight proof | P3 |
| Exposed resources | PARTIAL | Git/env/listing signatures; similar-length soft-404 false negative | P3 |
| Reflected XSS indicators | PARTIAL | Executable-context examples; inert JSON false positive | P3/P9 |
| SQL-error indicators | PARTIAL | Differential error examples; documentation false positive | P3/P9 |
| Disclosure | PARTIAL | Trace/version/map signatures; tutorial false positive | P3/P9 |
| GitHub URL/repo/branch/SHA workflow | PASS | Controlled transport selection, validation, pinned commit and persistence | P4 |
| Live GitHub private access/download reliability | NOT TESTED | No real PAT or remote repository used by this audit | P4 |
| ZIP extraction/file discovery | PASS | Sample traversal/type/size/ratio/exclusion and nonexecution controls | P4/P8 |
| Python AST and local data flow | PARTIAL | Positive/protected pairs; unrelated receiver/source identity errors | P4 |
| JavaScript/Java Tree-sitter | PARTIAL | Supported sampled rules work; incomplete API/dynamic/inter-file coverage | P4 |
| HTML analysis and source coordinates | PARTIAL | Sample checks work; HTML comment line hardcoded to 1 | P4 |
| Secret detection | PARTIAL | Custom-name miss and documentation noise; sampled masking passes | P4/P9 |
| Configuration analysis | PASS | Sample literal settings; some file-level line 1 locations intentionally coarse | P4 |
| Dependency analysis | PARTIAL | Mock exact-version advisory/outage/dedup; live freshness/reachability NOT TESTED | P4 |
| Correlation/deduplication | PARTIAL | Cross-engine tests work; separate same-line calls collapse | P4 |
| Semgrep integration | PASS | Installed, enabled by launcher, invoked, completed and results imported | P2/P9 |
| CodeQL with current launcher settings | FAIL | Installed/enabled, DB creation works, isolated pack resolution fails | P2 |
| CodeQL with diagnostic exact-pack paths | PARTIAL | Real Python/JS queries/import work; informational notifications cause Partial | P2 |
| Deterministic recommendations/code pairs | PASS | Sample retained-source/validated replacement or labeled illustrative fallback | P5/P6 |
| Automatic optional AI orchestration | PASS | Mocked invocation after persisted results, separate reviews, one composed fix | P5 |
| AI factual/security correctness | FAIL | Schema-valid unsupported versions/frameworks/actions accepted | P5 |
| New AI source-specific validation availability | PARTIAL | Full original normally unavailable without historical draft; safe base fallback | P5 |
| Live AI provider and model quality | NOT TESTED | No real paid calls; mock contract success is not model evaluation | P5 |
| Dashboard, findings/filter/triage/history | PASS | Persisted records, empty states, normal routes and status updates | P6/P7 |
| Scan progress/failure/partial display | PARTIAL | Server state/warnings pass; Completed does not guarantee complete coverage | P3/P6 |
| Browser polling/copy/menu/responsiveness | NOT TESTED | Static inspection only in this audit; no browser screenshots/automation | P6 |
| Comparison | PARTIAL | NEW/RESOLVED/UNCHANGED works; malformed snapshot causes 500 | P7 |
| Risk score/history charts | PASS | Documented arithmetic and persisted SVG data; browser visual QA NOT TESTED | P6/P7 |
| SQLite/schema/transactions/restart | PASS | Isolated v4 initialization, constraints/WAL/rollback/normal persistence | P1/P7 |
| Persisted JSON robustness | FAIL | Two deliberate corrupted-record cases break page/comparison workflows | P7 |
| HTML/JSON/CSV reports/downloads | PASS | Consistent saved data, masking, escaping, secure paths, ordinary cleanup | P6/P7 |
| PDF generation | SKIPPED | Unsupported; historical schema allowance is not an implemented generator | P7 |
| SSRF/CSRF/path/shell boundaries | PASS | Sample controls reject attempts; no successful bypass reproduced | P8 |
| Resource isolation/permissions/timeouts | PARTIAL | Segmented budgets, conditional existing-directory permissions, Nmap gaps | P8 |
| Queue/restart interruption recovery | PASS | Four admitted jobs, one active worker; interrupted scans marked Failed | P8 |
| User scan cancellation | SKIPPED | Not implemented; valid-CSRF cancel request returns 404 | P8 |
| Editing/pushing/PR publication/manual AI | SKIPPED | Intentionally removed current product scope, not missing required functionality | P6/context |
| Existing automated suite | PASS | 243/243 tests, zero skips in Phase 9 | P9 |
| Line/branch code coverage | NOT TESTED | Coverage tool absent; no installation performed | P9 |

## Environment and startup

Verified project root: `/Users/kribeshthapa/Developer/Vibe code/SentinalScan`.
The previously supplied `/Users/kribeshthapa/Desktop/Vibe code/SentinalScan` does not
exist. Python is the root's `.venv/bin/python`, macOS arm64, Python 3.13.5; Flask is
3.1.3. `pip check` found no broken requirements; all 11 declared constraints pass.

P1 verified `/bin/zsh -n run-local.sh` and `/bin/zsh ./run-local.sh` with temporary
SENTINELSCAN_DATA_DIR and AI off. The launcher served SentinelScan at loopback:5000
with HTTP 200 and debug disabled. A server remaining alive after a timeout is not a
startup failure. Control Center was also observed listening on port 5000, but no
conflict prevented that verified startup. This report does not assert a server is
currently running or restart any user process.

Defaults disable external engines; the untracked machine-specific launcher enables
both at `/opt/homebrew/bin/semgrep` and `/opt/homebrew/bin/codeql`. Startup success
does not establish external engine health. Existing database read-only integrity in
P1 was `ok`, schema v4, 33 scans/1,336 findings, zero FK violations: a dated observation,
not a newly queried current count.

## External engines: installation versus working coverage

| Configuration | Installed | Enabled | Invoked | Completed | Results imported |
|---|---|---|---|---|---|
| Semgrep launcher | Yes, 1.179.0 | Yes | Yes, real adapter | Yes Python/JS | 1 Python High and 1 JS Medium |
| CodeQL launcher | Yes, 2.27.2 | Yes | Yes, create/analyze | No: queries cannot resolve packs | No |
| CodeQL diagnostic overrides | Same CLI/packs | Yes, temporary config | Yes Python/JS | CLI yes; adapter Partial | 1 Python High and 1 JS High |

Semgrep bundled validation found three valid rules and zero configuration errors.
Its positive lines were Python line 7 and JavaScript line 2; parameterized SQL and
textContent negatives were unflagged. Additional tests cover shell/DOM protections.

CodeQL packs exist: `codeql/python-queries` 1.8.12 and
`codeql/javascript-queries` 2.4.7 under the user's `.codeql/packages`.
The private subprocess HOME cannot discover that cache with the launcher's empty
search path. A cache-root override also failed. Separate **exact version-directory**
overrides worked for each language, without installing anything. A permanent
mixed-language configuration was not verified. Created databases and temporary
workspaces were cleaned after both success and failure.

Successful CodeQL SARIF had executionSuccessful=true, zero rejected results and
informational notifications; the importer treats any notifications as Partial.
CodeQL also rounded `--ram=1024` up to 2048, so it is not evidence of a 1 GiB cap.
Missing executables, malformed SARIF, timeouts and nonzero exits were tested safely;
custom findings survive optional-engine failures. P9's hardcoded “unavailable”
CodeQL benchmark label is stale wording, not proof the CLI is absent.

## Detection results and measured accuracy

P3 exercised all 12 website modules with 20 existing tests, 66 characterization
cases and 13 transport/safety cases. Characterization PASS may deliberately confirm
a defect; it is not an accuracy PASS. Real local HTTP/TLS/Nmap complemented mocks.
P4 exercised 84 existing tests, 59 supplemental observations and controlled
URL-to-GitHubClient-to-ZIP-to-worker-to-SQLite/restart flow. Repository code stayed inert.

P9 benchmarks:

| Population/stage | N | TP | FP | TN | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|---:|
| Repository built-in/local flow | 54 | 26 | 4 | 23 | 1 | 86.67% | 96.30% |
| Repository built-in + Semgrep | 54 | 26 | 5 | 22 | 1 | 83.87% | 96.30% |
| Website four-family diagnostic sample | 12 | 4 | 3 | 4 | 1 | 57.14% | 80.00% |
| Independent Semgrep-only benchmark | — | — | — | — | — | N/A | N/A |
| CodeQL accuracy benchmark | — | — | — | — | — | N/A | N/A |

Precision=TP/(TP+FP); recall=TP/(TP+FN); undefined denominators/unmeasured results
are N/A. Repository fixtures contain 27 positives/27 negatives over nine categories,
three of each per category. Scores count category presence, all confidence levels,
and each fixture once, not individual occurrences. Both stages had complete required
coverage, zero unscored findings and no AI reviews. The combined stage is not an
independent Semgrep score. The frozen set was already consumed during development.

The website sample has five positives/seven negatives across framing, XSS indicators,
SQL indicators and disclosure. It deliberately targets known diagnostic boundaries;
it is not representative of all website modules or real exploitability. Its wildcard
framing miss and inert-JSON/documentation/tutorial false positives are reproduced.
P3 additionally found a directory-listing false negative from soft-404 filtering.
Do not average these different populations or extrapolate to universal accuracy.

## AI, UI and backend integration

Actual architecture: finding/evidence → deterministic recommendation → optional
completion-hook refinement → one final composition from saved components → UI/new
reports. `finding_solutions` and `ai_reviews` persist separate components; there is
no immutable final-recommendation row. GETs do not call providers. No manual AI button,
source editing or GitHub writes remain in the current product.

P5's 89 tests verify mocked enabled/disabled behavior, schema validation, redaction,
source matching, persistence, one displayed recommendation, illustrative examples
and fallback for 401/429/500, timeout and malformed output. Findings/severity/triage
stay unchanged. Repository evidence uses analyst/skeptic review; DAST/legacy paths
retain single-pass behavior. Up to 20 candidates, a between-review 60-second budget
and first-error stop apply; not every finding receives AI. Retained findings in Failed
scans may also be refined. Neither schema validity nor two-model agreement proves
factual accuracy. Unsupported package versions, framework claims, invalid header
values and harmful advice were accepted by mocked responses.

New source-specific AI suggestions generally lack a full pinned original because
only historical drafts supply that original; the removed workflow creates no new
drafts. They fall back safely with Not Available validation. Deterministic solutions
can still be generated during scanning. Real provider keys, quality, latency, billing
and privacy behavior were NOT TESTED.

P6 verified 89 tests, 34 expected route responses, eight navigation links and real
local/fixture worker persistence. Empty, active, completed, failed and partial states
render correctly at the server. Dashboard/history/charts use saved data rather than
fake results. Browser polling, clipboard, menus, focus and responsive rendering were
not executed. Older tracker browser claims are historical, not this audit's evidence.
Completed means orchestration finished; it does not mean every module succeeded or
that the target is secure. A warning is displayed, but unavailable sub-observations
can still live inside nominally Completed modules.

## Database, risk and reports

Fresh isolated SQLite has 14 tables, schema v4, FK constraints and WAL. Normal writes,
context connection reuse/close, rollback, restart, reader snapshots and bounded writer
contention worked. P7: 43 existing tests passed; 25 supplemental checks passed and two
malformed-data checks failed. These are defects in consuming intentionally corrupted
records, not evidence of normal writer corruption or a public injection path.

Risk for Open findings: points=10×Critical+7×High+4×Medium+1×Low+0×Informational;
score=`round(100 * points / (points + 50))`. Empty=0, one Critical=17,
one of each severity=31, 30 Low=38. Other triage statuses contribute zero. Stored
assessment-time scores remain historical while current risk changes with triage.
This is not CVSS, probability or unique-asset risk; repeated scan findings count again.

Comparison groups are NEW/RESOLVED/UNCHANGED for compatible ordered scans.
**RESOLVED means absent from the later scan, not proof of a fix** and does not
implicitly change triage. Coverage differences and coarse identities can affect it.

HTML/JSON/CSV generation, views/downloads, special-character escaping, synthetic
secret masking, formula-injection protections, path/symlink rejection and ordinary
failure cleanup passed. New reports use the same recommendation composition; old
reports remain immutable. PDF is unsupported. Files use registered IDs and exclusive
UUID names; metadata failure removed the new file. Power-loss atomicity, disk-full
recovery and sustained multi-process load remain NOT TESTED.

## Security and failure handling

Sampled SSRF/address restrictions, pinned DNS, same-origin redirects, GitHub URL/SHA
validation, ZIP traversal/bomb/type limits, report path guards, parameterized SQL,
CSRF, Host allowlist, output escaping, CSP and sanitized errors worked. No successful
SSRF, traversal, shell/SQL injection into SentinelScan, CSRF bypass or real-key leak
was reproduced. That is scoped evidence, not a penetration-test certification.

HTTP limits include 60 requests, 256 KiB/response, 0.2s minimum interval and a 150s
client budget. Repository bounds include 64 MiB compressed, 128 MiB expanded,
512 KiB/retained file, 2,000 retained files and 5,000 archive entries. Budgets are
segmented, not an absolute preemptive timeout for all DNS/parser work. P8 verified
four admitted jobs, rejection of a fifth and one active worker. Restart marks
interrupted scans Failed; no cancellation endpoint exists.

Conditional risks, not demonstrated remote exploits:

- Existing data directory 0755/DB0644 can permit local reading if ancestor permissions
  allow traversal. Cross-account access was not tested; new private directory0700
  and secret0600 behavior was observed.
- Probe generation preserves an untouched action query parameter while mutating
  another. A target with state-changing GET semantics could repeat an action. Only
  URL generation was exercised; no destructive request or impact was tested.
- Nmap captures output without an explicit byte cap and inherits environment, unlike
  the stronger external-engine wrapper. Malicious tool output/exfiltration was not tested.
- No multi-user authentication/authorization model is implemented. Loopback, Host checks
  and CSRF are not an access-control boundary against other local processes.

## Complete automated test result and quality

Phase 9 exact child command, with temporary data, AI off by default, synthetic/mocked
provider boundaries and installed optional Semgrep enabled for its test:

```sh
.venv/bin/python -B -m unittest discover -s tests -v
```

**33 modules; 243 discovered/executed; 243 passed; 0 failed; 0 errors; 0 skipped.
22.642 seconds unittest time; 23.129 seconds process wall; exit 0.**

Earlier focused runs overlap and MUST NOT be summed as additional unique coverage:
P2 32 passes; P3 20; P4 84; P5 89; P6 89; P7 43. P8 initially had one harness-blocked
DNS test; it passed unchanged after narrowing the guard, leaving 94 distinct passes
and one optional Semgrep skip. P9 ran the full suite without that skip.

No exact duplicate method bodies or duplicate executed identities were found.
No flake was observed in one complete run; repeated randomized/multi-platform
reliability was not measured. Old AI stub assertion text is misleading about invocation,
but its actual assertions exercise provider-failure survival. Tests were not weakened.
Coverage tooling was absent: line/branch coverage **NOT TESTED**, no percentage claimed.

## Confirmed defects and reproducible counterexamples

The steps below describe prior isolated runs, not instructions to corrupt user data.
Use the linked phase evidence helper sources, temporary databases and mocked clients
only. Expected versus actual results and severity are local audit judgments; no CVSS
or measured real-model failure rate is implied.

| ID | Defect / severity | Safe reproduction steps and actual result | Evidence |
|---|---|---|---|
| D01 | CodeQL configuration failure / Medium operational | Use existing isolated adapter with launcher empty search path and Python/JS positive+negative fixtures. DB creation succeeds; analyze cannot find installed query pack, imports none. | P2 real commands/evidence |
| D02 | Misclassified successful CodeQL status / Low | Repeat P2 with exact pack-version path. CLI/SARIF succeed with informational notifications; adapter says Partial, imports one positive per language. | P2 notification diagnostic |
| D03 | Unsupported AI advice / High recommendation integrity | P5 mock valid review of missing header with invented package 99.99.99/framework claim; refine, save and render. Unsupported prose is shown as AI-assisted. Two agreeing DOM reviews can select disabling authentication. | P5 probes |
| D04 | Invalid AI header example / Medium | Feed allowed header name X-Content-Type-Options with unsafe-value through existing mocked process/compose. Example selected with Not Available validation. | P5 probes |
| D05 | False source/sink certainty / High accuracy | P4 inert Python Display.execute that only prints receives constructed input; unrelated local request object supplies constant data. Scan source strings: SQL High/High and false input-flow findings result. | P4 R1/R2 |
| D06 | Same-line occurrence loss / Medium | Two eval calls on different request arguments on one line in controlled a.py. Analyze and persist: one raw/saved candidate instead of two occurrences. | P4 pipeline R3 |
| D07 | Wrong HTML comment location / Medium | Comment finding on fixture line2 reported at line1. | P4 R4 |
| D08 | Protected/documentary SAST noise / Medium to Low | Run frozen cmd_quoted, secret_doc, crypto_checksum, java_checksum; all flagged despite declared negative truth. With Semgrep, sql_allowlist adds another FP. | P4/P9 case IDs |
| D09 | Missed custom-named credential / Medium bounded limit | Run frozen secret_custom_name inert fixture; positive ground truth has no detected secret. Do not authenticate the fixture string. | P4/P9 |
| D10 | Ineffective framing accepted / Medium accuracy | Synthetic HTML response has frame-ancestors * and no X-Frame-Options. Header module marks framing protected, no finding. | P3 FN-1/P9 |
| D11 | Website contextual false indicators / Low–Medium accuracy | Mock reflection inside application/json script; separate responses with SQL exception documentation and traceback tutorial. Modules report XSS/SQL/disclosure respectively. | P3 FP1–3/P9 |
| D12 | Real listing suppressed / Medium accuracy | Missing path and directory-index page both 200/similar-length HTML. Soft-404 filter suppresses directory finding. | P3 FN-2 |
| D13 | Scan detail malformed JSON / Medium robustness | Temporary completed scan: set module data_json to `{bad`; GET /scans/<id>. Expected controlled unavailable record; actual sanitized500. Same report request400/no file. | P7 D1 |
| D14 | Comparison malformed snapshot / Medium robustness | Temporary compatible scans with finding snapshot `[]`; valid-CSRF POST /comparisons. Expected400 or warned fallback; actual500/AttributeError. | P7 D2 |

Additional implementation limitations (not invented vulnerabilities): new AI code
validation lacks full original context; legacy/DAST provider selection ignores the
selector used by the evidence path; Completed/Partial semantics are coarse (P5/P3).
P8 S1/S2 are reproducible permission/probe behaviors with conditional impact, not
confirmed cross-account disclosure or destructive execution. Nmap resource/environment
risk and exhaustive timeout exhaustion remain inspected/theoretical.

For exact fixture text/logs use the phase `.evidence.json` scripts collections.
P9 uses `reproduction_scripts`; its repository evaluation command was:

```sh
.venv/bin/python -B -m evaluation.run --output /tmp/phase09_repository.json --semgrep /opt/homebrew/bin/semgrep
```

Preserve frozen labels/results. No reproduction was rerun during consolidation.

## Unverified assumptions and coverage gaps

- Real GitHub authentication/private access and network reliability; OSV advisory
  freshness and reachable/transitive dependency vulnerability analysis.
- Real AI provider/model behavior, privacy/latency and hallucination frequency. Mocked
  two-pass agreement is not independent factual verification.
- Browser polling, clipboard, focus, mobile layouts and accessibility in this audit.
- A durable mixed-language CodeQL configuration and standalone external-engine accuracy.
- Independent unseen accuracy dataset; broad framework/API identity, cross-file flow,
  dynamic dispatch, unsupported languages (.ts/.rb), precise all-occurrence scoring,
  confidence/severity calibration and every secret format.
- Website authenticated sessions, browser DOM execution, blind/time SQLi and exploit
  success are outside existing checks; IPv6 live transport, every TLS/cookie/CORS
  variant, slow trickle, broad signature variants and all default timeout durations
  are not fully exercised.
- Code coverage, sustained memory/disk/load tests, process-kill/power-loss recovery,
  multi-process migrations, cross-account OS isolation and production access controls.
- Stale active wording remains in AGENTS (editor/PR reference), UI context (old tokens)
  and tracker (old in-progress entries). Later current-scope sections take precedence.
  These ambiguities were documented in P1, not silently repaired in this consolidation.

## Top five issues, ranked by priority

These are remediation priorities for safety and demo credibility, not exploit scores.

| Rank | Issue | Minimum proposed fix / acceptance condition |
|---|---|---|
| 1 — High | AI can promote unsupported or unsafe advice (D03/D04) | Reject contradicted/unsupported package, framework and security claims where evidence permits; validate supported header values. Add negative probes before promotion. Until verified, keep live AI off for demo. |
| 2 — High conditional | Website probes replay action parameters (P8 S2) | Review whole-query refusal/explicit policy for action-bearing URLs, rather than skipping only mutation. Acceptance: no probe replay of the action fixture; no destructive test required. |
| 3 — High accuracy | Incorrect source/sink identity and overconfident findings (D05) | Use available receiver/import identity and preserve unknowns; R1/R2 negatives must not earn SQL/Flask certainty. Retain true positives and protected cases. |
| 4 — Medium operational | CodeQL enabled but cannot resolve packs; misleading Partial (D01/D02) | Make trusted installed packs resolvable in the isolated environment and distinguish informational notifications. Verify both languages under the actual launcher; do not claim complete coverage until then. |
| 5 — Medium robustness | Malformed saved JSON breaks scan/comparison (D13/D14) | Validate decoding and object shape at read boundaries. Return explicit unavailable/error state without false clean/RESOLVED output; add both regressions. |

## Minimum before the capstone demo

**No fixes or configuration changes in this section have been applied.** Two demo
scopes must be distinguished:

1. **Restricted supervised demonstration of current behavior:** possible now with
   loopback-only disposable data and pre-reviewed authorized local fixtures. Keep
   live AI disabled, explicitly show CodeQL failed/skipped coverage, use no
   action-bearing GET targets, show known detector errors and do not claim autonomous
   remediation. Confirm the intended browser interactions manually before presenting;
   this audit cannot supply that missing browser verification.
2. **Demonstration claiming dependable end-to-end remediation and complete optional
   engine coverage:** first fix/verify ranks 1–5 for the enabled scope. If AI or CodeQL
   is deliberately excluded, state that exclusion rather than claiming it works.
   Correct D10's wildcard protection and D11's inert-script distinction before using
   those checks as accurate exemplars. Other noisy/limited categories must remain
   disclosed, with reviewed findings rather than automatic security conclusions.

For either scope: use the verified Developer path/venv, review module coverage
rather than only Completed, preserve user history, and retain human approval outside
SentinelScan. On a shared machine, verify effective data-directory ownership/access
and tighten it if needed before storing sensitive source. Browser smoke verification
and a rehearsed isolated demo are required readiness checks, not features. After any
approved fixes, rerun the existing suite plus the exact failing fixtures; current
243-pass results do not validate future edits. No deployment/auth feature expansion
is required for a strictly single-user local capstone demonstration.

## Optional future improvements — separate from minimum gates

After the immediate issues, consider precise same-line occurrence/comment locations,
narrower secret/checksum/protected-case handling, stronger soft-404 evidence and
clearer unavailable-module observations. Extend the evaluation with a fresh versioned
holdout, independent external-engine stages and semantic advice checks. Browser
regression automation, coverage measurement (after tool approval), Nmap environment/
output bounds, consistent provider selection and better source availability for AI
validation would improve reliability. Cancellation, multi-user deployment and broader
scanning are new scope and are not implied by this audit. None is implemented here.

## Final readiness decision

| Use | Readiness | Conditions/reason |
|---|---|---|
| Supervised local demo | CONDITIONAL / PARTIAL | Core flows work now; restrict scope as above, rehearse browser, disclose disabled/broken optional coverage and detector errors |
| Academic presentation | READY with explicit limitations | Present architecture, reproducible tests, counterexamples and honest fixture metrics; do not advertise validated autonomous fixes or universal accuracy |
| Controlled security testing | CONDITIONAL / PARTIAL | Authorized disposable labs, reviewed targets/evidence, no action-bearing URLs; human triage and independent confirmation remain necessary |
| Production deployment | NOT READY | Local unauthenticated workspace/development server; unresolved defects, conditional data/resource risks and missing operational/security validation |

The audit is complete, not the fixes. Only this consolidated report and the progress
tracker are changed in Phase 10. Earlier audit evidence remains the source of observed
results. Await user approval before any remediation; no next phase started.
