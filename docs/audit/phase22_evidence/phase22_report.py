from pathlib import Path
import json,hashlib,shutil
root=Path.cwd();out=root/'docs/audit'
def load(n):return json.loads((out/('PHASE_22_'+n+'.json')).read_text())
b=load('BASELINE'); h=load('HOLDOUT_RESULTS'); old=load('FROZEN_BENCHMARK'); live=load('LIVE'); cq=load('CODEQL')
archive=out/'phase22_evidence';archive.mkdir(exist_ok=True)
for p in Path('/tmp').glob('phase22_*.py'):shutil.copyfile(p,archive/p.name)
shutil.copyfile('/tmp/phase13_bench.py',archive/'original_benchmark_runner.py')
(archive/'launcher_hook').mkdir(exist_ok=True)
shutil.copyfile('/tmp/phase22-hook/sitecustomize.py',archive/'launcher_hook/sitecustomize.py')
changed=[p for p,digest in b['protected_files'].items() if not Path(p).exists() or hashlib.sha256(Path(p).read_bytes()).hexdigest()!=digest]
(out/'PHASE_22_PRESERVATION.json').write_text(json.dumps(dict(protected_count=len(b['protected_files']),changed=changed,holdout_hash_unchanged=hashlib.sha256((out/'PHASE_22_HOLDOUT.json').read_bytes()).hexdigest()==h['dataset_sha256'],user_data_policy='All audit application instances used temporary SQLite/data directories; user history not opened/reset by audit helpers. No pre/post user database byte hash was collected, so byte identity is not asserted.'),indent=2))
assert not changed
lines=[]
for label,stages,key in [('Original54',old['stages'],'overall'),('Holdout28',h['stages'],'metrics')]:
 for s in stages:
  m=s[key];lines.append(f"| {label} / {s['stage']} | {m['TP']} | {m['FP']} | {m['TN']} | {m['FN']} | {m['precision']:.2%} | {m['recall']:.2%} | {m['f1']:.2%} |")
cat=[]
for s in h['stages']:
 for c,m in s['categories'].items():cat.append(f"| {s['stage']} | {c} | {m['TP']}/{m['FP']}/{m['TN']}/{m['FN']} | {m['precision']:.2%} | {m['recall']:.2%} | {m['f1']:.2%} |")
ai=[]
for c in live['cases']:
 f=c['findings'][0];ch=[r for r in c['requests'] if r['path']=='/api/chat'];ai.append(f"| {c['case']} | {len(ch)} × HTTP200 | {', '.join(str(r['seconds']) for r in ch)} | Accepted/saved | {'AI selected' if f['final'].get('ai_assisted') else 'Deterministic retained'} | {f['ui_status']}; {f['single_recommendation']} panel |")
report='''# Phase 22 — Final end-to-end verification, security audit and readiness

Date: 2026-10-11. **Audit completed; overall PARTIAL. No fixes implemented.**

## 1. Executive summary

SentinelScan's three existing features work as a local, supervised assessment tool: website checks, repository analysis, and optional local Ollama recommendation refinement. The complete existing suite independently passes **338/338**, but this does not establish universal detection accuracy or production security. Real Semgrep and CodeQL execute and import findings. Real Ollama accepts five controlled reviews, selects three for display and retains deterministic recommendations for two.

A separately frozen holdout exposes two missed positive cases and one additional Semgrep false positive. Shared-machine file permissions and the absence of application authentication remain deployment concerns. Phase 20 query replay protections pass; queryless GETs are not guaranteed harmless. **Conditionally ready for a controlled academic demo; not ready for public or multi-user deployment.**

## 2. Scope and methodology

Read CLAUDE.md, project-overview, architecture, ui-context, code-standards, ai-workflow-rules, progress-tracker, AGENTS.md, and Phase17–21 reports. Document hashes and presence are in [baseline](PHASE_22_BASELINE.json); none of those required files was missing. Inspected current configuration, launcher, scanners, subprocess/network boundaries, validators, composer, routes and existing tests.

All executable fixture traffic was local or mocked. GitHub retrieval used fixture clients/archives; no personal credentials, public repository scans, model downloads, package installation, paid providers, untrusted-source execution or production fixes. Real Ollama calls were expressly in scope. Test helpers set temporary data directories before importing the app. Reports use disposable directories. Original tests and datasets were not weakened, relabeled or changed.

Status meanings: PASS = sampled expected behavior observed; FAIL = confirmed mismatch; PARTIAL = working subset with known limits; NOT TESTED = no execution evidence; SKIPPED = deliberately disabled component in a particular run. Passing a module does not mean the target is secure.

## 3. Environment and Git baseline

- Actual checkout: `/Users/kribeshthapa/Developer/Vibe code/SentinalScan` (older Desktop path is stale).
- Branch `main`, commit `05940c4cc3f02b6f7d9fd2b4079f307ee0ae6143`. Existing dirty changes were preserved; no staging, commits or pushes. Exact initial status is recorded in baseline JSON. This report describes the working tree, not just HEAD.
- Existing `.venv/bin/python`: Python3.13.5; Flask3.1.3; Werkzeug3.1.9; SQLite3.53.4; Tree-sitter0.25.2. Full installed distribution versions recorded in baseline. `.venv/bin/python -m pip check`: exit0, `No broken requirements found.`
- Semgrep1.179.0 `/opt/homebrew/bin/semgrep`; CodeQL2.27.2 `/opt/homebrew/bin/codeql`; cached Python queries1.8.12 and JavaScript queries2.4.7.
- Plain config defaults: AI/Semgrep/CodeQL disabled; Ollama loopback11434, model empty. `run-local.sh` enables engines and defaults AI on with `qwen2.5-coder:3b`; verification helpers explicitly disable unrelated AI, and the live helper enables only the approved model. These distinct startup modes are intentional.
- DebugFalse, trusted loopback Hosts, HttpOnly/Lax cookies; Secure cookies require HTTPS configuration. Generated session key0600. Baseline records only a safe configuration whitelist, never secret values.
- Launcher HTTP verification: actual shell launcher, temporary Flask.run port0 wrapper, HTTP200, debug off, loopback binding, CSP/nosniff/DENY headers. Temp SQLite initialized14 tables, schema4, integrity`ok`. [HTTP evidence](PHASE_22_HTTP.json).
- [Preservation evidence](PHASE_22_PRESERVATION.json): **163 protected application/template/test/evaluation files unchanged** against the pre-test baseline. No byte-for-byte assertion is made about the user's database: it was not opened for this audit; helpers used isolated paths.

Safety limits inspected: HTTP60 requests,256KiB response,5requests/s,150s HTTP budget; fixed small port list; ZIP64MiB compressed/128MiB declared expanded,512KiB individual text,2000 scanned files/5000 archive entries; repository loop180s. External runner caps output6MiB, workspace512MiB/20000files and kills process groups on timeout. These are segmented checks, not a universal end-to-end hard deadline or OS sandbox.

## 4. Automated regression results

| Run | Passed | Failed | Errors | Skipped | Runtime | Exit |
|---|---:|---:|---:|---:|---|---:|
| Complete existing suite |338|0|0|0|23.044s unittest;23.477s process|0|
| Selected workflow/replay/security/AI suites, repeated |63|0|0|0|8.208s harness|0|

Exact full command: `.venv/bin/python -B -m unittest discover -s tests -v`, launched by `/tmp/phase22_tests.py --full` with temporary data, AI disabled and installed Semgrep opted in. [Full log](PHASE_22_TESTS.log), [metadata](PHASE_22_TESTS.json). No failure was hidden by changing tests.

Focused command: `.venv/bin/python -B /tmp/phase22_focused.py`; modules and exact method names in [focused log](PHASE_22_FOCUSED.log) and [metadata](PHASE_22_FOCUSED.json). These63 are repeats, not additional unique tests beyond338. Supplemental checks below are separate evidence, not added to the338 total. Coverage instrumentation was not run in this phase; full path/branch coverage is NOT TESTED.

## 5. Website scanner verification

| Behavior | Result | Evidence / qualification |
|---|---|---|
| Form authorization, URL/scheme/credentials/port rejection |PASS|WebsiteTests.test_validation_and_authorization; hardening tests|
| DNS pinning, mixed-address rejection, private opt-in, metadata restrictions |PASS|WebsiteTests pinning/mixed DNS tests;22 address decisions in SECURITY JSON|
| HTTP, headers, cookies, technologies, discovery, CORS, XSS/SQL indicators |PASS sampled|Real inert local lab through form→queue→SQLite;12 modules Completed; expected XSS, SQL, credentialed CORS, Git/environment-resource findings|
| TLS |PASS controlled|Local generated valid/untrusted certificates; no public TLS target|
| Port/service discovery |PARTIAL|Real bounded TCP fallback on local lab; Nmap argument/error handling mocked, not a fresh live Nmap accuracy test|
| Severity/confidence/evidence/source context |PASS sampled|Persisted finding assertions, redaction, DAST backend-neutral examples; indicators not confirmed exploits|
| Module failure/baseline failure |PASS|Independent modules retained; missing HTTP data shown as unavailable/skipped; completed orchestration may coexist with partial coverage|
| Risk, persistence, triage, report export/restart |PASS|EndToEndTests actual local HTTP process, SQL risk formula, HTML/JSON/CSV, comparison and process restart|

The repeated 12-response authored website benchmark produces **TP5 FP0 TN7 FN0; precision/recall/F1=100% on these12 only**, [evidence](PHASE_22_WEBSITE.json). Cases cover framing wildcard/absence/restriction, script-vs-text-vs-inert JSON reflection, new SQL exception-vs-documentation, traceback-vs-tutorial. This is a tiny known development replay, not an independent DAST accuracy estimate. The helper now supplies exact inert query review to the existing probe generator; detector code is unchanged. No browser execution, exploitation, crawling or authenticated application coverage is implied.

## 6. Phase 20 replay safety

**PASS for the implemented boundary.** All nine existing replay tests reran in both full and focused suites:

- Original mixed action/query fixtures generate zero XSS/SQL requests without explicit review.
- Unreviewed baseline is blocked before socket creation.
- CORS shares the Client.get guard; cannot turn a blocked query into a request.
- Local same-origin redirect to unreviewed query is not followed.
- Only exact full URL plus reviewed component positions permits inert probe generation; unrelated encoded bytes/duplicate positions preserved.
- Parameter names, GET, authorization checkbox and private lab permission never approve replay.
- Review cannot bypass origin, address policy, deadline, request count or body caps.
- Blocked scan persists skipped HTTP and Failed scan state; no clean-assessment implication.

The UI has no operator query-review editor; trusted server configuration is required. This deliberately limits default query scanning. **Residual risk:** queryless GET endpoints can themselves change state; an incorrect trusted review can authorize harmful replay. Only use inert authorized lab endpoints for the demo. Do not claim universal safe GET scanning. UI placeholder mismatch is A22-08 below.

## 7. Repository scanner verification

**PASS for controlled end-to-end integration; PARTIAL for accuracy.** The source, archive, repository URL, engine, context, correlation, Phase21 and end-to-end suites exercise URL/branch/commit selection, safe extraction, language discovery, engine runs, normalized evidence, recommendations, saved results and reports.

- Fixture GitHub clients supply pinned SHA and ZIP content; downloaded source is never imported/executed/built.
- Malicious path/symlink/duplicate/ZIP-bomb fixtures rejected; excluded/binary/oversized/unsupported files limited and disclosed.
- Python AST, JS/Java Tree-sitter, HTML/config/secrets/dependencies run on controlled text. Dependency advisories/outages are mocked; no live OSV coverage claim.
- Genuine known engine positives and safe counterparts verified; unavailable/timeout/malformed external results preserve custom findings and visible coverage.
- Correlation retains distinct engine provenance and known operation identity. CodeQL JS High raw severity is retained as provenance while the merged built-in finding is Medium; engine agreement does not raise detection confidence automatically.
- Temporary archive/tool directories removed in benchmark and live-engine runs.
- **Live GitHub access NOT TESTED:** no repository specifically authorized for this audit and no personal token used. Private-access and rate-limit behavior are mock-tested, not a current account connectivity claim.

## 8. Separate holdout and original benchmark

The new `PHASE_22_HOLDOUT.json` is separately authored for this audit and labels were frozen before predictions: **28 scored cases (14positive/14negative) plus3 ambiguous**,32 text files, including a two-file SQL example. Origin/rationale is recorded per case. File SHA:
`ef1634f59e6a1d697453298ba26600c73ec013d17abd878c261588b6891d72eb`.
[Freeze record](PHASE_22_HOLDOUT_FREEZE.json), [predictions](PHASE_22_HOLDOUT_RESULTS.json).

It tests different API shapes (executemany, insertAdjacentHTML, decodeURIComponent, HMAC digest selection, direct credential APIs), aliases, shadowed int, inert documentation, placeholders, bound SQL, DOM text/sanitization, checksums and multi-file context. This is a separate authored challenge set, **not blinded external validation**: its author knew the architecture and previous failures. No rule tuning, post-result relabeling or case removal occurred. The HMAC-MD5 positive is explicitly a weak-primitive policy expectation, not proof of practical MAC forgery; that policy choice limits interpretation of its FN.

Scoring: one declared category-presence decision per case across its files, all confidence levels, duplicates count once; ambiguous cases excluded from denominators but reported. No unscored extra findings occurred. Both runs had required modules Completed and cleanup succeeded. Helper-file predictions are aggregated, not counted as independent test samples.

| Dataset / engine |TP|FP|TN|FN|Precision|Recall|F1|
|---|---:|---:|---:|---:|---:|---:|---:|
'''+ '\n'.join(lines)+'''

Holdout per-category results:

| Engine | Category | TP/FP/TN/FN | Precision | Recall | F1 |
|---|---|---|---:|---:|---:|
'''+ '\n'.join(cat)+'''

Representative errors:

- Both engines miss `dom_adjacent`: decoded location input enters `insertAdjacentHTML` at main.js:2. Concrete missing sink coverage, not proof that every DOM XSS is missed.
- Both miss `crypto_hmac_md5`: weak digest passed as HMAC callable at main.py:3. Policy coverage gap; do not misdescribe generic MD5 collision knowledge as demonstrated HMAC exploitability.
- Semgrep alone flags `sql_local_display` main.py:5, local Printer.execute only prints. Raw severityHigh/confidenceLow. Built-in correctly returns no SQL finding. D05's built-in fix did not solve matching-name ambiguity in all external rules.
- Original54 still contains two informationalLow checksum FPs and one context-free secret FN. Frozen original SHA unchanged `73c72c4db254ac9f52071915f5e8a56d111c7d0933ebc1e6ad363c4e25b3a2d1`; [evidence](PHASE_22_FROZEN_BENCHMARK.json).

Sample sizes are small, language/category coverage uneven and Java results aggregate multiple rules. No percentages are extrapolated to real repositories. CodeQL holdout accuracy **NOT TESTED**; its real integration evidence is separate.

## 9. Semgrep

**INSTALLED / ENABLED / INVOKED / COMPLETED / RESULTS IMPORTED: YES** in opt-in controlled runs. Version1.179.0. Real Python fixture imports one High/Low-confidence candidate at line7; JS one Medium/Low candidate at line2; safe counterparts absent. Elapsed1.725s/1.610s. Bundled rules compile and execute; exact trusted rule path/arguments captured in [Semgrep evidence](PHASE_22_SEMGREP.json). Temporary directories cleaned. Missing-tool/timeouts/nonzero/malformed SARIF exercised by existing tests. This operational PASS coexists with the new matching-name false positive.

## 10. CodeQL

**INSTALLED / ENABLED / INVOKED / COMPLETED / RESULTS IMPORTED: YES** through actual `run-local.sh` environment and temporary test hook replacing only Flask serving. Cached installed query packs resolve in private subprocess HOME; no downloads or builds. [CodeQL evidence](PHASE_22_CODEQL.json) includes exact create/analyze commands, raw SARIF locations, persisted provenance and cleanup.

| Repository fixture | Duration | Imported CodeQL candidates | Final merged findings | Status/cleanup |
|---|---:|---:|---:|---|
| Python |13.479s|1|1|Completed / removed|
| JavaScript |20.809s|1|1|Completed / removed|
| Mixed |42.225s|2|2|Completed / removed|

Python positive line7; JS positive line2; no safe fixture reports. Informational note/none notifications no longer make successful runs Partial. Genuine failure, missing packs and malformed SARIF remain covered by regressions. The Python path contains engine-reported source endpoints at line1; these are not independently verified source expressions, and UI evidence explicitly qualifies engine paths. Do not overstate path precision or general accuracy.

## 11. Live Ollama

Endpoint `http://127.0.0.1:11434`, installed `qwen2.5-coder:3b`. Native tags/show/chat calls observed with actual HTTP200. Existing20s request limit,3000 output-token budget,60s keep_alive unchanged. Seven real chat requests across five findings; repository reviews use two passes. Request hashes, minimized redacted context, response timings, saved reviews and final composition are in [live evidence](PHASE_22_LIVE.json). No model settings changed and no synthetic credential literal retained in payload/UI evidence.

| Case | Chat requests | Seconds per chat | Validation/storage | Final choice | Finding page |
|---|---|---|---|---|---|
'''+ '\n'.join(ai)+'''

Five accepted/saved, zero validation rejections in this live sample; **three selected**, two deterministic retained because review evidence remained Needs Review. All final pages have one recommendation, all scan pages HTTP200, temporary DB integrity`ok`. SQL/secret actually run the repository queue with synthetic ZIP; website cases run existing detector modules on controlled response fixtures and the completion callback. Website full queue behavior is separately tested in the local end-to-end suite, not misrepresented as live internet scanning.

Quality assessment: XSS advice uses text rendering without fabricated backend source; header suggestion is exact supported `nosniff`; SQL deterministic bound-parameter guidance retained; secret rotation/runtime configuration retained with values masked. No-code banner recommendation stays text-only, but its generic action says to merge an example when none exists (A22-09). Accepted guidance is chiefly a model selection from grounded deterministic statements, not unrestricted original repair generation. No source-specific generated patch was proved correct by this sample. Static syntax/schema success is not exploit verification or a guarantee of remediation.

Failure checks ([evidence](PHASE_22_FAILURES.json)): unavailable and timeout mocks stop provider processing after one call; actual tags with absent model name uses fallback. Invalid, unsafe and unsupported responses are independently rejected while subsequent candidates continue (three calls, no retries on one finding). Every case leaves scan Completed, original finding unchanged, base retained, zero AI rows and one recommendation. Dedicated Phase19 tests verify per-finding rejection versus provider outage, candidate/global budgets. Grounding/prompt-injection tests cover selected malicious strings, not exhaustive adversarial robustness.

## 12. Frontend, backend, database and reports

**HTTP/template PASS; actual browser behavior NOT TESTED.** Playwright/Selenium absent; no browser automation capability available; no installation undertaken. Responsive pixels, JS execution/polling, keyboard/screen-reader behavior and browser-enforced CSP were not verified. No screenshots fabricated.

-34 route checks meet expected responses;8 navigation URLs200; empty state visible. Deliberately mocked database outage produces the expected sanitized500 (not an unexpected test failure).
-Queued/Running responses expose polling markup/progress; Completed/Failed stop polling. Failed state has failure warning; partial coverage visible in all fixture states. Static markup checks do not prove JavaScript execution.
-Dashboard four scans and totals come from temporary persisted rows, not placeholders. Finding severity, confidence, evidence, single recommendation and AI indicator checked in tests/live fixture pages.
-27 database/report checks pass: schema/foreign keys/WAL, connection reuse/teardown, rollback, bounded writer lock, integrity, risk empty/all severities/ignored/rounding/large, malformed-data handling, redaction and escaping.
-HTML/JSON/CSV for emptyCompleted, emptyFailed and populated scans yield valid downloads. Report metadata failure removes orphan output; malformed module report400, scan display200, malformed comparison400.
-Comparison absence is displayed as RESOLVED with explicit no-proof warning. It does not establish an actual fix.
-Actual HTTP end-to-end test includes both scan submissions, status polling, triage, report generation, comparison, restart and history persistence.

Evidence: [UI](PHASE_22_UI.json), [database/reports](PHASE_22_DATABASE.json), focused/full logs. PDF is not an existing supported generated format and was not added.

## 13. Security/privacy findings and remaining limitations

No successful SSRF, archive traversal, shell injection, application SQL injection, CSRF bypass, stored-HTML execution or real-key leakage was reproduced in the sampled checks. This is not a security certification. Parameterized SQLite, Jinja escaping, secret redaction, loopback-only Ollama/no redirects/proxies, trusted Host validation, CSRF, CSP, no-store and private external-engine environments pass sampled tests. Address-policy22 decisions, queue4 admissions/fifth rejection, maximum one worker, header/CSRF and permissions outcomes: [security evidence](PHASE_22_SECURITY.json).

Issues below separate observed behavior from conditional impact; severity is audit impact, not scanner finding severity.

| ID | Severity / classification | Component, precondition and impact | Reproduction / expected → actual | Minimal recommendation | Blocks supervised demo / production |
|---|---|---|---|---|---|
| A22-01 |High conditional deployment gap, confirmed absent control|No application authentication/tenant isolation. Requires access to app (another local process, shared proxy or changed deployment). Other reachable clients can read shared findings and submit work; not a proven remote bypass of default loopback.|Fresh test client GET dashboard/findings200 without login; valid local CSRF session can submit. Expected for shared hosting: identity/authorization; actual single-user app. HTTP/UI/end-to-end evidence and app.py.|Keep loopback/single-user. Before hosting require authenticated access, ownership/isolation, target authorization and operational deployment review.|No with private local boundary / Yes|
| A22-02 |Medium conditional confidentiality risk|Pre-existing0755 data dir +0644 DB under tested umask, with traversable parents permits shared-account reading. Cross-account exploit not executed.|Security helper creates disposable existing0755 dir; initialization leaves0755/0644. Fresh0700 dir protects DB despite0644. Expected restrictive existing storage; actual mkdir doesn't tighten it.|Review ownership, directory/database permissions and backups before shared-machine use; do not change user files silently.|Conditional / Yes for shared storage|
| A22-03 |Medium detection gap, confirmed|DOM XSS sink omission can miss a real vulnerable pattern.|Frozen `dom_adjacent` decoded input→insertAdjacentHTML main.js:2, expectedpositive, actual no finding both runs.|Add narrowly scoped sink/flow coverage with safe counterpart regressions only after approval.|No if disclosed / Blocks claims of broad detection, not a standalone hosting exploit|
| A22-04 |Low policy coverage gap, confirmed|HMAC digest callable not recognized under frozen weak-primitive policy; no demonstrated practical forgery.|`crypto_hmac_md5` main.py:3 expectedpolicypositive, actualnone both runs.|Clarify supported crypto policy and callable identity before any targeted change.|No / No alone|
| A22-05 |Low false-positive defect, confirmed|Semgrep matching-name SQL rule yields misleading High-severity/Low-confidence candidate for printing.|`sql_local_display` Printer.execute main.py:5 expectednegative; customTN, combinedFP.|Review external rule receiver identity narrowly; preserve genuine SQL positives.|No if triaged / Quality limitation|
| A22-06 |Low observation/uncertainty limitation, confirmed|D08 checksum observations and D09 context-free opaque secret remain indistinguishable from source alone.|Original54: crypto_checksum/java_checksum informationalLow FP; secret_custom_name FN. Holdout unknowns separately ambiguous.|Preserve uncertainty; seek supported usage evidence, do not flag arbitrary entropy or erase observations to inflate scores.|No if disclosed / Accuracy limitation|
| A22-07 |Low hardening gap, mechanism confirmed; abuse theoretical|Nmap subprocess inherits environment and capture_output has no byte cap. Requires unexpected trusted-tool output or replaced local binary; no exfiltration/DoS demonstrated.|[Nmap mock](PHASE_22_NMAP.json): env omitted, capture_outputTrue, timeout bounded, shellFalse. Expected same isolation/output limits as engines; actual different runner.|Consider reusing bounded sanitized subprocess handling after approval; trust installed tool path.|No under trusted tool assumption / Review before hostile multi-user hosting|
| A22-08 |Low usability mismatch, confirmed|Website form suggests query URL, but default safety rejects it; confusing safe behavior, not a replay bypass.|templates/website_scan.html placeholder `?q=example`; replay test proves unreviewed baseline skipped/Failed. Expected advice explains prerequisite; current help omits trusted query review.|Clarify query review requirement/placeholder without weakening policy.|No, prepare inert fixture / No security blocker|
| A22-09 |Low recommendation clarity defect, confirmed|No-code banner action mentions merging an example that does not exist; low-information guidance, not unsafe generated code.|LIVE no_code_banner final examples[] with action “merge the example into your existing configuration”. Expected text-only actionable banner guidance; actual generic text. Base already contains it; AI selects it.|Improve existing deterministic no-code wording and grounded alternatives after approval; preserve one panel.|No if disclosed / No alone|

Other inspected operational limits: no cancellation endpoint (404), in-process single worker and restart marking interrupted jobs Failed rather than durable resumption; DNS caller timeout cannot kill every native lookup; bounded runner is not an OS network/filesystem sandbox. Resource bounds reduce risk but no sustained DoS, kill/power-loss torture, scanner-binary compromise, filesystem ACL attack or exhaustive parser fuzzing was conducted. Per-user quotas, identity-backed target ownership, production monitoring and recovery are not implemented/verified deployment guarantees. No discovered secret was authenticated.

## 14. Deployment readiness

| Use | Verdict | Conditions / blockers |
|---|---|---|
|Local development|Ready within documented single-user scope|Trusted local machine, existing venv/tools, isolated fixtures, correct launcher; review coverage and findings|
|Controlled academic demonstration|Conditionally Ready|Loopback only; authorized inert lab/repo; preflight model/tool availability; explain FP/FN, conservative skipped queries, optional AI and non-exploit proof; retain deterministic fallback|
|Private limited deployment|Not Ready as shared/network service|No auth/tenant isolation, target ownership enforcement, robust service/queue recovery or deployment security verification. A private single-user local demo is covered above|
|Public production deployment|Not Ready|All private-service blockers plus rate limits/quotas, hardened service/network/secret handling, monitoring, recovery, broader independent testing and deployment review|

## 15. Remaining D08/D09

D08 is PARTIAL: known explicit nonsecurity hashlib intent and safeCRC cases behave correctly; unknown digest purpose still emits informationalLow observations. Original benchmark labels know the caller's intent while code does not. Do not hide these findings or rename ambiguous cases to boost precision.

D09 is PARTIAL: holdout direct database password literal, aliased HTTPBasicAuth credential and env-file candidate detected; environment runtime value, public UUID and fixture placeholder remain negative. The original opaque custom constant has no supported format/use information and stays FN under its frozen contract. Holdout analogous unknown is separately ambiguous from the outset. Supported API usage improves detection; arbitrary strings cannot reliably be classified solely by names/entropy.

## 16. Prioritized remediation backlog (recommendations only)

1. For any network deployment, establish an approved authenticated/isolation and target-authorization boundary; otherwise keep local-only (A22-01).
2. Address demonstrable detection-quality gaps with narrow regressions: DOM sink coverage and Semgrep receiver identity (A22-03/05), retaining this consumed holdout for regression, not future independent validation.
3. Review existing data-directory/DB permission handling on shared machines (A22-02).
4. Bring optional Nmap environment/output controls into parity with bounded external engines without expanding scan scope (A22-07).
5. Correct query-form prerequisite wording and no-code remediation wording (A22-08/09); clarify HMAC policy and retain D08/D09 uncertainty (A22-04/06).

No item was implemented. A fresh independent dataset would be required to estimate generalization after future tuning. These are not guarantees that all false positives/negatives can be removed.

## 17. Final readiness verdict

All338 regressions and sampled local workflows pass. Operational integration works; accuracy and real-model guidance remain qualified. The project is suitable for a **supervised local capstone demonstration with disclosed limitations**, and academic discussion of both successful and failed cases. It is **not production-ready**, and passing tests must not be presented as a security or remediation guarantee.

No scanners, rules, schema, AI prompt/model/timeouts, frontend, risk calculation, production application files or existing user history were changed by Phase22. Only new audit artifacts and the progress tracker were updated. Audit stops here pending explicit approval for fixes.

## 18. Limitations, discrepancies and reproducibility

NOT TESTED: live GitHub/private credentials; real OSV service; CodeQL holdout accuracy; live Nmap detection accuracy; real browser/JS/accessibility/responsive rendering; authenticated crawling; public targets; sustained concurrent load; multi-user authorization; OS sandbox/ACL isolation; production server/TLS/proxy; disaster recovery. No real-model rejection occurred in these five live samples; rejection evidence is explicitly mocked. No universal AI factual correctness claim.

Current architecture/context accurately describes automatic Ollama, single final recommendation, Phase20 boundary and partial D08/D09. Historical reports remain historical. Two active UX mismatches are A22-08/09. The unchanged legacy benchmark runner writes `codeql: Not evaluated: unavailable`; in this audit it means **not evaluated in that benchmark**, not absent from this computer: fresh real CodeQL evidence supersedes that stale metadata. No production evaluator string was edited during audit.

### Commands and artifacts

All commands run from the actual checkout using existing venv. Helpers are retained in [phase22_evidence](phase22_evidence/) for inspection/replay. Original `/tmp` commands:

```text
.venv/bin/python -B /tmp/phase22_baseline.py
.venv/bin/python -m pip check
.venv/bin/python -B /tmp/phase22_tests.py --full
.venv/bin/python -B /tmp/phase22_freeze.py
.venv/bin/python -B /tmp/phase22_holdout.py
.venv/bin/python -B /tmp/phase13_bench.py --output docs/audit/PHASE_22_FROZEN_BENCHMARK.json --semgrep /opt/homebrew/bin/semgrep
.venv/bin/python -B /tmp/phase22_http.py
.venv/bin/python -B /tmp/phase22_security.py
.venv/bin/python -B /tmp/phase22_database.py
.venv/bin/python -B /tmp/phase22_ui.py
.venv/bin/python -B /tmp/phase22_semgrep.py
.venv/bin/python -B /tmp/phase22_launch.py
.venv/bin/python -B /tmp/phase22_live.py
.venv/bin/python -B /tmp/phase22_failures.py
.venv/bin/python -B /tmp/phase22_focused.py
.venv/bin/python -B /tmp/phase22_website.py
.venv/bin/python -B /tmp/phase22_nmap.py
```

Completed evidence exists for all listed checks; full/focused test exit0 recorded. Native engine exact args and timing in their JSON. No hidden engine installs. The launcher verification helper needs archived `launcher_hook/sitecustomize.py` restored to `/tmp/phase22-hook` and `phase22_launcher_verify.py` to its original `/tmp` location; hook calls the current app with temp storage. Running helpers again replaces same-named audit evidence, so copy the audit to a new output namespace to preserve this run. Freeze helper must not be used to relabel an evaluated dataset.

Supporting logs contain only synthetic redacted findings, no actual user secrets. Model quality evidence is local-fixture data, not private repository content. Evidence JSONs distinguish raw imported engine candidates, merged findings, AI reviews and final display choices. Browser screenshots were unavailable rather than inferred.
'''
(out/'PHASE_22_FINAL_READINESS_AUDIT.md').write_text(report)
print('report written',len(report),'protected unchanged',len(b['protected_files']))
