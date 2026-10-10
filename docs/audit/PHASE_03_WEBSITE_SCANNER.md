# Phase 03 — Existing website scanner audit

Date: 2026-10-08. Scope: testing only. No application code, detection modules, rules, coverage, settings or user database changed. All actual connections targeted loopback. DNS, adverse certificates and error boundaries used safe mocks. No public scanning, destructive payload, paid service, dependency installation or next phase.

Working directory: `/Users/kribeshthapa/Developer/Vibe code/SentinalScan`. Interpreter: existing `.venv/bin/python` (3.13.5). Required documents read: CLAUDE.md, then project-overview, architecture, ui-context, code-standards, ai-workflow-rules and progress-tracker under context; AGENTS.md; Phase 01 and Phase 02 audit reports. All present. Prior CodeQL pack/status limitations are unchanged and outside this phase.

## Summary

- **20 existing selected unittest methods passed, 0 failed/skipped:** website suite (9), finding context suite (7), selected hardening/network tests (3), finding schema/fingerprint test (1).
- **66 additional module characterization cases** and **13 live-transport/safety cases** passed their stated behavior assertions. These counts are not an accuracy score. Several cases intentionally reproduce undesirable behavior and still pass the characterization assertion.
- Real HTTP and trusted/untrusted local TLS fixtures exercised the pipeline. Installed Nmap 7.991 and real TCP fallback were tested on 127.0.0.1 only.
- Overall **PARTIAL**: conservative supported behavior works, but false-positive indicators, a framing-policy false negative and a resource-discovery false negative were reproduced. Missing coverage is recorded below.

## Actual architecture inspected

All 12 entries in `scanner/website_scanner.py:MODULES` were inspected: DNS, Ports, HTTP, Security headers, Cookies, TLS, Technologies, Resources, CORS, Reflected XSS, SQL injection, Information disclosure. Also inspected target.py, common.py, http_scanner.py, integrations/resolver.py, analysis/finding_engine.py, existing local lab and relevant tests. HTTP is the shared transport plus `http_run`; DNS reports the validated/pinned snapshot, not a DNS vulnerability detector.

## Module test matrix

PASS means supported checks matched the specified expectation; PARTIAL means gaps/heuristics remain. A row mentioning a failure path means the failure was handled, not that the audit command failed. Offline module checks use synthetic Response objects; real transport/pipeline tests supplement them.

| Module | Known vulnerable/positive → actual | Known secure/negative → actual | Malformed/error | Timeout/unavailable | Assessment |
|---|---|---|---|---|---|
| Target/URL validation | Private loopback without opt-in and metadata targets → rejected; authorized loopback → pinned | IPv4/IPv6 lab opt-in accepted, fragment dropped, query display redacted | Schemes, credentials, controls, backslash, ambiguous numeric IP, invalid ports, traversal paths rejected | DNS failures rejected before scan | PASS tested boundaries; state-changing query caveat below |
| DNS | Mixed metadata/loopback answers → TargetError | Mock A/AAAA/CNAME snapshot preserved; literal localhost avoids external DNS | NXDOMAIN/timeout-style mock → system fallback; invalid/unsafe address rejected | Both resolvers unavailable → TargetError | PASS supported inventory/safety; live DNS not tested |
| HTTP | Local 200/redirect responses captured; no vulnerability assigned for HTTP status alone | Same-origin redirect works; no cookie replay; GET only | Malformed HTTP → RequestFailure; external redirect recorded but not followed; loop capped | Local delayed response fails at ~0.101 s with 0.1 s setting; closed service fails | PASS |
| Security headers | Missing HTTPS HTML protections → 6 findings; unsafe-eval, bad nosniff, unsafe-url and max-age=0 detected | Complete strict set → 0; non-HTML → not assessed | Invalid tested values detected; missing baseline → SkipModule | Inherits baseline failure, no extra network | PARTIAL: frame-ancestors wildcard accepted as protection (FN) |
| Cookies | Missing flags → 3 Low/High-confidence findings; SameSite=None without Secure → specific finding plus missing flags | Secure/HttpOnly/SameSite=Lax → 0 | Malformed header counted unparsed, no fabricated cookie; no baseline → skipped | Inherits baseline failure | PASS supported flag checks; sensitivity is not inferred |
| TLS/SSL | Live self-signed untrusted cert → Medium/High trust finding; mocked near-expiry → Low/High; weak negotiated TLS → Medium/High | Live local certificate trusted with explicit test CA → verified; mocked modern 60-day cert → no findings | Malformed DER throws ValueError at module boundary; worker has generic failure handling | Mock timeout/OSError → available=false, no invented certificate finding | PARTIAL: one handshake only; unavailable result can appear module Completed |
| Nmap ports/services | Real Nmap reports local fixture port/service; mocked open XML reports https/version | Closed mocked XML → empty inventory, no vulnerability | Malformed XML → TCP fallback | Mock process timeout/unavailable → TCP fallback; real unavailable executable branch uses bounded connect inventory | PASS tested supported inventory; open port is never itself a finding |
| Technology fingerprinting | nginx, jQuery, WordPress markers → 3 observations | Neutral response → no finding/technology | Malformed HTML parses without crash; baseline missing → skip | Inherits baseline failure | PASS observation contract, not validated product identification |
| CORS | Untrusted origin+credentials → Medium/Medium; reflection alone → Low/Low; wildcard+credentials → Informational/High | Trusted origin or public wildcard without credentials → no finding | Invalid origin/value → no claim; missing baseline → skip | Probe RequestFailure propagates to worker failure | PASS supported GET-only checks; no authenticated read/preflight proof |
| Exposed resources | Git branch HEAD, env-style assignments, directory-index title → expected Medium/High, High/Medium, Low/High findings | 403 and soft missing responses → no finding | Traversal/path count invalid → rejected; failed individual resource retained as unavailable and other paths continue | Missing-page probe failure aborts module; per-resource failure is a row | PARTIAL: same-status similar-length HTML can hide real directory listing (FN) |
| Reflected XSS | Marker in executable script/event handler → Potential Reflected XSS, Low/Low | Ordinary HTML text/attribute or no reflection → no finding | Nonexecuting application/json script also triggers (FP indicator); no baseline → skip | Probe failure propagates | PARTIAL: context indicator, no encoding bypass or execution tested |
| SQL injection | New SQLite error after quote → Potential SQL Injection, Medium/Medium | Pre-existing same error, generic status/length-only changes → no finding | Documentation mentioning new error name triggers indicator (FP); baseline missing → skip | Probe failure propagates | PARTIAL: database-specific error indicator, not injection proof |
| Information disclosure | Traceback signature → Low/High; version banner/source map → Informational | Generic error/neutral body → no finding | Incomplete signature ignored; tutorial text matching signature flags (FP); baseline absent → skip | Inherits baseline failure | PARTIAL: content matching cannot distinguish documentation from live error |
| Finding contract/persistence | Website source, normalized location, allowed severity/confidence and structured probe observations verified | Cookie values, query values, raw env content absent from persisted lab records | Invalid confidence/severity/source/foreign key and duplicate fingerprints rejected | Module failure retains earlier findings; interrupted jobs marked failed | PASS selected existing tests |

## Reproduced false positives and false negatives

These are comparisons with authored fixture ground truth, not production accuracy estimates. No exploit execution was performed.

| ID | Fixture ground truth | Expected finding behavior | Actual | Accuracy verdict |
|---|---|---|---|---|
| FP-1 | `application/json` script contains JSON-serialized harmless marker; not executable script | No XSS vulnerability claim | Potential Reflected XSS Low/Low | FAIL for distinguishing executable contexts; conservative label reduces but does not remove noise |
| FP-2 | Probe response is documentation describing sqlite3.OperationalError, not a database exception | No SQL injection indication from known documentation-only fixture | Potential SQL Injection Medium/Medium | FAIL for semantic distinction; pattern cannot prove execution |
| FP-3 | Baseline is tutorial text quoting Python traceback heading | No live application-error disclosure claim | Verbose application error disclosure Low/High | FAIL for context distinction |
| FN-1 | CSP has `frame-ancestors *` with no X-Frame-Options; embedding is unrestricted | Flag ineffective framing restriction | No framing finding; `framing_protection=true` | FAIL; substring presence is treated as effective protection |
| FN-2 | Missing URL gives HTTP 200, 45-byte HTML; real uploads page has directory-index title of similar length | Directory listing finding | Suppressed as possible_soft_404 | FAIL; <80-byte length heuristic is overly broad |

Other limits are **NOT TESTED**, not measured false negatives: DOM-only XSS, blind/time-based SQLi, authentication, form submission, browser execution, all TLS protocol support, generic sensitive-file discovery beyond implemented paths/signatures. The scanner does not promise these behaviors. No new detection modules are proposed here.

## Safety and conservative behavior

- Default transport configuration, inspected: 60 requests, 262,144 bytes/response, 0.2-second minimum request interval, 12-second request timeout, 150-second client budget, five redirect attempts. Live reduced-limit tests confirm the same enforcement branches: request count=1, bytes=32, deadline=0, interval=0.1 s (observed ~0.106 s).
- HTTP connections use validated pinned IPs. Existing test forbids DNS re-resolution; metadata/out-of-scope redirect is blocked without contacting it. Only loopback was contacted during this audit.
- TLS verification stays enabled for HTTP data. Unverified fallback is certificate inspection only. Live self-signed certificate is accepted only when explicitly trusted by the temporary test CA.
- XSS uses alphanumeric markers; SQLi appends a single quote. No destructive, UNION, delay or extraction payload. Status/length deltas alone do not create SQL findings. Plain text/ordinary attributes do not create XSS findings.
- Probe generation limits itself to first five query pairs and skips dangerous/sensitive parameter names as mutation targets. **PARTIAL safety limitation:** untouched query pairs remain in each generated URL. A URL already containing `action=...` can therefore replay that value while probing another parameter. No state-changing handler was contacted/tested; this is an inspected and generated-URL behavior, not demonstrated destructive execution.
- Resource list limited to 15 paths with traversal restrictions; 200/401/403 alone is not a vulnerability. Soft-404 filter is heuristic.
- Ports limited to target port plus 80/443/8000/8080/8443. Nmap uses TCP connect, version-light, no name lookup, one retry, 15s host timeout/at most 18s process timeout. No shell invocation. Real audit target was 127.0.0.1. Fallback labels service guesses unverified. Nmap stdout is captured before parsing, without an explicit byte cap in this module (static observation, not stress-tested).
- Single worker and four queue slots are code-inspected, not stress-tested in this phase. Total client deadline bounds requests but is not a preemptive wall-clock limit for every Python parsing operation; initial DNS validation precedes that budget.
- Technology, DNS and port inventories do not generate vulnerability findings. A scan marked Completed is not a clean bill of health: HTTP baseline success permits overall Completed even if another module failed. TLS unavailable, unparsed cookies and resource-request errors can return observation data without a Failed module state. Those presentation/coverage semantics were inspected, not changed.

## Test execution and reproducible evidence

[Full case inputs/helper source, findings, contexts, observations, elapsed times and logs](PHASE_03_WEBSITE_SCANNER.evidence.json).

Audit scripts were temporary and never added to application modules:

```sh
.venv/bin/python -B /tmp/phase03_existing.py > /tmp/phase03_existing.log 2>&1
.venv/bin/python -B /tmp/phase03_matrix.py > /tmp/phase03_matrix.log 2>&1
.venv/bin/python -B /tmp/phase03_network.py > /tmp/phase03_network.log 2>&1
/opt/homebrew/bin/nmap --version
```

The evidence JSON embeds those exact scripts. Recreate them from project root with:

```sh
.venv/bin/python -B - <<'PYREPRO'
import json
from pathlib import Path
bundle=json.loads(Path('docs/audit/PHASE_03_WEBSITE_SCANNER.evidence.json').read_text())
for name,source in bundle['scripts'].items():
    Path('/tmp',name).write_text(source)
PYREPRO
```

The existing-test helper uses unittest discovery for `test_website_scanner.py` and `test_finding_context.py` and explicitly loads:

- `test_hardening.HardeningTests.test_malformed_nmap_falls_back_without_shell`
- `test_hardening.HardeningTests.test_dast_persistence_masks_credentials_and_form_errors`
- `test_network_reliability.NetworkReliabilityTests.test_browser_fragment_is_not_sent_or_persisted`

It sets a temporary SENTINELSCAN_DATA_DIR before constructing any app, plus AI disabled. Result: **19 passed in 1.146 seconds**.

Additional schema test command:

```sh
.venv/bin/python -B - <<'PYCONTRACT'
import os,sys,tempfile,unittest
sys.path[:0]=[os.getcwd(),os.path.join(os.getcwd(),'tests')]
with tempfile.TemporaryDirectory(prefix='phase03-contract-') as td:
    os.environ['SENTINELSCAN_DATA_DIR']=td
    os.environ['SENTINELSCAN_LLM_ENABLED']='false'
    suite=unittest.defaultTestLoader.loadTestsFromName('test_foundation.FoundationTests.test_schema_constraints_and_fingerprint')
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
PYCONTRACT
```

Result: **1 passed in 0.048 seconds**. Full project test suite was not run for this scoped website audit. The fixture HTTP server emitted a ConnectionResetError traceback during Nmap version probing; this was a reset of the disposable lab connection, not a scanner failure. The original log is preserved.

## Case-by-case observed results

PASS below means the characterization expectation held; refer to the accuracy table for intentionally reproduced failures. “DNS empty fallback” supplies a deliberately contract-breaking empty mock: target validation accepts it, but the real system resolver raises on empty results, so this is not claimed as a production DNS bug.

| Case | Behavior assertion | Actual finding titles or result | Time (s) |
|---|---|---|---|
| headers missing | PASS | Missing Content-Security-Policy, Missing X-Content-Type-Options, Missing Referrer-Policy, Missing Permissions-Policy, Missing or invalid framing protection, Missing or disabled HSTS | 0.002 |
| headers secure | PASS |  | 0.0 |
| headers invalid values | PASS | Permissive Content-Security-Policy, Invalid MIME sniffing protection, Missing or invalid framing protection, Permissive Referrer-Policy, Missing or disabled HSTS | 0.001 |
| headers non HTML | PASS |  | 0.0 |
| headers wildcard framing FN | PASS |  | 0.0 |
| cookie sid=FixtureValue | PASS | Cookie missing Secure: sid, Cookie missing HttpOnly: sid, Cookie missing SameSite: sid | 0.001 |
| cookie sid=FixtureValue; Secure; HttpOnly; SameSite=Lax | PASS |  | 0.0 |
| cookie sid=FixtureValue; SameSite=None | PASS | Cookie missing Secure: sid, Cookie missing HttpOnly: sid, SameSite=None cookie without Secure: sid | 0.001 |
| cookie not a valid cookie | PASS |  | 0.0 |
| CORS https://sentinelscan-probe.invalid true | PASS | Potential unsafe credentialed CORS | 0.0 |
| CORS https://sentinelscan-probe.invalid  | PASS | Potential arbitrary CORS origin reflection | 0.0 |
| CORS * true | PASS | Incompatible wildcard credentialed CORS | 0.0 |
| CORS https://trusted.invalid true | PASS |  | 0.0 |
| CORS *  | PASS |  | 0.0 |
| CORS not-an-origin bad | PASS |  | 0.0 |
| XSS script | PASS | Potential Reflected XSS | 0.0 |
| XSS event | PASS | Potential Reflected XSS | 0.0 |
| XSS text | PASS |  | 0.0 |
| XSS attribute | PASS |  | 0.0 |
| XSS none | PASS |  | 0.0 |
| XSS serialized | PASS | Potential Reflected XSS | 0.0 |
| SQL new SQLite | PASS | Potential SQL Injection | 0.001 |
| SQL baseline SQLite | PASS |  | 0.0 |
| SQL status only | PASS |  | 0.0 |
| SQL documentation FP | PASS | Potential SQL Injection | 0.0 |
| disclosure trace | PASS | Verbose application error disclosure | 0.0 |
| disclosure safe | PASS |  | 0.0 |
| disclosure documentation FP | PASS | Verbose application error disclosure | 0.0 |
| disclosure malformed | PASS |  | 0.0 |
| version and sourcemap | PASS | Server or framework version disclosed, Source map reference disclosed | 0.0 |
| technology indicators | PASS |  | 0.0 |
| technology secure neutral | PASS |  | 0.0 |
| technology malformed html | PASS |  | 0.0 |
| resources positive | PASS | Potential exposed environment configuration, Exposed Git metadata, Directory listing enabled | 0.001 |
| resources secure | PASS |  | 0.0 |
| resources soft | PASS |  | 0.0 |
| resources timeout | PASS | Exposed Git metadata, Directory listing enabled | 0.0 |
| resources similar length FN | PASS |  | 0.0 |
| scanner.header_scanner baseline unavailable | PASS | ; SkipModule: No usable HTTP response; prerequisite request failed. | 0.0 |
| scanner.cookie_scanner baseline unavailable | PASS | ; SkipModule: No usable HTTP response; prerequisite request failed. | 0.0 |
| scanner.cors_scanner baseline unavailable | PASS | ; SkipModule: No usable HTTP response; prerequisite request failed. | 0.0 |
| scanner.xss_scanner baseline unavailable | PASS | ; SkipModule: No usable HTTP response; prerequisite request failed. | 0.0 |
| scanner.sqli_scanner baseline unavailable | PASS | ; SkipModule: No usable HTTP response; prerequisite request failed. | 0.0 |
| scanner.disclosure_scanner baseline unavailable | PASS | ; SkipModule: No usable HTTP response; prerequisite request failed. | 0.0 |
| scanner.directory_scanner baseline unavailable | PASS | ; SkipModule: No usable HTTP response; prerequisite request failed. | 0.0 |
| scanner.technology_scanner baseline unavailable | PASS | ; SkipModule: No usable HTTP response; prerequisite request failed. | 0.0 |
| scanner.cors_scanner timeout | PASS | ; RequestFailure: fixture timeout | 0.0 |
| scanner.xss_scanner timeout | PASS | ; RequestFailure: fixture timeout | 0.0 |
| scanner.sqli_scanner timeout | PASS | ; RequestFailure: fixture timeout | 0.0 |
| scanner.directory_scanner timeout | PASS | ; RequestFailure: fixture timeout | 0.0 |
| DNS pinned | PASS |  | 0.001 |
| DNS timeout fallback | PASS |  | 0.0 |
| DNS unavailable | PASS | ; TargetError: Both direct DNS and the system resolver failed. Check this Mac’s network/VPN/DNS connection and retry. | 0.0 |
| DNS empty fallback | PASS |  | 0.0 |
| DNS unsafe mixed | PASS | ; TargetError: Link-local, metadata, multicast, unspecified and reserved addresses are blocked. | 0.0 |
| Nmap open | PASS |  | 0.001 |
| Nmap closed | PASS |  | 0.0 |
| Nmap malformed | PASS |  | 0.0 |
| Nmap timeout | PASS |  | 0.0 |
| Nmap unavailable | PASS |  | 0.0 |
| TLS secure | PASS |  | 0.009 |
| TLS expiry | PASS | TLS certificate expires soon | 0.001 |
| TLS weak | PASS | Weak negotiated TLS configuration | 0.001 |
| TLS malformed | PASS | ; ValueError: error parsing asn1 value: ParseError { kind: ShortData { needed: 96 } } | 0.0 |
| TLS timeout | PASS |  | 0.013 |
| TLS unavailable | PASS |  | 0.005 |
| HTTP same-origin redirect GET only no cookie replay | PASS | {"redirects": [{"status": 302, "from": "http://127.0.0.1:53960/redirect", "to": "http://127.0.0.1:53960/", "followed": true}], "no_cookie_replay": true} | 0.003 |
| HTTP /bad | PASS | {"expected": "RequestFailure", "error": "HTTP request failed or timed out"} | 0.0 |
| HTTP /slow | PASS | {"expected": "RequestFailure", "error": "HTTP connection or response timed out within the scan budget"} | 0.101 |
| HTTP /loop | PASS | {"expected": "RequestFailure", "error": "Redirect limit reached"} | 0.003 |
| HTTP external redirect blocked | PASS | {"status": 302, "from": "http://127.0.0.1:53960/external", "to": "[out-of-scope redirect blocked]", "followed": false} | 0.001 |
| HTTP bytes/request limits | PASS | {"captured_bytes": 32, "truncated": true, "request_limit": true} | 0.001 |
| HTTP deadline | PASS | "Scan time budget reached before request" | 0.0 |
| HTTP rate limit | PASS | {"configured_interval": 0.1, "observed_gap": 0.10611858405172825} | 0.107 |
| Nmap real loopback inventory | PASS | {"commands": [["/opt/homebrew/bin/nmap", "-sT", "-sV", "--version-light", "-Pn", "-n", "--max-retries", "1", "--host-timeout", "15s", "-p", "80,443,8000,8080,8443,53960", "-oX", "-", "127.0.0.1"]], "result": {"method": "Nmap TCP connect/version-light", "address": "127.0.0.1", "tested_ports": [80, 443, 8000, 8080, 8443, 53960], "open_ports": [{"port": 5396... (full evidence JSON) | 6.289 |
| TCP fallback real loopback inventory | PASS | {"method": "TCP connect fallback", "warning": "Nmap is not installed. Bounded TCP connect inventory used; versions are unavailable.", "address": "127.0.0.1", "tested_ports": [80, 443, 8000, 8080, 8443, 53960], "open_ports": [{"port": 53960, "protocol": "tcp", "service": "unknown (port convention; unverified)", "version": ""}]} | 0.001 |
| HTTP unavailable service | PASS | {"expected": "RequestFailure", "error": "Connection unavailable"} | 0.0 |
| parameter probe exclusions and first-five cap | PASS | {"eligible_names": ["q", "other"], "note": "Sensitive parameters not mutated, but original URL query pairs remain in requests."} | 0.0 |
| resource path limits | PASS | "invalid/traversal/over-limit paths rejected" | 0.0 |

## Missing coverage and untested cases

- **NOT TESTED:** live public DNS or remote websites (prohibited scope); resolver behavior is mocked or literal loopback.
- **NOT TESTED:** IPv6 live sockets/Nmap, slowloris-style continuous trickle, actual default 150-second expiry, production-size memory pressure, queue contention, Nmap excessive stdout.
- **PARTIAL:** TLS live trusted/untrusted, mocked expiry/weak/malformed/timeouts covered; expired/not-yet-valid/hostname mismatch error codes, real TLS 1.0/1.1 negotiation, cipher enumeration and certificate-chain variations not independently exercised.
- **PARTIAL:** SQLite differential SQL-error behavior exercised; all MySQL/PostgreSQL/SQL Server/Oracle regex alternatives not individually tested. No SQL exploit success is claimed.
- **PARTIAL:** Python error disclosure tested; Java/PHP/ASP.NET signatures not individually exercised. Technology checks cover three markers, not every product spelling.
- **PARTIAL:** malformed resource path/input and timeout tested; binary content, compressed/chunked responses, duplicate header combinations, detached Git HEAD and varied cookie parser quirks not exhaustively tested.
- **SKIPPED by supported design:** header checks on non-HTML, dependent checks after failed baseline, parameters beyond first five or excluded names.
- **NOT TESTED:** full UI/report rendering, full project suite, authenticated browsing or real exploitability. Existing selected persistence tests check normalization/redaction, not complete product regression.

## Recommended minimal fixes — not implemented

1. Treat restrictive frame-ancestors values separately from mere directive presence; add a regression for `frame-ancestors *`.
2. Exclude nonexecuting script MIME types from the existing XSS script-text classifier. Keep other script-string reflections explicitly unverified; do not claim encoding safety from alphanumeric probes.
3. Avoid dropping strong existing directory-index evidence based solely on similar HTML length; retain an uncertain observation or require stronger soft-404 equivalence.
4. Keep SQL/disclosure matches as low-certainty textual indicators when response context cannot distinguish documentation from live errors; add the demonstrated negative fixtures before adjusting claims.
5. Surface unavailable/unparsed/partial module observations consistently so Completed does not conceal unassessed coverage. Catch malformed certificate parsing with a specific safe module error.
6. For existing probe safety, decline replay of URLs containing state-changing parameters, rather than only skipping mutation of those pairs. Preserve current authorization and request limits.
7. Add an output bound around existing Nmap capture and tests for that bound; do not add port or vulnerability coverage.

No recommendation above has been implemented. Source-code diff check shows no Python/HTML/CSS/JS changes; only audit documentation/progress updates from this task. User data and saved configuration were not changed. Phase 3 ends here.
