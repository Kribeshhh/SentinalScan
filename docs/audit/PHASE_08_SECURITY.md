# Phase 08 — Application security and failure handling

Date: 2026-10-08. **Overall PARTIAL: sampled controls pass; conditional and previously confirmed limitations remain.** Audit only, no security controls or application code changed. No destructive payload execution, public-service testing, real credentials copied or paid services used.

Working directory: `/Users/kribeshthapa/Developer/Vibe code/SentinalScan`; existing `.venv/bin/python`. Read CLAUDE.md, six required context documents in order, AGENTS.md and prior Phase01–07 audit findings. All present. Local single-user loopback application is the documented threat model, not authenticated multi-user hosting.

## Commands and evidence

```sh
.venv/bin/python -B /tmp/phase08_tests.py > /tmp/phase08_tests.log 2>&1
.venv/bin/python -B /tmp/phase08_probes.py > /tmp/phase08_probes.log 2>&1
.venv/bin/python -B /tmp/phase08_dns_retry.py > /tmp/phase08_dns_retry.log 2>&1
git diff --check
```

Initial selected suite: **95 methods:93 passed,1 failed,1 skipped**, 8.562s. The failure was `test_dns_fallback.DNSFallbackTests.test_fixed_service_never_connects_to_private_dns_address`: the audit's blanket `_request_once` guard raised AssertionError before the test could exercise its mocked private DNS boundary. This was a harness interference, not an application security failure. The unchanged test reran with socket.connect forbidden and its own DNS fixture: **1 passed in0.012s**. Aggregate distinct methods verified: **94 passed,1 skipped; no unresolved regression failure**. The optional live Semgrep test was intentionally skipped; external adapters used safe mocks. Full project suite not run.

Suites: hardening, archive_limits, repository_phase2, website_scanner, repository_url, source_scanner, browser_github, dns_fallback, network_reliability, foundation, management, final_validation, restart. Exact qualified test names and both original/retry logs are retained in [evidence JSON](PHASE_08_SECURITY.evidence.json), with executable helper source. Additional observations include22 literal-address policy cases, queue admission, concurrency, CSRF/Host/headers and temporary permissions. No claim of exhaustive penetration testing.

Recreate helpers from project root:

```sh
.venv/bin/python -B - <<'PYREPRO'
import json
from pathlib import Path
bundle=json.loads(Path('docs/audit/PHASE_08_SECURITY.evidence.json').read_text())
for name,source in bundle['scripts'].items():
    Path('/tmp',name).write_text(source)
PYREPRO
```

## Boundary checks

| Boundary | Expected | Observed evidence | Result |
|---|---|---|---|
| SSRF/public scope | Reject unsafe destinations, pin validated addresses | Existing target/pinning/mixed-DNS tests;22 additional literal policy cases below | PASS sampled |
| Local/private labs | Require explicit opt-in; metadata always blocked | Loopback/RFC1918/ULA accepted only with allow_private; mapped loopback same; metadata/link-local/multicast/unspecified rejected even opted in | PASS |
| DNS/redirect | No unchecked re-resolution or out-of-origin follow | Pinned-IP tests, DNS fallback tests, corrected private fixed-service test pass; scope redirect blocked, loop cap tested | PASS sampled |
| GitHub URL/branch | Fixed GitHub HTTPS root and encoded identifiers | Repository URL rejection/normalization, branch/SHA tests, PAT only api.github.com; codeload redirect credentials omitted | PASS supported boundary |
| ZIP safety | Reject traversal/types/bombs and bounded extraction | Existing tests reject traversal, preexisting root, symlink, duplicate/case collision, oversized archives/ratios; excluded/build hooks remain inert; cleanup after retrieval/module failure | PASS sampled |
| Report/source paths | No arbitrary filesystem download | Traversal/symlink report tests pass; ID/filename and source-path validation inspected | PASS sampled |
| File/resource limits | Bound archive/file/tool/request workloads | ZIP64MiB compressed/128MiB expanded/512KiB file/2000 retained files/5000 entries; tool output/timeout tests, HTTP request/byte caps; no large malicious stress load | PASS sampled / PARTIAL hard caps |
| Timeouts | Bounded network/process failures with cleanup | Existing HTTP local timeout and tool trusted-helper timeout pass. DNS/TCP/TLS/HTTP have separate budgets; not a single end-to-end preemptive deadline | PARTIAL scope |
| Subprocess/shell | Argument vectors, trusted executable, no shell expansion | run_tool uses Popen list and isolated Python launcher; environment scrub, timeout/output tests pass. CodeQL no-build args and repo-owned executable rejection; Nmap shell-free fallback test | PASS tested contracts |
| Secret/PAT/API handling | Redact before persistence/provider/export; no error bodies | Existing source/DAST/final-validation tests verify synthetic secrets absent from DB/page/report/log; PAT server-memory behavior and request redaction tested | PASS samples; unknown formats not guaranteed |
| CSRF | Reject missing/wrong tokens before writes | Both supplemental requests400; existing valid/invalid/status/form tests pass; no manual AI or publication route restored | PASS |
| Security headers | CSP and browser hardening on responses | default-src self; script/style self; object-src none; base/frame/form restrictions, nosniff,DENY,no-referrer,no-store; sandbox HTML report view | PASS server headers; browser enforcement not retested |
| Host/session/error | Host allowlist, safe key storage, sanitized failures | Foreign Host400; key symlink/short key tests; exceptions omit bodies; HTTPOnly/Lax cookies, Secure opt-in for HTTPS | PASS documented local policy |
| Database safety | Parameters, constraints, no SQL interpolation from user | Foundation invalid filters/IDs/FKs/duplicates and management tests pass; Phase07 malformed JSON500 remains | PARTIAL robustness |
| Scan queue | One worker/four admitted jobs, excess rejected | Supplemental real executor with inert gated worker:4 accepted/persisted, fifth QueueFull, maximum active1 | PASS |
| External failure | Record failure/skip; retain custom findings | Mock missing binary, timeout/nonzero/invalid SARIF and worker optional-tool failures pass; prior real CodeQL pack failure unchanged | PASS fallback; engine health not certified |
| Interruption/cancellation | Preserve partial records on restart; no invented cancel | Existing restart tests mark active work Failed; shutdown waits. POST /scans/1/cancel with valid CSRF404; no cancellation endpoint implemented | PASS recovery / cancellation NOT IMPLEMENTED |

## Supplemental policy outcomes

For each address, opt-in false/true was tested without making a connection:

| Literal | Without opt-in | With opt-in |
|---|---|---|
| `127.0.0.1` | Rejected | Accepted |
| `10.1.2.3` | Rejected | Accepted |
| `192.168.1.1` | Rejected | Accepted |
| `[::1]` | Rejected | Accepted |
| `[fd12::1]` | Rejected | Accepted |
| `169.254.169.254` | Rejected | Rejected |
| `100.100.100.200` | Rejected | Rejected |
| `[fd00:ec2::254]` | Rejected | Rejected |
| `0.0.0.0` | Rejected | Rejected |
| `224.0.0.1` | Rejected | Rejected |
| `[::ffff:127.0.0.1]` | Rejected | Accepted |

Opted-in private-network access is intentional authorized-lab functionality, not a demonstrated SSRF bypass. Host validation and CSRF restrict browser-triggered actions, but they are not authentication against another process on the same machine.

## Classified findings and limitations

Severity is contextual to the documented local app. Likelihood is qualitative and conditional, not a measured exploit probability.

| ID | Classification | Severity | Likelihood/precondition | Impact | Reproducibility |
|---|---|---|---|---|---|
| S1 | Confirmed permission behavior; conditional confidentiality risk | Medium on shared machine | Existing data directory0755 and traversable parent directories; another local account | SQLite scan/source metadata readable where OS permissions allow | Reproduced temporary existing0755 directory remains0755, DB0644; fresh private0700 directory protects contents. Cross-account access NOT tested |
| S2 | Confirmed probe-generation behavior; potential state-changing replay | Medium conditional | Operator supplies target URL with a state-changing GET parameter alongside probed parameter; server implements unsafe GET action | Repeated unintended action at authorized target | Pure URL helper preserves action while mutating q. No state-changing handler contacted, no destructive impact demonstrated |
| S3 | Confirmed malformed persisted-data robustness defects, Phase07 | Low local availability | Corrupt/legacy/directly altered JSON; normal writer production not observed | Scan display or comparison500 for affected record | Prior audit reproducible; not rerun here; no demonstrated public injection path |
| S4 | Confirmed AI semantic acceptance, Phase05 | Medium advisory risk | Optional AI on and returns schema-valid inaccurate advice, human follows it | Misleading remediation, possible security regression | Mocked unsupported version/framework/header and agreeing bad advice accepted; no real-model frequency or automatic code execution |
| S5 | Inspected Nmap isolation/resource gap, theoretical | Low under trusted-binary assumption | Unexpected tool output or compromised locally selected binary | Memory pressure or inherited environment exposure | Nmap uses capture_output without byte cap and inherits environment; no malicious tool/secret exfiltration tested |
| S6 | Inspected timeout/cancellation limitations | Low availability | Slow/stalled native lookup or unusually expensive parser/tool work | Queue occupancy, delayed completion/shutdown | DNS caller timeout does not kill native daemon lookup; four slots bound outstanding calls. No user cancel endpoint; no exhaustive deadline/DoS test |

**No successful SSRF bypass, ZIP traversal, shell injection, SQL injection into SentinelScan, CSRF bypass or real-key leakage was reproduced in these tests.** This is a statement about sampled evidence, not a security certification.

### S1 reproduction and minimal suggestion

Create an audit-only directory with0755; set SENTINELSCAN_DATA_DIR to it and initialize temporary app. Directory remains0755; new SQLite file0644 under current umask. Fresh directory path created privately is0700 and .secret_key0600. Phase01 observed existing project data permissions consistent with this condition; effective parent ACL/traversal was not evaluated.

Suggestion only: evaluate tightening existing data directory/database permissions with explicit handling of ownership and deployment intent. Do not assume file0644 alone proves other users can traverse private ancestors. No user permissions changed.

### S2 reproduction and minimal suggestion

```python
from scanner.xss_scanner import parameter_urls
from urllib.parse import urlsplit, parse_qs
probes = list(parameter_urls('http://127.0.0.1/?action=fixture-noop&q=hello', lambda _: 'AUDITMARKER'))
assert len(probes) == 1
assert parse_qs(urlsplit(probes[0][1]).query)['action'] == ['fixture-noop']
```

Executed with0 network requests. The function skips mutating action itself but copies it into the probe for q; SQL indicator probes share this helper. Suggestion only: review whole-query rejection/confirmation policy for state-changing inputs rather than treating skipped mutation as no replay. Do not silently remove query values and pretend the target is unchanged.

### Other minimal suggestions, not implemented

- S3: validate persisted JSON shapes and show explicit unavailable evidence instead of generic500; keep comparison uncertainty.
- S4: retain human review and strengthen evidence-grounded advice validation in a separately authorized task; no autonomous application of suggestions.
- S5: consider applying existing subprocess environment/output safeguards to Nmap without expanding scanning. Trusted external tools are not a full OS sandbox: no network/filesystem sandbox is installed by run_tool.
- S6: document segmented budgets and lack of cancellation; do not claim every parser/native call obeys an absolute wall-clock cap. Future interruption changes require explicit scope.

## Safety and coverage limits

All app fixtures used disposable SQLite/data paths and synthetic values, never real API keys or scan history. Archive test strings were inert. The only executed subprocess scripts were trusted test helpers for environment/time/output checks, never downloaded repository code. Local HTTP/TLS labs and mocked failures supplied network behavior. No tool installation or live Semgrep/CodeQL/public-provider assessment this phase.

The shared external network guard intentionally blocked transport in the main runner; one DNS test needed a narrower socket guard to exercise its own validation. Both logs retained. Conditional deployment risks (binding beyond loopback, no multi-user auth, trusted binary replacement) were not demonstrated as remote exploits. Browser enforcement, OS account isolation, power-loss crash recovery, sustained memory/disk exhaustion and exhaustive encoding/address fuzzing NOT TESTED.

Current CSP report style exception is restricted to sandboxed generated HTML and is not evidence of an XSS bypass. Startup recovery updates only audit fixture active records in these tests. No application schema/security/risk/route changes. Only audit artifacts and progress tracker updated. Phase8 stops here.
