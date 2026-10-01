# SentinelScan security review

Phase 5 implementation review, 2026-09-24. This is a code review and regression-test record, not an independent penetration-test certification or a guarantee of vulnerability absence.

## Intended deployment

One trusted user, one local Flask process bound to 127.0.0.1. Only assess explicitly authorized targets. There is no multi-user authentication or tenant isolation. Do not expose the development server to a network. Other processes running as your user can access your environment and local files; protections here do not isolate a compromised operating-system account.

## Review matrix

| Area | Control and verification |
|---|---|
| SQL injection | Request values bound as SQLite parameters; dynamic columns/table names come from fixed application lists. Record IDs are bounded to SQLite's integer range; searches treat `%` and `_` literally. Injection and overflow regressions included. |
| XSS | Jinja autoescaping, textContent in JavaScript, restrictive CSP, escaped report fields, sandboxed HTML preview. Tests inject HTML into findings and reports. |
| CSRF | Random session token with constant-time comparison required on every mutating request; SameSite=Lax, HttpOnly cookies. Missing and invalid token tests. |
| SSRF | Only HTTP/HTTPS, no userinfo, ambiguous hosts or IPv6 zones. DNS snapshot validated and sockets pinned to it; local/private opt-in; link-local/metadata/special ranges blocked even in lab mode. GitHub/OSV use fixed HTTPS hosts. Host allowlist mitigates DNS rebinding against the app. |
| Command injection | Only Nmap is executed, by fixed argv with validated numeric IP/port inventory; shell is never enabled. Repository builds and scripts never run. |
| Path traversal | Validate every ZIP path before extraction, including excluded entries; report access uses numeric database IDs and strict generated basenames. |
| Subprocess safety | Nmap uses connect/version-light checks, no scripts or arbitrary flags, with process timeout and bounded target scope. Missing, failed or malformed Nmap results use TCP fallback. |
| Archive extraction | Compressed/expanded size, count, ratio and path-depth limits. Single root; reject special/encrypted members and duplicate/case-colliding names. No extractall. |
| Symlinks | Archive symlinks rejected; extraction requires a fresh private directory. Report opens use O_NOFOLLOW and a directory descriptor, and require regular files. Session key reads refuse symlinks/nonregular files. The configured project/storage parent directories must remain trusted. |
| Oversized repositories | 64 MiB compressed, 128 MiB expanded, 5,000 entries, 2,000 analyzed files. |
| Oversized files | 512 KiB per source file; bounded HTTP/API responses; capped findings and dependency lookups. |
| Temporary cleanup | TemporaryDirectory removes repository archive and source on completion and handled failure. Both paths tested. A forced OS kill can leave private temporary storage and needs operator cleanup. |
| Secret leakage | Shared masking for findings and observations at persistence/export; known source secrets redacted; URL userinfo and Bearer/Basic credentials masked. Bounded redacted source excerpts are retained; editor drafts can contain full selected files after secret checks. Response bodies are not stored. Secret detection remains heuristic. |
| Report filenames | UUID-generated exclusive files with 0600 permissions; strict extension validation, no caller-supplied path, no arbitrary filesystem serving. CSV formulas neutralized. Failed exclusive creation never deletes a preexisting file. |
| Debug mode | python3 app.py sets debug=False; no reloader or interactive debugger. |
| Error disclosure | Fixed user-facing errors; request error logs contain exception class, not exception message/traceback. Access logs omit paths, targets, query strings and credentials. |
| Redirects | DAST same-origin or same-host HTTPS upgrade, pinned IPs, finite redirect count. GitHub archive redirects restricted to codeload.github.com for the expected repository; auth header not forwarded. |
| User input | URL/repository/branch validation; enum checks; bounded IDs/search/pagination/forms, trusted Host list. Status update values cannot alter SQL. |
| Uploads | No upload feature; unexpected multipart files rejected. Request body, form-memory and part limits configured. Repository retrieval occurs through validated GitHub endpoints. |
| GitHub credentials | Masked browser token entry over loopback HTTP or HTTPS with CSRF validation; optional environment fallback. Verified tokens live in a bounded process-memory store, with only a random handle in the signed session cookie. No token in response HTML, DB, URLs, logs, reports or browser storage. Disconnect/restart clears the saved connection; running authorized work can finish. Read-only privileges recommended. |

## Resource limits and resilience

A single worker shares a four-job admission limit across DAST/SAST. DAST uses bounded GETs and a 150-second module budget, network timeouts and pinned addresses. SAST uses file/finding caps, a checked 180-second analysis budget, tree-sitter parser limits and bounded OSV lookup budgets. Limits are best-effort in-process budgets, not an OS-level sandbox or hard preemption of every native parser/DNS call. Unresolvable website hostnames are rejected before scanning because there is no safe address to pin. Failure of an admitted scan module does not prevent other independent modules from running. DNS/TLS/Nmap/OSV failures remain visible in coverage details. Interrupted jobs are marked Failed on startup; partial data survives.

## Verification

Run `python3 -m unittest discover -s tests -v` and `python3 -m pip check` inside the virtual environment.

- `test_browser_github.py`: browser token submission, authenticated scan, CSRF and transport restrictions, session isolation, invalid credentials, disconnect, eviction and restart; tokens never echoed or persisted.
- `test_foundation.py`: model, risk weights, SQLite constraints, SQL inputs, CSRF, XSS, headers and empty states.
- `test_website_scanner.py`: real loopback HTTP/HTTPS, findings, SSRF, pinned redirects, limits, TLS verification, module failures, migration and interrupted jobs.
- `test_source_scanner.py`: real source fixtures, language parsers, dependency outages, secret masking, archive attacks, GitHub auth boundary and non-execution sentinel.
- `test_management.py`: real scan comparison NEW/RESOLVED/UNCHANGED, filtering, reports, CSV injection, escaping, masking, download traversal/symlinks.
- `test_hardening.py`: integer overflow, unexpected upload/oversize rejection, safe logs/errors, DAST masking, key permissions/symlinks, extraction destination, malformed Nmap fallback, queue limits and cleanup on retrieval failure.
- `test_restart.py`: actual Flask process restart, persistent statuses, repository record and report download.
- `test_end_to_end.py`: real HTTP application subprocess → local educational scan → SQLite/risk → triage → SAST source-fixture scan → three report formats → second scan → comparison → process restart → persistent records/downloads.

Test fixtures are isolated under tests/ and temporary databases. No fake findings are seeded into the normal workspace. GitHub network behavior is simulated for reproducible private-repository tests; source analysis is real. Live private access requires the user's token and was not exercised in this phase. Dependency compatibility is checked; this review does not claim a complete audit of upstream package vulnerabilities.

## Important interpretation limits

SentinelScan Risk Score is a custom normalized weighted count, not CVSS. Dashboard risk counts open findings across scans, including repeated detections; historical assessment risk counts all detections at scan completion. Individual dependency advisories may include their source CVSS score, separately labeled.

Comparison RESOLVED means absent from the new scan, not verified remediation. Repository matching ignores line/column movement and groups same-rule occurrences in a file; no semantic code tracking. A completed scan can have partial/failed/skipped modules. Neither zero findings nor zero risk establishes security.


## Remediation workflow controls

Draft validation rechecks the saved version before publication, without running
source code. Supported syntax failures, remaining target-rule detections and new
High/Critical findings from the relevant module block publication. Unavailable
checks remain explicit and require human review; other modules and runtime behavior
are not verified. PR merge state and commit ancestry come from GitHub. Rescan
verification requires matching target/branch, complete module coverage and presence
of the affected analyzed file. Resolution is an explicit user choice after a
Not detected result. Retained source excerpts are bounded and redacted before
persistence; source masking remains heuristic. Local database access is sensitive.
`test_remediation_workflow.py` covers the workflow with isolated databases and
simulated GitHub responses; it creates no live PRs.
