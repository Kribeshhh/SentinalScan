# SentinelScan

Automated Web & Source Code Security Assessment Platform. The completed academic application integrates website DAST, GitHub SAST, vulnerability management, comparisons, database-backed dashboard trends and HTML/JSON/CSV reporting. HTML, CSS and vanilla JavaScript only; no Node.js dependency.

## Architecture

```text
                         SentinelScan / Flask
                       /                      \
          Authorized website             Authorized GitHub repository
                  |                              |
                 DAST                           SAST
          HTTP / TLS / Nmap            Code / Secrets / Dependencies
                       \                      /
                        Unified Finding Engine
                                  |
                     SentinelScan Risk Score Engine
                                  |
                                SQLite
                   /              |                \
              Dashboard         History           Reports
              Findings         Comparison      HTML / JSON / CSV
              Remediation       Risk trends
```

Dashboard metrics, severity/category/source breakdowns, unresolved counts, recent records and risk history all come from SQLite. Empty databases display zeros and empty states. No demonstration vulnerabilities are seeded into the application.

## Install and run

Use Python 3.11+ (verified with Python 3.14). From this project directory:

```sh
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 app.py
```

Open http://127.0.0.1:5000. Choose Website Scan or Repository Scan. Existing records remain in `data/sentinelscan.sqlite3`. The version-2 migration retains scan IDs and related records and converts old Pending scans to Queued. Version 3 adds repository snapshot metadata without replacing the existing tables. Application startup marks interrupted Queued/Running scans Failed rather than silently replaying network requests.

DAST dependencies: **dnspython**, **beautifulsoup4**, **cryptography**. SAST uses **tree-sitter**, **tree-sitter-javascript**, **tree-sitter-java**, **packaging**, **defusedxml**, **PyYAML** and **cvss**. Flask remains the web framework. Standard-library `http.client`, `socket`, `ssl` and `concurrent.futures` provide networking and job execution. Nmap is optional: when available on PATH, a fixed argument list invokes TCP connect and light version detection with a process timeout. Otherwise the scanner uses a bounded TCP connect fallback and explains that version detection is unavailable. No Nmap installation is required.

Optional [Nmap setup](https://nmap.org/book/install.html) (choose your platform):

```sh
# macOS, if Homebrew is already installed
brew install nmap
# Debian / Ubuntu
sudo apt-get update
sudo apt-get install nmap
# Confirm the executable is visible to the Flask process
nmap --version
```

The app uses TCP connect scans, so it does not need to run as root. Windows users can install Nmap from its official installer, but this application has only been validated on macOS; secure report access uses POSIX file-descriptor flags. Linux/POSIX is the intended alternative platform.

[.env.example](.env.example) documents optional settings. It contains no credentials and is not automatically loaded: set environment variables before starting Flask. The default private session key is generated on first use. See [SECURITY.md](SECURITY.md) for the complete 20-area review, threat model and test mapping.

## GitHub setup and repository scanning

When connected, browsing uses the authenticated repository list, including private repositories allowed by the token. Owner filtering applies to each fetched page; use Next or open owner/repository directly if the current page has no match. A verified connection confirms identity, not access to every repository.

Public repositories do not require a token. Open **Repository Scan**, browse public repositories by owner or enter `owner/repository`, then choose a branch. Public visibility does not replace the requirement to have authorization for your assessment.

For authorized private repositories:

1. Create a **fine-grained GitHub personal access token**, limited to the repositories you intend to assess, with **Contents: read-only** and **Metadata: read-only**. Organization approval/SSO policies may apply. See [GitHub repository archive permissions](https://docs.github.com/en/rest/repos/contents#download-a-repository-archive-zip).
2. Open **Repository Scan**, paste the token into **GitHub personal access token**, and click **Connect GitHub**. No terminal configuration is needed. The field is masked and is never filled back into a response.
3. The server verifies the token with GitHub and lists repositories accessible to that identity. The credential is retained only in process memory, with a random lookup handle in the signed browser session. Restarting the app or clicking **Disconnect GitHub** clears the saved connection. The store holds at most 32 connections; an evicted connection needs to reconnect. No OAuth application registration is needed.
4. Select a repository and branch, confirm assessment authorization, and optionally enable **OSV dependency lookup**. This sends package name, exact version and ecosystem to OSV. It sends no source code, repository identity or GitHub token. Private package names may themselves be sensitive, so lookup is off by default.
5. Click **Start repository analysis**. GitHub access is rechecked and the branch is pinned to its commit SHA. The existing queue, status polling and scan summary show retrieval, secrets, Python, JavaScript, Java, HTML, configuration and dependency progress. Findings use the same detail/status pages and risk model as DAST.

Browser-entered tokens are accepted only over loopback HTTP or HTTPS and require CSRF validation. They are not written to SQLite, reports, logs, browser storage or cookies. Only GitHub authentication requests receive the token; archive redirects to the expected repository on codeload.github.com receive no Authorization header. Already-authorized jobs may retain their transient client credential until they finish after disconnect. Revoke the token in GitHub when it is no longer needed.

Advanced setup still supports `SENTINELSCAN_GITHUB_TOKEN` in the server environment. If configured, leave the page's token field blank to use it. Disconnect clears the browser connection, not the environment variable.

### Source analysis architecture

```text
repository_routes.py → GitHub metadata + branch access validation
  → existing ScanManager queue (shared with DAST)
  → pinned commit archive → strict extraction into private TemporaryDirectory
  → Secrets → Python AST → JavaScript parser → Java parser → HTML → Configuration → Dependencies
  → redacted unified findings + module observations in SQLite
  → existing dashboard, scan history, finding details and risk engine
```

| Component | What it inspects |
|---|---|
| Python AST | Dynamic eval/exec, os shell calls, dynamic subprocess with shell=True, constructed SQL arguments, unsafe object deserialization and weak hash APIs; basic aliases and one-step assignments |
| JavaScript parser | Dynamic eval/Function, document.write, innerHTML/outerHTML assignments; ignores comments, quoted examples, static HTML and directly recognized DOMPurify sanitization |
| Java parser | Runtime.exec/ProcessBuilder with dynamic arguments, constructed query APIs, declared ObjectInputStream.readObject and weak hash/cipher selection |
| HTML parser | Password forms using GET, HTTP form/resource URLs, inline dynamic JavaScript and potentially sensitive comments; no rendering or remote resources |
| Secret scanner | Typed GitHub/cloud/payment token patterns, private keys, JWTs and contextual literal credentials; known placeholders suppressed; no credential validity checks |
| Configuration | Literal Python settings, JSON, safe YAML, .env files and properties; debug/development mode, disabled protections and wildcard allowed hosts |
| Dependencies | requirements.txt, package.json, pom.xml and common literal build.gradle declarations; exact declared versions queried against [OSV](https://google.github.io/osv.dev/quickstart/) only when enabled |

OSV findings retain package, version, ecosystem, vulnerability ID, supplied severity/CVSS, affected ranges/versions, advisory description and reference. Aliases are deduplicated per dependency occurrence. Unknown severity is Informational, not guessed. Version ranges, unresolved variables and remote requirements are not treated as installed versions. OSV failure produces partial coverage and leaves the rest of the scan working.

### Repository safety and secret handling

- No repository code runs. The scanner does not import repository modules, invoke setup.py/Makefiles/Gradle/Maven/npm, execute scripts/binaries, or install dependencies. External Nmap execution belongs exclusively to the existing DAST port module.
- Private temporary storage is removed on normal completion and handled errors. A hard OS/process kill can interrupt cleanup; downloaded content is still confined to the operating system's temporary directory with private directory/file permissions.
- Limits: 64 MiB compressed archive, 128 MiB declared expansion, 5,000 ZIP entries, 2,000 analyzed text files, 512 KiB per analyzed file, 30 path levels, compression-ratio checks. Every archive path/type is inspected before extraction. Traversal, absolute/Windows paths, symlinks, special/encrypted entries and case-colliding duplicates are rejected.
- .git, node_modules, venv, .venv, dist, build, target, vendor and related generated folders are excluded. Oversized, binary, non-UTF-8 and unsupported files are counted and skipped. No submodules, Git LFS objects, commit history or additional repositories are fetched.
- Source rules have a 180-second checked work budget and JavaScript/Java native parser timeouts. Findings are capped at 1,500 per scan. OSV uses at most 50 distinct exact-version queries, a 60-second lookup budget and stops after three failures. Partial, skipped and failed coverage remains visible.
- Raw source snippets and full detected secret values never become findings. Evidence uses structural descriptions and `[REDACTED]`. Candidate values exist only transiently for redaction; repository findings are scrubbed again at the persistence boundary. Stored observations and dependency metadata are also scrubbed. Dashboard/details/JSON consume sanitized records; Phase 4 exports use these sanitized records and apply redaction again; they never re-read raw source.
- Secret detection is heuristic and cannot discover every secret encoding or context. Avoid secrets in repository identifiers or filenames. Pattern-like credentials in repository/branch identifiers are rejected.

### Repository persistence and test coverage

Each repository scan has its own repository snapshot row: name, owner, GitHub URL, branch, immutable commit SHA, scan ID, language file counts, dependency inventory, creation time and scan date. `scan_modules` holds structured, redacted observations for the existing report architecture. The original DAST records and foreign keys are retained.

The local fixtures under `tests/fixtures/sast_lab/` contain intentionally vulnerable Python, JavaScript, Java, HTML, settings and dependency declarations. Test credentials are nonfunctional. They are read as text and zipped; never imported, built or executed. Tests use temporary databases, so synthetic API responses and fixture results are not inserted into the workspace database.

Repository validation includes DAST regression, repository workflow, secret suppression/redaction, malicious archives, parser false-positive checks, dependency outages, token forwarding safeguards and a non-execution sentinel. During Phase 3, live public GitHub metadata/branch/archive retrieval and live OSV lookup succeeded. The browser verified public repository/branch selection. No private GitHub token was configured; live private access was not tested, while its authorization and secrecy paths were exercised with an isolated API fixture.

## Vulnerability management and reporting

Architecture: existing DAST/SAST workers → SQLite scan/findings/module/repository snapshots → `analysis/management.py` metrics, comparison and trends → `management_routes.py` and `reports/report_generator.py` → server-rendered pages and private report files. No new runtime dependencies.

### Management workflow

- Open **Findings**, combine severity, confidence, category, source, status, scan and literal text search, then open a finding. All finding fields are visible; Open / Resolved / Ignored / False Positive changes persist and recalculate open risk.
- **Scan History** includes ID, target, type, date, duration, status, current open risk, all severity counts and total findings. Scan detail retains full DAST/SAST results and module observations.
- **Risk trends** plots up to 40 completed scans from SQLite, either across the scan sequence or for one target. The plotted assessment risk counts every detection at completion, so later triage does not rewrite the historical assessment. Scan History also shows current open risk. The all-target view is a sequence of assessments, not an aggregate portfolio trend.

### Comparison semantics

Choose two completed scans in chronological order under **Compare scans**. Websites must match scheme, normalized host/port, path and query parameter names (query values are intentionally not stored). Repositories must match owner/name and branch. Different scanner options and partial coverage produce warnings.

A separate stable comparison fingerprint hashes source, category, title and location, never database IDs. Repository line/column suffixes are removed so line movement alone does not create new issues. Repeated instances of the same rule in one file are grouped and occurrence counts retained. This may merge separate occurrences in that file; it is not semantic code tracking.

- NEW: fingerprint appears only in the current scan.
- RESOLVED: fingerprint appears only in the baseline scan.
- UNCHANGED: fingerprint appears in both, independently of manual triage status.

RESOLVED means no longer detected, not a verified fix; compare module coverage. Previous/current open risk and their difference are saved with the comparison snapshot. Re-comparing the same pair refreshes that snapshot.

### New and extended routes

| Method | Route | Purpose |
|---|---|---|
| GET | `/findings` | Extended filters: severity, confidence, category, source, status, scan_id, q |
| GET / POST | `/findings/<id>` / `/findings/<id>/status` | Existing full detail and persistent triage |
| GET | `/scans`, `/scans/<id>` | Extended history and complete scan results |
| GET / POST | `/comparisons` | List or create/refresh comparison |
| GET | `/comparisons/<id>` | Saved comparison results |
| GET | `/risk-trends?scan_id=<id>` | Historical assessment risk, optionally same target |
| GET | `/reports` | Report register and generation form |
| POST | `/reports/generate` | scan_id and format: HTML, JSON or CSV |
| GET | `/reports/<id>/view` | Sandboxed HTML preview or JSON; CSV downloads |
| GET | `/reports/<id>/download` | Download registered snapshot |

All POST routes require CSRF. The app remains a trusted single-user local tool.

### Database and file changes

Startup migrates to SQLite schema version 4, retaining prior scans, findings, repositories and report IDs. `scans.assessment_risk` stores historical all-detection risk; old terminal scans are backfilled from their findings. `reports.format` now permits CSV. The existing `scan_comparisons` table stores baseline/current IDs and comparison JSON. No finding status migration or reset occurs.

New files: `management_routes.py`, `analysis/management.py`, `tests/test_management.py`, and templates `comparisons.html`, `comparison_detail.html`, `risk_trends.html`, `report_document.html`. Existing routes, schema, scanner completion hooks, redaction, report generator, navigation, history, findings, CSS and restart tests were extended.

### Generate and test reports

1. Run an authorized website or repository scan (instructions below), or use an existing terminal scan.
2. Open **Reports**, choose the scan and HTML, JSON or CSV, then **Generate report**.
3. Use **View** for HTML/JSON or **Download** for any format. Reports contain metadata, severity statistics, full finding details, limitations and all module observations. Website modules include ports/services, DNS, HTTP, TLS and technologies. Repository snapshots include branch/commit, languages, dependencies, secrets, configuration and source findings.
4. Change a finding status and generate another report: the previous report remains an immutable snapshot.
5. Stop and restart Flask; statuses, comparisons, report register and generated files persist.

Files live in `reports_output/`, with random validated basenames and private permissions. Access accepts only database report IDs, rejects traversal and symlinks, and never serves arbitrary paths. Exports apply shared secret masking; HTML escapes input and disables active content in previews. CSV uses Python's csv module, includes scan/repository/module/finding record types and neutralizes spreadsheet formula prefixes. JSON is a structured machine-readable object with schema version, scan, repository, modules, findings and limitations.

Management tests run real local HTTP scans before and after a response change, and the actual SAST pipeline against source fixtures with a simulated GitHub API boundary. They verify all three comparison categories, filters, status updates, all report formats/downloads, HTML escaping, secret masking, traversal/symlink rejection and CSV formula protection. An actual Flask subprocess is stopped and restarted to verify finding status and generated report persistence. Test fixtures stay in isolated temporary databases; no synthetic scan records are added to the workspace database.

## Run an authorized website scan

1. Open **Website Scan** and enter an HTTP/HTTPS URL you own or are permitted to assess.
2. Confirm authorization, including the displayed port inventory. Enable **local/private lab addresses** for localhost, RFC1918 networks or IPv6 unique-local networks.
3. Optionally edit the resource wordlist (up to 15 safe paths).
4. Click **Validate URL** to inspect the resolved IPs, then **Start website scan**. Starting always repeats validation.
5. Watch Queued → Running → Completed/Failed and per-module progress. Open observations or individual findings from the summary. Scan History, Findings and the Dashboard update from SQLite.

A scan marked Completed can contain failed/skipped modules; coverage warnings are shown. If baseline HTTP fails, the overall scan is Failed but useful partial DNS, port or TLS observations and findings remain available.

### Legitimate local educational target

The included Flask lab deliberately exposes a few test weaknesses, contains no real credentials or application data, and binds only to loopback. Start it in a second terminal:

```sh
source .venv/bin/activate
python3 examples/lab_app.py
```

Scan **http://localhost:5001/?q=hello**, with the local/private option checked. The application has actual insecure cookie attributes, unsafe script interpolation, an actual SQLite query error on a quote, reflective CORS and educational configuration resources. Results are derived from HTTP responses, not inserted as seeded findings. Do not deploy this lab publicly. Stop it with Ctrl+C when done.

## Implemented modules

| Module | Assessment and stored observations |
|---|---|
| URL validation | Schemes, host/port syntax, IDNA, credentials rejection, local-lab opt-in, blocked metadata/link-local/special addresses, bounded DNS resolution and pinned IP snapshot |
| DNS | A/AAAA/CNAME results and per-record lookup failures; localhost/IP literals remain usable without DNS |
| Ports | Target port plus 80, 443, 8000, 8080, 8443; TCP protocol, service and versions where Nmap can identify them; open ports are observations, not vulnerabilities |
| HTTP | Status, selected response headers, content type, captured size, truncation, redirect chain, server and HTTPS use |
| Security headers | CSP, HSTS on HTTPS, MIME sniffing, framing, referrer and permissions policies; conservative severity and limited insecure-value checks |
| Cookies | Secure, HttpOnly, SameSite and SameSite=None/Secure compatibility; cookie values are never stored or shown |
| TLS | HTTPS availability, trust/identity validation, certificate validity dates/expiry, subject/issuer/SANs, negotiated protocol/cipher; unverified handshake only to inspect certificates, never to fetch application data |
| Technologies | Passive Apache/Nginx/IIS/PHP/WordPress/Django/Flask/jQuery/Bootstrap indicators; framework heuristics clearly labeled; no automatic vulnerability |
| Resources | Bounded configurable paths, random missing-page baseline, soft-404 filtering, resource inventory, evidence-based Git/environment/directory-index findings |
| CORS | Untrusted `.invalid` Origin probe and ACAO/ACAC/ACAM/ACAH observations; wildcard plus credentials is labeled browser-invalid, not an exploitable credential leak |
| Reflected XSS | Harmless unique alphanumeric markers, text/attribute/script context; potential finding only for script/event-handler reflection; never claims confirmed execution |
| SQL injection | One appended quote per eligible parameter; new database-specific errors support “Potential SQL Injection”; status/length differences alone are observations |
| Disclosure | Stack trace/error signatures, version banners, inline source-map references and exposed resource evidence; raw error/configuration contents omitted |

## Updated project structure

```text
SentinalScan/
├── analysis/
│   ├── __init__.py
│   ├── finding_engine.py
│   ├── management.py
│   ├── redaction.py
│   ├── risk_engine.py
│   └── validation.py
├── data/
│   └── .gitkeep; generated SQLite, WAL/SHM and private .secret_key (ignored)
├── examples/
│   └── lab_app.py
├── integrations/
│   ├── __init__.py
│   ├── credentials.py
│   ├── github.py
│   └── network.py
├── reports/
│   ├── __init__.py
│   └── report_generator.py
├── reports_output/
│   └── .gitkeep; generated report-<uuid> files (ignored)
├── scanner/
│   ├── sast/
│   │   ├── __init__.py
│   │   ├── common.py
│   │   ├── config_scanner.py
│   │   ├── dependency_scanner.py
│   │   ├── html_scanner.py
│   │   ├── java_scanner.py
│   │   ├── javascript_scanner.py
│   │   ├── python_scanner.py
│   │   └── secret_scanner.py
│   ├── __init__.py
│   ├── common.py
│   ├── cookie_scanner.py
│   ├── cors_scanner.py
│   ├── directory_scanner.py
│   ├── disclosure_scanner.py
│   ├── dns_scanner.py
│   ├── header_scanner.py
│   ├── http_scanner.py
│   ├── port_scanner.py
│   ├── repository_safety.py
│   ├── source_scanner.py
│   ├── sqli_scanner.py
│   ├── target.py
│   ├── technology_scanner.py
│   ├── tls_scanner.py
│   ├── website_scanner.py
│   └── xss_scanner.py
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── app.js
├── templates/
│   ├── _components.html
│   ├── _risk_chart.html
│   ├── base.html
│   ├── comparison_detail.html
│   ├── comparisons.html
│   ├── dashboard.html
│   ├── error.html
│   ├── finding_detail.html
│   ├── findings.html
│   ├── report_document.html
│   ├── reports.html
│   ├── repository_scan.html
│   ├── risk_trends.html
│   ├── scan_detail.html
│   ├── scans.html
│   └── website_scan.html
├── tests/
│   ├── fixtures/
│   │   └── sast_lab/
│   │       ├── App.java
│   │       ├── app.js
│   │       ├── application.yml
│   │       ├── build.gradle
│   │       ├── index.html
│   │       ├── insecure.py
│   │       ├── package.json
│   │       ├── pom.xml
│   │       ├── requirements.txt
│   │       └── settings.py
│   ├── test_browser_github.py
│   ├── test_end_to_end.py
│   ├── test_foundation.py
│   ├── test_hardening.py
│   ├── test_management.py
│   ├── test_restart.py
│   ├── test_source_scanner.py
│   └── test_website_scanner.py
├── .env.example
├── .gitignore
├── README.md
├── SECURITY.md
├── app.py
├── config.py
├── database.py
├── management_routes.py
├── repository_routes.py
└── requirements.txt
```

`.venv/`, bytecode and SQLite WAL/SHM sidecars are generated artifacts.

## Persistence and risk

The original `scans`, `findings`, `repositories`, `reports` and `scan_comparisons` tables are preserved. Scan metadata adds progress, start/completion timestamps, error, normalized risk and non-sensitive scan options. `scan_modules` stores each module's lifecycle, errors and structured JSON observations, keyed to the scan. Port inventories are stored here, separately from findings. This is the actual persisted input for Phase 4 reports.

Every issue uses the Phase 1 `Finding` contract and `save_finding`: title, severity, confidence, category, source, location, description, evidence, impact, recommendation, status and fingerprint, plus SQLite ID, timestamp and scan linkage. Fingerprints deduplicate within a scan; historical findings across scans remain distinct.

Critical 10, High 7, Medium 4, Low 1, Informational 0. For open findings with total weight `P`:

```text
risk = round(100 × P / (P + 50))
```

**SentinelScan Risk Score is not CVSS.** Individual OSV advisories can include their own CVSS values, separately labeled. The scan summary scores that scan. The dashboard aggregates all open findings across scans. Resolved/Ignored/False Positive findings do not contribute. A zero score does not prove security. Status changes update the persisted scan risk.

## Boundaries and security

- One worker, one concurrent HTTP request, four total active/queued jobs. Each scan has a 150-second module budget, at most 60 HTTP GETs, a minimum 0.2-second request interval, a 4-second network timeout/request cap and 256 KiB response cap. Paths are limited to 15; active query checks consider the first five parameters. Known command/action/secret parameter names are skipped. Bodies stay transient and are never stored.
- All returned DNS addresses must pass validation. Connections use the validated numeric IPs directly with the original Host/SNI; HTTP redirects never trigger DNS re-resolution. Mixed public/private answers fail unless lab access is explicitly allowed. OS proxy settings are ignored.
- Redirects stay on the exact authorized origin or upgrade HTTP to HTTPS on port 443 of the same hostname. Other hosts/ports are blocked, even if their addresses are public. No crawling, login, form submission, credential injection or authenticated browser state is used.
- Link-local, metadata, multicast, unspecified, reserved and other unsupported special-purpose ranges are rejected even in lab mode. Loopback, RFC1918 and IPv6 ULA need explicit opt-in. The scanner is for a trusted single-user local workspace, not a hosted multi-user scanning service.
- Query values are redacted in persisted URLs. Set-Cookie values, configuration bodies, raw SQL/stack errors and raw response bodies are never stored. Selected configuration headers and certificate metadata remain visible for evidence. Avoid secrets in URL paths, parameter names or custom configuration headers.
- Phase 1 protections remain: CSRF on POST, parameterized SQLite values, Jinja escaping, strict CSP, safe errors, local bind, trusted hosts, HttpOnly/SameSite cookies and private generated session key. The application server logs only response codes, never scan target URLs or credentials.
- Nmap uses `subprocess.run` with an argument array, fixed options, a validated numeric address, a small port list and timeout; no shell, NSE scripts or user-controlled command flags.

Optional environment configuration includes `SENTINELSCAN_GITHUB_TOKEN`, `SENTINELSCAN_DATA_DIR`, `SENTINELSCAN_SECRET_KEY` (32+ characters) and `SENTINELSCAN_HTTPS=1` (only behind configured HTTPS). Use a single application process; in-process scheduling is not a distributed job queue.

## Testing and known limitations

```sh
source .venv/bin/activate
python3 -m unittest discover -s tests -v
```

All 61 automated tests pass. Tests use isolated databases and real loopback HTTP/HTTPS servers. Coverage includes the Phase 1 tests, complete DAST ingestion, actual SQLite error detection, reflection contexts, cookie redaction, SSRF rejection, pinned sockets, blocked redirects, request/size limits, trusted and untrusted TLS, independent module failure, and migration with existing foreign-key records. The complete HTTP workflow test starts a real Flask subprocess, scans a loopback educational target, verifies SQLite/risk/status updates, analyzes actual SAST fixtures through a simulated GitHub boundary, exports all three formats, runs a second scan, compares and restarts Flask. It confirms scans, findings, statuses, repository records, comparisons and report downloads survive. Further hardening tests cover ID overflow, file uploads, safe logs, private keys, extraction symlinks, Nmap fallback, queue admission and temporary cleanup. The browser workflow is additionally exercised against the included local educational lab.

Limitations:

- Conservative heuristic assessment, not an exhaustive DAST product or proof of exploitability. No JavaScript execution, authenticated coverage, multi-page crawl, POST/form testing, database extraction or time-based SQL probes.
- Missing headers are checked principally on HTML; cookies only on the final baseline response. CSP analysis is limited rather than a full policy evaluator. Ordinary text/attribute reflections are inventory only.
- TLS probes one modern negotiated configuration, not every legacy protocol/cipher; HTTP availability checks try HTTPS only on port 443. An invalid certificate prevents application-layer HTTPS requests while certificate analysis still proceeds.
- DNS uses standard DNS resolution (localhost is special-cased); custom hosts-file-only lab names need an IP address or DNS entry. Port and TLS inspection use the first validated address, while HTTP can fall back across the snapshot.
- Resource discovery is intentionally small and soft-404 filtering is heuristic. Environment exposure findings omit contents. Source-map detection checks baseline references only and does not retrieve maps.
- GET requests can have side effects on poorly designed targets; assess only an approved scope without state-changing GET endpoints.
- Nmap absence/failure is handled with the socket fallback. The automated tests exercise the fallback; the browser-run local lab scan also exercised the installed Nmap successfully and identified the Werkzeug HTTP service. Version detection still depends on service responses.
- Jobs interrupted by restart are marked Failed and are not automatically resumed. Partial findings persist. No cancellation, remote authentication or multi-process scheduling yet.
- DVWA/Juice Shop are not required or bundled; testing here uses the included deliberately vulnerable Flask lab and temporary HTTPS servers. Phase 5 testing does not initiate scans against third-party websites. Existing user scan records are retained.
- SAST uses syntax/context heuristics, not whole-program taint analysis. Aliases/shadowing, framework-specific behavior, runtime overrides, TypeScript, transitive dependencies and complex Gradle/Maven resolution are outside current coverage. JSON/YAML locations are file-level line 1. Normal findings require manual triage.
- Fine-grained PAT authorization is implemented; OAuth, GitHub Apps, Enterprise hosts, multi-user authentication and credential storage are outside current scope.
- Native PDF generation is not implemented; HTML reports have print styles and can be saved as PDF using your browser. Possible future extensions: asset ownership, status audit history, scheduled scans, notifications, authentication and broader scanner coverage.

### Edit a finding and create a pull request

Open a repository finding and choose **Edit source & create pull request**. Load the
file from the scan's immutable commit, edit it, preview the diff, and save the draft.
Review the saved diff and check the publication checkbox to create a GitHub branch
and pull request against the scanned branch. The app never merges the PR or marks
the finding resolved automatically. Review/test on GitHub and re-scan after merging.

Connect a fine-grained token for the repository with **Contents: read and write**
and **Pull requests: read and write** to publish. Public source can be loaded without
a token. Private source requires working read access; editing does not bypass GitHub
permissions. Fork creation is not supported: publication requires write access to the
scanned repository. Workflow files are excluded from this editor.

Drafts and PR links persist in the new `remediation_drafts` SQLite table. Only the
file selected from the finding's stored location can be edited; the browser cannot
choose filesystem paths, repository, branch, or commit parameters. Text files are
limited to 512 KiB. Files with detected secrets/masking are blocked rather than storing
or publishing secrets or replacing source with masked placeholders. Detection is
heuristic; review code for sensitive material before saving/publishing. Drafts contain
source code and should be protected with the local database. They are not reports.

A version check prevents stale browser tabs from overwriting saved drafts. If the
base branch moved after the scan, run a new scan before publishing. Publication locks
the draft, uses a unique `sentinelscan/fix-*` branch, and retries against that same
branch, recognizing already-created PRs. A failed attempt may leave a branch/commit
on GitHub; the UI reports this and offers retry. On a local server restart, interrupted
publication becomes retryable. Do not run multiple app processes against this database.

Routes: `GET/POST /findings/<id>/edit`, `POST /findings/<id>/publish`, and
`GET /findings/<id>/patch`. All mutations require CSRF validation. No source is
executed, no shell or Git CLI is invoked, and no token is persisted with drafts.

Tests: `.venv/bin/python -m unittest discover -s tests -v`. Remediation tests exercise
SQLite persistence, preview/save, XSS escaping, secret blocking, CSRF, stale drafts,
branch conflicts, patch downloads, and recovery after a lost GitHub response.
GitHub publication tests simulate API responses and never create real remote PRs.

### Code solutions after scanning

Open any finding and scroll to **Code solution**, or use **View solution** in the
scan findings table. Supported scanner rules show a code/configuration example,
application notes and verification steps. Copy code uses plain text; if clipboard
access is unavailable it selects the snippet for manual copying. The same guidance
appears beside the repository source editor and in newly generated HTML, JSON and
CSV reports (CSV stores the structured solution in `details_json`). Existing saved
reports remain unchanged snapshots.

`analysis/solution_engine.py` maps finding types to curated examples and selects
language variants where supported. Existing SQLite findings receive guidance on
read, without a migration or rescan. It uses no external AI API, sends no source
code elsewhere, and never interpolates scanned evidence into executable examples.
Website examples explicitly identify their illustrative stack; DAST does not know
the original application source. Unknown rules display a manual-review fallback.
Dependency guidance requires checking the actual advisory for a fixed version;
certificate findings require certificate renewal/configuration, not just code.

These examples are adaptation guides, not automatically verified patches. They do
not alter source, publish a PR, execute commands or change finding status. Adapt
repository fixes using the existing draft/diff/PR workflow, test, then re-scan.

Solutions now show **What to change** and labeled vulnerable/replacement examples.
Repository findings offer **Load actual code from scanned commit**, using the
existing bounded source loader and persistent draft. The loaded detection line is
shown with surrounding context. Exact JavaScript DOM assignment candidates are
provided only for one unambiguous parsed assignment at the recorded line; variable
names and expression text are preserved. Plain-text and sanitized-HTML alternatives
are distinguished, including DOMPurify setup requirements. Full candidate files are
syntax-checked, but this does not verify runtime semantics or prove exploitability.
Other rule types retain explicitly labeled examples alongside source context. DAST
cannot supply exact backend source lines. Inaccessible source produces an access
error, never fabricated original code. New reports include vulnerable examples and
replacement boundaries; actual private source context is not added to reports.


### Remediation validation and verification

New repository scans retain a redacted excerpt around each finding (up to seven
lines, 1,000 characters per line, 1 MiB total per scan), the scan commit, and hashes
of analyzed files. Existing scans need a rescan to gain retained excerpts; their
full source can still be loaded through GitHub. Full temporary checkouts are deleted.
Secret masking is heuristic. Excerpts and editor drafts are local sensitive data.

Saving a draft runs supported syntax checks and the relevant scanner module against
original and edited source. Syntax errors, a remaining original detection, or new
High/Critical detections in that module block publication. Unsupported checks are
labeled unavailable and require manual review. No application code is executed;
passing static checks does not establish correct runtime behavior.

On a finding's **Remediation workflow** panel:

1. Load source, edit, save, review the diff and validation, then explicitly publish a PR.
2. Refresh its status from GitHub. Review and merge on GitHub.
3. Authorize **Scan merged branch**, then return using the scan's finding link.
4. Verify against the completed scan. Optionally mark the original finding Resolved.

Verification checks matching target/branch, module coverage, analyzed file presence,
and—when a PR is linked—that the scan commit contains the actual merge commit.
Results are **Still detected**, **Not detected**, or **Inconclusive**. Failed/partial
coverage and missing files do not count as verified absence. Matching uses the
existing stable fingerprint, ignoring line movement; this is scanner verification,
not a guarantee that the application is secure. Website findings can be checked
against a later scan of the same target with equivalent path coverage.

Additive SQLite tables: `finding_context`, `scan_files`, `draft_checks`,
`pull_request_tracking`, `remediation_verifications`. New POST routes beneath
`/findings/<id>`: `/validate`, `/pull-request/refresh`, `/rescan`, `/verify`.
All require CSRF protection; explicit authorization is required for a rescan.
`analysis/source_context.py`, `analysis/fix_validation.py`,
`analysis/remediation_workflow.py`, `workflow_routes.py` and `_workflow.html`
implement the workflow. Tests cover real fixture scans and mocked GitHub PR APIs,
merge ancestry, redaction, blocked edits, coverage failures and restart persistence.


### Scan from a GitHub URL

On Repository Scan, paste `https://github.com/owner/repository` in **Scan using a
GitHub URL**, click **Open repository**, choose a branch, confirm authorization,
and start analysis. `owner/repository`, a trailing slash, and HTTPS `.git` clone
URLs are supported. Use the repository root URL, not a file/tree link. Credentials,
query parameters, fragments, SSH URLs and non-GitHub hosts are rejected. Private
repositories use the current GitHub connection and still require read access.


### Source-first finding guidance

New repository scans prepare redacted source context and source-matched remediation
candidates while the scanned checkout is available; viewing the finding needs no
GitHub fetch or draft creation. Snapshots use `finding_solutions` (8 MiB budget per
scan). Existing scans require regeneration from their pinned source to gain these
snapshots. The editor is separate and now supports text files up to 512 KiB.

npm dependency locations identify the actual package/version entry. Guidance shows
recorded advisory severity, actual source, and candidate fixed releases where the
advisory provides them. A candidate addresses that advisory only and still needs
compatibility and other-advisory review. No fixed release means no invented patch
or copyable checklist. Translation JSON is excluded from generic assignment-based
secret detection; typed tokens/private keys are still checked in every file.


### Network reliability and scan interpretation

Website URLs may include browser fragments (`#/`); these are stripped before any
HTTP request or persistence. The scanner does not execute JavaScript routes.
Website socket/request allowance is 12 seconds within the existing 150-second
scan budget. GitHub GET/HEAD requests retry a transient failure once; writes,
TLS verification failures, scope rejection and size-limit errors are never retried.
Do not store a running SQLite database in cloud-offloaded storage. Keep the project
locally downloaded, or configure SENTINELSCAN_DATA_DIR to a local directory before
starting (copy existing data while the server is stopped to preserve history).


DNS fallback: if direct DNS queries return no addresses, the website validator uses
the operating system resolver with a bounded wait and bounded background workers.
Every address still passes SSRF checks before the snapshot is pinned. Fixed remote
services use native DNS, reject non-public addresses, and report DNS/TCP/TLS/HTTP
connection stages separately. No DNS settings, VPN settings or TLS verification
are changed. This improves recovery but cannot guarantee an unavailable network.
