# Phase 06 — Frontend and backend workflow audit

Date: 2026-10-08. Scope: existing workflows only. No application code, routes, UI, configuration, dependencies or user records changed. **Backend/Jinja checks PASS; browser execution and visual responsiveness NOT TESTED.** No paid API or public repository scanning.

Project: `/Users/kribeshthapa/Developer/Vibe code/SentinalScan`. Interpreter: existing `.venv/bin/python` (Python 3.13.5 per Phase 01). Required context read in prescribed order from CLAUDE.md through the six context files; AGENTS.md and earlier Phase 01–05 audit results reviewed. All required documents present. Prior detection, CodeQL configuration and AI factual-quality issues are unchanged, not fixed by this workflow audit.

## Execution and isolation

```sh
.venv/bin/python -B /tmp/phase06_tests.py > /tmp/phase06_tests.log 2>&1
.venv/bin/python -B /tmp/phase06_matrix.py
cat /tmp/phase06_tests_summary.json
git diff --check
```

**89 existing focused tests passed, 0 failures, 0 errors, 0 skips, 10.521 seconds.** Full project suite not run. Suites: test_foundation, test_management, test_end_to_end, test_read_only_product, test_website_scanner, test_source_scanner, test_browser_github, test_repository_url, test_unified_recommendation, test_finding_quality, test_hardening.

**34 additional route checks matched expected status codes**, plus eight rendered navigation links returned 200. Four persisted synthetic state records exercise Queued/Running/Completed/Failed markup; these are explicitly audit fixtures, not scanner accuracy claims. They existed only in disposable SQLite. Existing workflow tests also run actual scanner workers against an authorized loopback website and controlled GitHub ZIP fixture, producing real persisted findings from fixture analysis.

The runner sets a temporary data directory before app imports, disables live AI/external engines, removes inherited provider/GitHub tokens from its process and blocks the shared external transport. Existing end-to-end test starts its own Flask subprocess with temporary data, controlled GitHub factory and local lab, then terminates it. No existing user server restarted. Provider display tests use saved/mocked reviews. No downloaded repository code executed.

Complete test names, raw log, helper source and route/state results: [evidence JSON](PHASE_06_UI_BACKEND.evidence.json). Recreate temporary helpers from project root:

```sh
.venv/bin/python -B - <<'PYREPRO'
import json
from pathlib import Path
bundle=json.loads(Path('docs/audit/PHASE_06_UI_BACKEND.evidence.json').read_text())
for name,source in bundle['scripts'].items():
    Path('/tmp',name).write_text(source)
PYREPRO
```

## Workflow verification

| Workflow | Result | Observed evidence |
|---|---|---|
| Dashboard empty | PASS | HTTP 200, No scans recorded, no chart points; meaningful zero-data state. |
| Dashboard populated | PASS | Four persisted state fixtures produce Total scans 4, Repository scans 4, Website scans 0, Unresolved 0. app.py SQL aggregation inspected; real scanner workflow tests additionally exercise findings and risk. |
| Website submission | PASS | Local lab submission with CSRF/authorization redirects 303 to saved scan; worker completes and persists findings. Invalid target/authorization rejected; no public scan. |
| Repository submission | PASS mocked GitHub boundary | Existing controlled repository factory and URL tests exercise selection, submission and completed results; real GitHub availability/private permissions not tested here. |
| Progress/status | PASS server / NOT TESTED browser | Status JSON matches persisted Queued 0, Running 42, Completed 100, Failed 100; only active pages have polling attributes. Poll scheduling/reload was inspected, not executed. |
| Successful completion | PASS | Actual local/fixture workers finish; results and modules rendered. End-to-end HTTP workflow verifies scan completion and persistence across process restart. |
| Failed display | PASS fixture state | Failed page shows error and zero-findings warning; no success progress element; no polling attribute; repository retry link present in template. |
| Partial coverage | PASS display / PARTIAL semantics | Persisted Partial module produces coverage warning in all four states. Completed remains possible with partial/failed/skipped modules; completion is not full coverage. Existing module-failure tests preserve results. |
| Findings and labels | PASS sampled templates | Findings page/filter/history tests verify severity, confidence, status and counts. Finding-quality tests verify evidence/context, escaping and unknown-source handling. Labels are not proof of detection accuracy. |
| One recommended fix | PASS | UnifiedPageTests verify one recommendation section, source code pair when supported, illustrative fallback otherwise; no manual AI/edit/publication controls. |
| AI indicator | PASS mocked/saved | Enabled accepted contribution shows indicator; disabled, missing or failed refinement retains deterministic display. Phase 05 semantic-quality defects remain. No live provider. |
| Scan history | PASS | Stored scans/counts and result links render; pagination/filter invalid input returns 400. |
| Comparison | PASS | Two local scans generate NEW/RESOLVED/UNCHANGED groups; saved comparison survives restart. Wrong-target, reversed, identical or running selections rejected. |
| Risk charts | PASS SVG/data / NOT TESTED visual | Actual persisted scan history produces SVG and risk points; assessment scores remain historical while triage changes current risk. Chart geometry rendered server-side, no fabricated plotted scores. Visual hover/accessibility not exercised. |
| Reports | PASS | Actual website/repository fixture results generate HTML/JSON/CSV; download 200 with attachment disposition; JSON/CSV parse; HTML view sandbox CSP; redaction/path traversal/symlink protections and snapshot restart tested. |
| Navigation | PASS links / NOT TESTED menu interaction | Eight sidebar links extracted from empty dashboard all return 200. CSS/JS asset URLs return 200. Mobile menu click/Escape/focus not executed. |
| Invalid/error states | PASS | Bad filters/IDs/input return 400, absent records/removed routes 404, injected runtime error returns sanitized 500. CSRF/hardening tests pass. |
| Responsive/JavaScript | NOT TESTED dynamically | No isolated browser automation framework available in project venv; static inspection only, detailed below. |

## Supplemental route matrix

Expected errors are successful guard checks, not application failures. Unknown records used ID 99999. State IDs 1–4 are temporary audit-only records.

| Method | Path | Expected | Actual |
|---|---|---:|---:|
| GET | `/` | 200 | 200 |
| GET | `/website-scan` | 200 | 200 |
| GET | `/repository-scan` | 200 | 200 |
| GET | `/scans` | 200 | 200 |
| GET | `/findings` | 200 | 200 |
| GET | `/reports` | 200 | 200 |
| GET | `/comparisons` | 200 | 200 |
| GET | `/risk-trends` | 200 | 200 |
| GET | `/static/js/app.js` | 200 | 200 |
| GET | `/static/css/style.css` | 200 | 200 |
| GET | `/scans/99999` | 404 | 404 |
| GET | `/scans/99999/status` | 404 | 404 |
| GET | `/findings/99999` | 404 | 404 |
| GET | `/comparisons/99999` | 404 | 404 |
| GET | `/reports/99999/download` | 404 | 404 |
| GET | `/missing` | 404 | 404 |
| GET | `/findings/1/edit` | 404 | 404 |
| GET | `/scans?page=bad` | 400 | 400 |
| GET | `/findings?severity=Wrong` | 400 | 400 |
| GET | `/reports?scan_id=bad` | 400 | 400 |
| GET | `/risk-trends?scan_id=bad` | 400 | 400 |
| POST | `/website-scan` | 400 | 400 |
| POST | `/repository-scan` | 400 | 400 |
| POST | `/comparisons` | 400 | 400 |
| POST | `/reports/generate` | 400 | 400 |
| GET | `/scans/1` | 200 | 200 |
| GET | `/scans/1/status` | 200 | 200 |
| GET | `/scans/2` | 200 | 200 |
| GET | `/scans/2/status` | 200 | 200 |
| GET | `/scans/3` | 200 | 200 |
| GET | `/scans/3/status` | 200 | 200 |
| GET | `/scans/4` | 200 | 200 |
| GET | `/scans/4/status` | 200 | 200 |
| GET | `/` | 500 | 500 |

## Browser availability and static frontend inspection

Tool discovery found no dedicated browser automation tool. These checks returned:

```sh
.venv/bin/python -B -c "import importlib.util; print({x:bool(importlib.util.find_spec(x)) for x in ('playwright','selenium')})"
# {'playwright': False, 'selenium': False}
command -v playwright
command -v chromedriver
# neither found
command -v safaridriver
# /System/Cryptexes/App/usr/bin/safaridriver
```

Safari's driver binary exists, but an enabled isolated remote-automation session was not verified. No personal browser was controlled and no browser/package installed. **No screenshots captured.** Browser-specific runtime checks are NOT TESTED, rather than inferred to pass from Jinja responses.

Inspected static/js/app.js and templates/scan_detail.html, _risk_chart.html, dashboard.html, plus shared recommendation templates through the focused tests:

- Active scan polling starts after 1.5 seconds, updates status, reloads when progress changes or terminal status arrives; fetch failures display retry state with delay capped at 15 seconds. Actual polling, reload and network failure timing NOT TESTED in a browser.
- Submit handler retains submitter name/value, marks aria-busy, adds Processing request text and prevents repeated submit events. Back-forward persisted pages reload. Browser form interaction and back-forward cache behavior NOT TESTED.
- Clipboard uses writeText then selection fallback. Permission-denied/unsupported clipboard, actual copy and keyboard behavior NOT TESTED.
- Mobile menu toggles aria-expanded/nav-open; Escape closes and focuses toggle. Native disclosures and deep-link expansion exist. Runtime focus and disclosure behavior NOT TESTED.
- CSS has responsive breakpoints, code/table overflow handling, focus styling and reduced-motion handling. Actual desktop/mobile overflow, visual quality, contrast measurement and screen reader operation NOT TESTED.
- Risk chart is server-rendered SVG with title/description and point labels, not a JavaScript chart. Tests establish SVG/data presence, not visual correctness at all sizes.

## Data provenance and persisted-state checks

Dashboard queries SQLite for counts, open findings and recent records. Scan detail and status endpoints read scans/scan_modules/findings; history uses stored scan metrics. Comparison snapshots come from actual matching scan findings; report snapshots come from database results and registered report paths. Test_management's local website changes produce new cookie findings and resolved CSP finding while retaining unchanged findings; the test asserts all three comparison groups. EndToEndTests checks actual risk formula against stored severities and restarts its disposable Flask process before confirming table counts, triage and report downloads.

The four supplemental state records intentionally isolate UI rendering rather than pretend a real worker remained at 42%. No fixture data was placed in user history. Empty states have descriptive text rather than invented vulnerability results. This verifies sampled data wiring, not every possible historical database record.

## Failures, reproduction and remaining limitations

**No new failing route assertion, import error or Jinja rendering exception was reproduced.** The injected RuntimeError is intentional: patch app.risk_trend in the matrix helper, request `/`, expect HTTP 500 and verify the private exception text is absent. Log contains only `Request failed (RuntimeError)`.

Reproduce state display with the matrix helper: persisted Running/42 yields polling attributes/progress; switch to Failed/100 yields a failure warning and no progress bar. Persisted Partial module remains visible with coverage warning. This documents current behavior without redesign.

Outstanding limitations:

1. Browser-specific functionality remains unverified as listed above. Passing Flask tests cannot establish clipboard, viewport, focus or polling behavior.
2. Completed status can coexist with incomplete module coverage. The warning renders correctly, but a user must still review it; no universal full-scan-success claim is justified.
3. Earlier audits' SAST/DAST false positives/negatives, CodeQL default pack resolution and AI unsupported advice are unchanged. A correctly rendered finding/recommendation can still be inaccurate.
4. Live GitHub/provider availability, real credentials and provider latency are outside these fixture checks. No arbitrary remote requests or paid services were used.
5. This is 89 focused existing tests plus 34 route checks, not the complete project suite or exhaustive route/input fuzzing. No screenshots or visual regression baseline were produced.

Only this report, its evidence JSON and the progress tracker were updated. No features, source edits, route changes or UI redesign. Phase 6 stops here.
