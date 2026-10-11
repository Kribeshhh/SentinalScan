# Phase 20 — Website query replay safety

## Root cause recorded before implementation

`scanner/xss_scanner.py:parameter_urls` parsed all query pairs, skipped certain
names as mutation targets, copied the entire pair list, replaced one value and
re-encoded every pair. Non-target action parameters remained. SQL indicators import
the same helper. Neither a name blacklist nor HTTP GET proves a request inert.

`scanner/http_scanner.py:Client.get` enforced origin, pinned addresses, budgets and
redirect scope but no query replay policy. Consequently the original HTTP baseline,
CORS comparison GET and followed same-origin query redirects could repeat actions
without even reaching XSS/SQL mutation. Multiple pinned address attempts retry
connection establishment, not a transmitted HTTP request; there is no application
HTTP retry loop. Redirects are separate requests (up to five).

The original local-only mock reproduced one request in each module preserving
`action=fixture-noop` while mutating q. No network or destructive action executed.
See PHASE_20_BEFORE.json. Implementation/results follow below when verified.

## Verified outcome — 2026-10-10

**PASS for the original P8 S2 reproduction and scoped regression suite.** This
is a conservative query-request policy, not proof that every HTTP GET is harmless.
No public target, real credentials, live AI, package installation or user scan
history was used in this phase. No new routes, tables, engines or UI were added.

### Before / after

Original URL: `http://127.0.0.1/?action=fixture-noop&q=hello`.

| Path | Before | After, default configuration |
|---|---|---|
| XSS, selected q | 1 mock GET; `action=fixture-noop&q=ssprobe2de6f265601467851f79` | Skipped; 0 requests, 0 sockets, no generated probe |
| SQL, selected q | 1 mock GET; `action=fixture-noop&q=hello%27` | Skipped; 0 requests, 0 sockets, no generated probe |
| Baseline | Client allowed arbitrary submitted queries | Skipped before socket; persisted HTTP module reason and overall Failed scan |
| CORS comparison | Repeated original query URL | Skipped before socket |
| Same-origin redirect to unreviewed query | Could follow and replay query | Original redirect response retained; destination not followed, explicit safety reason |

The random XSS marker above is the actual captured pre-fix value. Both old probes
preserved the action pair. After-fix evidence: `PHASE_20_AFTER.json`; before evidence:
`PHASE_20_BEFORE.json`. The baseline/CORS/redirect pre-fix behavior was established
by source inspection; the original XSS/SQL reproduction was executed with mocks.

### Safety policy / compatibility trade-off

Unreviewed query-bearing URLs now cause `SkipModule` before any application HTTP
request. This includes ordinary submitted `?q=hello` URLs: a familiar name does
not prove safety. A URL without a query follows existing authorized target rules.
We do not remove action parameters and pretend the resulting endpoint is equivalent.

The existing trusted `SCANNER_CLIENT_OPTIONS` configuration can provide an exact
normalized full-URL map with reviewed mutation positions. This is deliberately not
accepted from the scan form, private-lab checkbox, URL parameters or remote content.
A review attests that replay of the entire endpoint/query and the selected mutations
are inert. Positions are zero-based ampersand-separated components; duplicate names
remain separate. Example **only for an operator-reviewed local fixture**:

```python
# Through the existing create_app configuration mechanism; not a new env option.
SCANNER_CLIENT_OPTIONS = {
    'reviewed_queries': {'http://127.0.0.1:8123/?q=hello': [0]}
}
```

Use the exact URL after `validate_target` normalization. Empty position lists permit
a reviewed baseline but skip mutation. Missing/wrong/out-of-range mutation positions
skip the probe. No wildcard or name-based approval exists. Changed values, path,
origin or ordering require a separate review. Explicit reviews must not contain
credentials. Merely entering this configuration is not an automated safety analysis.

For an approved mutation, the existing helper changes one raw component and encodes
its value; it preserves all other raw bytes, repeated pairs, blank values and encoded
Unicode. No global query re-encoding or arbitrary parameter deletion occurs. Only
helper-generated probe URLs enter the Client's in-memory permitted probe set.
The existing same-origin/HTTPS-upgrade, pinned-IP, request-count, byte, deadline,
TLS-verification and GET-only controls still apply independently.

A blocked redirect uses the existing `followed: false` observation with an added
query-safety reason; the received redirect response can still be assessed. If the
initial HTTP baseline is blocked, the worker records HTTP Skipped and overall Failed,
with partial observations retained. It does not report a successful clean scan.

### Exact modified files

Production (only these three files changed for Phase 20):

- `scanner/http_scanner.py`: optional trusted review map, shared query guard before
  connection, bounded helper-generated probe registration, redirect query guard.
- `scanner/xss_scanner.py`: replace name blacklist/full-pair rewriting with exact
  full-URL and position review; preserve unrelated raw components; run via Client.
- `scanner/sqli_scanner.py`: use the same Client-controlled parameter iterator.

Tests:

- New `tests/test_replay_safety.py`: nine methods with multiple cases/subtests.
- `tests/test_website_scanner.py` and `tests/test_end_to_end.py`: explicitly review
  existing authored inert query fixtures in Client configuration.
- `tests/test_phase16_accuracy.py`, `tests/test_final_validation.py` and
  `tests/test_finding_context.py`: mock Clients delegate parameter construction to
  the real helper with explicit review of their authored fixture URLs.
- Existing detection assertions were retained; no test was deleted or weakened.

Documentation: this report, `context/architecture.md`, `context/ai-workflow-rules.md`,
`context/progress-tracker.md`, `AGENTS.md`, new evidence/log files. Historical audit
reports remain unchanged. Pre-existing Phase 19 working-tree edits are not Phase 20
changes. Repository detection, external engines, Ollama, composition, risk, reports,
SQLite schema, frontend and existing user data were not modified in this phase.

### Regression evidence

| Requirement | Status | Evidence in `test_replay_safety.py` |
|---|---|---|
| Original XSS / SQL replay | PASS | `test_original_both_modules_no_requests`: mocked socket never called; Skipped; count 0 |
| Action before/after q, multiple actions | PASS | Same test, before/after/action+cmd cases; no name-based decision |
| Duplicate, blank, encoded and Unicode inputs | PASS | Default denied plus `test_review_preserves_unrelated_bytes_and_duplicate_positions` on explicitly reviewed mutations |
| No name-only approval; invalid review; max five probes | PASS | `test_names_do_not_confer_safety_and_reviews_are_bounded` |
| Baseline guard | PASS | `test_unreviewed_baseline_blocked_before_socket` |
| Same-origin query redirect | PASS | Local server records only `/redirect`, not action URL; explicit reason |
| Reviewed vulnerable and safe endpoints | PASS | Local fixture: baseline + XSS + SQL = 3 requests per case; vulnerable yields both Low indicator findings, safe yields neither |
| Persisted skipped/error state | PASS | Temporary SQLite worker: HTTP Skipped with safety error, scan Failed, no HTTP requests |
| SSRF/origin/deadline | PASS | Out-of-origin request denied, metadata address rejected even with lab permission, expired budget denied |
| Request/size bounds | PASS | Reviewed request truncated at four bytes; second request rejected at budget 1 |
| Broader existing functionality | PASS | Full 328-method suite, including HTTPS, pinning, limits, worker, reports, AI mocks and repository tests |

These are safety/behavior tests, not a precision/recall benchmark. Positive detection
continues to mean an indicator, not demonstrated exploitation. The safe fixture
alone cannot establish global absence of false positives.

### Commands and results

Working directory: `/Users/kribeshthapa/Developer/Vibe code/SentinalScan`.
Existing `.venv/bin/python` used. Outer helpers allocate a temporary
`SENTINELSCAN_DATA_DIR`, disable default AI, and remove inherited GitHub token from
the child environment. Full suite opts into the already installed
`SENTINELSCAN_TEST_SEMGREP=/opt/homebrew/bin/semgrep`. No installation performed.

```sh
.venv/bin/python -B /tmp/phase20_before.py
PYTHONPATH=. .venv/bin/python -B /tmp/phase20_after.py
.venv/bin/python -B /tmp/phase20_tests.py
.venv/bin/python -B /tmp/phase20_focused.py
```

The test wrappers execute exactly:

```sh
.venv/bin/python -B -m unittest discover -s tests -v
.venv/bin/python -B -m unittest discover -s tests -p test_replay_safety.py -v
```

| Final run | Passed | Failed | Errors | Skipped | unittest time | Process wall | Exit |
|---|---:|---:|---:|---:|---:|---:|---:|
| Complete | 328 | 0 | 0 | 0 | 21.732s | 22.227s | 0 |
| Independent replay suite | 9 | 0 | 0 | 0 | 0.604s | 0.739s | 0 |

See `docs/audit/PHASE_20_TESTS.{log,json}` and
`docs/audit/PHASE_20_FOCUSED.{log,json}`. Helpers archived under
`docs/fixes/evidence/phase20_*.py`. Run archived scripts from the project root
with `PYTHONPATH=.` where imports need it. The before script requires the pre-fix
implementation; its captured JSON is retained, not represented as current behavior.

An intermediate run failed the new no-HTTP worker assertion: the test's mocked
Nmap lookup ended before its background worker completed, so real service detection
sent `/`. Keeping that mock active through worker shutdown fixed fixture isolation.
The final full run and independent run both passed. Earlier existing query-fixture
tests required explicit inert review because the default safety contract changed;
their detection assertions remain intact.

### Remaining limitations

- A queryless GET/path may change state. Existing resource-discovery GETs, TLS and
  port inventory continue; this phase does not certify them as side-effect-free.
  Nmap service detection is a separate existing path and may send application probes.
- A trusted operator may incorrectly classify an endpoint or mutation as inert.
  Exact URL/position checks limit scope but cannot prove application semantics.
  Do not approve arbitrary remote URLs just to restore query coverage.
- Default query scanning loses coverage intentionally when safety is unknown.
  Only reviewed endpoints regain active indicator checks; skipped coverage is visible.
- Only query mutations generated through this bounded helper receive probe permission;
  future network paths must reuse the same boundary. There is no new session/auth
  model, form submission, crawler or state rollback mechanism.
- Local/mocked tests do not prove universal safety, accuracy or production readiness.

Phase 20 complete. No Phase 21 work or OpenAnt integration undertaken.
