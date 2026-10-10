# Phase 14 — CodeQL integration repair

Date: 2026-10-09. Scope: D01 query-pack discovery and D02 SARIF notification status.
The existing integration, process supervisor, resource limits and static-only
repository workflow remain. No query pack, dependency, model or scanner installed;
no public repository or paid provider contacted. Fixtures are inert source text.

## Required context and baseline

Read CLAUDE.md, the six context documents in their prescribed order, AGENTS.md,
COMPLETE_TEST_AUDIT.md, PHASE_02_EXTERNAL_ENGINES.md and its evidence JSON, prior
Phase 11–13 fix reports, and repository_upgrade_phase_2.md. Inspected configuration,
launcher, repository worker, external adapter, subprocess/limit launcher and SARIF
importer. Working project: `/Users/kribeshthapa/Developer/Vibe code/SentinalScan`.
The obsolete Desktop path does not exist; the existing Developer checkout and its
`.venv/bin/python` were used.

Fresh reproductions before editing, in `PHASE_14_BEFORE.json`:

- **D01:** existing empty search-path configuration creates the Python database but
  analysis fails; no findings imported. Isolated `resolve queries` also exits 2 for
  both language packs, with “Query pack … cannot be found.”
- **D02:** temporary exact Python pack override allows create/analyze and imports
  one candidate, but successful SARIF with `none`/`note` notifications is reported
  **Partial**. Temporary workspace cleanup succeeds in both cases.

## Actual installed tool and packs

```text
/opt/homebrew/bin/codeql
  -> /opt/homebrew/Caskroom/codeql/2.27.2/codeql/codeql
CodeQL CLI: 2.27.2
Python: /Users/kribeshthapa/.codeql/packages/codeql/python-queries/1.8.12
JavaScript: /Users/kribeshthapa/.codeql/packages/codeql/javascript-queries/2.4.7
```

`codeql version`, `resolve packs --format=json`, installed `qlpack.yml` files and
local `database analyze --help` verified these facts. CLI help permits an OS-path-
separated list of pack directories. The cache root itself is not equivalent to
those exact pack directories. The package contents include the dependencies used
by these precompiled query suites; no download or installation was needed.

`PHASE_14_RESOLUTION.json` records bounded resolution through the **unchanged**
private-HOME process runner. Empty search path fails for both languages. The trusted
combined search path resolves **45 Python queries / 89 JavaScript queries**, exit 0.
An existing empty pack directory fails resolution, exit 2. Every diagnostic helper
has private HOME, no inherited PYTHONPATH/GITHUB_TOKEN, and verified cleanup.

## Changes

- `scanner/engines/external.py`: validate the existing `CODEQL_SEARCH_PATH` as an
  OS-path-separated list (colon on this Mac), retaining single-directory support.
  Resolve and deduplicate each path separately; pass one `--search-path=` argument
  containing the validated list to analysis for both languages. Reject non-string,
  overlong, control-character, empty-list-entry, relative, missing and scanned-
  repository paths, including symlinks resolving into the repository. Limit 16
  entries / 8,192 characters. No automatic cache search, installation or download.
- `run-local.sh`: supplies the two **installed, pinned** pack versions above through
  the existing environment setting, unless the operator overrides it. HOME is used
  only to construct these explicit launcher paths; the subprocess still receives a
  private HOME. `config.py` and repository configuration propagation already work
  and were not changed. Direct `python3 app.py` defaults remain unchanged.
- `scanner/engines/sarif.py`: `none` and `note` execution/configuration notifications
  no longer imply incomplete analysis. Warning/error notifications, omitted levels
  (conservatively warning) and `executionSuccessful: false` still yield **Partial**,
  retaining valid candidates. Invalid invocation containers, levels or success
  types fail as malformed output. No raw notification messages enter findings.
  Actual tool nonzero exit, timeout, missing result or malformed JSON still gives
  **Failed** through the existing adapter. One failed language and one successful
  language gives **Partial**, preserving the successful findings.
- `tests/test_codeql_repair.py`: nine regression methods covering configuration,
  mixed-language commands, cleanup, informational notifications, real-warning/error
  semantics, malformed metadata, timeout/execution failures and retained findings.

The list setting is trusted server configuration, not an HTTP/repository field.
Binary validation, private HOME/TMPDIR, environment allowlist, stdin closure, argv
execution, process-group termination, time/output/disk limits and resource launcher
are unchanged. No `shell=True`, `--download`, repository command or build fallback.

## Real launcher and repository-worker verification

Command: `.venv/bin/python -B /tmp/phase14_launch.py` runs `/bin/zsh ./run-local.sh`.
The actual launcher activates `.venv`, invokes `python3 -u app.py`, and creates the
Flask application using its real settings. A **temporary test-only sitecustomize
hook replaces Flask.run at the serving boundary**, then invokes the existing
`run_repository` worker against authored ZIP fixtures. It does not mock CodeQL,
change engine configuration or replace subprocess execution. This is verified
launcher/configuration/worker execution, not a new HTTP-server/browser test.

The parent sets temporary SENTINELSCAN_DATA_DIR and disables AI. It removes any
inherited search-path override to exercise the launcher default. GitHub archive
transport is a controlled fixture; no repository code executes. The hook's PYTHONPATH
is not forwarded to external tools. Existing Semgrep also runs under launcher flags.
Saved SQLite results, engine coverage, raw candidate locations, pre-correlation
CodeQL import, and removal of archives/CodeQL databases are asserted.

Final outcomes and per-command timings: `PHASE_14_LAUNCHER.json`. Launcher exited 0.
Measured repository-worker wall times (including existing other modules): python 12.820s, javascript 21.156s, mixed 32.004s.

| Repository | Create/query | CodeQL status | Imported CodeQL candidates | Safe-file candidates | Cleanup |
| --- | --- | --- | ---: | ---: | --- |
| Python only | Real installed CLI | Completed | 1 | 0 | Passed |
| JavaScript only | Real installed CLI | Completed | 1 | 0 | Passed |
| Mixed Python + JavaScript | Both languages, shared existing budget | Completed | 2 | 0 | Passed |

Expected findings: `py/sql-injection` at `positive.py:7` and `js/xss` at
`positive.js:2`. Each CodeQL import is High severity / Medium confidence, with
engine-reported flow. Fixed parameter binding and textContent safe fixtures do not
produce CodeQL results. Every final invocation has successful execution; informational
notifications remain informational. This small SQL/XSS smoke set is not an accuracy
benchmark or proof of general coverage.

**Persistence distinction:** existing cross-engine correlation merges these into
prior custom findings and retains CodeQL provenance. The persisted Python finding
is High; the persisted JavaScript finding is **Medium**, retaining the existing
custom DOM finding's severity rather than replacing it with CodeQL's High. No
correlation policy was changed. The initial live harness incorrectly expected the
merged JS severity to equal the raw CodeQL severity and stopped before mixed mode;
that test assumption was corrected, and both raw import and persisted severity are
now checked separately. Earlier unit-test path expectations also needed canonical
`/private/var` paths on macOS. Neither required weakening production behavior.

## Commands, tests and reproducibility

```sh
/opt/homebrew/bin/codeql version
/opt/homebrew/bin/codeql resolve packs --format=json
/opt/homebrew/bin/codeql database analyze --help
.venv/bin/python -B /tmp/phase14_live.py       # pre-edit defect reproductions
.venv/bin/python -B /tmp/phase14_resolve.py    # isolated pack resolution
.venv/bin/python -B /tmp/phase14_launch.py     # actual launcher, inert ZIP workers
SENTINELSCAN_TEST_SEMGREP=/opt/homebrew/bin/semgrep .venv/bin/python -B -m unittest tests.test_codeql_repair tests.test_repository_phase2 -v
.venv/bin/python -B /tmp/phase14_run.py --full
/bin/zsh -n run-local.sh
git diff --check
```

Full suite: **289 tests passed, 0 failures/errors/skips, 23.663 seconds, exit 0**.
Focused suite: **25 passed, 0 failures/errors/skips, 2.876 seconds, exit 0**.
The full wrapper uses unittest discovery over `tests`, temporary data before app
imports, disabled/mocked AI and installed Semgrep. CodeQL real checks are separate
from ordinary mocked regressions. Complete logs are `PHASE_14_TESTS.log` and
`PHASE_14_FOCUSED.log`. `PHASE_14_VERIFICATION.json` preserves temporary helper bodies,
final summaries and hashes; restore them to the recorded `/tmp` paths to reproduce.
The pre-edit baseline helper run after repair is no longer expected to reproduce D02.

## Limitations and operational notes

- Launcher pack versions are intentionally pinned to this verified installation.
  After an operator upgrades/moves packs, set SENTINELSCAN_CODEQL_SEARCH_PATH to
  actual absolute installed version directories. No silent version selection.
- Default direct app startup still leaves external engines disabled. Existing
  running servers need a restart through the updated launcher to inherit its
  environment; no unrelated live server was stopped or restarted here.
- Keep real warnings/errors visible. A Completed module is not proof of accurate
  detection, full language coverage or runtime exploitability.
- Existing CodeQL 120-second shared budget / repository deadline can limit larger
  mixed repositories. Python/JavaScript no-build extraction only; no compiled
  language/build expansion. The existing 1,024 MB RAM hint is rounded up by this
  CLI as recorded in Phase 02; no new hard memory guarantee is claimed.
- The existing runner is isolated by environment, working directory and resource
  limits, **not an OS filesystem/network sandbox**. No security control was bypassed
  or weakened, and no new sandbox is claimed. Trusted installed tools/packs remain
  an operator responsibility.
- Query/safe fixture outcomes do not resolve other scanner or AI audit defects.
  Historical failed/partial scan records remain unchanged; rescan for new coverage.

Phase 14 only. Stop after verification; no subsequent phase started.
