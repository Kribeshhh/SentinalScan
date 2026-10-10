# Phase 02 — Existing Semgrep and CodeQL integration verification

2026-10-08. Audit only; no application, integration, rules, query packs, dependencies or saved configuration changed. No public repository, live provider or paid service used. Fixtures were authored locally in temporary directories and statically analyzed, never executed. Existing user SQLite was not opened by the audit application. Tool subprocesses use the existing private HOME, environment allowlist, resource limits and no-build adapter.

Working directory: `/Users/kribeshthapa/Developer/Vibe code/SentinalScan`. Audit Python: existing `.venv/bin/python`, Python 3.13.5. The obsolete Desktop path was not used.

## Documents and implementation inspected

Read `CLAUDE.md`, then `context/project-overview.md`, `architecture.md`, `ui-context.md`, `code-standards.md`, `ai-workflow-rules.md`, `progress-tracker.md`, then `AGENTS.md` and `docs/audit/PHASE_01_ENVIRONMENT.md`. All present. Inspected `scanner/engines/{external,process,sarif,limit_exec}.py`, `semgrep_rules.yml`, `scanner/source_scanner.py`, `config.py`, `run-local.sh`, `tests/test_repository_phase2.py` and `tests/test_source_scanner.py`. No `tests/test_external_engines.py` exists; coverage is in `test_repository_phase2.py`.

## Engine state — distinguish current configuration from diagnostic overrides

| Engine / configuration | INSTALLED | ENABLED | INVOKED | COMPLETED | RESULTS IMPORTED |
|---|---|---|---|---|---|
| Semgrep, existing launcher settings | Yes, 1.179.0 | Yes in launcher-created Flask configuration | Yes, real adapter | Yes, Python and JS | Yes: 1 Python High, 1 JS Medium |
| CodeQL, existing launcher settings | CLI 2.27.2; cached query packs exist | Yes; search path empty | Yes: create and analyze, both languages | **No**: query-pack resolution fails after DB creation | No; this is failed coverage, not a clean scan |
| CodeQL, temporary exact-pack search-path overrides | Same installation | Yes, isolated audit configuration only | Yes, both languages | CLI succeeds; **adapter status Partial** | Yes: 1 Python High, 1 JS High |

Default `config.py` flags are false. Existing `run-local.sh` forces both true and supplies Homebrew binary paths. This audit did not change those defaults or persist an override.

## Findings and blockers

1. **Semgrep PASS:** bundled configuration validation returns “Configuration is valid - found 0 configuration error(s), and 3 rule(s).” Live existing tests exercise SQL, shell and DOM positives, parameterized/constant/numeric SQL negatives, shell=False and DOMPurify protection. Additional real adapter runs verify exact paths, lines and severities below.
2. **CodeQL current configuration FAIL:** installed query packs are cached under the user's `.codeql/packages`, but `run_tool` replaces HOME with a private temporary directory. The launcher supplies no `CODEQL_SEARCH_PATH`. Both real analysis attempts report `Query pack codeql/<language>-queries cannot be found.` The initial legacy `resolve qlpacks` listing alone did not establish installation; `resolve packs --format=json` and filesystem manifests confirmed the cache.
3. **CodeQL diagnostic override PARTIAL:** searching the cache root still fails. Passing each exact installed version directory via the existing `CODEQL_SEARCH_PATH` setting succeeds, without any installation or integration change. These were separate per-language runs, not a verified permanent setting for a mixed-language repository.
4. **Misleading Partial classification:** successful CodeQL SARIF has `executionSuccessful: true`, zero rejected results, and informational execution notifications. `sarif.py` marks any nonempty `toolExecutionNotifications` as partial, even successful extraction/telemetry notifications. Both controlled analyses therefore report Partial despite successful query execution. This is an observed integration status limitation; it was not fixed.
5. CodeQL reports `Rounding --ram up to the minimum of 2048` despite the adapter's `--ram=1024`. Thus that flag is not an effective 1 GiB cap for this installed release. Existing time/disk bounds remained active.

## Installed packs and binaries

```text
/opt/homebrew/bin/semgrep -> ../Cellar/semgrep/1.179.0/bin/semgrep
Resolved adapter executable: /opt/homebrew/Cellar/semgrep/1.179.0/libexec/bin/semgrep
/opt/homebrew/bin/codeql -> /opt/homebrew/Caskroom/codeql/2.27.2/codeql/codeql
codeql/python-queries 1.8.12:
  /Users/kribeshthapa/.codeql/packages/codeql/python-queries/1.8.12
codeql/javascript-queries 2.4.7:
  /Users/kribeshthapa/.codeql/packages/codeql/javascript-queries/2.4.7
```

Both query-pack manifests identify build CLI 2.27.2. Installed precompiled queries execute under the exact-directory overrides. No dependency-pack download or source compilation setup was attempted.

Inventory commands:

```sh
ls -l /opt/homebrew/bin/semgrep /opt/homebrew/bin/codeql
/opt/homebrew/bin/semgrep --version
/opt/homebrew/bin/codeql version
/opt/homebrew/bin/codeql resolve qlpacks --format=json
/opt/homebrew/bin/codeql resolve packs --format=json
cat /Users/kribeshthapa/.codeql/packages/codeql/python-queries/1.8.12/qlpack.yml /Users/kribeshthapa/.codeql/packages/codeql/javascript-queries/2.4.7/qlpack.yml
```

The versions were also rechecked inside the real isolated runner (timed commands below). Default isolated `resolve queries codeql/python-queries` and its JavaScript equivalent both exit 2 with the fatal pack-not-found message. Exact-directory resolutions return query lists successfully. Full captured outputs are in the evidence JSON.

## Flask flags and pipeline wiring

The unchanged launcher was sourced with an audit-only shell function replacing its final `python3 -u app.py` call with a venv Python helper that creates the real Flask app against temporary SQLite and prints only allowlisted configuration. This verifies launcher environment inheritance into a Flask process, without leaving a server running or triggering a scan. It is an instrumented launcher check, not a claim about some other pre-existing server's configuration.

```sh
/bin/zsh -c 'function python3() { .venv/bin/python -B /tmp/sentinel_flags02.py; }; source ./run-local.sh'
```

Output:

```json
{
  "executable": "/Users/kribeshthapa/Developer/Vibe code/SentinalScan/.venv/bin/python",
  "config": {
    "SEMGREP_ENABLED": true,
    "CODEQL_ENABLED": true,
    "SEMGREP_BINARY": "/opt/homebrew/bin/semgrep",
    "CODEQL_BINARY": "/opt/homebrew/bin/codeql",
    "CODEQL_SEARCH_PATH": "",
    "LLM_ENABLED": false
  }
}
```

Static pipeline evidence: `run_repository` copies SEMGREP_ENABLED/BINARY and CODEQL_ENABLED/BINARY/SEARCH_PATH directly from Flask configuration into `ctx['engine_config']`. Both external adapters are registered in `MODULES`. Existing `test_optional_tool_failure_preserves_custom_scan` verifies the configured engines are invoked and their failures do not fail the deterministic repository scan, with mocked tool boundaries.

## Positive and negative checks

| Engine | Controlled positive | Imported severity / evidence | Negative |
|---|---|---|---|
| Semgrep Python | `positive.py:7`, constructed query from Flask request | High; bundled flask-sql-flow rule, normalized static-candidate evidence | Parameterized `negative.py`: 0 findings |
| Semgrep JavaScript | `positive.js:2`, location.hash to innerHTML | Medium; bundled dom-flow rule, normalized static-candidate evidence | textContent `negative.js`: 0 findings |
| CodeQL Python, exact pack path | `positive.py:7` | High; `py/sql-injection`, CWE-89, engine-reported flow, Medium confidence | Parameterized `negative.py`: 0 findings |
| CodeQL JavaScript, exact pack path | `positive.js:2` | High; `js/xss`, CWE-79, engine-reported flow, Medium confidence | textContent `negative.js`: 0 findings |

All imported locations are repository-relative fixture paths; no rejected SARIF results. Evidence explicitly says static candidates and paths do not prove runtime exploitability. Raw tool messages are not persisted by the importer. Positive/negative fixture results are narrow integration checks, not real-world precision/recall or proof that all vulnerabilities are detected.

## Safe failure and cleanup checks

- Missing executable: mocked for both adapters → Skipped, zero imported findings.
- Invalid JSON/SARIF: mocked for both adapters → Failed, deterministic results retained.
- Timeout: mocked adapter failures for both, plus existing trusted-helper process timeout test → bounded failure.
- Nonzero exit: mocked for both adapters and an actual trusted `raise SystemExit(7)` subprocess → sanitized ToolFailure.
- Missing CodeQL pack: mocked analyze-stage failure and actual isolated pack-not-found failures → Failed, no false clean assessment.
- Existing tests also cover traversal/remote SARIF URIs, rejected repository-owned executable, output bounds, stripped inherited credentials and safe no-build arguments.
- Actual database-create commands succeed for Python and JavaScript, with `codeql-database.yml` observed before analysis. SARIF export/parsing succeeds under exact-directory overrides. Each real adapter workspace is absent after return, on both success and failure; fixture/helper workspaces are TemporaryDirectory-managed as well.
- The existing repository pipeline test verifies custom findings survive engine failures. No change to scanner behavior or tests was made.

## Existing tests run

```sh
SENTINELSCAN_TEST_SEMGREP=/opt/homebrew/bin/semgrep .venv/bin/python -B -m unittest discover -s tests -p test_repository_phase2.py -v
.venv/bin/python -B -m unittest discover -s tests -p test_source_scanner.py -v
```

**32 tests passed, 0 failed, 0 skipped** across these two existing suites: 16 in 1.916s and 16 in 1.946s. This includes live Semgrep, mocked CodeQL contracts, and mocked repository network boundaries. Live CodeQL experiments above are separate from those unittest counts. The entire project suite was not run in this focused external-engine audit.

## Timed real commands and results

Commands were passed as argument arrays (no shell execution of scanned source). Each runs through the unchanged `run_tool`, which prepends `.venv/bin/python -I scanner/engines/limit_exec.py` and constructs the private environment. The trusted `python -I -c` capture helpers below only run tool inventory commands, never fixture code. `PASS` for a capture helper means the helper completed: consult its nested `returncode` for the inventory command's actual success.

### baseline

```sh
'/Users/kribeshthapa/Developer/Vibe code/SentinalScan/.venv/bin/python' -I -c 'import subprocess,json,pathlib; p=subprocess.run(['"'"'/opt/homebrew/bin/semgrep'"'"', '"'"'--version'"'"'],capture_output=True,text=True);pathlib.Path("capture.json").write_text(json.dumps({"returncode":p.returncode,"stdout":p.stdout,"stderr":p.stderr}))'
```

PASS; 1.497 s. 

```sh
'/Users/kribeshthapa/Developer/Vibe code/SentinalScan/.venv/bin/python' -I -c 'import subprocess,json,pathlib; p=subprocess.run(['"'"'/opt/homebrew/bin/codeql'"'"', '"'"'version'"'"'],capture_output=True,text=True);pathlib.Path("capture.json").write_text(json.dumps({"returncode":p.returncode,"stdout":p.stdout,"stderr":p.stderr}))'
```

PASS; 0.498 s. 

```sh
'/Users/kribeshthapa/Developer/Vibe code/SentinalScan/.venv/bin/python' -I -c 'import subprocess,json,pathlib; p=subprocess.run(['"'"'/opt/homebrew/bin/codeql'"'"', '"'"'resolve'"'"', '"'"'qlpacks'"'"', '"'"'--format=json'"'"'],capture_output=True,text=True);pathlib.Path("capture.json").write_text(json.dumps({"returncode":p.returncode,"stdout":p.stdout,"stderr":p.stderr}))'
```

PASS; 0.515 s. 

```sh
'/Users/kribeshthapa/Developer/Vibe code/SentinalScan/.venv/bin/python' -I -c 'import subprocess,json,pathlib; p=subprocess.run(['"'"'/opt/homebrew/bin/codeql'"'"', '"'"'resolve'"'"', '"'"'queries'"'"', '"'"'codeql/python-queries'"'"'],capture_output=True,text=True);pathlib.Path("capture.json").write_text(json.dumps({"returncode":p.returncode,"stdout":p.stdout,"stderr":p.stderr}))'
```

PASS; 0.479 s. 

```sh
'/Users/kribeshthapa/Developer/Vibe code/SentinalScan/.venv/bin/python' -I -c 'import subprocess,json,pathlib; p=subprocess.run(['"'"'/opt/homebrew/bin/codeql'"'"', '"'"'resolve'"'"', '"'"'queries'"'"', '"'"'codeql/javascript-queries'"'"'],capture_output=True,text=True);pathlib.Path("capture.json").write_text(json.dumps({"returncode":p.returncode,"stdout":p.stdout,"stderr":p.stderr}))'
```

PASS; 0.481 s. 

```sh
/opt/homebrew/bin/semgrep scan --validate --config '/Users/kribeshthapa/Developer/Vibe code/SentinalScan/scanner/engines/semgrep_rules.yml' --metrics=off --disable-version-check
```

PASS; 1.512 s. 

```text
Configuration is valid - found 0 configuration error(s), and 3 rule(s).

```

```sh
/opt/homebrew/Cellar/semgrep/1.179.0/libexec/bin/semgrep scan --config '/Users/kribeshthapa/Developer/Vibe code/SentinalScan/scanner/engines/semgrep_rules.yml' --sarif --output /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-semgrep-qrzh8gm0/result.sarif --dataflow-traces --metrics=off --disable-version-check --no-rewrite-rule-ids --disable-nosem --no-git-ignore --jobs=1 --max-memory=512 --timeout=5 --max-target-bytes=524288 /private/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinel-audit02-8pnv48lo/semgrep-python
```

PASS; 1.47 s. 

```text
               
               
┌─────────────┐
│ Scan Status │
└─────────────┘
  Scanning 2 files with 3 Code rules:
  Scanning 2 files with 2 python rules.
                
                
┌──────────────┐
│ Scan Summary │
└──────────────┘
✅ Scan completed successfully.
 • Findings: 1 (1 blocking)
 • Rules run: 2
 • Targets scanned: 2
 • Parsed lines: ~100.0%
 • No ignore information available
Ran 2 rules on 2 files: 1 finding.

```

Result: `{"check": "integration", "engine": "semgrep", "language": "python", "seconds": 1.476, "result": {"candidates": 1, "rejected_results": 0, "status": "Completed"}, "cleanup": true}`

```sh
/opt/homebrew/Cellar/semgrep/1.179.0/libexec/bin/semgrep scan --config '/Users/kribeshthapa/Developer/Vibe code/SentinalScan/scanner/engines/semgrep_rules.yml' --sarif --output /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-semgrep-sg7b375m/result.sarif --dataflow-traces --metrics=off --disable-version-check --no-rewrite-rule-ids --disable-nosem --no-git-ignore --jobs=1 --max-memory=512 --timeout=5 --max-target-bytes=524288 /private/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinel-audit02-8pnv48lo/semgrep-javascript
```

PASS; 1.278 s. 

```text
               
               
┌─────────────┐
│ Scan Status │
└─────────────┘
  Scanning 2 files with 3 Code rules:
  Scanning 2 files.
                
                
┌──────────────┐
│ Scan Summary │
└──────────────┘
✅ Scan completed successfully.
 • Findings: 1 (1 blocking)
 • Rules run: 1
 • Targets scanned: 2
 • Parsed lines: ~100.0%
 • No ignore information available
Ran 1 rule on 2 files: 1 finding.

```

Result: `{"check": "integration", "engine": "semgrep", "language": "javascript", "seconds": 1.282, "result": {"candidates": 1, "rejected_results": 0, "status": "Completed"}, "cleanup": true}`

```sh
/opt/homebrew/Caskroom/codeql/2.27.2/codeql/codeql database create /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-dv4d70_2/python-db --language=python --build-mode=none --source-root=/private/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinel-audit02-8pnv48lo/codeql-python --threads=1 --ram=1024
```

PASS; 3.484 s. 

```text
Initializing database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-dv4d70_2/python-db.
Running build command: []
Running command in /private/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinel-audit02-8pnv48lo/codeql-python: [/opt/homebrew/Caskroom/codeql/2.27.2/codeql/python/tools/autobuild.sh]
[2026-10-08 13:14:04]
[excerpt; full output in evidence JSON]
deql/python/tools/pre-finalize.sh]
[2026-10-08 13:14:05] [build-stderr] Scanning for files in /private/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinel-audit02-8pnv48lo/codeql-python...
Pre-finalize script /opt/homebrew/Caskroom/codeql/2.27.2/codeql/python/tools/pre-finalize.sh completed in 452 ms.
Running TRAP import for CodeQL database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-dv4d70_2/python-db...
WARNING: Rounding --ram up to the minimum of 2048
Importing TRAP files
Merging relations
Finished writing database (relations: 40.89 KiB; string pool: 2.06 MiB).
TRAP import complete (754ms).
Finished zipping source archive (956.00 B).
Successfully created database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-dv4d70_2/python-db.

```

```sh
/opt/homebrew/Caskroom/codeql/2.27.2/codeql/codeql database analyze /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-dv4d70_2/python-db codeql/python-queries --format=sarifv2.1.0 --output=/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-dv4d70_2/python.sarif --threads=1 --ram=1024 --timeout=30 --no-sarif-add-file-contents
```

FAIL; 0.939 s. Tool failed; raw diagnostics are omitted to protect source data.

```text
Running queries.
WARNING: Rounding --ram up to the minimum of 2048
A fatal error occurred: Query pack codeql/python-queries cannot be found. Check the spelling of the pack.

```

Result: `{"check": "integration", "engine": "codeql", "language": "python", "seconds": 4.442, "result": {"status": "Failed", "languages": [{"language": "python", "status": "Failed", "note": "Tool failed; raw diagnostics are omitted to protect source data."}], "note": "No-build extraction only. Installed query packs required; no automatic downloads or builds."}, "cleanup": true}`

```sh
/opt/homebrew/Caskroom/codeql/2.27.2/codeql/codeql database create /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-5yyc_qii/javascript-db --language=javascript --build-mode=none --source-root=/private/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinel-audit02-8pnv48lo/codeql-javascript --threads=1 --ram=1024
```

PASS; 4.643 s. 

```text
Initializing database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-5yyc_qii/javascript-db.
Running build command: []
Running command in /private/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinel-audit02-8pnv48lo/codeql-javascript: [/opt/homebrew/Caskroom/codeql/2.27.2/codeql/javascript/tools/autobuild.sh]
[2026-10-
[excerpt; full output in evidence JSON]
ript/tools/data/externs/es/es2016.js
[2026-10-08 13:14:09] [build-stdout] Done extracting /opt/homebrew/Caskroom/codeql/2.27.2/codeql/javascript/tools/data/externs/es/es2016.js (1 ms)
Finalizing database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-5yyc_qii/javascript-db.
Running TRAP import for CodeQL database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-5yyc_qii/javascript-db...
WARNING: Rounding --ram up to the minimum of 2048
Importing TRAP files
Merging relations
Finished writing database (relations: 3.07 MiB; string pool: 4.78 MiB).
TRAP import complete (1.8s).
Finished zipping source archive (247.58 KiB).
Successfully created database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-5yyc_qii/javascript-db.

```

```sh
/opt/homebrew/Caskroom/codeql/2.27.2/codeql/codeql database analyze /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-5yyc_qii/javascript-db codeql/javascript-queries --format=sarifv2.1.0 --output=/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-5yyc_qii/javascript.sarif --threads=1 --ram=1024 --timeout=30 --no-sarif-add-file-contents
```

FAIL; 0.98 s. Tool failed; raw diagnostics are omitted to protect source data.

```text
Running queries.
WARNING: Rounding --ram up to the minimum of 2048
A fatal error occurred: Query pack codeql/javascript-queries cannot be found. Check the spelling of the pack.

```

Result: `{"check": "integration", "engine": "codeql", "language": "javascript", "seconds": 5.635, "result": {"status": "Failed", "languages": [{"language": "javascript", "status": "Failed", "note": "Tool failed; raw diagnostics are omitted to protect source data."}], "note": "No-build extraction only. Installed query packs required; no automatic downloads or builds."}, "cleanup": true}`

```sh
'/Users/kribeshthapa/Developer/Vibe code/SentinalScan/.venv/bin/python' -I -c 'raise SystemExit(7)'
```

FAIL; 0.038 s. Tool failed; raw diagnostics are omitted to protect source data.

### cache_root_search

```sh
'/Users/kribeshthapa/Developer/Vibe code/SentinalScan/.venv/bin/python' -I -c 'import subprocess,json,pathlib; p=subprocess.run(['"'"'/opt/homebrew/bin/codeql'"'"', '"'"'resolve'"'"', '"'"'queries'"'"', '"'"'codeql/python-queries'"'"', '"'"'--search-path=/Users/kribeshthapa/.codeql/packages'"'"'],capture_output=True,text=True);pathlib.Path("capture.json").write_text(json.dumps({"returncode":p.returncode,"stdout":p.stdout,"stderr":p.stderr}))'
```

PASS; 0.855 s. 

```sh
/opt/homebrew/Caskroom/codeql/2.27.2/codeql/codeql database create /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-fk9q9ydz/python-db --language=python --build-mode=none --source-root=/private/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinel-packs02-w1ylmsz6/python --threads=1 --ram=1024
```

PASS; 3.459 s. 

```text
Initializing database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-fk9q9ydz/python-db.
Running build command: []
Running command in /private/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinel-packs02-w1ylmsz6/python: [/opt/homebrew/Caskroom/codeql/2.27.2/codeql/python/tools/autobuild.sh]
[2026-10-08 13:15:00] [build
[excerpt; full output in evidence JSON]
27.2/codeql/python/tools/pre-finalize.sh]
[2026-10-08 13:15:01] [build-stderr] Scanning for files in /private/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinel-packs02-w1ylmsz6/python...
Pre-finalize script /opt/homebrew/Caskroom/codeql/2.27.2/codeql/python/tools/pre-finalize.sh completed in 464 ms.
Running TRAP import for CodeQL database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-fk9q9ydz/python-db...
WARNING: Rounding --ram up to the minimum of 2048
Importing TRAP files
Merging relations
Finished writing database (relations: 40.90 KiB; string pool: 2.06 MiB).
TRAP import complete (901ms).
Finished zipping source archive (928.00 B).
Successfully created database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-fk9q9ydz/python-db.

```

```sh
/opt/homebrew/Caskroom/codeql/2.27.2/codeql/codeql database analyze /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-fk9q9ydz/python-db codeql/python-queries --format=sarifv2.1.0 --output=/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-fk9q9ydz/python.sarif --threads=1 --ram=1024 --timeout=30 --no-sarif-add-file-contents --search-path=/Users/kribeshthapa/.codeql/packages
```

FAIL; 0.985 s. Tool failed; raw diagnostics are omitted to protect source data.

```text
Running queries.
WARNING: Rounding --ram up to the minimum of 2048
A fatal error occurred: Query pack codeql/python-queries cannot be found. Check the spelling of the pack.

```

Result: `{"check": "configured integration", "language": "python", "seconds": 4.466, "result": {"status": "Failed", "languages": [{"language": "python", "status": "Failed", "note": "Tool failed; raw diagnostics are omitted to protect source data."}], "note": "No-build extraction only. Installed query packs required; no automatic downloads or builds."}, "cleanup": true}`

```sh
'/Users/kribeshthapa/Developer/Vibe code/SentinalScan/.venv/bin/python' -I -c 'import subprocess,json,pathlib; p=subprocess.run(['"'"'/opt/homebrew/bin/codeql'"'"', '"'"'resolve'"'"', '"'"'queries'"'"', '"'"'codeql/javascript-queries'"'"', '"'"'--search-path=/Users/kribeshthapa/.codeql/packages'"'"'],capture_output=True,text=True);pathlib.Path("capture.json").write_text(json.dumps({"returncode":p.returncode,"stdout":p.stdout,"stderr":p.stderr}))'
```

PASS; 0.533 s. 

```sh
/opt/homebrew/Caskroom/codeql/2.27.2/codeql/codeql database create /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-_rsadul0/javascript-db --language=javascript --build-mode=none --source-root=/private/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinel-packs02-w1ylmsz6/javascript --threads=1 --ram=1024
```

PASS; 4.706 s. 

```text
Initializing database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-_rsadul0/javascript-db.
Running build command: []
Running command in /private/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinel-packs02-w1ylmsz6/javascript: [/opt/homebrew/Caskroom/codeql/2.27.2/codeql/javascript/tools/autobuild.sh]
[2026-10-08 13:1
[excerpt; full output in evidence JSON]
ript/tools/data/externs/es/es2016.js
[2026-10-08 13:15:06] [build-stdout] Done extracting /opt/homebrew/Caskroom/codeql/2.27.2/codeql/javascript/tools/data/externs/es/es2016.js (1 ms)
Finalizing database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-_rsadul0/javascript-db.
Running TRAP import for CodeQL database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-_rsadul0/javascript-db...
WARNING: Rounding --ram up to the minimum of 2048
Importing TRAP files
Merging relations
Finished writing database (relations: 3.07 MiB; string pool: 4.78 MiB).
TRAP import complete (1.8s).
Finished zipping source archive (247.55 KiB).
Successfully created database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-_rsadul0/javascript-db.

```

```sh
/opt/homebrew/Caskroom/codeql/2.27.2/codeql/codeql database analyze /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-_rsadul0/javascript-db codeql/javascript-queries --format=sarifv2.1.0 --output=/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-_rsadul0/javascript.sarif --threads=1 --ram=1024 --timeout=30 --no-sarif-add-file-contents --search-path=/Users/kribeshthapa/.codeql/packages
```

FAIL; 1.061 s. Tool failed; raw diagnostics are omitted to protect source data.

```text
Running queries.
WARNING: Rounding --ram up to the minimum of 2048
A fatal error occurred: Query pack codeql/javascript-queries cannot be found. Check the spelling of the pack.

```

Result: `{"check": "configured integration", "language": "javascript", "seconds": 5.781, "result": {"status": "Failed", "languages": [{"language": "javascript", "status": "Failed", "note": "Tool failed; raw diagnostics are omitted to protect source data."}], "note": "No-build extraction only. Installed query packs required; no automatic downloads or builds."}, "cleanup": true}`

### exact_pack_search

```sh
'/Users/kribeshthapa/Developer/Vibe code/SentinalScan/.venv/bin/python' -I -c 'import subprocess,json,pathlib; p=subprocess.run(['"'"'/opt/homebrew/bin/codeql'"'"', '"'"'resolve'"'"', '"'"'queries'"'"', '"'"'codeql/python-queries'"'"', '"'"'--search-path=/Users/kribeshthapa/.codeql/packages/codeql/python-queries/1.8.12'"'"'],capture_output=True,text=True);pathlib.Path("capture.json").write_text(json.dumps({"returncode":p.returncode,"stdout":p.stdout,"stderr":p.stderr}))'
```

PASS; 0.917 s. 

```sh
/opt/homebrew/Caskroom/codeql/2.27.2/codeql/codeql database create /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-8hgbujrm/python-db --language=python --build-mode=none --source-root=/private/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinel-packs02-xxt7jumz/python --threads=1 --ram=1024
```

PASS; 3.275 s. 

```text
Initializing database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-8hgbujrm/python-db.
Running build command: []
Running command in /private/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinel-packs02-xxt7jumz/python: [/opt/homebrew/Caskroom/codeql/2.27.2/codeql/python/tools/autobuild.sh]
[2026-10-08 13:15:32] [build
[excerpt; full output in evidence JSON]
27.2/codeql/python/tools/pre-finalize.sh]
[2026-10-08 13:15:33] [build-stderr] Scanning for files in /private/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinel-packs02-xxt7jumz/python...
Pre-finalize script /opt/homebrew/Caskroom/codeql/2.27.2/codeql/python/tools/pre-finalize.sh completed in 454 ms.
Running TRAP import for CodeQL database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-8hgbujrm/python-db...
WARNING: Rounding --ram up to the minimum of 2048
Importing TRAP files
Merging relations
Finished writing database (relations: 40.90 KiB; string pool: 2.06 MiB).
TRAP import complete (683ms).
Finished zipping source archive (928.00 B).
Successfully created database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-8hgbujrm/python-db.

```

```sh
/opt/homebrew/Caskroom/codeql/2.27.2/codeql/codeql database analyze /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-8hgbujrm/python-db codeql/python-queries --format=sarifv2.1.0 --output=/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-8hgbujrm/python.sarif --threads=1 --ram=1024 --timeout=30 --no-sarif-add-file-contents --search-path=/Users/kribeshthapa/.codeql/packages/codeql/python-queries/1.8.12
```

PASS; 7.487 s. 

```text
Running queries.
WARNING: Rounding --ram up to the minimum of 2048
Resolving data extensions.
Finished resolving data extensions.
Loading data extensions.
Finished loading data extensions.
WARNING: Not caching stages during query-loading, since max heap size is only 1256 MB.
[1/45] Loaded /Users/kribeshthapa/.codeql/packages/codeql/python-queries/1
[excerpt; full output in evidence JSON]
odeql/python-queries/1.8.12/Diagnostics/ExtractedFiles.ql...
Interpreting /Users/kribeshthapa/.codeql/packages/codeql/python-queries/1.8.12/Diagnostics/ExtractionWarnings.ql...
Interpreting /Users/kribeshthapa/.codeql/packages/codeql/python-queries/1.8.12/Summary/LinesOfCode.ql...
Interpreting /Users/kribeshthapa/.codeql/packages/codeql/python-queries/1.8.12/Summary/LinesOfUserCode.ql...
Reading source archive /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-8hgbujrm/python-db/src.zip
CodeQL scanned 2 out of 2 Python files in this invocation. Typically CodeQL is configured to analyze a single CodeQL language per invocation, so check other invocations to determine overall coverage information.
Exporting results to SARIF v2.1.0...
Exported results to SARIF v2.1.0 (76ms).

```

Result: `{"check": "configured integration", "language": "python", "seconds": 10.848, "result": {"status": "Partial", "languages": [{"candidates": 1, "rejected_results": 0, "status": "Partial", "language": "python"}], "note": "No-build extraction only. Installed query packs required; no automatic downloads or builds."}, "cleanup": true}`

```sh
'/Users/kribeshthapa/Developer/Vibe code/SentinalScan/.venv/bin/python' -I -c 'import subprocess,json,pathlib; p=subprocess.run(['"'"'/opt/homebrew/bin/codeql'"'"', '"'"'resolve'"'"', '"'"'queries'"'"', '"'"'codeql/javascript-queries'"'"', '"'"'--search-path=/Users/kribeshthapa/.codeql/packages/codeql/javascript-queries/2.4.7'"'"'],capture_output=True,text=True);pathlib.Path("capture.json").write_text(json.dumps({"returncode":p.returncode,"stdout":p.stdout,"stderr":p.stderr}))'
```

PASS; 0.71 s. 

```sh
/opt/homebrew/Caskroom/codeql/2.27.2/codeql/codeql database create /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-nfo6ggf1/javascript-db --language=javascript --build-mode=none --source-root=/private/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinel-packs02-xxt7jumz/javascript --threads=1 --ram=1024
```

PASS; 4.328 s. 

```text
Initializing database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-nfo6ggf1/javascript-db.
Running build command: []
Running command in /private/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinel-packs02-xxt7jumz/javascript: [/opt/homebrew/Caskroom/codeql/2.27.2/codeql/javascript/tools/autobuild.sh]
[2026-10-08 13:1
[excerpt; full output in evidence JSON]
ript/tools/data/externs/es/es2016.js
[2026-10-08 13:15:45] [build-stdout] Done extracting /opt/homebrew/Caskroom/codeql/2.27.2/codeql/javascript/tools/data/externs/es/es2016.js (1 ms)
Finalizing database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-nfo6ggf1/javascript-db.
Running TRAP import for CodeQL database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-nfo6ggf1/javascript-db...
WARNING: Rounding --ram up to the minimum of 2048
Importing TRAP files
Merging relations
Finished writing database (relations: 3.07 MiB; string pool: 4.78 MiB).
TRAP import complete (1.6s).
Finished zipping source archive (247.55 KiB).
Successfully created database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-nfo6ggf1/javascript-db.

```

```sh
/opt/homebrew/Caskroom/codeql/2.27.2/codeql/codeql database analyze /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-nfo6ggf1/javascript-db codeql/javascript-queries --format=sarifv2.1.0 --output=/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-nfo6ggf1/javascript.sarif --threads=1 --ram=1024 --timeout=30 --no-sarif-add-file-contents --search-path=/Users/kribeshthapa/.codeql/packages/codeql/javascript-queries/2.4.7
```

PASS; 15.314 s. 

```text
Running queries.
WARNING: Rounding --ram up to the minimum of 2048
Resolving data extensions.
Finished resolving data extensions.
Loading data extensions.
Finished loading data extensions.
WARNING: Not caching stages during query-loading, since max heap size is only 1224 MB.
[1/89] Loaded /Users/kribeshthapa/.codeql/packages/codeql/javascript-queri
[excerpt; full output in evidence JSON]
7/Diagnostics/ExtractionErrors.ql...
Interpreting /Users/kribeshthapa/.codeql/packages/codeql/javascript-queries/2.4.7/Diagnostics/ExtractedFiles.ql...
Interpreting /Users/kribeshthapa/.codeql/packages/codeql/javascript-queries/2.4.7/Summary/LinesOfCode.ql...
Interpreting /Users/kribeshthapa/.codeql/packages/codeql/javascript-queries/2.4.7/Summary/LinesOfUserCode.ql...
Reading source archive /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-nfo6ggf1/javascript-db/src.zip
CodeQL scanned 2 out of 2 JavaScript/TypeScript files in this invocation. Typically CodeQL is configured to analyze a single CodeQL language per invocation, so check other invocations to determine overall coverage information.
Exporting results to SARIF v2.1.0...
Exported results to SARIF v2.1.0 (82ms).

```

Result: `{"check": "configured integration", "language": "javascript", "seconds": 19.796, "result": {"status": "Partial", "languages": [{"candidates": 1, "rejected_results": 0, "status": "Partial", "language": "javascript"}], "note": "No-build extraction only. Installed query packs required; no automatic downloads or builds."}, "cleanup": true}`

### notification_diagnostic

```sh
'/Users/kribeshthapa/Developer/Vibe code/SentinalScan/.venv/bin/python' -I -c 'import subprocess,json,pathlib; p=subprocess.run(['"'"'/opt/homebrew/bin/codeql'"'"', '"'"'resolve'"'"', '"'"'queries'"'"', '"'"'codeql/python-queries'"'"', '"'"'--search-path=/Users/kribeshthapa/.codeql/packages/codeql/python-queries/1.8.12'"'"'],capture_output=True,text=True);pathlib.Path("capture.json").write_text(json.dumps({"returncode":p.returncode,"stdout":p.stdout,"stderr":p.stderr}))'
```

PASS; 0.938 s. 

```sh
/opt/homebrew/Caskroom/codeql/2.27.2/codeql/codeql database create /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-6egbzp68/python-db --language=python --build-mode=none --source-root=/private/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinel-packs02-3k3ruh42/python --threads=1 --ram=1024
```

PASS; 3.519 s. 

```text
Initializing database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-6egbzp68/python-db.
Running build command: []
Running command in /private/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinel-packs02-3k3ruh42/python: [/opt/homebrew/Caskroom/codeql/2.27.2/codeql/python/tools/autobuild.sh]
[2026-10-08 13:16:23] [build
[excerpt; full output in evidence JSON]
27.2/codeql/python/tools/pre-finalize.sh]
[2026-10-08 13:16:25] [build-stderr] Scanning for files in /private/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinel-packs02-3k3ruh42/python...
Pre-finalize script /opt/homebrew/Caskroom/codeql/2.27.2/codeql/python/tools/pre-finalize.sh completed in 525 ms.
Running TRAP import for CodeQL database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-6egbzp68/python-db...
WARNING: Rounding --ram up to the minimum of 2048
Importing TRAP files
Merging relations
Finished writing database (relations: 40.90 KiB; string pool: 2.06 MiB).
TRAP import complete (904ms).
Finished zipping source archive (928.00 B).
Successfully created database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-6egbzp68/python-db.

```

```sh
/opt/homebrew/Caskroom/codeql/2.27.2/codeql/codeql database analyze /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-6egbzp68/python-db codeql/python-queries --format=sarifv2.1.0 --output=/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-6egbzp68/python.sarif --threads=1 --ram=1024 --timeout=30 --no-sarif-add-file-contents --search-path=/Users/kribeshthapa/.codeql/packages/codeql/python-queries/1.8.12
```

PASS; 7.41 s. 

```text
Running queries.
WARNING: Rounding --ram up to the minimum of 2048
Resolving data extensions.
Finished resolving data extensions.
Loading data extensions.
Finished loading data extensions.
WARNING: Not caching stages during query-loading, since max heap size is only 1256 MB.
[1/45] Loaded /Users/kribeshthapa/.codeql/packages/codeql/python-queries/1
[excerpt; full output in evidence JSON]
odeql/python-queries/1.8.12/Diagnostics/ExtractedFiles.ql...
Interpreting /Users/kribeshthapa/.codeql/packages/codeql/python-queries/1.8.12/Diagnostics/ExtractionWarnings.ql...
Interpreting /Users/kribeshthapa/.codeql/packages/codeql/python-queries/1.8.12/Summary/LinesOfCode.ql...
Interpreting /Users/kribeshthapa/.codeql/packages/codeql/python-queries/1.8.12/Summary/LinesOfUserCode.ql...
Reading source archive /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-6egbzp68/python-db/src.zip
CodeQL scanned 2 out of 2 Python files in this invocation. Typically CodeQL is configured to analyze a single CodeQL language per invocation, so check other invocations to determine overall coverage information.
Exporting results to SARIF v2.1.0...
Exported results to SARIF v2.1.0 (68ms).

```

SARIF status evidence:

```json
{
  "executionSuccessful": true,
  "notification_levels": {
    "none": 8,
    "note": 3
  },
  "notification_ids": [
    "py/diagnostics/successfully-extracted-files",
    "py/diagnostics/successfully-extracted-files",
    "py/baseline/expected-extracted-files",
    "py/baseline/expected-extracted-files",
    "cli/file-coverage-baseline",
    "cli/platform",
    "cli/build-mode",
    "cli/sip-enablement",
    "py/extractor/summary",
    "py/extractor/parser-statistics",
    "py/extractor/parser-statistics"
  ]
}
```

Result: `{"check": "configured integration", "language": "python", "seconds": 11.015, "result": {"status": "Partial", "languages": [{"candidates": 1, "rejected_results": 0, "status": "Partial", "language": "python"}], "note": "No-build extraction only. Installed query packs required; no automatic downloads or builds."}, "cleanup": true}`

```sh
'/Users/kribeshthapa/Developer/Vibe code/SentinalScan/.venv/bin/python' -I -c 'import subprocess,json,pathlib; p=subprocess.run(['"'"'/opt/homebrew/bin/codeql'"'"', '"'"'resolve'"'"', '"'"'queries'"'"', '"'"'codeql/javascript-queries'"'"', '"'"'--search-path=/Users/kribeshthapa/.codeql/packages/codeql/javascript-queries/2.4.7'"'"'],capture_output=True,text=True);pathlib.Path("capture.json").write_text(json.dumps({"returncode":p.returncode,"stdout":p.stdout,"stderr":p.stderr}))'
```

PASS; 0.679 s. 

```sh
/opt/homebrew/Caskroom/codeql/2.27.2/codeql/codeql database create /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-cdl209sp/javascript-db --language=javascript --build-mode=none --source-root=/private/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinel-packs02-3k3ruh42/javascript --threads=1 --ram=1024
```

PASS; 4.35 s. 

```text
Initializing database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-cdl209sp/javascript-db.
Running build command: []
Running command in /private/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinel-packs02-3k3ruh42/javascript: [/opt/homebrew/Caskroom/codeql/2.27.2/codeql/javascript/tools/autobuild.sh]
[2026-10-08 13:1
[excerpt; full output in evidence JSON]
ript/tools/data/externs/es/es2016.js
[2026-10-08 13:16:37] [build-stdout] Done extracting /opt/homebrew/Caskroom/codeql/2.27.2/codeql/javascript/tools/data/externs/es/es2016.js (1 ms)
Finalizing database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-cdl209sp/javascript-db.
Running TRAP import for CodeQL database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-cdl209sp/javascript-db...
WARNING: Rounding --ram up to the minimum of 2048
Importing TRAP files
Merging relations
Finished writing database (relations: 3.07 MiB; string pool: 4.78 MiB).
TRAP import complete (1.6s).
Finished zipping source archive (247.55 KiB).
Successfully created database at /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-cdl209sp/javascript-db.

```

```sh
/opt/homebrew/Caskroom/codeql/2.27.2/codeql/codeql database analyze /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-cdl209sp/javascript-db codeql/javascript-queries --format=sarifv2.1.0 --output=/var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-cdl209sp/javascript.sarif --threads=1 --ram=1024 --timeout=30 --no-sarif-add-file-contents --search-path=/Users/kribeshthapa/.codeql/packages/codeql/javascript-queries/2.4.7
```

PASS; 16.105 s. 

```text
Running queries.
WARNING: Rounding --ram up to the minimum of 2048
Resolving data extensions.
Finished resolving data extensions.
Loading data extensions.
Finished loading data extensions.
WARNING: Not caching stages during query-loading, since max heap size is only 1224 MB.
[1/89] Loaded /Users/kribeshthapa/.codeql/packages/codeql/javascript-queri
[excerpt; full output in evidence JSON]
7/Diagnostics/ExtractionErrors.ql...
Interpreting /Users/kribeshthapa/.codeql/packages/codeql/javascript-queries/2.4.7/Diagnostics/ExtractedFiles.ql...
Interpreting /Users/kribeshthapa/.codeql/packages/codeql/javascript-queries/2.4.7/Summary/LinesOfCode.ql...
Interpreting /Users/kribeshthapa/.codeql/packages/codeql/javascript-queries/2.4.7/Summary/LinesOfUserCode.ql...
Reading source archive /var/folders/02/fy2phk3d2c98n6c5ls6vc9g40000gn/T/sentinelscan-codeql-cdl209sp/javascript-db/src.zip
CodeQL scanned 2 out of 2 JavaScript/TypeScript files in this invocation. Typically CodeQL is configured to analyze a single CodeQL language per invocation, so check other invocations to determine overall coverage information.
Exporting results to SARIF v2.1.0...
Exported results to SARIF v2.1.0 (72ms).

```

SARIF status evidence:

```json
{
  "executionSuccessful": true,
  "notification_levels": {
    "none": 8
  },
  "notification_ids": [
    "js/diagnostics/successfully-extracted-files",
    "js/diagnostics/successfully-extracted-files",
    "js/baseline/expected-extracted-files",
    "js/baseline/expected-extracted-files",
    "cli/file-coverage-baseline",
    "cli/platform",
    "cli/build-mode",
    "cli/sip-enablement"
  ]
}
```

Result: `{"check": "configured integration", "language": "javascript", "seconds": 20.591, "result": {"status": "Partial", "languages": [{"candidates": 1, "rejected_results": 0, "status": "Partial", "language": "javascript"}], "note": "No-build extraction only. Installed query packs required; no automatic downloads or builds."}, "cleanup": true}`

## Evidence and reproduction helpers

[Full captured commands, timings, diagnostics, fixtures, normalized findings, SARIF notifications and unittest output](PHASE_02_EXTERNAL_ENGINES.evidence.json). Diagnostic output contains only local authored-fixture/tool data; no user repository or credential payloads. Temporary filenames in commands identify this run and were removed by cleanup.

The audit helpers lived outside the project. Exact helper invocations:

```sh
.venv/bin/python -B /tmp/sentinel_phase02.py > /tmp/sentinel_phase02.log 2>&1
.venv/bin/python -B /tmp/sentinel_codeql_paths02.py > /tmp/sentinel_codeql_paths02.log 2>&1
.venv/bin/python -B /tmp/sentinel_codeql_exact02.py > /tmp/sentinel_codeql_exact02.log 2>&1
.venv/bin/python -B /tmp/sentinel_codeql_diagnostics02.py > /tmp/sentinel_codeql_diagnostics02.log 2>&1
```

The final repeat was to inspect SARIF notifications explaining Partial status, not to count repeated runs as independent accuracy evidence. No existing rule or pack was edited.

## Conclusion

Semgrep works for the tested positive/negative/protected cases. CodeQL is installed and enabled by the launcher, but the current empty search-path configuration cannot resolve cached packs in the isolated subprocess. Diagnostic exact-pack overrides demonstrate working extraction, queries and finding import for both languages. The current SARIF notification policy labels these successful runs Partial. Both issues remain unchanged, as requested. Phase 2 verification is complete; no next phase started.
