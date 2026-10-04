# Code Standards

## General

Keep changes focused in the existing modules. Fix root causes, preserve public
finding identities and avoid unrelated rewrites. Use the actual current code and
applicable `AGENTS.md` subsystem rules rather than inferring features from templates.

## Python / Flask

- Python 3.11+; dependencies are declared in `requirements.txt`.
- Keep HTTP handlers focused; reuse existing analysis/scanner/service boundaries.
- Validate untrusted input at boundaries. Use parameterized SQLite queries.
- Preserve CSRF, Jinja escaping, secure headers, safe errors and secret-free logs.
- Never execute scanned source or use unsafe shell interpolation. External tools
  require vetted arguments, private environments, budgets and validated outputs.
- Keep source matching, redaction and static fix validation shared across UI/reports.

## Frontend

HTML, CSS and vanilla JavaScript only. Reuse existing CSS tokens and Jinja components.
Keep browser behavior accessible and compatible with the application's CSP. No
Node.js build requirement, inline unsafe script, or raw model-generated markup.

## Data / Files

Preserve compatible SQLite migrations, foreign-key relationships, fingerprints,
triage and immutable reports. Keep snapshots bounded and redacted. Report paths and
repository archive paths must remain validated. Secrets and provider credentials
must never appear in fixtures, committed configuration or output artifacts.

## Organization and Validation

Use the folder responsibilities in `architecture.md`. Tests live in `tests/` and
must use isolated temporary databases and mocked remote boundaries unless a live
integration is expressly authorized. Detection changes require vulnerable, safe
and protected examples. Run relevant focused checks and the full project suite for
implementation changes:

```sh
python3 -m unittest discover -s tests -v
```

Use an environment with project requirements installed. The optional real Semgrep
test uses `SENTINELSCAN_TEST_SEMGREP=/absolute/path/to/semgrep`. Do not install tools
or enable AI implicitly. Report passed/failed/skipped and mocked/live distinctions.
Documentation-only changes require reference/content checks, not a fabricated test
run. Frozen evaluation cases/results remain protected; new measurement outputs must
not overwrite historical baselines. Test pass counts are not accuracy scores.
