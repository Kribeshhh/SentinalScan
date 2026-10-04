# Accuracy refinement and finding readability — October 2026

This is maintenance of the existing scanner and finding workflow. DAST, optional
AI, reports, status persistence, source editing and human-reviewed PR publication
remain in place. No scanned source is executed and no provider is called.

## Detection changes

- Python resolves constant `getattr` operation names and assigned callable aliases.
  Runtime-selected attributes remain unknown. Scope shadowing is preserved.
- A narrow rejecting SQL identifier guard (`if name not in` a bounded literal
  identifier collection followed by return/raise) protects the continuing path.
  Non-terminating checks, reassignment and rejected helper return values do not
  establish protection. Protection is SQL-specific, not an eval sanitizer.
- `shlex.quote` is recognized only for one complete argument after explicit
  `/bin/echo`, `/usr/bin/echo` or `/usr/bin/printf` prefixes. Interpreter arguments,
  quoting inside quotes, executable selection and subsequent transformations are
  not suppressed. Bare `echo` remains conservative because platform is unknown.
- JavaScript resolves tracked constant computed HTML properties, including bounded
  string concatenation, while preserving sanitizer and reassignment checks.
- Imported Requests APIs with literal `verify=False` are recorded; unrelated APIs
  and shadowed imports are not inferred to be Requests. Additional `config_*.py`
  and `settings_*.py` configuration names are recognized.
- A narrow documentation-only instructional phrase filter reduces generic password
  false positives. Arbitrary spaced passphrases and typed token detection remain.
- Weak hashes without security-sensitive context are informational observations,
  still retained and scored by evaluation. Password-related weak hashes remain
  higher severity. Informational does not mean verified safe.

Existing findings and triage are not rewritten. Re-scan to apply detection changes;
previous immutable reports remain historical. Finding titles/fingerprints persist.
These additions do not imply that every new match has an automatic source patch.
The existing source matching and static validation requirements still apply.

## Finding page

One Recommendation follows a compact finding summary. The action and validation
status are prominent. Desktop shows current source and the primary suggested fix
side by side; narrow displays stack them without horizontal page overflow. The
matched line stays highlighted. Alternatives, extended test checklists, rationale,
raw context, evidence and workflow use disclosure controls. Active drafts still
open their workflow. Secret rotation/removal instructions and failed-validation
warnings remain visible. Confidence is separate from severity; low-confidence
findings are marked Needs review and informational findings Observation.

No evidence was removed, status changes still use CSRF protection, and template
escaping and copy/edit/diff/PR controls are preserved. Deep links into disclosures
open their parents. No replacement code is fabricated when context is insufficient.

## Evaluation protocol and results

The original 54-case dataset and original `evaluation/results.json` were preserved.
`evaluation/accuracy_holdout_v1.json` (26 cases) was authored and frozen **before
production edits**, and measured with the old scanner in `holdout_before.json`.
It is a related authored challenge set, not a blinded independent or production
benchmark. The developer knew its case families. It is now consumed evaluation
data and must not be described as a fresh holdout in future work.

Original dataset SHA:
`73c72c4db254ac9f52071915f5e8a56d111c7d0933ebc1e6ad363c4e25b3a2d1`

New dataset SHA:
`9fabe35ae18ac86e7ca97f9714b49f59ff626880dafc51685203e547ed999bb1`

| Dataset / engine | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Original before, both stages | 18 | 5 | 22 | 9 | 78.26% | 66.67% | 72.00% |
| Original after, custom | 26 | 4 | 23 | 1 | 86.67% | 96.30% | 91.23% |
| Original after, custom + Semgrep | 26 | 5 | 22 | 1 | 83.87% | 96.30% | 89.66% |
| New set before, both stages | 6 | 3 | 10 | 7 | 66.67% | 46.15% | 54.55% |
| New set after, custom | 13 | 0 | 13 | 0 | 100.00% | 100.00% | 100.00% |
| New set after, custom + Semgrep | 13 | 1 | 12 | 0 | 92.86% | 100.00% | 96.30% |

Artifacts: `evaluation/accuracy_refinement_results.json`, `holdout_before.json`,
`holdout_after.json`. Each records scanner/dataset hashes, coverage and environment.
Semgrep 1.179.0 was actually executed. CodeQL was mocked in contract tests, not
measured live. AI was disabled in evaluation; no live-model accuracy claim is made.

Remaining original errors are bare-shell quoting, a documentation credential-like
sentence, Python/Java checksum observations, and an arbitrary-name secret missed
by detection. Semgrep also flags a protected allowlist case in both datasets. All
confidence levels and informational findings remain counted, including these
errors; none were removed to inflate scores. Category presence is scored once per
fixture, not runtime exploitability or correctness of generated fixes.

## Verification

The full project suite: **230 tests passed, 0 failed**, including real optional
Semgrep, local DAST lab checks, persistence, mocked GitHub/provider boundaries,
reporting, source validation and 11 added detection/layout regressions. Tests use
temporary databases. Development failures were corrected before this final run;
a process-cleanup permission race and a background-worker timeout appeared in
intermediate runs; neither recurred in the final isolated run.

Browser checks used an isolated fixture server: source fix and secret guidance,
1280px desktop and 390px phone layouts, disclosure expansion, and no horizontal
page overflow at 390px. The preview is not a real scan or evidence of accuracy.

Reproduce without overwriting the baseline:

```sh
python3 -m unittest discover -s tests -v
# Opt in to a trusted installed Semgrep for its live integration test:
SENTINELSCAN_TEST_SEMGREP=/absolute/path/to/semgrep python3 -m unittest discover -s tests -v
python3 -m evaluation.run --output evaluation/refinement-repeat.json --semgrep /absolute/path/to/semgrep
python3 -m evaluation.run --dataset evaluation/accuracy_holdout_v1.json --output evaluation/holdout-repeat.json --semgrep /absolute/path/to/semgrep
```
