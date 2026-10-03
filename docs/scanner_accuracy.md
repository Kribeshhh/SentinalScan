# Scanner accuracy — controlled Phase 5 evaluation

## What was measured

This is a small, authored **challenge set**, not a random sample, independent external
benchmark, training set, or estimate of production accuracy. It contains **54 fixtures**:
27 vulnerable and 27 safe/protected, balanced across nine existing rule families.
Every fixture has an explicit boolean label, variant, rationale, hypothetical source
path and future-improvement note in [fixtures.json](../evaluation/fixtures.json).
The source is JSON data materialized into an isolated ZIP; it is never imported,
executed, built or installed. No live credentials are present.

Ground truth was fixed before the first run. Detection rules and fixture labels were
not tuned after observing results. The author had prior knowledge of the scanner:
straightforward cases and deliberate hard cases are included. This is not a blinded
holdout and overlaps conceptually with existing regression families. Future tuning
needs a separately authored holdout; repeatedly optimizing this set invalidates
any claim of independent evaluation.

Labels are for the stated security property and assumptions: SQLite binding, trusted
DOMPurify defaults, POSIX quoting, random password-hash salt, production debug settings,
and checksum-only use are explicit fixture contracts. A safe label does not certify
the entire snippet, dependency versions, runtime or application. Java combines its
existing SQL/process/deserialization/crypto rules into one six-fixture category.
Configuration cases deliberately expose representation/filename coverage limits.
No new category was implemented. Dependency/OSV accuracy and HTML accuracy are not
measured by this dataset; their existing regression tests remain separate.

## Scoring

Unit: one **fixture/category-presence** decision. Any matching final persisted
finding counts, including Low confidence and informational observations. Multiple
findings for the same category/file count once. This measures category-level detection
and alert burden, not exact vulnerable-line localization or confirmed exploitability.
Low-confidence checksum observations therefore count as false positives for the stated
benign ground truth rather than being silently filtered out.

- TP: vulnerable fixture with a matching finding.
- FN: vulnerable fixture without a matching finding.
- FP: safe/protected fixture with a matching finding.
- TN: safe/protected fixture without a matching finding.
- Precision = TP / (TP + FP). Recall = TP / (TP + FN).
- F1 = 2TP / (2TP + FP + FN), equivalent to the harmonic mean where defined.
- Undefined denominators are JSON null / “undefined”; a missed positive has F1 zero.

Overall metrics are micro-aggregated within each stage over all 54 decisions. The two
stages use the same fixtures, so their counts are not pooled into 108 independent
observations. Extra unmatched findings are listed as unscored in the artifact; this
run had zero. Failed or incomplete required modules invalidate the run instead of
being silently scored as clean. Per-module coverage is retained in the JSON.

## Actual results

Both measured configurations returned the same classification counts:

| Category | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Command Injection | 2 | 1 | 2 | 1 | 66.67% | 66.67% | 66.67% |
| Configuration | 1 | 0 | 3 | 2 | 100.00% | 33.33% | 50.00% |
| DOM XSS | 2 | 0 | 3 | 1 | 100.00% | 66.67% | 80.00% |
| Deserialization | 2 | 0 | 3 | 1 | 100.00% | 66.67% | 80.00% |
| Dynamic Code Execution | 2 | 0 | 3 | 1 | 100.00% | 66.67% | 80.00% |
| Java Security | 3 | 1 | 2 | 0 | 75.00% | 100.00% | 85.71% |
| SQL Injection | 2 | 1 | 2 | 1 | 66.67% | 66.67% | 66.67% |
| Secrets | 2 | 1 | 2 | 1 | 66.67% | 66.67% | 66.67% |
| Weak Cryptography | 2 | 1 | 2 | 1 | 66.67% | 66.67% | 66.67% |
| **Overall** | 18 | 5 | 22 | 9 | 78.26% | 66.67% | 72.00% |

The scanner missed **9 of 27** vulnerable examples and flagged **5 of 27**
safe/protected examples. These are material limitations. Passing regression tests
is not equivalent to detecting all vulnerabilities. Six fixtures per category are
too few to support strong generalization or ranking claims.

## Architecture-stage comparison

| Actual configuration | Final findings | TP / FP / TN / FN | F1 |
|---|---:|---|---:|
| Custom semantic analysis with existing data flow, secrets and configuration | 23 | 18 / 5 / 22 / 9 | 72.00% |
| Same pipeline + installed Semgrep 1.179.0 + correlation | 23 | 18 / 5 / 22 / 9 | 72.00% |

The full worker performs safe extraction, project indexing, all custom modules,
normalization, correlation, context retention and SQLite persistence. OSV is off;
no dependency fixtures are present. CodeQL is disabled and unavailable, so “full”
here means **full available static pipeline**, not every optional engine.

Semgrep returned five candidates: sql_concat, sql_format, sql_allowlist, cmd_shell
and dom_html. All correlated with existing custom findings. One of those agreements
(sql_allowlist) was a false positive. Agreement demonstrably did not prove correctness.
There was **no measured precision/recall improvement** from Semgrep on this set.

There is no supported semantic-only/no-data-flow runtime switch. Local semantic
analysis and data flow are integrated, so a separate earlier-architecture baseline
would require code changes or a historical checkout. No fabricated ablation is shown.

## Known false positives

| Category | Fixture ID / virtual path | Why flagged | Potential improvement |
|---|---|---|---|
| SQL Injection | `sql_allowlist.py` | The flow analysis does not prove the dominating membership check and exception exit constrain the identifier to two constants. Both custom analysis and Semgrep flag it. | Track dominating allowlist guards and exit paths. |
| Command Injection | `cmd_quoted.py` | The custom analyzer does not model POSIX shlex.quote as a sink-specific shell-argument protection. | Recognize platform-specific shell quoting only at appropriate sinks. |
| Secrets | `secret_doc.md` | A credential-shaped assignment in documentation still matches the generic secret rule. Lower confidence does not remove the candidate. | Distinguish prose/labels from credential assignments. |
| Weak Cryptography | `crypto_checksum.py` | MD5 is emitted as a Low-confidence checksum observation even though this fixture has no security-sensitive use. | Separate low-confidence observations from actionable vulnerability metrics. |
| Java Security | `java_checksum.java` | The Java rule flags MD5 algorithm selection; it does not establish a security-sensitive use. This is a Low-confidence observation. | Separate cryptographic observations from security use. |

## Known false negatives

| Category | Fixture ID / virtual path | Why missed | Potential improvement |
|---|---|---|---|
| SQL Injection | `sql_dispatch.py` | The SQL sink matcher does not resolve constant getattr(cursor, "execute") call targets. | Resolve constant getattr targets without execution. |
| Command Injection | `cmd_dispatch.py` | The shell sink matcher does not resolve constant getattr(os, "system") call targets. | Resolve constant getattr calls. |
| Dynamic Code Execution | `exec_dispatch.py` | Built-in dynamic lookup is not resolved to eval. | Resolve constant built-in attribute targets. |
| DOM XSS | `dom_dynamic.js` | The JavaScript sink matcher does not resolve a computed property variable to innerHTML. | Resolve constant computed-property names. |
| Secrets | `secret_custom_name.py` | The unusual constant name has no recognized credential label or typed format. Its authentication role is known only from fixture ground truth. | Track credential use sites; names alone cannot establish arbitrary secrets. |
| Deserialization | `deserialize_dispatch.py` | Constant getattr(pickle, "loads") is not resolved to an unsafe decoder. | Resolve constant attribute dispatch. |
| Weak Cryptography | `crypto_dispatch.py` | The dynamic cryptographic factory is not resolved to MD5. | Resolve constant cryptographic factory names. |
| Configuration | `config_debug.py` | Python literal configuration is inspected only in files named config.py or settings.py; this fixture is named config_debug.py. | Distinguish effective deployment environment. |
| Configuration | `config_tls.py` | The existing configuration scanner checks named literal security settings; it does not inspect requests.get(..., verify=False) call arguments. | Track connection-specific verification configuration. |

These explanations come from inspection of current rule/flow scope. They are not
claims that fixing one case generalizes safely. No detection changes were made to
conceal these errors. Full per-fixture decisions and engine provenance are in
[results.json](../evaluation/results.json).

## Separate AI evaluation

- Candidate findings before LLM: **23 per static stage**.
- Actual LLM reviews in evaluation: **0** (AI disabled).
- Needs Review downgrades, likely-false-positive judgments and human-label agreement:
  **not measured**, not zero-percent performance.
- Provider/model/version/settings: **not applicable; no live model invoked**.
- The nine Phase 4 mocked tests plus existing AI regressions validate contracts,
  redaction, disagreement, failure and presentation behavior, not model accuracy.

A future separately authorized AI benchmark should retain the frozen labels and
record provider/model snapshot, settings, prompts/version, repeated trials and
candidate-level human agreement. AI must not be mixed into these deterministic scores.

## Tool and environment limits

Semgrep uses only three bundled Python/JavaScript taint rules, not a comprehensive
rule registry. Java has no bundled Semgrep coverage. Timeouts, per-file size/memory
limits, incomplete path modeling and source/sanitizer assumptions still apply.
CodeQL was not installed in this environment: no live accuracy or extraction claim
is made. Its adapter tests are mocked; only Python/JavaScript no-build extraction
with installed trusted query packs is supported. LLM output remains nondeterministic
and potentially wrong; two agreeing passes may share the same error. No live-model
quality or adversarial-resistance measurement was performed.

Environment: Python 3.14.6; Semgrep 1.179.0; Flask 3.1.3, tree-sitter 0.25.2, tree-sitter-javascript 0.25.0, tree-sitter-java 0.23.5.

Frozen dataset SHA-256:
`73c72c4db254ac9f52071915f5e8a56d111c7d0933ebc1e6ad363c4e25b3a2d1`

Scanner/analysis Python files + bundled Semgrep rules SHA-256 (algorithm in runner):
`5e7752e3a857441c2f3e59e9bcac93267364ad842aa8cadb864169b2f08c5949`

## Reproduce

From the project root, with requirements.txt installed in the active Python 3.11+
environment and optional Semgrep installed separately:

```sh
python3 -m evaluation.run --output evaluation/results-custom.json
python3 -m evaluation.run --semgrep /absolute/path/to/semgrep --output evaluation/results.json
python3 -m unittest discover -s tests -p test_evaluation.py -v
SENTINELSCAN_TEST_SEMGREP=/absolute/path/to/semgrep python3 -m unittest discover -s tests -v
```

Exact commands used here (temporary verification environments already installed):

```sh
cd "/Users/kribeshthapa/Desktop/Vibe code/SentinalScan"
PYTHONPYCACHEPREFIX=/tmp/sentinelscan-phase5-pycache /tmp/sentinelscan-verify-venv/bin/python -m evaluation.run --semgrep /tmp/sentinelscan-semgrep-verify/bin/semgrep --output evaluation/results.json
PYTHONPYCACHEPREFIX=/tmp/sentinelscan-phase5-pycache SENTINELSCAN_TEST_SEMGREP=/tmp/sentinelscan-semgrep-verify/bin/semgrep /tmp/sentinelscan-verify-venv/bin/python -m unittest discover -s tests -v
git diff --check
```

The runner prints actual aggregate scores, writes detailed JSON, and exits nonzero
if required coverage is incomplete. It uses temporary databases/archives, disables
AI and remote dependency lookup, and never touches user scan history. No fake GitHub
results are used: the network/archive boundary is a local controlled archive, while
all scanner modules and persistence/correlation paths execute normally. Tool version
changes may change results; the output records versions and content hashes.
