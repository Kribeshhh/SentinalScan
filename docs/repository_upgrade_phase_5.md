# Repository scanner upgrade — Phase 5: final evaluation and validation

## Outcome

The frozen controlled benchmark contains 54 fixtures across nine existing category
families, with explicit vulnerable/safe/protected ground truth. Actual results for
both custom analysis and custom + installed Semgrep are:

**TP 18 · FP 5 · TN 22 · FN 9 · Precision 78.26% · Recall 66.67% · F1 72.00%.**

These are challenge-set scores, not production accuracy claims. Semgrep did not
improve category-level classification on this dataset. Five Semgrep candidates
correlated with custom results, including a false positive. The scanner missed nine
vulnerable fixtures. No rule or ground-truth label was tuned to conceal the failures.

See [scanner_accuracy.md](scanner_accuracy.md) for methodology, per-category metrics,
every false positive/negative and its explanation, exact reproducibility commands,
versions, dataset/code hashes and tool limitations. Machine-readable observations
are in [evaluation/results.json](../evaluation/results.json).

## Final architecture

```text
Repository / pinned commit
  ↓
Safe import (bounded ZIP, path/type checks, private temporary workspace)
  ↓
Language / project analysis (AST, Tree-sitter, bounded structural index)
  ↓
Custom semantic analysis + existing data flow
  + dedicated secrets + dependency/advisory analysis
  + optional Semgrep + optional CodeQL where available
  ↓
Normalized candidate and source/sink/flow evidence
  ↓
Bounded context retrieval + evidence verification + conservative correlation
  ↓
Final persisted finding, original evidence and engine provenance
  ↓
Optional explicit LLM analyst → skeptical review → advisory confidence
  ↓
ONE composed Recommendation (deterministic fallback)
  ↓
Static source-fix validation / diff where supported
  ↓
Human review
  ↓
Dashboard / reports / existing explicit GitHub remediation workflow
```

Retrieval, verification and correlation are interleaved per module in the actual
implementation: context supports an operation anchor before candidates merge.
Multiple engine candidates become one finding only when the evidence justifies it;
ambiguous or unrelated issues remain separate. Findings are persisted before optional
AI so AI failure cannot lose scanner results. AI never changes scanner severity,
risk, status or detection confidence. Source-specific AI fixes must pass the existing
validator before the composer selects them; validation is not deferred until after
an unsafe patch has been accepted. No automatic commits, merges or resolution occur.

The semantic/data-flow stage cannot currently be toggled into independent ablations.
No invented semantic-only comparison is reported. The available static pipeline was
measured with Semgrep 1.179.0; CodeQL was unavailable. Dependency lookup was disabled
and no dependency fixtures were used, so there is no dependency-accuracy claim.

## Regression verification

Final full suite: **219 tests run, 219 passed, 0 failed, 0 skipped** in 17.515 seconds.
This includes five new evaluation-harness tests and the real installed Semgrep
fixture. Python was 3.14.6 in the isolated verification environment. Provider, OSV
and GitHub service responses use controlled fixtures; HTTP/TLS integration uses local
lab servers. No paid model, production repository or remote website was scanned.
`git diff --check` passed.

Regression coverage includes:

| Application area | Existing/new test suites |
|---|---|
| Website scanner and graceful module failure | `test_website_scanner.py`, `test_final_validation.py` |
| Repository scanner / optional engines / correlation | `test_source_scanner.py`, `test_repository_foundation.py`, `test_repository_phase2.py`, `test_repository_phase3.py` |
| Dashboard, navigation, persistence | `test_foundation.py`, `test_hardening.py` |
| Reports/downloads, history, filtering and comparisons | `test_management.py`, `test_unified_recommendation.py` |
| Remediation, validation, reviewed GitHub workflow | `test_remediation_workflow.py`, `test_source_accuracy.py`, `test_source_solutions.py` |
| GitHub credential/redirect/private-list handling | `test_source_scanner.py` transport fixtures |
| AI disabled and enabled/mock failure behavior | `test_llm_review.py`, `test_llm_sast_dast.py`, `test_repository_phase4.py`, `test_final_validation.py` |
| Evaluation labels, formulas, actual worker/nonexecution | `test_evaluation.py` |

Regression pass counts validate specified behavior; they are not accuracy metrics.
The benchmark's 5 FP and 9 FN remain even while every regression test passes.

## Security review

Source inspection and the passing controlled tests verify the following boundaries:

| Boundary | Mechanism and test evidence | Qualification |
|---|---|---|
| No direct repository execution | AST/Tree-sitter/literal parsing; archive build-hook fixture; new evaluation inserts a top-level file-write sentinel and confirms it never runs | Optional analysis tools are trusted external programs, not an OS sandbox |
| Path traversal / malicious archives | Reject absolute/traversal/case collisions, encrypted and special entries, unsafe destination; archive/SARIF tests | Only vetted extracted source enters workers |
| Symlinks | ZIP type rejection, preexisting destination rejection, source membership checks | No blanket claim about unrelated filesystem access |
| Resource bounds | Archive expansion/file/count limits, scan deadlines, bounded context; oversized/bomb/recursion tests | Limits can cause partial coverage; not proof of completeness |
| Subprocess control | Argument arrays, trusted local rules/query packs, no shell or repository builds, private environment, time/output/disk bounds, process-group cleanup | CodeQL extraction itself was mocked because unavailable |
| Credential redaction | Typed/assignment/private-key masking, known credentials removed before AI; source/persistence/UI/report tests | Unknown unlabeled secrets can evade patterns |
| LLM context secrecy | Allowlisted bounded evidence, synthetic secret context, both-pass redaction and prompt/data separation tests | No live adversarial-provider robustness measurement |
| Logs/error bodies | Fixed safe error messages; tests capture logs and assert fixture credentials/provider errors absent | Tested patterns and paths only, not a mathematical guarantee |
| Temporary cleanup | Worker archive/workspace cleanup checked after success and failures; benchmark asserts cleanup before scoring | Original user database and source were not modified |

No blocking security test failure was found in the tested paths. Existing limitations
remain material: structural analysis can miss dynamic dispatch, redaction is
pattern-based, configuration coverage is limited, and external engines/LLMs are not
proof of correctness. Do not interpret a Completed scan, zero findings or a static
validation pass as security certification.

## LLM measurements

The accuracy benchmark explicitly disables AI. It records 23 pre-LLM persisted
candidates and zero AI reviews in each stage. Downgrade rate, likely-false-positive
rate and agreement with human labels are **not measured**; no model/provider version
can honestly be attached to nonexistent live evaluation. Mocked two-pass tests
exercise contracts and safe behavior separately from deterministic metrics. A future
AI study requires fixed model/settings, repeated trials and independent labels.

## Files and dependencies

Added:

- `evaluation/__init__.py`: offline evaluation package.
- `evaluation/fixtures.json`: frozen labeled source dataset (source stored as data).
- `evaluation/run.py`: actual worker runner, classification scoring, coverage/version/hash capture.
- `evaluation/results.json`: measured per-fixture/per-stage outcomes.
- `tests/test_evaluation.py`: five harness/metric/nonexecution tests.
- `docs/scanner_accuracy.md`: dataset, metrics, FP/FN analysis and reproduction.
- `docs/repository_upgrade_phase_5.md`: this final report/security review.

Modified in this phase: **README.md and AGENTS.md only**. Existing uncommitted work
from earlier phases remains preserved. No production detection rules, app routes,
database schema, AI flow or UI were changed for benchmark performance. No dependencies
were added; existing isolated Semgrep installation was used. No runtime Node dependency.

## Reproduction

From the project root with requirements installed:

```sh
python3 -m evaluation.run --output evaluation/results-custom.json
python3 -m evaluation.run --semgrep /absolute/path/to/semgrep --output evaluation/results.json
python3 -m unittest discover -s tests -p test_evaluation.py -v
SENTINELSCAN_TEST_SEMGREP=/absolute/path/to/semgrep python3 -m unittest discover -s tests -v
git diff --check
```

Without Semgrep, the custom evaluation still runs and the full suite skips its one
opt-in live Semgrep test. The exact local verification paths/commands and recorded
versions appear in scanner_accuracy.md. External tools are never installed by the
runner. The fixture hash is asserted by a test: deliberate dataset revisions must
create a new labeled version and document why, not silently replace a poor result.

Phase 5 is complete. Stop: no new vulnerability category or subsequent phase started.
