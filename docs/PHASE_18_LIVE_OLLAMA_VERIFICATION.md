# Phase 18 — Live Ollama integration verification

Date: 2026-10-10. Verification only, existing project and existing virtual environment.

## Result

**PARTIAL: local integration works, but useful accepted live AI refinement was not
demonstrated in the four primary cases.** The service and installed model respond;
the repository completion callback invokes the real native Ollama API. Three model
responses were received and rejected by existing validation; the first SQL call
hit its timeout. All four findings retained a saved deterministic recommendation
and rendered successfully. A recommendation on screen is therefore not evidence
of accepted AI enhancement.

**Regression suite: 310 passed, 0 failed, 0 errors, 0 skipped**, 21.697s unittest time,
22.224s subprocess wall time, exit 0. This is contract/regression coverage, not a live
model accuracy score.

No production code, scanner algorithms, validators, UI, model installation or user
scan data changed. No new provider, OpenAnt integration or paid call. Existing Ollama
and Flask processes were not terminated. Only temporary fixture databases/apps and
controlled local observations were used. The existing single final recommendation
workflow was preserved.

## Context and environment

Read CLAUDE.md; project-overview, architecture, ui-context, code-standards,
ai-workflow-rules and progress-tracker; AGENTS.md; POST_FIX_VERIFICATION.md; Phase 11
Ollama migration/model setup and Phase 12 grounding reports. Their important limit
is unchanged: AI selects grounded deterministic statements and source proposals must
pass validation. This is not unrestricted explanation/code generation.

Project: `/Users/kribeshthapa/Developer/Vibe code/SentinalScan`.
Python: existing `.venv/bin/python` (3.13.5).
Model: **qwen2.5-coder:3b**, installed GGUF, 3.1B, Q4_K_M, 1,929,912,626 bytes;
digest `f72c60cabf6237b07f6e632b2c48d533cef25eda2efbd34bed21c5e9c01e6225`.
Endpoint: **http://127.0.0.1:11434**.

`GET /api/tags` returned HTTP 200 and the exact installed model. Before each main
inference, native `/api/tags` and `/api/show` returned 200 and passed local metadata
checks. Native `/api/chat`, not an OpenAI-compatible endpoint or substitute provider,
was used with production settings: stream false, think false, temperature 0,
num_predict 3000, keep_alive 0 and 20-second request budget. No models downloaded.

An actual `run-local.sh` subprocess, with temporary data and serving replaced by a
configuration inspection hook, observed LLM_ENABLED=true, the exact model and endpoint
above. This verifies launcher defaults, not the environment of an already-running
personal Flask process. Direct config.py defaults remain off/model-empty.
[Configuration evidence](audit/PHASE_18_CONFIG.json).

## Commands and evidence

All commands ran from the project directory. Temporary helpers and code hashes are
archived in [verification evidence](audit/PHASE_18_VERIFICATION.json); scripts can be
restored to their recorded paths. No production monkeypatch is persisted.

| Command | Outcome |
|---|---|
| `curl --max-time 5 -sS http://127.0.0.1:11434/api/tags` | Exit 0, HTTP inventory available |
| `.venv/bin/python -B /tmp/phase18_live.py` | Initial harness failed during evidence serialization after SQL; corrected harness retry exit 0 |
| `.venv/bin/python -B /tmp/phase18_failures.py` | Six failure cases PASS, exit 0 after correcting a fixture constructor |
| `.venv/bin/python -B /tmp/phase18_config.py` | Actual launcher config inspected, exit 0 |
| `.venv/bin/python -B /tmp/phase18_tests.py` | Runs exact requested unittest command in isolated environment, exit 0 |
| `.venv/bin/python -B -m unittest discover -s tests -v` | Child command: 310/310 pass |

The unittest wrapper sets temporary SENTINELSCAN_DATA_DIR, disables live AI, removes
inherited GitHub credentials and enables the existing installed-Semgrep opt-in test.
[Full log](audit/PHASE_18_TESTS.log), [command/exit/timing](audit/PHASE_18_TESTS.json).

The first diagnostic serializer tried redacting an entire serialized JSON document
and parsing it again; redaction broke that *audit representation*. It was replaced
in the temporary harness with recursive string redaction. SQL evidence already
saved was retained; the remaining three cases were rerun. The discarded intermediate
XSS attempt is not counted as a product validation outcome. Another temporary failure
fixture initially omitted required description/impact constructor fields; these
were supplied before the six-case run. Neither error required application changes.
Redacted embedded model content is diagnostic text and may no longer be parseable
as nested JSON; this must not be confused with malformed wire output.

## Real workflow verification

Three separate inert repositories contain, respectively:

- Python Flask request data concatenated into a sqlite3 SQL query, line 5.
- JavaScript location.hash assigned to a DOM innerHTML sink, line 2.
- Python password assignment to a freshly generated **synthetic, invalid credential**,
  line 1. The value is never used for authentication and is not retained in evidence.

Only the GitHub archive boundary is replaced with a local ZIP writer. The real
ScanManager.submit_repository, static scanner, SQLite persistence and automatic
completion callback execute. Source is never imported/executed. Semgrep/CodeQL are
disabled in these focused AI cases to isolate the existing built-in candidate path;
their real verification remains in Phase 17. OSV lookup is disabled.

For the website case, the existing header scanner consumes a controlled HTML response
missing X-Content-Type-Options. Its finding is saved and the same completion callback
is invoked. This is a genuine rule-produced observation, but not a new full live DAST
crawl/server scan. The repository cases exercise automatic worker completion.

The transport wrapper delegates to the **real** existing HTTP function, recording
path, status, duration, sanitized model output and context, input byte length and
SHA-256. It does not supply mock responses. Evidence:
[primary live cases](audit/PHASE_18_LIVE.json), [completed run log](audit/PHASE_18_LIVE_RETRY.log).

| Primary case | Detection | Chat result | Validation / saved AI | Final display |
|---|---|---|---|---|
| SQL injection | High / High; app.py:5 | Timeout 20.017s; no response available | No accepted review | Deterministic parameter binding guidance |
| XSS | Medium / High; app.js:2 | HTTP 200, 13.269s | Rejected: `Inconsistent example`; no AI row | Deterministic textContent/sanitization guidance |
| Hardcoded credential | High / Medium; settings.py:1 | HTTP 200, 7.581s | Rejected: `Unexpected source`; no AI row | Deterministic removal/runtime configuration and rotation guidance |
| Missing header | Low / High; endpoint recorded | HTTP 200, 7.535s | Rejected: `Inconsistent example`; no AI row | Deterministic header guidance/example |

Each primary case has one actual chat attempt. Request success = 3/4; accepted live
reviews = 0/4; composed AI enhancements = 0/4; deterministic fallback = 4/4. These are
four selected cases, not stable acceptance-rate estimates. The rejected repository
analyst responses did not reach the second skeptic pass; a real accepted two-pass
review is **NOT VERIFIED** here. HTTP 200/JSON parsing alone does not imply acceptance.

## Separate SQL repeat (not an application retry)

After the other work finished, `.venv/bin/python -B /tmp/phase18_sql_repeat.py`
ran a fresh isolated SQL scan with unchanged settings (exit 0). Native chat returned
HTTP 200 in **18.625s**, but validation rejected `Inconsistent example`. The model
proposed a sqlite3 `?` placeholder and a one-element bound parameter tuple, matching
the detected language/library. It still set example_type to `none` with nonempty
code and original_code. Its rendered string also contains escaped line/quote text;
no source parsing or secure patch validation was reached, and the code must not be
presented as a validated replacement. The deterministic result remained saved,
scan Completed, page 200. [Repeat evidence](audit/PHASE_18_SQL_REPEAT.json).

Across the four primary cases **plus this separately recorded repeat**: five chat
attempts, four HTTP 200 responses, one timeout, zero accepted reviews and five
fallbacks. This is not a statistical model-quality estimate. The repeat establishes
real SQL inference, not a successful AI refinement. It does not erase the first timeout.

## Recommendation quality assessment

**SQL:** The initial call produced no response within the application deadline. Its
explanation and proposed fix cannot be assessed from that attempt. The separate
repeat above proposes the appropriate binding approach but fails the output contract. The saved base
action recommends the actual database library's parameterized API and separate SQL
structure/values; it does not fabricate an exact AI replacement or claim exploitation.

**XSS:** The model's reason preserves uncertainty. It proposes textContent in place
of the observed innerHTML assignment, which is appropriate for intended plain text,
not universally equivalent for intentional HTML. However, the code field contains
English replacement instructions, example_type is `none`, and original_code contains
a broader source string. This is not a validated executable patch. Existing validation
correctly rejects the inconsistent contract before any patch could be promoted.
No unsupported framework/package or confirmed-exploitation claim was observed.

**Credential:** The model correctly says validity was not tested and recommends
removal, rotation/revocation if real and protected runtime configuration. It does not
provide replacement code, but returns nonempty original_code despite guidance-only
mode. That violates the existing source policy and is rejected. The generated dummy
credential was absent from every outgoing request body and rendered page. Real
credential recognition/redaction is not universally guaranteed by this one fixture.

**Header:** The model proposes the correct plain HTTP line
`X-Content-Type-Options: nosniff`, with no invented application framework/source. But
it labels the nonempty configuration `none`. Rejection is correct under the current
contract; the content can be sensible while its machine-readable form is invalid.
Even a correctly labeled example would be illustrative configuration, not proof of
secure deployment. The deterministic example remains usable.

Across the three returned answers, explanation depth is constrained to the existing
closed statement choices. No new secure source-specific AI fix was validated. No
claim is made that a generated fix is safe merely because it came from this model.

## Failure handling

[Six-case evidence](audit/PHASE_18_FAILURES.json):

| Condition | Test method | Result |
|---|---|---|
| Service unavailable | Mock RemoteError at native transport boundary | PASS: fallback, finding unchanged, Completed scan, HTTP 200 |
| Missing model | Real inventory with deliberately absent synthetic model name; no chat/download | PASS: rejected before inference, fallback |
| Timeout | Mock timeout boundary plus actual SQL 20s timeout | PASS: completed scan remains usable |
| Invalid output | Mock native HTTP 200 with invalid JSON | PASS: not saved/promoted |
| Unsafe recommendation | Mock header `disabled` | PASS: rejected, deterministic fallback |
| Unsupported advice | Mock imaginary package/version and disabling authentication | PASS: rejected, deterministic fallback |

All six retain saved finding_solution records, zero accepted AI rows, exactly one
recommendation element and unchanged finding rows. Regression tests independently
cover missing/extra fields, contradictions, secrets, successful mocked refinement,
saved recommendation composition and failed refresh behavior. Missing-model testing
used the existing service only for inventory; the daemon was not stopped or modified.

## SQLite and UI

All three repository scans finish Completed. The controlled header record is
Completed. Each isolated database reports integrity `ok`. All four finding pages and
scan detail routes return HTTP 200. Finding pages contain exactly one
`id="recommendation"`, no accepted AI indicator, and no synthetic credential value.
Base recommendation snapshots are persisted; rejected AI responses are deliberately
not saved in ai_reviews. `final_solution` reads the saved state and chooses the
existing deterministic result. No extra recommendation panel is introduced.

The detailed recommendation is on the finding page linked from scan detail, not a
new recommendation block on the scan-summary page. UI verification uses actual
Flask/Jinja responses; visual layout, JavaScript/clipboard and real-browser behavior
are **NOT TESTED** in this phase. User databases were not used or changed.

## Confirmed limitations and minimal fixes for approval

1. **Response contract reliability:** the real small model can produce independently
   valid enum/string fields that contradict each other. All three returned primary
   responses failed this contract. A narrowly scoped follow-up could constrain code,
   original_code and example_type together in the existing native schema (with tests
   for Ollama support), and use guidance-only constraints when no source patch can be
   validated. Preserve the independent validator; do not silently accept unsafe code.
2. **Latency:** one real SQL request exceeded the fixed 20-second budget. Measure
   repeated cold/warm latency before proposing a bounded timeout/output-budget change.
   keep_alive=0 can impose repeated loading work; it is not proven the sole cause.
   The suite overlapped part of initial measurement, so this is not an isolated
   performance benchmark. No timeout or runtime setting was changed.
3. **Coverage after rejection:** current refine_scan stops at the first failed review,
   including validation rejection, so later findings in a multi-finding scan may not
   receive AI. This follows existing code and prior reports; the focused live cases
   use one finding each. A future narrowly scoped distinction between model-contract
   rejection and service outage could be considered with existing resource bounds.
4. **Missing full source:** fresh scans generally do not retain full pinned source
   needed for arbitrary new AI patches. Retain guidance-only/deterministic fallback;
   do not label unverifiable generated source a validated fix.

These are recommendations only. No fixes or additional features implemented. Local
service/inference: PASS. Validation/fallback: PASS for tested cases. Useful accepted
live remediation: NOT DEMONSTRATED. Overall Phase 18 objective: PARTIAL.
