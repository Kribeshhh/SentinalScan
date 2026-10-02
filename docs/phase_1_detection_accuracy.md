# Phase 1: repository detection accuracy

## Scope

This extends the existing scanner. DAST, database schema, GitHub integration,
reporting, UI and remediation workflows are unchanged. Finding titles and source
locations remain compatible with fingerprinting and existing solution selection.
Historical scans retain their original findings: run a new scan to use these rules.
No repository code or discovered credentials are executed or tested.

## Review and changes

All existing SAST modules were reviewed. The table records important triggers,
false positives/negatives and how they are handled. Confidence describes evidence
for a potential issue, not a guarantee of exploitability or credential validity.

| Existing rules | Trigger and previous weakness | Phase 1 behavior / remaining qualification |
| --- | --- | --- |
| Python SQL | Constructed query at execute/executemany/executescript/raw; whole-file assignments lost ordering and aliases | Follow local aliases, concatenation, f-strings and format values. Constant queries and bound parameters are safe. Adding parameters does not protect an already interpolated query. Arbitrary similarly named methods remain a heuristic. |
| Python os.system/os.popen | Dynamic shell argument, little source context | Static arguments suppressed; known Flask input High confidence, unknown dynamic Medium. |
| Python subprocess | Dynamic command with shell=True | Track simple aliases and constant shell flags; argument arrays with shell=False are not shell injection. This does not certify executable/argument safety. |
| Python eval/exec | Dynamic code, little flow context | Skip tracked static values; request input High confidence and severity, unknown dynamic Medium. Imported aliases and simple builtin shadowing handled. |
| Python pickle/dill/marshal/yaml.load | Unsafe object loader | Known input High confidence; unknown origin Low. yaml.safe_load and explicit SafeLoader/CSafeLoader/BaseLoader are not reported. Custom loader aliases/implementations require review. |
| Python MD5/SHA-1 | All weak hashes treated similarly | Checksum/unknown purpose Low severity and confidence. Password/credential-sensitive variable context High severity with Medium confidence (High with tracked input). SHA-256 is not a weak-hash finding. Naming is not proof of purpose. |
| JS innerHTML/outerHTML/document.write | Dynamic HTML; global assignments and shallow sanitizer checks | Ordered aliases; constants suppressed. DOMPurify.sanitize protection follows aliases and is invalidated on reassignment/unknown transforms. Browser/HTTP input High, unknown dynamic Medium. |
| JS eval/Function | Dynamic execution, sanitizer could incorrectly suppress | Static code suppressed. HTML sanitization never protects code execution. Track arguments through local aliases; recognized input increases confidence/severity. |
| Java Runtime.exec/ProcessBuilder | Dynamic process arguments; global variable maps | Track ordered locals and declared Runtime types; static commands suppressed. Servlet input High, unknown dynamic Medium. Execution of a dynamic argument is a review finding, not proof that a shell is involved. |
| Java dynamic SQL | Constructed statement argument | Local alias/concatenation tracking; constant concatenation/formatting and PreparedStatement placeholders suppressed. Binding parameters does not repair concatenated SQL. |
| Java ObjectInputStream.readObject | Object stream type | Follow input-stream variables to request input, High confidence; unknown origin Low. Custom object filters are not proven safe by this phase. |
| Java weak crypto | MD5/SHA-1, DES/RC4/ECB selection | Track simple algorithm aliases; checksum hashes Low/Low; security-sensitive names High/Medium; weak ciphers Medium/Medium. Modern algorithms do not trigger. |
| Secrets | Typed tokens/private keys and credential assignments | Existing redaction/localization exclusions retained; explicit replace-me, dummy-password, test-secret and related placeholders suppressed. SECRET_KEY assignments recognized. Typed formats High confidence, generic candidates Medium; neither proves a live credential. |
| Configuration | Parsed literal debug/development, disabled controls, wildcard hosts | Reviewed, unchanged. Medium/High for explicit disabled controls, Low/High wildcard hosts. Development fixtures can be intentional; runtime overrides are not evaluated. |
| HTML | Password GET forms, HTTP form/resource URLs, sensitive comments; inline JS | Literal rules unchanged; inline JS inherits improved flow. Explicit markup generally High confidence, comments Low/Low. Templates/runtime changes are not evaluated. |
| Dependencies | Existing exact-version OSV matching | Reviewed, unchanged. Unresolved ranges are not treated as confirmed installed vulnerable versions. Advisory severity and existing lookup coverage reporting retained; availability, reachability and compatibility remain separate questions. |

## Local flow model

`scanner/sast/flow.py` stores an immutable abstract value: static/dynamic,
recognized source labels, variable-name trace, construction state, HTML protection,
and security-sensitive naming. It does not put actual values into finding evidence.
Only literal metadata needed for analysis (such as an algorithm or shell flag) is
held in memory. Existing central redaction still applies before persistence.

Python walks statements in order using AST. Java/JavaScript retain Tree-sitter and
use `tree_flow.py`. Assignments copy abstract values; reassignment replaces them.
Functions get separate environments with unknown parameters. Branch environments
merge conservatively rather than selecting the last assignment from the file.
Class traversal is isolated. This is lightweight local analysis, not a call graph.

Example evidence: recognized request input → username → name → query → SQL execute.
High confidence means a recognized input source reaches a supported sink without
recognized protection. Medium means a dynamic value with unknown original source.
Low means a security-relevant pattern with insufficient context, such as a weak
checksum or an object stream of unknown origin.

Flask sources include request.args/form/values/json/get_json/headers/cookies,
including ordinary imported request aliases. JavaScript recognizes location hash/
search, document URL and common req/request properties. Java recognizes common
Servlet request methods using request/req names or ServletRequest declared types.
These source classifications are heuristics, particularly receiver-name matching.

## Verification

`tests/test_detection_accuracy.py` holds text-only vulnerable, safe and protected
examples. It covers every improved sink family, all requested Flask sources,
parameterized SQL, static concatenation, alias chains, reassignment order,
function isolation, branch joins, sanitizer aliases and sanitizer/sink mismatch,
weak crypto context, placeholders and redaction. No fixture is imported/executed.
Verification result: **104 tests passed, 0 failed** (11 new accuracy test methods
with multiple vulnerable/safe/protected subcases, plus 93 existing tests).
The existing suite also checks pipeline persistence, nonexecution, reports,
remediation, dependency lookup, archive safety and GitHub/DAST behavior.

Run:

```sh
python3 -m unittest discover -s tests -v
```

## Limitations

- No interprocedural/cross-file taint analysis, call-site resolution, object heap,
  full type system, path feasibility, loop fixed points or framework runtime.
- Nested block shadowing, exception paths, closures and mutations can still lose
  precision. Branch merging intentionally favors review over declaring safety.
- Dynamic imports, aliased callable/sanitizer objects, destructuring, reflection,
  custom validators and custom deserialization filters are not fully modeled.
- DOMPurify recognition assumes the standard sanitizer; configuration and HTML
  insertion context are not validated. Sanitized text is not generically safe in
  other languages/contexts.
- Java password-hashing context relies on names at algorithm selection; later
  digest/update calls and complete crypto protocols are not analyzed.
- Placeholder suppression can miss a real secret deliberately resembling a
  placeholder. Typed candidates are not authenticated; redaction remains required.
- Invalid/unsupported syntax is reported through existing coverage metadata.
  A completed scan or zero findings is not proof of a secure repository.

Phase 1 stops here. No Phase 2 features or GitHub modifications are performed.
