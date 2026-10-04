# AI Workflow Rules

## Approach

Use the six context files as the maintained project map, alongside the detailed
subsystem constraints in `AGENTS.md`. Implement the user's requested change in the
existing SentinelScan application. Templates describe a workflow, not permission to
invent features, replace the stack or start another phase.

## Scoping Rules

- Work on one feature unit at a time in small, verifiable increments.
- Split UI changes from background-task changes when they can be independently
  verified. Split unrelated route changes and uncertain architectural changes.
- A larger authorized task may contain several sequential units; complete all of
  its requested units rather than stopping after the first increment.
- Preserve unrelated working-tree edits. Do not delegate to agents unless requested
  by the user or an applicable explicit instruction.

## Missing Requirements

Record missing requirements/open questions in `progress-tracker.md`. Resolve clear
routine choices using existing behavior and document the decision. Ask about
materially ambiguous product behavior or major architecture before dependent work;
continue independent work when possible. Do not guess new product capabilities.

## Protected Files / Data

Without an explicit scoped request, do not rewrite user scan data, saved immutable
reports, secrets/local configuration, vendored dependencies or third-party internals.
Do not relabel frozen evaluation fixtures or replace baseline artifacts to hide
errors. Intentional dataset revisions need a new version and rationale. Normal
application operations continue to persist the user's authorized actions.

## Keeping Docs in Sync

Update `progress-tracker.md` after every meaningful implementation change. If scope,
architecture, storage, UI or standards change, update the corresponding context
file before continuing. Link detailed phase documentation rather than duplicating
all historical specifications. Keep historical test results labelled as historical.

## Before Moving to the Next Unit

1. Verify the current unit end to end within its defined scope.
2. Check architecture invariants and privacy/security requirements.
3. Update the progress tracker and any affected context file.
4. Run appropriate focused checks and the full Python unittest suite for code
   changes. There is no `npm run build` in this Flask project. For documentation-only
   work, check references/content; run the complete suite when the user requests it,
   otherwise state explicitly if tests were not rerun.
5. Report actual outcomes, unresolved limitations and next steps; stop when the
   authorized task is complete, without starting an unrequested phase.
