## Application Building Context

Read these files in order before implementing or making an architectural decision:

1. `context/project-overview.md` — product, goals, features and scope
2. `context/architecture.md` — boundaries, storage, access and invariants
3. `context/ui-context.md` — theme, components and information hierarchy
4. `context/code-standards.md` — implementation and verification conventions
5. `context/ai-workflow-rules.md` — scope, workflow and protected data
6. `context/progress-tracker.md` — current state, verification and next steps

Also follow `AGENTS.md` and its applicable subsystem documentation. These files
adapt the user's Six-File Context Methodology to the existing SentinelScan project;
examples for other technology stacks are not requirements for this application.

Update `context/progress-tracker.md` after every meaningful implementation change.
When architecture, scope, UI or standards change, update the relevant context file
before continuing. Preserve existing security constraints and user data. User
instructions govern the requested scope; record and resolve material conflicts
rather than silently inventing behavior.
