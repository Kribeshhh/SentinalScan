# UI Context

## Theme and Tokens

Dark technical workspace with layered cards and mint interactive accents. Reuse
existing CSS variables in `static/css/style.css`; do not introduce a new UI library.

| Role | Existing variable | Value |
| --- | --- | --- |
| Background | `--bg` | `#0b1017` |
| Panel | `--panel` | `#111923` |
| Border | `--line` | `#25303e` |
| Primary text | `--text` | `#e5edf6` |
| Muted text | `--muted` | `#91a1b5` |
| Accent | `--accent` | `#5ce0b6` |
| Critical | `--critical` | `#ff7189` |
| High | `--high` | `#ffac72` |
| Medium | `--medium` | `#ebcc77` |
| Low | `--low` | `#7babff` |
| Informational | `--informational` | `#9babbf` |

Existing CSS also contains local literal colors; reuse tokens for new shared styles.
Do not claim a token migration has happened. Severity colors need text labels.

## Typography and Components

UI: Inter/system sans-serif stack, 14px root. Code: ui-monospace/SFMono-Regular/
Consolas stack. Existing radii are generally 5–6px for controls and 8–10px for
cards/panels; extend existing classes rather than adding a second styling system.
Reuse Jinja macros in `_components.html` and existing buttons, tables, badges and
forms. Navigation uses simple text symbols; no React icon dependency.

## Layout and Information Hierarchy

- Sidebar/top navigation on desktop; accessible collapsible navigation on mobile.
- Cards, readable tables and meaningful empty states backed by actual SQLite data.
- One Recommended Fix: concise action, optional safe primary example, fix confidence
  and fix confidence. One collapsed Technical Details holds source, evidence,
  rationale, alternatives, detailed validation, AI review and workflow.
- Highlight the detected line. Label source-matched fixes versus illustrative code.
- Keep the title, severity, location, short explanation and detection confidence
  visible. Do not render competing scanner/AI recommendations or empty subsections.
- Keep secret rotation/removal actions and failed-validation warnings visible.
- Preserve `#recommendation`, `#code-solution` and historical code links. No manual AI form or second recommendation.

## Verification

Use semantic HTML, labels, keyboard focus, escaped output and readable contrast.
Check desktop and phone widths, disclosure controls and page overflow for layout
changes. Use explicitly labelled isolated fixture previews; never seed fake results
into the real scan history. Do not restore editor or GitHub publication controls.

AI contributes automatically after new scans when enabled. Show a small AI Assisted
indicator only for an accepted improvement; failure leaves ordinary guidance.

Fallback: when no exact fix exists, show a short Example Secure Pattern with an
explicit illustrative/adaptation note where safe. Preserve source-specific labels;
unknown website APIs use pseudocode. Operational findings may remain text-only.

Current/recommended code display: the existing Recommended Fix card now pairs
retained actual source with a statically validated source replacement, or a complete
matched dependency entry with an advisory-supported fixed release. Historical
dependency snippets may supply a unique complete recorded entry; advisory metadata
alone never supplies Current Code. Missing, truncated or ambiguous current entries
retain Example Secure Pattern. Website/secret findings never get fabricated pairs.
Desktop uses two columns; mobile stacks them. Each block has its own copy control.
Source context remains in Technical Details without a duplicate Current Code label.
No detector, source capture, AI workflow or publication behavior changed.

## Final product polish

Shared tokens use charcoal #101214 / #181b1e, neutral #2b3035 borders, soft-white
#edf0f2 text, #a0a9b2 secondary text and emerald #62d5b0. Controls have a 42px minimum
height; severity colors indicate findings only. Sidebar groups Overview, Assess,
Analysis and Reports. Risk leads the dashboard. Forms use expandable scope details;
findings expose location/confidence/scan in scrollable tables. Current/Recommended
Code uses two framed panels on desktop and stacks below 850px, with separate Copy
buttons. There is no editor or publication action. Native disclosures, keyboard
focus, table regions and reduced-motion handling remain. Reports are light for print.

## Phase 23 — instructions and text-only guidance

Website form examples are queryless. Concise help explains that query URLs require
trusted inert-endpoint review, unsafe replay is blocked, and skipped checks do not
prove security. No controls/routes or replay policy changed. The shared recommendation
policy removes obsolete references to nonexistent examples in text-only actions;
banner findings advise minimizing version headers while keeping software patched.
Existing examples, one final recommendation and AI indicators remain unchanged.

## Phase 24 — example labels

Inside the one Recommended Fix card, supported illustrative examples may show
Vulnerable Example followed by Safer Example / Example Secure Pattern. They never
use Current Code or Recommended Code labels reserved for supported actual pairs.
Show example type, conservative fix confidence and existing validation status.
YAML credential examples use [REDACTED]; Python runtime loading is explicitly
cross-language illustration, not YAML interpolation or a verified replacement.
Reuse escaped code blocks and existing copy controls; Technical Details is retained.
