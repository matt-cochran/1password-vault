# `opv ui`: mockups for review

Status: mockups for owner review, 2026-10-13 (#82). No code until the owner approves a direction.
Canvas (private to the owner): https://claude.ai/artifact/Nwh6mBbYQW3JihuyeFDwyj

## Principles the mockups follow

- One binary, one core: the TUI renders the readiness receipt (FR-51, `opv ready --json`) and the
  existing `status`/`plan`/`explain`/`adopt` models. It keeps no state of its own.
- Values are never fetched for display. A secret shows as `••••` plus its state (saved, same,
  changed, new, held, unknown); config values, which are not secret (FR-14), are shown.
- Every action shows who acts (owner, agent, CI), what it changes, and the exact `opv` command it
  runs (`c` copies it), so nothing is a hidden side effect and everything stays scriptable.
- Sign-in and value entry never happen inside the TUI: they hand off to 1Password's own prompt or
  app and resume (FR-50, SR-1, SR-3).
- Keyboard first (a key bar on every screen), no colour-only signals, a line-mode fallback for
  screen readers, dumb terminals and non-TTY runs.

## Screens

1. **Overview**: environments × products readiness grid (saved/declared, the next sync's action,
   `not here` where a target does not deliver a product), "needs attention", and one next action.
2. **Product**: one product's keys × environments, with kind, masked state, rules, shared-value
   pointers, and a legend.
3. **Key detail**: where the key lands in each environment, why it is blocked, and the actions
   (fix in 1Password, re-check, plan, point at a shared value, explain) with their commands.
4. **Shared values**: each canonical value and every consumer across repositories and apps (the
   blast radius), with a guided rotation that plans every consumer first.
5. **Sync**: the plan with its id (write, held, prune, never touched), blockers, options, typed
   confirmation for a guarded environment, and the result with provenance.
6. **Account picker**: shown even with one account, "Add another", the WSL explanation, and
   sign-in failures in opv's words.
7. **Adoption review**: found vs 1Password per key (never values), keep/replace/skip decisions,
   apply with verification, resumable.

## Decisions for the owner

1. Navigation: persistent left sidebar (as drawn) or full-screen views with tabs?
2. Grid cells: counts plus the next sync action (as drawn), or a simpler ✓ / ! / ✗?
3. Writes: may `opv ui` run sync and adoption itself behind the plan-and-confirm step (as drawn),
   or only open the exact command for the person to run?
4. Missing views: audit history (provenance), a CI-reader access view, or editing the
   configuration itself?
