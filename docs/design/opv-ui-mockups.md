# `opv ui`: mockups for review

Status: implemented in `src/ui/` (#82), 2026-10-13, following these mockups; the decisions taken are recorded below.
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

## Decisions, as built

1. Navigation: a persistent left sidebar (Overview, Shared values, each environment, each product) with `tab` between it and the main pane.
2. Grid cells: saved/declared counts with a findings count, `not here` where a target does not deliver a product.
3. Writes: `opv ui` runs sync and adoption itself, but only as the same `opv` command, shown first, run in the person's terminal: sync runs exactly the reviewed plan (`--expect-plan`), and a guarded environment needs its name typed. Sign-in and value entry hand off to 1Password (`o` = `opv open`).
4. Not built yet: audit history (provenance), a CI-reader access view, editing the configuration, and the per-key keep/replace/skip adoption review (adoption runs `opv adopt`, which reviews in the terminal). Each can follow as its own issue.

The screens are frames tested in ratatui's in-memory backend from documents recorded from a real run (`src/ui/render_tests.rs`), including that no screen ever contains a value.
