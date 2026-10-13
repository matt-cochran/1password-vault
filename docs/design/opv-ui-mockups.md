# `opv ui`: mockups for review

Status: implemented in `src/ui/` for 0.6.0 (#82, #94, #95, #96, #97), 2026-10-13, following these mockups; every screen below is built, and the decisions taken are recorded at the end.
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

1. Navigation: a persistent left sidebar (Overview, Shared values, CI access, each environment, each product) with `tab` between it and the main pane.
2. Grid cells: saved/declared counts with a findings count, `not here` where a target does not deliver a product.
3. Writes: `opv ui` runs sync, adoption and configuration edits itself, but only as the same `opv` command, shown first (paste-safe) and run in the person's terminal: sync runs exactly the reviewed plan (`--expect-plan`), and a guarded environment needs its name typed. Sign-in and value entry hand off to 1Password (`o` = `opv open`).
4. The views decision 4 left open, each built as its own issue:
   - **Adoption review** (#94, screen 7): `i` reads `opv adopt --json`; per key import/skip or keep/replace/skip (with `--rotate` for an immutable key); `y` runs exactly the `opv adopt … --apply` it shows.
   - **Audit history** (#95): `h` on an environment reads `opv history --json`: the last write per key (stamp time, plan id, opv version) and what changed outside opv since; never a digest of a value.
   - **CI-reader access** (#96): the "CI access" sidebar entry reads `opv access --json`: people counted (never named), service accounts read-only or not, and the owner's exact `op service-account create … :read_items` command where one is missing.
   - **Editing the configuration** (#97): `+` declares a key and `E` adds an environment through forms that run the exact `opv add` / `opv init --add-env` they show; `e` hands off to `opv config edit`.
5. Settings health (#92) shows in the overview's "needs attention" and on the key screen.

The screens are frames tested in ratatui's in-memory backend from documents recorded from a real run (`src/ui/render_tests.rs`), including that no screen ever contains a value, and were driven by hand in a real terminal (tmux, three sizes) before 0.6.0, which found and fixed 11 terminal bugs (keys, signals, `NO_COLOR`, redraws).
