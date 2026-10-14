---
name: opv
description: Set up and run opv, which syncs secrets and settings from 1Password into local runs, Fly.io, Azure, Kubernetes and GitHub Actions without printing a value. Use when a project has a secrets.toml, a .opv file or an opv manifest, or when the user wants to move secrets or settings into 1Password, onboard a fleet, run an app with its secrets, or sync or deploy them.
version: {{OPV_VERSION}}
---

# opv

This skill was installed by opv {{OPV_VERSION}}. The installed binary is the source of truth:
if `opv --version` differs, run `opv skill install` again (it keeps your edits unless you pass
`--force`).

## First, every session

```sh
opv guide agent            # the full guide for this version: rules, flows, exit codes
opv schema                 # every command, flag, effect, JSON document and error code
opv ready --json           # what is ready, what is not, who acts next (read-only)
```

`opv ready --json` and `opv doctor --env <env> --json` never write 1Password, whoever is
signed in: they are the safe readiness checks. Other commands that read an item may tidy its
layout when run in the user's own session (the schema's `tidies_1password`); when a layout
needs tidying, the explicit repair is `opv tidy <env>` (writes 1Password: ask first).

Read the rules in `opv guide agent` before anything else. In short: you never see, ask for,
type or store a secret value; the user signs in and types values only at 1Password's own
prompts or in the 1Password app; ask before anything that writes (the schema's
`ask_user_first`); prefer `--json` and act on `error.code`, `next` and `human_required`, not
on message text.

## Pick the flow from `opv ready --json`

- **No configuration yet** (`config_not_found`): ask which profile (one app: simple; several
  products: fleet), write `secrets.toml` without IDs, then the user runs `opv bootstrap` (it
  creates vaults and items in the selected account and records the IDs). Never create a second
  configuration beside one that exists, and never edit a file whose first line says it is
  generated: hand the printed IDs to its generator.
- **Account findings** (`no_accounts`, `selected_account_absent`, `account_ambiguous`,
  `selected_signed_out`): run `opv account list --json`; ask the user which account; record it
  with `opv account use <ID>`; hand `opv login --add --account <email>` or
  `opv login --account <ID>` to the user, wait, then re-run `opv ready --json`.
- **`ids_not_in_account`**: the recorded vault is in another account. Ask the user: select
  that account (`opv account use <ID>`) or rebind (`opv bootstrap --rebind <env>`).
- **`key_missing`, `key_empty`, `key_failed_rule`**: the user fills or fixes the value in
  1Password; give them the finding's `prerequisite` (`opv open <key> --env <env>`). Values that
  already exist elsewhere: `opv adopt <env> --from <file.env>` shows what would come in;
  `--apply` (asked first) writes it; `--replace` is the user's decision.
- **Everything saved**: local runs use `opv run <env> --product <p> -- <command>`; deploys go
  `opv plan <env>` then `opv sync <env> --expect-plan <id>` (add `--deploy` only when the user
  wants to deploy). CI secrets in GitHub Actions use a `github` environment and the same sync.
- **"Is product P still what was delivered?"** (environments with `state_vault_id`): run
  `opv delivery verify <env> --product <P> --json`. Only `verified` is proof. Report `changed`
  names with their state (`source_changed`, `drifted_on_target`, `missing_on_target`),
  `not_delivered` and `unverifiable` with their reason, and `deployed` separately. Never
  present a revision as proof without `verified`; a re-sync of P mints the new revision.

Resume after any interruption by running `opv ready --json` again: every step is safe to
repeat, and the receipt says what is left.
