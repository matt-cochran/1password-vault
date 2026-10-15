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

## Agents own structure; people own sign-in, approval and values

With the opv MCP server (`opv-mcp`), declare products, keys, environments and targets with
`opv_declare_key`, `opv_declare_environment` and `opv_declare_target` (local `secrets.toml`
only; never a value), then `opv_structure_plan`. Ask the user to run `opv approve <plan_id>`
in their own terminal (never run it yourself), then `opv_structure_apply` with that id. Hand
the user the returned 1Password links to enter values there, and finish with `opv_ready`.
`stale_plan`: plan and ask again. `approval_required`: wait for the user's approval.
`credential_in_environment`: the user restarts the server without `op` session, service
account or Connect credentials. If a tool is missing in this version, say so; use
`opv bootstrap` in the user's terminal instead and never work around it. Details:
`opv guide agent`, section "Optional MCP server".

## CI identities

A validation job (`check`, `plan`, `ready`) uses the read-only reader from
`opv bootstrap --ci-reader <env>`. A job that syncs uses the target's deploy identity from
`opv access <env> --target <name>`: boundary read plus read and write on its own state vault,
where delivery evidence goes. `opv ready` says `evidence_write: "not_verified"`: only a sync
checked with `opv delivery verify` proves it. Never widen a boundary vault to write.

## Pick the flow from `opv ready --json`

- **No configuration yet** (`config_not_found`): there is one form (FR-60). Let
  `opv init`/`opv add` write `[products.<name>.keys.<KEY>]` (one product for one app, more
  for a fleet) and a boundary per environment; `opv init` writes no target. Then the user
  runs `opv bootstrap`, which creates each boundary's vault and item in the selected account
  and records their IDs, and adds each deploying environment's target with
  `opv target add <env> <name> --<provider options>`, the one way to add a target (it
  validates it, creates its state vault and records its placements). Never create a second configuration beside
  one that exists, and never edit a file whose first line says it is generated: hand the
  printed IDs to its generator.
- **Finding existing projects**: `opv projects --json` lists manifests per 1Password account.
  Use `--account <email or account ID>` (or run it as `opv login --account <a> -- opv projects
  --account <a> --json`) to ask one account. Trust a missing project only when `complete` is
  `true`. An `inventory_incomplete` error (exit 4) or an `accounts[]` entry with `status:
  "failed"` means that account was not read: hand its `next` to the user and wait. Never
  treat an incomplete inventory as permission to create a replacement vault or manifest.
- **Adding a placement** (a product on another target): `opv ready --json` names a target as
  `grants_missing` until its deploy credentials, state vault and every boundary it reads can
  be opened. Declare one with `opv target add <env> <name> --<provider options>` (it asks
  first and creates the target's state vault). A `state_vault_wider_than_values` load error
  means a target shares a state vault it cannot read; give it its own by deleting its
  `state_vault_id` and running `opv bootstrap`.
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
- **"Is product P still what was delivered?"** (targets with a state vault): run
  `opv delivery verify <env> --product <P> --json`. It reports every placement of P, each with
  its target and state; `--target <name>` narrows to one placement. Only `verified` is proof.
  Report `changed` names with their state (`source_changed`, `drifted_on_target`,
  `missing_on_target`), `not_delivered` and `unverifiable` with their reason, and `deployed`
  separately. Never present a revision as proof without `verified`; a re-sync of P mints the
  new revision.

Resume after any interruption by running `opv ready --json` again: every step is safe to
repeat, and the receipt says what is left.
