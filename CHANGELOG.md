# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - Unreleased

Azure and Kubernetes targets, a more resilient CLI, and one install location. Check **Changed**
before upgrading.

### Added

- Configuration in 1Password (FR-44): the `secrets.toml` schema can live in a project manifest (Secure Note `opv · <project>`, tagged `opv-manifest` and `opv-repo:<host>|<owner>|<repo>`), so a checkout needs no file. Discovery: `--config`, `OPV_PROJECT`, an existing `secrets.toml` (still wins), a `.opv` file, then the git remote; monorepos match by path tag (`--path`), longest prefix first. New: `opv config import`, `opv config export [--toml|--json]`, `opv config edit` (diff, confirm, refuses a concurrent change), `opv config check --file` (exit 8 with a diff), `opv projects [--long] [--json]`, `opv status --all [--json]`; `opv init` in a new project saves a manifest unless `--file`; `opv add` and `opv init --add-env` edit a manifest as they edit a file (same validation, atomic write and concurrency refusal). Manifests are found in `OP_ACCOUNT` (or the `.opv` account), else in every signed-in account; once loaded each environment uses its own `account` and `deploy_credentials`, in `status --all` too. A configuration error in a manifest names `manifest "opv · <project>": <field>` with `Next: opv config edit`. `doctor` names the configuration source. See [configuration](docs/configuration.md#configuration-in-1password) and [design](docs/design/config-in-1password.md).

- Shared keys: `from = "<product>/<KEY>"` on a key reads another key's field in the same environment's item, so a value two products use (e.g. `DATABASE_URL`) has one copy in 1Password and one place to rotate. Each key keeps its own target name and `run` export; a missing source is one finding listing the keys it affects; `explain` shows the chain; `item skeleton` adds no field for a sharing key. Validated at load: same kind, source declared for the same environments, no chains or cycles, no cross-item or cross-environment references ([configuration](docs/configuration.md#shared-keys-from); FR-45).
- Azure target: `[environments.<env>.azure]` syncs secrets to Key Vault and binds them to a Container App ([#39](https://github.com/matt-cochran/1password-vault/issues/39); FR-28 to FR-33). Secrets are written as new versions and the app uses them only after `opv sync <env> --deploy`; `--prune` removes old entries only after a healthy revision. See [usage](docs/usage.md#sync-on-azure-and-kubernetes).
- Kubernetes target: `[environments.<env>.kubernetes]` stores values as immutable Secrets and updates a Deployment through `kubectl` (FR-38).
- Named stores: `[stores.<name>]` declares a store once and `secrets_in = "<name>"` on a runtime keeps its secrets there; commands are unchanged. First pair: Azure Key Vault → Kubernetes Deployment through the External Secrets Operator, pinned to one Key Vault version per ExternalSecret, checked before any write and pruned only after a healthy rollout ([configuration](docs/configuration.md#secrets-in-a-named-store-storesname-and-secrets_in); FR-39).
- Plug-in providers: Fly, Azure and Kubernetes implement one contract, so a new provider is one module ([CONTRIBUTING.md](CONTRIBUTING.md#adding-a-provider); FR-37).
- Resilience (NR-1 to NR-30): reads retry up to 3 times, writes never; progress lines during waits and while a rollout write runs; `--timeout <secs>` (default 1800) caps a run; a write that waits for a rollout (`flyctl secrets deploy`, `az containerapp update`, `kubectl apply`/`replace`) may run up to 15 minutes, other writes 2; `--verbose` prints one line per external call; every mutating run ends with a summary and every failure with one `Next:` line; Ctrl-C and SIGTERM leave the target safe to re-run (exit 130/143).
- Exit code 9: outcome unknown, or a provider did not answer. Nothing is known to be broken; re-run the same command. A read that never answers after a run started writing is exit 9, never "nothing was changed"; an Azure read outage before any write is exit 9 `provider_unavailable` naming azure.status.microsoft. An Azure update that Azure refused with nothing applied (no new revision, provisioning `Failed`) is exit 5 `update_refused` with `Next: opv doctor --env <env>`, so CI does not retry it.
- Kubernetes: every right `sync` needs is required; `doctor` fails a missing one with the exact grant, and `sync` refuses before its first write without the rights only a deploy uses (delete Secrets or ExternalSecrets, list ReplicaSets and Pods). Removing superseded versions after a healthy deploy is a warning when it fails, never the run's result. A second `sync` without `--deploy` reuses the version it already wrote; a name kept for rollback by an older ReplicaSet is reported as unbound, not pruned.
- Azure `--prune --deploy` removes a pruned name's Container Apps secret in the same update and deletes the Key Vault entry only once no configuration references it.
- Known Fly limitation, documented: a run interrupted between `flyctl secrets unset --stage` and the deploy leaves the name on the machines, and the next run cannot see it because Fly hides unset names at once. Run `opv sync <env> --deploy` again or `flyctl secrets deploy` ([usage](docs/usage.md#pruning-on-fly)).
- `opv completions <bash|zsh|fish|powershell>` prints a shell completion script ([usage](docs/usage.md#shell-completion)).
- `OPV_CONFIG` sets the default for `--config`; `OPV_PRODUCT` sets the default for `--product` on `check`, `run`, `doctor`, `explain`, `status` and `plan` (fleet profile, never `sync`), reported on stderr when used.
- `--color auto|always|never`: state words are coloured on a terminal; `NO_COLOR` is honoured and piped output is unchanged.
- Every command's help groups `Global options:` and ends with examples; exit-code help names Fly, Azure and Kubernetes. `config export` no longer needs `--json` (still accepted).
- `confirm_env = true` on an environment makes `sync` refuse (exit 6, before any write) without `--confirm <env>`; the refusal's `Next:` line is the exact command to re-run. A `--confirm` naming another environment is always refused (P10, NR-20). CI jobs that sync a guarded environment must pass the flag.
- Every failure ends with exactly one `Next: <command>` line, the last line on stderr, for every error category, usage errors and interruptions; scripts and assistants can match `^Next: ` (P1, NR-19). `Next:` is always one command that runs as typed; a step only a person can take (fill a value in 1Password, sign in, approve a guarded environment, use their own terminal) is on a `Do:` line right before it. A misspelt environment or product, an undeclared key and a usage error point to `opv <command> --help` instead of `opv doctor` (A3).
- `--json` failures print one document on stdout instead of nothing: `{schema_version, ok: false, exit_code, next, do, error: {code, category, message, detail, retry, human_required, do, next}}`, with the human text still on stderr. Every `--json` document starts with `schema_version` and `ok` and ends with `next` and `do`; findings (exit 8) keep their rows and add `error`. `retry` is `safe`, `after_fix` or `never`; `human_required` marks a step to hand to the user (A1, A9).
- Stable error codes (`error.code`): a closed list such as `unknown_env`, `keys_blocking`, `confirm_required`, `terminal_required`, `op_not_signed_in`, `item_not_found`, `vault_no_access`, `target_unhealthy`, `findings`, `outcome_unknown`; exit codes are unchanged ([usage](docs/usage.md#json-contract); A2).
- `opv schema` prints a machine-readable description of the installed binary: commands, arguments, flags, effects (what each command changes, whether it needs a terminal, whether to ask the user first), exit codes, error codes, state words and document fields, generated from the command definitions (A4).
- `--json` on `explain`, `init` and `item skeleton`, and on `status` without an environment (one entry per environment) (A5).
- `sync` ends with one summary line, the same on Fly, Azure and Kubernetes: `summary: written N · unchanged N · held N · deployed <revision|yes|no>[ (N pending from an earlier run)] · pending N · pruned N · kept N · skipped N`, then `Next:` when a deploy or prune is left to do. `sync --json` prints that report as one document (`schema_version` 1) whose lists hold `{product, key, target_name}` objects, with `deploy_reason`, `deployed_names` and `written_names`. `--prune` prints `will prune: <names>` before it acts (P2, NR-18, NR-20, S4).
- `plan` names what a sync would do (`would stage:` or `would write:`, `would prune (needs --prune):`, `held (immutable):`) and ends with the exact sync command, including `--prune`, `--product` or `--confirm <env>` when they apply (P11).
- `--product <p>` on `status` and `plan` limits rows, totals and exit-8 findings to one product; `OPV_PRODUCT` is their default (P12, NR-16). `sync --product <p>` writes, prunes and deploys only that product's names and says when a Fly deploy would also apply other products' staged changes (P20).
- `opv guide agent` prints the agent setup guide built into the binary, with links to the docs of the same release; llms.txt starts with a short contract (safe commands, ask-first list, `Next:` rules, exit codes with retry semantics) (A10).
- Shorter subcommand help: the about line, usage, two or three examples, the command's own options, then details and more examples; the global options are one closing line (`opv --help` keeps them in full) and `-h` hides `--rotate`/`--prune-immutable` (H9). Help examples never chain a write after `||` or `&&` (S3).
- A `secrets.toml` error names `file:line: field`, shows the line, and prints the edit on a `Do:` line when it can be derived (closest field, value or environment). Usage and configuration errors end with a specific read-only `Next:` (`opv status prod`, `opv check dev --product api`, `opv explain api/KEY --env prod`, `opv plan <env>` after a broken file under `sync`) instead of `opv doctor` (H10).
- On a `confirm_env` environment, `sync` without `--confirm` now reads and validates first and refuses right before the first write, so one refusal names the blocking keys and the missing flag together; a `--confirm` naming another environment is still refused before any call (H12).
- `opv status` without an environment prints one count line per environment (P22). It reads run-only environments too (`dev: run-only · 6 keys · 5 saved · 0 skipped · 1 finding`), so a broken local environment is a finding (exit 8) instead of a green overview, and it honours `--product`, `OPV_PRODUCT` and `--json` (one entry per environment: `name, target, state, keys, saved, skipped, findings, error_code, error, next`; `next` is the runnable command for an environment that could not be read, see A5) (H11).
- Links to 1Password: every missing or failing row in `status`, `plan` and `check` carries `open: <link> (section <product>, field <KEY>)`, 1Password's private item link (account, vault and item IDs and the sign-in host from one free `op whoami`, made only when something needs fixing; never a value). `--json` rows gain `open_url`. The findings `Next:` line is now `opv open <first key> --env <env>` instead of the non-runnable `fix the keys above in 1Password, then run ...` (H1).
- `opv open <[product/]KEY> [--env <env>] [--print]` prints a key's section, field and item link and opens it with `xdg-open`, `wslview`, `open` or `rundll32` (a structured command, never a shell); over SSH, under CI, without a display or with `--print` it only prints the link. `explain` shows the `open:` command (H1).
- `opv help states` defines every state word; `opv help <command>` prints that command's help (H5).
- CI job summary: with `$GITHUB_STEP_SUMMARY` set, `status`, `plan` and `sync` append a Markdown table or summary (names and state words only; no value, rule reason or link). `status --json` and `plan --json` gain `changes`: `none`, `some` or `unknown` (only Fly keys whose values cannot be compared would be staged) (H8).
- `status` and `plan` JSON rows carry `target_name` next to `fly_name` (same value; `fly_name` is deprecated and kept); `"product"` is the `--product` that scoped the document, or `null`. `status`, `plan` and `check` share one row shape and key order (`product, key, kind, state, rule, reason, target_name, fly_name, target, action`); `check --json` rows gain `kind`, `target_name`, `fly_name`, `target` and `action`, and the document gains `product` and `totals`; `plan --json` carries the sync command as `next`. Keys keep their declared order in every document. `--json` rows gain `open_url` (H1) and `status`/`plan` documents gain `changes` (H8). `schema_version` stays 1 (P4, A6).
- `opv doctor` lists every `opv` on `PATH` and warns about more than one; it checks `az` (2.60 or newer) and `kubectl` for environments that use them. <!-- verify -->
- `opv login [<env>] [-- <command>]` and `opv setup`: guided sign-in to the 1Password account an environment uses, and resumable project onboarding ([guided setup](docs/guided-setup.md); [#63](https://github.com/matt-cochran/1password-vault/pull/63); FR-40). No token is printed and nothing needs `eval`; a command after `--` keeps its exit code; sessions for environments in different accounts coexist in one terminal. Every sign-in hint (doctor, errors) is now `opv login <env>`, the same in every shell, instead of `eval $(op signin)`.
- `account = "<sign-in address or account ID>"` per environment: every `op` call for it uses that account (FR-40).
- `deploy_credentials = "op://<vault>/<item>"` per environment: `status`, `plan`, `sync` and `doctor --env` sign the target CLI in with that environment's least-privilege deploy identity for the run only. Fly: `FLY_API_TOKEN`, only in `flyctl`'s environment. Azure: a service principal signed in to a private per-run `AZURE_CONFIG_DIR` (RAM-only on Linux/WSL, DPAPI-encrypted on Windows; not macOS), removed at the end of the run, including Ctrl-C and SIGTERM. Kubernetes only when its secrets are in a Key Vault (`secrets_in`): the Azure fields sign in the `az` that writes it. A failed deploy sign-in is one `FAIL deploy credentials` line in `doctor --env`, which still runs its other checks (FR-40, SR-4, SR-5). See [configuration](docs/configuration.md#account-and-deploy-credentials).
- Azure on native Windows: values reach `az` through a user-only named pipe instead of `/dev/stdin`, so Key Vault writes and Container App updates work without WSL.
- `opv sync` checks the Fly app before its first write (`flyctl status`, `flyctl releases`): a deleted (`dead`) app stops it with nothing written and the next step; a Fly deploy already running is waited for, with a progress line at least every 15 s, within `--timeout` (at most 10 minutes), and stops it with nothing written only if it is still running then; suspended, pending or stopped-machine apps print a `warn` line and staging goes ahead, and `--deploy` is skipped with a notice when the app has no machines (NR-23, NR-24).
- `opv doctor --env <env> [--product <p>]` reads the item once by IDs and reports `ok item: <vault>/<item> readable (<n> field(s) in section <p>)`, or a failing line naming each key that is not ready and `opv check` as the next step, so doctor is never all clear when `check` would fail. `opv doctor --json` prints `{schema_version, ok, checks: [{name, status, detail, next, do}], next, do}`.
- `opv explain KEY` resolves the product when only one declares the key, lists the candidates when several do, and suggests close names for an unknown key or product; a single close name becomes the `Next:` command.
- When an external call fails, its last stderr lines (at most 5, every secret masked as `__SECRET__`) follow opv's error line as `  <program> said: …`, before the `Next:` line (NR-31).
- Plan ids: `plan` prints `plan <id> (1Password item v<n>)` and `plan --json` carries `plan_id`; `opv sync <env> --expect-plan <id>` applies exactly that plan and refuses before any write (exit 6) with the new id and the exact command if the item, a store version or `secrets.toml` changed. The id covers names, states, version ids and the item's version number, never a value; nothing is stored. `--expect-plan` satisfies `confirm_env`; `sync --json` reports `plan_id` ([usage](docs/usage.md#review-then-apply-exactly-that-plan---expect-plan); FR-41, A7).
- Provenance stamps: Key Vault versions opv writes are tagged, and Kubernetes Secrets, ExternalSecrets and Deployments it writes are annotated, with `opv-version`, `opv-written` (UTC), `opv-env` and `opv-plan`, never a value. `status` prints `<provider>: last changed by opv <version> at <time> (plan <id>)` and `status --json` carries `provenance`. Not on Fly (FR-42, H7).
- A missing object is reported at once instead of after 3 tries: `op` saying an item or vault does not exist (also after the vault-access diagnosis), `kubectl` `NotFound`, and `az` `SecretNotFound`/`ResourceNotFound`. Unrecognised failure text keeps its retries (S2).
- After staging, `sync` re-reads Fly's list for up to 30 seconds until every staged name shows a digest, so a lagging list is never reported as unchanged (NR-30).
- `opv add <[product/]KEY> --kind secret|config [--env e …] [--rule name=value …] [--guidance …] [--immutable]` declares a key in the configuration (`secrets.toml` or a manifest), or adds environments to a declared key, without hand-editing. It is edited in place (comments and order kept), validated like a hand-written file before writing (a name colliding on any target, an unknown rule or a bad value is refused and nothing is written) and written atomically. No item or target call; `Next: opv item skeleton <env>` ([configuration](docs/configuration.md#declare-a-key-opv-add); H2).
- `opv init <env> --vault … --item … --add-env` adds one environment to the existing `secrets.toml` and includes it in every declared key the item has; it refuses an environment that already exists (H2).
- `opv init --target fly|azure|kubernetes` with each provider's options (`--azure-key-vault`, `--kubernetes-namespace`, …) writes the target section for every provider; the options come from the provider contract (`Provider::init_fields`), so a new provider brings its own. `--fly-app` keeps working ([configuration](docs/configuration.md#start-from-an-existing-item-opv-init); H3).
- Self-healing 1Password conventions (FR-43): you no longer lay out the item by hand. Every command finds each declared key wherever its field is (label spelled differently, wrong section, top level, saved as the other kind, given twice), so a layout difference never blocks a command. Run by a signed-in person, opv also tidies the item in one atomic edit: creates missing sections and empty fields, conceals secrets saved as text, renames and moves fields, sets duplicates aside, and fixes a trailing newline or a missing `ensure_prefix` where the rules make the intent unambiguous. Nothing is deleted: displaced or replaced copies go to section `opv · kept`. One `tidied 1Password (<env>): ...` line on stderr and a `tidy` array in `--json` say what changed. Service accounts, Connect, CI and runs under an environment's deploy credentials never write; they print one note, once per environment, and only when a person's run would change existing fields. The project manifest item and an item holding an attachment, a website list, a one-time password, an SSH key or another field type an edit is not proven to keep are never tidied (one note). `opv init` creates a missing vault or item for a person. See [configuration](docs/configuration.md#store-layout).

### Changed

- A key saved as the other field type, a duplicate label, or a field outside its section is no longer an error in `status`, `plan`, `sync`, `check`, `config export`, `init` or `setup`; it is read tolerantly (and tidied for a person). `wrong kind` no longer appears for a field opv can find (FR-43).
- `run` reads the item once before `op run`, to tidy it (for a person) or to reference a misplaced field by its ID (FR-43). Under a read-only identity a value a person's tidy would normalize (trailing newline or space, missing `ensure_prefix`) reaches the child already normalized, through `op run`'s environment, so `run` and `sync` see the same value whether or not the tidy has written yet.
- `--json` covers the new fields: rows carry `shared_from` (state `source_blocked` while the source has a finding), documents carry `tidy` and, when a tidy did not complete or could not be verified, `tidy_error` (new codes `tidy_conflict` and `tidy_unverified`, never a failure). `opv open --json` prints the key's section, field and link; `opv schema` lists `open`, `help`, every new field and the `changes`, `tidy_action` and TARGET word sets. `item skeleton` reads the item tolerantly, so a field opv finds elsewhere counts as present. Self-healing never creates a field for a shared key, and the `still needs a value` line ends with the item link.
- A 1Password or Fly read that gets no answer after 3 attempts exits 9 naming the provider, the step and its status page (status.1password.com, status.flyio.net); nothing was changed. It was exit 4 (1Password) or 5 (Fly) (NR-28).
- With no `secrets.toml`, opv offers both ways to start: `opv init` for an existing 1Password item, `opv setup` for a new project. `opv setup` without `opv.setup.toml` points to the generic recipe and the command that uses it.
- A failing `enum` rule lists the declared values: `failed enum (expected one of: debug, info)`, never the stored value.
- A failed item read is diagnosed (`op whoami`, `op vault get`) before it is retried; it is retried only when signed in with access to the vault, so a wrong ID or a missing sign-in is reported at once instead of after two retries.
- `doctor` reports a missing `op` once (the sign-in check is skipped), an older `op` with an upgrade command, and no longer repeats a long failure (a TOML error) in its final error line.
- A failed item read while signed in now tells removed vault access from a moved, archived or deleted item (`op vault get <vault_id>`, by ID), with the next command (NR-26).
- A `sync` refusal ends with the `opv explain` command for the blocking keys (NR-17). A sign-in lost after `sync` wrote something names the writes that completed (NR-10).
- npm and `install.sh` install to the same place (`~/.local/bin/opv`, or `%LOCALAPPDATA%\Programs\opv\opv.exe` on Windows), so either can update the other's copy ([install](docs/install.md#one-install-location)).
- `status` and `plan` start with a one-line count summary (`prod: 4 keys · 3 saved · 1 skipped · 0 findings · 1 not yet on Fly`); rows are unchanged. The `status` closing line (`N saved, M not yet on Fly (staged by the next sync), 0 findings`), the `N key(s) missing ...` and `N key(s) block a sync` lines and the plan's `to prune (with --prune):` lines are gone. On clouds `--json` gains optional `binding`, `pending_deploy` and `drift` fields; `schema_version` stays 1.
- Sync output names keys as `product/KEY (TARGET_NAME)` and uses the same words on every provider: `written:`, `unchanged:`, `pending deploy (pass --deploy):`, `extra, not pruned (pass --prune to remove):`, `held (immutable), ...`, `deployed: ...`, `pruned: ...`. The Fly-only lines `N to stage, ...`, `staged: N changed, M unchanged`, `pending on Fly:`, `nothing pending` and `staged changes not deployed (no --deploy)` are replaced (P2, P19).
- `doctor`'s `Next step (<check>): ...` line is now the `Do:`/`Next:` lines on stderr (on success, `all clear: nothing pending` on stdout), and a failing check shows its fix under it as `  fix: ...`. `check` labels a key's guidance `guidance:` instead of `Next:`. Findings print `opv: 1 finding` / `opv: N findings` instead of `opv: status findings: N` (P1).
- `status` and `plan` list problem rows first and give the full fix reason (for example `failed enum (expected one of: debug, info)`). `plan` says `would stage once the findings are fixed:` while findings block the sync (H4).
- One state vocabulary on every provider and in both `status` and `plan`. TARGET is `new`, `same`, `changed`, `unknown`, `pending`, `held`, `extra`, `drift` or `n/a`: `absent`/`absent (new)` became `new`, `unchanged` became `same`, Fly's `present`/`potentially changed` became `unknown` (explained once under the table), `present (not desired)` became `extra`, `present (immutable, held)` became `held`, and the bare `-` for config became `n/a`. Sync's `kept` line reads `extra, not pruned`. The JSON `state` and `target` fields are unchanged (H5).
- Provider-neutral wording: the drift line no longer says "Key Vault" (it is wrong on Kubernetes); an environment without a target suggests adding a `fly`, `azure` or `kubernetes` section; `explain` shows `target: none (run-only)` for it and keeps every value in one column (P4).
- `opv doctor` no longer warns for a later `flyctl` patch release in the tested minor (0.4.113 and up). Another minor, or a patch older than 0.4.112, still warns.
- Every external call names its scope explicitly (Azure `subscription`, Fly `--app`, Kubernetes `--context` and `--namespace`) and runs with a pinned environment, so your default subscription or CLI settings no longer matter.

### Fixed

- Secret safety (SR-1, SR-4): a configuration error never prints the file's text, so a `.env` given as `--config`, `OPV_CONFIG`, `config import --file` or `config check --file` no longer shows its values (also in `--json`); the stderr scrubber masks values holding CR, BEL or ESC and each line of a multi-line value; every `op item get` registers its values without `--verbose`; the `az said:` excerpt of a failed deploy sign-in stays out of `doctor --json`; the private Azure directory is removed on SIGHUP and SIGQUIT and on Windows console events, and stale ones are swept at the start of every Azure run; the Windows value pipe accepts only the `az` process opv started (or a process it started) and fails the call when another process connects; a config key stored concealed is shown as `<concealed in 1Password>` by `config export` and warned about by `status`.

- 1Password data safety (FR-43, FR-44): every read a 1Password write is built from or checked against (the tidy, `item skeleton`, `setup`, and every manifest write: `add`, `init --add-env`, `config edit`, `config import`) passes `--cache=false`, so a write never puts op's cached copy over a newer edit. After each edit the item must be exactly one version past that read and hold what opv wrote; otherwise the tidy reports `tidy_conflict` (or `tidy_unverified` when a field opv wrote or kept is missing) and a manifest write fails with `config_changed`, never retried. A manifest whose path tags do not cover the current directory is not used; a manifest's `account` reaches its environments (`status --all` too); manifest writes need a signed-in person (`Next: opv login`). The fleet and simple readers no longer move each other's fields back and forth.
- `opv setup` re-reads the item (`--cache=false`) right before it saves: if someone changed it while setup was open, nothing is overwritten; setup re-plans on the fresh item, keeps the values already entered (they fill only fields still empty; a field filled elsewhere keeps its value and is named), says so and asks once more. A second change before the save, an edit landing with setup's, or a value missing after the save is the new code `item_changed` (exit 4), with nothing overwritten silently.
- `sync --expect-plan <id>` re-run after an exit 9 (a deploy that timed out or lost its connection) matches the same plan: values that run staged or stamped with this plan id count as the plan's own progress, not a change (FR-41).
- A config key stored in a concealed field is accepted and delivered as a plain value (FR-14): `config export` shows `<concealed in 1Password>` instead of its value, `status` warns once per key, and no command reports it as a finding.
- `opv schema` lists `init`'s provider flags and every error code; the codes table in [usage](docs/usage.md#json-contract) is generated from the code. `explain --json` names its fields like a status row: `target_name`, plus the provider's lines as `target_details` (was `target`). `status --all` gives an environment it could not read a runnable `Next:` (and `next` in `--json`) instead of the error's prose. Refusals from `add`, `init --add-env` and `open` end with a `Next:` that runs as typed (`opv add --help`, `opv config edit`, the full `init --add-env` command), and a suggested `opv open` keeps the run's `--print` or `--json`.
- A failed write is read back before opv reports a result, so a dropped connection no longer looks like "nothing happened". <!-- verify -->

## [0.4.0] - 2026-10-08

Local development without a deployment target. Two deprecated forms are removed, so check the
**Removed** section before upgrading.

### Added

- `opv check <env> [--product <p>] [--json]`: validates an environment's keys for local work by name only, with one 1Password read and no deployment target call; exits 8 when a key is missing, of the wrong kind or failing a rule. With `--product`, other products' sections are skipped. `--json` carries `schema_version`, `environment`, `target_checked: false`, `rows` and `findings` ([#55](https://github.com/matt-cochran/1password-vault/pull/55), [#56](https://github.com/matt-cochran/1password-vault/pull/56); #52).
- `opv doctor --env <env> [--product <p>]`: checks only what that scope needs; a local-only environment needs no deployment CLI ([#55](https://github.com/matt-cochran/1password-vault/pull/55); #52).
- `opv init` without `--fly-app` writes a run-only environment ([#55](https://github.com/matt-cochran/1password-vault/pull/55); #52).
- `doctor` reports `op local run` on Linux and macOS: a Windows `op.exe` first on PATH (WSL) fails a local-only scope and warns otherwise, and every other check and the `Next step` line still print ([#55](https://github.com/matt-cochran/1password-vault/pull/55), [#56](https://github.com/matt-cochran/1password-vault/pull/56); #54).
- [Local development guide](docs/local-development.md): local-only setup, adding a `dev` environment to an existing file, switching products, WSL, supported versions ([#55](https://github.com/matt-cochran/1password-vault/pull/55), [#56](https://github.com/matt-cochran/1password-vault/pull/56)).

### Changed

- `opv run` removes every key name declared in the configuration from the inherited environment before adding the selected product's references, so another product's or a mode-skipped key no longer leaks into the child. PATH, tool context, the 1Password sign-in and undeclared variables are still inherited; this is not a sandbox ([#55](https://github.com/matt-cochran/1password-vault/pull/55); #53).
- `opv run` refuses a Windows `op.exe` under WSL before starting anything (exit 3) ([#55](https://github.com/matt-cochran/1password-vault/pull/55); #54).
- Output that named the removed command now says `sync`: the `status` summary (`staged by the next sync`) and the refusal (`sync refused, nothing staged`). Scripts matching the old text need updating ([#56](https://github.com/matt-cochran/1password-vault/pull/56)).
- Keys named `PATH`, `HOME`, `XDG_CONFIG_HOME` or `OP_*` are a configuration error, because `run` would remove the 1Password CLI's own environment ([#56](https://github.com/matt-cochran/1password-vault/pull/56)).
- Library API: `InitArgs::fly_app` is now `Option<String>`; the `CommandRunner` trait gains `run_inherited_clean` (its default fails closed when there are names to remove) and `local_run_supported`; new `app::local::{check, select}`, `app::doctor::run_scoped` and `adapters::onepassword::read_item_in_sections` ([#55](https://github.com/matt-cochran/1password-vault/pull/55), [#56](https://github.com/matt-cochran/1password-vault/pull/56)).

### Removed

- `opv fly plan` and `opv fly sync`, deprecated in 0.3.0. Use `opv plan` and `opv sync`; the old forms are now a usage error (exit 2) ([#56](https://github.com/matt-cochran/1password-vault/pull/56)).
- `transform = "signoz_ingestion_header"`, deprecated in 0.2.0. A configuration that still uses it fails to load and names the key; use `ensure_prefix = "signoz-ingestion-key="` with `pattern = "[A-Za-z0-9._~+/-]+={0,2}"` ([#56](https://github.com/matt-cochran/1password-vault/pull/56)).

- Library API: `config::deprecation_warnings` and `domain::rules::SIGNOZ_INGESTION_HEADER` ([#56](https://github.com/matt-cochran/1password-vault/pull/56)).

### Fixed

- `opv init` with an invalid `--fly-app` quotes the app name instead of printing `Some(...)` ([#56](https://github.com/matt-cochran/1password-vault/pull/56)).

## [0.3.0] - 2026-10-08

### Added

- `opv plan` and `opv sync`, which work for any target ([#44](https://github.com/matt-cochran/1password-vault/pull/44)).

### Changed

- npm package is published as `@matthew-cochran/opv` using npm trusted publishing ([#32](https://github.com/matt-cochran/1password-vault/pull/32)).
- Documentation reorganised: a shorter README, user guides in `docs/`, design documents in `docs/design/`; added CHANGELOG, CONTRIBUTING, a code of conduct and issue templates.
- `docs/agent-setup.md` and `llms.txt`: setup guide and docs index for AI assistants.
- Internal `SecretStore` and `Runtime` target ports, the base for the planned Azure, AWS and GCP targets; Fly.io behaviour is unchanged ([#44](https://github.com/matt-cochran/1password-vault/pull/44)).

### Deprecated

- `opv fly plan` and `opv fly sync`; use `opv plan` and `opv sync` instead. They print a warning and are removed in 0.4.0 ([#44](https://github.com/matt-cochran/1password-vault/pull/44)).

## [0.2.1] - 2026-10-07

### Added

- First npm release ([#29](https://github.com/matt-cochran/1password-vault/pull/29)).

## [0.2.0] - 2026-10-07

### Added

- `opv init` writes a starter `secrets.toml` from an existing 1Password item ([#25](https://github.com/matt-cochran/1password-vault/pull/25)).
- Simple profile for one app per environment ([#23](https://github.com/matt-cochran/1password-vault/pull/23)).
- `--json` output on `opv status` and `opv fly plan` ([#21](https://github.com/matt-cochran/1password-vault/pull/21)).
- `opv explain`, a Next step in `opv doctor`, and value-free failure reasons ([#24](https://github.com/matt-cochran/1password-vault/pull/24)).
- `secrets.toml` discovery in parent directories ([#20](https://github.com/matt-cochran/1password-vault/pull/20)).
- `ensure_prefix` and `pattern` rules ([#19](https://github.com/matt-cochran/1password-vault/pull/19)).
- `install.sh` installs and updates `opv` from GitHub releases ([#22](https://github.com/matt-cochran/1password-vault/pull/22)).

### Deprecated

- `transform = "signoz_ingestion_header"`; use `ensure_prefix` and `pattern` instead ([#19](https://github.com/matt-cochran/1password-vault/pull/19)).

## [0.1.2] - 2026-10-07

### Added

- Guided errors diagnose failures and print the exact next command ([#14](https://github.com/matt-cochran/1password-vault/pull/14)).

### Changed

- npm publishing gated until v0.2.0 ([#13](https://github.com/matt-cochran/1password-vault/pull/13)).

## [0.1.1] - 2026-10-07

### Added

- `pem_private_key` transform: a multi-line PEM in a concealed field becomes one line ([#8](https://github.com/matt-cochran/1password-vault/pull/8)).
- npm packaging ([#9](https://github.com/matt-cochran/1password-vault/pull/9)).

## [0.1.0] - 2026-10-07

### Added

- Initial release: `opv doctor`, `opv run`, `opv fly plan`, `opv fly sync` and `opv status`, config export, 1Password item skeleton, fleet profile and rules ([#1](https://github.com/matt-cochran/1password-vault/pull/1)).
- `secretctl` renamed to `opv` ([#4](https://github.com/matt-cochran/1password-vault/pull/4)).
- Gitflow guard, CI on `dev`/`staging`/`main`, and Dependabot targeting `dev` ([#5](https://github.com/matt-cochran/1password-vault/pull/5)).

[Unreleased]: https://github.com/matt-cochran/1password-vault/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/matt-cochran/1password-vault/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/matt-cochran/1password-vault/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/matt-cochran/1password-vault/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/matt-cochran/1password-vault/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/matt-cochran/1password-vault/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/matt-cochran/1password-vault/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/matt-cochran/1password-vault/releases/tag/v0.1.0
