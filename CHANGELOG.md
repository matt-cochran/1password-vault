# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `opv access` reports `pending_revoke` when several service accounts with one name read a vault (after `opv access --create` replaced an identity): keep the newest until `opv delivery verify` shows its delivery, then remove the older ones. `no_ci_reader` now steps to `opv access <env> --create --github <owner/repo>`.
- The agent skill is registered automatically when opv is installed or upgraded: `install.sh` installs the user-level skill by default (`--no-skill`, `CI` or `OPV_NO_SKILL=1` opt out; `--skill` is still accepted), the npm postinstall runs `opv skill install --user --target all`, and any upgrade refreshes existing unedited user copies on the next opv run. `opv skill status` names `opv skill install --user` when a copy is older, and `opv doctor` still warns.
- `opv run --role <ROLE>`: a key may declare `roles = ["serve", "migrate"]` (lower-case names, validated at load; an empty list is refused). A key without `roles` reaches every role; a key with them only when `--role` names one. A product with role-scoped keys requires `--role`, and an undeclared role is refused (exit 2), both before anything is read from 1Password. Roles apply to local `opv run` only, never to `sync` or a target (#136).
- `opv run --preview [--json]`: a metadata-only delivery preview. It lists each key the run would deliver with its source, destination (`env:<NAME>` or `file:<relative path>`) and roles, the keys a role withholds, the environment mode, the secrets-directory variable, RAM-backed file-delivery support and the `op`/signed-in prerequisites (`unknown` when undeterminable). It reads no value and runs no command (#136).
- The MCP tool `opv_delivery_preview` returns the same preview document as `opv run --preview --json`, built field by field from identifiers, read-only (#136).

- `opv target credentials <env> --target <name> --create`: mint a target's least-privilege deploy credential at its provider and store it straight in a new 1Password item in the target's state vault, then record `deploy_credentials`. The token is never shown, copied or pasted (stdin only, held in a zeroizing buffer); one confirmation names the credential and its 90-day validity, and it refuses a target that already records `deploy_credentials` before any provider call (0.9.0).
- CLI parity with the MCP server (j8): `opv env add <env>` declares an environment (the `opv_declare_environment` work and refusals), `opv structure plan [--json]` prints the `opv_structure_plan` document and its `plan_id`, `opv structure apply <plan_id> [--json]` applies an approved plan through the same single-use `opv approve` and returns the `opv_structure_apply` document, and `opv config describe [--json]` prints the `opv_configuration` metadata; docs/mcp.md lists each tool's command and `opv schema` exposes them under `mcp_tools`.
- `opv access <env> [--target <name>] --create --github <owner/repo> [--github-env <env>]`: create a CI or deploy identity with exactly its grants and store its token as a GitHub secret on stdin, never shown; one confirmation, GitHub checked first. The MCP tool `opv_access` gives assistants each identity, its state and this command (0.9.0).
- `opv generate <env> <product/KEY>…`: self-made secrets (keys with `base64_bytes` or `hex_bytes`) generated with the OS CSPRNG straight into their empty 1Password field, read back and verified; never shown, never over a value, provider-issued keys refused (0.9.0).
- The MCP tool `opv_generate` exposes `opv generate <env> <product/KEY>…` to assistants: it writes the generated values only into empty fields, never replaces a value, never returns a value, and refuses when an op session, service-account or Connect credential is in the server's environment (0.9.0).
- `opv vault locate <vault ID>`: which of the 1Password accounts this CLI knows holds a vault (found, not found, or unknown when not signed in); never claims "absent" for an account it could not ask (#153).
- `opv login --account <ID> --no-record`: sign in to an account for this login only, leaving the project's `.opv` unchanged (#153).
- `opv plan --rotate <product/KEY>` (repeatable) plans the replacement of an immutable key already on the target: its rows show `would_stage` and the ON TARGET word `rotate` (`"rotate": true` in JSON), and the sorted rotate set is part of the plan id, so a plan with a rotation never shares an id with one without. `opv sync --rotate <k> --expect-plan <id>` now applies such a plan (only `--prune-immutable` stays refused with `--expect-plan`), a person can approve a rotating sync with `opv approve <id> --sync <env> --rotate <k>` (the rotate set is part of the approval scope), and the MCP tool `opv_sync` takes an optional `rotate`.
- `opv setup` takes secrets in a masked prompt: a fixed `********` once anything is typed or pasted, never the length.

### Fixed

- `opv access` reported a vault outside the selected account as "not visible" and printed an `Owner runs:` command that could not succeed. It now reports `not in this account` with a `vault_not_in_account` finding (next: `opv vault locate`) and prints no such command (#153).
- One account order everywhere: `OP_ACCOUNT` (set by `opv login --account` for its command), then `.opv`, then the only account. `opv login --account B -- opv check` ran against `.opv`'s account before. A non-ID account value is resolved to one account ID (ambiguous values are refused), no account is passed beside a service-account or Connect credential, and the automatic sign-in signs in to the account of the call that failed.
- A bare `OP_SESSION` variable is reported (`stale_session_variable`) and refused by the MCP structural apply, like `OP_SESSION_<name>`.

### Changed

- `opv run` on an environment with `confirm_env = true` (production, typically) needs `--confirm <env>`, as `opv sync` does, before its values reach a local process; nothing is read without it. `--preview` needs none.

## [0.8.1] - 2026-10-15

### Added

- `opv mcp serve --project <dir>`: opv's MCP server ships in every released `opv` (npm, `install.sh`, the GitHub release), so assistants need no separate build. `opv mcp install [--client claude|codex|all]` registers it for a project in Claude Code's `.mcp.json` and Codex's `config.toml`, merging into existing configuration (other servers kept, a different `opv` entry refused unless `--force`, no value or credential written; npm installs register the shared `~/.local/bin/opv`).

### Changed

- The separate `opv-mcp` binary is removed (FR-60, one way only): run `opv mcp serve` instead; `opv mcp install` rewrites an assistant's entry with `--force`.

### Fixed

- A write to 1Password with nobody signed in (`opv target add` right after its `--dry-run` signed in, #150) was a "policy denied" refusal with a bare `Next: opv login`. It is now `op_not_signed_in`: in a person's terminal opv signs them in at op's prompt and runs the command again (still only for a person), the message says that an earlier command's sign-in has ended, and `Next:` names the project's account.
- `opv doctor`'s tests no longer depend on the agent skill installed on the machine running them.

## [0.8.0] - 2026-10-15

### Dependencies

- `sha2` 0.11 (digests are hex-encoded explicitly; output unchanged), `signal-hook` 0.4, `serde_json` 1.0.154. Release workflow: `actions/upload-artifact` 7.0.2, `actions/download-artifact` 8.0.2 (a download whose hash does not match now fails the release), `actions/setup-node` 7.1.0, `taiki-e/install-action` 2.87.27.

### Changed

- CI guidance separates the read-only validation reader (`opv bootstrap --ci-reader`) from each target's deploy identity (`opv access <env> --target <name>`: boundary read, its own state vault read and write), which a syncing job needs to record delivery evidence. `bootstrap --ci-reader` says so, and `opv ready` marks each target `evidence_write: "not_verified"` instead of implying that a visible state vault can be written (#134).

### Fixed

- An approval is claimed by an exclusive create (`O_EXCL`, `CREATE_NEW` on Windows), which has exactly one winner on every platform; on Windows two concurrent claims could both be refused by a rename sharing violation. The record is spent whatever the verdict, and a new approval of the same plan replaces a used one (#133).
- `opv login` on a machine with several accounts on one sign-in address (WSL, op 2.40) could fail after the password with "1Password did not start a session" (#142). `op signin` no longer inherits `OP_SESSION_*` variables from the shell. A refused sign-in now shows op's own message (scrubbed) on a `1Password said:` line. The status check before the prompt is one probe instead of three retries.
- New advisory findings in `opv account list`, `opv ready` and before `opv login`'s prompt: `shared_sign_in_address`, `session_for_other_account` and `stale_session_variable`, each naming accounts by shorthand, email and ID and variables by name only (#142).

- A structural apply that stops part-way keeps the IDs it already recorded; declarations work on a configuration that is not bootstrapped yet (#133).

- `opv projects` and `opv status --all` no longer report a successful empty inventory when 1Password accounts could not be listed (#135). Each account asked is reported in `accounts` by account ID (accounts sharing `my.1password.com` are told apart; never an email), `complete` says whether every account was listed, and an incomplete inventory keeps the projects it found but exits 4 with the new `inventory_incomplete` code, whose `next` signs in to that account.
- A listing that failed for one account is diagnosed for that account (`op whoami --account <id>`), never as another account's signed-in identity (#135).

### Added

- Assistant-managed structure through MCP, approved by a person (#133, FR-61). New tools `opv_declare_key`, `opv_declare_environment` and `opv_declare_target` (local `secrets.toml` only; never a value), `opv_structure_plan` (read-only; returns a `plan_id` bound to the project, account and configuration) and `opv_structure_apply` (creates exactly an approved plan through the 1Password app's authorization; refuses stale or unapproved plans and credential-bearing environments; returns public IDs and 1Password links for key entry). New command `opv approve <plan_id>`: the person reviews the plan in their own terminal and approves it once (15 minutes). New error codes `approval_required` and, from MCP, `credential_in_environment`.
- Local delivery for secret-store apps and Cloudflare Workers (#136, #137, FR-62). `[products.<p>.local]` with `environment = "declared_only"` gives the app only its declared keys and a fixed set of non-secret basics. `file = "<path>"` on a key, with `secrets_dir_env`, delivers that key as a 0400 file in a private RAM directory (Linux and WSL; refused, never written to disk, elsewhere), removed when the app exits. Under `local`, no `OP_*` credential reaches the app. Products without `local` are unchanged. Recipes in local development; guarantees and limits in `docs/design/local-delivery.md`.
- `opv_configuration` (MCP) also lists each declared target: its provider, the products it delivers, and whether its state vault and deploy identity are declared; never a locator, vault ID or credential reference (#133).
- `opv version [--json]`: opv's version and every CLI it runs (1Password, then each provider's), each `installed` with its version, `missing` or `unknown` with a reason, and whether this project's configuration uses it, from one bounded local version probe per CLI (no sign-in, no service call). `opv --version` is unchanged (#131).
- `opv projects --account <a>` lists one account; without it, `OP_ACCOUNT` (set by `opv login --account <a> -- <command>`) selects it (#135).

## [0.7.0] - 2026-10-14

Named deployment targets and one vault per access boundary, with **no backward compatibility**. opv is not yet declared live, so 0.7.0 keeps one way to do each thing (FR-60). Nothing is migrated: a configuration in a removed form fails at load, and the error shows the exact current form to write. See [docs/configuration.md](docs/configuration.md) ("Removed forms") and [docs/design/placements-and-access-boundaries.md](docs/design/placements-and-access-boundaries.md).

### Added

- **Named targets** ([#114](https://github.com/matt-cochran/1password-vault/issues/114)): an environment declares `[environments.<env>.targets.<name>]`, also when it has one. One product can run on a shared app and on a dedicated overflow app in the same environment, reading the same values. `plan`, `status` and `sync` cover every target under one plan id, and `--target` narrows them. Rows carry `TARGET`; the target-state column is `ON TARGET` (JSON `target_state`).
- **`opv target add` / `opv target list`**: add a target in one confirmed step. The provider comes from its options, and the command creates the target's state vault and its placements' delivery items, then ends with `Next: opv access`.
- **One vault per access boundary** ([#120](https://github.com/matt-cochran/1password-vault/issues/120)): each product's values live in their own vault (`<project>-<product>-<env>`), recorded as `boundaries.<name>`. `boundary = "<group>"` lets products share one vault as an explicit, opt-in trade. `from` reads a source in another boundary, and a key always has exactly one source.
- **Delivery evidence per placement**: each product on each target has its own evidence item in that target's state vault (`state_vault_id`, required). The evidence is also the version ledger. `opv delivery verify` reports every placement.
- **`opv access` per boundary and target**: who needs which vault, compared with each vault's readers. It prints one owner `op service-account create` command per principal and never reports "clean".
- **`opv explain`** names a key's source, boundary, delivering targets and readers. `opv explain --target` describes a target.
- **`opv ready`** lists every target, and reports `grants_missing` with its reason. `opv doctor --env` checks each target. `opv adopt --from target:<name>` and `opv history --target` work per target.
- **`--product` may be omitted** when exactly one product has keys desired in the environment (`check`, `run`, `config export`, `open`).
- **Self-explaining vaults and items**: every vault and item opv creates carries notes saying what it holds and what not to do by hand.
- **New error codes**: `boundary_missing`, `state_vault_missing`, `state_vault_wider_than_values` and `duplicate_scope`.

- Optional `opv-mcp` stdio server using rmcp: readiness, configuration metadata,
  and deployment previews. The server returns allowlisted metadata only and
  refuses writes below orchestration; humans enter secrets and approve changes
  outside MCP. Build from source with the `mcp` feature.
- Opt-in Claude Code SessionStart readiness adapter with bounded execution,
  fixed diagnostics, fake-only tests, and manual per-project configuration.
- Architecture/review map linking security, recovery, and release evidence.

### Removed

- **The simple profile and `[profile]`**: a single-app project is one product with a `{KEY}` target template.
- **Environment-level forms**: `vault_id`/`item_id`, provider tables, `deploy_credentials` and `state_vault_id`. Use `boundaries.<name>` and `targets.<name>`.
- **GitHub's provider-level `products`**: use the target's `products`.
- **Deprecated forms**: the `pattern` rule (use `regex`), the `fly_name` JSON field (use `target_name`) and `opv schema`'s `deprecated` list.
- **Retired ledger and flags**: the values item's `opv · state` ledger section, `opv bootstrap --state` (bootstrap records every missing ID), and `opv init --profile`.
- **`opv init --target`, `--target-name` and the provider options**: `opv init` writes products and boundaries, and `opv target add` is the one way to add a target. Passing a removed option fails with the exact `opv target add` command.
- **The `required_with_target` schema field**: it is now `required_for_provider`.

### Fixed

- **Skipped keys and delivery revisions:** a key skipped by a mode (or otherwise not delivered) no longer stays in a placement's binding set, so such a product now mints a delivery revision.
- Align front-page security claims with documented runtime, memory, local-state,
  and Azure credential-cache boundaries; scope agent guidance appropriately.
- Isolate independent Fly parser corpus cases and fake-host unit tests from
  accumulated redaction values and the developer's installed tools respectively.

## [0.6.1] - 2026-10-14

A safety fix for assistants working in a person's signed-in session: `opv doctor` and `opv ready` now never write 1Password, and the layout repair is an explicit command. No configuration change is required to upgrade.

### Fixed

- **`opv doctor` and `opv ready` never write 1Password** ([#113](https://github.com/matt-cochran/1password-vault/issues/113)): the schema says `doctor` only reads, yet run in a person's signed-in session its item check and `--settings` check could tidy the item's layout (one `op item edit`, bumping its version), and so could the `ready` receipt. Both now read the item as it is, whoever runs them, so an agent holding a person's session can rely on them as the readiness check; when the layout needs a tidy, `doctor` names the explicit repair.

### Added

- **`opv tidy <env> [--json]`** ([#113](https://github.com/matt-cochran/1password-vault/issues/113)): the explicit layout repair, the same guarded, verified, non-destructive tidy a person's reads run (nothing deleted; displaced fields kept in `opv · kept`). It refuses unless a person signed in with their own session runs it; `opv schema` lists it as `writes_1password`, asked first.
- **`tidies_1password` in `opv schema`**: per command, whether a person's run may tidy the item's layout. `doctor` and `ready` are `false`.

## [0.6.0] - 2026-10-13

A terminal UI (`opv ui`) over everything opv knows, a one-step start from an existing `.env`, per-developer personal keys, GitHub Actions as a target, settings health checks, verifiable delivery receipts per product, and a readiness receipt that people and agents share. No configuration change is required to upgrade.

### Added

#### The terminal UI

- **`opv ui`** ([#82](https://github.com/matt-cochran/1password-vault/issues/82)): a terminal UI to browse and manage every environment (from the configuration, by title and order), product, key, shared value and account, with secrets never shown; actions run the same `opv` commands in your terminal, a sync only exactly the plan you reviewed, a guarded environment only after you type its name. Falls back to `opv ready` text without an interactive terminal.
- **`opv ui` adoption review** ([#94](https://github.com/matt-cochran/1password-vault/issues/94)): `i` reads `opv adopt --json` and lets you decide per key (import or skip; keep, replace or skip), then runs exactly the `opv adopt … --apply` it shows. `opv adopt --skip <product/KEY>` leaves a key out.
- **`opv ui` configuration editing** ([#97](https://github.com/matt-cochran/1password-vault/issues/97)): `+` declares a key and `E` adds an environment through forms that run the exact `opv add` / `opv init --add-env` they show; `e` opens `opv config edit`. `opv add` takes `--from PRODUCT/KEY`, `--personal` and `--allow-same-value`.
- **`opv history <env>`** ([#95](https://github.com/matt-cochran/1password-vault/issues/95)): what opv last wrote to an environment's target, per key (time, plan id and opv version from Key Vault and Kubernetes stamps; versions from the Fly/GitHub ledger), and what changed outside opv since. Read-only, values never shown; `--json`; `h` in `opv ui`.
- **`opv access`** ([#96](https://github.com/matt-cochran/1password-vault/issues/96)): who can read each environment's vault (people counted, never named; service accounts named, read-only or not), with the owner's exact command for a least-privilege CI reader where a deployed environment has none, and a warning for a service account that can write. "CI access" in `opv ui`.

#### Getting started and handing off

- **`opv init <env> --from .env`** ([#90](https://github.com/matt-cochran/1password-vault/issues/90)): start a project from an existing `.env` in one step. It declares every key (kind by name, secret when unsure; `--config-key` / `--secret-key` to change one) and shows the plan; `--apply` creates the vault and item, writes the configuration and imports the values, read back and verified. No value is ever printed, and no hand-written import script is needed.
- **`opv bootstrap`** ([#77](https://github.com/matt-cochran/1password-vault/issues/77); FR-52): creates every environment's vault, item and empty fields in the selected account and records their IDs (comments kept); stops on IDs from another account (`ids_not_in_account`, `--rebind <env>`), never rewrites a generated file, never syncs; `--ci-reader <env>` prints the owner's commands for a read-only CI service account. Walk-through: [examples/fleet-fly](examples/fleet-fly/).
- **`opv ready [<env>] [--json] [--save <file>]`** ([#81](https://github.com/matt-cochran/1password-vault/issues/81); FR-51): one read-only receipt of every environment × product, the findings with stable codes, who acts (owner, agent, CI), what each step changes, one prerequisite and one verify command, and the next step; `receipt_id` binds it to what it saw.
- **`opv account list [--json]` and `opv account use`** ([#80](https://github.com/matt-cochran/1password-vault/issues/80); FR-49): the 1Password accounts this CLI knows, which one the project uses and why, whether each is signed in, and findings with stable codes and one next step each, without a prompt, a sign-in or any write; `use` records the project's account in `.opv` deterministically. "No accounts" is now told apart from "op failed".
- **Account choice you can see** ([#79](https://github.com/matt-cochran/1password-vault/issues/79); FR-50): `opv login` shows the account menu even with one account added to the CLI, marks signed-in accounts, always offers **Add another 1Password account**, and explains on WSL that the Windows app's accounts are not visible; `opv login --add [--account <email>]` adds one directly.
- **An installable agent skill** ([#76](https://github.com/matt-cochran/1password-vault/issues/76)): `opv skill install` writes a skill versioned with the binary to `.claude/skills/opv/` and `.agents/skills/opv/` (project or `--user`), keeping a copy you edited unless `--force`; `opv skill status` lists copies and `opv doctor` warns about an older one; `install.sh --skill` installs the CLI and the skill in one step. The agent guide now starts every session from `opv ready --json` and covers accounts, bootstrap and adoption; a test fails when a command has no agent guidance.
- A tool installed outside `PATH` is named with its location and the `PATH` fix, instead of an install suggestion (#77).

#### Delivery evidence

- **Delivery receipts** ([#106](https://github.com/matt-cochran/1password-vault/issues/106)): with a state vault (`state_vault_id`, `opv bootstrap --state <env>`), each confirmed sync records per product an opaque revision with private evidence. `opv delivery verify` (read-only) answers whether the target still holds exactly that binding set, naming rotation, shared-value changes, drift outside opv, missing names and staged-vs-deployed. `opv sync --receipt FILE` keeps the receipt. No value or value-derived digest is ever emitted.

#### Configuration and values

- **Personal keys** ([#86](https://github.com/matt-cochran/1password-vault/issues/86); FR-55): `personal = true` keeps each developer's own value (an LLM key billed to them) in their own item in their own vault, per product, with shared personal values through a source-only product; `run`, `check` and `ready` read it, `bootstrap` creates it, and it is never deployed or mixed with team values. Environments take `title`, `order` and `audience` (people outside an environment's audience see it as not theirs instead of an access error). Example: [examples/team-personal](examples/team-personal/).
- **Settings health** ([#92](https://github.com/matt-cochran/1password-vault/issues/92)): `opv ready`, `opv ui` and `opv doctor --settings` warn about likely-wrong values: the same secret in two environments, one value under two keys, placeholders, stray whitespace, `localhost` in a deployed environment, and test/live keys in the wrong kind of environment. Values are compared in memory and never shown; `allow_same_value = true` on a key marks an intended repeat.
- **`opv adopt <env> --from <file.env>|target [--replace <p/KEY>]... [--apply]`** ([#78](https://github.com/matt-cochran/1password-vault/issues/78); FR-53): plans, and with `--apply` writes in one verified edit, values that already exist elsewhere into the environment's item. Names map to declared keys (target name, then bare name), shared values land in their source's field once, rules normalise both sides (format-only differences are not changes), filled fields are kept unless `--replace` names them (old values kept in `opv · kept`), and nothing is ever printed, synced or deleted. Fly and GitHub secrets cannot be read back and say so.
- **One home for shared values**: `[products.<name>] source_only = true` declares a product whose keys hold values other keys point at with `from` (one Fly token for every repository's CI). Its keys are never delivered, pruned or checked for name collisions; `plan` and `status` warn about one nothing points at ([configuration](docs/configuration.md#one-home-for-shared-values-source_only-products); FR-47).

#### Targets and sync

- **GitHub Actions target**: `[environments.<env>.github]` with `repo` (or `repos`), an optional GitHub `environment`, `products` and `secret_name` sets Actions secrets (concealed fields) and Actions variables (text fields) with `gh`, values on stdin. Writes are live at once (`--deploy` has nothing to do); variables are compared exactly, secrets are written each sync because GitHub cannot show them; `--prune` deletes only managed names. A missing GitHub environment stops the sync before any write with the `gh api` command that creates it; opv never creates one. `deploy_credentials` takes a fine-grained `GH_TOKEN` ([#75](https://github.com/matt-cochran/1password-vault/issues/75); [configuration](docs/configuration.md#github-actions-repository-and-environment-secrets); FR-46).
- **Target product scope**: a target can deliver only some products' keys (`products = [...]` on `github`); `plan` and `status` list the declared keys it leaves out (FR-48).
- **Exact `plan` on Fly and GitHub** ([#36](https://github.com/matt-cochran/1password-vault/issues/36); FR-54): a sync you run records, in the item's `opv · state` section, each written name's target version and a keyed fingerprint of its value (never the value). `plan` then shows `same` or `changed` exactly instead of `unknown`, reports names changed outside opv (drift), and GitHub secrets that did not change are no longer rewritten each sync.
- [examples/github-ci](examples/github-ci/): a fleet with two repositories, shared values and a sync workflow.

### Changed

- **Sign-in failures in opv's words** (#79, FR-50): 1Password's prompts still show as they come, but its error lines are classified (`account_not_registered`, `op_not_signed_in`, `desktop_app_unavailable`, `credential_rejected`, `sign_in_cancelled`, `provider_unavailable`, `op_unexpected`), each naming the account and one next step; op's own directions (`op signin --help`) are no longer shown, and the message names the command that was running. A session that ends mid-command and cannot be renewed now reports why.
- **`pattern` merges into `regex`** ([#37](https://github.com/matt-cochran/1password-vault/issues/37); FR-24): `regex` now checks the value as it will be staged (after `ensure_prefix`), so the two combine. `pattern` keeps working as a deprecated alias; loading a file that uses it prints the equivalent `regex = '…'` line to paste.
- `opv init --help` shows two examples instead of three, to fit on one screen with the GitHub options.

### Fixed

- npm: the 0.5.0 package shipped without its install script, so `npm i -g` never put `opv` in `~/.local/bin`; the build and the manual publish now refuse a main package without it.
- `opv ui` in a real terminal: under `NO_COLOR` the selected row lost its highlight (each colour change reset it); Ctrl-C quits instead of acting as `c`, and Ctrl/Alt chords no longer act as their letter (Ctrl-S was `s`, sync); Ctrl-C while an action's command runs stops that command, not the UI; SIGTERM or SIGHUP puts the terminal back (it was left in raw mode on the alternate screen); the screen shows what it is reading instead of going blank or stale while opv reads 1Password; the key bar wraps so `q quit` is visible; shown commands quote a word with spaces, the key screen names the exact `opv open … --env` that `o` runs, a blocked sync names no command, and an empty or failed account list says so.
- An interrupted `--json` command (Ctrl-C, SIGTERM) hung instead of exiting 130/143: the handler printed its document through stdout's lock, which the command holds.
- `status`/`plan --json`: a key the target does not deliver (source-only, or outside `products`) reported `"target": "present"`; it is now `"not_delivered"`.

### Security

- Settings health compares values in place (no unzeroized copy), and the version ledger's key is zeroized; `opv history` never shows a Fly version, which is a digest of the value. Health findings state one fact about a value (equality, a placeholder, whitespace, localhost, a test/live prefix) and never the value: documented as the one exception to SR-1.

## [0.5.0] - 2026-10-12

Azure and Kubernetes targets, configuration kept in 1Password, self-healing 1Password layout, a machine-readable contract for scripts and AI assistants, and a CLI that survives failing networks. Several outputs and exit codes changed: read **Changed** before upgrading scripts or CI.

### Added

- **An ended 1Password session no longer stops a command.** At an interactive terminal, a command that finds the session gone (op sessions expire after 30 minutes idle) signs you in at op's own prompt and runs once more; scripts, `--json`, CI and service accounts still get the error (FR-40).
- **Azure Key Vault + Container Apps target**: `[environments.<env>.azure]` writes each secret as a new Key Vault version and binds the Container App to that exact version; the app changes only with `sync --deploy`, which waits for a healthy revision, and `--prune` deletes Key Vault entries only after it ([#39](https://github.com/matt-cochran/1password-vault/issues/39); FR-28 to FR-33). See [usage](docs/usage.md#sync-on-azure-and-kubernetes).
- **Kubernetes target**: `[environments.<env>.kubernetes]` stores each value as an immutable Secret and repins a Deployment through `kubectl`, keeping the Secrets older ReplicaSets use so `kubectl rollout undo` works (FR-38).
- **Named stores**: `[stores.<name>]` declares a store once and `secrets_in = "<name>"` on a runtime keeps its secrets there. First pair: Azure Key Vault → Kubernetes Deployment through the External Secrets Operator, one ExternalSecret per pinned Key Vault version, checked before any write and pruned only after a healthy rollout ([configuration](docs/configuration.md#secrets-in-a-named-store-storesname-and-secrets_in); FR-39).
- **Plug-in providers**: Fly, Azure and Kubernetes implement one contract, so a new provider is one module ([CONTRIBUTING.md](CONTRIBUTING.md#adding-a-provider); FR-37).
- **Configuration in 1Password** (FR-44): the same TOML can live in a project manifest (Secure Note `opv · <project>`, tagged `opv-manifest` and with the git remote), so a checkout needs no file. Discovery: `--config`/`OPV_CONFIG`, `OPV_PROJECT`, `secrets.toml` here or above (still wins), a `.opv` file, then the git remote; monorepos match by path tag, longest prefix first. New commands: `opv config import`, `opv config export [--toml|--json]`, `opv config edit` (diff, confirm, refuses a concurrent change), `opv config check --file` (exit 8 with a diff), `opv projects [--long] [--json]`, `opv status --all [--json]`. `opv init <env>` alone is enough: the vault defaults to `<project>-<env>` and the item to `<project> · <env> values`. In a new project it saves a manifest unless `--file` ([configuration](docs/configuration.md#configuration-in-1password)) The manifest's notes open with an "opv managed configuration" heading and a short explanation, and hold the TOML in one `toml` code block; opv reads only that block and keeps whatever a person writes around it.
- **Self-healing 1Password layout** (FR-43): every command finds each declared key wherever its field is (label spelled differently, wrong section, top level, other field type, given twice). Run by a signed-in person, opv also tidies the item in one verified edit: missing sections and empty fields, secrets saved as text concealed, labels renamed, fields moved, duplicates set aside, a trailing newline or missing `ensure_prefix` fixed where the rules make it unambiguous. A simple-profile field opv writes goes in the item's unnamed default section, where the 1Password app shows it; a field outside every section (readable by `op`, hidden in the app) is moved there. Nothing is deleted (displaced copies go to section `opv · kept`); one `tidied 1Password (<env>): ...` line and a `tidy` array in `--json` say what changed ([store layout](docs/configuration.md#store-layout)).
- **Shared keys**: `from = "<product>/<KEY>"` reads another key's field in the same item, so a value two products use has one copy and one place to rotate; each key keeps its own target name ([configuration](docs/configuration.md#shared-keys-from); FR-45).
- **Sign-in and deploy credentials** (FR-40): `opv login [<env>] [-- <command>]` signs in to the account an environment uses at 1Password's own prompts and opens a signed-in terminal or runs one command (no token printed, nothing to `eval`; sessions for several accounts coexist). `opv setup` is resumable, guided onboarding from an `opv.setup.toml` recipe ([guided setup](docs/guided-setup.md); [#63](https://github.com/matt-cochran/1password-vault/pull/63)). Per environment, `account = "..."` pins the 1Password account and `deploy_credentials = "op://<vault>/<item>"` signs the target CLI in for one run with a least-privilege deploy identity (Fly `FLY_API_TOKEN`; Azure service principal in a private per-run directory; not on macOS) ([configuration](docs/configuration.md#account-and-deploy-credentials)).
- **Plan ids**: `plan` prints `plan <id> (1Password item v<n>)` and ends with `opv sync <env> --deploy --expect-plan <id>`, which applies exactly that plan or refuses before any write (exit 6) with the new id. The id covers names, states, version ids and the item version, never a value; nothing is stored ([usage](docs/usage.md#review-then-apply-exactly-that-plan---expect-plan); FR-41).
- **Provenance**: Key Vault versions, Kubernetes Secrets, ExternalSecrets and Deployments opv writes carry `opv-version`, `opv-written`, `opv-env` and `opv-plan`; `status` prints `<provider>: last changed by opv <version> at <time> (plan <id>)` and `status --json` carries `provenance`. Not on Fly (FR-42).
- **Guarded environments**: `confirm_env = true` makes `sync` refuse (exit 6, before the first write, after naming any blocking keys) without `--confirm <env>`; a reviewed `--expect-plan` id also satisfies it (NR-20).
- **Writing the configuration with commands**: `opv add <[product/]KEY> --kind secret|config [--env ...] [--rule ...] [--guidance ...] [--immutable]` declares a key or adds environments to one; `opv init <env> --add-env` adds an environment; `opv init --target fly|azure|kubernetes` with `--<provider>-<field>` options writes any target section. Comments and order are kept, the result is validated like a hand-written file and written atomically ([configuration](docs/configuration.md#declare-a-key-opv-add)).
- **For scripts and AI assistants**: `opv schema` describes the installed binary as JSON (commands, flags, effects, which commands to ask about first, exit codes, error codes, states, documents); `opv guide agent` prints the agent guide for this version; `--json` on `doctor`, `explain`, `open`, `init`, `add`, `item skeleton`, `projects`, `sync` and `status` without an environment.
- **Finding and fixing keys**: every missing or failing row carries an `open:` link to its item in 1Password (IDs only), and `opv open <[product/]KEY> [--env] [--print] [--json]` opens it. `opv explain KEY` resolves the product when only one declares it and suggests close names. `opv help states` defines every state word.
- **Overviews**: `opv status` without an environment prints one line per environment, run-only ones included; `--product` on `status` and `plan` (default `OPV_PRODUCT`) and on `sync` (never from `OPV_PRODUCT`) limits rows, findings and writes to one product.
- **Resilience** (NR-1 to NR-31): reads retried up to 3 times, writes never repeated but read back; one run budget `--timeout`; progress lines at least every 15 s; `--verbose` (one line per external call); a failed external call's last stderr lines shown scrubbed as `  <program> said: ...`; Ctrl-C and SIGTERM leave the target safe to re-run. Before its first write `sync` checks the target read-only (a dead Fly app, a Fly deploy in progress, which it waits for, Azure subscription, vault and app state, Kubernetes rights, External Secrets readiness). See [how opv handles failures](docs/how-opv-handles-failures.md).
- **CI job summary**: with `$GITHUB_STEP_SUMMARY` set, `status`, `plan` and `sync` append a Markdown summary (names and state words only).
- `opv completions <bash|zsh|fish|powershell>`, `--color auto|always|never` (honours `NO_COLOR`), `OPV_CONFIG` and `OPV_PRODUCT` defaults, and `Global options:` plus examples in every command's help.
- `opv doctor` lists every `opv` on `PATH` and warns about more than one; it checks `az` (2.60 or newer) and `kubectl` for environments that use them; `doctor --env` reads the item once and fails when `check` would; `doctor --json`.
- npm and `install.sh` install to the same place (`~/.local/bin/opv`, `%LOCALAPPDATA%\Programs\opv\opv.exe` on Windows), so either updates the other's copy ([install](docs/install.md#one-install-location)).
- Docs: [how opv handles failures](docs/how-opv-handles-failures.md); a test runs every `opv ...` line in the docs through the real parser.

### Changed

Contract changes first; scripts and CI that parse output or exit codes may need updating.

- **Quieter output.** `status`, `plan` and `check` no longer print the item link under each finding (`Next: opv open <KEY>` gets you there; `--json` keeps `open_url`); the `using manifest …` line appears only with `--verbose` when the git remote or `.opv` found it; `opv init` drops its tagging note and docs pointer; account lines name the account by its email. In WSL, `opv open` uses Windows' own opener (`rundll32`), falling back to `wslview`.
- **Exit code 9** is new: outcome unknown, or a provider did not answer (`outcome_unknown`, `provider_unavailable`); re-run the same command, CI may retry it. A 1Password or Fly read that never answers is now exit 9 naming the provider and its status page, in `status` and `plan` too; it was exit 4 (1Password) or 5 (Fly). After a run has started writing, an unanswered read is exit 9, never "nothing was changed". An Azure update refused with nothing applied is exit 5 `update_refused`, not retried (NR-2, NR-28).
- **Interruptions** exit 130 (SIGINT) or 143 (SIGTERM) after giving the running call 5 s to stop, with `interrupted during <step>; safe to re-run` (NR-12).
- **`--timeout` defaults to 1800 s** for the whole run; each call also has its own limit (diagnosis 15 s, read 60 s, write 120 s, a write that waits for a rollout 15 min) (NR-4).
- **`azure.subscription` is required** and passed on every `az` call; every external call names its scope (`--subscription`, Fly `--app`, Kubernetes `--context` and `--namespace`) and runs with a pinned environment, so your CLI defaults no longer matter (NR-7).
- **Sign-in hints say `opv login <env>`** everywhere (doctor, errors), the same in every shell, instead of `eval $(op signin)`; CI wording is unchanged. The unreleased `opv session` from #63 shipped as `opv login`, without an alias; `signin`, `sign-in` and `auth` are hidden aliases of `login`. With the 1Password app integration, `doctor` asks the app to approve once (`op vault list`) before reporting "not signed in", since `op whoami` fails until a command is approved; the not-signed-in message names the app setting (Settings > Developer > Integrate with 1Password CLI), except in WSL.
- **One `Next:` line, always last, on every failure**: a command that runs as typed. A step only a person can take is on a `Do:` line before it. This replaces doctor's `Next step (<check>): ...` line and the other spellings; `check` labels guidance `guidance:`; findings print `opv: N findings` instead of `opv: status findings: N`; a usage error points to the command's `--help` (NR-19).
- **Fly output**: `sync` names keys as `product/KEY (TARGET_NAME)` with the same words on every provider (`written:`, `unchanged:`, `pending deploy (pass --deploy):`, `extra, not pruned (pass --prune to remove):`, `held (immutable), ...`, `deployed:`, `pruned:`) and ends with `summary: written N · unchanged N · held N · deployed <revision|yes|no> · pending N · pruned N · kept N · skipped N`. The Fly-only lines `N to stage, ...`, `staged: N changed, M unchanged`, `pending on Fly:`, `nothing pending` and `staged changes not deployed (no --deploy)` are gone. `status` and `plan` start with a count line, list problem rows first with the full reason, and drop their old closing lines; `plan` names what a sync would do and ends with the sync command. A Fly deploy already running is waited for instead of refused; an app with no machines skips the deploy with a notice (exit 0) (NR-18, NR-24).
- **One state vocabulary** on every provider: TARGET is `new`, `same`, `changed`, `unknown`, `pending`, `held`, `extra`, `drift` or `n/a` (`absent` became `new`, `unchanged` became `same`, Fly's `present`/`potentially changed` became `unknown`, `present (not desired)` became `extra`, `present (immutable, held)` became `held`, `-` became `n/a`). The JSON `state` and `target` values are unchanged.
- **JSON contract**: every `--json` document starts with `schema_version` and `ok` and ends with `next` and `do`; a failure prints one document on stdout too, adding `exit_code` and `error: {code, category, message, detail, retry, human_required, do, next}`, with the human text still on stderr. `error.code` is a closed list (`opv schema`, [usage](docs/usage.md#json-contract)). `status`, `plan` and `check` share one row shape and key order (`product, key, kind, state, rule, reason, target_name, fly_name, target, action`, plus `open_url`, `shared_from`); `target_name` joins `fly_name` (deprecated, same value); `check --json` gains `product` and `totals`; `status`/`plan` gain `changes` (`none`, `some`, `unknown`) and `plan` gains `plan_id`; `explain --json` names its provider lines `target_details`. `schema_version` stays 1.
- **A config key stored in a concealed field is accepted** and delivered as a plain value; opv never prints it (`config export` shows `<concealed in 1Password>`, `status` warns once). A key saved as the other field type, a duplicate label or a field outside its section is no longer an error anywhere (FR-14, FR-43).
- **Who writes to 1Password**: a signed-in person's runs may tidy the item's layout (above), and `item skeleton`, `setup`, `init` (a missing vault or item, a new manifest) and the manifest commands write; service accounts, Connect, CI and runs under `deploy_credentials` only read and print one note. `item skeleton` reads the item tolerantly, so a field opv finds elsewhere counts as present.
- `run` reads the item once before `op run` (to tidy it for a person, or to reference a misplaced field by its ID); it still passes only `op://` references, and under a read-only identity warns once per key whose stored value a person's tidy would normalize (FR-43).
- A failed item read is diagnosed (`op whoami`, `op vault get`) before it is retried, and told apart: not signed in, removed vault access, or a moved, archived or deleted item. A missing object (`op` not found, `kubectl` `NotFound`, `az` `SecretNotFound`/`ResourceNotFound`) is reported at once instead of after 3 tries (NR-3, NR-26).
- With no configuration, opv offers both ways to start (`opv init` for an existing item, `opv setup` for a project with a recipe). A configuration error names `file:line: field` (or the manifest), shows the line and puts the derivable edit on `Do:`. A failing `enum` lists the declared values.
- After staging, `sync` re-reads Fly's list for up to 30 s until every staged name shows a digest, so a lagging list is never reported as unchanged (NR-30).
- `opv doctor` no longer warns for a later `flyctl` patch in the tested minor (0.4.113 and up).

### Fixed

- **External Secrets: an expired or rejected store credential is named.** When an ExternalSecret cannot read its version, opv now reads the operator's newest warning event and says whether the ClusterSecretStore's credential has expired (AADSTS7000222), cannot sign in (401) or may not read the secret (403). Before, a store still cached as Ready always got the generic "most likely cannot read" cause. The event text is classified, never printed.
- **One 1Password account per project, never the default by accident** (found in a fresh-account run-through): with several accounts on a machine, every `op` call went to op's default account, the 1Password app could only approve that one, `init` would have created the vault there, and manifest discovery searched every account (minutes of approval prompts for accounts the project was never pointed at). Now `opv login --account <email>` (or `opv init --account`) records the account ID in `.opv`; with several accounts and none recorded, commands stop at once with `account_required` listing them and `opv login` asks; with one, it is used. Every `op` call carries `--account` (an environment variable never reached a Windows `op.exe` started from WSL). An email or sign-in address is resolved to the account ID. `doctor` checks the chosen account's sign-in only. On Linux and WSL, where `op` keeps its own accounts, `opv login --account <email>` adds an account `op` does not know yet at op's own prompts and signs in in the same step, and the account menu offers "Add another 1Password account": no separate `op account add`. `add` points at `opv check <env>`, which creates the empty field; `status` on a local-only environment no longer sends a manifest user to `secrets.toml`.
- 1Password writes never overwrite a newer edit: every read a write is built from passes `--cache=false`, and after each edit the item must be exactly one version past that read and hold what opv wrote; otherwise the tidy reports `tidy_conflict` or `tidy_unverified`, and a manifest write fails with `config_changed`, never retried. `opv setup` re-reads the item before saving and re-plans instead of overwriting (`item_changed`, exit 4).
- `sync --expect-plan <id>` re-run after an exit 9 matches the same plan: what the interrupted run already wrote counts as the plan's own progress (FR-41).
- A manifest whose path tags do not cover the current directory is not used; a manifest's `account` reaches its environments, `status --all` included. The fleet and simple readers of one item no longer move each other's fields back and forth.
- Refusals from `add`, `init --add-env` and `open`, and `status --all` for an environment it could not read, end with a `Next:` that runs as typed.
- A write that fails or times out is read back before opv reports a result, so a dropped connection no longer looks like "nothing happened" (NR-2).
- Found by the live smoke tests against Azure, kind and 1Password: with the 1Password app integration, `op whoami` reports no `user_type`, so opv could not tell a person was signed in and refused to tidy or to write a manifest (`init`, `add`, `config import`); a `whoami` that names a user is now a person. A fleet configuration with one product no longer asks for `--product`. A key pruned from Key Vault and later added back failed (the name stays soft-deleted): opv now tags `opv-pruned=<env>` just before a prune deletes, and recovers a soft-deleted entry only when it carries that tag and `opv-managed=<env>`, then writes the new version (FR-32); a secret anyone else deleted is left alone, and the `Next:` step is the `az keyvault secret recover` command. `will prune:` lists each key once. When `init` may not create a missing vault or item, it says to create it. The tidy refusal names date, month-year, address and reference fields. `config import` without a git remote suggests `rm`, not `git rm`. When `op` stops answering for a person (not CI), the message also says to approve the 1Password app's prompt, which is what an unanswered approval looks like.

### Security

- A configuration error never prints the file's text, so a `.env` given as `--config`, `OPV_CONFIG`, `config import --file` or `config check --file` does not show its values (also in `--json`) (FR-2, SR-1).
- External CLI stderr is shown only scrubbed: every value read or written in the run, in its common encodings, and secret-shaped tokens (JWTs, bearer and service-account tokens, Azure keys and signatures, PEM keys, API key prefixes, `password=`-style assignments) are masked as `__SECRET__`, including values holding CR, BEL or ESC and each line of a multi-line value. stdout and stdin are never shown (NR-31).
- Azure `deploy_credentials` keep the service principal in a private per-run `AZURE_CONFIG_DIR` (RAM-only on Linux/WSL, DPAPI-encrypted on Windows), removed on exit, Ctrl-C, SIGTERM, SIGHUP, SIGQUIT and Windows console events; stale ones are swept at the start of every Azure run. The `az said:` excerpt of a failed deploy sign-in stays out of `doctor --json` (SR-4, FR-40).
- On native Windows, values reach `az` through a user-only named pipe that serves only the `az` process opv started (or its descendants); any other client fails the call.
- Kubernetes Secret and ExternalSecret names come from random or Key Vault version ids, never from the value; no name, label or annotation carries anything value-derived (SR-1, SR-2).

### Known limitations

- Fly: a run interrupted between `flyctl secrets unset --stage` and the deploy leaves the name on the machines, and the next run cannot see it because Fly hides unset names at once. Run `opv sync <env> --deploy` again or `flyctl secrets deploy` ([usage](docs/usage.md#pruning-on-fly)).
- Azure `deploy_credentials` are not supported on macOS (no RAM-only private directory): sign in with `az login`, or use OIDC in CI.
- opv never tidies an item holding an attachment, a website list, a one-time password, an SSH key or another field type an edit is not proven to keep; it says so in one note. The project manifest item is never tidied.
- Masking can only catch values opv knows or recognises: a CLI failure during the item read itself is masked by the patterns alone.

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

[Unreleased]: https://github.com/matt-cochran/1password-vault/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/matt-cochran/1password-vault/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/matt-cochran/1password-vault/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/matt-cochran/1password-vault/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/matt-cochran/1password-vault/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/matt-cochran/1password-vault/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/matt-cochran/1password-vault/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/matt-cochran/1password-vault/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/matt-cochran/1password-vault/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/matt-cochran/1password-vault/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/matt-cochran/1password-vault/releases/tag/v0.1.0
