# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Azure companion jobs (#238).** `azure.companion_jobs = ["job-a", …]` lists Container Apps jobs in the app's resource group that carry the same Key Vault references as the app; `opv propose target --azure-companion-jobs a,b` writes the list. `sync --deploy` updates the jobs first, then the app, each only where it is behind; a job-only change leaves the app unchanged. Before any update, opv refuses the deploy when a job's identity certainly cannot read the vault (naming the identity; `doctor` prints the grant command), warns when it cannot tell, and notes a grant under 10 minutes old. `doctor`, `status` and `plan` show each job and its identity's access. The deploy identity also needs Contributor on each job and read access to role assignments at the vault. Two targets cannot share a job. See [companion jobs](docs/configuration.md#companion-jobs).

### Changed

- **`delivery verify` on Azure Key Vault and Kubernetes also checks what the app (and its companion jobs) are bound to** (#238). A name the runtime binds at another version than the receipt is `drifted_on_target`, and one it does not bind is `missing_on_target`. So right after a sync without `--deploy`, verify reports the rotated names as `drifted_on_target` with `deployed: "staged"`, where it used to report them verified.

## [0.17.0] - 2026-10-23

0.17.0 runs a reviewed operation on a target with that target's own deploy credentials.

### Added

- **`opv target op <env> --target <name> machines|machine-update` (#234).** A closed set of reviewed Fly operations, run under the named target's `deploy_credentials` and never your own login or an organisation token. `machines` lists the app's Machines (id, name, state, region, image); `machine-update --machine <id> --image <ref>` moves one listed Machine to an image in the target's own repository (`registry.fly.io/<fly.app>:<tag>` or `@sha256:<digest>`) and needs `--confirm <env>` where the environment sets `confirm_env`. Every check (environment, target, provider, deploy credentials, confirmation, image and Machine format, the tool) runs before any 1Password read; the app is always the target's own; the `flyctl` child gets a cleared environment with only the basics; nothing prints a value. Not exposed over MCP. `registry-push` is designed but not yet available (it refuses); it follows in 0.17.x.

### Internal

- `TargetConfig::operations()` and the `TargetOperations` hook keep operations provider-neutral in the core; `runner::isolated_env` scopes a cleared child environment; `signin::open_for_operation` is a strict deploy sign-in that never falls back; `System::Docker`, the `docker` tool and `Guard::OperationRefused` are in the catalog ahead of `registry-push`.
- The shared environment allowlist (`host::ENV_BASICS`) now also carries the proxy and CA variables, `XDG_RUNTIME_DIR` and the Windows basics (Windows `Path` in any case); `declared_only` local and remote delivery get them too.
- opv-sim answers `flyctl machine list` and `machine update` in flyctl's documented shape (not yet recorded: the live spikes were skipped by owner decision).

## [0.16.1] - 2026-10-23

0.16.1 makes the `http` target practical to set up and fixes `delivery verify` on Key Vault and Kubernetes targets.

### Fixed

- **`delivery verify` on pinned targets (#241).** On an Azure Key Vault or Kubernetes target every key read `missing_on_target`, because the store's list carries no versions. verify now reads each key's current version as sync does, so a freshly synced key is delivered and a key changed on the target is `drifted_on_target`.
- **`http.descriptor` resolves beside the configuration file (#237).** A file given with `--config` (or found by discovery) parsed without its directory, so every `http` target's relative descriptor resolved against the working directory. It now resolves beside the file, as the 0.16.0 notes said.
- **`opv propose target --provider http` writes a section that loads (#236).** Names and paths in its options (the descriptor file, the gRPC service, the host) are no longer refused as high-entropy values; a pasted credential (a known prefix, a PEM block) still is. The generated `http.list`/`http.put` keys stay inside the target's table. A section that cannot be generated says why (for example `service x.S is not in the descriptor`) instead of "names no provider".

### Added

- **`--http-host <host>` and `--http-names KEY=remote,...` on `opv propose target --provider http` (#236).** Both are required: opv never guesses the host or the application's name for a key.

### Security

- **Another CLI never inherits a 1Password token.** `flyctl`, `az`, `kubectl`, `gh` and the editor already ran without the shell's `OP_SESSION*`; they now also run without `OP_SERVICE_ACCOUNT_TOKEN` and `OP_CONNECT_TOKEN`, so CI's service-account token stays with `op`.

### Documentation

- **Azure `env_name` needs only `{KEY}` (#239).** The configuration reference said `{PRODUCT}` was required; a `"{KEY}"` template delivers bare names, two keys that would render one name are refused when the file loads, and a prune only touches declared, opv-tagged names.

## [0.16.0] - 2026-10-21

0.16.0 delivers to an application's own secret store through its API.

### Added

- **The `http` target (#231).** A key can be delivered to an application's own store over gRPC-Web, the calls described in configuration and checked against the application's descriptor set pinned by sha256. The value goes in exactly one pinned field and never through JSON or a string. Destination and credentials come from the 1Password item (`base_url`, `token`, `cf_access_client_id`, `cf_access_client_secret`), and the item's host must equal the reviewed `http.host`. HTTPS only, no redirects, the operating system's trust store, proxies honoured. Drift comes from the store's version counter: a change is detected, equality is not proven. A key the store rejects fails the sync with `target_unhealthy` after its delivery is recorded, and retire is refused for this target. Requires application support; see [the HTTP target guide](docs/http-target.md).
- **`opv propose target <env> <name> --provider http --http-descriptor <file> --http-service <name>`** generates the section from the descriptor set.

### Internal

- HTTPS runs as a runner effect (retries, budget, observation and the test fakes shared); opv-sim stands in for `https` with a descriptor-driven fake store; recorded gRPC-Web replies are test fixtures; `ChangedBeforeWrite` is reached end to end; a configuration file's relative references resolve beside it.

## [0.15.0] - 2026-10-21

0.15.0 lets a person store a file key's exact bytes.

### Added

- **`opv set <[p/]KEY> --env <env> --from-file <PATH>` (#217).** For a key declared with `file`, opv reads a regular file's exact bytes (line breaks and a trailing newline kept) and checks them with the verbatim rules. It refuses a symbolic link, a non-regular file, a file over 64 KiB and non-UTF-8 bytes (`input_invalid`); a key without `file` is a usage error, and the person uses plain `opv set` (`usage`). Only a person in their own terminal may run it: an assistant and a non-TTY process are refused. A file other users can read is written, then warned about (`warnings` in `--json`); the file stays on disk.
- **The absent-file-key guidance names the verbatim store.** `opv next`, `opv inventory` and the `opv_next` MCP tool suggest `opv set <[p/]KEY> --env <env> --from-file <PATH>` for an absent file key, instead of the masked entry that would flatten it.
- **`opv open` warns on a file key.** Pasting the value into the 1Password app turns line breaks into spaces and drops a trailing newline, so `opv open` says so and names the verbatim store (`warning` in `--json`).

### Internal

- The e2e coverage check reads labelled JSON sections, so `target_drift` counts as reached (it was listed as unreachable).
- opv-sim e2e scenarios for `--from-file` run the real binary in a pseudo-terminal on Unix, and for the file-key guidance.

## [0.14.1] - 2026-10-21

0.14.1 fixes four defects found by #136's live verification against real 1Password, Fly and Kubernetes.

### Upgrade note

- **`opv status --fail-on-drift` now fails on real drift** (#219). A CI gate built on it that passed before may now exit 8 (`target_drift`), when a value or wiring was changed outside opv. That's the gate doing its job. Run `opv sync <env> --deploy` to restore 1Password's values, and check who changed the target.

### Fixed

- **`status --fail-on-drift` missed drift** (#219), in two cases:
  - **On a staged target such as Fly:** a value changed outside opv was named ("changed outside opv since its last sync") but the command still exited 0.
  - **On Kubernetes:** a workload reference opv had deployed, then replaced or removed by hand (for example with `kubectl set env`), was reported as "pending deploy".
  
  Both are now `target_drift`, exit 8. On Kubernetes, opv records the names it binds in an `opv-bound` annotation on the Deployment: object names only, never a value. `status` and `sync` say "changed outside opv since its last deploy". A Deployment last deployed by 0.14.0 or earlier has no such record, so a hand change there still shows as pending deploy until its next `opv sync --deploy`.
- **`opv changed` before the first sync** exited 4 ("op failed in a way opv does not recognise"), because op 2.40 replies "does not have a field" (#218). It now reports no record (`ok: true`, exit 10), and the sync is the next step.
- **A deleted service account** (op: "(403) Forbidden (Service Account Deleted)") was reported as an unrecognised failure (exit 4). It is now the rejected service-account token it is (exit 7): replace `OP_SERVICE_ACCOUNT_TOKEN` (#221).
- **`opv import` refused a multi-line value for a `file` key** with `single_line`, although opv delivers file keys verbatim (#217). Import and `inventory` now apply the verbatim rules for file keys (`nonempty`, `max_len` and the declared rules), so a PEM or other multi-line file keeps its exact bytes. A non-file key still refuses a line break. Pasting a multi-line value into a field in the 1Password app flattens its line breaks, so import it from a single-quoted `.env` value instead.

### Internal

- The #136 live verification record (`docs/verification/v0.13.0-file-delivery.md`), recorded Fly fixtures and `delivery-transports.md` §7.3's Fly answers (#220).
- Recorded op replies 16 and 17. opv-sim e2e scenarios cover all four fixes; with a fix reverted, its scenarios fail.

## [0.14.0] - 2026-10-20

0.14.0 keeps you signed in to 1Password across opv commands without putting the session where anything else can read it. It also closes a leak: `opv run` could hand the 1Password CLI's session or service-account token to the app.

### Security

- **`opv run` no longer passes 1Password credentials to the app** ([GHSA-96pq-fxvx-w6xq](https://github.com/matt-cochran/1password-vault/security/advisories/GHSA-96pq-fxvx-w6xq)). For a product without a `[products.<p>.local]` section, earlier versions ran `op run -- <command>` directly, and `op run` passed every `OP_*` variable from your shell to the app: an `OP_SESSION_*` session, `OP_SERVICE_ACCOUNT_TOKEN` or `OP_CONNECT_TOKEN`. Every local `opv run` now starts the app through opv's delivery step, which removes all of them. opv also stops passing `OP_SESSION*` to the other tools it starts (flyctl, gh, az, kubectl, and the `opv config edit` editor). On an earlier version, add a `[products.<p>.local]` section (even an empty one) to each product, and rotate any token that was present when an app was started this way.

### Upgrade note

- **A script run under `opv run` that calls `op` itself** (for example `opv run -- ./deploy.sh` that uses `op read`) no longer receives your shell's session or `OP_SERVICE_ACCOUNT_TOKEN`. That includes CI. Call `op` outside `opv run`, or rely on the 1Password desktop app integration.

### Added

- **Sign in once per terminal (#203).** With the 1Password desktop app integration, opv reuses the app's unlock across commands and holds nothing itself. Without it (WSL with the Linux `op`, or headless), `eval "$(opv login --shell)"` or `opv login --shell=fish | source` signs this shell in once:
  - The session goes into a non-exported variable and an `opv` shell function that passes it to opv alone. Plain `op`, assistants, scripts and editors started from that shell never see it, and the token never touches disk.
  - `--shell` writes only to its own shell's pipe. `| cat`, `| tee`, a file or a terminal is refused (`shell_eval_required`), and so is syntax for a different shell than the one running (`shell_mismatch`), before any sign-in.
  - A live session is reused with no prompt. An expired one names the same line as its Next.
  - PowerShell is not supported yet.
  - `opv doctor` reports whether the app integration is on and whether this shell holds a live session.
  - An assistant hands `opv login --shell` to the person and never runs it.
- **MCP `opv_state` `delivery_preview` takes a `role`** (like `opv run --preview --role`), so a role-scoped product answers instead of refusing with `choice_required`.

### Changed

- **Sign-in errors agree across commands.** `inventory` and `next` report an expired shell session as `expired` with the refresh line, as `ready` and `access` already did. Where `op` talks to the 1Password desktop app (macOS, Windows, WSL with `op.exe`), a signed-out reply with no shell session reads as the app being locked (`app_locked`).
- **`opv config check` and `opv config edit` print unified hunks** with three lines of context, instead of every line of both files. A proposal's contract diff is unchanged: it is still the whole file, because an assistant writes the proposed file from it.

### Fixed

- **The npm release no longer needs re-runs when npm is slow to list a package.** The platform packages publish back to back, one window of up to 90 minutes waits for npm's integrity to match the released bytes, and then the main package publishes. A duplicate-publish refusal for a version npm has not listed yet waits instead of failing, and a timeout says re-running is safe. In 0.13.0, npm took 2 to 56 minutes to list each package.

### Internal

- **#136 live-check kit:** `docs/verification/v0.13.0-file-delivery.md` holds the runbook and canary tooling for the remaining file-delivery checks. They run on a throwaway Fly app with canary secrets only.
- **Design records:** `docs/design/session-reuse.md` and its DESIGN-FMECA review, with the owner's decisions.

## [0.13.0] - 2026-10-20

0.13.0 keeps an application's keys consistent across every environment, lets infrastructure-generated values reach targets without being stored in 1Password, and gives an assistant a fuller picture of the application, still without ever seeing a value.

### Added

- **Infrastructure values (#206).** A key declared `source = "infrastructure"` is supplied by the deploy job that produces it, as an `opv.supply/1` document on `opv sync <env> --supply-stdin`, and is never stored in 1Password. opv validates it against the key's rules and delivers it through the normal plan and sync path, with `s1` delivery evidence and receipts that list it as `supplied`. CI still never writes a value to 1Password. `opv ci workflow --supply` prints the step for the producing job, and `--supply-check` refuses a step that would expand a value into the job log. The plan, `status`, `ready --gate` and `delivery verify` show such keys as supplied at sync, as supplied, drifted or not recorded. `opv set`, `opv import`, `opv open`, `opv propose structure`, `generate` and attestation all refuse or skip them. Guide: [Supplying infrastructure-generated values](docs/infra-generated-values.md).
- **Retiring a key, end to end (#179).** After `opv propose retire`, CI runs `opv sync <env> --prune --retire` in tier order (production only after shared and local environments are clean, respecting `confirm_env`, and never while the deployed code still reads the key). Then a person's `opv apply rp-<id>` moves the key's fields into an `archived · <date> · retired <product>/<KEY>` section of each item, never deleting a value, and marks the key `lifecycle = "retired"`. `ready` shows a `retirement_incomplete` finding with the remaining steps.
- **Consistency across environments (#179).** `ready` reports a non-blocking `environment_gap` for a key whose explicit `environments` list leaves out an environment without an `except`. A new `extend` proposal adds an environment to every explicit-list key of a product or the project. `opv propose setup --names-from` declares keys for every environment. `examples/ci-change-detection` gains a dev → staging → prod promotion recipe gated by `opv ready --gate`.
- **Inventory (#174).** Each key row carries its declared attributes (immutable, allow_same_value, rule names, guidance, roles, file, delivered names), where it lives in 1Password (section, field, item link), its delivery state on each target (delivered, attested, supplied, stale, not delivered, unreadable) and its own next step. `opv schema` documents the inventory.
- **Needs (#175).** `opv needs [<env>] [--product] [--scan <dir> | --names <file>]`, also over MCP; Ruby and C/C++ reads and files under a declared secrets directory are scanned. Declared rows carry their value state, undeclared rows a suggested declaration that loads, and `ambiguous` names its candidate products (a computed name is `computed`).
- **Generated configurations (#178).** On a generated configuration, a proposal returns the fragment the generator must emit (TOML, JSON, removed paths and the load error it would raise) and `generated_by`. The `--write` refusal carries the same fragment. `opv config check --file` confirms a regenerated file project (`regenerated_file_differs` when it does not match).
- **Signals (#177).** A placeholder in a config key is warned like one in a secret; a `low_entropy` advisory for secrets; an opt-in `github_pat` shape.

### Fixed

- MCP `opv_state`'s `needs` section accepts a scan directory inside the project on macOS, where the project's path and its real path differ (`/var` and `/private/var`).
- `opv propose structure` / `opv apply` planned no boundary for a key present in every environment by default, so a setup from a `.env` failed with `boundary_missing`; a new environment's proposal now also declares the boundaries of the keys it inherits (#210).
- `opv propose setup --names-from` against an existing contract proposes only the keys it does not declare yet (#176).
- Local file delivery refuses a runtime directory others can write to without the sticky bit (`ram_dir_unavailable`, `writable_by_others`), writes through a handle on its private directory so a renamed entry cannot redirect a write, and closes descriptors inherited from `op run` before the app starts (#136).
- `opv explain` says an infrastructure key is supplied at sync and never stored, with its recorded serial.
- The release waits up to 15 minutes for npm to serve each platform package before publishing the main package.

### Internal

- Local-delivery lifecycle tests (signals, SIGKILL sweep, failed launches) and a canary sweep across every output channel of role-scoped delivery (#136); the platform matrix and limits are documented in `docs/design/local-delivery.md`.
- A chained opv-sim scenario covers add, inherit, gap, retire and gate (#179).
- A lib test's outer `opv run` no longer leaks into later tests' sign-in steps, so plain `cargo test` passes as nextest does.

## [0.12.3] - 2026-10-19

### Added

- `opv apply --attest <env>:<target>:<product/KEY>` records a person's attestation that a staged target (Fly) already holds 1Password's value of an immutable key that every sync holds and so can never prove. It writes the key's delivery evidence at the target's current version and never writes the target, so the product can get a delivery revision again; receipts, `plan`, `status`, `sync` and `opv delivery verify` mark such names `attested`, not proven, and an opv before 0.12.3 drops an attested line rather than read it as proof. Proposed with an `attest` intent (`opv propose --intent <file>` or MCP `opv_propose`); applying needs a person's own terminal and refuses CI and agent mode. See [Attesting a held immutable key](docs/attestation.md) (#201).

### Fixed

- `plan --json` and `status --json` report a secret opv cannot compare as `target_state: "unknown"`, not `"present"`; only a proven match reads `present` (#201).
- `opv login -- <command> > file` works: login and opv's own sign-in prompt need stdin and stderr to be terminals, not stdout (#202).
- `opv login` rewrites `.opv`, and says "commit it", only when the recorded account changes. The sign-in prompt no longer suggests that a session outlives the command; the WSL notes say how to sign in once for several commands (#203).
- `install.js` and `opv doctor` name the repair `node "$(npm root -g)/@matthew-cochran/opv/install.js"` instead of `npm rebuild --allow-scripts` (#204).
- Only a global npm install owns `~/.local/bin/opv`; a project-local install runs its own binary and never touches the shared copy (on Windows the global root is `%APPDATA%\npm`) (#200).
- Releases publish the six platform npm packages first and wait until npm serves each tarball before publishing `@matthew-cochran/opv`, so a fresh install never finds the main package without its binary (#199). The publish jobs run on GitHub-hosted runners with npm scripts disabled (#195).
- A CI run called by the release workflow no longer shares a concurrency group with a direct CI run, so neither cancels the other; a staging push whose tree already has a retained candidate reuses it instead of rebuilding (#197).

### Internal

- The e2e matrix applies its short call limit only to the call under test and never caches a run that a real slow call disturbed (#205). CI runs every `tests/*.test.ts`.

## [0.12.2] - 2026-10-19

### Fixed

- An npm upgrade no longer leaves the old opv in place when npm skips install scripts. The `opv` command npm installs now updates `~/.local/bin/opv` itself (Windows: `%LOCALAPPDATA%\Programs\opv\opv.exe`) when that copy is missing or is the one npm installed for an earlier version, and says so once. It never overwrites a binary that `install.sh` or another method installed; then it runs npm's own copy and says how to update. `opv doctor` names the cause and the repair command, `node "$(npm root -g)/@matthew-cochran/opv/install.js"` (#193).

### Internal

- Releases are built once: the promotion to `staging` builds and tests every platform binary and npm package and keeps them with a manifest of their source tree and checksums; `main` and the version tag publish exactly those files and never rebuild (#191). The branch rules require `Build gate` and `gitflow-guard`.
- CHANGELOG comparison links cover every release.

## [0.12.1] - 2026-10-19

### Fixed

- `opv config export <env>` works with several products. It used to ask for `--product`, which the command did not accept, so a configuration with more than one product could not export its config values at all (since 0.10). It now prints every product's config values as `{product: {KEY: value}}`, leaving out source-only products and products with no config value there; `--product <p>` limits it to one product, and then only that product's keys (and the shared sources it reads) can block the export (#188).
- `opv propose target`, `opv propose structure` and `opv apply` take `--project <name>`, as `opv access` does, so new state vaults and items keep a project's established name when the checkout's directory or repository is named differently. The next steps opv prints carry the flag, and a plan proposed under one project is refused under another (#183).
- On a generated configuration, `opv propose … --write` is still refused, and the refusal now shows the change to make in the generator's input and steps to `opv propose structure`, then `opv apply`, which returns the ids for the generator to record. The read-only proposal no longer offers the refused `--write` as its next step, from the CLI or MCP (#184).
- `opv needs` matches the names a target delivers a declared key under (for example `FLEET__WEB__API_KEY` from `secret_name = "FLEET__{PRODUCT}__{KEY}"`): such a read is the declared key, not an undeclared name, and the key is no longer reported as unobserved (#187).
- Output masking no longer hides the word after a bare "Bearer" in prose, so a guidance string such as "never a Bearer header." survives `config export`. A value after `Authorization: Bearer` (also in JSON or `=` form) is always masked, and a bare "Bearer" before a token-like word (one with a digit, or 16 characters or more) still is (#186).
- Docs: `opv config export` prints the contract without its 1Password ids; `--with-ids` fills them in (#185).

## [0.12.0] - 2026-10-18

0.12.0 is a breaking release with one interface for people and assistants, from the CLI and five MCP tools: an assistant can guide setup end to end and sees every key's value state but never a value (#173-#178; design: `docs/design/assistant-guided-setup.md`).

### Breaking: one interface

opv 0.12.0 replaces the plan/approve/apply commands and the MCP tool set with one
interface. There are no aliases: update scripts and assistant settings when you upgrade.

- Changes to the configuration are proposed, then applied by a person:
  `opv propose key|env|target|retire|setup|structure|generate …`, then `opv apply <plan_id>`.
  This replaces `opv add`, `opv env add`, `opv target add`, `opv init`, `opv bootstrap`,
  `opv structure plan|apply`, `opv item skeleton`, `opv generate`, `opv tidy` and `opv approve`.
  `opv tidy` is removed with no replacement in 0.12.0 (deferred).
- `opv adopt` is now `opv import <env> --from <file|target:NAME>`. It is write-only and
  reports imported / skipped per key; it no longer says whether a value differs.
- `opv check` is `opv inventory --env <env>`; `opv config describe` is `opv inventory`
  and `opv contract`.
- 1Password ids move out of `secrets.toml` into `secrets.bindings.toml`. A `secrets.toml`
  with inline ids is refused until you run `opv propose structure`, then `opv apply`, once.
  A manifest project keeps its ids in a `toml opv-bindings` block inside the manifest
  instead of `secrets.bindings.toml`.
- `opv apply` records what it applied in `secrets.applied.json` beside the bindings, and
  refuses under CI and agent mode.
- Assistant-approved syncs are gone (`opv approve --sync`, `opv sync --approved`). Run
  `opv sync` yourself, or let CI run it.
- MCP: 13 tools become 5 (`opv_state`, `opv_next`, `opv_propose`, `opv_import_local`,
  `opv_explain`). `opv_structure_apply`, `opv_generate` and `opv_sync` are removed, and
  `opv_declare_*` are replaced by `opv_propose`, which accepts catalog shape names, not rule text. Re-run `opv mcp install`
  and `opv skill install` after upgrading.
- Validation rules count for assistants only once committed on the default branch;
  until then they show `rules_pending_review`.
- `opv ready --gate` fails on a value that is set but not yet delivered.

### Added

- `opv inventory [--env <env>] [--product <p>] [--json]` prints a key by environment matrix of value states: absent, empty, placeholder, malformed, set, unreadable and not_wanted. A cell never carries any part of a value, and a vault this session cannot read is unreadable, never absent.
- `opv next [--env <env>] [--json]` picks the one action this session can take, from unbound boundary to apply, absent/empty/placeholder/malformed to set, stale delivery to sync, else none; the rest queue, and actions on a vault the session cannot write wait on others by vault. Identical commands fold into one action naming its keys.
- `opv contract [--env <env>] [--component <c>] [--schema] [--check] [--relaxations] [--base <ref>]` prints the contract as data per component and environment (name, kind, catalog shape name, required, digest), with no id, rule parameter or value; `--schema` prints the contract's own JSON Schema, `--check` fails `contract_stale` on a stale committed copy, and `--relaxations` classifies relaxations against the default branch.
- `opv import <env> --from <file|target:NAME>` replaces `opv adopt`: it is write-only, with `--replace`, `--rotate`, `--skip` and `--dry-run`, reports imported and skipped per key, and passes each value from the file to 1Password on stdin only. Import into a `confirm_env` or production-tier environment needs `--confirm <env>`.
- `opv set <key>` reads one value with masked entry and writes it to 1Password; agent mode and a missing terminal are refused before any prompt, and only the key's new value state is printed.
- `opv access` lists for each vault who can write it where 1Password reports it (names only, never an email), marks production-tier vaults and this session's capability in text and `--json`, and raises `single_writer` for a deployed-tier vault with exactly one writer and `no_writer` for a production vault whose readable user list names no writer.
- `opv doctor` warns, never fails, when this session can read a production-tier vault or is signed in live to a production target's platform; each names the fix and the hardened option of a separate 1Password admin account.
- `opv ready --gate` fails `gate_failed` unless every present key is set and delivered at the source item version 1Password now has, and fails an environment it could not read as unreadable. A key `expires` within 30 days is the advisory `expires_soon`.
- Environments have a `tier` of `local`, `shared` or `production`; absent, it is production where the name or title reads as production today, else shared, and `local` with a target or `confirm_env` is refused.
- Keys carry `source` (person, generated, derived), `expires` and `lifecycle` (active, retiring, retired), and a retiring key is pruned by tier and archived after its needs are checked at the deployed revision; `retire_still_read` names the file that still reads it.
- `opv explain <KEY>` lists every place the key is delivered, for leak response: every environment it is desired in, every target that delivers its product and the delivery item recording it, names only. `opv explain <plan_id>` explains each step of the recomputed plan.
- The safe rotation procedure is documented on `opv sync --rotate` and `opv delivery verify`, including consumers outside opv and the `expires` attribute with `ready`'s advisory finding.
- `opv_import_local` imports write-only into a local-tier environment only (`import_tier_refused` otherwise) and tags each written item `assistant_imported`; health comparisons skip tagged values, and `opv ready --gate` counts them as set only in a local-tier environment, so they never count toward promotion.
- `opv ci workflow <env> --target <t>` also prints pull-request jobs that run `opv needs --gate`, `opv contract --check` and `opv ready --gate`, plus an `opv/relaxations` status that fails until the pull request has an approving review at its head; both check out full history for the default branch.

### Changed

- Value states are computed in memory from committed rules only, and a read error never converts to absent. Every `--json` document now uses schema 3 with the typed `next {kind, actor, command}`.
- The removed commands fail as unknown subcommands, with no aliases. `opv ui` actions call `import`, `propose key` and `propose env`, then `apply`.
- 1Password ids live only in `secrets.bindings.toml` (or a manifest project's `toml opv-bindings` block); inline ids are refused at load, naming the field, and a contract without bindings loads with an `opv apply` handoff.
- `opv config check` fails `bindings_unapplied` when the committed bindings differ from the `secrets.applied.json` apply record.
- MCP is five tools: `opv_state` answers each section with the CLI's whole `--json` document, `opv_next` answers `opv next`, `opv_propose` answers `opv propose`, `opv_import_local` is the only writer, and `opv_explain` answers `opv explain`. Every failure is the CLI's whole `--json` frame.
- Retiring a key checks needs at each environment's deployed revision, prunes shared tiers before production, archives the fields and marks the key retired last, and is resumable.

### Removed

- `opv add`, `opv env add`, `opv target add`, `opv init`, `opv bootstrap`, `opv structure plan|apply`, `opv item skeleton`, `opv generate`, `opv tidy`, `opv adopt`, `opv check`, `opv config describe` and `opv approve`, with no aliases.
- The approval file and every approve path, including assistant-approved syncs.
- MCP `opv_declare_key`, `opv_declare_environment`, `opv_declare_target`, `opv_ready`, `opv_configuration`, `opv_deployment_plan`, `opv_changed`, `opv_access`, `opv_delivery_preview`, `opv_structure_plan`, `opv_structure_apply`, `opv_generate` and `opv_sync`, with no aliases.

### Deferred

- `opv propose tidy`, purpose tokens, Docker Swarm, GCP Secret Manager and VMs.

## [0.11.0] - 2026-10-17

1Password stays the single source of truth for config and secrets: `opv sync` runs from CI and puts each kind into the platform's own channel, and nothing in production needs 1Password or opv at runtime (#136; design: `docs/design/delivery-transports.md`).

### Added

- `opv changed <env> [--product p] [--target t] [--json]` tells CI whether a source item changed since the last confirmed sync, from item version numbers only (one `op item list` per vault, never a value). Exit 0: unchanged; **exit 10** (`source_changed`): something changed, run a sync; any other exit is a failure. A confirmed sync now records each source item's version in the placement's delivery item, so `changed` can compare. A rate-limited listing exits 9 with the retry time.
- `opv status --fail-on-drift` exits 8 (`target_drift`) when a platform no longer matches 1Password; without the flag the exit code is unchanged.
- `opv ci workflow --on-change [--every <minutes>]` and `--drift` print the two GitHub Actions workflows: a scheduled change check that syncs only on exit 10 (every sync job in one concurrency group, `confirm_env` environments gated), and a nightly drift check. A ready-made example is in `examples/ci-change-detection/`, and the README has a "how opv works" section.
- Kubernetes ConfigMaps: `kubernetes.config = "configmap"` writes config keys as immutable, versioned ConfigMaps bound with `configMapKeyRef`, compared exactly and cleaned up like Secrets. It needs `get`, `list`, `create`, `patch` and `delete` on ConfigMaps, all checked by `doctor` (`sync` checks `delete` before its first write); grant them with a namespaced Role. It cannot be combined with `secrets_in`, which is refused at load (`config_invalid`).
- Kubernetes files: `kubernetes.secrets_dir = "/run/secrets/{product}"` mounts every delivered key that has `file` as a read-only file (mode 0440) in a projected volume `opv-files-<product>`, in the target's container only, and removes its variable. A file key's bytes are delivered exactly as stored, multi-line PEM and trailing newline included. `plan` names each file's path and the volume a deploy would change (`would deploy: volume opv-files-<product>, …`), and `status` chains each file to its Secret or ConfigMap. Before writing, `sync` refuses a workload that could not read the files (`mount_unreadable`, exit 6, with the `fsGroup` line to add) and a directory another volume already uses (`policy_refused`); `plan`, `status` and `doctor` warn about an unreadable workload, and a workload running as root gets a warning on every run.
- Fly: `fly.config = "secrets"` delivers config keys as Fly secrets; `"none"` declares that config is not delivered there, with a warning per run.
- Every `plan` and `status` row, text and `--json`, names its channel: `channel`, `via` (`Fly secret`, `Kubernetes Secret`, `ConfigMap`, `GitHub variable`, `env`, …), `delivered_as` (`env` or `file`), `form` and `path`. The plan id now covers each key's channel and form.
- MCP: an `opv_changed` tool (item ids and version numbers only); `opv_declare_target` and `opv target add` accept `roles` (`--role`), `kubernetes.secrets_dir` and `fly.config`.
- `opv run` adds `OPV_UID` and `OPV_GID` to a child that receives files, and `docs/local-development.md` has a Docker Compose recipe that reads them.

### Changed

- **Breaking: a target that delivers a product whose keys declare `roles` must declare `roles` itself.** Before, such a target silently got every role's keys. Now the configuration is refused at load (`config_invalid`, exit 2, naming the target's `roles`). The fix is one line on the target, listing the roles it serves:

  ```toml
  [environments.prod.targets.web]
  roles = ["serve"]
  ```

  A key whose roles the target doesn't list is not desired there, and `--prune` removes it. Targets of products without role-scoped keys are unchanged.
- New Kubernetes targets get `kubernetes.config = "configmap"` from `opv init` and `opv target add`. Existing targets without `config` keep `env`.
- A remote development profile (`[products.<p>.remotes.<r>]`) may no longer name an environment that has a deployment target: such a profile is refused at load (`config_invalid`, exit 2, naming the profile, the environment and one target). Remote delivery is for development environments; deployed ones get their values from CI.
- A config key on a target with no config channel is no longer shown as `n/a`: `plan` and `status` print a warning and `sync` refuses (`policy_refused`), unless the target declares `config = "none"`.
- The new exit code **10** (`source_changed`) belongs to `opv changed` only. Scripts that treat every non-zero exit as a failure must branch on it.
- The Kubernetes RBAC grant in an error now names "a Role in namespace <ns>".

### Fixed

- `opv schema`'s `documents.error` is generated from the real error object, so it no longer lists the removed `detail` field (#166).
- `opv login` with a stale session whose vault list is signed out now asks for the password instead of exiting with "not currently signed in" (#167).
- A key withheld by a target's roles is no longer counted in that target's binding set.
- Kubernetes and Azure: `sync` no longer writes or binds the keys of a `source_only` product on a target. Before, on Kubernetes, a whole-environment `sync --deploy` whose source-only product held a config key stopped with `policy_refused` ("was not created by opv").

## [0.10.1] - 2026-10-17

### Fixed

- `opv init <env> --add-env` refuses an item that holds only personal keys before it proposes or writes anything. Personal keys live in each person's own item, so that item can't be the environment's boundary. The error names the item and asks for the environment's shared item.
- A Kubernetes external secret store that isn't ready is reported with its reason code wherever opv meets it: preflight, `opv doctor` and the diagnosis after a failed sync. A store with no reason is described without one.
- `opv delivery verify` on a target whose products deliver no secret says so, instead of reporting that nothing is delivered.
- With no 1Password account added on the machine, the error says no account is added rather than naming an invented one.
- An account taken from the project's `.opv` is named as coming from `.opv`, not from the environment.
- `opv mcp install --client all` reports the clients it already registered when a later client fails, and its next step is the failed client's own. Help text and docs give the config check's exit code as 2.
- `opv add` reports a refused proposal as a refused proposal (`config_proposal_invalid`), saying nothing was written.
- `opv ui`: the key-name rule is stated in plain words, a findings list cut at five says how many more there are, and the copy status labels its next command.
- `opv setup` checks the shape of its 1Password item reads like every other read, so an unexpected reply is `unexpected_output`.

- An account `op account list` lists is no longer reported as "not added to op on this machine" when `op whoami` can't find it, which happens with several accounts on one sign-in address. opv now checks the listing: a listed account needs a sign-in, and only an absent one is an account to add (#165).
- Kubernetes: `opv doctor`, `opv ready` and the sync preflight check the `patch` right on Secrets and ExternalSecrets, which `kubectl apply --server-side` needs to write them. Before, an identity with exactly the checked rights passed `doctor` and then failed `sync` with a 403.

### Internal

- The simulator plays a recorded `op signin` (#160 scenario now runs). A coverage gate proves sync refuses every value a store would reject as `keys_blocking`, never an internal error. The security tests copy their configuration into their own temporary directory, so a developer's `.opv` can't change them.

## [0.10.0] - 2026-10-16

Every failure is now one typed cause from a closed catalog (#157, #159, #160; design: `docs/design/error-catalog.md`). This changes the `--json` error object and removes error codes; see Changed.

### Added

- `opv run <env> --product <p> [--role <r>] --remote <profile>`: remote development delivery without plaintext environment files (#139). A reviewed profile, `[products.<p>.remotes.<name>]`, pins the SSH host and its public host key, the user and port, the environments and roles that may go there, the remote `opv` path, the working directory and the command; every field is validated at load. The run's selection is resolved by `op run` and sent by `opv remote-send` over `ssh -F none` with strict pinned host-key checking, batch mode and no forwarding or multiplexing, to `opv remote-receive`, as one framed payload on stdin that is validated whole before anything is written or started. File keys go to a RAM-only 0700 directory on the remote host (refused, never written to disk, without one); the remote app's environment is declared-only and never holds an `OP_*` variable. A disconnect, 45 seconds without a heartbeat, or a signal stops the app's process group and removes the directory. It needs a person's terminal; no MCP tool runs it. Design, trust model and limits: `docs/design/remote-delivery.md` (FR-63).
- `opv run --preview --remote <profile>` and `opv_delivery_preview` with `remote` preview a remote run: `transport`, the profile's pinned connection and command, and `remote_profiles` (identifiers only).
- A `MountedSecretStore`-shaped fixture consumer reads the serving role's #136 mapping through `opv local-delivery` byte for byte, finds no migration material and refuses a traversing name (`tests/mounted_consumer.rs`).
- Error codes `permission_denied` (signed in, but missing a right; human required, the grant in `Do:`) and `owner_setup_required` (a GitHub environment its owner must create; the command in `Do:`).
- `opv_deployment_plan` takes optional `targets`, `product` and `rotate`, so a scoped `opv_sync` can be previewed and approved with the same scope.
- The error catalog. Every failure, on the CLI, in `--json` and in MCP, is one cause from a closed list, with a message filled from typed fields (the vault, account, environment, target, key, file and line), at most one `Do:` and a `Next:` that runs as typed and never loops back to the same failure. Exit code, `retry` and `human_required` are derived from the cause, so they cannot contradict each other. An external failure becomes a cause only through that tool's diagnosis (`op`, `flyctl`, `az`, `kubectl`, `gh`, `ssh`), built from recorded replies; what opv cannot recognise is `unrecognized_failure`, with what opv did establish, never a guess. The code table in `docs/usage.md` is generated from the catalog.
- What opv checked and what the tool said: a failed call adds a `checked:` line (the call, names and IDs only, and the account it ran in) and a box with the tool's error line plus its tail (at most 5 lines; `--verbose` and MCP `verbose` pass the complete reply), scrubbed, with escape sequences and bidi overrides removed, and marked when opv cut the tool's own advice.
- The `--json` error object carries `subject`, `evidence` (`checked`, `account`, `upstream`), `retry`, `human_required`, `do`, `next` and `next_kind` (`rerun`, `run`, `check`, `handoff`, `vendor`, `none`). Text another program wrote sits only in `evidence.upstream`, always with `"untrusted": true`. `retry` adds `check_first`: something may already exist, so `next` is a read.
- MCP answers a failure with `{ok: false, error}`, where `error` is exactly the CLI's `--json` object, built by the same code. Every MCP tool takes `verbose`, like `--verbose`.
- New error codes, among them `unrecognized_failure`, `unexpected_output`, `resource_not_found`, `create_outcome_unknown`, `secret_not_stored`, `budget_spent`, `concurrent_edit`, `target_changed`, `own_session_required`, `target_not_signed_in`, `tool_unusable`, `remote_unreachable`, `remote_disconnected`, `remote_version_mismatch`, `child_start_failed`, `delivery_unverified`, `unknown_target`, `unknown_role`, `unknown_profile` and `internal_error`. `opv schema` and `docs/usage.md` list them all.
- Exit 70 (`internal_error`): an opv bug, with `Next: opv version` to report it. Exits 129 (SIGHUP) and 131 (SIGQUIT) join 130 and 143 as `interrupted`; an interruption says whether writes had started.
- Every opv process makes itself non-dumpable first thing, for every command: `PR_SET_DUMPABLE=0` and a soft `RLIMIT_CORE` of 0 on Linux (the hard limit and `opv run`'s child are untouched), a soft `RLIMIT_CORE` of 0 and `PT_DENY_ATTACH` on macOS, no crash dialog and no heap in error reports on Windows. `opv doctor` reports a Linux `fs.suid_dumpable` that would still allow a dump.
- One output guard under every byte opv writes (stdout, stderr, `--json`, MCP answers). Values opv read from 1Password are masked deterministically, as a fixed `********` whatever their length, together with the credentials in opv's own environment (`OP_SERVICE_ACCOUNT_TOKEN`, `OP_SESSION_*`, `OP_CONNECT_TOKEN`, Fly, GitHub and Azure tokens), tokens opv mints, and known token shapes. opv's own names are never value-matched, so `--json` stays valid.

### Changed

- Breaking for `--json` and MCP consumers: the `error` object is the catalog's (see Added), and `detail` is gone. An MCP error is no longer `{ok, code, human_required, human_action}`. Every document (CLI `--json`, MCP, `opv schema`, `run --preview --json`) now carries `schema_version` 2: the error object changed shape and the removed codes have no aliases (FR-60), so a consumer must branch on 2 and the new codes.
- Removed error codes, with no aliases: `source_error`, `target_error` and `op_unexpected` (now a specific cause, or `unrecognized_failure`), `auth_required` (now `permission_denied`, `target_not_signed_in` or `credential_rejected`), `desktop_app_unavailable` and `sign_in_cancelled` (now `op_not_signed_in`), `duplicate_scope` (now `input_invalid`), and `tidy_conflict` as an error code (now `item_changed` or `concurrent_edit`; a status or plan document's `tidy_error` still says `tidy_conflict`). The MCP-only codes are gone too: `invalid_name` and `invalid_plan_id` are `usage`, `credential_in_environment` is `own_session_required`, a write under CI is `terminal_required`, and `invalid_receipt`, `unsupported_receipt` and `inspection_unavailable` are `internal_error`.
- `.opv` discovery stops at the repository root: opv never reads a `.opv` above the top of the checkout, and outside a repository it reads only the current directory. `opv bootstrap --file <f>` reads the `.opv` beside that configuration, not the shell's.
- The agent skill is refreshed only on install: by `install.sh`, the npm postinstall and `opv skill install`. No other command writes your home directory. `opv doctor` and `opv skill status` report an outdated copy, and `opv skill status` names the install that updates it.
- GitHub targets need gh 2.43.0 or later, the first release with `gh variable list --json`; `opv doctor` warns about an older gh.

### Fixed

- `opv plan` shows every write a sync makes, including the GitHub variables it sets or prunes, so a confirmed sync writes exactly the plan (#150).
- A vault in another 1Password account names the account that holds it: `ids_not_in_account` looks it up in the machine's other accounts with the same read-only probe as `opv vault locate` (it never prompts or signs in) and steps to `opv account use <account>`. When no account that could be asked holds it, it names the accounts that could not be asked (#153).
- An `OP_SESSION_*` for another account is never used for the project's account: the `op signin` opv runs ignores `OP_ACCOUNT` and every inherited `OP_SESSION_*` (#153).
- A one-off `opv login --account <ID> -- <command>` outside a project writes no `.opv` (#153).
- `opv login --account <ID> -- opv … --file <f>` takes the account from the child's `--file` or `--config`. Its failures carry their own cause (a signed-out reply is `op_not_signed_in`, never `ids_not_in_account`), and a sign-in that fails before the child starts still prints one `--json` document when the child asked for one (#159).
- `opv login` signs in to the account asked for, whatever session is live: only a session for that account counts as signed in (a bare `op whoami` no longer does), the account chosen at the menu or with `--account` is used when the configuration names none, `.opv` is written only after the sign-in succeeds, and an empty account is never passed to `op` (#160).

Wrong causes and looping next steps, found by a sweep of the CLI and MCP after #157:

- `opv access` checks the 1Password session first and reports `op_not_signed_in` instead of every vault being outside the account; each environment's vaults are checked in its own account, one vault outside it is reported on its own, and the finding names the account (#157).
- `opv login` no longer says "signed in, but vault access failed … setup vault" with a `Next: opv login` loop when `op vault list` fails under a live session. It says the session may belong to another account on the same sign-in address, runs nothing, and points at `opv account list` (#157; checking that the session belongs to the requested account is #160). A failed `op account list` no longer starts the add-account flow.
- `opv bootstrap` (including `--dry-run`), `opv structure plan` and the MCP structure tools report a missing session as `op_not_signed_in`, not `ids_not_in_account` with a `--rebind` step; `opv_structure_apply` checks the person before it uses the single-use approval.
- `opv ready` reports a target's real cause (sign-in, missing CLI, provider outage) instead of `grants_missing`, checks a state vault that can be read but not managed with `op vault get`, and reads each environment in its own account (as `doctor` now does).
- "…, then run opv again" no longer renders as `Next: opv`, and a target error without a step says to fix the cause before re-running.
- Fly failures under deploy credentials are diagnosed as the token, not "not logged in to Fly"; Kubernetes tells a 401 (sign-in), a 403 (`permission_denied`) and an outage apart, and no longer reports a forbidden API list as "ESO not installed"; Azure and Kubernetes missing rights are `permission_denied`, not `auth_required`; the Key Vault access wait tells a missing vault, no answer and a refusal apart.
- `opv delivery verify` and receipts never use an "unknown" account (a failed `op whoami` is its own error), and `--product` with an undeclared product fails instead of passing with nothing checked.
- `opv sync --receipt` checks the path before anything is staged, and a target error after staging says what was already staged.
- `opv run` reports a failed personal-item lookup by its cause, not "not set up yet".
- Manifest errors keep the step `op`'s session diagnosis gave (`opv login --add`, the CI token step) instead of `opv login`; a service account or CI is told a person runs the write in their own terminal; advisory account findings carry no login step.
- `opv target credentials` steps follow the target's state (recorded, cannot mint, needs a provider sign-in); existing targets point at `opv config edit`, and a misspelt target lists the targets.
- Exit codes match their error codes (`inventory_incomplete`, `account_not_registered`, `policy_refused`, deploy-credential failures), and repeated refusals no longer say to re-run.
- MCP errors carry `human_required` and the error's own runnable `opv` step; MCP-only codes are gone (see Changed); `opv_access` returns its `checked` and `unclassified` counts and has a budget longer than the 1Password app's approval prompt; `opv_ready` findings keep their target; `docs/mcp.md` no longer says sync is unavailable through MCP.

Found by the release review of every error message (the snapshot set):

- A check that could not run is never reported as a guess. When op, kubectl or gh is missing, opv says so (`dependency_missing`, exit 3). When one never answers, opv reports the service unavailable with the real number of attempts. Before, these read as "not signed in", "you may not delete secrets", "account not registered" or "needs the Manage permission", and `opv account list` and `opv access` exited 0.
- `opv account list` and `opv access` report a missing op as an error instead of a guessed state.
- An account named by `.opv` (or `OP_ACCOUNT`) that op doesn't know is "add this account" (`account_not_registered`, `opv login --add`; on macOS, add it in the 1Password app), not "not signed in". The message names where the account was chosen.
- Next steps keep the flags that matter (`--apply`, `--confirm`, `--timeout`), never point at `--help` when the command can be run again, and a placeholder in a step is explained by its Do.
- The budget error says what was already written when writes had started. `opv tidy` says "tidied" only when the tidy succeeded. A file-write error names the file, not opv's temporary file.
- `opv status` and the plan and sync errors name the environment. A Kubernetes error names the namespace and the context separately.
- A GitHub environment that is gone is reported as needing an owner to set it up, not as an unrecognised failure.
- `opv run --json` without `--preview` says that `--json` needs `--preview`.
- MCP honours `OPV_PROJECT` and uses the project's account, as the CLI does, and `opv_structure_apply` checks in the CLI's order.
- An item listed with `"tags": null` no longer breaks the manifest listing.
- The example Claude Code readiness hook reads `schema_version` 2 (it reported every opv 0.10 receipt as unconfirmed).

## [0.9.0] - 2026-10-15

0.8.1 was not released on its own; its changes are part of 0.9.0.

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
- `opv approve <plan_id> --sync <env> [--target …] [--product …] [--deploy] [--prune] [--rotate …]`: a person approves one deployment plan in their own terminal (each name it writes or unsets is listed, never a value); `opv sync <env> --approved <plan_id>` and the MCP tool `opv_sync` then run exactly that plan once, within 15 minutes. A stale plan is refused before the approval is used; `--prune-immutable` is never approved this way.
- `opv ci workflow <env> --target <name> [--github-env <env>] [--deploy]` prints a ready-to-commit GitHub Actions workflow for one target: pinned actions and opv release, `--confirm` for a `confirm_env` environment, the delivery receipt uploaded and verified, and the `opv access … --create` command its token comes from.
- `opv_ready` (MCP) returns each finding's code, blocking flag, actor, effect and next step (an `opv` command or a 1Password item link only) and each target's state; the environment is optional.
- `docs/design/delivery-transports.md`: the same delivery contract for local containers and Fly, and the plan for retiring an app-side env shim (#136; design only).
- `opv mcp serve --project <dir>`: opv's MCP server ships in every released `opv` (npm, `install.sh`, the GitHub release), so assistants need no separate build. `opv mcp install [--client claude|codex|all]` registers it for a project in Claude Code's `.mcp.json` and Codex's `config.toml`, merging into existing configuration (other servers kept, a different `opv` entry refused unless `--force`, no value or credential written; npm installs register the shared `~/.local/bin/opv`).

### Changed

- `opv run` on an environment with `confirm_env = true` (production, typically) needs `--confirm <env>`, as `opv sync` does, before its values reach a local process; nothing is read without it. `--preview` needs none.
- `opv bootstrap --ci-reader <env>` steps first to `opv access <env> --create --github <owner/repo>` (token stored without being shown); the raw `op service-account create` command remains for other CI providers.
- The generated and documented GitHub Actions workflow pins `superfly/flyctl-actions/setup-flyctl@1.6` instead of `@master`.
- The separate `opv-mcp` binary is removed (FR-60, one way only): run `opv mcp serve` instead; `opv mcp install` rewrites an assistant's entry with `--force`.

### Fixed

- `opv access` reported a vault outside the selected account as "not visible" and printed an `Owner runs:` command that could not succeed. It now reports `not in this account` with a `vault_not_in_account` finding (next: `opv vault locate`) and prints no such command (#153).
- One account order everywhere: `OP_ACCOUNT` (set by `opv login --account` for its command), then `.opv`, then the only account. `opv login --account B -- opv check` ran against `.opv`'s account before. A non-ID account value is resolved to one account ID (ambiguous values are refused), no account is passed beside a service-account or Connect credential, and the automatic sign-in signs in to the account of the call that failed.
- A bare `OP_SESSION` variable is reported (`stale_session_variable`) and refused by the MCP structural apply, like `OP_SESSION_<name>`.
- `opv_deployment_plan` reported every row's action as `review`: it now maps the plan's own actions (`write`, `unset`, `hold`, `none`), names each row's target and returns the `approve_command`.
- In WSL with the Windows `op.exe`, sign-in and account steps point to the Windows 1Password app instead of `opv login --add`, which cannot reach the app's accounts there.
- Minted tokens (`opv access --create`, `opv target credentials --create`) are registered with the output scrubber the moment they exist.
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

[Unreleased]: https://github.com/matt-cochran/1password-vault/compare/v0.16.0...HEAD
[0.16.0]: https://github.com/matt-cochran/1password-vault/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/matt-cochran/1password-vault/compare/v0.14.1...v0.15.0
[0.14.1]: https://github.com/matt-cochran/1password-vault/compare/v0.14.0...v0.14.1
[0.14.0]: https://github.com/matt-cochran/1password-vault/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/matt-cochran/1password-vault/compare/v0.12.3...v0.13.0
[0.12.3]: https://github.com/matt-cochran/1password-vault/compare/v0.12.2...v0.12.3
[0.12.2]: https://github.com/matt-cochran/1password-vault/compare/v0.12.1...v0.12.2
[0.12.1]: https://github.com/matt-cochran/1password-vault/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/matt-cochran/1password-vault/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/matt-cochran/1password-vault/compare/v0.10.1...v0.11.0
[0.10.1]: https://github.com/matt-cochran/1password-vault/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/matt-cochran/1password-vault/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/matt-cochran/1password-vault/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/matt-cochran/1password-vault/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/matt-cochran/1password-vault/compare/v0.6.1...v0.7.0
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
