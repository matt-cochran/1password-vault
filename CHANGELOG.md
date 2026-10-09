# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - Unreleased

Azure and Kubernetes targets, a more resilient CLI, and one install location. Check **Changed**
before upgrading.

### Added

- Azure target: `[environments.<env>.azure]` syncs secrets to Key Vault and binds them to a Container App ([#39](https://github.com/matt-cochran/1password-vault/issues/39); FR-28 to FR-33). Secrets are written as new versions and the app uses them only after `opv sync <env> --deploy`; `--prune` removes old entries only after a healthy revision. See [usage](docs/usage.md#sync-on-azure-and-kubernetes).
- Kubernetes target: `[environments.<env>.kubernetes]` stores values as immutable Secrets and updates a Deployment through `kubectl` (FR-38).
- Plug-in providers: Fly, Azure and Kubernetes implement one contract, so a new provider is one module ([CONTRIBUTING.md](CONTRIBUTING.md#adding-a-provider); FR-37).
- Resilience (NR-1 to NR-30): reads retry up to 3 times, writes never; progress lines during waits; `--timeout <secs>` (default 900) caps a run; `--verbose` prints one line per external call; every mutating run ends with a summary and every failure with one `Next:` line; Ctrl-C and SIGTERM leave the target safe to re-run (exit 130/143).
- Exit code 9: outcome unknown, or a provider did not answer. Nothing is known to be broken; re-run the same command.
- `opv completions <bash|zsh|fish|powershell>` prints a shell completion script ([usage](docs/usage.md#shell-completion)).
- `OPV_CONFIG` sets the default for `--config`; `OPV_PRODUCT` sets the default for `--product` on `check`, `run`, `doctor` and `explain` (fleet profile, never `sync`), reported on stderr when used.
- `--color auto|always|never`: state words are coloured on a terminal; `NO_COLOR` is honoured and piped output is unchanged.
- Every command's help groups `Global options:` and ends with examples; exit-code help names Fly, Azure and Kubernetes. `config export` no longer needs `--json` (still accepted).
- `confirm_env = true` on an environment requires `--confirm <env>` for `sync`.
- `opv doctor` lists every `opv` on `PATH` and warns about more than one; it checks `az` (2.60 or newer) and `kubectl` for environments that use them. <!-- verify -->
- `opv session` and `opv setup`: guided sign-in and resumable project onboarding ([guided setup](docs/guided-setup.md); [#63](https://github.com/matt-cochran/1password-vault/pull/63)).
- `opv sync` checks the Fly app before its first write (`flyctl status`, `flyctl releases`): a deleted (`dead`) app or a deploy already running stops it with nothing written and the next step; suspended, pending or stopped-machine apps print a `warn` line and staging goes ahead, and `--deploy` is skipped with a notice when the app has no machines (NR-23, NR-24).
- `opv doctor --env <env> [--product <p>]` reads the item once by IDs and reports `ok item: <vault>/<item> readable (<n> field(s) in section <p>)`, or a failing line naming each key that is not ready and `opv check` as the next step, so doctor is never all clear when `check` would fail. `opv doctor --json` prints `{schema_version, checks: [{name, status, detail, next}], next}`.
- `opv explain KEY` resolves the product when only one declares the key, lists the candidates when several do, and suggests close names for an unknown key or product.
- After staging, `sync` re-reads Fly's list for up to 30 seconds until every staged name shows a digest, so a lagging list is never reported as unchanged (NR-30).

### Changed

- A 1Password or Fly read that gets no answer after 3 attempts exits 9 naming the provider, the step and its status page (status.1password.com, status.flyio.net); nothing was changed. It was exit 4 (1Password) or 5 (Fly) (NR-28).
- With no `secrets.toml`, opv offers both ways to start: `opv init` for an existing 1Password item, `opv setup` for a new project. `opv setup` without `opv.setup.toml` points to the generic recipe and the command that uses it.
- On an interactive terminal the sign-in advice is `opv session   (or: eval $(op signin))`; CI and service-account wording is unchanged.
- A failing `enum` rule lists the declared values: `failed enum (expected one of: debug, info)`, never the stored value.
- A failed item read is diagnosed (`op whoami`, `op vault get`) before it is retried; it is retried only when signed in with access to the vault, so a wrong ID or a missing sign-in is reported at once instead of after two retries.
- `doctor` reports a missing `op` once (the sign-in check is skipped), an older `op` with an upgrade command, and no longer repeats a long failure (a TOML error) in its final error line.
- A failed item read while signed in now tells removed vault access from a moved, archived or deleted item (`op vault get <vault_id>`, by ID), with the next command (NR-26).
- A `sync` refusal ends with the `opv explain` command for the blocking keys (NR-17). A sign-in lost after `sync` wrote something names the writes that completed (NR-10).
- npm and `install.sh` install to the same place (`~/.local/bin/opv`, or `%LOCALAPPDATA%\Programs\opv\opv.exe` on Windows), so either can update the other's copy ([install](docs/install.md#one-install-location)).
- `status` and `plan` start with a one-line count summary; rows are unchanged. On clouds they gain optional `binding`, `pending_deploy` and `drift` fields in `--json`; `schema_version` stays 1. <!-- verify -->
- `opv doctor` no longer warns for a later `flyctl` patch release in the tested minor (0.4.113 and up). Another minor, or a patch older than 0.4.112, still warns.
- Every external call names its scope explicitly (Azure `subscription`, Fly `--app`, Kubernetes `--context` and `--namespace`) and runs with a pinned environment, so your default subscription or CLI settings no longer matter.

### Fixed

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
