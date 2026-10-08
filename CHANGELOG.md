# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.4.0]: https://github.com/matt-cochran/1password-vault/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/matt-cochran/1password-vault/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/matt-cochran/1password-vault/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/matt-cochran/1password-vault/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/matt-cochran/1password-vault/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/matt-cochran/1password-vault/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/matt-cochran/1password-vault/releases/tag/v0.1.0
