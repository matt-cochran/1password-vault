# Contributing

Thanks for helping. This page covers how to build, test and submit a change. Look for issues labelled `good first issue`, or open an issue to discuss a larger change before writing it.

```sh
git clone https://github.com/matt-cochran/1password-vault
cd 1password-vault
cargo build
```

## Prerequisites

- Rust 1.88 or newer (`rust-version` in `Cargo.toml`).
- `op` (1Password CLI) and `flyctl` are only needed for manual testing. The test
  suite uses fakes and does not call either tool.

## Checks

Run the same checks CI runs before opening a pull request:

```sh
cargo fmt --all --check
cargo clippy --all-targets --features fake -- -D warnings
cargo test --locked --features fake
cargo deny check
```

When you change `install.sh`, also run:

```sh
shellcheck install.sh
bash tests/install/test_install.sh
```

## Branch flow

Target your pull request at `dev`, never at `main`.

```text
feature branch → dev → staging → main
```

`gitflow-guard` enforces this topology. `main` only accepts pull requests from
`staging`, and `staging` only accepts pull requests from `dev`.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/). Cite the
requirement IDs the change implements, for example `FR-12` or `SR-3` from
`docs/design/requirements.md`.

```text
feat(cli): find secrets.toml in parent directories (FR-25)
```

## Secret safety

These rules are non-negotiable. A secret value must never appear in:

- argv,
- logs,
- errors,
- `Debug` output,
- files.

Values travel on stdin to the vendor CLI, or, for `run`, in the child's environment through `op run`. New adapters and runners must include a
marker-value test that asserts no secret value reaches argv.

## Tests

Write atomic scenarios with declarative names and exactly one behavioural
assertion per test. Test observable outcomes. Fly behaviour is pinned by golden transcripts in
`tests/fixtures/characterization/`; a change that alters them must say why.

## Adding a provider

A provider is one module; no core code changes (FR-37, `docs/design/multi-cloud-targets.md` section 11).

1. Run a live spike first and save the real command outputs, with values replaced by markers, under `tests/fixtures/<provider>/`. Adapter tests use those recordings, never invented JSON. Write the findings in `docs/design/spike-<provider>-findings.md`.
2. Create `src/adapters/<provider>/` and implement the `Provider` and `TargetConfig` traits (config section, name rules, `open`, preflight, `doctor`, `explain`) plus the store and runtime ports. Send every subprocess through `CommandRunner` (`read` for reads, `write` for writes) and put values on stdin only.
3. Register it: `pub mod <provider>;` in `src/adapters/mod.rs` and one line in `src/adapters/registry.rs`.
4. Extend the guard test so `app/`, `domain/` and `config.rs` do not name the new module.
5. Add the marker-value test (no value in argv), a "converges after interruption at every call" test, and the docs: a section in `docs/configuration.md`, the prerequisite in `docs/install.md`, and the changelog.

## Design decisions

Requirements and design decisions live in `docs/design/`. A change that alters a
requirement updates `docs/design/requirements.md` in the same pull request.

## Releases

Maintainers bump the version and `CHANGELOG.md` on `dev`, promote through `staging`
to `main`, and push a `vX.Y.Z` tag; the release workflow builds, signs and publishes the
GitHub release. npm is published by hand afterwards with
`scripts/npm/publish-manual.sh vX.Y.Z`.

## Security

Do not report vulnerabilities in issues. Follow `SECURITY.md` for private
vulnerability reporting.
