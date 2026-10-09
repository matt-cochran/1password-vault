# Contributing

Thanks for helping. This page covers how to build, test and submit a change. Look for issues labelled `good first issue`, or open an issue to discuss a larger change before writing it.

```sh
git clone https://github.com/matt-cochran/1password-vault
cd 1password-vault
cargo build
```

## Prerequisites

- Rust 1.88 or newer (`rust-version` in `Cargo.toml`).
- `op` (1Password CLI), `flyctl`, `az` and `kubectl` are only needed for manual testing.
  The test suite uses fakes and recorded CLI output and calls none of them.
- Node.js, `shellcheck` and `bash` for the packaging and install-script checks.

## Checks

Run the same checks CI runs before opening a pull request:

```sh
cargo fmt --all --check
cargo clippy --all-targets --features fake -- -D warnings
cargo test --locked --features fake
cargo deny check
```

CI also runs the install-script and npm packaging checks:

```sh
shellcheck install.sh
bash tests/install/test_install.sh
node --test 'packaging/npm/**/*.test.js'
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
2. Create `src/adapters/<provider>/` and implement the `Provider` and `TargetConfig` traits (config section, name rules, `open`, preflight, `doctor`, `explain`, and `init_fields` / `init_section` so `opv init --target <provider>` can write the section) plus the store and runtime ports. Declare the provider's CLI as a `Tool` (install lines, status page, pinned environment, not-found phrases) and return it from `Provider::tools`: the runner, the `Next:` checks, the help text and the schema take it from the registry. Send every subprocess through `CommandRunner` (`read` for reads, `write` for writes, `Call::rollout` for a write that waits for a rollout) and put values on stdin only.
3. Register it: `pub mod <provider>;` in `src/adapters/mod.rs` and one line in `src/adapters/registry.rs`.
4. Extend the guard test so `app/`, `domain/` and `config.rs` do not name the new module.
5. Add the marker-value test (no value in argv), the interruption matrix (a run cut at every call converges on a clean re-run, and the cut run exits 0 or 9), and the docs: a section in `docs/configuration.md`, the prerequisite in `docs/install.md`, and the changelog.

## Documentation

Generate, don't guess: copy command output from a real run (the fake CLIs in the tests, or stub scripts), never from memory. Each fact has one home, and other pages link to it:

| Page | Holds |
|---|---|
| `README.md` | what opv is, the quick start, the target table |
| `docs/usage.md` | every command and flag, the JSON contract, exit codes |
| `docs/configuration.md` | configuration sources, the schema, every target section, rules |
| `docs/how-opv-handles-failures.md` | retries, time limits, exit 9, `Next:`/`Do:`, interruptions |
| `docs/local-development.md`, `docs/guided-setup.md` | the local and guided journeys |
| `docs/agent-setup.md`, `llms.txt` | the AI assistant journey; `opv guide agent` prints `agent-setup.md` from the binary |

`tests/docs_commands.rs` runs every `opv ...` line in a shell code block of these pages through the real parser, ties the GitHub Actions example's pin to `Cargo.toml`, and checks the error-code table in `docs/usage.md` against the code (regenerate it with `UPDATE_DOCS=1 cargo test --features fake --test docs_commands`).

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
