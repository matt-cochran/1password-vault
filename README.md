<p align="center">
  <img src="docs/assets/opv-header.webp" alt="opv bridges secrets from a 1Password vault to local development (shell, IDE, Docker), Fly.io, Azure, Kubernetes, AWS and GCP: opv run dev -- npm run dev" width="100%">
</p>

# opv

[![CI](https://github.com/matt-cochran/1password-vault/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/matt-cochran/1password-vault/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/matt-cochran/1password-vault)](https://github.com/matt-cochran/1password-vault/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV 1.88](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](Cargo.toml)

Sync secrets from 1Password into the places your apps run, without ever printing, logging or writing a value.

1Password owns the values. Your runtime consumes them. `opv` connects the two and nothing else: no server, no state, no encryption of its own, and no command that prints a secret. What to sync lives in a committed `secrets.toml` that holds IDs and validation rules, never values.

```console
$ opv status prod
PRODUCT   KEY                  KIND    STATE    TARGET
allumata  INTEGRATION_ENC_KEY  secret  saved    absent
allumata  OPENAI_API_KEY       secret  saved    absent
allumata  SIGNUP_POLICY        config  saved    -
allumata  STRIPE_SECRET_KEY    secret  skipped  absent
3 saved, 2 not yet on Fly (staged by the next sync), 0 findings
```

## Why

- **Values stay out of your tooling.** They travel only on stdin to the official `op` and target CLIs: never in argv, files, logs, errors or CI output.
- **Typed and checked before they ship.** Each key declares its kind (secret or config) and rules (`prefix`, `base64_bytes`, `enum`, `https_url`, ...). A bad value fails `status` with the key, the rule and a reason, never the value.
- **Explicit, never surprising.** No prompts. Nothing is deployed without `--deploy`, nothing is deleted without `--prune`, and prune only touches names opv declares.
- **Cheap in CI.** Each environment is read from 1Password once, by ID, so a sync costs a few requests with a read-only service account.

## Targets

| Target | Status |
|---|---|
| Fly.io | supported |
| Azure (Key Vault + Container Apps) | supported <!-- verify: preview until the live receipt in #39? --> |
| Kubernetes (Secrets + Deployment) | supported |
| Azure App Service | planned ([#40](https://github.com/matt-cochran/1password-vault/issues/40)) |
| AWS (Secrets Manager + ECS) | planned ([#41](https://github.com/matt-cochran/1password-vault/issues/41)) |
| GCP (Secret Manager + Cloud Run) | planned ([#42](https://github.com/matt-cochran/1password-vault/issues/42)) |

Each environment names one target in `secrets.toml`; every command is the same for all of them ([configuration](docs/configuration.md#targets)). On Azure and Kubernetes a secret is written as a new version and the app keeps the old one until you run `sync --deploy`.

For local development, `opv run dev -- <command>` starts any command with the environment's keys set as variables, through `op run`, with no `.env` file ([patterns](docs/usage.md#local-development)).

## Guided local setup

`opv session` and `opv setup` handle sign-in and resumable project onboarding, with plain instructions and private input. See [guided setup](docs/guided-setup.md) and the [CLI interaction review](docs/cli-ux-review.md).

## Quickstart

Install on Linux or macOS ([docs/install.md](docs/install.md) covers npm, Windows, source builds and checksum verification):

```sh
curl -fsSL https://raw.githubusercontent.com/matt-cochran/1password-vault/main/install.sh | sh
```

Then, with `op` and your target CLI (`flyctl`, `az` or `kubectl`) signed in:

```sh
opv init staging --vault myapp-staging --item myapp --fly-app myapp-staging   # starter secrets.toml from an existing item
opv doctor                     # config, op, flyctl and sign-in; ends with the next step
opv status staging             # one row per key: saved, missing, wrong kind or failing a rule
opv plan staging               # what a sync would stage, hold and prune; changes nothing
opv sync staging --deploy      # stage on the target, deploy only if something changed
opv check staging              # every key saved? names only, no deployment target touched
opv run staging -- ./server    # run a process with the secrets in its environment
```

A minimal `secrets.toml` for one app per environment:

```toml
[profile]
kind = "simple"

[environments.staging]
vault_id = "vstg1234example"     # IDs, not names
item_id  = "istg1234example"
fly.app  = "myapp-staging"

[keys.DATABASE_URL]
kind = "secret"
environments = ["staging"]

[keys.JWT_KEY]
kind = "secret"
environments = ["staging"]
immutable = true                 # never overwritten unless you pass --rotate
rules = { base64_bytes = 32 }
```

## Documentation

- [Installing](docs/install.md): install script, release binaries, npm, from source, verifying downloads, prerequisites.
- [Configuration](docs/configuration.md): store layout, `secrets.toml`, the fleet and simple profiles, `opv init`, rules and failure reasons.
- [Local development](docs/local-development.md): local-only environments, `opv check`, switching products, WSL.
- [Usage](docs/usage.md): every command, how sync works on Fly, Azure and Kubernetes, JSON output, pruning, retries, exit codes, security model, GitHub Actions.
- [Setting up with an AI assistant](docs/agent-setup.md): a step-by-step procedure and safety rules for Claude Code, Codex, Cursor and similar; [llms.txt](llms.txt) indexes the docs for them.
- [Design](docs/design/): requirements, design decisions and plans, for contributors.
- [Changelog](CHANGELOG.md).

## Security

Values are held in redacting, zeroizing types and travel only on stdin or in a child process's environment. The stderr of `op`, `flyctl`, `az` and `kubectl` is suppressed because it could echo a value. `config export` prints config-kind values by design, and `run` hands secrets to the process you start. The full model and its limits are in [docs/usage.md](docs/usage.md#security-model-and-limits).

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in a public issue.

## Contributing

Contributions are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) covers the checks, the branch flow and the secret-safety rules every change must keep. This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

The repository is named `1password-vault` for historical reasons; the tool is `opv`. It borrows its workflow from [significa/1password-secrets](https://github.com/significa/1password-secrets) and none of its code; the behaviours it deliberately rejects are listed in the [requirements](docs/design/requirements.md).

## License

[MIT](LICENSE)
