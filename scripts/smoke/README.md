# Live smoke kit for opv 0.5.0

One command runs the real CLI against the disposable sandbox and proves the Azure (Key Vault + Container Apps), Kubernetes (Secrets + Deployment) and Key Vault → Kubernetes (External Secrets) paths end to end. It is run by hand before a release, not in CI.

## Run

```sh
op signin --account you@example.com          # the only interactive step
scripts/smoke/run.sh --account you@example.com
```

`OPV_SMOKE_TARGETS="kubernetes"` runs one environment; `OPV_BIN=/path/to/opv` tests a build that is not on `PATH`. `--vault <vault ID>` uses an existing vault when the account cannot create one.

## What it does

1. Finds the sandbox: the subscription from `az account show`, the one Key Vault in `opv-spike-rg`, and the defaults below.
2. Creates a vault `opv-smoke-<random>` and an item holding random markers (`OPVSMOKE-…`) in section `smoke`: concealed `DB_URL` and `API_TOKEN`, text `LOG_LEVEL`. The item JSON goes to `op` on stdin, never as an argument or a file.
3. Per environment (`azure`, `kubernetes`, `eso`): `doctor --env`, `check`, `plan`, `sync`, `sync --deploy`, `status`, then checks the running app sees `API_TOKEN` at its marker's length.
4. Rotates `API_TOKEN` to a marker of a different length, then per environment: `plan`, `sync --deploy` (repin), `status`, the length check again, and `sync --deploy --prune` with `LOG_LEVEL` removed from the config, checking the app no longer has it.
5. Checks the receipt holds no marker, and on every exit, pass or fail, deletes the test item and vault.

It stops on the first failure. Read the receipt before re-running a prune by hand.

## Sandbox

| Resource | Default | Override |
|---|---|---|
| Azure resource group | `opv-spike-rg` (Key Vault, Container Apps environment) | `OPV_SMOKE_AZ_RG` |
| Container App | `opv-spike-app`, system identity with read access to the Key Vault | `OPV_SMOKE_AZ_APP` |
| Subscription / Key Vault | discovered | `OPV_SMOKE_AZ_SUBSCRIPTION`, `OPV_SMOKE_AZ_KEY_VAULT` |
| kind context / namespace / Deployment | `kind-opv` / `opv-spike` / `api` | `OPV_SMOKE_K8S_CONTEXT`, `_NAMESPACE`, `_DEPLOYMENT` |
| ClusterSecretStore | `prod-vault` (External Secrets, backed by the Key Vault) | `OPV_SMOKE_ESO_STORE` |

Tools: `opv` 0.5.0, `op`, `az` logged in to the sandbox subscription, `kubectl`, and `script` (util-linux) for `az containerapp exec`.

## Safety

- The script refuses a non-`kind-*` context and a resource group or app not named `opv-spike*`.
- Markers only, generated per run. Nothing prints a value: opv prints names and versions, and the app checks print lengths.
- No Fly writes.

## Reading the receipt

The script prints `PASS`/`FAIL` per step and, on exit, `receipt: <tmpdir>/receipt.txt`. Each opv step is recorded as `=== <label>: opv <args>`, the output, and `--- exit N (expected 0)`. Exit codes: 2 config, 3 dependency, 4 1Password, 5 target (including an unhealthy rollout), 6 refusal, 7 auth, 8 findings, 9 outcome unknown (safe to re-run). Paste the receipt into the release PR and issue #39. When the sandbox is no longer needed, follow `teardown.md`.
