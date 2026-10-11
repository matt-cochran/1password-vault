# Live smoke kit for opv 0.5.0

Runs the real CLI against disposable targets, once, with the owner's approval. It proves the Azure, Kubernetes and Key Vault -> Kubernetes (External Secrets Operator) paths end to end. It is not part of CI.

## Disposable resources

| Resource | Name | Passed in as |
|---|---|---|
| Azure resource group | `opv-spike-rg` | `OPV_SMOKE_AZ_RG` |
| Azure Key Vault (sandbox) | recreated per the Azure spike | `OPV_SMOKE_AZ_KEY_VAULT` |
| Container App | `opv-spike-app` in environment `opv-spike-env2` | `OPV_SMOKE_AZ_APP` |
| Azure subscription | the sandbox subscription | `OPV_SMOKE_AZ_SUBSCRIPTION` |
| kind cluster / namespace / Deployment | `kind-opv` / `opv-spike` / `api` | `OPV_SMOKE_K8S_CONTEXT`, `_NAMESPACE`, `_DEPLOYMENT` |
| ClusterSecretStore | `prod-vault` (ESO, backed by the sandbox vault) | `OPV_SMOKE_ESO_STORE` |
| 1Password account | the one holding the disposable item (email or account ID); opv never falls back to op's default | `OPV_SMOKE_OP_ACCOUNT` |
| 1Password item | disposable, section `smoke`, concealed `DB_URL` and `API_TOKEN`, text `LOG_LEVEL` | `OPV_SMOKE_OP_VAULT_ID`, `OPV_SMOKE_OP_ITEM_ID` |

Fly is not exercised. Do not add a `fly` section unless a disposable Fly app is named by the owner.

## Prerequisites

- `opv` 0.5.0 on PATH (or `OPV_BIN=/path/to/opv`), `op` signed in to that account (`op signin --account <account>`), `az` >= 2.60 logged in to the sandbox subscription, `kubectl`, `kind`, `script` (util-linux).
- The sandbox exists (Azure spike findings, K1 spike) and the Container App identity can read the Key Vault.
- The ESO operator is installed in the kind cluster and `ClusterSecretStore/prod-vault` is Ready (credential Secret from the temporary service principal `opv-spike-eso`).
- The 1Password item holds only marker values, all starting with one prefix, for example `OPVSMOKE-<random>`. Export `OPV_SMOKE_MARKER_PREFIX=OPVSMOKE-` so the script can prove the receipt holds none.

## Run

```sh
export OPV_SMOKE_OP_ACCOUNT=... OPV_SMOKE_OP_VAULT_ID=... OPV_SMOKE_OP_ITEM_ID=...
export OPV_SMOKE_AZ_SUBSCRIPTION=... OPV_SMOKE_AZ_KEY_VAULT=... \
       OPV_SMOKE_AZ_RG=opv-spike-rg OPV_SMOKE_AZ_APP=opv-spike-app
export OPV_SMOKE_MARKER_PREFIX=OPVSMOKE-
scripts/smoke/run.sh                       # all three; OPV_SMOKE_TARGETS="kubernetes" for one
```

Environments: `azure` (Key Vault + Container Apps), `kubernetes` (Secrets + Deployment), `eso` (`secrets_in = "prod-vault"`, so Key Vault feeds the Deployment through ExternalSecrets). Per environment: `doctor --env`, `check`, `plan`, `sync`, `sync --deploy`, `status`. Then the script pauses: change `smoke/API_TOKEN` in the disposable item by hand (the value is typed only in 1Password). After Enter: `plan`, `sync --deploy` (repin), `status`, and `sync --deploy --prune` against a copy of the config with `LOG_LEVEL` removed.

`verify-pinning.sh` checks the replica sees the pinned value by length only (set `OPV_SMOKE_EXPECT_LEN` to the marker's length, `OPV_SMOKE_VAR` to e.g. `FLEET__SMOKE__API_TOKEN`; use `ESO__SMOKE__API_TOKEN` for `eso`). Run it after phase one (old length) and again after the rotation (new length). Use a marker of a different length for the rotated value so a stale pin is visible. `OPV_SMOKE_SKIP_K8S=1` or `OPV_SMOKE_SKIP_AZ=1` limits it to one runtime. The `azure` and `kubernetes`/`eso` environments share one Deployment `api`; their variable names differ by template.

## Safety rules

- Marker values only. Never a real secret, never a production vault, app, cluster or subscription. `run.sh` refuses a non-`kind-*` context and a resource group or app not named `opv-spike*`.
- No Fly writes unless the owner names a disposable Fly app.
- No value is typed into, stored by or printed by these scripts. opv prints names and versions only; `verify-pinning.sh` prints lengths only.
- Stop on the first FAIL. Do not retry destructive steps (`--prune`) by hand; read the receipt first.

## Reading the receipt

`run.sh` prints `PASS`/`FAIL <step> (exit N)` per step and, on exit, `receipt: <tmpdir>/receipt.txt`. Each step in the receipt is `=== <label>: opv <args>`, the output, and `--- exit N (expected M)`. All expected exits are 0. Exit codes: 2 config, 3 dependency, 4 1Password, 5 target (including an unhealthy rollout), 6 refusal, 7 auth, 8 findings, 9 outcome unknown (safe to re-run). Paste the receipt into the PR and issue #39 after a skim for anything that is not a name or version. No smoke environment sets `confirm_env`, so `--confirm` is not needed. Then follow `teardown.md`.
