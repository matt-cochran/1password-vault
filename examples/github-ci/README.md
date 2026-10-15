# CI secrets in GitHub Actions, from 1Password

This example keeps the secrets and variables of two repositories (`my-org/api`, `my-org/web`) in one 1Password item and lets `opv sync` set them. One Fly token and one Cloudflare account ID live once, in a `shared` section, and feed both repositories.

| File | What it is |
|---|---|
| [secrets.toml](secrets.toml) | the configuration: two `github` environments, a `source_only` product for shared values |
| [sync-ci-secrets.yml](sync-ci-secrets.yml) | a workflow for an operations repository that syncs both on demand and weekly |

## Set it up

1. **Values.** In 1Password, create vault `ci` and item `ci values` (or run `opv init ci-api --vault ci --item "ci values"`, which creates them and writes the IDs, then `opv target add ci-api app --github-repo my-org/api` for its target). Then fill in the fields opv asks for:

   ```sh
   opv item skeleton ci-api   # adds empty fields: shared/FLY_API_TOKEN, api/NPM_TOKEN, ...
   opv status ci-api          # one row per key; fill what is missing in 1Password
   ```

2. **The token opv writes with.** Create a fine-grained GitHub token limited to `my-org/api` and `my-org/web`, with **Secrets: write**, **Variables: write** and **Environments: read**. Save it in 1Password as item `github-secrets-writer` in vault `ci`, in a concealed field named `GH_TOKEN`. Never use an owner or classic token.

3. **The GitHub environment.** `ci-web` writes the `production` environment of `my-org/web`. Create it in the repository (Settings → Environments) with the protection rules you want; opv never creates it.

4. **Check, then sync from your machine.**

   ```sh
   opv plan ci-api            # names and states only: new / same / changed / unknown
   opv sync ci-api            # writes; nothing to deploy, values are live at once
   opv sync ci-web --prune    # also deletes managed names no longer declared
   ```

5. **Automate (optional).** Copy `sync-ci-secrets.yml` to `.github/workflows/` of an operations repository, and give it one secret, `OP_SERVICE_ACCOUNT_TOKEN`, for a service account with read access to vault `ci`.

## What to expect

- Secrets show `unknown` in `status`: GitHub never reveals a secret's value, so `sync` writes each one again. Variables are compared, so they show `same` when nothing changed.
- `prune` touches only names this configuration declares. Secrets set by other tools are listed as unmanaged and never changed.
- To rotate the Fly token for both repositories, change `shared/FLY_API_TOKEN` in 1Password and run both syncs.

Reference: [GitHub Actions target](../../docs/configuration.md#github-actions-repository-and-environment-secrets), [shared values](../../docs/configuration.md#one-home-for-shared-values-source_only-products).
