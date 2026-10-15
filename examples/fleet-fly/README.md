# A fleet on Fly, from a fresh 1Password account

Two products (`api`, `worker`), three environments (`dev` for local runs, `staging` and `prod` on Fly), one shared database URL. Every step below is a command you can paste; nothing here needs a value in your terminal, your chat with an assistant, or a file.

## 1. Install and pick the account

```sh
opv doctor                 # op and flyctl present? it says where they are if not on PATH
opv account list           # the 1Password accounts this CLI knows, and which one is selected
opv login --add            # add your account here if it is not listed (1Password's own prompt)
opv account use you@example.com   # record it for this project in .opv (commit .opv)
```

On WSL, the Linux 1Password CLI does not see the Windows app's accounts: `opv login --add` adds yours to the Linux CLI once. On macOS and Windows the CLI uses the app's accounts (turn on Settings > Developer > Integrate with 1Password CLI).

## 2. Create the vaults, items and fields

Copy [secrets.toml](secrets.toml) into your repository, change the Fly app names, then:

```sh
opv bootstrap --dry-run    # per environment: what will be created or checked
opv bootstrap              # vaults <project>-<env>, items, every declared field (empty); records the boundary and state vault IDs
```

If an environment's IDs belong to another account, bootstrap stops (`ids_not_in_account`) and names both fixes: `opv account use <ID>` for the owning account, or `opv bootstrap --rebind <env>` to start that environment in this account.

## 3. Fill the values, see what is left

```sh
opv ready                  # environment x product grid, each empty or failing key, who acts next
opv open shared/DATABASE_URL --env staging   # opens the field in 1Password; type the value there
opv ready                  # repeat until nothing needs attention
```

Already have the values in `.env` files? `opv adopt staging --from .env.staging` shows what would come in; add `--apply` to write it (filled fields are never replaced without `--replace`).

## 4. Run locally

```sh
opv check dev --product api
opv run dev --product api -- npm run dev
```

## 5. First protected deploy

```sh
opv plan staging                              # what the sync would stage, and its plan id
opv sync staging --deploy --expect-plan <id>  # exactly that plan, then deploy
opv plan prod
opv sync prod --deploy --expect-plan <id>     # prod is guarded: the reviewed id is the confirmation
```

## 6. CI

```sh
opv bootstrap --ci-reader staging   # prints the owner's commands for a read-only CI service account
```

That read-only reader is for validation jobs (`opv check`, `opv plan`, `opv ready`); it cannot write delivery evidence. A job that syncs or deploys uses the target's own deploy identity instead, which reads the boundary vaults and reads and writes only that target's state vault:

```sh
opv access staging --target web     # prints the owner's create command for the web target's deploy identity
```

Give each job only the token it needs (`OP_SERVICE_ACCOUNT_TOKEN`) and, for deploys, a `deploy_credentials` item with a Fly deploy token for that one app ([configuration](../../docs/configuration.md#account-and-deploy-credentials)). Keep an old token until its replacement has recorded verified delivery evidence (`opv delivery verify staging --product <p>`). The CI job itself is in [usage](../../docs/usage.md#github-actions-example); to manage the repositories' own CI secrets from 1Password, see [examples/github-ci](../github-ci/).
