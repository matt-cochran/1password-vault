# Using opv

Every command and flag, what each prints, the JSON contract and the exit codes. `opv <command> --help` shows the same for the version you run, and `opv schema` prints it as JSON. Where the configuration comes from and what it holds is in [configuration](configuration.md); retries, exit 9, `Next:`/`Do:` and interruptions are in [how opv handles failures](how-opv-handles-failures.md).

## Commands

| Command | What it does | Changes |
|---|---|---|
| `opv login [<env>] [--add] [--account <a>] [-- <cmd>]` | sign in to the environment's 1Password account: a signed-in terminal, or one command | nothing; needs your own terminal |
| `opv adopt <env> --from <file.env>\|target [--replace <p/KEY>]... [--apply] [--json]` | bring values that exist elsewhere into the item, after review | with `--apply`: the 1Password item |
| `opv ui` | browse and manage every environment, product and key in a terminal UI; actions run these same commands behind plan and confirmation | what you confirm |
| `opv tidy <env> [--json]` | put the environment's 1Password item in opv's layout: one verified edit, nothing deleted ([store layout](configuration.md#store-layout)); a person signed in with their own session only | the 1Password item's layout |
| `opv history <env> [--json]` | what opv last wrote to the target, per key: time, plan id, changed outside opv ([usage](#write-history-opv-history)) | nothing (read-only) |
| `opv access [<env>] [--target <t>] [--json]` | who needs each boundary and target, and who can read it now; the owner's command to create a reader ([usage](#who-can-read-each-vault-opv-access)) | nothing (read-only) |
| `opv delivery verify <env> [--product <p>] [--target <t>] [--receipt <file>] [--json]` | does every placement of a product still hold what opv delivered ([usage](#delivery-receipts-opv-sync---receipt-and-opv-delivery-verify)) | nothing (read-only) |
| `opv ready [<env>] [--json] [--save <file>]` | one receipt: every environment × product, findings, who acts and the next step | nothing |
| `opv version [--json]` | opv's version and each CLI it runs (op, flyctl, az, kubectl, gh): installed with its version, missing or unknown, and which ones this project's configuration uses; no sign-in | nothing |
| `opv approve <plan_id>` | in your own terminal: review the structural plan an assistant prepared through MCP and approve it once (15 minutes) | a local approval record |
| `opv bootstrap [--dry-run] [--rebind <env>] [--ci-reader <env>] [--json]` | create every missing boundary vault, item and state vault, record their IDs and add every declared field empty | 1Password and `secrets.toml` |
| `opv target add <env> <name> --<provider options> [--products <p>]... [--deploy-credentials <op://v/i>] [--dry-run] [--json]` | declare one named target, infer its provider from the options, create its state vault and record its ID ([usage](#add-a-target-opv-target-add)) | the configuration and 1Password |
| `opv target list [--env <env>] [--json]` | the declared targets: provider, locator, products, deploy identity and state vault ([usage](#add-a-target-opv-target-add)) | nothing (read-only) |
| `opv account list [--account <a>] [--json]` | the 1Password accounts this CLI knows, which one the project uses, what to do next | nothing |
| `opv account use <email or ID>` | record the project's account in `.opv`, without a prompt | `.opv` |
| `opv setup [--product <p>] [--recipe <file>] [--account <a>]` | guided, resumable onboarding from `opv.setup.toml` ([guided setup](guided-setup.md)) | the 1Password item; needs your own terminal |
| `opv doctor [--env <env> [--product <p>]] [--json]` | find setup problems and show the next step | nothing |
| `opv check <env> [--product <p>] [--json]` | are the keys saved and valid? no target is contacted | nothing |
| `opv status [<env>] [--product <p>] [--all] [--json] [--target <name>]` | 1Password and every target side by side, names only | nothing |
| `opv plan <env> [--product <p>] [--json] [--target <name>]` | what a sync would do on every target, and its one plan id | nothing |
| `opv sync <env> [--deploy] [--prune] [--expect-plan <id>] [--confirm <env>] [--product <p>] [--json] [--target <name>]` | write to every target; deploy only with `--deploy` | the targets |
| `opv run <env> [--product <p>] -- <cmd>` | run a command with the keys as environment variables ([local development](local-development.md)) | nothing |
| `opv explain <[product/]KEY> [--env <env>] [--json]` | what the configuration says about one key | nothing |
| `opv open <[product/]KEY> [--env <env>] [--print] [--json]` | open the key's item in 1Password, where its value is typed | nothing |
| `opv init <env> [--vault <title>] [--item <title>] [--product <p>]` | configuration (boundaries and products) from an existing item; no target ([configuration](configuration.md#start-from-an-existing-item-opv-init)) | the manifest or `secrets.toml` |
| `opv init <env> --from <file.env> [--config-key KEY]... [--secret-key KEY]... [--apply]` | start from an existing `.env`: declare every key, then import the values, verified ([configuration](configuration.md#start-from-an-existing-env-opv-init---from)) | with `--apply`: the configuration and the item's fields |
| `opv add <[product/]KEY> --kind secret\|config [...]` | declare a key, or add environments to one | the configuration |
| `opv item skeleton <env> [--json]` | add every missing declared field to the item, empty | the 1Password item |
| `opv config export [<env>] [--toml\|--json]` | print the configuration, or an environment's config values | nothing |
| `opv config import --vault <v> [--file <f>] [--project <p>] [--path <dir>]...` | save a `secrets.toml` as the project manifest | 1Password (a new manifest) |
| `opv config edit` | edit, validate, diff and save the configuration | the configuration; needs your own terminal |
| `opv config check --file <f>` | compare a committed copy with the manifest | nothing |
| `opv projects [--account <a>] [--long] [--json]` | projects whose configuration lives in 1Password | nothing |
| `opv help states`, `opv help <command>` | what each state word means; a command's help | nothing |
| `opv completions <bash\|zsh\|fish\|powershell>` | a shell completion script | nothing |
| `opv schema` | the installed binary as one JSON document | nothing |
| `opv guide agent` | the setup guide for AI assistants, for this version | nothing |
| `opv skill install [--target claude\|codex\|all] [--user\|--project <dir>] [--force]` | install the agent skill (versioned with this binary) where coding agents look | the skill files |
| `opv skill status [--json]` | installed skill copies: version, current or older, edited | nothing |

"Nothing" means nothing on your targets and no change to what a value means. Run by a person signed in with their own session, a command that reads an item (except `doctor` and `ready`, which never write; `opv schema` marks the others `tidies_1password`) may also tidy its 1Password layout once (missing sections and empty fields, labels, duplicates; nothing is deleted, [store layout](configuration.md#store-layout)); a service account, Connect, CI or a run under `deploy_credentials` never writes to 1Password.

`sync` also takes `--rotate <product/KEY>` and `--prune-immutable <product/KEY>` for immutable keys (both repeatable, shown by `--help`, not `-h`; [below](#status-plan-and-sync)).

### Global options and environment

| Option | Environment | Meaning |
|---|---|---|
| `--config <PATH>` | `OPV_CONFIG` | use this `secrets.toml`; otherwise the configuration is [discovered](configuration.md#how-opv-finds-the-configuration) and stderr says `using ...` |
| | `OPV_PROJECT` | use the manifest of this project (`opv · <name>`) |
| | `OP_ACCOUNT` | the 1Password account to find a manifest in (an environment's own `account` is used for its reads) |
| | `OPV_PRODUCT` | default for `--product` on `check`, `run`, `open`, `explain`, `status`, `plan` and `doctor --env`, never `sync`; stderr says `product <p> (from OPV_PRODUCT)` |
| `--timeout <SECS>` | | budget for the whole run (default 1800); see [time limits](how-opv-handles-failures.md#time-limits-and-progress) |
| `--verbose` | | one stderr line per call to `op` or the target CLI, with its scrubbed stderr |
| `--color auto\|always\|never` | `NO_COLOR` | colour state words (`ok`, `warn`, `FAIL`, `saved`, `missing`, ...) on a terminal; JSON and values never |

A typical session:

```sh
opv login dev                         # sign in to dev's 1Password account; type exit to leave
opv doctor --env dev                  # what dev needs, plus one read of its item
opv check dev --product api           # api's keys saved and valid? no target touched
opv run dev --product api -- npm run dev
opv status                            # one line per environment
opv status staging                    # one row per key, problems first
opv plan staging                      # what a sync would write, hold and prune, and its plan id
opv sync staging --deploy --expect-plan 674d43e2   # exactly that plan, then deploy
```

## Status, plan and sync

An environment has one or more named targets. `status` shows what is missing or failing a rule, problems first, each with its reason and its declared `guidance`; the findings end with `Next: opv open <KEY>`, which opens the first key's item in 1Password. `plan` adds what a sync would do on every target and ends with the command that does it. `sync` writes. All three read each boundary item once, by IDs, and print names, never values.

Without `--target`, `status`, `plan` and `sync` cover every target of the environment. `plan` and `sync` use one plan id that names the targets it covers. `--target <name>` (repeatable) narrows the run to those targets. Every row carries its target in the `TARGET` column (JSON `target`), and the run starts with one count line per target, each starting `<env>/<target>:`.

```text
$ opv status prod
prod/web: 2 keys · 0 saved · 0 skipped · 2 findings · 0 not yet on Fly
TARGET  PRODUCT  KEY             KIND    STATE                                             ON TARGET
web     api      LOG_LEVEL       config  failed enum (expected one of: debug, info, warn)  n/a
web     api      OPENAI_API_KEY  secret  missing                                           unknown
    guidance: OpenAI platform / API keys
unknown: Fly does not reveal stored values, so opv cannot compare them; sync stages them and compares digests (opv help states)
opv: 2 findings
Do: fix the keys above in 1Password (click Edit on the item: it hides empty fields until then)
Next: opv open api/LOG_LEVEL --env prod
```

The count lines count the rows per target. `status`, `plan` and `check` exit 8 when a key is missing or failing a rule. On Azure and Kubernetes, `status` also prints when opv last changed the target (`Azure: last changed by opv 0.5.0 at 2026-10-08T14:02:11Z (plan 7f3c9a1e)`) and reports drift.

`sync` refuses (exit 6) and writes nothing while any key is missing or failing a rule, naming every blocking key and the `opv explain` command for them, and it checks the target read-only before its first write ([checks before the first write](how-opv-handles-failures.md#checks-before-the-first-write)). Nothing is deployed without `--deploy` and nothing removed without `--prune`. `--rotate <product/KEY>` (repeatable) writes an immutable key that is already on the target; `--prune-immutable <product/KEY>` (repeatable) lets `--prune` remove one. On Fly, values are staged with `flyctl secrets import --stage`, values on stdin.

### States

`status`, `plan` and `check` use one small set of words, the same on every provider. `opv help states` prints them. Each row's `STATE` column is the key in 1Password (JSON `state`); its `ON TARGET` column is the key on its deployment target (JSON `target_state`); the `TARGET` column names that target (JSON `target`).

| Column | Word | Meaning |
|---|---|---|
| STATE (1Password) | `saved` | stored and passes every rule; either field type is accepted (a config key stored concealed is delivered as a plain value, opv never prints its value, and `status` warns about it once) |
| | `missing` | no field with this name in the item's section |
| | `failed` | fails a rule; the rule and the reason follow: `failed enum (expected one of: debug, info)` |
| | `skipped` | not required in this environment |
| | `blocked by source` | shares another key's value and that key has a finding; fixed with it and not counted again ([Shared keys](#shared-keys)) |
| ON TARGET | `new` | not on the target yet; the next sync writes it |
| | `same` | on the target with the same value (Azure, Kubernetes; GitHub variables) |
| | `changed` | on the target with another value; the next sync writes it |
| | `unknown` | on the target, but the target does not reveal values, so opv cannot compare them; on Fly sync stages and compares digests, on GitHub it writes the secret again |
| | `pending` | written but not yet live; the next `sync --deploy` rolls it out |
| | `held` | immutable and already set; replace it with `--rotate` |
| | `extra` | on the target but not wanted in this environment; removed only with `--prune` (sync prints `extra, not pruned`) |
| | `drift` | the app is bound to something other than what opv last wrote |
| | `n/a` | not delivered to the target (config keys, except GitHub variables, and skipped keys that are not on the target) |

`missing` and `failed` are findings. In `status` and `plan` their rows come first, so a 40-key fleet with one problem shows it on the first table line. The JSON `state` and `target_state` fields keep their own spellings (below).

### Open a key in 1Password

```sh
opv open <[product/]KEY> [--env <environment>] [--print] [--json]
```

`status`, `plan` and `check` end their findings with `Next: opv open <KEY> --env <env>` for the first key to fix; `--json` rows carry the item link as `open_url`.

The link is 1Password's private item link, the form "Copy Private Link" produces: account, vault and item IDs and the sign-in host, never a value. 1Password links to items, not single fields, so the section and field are named next to it. opv takes the account from one free `op whoami` call; when that call fails the link has the vault and item only.

`opv open` resolves the key as `explain` does (a bare `KEY` under one product, `--env` optional with one environment), prints its section and field and the link, and opens the link with the desktop's opener: `xdg-open` (Linux with a display), Windows' `rundll32 url.dll,FileProtocolHandler` from WSL (else `wslview`), `open` (macOS) or `rundll32 url.dll,FileProtocolHandler` (Windows). The opener gets the link as its only argument; no shell is involved. Over SSH, under CI, on a machine without a display, or with `--print` it only prints the link, which is what an assistant should show its user. It never reads the item. A shared key (`from = ...`) opens its source's field. `--json` prints `{environment, product, key, section, field, open_url}` and opens nothing.

### Every environment: `opv status`

Without an environment, `status` prints one line per target of each environment, in name order (a run-only environment has none):

```text
dev: run-only · 6 keys · 5 saved · 0 skipped · 1 finding
prod/web: 14 keys · 13 saved · 1 skipped · 0 findings · 0 not yet on Fly
prod/p-overflow: 6 keys · 6 saved · 0 skipped · 0 findings · 0 not yet on Fly
staging/web: 14 keys · 11 saved · 1 skipped · 2 findings · 1 not yet on Fly
```

It reads each boundary item once per target, a run-only environment's too, so a green overview means every environment is green. An environment it cannot read is one line `prod: not checked (<error>)` and the others are still shown; the exit code is that error's, else 8 when any environment has findings (with `Next: opv status <env>`, or `opv check <env> --product <p>` for a run-only one, for the first), else 0.

`--product <p>` (or `OPV_PRODUCT`) counts only that product's keys in every line. `--json` prints one document instead, with one entry per environment that adds up its targets:

```json
{"schema_version":1,"ok":false,"exit_code":4,"product":null,"environments":[{"name":"dev","target":null,"state":"run_only","keys":6,"saved":5,"skipped":0,"findings":1,"error_code":null,"error":null,"next":null},{"name":"prod","target":"fly","state":"not_checked","keys":null,"saved":null,"skipped":null,"findings":null,"error_code":"vault_no_access","error":"source error: ...","next":"op vault get vprd0000000000000000000001"}],"totals":{"environments":2,"findings":1},"next":"op vault get vprd0000000000000000000001","do":"grant this identity access to the vault ..."}
```

(The failure's `error` object, last in the document, is left out above.)

`target` is the target section (`fly`, `azure`, `kubernetes`) or `null` for run-only; `state` is `checked`, `run_only` or `not_checked`. An environment that could not be read has `null` counts, its error code in `error_code`, the first line of its error in `error`, and in `next` the one command that runs as typed to get past it.

### Every project: `opv projects` and `opv status --all`

When configurations live in 1Password (see [configuration](configuration.md#configuration-in-1password)):

```text
$ opv projects
api: vault acme-dev; repo github.com/acme/platform; paths apps/api
web: vault acme-dev; repo github.com/acme/platform; paths apps/web
$ opv projects --long          # adds "environments dev, prod" (one read per project)
$ opv status --all
api (vault acme-dev):
  dev: run-only · 6 keys · 5 saved · 0 skipped · 1 finding
  prod: 14 keys · 13 saved · 1 skipped · 0 findings · 0 not yet on Fly
```

`projects` makes one metadata listing per 1Password account op knows (no manifest is read unless `--long`). `--account <email, account ID or sign-in address>` lists that account only, and so does `OP_ACCOUNT`, which `opv login --account <a> -- opv projects` sets for its command. `--json` names every account it asked in `accounts` (`account_id`, `sign_in`, `shorthand`, `status` `listed` or `failed`, `manifests`, `error_code`, `reason`; never an email), says which accounts with `scope` (`selected`, `all` or `default`), and gives each project its `account_id`. Several accounts can share one sign-in address (`my.1password.com`), so the account ID is what tells them apart. When any account could not be listed, `complete` is `false`: the projects that were listed are still shown, the text listing says `the inventory is incomplete`, and opv exits 4 with `inventory_incomplete`, whose `next` signs in to the first such account and lists it again. A project missing from an incomplete inventory may be in an account that was not read; it is not absent. `status --all` reports the same way. `status --all` reads each manifest once and then does what `opv status` does per environment, with the usual read retries; a project that cannot be read is one line `name (vault V): not read (<reason>)` and the others still run. `status --all --product <p>` (or `OPV_PRODUCT`) lists only the projects that declare `<p>` and counts only its keys. Its `Next:` is a command (never an error's prose) and names the project, so it runs from any directory: `Next: env OPV_PROJECT=myapp opv status dev`. In `--json`, an environment that could not be read carries that command as `next`. Both take `--json`. Names only, never values.

### Plan

`plan` starts with one count line per target, then one table whose rows name their target, then what a sync would do on each target, by name, and ends with the one sync command that applies exactly this plan:

```text
$ opv plan prod
prod/web: 4 keys · 0 findings · 1 to stage · 1 held (immutable) · 1 to prune · 1 unmanaged on Fly (never touched)
TARGET  PRODUCT   KEY                  KIND    STATE    ON TARGET
web     allumata  OPENAI_API_KEY       secret  saved    unknown
web     allumata  INTEGRATION_ENC_KEY  secret  saved    held
web     allumata  SIGNUP_POLICY        config  saved    n/a
web     allumata  STRIPE_SECRET_KEY    secret  skipped  extra
unknown: Fly does not reveal stored values, so opv cannot compare them; sync stages them and compares digests (opv help states)
prod/web: would stage: allumata/OPENAI_API_KEY (FLEET__ALLUMATA__OPENAI_API_KEY)
prod/web: would prune (needs --prune): allumata/STRIPE_SECRET_KEY (FLEET__ALLUMATA__STRIPE_SECRET_KEY)
prod/web: held (immutable): allumata/INTEGRATION_ENC_KEY (FLEET__ALLUMATA__INTEGRATION_ENC_KEY) (pass --rotate PRODUCT/KEY to replace)
plan 7f3c9a1e (1Password item v41): sync --expect-plan 7f3c9a1e applies exactly this plan and refuses if the item, the target or secrets.toml changed
Next: opv sync prod --deploy --prune --expect-plan 7f3c9a1e
```

`plan` covers every target of the environment under one plan id; `--target <name>` (repeatable) narrows it to those targets. On Azure and Kubernetes the line says `would write`. The `Next:` command carries the plan id (`--expect-plan`, which also stands for `--confirm` on a [guarded environment](#guarded-environments)), adds `--prune` only when something would be pruned, `--product` when you scoped the plan and `--target` when you narrowed the targets. When a key blocks the sync, `plan` lists it first with its `open:` link, says `would stage once the findings are fixed:`, exits 8 with `Do: fix the keys above in 1Password`, and its `Next:` line opens the first key in 1Password.

### Review, then apply exactly that plan: `--expect-plan`

`plan` prints a short plan id, and `plan --json` carries it as `plan_id`. Pass it to `sync` to apply exactly what was reviewed:

```sh
opv plan prod                                         # a person or reviewer reads it: plan 7f3c9a1e (...)
opv sync prod --deploy --expect-plan 7f3c9a1e         # applies it, or refuses if anything changed
```

`sync` re-derives the id from what it reads. If a teammate edited the 1Password item, another tool wrote or re-pinned a store version, or `secrets.toml` changed the plan, the id differs and `sync` refuses before any write (exit 6), naming the new id and the exact command to apply it:

```text
opv: policy denied: stale plan: the plan changed since 7f3c9a1e; it is now 1b2c3d4e (1Password item v42) (the 1Password item, the target or secrets.toml changed); nothing was changed
  review it, then apply exactly that plan with: opv sync prod --deploy --expect-plan 1b2c3d4e
Next: opv plan prod
```

- The id covers names, states, version ids and the item's version number, never a value or a digest of one, so it is safe to paste into a PR or chat. Any edit to the item changes it, even to a field this environment does not use.
- Nothing is stored: there is no plan file. A CI job can plan in a pull request and apply on merge with the id from the plan step.
- On a [guarded environment](#guarded-environments), `--expect-plan` is enough on its own: the id is bound to that environment.
- `--expect-plan` cannot be combined with `--rotate` or `--prune-immutable` (exit 2), because `plan` never shows a rotation.
- `sync --json` reports the id of the plan it applied as `plan_id`.
- An exit 9 (a deploy that timed out or lost its connection) is safe to re-run with the same id: what that run already wrote is the plan's own progress, not a change to it (values it staged that wait for a deploy on Fly, or versions stamped with this plan id on Azure and Kubernetes), so `sync --expect-plan <id>` still matches and finishes the deploy.

### Change detection on Fly

Fly digests cannot be computed locally, so opv cannot tell in advance whether a value changed. `sync` reads Fly's secret metadata, stages, reads it again and compares the digests. Fly's list can lag right after staging, so the second read is repeated (for up to 30 seconds, with a progress line on stderr) until every staged name shows a digest; a name still without one counts as changed. Without more, `plan` would show a desired key that is already on Fly as `unknown`; the version ledger closes that gap. After each confirmed write, the sync (yours or CI's) records in the placement's delivery item in the target's state vault each written name with the digest Fly gave it and a keyed fingerprint of the value (never the value). `plan` then compares exactly: a name Fly still holds at that digest is `same` when the 1Password value has not changed and `changed` when it has; a name whose digest changed since is reported as **changed outside opv** (someone set it on Fly; the next sync writes 1Password's value back). A name no sync has recorded yet, or a placement without a recorded delivery item, stays `unknown`. The same ledger makes GitHub secrets exact: one that is unchanged is no longer rewritten by every sync. An immutable key already on Fly is "held" and is not staged unless you pass `--rotate` for it. On Azure, opv reads each listed Key Vault secret and compares it exactly, so `plan` shows `same` or `changed` instead.

Staging uses stage semantics, so it coexists with other tools that stage secrets on the same Fly app. A deploy happens only with `--deploy`, and only when a staged digest changed, a prune happened, or a managed name is still pending on Fly (status Staged or Partial) from an earlier run. An app with no machines skips the deploy with a notice ([checks before the first write](how-opv-handles-failures.md#checks-before-the-first-write)).

### Sync on Azure and Kubernetes

On Azure and Kubernetes `sync` works in two steps, and the running app only changes in the second:

1. **Written.** Each changed secret is written to the store (Key Vault, or a Kubernetes Secret) as a new version. The app does not see it, even if it restarts or scales out, because it is bound to the old version.
2. **Deployed.** With `--deploy`, opv points the app at the new versions and sets any changed config, which starts a new revision (Container Apps) or rollout (Kubernetes). It then waits until that revision is healthy.

```sh
opv plan prod                            # what would be written and re-pinned; changes nothing on the target
opv sync prod                            # step 1 only: secrets written, app unchanged ("pending deploy")
opv sync prod --deploy                   # steps 1 and 2
opv sync prod --deploy --prune           # also remove names no longer wanted, after the app is healthy
```

- **Pending deploy.** `status` and `plan` show a key as pending when the store holds a newer version than the app uses. Config values are only ever set by `--deploy`, so they are pending until then.
- **Nothing changed.** If every store value matches 1Password and the app already uses the current versions, opv writes and deploys nothing, and creates no new version.
- **Healthy means ready.** After a deploy opv waits for the new revision to be ready and healthy (Container Apps: the latest ready revision reports `Healthy`; Kubernetes: `kubectl rollout status` succeeds and no new pod is stuck). If it is not healthy, the old revision keeps serving, nothing is pruned, and opv exits 5 with the reason and a `Next:` line.
- **Prune order.** `--prune` without `--deploy` only lists what it would remove. With `--deploy`, opv removes a name from the app first, waits for the healthy revision, and only then deletes it from the store. It deletes only entries it tagged `opv-managed=<env>`, and only names the configuration declares; other names are counted as unmanaged and left alone. To remove a key from the app, keep it declared with `environments` that leave this environment out (`environments = []` for none), run `--deploy --prune`, then delete the declaration. A key already deleted from the configuration is never pruned: remove it by hand (`az containerapp update --remove-env-vars <NAME>`, or `kubectl set env deployment/<name> <NAME>-`). A key added back after a prune is recovered from Key Vault's soft delete, because opv tags `opv-pruned=<env>` before it deletes; a secret someone else deleted is never recovered by opv.
- **Drift.** If someone re-pins a variable by hand to another version, `status` reports drift for that key. opv overwrites it only under `--deploy`.
- **An update already in progress.** If the Container App is being updated when opv starts (`provisioningState` `InProgress`), `sync` waits for it to finish, with a progress line, within `--timeout`. `status` and `plan` never wait: they print one `warn` line on stderr and show the current state.
- **Superseded versions (Kubernetes).** After a healthy rollout, `--deploy` deletes the older version Secrets of each key that neither the Deployment nor any ReplicaSet still references (so `kubectl rollout undo` keeps working); Key Vault keeps old versions as history.
- **Changed while applying.** opv changes only the variables it manages and checks that the rest of the app did not change under it. If it did, opv stops with the changed setting names (never values), and it is safe to re-run.
- **Soft-deleted names (Key Vault).** A deleted secret name stays reserved until it is purged, so writing it again fails. opv prints the exact command, `az keyvault secret recover --vault-name <vault> --name <name>`; it never recovers or purges anything itself.
- **Provenance.** Each Key Vault version opv writes is tagged, and each Kubernetes Secret, ExternalSecret and Deployment it writes is annotated, with `opv-version`, `opv-written` (UTC), `opv-env` and `opv-plan` (the [plan id](#review-then-apply-exactly-that-plan---expect-plan)). Never a value. `status` reads them back as one line, e.g. `Azure: last changed by opv 0.5.0 at 2026-10-08T14:02:11Z (plan 7f3c9a1e)`, and `status --json` as `provenance`. Nothing is stored anywhere else; Fly is not stamped.
- **Access.** The app's identity needs read access to the vault secrets. `opv doctor` warns, with the grant command, if it cannot confirm that. If the identity really cannot read a secret, Azure refuses the new revision, the old one keeps serving, and `sync` reports it.

#### Key Vault → Kubernetes through External Secrets (`secrets_in`)

With `secrets_in` (see [configuration](configuration.md#secrets-in-a-named-store-storesname-and-secrets_in)) the same commands run, with these differences:

- **Before any write**, `sync` checks the vault (subscription, vault, data-plane access), that the cluster serves `external-secrets.io/v1`, that the `ClusterSecretStore` exists and is `Ready`, and that you may create ExternalSecrets in the namespace. Any failure stops the run with nothing written and names the fix; a store that is not Ready is quoted with its own message. `status` and `plan` print the same findings as `warn` lines and go on.
- **Deploy** writes Key Vault versions, applies one ExternalSecret per pinned version, and waits (progress line every 15 seconds, within `--timeout`) until each is `Ready`. Only then does it repin the Deployment and wait for the rollout.
- **When an ExternalSecret cannot sync**, the operator only says `could not get secret data from provider`, so opv finds the cause itself: the version is missing from Key Vault, the `ClusterSecretStore` is missing or not Ready, it points at another vault, or (when all of that is fine) its identity cannot read the secret. The Deployment is not changed and the message ends with the next step.
- **Clean-up.** After a healthy rollout opv deletes the ExternalSecrets (and with them their Secrets) that neither the Deployment nor any ReplicaSet references, so `kubectl rollout undo` keeps working. `--prune` deletes a pruned key's unreferenced ExternalSecrets first and its Key Vault entry after; ExternalSecrets an older ReplicaSet still references stay for rollback and are deleted by a later run once nothing references them. Key Vault keeps old versions as history.
- **`status`** prints one `chain:` line per bound key, e.g. `chain: DB_URL → Key Vault kv-myapp-prod (46687ce78b…) → ExternalSecret opv-db-url-46687ce78b → env DB_URL`.

Values reach `az` and `kubectl` only on stdin (on native Windows, `az` gets them through a named pipe only your user can open).

### Run summary

`sync` names each key as `product/KEY (TARGET_NAME)` and ends with one summary line, the same on Fly, Azure and Kubernetes:

```text
written: api/OPENAI_API_KEY (FLEET__API__OPENAI_API_KEY)
unchanged: api/DATABASE_URL (FLEET__API__DATABASE_URL)
pending deploy (pass --deploy): api/OPENAI_API_KEY (FLEET__API__OPENAI_API_KEY)
summary: written 1 · unchanged 1 · held 0 · deployed no · pending 1 · pruned 0 · kept 0 · skipped 0
Next: opv sync prod --deploy
```

The line is always `summary: written N · unchanged N · held N · deployed <revision|yes|no>[ (N pending from an earlier run)] · pending N · pruned N · kept N · skipped N`. `written` counts new values (staged on Fly, new versions on Azure and Kubernetes); `held` counts immutable keys left alone; `deployed` is the revision name (`yes` on Fly, which names none) or `no`, and says when the deploy applied names an earlier run left pending (so a run that wrote nothing can still deploy); `pending` counts names still waiting for a deploy after this run; `kept` counts names not desired here that stayed because `--prune` was not given; `skipped` counts declared keys not desired in this environment. The `Next:` line follows only when something is left to do: a deploy for pending names, or `--prune` for names kept because `--prune` was not given. `--prune` prints `will prune: <names>` before it removes anything.

`sync --json` prints the same report as one JSON document on stdout (names only, never values; detail lines are not printed, and preflight warnings go to stderr):

```json
{
  "schema_version": 1,
  "environment": "prod",
  "product": null,
  "targets": [{"target": "web", "provider": "fly", "deployed": false, "revision": null}],
  "written": [{"target": "web", "product": "api", "key": "OPENAI_API_KEY", "target_name": "FLEET__API__OPENAI_API_KEY"}],
  "unchanged": [{"target": "web", "product": "api", "key": "DATABASE_URL", "target_name": "FLEET__API__DATABASE_URL"}],
  "held": [],
  "deployed": false,
  "deploy_reason": [],
  "deployed_names": [],
  "pending": [{"target": "web", "product": "api", "key": "OPENAI_API_KEY", "target_name": "FLEET__API__OPENAI_API_KEY"}],
  "pruned": [],
  "kept": [],
  "skipped": [],
  "written_names": ["FLEET__API__OPENAI_API_KEY"],
  "plan_id": "7f3c9a1e",
  "next": "opv sync prod --deploy",
  "do": null,
  "delivery": {"minted": [{"target": "web", "product": "api", "revision": 3}], "not_minted": []}
}
```

Lists follow the summary line's order and hold `{target, product, key, target_name}` objects over every target in target order. `targets` names each target, its provider, whether this run deployed and the revision it applied. `delivery` appears when a state vault recorded receipts: `minted` holds one `{target, product, revision}` per product whose every written name this run confirmed, and `not_minted` holds one `{target, product, reason}` for each receipt it could not record. `deploy_reason` says why a deploy happened (`written`, `pruned`, `pending_from_earlier_run`), `deployed_names` and `written_names` are bare target names, and `next` is the `Next:` command or `null`. Every failure ends with one `Next:` line ([what a failure looks like](how-opv-handles-failures.md#what-a-failure-looks-like)); with `--json`, stdout is then the [failure document](#json-contract).

### One product: `--product`

On `check`, `run`, `config export` and `open`, `--product` may be left out when exactly one product has keys desired in that environment: opv uses that one. When several do, it is a usage error that lists them.

`status`, `plan` and `sync` take `--product <p>`, and `add`/`explain` use `PRODUCT/KEY`:

- `status` and `plan` show only that product's rows; the count line, the totals and the exit-8 findings count that product only, so another team's missing key does not turn your status red. `OPV_PRODUCT` is the default for both.
- `sync --product <p>` writes, prunes and deploys only that product's managed names; `--prune` never removes another product's name, and another product's missing key does not block it. A Fly deploy still restarts the whole app with every staged change: when another product has staged changes waiting, sync prints `pending for other products: web/TOKEN (FLEET__WEB__TOKEN); a deploy restarts the app with them too`. `OPV_PRODUCT` is never used by `sync`.

### Guarded environments

If an environment sets `confirm_env = true` ([configuration](configuration.md#guarding-an-environment-confirm_env)), `sync` refuses (exit 6) before the first write unless you repeat the name (the read-only checks run first, so blocking keys are reported in the same refusal): `opv sync prod --deploy --confirm prod`. The refusal ends with that exact command, with every flag you gave:

```text
opv: policy denied: environment prod is guarded (confirm_env = true): sync needs --confirm prod; nothing was changed
Next: opv sync prod --deploy --confirm prod
```

A `--confirm` that names another environment is refused everywhere, guarded or not. The `Next:` line after a guarded sync includes `--confirm <env>`; `plan`'s carries `--expect-plan <id>` instead, which is enough on its own. `--prune` always lists the names it will remove before it acts.

### Sync on GitHub Actions

Secrets are written with `gh secret set` and config with `gh variable set`, values on stdin, in every listed repository (and GitHub environment). A write is live at once: `sync` prints no pending line, and `--deploy` prints `nothing to deploy: GitHub applies each write at once`. GitHub never shows a secret's value again, so every sync writes each ready secret (`unknown` in `status`); variables are compared and written only when they differ. `--prune` deletes managed secrets and variables that are no longer declared; other names in the repository are never touched. Setup: [configuration](configuration.md#github-actions-repository-and-environment-secrets), [example](../examples/github-ci/).

`plan` and `status` also list keys the environment does not deliver (`not delivered here: …`, JSON `undelivered`), when the target's `products` leaves their product out, and warn about a source-only value nothing points at (`unreferenced shared value …`, JSON `unreferenced_sources`).

### Pruning on Fly

Nothing is deleted by default. `--prune` unsets only names that the template produces for declared keys that are not desired in this environment. Names outside that set are never touched. Immutable keys are never pruned unless named with `--prune-immutable`; they are reported as "held (immutable), not pruned". A name staged by the same run is never pruned. A key you delete from `secrets.toml` is no longer declared, so it is neither reported nor pruned: unset it manually with `flyctl secrets unset`.

Known limitation: Fly hides an unset name as soon as `flyctl secrets unset --stage` runs, before any deploy. A run interrupted between that unset and the deploy (Ctrl-C, CI cancel, lost network, or a run without `--deploy`) leaves the name on the machines, and the next run cannot see it, so it neither reports nor deploys it. Any later deploy finishes the removal: run `opv sync <env> --deploy` again (it deploys when anything else changed or is pending), or `flyctl secrets deploy --app <app>`, which always deploys.

### Shared keys

A key declared with `from = "<product>/<KEY>"` ([configuration](configuration.md#shared-keys-from)) has a row of its own in `status`, `plan` and `check`, with the source under it:

```text
TARGET  PRODUCT  KEY           KIND    STATE              ON TARGET
web     api      DATABASE_URL  secret  missing            new
    affects worker/DATABASE_URL
    guidance: Neon / connection string
web     worker   DATABASE_URL  secret  blocked by source  new
    shared from api/DATABASE_URL
```

A missing or failing source is one finding, reported on the source with the keys it affects; the sharing keys read `blocked by source` and are not counted again. `check --product worker` and `status --product worker` include the source's row, because worker's key depends on it. JSON rows carry `"shared_from": "api/DATABASE_URL"` and the state `source_blocked`. `explain worker/DATABASE_URL` shows the source's `op://` reference and `shared from:`; `explain api/DATABASE_URL` lists `shared by:`.

### Explain a key

```sh
opv explain <product>/<key> [--env <environment>]
```

`explain` prints what the configuration declares for one key in one environment: the `op://` reference, the field kind, the target name, the declared rules, `immutable` and `guidance`, plus an `op item get <item_id> --vault <vault_id>` command you can run in your own terminal to look at the item. That command never contains `--reveal`.

```text
allumata/OPENAI_API_KEY in prod
  reference:  op://vprd/iprd/allumata/OPENAI_API_KEY
  kind:       secret (concealed field)
  fly name:   FLEET__ALLUMATA__OPENAI_API_KEY
  rules:      prefix = "sk-", not_prefix = "sk-or-"
  immutable:  no
  guidance:   OpenAI platform / API keys
  inspect:    op item get iprd --vault vprd
  open:       opv open allumata/OPENAI_API_KEY --env prod
```

A bare `<KEY>` resolves to the one product that declares it; when several do, the error lists them (`ambiguous key "KEY": declared as api/KEY, web/KEY`). An undeclared key or product suggests the closest declared names; when exactly one is close, the `Next:` line is `opv explain <that name>`.

It reads only the configuration (when that is a manifest, the manifest itself): no item or target call, and no value or value fragment (it is not a `secret get`). `--env` may be omitted when the configuration declares exactly one environment. An undeclared product, key or environment, or an environment the key is not declared for, is a configuration error (exit 2).

## Local development: `check` and `run`

`check <env> [--product <p>]` reads the environment's item once and reports each key as saved, missing or failing a rule, by name; it never contacts a deployment target and exits 8 when a key needs fixing. A failing key's guidance is printed under it as `  guidance: <text>`. `--json` prints the [shared row shape](#machine-readable-status-and-plan) with `target_checked: false`.

```text
$ opv check dev --product api
api/LOG_LEVEL: saved
api/OPENAI_API_KEY: saved
no findings; no deployment target checked
```

`run <env> [--product <p>] -- <cmd>` starts a command with the keys as environment variables under their plain names, through `op run`, with no `.env` file. It first removes every key name declared in the configuration from the inherited environment, so another product's keys never leak in. opv's options go before `--`; `run` takes no `--json` and exits with the command's own exit code. The local guide, with Docker Compose, editors, product switching and WSL, is [local-development.md](local-development.md).

## Doctor

`doctor` prints one line per check: the configuration and where it came from, `op` and its sign-in, each target CLI the environments use (`flyctl`, `az` 2.60 or newer, `kubectl`) and its sign-in, whether `op` can start local commands (`op local run`), and every `opv` on `PATH` (more than one different file is a warning with the command that removes the extra).

```text
$ opv doctor --env prod
ok    config: valid (1 environment, 1 product); source: /home/me/myapp/secrets.toml
ok    op: version 2.40.0
ok    op auth: signed in (USER)
ok    item: vprd/iprd readable (2 fields in section api)
ok    flyctl: version v0.4.112
ok    fly auth: signed in
ok    op local run: native op; opv run can start local commands
ok    opv: /home/me/.local/bin/opv 0.5.0
all clear: nothing pending
```

- A failing check has its fix under it as `  fix: ...`; `doctor` then exits with the first failing check as the error, and its `Do:`/`Next:` lines are that check's fix. An older tool is a `warn` line with the upgrade command (exit code unchanged).
- `--env <env>` checks only what that environment needs (a run-only environment needs no target CLI) and reads its item once, by IDs, checking the keys as `check` does: a key missing or failing a rule is a `FAIL  item:` line naming it, with `Next: opv check <env> --product <p>` (exit 8). `--product` limits that to one product. Without `--env` no item is read.
- `--settings` also looks for likely-wrong values across every environment you can read (the same secret in two environments, a placeholder, stray whitespace, `localhost` where it deploys, a test key in production): one `warn  settings:` line listing each, with `fix: opv open <key> --env <env>`. It reads every environment's item; values are compared, never shown. A warning never changes the exit code. `opv ready` reports the same findings. See [settings health](configuration.md#settings-health-likely-wrong-values).
- `doctor` never writes 1Password, whoever runs it, so an assistant can rely on it in a person's session. When an item is not laid out the way opv expects, it reads it as it is and says so once, naming `opv tidy <env>`, the explicit repair (a signed-in person runs it; one verified edit, nothing deleted).
- With `deploy_credentials`, a failed sign-in is one `FAIL deploy credentials` line; the other checks still run.
- `--json` prints `{schema_version, ok, config_source, checks: [{name, status: ok|warn|fail|skip, detail, next, do}], next, do}`; the top-level `next` and `do` are the first failing check's, or `null`.
- With no configuration at all, the config line lists both ways to start (`opv init` for an existing item, `opv setup` for a project that ships `opv.setup.toml`).

## Terminal UI: `opv ui`

`opv ui` shows, in one full-screen view, every environment (by its title, in its configured order) against every product, each product's keys across environments, a key's details and who reads it, the shared values and their consumers, and the 1Password accounts. Secrets are shown as `••••` with their state; no value is ever fetched. Environments you cannot open are dimmed with their `audience`; your personal keys are marked as yours.

Every action is an `opv` command, shown before it runs and run in your terminal, so 1Password's prompts and opv's output look exactly as they do on the command line: `s` syncs the selected environment by first showing `opv plan`, then running exactly that plan with `--expect-plan` after you confirm (for a guarded environment, by typing its name); `i` reviews values from a file before adopting them (what `opv adopt` found per key; you choose import or skip, keep or replace, then it runs exactly the `opv adopt … --apply` it shows); `o` opens a key in 1Password; `n` runs the next step from `opv ready`; `a` lists accounts; `+` declares a key (a form: product, name, kind, environments, guidance, personal, same value intended) and `E` adds an environment, each becoming the exact `opv add …` / `opv init <env> --add-env` it shows before running; `e` hands off to `opv config edit`; `r` re-reads everything. Keys: arrows, `tab` between the sidebar and the main pane, `enter` to open, `esc` to go back, `q` (or Ctrl-C) to quit; Ctrl-C while an action's command runs stops that command and returns to the UI. Without an interactive terminal (or with `OPV_UI_TEXT=1`, for screen readers) it prints `opv ready` instead. It is part of the default build; `cargo build --no-default-features` leaves it out.

## Write history: `opv history`

`opv history <env>` shows, per secret, what opv last wrote to the environment's target, from what is already recorded: on Key Vault and Kubernetes the stamp opv puts on each value it writes (UTC time, plan id, opv version); on Fly and GitHub the version opv's own sync recorded in each placement's delivery evidence (on Fly the version is a digest of the value, so it is compared in memory and never shown: only the state is). Each key is `written by opv` (stamped), `as opv's last sync left it`, `changed outside opv since its last sync` (then `Next: opv plan <env>`), `on the target; opv has no record of writing it`, or `not on the target`. It is read-only, as `opv status` (the item reads, each recorded delivery item and one store listing), and shows names, versions, times and plan ids, never a value or a fingerprint. `--json` gives `{schema_version, environment, target, latest: {written, plan, opv_version} | null, rows: [{product, key, name, on_target, version, pending, written, opv_version, plan, recorded_version, state}]}`. An environment without a target has no history. In `opv ui`, `h` on an environment opens the same.

## Who can read each vault: `opv access`

Every environment needs, per target, its deploy identity's read of the boundary vaults that target's products need and read-write on that target's state vault; plus a read-only CI reader over every boundary vault of the environment. `opv access [<env>] [--target <name>]` prints, per environment and target, who needs each vault and who can read it today (one read-only listing each). People and guests are counts, never names; each service account is named with whether it can only read. `--target <name>` narrows to one target's deploy identity and omits the CI reader.

```text
$ opv access prod
prod:
  deploy prod/web:
    vprd0000000000000000000001: read: present
    vprd0000000000000000000002: read-write: missing
  ci reader prod:
    vprd0000000000000000000001: read: present
  checked: 3, unclassified: 0
Owner runs: op service-account create "myapp-prod-web" --vault vprd0000000000000000000002:read_items --vault vstate0000000000000000001:read_items,write_items
```

The states are `present`, `missing` and `read-only needed`; a vault it cannot see is `not visible` and is counted under `unclassified`, never assumed fine. It never says "clean": it says what was checked and what it could not classify. It warns when an environment that deploys has no read-only CI reader (`no_ci_reader`), when a reader can write (`ci_reader_can_write`), or when it cannot see who uses a vault (`access_not_visible`); each finding carries the owner's exact command. One `Owner runs:` create command is printed per principal with a missing or too-broad grant, because 1Password fixes a service account's vaults and permissions at creation. opv prints it and never runs it, because 1Password shows the new token once, to you. Store it as the CI secret `OP_SERVICE_ACCOUNT_TOKEN` yourself.

`--json` gives `{environments: [{environment, report, commands}]}`, where `report` holds the checks (principal, vault id, permission, state), the extra readers, the findings and the `checked`/`unclassified` counts. In `opv ui` it is the "CI access" entry in the sidebar.

## Delivery receipts: `opv sync --receipt` and `opv delivery verify`

When a target has a state vault (created by `opv target add`, or by `opv bootstrap` for a target already declared), every sync whose writes that target confirmed records, **per placement** (product and target), its evidence in the target's state vault, in the item `opv · delivery · <product> · <target>` that `opv bootstrap` creates and records (`delivery_items`). Each placement has its own evidence, so a product on a shared app and on a dedicated target are promoted and checked independently. `opv delivery verify <env> --product <p>` reports every placement of the product, each with its target and state; `--target <name>` narrows it to one placement and is never required. Verify reads each placement's own state vault.

```sh
opv sync prod --product api --receipt api.receipt.json   # deliver; keep the receipt (names, ids, times)
opv delivery verify prod --product api --json            # read-only: is api still exactly what was delivered, on each target?
opv delivery verify prod --product api --target web      # one placement only
opv delivery verify prod --receipt api.receipt.json      # is the receipt I kept still the current delivery?
```

- **When a revision is minted.** Only when every secret in the placement's binding set (exactly the secrets the target delivers for the product: a key a mode skips is not in it) was written by this sync (confirmed by the provider) or proven identical; each confirmed name's evidence line is recorded either way. The revision (`drv-` and 26 random characters) is opaque and derived from nothing.
  - A failed, partial or interrupted sync mints nothing. Its product stays as it was, and a retry mints once everything is confirmed.
  - An unchanged re-sync keeps the same revision, so an accepted record stays reusable.
- **What verify reports**, per placement: every target that delivers the product, each with its target and state; `--target` narrows. Exit 0 only when everything checked is `verified`; otherwise exit 8 with `Next: opv sync <env>`.
  - `verified`: every name holds what was delivered.
  - `changed`, with each name's state:
    - `source_changed`: the 1Password value was rotated, or a shared value it reads changed. A shared value invalidates every product that reads it.
    - `drifted_on_target`: edited outside opv.
    - `missing_on_target`.
  - `unverifiable`, with a reason.
  - `not_delivered`: nothing recorded, or recorded for another account, environment, product or target, or the binding set changed (a key added or removed).
  - `superseded`: the receipt you passed is no longer the current delivery.

  `deployed` is reported separately: `staged` (Fly secrets waiting for a deploy), `deployed`, or `n/a` (GitHub applies writes at once). It is never folded into `verified`.
- **Never a value, never a digest.**
  - The receipt holds names, IDs, times, the plan id and the opv version.
  - The evidence (each name's store version and a keyed fingerprint of its 1Password value) stays in the state item and is compared in memory. Fly digests included, it is never printed, logged or written to a file.
  - Give the state vault only to identities that can also read the values.
- **Least privilege.** A target's deploy identity reads the boundary vaults that target's products need and writes only its own state vault. `opv access <env> --target <name>` prints its exact `op service-account create … --vault <boundary>:read_items --vault <state>:read_items,write_items` command, which you run yourself (1Password shows the token once).
- **Receipt file**: `{"schema": "opv.delivery/1", "deliveries": [{"revision", "scope": {"account_id", "environment", "product", "target", "provider", "locator"}, "bindings": [{"name", "source": {"item_id", "field"}}], "delivered_at", "plan_id", "opv_version"}]}`. A receipt is selected by its full scope, in any order; two with the same full scope are refused (`duplicate_scope`). `opv delivery verify --json` returns `{schema_version, environment, placements: [{product, target, revision, state, reason, names: [{name, state}], deployed, receipt_revision?}]}`.
- **Capability check**: an installed opv supports this when `opv schema` lists the command `delivery verify`.

The four kinds of evidence are kept apart:

| Evidence | What it proves |
|---|---|
| `opv ready` (`receipt_id`) | what is declared and saved now |
| `plan_id` | the intent a person reviewed |
| delivery revision | that a confirmed write put this binding set on the target, and whether it still holds |
| `deployed` | whether the running release uses it |

## Readiness: `opv ready`

`opv ready` answers "what is ready, what is not, and who does what next" in one read-only command. It reads the account (as `opv account list`) and every environment (as `opv status`), and prints a product × environment grid (`saved/declared`, `n/a` where the environment's target does not deliver the product), the findings, and the first step:

```text
ready: 1 blocking · 1 findings · receipt rcpt-3f9a1c0d2e7b
PRODUCT  dev  staging          prod
api      6/6  5/6 · 1 finding  6/6
shared   n/a  n/a              n/a
Needs attention:
  [owner] key_missing staging api/STRIPE_KEY → opv open api/STRIPE_KEY --env staging
Next (owner): opv open api/STRIPE_KEY --env staging
```

`--json` gives the receipt as one document (`opv schema` lists its fields). Each finding has a stable `code`, a `scope` (account, environment, product, key), `blocking`, the `actor` who acts (`owner`, `agent`, `ci`), its `effect` (`none`, `signs_in`, `writes_1password`, `writes_target`, `writes_config`), one `prerequisite` command and one `verify` command, so an assistant never parses prose; a [settings health](configuration.md#settings-health-likely-wrong-values) finding (non-blocking) also has a `message`, one sentence naming the keys and environments, never a value. `receipt_id` changes whenever anything in the receipt does; `--save <file>` keeps the receipt (names, IDs and codes only) to resume a handoff after a session ends. It never tidies or writes.

## Moving existing settings in: `opv adopt`

Starting a project from a `.env` file? `opv init <env> --from .env --apply` declares every key and imports the values in one step ([configuration](configuration.md#start-from-an-existing-env-opv-init---from)); `adopt` is for keys already declared.

When values already live somewhere else (a project's `.env` file, a Key Vault, a cluster), `opv adopt <env> --from <file>` shows what would come into the environment's 1Password item, without writing anything:

```text
staging: 4 found · 2 to write · 1 need a decision
  api/DATABASE_URL                 differs: 1Password is kept (--replace api/DATABASE_URL to take the found value)  (from DATABASE_URL)
  api/PRIVATE_KEY_PEM              import (to write)  (from PRIVATE_KEY_PEM)
  api/LOG_LEVEL                    same value after the key's rules; nothing to do  (from LOG_LEVEL)
  shared/FLY_API_TOKEN             import (to write)  (from FLEET__API__FLY_API_TOKEN, FLEET__WEB__FLY_API_TOKEN)
Next: opv adopt staging --from .env.staging --apply
```

- A found name becomes a declared key by its target name, else by its bare key name; a name several keys share is skipped as ambiguous. A key that shares a value (`from`) lands in its source's field once; copies that differ are reported, never merged.
- Each key's rules and transforms apply to both sides before comparing (`ensure_prefix`, a trailing newline, `pem_private_key`), so a formatting difference is not a change. Values are never printed, not even partly.
- `--skip product/KEY` (repeatable) leaves a key out of the import although it would come in; it is listed as `skipped`. In `opv ui`, `i` opens the same review per key (import or skip, keep or replace) and runs exactly the `opv adopt … --apply` it shows.
- A filled 1Password field is never replaced unless you name it with `--replace product/KEY` (an immutable key also needs `--rotate product/KEY`); the old value is kept in the section `opv · kept`.
- `--apply` writes everything in one item edit, reads the item back and checks each field. It needs your own session, and re-running is safe: the plan is recomputed from what is there. It never syncs, deploys, prunes or deletes the source; your apps keep their current secrets until you sync.
- Sources: a dotenv file (literal `KEY=value` lines, never executed; it must be a private regular file under 1 MiB), or `--from target` for targets that can show values: Azure Key Vault, Kubernetes Secrets, and GitHub variables (config). Fly secrets and GitHub secrets can never be read back: put those values in a private dotenv file from where you keep them today, or type them in 1Password.

## New environment: `opv init`

`opv init <env>` writes the configuration from an environment's 1Password item, created if missing. There is one model for every project: a run-only environment's item has unsectioned fields, so `--product` names the product they belong to (each named section is a product of its own). It writes boundaries and products, never a target: `opv target add` is the one way to add a deployment target ([below](#named-targets-opv-target-add-and-opv-target-list)), and a run-only environment needs none.

```sh
opv init dev --product api                    # run-only: vault myapp-api-dev, item "myapp · api · dev values"
opv init prod --product api                   # then its deployment target:
opv target add prod web --fly-app myapp       # validates it, creates its state vault and records its placements
```

It reads field names and types once, never values. Its output names `opv target add` for a deployment target and ends with `Next: opv bootstrap`, which is runnable as printed for every environment: it records any boundary still missing its IDs, adds each declared field, empty, and ends with `Next: opv ready`. `--add-env` adds the environment to the existing configuration instead of writing a new one. Details and the `--from` form: [configuration](configuration.md#start-from-an-existing-item-opv-init).

## Named targets: `opv target add` and `opv target list`

A target is one named deployment target under `[environments.<env>.targets.<name>]`. `opv target add <env> <name>` writes one: pass the provider's options (`opv target add --help` lists them) and opv infers the provider from them, or pass `--provider`. `--products <p>` (repeatable) limits what it delivers (without it, every non-source-only product), and `--deploy-credentials op://<vault>/<item>` records its least-privilege deploy identity. In the same step it finds or creates the target's state vault `<project>-<env>-<target>-state` and records its ID; the edit keeps comments, validates the whole configuration first and refuses a concurrent change. `--dry-run` changes nothing. It ends with `Next: opv access <env> --target <name>`. `opv target list [--env <env>]` is read-only and shows each target's provider, locator, products, deploy identity and state vault.

```sh
opv target add prod p-overflow --fly-app p-overflow-prod --products p
opv target add staging site --fly-app site-staging --dry-run
opv target list --env prod --json
```

## Fresh fleet: `opv bootstrap`

`opv bootstrap` completes a configuration whose boundaries and targets have no IDs yet. In the selected 1Password account it creates, for every boundary an environment needs and does not record, a vault `<project>-<boundary>-<env>` and an item `<project> · <boundary> · <env> values` (found when they exist); and for every target without `state_vault_id`, a state vault `<project>-<env>-<target>-state`. It records their IDs in the file (comments and order kept) and adds every declared field, empty. One run records every missing boundary and state vault; bootstrap has no flag that narrows it to one. `--dry-run` shows the plan and changes nothing. Recorded IDs the selected account cannot see stop with `ids_not_in_account`: select the account that holds them (`opv account use <ID>`) or pass `--rebind <env>` to record new boundary IDs in this account (values are not moved). A file whose first line starts with `# generated` is never rewritten; the IDs are printed for its generator. It needs your own session (it writes 1Password), never syncs or deploys, and ends with `Next: opv ready`. Re-running is safe. `--ci-reader <env>` also prints one owner command: the create command for a read-only CI service account over every boundary vault of that environment (`op service-account create … --vault <id>:read_items`), which you run yourself, because 1Password shows the token once. A complete walk-through from a fresh account to the first guarded deploy is in [examples/fleet-fly](../examples/fleet-fly/).

```sh
opv bootstrap --dry-run                # each boundary and state vault: ok, create or ids_not_in_account
opv bootstrap                          # create the missing ones and record every ID
opv bootstrap --ci-reader prod         # also print the CI reader's create command
```

## Assistant-prepared structure: `opv approve`

An assistant connected to the [opv MCP server](mcp.md) can declare keys, environments and targets in `secrets.toml` and prepare the same structure `opv bootstrap` creates as a plan (`opv_structure_plan`), but it cannot create it on its own. You review and approve that exact plan in your own terminal:

```sh
opv approve sp-3f9c0a1b2c3d4e5f        # shows each vault, item and empty field; type the id back to approve
```

`approve` re-plans and refuses an id that no longer matches (`stale_plan`, exit 6, with the current id in `Next:`). It lists every step by name and asks you to type the plan id; any other answer records nothing. The approval is single use, expires after 15 minutes, and names the project and 1Password account (from `OP_ACCOUNT`, the `.opv` pointer, or the only account op knows). It needs an interactive terminal and refuses under CI or with a service-account or Connect credential set; it has no flag that skips the question. The assistant then applies the plan (`opv_structure_apply`), which the 1Password app asks you to authorize, and gives you the links where you enter each value. Without an approval it fails with `approval_required`. Approving never syncs, deploys, grants access or touches a value.

## Walkthrough: one product on a shared app and a dedicated overflow app

Product `p` runs on the shared app `portfolio-prod` and, for overflow, on the dedicated app `p-overflow-prod`. Both placements read the same boundary item, so no value is entered twice; each target keeps its own state vault and its own delivery evidence. The configuration is the one in [configuration](configuration.md#one-baseline-plus-a-dedicated-overflow).

```sh
opv init prod --product p                    # p's boundary: vault and item, IDs recorded
opv target add prod shared --fly-app portfolio-prod
opv target add prod p-overflow --fly-app p-overflow-prod --products p
opv access prod --target p-overflow          # the deploy identity's vaults and its create command
opv bootstrap --ci-reader prod               # the CI reader's command over every boundary vault
```

Then the normal loop covers both placements in one run:

```sh
opv plan prod                                # one plan id over shared and p-overflow; rows carry TARGET
opv sync prod --deploy --expect-plan <id>     # writes p to both, each confirmed on its own app
opv delivery verify prod --product p --json   # each placement's own state vault and revision
```

`plan` shows `p`'s keys once per target (`prod/shared` and `prod/p-overflow`), `sync` records a delivery receipt in each target's state vault, and `delivery verify --product p` reports both placements, each with its target and state (narrow it with `--target p-overflow`). `--target shared` (repeatable) narrows any of `status`, `plan` and `sync` to one placement. Nothing is typed twice: change `p`'s value once in its boundary item and the next sync updates both apps.

## Sign-in: `opv login`

`opv login <env>` signs in to the 1Password account that environment uses (its `account` setting), at 1Password's own prompts, and opens a signed-in terminal (type `exit` to leave it); `opv login <env> -- <command>` runs one command signed in and exits with its code. No token is printed and nothing needs `eval`. Without an environment it uses the one account every environment uses (or your default account), and asks which environment when they differ. Sessions for environments in different accounts coexist in one terminal (`OP_SESSION_<account>` each), and every command uses the account of the environment it acts on. Every sign-in hint opv prints is `opv login <env>`.

**Accounts, without signing in.** `opv account list` shows the accounts this 1Password CLI knows, whether each is signed in, which one the project uses and why (`--account`, `OP_ACCOUNT`, `.opv`, or the only one), and what to do next; it never prompts or signs in. `--json` gives the same as one document (`opv schema` lists its fields): `discovery` (`ok`, `unavailable`, `op_missing`), `selected`, `accounts` and `findings` with stable codes (`no_accounts`, `selected_account_absent`, `account_ambiguous`, `selected_signed_out`, `discovery_unavailable`, `op_missing`), each with one `next` command. Only accounts this CLI knows are listed; on Linux and WSL an account that is only in the 1Password app appears after `opv login --add`. `opv account use <email or ID>` records the project's account in `.opv` with no prompt; a value several accounts match (a shared sign-in address) is refused with the candidates' IDs.

**Choosing the account.** Until the project records one (`.opv`, written by your first choice; commit it), `opv login` asks which 1Password account holds the project's secrets, even when only one is added to this CLI, so you always see which one it is; each entry says whether it is signed in, and the last one is **Add another 1Password account**. `opv login --add [--account <email>]` adds an account right away. You type the sign-in address, Secret Key and password only at 1Password's own prompt (your Emergency Kit has them). On Linux and WSL the CLI keeps its own accounts: in WSL, accounts that are only in the Windows 1Password app are not listed until you add them here. On macOS and Windows the CLI uses the app's accounts, so you add an account in the app.

**When sign-in fails** opv says why in its own words, names the account, and gives one next step: the account is not added to this CLI (`account_not_registered`, `Next: opv login --add --account <email>`), no session (`op_not_signed_in`), the 1Password app is locked or its CLI integration is off (`desktop_app_unavailable`), what was typed was not accepted (`credential_rejected`), the prompt was cancelled (`sign_in_cancelled`), 1Password could not be reached (`provider_unavailable`, exit 9, nothing changed), or a reason opv does not recognise (`op_unexpected`, `Next: opv doctor`). It never guesses that a password was wrong, and 1Password's own CLI directions are not repeated.

`login`, `setup` and `config edit` need your own interactive terminal; without one they refuse (exit 6, `terminal_required`) and name themselves on `Next:`. Automation uses a 1Password service-account token (`OP_SERVICE_ACCOUNT_TOKEN`) instead, which decides the account. Per-environment `account` and `deploy_credentials`: [configuration](configuration.md#account-and-deploy-credentials).

## Configuration commands

| Command | What it does |
|---|---|
| `opv config export [--toml\|--json]` | print the configuration (no values) |
| `opv config export <env> --json` | that environment's config-kind values |
| `opv config import --vault V [--file F] [--project P] [--path D]...` | save a `secrets.toml` as the project manifest; never deletes the file |
| `opv config edit` | edit in `$VISUAL`/`$EDITOR`, validate, diff, confirm, save unless changed meanwhile |
| `opv config check --file F` | exit 8 with a diff when a committed copy differs from the manifest |

Details, discovery and the review trade-off: [configuration in 1Password](configuration.md#configuration-in-1password). `init`, `add` and `item skeleton`: [configuration](configuration.md#start-from-an-existing-item-opv-init).

## Shell completion

`opv completions <bash|zsh|fish|powershell>` prints a completion script for commands and options (static: environment and product names are not completed). Install it once per shell:

```sh
opv completions bash > ~/.local/share/bash-completion/completions/opv
opv completions zsh > "${fpath[1]}/_opv"            # then restart zsh
opv completions fish > ~/.config/fish/completions/opv.fish
```

```powershell
opv completions powershell | Out-String | Invoke-Expression   # add this line to $PROFILE
```

## Colour

On a terminal, opv colours state words only: `ok`, `warn`, `FAIL` and `skip` in `doctor`, and the row state (`saved`, `missing`, `failed`, `skipped`) in `status`, `plan` and `check`. Nothing derived from a value is coloured, and JSON never is. `--color auto` (the default) colours only when stdout is a terminal and `NO_COLOR` is unset or empty; `--color never` turns it off and `--color always` forces it, even when piped. Piped output under `auto` is byte-for-byte the same as before colour existed.

## JSON contract

Every command that takes `--json` (`doctor`, `check`, `status` including `status --all`, `projects`, `plan`, `sync`, `explain`, `open`, `init` including `--add-env`, `add`, `item skeleton`, `config export`), plus `config export <ENV>` and `opv schema`, prints exactly one JSON document on stdout, success or failure, and the human text on stderr. No document ever contains a secret value. Each one starts with `schema_version` and `ok` and ends with `next` (a command that runs as typed, or `null`) and `do` (an action only a person can take, or `null`). A failure adds `exit_code` after `ok` and an `error` object last:

```json
{
  "schema_version": 1,
  "ok": false,
  "exit_code": 6,
  "next": "opv explain api/OPENAI_API_KEY --env prod",
  "do": "fix api/OPENAI_API_KEY in 1Password",
  "error": {
    "code": "keys_blocking",
    "category": "policy",
    "message": "sync refused, nothing staged: api/OPENAI_API_KEY (missing)",
    "detail": [],
    "retry": "after_fix",
    "human_required": true,
    "do": "fix api/OPENAI_API_KEY in 1Password",
    "next": "opv explain api/OPENAI_API_KEY --env prod"
  }
}
```

A failure after the command produced its document (findings, exit 8) keeps that document's fields between `exit_code` and `next`. `config export <ENV>` (and `config export --json`) prints the bare document on success and the failure document on failure. Usage errors (`--json` with an unknown flag) print the failure document with code `usage`.

`retry` says whether to run the same command again: `safe` (now; nothing is known to be broken), `after_fix` (once `do` is done) or `never` (the command itself must change: run `next`). `human_required` is `true` when only a person can take the next step; an assistant then hands `do` and `next` to the user instead of acting. `code` is one of a closed list:

<!-- error-codes:begin (generated from src/error.rs by tests/docs_commands.rs) -->
| `code` | Exit | `retry` | Human | Meaning |
|---|---|---|---|---|
| `usage` | 2 | never | no | the command line is not valid (unknown flag, missing argument) |
| `config_not_found` | 2 | after_fix | no | no secrets.toml in this directory or a parent, and no 1Password manifest for this checkout |
| `account_required` | 2 | after_fix | yes | several 1Password accounts are on this machine and none is chosen for this project; a person picks one with opv login --account |
| `account_ambiguous` | 2 | after_fix | yes | an email or sign-in address names several 1Password accounts; a person picks one by its account ID |
| `manifest_not_found` | 2 | after_fix | no | no 1Password manifest has the project's title (OPV_PROJECT or .opv) |
| `manifest_ambiguous` | 2 | after_fix | yes | several 1Password manifests match; a person keeps one and archives the others |
| `manifest_exists` | 2 | never | no | a manifest for this project already exists; change it with opv config edit |
| `config_changed` | 2 | safe | no | the configuration changed while opv was editing it: nothing was written and re-running is safe, or (when the error says so) another edit landed with opv's and a person checks the manifest's history |
| `config_invalid` | 2 | after_fix | no | secrets.toml or a flag value is not valid |
| `boundary_missing` | 2 | after_fix | no | a product has a key desired in an environment whose boundary (vault and item) is not recorded |
| `state_vault_missing` | 2 | after_fix | no | a target has no state vault recorded for its delivery evidence |
| `state_vault_wider_than_values` | 2 | after_fix | yes | a state vault shared by targets could be readable more widely than the values its evidence describes; a person gives one target its own |
| `duplicate_scope` | 2 | never | no | a receipt file holds more than one entry for the same environment, product and target |
| `unknown_env` | 2 | never | no | the environment is not defined in secrets.toml |
| `unknown_product` | 2 | never | no | the product is not declared |
| `undeclared_key` | 2 | never | no | the key is not declared (for this environment) |
| `no_target` | 2 | never | no | the environment has no deployment target (run-only) |
| `dependency_missing` | 3 | after_fix | no | op or the target CLI is missing or unusable |
| `source_error` | 4 | after_fix | no | 1Password could not be read |
| `item_not_found` | 4 | after_fix | no | the item is not in the vault (moved, archived, deleted, or a wrong item_id) |
| `vault_no_access` | 4 | after_fix | yes | the signed-in identity cannot access the vault |
| `item_changed` | 4 | after_fix | yes | opv setup: the 1Password item changed while setup was saving it: again after setup re-read it (nothing was written; run opv setup again), or another edit landed with setup's or a field setup wrote is missing (a person checks the item's history) |
| `inventory_incomplete` | 4 | after_fix | yes | one or more 1Password accounts could not be listed, so the project inventory is incomplete; a project missing from it is not evidence that it does not exist |
| `target_error` | 5 | after_fix | no | the target (Fly, Azure, Kubernetes) refused or failed |
| `target_unhealthy` | 5 | after_fix | no | the new revision did not become healthy; the previous one keeps serving |
| `update_refused` | 5 | after_fix | no | the target refused the update and applied nothing; the previous revision keeps serving; re-running repeats the refusal |
| `policy_refused` | 6 | after_fix | no | opv refused the operation |
| `approval_required` | 6 | after_fix | yes | the structural plan has no unused, unexpired approval for this project and account; a person runs opv approve <plan_id> in their own terminal |
| `keys_blocking` | 6 | after_fix | yes | sync refused: keys are missing or failing a rule; nothing was written |
| `confirm_required` | 6 | never | yes | the environment sets confirm_env; pass --confirm <env> |
| `confirm_mismatch` | 6 | never | no | --confirm names another environment |
| `stale_plan` | 6 | never | no | sync --expect-plan: the plan changed since it was reviewed (the item, the target or the configuration); nothing was changed; review the new plan |
| `ram_dir_unavailable` | 6 | after_fix | no | deploy credentials for Azure need a private RAM-backed directory (XDG_RUNTIME_DIR on Linux, %LOCALAPPDATA%\Temp on Windows) and none is usable; nothing was read or changed |
| `terminal_required` | 6 | never | yes | the command needs the user's own interactive terminal |
| `auth_required` | 7 | after_fix | yes | not signed in to 1Password or the target CLI |
| `op_not_signed_in` | 7 | after_fix | yes | not signed in to 1Password |
| `ids_not_in_account` | 2 | after_fix | yes | an environment's recorded vault is not in the selected 1Password account; a person selects the owning account or rebinds the environment (opv bootstrap --rebind) |
| `account_not_registered` | 7 | after_fix | yes | the 1Password account is not added to this 1Password CLI; a person adds it at 1Password's prompt with opv login --add |
| `desktop_app_unavailable` | 7 | after_fix | yes | the 1Password app is locked, closed, or its CLI integration is off |
| `credential_rejected` | 7 | after_fix | yes | 1Password did not accept what was typed at its prompt |
| `sign_in_cancelled` | 7 | after_fix | yes | the 1Password sign-in prompt was cancelled |
| `op_unexpected` | 7 | after_fix | yes | 1Password's CLI failed for a reason opv does not recognise; opv doctor checks it |
| `deploy_credentials_failed` | 7 | after_fix | yes | the environment's deploy credentials in 1Password were rejected or are incomplete; nothing was changed |
| `findings` | 8 | after_fix | yes | keys are missing or failing a rule (values are filled in 1Password by a person) |
| `outcome_unknown` | 9 | safe | no | a change may or may not have been applied; re-running is safe |
| `provider_unavailable` | 9 | safe | no | a provider did not answer after its retries; nothing was changed |
| `interrupted` | 130/143 | safe | no | interrupted by SIGINT (130) or SIGTERM (143); re-running is safe |
| `tidy_conflict` | 4 | safe | no | the 1Password item changed while opv was tidying it: twice before the write (nothing was written), or another edit landed with opv's (check the item's history; opv never retries); never a failure: reported in a document's tidy_error while the command reads the item as it is |
| `tidy_unverified` | 4 | after_fix | yes | opv tidied the 1Password item but the item read back lacks a field opv wrote or kept; a person restores it from the item's history; never a failure: reported in a document's tidy_error |
<!-- error-codes:end -->

`opv schema` prints a description of the installed binary as one JSON document: every command with its arguments, flags, whether it takes `--json`, what it changes (`effect`: `none`, `reads`, `opens_browser`, `writes_file`, `writes_1password`, `writes_target`, `runs_command`, `interactive`), whether it needs the user's terminal and whether to ask the user first, and the flags that add an effect of their own (`--deploy`: `deploys`, `--prune`: `deletes`, `--rotate`, `--prune-immutable`, `--confirm`, `init --force`); `target add`'s provider options (`--fly-app`, `--azure-key-vault`, `--kubernetes-context`, ...), each with its `provider` and `required_for_provider` (required for that provider); the exit codes, the error codes above, the state words and the fields of each document. It is generated from the binary itself, so it always matches the version you run:

```sh
opv schema | jq '.commands[] | select(.ask_user_first) | .name'
opv schema | jq -r '.error_codes[] | "\(.code) \(.retry)"'
```

### Machine-readable status and plan

`status <ENV> --json` and `plan <ENV> --json` print exactly one JSON document on stdout
and nothing else. It contains names, states and counts only: no value, no value fragment,
no value length and no guidance. Exit codes are unchanged. Findings (exit 8) keep the rows
and add `ok: false`, `exit_code` and `error`; an error before the rows exist prints the
[failure document](#json-contract). The top-level `schema_version` is `1`; adding a field
keeps it, while renaming or removing a field, or changing its meaning, increments it.

```json
{
  "schema_version": 1,
  "ok": true,
  "environment": "prod",
  "product": null,
  "changes": "some",
  "rows": [
    {
      "target": "shared",
      "product": "allumata",
      "key": "OPENAI_API_KEY",
      "kind": "secret",
      "state": "saved",
      "rule": null,
      "reason": null,
      "target_name": "FLEET__ALLUMATA__OPENAI_API_KEY",
      "target_state": "absent",
      "action": "would_stage"
    }
  ],
  "extras": [],
  "stage": ["FLEET__ALLUMATA__OPENAI_API_KEY"],
  "held": [],
  "prune": [],
  "totals": { "rows": 1, "findings": 0, "extras": 0, "to_stage": 1, "held": 0, "to_prune": 0 },
  "plan_id": "7f3c9a1e",
  "next": "opv sync prod --deploy --expect-plan 7f3c9a1e",
  "do": null
}
```

`state` is `saved`, `missing`, `failing_rule`, `skipped` or `source_blocked`; `rule` names the
failing rule when `state` is `failing_rule`, and `reason` says why (see
[Failure reasons](configuration.md#failure-reasons)); `target` names the row's target (FR-56); `target_name` is the key's name on the
target for every provider; `target_state` is `present`, `absent` or `would_change` for a secret, `not_delivered`
for a key the target does not deliver (a source-only value, or a product left out of
the target's `products`), and `null` for a config key (or `present`/`absent`/`would_change` where
the target takes config as variables), exactly the row's ON TARGET column; `action` is `would_stage`, `would_prune`, `held` or `null`. The same row shape,
in the same key order, is used by `status`, `plan` and `check`. With `--product`,
the document carries `"product": "<p>"` (otherwise `null`) and only that product's rows and
totals. `next` is the sync command for `plan`, `null` for `status`. `plan --json` adds
`"plan_id"` when nothing blocks ([`--expect-plan`](#review-then-apply-exactly-that-plan---expect-plan)),
and `status --json` on Azure or Kubernetes adds `"provenance": {"opv_version", "written",
"plan_id"}` once opv has stamped the target. The document is meant for the scheduled drift
check.

`opv status --json` without an environment prints one entry per environment:
`{"product", "environments": [{"name", "target", "state": "checked"|"run_only"|"not_checked", "keys", "saved", "skipped", "findings", "error_code", "error"}], "totals": {"environments", "findings"}}`. Run-only environments are read too (`state: "run_only"`, `target: null`); an environment's entry adds up all its targets, and its `target` is its first target's provider section (`fly`, `azure`, `kubernetes`) or `null`.

Two fields arrived in 0.5.0. `changes` is `some` when a sync would certainly change the
target (a new or changed key, a prune, a pending binding), `unknown` when only keys whose
values the target hides (Fly) would be staged, and `none` otherwise; a nightly drift job
can alert on `some`. A missing or failing row also carries `open_url`, the 1Password item
link to fix it in (IDs only); `check --json` rows carry it too.

A shared key's row carries `shared_from` (`api/DATABASE_URL`) and, while its source has a
finding, the state `source_blocked`. When a person's run tidied the item (FR-43),
`status`, `plan` and `check` documents carry `tidy`, a list of `{action, name}` (names
only; omitted when nothing was tidied). A tidy that was tried and did not complete puts
its error code in `tidy_error` (`tidy_conflict` when the item changed twice meanwhile or
another edit landed together with opv's, `tidy_unverified` when the item read back lacks
a field opv wrote or kept); the command itself still succeeds or fails on its own result.
opv never tidies an item holding an attachment, a website list, a one-time password, an
SSH key or any other field type it does not rewrite exactly; it says so in one note.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 2 | configuration or command-line usage error |
| 3 | dependency: `op`, `flyctl`, `az` or `kubectl` missing or unusable (including a Windows `op.exe` for `run` under WSL), or output cannot be written |
| 4 | 1Password: the item or vault could not be read or written |
| 5 | target (Fly, Azure, Kubernetes): refused or failed, including an unhealthy revision or rollout (the previous one keeps serving) and an update refused with nothing applied (`update_refused`) |
| 6 | refused by policy: blocking keys, a missing or wrong `--confirm`, a stale `--expect-plan`, a command that needs your own terminal |
| 7 | authentication: not signed in to 1Password or the target CLI, or `deploy_credentials` rejected |
| 8 | findings: `status`, `plan`, `check` (or `doctor --env`) found keys missing or failing a rule |
| 9 | outcome unknown, or a provider did not answer: nothing is known to be broken; re-run the same command ([exit 9](how-opv-handles-failures.md#exit-9-re-run-the-same-command)) |
| 130 / 143 | interrupted by Ctrl-C (SIGINT) or SIGTERM; safe to re-run |

CI may retry a job that exited 9; codes 2 to 8 need a fix first. `run` exits with the child's own exit code, which can equal one of these; opv's own errors print `opv: ...` on stderr. A closed stdout (`status | head`) does not change the result. With `--json`, `error.code` names the cause within a category ([codes](#json-contract)).

## GitHub Actions example

```yaml
jobs:
  sync-secrets:
    runs-on: ubuntu-latest
    env:
      OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      FLY_API_TOKEN: ${{ secrets.FLY_API_TOKEN }}
      OP_CACHE: "false"
      OPV_VERSION: v0.7.0   # pin the release you tested; bump it deliberately
    steps:
      - uses: actions/checkout@v4
      - name: Install the 1Password CLI
        uses: 1password/install-cli-action@v1
      - name: Install flyctl
        uses: superfly/flyctl-actions/setup-flyctl@master
      - name: Install opv
        run: |
          base=https://github.com/matt-cochran/1password-vault/releases/download/$OPV_VERSION
          curl -fsSLO "$base/opv-x86_64-unknown-linux-musl"
          curl -fsSLO "$base/SHA256SUMS"
          sha256sum -c SHA256SUMS --ignore-missing
          install -m 0755 opv-x86_64-unknown-linux-musl /usr/local/bin/opv
      - name: Stage secrets on Fly
        run: opv sync prod
```

CI uses one 1Password service-account token (`OP_SERVICE_ACCOUNT_TOKEN`), scoped to the vaults the job needs. The target credential comes either from `deploy_credentials` in that vault (opv reads it and hands it to the target CLI for the run only, so the job needs no `FLY_API_TOKEN` secret of its own) or from the CI provider's OIDC federation (for example `azure/login` with a federated credential), which needs no stored secret at all. Never give CI a break-glass credential.

This stages without deploying; a later `fly deploy` (or `opv sync prod --deploy`) applies everything staged by every tool. Install `op` and `flyctl` on the runner first (for example with the official 1Password and Fly GitHub Actions); on Azure or Kubernetes, install `az` or `kubectl` instead of `flyctl` and sign the runner in to it (or use `deploy_credentials`). An environment with `confirm_env = true` also needs `--confirm <env>` in the job.

**One product at a time on a shared Fly app, with delivery receipts.** With each target's own `state_vault_id` and a deploy identity that reads the boundary vaults and writes the state vault:

```yaml
      - name: Deliver api's secrets and keep the receipt
        run: opv sync prod --product api --expect-plan "$PLAN_ID" --receipt api.receipt.json
      - uses: actions/upload-artifact@v4
        with: { name: api-delivery, path: api.receipt.json }
      # Later, before reusing an accepted record (read-only; exit 8 unless verified):
      - name: Is api still exactly what was delivered?
        run: opv delivery verify prod --product api --receipt api.receipt.json --json
```

The receipt names `api`'s revision and binding set, never a value or digest. Another product's later sync leaves `api` verified, and a rotation of `api`'s values or of a shared value it reads does not. See [delivery receipts](#delivery-receipts-opv-sync---receipt-and-opv-delivery-verify).

**Job summary.** When `$GITHUB_STEP_SUMMARY` is set (GitHub Actions sets it for every step), `status`, `plan` and `sync` append a Markdown section to the job's summary page: for `status` and `plan`, the count line, `changes` (plan) and one table row per key, problems first, with target, product, key, kind, state word (`failed <rule>`, without the reason) and on-target word; for `sync`, its summary line and the written, pruned, pending, held, extra and unchanged names. It holds names and state words only: no value, no rule reason and no 1Password link (the link names your account). Nothing to configure; outside GitHub Actions nothing is written. For a nightly drift check, run `opv plan prod --json` and alert when `changes` is `some`.

Rate limits: a cold whole-item read costs about 2 requests, so a fleet sync costs a handful per environment. 1Password Families service accounts allow 1,000 requests per hour per token and 1,000 per day for the account. `OP_CACHE=false` makes the cost the worst case, since `op` caches by default on Linux and macOS.

## Security model and limits

- Values travel only on stdin (on native Windows, a user-only named pipe for `az`) or in the environment of a child process. opv is designed to keep secret-kind values out of argv and reporting output; the private Azure credential-cache exception and other limits are described below.
- One documented exception to "no files" (SR-4): with Azure `deploy_credentials`, the Azure CLI stores the service principal's secret in opv's private per-run `AZURE_CONFIG_DIR`, which is RAM-only on Linux/WSL, DPAPI-encrypted on Windows, and removed when the run ends. macOS is not supported for Azure deploy credentials.
- The stderr of `op`, `flyctl`, `az` and `kubectl` is shown only scrubbed, at most 5 lines on failure (more with `--verbose`); their stdout and what opv sends on stdin are never shown ([details](how-opv-handles-failures.md#what-a-cli-said-without-the-secrets)).
- `serde` can leave transient scratch copies of values in memory while parsing `op` output; opv wraps values in redacting, zeroizing types but cannot control those copies.
- `config export` prints config-kind values by design, never secrets. A config key stored in a concealed field is accepted and delivered as a plain value, but opv never prints it: `config export` shows `<concealed in 1Password>` and `status` warns about it once per key.
- `run` hands secret values to the child process through `op run`; the child can read them.
- No multiline values (a `pem_private_key` transform turns a PEM key into one line). `--json` documents hold names, states and counts only, except `config export <env>`, which prints config-kind values by design.
- Settings health findings (`opv ready`, `opv doctor --settings`, `opv ui`) never contain a value, but by design they state facts about one: that a secret equals another (across environments or keys), is a known placeholder, starts or ends with whitespace, points at `localhost`, or is a Stripe-style test or live key. Treat `ready --json` output like the configuration (fine for CI logs you trust, not for public ones), or skip it there. `opv history` never shows a Fly version, which is a digest of the value.
- In CI a release reads each item once, by vault ID and item ID.

See [SECURITY.md](../SECURITY.md) to report a vulnerability.
