# Using opv

Every command and flag, what each prints, the JSON contract and the exit codes. `opv <command> --help` shows the same for the version you run, and `opv schema` prints it as JSON. Where the configuration comes from and what it holds is in [configuration](configuration.md); retries, exit 9, `Next:`/`Do:` and interruptions are in [how opv handles failures](how-opv-handles-failures.md).

## Commands

| Command | What it does | Changes |
|---|---|---|
| `opv login [<env>] [-- <cmd>]` | sign in to the environment's 1Password account: a signed-in terminal, or one command | nothing; needs your own terminal |
| `opv setup [--product <p>] [--recipe <file>] [--account <a>]` | guided, resumable onboarding from `opv.setup.toml` ([guided setup](guided-setup.md)) | the 1Password item; needs your own terminal |
| `opv doctor [--env <env> [--product <p>]] [--json]` | find setup problems and show the next step | nothing |
| `opv check <env> [--product <p>] [--json]` | are the keys saved and valid? no target is contacted | nothing |
| `opv status [<env>] [--product <p>] [--all] [--json]` | 1Password and the target side by side, names only | nothing |
| `opv plan <env> [--product <p>] [--json]` | what a sync would do, and its plan id | nothing |
| `opv sync <env> [--deploy] [--prune] [--expect-plan <id>] [--confirm <env>] [--product <p>] [--json]` | write to the target; deploy only with `--deploy` | the target |
| `opv run <env> [--product <p>] -- <cmd>` | run a command with the keys as environment variables ([local development](local-development.md)) | nothing |
| `opv explain <[product/]KEY> [--env <env>] [--json]` | what the configuration says about one key | nothing |
| `opv open <[product/]KEY> [--env <env>] [--print] [--json]` | open the key's item in 1Password, where its value is typed | nothing |
| `opv init <env> --vault <title> --item <title> [target options]` | configuration from an existing item ([configuration](configuration.md#start-from-an-existing-item-opv-init)) | the manifest or `secrets.toml` |
| `opv add <[product/]KEY> --kind secret\|config [...]` | declare a key, or add environments to one | the configuration |
| `opv item skeleton <env> [--json]` | add every missing declared field to the item, empty | the 1Password item |
| `opv config export [<env>] [--toml\|--json]` | print the configuration, or an environment's config values | nothing |
| `opv config import --vault <v> [--file <f>] [--project <p>] [--path <dir>]...` | save a `secrets.toml` as the project manifest | 1Password (a new manifest) |
| `opv config edit` | edit, validate, diff and save the configuration | the configuration; needs your own terminal |
| `opv config check --file <f>` | compare a committed copy with the manifest | nothing |
| `opv projects [--long] [--json]` | projects whose configuration lives in 1Password | nothing |
| `opv help states`, `opv help <command>` | what each state word means; a command's help | nothing |
| `opv completions <bash\|zsh\|fish\|powershell>` | a shell completion script | nothing |
| `opv schema` | the installed binary as one JSON document | nothing |
| `opv guide agent` | the setup guide for AI assistants, for this version | nothing |

"Nothing" means nothing on your targets and no change to what a value means. Run by a person signed in with their own session, a command that reads an item may also tidy its 1Password layout once (missing sections and empty fields, labels, duplicates; nothing is deleted, [store layout](configuration.md#store-layout)); a service account, Connect, CI or a run under `deploy_credentials` never writes to 1Password.

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

`status` shows what is missing or failing a rule, problems first, each with its reason, its declared `guidance` and an `open:` link to its item in 1Password. `plan` adds what a sync would do and ends with the command that does it. `sync` writes. All three read the environment's item once, by IDs, and print names, never values.

```text
$ opv status prod
prod: 2 keys · 0 saved · 0 skipped · 2 findings · 0 not yet on Fly
PRODUCT  KEY             KIND    STATE                                             TARGET
api      LOG_LEVEL       config  failed enum (expected one of: debug, info, warn)  n/a
    open: https://start.1password.com/open/i?a=ACCOUNTID&v=vprd&i=iprd&h=my.1password.com (section api, field LOG_LEVEL)
api      OPENAI_API_KEY  secret  missing                                           unknown
    guidance: OpenAI platform / API keys
    open: https://start.1password.com/open/i?a=ACCOUNTID&v=vprd&i=iprd&h=my.1password.com (section api, field OPENAI_API_KEY)
unknown: Fly does not reveal stored values, so opv cannot compare them; sync stages them and compares digests (opv help states)
opv: 2 findings
Do: fix the keys above in 1Password
Next: opv open api/LOG_LEVEL --env prod
```

The first line counts the rows. `status`, `plan` and `check` exit 8 when a key is missing or failing a rule. On Azure and Kubernetes, `status` also prints when opv last changed the target (`Azure: last changed by opv 0.5.0 at 2026-10-08T14:02:11Z (plan 7f3c9a1e)`) and reports drift.

`sync` refuses (exit 6) and writes nothing while any key is missing or failing a rule, naming every blocking key and the `opv explain` command for them, and it checks the target read-only before its first write ([checks before the first write](how-opv-handles-failures.md#checks-before-the-first-write)). Nothing is deployed without `--deploy` and nothing removed without `--prune`. `--rotate <product/KEY>` (repeatable) writes an immutable key that is already on the target; `--prune-immutable <product/KEY>` (repeatable) lets `--prune` remove one. On Fly, values are staged with `flyctl secrets import --stage`, values on stdin.

### States

`status`, `plan` and `check` use one small set of words, the same on every provider. `opv help states` prints them.

| Column | Word | Meaning |
|---|---|---|
| STATE (1Password) | `saved` | stored and passes every rule; either field type is accepted (a config key stored concealed is delivered as a plain value, opv never prints its value, and `status` warns about it once) |
| | `missing` | no field with this name in the item's section |
| | `failed` | fails a rule; the rule and the reason follow: `failed enum (expected one of: debug, info)` |
| | `skipped` | not required in this environment |
| | `blocked by source` | shares another key's value and that key has a finding; fixed with it and not counted again ([Shared keys](#shared-keys)) |
| TARGET | `new` | not on the target yet; the next sync writes it |
| | `same` | on the target with the same value (Azure, Kubernetes) |
| | `changed` | on the target with another value; the next sync writes it |
| | `unknown` | on the target, but Fly does not reveal values, so opv cannot compare them; sync stages and compares digests |
| | `pending` | written but not yet live; the next `sync --deploy` rolls it out |
| | `held` | immutable and already set; replace it with `--rotate` |
| | `extra` | on the target but not wanted in this environment; removed only with `--prune` (sync prints `extra, not pruned`) |
| | `drift` | the app is bound to something other than what opv last wrote |
| | `n/a` | not a target secret (config keys, and skipped keys that are not on the target) |

`missing` and `failed` are findings. In `status` and `plan` their rows come first, so a 40-key fleet with one problem shows it on the first table line. The JSON `state` and `target` fields keep their own spellings (below).

### Open a key in 1Password

```sh
opv open <[product/]KEY> [--env <environment>] [--print] [--json]
```

Every missing or failing row in `status`, `plan` and `check` carries the link to its item, with the field to fix:

```text
allumata  OPENAI_API_KEY  secret  missing  new
    guidance: OpenAI platform / API keys
    open: https://start.1password.com/open/i?a=<account>&v=vprd&i=iprd&h=my.1password.com (section allumata, field OPENAI_API_KEY)
```

The link is 1Password's private item link, the form "Copy Private Link" produces: account, vault and item IDs and the sign-in host, never a value. 1Password links to items, not single fields, so the section and field are named next to it. opv takes the account from one free `op whoami` call, made only when there is something to fix; when that call fails the link has the vault and item only.

`opv open` resolves the key as `explain` does (a bare `KEY` under one product, `--env` optional with one environment), prints its section and field and the link, and opens the link with the desktop's opener: `xdg-open` (Linux with a display), `wslview` (WSL), `open` (macOS) or `rundll32 url.dll,FileProtocolHandler` (Windows). The opener gets the link as its only argument; no shell is involved. Over SSH, under CI, on a machine without a display, or with `--print` it only prints the link, which is what an assistant should show its user. It never reads the item. A shared key (`from = ...`) opens its source's field. `--json` prints `{environment, product, key, section, field, open_url}` and opens nothing.

### Every environment: `opv status`

Without an environment, `status` prints one line per environment, in name order:

```text
dev: run-only · 6 keys · 5 saved · 0 skipped · 1 finding
prod: 14 keys · 13 saved · 1 skipped · 0 findings · 0 not yet on Fly
staging: 14 keys · 11 saved · 1 skipped · 2 findings · 1 not yet on Fly
```

It reads each environment's item once, a run-only environment's too, so a green overview means every environment is green. An environment it cannot read is one line `prod: not checked (<error>)` and the others are still shown; the exit code is that error's, else 8 when any environment has findings (with `Next: opv status <env>`, or `opv check <env> --product <p>` for a run-only one, for the first), else 0.

`--product <p>` (or `OPV_PRODUCT`) counts only that product's keys in every line. `--json` prints one document instead:

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

`projects` makes one metadata listing per 1Password account op knows (no manifest is read unless `--long`). `status --all` reads each manifest once and then does what `opv status` does per environment, with the usual read retries; a project that cannot be read is one line `name (vault V): not read (<reason>)` and the others still run. `status --all --product <p>` (or `OPV_PRODUCT`) lists only the projects that declare `<p>` and counts only its keys. Its `Next:` is a command (never an error's prose) and names the project, so it runs from any directory: `Next: env OPV_PROJECT=myapp opv status dev`. In `--json`, an environment that could not be read carries that command as `next`. Both take `--json`. Names only, never values.

### Plan

`plan` starts with one count line, then the rows, then what a sync would do, by name, and ends with the sync command that applies exactly this plan:

```text
prod: 4 keys · 0 findings · 1 to stage · 1 held (immutable) · 1 to prune · 1 unmanaged on Fly (never touched)
PRODUCT   KEY                  KIND    STATE    TARGET
allumata  OPENAI_API_KEY       secret  saved    unknown
allumata  INTEGRATION_ENC_KEY  secret  saved    held
allumata  SIGNUP_POLICY        config  saved    n/a
allumata  STRIPE_SECRET_KEY    secret  skipped  extra
unknown: Fly does not reveal stored values, so opv cannot compare them; sync stages them and compares digests (opv help states)
would stage: allumata/OPENAI_API_KEY (FLEET__ALLUMATA__OPENAI_API_KEY)
would prune (needs --prune): allumata/STRIPE_SECRET_KEY (FLEET__ALLUMATA__STRIPE_SECRET_KEY)
held (immutable): allumata/INTEGRATION_ENC_KEY (FLEET__ALLUMATA__INTEGRATION_ENC_KEY) (pass --rotate PRODUCT/KEY to replace)
plan 7f3c9a1e (1Password item v41): sync --expect-plan 7f3c9a1e applies exactly this plan and refuses if the item, the target or secrets.toml changed
Next: opv sync prod --deploy --prune --expect-plan 7f3c9a1e
```

On Azure and Kubernetes the line says `would write`. The `Next:` command carries the plan id (`--expect-plan`, which also stands for `--confirm` on a [guarded environment](#guarded-environments)), adds `--prune` only when something would be pruned and `--product` when you scoped the plan. When a key blocks the sync, `plan` lists it first with its `open:` link, says `would stage once the findings are fixed:`, exits 8 with `Do: fix the keys above in 1Password`, and its `Next:` line opens the first key in 1Password.

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

Fly digests cannot be computed locally, so opv cannot tell in advance whether a value changed. `sync` reads Fly's secret metadata, stages, reads it again and compares the digests. Fly's list can lag right after staging, so the second read is repeated (for up to 30 seconds, with a progress line on stderr) until every staged name shows a digest; a name still without one counts as changed. `plan` therefore shows a desired key that is already on Fly as `unknown`. An immutable key already on Fly is "held" and is not staged unless you pass `--rotate` for it. On Azure, opv reads each listed Key Vault secret and compares it exactly, so `plan` shows `same` or `changed` instead.

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
- **Prune order.** `--prune` without `--deploy` only lists what it would remove. With `--deploy`, opv removes a name from the app first, waits for the healthy revision, and only then deletes it from the store. It deletes only entries it tagged `opv-managed=<env>`, and only names the configuration declares; other names are counted as unmanaged and left alone.
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

`sync` names each key as `product/KEY (TARGET_NAME)` (`KEY` alone under the simple profile) and ends with one summary line, the same on Fly, Azure and Kubernetes:

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
  "ok": true,
  "environment": "prod",
  "provider": "fly",
  "product": null,
  "written": [{"product": "api", "key": "OPENAI_API_KEY", "target_name": "FLEET__API__OPENAI_API_KEY"}],
  "unchanged": [{"product": "api", "key": "DATABASE_URL", "target_name": "FLEET__API__DATABASE_URL"}],
  "held": [],
  "deployed": false,
  "revision": null,
  "deploy_reason": [],
  "deployed_names": [],
  "pending": [{"product": "api", "key": "OPENAI_API_KEY", "target_name": "FLEET__API__OPENAI_API_KEY"}],
  "pruned": [],
  "kept": [],
  "skipped": [],
  "written_names": ["FLEET__API__OPENAI_API_KEY"],
  "plan_id": "7f3c9a1e",
  "next": "opv sync prod --deploy",
  "do": null
}
```

Lists follow the summary line's order and hold `{product, key, target_name}` objects (`product` is `null` under the simple profile). `deploy_reason` says why a deploy happened (`written`, `pruned`, `pending_from_earlier_run`), `deployed_names` and `written_names` are bare target names, and `next` is the `Next:` command or `null`. Every failure ends with one `Next:` line ([what a failure looks like](how-opv-handles-failures.md#what-a-failure-looks-like)); with `--json`, stdout is then the [failure document](#json-contract).

### One product: `--product`

`status`, `plan` and `sync` take `--product <p>` under the fleet profile:

- `status` and `plan` show only that product's rows; the count line, the totals and the exit-8 findings count that product only, so another team's missing key does not turn your status red. `OPV_PRODUCT` is the default for both.
- `sync --product <p>` writes, prunes and deploys only that product's managed names; `--prune` never removes another product's name, and another product's missing key does not block it. A Fly deploy still restarts the whole app with every staged change: when another product has staged changes waiting, sync prints `pending for other products: web/TOKEN (FLEET__WEB__TOKEN); a deploy restarts the app with them too`. `OPV_PRODUCT` is never used by `sync`.

### Guarded environments

If an environment sets `confirm_env = true` ([configuration](configuration.md#guarding-an-environment-confirm_env)), `sync` refuses (exit 6) before the first write unless you repeat the name (the read-only checks run first, so blocking keys are reported in the same refusal): `opv sync prod --deploy --confirm prod`. The refusal ends with that exact command, with every flag you gave:

```text
opv: policy denied: environment prod is guarded (confirm_env = true): sync needs --confirm prod; nothing was changed
Next: opv sync prod --deploy --confirm prod
```

A `--confirm` that names another environment is refused everywhere, guarded or not. The `Next:` line after a guarded sync includes `--confirm <env>`; `plan`'s carries `--expect-plan <id>` instead, which is enough on its own. `--prune` always lists the names it will remove before it acts.

### Pruning on Fly

Nothing is deleted by default. `--prune` unsets only names that the template produces for declared keys that are not desired in this environment. Names outside that set are never touched. Immutable keys are never pruned unless named with `--prune-immutable`; they are reported as "held (immutable), not pruned". A name staged by the same run is never pruned. A key you delete from `secrets.toml` is no longer declared, so it is neither reported nor pruned: unset it manually with `flyctl secrets unset`.

Known limitation: Fly hides an unset name as soon as `flyctl secrets unset --stage` runs, before any deploy. A run interrupted between that unset and the deploy (Ctrl-C, CI cancel, lost network, or a run without `--deploy`) leaves the name on the machines, and the next run cannot see it, so it neither reports nor deploys it. Any later deploy finishes the removal: run `opv sync <env> --deploy` again (it deploys when anything else changed or is pending), or `flyctl secrets deploy --app <app>`, which always deploys.

### Shared keys

A key declared with `from = "<product>/<KEY>"` ([configuration](configuration.md#shared-keys-from)) has a row of its own in `status`, `plan` and `check`, with the source under it:

```text
PRODUCT  KEY           KIND    STATE              TARGET
api      DATABASE_URL  secret  missing            new
    affects worker/DATABASE_URL
    guidance: Neon / connection string
worker   DATABASE_URL  secret  blocked by source  new
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

Under the simple profile the form is `opv explain <KEY> [--env <environment>]`: the reference is the unsectioned field `op://<vault_id>/<item_id>/<KEY>` and the Fly name is the key. Other providers show their own rows (`env name:`, `key vault name:`, ...), and every value starts in one column. An environment without a target section shows `target:     none (run-only)`. The fleet form `<product>/<key>` is a configuration error under the simple profile that names the bare key (`did you mean KEY?`). Under the fleet profile a bare `<KEY>` resolves to the one product that declares it; when several do, the error lists them (`ambiguous key "KEY": declared as api/KEY, web/KEY`). An undeclared key or product suggests the closest declared names; when exactly one is close, the `Next:` line is `opv explain <that name>`.

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
- With `deploy_credentials`, a failed sign-in is one `FAIL deploy credentials` line; the other checks still run.
- `--json` prints `{schema_version, ok, config_source, checks: [{name, status: ok|warn|fail|skip, detail, next, do}], next, do}`; the top-level `next` and `do` are the first failing check's, or `null`.
- With no configuration at all, the config line lists both ways to start (`opv init` for an existing item, `opv setup` for a project that ships `opv.setup.toml`).

## Sign-in: `opv login`

`opv login <env>` signs in to the 1Password account that environment uses (its `account` setting), at 1Password's own prompts, and opens a signed-in terminal (type `exit` to leave it); `opv login <env> -- <command>` runs one command signed in and exits with its code. No token is printed and nothing needs `eval`. Without an environment it uses the one account every environment uses (or your default account), and asks which environment when they differ. Sessions for environments in different accounts coexist in one terminal (`OP_SESSION_<account>` each), and every command uses the account of the environment it acts on. Every sign-in hint opv prints is `opv login <env>`.

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
| `manifest_not_found` | 2 | after_fix | no | no 1Password manifest has the project's title (OPV_PROJECT or .opv) |
| `manifest_ambiguous` | 2 | after_fix | yes | several 1Password manifests match; a person keeps one and archives the others |
| `manifest_exists` | 2 | never | no | a manifest for this project already exists; change it with opv config edit |
| `config_changed` | 2 | safe | no | the configuration changed while opv was editing it: nothing was written and re-running is safe, or (when the error says so) another edit landed with opv's and a person checks the manifest's history |
| `config_invalid` | 2 | after_fix | no | secrets.toml or a flag value is not valid |
| `unknown_env` | 2 | never | no | the environment is not defined in secrets.toml |
| `unknown_product` | 2 | never | no | the product is not declared, or the simple profile takes none |
| `undeclared_key` | 2 | never | no | the key is not declared (for this environment) |
| `no_target` | 2 | never | no | the environment has no deployment target (run-only) |
| `dependency_missing` | 3 | after_fix | no | op or the target CLI is missing or unusable |
| `source_error` | 4 | after_fix | no | 1Password could not be read |
| `item_not_found` | 4 | after_fix | no | the item is not in the vault (moved, archived, deleted, or a wrong item_id) |
| `vault_no_access` | 4 | after_fix | yes | the signed-in identity cannot access the vault |
| `item_changed` | 4 | after_fix | yes | opv setup: the 1Password item changed while setup was saving it: again after setup re-read it (nothing was written; run opv setup again), or another edit landed with setup's or a field setup wrote is missing (a person checks the item's history) |
| `target_error` | 5 | after_fix | no | the target (Fly, Azure, Kubernetes) refused or failed |
| `target_unhealthy` | 5 | after_fix | no | the new revision did not become healthy; the previous one keeps serving |
| `update_refused` | 5 | after_fix | no | the target refused the update and applied nothing; the previous revision keeps serving; re-running repeats the refusal |
| `policy_refused` | 6 | after_fix | no | opv refused the operation |
| `keys_blocking` | 6 | after_fix | yes | sync refused: keys are missing or failing a rule; nothing was written |
| `confirm_required` | 6 | never | yes | the environment sets confirm_env; pass --confirm <env> |
| `confirm_mismatch` | 6 | never | no | --confirm names another environment |
| `stale_plan` | 6 | never | no | sync --expect-plan: the plan changed since it was reviewed (the item, the target or the configuration); nothing was changed; review the new plan |
| `ram_dir_unavailable` | 6 | after_fix | no | deploy credentials for Azure need a private RAM-backed directory (XDG_RUNTIME_DIR on Linux, %LOCALAPPDATA%\Temp on Windows) and none is usable; nothing was read or changed |
| `terminal_required` | 6 | never | yes | the command needs the user's own interactive terminal |
| `auth_required` | 7 | after_fix | yes | not signed in to 1Password or the target CLI |
| `op_not_signed_in` | 7 | after_fix | yes | not signed in to 1Password |
| `deploy_credentials_failed` | 7 | after_fix | yes | the environment's deploy credentials in 1Password were rejected or are incomplete; nothing was changed |
| `findings` | 8 | after_fix | yes | keys are missing or failing a rule (values are filled in 1Password by a person) |
| `outcome_unknown` | 9 | safe | no | a change may or may not have been applied; re-running is safe |
| `provider_unavailable` | 9 | safe | no | a provider did not answer after its retries; nothing was changed |
| `interrupted` | 130/143 | safe | no | interrupted by SIGINT (130) or SIGTERM (143); re-running is safe |
| `tidy_conflict` | 4 | safe | no | the 1Password item changed while opv was tidying it: twice before the write (nothing was written), or another edit landed with opv's (check the item's history; opv never retries); never a failure: reported in a document's tidy_error while the command reads the item as it is |
| `tidy_unverified` | 4 | after_fix | yes | opv tidied the 1Password item but the item read back lacks a field opv wrote or kept; a person restores it from the item's history; never a failure: reported in a document's tidy_error |
<!-- error-codes:end -->

`opv schema` prints a description of the installed binary as one JSON document: every command with its arguments, flags, whether it takes `--json`, what it changes (`effect`: `none`, `reads`, `opens_browser`, `writes_file`, `writes_1password`, `writes_target`, `runs_command`, `interactive`), whether it needs the user's terminal and whether to ask the user first, and the flags that add an effect of their own (`--deploy`: `deploys`, `--prune`: `deletes`, `--rotate`, `--prune-immutable`, `--confirm`, `init --force`); `init`'s provider options (`--fly-app`, `--azure-key-vault`, `--kubernetes-context`, ...), each with its `provider` and `required_with_target`; the exit codes, the error codes above, the state words and the fields of each document. It is generated from the binary itself, so it always matches the version you run:

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
      "product": "allumata",
      "key": "OPENAI_API_KEY",
      "kind": "secret",
      "state": "saved",
      "rule": null,
      "reason": null,
      "target_name": "FLEET__ALLUMATA__OPENAI_API_KEY",
      "fly_name": "FLEET__ALLUMATA__OPENAI_API_KEY",
      "target": "absent",
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
[Failure reasons](configuration.md#failure-reasons)); `target_name` is the key's name on the
target for every provider (`fly_name` holds the same value and is kept for older scripts; it
is deprecated); `target` is `present`, `absent` or `would_change` for a secret and `null` for
a config key; `action` is `would_stage`, `would_prune`, `held` or `null`. The same row shape,
in the same key order, is used by `status`, `plan` and `check`. With `--product`,
the document carries `"product": "<p>"` (otherwise `null`) and only that product's rows and
totals. `next` is the sync command for `plan`, `null` for `status`. `plan --json` adds
`"plan_id"` when nothing blocks ([`--expect-plan`](#review-then-apply-exactly-that-plan---expect-plan)),
and `status --json` on Azure or Kubernetes adds `"provenance": {"opv_version", "written",
"plan_id"}` once opv has stamped the target. The document is meant for the scheduled drift
check.

`opv status --json` without an environment prints one entry per environment:
`{"product", "environments": [{"name", "target", "state": "checked"|"run_only"|"not_checked", "keys", "saved", "skipped", "findings", "error_code", "error"}], "totals": {"environments", "findings"}}`. Run-only environments are read too (`state: "run_only"`, `target: null`).

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
      OPV_VERSION: v0.5.0   # pin the release you tested; bump it deliberately
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

**Job summary.** When `$GITHUB_STEP_SUMMARY` is set (GitHub Actions sets it for every step), `status`, `plan` and `sync` append a Markdown section to the job's summary page: for `status` and `plan`, the count line, `changes` (plan) and one table row per key, problems first, with product, key, kind, state word (`failed <rule>`, without the reason) and target word; for `sync`, its summary line and the written, pruned, pending, held, extra and unchanged names. It holds names and state words only: no value, no rule reason and no 1Password link (the link names your account). Nothing to configure; outside GitHub Actions nothing is written. For a nightly drift check, run `opv plan prod --json` and alert when `changes` is `some`.

Rate limits: a cold whole-item read costs about 2 requests, so a fleet sync costs a handful per environment. 1Password Families service accounts allow 1,000 requests per hour per token and 1,000 per day for the account. `OP_CACHE=false` makes the cost the worst case, since `op` caches by default on Linux and macOS.

## Security model and limits

- Values travel only on stdin (on native Windows, a user-only named pipe for `az`) or in the environment of a child process. They never appear in argv, files, logs, errors, `Debug` or `Display` output.
- One documented exception to "no files" (SR-4): with Azure `deploy_credentials`, the Azure CLI stores the service principal's secret in opv's private per-run `AZURE_CONFIG_DIR`, which is RAM-only on Linux/WSL, DPAPI-encrypted on Windows, and removed when the run ends. macOS is not supported for Azure deploy credentials.
- The stderr of `op`, `flyctl`, `az` and `kubectl` is shown only scrubbed, at most 5 lines on failure (more with `--verbose`); their stdout and what opv sends on stdin are never shown ([details](how-opv-handles-failures.md#what-a-cli-said-without-the-secrets)).
- `serde` can leave transient scratch copies of values in memory while parsing `op` output; opv wraps values in redacting, zeroizing types but cannot control those copies.
- `config export` prints config-kind values by design, never secrets. A config key stored in a concealed field is accepted and delivered as a plain value, but opv never prints it: `config export` shows `<concealed in 1Password>` and `status` warns about it once per key.
- `run` hands secret values to the child process through `op run`; the child can read them.
- No multiline values (a `pem_private_key` transform turns a PEM key into one line). `--json` documents hold names, states and counts only, except `config export <env>`, which prints config-kind values by design.
- In CI a release reads each item once, by vault ID and item ID.

See [SECURITY.md](../SECURITY.md) to report a vulnerability.
