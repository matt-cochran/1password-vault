# Using opv

## Workflow

Global option: `--config <PATH>`, or the `OPV_CONFIG` environment variable (the flag wins). Without either, opv looks for `secrets.toml` in the current directory and then each parent directory up to the filesystem root, uses the first one found (files are never merged), and prints `using <absolute path>` on stderr before the command runs. With `--config` or `OPV_CONFIG`, the path is used exactly as given and no search is done; a path from `OPV_CONFIG` is announced as `using <path> (from OPV_CONFIG)` on stderr. `init` refuses both, because it always writes `./secrets.toml`; `init --add-env` and `add` edit the configuration found this way, file or [manifest](configuration.md#configuration-in-1password). `<ENV>` is an environment name from the file.

`OPV_PRODUCT` is the default for `--product` on `check`, `run`, `doctor --env`, `explain` (where a bare `KEY` means `$OPV_PRODUCT/KEY`), `status <ENV>` and `plan`. It applies under the fleet profile only, never to `sync`, and opv prints `product <p> (from OPV_PRODUCT)` on stderr whenever it uses it. A single-product repository inside a fleet can export it once (for example in `.envrc`) and then run `opv run dev -- npm run dev`.

Every command's `--help` lists its own options first, then the global options (`--config`, `--timeout`, `--verbose`, `--color`) under `Global options:`, then a few examples.

```sh
opv login prod                      # sign in to prod's 1Password account; opens a signed-in terminal
opv doctor                          # config, op and sign-in, flyctl and sign-in, op local run
opv doctor --env dev --product allumata   # only what local work in dev needs, plus one read of its item
opv doctor --json                   # the same checks as one JSON document
opv init staging --vault myapp-staging --item myapp --fly-app myapp-staging   # starter secrets.toml
opv init prod --vault myapp-prod --item myapp --add-env --target kubernetes \
  --kubernetes-context prod --kubernetes-namespace myapp --kubernetes-deployment web   # one more environment
opv add api/STRIPE_KEY --kind secret --env staging,prod --rule prefix=sk_   # declare a key; comments kept
opv item skeleton staging           # add every missing declared field, empty; the only 1Password write
opv status                          # one line per environment
opv status staging                  # one row per product and key; exit 8 if any blocks
opv status staging --product api    # one product's rows, totals and findings
opv status staging --json           # the same state as one machine-readable JSON document
opv plan staging                    # what a sync would stage, hold and prune, and the command to run
opv plan staging --json             # the same plan as one machine-readable JSON document
opv sync staging [--deploy] [--prune] [--product P] [--confirm staging] [--json] [--rotate PRODUCT/KEY] [--prune-immutable PRODUCT/KEY]
opv config export staging --json    # config-kind values as JSON
opv explain allumata/OPENAI_API_KEY --env prod   # what opv knows about one key, from the config alone
opv check dev --product allumata    # each key saved, missing, wrong kind or failing a rule; exit 8 if any
opv run dev --product allumata -- cargo run
opv run prod -- ./server            # simple profile: no --product
```

1. `init` writes `secrets.toml` from an existing item, `init --add-env` adds an environment to it and `add` declares a key in it, all without hand-editing (see [configuration](configuration.md#declare-a-key-opv-add)). `item skeleton` creates the empty fields in the 1Password item. Fill them in 1Password.
2. `status` shows what is missing, of the wrong kind, or failing a rule. It prints names and the declared `guidance`, never values. Its first line counts the rows: `staging: 12 keys · 10 saved · 1 skipped · 1 finding · 2 not yet on Fly`.
3. `plan` shows the same rows plus the target side, then names what a sync would do and ends with the command that does it (see [Plan](#plan)). It changes nothing.
4. `sync` stages the values on the target (on Fly, through `flyctl secrets import --stage`, values on stdin; Azure and Kubernetes: [below](#sync-on-azure-and-kubernetes)). It refuses (exit 6) and stages nothing if any key is missing, of the wrong kind or failing a rule; the refusal names every blocking key and an `opv explain` command for them. Before its first write it checks the Fly app (`flyctl status`, `flyctl releases`): a deleted (`dead`) app stops it with nothing written. A Fly deploy already running is waited for: opv reads the releases again every 5 s, prints `waiting for the running Fly deploy of <app> (release vN) to finish, 15 s` on stderr at least every 15 s, and goes on once it has finished; if it is still running when the `--timeout` budget is nearly spent (or after 10 minutes), opv stops with nothing written and a `Next:` line. A suspended or never-deployed app has no machines; secrets are app-level, so staging goes ahead with a `warn  fly app <app>: no machines; ...` line, and `--deploy` prints `deploy skipped: <app> has no machines; staged secrets apply when machines start` (exit 0). Stopped machines are a `warn` line too.
5. `--rotate PRODUCT/KEY` (repeatable) stages an immutable key that is already on Fly. `--prune-immutable PRODUCT/KEY` (repeatable) lets `--prune` unset a named immutable key.
6. `config export <ENV> --json` prints the config-kind values for deployment tooling. `--json` is required and is the only format.
7. `check <ENV> [--product <p>]` validates the environment's keys for local work, by name only: it reads the item once, skips other products' sections, never calls a deployment target, and exits 8 when a key is missing, of the wrong kind or failing a rule. A failing key's declared guidance is printed under it as `  guidance: <text>`. `--json` prints `schema_version`, `environment`, `target_checked: false`, `rows` (product, key, state, rule, reason) and `findings`.
8. `run <ENV> --product <p> -- <cmd>` runs a command with the product's keys in its environment under plain names (`OPENAI_API_KEY`, not the Fly name), through `op run`. It first removes every key name declared in the configuration from the inherited environment, so another product's keys never leak in. It writes no `.env` file. See [Local development](#local-development).

### Next step

Every command that fails (any exit code other than 0, except `run`, which passes the command's own code through) ends with exactly one `Next:` line, the last line on stderr. It holds the command to run, or the fix and then the command:

```text
opv: policy denied: sync refused, nothing staged: api/OPENAI_API_KEY (missing)
Next: opv explain api/OPENAI_API_KEY --env prod
```

```text
opv: 1 finding
Next: fix the keys above in 1Password, then run opv check dev --product api
```

When the failure came from an external call, what that program wrote on stderr (at most 5 lines, every secret masked as `__SECRET__`) sits between the error line and `Next:`:

```text
opv: target error: az keyvault secret list failed for kv-prod
  az said: ERROR: (Forbidden) The user does not have secrets list permission
Next: opv doctor
```

A usage error ends with `Next: opv <command> --help`; an outcome that is unknown (exit 9) or an interruption (130/143) ends with the same command line and `(safe to re-run)`. Scripts and AI assistants can rely on the pattern `^Next: `. Guidance from the configuration is labelled `guidance:` and is never a `Next:` line.

`doctor` prints one line per check; a failing check has its fix on the line under it (`  fix: ...`) when the fix is not already in its text. When a check fails, `doctor` exits with the first failing check as the error, and its `Next:` line is that check's fix:

```text
FAIL  op auth: authentication error: not signed in to 1Password
...
opv: authentication error: op auth check failed (see the FAIL line above)
Next: sign in: opv login
```

On a machine a person signs in from (not CI, no service-account token) the sign-in step is `opv login <env>` (`opv login` when doctor has no `--env`), the same in every shell. Under CI it is the service-account wording instead.

With `--env`, doctor also reads that environment's item once, by IDs, and checks the selected product's keys as `check` does: `ok    item: <vault_id>/<item_id> readable (<n> field(s) in section <product>)`, or a `FAIL  item:` line naming each key that is missing, of the wrong kind or failing a rule, with `fill them in 1Password, then opv check <env> --product <p>` as the next step (exit 8). So doctor is never all clear when `check` would fail. Without `--env` no item is read.

`--json` prints `{"schema_version": 1, "checks": [{"name", "status": "ok"|"warn"|"fail"|"skip", "detail", "next"}], "next"}`: `detail` is the check's first line (names, versions and commands only), `next` its remediation or `null`, and the top-level `next` is the first failing check's step, or `null` when nothing is pending. The exit code is the same as without `--json`; on failure stderr still ends with the `Next:` line.

With no `secrets.toml` at all, the `Next:` step is `opv init <env> --vault <vault title> --item <item title>` for an existing item; the config line also lists `opv setup` for a project that ships `opv.setup.toml` and `--config <path>`. An invalid configuration always gets `Next: fix secrets.toml (see the config line above), then run opv doctor`; another failure with no command of its own gets `Next: fix the <check> failure above, then run opv doctor`. When every check passes, the last line is `Next: nothing pending`. The line is text, never a prompt.

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
```

Under the simple profile the form is `opv explain <KEY> [--env <environment>]`: the reference is the unsectioned field `op://<vault_id>/<item_id>/<KEY>` and the Fly name is the key. Other providers show their own rows (`env name:`, `key vault name:`, ...), and every value starts in one column. An environment without a target section shows `target:     none (run-only)`. The fleet form `<product>/<key>` is a configuration error under the simple profile that names the bare key (`did you mean KEY?`). Under the fleet profile a bare `<KEY>` resolves to the one product that declares it; when several do, the error lists them (`ambiguous key "KEY": declared as api/KEY, web/KEY`). An undeclared key or product suggests the closest declared names; when exactly one is close, the `Next:` line is `opv explain <that name>`.

It reads only the configuration: no 1Password or Fly call, and no value or value fragment (it is not a `secret get`). `--env` may be omitted when the configuration declares exactly one environment. An undeclared product, key or environment, or an environment the key is not declared for, is a configuration error (exit 2).

### Machine-readable status and plan

`status <ENV> --json` and `plan <ENV> --json` print exactly one JSON document on stdout
and nothing else. It contains names, states and counts only: no value, no value fragment,
no value length and no guidance. Exit codes are unchanged, and an error is still reported
on stderr with no partial document on stdout. The top-level `schema_version` is `1`; adding
a field keeps it, while renaming or removing a field, or changing its meaning, increments it.

```json
{
  "schema_version": 1,
  "environment": "prod",
  "rows": [
    {
      "product": "allumata",
      "key": "OPENAI_API_KEY",
      "kind": "secret",
      "state": "saved",
      "rule": null,
      "reason": null,
      "fly_name": "FLEET__ALLUMATA__OPENAI_API_KEY",
      "target_name": "FLEET__ALLUMATA__OPENAI_API_KEY",
      "target": "absent",
      "action": "would_stage"
    }
  ],
  "extras": [],
  "stage": ["FLEET__ALLUMATA__OPENAI_API_KEY"],
  "held": [],
  "prune": [],
  "totals": { "rows": 1, "findings": 0, "extras": 0, "to_stage": 1, "held": 0, "to_prune": 0 }
}
```

`state` is `saved`, `missing`, `wrong_kind`, `failing_rule` or `skipped`; `rule` names the
failing rule when `state` is `failing_rule`, and `reason` says why (see
[Failure reasons](configuration.md#failure-reasons)); `target_name` is the key's name on the
target for every provider (`fly_name` holds the same value and is kept for older scripts; it
is deprecated); `target` is `present`, `absent` or `would_change` for a secret and `null` for
a config key; `action` is `would_stage`, `would_prune`, `held` or `null`. With `--product`,
the document carries `"product": "<p>"` and only that product's rows and totals. `plan
--json` adds `"plan_id"` when nothing blocks ([`--expect-plan`](#review-then-apply-exactly-that-plan---expect-plan)),
and `status --json` on Azure or Kubernetes adds `"provenance": {"opv_version", "written",
"plan_id"}` once opv has stamped the target. The document is meant for the scheduled drift
check.

### One product: `--product`

`status`, `plan` and `sync` take `--product <p>` under the fleet profile:

- `status` and `plan` show only that product's rows; the count line, the totals and the exit-8 findings count that product only, so another team's missing key does not turn your status red. `OPV_PRODUCT` is the default for both.
- `sync --product <p>` writes, prunes and deploys only that product's managed names; `--prune` never removes another product's name, and another product's missing key does not block it. A Fly deploy still restarts the whole app with every staged change: when another product has staged changes waiting, sync prints `pending for other products: web/TOKEN (FLEET__WEB__TOKEN); a deploy restarts the app with them too`. `OPV_PRODUCT` is never used by `sync`.

### Every environment: `opv status`

Without an environment, `status` prints one line per environment, in name order:

```text
dev: run-only (no target)
prod: 14 keys · 13 saved · 1 skipped · 0 findings · 0 not yet on Fly
staging: 14 keys · 11 saved · 1 skipped · 2 findings · 1 not yet on Fly
```

It reads each environment's item once. An environment it cannot read is one line `prod: not checked (<error>)` and the others are still shown; the exit code is that error's, else 8 when any environment has findings (with `Next: opv status <env>` for the first), else 0.

### Every project: `opv projects` and `opv status --all`

When configurations live in 1Password (see [configuration](configuration.md#configuration-in-1password)):

```text
$ opv projects
api: vault acme-dev; repo github.com/acme/platform; paths apps/api
web: vault acme-dev; repo github.com/acme/platform; paths apps/web
$ opv projects --long          # adds "environments dev, prod" (one read per project)
$ opv status --all
api (vault acme-dev):
  dev: run-only (no target)
  prod: 14 keys · 13 saved · 1 skipped · 0 findings · 0 not yet on Fly
```

`projects` makes one metadata listing per 1Password account op knows (no manifest is read unless `--long`). `status --all` reads each manifest once and then does what `opv status` does per environment, with the usual read retries; a project that cannot be read is one line `name (vault V): not read (<reason>)` and the others still run. Both take `--json`. Names only, never values.

### Configuration commands

| Command | What it does |
|---|---|
| `opv config export [--toml\|--json]` | print the configuration (no values) |
| `opv config export <env> --json` | that environment's config-kind values |
| `opv config import --vault V [--file F] [--project P] [--path D]...` | save a `secrets.toml` as the project manifest; never deletes the file |
| `opv config edit` | edit in `$VISUAL`/`$EDITOR`, validate, diff, confirm, save unless changed meanwhile |
| `opv config check --file F` | exit 8 with a diff when a committed copy differs from the manifest |

### Plan

`plan` starts with one count line, then the rows, then what a sync would do, by name, and ends with the sync command:

```text
prod: 4 keys · 0 findings · 1 to stage · 1 held (immutable) · 1 to prune · 1 unmanaged on Fly (never touched)
PRODUCT   KEY                  KIND    STATE    TARGET
...
would stage: allumata/OPENAI_API_KEY (FLEET__ALLUMATA__OPENAI_API_KEY)
would prune (needs --prune): allumata/STRIPE_SECRET_KEY (FLEET__ALLUMATA__STRIPE_SECRET_KEY)
held (immutable): allumata/INTEGRATION_ENC_KEY (FLEET__ALLUMATA__INTEGRATION_ENC_KEY) (pass --rotate PRODUCT/KEY to replace)
plan 7f3c9a1e (1Password item v41): sync --expect-plan 7f3c9a1e applies exactly this plan and refuses if the item, the target or secrets.toml changed
Next: opv sync prod --deploy --prune
```

On Azure and Kubernetes the line says `would write`. The `Next:` command adds `--prune` only when something would be pruned, `--product` when you scoped the plan, and `--confirm <env>` for a [guarded environment](#guarded-environments). When a key blocks the sync, `plan` exits 8 and the `Next:` line says to fix it and run `plan` again.

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

### Change detection on Fly

Fly digests cannot be computed locally, so opv cannot tell in advance whether a value changed. `sync` reads Fly's secret metadata, stages, reads it again and compares the digests. Fly's list can lag right after staging, so the second read is repeated (for up to 30 seconds, with a progress line on stderr) until every staged name shows a digest; a name still without one counts as changed. `plan` therefore shows a desired key that is already on Fly as "potentially changed". An immutable key already on Fly is "held" and is not staged unless you pass `--rotate` for it. On Azure, opv reads each listed Key Vault secret and compares it exactly, so `plan` shows "unchanged" or "changed" instead.

Staging uses stage semantics, so it coexists with other tools that stage secrets on the same Fly app. A deploy happens only with `--deploy`, and only when a staged digest changed, a prune happened, or a managed name is still pending on Fly (status Staged or Partial) from an earlier run. Deploying an app that has no machines exits 5.

### Sync on Azure and Kubernetes

On Azure and Kubernetes `sync` works in two steps, and the running app only changes in the second:

1. **Written.** Each changed secret is written to the store (Key Vault, or a Kubernetes Secret) as a new version. The app does not see it, even if it restarts or scales out, because it is bound to the old version.
2. **Deployed.** With `--deploy`, opv points the app at the new versions and sets any changed config, which starts a new revision (Container Apps) or rollout (Kubernetes). It then waits until that revision is healthy.

```sh
opv plan prod                            # what would be written and re-pinned; changes nothing
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
- **Clean-up.** After a healthy rollout opv deletes the ExternalSecrets (and with them their Secrets) that neither the Deployment nor any ReplicaSet references, so `kubectl rollout undo` keeps working. `--prune` deletes a pruned key's ExternalSecrets first and its Key Vault entry after. Key Vault keeps old versions as history.
- **`status`** prints one `chain:` line per bound key, e.g. `chain: DB_URL → Key Vault kv-myapp-prod (46687ce78b…) → ExternalSecret opv-db-url-46687ce78b → env DB_URL`.

Values reach `az` and `kubectl` only on stdin. On native Windows the Azure writes stop with a message that names WSL; `plan` and `status` work everywhere.

### Progress, summary and next step

Long steps print a progress line on stderr at least every 15 seconds (`waiting for revision ca-myapp--0000002: Provisioning, 45 s`).

`sync` names each key as `product/KEY (TARGET_NAME)` (`KEY` alone under the simple profile) and ends with one summary line, the same on Fly, Azure and Kubernetes:

```text
written: api/OPENAI_API_KEY (FLEET__API__OPENAI_API_KEY)
unchanged: api/DATABASE_URL (FLEET__API__DATABASE_URL)
pending deploy (pass --deploy): api/OPENAI_API_KEY (FLEET__API__OPENAI_API_KEY)
summary: written 1 · deployed no · pruned 0 · pending 1 · unchanged 1 · skipped 0
Next: opv sync prod --deploy
```

`written` counts new values (staged on Fly, new versions on Azure and Kubernetes); `deployed` is the revision name (`yes` on Fly, which names none) or `no`; `pending` counts names still waiting for a deploy after this run; `skipped` counts declared keys not desired in this environment. The `Next:` line follows only when something is left to do: a deploy for pending names, or `--prune` for names kept because `--prune` was not given. `--prune` prints `will prune: <names>` before it removes anything.

`sync --json` prints the same report as one JSON document on stdout (names only, never values; detail lines are not printed, and preflight warnings go to stderr):

```json
{
  "schema_version": 1,
  "environment": "prod",
  "provider": "fly",
  "product": null,
  "written": ["FLEET__API__OPENAI_API_KEY"],
  "deployed": false,
  "revision": null,
  "pruned": [],
  "pending": ["FLEET__API__OPENAI_API_KEY"],
  "unchanged": ["FLEET__API__DATABASE_URL"],
  "skipped": [],
  "held": [],
  "kept": [],
  "next": "opv sync prod --deploy",
  "plan_id": "7f3c9a1e"
}
```

Names are target names. `held` lists immutable keys left alone, `kept` names not desired here that stayed because `--prune` was not given, and `next` is the `Next:` command or `null`. Every failure ends with exactly one `Next:` line ([Next step](#next-step)); with `--json`, stdout is empty on failure.

### Retries, timeouts and interruptions

- **Reads are retried, writes are not.** A failed read (`op item get`, a list, a status check) is tried up to 3 times, with a 1 s then 2 s pause, printing `retrying az keyvault secret list (2/3) in 2 s`. A refusal such as not found or not signed in is never retried: when `op` says an item or vault does not exist, `kubectl` reports `NotFound`, or `az` reports a missing secret or resource, opv reports it at once (failure text it does not recognise keeps its retries). A write is never repeated blindly: opv reads the target back to see what happened.
- **One time budget.** `--timeout <secs>` (default 900) caps the whole run, including waits for a revision or rollout. There is no separate deploy timeout.
- **`--verbose`** prints one stderr line per external call: the program, its arguments, how long it took and the outcome. Under it come the call's own error output (`    stderr: ...`, every secret masked as `__SECRET__`) and the size and JSON shape of its result (`    stdout: 412 bytes, JSON object with keys: ...`). A result's content is never shown.
- **Safe to re-run.** Stopping opv at any point (Ctrl-C, a CI cancel, a lost connection) leaves the app working. Run the same command again and it finishes the rest.
- **Exit 9** means opv cannot tell what happened: a write may or may not have been applied, or 1Password, Fly, Azure or the cluster did not answer after 3 tries (nothing was written). Nothing is known to be broken. Check the provider's status page if one is named, then re-run the same command. CI may retry a job that exits 9.
- **Exit 130 / 143** means you pressed Ctrl-C or the job was terminated. opv names the step it stopped in.

### Guarded environments

If an environment sets `confirm_env = true` ([configuration](configuration.md#guarding-an-environment-confirm_env)), `sync` refuses (exit 6) before the first write unless you repeat the name (the read-only checks run first, so blocking keys are reported in the same refusal): `opv sync prod --deploy --confirm prod`. The refusal ends with that exact command, with every flag you gave:

```text
opv: policy denied: environment prod is guarded (confirm_env = true): sync needs --confirm prod; nothing was changed
Next: opv sync prod --deploy --confirm prod
```

A `--confirm` that names another environment is refused everywhere, guarded or not. `plan` and the `Next:` line after a guarded sync include `--confirm <env>`. `--prune` always lists the names it will remove before it acts.

### Pruning on Fly

Nothing is deleted by default. `--prune` unsets only names that the template produces for declared keys that are not desired in this environment. Names outside that set are never touched. Immutable keys are never pruned unless named with `--prune-immutable`; they are reported as "held (immutable), not pruned". A name staged by the same run is never pruned. A key you delete from `secrets.toml` is no longer declared, so it is neither reported nor pruned: unset it manually with `flyctl secrets unset`.

## Sign-in, accounts and deploy credentials

`opv login <env>` signs in to the 1Password account that environment uses, at 1Password's own prompts, and opens a signed-in terminal (type `exit` to leave it); `opv login <env> -- <command>` runs one command signed in and exits with its code. No token is printed and nothing needs `eval`. Without an environment it uses the one account every environment uses (or your default account), and asks which environment when they differ. Every sign-in hint opv prints, in `doctor` and in errors, is `opv login <env>`. Like `setup`, `login` needs your own interactive terminal; automation uses a service-account token instead.

`account = "<sign-in address or account ID>"` on an environment makes every `op` call for it use that account (`OP_ACCOUNT` in the child's environment). Logging in to two environments in different accounts in the same terminal keeps both sessions (`OP_SESSION_<account>` each), and `check`, `run`, `plan`, `status` and `sync` use the account of the environment they act on. With `OP_SERVICE_ACCOUNT_TOKEN` (or Connect) set, the token decides the account and `account` is not added.

`deploy_credentials = "op://<vault>/<item>"` names an item that holds only that environment's least-privilege deploy identity. `status`, `plan`, `sync` and `doctor --env` read it once and sign the target CLI in for that run only; `check`, `run`, `config export` and `item skeleton` never read it. Fields, by provider:

| Provider | Fields | How the run uses them |
|---|---|---|
| Fly | `FLY_API_TOKEN` (concealed) | set only in the environment of each `flyctl` call (`FLY_API_TOKEN`, and `FLY_ACCESS_TOKEN` so it wins over a token in your shell) |
| Azure | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` (text), `AZURE_CLIENT_SECRET` (concealed) | `az login --service-principal ... -p @<hand-off>` once, in a private `AZURE_CONFIG_DIR` used by every `az` call of the run and removed when it ends (also on Ctrl-C / SIGTERM; a directory left by a killed run is removed by the next one) |
| Kubernetes | only with `secrets_in` a Key Vault: the Azure fields, for the `az` that writes it | otherwise a configuration error: `kubectl` uses your kubeconfig (`kubernetes.context`) |

Azure deploy credentials, by OS (the Azure CLI stores the service principal's secret in its configuration directory):

| OS | Private `AZURE_CONFIG_DIR` | Supported |
|---|---|---|
| Linux, WSL | `$XDG_RUNTIME_DIR/opv-az.<pid>-<random>`, mode 0700; `$XDG_RUNTIME_DIR` must be on tmpfs (RAM) and owned by you | yes; without a RAM `$XDG_RUNTIME_DIR` opv refuses before reading anything |
| Windows | `%LOCALAPPDATA%\Temp\opv-az-<pid>-<random>`, ACL for you only; az encrypts the stored secret with DPAPI (`service_principal_entries.bin`) | yes; a plaintext `service_principal_entries.json` makes opv remove the directory and refuse |
| macOS | none | no: sign in with `az login` and remove `deploy_credentials`, or use OIDC in CI |

On native Windows, values reach `az` (the service-principal secret, Key Vault values, the Container App update) through a named pipe `\\.\pipe\opv-<random>` that only your user can open, instead of `/dev/stdin`; Linux, WSL and macOS use stdin. Fly deploy credentials work on every OS.

Keep break-glass (owner or admin) credentials out of opv: they are for people, in 1Password, and no `deploy_credentials` should reference them.

## Local development

`opv run` starts a command with the environment's keys set as environment variables, under their plain names (`DATABASE_URL`, `OPENAI_API_KEY`), secrets and config alike. opv never sees the values: it hands `op run` a list of `op://` references, and `op run` resolves them and starts the command. Nothing is written to disk, and the values are gone when the process exits.

```sh
opv run dev -- npm run dev                 # simple profile: every key desired in dev
opv run dev --product api -- cargo run     # fleet profile: the keys of one product
```

Only keys whose `environments` include the environment are set. An environment used only for local work needs no target section:

```toml
[environments.dev]
vault_id = "vdev1234example"
item_id  = "idev1234example"
```

Common setups:

| You want | Run |
|---|---|
| An app or test suite | `opv run dev -- npm test` |
| A shell with every variable set (gone on `exit`) | `opv run dev -- $SHELL` |
| Docker Compose (`${VAR}` in `compose.yaml` and `environment:` entries without a value read from the starting process) | `opv run dev -- docker compose up` |
| An editor or debugger whose run configurations inherit the variables | `opv run dev -- code .` |
| Config values (not secrets) as JSON for another tool | `opv config export dev --json` |

Before the first run, `opv check dev` (fleet: `--product <p>`) tells you which keys are missing, of the wrong kind or failing a rule, by name only. `run` removes every key name declared in the configuration from the inherited environment before adding the selected keys, so switching products in one shell never leaks the previous product's keys; everything else (PATH, tool settings, the 1Password sign-in) is inherited, so this is not a sandbox. The full local guide, including WSL, is [local-development.md](local-development.md).

`op run` masks secret values that the command prints to stdout. `run` needs a signed-in `op` (`opv login dev`, or the 1Password desktop app integration); it exits with the command's own exit code.

There is no command that writes a `.env` file or prints `export` lines, on purpose: a secret never lands on disk (SR-4). If a tool insists on a `.env` file, configure it to read the process environment instead (most frameworks fall back to it, and Compose's `env_file` can be replaced by `environment:` entries without values).

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

On a terminal, opv colours state words only: `ok`, `warn`, `FAIL` and `skip` in `doctor`, and the row state (`saved`, `missing`, `wrong kind`, `failed`, `skipped`) in `status`, `plan` and `check`. Nothing derived from a value is coloured, and JSON never is. `--color auto` (the default) colours only when stdout is a terminal and `NO_COLOR` is unset or empty; `--color never` turns it off and `--color always` forces it, even when piped. Piped output under `auto` is byte-for-byte the same as before colour existed.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 2 | configuration error or command-line usage error |
| 3 | dependency: `op`, `flyctl`, `az` or `kubectl` missing or unusable (including a Windows `op.exe` for `run` under WSL), or output cannot be written |
| 4 | 1Password source error (including an `op` timeout) |
| 5 | target error: Fly, Azure or Kubernetes (including an unhealthy revision or rollout, a change made under opv while it applied, a `flyctl secrets list` timeout, and deploy on an app with no machines) |
| 6 | policy refusal: `sync` refused (missing, wrong kind, failing rule, or `--confirm <env>` missing or naming another environment), or `config export` refused |
| 7 | authentication |
| 8 | findings: `status`, `plan` or `check` found blocking keys |
| 9 | outcome unknown, or a provider did not answer: a change may or may not have been applied (a `flyctl secrets deploy` that timed out, an `az` call that lost its connection), or a provider was unreachable before anything was written; nothing is known to be broken; re-run the same command |
| 130 / 143 | interrupted by Ctrl-C (SIGINT) / SIGTERM (Unix): the running `op` or `flyctl` call gets the signal and 5 s to stop, then opv prints `interrupted during <step>; safe to re-run` and `Next: <the same command> (safe to re-run)` |
| 101 | internal panic (Rust default) |

CI may retry a job that exited 9; codes 2 to 8 need a fix first.

Global options: `--timeout <secs>` (default 900), `--verbose`, `--config` and `--color auto|always|never`. Retries, progress and the per-call limits are described in [Retries, timeouts and interruptions](#retries-timeouts-and-interruptions). Each `op`, `flyctl`, `az` or `kubectl` call also has its own limit (diagnosis 15 s, read 60 s, write 120 s).

`run` exits with the child's own exit code, which can equal one of the codes above; opv's own errors print `opv: ...` on stderr. A closed stdout (`status | head`) does not change the result.

Diagnose and guide: after any failed `op` call (`op item get`, `op item edit`) opv runs `op whoami`, and when that fails (with no service-account or Connect credential set, outside CI) `op account list`. These diagnosis calls are free under 1Password rate limits, have their own 15 s limit, and no item is read a second time.

- Not signed in, with no non-interactive credential set (no session, an expired `OP_SESSION_*`, a locked desktop app), is authentication (7), with the sign-in command `opv login <env>` (the same in every shell; `opv login` from `doctor` without `--env`), plus "if you are signed in, check network access to 1Password". Under CI (`CI` or `GITHUB_ACTIONS` truthy, so `CI=false` does not count) it says "set OP_SERVICE_ACCOUNT_TOKEN" and gives no interactive command.
- No account on the machine (fresh WSL or Linux) gives the `op account add` command first.
- With `OP_SERVICE_ACCOUNT_TOKEN` or Connect (`OP_CONNECT_HOST` / `OP_CONNECT_TOKEN`) set, a failing `op whoami` is ambiguous (rejected token or no network), so it stays a source error (4): "1Password rejected the service-account (or Connect) token or could not be reached: check the token in <variable> and network access". No interactive command is printed.
- Signed in but the read still failed is a source error (4) naming the vault and item IDs and the identity type (USER or SERVICE_ACCOUNT, never the identity) and saying to grant that identity access to the vault.
- On Fly, a failed `flyctl` call with `FLY_API_TOKEN` or `FLY_ACCESS_TOKEN` set is a Fly target error (5): "flyctl failed for app <app>: check that the token in <variable> can access it, that the app exists, and, for a deploy, that it has at least one machine". `flyctl auth whoami` is not consulted there, because app-scoped deploy tokens fail it. With no Fly token set, opv runs `flyctl auth whoami` (exit status only; its output names the account and is never shown): logged out is authentication (7), "not logged in to Fly", with `flyctl auth login`, or "set FLY_API_TOKEN" under CI; logged in is a target error (5) with the same app wording.

`doctor` uses the same checks, and a missing `op` or `flyctl` names the install command for your OS. When a call fails, the last lines (at most 5) it wrote on stderr follow opv's error line, labelled with the program (`  az said: ...`), after every value opv read or staged and every token, key or password pattern is masked as `__SECRET__`; its output on stdout is never shown. A re-run hint ("... to see why") remains only when `op whoami` or `flyctl auth whoami` cannot run or times out. An `op` timeout and `opv run` (which passes the child's exit code through) are not diagnosed.

`status` starts with a count line, for example `prod: 62 keys · 49 saved · 0 skipped · 0 findings · 13 not yet on Fly`.

## GitHub Actions example

```yaml
jobs:
  sync-secrets:
    runs-on: ubuntu-latest
    env:
      OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
      FLY_API_TOKEN: ${{ secrets.FLY_API_TOKEN }}
      OP_CACHE: "false"
      OPV_VERSION: v0.4.0   # pin the release you tested; bump it deliberately
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

Rate limits: a cold whole-item read costs about 2 requests, so a fleet sync costs a handful per environment. 1Password Families service accounts allow 1,000 requests per hour per token and 1,000 per day for the account. `OP_CACHE=false` makes the cost the worst case, since `op` caches by default on Linux and macOS.
## Security model and limits

- Values travel only on stdin (on native Windows, a user-only named pipe for `az`) or in the environment of a child process. They never appear in argv, files, logs, errors, `Debug` or `Display` output.
- One documented exception to "no files" (SR-4): with Azure `deploy_credentials`, the Azure CLI stores the service principal's secret in opv's private per-run `AZURE_CONFIG_DIR`, which is RAM-only on Linux/WSL, DPAPI-encrypted on Windows, and removed when the run ends. macOS is not supported for Azure deploy credentials.
- The stderr of `op` and `flyctl` is suppressed so it cannot leak a value.
- `serde` can leave transient scratch copies of values in memory while parsing `op` output; opv wraps values in redacting, zeroizing types but cannot control those copies.
- `config export` prints config-kind values by design. It refuses if a config key is stored concealed or a secret key as text.
- `run` hands secret values to the child process through `op run`; the child can read them.
- No multiline values. Two profiles: `fleet` (products, sections, a naming template) and `simple` (one app per environment, unsectioned fields, Fly name = key name). `--json` on `status` and `plan` prints names, states and counts only; `config export --json` prints config-kind values by design.
- In CI a release reads each item once, by vault ID and item ID.

See [SECURITY.md](../SECURITY.md) to report a vulnerability.
