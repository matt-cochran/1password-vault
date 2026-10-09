# Using opv

## Workflow

Global option: `--config <PATH>`, or the `OPV_CONFIG` environment variable (the flag wins). Without either, opv looks for `secrets.toml` in the current directory and then each parent directory up to the filesystem root, uses the first one found (files are never merged), and prints `using <absolute path>` on stderr before the command runs. With `--config` or `OPV_CONFIG`, the path is used exactly as given and no search is done; a path from `OPV_CONFIG` is announced as `using <path> (from OPV_CONFIG)` on stderr. `init` refuses both, because it always writes `./secrets.toml`. `<ENV>` is an environment name from the file.

`OPV_PRODUCT` is the default for `--product` on `check`, `run`, `doctor --env`, `explain` (where a bare `KEY` means `$OPV_PRODUCT/KEY`), `status <ENV>` and `plan`. It applies under the fleet profile only, never to `sync`, and opv prints `product <p> (from OPV_PRODUCT)` on stderr whenever it uses it. A single-product repository inside a fleet can export it once (for example in `.envrc`) and then run `opv run dev -- npm run dev`.

Every command's `--help` lists its own options first, then the global options (`--config`, `--timeout`, `--verbose`, `--color`) under `Global options:`, then a few examples.

```sh
opv doctor                          # config, op and sign-in, flyctl and sign-in, op local run
opv doctor --env dev --product allumata   # only what local work in dev needs, plus one read of its item
opv doctor --json                   # the same checks as one JSON document
opv init staging --vault myapp-staging --item myapp --fly-app myapp-staging   # starter secrets.toml
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

1. `item skeleton` creates the empty fields in the 1Password item. Fill them in 1Password.
2. `status` shows what is missing, of the wrong kind, or failing a rule. It prints names and the declared `guidance`, never values. Its first line counts the rows: `staging: 12 keys · 10 saved · 1 skipped · 1 finding · 2 not yet on Fly`.
3. `plan` shows the same rows plus the target side, then names what a sync would do and ends with the command that does it (see [Plan](#plan)). It changes nothing.
4. `sync` stages the values on the target (on Fly, through `flyctl secrets import --stage`, values on stdin; Azure and Kubernetes: [below](#sync-on-azure-and-kubernetes)). It refuses (exit 6) and stages nothing if any key is missing, of the wrong kind or failing a rule; the refusal names every blocking key and an `opv explain` command for them. Before its first write it checks the Fly app (`flyctl status`, `flyctl releases`): a deleted (`dead`) app stops it with nothing written. A Fly deploy already running is waited for: opv reads the releases again every 5 s, prints `waiting for the running Fly deploy of <app> (release vN) to finish, 15 s` on stderr at least every 15 s, and goes on once it has finished; if it is still running when the `--timeout` budget is nearly spent (or after 10 minutes), opv stops with nothing written and a `Next:` line. A suspended or never-deployed app has no machines; secrets are app-level, so staging goes ahead with a `warn  fly app <app>: no machines; ...` line, and `--deploy` prints `deploy skipped: <app> has no machines; staged secrets apply when machines start` (exit 0). Stopped machines are a `warn` line too.
5. `--rotate PRODUCT/KEY` (repeatable) stages an immutable key that is already on Fly. `--prune-immutable PRODUCT/KEY` (repeatable) lets `--prune` unset a named immutable key.
6. `config export <ENV>` prints the config-kind values for deployment tooling as JSON, the only format (`--json` is accepted). On failure stdout is the [failure document](#json-contract) instead.
7. `check <ENV> [--product <p>]` validates the environment's keys for local work, by name only: it reads the item once, skips other products' sections, never calls a deployment target, and exits 8 when a key is missing, of the wrong kind or failing a rule. A failing key's declared guidance is printed under it as `  guidance: <text>`. `--json` prints `schema_version`, `ok`, `environment`, `product`, `target_checked: false`, `rows` (the [shared row shape](#machine-readable-status-and-plan); `target` and `action` are `null`), `findings` and `totals`.
8. `run <ENV> --product <p> -- <cmd>` runs a command with the product's keys in its environment under plain names (`OPENAI_API_KEY`, not the Fly name), through `op run`. It first removes every key name declared in the configuration from the inherited environment, so another product's keys never leak in. It writes no `.env` file. See [Local development](#local-development).

### Next step

Every command that fails (any exit code other than 0, except `run`, which passes the command's own code through) ends with exactly one `Next:` line, the last line on stderr. `Next:` is always one command that runs as typed: no prose, no placeholders, no parentheses. When something only a person can do comes first (fill a value in 1Password, sign in, approve a guarded environment), it is on its own `Do:` line right before `Next:`:

```text
opv: policy denied: sync refused, nothing staged: api/OPENAI_API_KEY (missing)
Do: fix api/OPENAI_API_KEY in 1Password
Next: opv explain api/OPENAI_API_KEY --env prod
```

```text
opv: 1 finding
Do: fix the keys above in 1Password
Next: opv check dev --product api
```

When the failure came from an external call, what that program wrote on stderr (at most 5 lines, every secret masked as `__SECRET__`) sits between the error line and `Do:`/`Next:`:

```text
opv: target error: az keyvault secret list failed for kv-prod
  az said: ERROR: (Forbidden) The user does not have secrets list permission
Next: opv sync prod
```

When the fix is not a command, `Next:` is the command you ran, to run again once the `Do:` step is done. A usage error, a misspelt environment or product and an undeclared key end with `Next: opv <command> --help` instead, because running the same line again cannot work. An outcome that is unknown (exit 9) or an interruption (130/143) ends with the same command line: re-running it is safe. A command that needs your own terminal (`opv setup`, `opv session`) says so on `Do:` and names itself on `Next:`. Scripts and AI assistants can rely on the patterns `^Do: ` and `^Next: `. Guidance from the configuration is labelled `guidance:` and is never a `Next:` line. With `--json`, the same `do` and `next` are fields of the [failure document](#json-contract).

`doctor` prints one line per check; a failing check has its fix on the line under it (`  fix: ...`) when the fix is not already in its text. When a check fails, `doctor` exits with the first failing check as the error, and its `Next:` line is that check's fix:

```text
FAIL  op auth: authentication error: not signed in to 1Password
...
opv: authentication error: op auth check failed (see the FAIL line above)
Do: sign in: eval $(op signin)
Next: opv doctor
```

On an interactive terminal (not CI, no service-account token) the sign-in step is `opv session   (or: eval $(op signin))`.

With `--env`, doctor also reads that environment's item once, by IDs, and checks the selected product's keys as `check` does: `ok    item: <vault_id>/<item_id> readable (<n> field(s) in section <product>)`, or a `FAIL  item:` line naming each key that is missing, of the wrong kind or failing a rule, with `Do: fill them in 1Password` and `Next: opv check <env> --product <p>` (exit 8). So doctor is never all clear when `check` would fail. Without `--env` no item is read.

`--json` prints `{"schema_version": 1, "ok", "checks": [{"name", "status": "ok"|"warn"|"fail"|"skip", "detail", "next", "do"}], "next", "do"}`: `detail` is the check's first line (names, versions and commands only); a check with something to do has `do` (the action only a person can take, or `null`) and `next` (a command), both `null` otherwise; the top-level pair is the first failing check's, or `null` when nothing is pending. On failure the document also carries `exit_code` and `error` ([JSON contract](#json-contract)). The exit code is the same as without `--json`; on failure stderr still ends with the `Do:`/`Next:` lines.

With no `secrets.toml` at all, the step is `Do: fill in and run: opv init <env> --vault <vault title> --item <item title>` for an existing item; the config line also lists `opv setup` for a project that ships `opv.setup.toml` and `--config <path>`. An invalid configuration always gets `Do: fix secrets.toml (see the config line above)`; another failure with no command of its own gets `Do: fix the <check> failure above`; both end with `Next: opv doctor`. When every check passes, the last line is `all clear: nothing pending`. The lines are text, never a prompt.

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
  "next": "opv sync prod --deploy",
  "do": null
}
```

`state` is `saved`, `missing`, `wrong_kind`, `failing_rule` or `skipped`; `rule` names the
failing rule when `state` is `failing_rule`, and `reason` says why (see
[Failure reasons](configuration.md#failure-reasons)); `target_name` is the key's name on the
target for every provider (`fly_name` holds the same value and is kept for older scripts; it
is deprecated); `target` is `present`, `absent` or `would_change` for a secret and `null` for
a config key; `action` is `would_stage`, `would_prune`, `held` or `null`. The same row shape,
in the same key order, is used by `status`, `plan` and `check`. With `--product`,
the document carries `"product": "<p>"` (otherwise `null`) and only that product's rows and
totals. `next` is the sync command for `plan`, `null` for `status`. The document is meant
for the scheduled drift check.

`opv status --json` without an environment prints one entry per environment:
`{"environments": [{"name", "target", "state": "checked"|"run_only"|"not_checked", "keys", "findings", "error_code"}], "totals": {"environments", "findings"}}`.

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

### Plan

`plan` starts with one count line, then the rows, then what a sync would do, by name, and ends with the sync command:

```text
prod: 4 keys · 0 findings · 1 to stage · 1 held (immutable) · 1 to prune · 1 unmanaged on Fly (never touched)
PRODUCT   KEY                  KIND    STATE    TARGET
...
would stage: allumata/OPENAI_API_KEY (FLEET__ALLUMATA__OPENAI_API_KEY)
would prune (needs --prune): allumata/STRIPE_SECRET_KEY (FLEET__ALLUMATA__STRIPE_SECRET_KEY)
held (immutable): allumata/INTEGRATION_ENC_KEY (FLEET__ALLUMATA__INTEGRATION_ENC_KEY) (pass --rotate PRODUCT/KEY to replace)
Next: opv sync prod --deploy --prune
```

On Azure and Kubernetes the line says `would write`. The `Next:` command adds `--prune` only when something would be pruned, `--product` when you scoped the plan, and `--confirm <env>` for a [guarded environment](#guarded-environments). When a key blocks the sync, `plan` exits 8 with `Do: fix the keys above in 1Password` and `Next: opv plan <env>`.

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
- **Soft-deleted names (Key Vault).** A deleted secret name stays reserved until it is purged, so writing it again fails. opv prints the exact `az keyvault secret recover` command; it never recovers or purges anything itself. <!-- verify: exact recover command text -->
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
  "next": "opv sync prod --deploy",
  "do": null
}
```

Lists follow the summary line's order and hold `{product, key, target_name}` objects (`product` is `null` under the simple profile). `deploy_reason` says why a deploy happened (`written`, `pruned`, `pending_from_earlier_run`), `deployed_names` and `written_names` are bare target names, and `next` is the `Next:` command or `null`. Every failure ends with one `Next:` line ([Next step](#next-step)); with `--json`, stdout is then the [failure document](#json-contract).

### Retries, timeouts and interruptions

- **Reads are retried, writes are not.** A failed read (`op item get`, a list, a status check) is tried up to 3 times, with a 1 s then 2 s pause, printing `retrying az keyvault secret list (2/3) in 2 s`. A refusal such as not found or not signed in is never retried. A write is never repeated blindly: opv reads the target back to see what happened.
- **One time budget.** `--timeout <secs>` (default 900) caps the whole run, including waits for a revision or rollout. There is no separate deploy timeout.
- **`--verbose`** prints one stderr line per external call: the program, its arguments, how long it took and the outcome. Under it come the call's own error output (`    stderr: ...`, every secret masked as `__SECRET__`) and the size and JSON shape of its result (`    stdout: 412 bytes, JSON object with keys: ...`). A result's content is never shown.
- **Safe to re-run.** Stopping opv at any point (Ctrl-C, a CI cancel, a lost connection) leaves the app working. Run the same command again and it finishes the rest.
- **Exit 9** means opv cannot tell what happened: a write may or may not have been applied, or 1Password, Fly, Azure or the cluster did not answer after 3 tries (nothing was written). Nothing is known to be broken. Check the provider's status page if one is named, then re-run the same command. CI may retry a job that exits 9.
- **Exit 130 / 143** means you pressed Ctrl-C or the job was terminated. opv names the step it stopped in.

### Guarded environments

If an environment sets `confirm_env = true` ([configuration](configuration.md#guarding-an-environment-confirm_env)), `sync` refuses (exit 6) before any call unless you repeat the name: `opv sync prod --deploy --confirm prod`. The refusal ends with that exact command, with every flag you gave:

```text
opv: policy denied: environment prod is guarded (confirm_env = true): sync needs --confirm prod; nothing was changed
Next: opv sync prod --deploy --confirm prod
```

A `--confirm` that names another environment is refused everywhere, guarded or not. `plan` and the `Next:` line after a guarded sync include `--confirm <env>`. `--prune` always lists the names it will remove before it acts.

### Pruning on Fly

Nothing is deleted by default. `--prune` unsets only names that the template produces for declared keys that are not desired in this environment. Names outside that set are never touched. Immutable keys are never pruned unless named with `--prune-immutable`; they are reported as "held (immutable), not pruned". A name staged by the same run is never pruned. A key you delete from `secrets.toml` is no longer declared, so it is neither reported nor pruned: unset it manually with `flyctl secrets unset`.

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

`op run` masks secret values that the command prints to stdout. `run` needs a signed-in `op` (the 1Password desktop app integration or `op signin`); it exits with the command's own exit code.

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

## JSON contract

Every command that takes `--json` (`doctor`, `check`, `status`, `plan`, `sync`, `explain`, `init`, `item skeleton`), plus `config export` and `opv schema`, prints exactly one JSON document on stdout, success or failure, and the human text on stderr. No document ever contains a secret value. Each one starts with `schema_version` and `ok` and ends with `next` (a command that runs as typed, or `null`) and `do` (an action only a person can take, or `null`). A failure adds `exit_code` after `ok` and an `error` object last:

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

A failure after the command produced its document (findings, exit 8) keeps that document's fields between `exit_code` and `next`. `config export` prints the bare config map on success and the failure document on failure. Usage errors (`--json` with an unknown flag) print the failure document with code `usage`.

`retry` says whether to run the same command again: `safe` (now; nothing is known to be broken), `after_fix` (once `do` is done) or `never` (the command itself must change: run `next`). `human_required` is `true` when only a person can take the next step; an assistant then hands `do` and `next` to the user instead of acting. `code` is one of a closed list:

| `code` | Exit | `retry` | Human | Meaning |
|---|---|---|---|---|
| `usage` | 2 | never | no | the command line is not valid |
| `config_not_found` | 2 | after_fix | no | no `secrets.toml` here or in a parent |
| `config_invalid` | 2 | after_fix | no | `secrets.toml` or a value is not valid |
| `unknown_env` | 2 | never | no | the environment is not defined |
| `unknown_product` | 2 | never | no | the product is not declared (or the simple profile takes none) |
| `undeclared_key` | 2 | never | no | the key is not declared (for this environment) |
| `no_target` | 2 | never | no | the environment has no deployment target |
| `dependency_missing` | 3 | after_fix | no | `op` or the target CLI is missing or unusable |
| `source_error` | 4 | after_fix | no | 1Password could not be read |
| `item_not_found` | 4 | after_fix | no | the item is not in the vault |
| `vault_no_access` | 4 | after_fix | yes | the signed-in identity cannot access the vault |
| `target_error` | 5 | after_fix | no | the target refused or failed |
| `target_unhealthy` | 5 | after_fix | no | the new revision is not healthy; the previous one keeps serving |
| `policy_refused` | 6 | after_fix | no | opv refused the operation |
| `keys_blocking` | 6 | after_fix | yes | `sync` refused: keys missing, of the wrong kind or failing a rule |
| `confirm_required` | 6 | never | yes | the environment sets `confirm_env`; confirm with the user, then run `next` |
| `confirm_mismatch` | 6 | never | no | `--confirm` names another environment |
| `terminal_required` | 6 | never | yes | the command needs the user's own terminal |
| `auth_required` | 7 | after_fix | yes | not signed in to 1Password or the target CLI |
| `op_not_signed_in` | 7 | after_fix | yes | not signed in to 1Password |
| `findings` | 8 | after_fix | yes | keys are missing, of the wrong kind or failing a rule |
| `outcome_unknown` | 9 | safe | no | a change may or may not have been applied |
| `provider_unavailable` | 9 | safe | no | a provider did not answer; nothing was changed |
| `interrupted` | 130/143 | safe | no | interrupted by SIGINT or SIGTERM |

`opv schema` prints a description of the installed binary as one JSON document: every command with its arguments, flags, whether it takes `--json`, what it changes (`effect`: `none`, `reads`, `writes_file`, `writes_1password`, `writes_target`, `runs_command`, `interactive`), whether it needs the user's terminal and whether to ask the user first, and the flags that add an effect of their own (`--deploy`: `deploys`, `--prune`: `deletes`, `--rotate`, `--prune-immutable`, `--confirm`, `init --force`); the exit codes, the error codes above, the state words and the fields of each document. It is generated from the binary itself, so it always matches the version you run:

```sh
opv schema | jq '.commands[] | select(.ask_user_first) | .name'
opv schema | jq -r '.error_codes[] | "\(.code) \(.retry)"'
```

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
| 130 / 143 | interrupted by Ctrl-C (SIGINT) / SIGTERM (Unix): the running `op` or `flyctl` call gets the signal and 5 s to stop, then opv prints `interrupted during <step>; safe to re-run` and `Next: <the same command>` (with `--json`, also the failure document with code `interrupted`) |
| 101 | internal panic (Rust default) |

CI may retry a job that exited 9; codes 2 to 8 need a fix first.

Global options: `--timeout <secs>` (default 900), `--verbose`, `--config` and `--color auto|always|never`. Retries, progress and the per-call limits are described in [Retries, timeouts and interruptions](#retries-timeouts-and-interruptions). Each `op`, `flyctl`, `az` or `kubectl` call also has its own limit (diagnosis 15 s, read 60 s, write 120 s).

`run` exits with the child's own exit code, which can equal one of the codes above; opv's own errors print `opv: ...` on stderr. A closed stdout (`status | head`) does not change the result.

Diagnose and guide: after any failed `op` call (`op item get`, `op item edit`) opv runs `op whoami`, and when that fails (with no service-account or Connect credential set, outside CI) `op account list`. These diagnosis calls are free under 1Password rate limits, have their own 15 s limit, and no item is read a second time.

- Not signed in, with no non-interactive credential set (no session, an expired `OP_SESSION_*`, a locked desktop app), is authentication (7), with the sign-in command for your shell: `eval $(op signin)` for bash and zsh, `eval (op signin)` for fish, `Invoke-Expression $(op signin)` for PowerShell (the default on Windows), or "sign in with `op signin` (see `op signin --help` for your shell)" for any other shell, plus "if you are signed in, check network access to 1Password". Under CI (`CI` or `GITHUB_ACTIONS` truthy, so `CI=false` does not count) it says "set OP_SERVICE_ACCOUNT_TOKEN" and gives no interactive command.
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
    steps:
      - uses: actions/checkout@v4
      - name: Install opv
        run: |
          base=https://github.com/matt-cochran/1password-vault/releases/download/v0.3.0
          curl -fsSLO "$base/opv-x86_64-unknown-linux-musl"
          curl -fsSLO "$base/SHA256SUMS"
          sha256sum -c SHA256SUMS --ignore-missing
          install -m 0755 opv-x86_64-unknown-linux-musl /usr/local/bin/opv
      - name: Stage secrets on Fly
        run: opv sync prod
```

This stages without deploying; a later `fly deploy` (or `opv sync prod --deploy`) applies everything staged by every tool. Install `op` and `flyctl` on the runner first (for example with the official 1Password and Fly GitHub Actions).

Rate limits: a cold whole-item read costs about 2 requests, so a fleet sync costs a handful per environment. 1Password Families service accounts allow 1,000 requests per hour per token and 1,000 per day for the account. `OP_CACHE=false` makes the cost the worst case, since `op` caches by default on Linux and macOS.
## Security model and limits

- Values travel only on stdin or in the environment of a child process. They never appear in argv, files, logs, errors, `Debug` or `Display` output.
- The stderr of `op` and `flyctl` is suppressed so it cannot leak a value.
- `serde` can leave transient scratch copies of values in memory while parsing `op` output; opv wraps values in redacting, zeroizing types but cannot control those copies.
- `config export` prints config-kind values by design. It refuses if a config key is stored concealed or a secret key as text.
- `run` hands secret values to the child process through `op run`; the child can read them.
- No multiline values. Two profiles: `fleet` (products, sections, a naming template) and `simple` (one app per environment, unsectioned fields, Fly name = key name). `--json` on `status` and `plan` prints names, states and counts only; `config export --json` prints config-kind values by design.
- In CI a release reads each item once, by vault ID and item ID.

See [SECURITY.md](../SECURITY.md) to report a vulnerability.
