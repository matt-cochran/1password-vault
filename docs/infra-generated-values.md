# Supplying infrastructure-generated values

Some values are produced by infrastructure, not by a person: the database URL Terraform
creates, the webhook signing secret a Stripe endpoint gets. From opv 0.13.0, a key holding
such a value declares `source = "infrastructure"`. The deploy job that produced the value pipes
it to `opv sync <env> --supply-stdin`, and opv delivers it through the same staged sync, rules
and delivery evidence as any other key.

**The value is never written to 1Password.** opv keeps only the target's version, a keyed
fingerprint and the producer's serial in the environment's state vault. CI gets no new
1Password permission: the deploy identity it already has (read the boundary vaults, write the
state vault) is enough.

This page is the supported way to move a value that a deploy job delivers directly today
(`flyctl secrets set`, `gh secret set`) under opv.

## When to use it

| The value | Use |
|---|---|
| A person chooses or copies it (an API key from a provider's dashboard) | a normal key: the value lives in 1Password |
| opv can generate it (a random signing key) | a normal key with `source = "generated"` |
| Infrastructure creates it and only the job that ran the infrastructure sees it (a Terraform output, a webhook endpoint's secret) | `source = "infrastructure"` |

Choose `source = "infrastructure"` only when copying the value into 1Password would create a
second source of truth: someone edits the 1Password copy, nothing changes in production, and
the next `terraform apply` overwrites the target anyway. If a person could hold the value, keep
it a normal key.

What it does not cover:

- **Staged targets only.** An infrastructure key can be delivered by Fly and GitHub targets.
  A Kubernetes or Azure target that delivers the product in one of the key's environments is
  refused when the configuration loads.
- **Secrets only.** `kind = "config"` is refused.
- **No local runs.** `opv run` does not inject an infrastructure key; it prints one note naming
  it.
- **No sharing.** Another key cannot read it with `from = …`. Declare a second infrastructure
  key and supply it too.

## Before you start: every opv must be 0.13.0 or later

An opv older than 0.13.0 refuses a configuration that contains `source = "infrastructure"`
(it does not know the value), so an old binary fails loudly rather than skipping the key.
That also means every workflow, every teammate and every other repository that loads the
configuration fails once the key is committed.

Move every pin first, in its own change:

- each workflow's `OPV_VERSION` (or lock file, such as an `opv.lock`) to `v0.13.0` or later;
- each teammate's installed opv (`opv --version`);
- any other repository that reads the same configuration.

Commit the new key only after those have merged.

## 1. Declare the key

```toml
[products.api.keys.DATABASE_URL]
kind = "secret"
source = "infrastructure"
environments = ["staging", "prod"]
rules = { regex = "postgres(ql)?://.+" }

[products.api.keys.STRIPE_WEBHOOK_SECRET]
kind = "secret"
source = "infrastructure"
environments = ["staging", "prod"]
rules = { prefix = "whsec_" }
```

Propose each key rather than editing the file by hand:

```sh
opv propose key api/DATABASE_URL --kind secret --source infrastructure --env staging,prod --rule 'regex=postgres(ql)?://.+' --write
opv propose key api/STRIPE_WEBHOOK_SECRET --kind secret --source infrastructure --env staging,prod --rule prefix=whsec_ --write
```

Review and merge the change like any other contract change. The rules count once they are
committed on the default branch.

**A shape rule is required.** It is what makes a mis-mapped value fail: if the producer's
output names get swapped, the webhook secret will not match the database URL's rule, and opv
refuses before writing anything. Use one of `prefix`, `ensure_prefix`, `prefix_by_mode`,
`regex`, `enum`, `base64_bytes`, `hex_bytes`, `https_url` or `email_list`.

**`regex` is a full match.** The value must match the whole pattern, so the pattern spells out
the rest of the value (`.+`) and needs no `^…$` anchors. `postgres(ql)?://.+` accepts
`postgres://…` and `postgresql://…` and nothing else. `postgres://` on its own would accept
only that literal string.

opv refuses these combinations when the configuration loads:

| Combination | Why |
|---|---|
| `from = …` on the key, or another key's `from` naming it | there is no 1Password field to read |
| `kind = "config"` | config is not concealed, and a short config value would escape the output guard |
| `personal = true` | personal keys exist only in environments without targets |
| no `environments`, or one of them has no target | the scope must be written down, and something must deliver it |
| no shape rule | see above |
| `allow_same_value` | there is no stored value to compare against |
| the product is `source_only` | it is never delivered |
| a Kubernetes or Azure target delivers the product in one of the key's environments | staged targets (Fly, GitHub) only |

`immutable`, `expires`, `lifecycle`, `roles`, `except`, `guidance` and `file` keep their usual
meanings.

### An existing 1Password field

An infrastructure key must not have a field in 1Password. If one exists (because the value
used to be copied there by hand), every sync refuses with `Stored` until it is archived.
`opv propose key … --source infrastructure` plans the archive, and a person applies it in
their own terminal:

```sh
opv apply <plan-id>
```

From then on `opv set`, `opv import`, `opv open`, `opv propose generate` and an attestation
(`opv apply --attest`) all refuse the key and point at the deploy job instead.

### The delivery item

A supplying sync records its evidence in the placement's delivery item in the state vault.
If a placement has none yet, the sync refuses before any write. Create it once:

```sh
opv propose structure
opv apply <plan-id>
```

## 2. The supply document: `opv.supply/1`

The producer prints one or more JSON documents, back to back, on the standard input of
`opv sync <env> --supply-stdin`:

```json
{"schema": "opv.supply/1", "env": "prod", "serial": 4182,
 "values": {"api/DATABASE_URL": "postgresql://example-user:example-password@db.example.invalid/app"}}
{"schema": "opv.supply/1", "env": "prod", "serial": 1760000000,
 "values": {"api/STRIPE_WEBHOOK_SECRET": "whsec_EXAMPLE_NOT_A_REAL_SECRET"}}
```

(The values are placeholders. Never paste a real value into a document, an issue or a log.)

| Field | Rule |
|---|---|
| `schema` | exactly `"opv.supply/1"` |
| `env` | the sync's environment. A document produced for staging piped into a prod sync is refused |
| `serial` | required whole number from the producer's own object (see below) |
| `values` | a non-empty object of `"<product>/<KEY>": "<value>"` |

No other field is allowed. Names are canonical `<product>/<KEY>`: a bare `KEY`, or the name
the target uses (`API__DATABASE_URL`), is refused. Each name appears once across the whole
stream.

Each value must be a JSON string (not `null`, a number or an object), non-empty, without a
NUL byte, not a known placeholder, and at least 8 bytes long, so opv's output guard can
mask it. opv takes it byte for byte, then applies the key's rules (including `ensure_prefix`
and `transform`) as it would to a stored value.

Limits: 1 MiB for the whole stream and 256 names. The stream must end within the run's
`--timeout`; a producer that never closes its output fails the run instead of hanging the
job.

### The serial

The serial is how opv tells a new value from an old one replayed. It must come from the
producer's own object, never from a CI counter or the run number:

| Producer | Serial |
|---|---|
| Terraform or OpenTofu | the state's `serial` (`terraform state pull \| jq -e '.serial'`) |
| A Stripe webhook endpoint | the endpoint secret's creation time, in Unix seconds (Stripe's `created`) |

Because each producer has its own serial, each producer prints its own document.

opv compares each name's serial with the one it last recorded:

| Supplied serial | Outcome |
|---|---|
| lower | refused: `Stale` |
| equal, same value, target unchanged | nothing written (a re-run is idempotent) |
| equal, same value, target drifted | written again (the drift is repaired) |
| equal, different value | refused: `SerialReused` |
| higher | written |

When a producer really does start over (a Terraform state migration resets the serial),
`--rotate <product/KEY>` overrides `Stale` and `SerialReused` for that run, and the run
prints `rotated <product/KEY> at serial <N>`.

### Which names a run must supply

A supplying run must supply **every** infrastructure key in its scope. The scope is the
environment, the `--product` (if given) and the selected targets (`--target`, or every
target). A key left out is refused as `NotSupplied`, naming it. This is deliberate: it stops a
green job from quietly keeping an old value after Terraform rotated it.

If two producers run in different jobs, narrow each run with `--product` or `--target` so
that each run's scope holds only the keys its producer makes. In the same job, pipe both
producers into one sync (below).

## 3. The deploy-job step

### Put it in the job that ran `terraform apply`

The step goes into the **same job** that produced the values, right after the apply, under
that job's own concurrency group. Not a separate job, and not the scheduled `opv-sync` job:
GitHub cancels a pending job in a concurrency group when another one queues, so a scheduled
sync could cancel a supply right after Terraform rotated a value. Separate jobs would also
need the value passed between them, which is exactly what this design avoids.

### Generate it

```sh
opv ci workflow prod --target web --supply --deploy
```

prints the step for target `web` in `prod`, one jq mapping per infrastructure key the target
delivers, followed by a pull-request job (section 4). For the configuration above:

```yaml
# opv: deliver web's infrastructure values (prod). Paste this step into the job
# that produced them (the job that runs terraform apply), after that step, in the
# job's own concurrency group. The job needs opv, the 1Password CLI and the target's
# CLI: see opv ci workflow prod --target web for those steps.
# Map each output below to your producer's own output name.
# Never put ${{ ... }} in the script: GitHub expands it into the logged script.
# Pass values through the step's env: instead (checked by opv ci workflow --supply-check).
      - name: Deliver infrastructure values to web through opv
        env:
          OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
        run: |
          set -euo pipefail
          # the producer's own serial (Terraform's state serial), never a CI counter
          serial=$(terraform state pull | jq -e '.serial')
          terraform output -json | jq -ce --argjson s "$serial" '{schema: "opv.supply/1", env: "prod", serial: $s, values: {
            "api/DATABASE_URL": (.database_url.value | strings // error("database_url missing")),
            "api/STRIPE_WEBHOOK_SECRET": (.stripe_webhook_secret.value | strings // error("stripe_webhook_secret missing"))}}' |
            opv sync prod --target web --supply-stdin --deploy --receipt web.receipt.json --confirm prod
          opv delivery verify prod --target web --receipt web.receipt.json
```

Without `--deploy` the sync only stages the values; `--confirm prod` appears because `prod`
sets `confirm_env = true`. The generator never adds `--rotate` (section 5).

Adapt it to your job:

- **Output names.** The generator guesses `.database_url` from `api/DATABASE_URL`. Change each
  to your Terraform output's real name.
- **Tokens.** The job also needs the target's token (`FLY_API_TOKEN` for Fly, a GitHub token
  for a GitHub target) and the CLIs; `opv ci workflow prod --target web` shows those steps.
  Use the environment's existing deploy service account for `OP_SERVICE_ACCOUNT_TOKEN`.
- **Working directory.** Add `-chdir=<dir>` to both `terraform` calls when the stack is not
  at the job's working directory.

What each part guarantees:

- `set -euo pipefail` fails the step if any producer fails, even when opv itself succeeded
  on a partial stream.
- `jq -e '… | strings // error("<output> missing")'` fails on a missing or non-string output
  with a fixed message. jq never quotes its input in that error, so a value cannot reach the
  log through it.
- Values travel only through the pipe. Not through argv (visible in `ps` and logs), not
  through environment variables (inherited by `flyctl` and `gh`), not through files (left on
  the runner).
- `opv delivery verify` reads back the placement and fails the job if the target does not hold
  what was just recorded.

### Two producers in one step

When the Stripe secret comes from a helper rather than a Terraform output, each producer
prints its own document (with its own serial) and both go into one sync, so the run's scope
is complete:

```yaml
      - name: Deliver Terraform and Stripe values through opv
        env:
          OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OPV_PROD_DEPLOY }}
          FLY_API_TOKEN: ${{ secrets.FLY_API_TOKEN }}
        run: |
          set -euo pipefail
          serial=$(terraform -chdir=infra state pull | jq -e '.serial')
          {
            terraform -chdir=infra output -json | jq -ce --argjson s "$serial" '{schema: "opv.supply/1", env: "prod", serial: $s, values: {
              "api/DATABASE_URL": (.neon_database_url.value | strings // error("neon_database_url missing"))}}'
            python3 scripts/stripe_webhook_supply.py --env prod
          } | opv sync prod --target web --supply-stdin --deploy --receipt web.receipt.json --confirm prod
          opv delivery verify prod --target web --receipt web.receipt.json
```

`scripts/stripe_webhook_supply.py` stands for your helper. It prints exactly one
`opv.supply/1` document on stdout, with `serial` set to the endpoint secret's `created` time,
and nothing else on stdout. Its own diagnostics go to stderr and must never include the
value.

### Never put `${{ … }}` in the script

GitHub substitutes `${{ … }}` expressions into the script text before it runs, and the
substituted script appears in the job log. A value reached through `${{ steps.x.outputs.v }}`
or `${{ secrets.X }}` inside `run:` would therefore be logged (GitHub's masking only knows
registered secrets). Pass anything you need through the step's `env:` instead, as the
examples do. `${{ github.* }}` expressions are allowed: they hold no secrets.

## 4. Guard the step in pull requests: `--supply-check`

```sh
opv ci workflow --supply-check .github/workflows/apply.yml
```

reads the workflow file, finds every step whose `run:` script pipes into `--supply-stdin`, and
refuses a `${{ … }}` expression other than `github.*` in that script (the step's `env:` may
use any expression). It prints one line when the file passes:

```text
.github/workflows/apply.yml: no step that pipes into --supply-stdin expands a ${{ }} expression other than github.*
```

and otherwise names the line and column, with exit 2:

```text
opv: the workflow file .github/workflows/apply.yml at line 9, column 24: the run: script of a step that pipes into --supply-stdin expands a ${{ … }} expression on line 9, in a step that pipes into --supply-stdin
Do: edit .github/workflows/apply.yml at line 9, column 24: pass the value through the step's env: and use only github.* expressions in its script
```

`opv ci workflow … --supply` prints this job after the step. Add it to a workflow that runs on
`pull_request` (your existing checks workflow), and point it at the file that holds the step:

```yaml
  opv-supply-check:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    env:
      OPV_VERSION: v0.13.0   # pin the release you tested; bump it deliberately
    steps:
      - uses: actions/checkout@v4
      - name: Install opv
        run: |
          base=https://github.com/matt-cochran/1password-vault/releases/download/$OPV_VERSION
          curl -fsSLO "$base/opv-x86_64-unknown-linux-musl"
          curl -fsSLO "$base/SHA256SUMS"
          sha256sum -c SHA256SUMS --ignore-missing
          install -m 0755 opv-x86_64-unknown-linux-musl /usr/local/bin/opv
      - name: Fail on an expression in a step that pipes into --supply-stdin
        run: opv ci workflow --supply-check .github/workflows/apply.yml
```

## 5. First adoption: one deliberate rotation

Before the migration, the infrastructure set the value on the target directly, so the target
lists the name but opv has no evidence of what it holds. opv will not overwrite a value it
cannot vouch for: the first supplying run is refused as **`Unproven`** ("the target lists it
without delivery evidence, so only a rotation may write it").

Adopt it with one run that names each such key with `--rotate`. The generator never emits
`--rotate`, so that a routine run can never force a write. Add a boolean input to the
workflow's manual trigger, pass it through `env:` (never `${{ … }}` in the script), and turn
it into flags for that run only:

```yaml
on:
  push:
    branches: [main]
  workflow_dispatch:
    inputs:
      rotate_infrastructure_values:
        description: "Rotate the infrastructure values once (first adoption, or a producer reset)"
        type: boolean
        default: false

# ...in the job that runs terraform apply:
      - name: Deliver infrastructure values to web through opv
        env:
          OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OPV_PROD_DEPLOY }}
          FLY_API_TOKEN: ${{ secrets.FLY_API_TOKEN }}
          ROTATE: ${{ inputs.rotate_infrastructure_values }}
        run: |
          set -euo pipefail
          rotate=()
          if [ "${ROTATE:-false}" = true ]; then
            rotate=(--rotate api/DATABASE_URL --rotate api/STRIPE_WEBHOOK_SECRET)
          fi
          serial=$(terraform state pull | jq -e '.serial')
          {
            terraform output -json | jq -ce --argjson s "$serial" '{schema: "opv.supply/1", env: "prod", serial: $s, values: {
              "api/DATABASE_URL": (.database_url.value | strings // error("database_url missing"))}}'
            python3 scripts/stripe_webhook_supply.py --env prod
          } | opv sync prod --target web --supply-stdin --deploy --receipt web.receipt.json --confirm prod "${rotate[@]}"
          opv delivery verify prod --target web --receipt web.receipt.json
```

Run it once per environment from the Actions tab with the box ticked, staging first. The run
prints `rotated api/DATABASE_URL at serial <N>` for each key. Every later run (push, or
dispatch with the box clear) needs no rotation.

`--rotate` names only keys this run supplies; naming one it does not supply is refused
(`RotateWithoutValue`). An immutable infrastructure key is honoured too: once delivered, a
different value is refused (`ImmutableDiffers`) unless rotated.

The same rotation is needed again if the evidence is ever lost (an opv older than 0.13.0
rewrote the delivery item, or the key left the target's binding set and came back). opv then
reports the name as `not recorded` (below).

## What opv shows afterwards

| Command | What an infrastructure key shows |
|---|---|
| `opv plan <env>`, `opv status <env>` | 1Password column: `supplied at sync`. ON TARGET: `as supplied` (the target still holds the version opv recorded), `drifted` (the target holds another version), `absent`, or `not recorded` (the target lists it, with no evidence). `--json` rows add `"value_state": "supplied"` and `"supplied": true` |
| `opv status <env> --fail-on-drift` | fails (exit 8) on a `drifted` supplied name |
| `opv ready <env> --gate` | fails (exit 8, `gate_failed`) unless every present infrastructure key is `as supplied` on every target: reason `supplied_not_delivered` (absent or not recorded) or `supplied_drifted`. Do: run the deploy job that produces it |
| `opv delivery verify <env>` | `verified` with `"supplied": true`, which means *unchanged on the target since it was supplied*, not *current with Terraform*. Also `missing_on_target` or `drifted_on_target`; never `source_changed` |
| `opv inventory` | value state `supplied` |
| `opv sync <env>` without a supply | holds every infrastructure name and never writes it. If each one is `as supplied`, the delivery revision stays valid; otherwise the run says `delivery: <product> not recorded: supplied at sync, not supplied by this run: <names>` and exits 0 |
| `opv run <env>` | does not inject the key; prints `<product/KEY> is not injected: its value is supplied at sync by the deploy job that produced it and never stored in 1Password` |

A receipt from `--receipt` lists the supplied names under `supplied`, and each supplied
binding's source is `{"item_id": "supplied", "field": "<product/KEY>"}`.

### Repairing drift

`drifted` means someone or something changed the name on the target outside opv (a manual
`flyctl secrets set`, an old script still running). There is no 1Password value to restore
from, and opv never stores one. Repair it by re-running the deploy job that produces the
value: the same serial and value are written again (equal serial, target drifted), and the
name returns to `as supplied`. Then find and stop whatever wrote the target directly.

## Failure modes and exit codes

Every refusal happens before the first write: stream and name problems before opv reads
1Password, rule, target-state and serial problems before it writes the target.

| Exit | Code | When |
|---|---|---|
| 2 | `input_invalid` | the stream is wrong: standard input is a terminal, not JSON (reported by line and column only, never quoting the input), an unknown field, a wrong `schema`, no `serial`, no `values`, no document at all, over 1 MiB or 256 names, or it did not end within `--timeout` |
| 6 | `policy_refused` (`supply_refused`) | a document or name is refused: `WrongEnvironment`, `Undeclared` (reported by position, with the closest infrastructure key), `NotOptedIn` (a normal key), `NotInEnvironment`, `OutOfScope`, `NotSupplied`, `Duplicate`, `Empty`, `TooShort`, `Placeholder`, `NotAString`, `RotateWithoutValue`, `RuleFailed`, `Stored`, `Unproven`, `ImmutableDiffers`, `Stale`, `SerialReused` |
| 6 | | `--supply-stdin` run by an AI assistant: it is refused before anything is read. An assistant proposes the key; the deploy job supplies the value |
| 8 | `delivery_unverified` | the target was written but a supplied name got no evidence line (no listed version, no delivery item, a failed record). Re-run the deploy job: the target may hold the value, but opv cannot vouch for it |
| 4 | `item_changed` | another run changed the delivery item twice while this one recorded it |
| the cause's | the cause's | a target write failed or was not confirmed: opv lists the names it wrote, then the cause, and mints no revision. A re-run with the same supply finishes it |

A producer that fails mid-stream leaves invalid JSON (exit 2); one that fails before printing
its document leaves a key unsupplied (`NotSupplied`, exit 6); and `set -o pipefail` fails the
step in either case. If another run recorded a newer serial for a name while this one was
writing, the newer evidence is kept and this run fails with `Stale`; the name reads `drifted`
until the next supply.

No error, log line, `--json` document, receipt or evidence line ever contains a supplied
value. An entry is named in an error only if it is a declared key; anything else is reported
by position (`document 2, entry 3`), because a mapping bug can put a value where a name
belongs.

## Worked migration: `matt-cochran-products/infra`

Today, two places in infra deliver infrastructure-generated values to Fly directly:

- `.github/workflows/apply.yml`, in the `apply` job (concurrency group `apply`), reads the Neon
  connection URIs from the `terraform/bootstrap/neon` OpenTofu state and pipes
  `DATABASE_URL=…` lines into `flyctl secrets import`;
- `fly/shared-host/stripe_webhooks.py`, called by the same job, reads each product's Stripe
  webhook signing secret from its billing stack's state and calls
  `flyctl secrets import --stage`.

The change moves both values onto opv's staged sync for the `fleet` target, keeping each one
in the job that produced it. Do the steps in order.

**0. Pin opv.** Move `fly/shared-host/opv.lock` and every other opv pin in infra to v0.13.0 or
later, and merge that first. The pinned v0.12 refuses the new keys.

**1. Declare the keys.** `fly/shared-host/fleet/secrets.toml` is generated by
`fleet_secrets.py` from `catalog.json`, so the declaration goes into the generator, not the
file: for each product that reads them, `DATABASE_URL` with `source = "infrastructure"` and
`rules = { regex = "postgres(ql)?://.+" }`, and `STRIPE_WEBHOOK_SECRET` with
`source = "infrastructure"` and `rules = { prefix = "whsec_" }`. Make the Stripe key present
only where the product's payments mode delivers it (a product with payments `off` in an
environment must not list it there), so that a run never needs to supply a value the product
does not use. Run `opv propose structure` and `opv apply` if a placement has no delivery item.
If any of these keys has a 1Password field, archive it with the proposal's `opv apply`.

**2. Make the Stripe helper a producer.** Change `stripe_webhooks.py` so that, for opv, it
prints exactly one `opv.supply/1` document on stdout per environment, naming each product's
`<product>/STRIPE_WEBHOOK_SECRET`, with `serial` set to the endpoint secret's `created` time,
and stops calling `flyctl secrets import` for the fleet. Its notices (payments off, endpoint
not created yet) stay on stderr.

**3. Add the supply step to the `apply` job**, after the stacks are applied, in place of the
fleet part of the direct transfer. The shape, with the infra paths:

```yaml
      - name: Deliver Neon and Stripe values to the fleet through opv
        env:
          OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OPV_STAGING_DEPLOY }}
          FLY_API_TOKEN: ${{ secrets.FLY_API_TOKEN }}
          ROTATE: ${{ inputs.rotate_infrastructure_values }}
        run: |
          set -euo pipefail
          rotate=()
          if [ "${ROTATE:-false}" = true ]; then
            rotate=(--rotate fantasticus/DATABASE_URL --rotate preveti/STRIPE_WEBHOOK_SECRET)
          fi
          tofu -chdir=terraform/bootstrap/neon init -input=false -no-color \
            -backend-config=../../backend/r2.hcl -backend-config=key=bootstrap/neon.tfstate >/dev/null
          serial=$(tofu -chdir=terraform/bootstrap/neon state pull | jq -e '.serial')
          {
            tofu -chdir=terraform/bootstrap/neon output -json | jq -ce --argjson s "$serial" '{schema: "opv.supply/1", env: "staging", serial: $s, values: {
              "fantasticus/DATABASE_URL": (.fleet_staging_connection_uris.value.fantasticus | strings // error("fantasticus staging uri missing"))}}'
            python3 fly/shared-host/stripe_webhooks.py test --emit-opv-supply
          } | opv --config fly/shared-host/fleet/secrets.toml sync staging --target fleet --supply-stdin --receipt fleet.receipt.json "${rotate[@]}"
          opv --config fly/shared-host/fleet/secrets.toml delivery verify staging --target fleet --receipt fleet.receipt.json
```

The product list in the jq mapping and the `--rotate` flags follow the declared keys; the
`--emit-opv-supply` flag is the helper's new mode from step 2. There is no `--deploy`: the
fleet stays staged, and the next reviewed shared-host deploy activates it, as today. Add the
`rotate_infrastructure_values` input to `apply.yml`'s `workflow_dispatch`, and the
`opv-supply-check` job to the pull-request checks workflow (`platform-ci-checks.yml`),
pointed at `.github/workflows/apply.yml`.

**4. Adopt once per environment.** The fleet already lists these names without opv evidence,
so the first run is `Unproven`. Dispatch `apply.yml` once with the rotation box ticked, on
staging first. Prod follows the same steps once its `fleet` target is declared (it is not yet:
the owner records prod's state vault in `catalog.json` first).

**5. Retire the direct delivery last.** Keep the old `flyctl secrets import` lines for the
fleet until the supply step has run green on staging and prod and
`opv delivery verify <env> --target fleet` reports `verified` for each. Then remove them, and
the corresponding code path in `stripe_webhooks.py`. Apps that are not opv targets yet (the
legacy per-product apps such as `fantasticus`, `allumata` and `pubops`) keep their direct
delivery until they become targets or are retired.

The step compiles nothing, so build-once promotion and infra's build gate are unaffected.
