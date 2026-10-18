# Configuration

opv's configuration says where each value lives in 1Password, which environments want it, where each environment deploys, and the rules a value must pass. It holds IDs, names, kinds and rules, never values. It is TOML, kept either in 1Password as a project manifest (no file in the repository) or in a `secrets.toml` file; the schema is the same.

## Where the configuration lives

### How opv finds the configuration

First match wins:

1. `--config <file>` or `OPV_CONFIG`;
2. `OPV_PROJECT=<name>`: the manifest titled `opv · <name>`;
3. `secrets.toml` in the current directory or a parent (an existing file always wins over a manifest);
4. a `.opv` file in the current directory or a parent: `project = "<name>"`, `account = "<account ID>"`, or both. `opv login --account` and `opv propose setup --account` write the account line; commit the file;
5. the manifest tagged with this checkout's git remote (`git remote get-url origin`, normalized to `host/owner/repo`; https, ssh and `git@host:owner/repo` forms are the same).

**Which 1Password account.** opv uses one account per project and never falls back to op's default when that could be the wrong one: the account recorded in `.opv` (or `OP_ACCOUNT`), else the only account `op` knows on this machine. With several accounts and none recorded, every command stops with `account_required`, lists the accounts (email, sign-in address, account ID) and asks you to run `opv login --account <email>` once; opv never searches your other accounts. An email or sign-in address is resolved to the account ID, which is what gets recorded (op itself takes no email, and several accounts can share `my.1password.com`). Every `op` call then carries `--account <ID>`.

`using …` on stderr names what was used (not when given with `--config`). Steps 2, 4 and 5 make one `op item list --tags opv-manifest` call (names and tags only), and loading a manifest is one `op item get`, so these commands need a 1Password session even for `explain` and `config export`; without one the error says so and ends with `Next: opv login`. No match ends with `Next: opv propose setup …`; several matches are listed, and `OPV_PROJECT` picks one.

**Tags.** 1Password reads `/` in a tag as nesting, so the repository tag writes `/` as `|`: `opv-repo:github.com|acme|myapp`. In a monorepo a manifest can cover directories with path tags (`opv-path:apps|api`, from `opv config import --path apps/api`): among manifests for the remote, the one whose path is the longest prefix of the current directory (relative to the repository root) wins; a manifest without paths covers the whole repository at the lowest priority. At the root, or when no path matches and several manifests remain, they are listed with their paths.

### Configuration in 1Password

The configuration can live in 1Password as a **project manifest**: one Secure Note per project, titled `opv · <project>` and tagged `opv-manifest`, whose notes start with an "opv managed configuration" heading and a short explanation, then hold two fenced code blocks. The first, tagged `toml`, is the contract: exactly the TOML of a `secrets.toml` (same schema, same validation), with no 1Password ids. The second, tagged `toml opv-bindings`, holds the ids, in the format of [`secrets.bindings.toml`](#where-the-ids-live-secretsbindingstoml) (one sorted dotted line per id); `opv apply` writes it, and nobody else needs to. An id written inline in the contract block is refused at load by every command (`config_invalid`, naming the field), as in a `secrets.toml`; the one-time move is `opv propose structure`, then `opv apply`. A manifest without a bindings block (before the first `opv apply`) loads as a file without `secrets.bindings.toml` does. opv reads only the two code blocks, and text you add around them is kept. It also has a text field `project`, a field `convention` = `1`, and tags that tie it to a repository. It holds IDs, names and rules, never a value. Every command treats it exactly like a file, and `config edit` edits it in place, with the ids filled in as for a file and saved back to the bindings block.

#### Moving a file into 1Password

```sh
opv config import --vault myapp-dev                     # validates ./secrets.toml, creates the manifest (ids from secrets.bindings.toml in its opv-bindings block)
OPV_PROJECT=myapp opv config check --file secrets.toml  # identical? exit 0; else exit 2 with a diff
git rm secrets.toml                                     # opv never deletes it for you
```

`import` takes `--file <path>` (default: the `secrets.toml` found from here), `--project <name>` (default: the repository's name) and `--path <dir>` (repeatable). It refuses when a manifest for the same project, or for the same repository and paths, exists.

#### Reading and changing it

- `opv config export` prints the configuration as TOML, the contract with its ids filled in (from `secrets.bindings.toml` or the manifest's `opv-bindings` block); `--json` as JSON. `opv config export <env> --json` still prints that environment's config-kind values.
- `opv config edit` opens `$VISUAL` or `$EDITOR` (default `vi`) on a temporary copy (mode 0600, removed afterwards), validates it, shows the diff and asks once. It saves only when nobody changed the configuration since it was opened; otherwise it refuses and re-opens on the new version. It works on a `secrets.toml` too.
- `opv config check --file <path>` compares a committed copy with the manifest: the contract block with the file, then the `opv-bindings` block with the file's `secrets.bindings.toml`; exit 2 with a diff when they differ. Teams that want pull-request review keep a copy and run it in CI; 1Password's item history records every change either way.

## The `secrets.toml` schema

There is one schema. A configuration names environments, the products and keys that live in them, the boundaries (1Password vaults) that hold the values, and the targets that deploy them. There are no profiles: a single-app project is a configuration with one product.

### Boundaries: where values live

A **boundary** is one 1Password vault holding the values for one set of products in one environment. 1Password grants access per vault, so a boundary is the smallest set of values you can give a person or an identity. An environment records a boundary with `boundaries.<name> = {}`; the vault and item **ids** it actually has live in the bindings file (see [Where the ids live](#where-the-ids-live-secretsbindingstoml)), never in the contract. Every command reads those ids, never the names.

By default each product is its own boundary:

| Boundary | Vault | Item |
|---|---|---|
| product (default) | `<project>-<product>-<env>` | `<project> · <product> · <env> values` |
| project shared | `<project>-shared-<env>` | `<project> · shared · <env> values` |
| group (opt-in) | `<project>-<group>-<env>` | `<project> · <group> · <env> values` |

```toml
# Values vaults, one per boundary; opv records the ids in the bindings file.
[environments.prod]
boundaries.web = {}
boundaries.api = {}
```

Only team keys need a boundary. A product whose keys desired in an environment are all personal needs none there, because each person's values live in their own item ([personal keys](#personal-keys-each-developers-own-values)).

#### Sharing one boundary: `boundary = "<group>"`

Products that must share one vault set `boundary` to the same group name. This is an opt-in with an explicit trade: 1Password grants access per vault, so anyone who can read the group's boundary can read every product in it. Use it only when the same people or identity must read those products together.

```toml
[products.web]
boundary = "core"          # web and api share the "core" boundary

[products.api]
boundary = "core"
```

The group's vault is `<project>-core-<env>` and its item `<project> · core · <env> values`.

#### Missing and unused boundaries

Two load errors protect the boundaries:

- `boundary_missing`: a product has a team key desired in an environment whose boundary is not recorded. Its next step is `opv propose structure`, then `opv apply`.
- A recorded boundary that no product with a key in that environment lives in is refused; remove it, or declare that product's keys for the environment. The configuration never names a vault nothing reads.

### Where the ids live: `secrets.bindings.toml`

A 1Password id is not part of the contract. The contract says a boundary exists (`boundaries.api = {}`) and a target deploys to a vault; the **ids** the vault and item actually have live beside it, in `secrets.bindings.toml`, one sorted dotted line per id. The file is written by opv (`opv propose structure`, then `opv apply`), not by hand, and two branches that record different ids merge by union.

```toml
# secrets.bindings.toml — the ids for secrets.toml, one sorted line per id
environments.dev.boundaries.api.item_id          = "idev-api"
environments.dev.boundaries.api.vault_id         = "vdev-api"
environments.dev.targets.fly.state_vault_id      = "sdev-state"
environments.prod.boundaries.api.item_id         = "iprd-api"
environments.prod.boundaries.api.vault_id        = "vprd-api"
environments.prod.targets.fly.state_vault_id     = "sprd-state"
environments.prod.targets.fly.delivery_items.api = "dapiprd000000000000000000"
```

An id is one of four families: a boundary's `vault_id` and `item_id`, a target's `state_vault_id`, and a target's per-product `delivery_items`. A committed `secrets.toml` that still writes one inline is refused at load by every command with `config_invalid`, naming the field and the one-way move. To make the move:

```sh
opv propose structure          # plan the vaults and items, and collect any inline ids
opv apply                      # write secrets.bindings.toml and .opv/applied.json
```

`opv propose structure --rebind <env>` records fresh ids for an environment (a new 1Password account, say); ids not being rebound are kept.

The **apply record** `.opv/applied.json` remembers the plan last applied and the sha256 of the contract and bindings files it wrote:

```json
{
  "plan_id": "3f9c0a1b2c3d4e5f",
  "contract_digest": "…",
  "bindings_digest": "…"
}
```

`opv config check` compares the committed `secrets.bindings.toml` with `bindings_digest`. When they differ it exits 2 with `bindings_unapplied`, naming the environments whose ids moved; when they match it passes. A project that has never been applied has no record, and there is nothing to compare.

### Products and keys

A **product** is a set of keys with one role, named `web`, `api` or `worker`. A **key** is one value with a kind, the environments that want it, and optional rules and guidance. Keys live in their product's section of the boundary item.

```toml
[products.shared]
source_only = true                           # holds values other products read with from

[products.shared.keys.FLY_API_TOKEN]
kind = "secret"
environments = ["staging", "prod"]
guidance = "Fly org deploy token"

[products.api.keys.OPENAI_API_KEY]
kind = "secret"                              # "secret" (concealed) or "config" (text)
environments = ["prod"]                      # where the key is desired
rules = { prefix = "sk-", not_prefix = "sk-or-" }
guidance = "OpenAI platform / API keys"      # printed by status for a missing key

[products.api.keys.INTEGRATION_ENC_KEY]
kind = "secret"
environments = ["staging", "prod"]
immutable = true                             # written only when absent on the target; see --rotate
rules = { base64_bytes = 32 }
allow_same_value = true                      # the same value in staging and prod is intended (see settings health)

[products.api.keys.STRIPE_SECRET_KEY]
kind = "secret"
environments = ["staging", "prod"]
rules = { prefix_by_mode = { mode = "payments", values = { test = "sk_test_", live = "sk_live_" }, skip = ["off", "external"] } }

[products.api.keys.SIGNUP_POLICY]
kind = "config"
environments = ["dev", "staging", "prod"]
rules = { enum = ["open", "invite_only"] }

[products.api.keys.DATABASE_URL]
kind = "secret"
environments = ["staging", "prod"]
guidance = "Neon / connection string"

[products.worker.keys.DATABASE_URL]
kind = "secret"
from = "api/DATABASE_URL"                    # one source: api's field in api's boundary item
environments = ["prod"]
```

Product names match `^[a-z][a-z0-9_-]*$` and key names `^[A-Z][A-Z0-9_]*$`. A product name is upper-cased into a target's template (`api` becomes `API`), so with `fly.secret_name = "FLEET__{PRODUCT}__{KEY}"` the key `OPENAI_API_KEY` is staged as `FLEET__API__OPENAI_API_KEY`. The template must contain `{PRODUCT}` and `{KEY}`, and it defines the target's managed set.

`kind` is `secret` (a concealed field) or `config` (a text field). `rules`, `guidance`, `immutable`, `personal`, `allow_same_value`, `from`, `source`, `expires` and `lifecycle` work as described below and in the [rules reference](#rules-reference). Modes are per product on the environment (`modes.<product>.<mode>`), an input to `prefix_by_mode`.

#### Presence: every environment, minus `except`

`environments` is optional. Without it the key is present in **every** environment, and a new environment inherits it. An explicit list names only the environments the key is wanted in. Either way, `except = { <env> = "<reason>" }` removes the key from a named environment and records why:

```toml
[products.api.keys.OPENAI_API_KEY]
kind = "secret"
                                # no environments: present everywhere
except = { staging = "we have no staging OpenAI account" }

[products.api.keys.STRIPE_SECRET_KEY]
kind = "secret"
environments = ["prod"]         # only prod
```

In an environment a key is excepted from its state is `not_wanted` and its plan row is skipped. An explicit `environments` list that leaves out an environment without an `except` is a likely mistake: the configuration still loads and `environment_gap` warns, naming the key and the environment. An empty reason, an environment that is not declared, or an `except` for an environment the `environments` list already names is refused at load with `config_invalid`.

#### Key attributes: `source`, `expires` and `lifecycle`

```toml
[products.api.keys.STRIPE_SECRET_KEY]
kind = "secret"
environments = ["prod"]
source = "person"               # person | generated | derived
expires = "2026-06-30"          # a quoted "YYYY-MM-DD" date
lifecycle = "active"            # active | retiring | retired

[products.api.keys.JWT_SECRET]
kind = "secret"
environments = ["prod"]
source = "generated"
rules = { base64_bytes = 32 }   # generated needs a base64_bytes or hex_bytes rule

[products.worker.keys.DATABASE_URL]
kind = "secret"
from = "api/DATABASE_URL"
source = "derived"              # the only source allowed with from
```

- `source` is who or what produces the value: `person` (someone fetches it), `generated` (opv makes it from the key's byte-count rule) or `derived` (another key's value, named by `from`). `derived` requires `from`; `from` requires `derived`; `generated` requires a `base64_bytes` or `hex_bytes` rule. Any other combination is refused at load, naming the key.
- `expires` is a calendar date written as a quoted string (`expires = "2026-06-30"`). An unquoted date or an impossible day is refused at load. Within 30 days of the date `opv ready` reports an advisory `expires_soon` finding; it never blocks a gate.
- `lifecycle` is `active` (the default), `retiring` or `retired`. A `retiring` key is on its way out; `opv propose retire` marks it, prunes it from the shared tiers before production, then archives its fields and marks it `retired`. Removal is a state, never a deletion.

#### Ignoring an observed name: `[products.<p>.ignore]`

The scanner reports every name the code reads. A false positive is annotated once, with a reason and the evidence span it was made against:

```toml
[products.api.ignore]
DEBUG_LOG = { reason = "a framework variable, not a key", span = "9f2c0a1b3d4e5f60" }
```

`span` is a stable hash of the evidence line `opv needs` reports. When that line changes the annotation is invalidated and the name shows again as unannotated (with the new span to record). An empty reason is refused at load.

#### A single-app project: one product

A single-app project is a configuration with one product, written exactly like any other. Name the product after its role. When the app expects bare variable names, use `secret_name = "{KEY}"` on the target, so no product prefix is added.

```toml
# Values vault for the one product; opv records the ids in the bindings file.
[environments.prod]
boundaries.web = {}

[environments.prod.targets.web]
fly.app = "myapp-production"
fly.secret_name = "{KEY}"                    # the app reads bare names: no product prefix
                                             # state_vault_id: the bindings file

[products.web.keys.DATABASE_URL]
kind = "secret"
environments = ["prod"]

[products.web.keys.JWT_KEY]
kind = "secret"
environments = ["prod"]
immutable = true
rules = { base64_bytes = 32 }

[products.web.keys.LOG_LEVEL]
kind = "config"
environments = ["prod"]
rules = { enum = ["debug", "info", "warn"] }
```

### Local delivery: `[products.<p>.local]` and `file`

Optional, for `opv run` only (targets ignore both). `environment = "declared_only"` gives the app only the product's declared keys and a fixed set of basics; `secrets_dir_env = "<VAR>"` names the variable that points at a private RAM directory holding every key with `file = "<relative/path>"` (as a file, not a variable). Paths are relative, at most four `/`-separated parts, each matching `^[a-z0-9]+(-[a-z0-9]+)*$` (lower-case letters and digits, `-` only between them: no uppercase, `.`, `_`, empty part, or leading/trailing `-`), unique, and never inside another key's path; `secrets_dir_env` must be a plain variable name, not `PATH`, `HOME`, `XDG_CONFIG_HOME`, `OP_*` or one of the product's keys, and needs at least one `file` key. Recipes for secret-store apps and Cloudflare Workers: [local development](local-development.md#only-the-declared-keys-or-keys-as-files-productsplocal); guarantees and limits: [design](design/local-delivery.md).

### Remote development: `[products.<p>.remotes.<name>]`

Optional, for `opv run --remote <name>` only. A reviewed profile pins where a product's values may go over SSH and what runs there: `host`, `port` (default 22), `user`, `host_key` (the host's public key as `<type> <base64>`, for example from `ssh-keyscan`, without the host name; types `ssh-ed25519`, `ecdsa-sha2-nistp256/384/521`, `ssh-rsa`), `environments` (at least one defined environment, each with no deployment target, whose values may go there: a deployed environment's values reach the host only through the CI sync), `roles` (optional; roles the product's keys declare), `opv` and `workdir` (absolute remote paths of letters, digits and `. _ / + -`, no `..`), `command` (the program and its arguments; no control character but newline and tab) and `identity_file` (optional; default the SSH agent). Every field is checked at load. Recipe: [local development](local-development.md#remote-development-run---remote); guarantees and limits: [design](design/remote-delivery.md).

### Targets: where products deploy

A **target** is one named placement in one environment: one provider's options, the products it serves, its deploy identity and its delivery evidence. An environment declares its targets only as `[environments.<env>.targets.<name>]`, also when there is just one. An environment with no target is run-only: `check`, `run`, `config export` and `item skeleton` work; `plan` and `sync` refuse it.

A target holds:

- exactly one provider section, `fly`, `azure`, `kubernetes` or `github` ([targets by provider](#targets-by-provider));
- `products = ["..."]`, optional: without it the target delivers every non-source-only product with a key desired in the environment;
- `deploy_credentials = "op://<vault>/<item>"`, optional: the item holding only this target's least-privilege deploy identity ([account and deploy credentials](#account-and-deploy-credentials));
- `state_vault_id`, required: the vault that holds this target's delivery evidence ([delivery evidence](#delivery-evidence-state_vault_id)).

```toml
[environments.prod.targets.shared]
fly.app = "portfolio-prod"
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"
deploy_credentials = "op://infra-prod/fly-deploy-shared"
                                             # state_vault_id: the bindings file
```

Target names match `^[a-z][a-z0-9-]*$` and are chosen by a person. There is no generated or default name.

#### Adding a target

`opv propose target <env> <name> --<provider options> [--products …] [--deploy-credentials …]` plans the target; `opv apply` writes it through the configuration editor (comments kept, the result validated, a concurrent change refused). In the same confirmed step it creates the target's state vault and records `state_vault_id` in `secrets.bindings.toml`, so the configuration never names a target without one. It ends with `Next: opv access <env> --target <name>`. If you write the target by hand, leave `state_vault_id` out and run `opv propose structure`: `opv apply` creates the state vault and records it.

#### One provider locator per target

Within one environment a `(provider, locator)` belongs to one target: the same Fly app, the same Key Vault and Container App, or the same context, namespace and Deployment cannot appear on two targets. Across environments one Fly app is allowed when the name templates differ, because the environment is part of the evidence scope.

#### One baseline plus a dedicated overflow

One product can run on a shared app and also on a dedicated overflow app in the same environment. Both targets read the same boundary items, so no value is entered twice, and each keeps its own delivery evidence:

```toml
[environments.prod.targets.shared]
fly.app = "portfolio-prod"                   # every product, p included
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"
                                             # state_vault_id: the bindings file

[environments.prod.targets.p-overflow]
fly.app = "p-overflow-prod"                  # p only
fly.secret_name = "{KEY}"
products = ["p"]
                                             # state_vault_id: the bindings file
```

`shared` has no `products` list, so it delivers every product, `p` included; `p-overflow` delivers only `p`. Both read `p`'s boundary item, so `p`'s values exist once, and `opv delivery verify prod --product p` reports each placement separately.

### One source per key: `from`

Every value has exactly one source: a key's own field, or the field named by `from = "<product>/<KEY>"`. The source is in the source product's boundary item in the same environment. There is no precedence and no fallback: a key never reads a local value, then a wider one, then a default. That is deliberate. A missing value must not silently fall back to another vault, and a value's source is decided by the configuration, not by what happens to exist. [Shared keys](#shared-keys-from) shows the full rule.

### Delivery evidence: `state_vault_id`

Every target needs a state vault for its delivery evidence. `state_vault_id` records it; `opv propose target` and `opv apply` create it, and `opv propose structure` creates and records any that is missing. A target without one fails at load with `state_vault_missing`.

Each placement (a product the target delivers) keeps its evidence in one item of that vault, `opv · delivery · <product> · <target>`. `opv apply` creates it and records its id in `secrets.bindings.toml` under the target, so no command ever looks a state item up by title:

```toml
[environments.prod.targets.shared]
# state_vault_id and delivery_items: the bindings file
```

A placement without a recorded item gets no evidence (its sync names `opv propose structure` as the next step), and an entry for a product the target does not deliver fails at load. The item's evidence lines (store version and keyed fingerprint per name) are also the version ledger `plan` and `status` judge Fly and GitHub secrets by.

The state item holds the evidence key, the keyed fingerprints and, for Fly, digests, so its reader can test guesses against values. A state vault must therefore never be readable more widely than the values it covers. Several targets may share one state vault only when they deliver products from the same set of boundaries. Otherwise the configuration fails at load with `state_vault_wider_than_values`, naming the vault, the targets as `<env>/<target>` and a boundary one of them cannot read. One state vault per target is the safe choice.

### Account and deploy credentials

`account` is the one connection setting that sits on the environment, not on a target. `deploy_credentials` sits on a target, with no environment-level form and no fallback.

```toml
[environments.prod]
account = "ACCOUNTID0000000000000000"            # account ID (opv login --account records it)
boundaries.api = {}

[environments.prod.targets.api]
fly.app = "example-portfolio-production"
deploy_credentials = "op://infra-prod/fly-deploy" # the deploy identity's item, by ID or name
                                                 # state_vault_id: the bindings file
```

- `account`: every `op` call for this environment uses this 1Password account (passed as `--account`), and `opv login prod` signs in to it. Set it only when your environments live in different accounts; otherwise the project's account (above) applies. Use the account ID (`op account list` shows it): op takes no email, and a sign-in address may be shared by several accounts. A bad value is a configuration error pointing at its line and column. Under a service-account token in CI the token decides the account.
- `deploy_credentials`: an `op://<vault>/<item>` reference to a whole item (never a field) holding only this target's least-privilege deploy identity. `status`, `plan`, `sync` and `doctor --env` read it and sign the target CLI in for that run only. The fields are fixed per provider: Fly `FLY_API_TOKEN` (concealed); Azure `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` (text) and `AZURE_CLIENT_SECRET` (concealed). Kubernetes takes none (`kubectl` uses your kubeconfig), except when its secrets live in a Key Vault (`secrets_in`): then the item holds the Azure fields and signs in the `az` that writes that Key Vault. Otherwise `deploy_credentials` on a Kubernetes target is a configuration error. If the sign-in fails, `doctor --env` shows one `FAIL deploy credentials:` line, runs its other checks and skips the target checks that need those credentials.

Give the deploy identity only what a sync needs: a Fly deploy token for that one app, or an Azure service principal with Key Vault Secrets Officer on that vault and Contributor on that Container App. Break-glass (owner or admin) credentials are for people and are never referenced by `deploy_credentials`.

How a run uses each field, and where Azure keeps its sign-in:

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

`check`, `run`, `config export` and `item skeleton` never read `deploy_credentials`.

### Guarding an environment: `confirm_env`

```toml
[environments.prod]
confirm_env = true
```

With `confirm_env = true`, `sync` must be given the environment name again: `opv sync prod --deploy --confirm prod`. Without it, opv reads the boundary items and the target and validates every key first, then refuses before the first write (exit 6), so one refusal also names any blocking keys; its `Next:` line is the exact command to re-run, with every flag you gave plus `--confirm prod`. A `--confirm` naming another environment is refused for every environment, before any call. Only `sync` changes the target, so only `sync` needs it: reading commands (`status`, `plan`, `check`, `run`) and `item skeleton` (which writes to 1Password, not the target) are unaffected. `plan` suggests the sync command with `--confirm prod` already in it. CI jobs that sync a guarded environment must pass the flag. `confirm_env` is a boolean (default `false`); any other value is a configuration error.

### Removed forms

There is one configuration form. Input in a removed form fails at load with its line, its column and the exact current form to write; nothing reads or converts it. This table lists every form removed in 0.7.0 and what replaces it.

| Removed form | Current form |
|---|---|
| environment-level `vault_id` / `item_id` | `boundaries.<product> = {}`, with the ids in `secrets.bindings.toml`, recorded by `opv apply` |
| an environment-level provider table (`fly.app = "…"`, `[environments.<env>.azure]`, …) | `[environments.<env>.targets.<name>]` with that provider section under it |
| environment-level `deploy_credentials` / `state_vault_id` | the same keys on the target, under `[environments.<env>.targets.<name>]` |
| `[profile]` and `profile.kind` | none: one form; declare each key under `[products.<name>.keys.<KEY>]` |
| top-level `[keys]` | `[products.<name>.keys.<KEY>]` |
| `from = "<KEY>"` (a bare key) | `from = "<product>/<KEY>"` |
| `products` inside a provider section (`github.products`, …) | the target's `products = ["…"]`, beside the provider section, on every provider |
| the `pattern` rule | `regex = "<regex-escaped prefix>(?:<pattern>)"` |

There is no conversion. Every removed form's load error shows the replacement to paste.

## Store layout

One vault per access boundary, one values item in it, one section per product, one field per key. A concealed field is a secret; a text field is config.

You don't need to lay out 1Password by hand. opv finds each declared key wherever its field is (a label spelled `openai api key`, a field in the wrong section or at the top level, a secret saved as text, a duplicate), so a layout difference never stops a command. When you run opv yourself (signed in to `op` as a person), it also tidies the item to this layout (every command that reads the item except `opv doctor` and `opv ready`, which never write; `opv propose tidy <env>` plans it): it creates missing sections and empty fields, conceals secrets saved as text, renames and moves fields, and sets duplicates aside. It deletes nothing: anything it displaces or replaces goes to a section named `opv · kept`, labelled with where it came from and the date. It prints one line saying what it changed:

```text
tidied 1Password (dev): created section api; made api/OPENAI_API_KEY concealed; kept old copies in "opv · kept"
```

A sync records its delivery evidence in the target's state vault, not in the values item: one evidence line per written name, with the store's version and a keyed fingerprint. That lets `plan` tell exactly whether a Fly or GitHub secret matches 1Password. See [delivery evidence](#delivery-evidence-state_vault_id).

Under a service account, Connect or in CI, opv never writes to 1Password: it reads the item as it is and prints one note that your next local run will tidy it. A value it can fix unambiguously from the key's rules (a trailing newline, a missing `ensure_prefix`) is used in its fixed form, and the tidy writes it back, keeping the original in `opv · kept`. Filling in a missing value is always up to you; opv names the keys that still need one. Design: [self-healing conventions](design/self-healing-conventions.md).

```text
vault portfolio-api-prod   item portfolio · api · prod values   section api   field OPENAI_API_KEY   (concealed)
                                                                              field SIGNUP_POLICY    (text)
```

## Targets by provider

Each target's one provider section uses the fields below. The target also carries `products`, `deploy_credentials` and `state_vault_id` ([above](#targets-where-products-deploy)).

How the values travel depends on the field kind:

- A **secret** (concealed field) is stored in the target's secret store and bound to the app as a reference to one exact version.
- **Config** (text field) is set as a plain environment variable on the app. Set `config = "store"` to keep config in the store too. There is no way to put a secret in a plain variable.
- On Fly, config is synced only when `fly.config = "secrets"`; otherwise deployment tooling reads it with `opv config export <env> --json`.
- On GitHub Actions, secrets become Actions **secrets** and config becomes Actions **variables**.

### Fly

```toml
[environments.prod.targets.shared]
fly.app  = "myapp-production"                  # required; passed as --app on every flyctl call
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"    # optional; defines target names; one product may use "{KEY}"
fly.config = "secrets"                         # optional: secrets (store config too) or none
deploy_credentials = "op://infra-prod/fly-deploy"
                                             # state_vault_id: the bindings file
```

`fly.config` decides what happens to config (text) keys. `secrets` stages them in Fly secrets under the same name template and deploys them exactly like secrets (`flyctl secrets import --stage`, values on stdin, compared by digest). `none` says the target deliberately carries no config, and each run warns `not delivered (no config channel: fly.config = none)`. Unset warns `not delivered (no config channel: set fly.config)` in 0.11.0 and will be refused from 0.12.0. Config stays config: the app sees it as an environment variable at boot, plan rows show it `via Fly secret`, and anything sensitive must be `kind = "secret"`.

Secrets are staged with `flyctl secrets import --stage` (values on stdin) and deployed with `flyctl secrets deploy` only under `sync --deploy`. Fly does not reveal stored values, so opv compares digests after staging ([change detection](usage.md#change-detection-on-fly)). With one product, `secret_name = "{KEY}"` delivers bare names, and two targets may not share an app within one environment. `deploy_credentials` can hold a `FLY_API_TOKEN` for the app ([above](#account-and-deploy-credentials)).

### Azure: Key Vault + Container Apps

```toml
[environments.prod.targets.api]
azure.subscription   = "00000000-0000-0000-0000-000000000000"   # id or name; required
azure.key_vault      = "kv-myapp-prod"
azure.resource_group = "rg-myapp"
azure.container_app  = "ca-myapp"
azure.container      = "api"                       # only if the app has more than one container
azure.identity       = "system"                    # or the resource id of a user-assigned identity
azure.env_name       = "FLEET__{PRODUCT}__{KEY}"   # optional; defines target names
azure.config         = "env"                       # default; "store" keeps config in Key Vault too
                                                   # state_vault_id: the bindings file
```

| Field | Meaning |
|---|---|
| `subscription` | Required. opv passes it on every `az` call and never uses your default subscription. |
| `key_vault` | The vault that holds the secrets. |
| `resource_group` | The resource group of the Container App. The vault is found by name in the subscription, so it may live in another resource group. |
| `container_app` | The app that receives the variables. |
| `container` | Optional. Required only when the app runs more than one container; opv then lists the names. |
| `identity` | `system`, or the resource id of the user-assigned identity the app uses to read Key Vault. |
| `env_name` | Template for the variable name; must contain `{PRODUCT}` and `{KEY}`. It defines the managed set. With one product, a `{KEY}` template delivers bare names. |
| `config` | `env` (default) or `store`. |

Names and limits are checked when the file loads, before any call:

- The Key Vault name is the variable name with `_` changed to `-`, and must match `^[0-9A-Za-z-]{1,127}$`. `FLEET__API__OPENAI_API_KEY` is stored as `FLEET--API--OPENAI-API-KEY`.
- Key Vault names ignore case, so two keys that map to the same name, even in different case, are an error naming both.
- A Key Vault value may be at most 25 KB (25,600 bytes) and cannot be empty. A longer or empty value blocks the sync like a failed rule: `failed store_limit (longer than the Key Vault limit of 25 KB)`.
- Every identifier is checked like `fly.app` (no leading `-`, no shell metacharacters).

opv tags every secret it writes `opv-managed=<env>` and only ever deletes tagged secrets. Just before a prune deletes one, opv adds `opv-pruned=<env>`; Key Vault keeps deleted secrets for its retention period, and when that key comes back opv recovers the entry and writes the new version. A deleted secret without both tags is never recovered by opv: sync stops with the `az keyvault secret recover` command. opv never purges. `opv explain <KEY>` shows the Key Vault name and the variable it feeds.

### Kubernetes: Secrets + Deployment

```toml
[environments.dev.targets.api]
kubernetes.context    = "kind-opv"                  # required; passed to every kubectl call
kubernetes.namespace  = "myapp"                     # required
kubernetes.deployment = "api"                       # required
kubernetes.container  = "api"                       # optional when the pod has one container
kubernetes.env_name   = "FLEET__{PRODUCT}__{KEY}"   # optional; defines target names
kubernetes.config     = "configmap"                 # or "env" (the default when unset) or "store"
kubernetes.secrets_dir = "/run/secrets/{product}"   # optional: file keys become files here
roles = ["serve"]                                   # required when a delivered key declares roles
                                                    # state_vault_id: the bindings file
```

opv always passes `--context` and `--namespace`, so it never acts on whatever context your shell has selected. Each secret value becomes an immutable Kubernetes Secret named `opv-<name>-<random id>` (the id says nothing about the value), labelled `opv-managed=<env>`, and the Deployment's variable points at it with `secretKeyRef`. An unchanged value writes nothing (opv compares it with the bound Secret); a changed value is a new Secret. After a healthy rollout opv deletes the older Secrets that neither the Deployment nor any ReplicaSet references, and `--prune` removes a key that is no longer declared. The Secret name is the variable name lower-cased with `_` changed to `-`; that part is also the `opv-key` label value, so it must match `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` with at most 63 characters, and collisions are an error. A longer name is refused when the configuration loads (`renders Kubernetes name of N characters, which must match …`). A key whose variable name starts or ends with `_` (a Secret name starting or ending in `-`) is refused the same way, naming the key and its line.

**Config (`kubernetes.config`).** Where config keys go:

| Value | Config keys become | Readable by |
|---|---|---|
| `env` (default when unset) | plain `value` entries on the Deployment | anyone who can read the Deployment |
| `configmap` (what `opv apply` writes) | immutable ConfigMaps `opv-<name>-<random id>`, bound with `configMapKeyRef` | anyone who can read ConfigMaps or the Deployment |
| `store` | Secrets, like secret keys | as Secrets |

ConfigMaps are versioned, compared exactly and cleaned up like Secrets. Config is declared non-secret, so a ConfigMap is the right place for it; every `plan` and `status` row names its channel. `configmap` cannot be combined with `secrets_in` (External Secrets bind every key from the named store), and is refused when the configuration loads; use `env` or `store` there.

**Files (`kubernetes.secrets_dir`).** Without it, no key is a file and everything is a variable. With it, every delivered key that has `file = "<relative/path>"` is mounted at `<secrets_dir>/<path>` and only there: its variable is removed in the same change. `{product}` in the directory renders the product name (`_` becomes `-`); it is required when two products deliver file keys to one target, and two products may not render the same directory. The directory must be absolute and normalised, not `/`, not under `/proc`, `/sys`, `/dev` or `/var/run/secrets/kubernetes.io`, at most 255 bytes, with no `:` or whitespace. A config key with `file` needs `config = "configmap"` or `"store"`, and within one product no key's `file` may be a parent directory of another's (`a` and `a/b`): Kubernetes accepts that volume with only a warning and the pod never starts.

- **How it is mounted.** One projected volume per product, `opv-files-<product>`, holds one item per file key, each pointing at that key's immutable Secret (or ConfigMap) version. The `opv-files-` prefix is reserved for opv. The volume is read-only and mounted **only into the target's container** (`kubernetes.container`); other containers in the pod, a sidecar for example, get no mount.
- **Who can read the files.** Files are mode 0440, owned by root with the pod's `fsGroup` as group. Kubernetes has no per-file owner for these volumes, so set `spec.template.spec.securityContext.fsGroup` to a group that **this product's container alone** uses. opv never sets `fsGroup`. Before any write, `sync` checks the Deployment's security context: a workload that sets no `fsGroup` and runs as a non-root user (or whose user or group opv cannot tell) is refused as `mount_unreadable` with nothing written; `plan`, `status` and `doctor` print the same finding as a warning. A workload running as root (or in group 0) can read the files; opv prints a warning on every run and goes on.
- **A path already in use.** If the target container already mounts another volume at the directory, above it or inside it, `plan`, `status` and `sync` refuse (`policy_refused`, exit 6) and name the volume, and `doctor` reports it.
- **Refresh.** A new value is a new object version, so the Deployment changes and Kubernetes rolls out new pods; running pods never see a value change in place.

**Rights.** opv needs `get`, `create`, `patch`, `list` and `delete` on Secrets, `get` and `update` on Deployments, and `list` on ReplicaSets and Pods; a `configmap` target also needs `get`, `list`, `create`, `patch` and `delete` on ConfigMaps (`apply --server-side` is authorised as `patch`, and as `create` for a new object). Grant them with a **namespaced Role** in the target's namespace, never a ClusterRole. `opv doctor` checks each one and names the grant; `sync` checks the rights only a deploy uses (`delete`, and `list` on ReplicaSets and Pods) before its first write.

### GitHub Actions: repository and environment secrets

Keep CI secrets in 1Password and let `opv sync ci` set them, instead of running `gh secret set` by hand.

```toml
[environments.ci.targets.actions]
github.repo        = "my-org/my-app"       # or repos = ["my-org/api", "my-org/web"]: the same values in each
github.environment = "staging"             # optional: that GitHub environment's secrets and variables
github.secret_name = "{KEY}"               # optional; default {KEY}, so workflows read secrets.FLY_API_TOKEN
products           = ["api"]               # optional: only these products' keys go here
                                           # state_vault_id: the bindings file
```

| Field | Meaning |
|---|---|
| `repo` / `repos` | Exactly one of them. `owner/name`; each listed repository gets every value. |
| `environment` | A GitHub environment that must already exist in every listed repository. opv never creates one, because its protection rules and reviewers are your decision; `sync` stops before any write and prints the `gh api -X PUT repos/<repo>/environments/<name>` command. |
| `products` | Keys of other products are not delivered here (they are still read, and keys here may point at them with `from`). `plan` lists declared keys it does not deliver. |
| `secret_name` | Name template with `{KEY}` and optionally `{PRODUCT}`. Names must match `^[A-Z][A-Z0-9_]*$` and may not start with `GITHUB_`. |

What happens on each command:

- **Secrets** (concealed fields) are set with `gh secret set NAME`, the value on stdin. GitHub never shows a secret's value again, so `status` shows an existing one as `unknown` and every `sync` writes it again; an `immutable` key that is already there is held.
- **Config** (text fields) is set with `gh variable set NAME`, the value on stdin. Variables can be read back, so `status` and `plan` show `new`, `same` or `changed`, and `sync` writes only what differs. A config key kept in a concealed field is refused here (`concealed-config`): a variable is readable by everyone who can read the repository.
- Writes are live at once: there is nothing to deploy, and `sync --deploy` says so.
- `--prune` deletes only names opv manages (secrets and variables alike); other secrets in the repository are listed as unmanaged and never touched.
- Limits, shown by `status` and `plan` before any write: a secret over 47 952 bytes, an empty variable, or a variable over 48 000 bytes.

Sign-in: your `gh auth login` session, or `GH_TOKEN` / `GITHUB_TOKEN`. For CI, put a fine-grained token in a `deploy_credentials` item with one concealed field `GH_TOKEN`, scoped to the listed repositories with **Secrets: write** and **Variables: write** (and **Environments: read** when you use `environment`). Never use an owner or classic token. A ready-made setup is in [examples/github-ci](../examples/github-ci/).

### Secrets in a named store: `[stores.<name>]` and `secrets_in`

A runtime can keep its secrets in a store from another provider. Declare the store once and point the target at it with one line; the commands do not change. In 0.5.0 the one supported pair is **Azure Key Vault → Kubernetes Deployment**, through the [External Secrets Operator](https://external-secrets.io) (ESO).

```toml
[stores.prod-vault]                        # any name: lower-case letters, digits and -
azure_key_vault = "kv-myapp-prod"          # the store kind is the key; its value is the vault
subscription    = "00000000-0000-0000-0000-000000000000"   # required
# secret_store  = "prod-vault"             # the in-cluster ClusterSecretStore; default: the store name

[environments.prod.targets.api]
kubernetes.context    = "aks-prod"
kubernetes.namespace  = "api"
kubernetes.deployment = "api"
kubernetes.secrets_in = "prod-vault"       # optional; without it, opv's own Kubernetes Secrets
                                           # state_vault_id: the bindings file
```

| Field | Meaning |
|---|---|
| `azure_key_vault` | The vault that holds the values (3 to 24 letters, digits and `-`). |
| `subscription` | Required subscription id. opv passes it on every `az` call. |
| `secret_store` | Optional. The `ClusterSecretStore` that reads this vault in the cluster. Defaults to the store's name. |
| `secrets_in` | On a target's provider section: the store its secrets live in. |

- **What opv does.** Each secret is written to Key Vault as a new version (as for an Azure target). With `--deploy`, opv creates an `ExternalSecret` named `opv-<name>-<first 10 characters of the version id>` that fetches exactly that version once (`refreshInterval: "0"`), waits until it is `Ready` (its Secret exists), and only then points the Deployment's variable at that Secret. The version id is random, so no name or label says anything about the value.
- **Names.** Key Vault rules apply (`_` becomes `-`, names ignore case), and the name must also fit a Kubernetes name of at most 63 characters, starting and ending with a letter or digit. Two environments that keep the same Key Vault name in one store are an error naming both, because each would overwrite and prune the other's value.
- **Config.** `config = "env"` (default) keeps config as plain variables on the Deployment; `config = "store"` routes it through Key Vault and an ExternalSecret like a secret.
- **Unsupported pairs.** `secrets_in` on `fly` or `azure`, or a store name that is not declared, is a configuration error that lists the defined stores or the supported pairs, at its line.
- **Prerequisites.** ESO serving `external-secrets.io/v1` (tested with 2.11) and a `ClusterSecretStore` that can read the vault. `opv doctor` checks both; [agent-setup.md](agent-setup.md#azure-or-kubernetes-instead-of-fly) shows how to create the store.

`opv explain <KEY>` prints the whole chain, for example `DB_URL → Key Vault kv-myapp-prod (pinned version) → ExternalSecret opv-db-url-<version> → Secret of the same name → env DB_URL`.

## Shared keys: `from`

When two products need the same value (both `api` and `worker` read `DATABASE_URL`), keep one field in 1Password and point the second key at it with `from`. The source is the source product's boundary item in the same environment; there is no other source and no precedence.

```toml
[products.api.keys.DATABASE_URL]
kind = "secret"
environments = ["staging", "prod"]
guidance = "Neon / connection string"

[products.worker.keys.DATABASE_URL]
kind = "secret"
from = "api/DATABASE_URL"            # read api's field; worker has no field of its own
environments = ["prod"]
rules = { prefix = "postgres://" }   # optional: checked as well as api's own rules
```

- The value comes from the source's field in the same environment's boundary item. References to another item or environment (`op://...`, `staging/api/KEY`) are refused at load.
- Each key keeps its own target name: `sync` writes `FLEET__API__DATABASE_URL` and `FLEET__WORKER__DATABASE_URL` from the one field, and `run --product worker` exports `DATABASE_URL` from `op://<vault>/<item>/api/DATABASE_URL`. Change the source and every key sharing it changes in the same sync.
- Checked at load, with the line of the `from`: the source is declared, has its own field (no chains or cycles), has the same `kind`, and is declared for every environment the sharing key uses.
- The source's rules apply first, then the sharing key's own `rules` on the same value. `immutable` follows the source and may not be set on the sharing key; `--rotate api/DATABASE_URL` rotates both.
- `item skeleton` never adds a field for a sharing key. A leftover field from before the switch (`worker/DATABASE_URL`) is reported as an extra field; delete it in 1Password.

### One home for shared values: `source_only` products

When one value feeds many products (one Fly org token, one Cloudflare account ID for every repository's CI), give it a neutral home instead of making one product its owner. Mark a product `source_only` and point the others at its keys:

```toml
[products.shared]
source_only = true                         # holds values; never delivered anywhere itself

[products.shared.keys.FLY_API_TOKEN]
kind = "secret"
environments = ["ci"]
guidance = "Fly org deploy token"

[products.api.keys.FLY_API_TOKEN]
kind = "secret"
from = "shared/FLY_API_TOKEN"              # no field of its own: reads section "shared"
environments = ["ci"]

[products.web.keys.FLY_API_TOKEN]
kind = "secret"
from = "shared/FLY_API_TOKEN"
environments = ["ci"]
```

- The value lives once, in section `shared` of each environment's boundary item. Change it there and every key pointing at it changes in the next sync; `--rotate shared/FLY_API_TOKEN` rotates them all.
- A source-only product's keys get fields, rules, `immutable` and the missing-value lines like any key, but they are never written to a target, never pruned, and their names never collide with a delivered key's.
- `check`, `status` and `plan` warn about a source-only key that nothing points at. `opv run --product shared` is refused: run the product that uses the value.
- Values never cross environments: `ci` reads the `shared` section of the `ci` boundary item only.
- The name `shared` is a convention; any product name works.

## Settings health: likely-wrong values

A value can be present and pass its rules and still be wrong. `opv ready` (and `opv ui`, and `opv doctor --settings`) compares the values it reads, in memory and never shown, and warns about:

| code | when |
|---|---|
| `same_value_across_environments` | a secret has the identical value in two or more environments (production's key copied into development, or the other way round) |
| `same_value_under_two_keys` | two secrets in one environment hold the identical value without `from` |
| `placeholder_value` | a secret is `changeme`, `xxx`, `<your key>`, `your_api_key_here` and the like |
| `whitespace_around_value` | a one-line value starts or ends with a space, tab or newline |
| `local_address_in_deployed_environment` | a value in an environment with a target points at `localhost`, `127.0.0.1`, `0.0.0.0` or `host.docker.internal` |
| `test_key_in_production` / `live_key_outside_production` | a `sk_test_`/`pk_test_`/`rk_test_` key where the environment's `tier` is production, or a `sk_live_`/`rk_live_` key in any other tier |

- These are **advisory only**: they never block `opv ready --gate`, `opv apply` or anything else. Each names the environments and keys and ends with `opv open <key> --env <env>`.
- Config values may be the same everywhere; only secrets are compared across environments. Personal keys and empty values are never looked at.
- The cross-environment comparison (`same_value_across_environments`) is computed only for a person at a terminal and for CI. It is never computed on an assistant surface (MCP or agent mode), because a development environment is readable by design and the bit would disclose an equal production value.
- When one secret really is meant for several environments, say so on the key with `allow_same_value = true`. One value for several keys inside an environment is a [shared value](#shared-keys-from) (`from`), which has one field and is never a duplicate.

## Personal keys: each developer's own values

Some local values should be each person's own: an LLM API key, so every developer's spend is on their own key; a personal access token. Mark the key `personal = true`:

```toml
[products.api.keys.OPENAI_API_KEY]
kind = "secret"
environments = ["dev"]
personal = true
guidance = "create your own key (billed to you)"
```

- The value lives in each person's own item: in their own Private (or Employee, or Personal) vault, titled `<project> · <env> (personal)`. Set `personal_vault` and `personal_item` on the environment to use other titles. `opv apply` creates your item with an empty field for each personal key; `opv ready` names the ones you still need to fill as yours.
- `opv run` reads team keys from the team boundary items and your personal keys from your own item, never the other way round: a personal key never falls back to a team value, and nobody else's item is ever read.
- One personal value for several products: put it in a source-only product (`[products.shared] source_only = true`, the key `personal = true`) and point each product's personal key at it with `from = "shared/OPENAI_API_KEY"`. A personal key may only point at a personal value, and a team key never at one.
- Personal keys are for local environments only: declaring one for an environment with a target is a configuration error, and `sync` never reads a personal item. Deployed environments use the service's own value. A product whose keys in an environment are all personal needs no boundary there.

Example: [examples/team-personal](../examples/team-personal/).

## Environment display name, order and audience

Besides its key, an environment can carry a display name, an order and an audience for people.

```toml
[environments.prod-us]
title = "Production (US)"     # shown in opv ui, opv ready and status; defaults to the key
order = 30                    # grid and column order; defaults to the keys' order
audience = "devops"           # who it is for
```

The key (`prod-us`) stays the name in every command. Who can open an environment is 1Password's decision (share its boundary vaults with a group); `audience` only tells opv what to say to everyone else: someone who cannot open `prod-us` sees "not available to you (audience: devops)" in `opv ready`, as a note, not a problem to fix. `opv apply` tags each item it creates `opv-env:<project>/<env>`.

## Environment tier: `local`, `shared` or `production`

Every environment has a **tier**, written `tier = "local" | "shared" | "production"`, that says how much a mistake in it costs and what opv may do without asking.

```toml
[environments.dev]
tier = "local"                # your machine: no target, no confirmation

[environments.staging]
tier = "shared"               # a team environment (the default)

[environments.prod]
tier = "production"           # real users
```

- The default is `production` when the environment's name or title says production (`prod`, but not `preprod` or `nonprod`), and `shared` otherwise. Write `tier` only to override that guess.
- `local` is a development environment: declaring a **target** on it, or `confirm_env`, is refused at load with `config_invalid`. It has no state vault and never deploys; a local value is delivered from the developer's own item through [`[products.<p>.local]`](#local-delivery-productsplocal-and-file) instead.
- `shared` environments ask for nothing extra.
- `production` environments are guarded: `sync` and `deploy` ask you to type the environment's name first (unless `confirm_env = false`, the [guarded-environment escape](#guarding-an-environment-confirm_env)), and production is the last tier a [retiring key](#key-attributes-source-expires-and-lifecycle) is pruned from.

## Writing the configuration with commands

Configuration changes are **proposed**, then **applied**. `opv propose …` writes the contract diff and the 1Password plan and nothing else; `opv apply` runs the plan you reviewed, writes the configuration where it lives (manifest or file) and records `.opv/applied.json`. Comments and order are kept, the result is validated like a hand-written file, and a concurrent change is refused. `opv config edit` covers everything else.

The 0.11 commands (`opv init`, `opv add`, `opv bootstrap`, `opv target add`, `opv check`, `opv adopt`) are gone; [Migrating from 0.11](usage.md#migrating-from-011) maps each one to the command that replaces it.

<a id="start-from-an-existing-item-opv-init"></a>

### Start from an existing item: `opv propose setup`

If the 1Password item already exists, `opv propose setup --from-item` builds the contract from it instead of writing one by hand. Review the plan, then apply it:

```sh
opv propose setup --from-item staging --vault myapp-staging --item myapp --project api
opv apply
```

- Without `--vault` and `--item` it uses the boundary titles `<project>-<product>-<env>` and `<project> · <product> · <env> values` (the project name is `--project`, else the repository's, else the directory's), so the values item reads apart from the manifest `opv · <project>`. `opv propose setup --from-item dev` alone is enough for a new project.
- The product that unsectioned fields belong to is chosen in the plan; it is required when the item has unsectioned fields. Sectioned fields become products named by their section. An item with both shapes is an error naming both, and opv never guesses. Product names describe the app's role (`web`, `api`, `worker`).
- **One item is one boundary.** The item lives in one vault, so the products it declares share one boundary. One product records `boundaries.<product>`; several record `boundary = "core"` on each product and one `boundaries.core`.
- It looks the vault and the item up **by title**, once (exact, case-sensitive match). No match, or more than one, is an error (exit 2) that lists the candidates by name and ID. This is the only title lookup in opv: every other command reads the item by vault ID and item ID.
- It reads the item once and writes **ids, key names and kinds only**. A concealed field becomes `kind = "secret"`, a text field `kind = "config"`, each with `environments = ["<env>"]`. Values are never read into opv, written or printed. Rules, guidance, modes and other environments are left for you to add.
- A field whose label is not a valid key name (`^[A-Z][A-Z0-9_]*$`), a section whose label is not a valid product name, and a field of another type (URL, email, ...) are skipped with a note naming them. Nothing is renamed: rename the field in 1Password and propose setup again. A label given twice is declared once. When the vault or item does not exist yet, `opv apply` creates them (the vault only if your account allows it) and records their ids in `secrets.bindings.toml`; under a service account or in CI it stops and names the next step.
- **It writes no target.** It writes boundaries and products only; `opv propose target` is the one way to add a deployment target ([below](#add-a-target-opv-propose-target)), and a run-only environment needs none.
- **Where it writes.** In a new project (no `secrets.toml` here or in a parent) the plan saves a manifest `opv · <project>` in the item's vault, tagged with the git remote. An existing manifest for the project is never overwritten: change it with `opv config edit`. With `--file`, or when a `secrets.toml` is already found, it writes `./secrets.toml` in the current directory instead (`--config` and `OPV_CONFIG` are refused; use `opv propose env` to extend a file elsewhere). An existing file is refused (exit 2). The text is validated like a hand-written one and written atomically by `opv apply`.

### Add a target: `opv propose target`

`opv propose target <env> <name> --<provider options> [--products …] [--deploy-credentials …]` plans a named target; `opv apply` writes it through the configuration editor (comments kept, the result validated, a concurrent change refused) and creates the target's state vault, recording `state_vault_id` in `secrets.bindings.toml` ([adding a target](#adding-a-target)). Target names match `^[a-z][a-z0-9-]*$` and are chosen by a person; opv generates no name. `opv target list [--env <env>] [--json]` shows the declared targets, and the provider's fields are in [targets by provider](#targets-by-provider).

```sh
opv propose target prod shared --fly-app myapp-production
opv propose target ci actions --github-repo my-org/my-app --products api
opv apply
```

### Mint a target's deploy credential: `opv target credentials`

A target that deploys through `deploy_credentials` needs an item with just its least-privilege identity. `opv target credentials <env> --target <name> --create` mints that credential at the provider and stores it straight in a new 1Password item in the target's state vault, then records `deploy_credentials` for you. The token is never shown, copied or pasted: it stays in memory and reaches `op item create` on stdin only. The credential is named `opv-<project>-<env>-<target>`, asked to be valid for 90 days, and stored under the title `<project> · <target> · <env> deploy credentials`. One confirmation names all of that and the state vault; declining creates nothing. It refuses, before calling the provider, a target that already records `deploy_credentials` — rotation is a separate reviewed step — and a provider that cannot mint one here. A person's own interactive terminal and 1Password session are required. It writes the reference through the same configuration editor as `opv propose target` (comments kept, the whole file validated, a concurrent change refused). Without `--create` it prints whether `deploy_credentials` is recorded and whether the provider can mint one.

```sh
opv target credentials prod --target shared --create
opv target credentials prod --target shared
```

<a id="start-from-an-existing-env-opv-init---from"></a>

### Start from an existing `.env`: `opv propose setup --names-from`

A project that already runs from a `.env` file gets into opv in one step, without a script:

```sh
chmod 600 .env
opv propose setup --names-from .env --file                   # every name and its kind; nothing written
opv apply                                                   # create the vault and item, declare, import
```

- Every `KEY=value` line becomes a declared key for the chosen environment, next to any field the item already has. A field the item already has keeps its kind and its value: a differing value in the file is reported, never written (`opv import <env> --from .env --replace <p/KEY>` takes it).
- The kind comes from the name only, never the value, and is secret when unsure: config for names like `*_ENABLED`, `*_MODEL`, `PORT`, `*_ORIGIN`, `*_CLIENT_ID`, `*_REDIRECT_URI`; secret for everything else, including `*_URL` (a database or webhook URL carries credentials) and any name with `SECRET`, `TOKEN`, `PASSWORD`, `PRIVATE` or `CREDENTIAL`. Change one with `--config-key KEY` or `--secret-key KEY` (repeatable); the plan shows every kind before anything is written.
- `opv apply` imports the values the way `opv import` does: one item edit, read back and checked. An empty value is declared but not imported, so `opv ready` lists it as missing. Values go to 1Password on stdin only, never in arguments, files or output.
- The file must be a private regular file (`chmod 600`) under 1 MiB; it is read as literal assignments, never executed, and left as it is. Delete it yourself once `opv run <env> -- …` works.
- Multi-product items: an item already in the multi-product shape (sections per product) is refused by `--names-from`; declare there with `opv propose key`. `--names-from` does not combine with `--from-item`.

### Add an environment: `opv propose env`

```sh
opv propose env staging --tier shared
opv apply
```

Adds one `[environments.<env>]` to the existing configuration (found like every other command's: `--config`, `OPV_CONFIG`, the nearest `secrets.toml`, or the project's manifest in 1Password) instead of writing a new one, with `opv propose key`'s validation, atomic write and concurrency refusal. `--tier local|shared|production` sets the [tier](#environment-tier-local-shared-or-production); the default is `shared`, or `production` when the name says production. A new environment inherits every key whose `environments` list is absent and every key that lists it; keys with an explicit list that omits it are not declared there, and an `environment_gap` warns about a key that looks left out by mistake. It writes no target; add one with `opv propose target`. It prints the keys left out and the fields not declared, each with the command that includes or declares one. It refuses an environment that already exists and never changes anything else.

<a id="declare-a-key-opv-add"></a>

### Declare a key: `opv propose key`

```sh
opv propose key api/STRIPE_KEY --kind secret --env dev --env prod --rule prefix=sk_ --guidance "Stripe › Developers › API keys"
opv propose key api/JWT_KEY --kind secret --rule base64_bytes=32 --immutable
opv propose key api/STRIPE_KEY --env staging                             # a declared key, one more environment
opv propose key web/DATABASE_URL --kind secret --from api/DATABASE_URL   # read another key's value
opv propose key shared/OPENAI_API_KEY --kind secret --env dev --personal # each developer's own value
opv apply
```

- The name is always `PRODUCT/KEY`; `--kind secret|config` is required for a new key. `--env` (repeat it or separate with commas) defaults to every declared environment; `--except <env>=<reason>` removes the key from an environment and records why ([presence](#presence-every-environment-minus-except)).
- `--source person|generated|derived` and `--expires <date>` set the [key attributes](#key-attributes-source-expires-and-lifecycle). `--rule NAME=VALUE` is repeatable and uses the [rules reference](#rules-reference) names. The value is read as a TOML value when the rule takes one (`base64_bytes=32`, `enum=["a","b"]`), else as text (`prefix=sk_`), else as a comma-separated list (`enum=debug,info`). A flag rule is given by name alone (`--rule https_url`). `--guidance` and `--immutable` set those fields; `--from PRODUCT/KEY` makes a [shared key](#shared-keys-from), `--personal` a [personal key](#personal-keys-each-developers-own-values), and `--allow-same-value` marks a repeat across environments as intended ([settings health](#settings-health-likely-wrong-values)). In `opv ui`, `+` fills in the same through a form.
- On a key that is already declared, `opv propose key` only adds the environments it lacks; a different `--kind`, or any rule, guidance, `--immutable`, `--from`, `--personal` or `--allow-same-value`, is refused (change those by hand, or with `opv config edit`). When nothing is missing it says so and changes nothing (exit 0).

### Proposed and applied

`opv propose …` and `opv apply` are two halves of one edit:

- **`opv propose …` writes nothing.** It prints the contract diff (added, removed, changed keys) and the plan of 1Password changes, and exits; a plan is a review artefact, not a change.
- **`opv apply` runs the plan you reviewed.** It writes the contract where it lives and the ids to `secrets.bindings.toml`, creates the vaults, items and state vaults, and records `.opv/applied.json` ([the apply record](#where-the-ids-live-secretsbindingstoml)). A concurrent change to either file is refused; re-run the propose and review the new plan.
- **Rules are evaluated as committed.** A rule that exists only in an uncommitted or branch edit shows `rules_pending_review` and is not evaluated for MCP or agent-mode callers; commit it on the default branch to make it count.

## Rules reference

Rules go in a key's `rules = { ... }` table. A failure names the key, the rule and a reason, never the value.

Always on, for every key (after a `pem_private_key` transform, see below): `nonempty`; `single_line` (no `\n`, `\r` or NUL); `no_surrounding_space`; `max_len` (59,000 bytes).

One exception: a key with `file = "<relative/path>"` delivered to a target that writes files to a filesystem the app reads is staged and delivered **verbatim**, so `single_line`, `no_surrounding_space` and `ensure_prefix` are skipped and the stored bytes are kept exactly (a PEM's trailing newline included); `nonempty`, `max_len` and the declared rules still apply. A declared `transform` runs first, so a `pem_private_key` file key is still delivered as one line. On a target without such a file channel the key is delivered as a variable, and the always-on rules apply as usual.

| Rule | Meaning |
|---|---|
| `prefix = "sk-"` | value starts with the prefix |
| `not_prefix = "sk-or-"` or a list | value starts with none of them |
| `regex = "..."` | the whole value **as staged** matches (full match): after `ensure_prefix` normalisation when the key has one, otherwise the stored value |
| `ensure_prefix = "sk-"` | accepts the value with or without the prefix and stages it with exactly one `sk-`; a value that is only the prefix fails |
| `enum = ["a", "b"]` | value is one of the listed strings |
| `base64_bytes = N` | valid base64 that decodes to N bytes |
| `hex_bytes = N` | valid hex that decodes to N bytes |
| `email_list = true` | comma-separated list of email addresses |
| `https_url = true` | an `https://` URL |
| `prefix_by_mode = { mode, values, skip }` | prefix chosen by the environment's declared mode for the product (`modes.<product>.<mode>`); a mode listed in `skip` disables the check and the key is not required |
| `refuse_in = ["prod"]` | the key must not exist in those environments: a non-empty field there is a blocking failure even though the key is not otherwise expected. The environments must be defined and not also appear in `environments` |
| `transform = "pem_private_key"` | accepts one PEM private key block (label ending `PRIVATE KEY`, not encrypted, matching BEGIN/END, no headers, base64 of a DER SEQUENCE) pasted multi-line into a concealed field or already on one line, and stages it as one line `-----BEGIN <label>-----<base64>-----END <label>-----`. It runs before the always-on rules, which then see the one-line value. Only whitespace is removed, so RFC 7468 parsers that skip body whitespace (Rust `pem` 3.x) read the same key |

The `pattern` rule was removed in 0.7.0; a key that still sets it fails at load. Write `regex = "<regex-escaped prefix>(?:<pattern>)"` instead ([removed forms](#removed-forms)).

Fly import refusals are checked for every ready secret by `status` and `plan` as well as `sync`, so a green status means sync will not refuse the value:

| Rule | Refuses |
|---|---|
| `fly-name-invalid` | a Fly name that does not match `^[A-Z][A-Z0-9_]*$` |
| `import-newline` | a value containing `\n` or `\r` (multiline values are not supported) |
| `import-hash-after-odd-quotes` | a `#` after an odd number of `"` (the import format would truncate it) |
| `import-line-too-long` | an encoded import line over 60,000 bytes |
| `import-invalid-utf8` | a value that is not valid UTF-8 |
| `import-duplicate-name` | the same Fly name twice in one batch |

### Failure reasons

Every rule failure carries a reason. `status`, `plan` and `sync` print it after the rule name, and `--json` carries it in a separate `reason` field next to `rule`:

```text
journeeze/GITHUB_APP_PRIVATE_KEY: failed transform (BEGIN/END labels differ)
```

The rule name is the stable identifier to match on; a reason may be added or reworded in a minor release. Each reason comes from a fixed set per rule, or is built only from the configuration (a configured prefix, mode, byte count or list of allowed values). It never contains anything read from the value: no length, position, character, actual prefix or label.

| Rule | Reasons |
|---|---|
| `refuse_in` | `must not be set in this environment` |
| `nonempty` | `empty` |
| `single_line` | `contains a line break or NUL` |
| `no_surrounding_space` | `leading or trailing whitespace` |
| `max_len` | `longer than the 59000-byte limit` |
| `prefix` | `expected prefix <configured prefix>` |
| `not_prefix` | `starts with a refused prefix` (never which one) |
| `prefix_by_mode` | `wrong prefix for mode <mode>`, `mode <mode name> is not set in this environment`, `no prefix is configured for mode <mode>` |
| `regex` | `does not match the configured regex` |
| `enum` | `expected one of: <declared values>` (from `secrets.toml`, never the stored value) |
| `base64_bytes` | `not standard base64`, `does not decode to <N> bytes` |
| `hex_bytes` | `not hex`, `does not decode to <N> bytes` |
| `email_list` | `not a comma-separated list of email addresses` |
| `https_url` | `not an https:// URL`, `URL contains whitespace` |
| `ensure_prefix` | `nothing after the prefix` |
| `transform` (`pem_private_key`) | `no BEGIN/END markers`, `BEGIN/END labels differ`, `not a private key`, `encrypted key`, `more than one PEM block`, `body is not base64`, `not a key structure` |
| `transform` (other name) | `unknown transform` |
| Fly import rules | `not a valid Fly secret name`, `contains a line break`, `a # follows an odd number of double quotes`, `too long for one Fly import line`, `not valid UTF-8`, `name occurs twice in one import` |

`pem_private_key` refuses an encrypted key, whether it has a `Proc-Type` header or the PKCS#8 `ENCRYPTED PRIVATE KEY` label.
