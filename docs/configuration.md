# Configuration

opv's configuration says where each value lives in 1Password, which environments want it, where each environment deploys, and the rules a value must pass. It holds IDs, names, kinds and rules, never values. It is TOML, kept either in 1Password as a project manifest (no file in the repository) or in a `secrets.toml` file; the schema is the same.

## Where the configuration lives

### How opv finds the configuration

First match wins:

1. `--config <file>` or `OPV_CONFIG`;
2. `OPV_PROJECT=<name>`: the manifest titled `opv · <name>`;
3. `secrets.toml` in the current directory or a parent (an existing file always wins over a manifest);
4. a `.opv` file in the current directory or a parent: `project = "<name>"`, `account = "<account ID>"`, or both. `opv login --account` and `opv init --account` write the account line; commit the file;
5. the manifest tagged with this checkout's git remote (`git remote get-url origin`, normalized to `host/owner/repo`; https, ssh and `git@host:owner/repo` forms are the same).

**Which 1Password account.** opv uses one account per project and never falls back to op's default when that could be the wrong one: the account recorded in `.opv` (or `OP_ACCOUNT`), else the only account `op` knows on this machine. With several accounts and none recorded, every command stops with `account_required`, lists the accounts (email, sign-in address, account ID) and asks you to run `opv login --account <email>` once; opv never searches your other accounts. An email or sign-in address is resolved to the account ID, which is what gets recorded (op itself takes no email, and several accounts can share `my.1password.com`). Every `op` call then carries `--account <ID>`.

`using …` on stderr names what was used (not when given with `--config`). Steps 2, 4 and 5 make one `op item list --tags opv-manifest` call (names and tags only), and loading a manifest is one `op item get`, so these commands need a 1Password session even for `explain` and `config export`; without one the error says so and ends with `Next: opv login`. No match ends with `Next: opv init …`; several matches are listed, and `OPV_PROJECT` picks one.

**Tags.** 1Password reads `/` in a tag as nesting, so the repository tag writes `/` as `|`: `opv-repo:github.com|acme|myapp`. In a monorepo a manifest can cover directories with path tags (`opv-path:apps|api`, from `opv config import --path apps/api`): among manifests for the remote, the one whose path is the longest prefix of the current directory (relative to the repository root) wins; a manifest without paths covers the whole repository at the lowest priority. At the root, or when no path matches and several manifests remain, they are listed with their paths.

### Configuration in 1Password

The configuration can live in 1Password as a **project manifest**: one Secure Note per project, titled `opv · <project>` and tagged `opv-manifest`, whose notes start with an "opv managed configuration" heading and a short explanation, then hold exactly the TOML of a `secrets.toml` (same schema, same validation) in one `toml` code block. opv reads only the code block, and text you add around it is kept. It also has a text field `project`, a field `convention` = `1`, and tags that tie it to a repository. It holds IDs, names and rules, never a value. Every command treats it exactly like a file: `add`, `init --add-env` and `config edit` edit it in place.

#### Moving a file into 1Password

```sh
opv config import --vault myapp-dev                     # validates ./secrets.toml, creates the manifest
OPV_PROJECT=myapp opv config check --file secrets.toml  # identical? exit 0; else exit 2 with a diff
git rm secrets.toml                                     # opv never deletes it for you
```

`import` takes `--file <path>` (default: the `secrets.toml` found from here), `--project <name>` (default: the repository's name) and `--path <dir>` (repeatable). It refuses when a manifest for the same project, or for the same repository and paths, exists.

#### Reading and changing it

- `opv config export` prints the configuration as TOML (byte for byte as stored); `--json` as JSON. `opv config export <env> --json` still prints that environment's config-kind values.
- `opv config edit` opens `$VISUAL` or `$EDITOR` (default `vi`) on a temporary copy (mode 0600, removed afterwards), validates it, shows the diff and asks once. It saves only when nobody changed the configuration since it was opened; otherwise it refuses and re-opens on the new version. It works on a `secrets.toml` too.
- `opv config check --file <path>` compares a committed copy with the manifest: exit 2 with a diff when they differ. Teams that want pull-request review keep a copy and run it in CI; 1Password's item history records every change either way.

## The `secrets.toml` schema

There is one schema. A configuration names environments, the products and keys that live in them, the boundaries (1Password vaults) that hold the values, and the targets that deploy them. There are no profiles: a single-app project is a configuration with one product.

### Boundaries: where values live

A **boundary** is one 1Password vault holding the values for one set of products in one environment. 1Password grants access per vault, so a boundary is the smallest set of values you can give a person or an identity. An environment records a boundary with `boundaries.<name> = { vault_id, item_id }`; `opv bootstrap` creates the vault and item and writes the IDs. Every command reads the IDs, never the names.

By default each product is its own boundary:

| Boundary | Vault | Item |
|---|---|---|
| product (default) | `<project>-<product>-<env>` | `<project> · <product> · <env> values` |
| project shared | `<project>-shared-<env>` | `<project> · shared · <env> values` |
| group (opt-in) | `<project>-<group>-<env>` | `<project> · <group> · <env> values` |

```toml
# Values vaults, one per boundary; opv bootstrap records the IDs here.
[environments.prod]
boundaries.web = { vault_id = "vprd-web", item_id = "iprd-web" }
boundaries.api = { vault_id = "vprd-api", item_id = "iprd-api" }
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

- `boundary_missing`: a product has a team key desired in an environment whose boundary is not recorded. Its next step is `opv bootstrap`.
- A recorded boundary that no product with a key in that environment lives in is refused; remove it, or declare that product's keys for the environment. The configuration never names a vault nothing reads.

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

`kind` is `secret` (a concealed field) or `config` (a text field). `environments` lists where the key is desired. `rules`, `guidance`, `immutable`, `personal`, `allow_same_value` and `from` work as described below and in the [rules reference](#rules-reference). Modes are per product on the environment (`modes.<product>.<mode>`), an input to `prefix_by_mode`.

#### A single-app project: one product

A single-app project is a configuration with one product, written exactly like any other. Name the product after its role. When the app expects bare variable names, use `secret_name = "{KEY}"` on the target, so no product prefix is added.

```toml
# Values vault for the one product; opv bootstrap records the IDs here.
[environments.prod]
boundaries.web = { vault_id = "vprd1234example", item_id = "iprd1234example" }

[environments.prod.targets.web]
fly.app = "myapp-production"
fly.secret_name = "{KEY}"                    # the app reads bare names: no product prefix
state_vault_id = "vstate1234example"         # created by opv target add

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
state_vault_id = "vprd-state-shared"
```

Target names match `^[a-z][a-z0-9-]*$` and are chosen by a person. There is no generated or default name.

#### Adding a target

`opv target add <env> <name> --<provider options> [--products …] [--deploy-credentials …]` writes the target through the configuration editor (comments kept, the result validated, a concurrent change refused). In the same confirmed step it creates the target's state vault and records `state_vault_id`, so the configuration never names a target without one. It ends with `Next: opv access <env> --target <name>`. If you write the target by hand, leave `state_vault_id` out and run `opv bootstrap`: it creates the state vault and records it.

#### One provider locator per target

Within one environment a `(provider, locator)` belongs to one target: the same Fly app, the same Key Vault and Container App, or the same context, namespace and Deployment cannot appear on two targets. Across environments one Fly app is allowed when the name templates differ, because the environment is part of the evidence scope.

#### One baseline plus a dedicated overflow

One product can run on a shared app and also on a dedicated overflow app in the same environment. Both targets read the same boundary items, so no value is entered twice, and each keeps its own delivery evidence:

```toml
[environments.prod.targets.shared]
fly.app = "portfolio-prod"                   # every product, p included
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"
state_vault_id = "vprd-state-shared"

[environments.prod.targets.p-overflow]
fly.app = "p-overflow-prod"                  # p only
fly.secret_name = "{KEY}"
products = ["p"]
state_vault_id = "vprd-state-p"
```

`shared` has no `products` list, so it delivers every product, `p` included; `p-overflow` delivers only `p`. Both read `p`'s boundary item, so `p`'s values exist once, and `opv delivery verify prod --product p` reports each placement separately.

### One source per key: `from`

Every value has exactly one source: a key's own field, or the field named by `from = "<product>/<KEY>"`. The source is in the source product's boundary item in the same environment. There is no precedence and no fallback: a key never reads a local value, then a wider one, then a default. That is deliberate. A missing value must not silently fall back to another vault, and a value's source is decided by the configuration, not by what happens to exist. [Shared keys](#shared-keys-from) shows the full rule.

### Delivery evidence: `state_vault_id`

Every target needs a state vault for its delivery evidence. `state_vault_id` records it; `opv target add` creates it, and `opv bootstrap` creates and records any that is missing. A target without one fails at load with `state_vault_missing`.

Each placement (a product the target delivers) keeps its evidence in one item of that vault, `opv · delivery · <product> · <target>`. `opv bootstrap` creates it and records its ID under the target, so no command ever looks a state item up by title:

```toml
[environments.prod.targets.shared]
state_vault_id = "vprd-state-shared"
delivery_items = { api = "dapi0000000000000000000001", p = "dp00000000000000000000001" }   # recorded by opv bootstrap
```

A placement without a recorded item gets no evidence (its sync says `opv bootstrap creates it`), and an entry for a product the target does not deliver fails at load. The item's evidence lines (store version and keyed fingerprint per name) are also the version ledger `plan` and `status` judge Fly and GitHub secrets by.

The state item holds the evidence key, the keyed fingerprints and, for Fly, digests, so its reader can test guesses against values. A state vault must therefore never be readable more widely than the values it covers. Several targets may share one state vault only when they deliver products from the same set of boundaries. Otherwise the configuration fails at load with `state_vault_wider_than_values`, naming the vault, the targets as `<env>/<target>` and a boundary one of them cannot read. One state vault per target is the safe choice.

### Account and deploy credentials

`account` is the one connection setting that sits on the environment, not on a target. `deploy_credentials` sits on a target, with no environment-level form and no fallback.

```toml
[environments.prod]
account = "ACCOUNTID0000000000000000"            # account ID (opv login --account records it)
boundaries.api = { vault_id = "vprd-api", item_id = "iprd-api" }

[environments.prod.targets.api]
fly.app = "example-portfolio-production"
deploy_credentials = "op://infra-prod/fly-deploy" # the deploy identity's item, by ID or name
state_vault_id = "vprd-state"
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
| environment-level `vault_id` / `item_id` | `boundaries.<product> = { vault_id = "…", item_id = "…" }`, recorded by `opv bootstrap` |
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

You don't need to lay out 1Password by hand. opv finds each declared key wherever its field is (a label spelled `openai api key`, a field in the wrong section or at the top level, a secret saved as text, a duplicate), so a layout difference never stops a command. When you run opv yourself (signed in to `op` as a person), it also tidies the item to this layout (every command that reads the item except `opv doctor` and `opv ready`, which never write; `opv tidy <env>` does it on its own): it creates missing sections and empty fields, conceals secrets saved as text, renames and moves fields, and sets duplicates aside. It deletes nothing: anything it displaces or replaces goes to a section named `opv · kept`, labelled with where it came from and the date. It prints one line saying what it changed:

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
- On Fly, config is not synced; deployment tooling reads it with `opv config export <env> --json`.
- On GitHub Actions, secrets become Actions **secrets** and config becomes Actions **variables**.

### Fly

```toml
[environments.prod.targets.shared]
fly.app  = "myapp-production"                  # required; passed as --app on every flyctl call
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"    # optional; defines target names; one product may use "{KEY}"
deploy_credentials = "op://infra-prod/fly-deploy"
state_vault_id = "vprd-state"
```

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
state_vault_id = "vprd-state"
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
kubernetes.config     = "env"                       # or "store"
state_vault_id = "vdev-state"
```

opv always passes `--context` and `--namespace`, so it never acts on whatever context your shell has selected. Each secret value becomes an immutable Kubernetes Secret named `opv-<name>-<random id>` (the id says nothing about the value), labelled `opv-managed=<env>`, and the Deployment's variable points at it with `secretKeyRef`. An unchanged value writes nothing (opv compares it with the bound Secret); a changed value is a new Secret. After a healthy rollout opv deletes the older Secrets that neither the Deployment nor any ReplicaSet references, and `--prune` removes a key that is no longer declared. The Secret name is the variable name lower-cased with `_` changed to `-`; that part is also the `opv-key` label value, so it must match `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` with at most 63 characters, and collisions are an error. A longer name is refused when the configuration loads (`renders Kubernetes name of N characters, which must match …`). A key whose variable name starts or ends with `_` (a Secret name starting or ending in `-`) is refused the same way, naming the key and its line.

### GitHub Actions: repository and environment secrets

Keep CI secrets in 1Password and let `opv sync ci` set them, instead of running `gh secret set` by hand.

```toml
[environments.ci.targets.actions]
github.repo        = "my-org/my-app"       # or repos = ["my-org/api", "my-org/web"]: the same values in each
github.environment = "staging"             # optional: that GitHub environment's secrets and variables
github.secret_name = "{KEY}"               # optional; default {KEY}, so workflows read secrets.FLY_API_TOKEN
products           = ["api"]               # optional: only these products' keys go here
state_vault_id     = "vci-state"
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
state_vault_id        = "vprd-state"
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
| `test_key_in_production` / `live_key_outside_production` | a `sk_test_`/`pk_test_`/`rk_test_` key where the environment's name or title says production, or a `sk_live_`/`rk_live_` key elsewhere |

- Each is a warning, never blocking: it names the environments and keys and ends with `opv open <key> --env <env>`.
- Config values may be the same everywhere; only secrets are compared across environments. Personal keys and empty values are never looked at.
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

- The value lives in each person's own item: in their own Private (or Employee, or Personal) vault, titled `<project> · <env> (personal)`. Set `personal_vault` and `personal_item` on the environment to use other titles. `opv bootstrap` creates your item with an empty field for each personal key; `opv ready` and `opv check` name the ones you still need to fill as yours.
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

The key (`prod-us`) stays the name in every command. Who can open an environment is 1Password's decision (share its boundary vaults with a group); `audience` only tells opv what to say to everyone else: someone who cannot open `prod-us` sees "not available to you (audience: devops)" in `opv ready`, as a note, not a problem to fix. `opv bootstrap` tags each item it creates `opv-env:<project>/<env>`.

## Writing the configuration with commands

`init` and `add` write the configuration for you, where it lives (manifest or file), keeping comments and order, validating the result like a hand-written one and refusing a concurrent change. `opv config edit` covers everything else.

### Start from an existing item: `opv init`

If the 1Password item already exists, `init` writes the configuration from it instead of writing one by hand. In a new project it saves it as a manifest in 1Password ([configuration in 1Password](#configuration-in-1password)); `--file` writes `./secrets.toml` instead:

```sh
opv init staging --vault myapp-staging --item myapp --product api
```

- Without `--vault` and `--item` it uses the boundary titles `<project>-<product>-<env>` and `<project> · <product> · <env> values` (the project name is `--project`, else the repository's, else the directory's), so the values item reads apart from the manifest `opv · <project>`. `opv init dev --product api` alone is enough for a new project.
- `--product <name>` names the product that unsectioned fields belong to; it is required when the item has unsectioned fields. Sectioned fields become products named by their section. An item with both shapes is an error naming both, and `init` never guesses. Product names describe the app's role (`web`, `api`, `worker`); `init` asks for one and does not suggest the project name.
- **One item is one boundary.** The item lives in one vault, so the products it declares share one boundary. One product records `boundaries.<product>`; several record `boundary = "core"` on each product and one `boundaries.core`.
- It looks the vault and the item up **by title**, once (exact, case-sensitive match), and writes their IDs into that boundary (`boundaries.<product>`, or `boundaries.<group>` when several products share it). No match, or more than one, is an error (exit 2) that lists the candidates by name and ID. This is the only title lookup in opv and only `init` can make it: every other command reads the item by vault ID and item ID.
- It reads the item once and writes **IDs, key names and kinds only**. A concealed field becomes `kind = "secret"`, a text field `kind = "config"`, each with `environments = ["<env>"]`. Values are never read into opv, written or printed. Rules, guidance, modes and other environments are left for you to add.
- A field whose label is not a valid key name (`^[A-Z][A-Z0-9_]*$`), a section whose label is not a valid product name, and a field of another type (URL, email, ...) are skipped with a note naming them. Nothing is renamed by `init` itself: rename the field in 1Password and run `init --force` again. A label given twice is declared once. When you run `init` yourself and the vault or item does not exist yet, it creates them (the vault only if your account allows it) and writes their IDs; under a service account or in CI it stops and names the next step.
- **It writes no target.** It writes boundaries and products only; `opv target add` is the one way to add a deployment target ([below](#add-a-target-opv-target-add)), and a run-only environment needs none.
- **Where it writes.** In a new project (no `secrets.toml` here or in a parent) it saves a manifest `opv · <project>` in the item's vault, tagged with the git remote (`--project <name>` names it; default: the repository's name). This is a 1Password write, so it needs a person signed in with their own session; under a service account or CI it refuses with `Next: opv login`. An existing manifest for the project is never overwritten: change it with `opv config edit`. With `--file`, or when a `secrets.toml` is already found, it writes `./secrets.toml` in the current directory instead (`--config` and `OPV_CONFIG` are refused; use `--add-env` to extend a file elsewhere). An existing file is refused (exit 2) unless `--force` is given; it never merges. The text is validated like a hand-written one and written atomically.
- It reads three things from 1Password: `op vault list`, `op item list` and one `op item get`.

It ends with what it wrote and the next command:

```text
$ opv init prod --vault myapp-prod --item app --product api --file
vault "myapp-prod" is vprd, item "app" is iprd
wrote /home/me/myapp/secrets.toml (product api): 1 secret, 1 config, skipped 0
add a deploy target: opv target add prod <name> --<provider options> (opv target add --help); a run-only environment needs none
Next: opv bootstrap
```

`opv bootstrap` is runnable as printed for every environment: it records any boundary still missing its IDs and adds each declared field, empty. Give an environment that deploys its target with `opv target add`.

### Add a target: `opv target add`

`opv target add <env> <name> --<provider options> [--products …] [--deploy-credentials …]` writes a named target through the configuration editor (comments kept, the result validated, a concurrent change refused); in the same confirmed step it creates the target's state vault and records `state_vault_id` ([adding a target](#adding-a-target)). It ends with `Next: opv access <env> --target <name>`. Target names match `^[a-z][a-z0-9-]*$` and are chosen by a person; opv generates no name. `opv target list [--env <env>] [--json]` shows the declared targets, and the provider's fields are in [targets by provider](#targets-by-provider).

```sh
opv target add prod shared --fly-app myapp-production
opv target add ci actions --github-repo my-org/my-app --products api
```

### Mint a target's deploy credential: `opv target credentials`

A target that deploys through `deploy_credentials` needs an item with just its least-privilege identity. `opv target credentials <env> --target <name> --create` mints that credential at the provider and stores it straight in a new 1Password item in the target's state vault, then records `deploy_credentials` for you. The token is never shown, copied or pasted: it stays in memory and reaches `op item create` on stdin only. The credential is named `opv-<project>-<env>-<target>`, asked to be valid for 90 days, and stored under the title `<project> · <target> · <env> deploy credentials`. One confirmation names all of that and the state vault; declining creates nothing. It refuses, before calling the provider, a target that already records `deploy_credentials` — rotation is a separate reviewed step — and a provider that cannot mint one here. A person's own interactive terminal and 1Password session are required. It writes the reference through the same configuration editor as `opv target add` (comments kept, the whole file validated, a concurrent change refused) and ends with `Next: opv doctor --env <env> --target <name>`. Without `--create` it prints whether `deploy_credentials` is recorded and whether the provider can mint one.

```sh
opv target credentials prod --target shared --create
opv target credentials prod --target shared
```

### Start from an existing `.env`: `opv init --from`

A project that already runs from a `.env` file gets into opv in one step, without a script:

```sh
chmod 600 .env
opv init dev --product api --from .env   # every key and its kind; nothing written anywhere
opv init dev --product api --from .env --apply  # create the vault and item, declare, import
```

- Every `KEY=value` line becomes a declared key for `dev`, in the product `--product` names, next to any field the item already has. A field the item already has keeps its kind and its value: a differing value in the file is reported, never written (`opv adopt dev --from .env --replace KEY --apply` takes it).
- The kind comes from the name only, never the value, and is secret when unsure: config for names like `*_ENABLED`, `*_MODEL`, `PORT`, `*_ORIGIN`, `*_CLIENT_ID`, `*_REDIRECT_URI`; secret for everything else, including `*_URL` (a database or webhook URL carries credentials) and any name with `SECRET`, `TOKEN`, `PASSWORD`, `PRIVATE` or `CREDENTIAL`. Change one with `--config-key KEY` or `--secret-key KEY` (repeatable); the plan shows every kind before anything is written.
- `--apply` imports the values the way `opv adopt --apply` does: one item edit, read back and checked. An empty value is declared but not imported, so `opv ready` lists it as missing. Values go to 1Password on stdin only, never in arguments, files or output.
- The file must be a private regular file (`chmod 600`) under 1 MiB; it is read as literal assignments, never executed, and left as it is. Delete it yourself once `opv run dev -- …` works.
- Multi-product items: an item already in the multi-product shape (sections per product) is refused by `--from`; declare there with `opv add`, then `opv adopt`. `--from` does not combine with `--add-env`.

### Add an environment: `opv init --add-env`

```sh
opv init staging --vault myapp-staging --item myapp --product api --add-env
```

Adds one `[environments.<env>]` to the existing configuration (found like every other command's: `--config`, `OPV_CONFIG`, the nearest `secrets.toml`, or the project's manifest in 1Password) instead of writing a new one, with `opv add`'s validation, atomic write and concurrency refusal. It looks up and reads the item the same way, writes the IDs into the product's `boundaries.<product>` table, and adds the environment to each declared key whose field the item has. It writes no target; add one with `opv target add`. It prints the keys left out because the item lacks them and the item's fields that are not declared, each with the `opv add` command that includes or declares one. It refuses an environment that already exists and never changes anything else. `--force` does not apply.

### Declare a key: `opv add`

```sh
opv add api/STRIPE_KEY --kind secret --env dev,prod --rule prefix=sk_ --guidance "Stripe › Developers › API keys"
opv add api/JWT_KEY --kind secret --rule base64_bytes=32 --immutable
opv add api/STRIPE_KEY --env staging                             # a declared key, one more environment
opv add web/DATABASE_URL --kind secret --from api/DATABASE_URL   # read another key's value
opv add shared/OPENAI_API_KEY --kind secret --env dev --personal # each developer's own value
```

- The name is always `PRODUCT/KEY`; `--kind secret|config` is required for a new key. `--env` (repeat it or separate with commas) defaults to every declared environment.
- `--rule NAME=VALUE` is repeatable and uses the [rules reference](#rules-reference) names. The value is read as a TOML value when the rule takes one (`base64_bytes=32`, `enum=["a","b"]`), else as text (`prefix=sk_`), else as a comma-separated list (`enum=debug,info`). A flag rule is given by name alone (`--rule https_url`). `--guidance` and `--immutable` set those fields; `--from PRODUCT/KEY` makes a [shared key](#shared-keys-from), `--personal` a [personal key](#personal-keys-each-developers-own-values), and `--allow-same-value` marks a repeat across environments as intended ([settings health](#settings-health-likely-wrong-values)). In `opv ui`, `+` fills in the same through a form.
- On a key that is already declared, `opv add` only adds the environments it lacks; a different `--kind`, or any rule, guidance, `--immutable`, `--from`, `--personal` or `--allow-same-value`, is refused (change those by hand, or with `opv config edit`). When nothing is missing it says so and changes nothing (exit 0).
- The configuration is edited where it lives, a `secrets.toml` or the project's [manifest in 1Password](#configuration-in-1password): its comments, blank lines and order are kept, and the new key goes after its product's last key. The edited text is validated like a hand-written one before anything is written, so a name that would collide on any target, an unknown rule, a bad rule value or an unknown environment is refused (exit 2) and nothing changes. The write is atomic (a file: a temporary file in the same directory, then a rename; a manifest: one item edit) and refused when someone changed the configuration since opv read it (run the command again).
- It reads no item and makes no target call (on a manifest it reads and edits only the manifest). It ends with `Next: opv item skeleton <env>`, which adds the empty field to that environment's item; type the value in 1Password, then run `opv check <env>`.

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
