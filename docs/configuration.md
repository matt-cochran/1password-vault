# Configuration

`secrets.toml` declares where each value lives in 1Password, which environments want it, and the rules it must pass. It holds IDs and rules, never values.

## Store layout

One vault per environment (`<name>-<env>`), one item in it, one section per product, one field per key. A concealed field is a secret; a text field is config. A key stored with the wrong field type is an error.

```text
vault portfolio-prod   item portfolio   section allumata   field OPENAI_API_KEY   (concealed)
                                                           field SIGNUP_POLICY    (text)
```

### `secrets.toml`

```toml
[profile]
kind = "fleet"                       # or "simple" (one app per environment, below)

[environments.staging]
vault_id = "vstg1234example"         # IDs, not names; [A-Za-z0-9][A-Za-z0-9._-]*
item_id  = "istg1234example"
fly.app  = "example-portfolio-staging"
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"   # naming template; defines the managed set
modes.allumata.payments = "test"     # input to prefix_by_mode rules

[environments.prod]
vault_id = "vprd1234example"
item_id  = "iprd1234example"
fly.app  = "example-portfolio-production"
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"
modes.allumata.payments = "off"

# Run-only environment: no fly section. `run`, `config export` and `item skeleton`
# work; `status`, `plan` and `sync` refuse it with a configuration error.
[environments.dev]
vault_id = "vdev1234example"
item_id  = "idev1234example"

[products.allumata.keys.OPENAI_API_KEY]
kind = "secret"                      # "secret" (concealed) or "config" (text)
environments = ["prod"]              # where the key is desired
rules = { prefix = "sk-", not_prefix = "sk-or-" }
guidance = "OpenAI platform / API keys"       # printed by status for a missing key

[products.allumata.keys.INTEGRATION_ENC_KEY]
kind = "secret"
environments = ["staging", "prod"]
immutable = true                     # staged only when absent on Fly; see --rotate
rules = { base64_bytes = 32 }

[products.allumata.keys.STRIPE_SECRET_KEY]
kind = "secret"
environments = ["staging", "prod"]
rules = { prefix_by_mode = { mode = "payments", values = { test = "sk_test_", live = "sk_live_" }, skip = ["off", "external"] } }

[products.allumata.keys.SIGNUP_POLICY]
kind = "config"
environments = ["dev", "staging", "prod"]
rules = { enum = ["open", "invite_only"] }
```

Product names match `^[a-z][a-z0-9_-]*$` and key names `^[A-Z][A-Z0-9_]*$`. A product name is upper-cased into the template (`allumata` becomes `ALLUMATA`), so `OPENAI_API_KEY` is staged on Fly as `FLEET__ALLUMATA__OPENAI_API_KEY`. The template must contain `{PRODUCT}` and `{KEY}`.

### Simple profile (one app per environment)

For one app per environment with no products, use `kind = "simple"` and a flat `[keys]` map. Each key is an unsectioned field of the environment's item (a field outside any section) and is staged on Fly under its own name: `[keys.JWT_KEY]` reads field `JWT_KEY` and stages `JWT_KEY`. There is no `[products]` table and no `fly.secret_name`; either one under the simple profile is a configuration error.

```text
vault myapp-prod   item myapp   field DATABASE_URL   (concealed)
                                field JWT_KEY        (concealed)
                                field LOG_LEVEL      (text)
```

```toml
[profile]
kind = "simple"

[environments.prod]
vault_id = "vprd1234example"
item_id  = "iprd1234example"
fly.app  = "myapp-production"        # one app per environment; two environments may not share it
modes.payments = "live"              # input to prefix_by_mode rules; flat, no product level

[keys.DATABASE_URL]
kind = "secret"
environments = ["prod"]

[keys.JWT_KEY]
kind = "secret"
environments = ["prod"]
immutable = true
rules = { base64_bytes = 32 }

[keys.LOG_LEVEL]
kind = "config"
environments = ["prod"]
rules = { enum = ["debug", "info", "warn"] }
```

Kinds, rules, guidance, modes and `immutable` work as in the fleet profile. Key names match `^[A-Z][A-Z0-9_]*$`. The managed set is exactly the declared keys: `--prune` unsets only a declared key that is not desired in the environment, and any other name on the Fly app is reported as unmanaged and never touched. Every command reads the item once, by vault ID and item ID.

Under the simple profile, commands name a key by its name alone: `status` and `plan` print no PRODUCT column, their `--json` rows carry `"product": null`, `--rotate` and `--prune-immutable` take `KEY`, `config export` prints a flat `{"KEY": "value"}` object, and `run <ENV> -- <cmd>` takes no `--product` and passes every key desired in the environment.

One caveat for `run` under the simple profile: it hands `op run` references of the form `op://<vault>/<item>/KEY`, and `op` matches a field with that label in *any* section. Keep simple-profile keys only as unsectioned fields: a sectioned field with the same label can be picked up by `run` while `status` reports the key missing, and having both can make `op` report the reference as ambiguous.

Changed in v0.2 for fleet files: `run` without `--product` is now an opv configuration error (still exit 2) rather than a usage error, and a bad `profile.kind` names both supported profiles.

### Start from an existing item: `opv init`

If the 1Password item already exists, `init` writes a starter `secrets.toml` from it instead of writing one by hand:

```sh
opv init staging --vault myapp-staging --item myapp --fly-app myapp-staging [--profile simple|fleet] [--force]
```

- It looks the vault and the item up **by title**, once (exact, case-sensitive match), and writes their IDs. No match, or more than one, is an error (exit 2) that lists the candidates by name and ID. This is the only title lookup in opv and only `init` can make it: every other command reads the item by vault ID and item ID.
- It reads the item once and writes **IDs, key names and kinds only**. A concealed field becomes `kind = "secret"`, a text field `kind = "config"`, each with `environments = ["<env>"]`. Values are never read into opv, written or printed. Rules, guidance, modes and other environments are left for you to add.
- The profile follows the item's shape: only unsectioned fields gives a simple file, only sectioned fields gives a fleet file (one product per section, `fly.secret_name = "FLEET__{PRODUCT}__{KEY}"`). An item with both is an error naming both shapes; `--profile` then decides, and the fields of the other shape are ignored with a note.
- A field whose label is not a valid key name (`^[A-Z][A-Z0-9_]*$`), a section whose label is not a valid product name, and a field of another type (URL, email, ...) are skipped with a note naming them. Nothing is renamed: rename the field in 1Password and run `init --force` again. When `status` and `sync` would reject such a field (a wrong type, a field in a section without a label, a sectioned field without a label), the note says so. A label given twice where opv reads the item is an error and nothing is written.
- `--fly-app` is optional; omitting it creates a run-only environment. flyctl is not called.
- It writes `./secrets.toml` in the current directory (`--config` and `OPV_CONFIG` are not accepted). If the file exists, it refuses (exit 2) unless `--force` is given; it never merges. If a parent directory already holds a `secrets.toml`, a note names it: the new file takes precedence for commands run from here down. The file is validated like a hand-written one and written atomically (a temporary file in the same directory, then a rename).
- It writes nothing to 1Password. It costs three 1Password requests (`op vault list`, `op item list`, `op item get`), at dev time only.

It ends with the path, the counts (`N secret, M config, skipped K`) and `Next step: opv plan <env>`.

### Account and deploy credentials

Two optional settings per environment:

```toml
[environments.prod]
vault_id = "vprd1234example"
item_id  = "iprd1234example"
account  = "mycompany.1password.com"            # sign-in address, email or account ID
deploy_credentials = "op://infra-prod/fly-deploy" # the deploy identity's item, by ID or name
fly.app  = "example-portfolio-production"
```

- `account`: every `op` call for this environment uses this 1Password account, and `opv login prod` signs in to it. Set it when your environments live in different accounts. It must look like a sign-in address, an email or an account ID (no spaces, no leading `-`); a bad value is a configuration error pointing at its line and column. Under a service-account token in CI the token decides the account.
- `deploy_credentials`: an `op://<vault>/<item>` reference to a whole item (never a field) holding only this environment's least-privilege deploy identity. `status`, `plan`, `sync` and `doctor --env` read it and sign the target CLI in for that run only. The fields are fixed per provider: Fly `FLY_API_TOKEN` (concealed); Azure `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` (text) and `AZURE_CLIENT_SECRET` (concealed). Kubernetes takes none (`kubectl` uses your kubeconfig): `deploy_credentials` there, or on an environment without a target, is a configuration error. Platform support and how each value is handled: [usage](usage.md#sign-in-accounts-and-deploy-credentials).

Give the deploy identity only what a sync needs: a Fly deploy token for that one app, or an Azure service principal with Key Vault Secrets Officer on that vault and Contributor on that Container App. Break-glass (owner or admin) credentials are for people and are never referenced by `deploy_credentials`.

## Targets

Each environment names at most one target: `fly` (above), `azure` or `kubernetes`. Two target sections in one environment is a configuration error, and an environment with none is run-only. Two environments may not share one target (the same Fly app, Key Vault and Container App, or context, namespace and Deployment).

How the values travel depends on the field kind:

- A **secret** (concealed field) is stored in the target's secret store and bound to the app as a reference to one exact version.
- **Config** (text field) is set as a plain environment variable on the app. Set `config = "store"` to keep config in the store too. There is no way to put a secret in a plain variable.
- On Fly, config is not synced, as before; read it with `config export`.

### Azure: Key Vault + Container Apps

```toml
[environments.prod.azure]
subscription   = "00000000-0000-0000-0000-000000000000"   # id or name; required
key_vault      = "kv-myapp-prod"
resource_group = "rg-myapp"
container_app  = "ca-myapp"
container      = "api"                       # only if the app has more than one container
identity       = "system"                    # or the resource id of a user-assigned identity
env_name       = "FLEET__{PRODUCT}__{KEY}"   # fleet profile only
config         = "env"                       # default; "store" keeps config in Key Vault too
```

| Field | Meaning |
|---|---|
| `subscription` | Required. opv passes it on every `az` call and never uses your default subscription. |
| `key_vault` | The vault that holds the secrets. |
| `resource_group` | The resource group of the Container App. <!-- verify: also used for the vault? --> |
| `container_app` | The app that receives the variables. |
| `container` | Optional. Required only when the app runs more than one container; opv then lists the names. |
| `identity` | `system`, or the resource id of the user-assigned identity the app uses to read Key Vault. |
| `env_name` | Template for the variable name; must contain `{PRODUCT}` and `{KEY}`. It defines the managed set. Not allowed under the simple profile, where the field name is the variable name. |
| `config` | `env` (default) or `store`. |

Names and limits are checked when the file loads, before any call:

- The Key Vault name is the variable name with `_` changed to `-`, and must match `^[0-9A-Za-z-]{1,127}$`. `FLEET__ALLUMATA__OPENAI_API_KEY` is stored as `FLEET--ALLUMATA--OPENAI-API-KEY`.
- Key Vault names ignore case, so two keys that map to the same name, even in different case, are an error naming both.
- A Key Vault value may be at most 25 KB. <!-- verify: exact limit and wording of the failure -->
- Every identifier is checked like `fly.app` (no leading `-`, no shell metacharacters).

opv tags every secret it writes `opv-managed=<env>` and only ever deletes tagged secrets. `opv explain <KEY>` shows the Key Vault name and the variable it feeds.

### Kubernetes: Secrets + Deployment

```toml
[environments.dev.kubernetes]
context    = "kind-opv"                  # required; passed to every kubectl call
namespace  = "myapp"                     # required
deployment = "api"                       # required
container  = "api"                       # optional when the pod has one container
env_name   = "FLEET__{PRODUCT}__{KEY}"   # fleet profile only
config     = "env"                       # or "store"
```

opv always passes `--context` and `--namespace`, so it never acts on whatever context your shell has selected. Each secret value becomes an immutable Kubernetes Secret named `opv-<name>-<random id>` (the id says nothing about the value), labelled `opv-managed=<env>`, and the Deployment's variable points at it with `secretKeyRef`. An unchanged value writes nothing (opv compares it with the bound Secret); a changed value is a new Secret. After a healthy rollout opv deletes the older Secrets that neither the Deployment nor any ReplicaSet references, and `--prune` removes a key that is no longer declared. The Secret name is the variable name lower-cased with `_` changed to `-`, so it must be a valid DNS-1123 name (at most 253 characters with the suffix), and collisions are an error. A key whose variable name starts or ends with `_` (a Secret name starting or ending in `-`) is refused when the configuration loads, naming the key and its line. <!-- verify: name length/limit message -->

### Secrets in a named store: `[stores.<name>]` and `secrets_in`

A runtime can keep its secrets in a store from another provider. Declare the store once and point the runtime at it with one line; the commands do not change. In 0.5.0 the one supported pair is **Azure Key Vault → Kubernetes Deployment**, through the [External Secrets Operator](https://external-secrets.io) (ESO).

```toml
[stores.prod-vault]                        # any name: lower-case letters, digits and -
azure_key_vault = "kv-myapp-prod"          # the store kind is the key; its value is the vault
subscription    = "00000000-0000-0000-0000-000000000000"   # required
# secret_store  = "prod-vault"             # the in-cluster ClusterSecretStore; default: the store name

[environments.prod.kubernetes]
context    = "aks-prod"
namespace  = "api"
deployment = "api"
secrets_in = "prod-vault"                  # optional; without it, opv's own Kubernetes Secrets
```

| Field | Meaning |
|---|---|
| `azure_key_vault` | The vault that holds the values (3 to 24 letters, digits and `-`). |
| `subscription` | Required subscription id. opv passes it on every `az` call. |
| `secret_store` | Optional. The `ClusterSecretStore` that reads this vault in the cluster. Defaults to the store's name. |
| `secrets_in` | On a runtime section: the store its secrets live in. |

- **What opv does.** Each secret is written to Key Vault as a new version (as for an Azure target). With `--deploy`, opv creates an `ExternalSecret` named `opv-<name>-<first 10 characters of the version id>` that fetches exactly that version once (`refreshInterval: "0"`), waits until it is `Ready` (its Secret exists), and only then points the Deployment's variable at that Secret. The version id is random, so no name or label says anything about the value.
- **Names.** Key Vault rules apply (`_` becomes `-`, names ignore case), and the name must also fit a Kubernetes name of at most 63 characters, starting and ending with a letter or digit. Two environments that keep the same Key Vault name in one store are an error naming both, because each would overwrite and prune the other's value.
- **Config.** `config = "env"` (default) keeps config as plain variables on the Deployment; `config = "store"` routes it through Key Vault and an ExternalSecret like a secret.
- **Unsupported pairs.** `secrets_in` on `fly` or `azure`, or a store name that is not declared, is a configuration error that lists the defined stores or the supported pairs, at its line.
- **Prerequisites.** ESO serving `external-secrets.io/v1` (tested with 2.11) and a `ClusterSecretStore` that can read the vault. `opv doctor` checks both; [agent-setup.md](agent-setup.md#azure-or-kubernetes-instead-of-fly) shows how to create the store.

`opv explain <KEY>` prints the whole chain, for example `DB_URL → Key Vault kv-myapp-prod (pinned version) → ExternalSecret opv-db-url-<version> → Secret of the same name → env DB_URL`.

### Guarding an environment: `confirm_env`

```toml
[environments.prod]
vault_id = "vprd1234example"
item_id  = "iprd1234example"
confirm_env = true
```

With `confirm_env = true`, a command that changes the target must be given the environment name again: `opv sync prod --deploy --confirm prod`. Without it, opv refuses (exit 6) and prints the exact command to re-run. Reading commands (`status`, `plan`, `check`) are unaffected. <!-- verify: which commands require --confirm: sync only, or item skeleton too? -->

## Rules reference

Rules go in a key's `rules = { ... }` table. A failure names the key, the rule and a reason, never the value.

Always on, for every key (after a `pem_private_key` transform, see below): `nonempty`; `single_line` (no `\n`, `\r` or NUL); `no_surrounding_space`; `max_len` (59,000 bytes).

| Rule | Meaning |
|---|---|
| `prefix = "sk-"` | value starts with the prefix |
| `not_prefix = "sk-or-"` or a list | value starts with none of them |
| `regex = "..."` | the whole value matches (full match) |
| `ensure_prefix = "sk-"` | accepts the value with or without the prefix and stages it with exactly one `sk-`; a value that is only the prefix fails |
| `pattern = "..."` | only with `ensure_prefix`: the text after the prefix fully matches (full match) |
| `enum = ["a", "b"]` | value is one of the listed strings |
| `base64_bytes = N` | valid base64 that decodes to N bytes |
| `hex_bytes = N` | valid hex that decodes to N bytes |
| `email_list = true` | comma-separated list of email addresses |
| `https_url = true` | an `https://` URL |
| `prefix_by_mode = { mode, values, skip }` | prefix chosen by the environment's declared mode for the product (`modes.<product>.<mode>`); a mode listed in `skip` disables the check and the key is not required |
| `refuse_in = ["prod"]` | the key must not exist in those environments: a non-empty field there is a blocking failure even though the key is not otherwise expected. The environments must be defined and not also appear in `environments` |
| `transform = "pem_private_key"` | accepts one PEM private key block (label ending `PRIVATE KEY`, not encrypted, matching BEGIN/END, no headers, base64 of a DER SEQUENCE) pasted multi-line into a concealed field or already on one line, and stages it as one line `-----BEGIN <label>-----<base64>-----END <label>-----`. It runs before the always-on rules, which then see the one-line value. Only whitespace is removed, so RFC 7468 parsers that skip body whitespace (Rust `pem` 3.x) read the same key |

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
| `pattern` | `text after the prefix does not match the pattern` |
| `transform` (`pem_private_key`) | `no BEGIN/END markers`, `BEGIN/END labels differ`, `not a private key`, `encrypted key`, `more than one PEM block`, `body is not base64`, `not a key structure` |
| `transform` (other name) | `unknown transform` |
| Fly import rules | `not a valid Fly secret name`, `contains a line break`, `a # follows an odd number of double quotes`, `too long for one Fly import line`, `not valid UTF-8`, `name occurs twice in one import` |

`pem_private_key` refuses an encrypted key, whether it has a `Proc-Type` header or the PKCS#8 `ENCRYPTED PRIVATE KEY` label.
