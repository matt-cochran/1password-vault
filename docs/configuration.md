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
- It writes `./secrets.toml` in the current directory (`--config` is not accepted). If the file exists, it refuses (exit 2) unless `--force` is given; it never merges. If a parent directory already holds a `secrets.toml`, a note names it: the new file takes precedence for commands run from here down. The file is validated like a hand-written one and written atomically (a temporary file in the same directory, then a rename).
- It writes nothing to 1Password. It costs three 1Password requests (`op vault list`, `op item list`, `op item get`), at dev time only.

It ends with the path, the counts (`N secret, M config, skipped K`) and `Next step: opv plan <env>`.

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

The rule name is the stable identifier to match on; a reason may be added or reworded in a minor release. Each reason comes from a fixed set per rule, or is built only from the configuration (a configured prefix, mode or byte count). It never contains anything read from the value: no length, position, character, actual prefix or label.

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
| `enum` | `not one of the allowed values` |
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


Local-only setup, scoped check/doctor, product switching and WSL support in v0.4:
[Local development](local-development.md).
