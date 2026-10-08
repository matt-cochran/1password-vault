# opv

`opv` is a Rust CLI that syncs secrets from 1Password into runtime targets, with Fly.io as the first target. 1Password owns the values, Fly consumes them, and opv only connects the two: it keeps no state, runs no server, does no encryption of its own, and has no command that prints a secret. Configuration lives in a committed `secrets.toml` that holds `op://`-style IDs and rules, never values.

The repository is named `1password-vault` for historical reasons; the tool is `opv`. The design document is [OVERVIEW.md](OVERVIEW.md).

## Install

### Install script (Linux and macOS)

```sh
curl -fsSL https://raw.githubusercontent.com/matt-cochran/1password-vault/main/install.sh | sh
```

`install.sh` installs or updates `opv` into `~/.local/bin` without `sudo` and without
npm, Homebrew or Rust. It picks the release asset for your OS and CPU (including
WSL and macOS under Rosetta), verifies the download against the release's
`SHA256SUMS`, and, when `gh` is available, runs
`gh attestation verify <file> --repo matt-cochran/1password-vault`. An unknown
platform, a missing checksum tool or a checksum mismatch fails closed.

```sh
sh install.sh --version v0.1.2   # install exactly this release (default: latest)
sh install.sh --dir /usr/local/bin
sh install.sh --check            # report what would happen, change nothing
```

When `opv` is already present in the target directory, the script compares
`opv --version` with the target version: it prints `opv <old> → <new>` when it
replaces the binary and `opv <version> is already installed` when it is already
current. `--check` prints the same intent without downloading or writing
anything. The binary is downloaded to a temporary file in the target directory
and moved into place only after verification, so an interrupted run never
leaves a broken `opv`. If the directory is not on `PATH`, the script prints the
`export PATH=...` line to add.

`OPV_INSTALL_BASE_URL` overrides the release base URL for the test harness only.

### Release binaries

Download the asset for your platform from the [latest release](https://github.com/matt-cochran/1password-vault/releases/latest), together with `SHA256SUMS`, and [verify it](#verify-a-download).

| Platform | Asset |
|---|---|
| Linux x86_64 (musl) | `opv-x86_64-unknown-linux-musl` (also published as `opv`, an alias of this file) |
| Linux aarch64 (musl) | `opv-aarch64-unknown-linux-musl` |
| macOS Intel | `opv-x86_64-apple-darwin` |
| macOS Apple Silicon | `opv-aarch64-apple-darwin` |
| Windows x86_64 | `opv-x86_64-pc-windows-msvc.exe` |
| Windows ARM64 | `opv-aarch64-pc-windows-msvc.exe` |

Linux and macOS:

```sh
chmod +x opv-aarch64-apple-darwin
# macOS only: remove the quarantine flag set on downloaded files
xattr -d com.apple.quarantine opv-aarch64-apple-darwin
mv opv-aarch64-apple-darwin /usr/local/bin/opv
```

Windows: rename the `.exe` to `opv.exe` and put it on your `PATH`.

### From source

```sh
cargo install --git https://github.com/matt-cochran/1password-vault --locked
```

The minimum supported Rust version is 1.88.

### npm

```sh
npm i -g @matthew-cochran/opv
npx @matthew-cochran/opv --version
```

The npm package is `@matthew-cochran/opv` (npm does not allow the unscoped name `opv`), published from v0.2.1; the installed command is `opv`. It installs a tiny Node shim and, through per-platform optional dependencies, npm picks the right prebuilt binary for your OS and CPU automatically with no install scripts.

Homebrew and crates.io packages arrive in v0.1.1.

## Verify a download

Download the release asset you want and the `SHA256SUMS` file. Then, from the directory containing both, verify the checksum and the build provenance. Replace the asset name with the one you downloaded.

Linux:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

macOS (the `--ignore-missing` flag does not exist in `shasum`, so check the one line):

```sh
grep opv-aarch64-apple-darwin SHA256SUMS | shasum -a 256 -c
```

Windows PowerShell (compare the output with the matching line in `SHA256SUMS`):

```powershell
Get-FileHash .\opv-x86_64-pc-windows-msvc.exe -Algorithm SHA256
```

Provenance, on any platform with the GitHub CLI:

```sh
gh attestation verify opv-x86_64-unknown-linux-musl --repo matt-cochran/1password-vault
```

## Prerequisites

- The 1Password CLI `op`, tested with 2.40.0. The Fly CLI `flyctl`, tested with 0.4.112. `opv doctor` warns (exit code unchanged) when a version differs.
- For CI: a read-only 1Password service account (`OP_SERVICE_ACCOUNT_TOKEN`) with access to the environment's vault, and `FLY_API_TOKEN`.
- Locally: the 1Password desktop app integration or `op signin`, and `fly auth login`.
- `item skeleton` is the only command that writes to 1Password; it needs a write-capable identity.

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
# work; `status` and the `fly` commands refuse it with a configuration error.
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
- `--fly-app` is required; `flyctl` is not called.
- It writes `./secrets.toml` in the current directory (`--config` is not accepted). If the file exists, it refuses (exit 2) unless `--force` is given; it never merges. If a parent directory already holds a `secrets.toml`, a note names it: the new file takes precedence for commands run from here down. The file is validated like a hand-written one and written atomically (a temporary file in the same directory, then a rename).
- It writes nothing to 1Password. It costs three 1Password requests (`op vault list`, `op item list`, `op item get`), at dev time only.

It ends with the path, the counts (`N secret, M config, skipped K`) and `Next step: opv plan <env>`.

## Workflow

Global option: `--config <PATH>`. Without it, opv looks for `secrets.toml` in the current directory and then each parent directory up to the filesystem root, uses the first one found (files are never merged), and prints `using <absolute path>` on stderr before the command runs. With `--config`, the path is used exactly as given and no search is done. `<ENV>` is an environment name from the file.

```sh
opv doctor                          # config, op and sign-in, flyctl and sign-in
opv init staging --vault myapp-staging --item myapp --fly-app myapp-staging   # starter secrets.toml
opv item skeleton staging           # add every missing declared field, empty; the only 1Password write
opv status staging                  # one row per product and key; exit 8 if any blocks
opv status staging --json           # the same state as one machine-readable JSON document
opv plan staging                    # what a sync would stage, hold and prune; exit 8 if any blocks
opv plan staging --json             # the same plan as one machine-readable JSON document
opv sync staging [--deploy] [--prune] [--rotate PRODUCT/KEY] [--prune-immutable PRODUCT/KEY]
opv config export staging --json    # config-kind values as JSON
opv explain allumata/OPENAI_API_KEY --env prod   # what opv knows about one key, from the config alone
opv run dev --product allumata -- cargo run
opv run prod -- ./server            # simple profile: no --product
```

`opv fly plan` and `opv fly sync` remain as deprecated aliases for one minor release: they print a warning on stderr and behave exactly like `opv plan` and `opv sync`.

1. `item skeleton` creates the empty fields in the 1Password item. Fill them in 1Password.
2. `status` shows what is missing, of the wrong kind, or failing a rule. It prints names and the declared `guidance`, never values.
3. `plan` shows the same rows plus the target side. It changes nothing.
4. `sync` stages the values on Fly (through `flyctl secrets import --stage`, values on stdin). It refuses (exit 6) and stages nothing if any key is missing, of the wrong kind or failing a rule.
5. `--rotate PRODUCT/KEY` (repeatable) stages an immutable key that is already on Fly. `--prune-immutable PRODUCT/KEY` (repeatable) lets `--prune` unset a named immutable key.
6. `config export <ENV> --json` prints the config-kind values for deployment tooling. `--json` is required and is the only format.
7. `run <ENV> --product <p> -- <cmd>` runs a command with the product's keys in its environment under plain names (`OPENAI_API_KEY`, not the Fly name), through `op run`. It writes no `.env` file.

### Next step

`doctor` ends with one `Next step` line. When a check fails it names the first failing check and the safe command that addresses it, the same command the failure prints under it:

```text
Next step (op auth): sign in: eval $(op signin)
```

An invalid configuration always gets ``Next step (config): fix secrets.toml (see the config line above) and re-run `opv doctor` ``; another failure with no command of its own gets ``fix the failure reported above and re-run `opv doctor` ``. When every check passes the line is `Next step: nothing pending`. The line is text, never a prompt.

### Explain a key

```sh
opv explain <product>/<key> [--env <environment>]
```

`explain` prints what the configuration declares for one key in one environment: the `op://` reference, the field kind, the Fly name, the declared rules, `immutable` and `guidance`, plus an `op item get <item_id> --vault <vault_id>` command you can run in your own terminal to look at the item. That command never contains `--reveal`.

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

Under the simple profile the form is `opv explain <KEY> [--env <environment>]`: the reference is the unsectioned field `op://<vault_id>/<item_id>/<KEY>` and the Fly name is the key. The fleet form `<product>/<key>` is a configuration error under the simple profile, and a bare `<KEY>` is one under the fleet profile.

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
[Failure reasons](#failure-reasons)); `target` is `present`, `absent` or
`would_change` for a secret and `null` for a config key; `action` is `would_stage`,
`would_prune`, `held` or `null`. The document is meant for the scheduled drift check.

### Change detection

Fly digests cannot be computed locally, so opv cannot tell in advance whether a value changed. `sync` reads Fly's secret metadata, stages, reads it again and compares the digests. `plan` therefore shows a desired key that is already on Fly as "potentially changed". An immutable key already on Fly is "held" and is not staged unless you pass `--rotate` for it.

Staging uses stage semantics, so it coexists with other tools that stage secrets on the same Fly app. A deploy happens only with `--deploy`, and only when a staged digest changed, a prune happened, or a managed name is still pending on Fly (status Staged or Partial) from an earlier run. Deploying an app that has no machines exits 5.

### Pruning

Nothing is deleted by default. `--prune` unsets only names that the template produces for declared keys that are not desired in this environment. Names outside that set are never touched. Immutable keys are never pruned unless named with `--prune-immutable`; they are reported as "held (immutable), not pruned". A name staged by the same run is never pruned. A key you delete from `secrets.toml` is no longer declared, so it is neither reported nor pruned: unset it manually with `flyctl secrets unset`.

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
| `transform = "signoz_ingestion_header"` | **deprecated**: kept for one release as an alias for `ensure_prefix = "signoz-ingestion-key="` with `pattern = "[A-Za-z0-9._~+/-]+={0,2}"`; loading a configuration that uses it prints a deprecation warning naming the product and key. Use the generic rules instead |
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
| `transform` (deprecated SigNoz alias) | the `ensure_prefix` and `pattern` reasons; the rule name stays `transform` |
| `transform` (other name) | `unknown transform` |
| Fly import rules | `not a valid Fly secret name`, `contains a line break`, `a # follows an odd number of double quotes`, `too long for one Fly import line`, `not valid UTF-8`, `name occurs twice in one import` |

`pem_private_key` refuses an encrypted key, whether it has a `Proc-Type` header or the PKCS#8 `ENCRYPTED PRIVATE KEY` label.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 2 | configuration error or command-line usage error |
| 3 | dependency: `op` or `flyctl` missing or unusable, or output cannot be written |
| 4 | 1Password source error (including an `op` timeout) |
| 5 | Fly target error (including a `flyctl` timeout, and deploy on an app with no machines) |
| 6 | policy refusal: `fly sync` refused (missing, wrong kind, failing rule), or `config export` refused |
| 7 | authentication |
| 8 | findings: `status` or `plan` found blocking keys |
| 101 | internal panic (Rust default) |

`run` exits with the child's own exit code, which can equal one of the codes above; opv's own errors print `opv: ...` on stderr. A closed stdout (`status | head`) does not change the result.

Diagnose and guide: after any failed `op` call (`op item get`, `op item edit`) opv runs `op whoami`, and when that fails (with no service-account or Connect credential set, outside CI) `op account list`. These diagnosis calls are free under 1Password rate limits, have their own 15 s limit, and no item is read a second time.

- Not signed in, with no non-interactive credential set (no session, an expired `OP_SESSION_*`, a locked desktop app), is authentication (7), with the sign-in command for your shell: `eval $(op signin)` for bash and zsh, `eval (op signin)` for fish, `Invoke-Expression $(op signin)` for PowerShell (the default on Windows), or "sign in with `op signin` (see `op signin --help` for your shell)" for any other shell, plus "if you are signed in, check network access to 1Password". Under CI (`CI` or `GITHUB_ACTIONS` truthy, so `CI=false` does not count) it says "set OP_SERVICE_ACCOUNT_TOKEN" and gives no interactive command.
- No account on the machine (fresh WSL or Linux) gives the `op account add` command first.
- With `OP_SERVICE_ACCOUNT_TOKEN` or Connect (`OP_CONNECT_HOST` / `OP_CONNECT_TOKEN`) set, a failing `op whoami` is ambiguous (rejected token or no network), so it stays a source error (4): "1Password rejected the service-account (or Connect) token or could not be reached: check the token in <variable> and network access". No interactive command is printed.
- Signed in but the read still failed is a source error (4) naming the vault and item IDs and the identity type (USER or SERVICE_ACCOUNT, never the identity) and saying to grant that identity access to the vault.
- A failed `flyctl` call with `FLY_API_TOKEN` or `FLY_ACCESS_TOKEN` set is a Fly target error (5): "flyctl failed for app <app>: check that the token in <variable> can access it, that the app exists, and, for a deploy, that it has at least one machine". `flyctl auth whoami` is not consulted there, because app-scoped deploy tokens fail it. With no Fly token set, opv runs `flyctl auth whoami` (exit status only; its output names the account and is never shown): logged out is authentication (7), "not logged in to Fly", with `flyctl auth login`, or "set FLY_API_TOKEN" under CI; logged in is a target error (5) with the same app wording.

`doctor` uses the same checks, and a missing `op` or `flyctl` names the install command for your OS. Child stderr is suppressed on purpose, because it could echo a value; a re-run hint ("... to see why") remains only when `op whoami` or `flyctl auth whoami` cannot run or times out. An `op` timeout and `opv run` (which passes the child's exit code through) are not diagnosed.

A clean `status` ends with a summary line, for example `49 saved, 13 not yet on Fly (staged by the next fly sync), 0 findings`.

## Security model and limits

- Values travel only on stdin or in the environment of a child process. They never appear in argv, files, logs, errors, `Debug` or `Display` output.
- The stderr of `op` and `flyctl` is suppressed so it cannot leak a value.
- `serde` can leave transient scratch copies of values in memory while parsing `op` output; opv wraps values in redacting, zeroizing types but cannot control those copies.
- `config export` prints config-kind values by design. It refuses if a config key is stored concealed or a secret key as text.
- `run` hands secret values to the child process through `op run`; the child can read them.
- No multiline values. Two profiles: `fleet` (products, sections, a naming template) and `simple` (one app per environment, unsectioned fields, Fly name = key name). `--json` on `status` and `plan` prints names, states and counts only; `config export --json` prints config-kind values by design.
- In CI a release reads each item once, by vault ID and item ID.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

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
          base=https://github.com/matt-cochran/1password-vault/releases/download/v0.1.0
          curl -fsSLO "$base/opv-x86_64-unknown-linux-musl"
          curl -fsSLO "$base/SHA256SUMS"
          sha256sum -c SHA256SUMS --ignore-missing
          install -m 0755 opv-x86_64-unknown-linux-musl /usr/local/bin/opv
      - name: Stage secrets on Fly
        run: opv sync prod
```

This stages without deploying; a later `fly deploy` (or `opv sync prod --deploy`) applies everything staged by every tool. Install `op` and `flyctl` on the runner first (for example with the official 1Password and Fly GitHub Actions).

Rate limits: a cold whole-item read costs about 2 requests, so a fleet sync costs a handful per environment. 1Password Families service accounts allow 1,000 requests per hour per token and 1,000 per day for the account. `OP_CACHE=false` makes the cost the worst case, since `op` caches by default on Linux and macOS.

## Prior art

[significa/1password-secrets](https://github.com/significa/1password-secrets) (Python, MIT) solves a similar problem. opv borrows its workflow (read the item, compute a diff, stage on Fly, deploy) and none of its code. It deliberately rejects:

| Their behavior | opv instead |
|---|---|
| Debug log prints the parsed secrets | values are never logged |
| `op item create/edit` with values as arguments | values only on stdin |
| Secrets written to a temp file for the editor | no plaintext files |
| `local pull` writes `./.env` | `run` delegates to `op run` |
| Deletes every Fly secret not in the note, after a prompt | explicit flags, managed set only, no prompts |
| Writes "last imported at" back to 1Password | read-only against 1Password |
| Finds items by title search | one read by vault ID and item ID |
| One `.env` blob per app | one typed field per key |

## License

MIT, see [LICENSE](LICENSE).
