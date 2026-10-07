# opv

`opv` is a Rust CLI that syncs secrets from 1Password into runtime targets, with Fly.io as the first target. 1Password owns the values, Fly consumes them, and opv only connects the two: it keeps no state, runs no server, does no encryption of its own, and has no command that prints a secret. Configuration lives in a committed `secrets.toml` that holds `op://`-style IDs and rules, never values.

The repository is named `1password-vault` for historical reasons; the tool is `opv`. The design document is [OVERVIEW.md](OVERVIEW.md).

## Install

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
npm i -g opv
npx opv --version
```

The npm package is planned for v0.2.0 (not yet published); until then, use a GitHub release binary. It installs a tiny Node shim and, through per-platform optional dependencies, npm picks the right prebuilt binary for your OS and CPU automatically with no install scripts.

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
kind = "fleet"                       # the only profile in v0.1

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

## Workflow

Global option: `--config <PATH>` (default `secrets.toml`). `<ENV>` is an environment name from the file.

```sh
opv doctor                          # config, op and sign-in, flyctl and sign-in
opv item skeleton staging           # add every missing declared field, empty; the only 1Password write
opv status staging                  # one row per product and key; exit 8 if any blocks
opv fly plan staging                # what a sync would stage, hold and prune; exit 8 if any blocks
opv fly sync staging [--deploy] [--prune] [--rotate PRODUCT/KEY] [--prune-immutable PRODUCT/KEY]
opv config export staging --json    # config-kind values as JSON
opv run dev --product allumata -- cargo run
```

1. `item skeleton` creates the empty fields in the 1Password item. Fill them in 1Password.
2. `status` shows what is missing, of the wrong kind, or failing a rule. It prints names and the declared `guidance`, never values.
3. `fly plan` shows the same rows plus the Fly side. It changes nothing.
4. `fly sync` stages the values on Fly (through `flyctl secrets import --stage`, values on stdin). It refuses (exit 6) and stages nothing if any key is missing, of the wrong kind or failing a rule.
5. `--rotate PRODUCT/KEY` (repeatable) stages an immutable key that is already on Fly. `--prune-immutable PRODUCT/KEY` (repeatable) lets `--prune` unset a named immutable key.
6. `config export <ENV> --json` prints the config-kind values for deployment tooling. `--json` is required and is the only format.
7. `run <ENV> --product <p> -- <cmd>` runs a command with the product's keys in its environment under plain names (`OPENAI_API_KEY`, not the Fly name), through `op run`. It writes no `.env` file.

### Change detection

Fly digests cannot be computed locally, so opv cannot tell in advance whether a value changed. `fly sync` reads Fly's secret metadata, stages, reads it again and compares the digests. `fly plan` therefore shows a desired key that is already on Fly as "potentially changed". An immutable key already on Fly is "held" and is not staged unless you pass `--rotate` for it.

Staging uses stage semantics, so it coexists with other tools that stage secrets on the same Fly app. A deploy happens only with `--deploy`, and only when a staged digest changed, a prune happened, or a managed name is still pending on Fly (status Staged or Partial) from an earlier run. Deploying an app that has no machines exits 5.

### Pruning

Nothing is deleted by default. `--prune` unsets only names that the template produces for declared keys that are not desired in this environment. Names outside that set are never touched. Immutable keys are never pruned unless named with `--prune-immutable`; they are reported as "held (immutable), not pruned". A name staged by the same run is never pruned. A key you delete from `secrets.toml` is no longer declared, so it is neither reported nor pruned: unset it manually with `flyctl secrets unset`.

## Rules reference

Rules go in a key's `rules = { ... }` table. A failure names the key and the rule, never the value.

Always on, for every key (after a `pem_private_key` transform, see below): `nonempty`; `single_line` (no `\n`, `\r` or NUL); `no_surrounding_space`; `max_len` (59,000 bytes).

| Rule | Meaning |
|---|---|
| `prefix = "sk-"` | value starts with the prefix |
| `not_prefix = "sk-or-"` or a list | value starts with none of them |
| `regex = "..."` | the whole value matches (full match) |
| `enum = ["a", "b"]` | value is one of the listed strings |
| `base64_bytes = N` | valid base64 that decodes to N bytes |
| `hex_bytes = N` | valid hex that decodes to N bytes |
| `email_list = true` | comma-separated list of email addresses |
| `https_url = true` | an `https://` URL |
| `prefix_by_mode = { mode, values, skip }` | prefix chosen by the environment's declared mode for the product (`modes.<product>.<mode>`); a mode listed in `skip` disables the check and the key is not required |
| `refuse_in = ["prod"]` | the key must not exist in those environments: a non-empty field there is a blocking failure even though the key is not otherwise expected. The environments must be defined and not also appear in `environments` |
| `transform = "signoz_ingestion_header"` | accepts a bare SigNoz ingestion key or one already prefixed `signoz-ingestion-key=`, and stages it as `signoz-ingestion-key=<key>` |
| `transform = "pem_private_key"` | accepts one PEM private key block (label ending `PRIVATE KEY`, matching BEGIN/END, no headers, base64 of a DER SEQUENCE) pasted multi-line into a concealed field or already on one line, and stages it as one line `-----BEGIN <label>-----<base64>-----END <label>-----`. It runs before the always-on rules, which then see the one-line value. Only whitespace is removed, so RFC 7468 parsers that skip body whitespace (Rust `pem` 3.x) read the same key |

Fly import refusals are checked for every ready secret by `status` and `fly plan` as well as `fly sync`, so a green status means sync will not refuse the value:

| Rule | Refuses |
|---|---|
| `fly-name-invalid` | a Fly name that does not match `^[A-Z][A-Z0-9_]*$` |
| `import-newline` | a value containing `\n` or `\r` (multiline values are not supported) |
| `import-hash-after-odd-quotes` | a `#` after an odd number of `"` (the import format would truncate it) |
| `import-line-too-long` | an encoded import line over 60,000 bytes |
| `import-invalid-utf8` | a value that is not valid UTF-8 |
| `import-duplicate-name` | the same Fly name twice in one batch |

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
| 8 | findings: `status` or `fly plan` found blocking keys |
| 101 | internal panic (Rust default) |

`run` exits with the child's own exit code, which can equal one of the codes above; opv's own errors print `opv: ...` on stderr. A closed stdout (`status | head`) does not change the result.

Diagnose and guide: after any failed `op` call (`op item get`, `op item edit`) opv runs `op whoami`, and when that fails `op account list`; both are free under 1Password rate limits, and no item is read a second time. Not signed in (no session, an expired `OP_SESSION_*`, a locked desktop app, or a rejected `OP_SERVICE_ACCOUNT_TOKEN`) is authentication (7), with the sign-in command for your shell: `eval $(op signin)` for bash and zsh, `eval (op signin)` for fish, `Invoke-Expression $(op signin)` for PowerShell (the default on Windows), or, under CI (`CI` or `GITHUB_ACTIONS` set), "set OP_SERVICE_ACCOUNT_TOKEN" and no interactive command. No account on the machine (fresh WSL or Linux) gives the `op account add` command first. Signed in but the read still failed is a source error (4) naming the vault and item IDs and the identity type (USER or SERVICE_ACCOUNT, never the identity) and saying to grant that identity access to the vault. `doctor` uses the same check, and a missing `op` or `flyctl` names the install command for your OS. Child stderr is suppressed on purpose, because it could echo a value; a re-run hint such as `run \`flyctl secrets list --app <app>\` to see why` remains only where opv cannot find out more itself (Fly failures, or when `op whoami` cannot run).

A clean `status` ends with a summary line, for example `49 saved, 13 not yet on Fly (staged by the next fly sync), 0 findings`.

## Security model and limits

- Values travel only on stdin or in the environment of a child process. They never appear in argv, files, logs, errors, `Debug` or `Display` output.
- The stderr of `op` and `flyctl` is suppressed so it cannot leak a value.
- `serde` can leave transient scratch copies of values in memory while parsing `op` output; opv wraps values in redacting, zeroizing types but cannot control those copies.
- `config export` prints config-kind values by design. It refuses if a config key is stored concealed or a secret key as text.
- `run` hands secret values to the child process through `op run`; the child can read them.
- No multiline values. Fleet profile only. No `--json` output other than `config export`.
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
        run: opv fly sync prod
```

This stages without deploying; a later `fly deploy` (or `opv fly sync prod --deploy`) applies everything staged by every tool. Install `op` and `flyctl` on the runner first (for example with the official 1Password and Fly GitHub Actions).

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
