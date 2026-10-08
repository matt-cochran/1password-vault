# Using opv

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
7. `run <ENV> --product <p> -- <cmd>` runs a command with the product's keys in its environment under plain names (`OPENAI_API_KEY`, not the Fly name), through `op run`. It writes no `.env` file. See [Local development](#local-development).

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
[Failure reasons](configuration.md#failure-reasons)); `target` is `present`, `absent` or
`would_change` for a secret and `null` for a config key; `action` is `would_stage`,
`would_prune`, `held` or `null`. The document is meant for the scheduled drift check.

### Change detection

Fly digests cannot be computed locally, so opv cannot tell in advance whether a value changed. `sync` reads Fly's secret metadata, stages, reads it again and compares the digests. `plan` therefore shows a desired key that is already on Fly as "potentially changed". An immutable key already on Fly is "held" and is not staged unless you pass `--rotate` for it.

Staging uses stage semantics, so it coexists with other tools that stage secrets on the same Fly app. A deploy happens only with `--deploy`, and only when a staged digest changed, a prune happened, or a managed name is still pending on Fly (status Staged or Partial) from an earlier run. Deploying an app that has no machines exits 5.

### Pruning

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

`op run` masks secret values that the command prints to stdout. `run` needs a signed-in `op` (the 1Password desktop app integration or `op signin`); it exits with the command's own exit code.

There is no command that writes a `.env` file or prints `export` lines, on purpose: a secret never lands on disk (SR-4). If a tool insists on a `.env` file, configure it to read the process environment instead (most frameworks fall back to it, and Compose's `env_file` can be replaced by `environment:` entries without values).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 2 | configuration error or command-line usage error |
| 3 | dependency: `op` or `flyctl` missing or unusable, or output cannot be written |
| 4 | 1Password source error (including an `op` timeout) |
| 5 | Fly target error (including a `flyctl` timeout, and deploy on an app with no machines) |
| 6 | policy refusal: `sync` refused (missing, wrong kind, failing rule), or `config export` refused |
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

