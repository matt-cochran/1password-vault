# Local development

`opv run` starts your app with its settings from 1Password as environment variables, with no `.env` file. This page covers getting there and the everyday patterns.

## First run

When the project's configuration already lives in 1Password (a [manifest](configuration.md#configuration-in-1password)), a checkout needs no file:

```sh
opv login dev                                # sign in to dev's 1Password account
opv check dev --product api                  # every key saved and valid? names only
opv run dev --product api -- npm run dev
```

Every project uses products: a project with one app is a configuration with one product (FR-60). When exactly one product has keys desired in the environment, `--product` may be omitted (D10), so this also works: `opv check dev`, then `opv run dev -- npm run dev`. With several products it is a usage error that lists them; name the product.

Requirements: the 1Password CLI `op` 2.40.0 or newer, signed in (`opv login dev`, or the 1Password desktop app integration). No deployment CLI is needed. `opv doctor --env dev` checks exactly what local work needs (configuration, `op`, its sign-in, whether `op` can start a local command) and reads the item once, as `check` does.

## No configuration yet

Let `init` write the configuration. Without `--vault` and `--item` it uses vault `<project>-dev` and item `<project> · dev values`, creating them if missing; pass both to start from an item you already have. Without a target option it declares a run-only environment, which needs no deployment target:

```sh
opv init dev                                 # new project: a manifest in 1Password (--file for secrets.toml)
opv check dev --product api
```

If the project already has a configuration for its deployed environments, add the local one with `--add-env`; it includes `dev` in every declared key the item has and names the rest:

```sh
opv init dev --add-env
```

A key the item does not have yet: `opv add api/STRIPE_KEY --kind secret --env dev`, then `opv item skeleton dev` adds its empty field, and you type the value in 1Password. A project that ships `opv.setup.toml` has a guided path instead: [guided setup](guided-setup.md).

## How `run` works

`run` hands `op run` one `op://` reference per key; `op run` resolves them and starts your command. opv never sees the values, `op run` masks them in your command's output, nothing is written to disk, and the values are gone when the process exits. Only keys whose `environments` include the environment are set, under their plain names (`DATABASE_URL`, not `FLEET__API__DATABASE_URL`). `run` exits with your command's own exit code.

Before adding the selected keys, `run` removes every key name declared in the configuration from the inherited environment, so switching products in one shell never leaks the previous product's keys, and a key a mode skips is not inherited either. Everything else (PATH, tool settings, the 1Password sign-in, undeclared variables) is inherited: this is not a sandbox. Keys named `PATH`, `HOME`, `XDG_CONFIG_HOME` or `OP_*` are a configuration error for that reason.

When a stored value has a formatting problem opv can fix (a trailing newline or space, a missing `ensure_prefix`) and you run under a service account or CI, the command gets the value as stored and opv prints one warning per key: `api/KEY has a fixable formatting problem in 1Password; run as yourself (opv login dev) and opv will tidy it`.

| You want | Run |
|---|---|
| An app or test suite | `opv run dev -- npm test` |
| A shell with every variable set (gone on `exit`) | `opv run dev -- $SHELL` |
| Docker Compose (`${VAR}` in `compose.yaml`, and `environment:` entries without a value) | `opv run dev -- docker compose up` |
| An editor or debugger whose run configurations inherit the variables | `opv run dev -- code .` |
| Config values (not secrets) as JSON for another tool | `opv config export dev --json` |

There is no command that writes a `.env` file or prints `export` lines, on purpose (SR-4). If a tool insists on a `.env` file, configure it to read the process environment instead; Compose's `env_file:` can be replaced by `environment:` entries without values.

## Only the declared keys, or keys as files: `[products.<p>.local]`

By default the app inherits your environment as described above. A product can narrow that, or take some keys as files, with a `local` table ([design and guarantees](design/local-delivery.md)):

```toml
[products.journeeze.local]
environment = "declared_only"        # the app gets its declared keys and PATH, HOME, user, shell, locale, terminal, TMPDIR; nothing else
secrets_dir_env = "JZ_SECRETS_DIR"   # the variable naming the directory of file keys

[products.journeeze.keys.GITHUB_APP_PRIVATE_KEY]
kind = "secret"
environments = ["dev", "prod"]
file = "github-app/private-key"      # under opv run: a file in that directory, not a variable
```

`opv run` then starts its delivery step between `op run` and your command. With or without `declared_only`, no `OP_*` variable (1Password sessions, service-account or Connect credentials) reaches the app. A key with `file` is written to a fresh private directory in RAM (`$XDG_RUNTIME_DIR` on tmpfs, mode 0700, files 0400, never through a link), named by `secrets_dir_env`. Each `file` path is relative, at most four `/`-separated parts, each matching `^[a-z0-9]+(-[a-z0-9]+)*$` (lower-case letters and digits, `-` only between them), so the app's own store sees names like `github-app/private-key`. The directory is removed when the app exits or on Ctrl-C, and if opv was killed, by the next run or at logout. Without a RAM-backed runtime directory (macOS, native Windows, a WSL session without one), a file key refuses the run (`ram_dir_unavailable`, exit 6) instead of writing to disk. Targets ignore `local` and `file`: they deliver keys as before.

**Secret-store apps.** An app with a `SecretStore` / mounted-secrets port reads `$JZ_SECRETS_DIR/github-app/private-key`, its own naming contract, and needs no variable or file of its own:

```sh
opv run dev --product journeeze -- cargo run
```

**Cloudflare Workers (Vite plugin, wrangler).** Do not create `.dev.vars`. Declare the product `declared_only` and let the plugin read process variables. The Worker's `env` bindings are then exactly the declared keys (plus the basics, none of them secret), never your shell's other tokens:

```sh
opv run dev --product valum -- env CLOUDFLARE_INCLUDE_PROCESS_ENV=true npx vite dev
```

Each Worker or service is its own product, run with its own `--product`. A key the current mode does not need (for example the mail provider's key while mail is captured locally) is left out by its rules, and test versus live billing keys are separate values per environment. opv's tests check the filtering with the real binary and fake values. Cloudflare's own reading of the variables follows its documentation for `CLOUDFLARE_INCLUDE_PROCESS_ENV`; check it once with your plugin version.

What opv cannot do: stop the app (or another process of the same user) from logging or copying what it receives. This narrows what reaches the app; it is not a sandbox.

## Remote development: `run --remote`

When the app builds and runs on a remote machine, do not copy a `.env` there. Declare a reviewed profile for the product, and let opv carry the values over SSH into the remote app's RAM:

```toml
[products.journeeze.remotes.builder]
host = "builder.example.internal"
user = "dev"
host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA…"   # ssh-keyscan -t ed25519 builder.example.internal, without the host name
environments = ["dev"]
opv = "/usr/local/bin/opv"                          # install the same opv release there
workdir = "/home/dev/src/journeeze"
command = ["cargo", "run", "-p", "jz-serve"]
```

```sh
opv run dev --product journeeze --role serve --remote builder --preview
opv run dev --product journeeze --role serve --remote builder
```

The remote host needs the same opv release and, for `file` keys, a user-owned `$XDG_RUNTIME_DIR` on tmpfs (systemd-logind sets one for SSH sessions). opv connects with only the pinned host key, no SSH configuration of yours and no agent forwarding; the remote app gets the declared keys and files, never a 1Password session. Closing the terminal, Ctrl-C or a dropped connection stops the remote app and removes its files. The remote app does not read your terminal's input. What this cannot protect against, such as untrusted code in the remote source tree, is in the [design](design/remote-delivery.md#what-opv-enforces-and-what-it-cannot).

## Several products or checkouts

- `OPV_PRODUCT=api` sets the default `--product` for `check`, `run`, `open`, `explain`, `status`, `plan` and `doctor --env` (never `sync`); stderr says `product api (from OPV_PRODUCT)`. A single-product repository in a fleet can export it once, for example in `.envrc`.
- Worktrees and clones of one repository find the same manifest by its git remote. In a monorepo, a manifest tagged with paths covers its directories ([monorepo paths](configuration.md#how-opv-finds-the-configuration)).
- To use a configuration from elsewhere, name it: `OPV_PROJECT=<name>` for a manifest, `--config <path>` (or `OPV_CONFIG`) for a file. Never infer a product from a directory name.

## WSL

Use the Linux `op` installed inside WSL, signed in with its own session (`opv login dev` adds the account at `op`'s prompts if none is set up yet). A Windows `op.exe` first on `PATH` can read metadata through the Windows desktop app but cannot start a Linux command: `run` refuses it (exit 3), and `doctor` reports it on its `op local run` line (a failure under `--env` for a run-only environment, a warning otherwise). Shell aliases do not count, because subprocess lookup ignores them. On native Windows, use the Windows `opv` and `op` in PowerShell.

Follow sign-in prompts yourself; never give credentials or session tokens to an assistant, and do not save them in shell profiles.
