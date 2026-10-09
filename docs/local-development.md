# Local development

`opv run` starts your app with its settings from 1Password as environment variables, with no `.env` file. This page covers getting there and the everyday patterns.

## First run

When the project's configuration already lives in 1Password (a [manifest](configuration.md#configuration-in-1password)), a checkout needs no file:

```sh
opv login dev                                # sign in to dev's 1Password account
opv check dev --product api                  # every key saved and valid? names only
opv run dev --product api -- npm run dev
```

Under the simple profile there is no `--product`: `opv check dev`, then `opv run dev -- npm run dev`.

Requirements: the 1Password CLI `op` 2.40.0 or newer, signed in (`opv login dev`, or the 1Password desktop app integration). No deployment CLI is needed. `opv doctor --env dev` checks exactly what local work needs (configuration, `op`, its sign-in, whether `op` can start a local command) and reads the item once, as `check` does.

## No configuration yet

If the 1Password item exists, let `init` write the configuration from it. Without a target option it declares a run-only environment, which needs no deployment target:

```sh
opv init dev --vault myapp-dev --item app    # new project: a manifest in 1Password (--file for secrets.toml)
opv check dev --product api
```

If the project already has a configuration for its deployed environments, add the local one with `--add-env`; it includes `dev` in every declared key the item has and names the rest:

```sh
opv init dev --vault myapp-dev --item app --add-env
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

## Several products or checkouts

- `OPV_PRODUCT=api` sets the default `--product` for `check`, `run`, `open`, `explain`, `status`, `plan` and `doctor --env` (never `sync`); stderr says `product api (from OPV_PRODUCT)`. A single-product repository in a fleet can export it once, for example in `.envrc`.
- Worktrees and clones of one repository find the same manifest by its git remote. In a monorepo, a manifest tagged with paths covers its directories ([monorepo paths](configuration.md#how-opv-finds-the-configuration)).
- To use a configuration from elsewhere, name it: `OPV_PROJECT=<name>` for a manifest, `--config <path>` (or `OPV_CONFIG`) for a file. Never infer a product from a directory name.

## WSL

Use the Linux `op` installed inside WSL, signed in with its own session (`opv login dev` adds the account at `op`'s prompts if none is set up yet). A Windows `op.exe` first on `PATH` can read metadata through the Windows desktop app but cannot start a Linux command: `run` refuses it (exit 3), and `doctor` reports it on its `op local run` line (a failure under `--env` for a run-only environment, a warning otherwise). Shell aliases do not count, because subprocess lookup ignores them. On native Windows, use the Windows `opv` and `op` in PowerShell.

Follow sign-in prompts yourself; never give credentials or session tokens to an assistant, and do not save them in shell profiles.
