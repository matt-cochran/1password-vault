# Local delivery: declared-only environments and mounted secret files

Status: implemented for review (#136, #137). The owner reviews this design before the change merges.

## Problem

`opv run` gives the app a child environment of `op://` references, which `op run` resolves into variables. Two kinds of app cannot use that safely:

- **Secret-store apps (#136).** For example, Journeeze's ADR 0006 requires GitHub App private keys and webhook secrets to be read through a `SecretStore` / `MountedSecretStore` port: files at stable names such as `github-app/private-key`, never ordinary secret variables. Only its shared-host entrypoint has an exception, which converts delivered variables to tmpfs files.
- **Cloudflare Workers under Vite (#137).** For example, Valum's local Worker reads its bindings from `.dev.vars`, or, with `CLOUDFLARE_INCLUDE_PROCESS_ENV=true`, from every process variable. The first is a secret file on disk. The second turns the developer's whole environment into Worker bindings, including 1Password session tokens, cloud credentials and other products' keys.

Rejected answers: an ad-hoc wrapper script, `.env` / `.dev.vars` export, `op inject` to a file on disk, extending the shared-host exception to local development, or `CLOUDFLARE_INCLUDE_PROCESS_ENV` over an unfiltered environment.

## Design

A product opts in with `[products.<p>.local]`. `opv run` then starts its own delivery step as `op run`'s child, between `op run` and the app:

```text
opv run dev --product journeeze -- cargo run
  └─ op run -- opv local-delivery --key K… [--file K=path…] [--dir-env VAR] [--declared-only] -- cargo run
       └─ cargo run          (environment filtered; file keys in a private RAM directory)
```

- `op run` stays the only thing that resolves references, and stays the parent, so it keeps masking values in the app's output. opv's own process never resolves a value. The delivery step receives values the same way the app would have: in its environment, from `op run`.
- The step's arguments are key names, relative paths and a variable name, never a value (SR-3).
- **Always:** no `OP_*` variable reaches the app. That covers `OP_SESSION_*`, `OP_SERVICE_ACCOUNT_TOKEN`, `OP_CONNECT_*` and `OP_ACCOUNT`. Key names cannot be `OP_*` (load-time rule), so nothing declared is lost. This also closes the pre-existing path by which an `op signin` session token passed through `op run` into the app.
- **`environment = "declared_only"`:** the app's environment is the product's selected keys (those `opv run` passes: declared for the environment, rules applying, so a capture-mail mode leaves the mail provider's key out) plus a fixed set of basics: `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `TERM`, `COLORTERM`, `NO_COLOR`, `LANG`, `LANGUAGE`, `TZ`, `TMPDIR` and `LC_*`. None of these is a credential. Other products' keys were already removed by `opv run` (#53).
- **Keys with `file = "<relative path>"`** are written to files, and the app gets the directory in the product's `secrets_dir_env` variable. They are not passed as variables.

### The private directory (#136)

| Property | How |
|---|---|
| RAM only | Created under `$XDG_RUNTIME_DIR` only when it is absolute, a directory (not a link) owned by the user, and on tmpfs or ramfs (`statfs` magic). Otherwise the run is refused with `ram_dir_unavailable` (exit 6), before the app starts and before anything is written. There is no disk fallback. |
| Platforms | Linux and WSL (with a session runtime directory). macOS and native Windows are refused for file keys; `declared_only` without file keys works everywhere. |
| Fresh and private | `opv-run.<pid>-<random>`, created with mode 0700, never an existing path (a planted directory makes creation fail), then checked to be owned by the user with no group or other access. The same code as Azure's deploy-credential directory, moved to `src/ramdir.rs`. |
| Files | Each path is relative, at most four components of `[A-Za-z0-9][A-Za-z0-9._-]*`, unique, and never inside another key's path (load-time rules). Intermediate directories are created 0700 inside the private directory; a component that exists as anything but a directory (a planted link) refuses. Files are created exclusively (`O_CREAT|O_EXCL`), `O_NOFOLLOW`, mode 0400, synced. |
| Lifetime | Removed when the app exits (any exit code), and by the signal handler on Ctrl-C or SIGTERM. If opv itself is killed (SIGKILL, power loss), the files stay in RAM until the next `opv run` of any product sweeps directories whose process is gone, or until the session's runtime directory is cleared at logout or reboot. |
| Values in memory | The step's copy of its environment is zeroized when dropped. The app's own handling of the files is the app's. |

### What opv can and cannot enforce

opv enforces:

- No value in argv, terminal output, logs or files outside the private directory.
- No `OP_*` credential in the app's environment.
- The declared-only scope.
- The directory's location, permissions, link resistance and cleanup on exit or signal.
- A refusal, never a fallback, where those properties cannot hold.

opv cannot enforce:

- What the app does with values: logging them, or copying the files elsewhere.
- Isolation from other processes of the same OS user. They can read the files while the app runs, as they could read its environment through `/proc`.
- That an agent with an unrestricted shell as that user cannot run `opv run` itself. Hiding values from MCP responses does not isolate such an agent; see [mcp.md](../mcp.md).
- Cleanup after SIGKILL of opv, which is bounded by the next sweep or by logout instead.

Existing behaviour is unchanged for every product without `local`: no delivery step, same `op run` call. Targets (Fly, Azure, Kubernetes, GitHub) ignore `local` and `file`. The shared-host entrypoint path is untouched.

## Cloudflare Workers (#137)

Run the dev server with the declared scope as its process environment, and let Cloudflare's Vite plugin read process variables:

```toml
[products.valum.local]
environment = "declared_only"
```

```sh
opv run dev --product valum -- env CLOUDFLARE_INCLUDE_PROCESS_ENV=true npx vite dev
```

The Worker's `env` binding object then holds the declared keys (and the basics listed above, which are not secrets). `process.env` in Node-side code sees the same set. Separate Workers or services are separate products, each run with its own `--product`, so one service's keys never reach another. Test versus live billing keys live in different environments' items (dev versus prod), and a capture-mail mode leaves the mail provider's key out through the key's rules.

Verified in CI: the delivery step's filtering, run as the real binary with fake values (`tests/local_delivery.rs`). Not verified in CI: Cloudflare's Vite plugin and Workers runtime reading those variables. That is Cloudflare's documented behaviour for `CLOUDFLARE_INCLUDE_PROCESS_ENV`, and needs a manual check with the project's plugin version.

## Open points for review

1. `BASICS` is the fixed keep-list for `declared_only`. Is any entry unwanted for Worker bindings, or is one missing (for example a proxy or CA variable some toolchains need)? Proxy and CA variables are deliberately left out.
2. File keys require Linux or WSL. macOS could use a RAM disk created with `hdiutil`, which needs a separate design; it is refused for now.
3. The config shape (`[products.<p>.local]`, `file`) is new under FR-60, so there is one form only. Is it acceptable?
