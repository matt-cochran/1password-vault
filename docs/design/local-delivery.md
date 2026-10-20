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
| Platforms | Linux and WSL (with a session runtime directory). macOS and native Windows are refused for file keys; `declared_only` without file keys works everywhere. Every platform, with its cause code: [Platforms and limits](#platforms-and-limits). |
| Fresh and private | `opv-run.<pid>-<random>`, created with mode 0700, never an existing path (a planted directory makes creation fail), then checked to be owned by the user with no group or other access, by path and again through its open handle. The runtime directory it is made in must not be writable by other users unless sticky. The same code as Azure's deploy-credential directory, moved to `src/ramdir.rs`. |
| Files | Each path is relative, at most four `/`-separated components, each matching `^[a-z0-9]+(-[a-z0-9]+)*$` (lower-case letters and digits, `-` only between them), unique, and never inside another key's path (load-time rules). Intermediate directories are created 0700 inside the private directory, relative to a handle opened on it once (so a later rename of its entry cannot redirect a write); a component that exists as anything but a directory (a planted link) refuses. Files are created exclusively (`O_CREAT|O_EXCL`), `O_NOFOLLOW`, mode 0400, synced. |
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

## Platforms and limits

What file-key delivery does on each platform, and which limits opv enforces. Each claim cites the code that makes it true; a limit no code handles says so. Line numbers are those of the commit that added this section; references into `src/app/local_delivery.rs`, `src/hardening.rs` and `src/app/local_delivery_tests.rs` are those of the hardening commit (runtime directory mode, directory-handle writes, inherited descriptors).

### Platform matrix

The file-key check is one function, `runtime_dir_support` (`src/app/local_delivery.rs:219-264`, with `runtime_dir_at` and `writable_by_others`). The delivery step runs it only when the run has file keys (`:415-418`), so `declared_only` without file keys works on every platform. The step runs under `op run`, so a refusal comes after `op run` has resolved the values into the step's environment, but before the private directory is made, before any file is written and before the app starts. `opv run … --preview` runs the same check without reading a value and reports it as `file_delivery.supported` and `reason` (`src/app/delivery_preview.rs:177-187`).

| Platform | File keys | Reason | Refusal: cause code (exit), where |
|---|---|---|---|
| Linux | Supported | `$XDG_RUNTIME_DIR` must be set, absolute, a directory owned by the user (checked with `lstat`, so a link to a directory fails), not writable by other users (no group or other write bit, unless the sticky bit is set: 0700 and 1777 pass, 0777 and 0770 do not) and on tmpfs or ramfs (`statfs` magic). There is no disk fallback. | `ram_dir_unavailable` (6), `why` = `unset` / `not_absolute` / `not_owned` / `writable_by_others` / `not_tmpfs`: `src/app/local_delivery.rs:225-248`, mode `:256-259`, raised at `:417-418`; `src/ramdir.rs:18-24` (owner, not a link), `:47-54` (tmpfs/ramfs); variant `src/cause/mod.rs:1666`. If the private directory can't be made, opened as private, or written: `private_dir_failed` (6), `src/app/local_delivery.rs:420-423`, `:436-437`. Codes: `src/cause/mod.rs:1670-1671`; exit 6: `:1769-1774`. |
| WSL | Supported, as Linux | opv in WSL is the Linux build, with the same checks. With systemd, logind sets `/run/user/<uid>` on tmpfs, mode 0700, which passes. WSLg's `/mnt/wslg/runtime-dir` is owner-held tmpfs with mode 0777 and no sticky bit, so another user could rename or replace the `opv-run.*` entry in it: it is refused with `why` = `writable_by_others`, and the step says to enable systemd in `/etc/wsl.conf`. | As Linux. Separately, every `opv run` in WSL refuses a Windows `op.exe` that comes first on `PATH`, since it cannot start a Linux child: `tool_unusable` (3), `src/app/run.rs:374`, `:474-488`; `src/runner.rs:1808-1820`, `:1861-1868`; code `src/cause/mod.rs:1655`, exit `:1728-1730`. |
| Containers via Compose | Supported through the host | `opv run` on a Linux or WSL host writes the directory, and the [Compose recipe](../local-development.md#docker-compose) bind-mounts it `read_only` into a container that runs as `OPV_UID:OPV_GID`. opv sets those as its effective ids for a run that delivers files (`src/app/local_delivery.rs:190-196`). On WSL 2 with Docker Desktop, the bind shows as tmpfs inside the container (`delivery-transports.md` §5). | The host's check (Linux row). Outside `opv run`, Compose refuses the recipe itself (exit 15, its own `${…:?}`), which is not an opv cause. `opv run` inside a container runs the Linux check, so a container without a user-owned tmpfs `$XDG_RUNTIME_DIR` is refused with `ram_dir_unavailable` (6). Docker Desktop on a macOS or Windows host: see those rows. |
| macOS | Refused | No RAM-backed runtime directory qualifies. Any OS other than Linux is refused before `$XDG_RUNTIME_DIR` is read, and `ram_backed` is false off Linux (`src/ramdir.rs:55-59`). A `hdiutil` RAM disk would need its own design (open point 2). | `ram_dir_unavailable` (6), `why` = `none_on_platform`: `src/app/local_delivery.rs:220-223`. |
| Windows (native) | Refused | Same check as macOS. Azure's sign-in directory uses a user-only ACL on Windows (`src/ramdir.rs:178-189`), but file delivery does not use it: the directory would be on disk. | `ram_dir_unavailable` (6), `why` = `none_on_platform`: `src/app/local_delivery.rs:220-223`. |
| Kubernetes | Not local delivery. The Kubernetes target delivers file keys when `kubernetes.secrets_dir` is set. | The target ignores `local`. With `secrets_dir`, file keys become a read-only projected volume, 0440 files (`delivery-transports.md` §6.3; `FileCapability::Native`, `src/adapters/kubernetes/config.rs:468-471`). Without it, the key goes to the secret channel as a variable, and `plan` prints `warning: … file destination not honoured on <target>` (`src/app/mod.rs:1209-1214`). That is a warning, not a refusal. | Under `sync`, a workload that can't read the files, or whose reader is unknown, is refused before anything is written: `mount_unreadable` (6), `src/adapters/kubernetes/config.rs:639-650`; code `src/cause/mod.rs:1640`, exit `:1761-1774`. |
| Fly | Not delivered as files by opv | The Fly target stages keys as Fly secrets, which reach the app as variables at boot. The app's shim writes them to files (`FileCapability::ViaApp`, `src/adapters/fly/config.rs:295-297`), and `plan` prints `note: … file via the app (…)` (`src/app/mod.rs:1203-1208`). `--file-secret` waits on the F1–F4 live check (`delivery-transports.md` §7.3), which has moved to a Journeeze/infra issue. | None: nothing is refused, and opv never claims these keys are delivered as files. |

### Limits

Verdicts:
- **Enforced:** code makes it hold, or refuses the run.
- **Mitigated:** code narrows it, but a gap remains, which the row names.
- **Unsupported:** opv does not protect against it.

| Limit | Verdict | Why | Code |
|---|---|---|---|
| Same UID | Unsupported (accepted residual) | The files are 0400 and the directory 0700, both owned by the user, so any process of that user can read them while the app runs, just as it can read the app's environment. This is the owner's accepted residual (`delivery-transports.md` §5). | File mode `src/app/local_delivery.rs:365`; directory mode `src/ramdir.rs:196` |
| Another user | Enforced | The runtime directory must not be writable by other users unless it has the sticky bit, so no other user can rename or replace the `opv-run.*` entry (`writable_by_others`, see WSL above). The private directory is created 0700, checked by path, then opened once (`O_DIRECTORY\|O_NOFOLLOW`) and checked again through that handle (`fstat`: a directory, owned by the user, no group or other bits); if either check fails the run is refused. Every subdirectory and file is then created relative to that handle (`mkdirat`, `openat` with `O_NOFOLLOW`, files `O_CREAT\|O_EXCL`, 0400), never by a path looked up again, so renaming or replacing the entry after it was opened cannot redirect a write. The app gets the directory by path, and removal is by path: those are the user's own entries, which only the same UID (accepted above) can rename. | `src/app/local_delivery.rs:238-264` (runtime mode), `:292-370` (handle and writes), `:422-423`, `:436`; `src/ramdir.rs:31-38`, `:165-170`, `:192-198`; tests `src/app/local_delivery_tests.rs:264`, `:278`, `:300-322` |
| Root | Unsupported | Root reads every file regardless of mode, and can ptrace any process. opv does not refuse to run as root: no code checks for uid 0. | none |
| ptrace | Mitigated | The delivery step makes itself non-dumpable as its first statement (best effort; the result is not checked). Other processes of the same user then cannot ptrace it or read its `/proc/<pid>/environ` and `mem`, which hold the values `op run` gave it. Root and `CAP_SYS_PTRACE` still can. Not enforced: the app (`execve` resets the dumpable flag, so the app is as traceable as any process of the user) and `op run` (1Password's process). | `src/main.rs:1841`; `src/hardening.rs:69-78` |
| Inherited fds | Enforced | Just before the app is started, the step marks every descriptor above 2 close-on-exec: `close_range(3, ~0, CLOSE_RANGE_CLOEXEC)`, or on kernels before 5.11 each entry of `/proc/self/fd` (`/dev/fd` on other Unix). A descriptor the step inherited from `op run` without `FD_CLOEXEC` therefore stops at `execve`. Nothing is closed in the step itself, so every descriptor opv still uses stays open; its own are opened `O_CLOEXEC` anyway (the directory handle and each file, closed when its write returns). stdin, stdout and stderr pass to the app on purpose, so `op run` keeps masking. The remote receiver does the same before its app. | `src/hardening.rs:18-66`; called at `src/app/local_delivery.rs:448`, `src/app/remote_delivery.rs:808`; test `src/app/local_delivery_tests.rs:328` |
| Swap | Unsupported | tmpfs pages can be swapped to disk under memory pressure. ramfs, which never swaps, is accepted but not required, and opv never calls `mlock` on its own memory. The step's copy of its environment is zeroized when dropped, which clears it in memory but does not keep it out of swap. Encrypted swap, or no swap, is the host's choice. | tmpfs or ramfs check `src/ramdir.rs:47-54`; zeroize `src/app/local_delivery.rs:413`, `:444` |
| Core dumps | Mitigated | For every command, including the step, opv first sets non-dumpable, which stops cores through a pipe handler as well (systemd-coredump, apport, WSL's capture), and sets a zero soft `RLIMIT_CORE`. Both are best effort. Not enforced for the app: the hard limit is left alone on purpose, so the app keeps its own core-dump behaviour, and a core of the app holds whatever it read from the files. The files themselves are on tmpfs, not in any core. | `src/main.rs:1841`; `src/hardening.rs:69-107` |
| Hard links planted before the write | Enforced | The private directory gets a new name (pid plus random) and is created with `mkdir`, which fails on any existing path. Each file is created relative to the directory's handle with `O_CREAT\|O_EXCL\|O_NOFOLLOW`, so a name that already exists, as a hard link, a symlink or anything else, fails instead of being written through. An intermediate component that exists but is not a real directory refuses too. Each failure is `private_dir_failed` (6). | `src/ramdir.rs:156-165`, `:177-199`; `src/app/local_delivery.rs:327-370`, `:436-437`; tests `src/app/local_delivery_tests.rs:245`, `:254` |
| Hard links made during the run | Unsupported | A process of the same user can hard-link a delivered file to another name on the same tmpfs while the app runs. `fs.protected_hardlinks` does not stop the file's owner. Removing the directory unlinks only the names inside it, so that link keeps the bytes until it is removed or the tmpfs is cleared. | removal `src/ramdir.rs:213-217` |
| Reboot | Mitigated | The directory exists only on tmpfs or ramfs, which is empty after a reboot. If a run is killed, its directory is swept by the next run that delivers files (one whose pid is gone; a directory whose pid has been reused waits until that process ends), or goes with the runtime directory at logout (logind, not opv). Not enforced: a tmpfs page swapped to a persistent, unencrypted swap device can outlive a reboot (Swap). | RAM check `src/app/local_delivery.rs:246-248`; sweep `:419`, `src/ramdir.rs:65-84` |

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

## Process roles and the delivery preview (#136)

A key may carry `roles = ["serve", "migrate"]` (one or more names matching `^[a-z0-9-]{1,32}$`; an empty list is a load error). Selection happens once, in `src/app/delivery_preview.rs::select`, where `opv run` chooses both the `op run` reference set and the local delivery step. A key without `roles` is delivered to every role and to a run without `--role`; a key with `roles` is delivered only when `--role` names one of them. The same filtered list feeds the `op run` arguments, the child environment and `delivery_args`, so a withheld key is never resolved by `op`, never written to a file and never put in the app's environment — `DATABASE_URL_UNPOOLED` with `roles = ["migrate"]` cannot reach a `--role serve` run. Both refusals fail closed with `Code::Usage` before any 1Password read: a product whose keys declare roles and a run with no `--role`, and a `--role` no key declares. Target-level `roles` (M3, delivery-transports §4.4) scope the other direction: a target declares the roles it serves, a target that delivers a product whose keys declare roles must declare `roles` (missing, undeclared or empty is a load error), and a key whose `roles` miss the target's is not desired there, so `--deploy --prune` removes an existing binding. A key without `roles`, and a target without role-scoped keys, are unchanged.

`opv run <env> [--product <p>] [--role <r>] --preview [--json]` and the MCP tool `opv_delivery_preview` call one shared builder, `src/app/delivery_preview.rs::build`, so CLI and MCP answer with the same document (`schema_version` 1): per delivered key its product, key, `source` (`<product>/<KEY>`, or the `from` source), `destination` (`env:<NAME>` or `file:<relative path>`) and `roles`; then `environment_mode`, `secrets_dir_env`, `file_delivery` (supported, with the reason from the same `$XDG_RUNTIME_DIR` check the file step uses) and `prerequisites` (`op` and signed-in as `yes`/`no`/`unknown`), with `withheld_by_role` naming the role-excluded keys. The builder reads identifiers only: no value, no `op run`, no `op read` and no item read. Its one optional `op` call is the existing cheap session probe (`op whoami`, falling back to `op account list`); when that cannot determine the state, both prerequisites are `unknown`, never `no`.

## Open points for review

1. `BASICS` is the fixed keep-list for `declared_only`. Is any entry unwanted for Worker bindings, or is one missing (for example a proxy or CA variable some toolchains need)? Proxy and CA variables are deliberately left out.
2. File keys require Linux or WSL. macOS could use a RAM disk created with `hdiutil`, which needs a separate design; it is refused for now.
3. The config shape (`[products.<p>.local]`, `file`) is new under FR-60, so there is one form only. Is it acceptable?
