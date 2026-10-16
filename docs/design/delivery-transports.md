# Delivery transports: containers, Fly and the shared-host shim

Status: **container transport — design for implementation in 0.11.0** (#136). **Fly — design only.** The owner's decisions of 2026-10-16 (`.delivery/v0101/decisions-136.md:5-13`, a local delivery file, not in git) are binding here:

1. 0.11.0 implements the container transport (a host RAM-only directory bind-mounted read-only into the container) and a recorded verification run of the tagged release. Fly stays design-only.
2. When Fly is implemented, migration credentials live in a separate migration app (its own opv target), never on the serving app.
3. File-destination keys deliver the stored bytes verbatim (multi-line PEM, trailing newline). No staging transform applies at delivery.
4. Journeeze's serve role mapping gains `GITHUB_WEBHOOK_SECRET` → `github/webhook-secret`.

Defaults the owner took without asking: a runtime whose UID mapping can't be determined is refused, never answered with world-readable files; the same-user isolation limit is documented; macOS and Windows file delivery stays refused.

Conventions in this document: a **fact** carries a `file:line` citation (opv at `origin/dev` `ab88b30`) or a `commit:path:line` citation (Journeeze at `ced358d`). **[Assumption An]** marks something not verified; §12 lists them all. Recorded tool replies are under `tests/fixtures/docker/` (README there); nothing in this design depends on a reply nobody recorded.

## 1. The one contract, several transports

Every transport delivers the same declared contract, which local delivery already uses:

| Part | Where it is declared | Example |
|---|---|---|
| Source | the key's own field, or `from = "<product>/<KEY>"` | `journeeze/GITHUB_APP_PRIVATE_KEY` |
| Destination | `file = "<lowercase/dash segments>"` | `github-app/private-key` |
| Directory variable | `[products.<p>.local] secrets_dir_env` | `JZ_VAULT_DIR` |
| Role | `roles = [...]` on the key (0.9.0); none means every role | `["migrate"]` for `DATABASE_URL_UNPOOLED` |
| Environment mode | `[products.<p>.local] environment` | `declared_only` |
| Bytes | always verbatim for a file destination (§5) | a PEM with its line breaks and final newline |

The rules don't change between transports:
- Bytes are delivered exactly: no interpolation, transform or newline change (§5).
- Files are 0400 inside a 0700 directory that lives in RAM.
- Names follow the consumer's contract.
- A key outside the run's role is never resolved.
- An unsupported transport fails closed, with a metadata-only reason. It never falls back to disk or to plain environment variables.

`opv run --preview` and `opv_delivery_preview` report what a transport would deliver without reading a value. Each transport sets the preview's `transport` field (`src/app/delivery_preview.rs:222`).

### 1.1 Journeeze's mapping (serve and migrate)

The names are Journeeze's own store constants. The serve list is the shim's `SERVE` list (`ced358d:crates/jz_host/src/fleet_secrets.rs:40-76`) **plus the webhook secret** (decision 4). The migrate list is the shim's `MIGRATE` list (`ced358d:crates/jz_host/src/fleet_secrets.rs:79-82`).

| Key | Destination | Roles | Destination constant |
|---|---|---|---|
| `DATABASE_URL` | `database/url` | serve | `ced358d:crates/jz_host/src/lib.rs:92` |
| `GITHUB_APP_PRIVATE_KEY` | `github-app/private-key` | serve | `ced358d:crates/jz_github/src/lib.rs:67` |
| `GITHUB_WEBHOOK_SECRET` | `github/webhook-secret` | serve | `ced358d:crates/jz_github/src/events.rs:251` — **new in the mapping** |
| `TYPESAFE_JEV_API_KEY` | `jev/api-key` | serve | `ced358d:crates/jz_jev/src/live.rs:24` |
| `BLOB_ACCESS_KEY_ID` | `blob/access-key-id` | serve | `ced358d:crates/jz_blob/src/s3.rs:20` |
| `BLOB_SECRET_ACCESS_KEY` | `blob/secret-access-key` | serve | `ced358d:crates/jz_blob/src/s3.rs:21` |
| `GUIDE_ASSET_SIGNING_KEY` | `guide-assets/signing-key` | serve | `ced358d:crates/jz_auth/src/asset_links.rs:13` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `otel/endpoint` | serve | `ced358d:crates/jz_host/src/telemetry.rs:24` |
| `OTEL_EXPORTER_OTLP_HEADERS` | `otel/headers` | serve | `ced358d:crates/jz_host/src/telemetry.rs:27` |
| `DATABASE_URL_UNPOOLED` | `database/owner-url` | migrate | `ced358d:crates/jz_host/src/lib.rs:203` |
| `JOURNEEZE_APP_PASSWORD` | `database/app-password` | migrate | `ced358d:crates/jz_host/src/lib.rs:204` |

- **Every key carries explicit `roles`.** A key without `roles` goes to every role (`src/app/delivery_preview.rs:92-96`), which would put serving material on the migration app of §6.
- **The webhook secret.** The app reads `github/webhook-secret` before it checks `X-Hub-Signature-256` (`ced358d:crates/jz_github/src/events.rs:251`). The shim's `SERVE` list doesn't contain it (`ced358d:crates/jz_host/src/fleet_secrets.rs:40-76`). So while the shim stays the default on the shared host, the webhook secret is **not delivered by the shim**. That absence is stated, not implied away. opv's fixture consumer already expects it in the serve mapping (`tests/mounted_consumer.rs:16-24`).
- **The directory variable** is `JZ_VAULT_DIR`, default `/run/secrets/journeeze` (`ced358d:crates/jz_host/src/lib.rs:193-199`).
- **Where the mapping is declared.** Journeeze has no opv configuration in its repository at `ced358d` (no `secrets.toml`). The mapping lives in its opv configuration, which is assumed to be a manifest in 1Password **[A1]**. The verification (§7) declares the same mapping for a test product.

```toml
[products.journeeze.local]
environment = "declared_only"
secrets_dir_env = "JZ_VAULT_DIR"

[products.journeeze.keys.GITHUB_WEBHOOK_SECRET]
kind = "secret"
environments = ["dev", "staging", "prod"]
file = "github/webhook-secret"
roles = ["serve"]
# … the other ten keys as in the table, each with file and roles
```

## 2. Platform matrix

| Transport | Status in 0.11.0 | Where values live | Role separation | Evidence |
|---|---|---|---|---|
| Local process, Linux/WSL | implemented | `op run` env, then a tmpfs directory | the selection never resolves another role's keys | `src/app/local_delivery.rs:283-350` |
| Local process, macOS / Windows | refused for file keys | n/a | n/a | `src/app/local_delivery.rs:196-201` |
| Container, WSL 2 + Docker Desktop (WSL integration) | **implemented** | host tmpfs directory, bind-mounted read-only; the container sees tmpfs | same as local | recorded: `tests/fixtures/docker/success/05`, `08` |
| Container, native Linux + Docker Engine (rootful) | **implemented once its replies are recorded** (README item 1); refused (`mapping_unknown`) until then | same | same | **[A2]** |
| Container, rootless Docker | refused (`rootless`) | n/a | n/a | the container user isn't the host user (`failures/01` shows another uid is denied) |
| Container, Docker with `userns-remap` | refused (`userns_remap`) | n/a | n/a | as above |
| Container, Docker Desktop on native Linux or macOS | refused (`desktop_outside_wsl`, or `ram_dir_unavailable` on macOS) | n/a | n/a | how the mount is shared isn't recorded **[A3]** |
| Container, any remote daemon (`tcp://`, `ssh://`, `npipe://`) | refused (`remote_endpoint`) | n/a | n/a | a bind source names a path on the daemon's host, not here |
| Container, rootless Podman (`--userns=keep-id`) | **implemented once its replies are recorded** (README item 6); refused (`not_verified`) until then | host tmpfs, bind-mounted read-only | same | **[A4]** |
| Container, rootful or remote Podman | refused (`host_user_is_root` / `remote_endpoint`) | n/a | n/a | — |
| Container, macOS / Windows hosts | refused (`ram_dir_unavailable`, no RAM directory) | n/a | n/a | `src/app/local_delivery.rs:197-201` |
| Fly machine, entrypoint step, separate migration app | **design only** (§6) | Fly secrets (env at boot), then a tmpfs directory in the guest | serving and migration material on different Fly apps | — |
| Fly `[[files]]` from a secret | **rejected as default** | written by Fly into the guest root filesystem | none | not RAM-only; a spike would have to show otherwise |
| Kubernetes, Azure | out of scope | provider secret stores | n/a | #40–#42 deferred |

## 3. Container transport (0.11.0)

### 3.1 The CLI surface: a reviewed container profile

**Choice:** a product declares reviewed container profiles next to its keys, the same shape as #139's remote profiles (`src/domain/model.rs:161-186`). The person runs one by name:

```text
opv run <env> [--product <p>] --role <r> --container <profile> [--confirm <env>] [-- <container args>]
opv run <env> [--product <p>] --role <r> --container <profile> --preview [--json]
```

```toml
[products.journeeze.containers.serve]
runtime = "docker"                            # "docker" or "podman"
image = "journeeze@sha256:…"                  # never starts with "-"; see the digest rule below
mount_at = "/run/secrets/journeeze"           # absolute; where the RAM directory appears, read-only
environments = ["dev", "staging"]             # whose values may go to this container
roles = ["serve"]                             # optional; default every role the keys declare
publish = ["127.0.0.1:18088:18088"]           # optional; -p entries
network = "bridge"                            # optional; a network name
command = ["serve"]                           # optional; the container's arguments after the image
container_user = "10001:10001"                # optional; podman only (keep-id:uid=,gid=); refused for docker
```

- **Words after `--` are the container's arguments only.** They go after the image and replace `command`. The runtime never parses them as its own flags. So `--user 0`, `-e`, `--env-file`, `--privileged` or another `--mount` can't be smuggled in: everything before the image comes from the reviewed profile, built by one function (§3.4).
- `--container` conflicts with `--remote` (a `Usage{ConflictsWith}`, as `--remote` does with `-- <command>` at `src/main.rs:3006-3016`).
- Unlike `--remote`, a container run needs no terminal (`src/main.rs:3019` requires one for remote). The values stay on this machine, as in a local run. A `confirm_env` environment still needs `--confirm` (`src/main.rs:3037`).
- No MCP tool runs a container. MCP gets the preview only (§3.7).

**Why a profile, and the alternatives I rejected:**

| Alternative | Why rejected |
|---|---|
| `opv run … --container docker -- <docker run flags> <image> <args>` | opv would have to parse Docker's flag grammar to keep `--user`, `-e`, `--env-file`, `--privileged`, `--userns` and extra mounts out. A later `--user` overrides an earlier one. A deny-list over another tool's grammar isn't poka-yoke. |
| `transport = "container"` on `[products.<p>.local]` | One product runs both as a process and in a container. A product-wide switch silently changes every `opv run`, and still needs the image and mount somewhere. |
| A new `opv container run` subcommand | It duplicates `run`'s selection, roles, `--confirm`, preview and `Outer` plumbing. FR-60 allows one way only. |
| A `local-delivery --container` mode the person calls directly | `local-delivery` is a hidden internal step (`src/main.rs:883`). Its errors already render against the person's `opv run` (`src/app/local_delivery.rs:126-148`). |

**Digest rule.** An `image` for an environment with `confirm_env = true` must be pinned by digest (`@sha256:`), checked at load. For other environments a tag is allowed. This needs an owner decision (§13 D5).

### 3.2 The process chain

```text
opv run dev --product journeeze --role serve --container serve
  ├─ select keys (roles) ─ profile checks ─ runtime probe (§3.3)        ← all before any 1Password read
  └─ op run -- opv local-delivery --key … --file K=path … --dir-env JZ_VAULT_DIR --container '<plan>' -- <args>
       ├─ sweep: dead opv-run.<pid>-* directories; labelled containers of dead runs (§3.5)
       ├─ the probe again, with the runtime client's own environment (authoritative)
       ├─ PrivateDir under $XDG_RUNTIME_DIR (tmpfs, 0700), files 0400
       └─ docker run --rm --name opv-<product>-<pid>-<rand> --label io.opv.run=<pid> --label io.opv.uid=<uid>
                     --log-driver none
                     --mount type=bind,src=<ramdir>,dst=/run/secrets/journeeze,readonly
                     --user <uid>:<gid>
                     -e JZ_VAULT_DIR=/run/secrets/journeeze [-e <CONFIG_KEY> …]
                     [-p …] [--network …] <image> <args>
```

- `op run` stays the only thing that resolves references and stays the parent, so it still masks values in the output (`src/app/run.rs:1-12`). The step gets values in its environment, exactly as today (`src/app/local_delivery.rs:295`).
- `<plan>` is JSON, like `remote-send --plan` (`src/app/run.rs:418-447`). It carries names, paths and the profile only: profile name, runtime, image, `mount_at`, `publish`, `network`, the config key names to pass, the mapping the outer probe found, and the `Outer` run. It never carries a value.

### 3.3 The runtime probe: UID and user namespaces

**The problem.** The files are 0400, owned by the host user (`src/app/local_delivery.rs:274`). The container's process has to be that user, as the host kernel sees it. Recorded:
- the host user (uid 1000) reads the file in the container (`success/05`);
- another container uid (10001) gets `Permission denied` (`failures/01`);
- container root reads it anyway (`success/07`).

**The probe**, one function `container::probe(runtime, env) -> Result<Mapping, Cause>`. It is bounded by the runner's captured-call budget, and it uses only the recorded calls:

| Order | Call (exact; recorded) | Accept | Otherwise |
|---|---|---|---|
| 0 | `geteuid()` | not 0 | `ContainerUnsupported{HostUserIsRoot}` |
| 1 | `DOCKER_HOST` if set, else `docker context inspect --format '{{json .Endpoints.docker.Host}}'` (`success/14`) | a JSON string starting `unix://` | `RemoteEndpoint{scheme}`; an unreadable reply is `MappingUnknown` |
| 2 | `docker info --format '{{json .SecurityOptions}}'` (`success/02`) | a JSON **array** of `name=<x>[,k=v]` strings whose names are all recorded as safe (today `seccomp`, `cgroupns`) | `name=rootless` → `Rootless`; `name=userns` → `UserNamespaceRemap`; any other name → `MappingUnknown` (until recorded); stdout `null` with `Cannot connect to the Docker daemon` on stderr → `Unavailable{Docker, DaemonNotRunning}` (`failures/05`, which **exits 0**) |
| 3 | `docker version --format '{{json .}}'` (`success/01`) | `Server.Platform.Name` doesn't start with `Docker Desktop`; or it does, `Server.KernelVersion` ends with `-microsoft-standard-WSL2`, and opv itself runs on WSL (`Host::detect`) | `DesktopOutsideWsl` |
| — | Podman: `podman info --format json` | `host.security.rootless == true`, `host.serviceIsRemote == false` **[A4]** | otherwise refused; **until the README item 6 replies are recorded, every Podman run is `NotVerified`** |

The result:

- `HostUser{uid, gid}` (Docker): `--user <euid>:<egid>`.
- `KeepId{uid, gid}` (Podman): `--userns=keep-id`, or `--userns=keep-id:uid=U,gid=G` when the profile sets `container_user`. The host user then appears as the image's own user (Journeeze runs as uid 10001: `ced358d:deploy/Dockerfile`, the `useradd --uid 10001` and `USER journeeze` lines) **[A4]**.

**When the probe runs:**
- In the outer `opv run`, before `op run`, so a refusal reads nothing from 1Password.
- Again in the step, with the client's exact environment, right before any file is written. That second probe is authoritative. If its mapping differs from the plan's, the run is refused (`MappingChanged`) and nothing is written.

**Why Docker Desktop is accepted only on WSL.** Recorded on WSL 2: the bind source shows up in the container as `tmpfs`, `ro`, `uid=1000`, `mode=700` (`success/08`), so values stay in RAM. How Docker Desktop shares a native Linux or macOS path into its VM is not recorded, and the host-side `statfs` check can't see it **[A3]**.

**Fail closed on parse.** The parser accepts only the recorded shapes. `null`, an object where an array is expected, or an unknown option name are each `MappingUnknown`, never "no options" (`failures/05` shows exit 0 with `null`).

### 3.4 The container's environment and arguments

One pure function, `container::run_argv(plan, mapping, dir, name, pid, uid) -> Vec<String>`, builds the runtime command. opv always adds:

| Flag | Why |
|---|---|
| `run --rm` | no stopped container keeps the mount reference |
| `--name opv-<product>-<pid>-<16 hex>` | `rm -f` by name on every exit path (`success/12`) |
| `--label io.opv.run=<step pid> --label io.opv.uid=<uid>` | the sweep finds containers of dead runs (`success/17`) |
| `--log-driver none` | the daemon's default `json-file` driver writes the app's output to disk (`success/16`); with `none` the attached client still prints it (`success/15`) |
| `--mount type=bind,src=<ramdir>,dst=<mount_at>,readonly` | read-only (`failures/02`). `--mount`, not `-v`. Neither refuses a missing source on Docker Desktop (`failures/03`), so opv keeps the directory alive until the client exits (§3.5). |
| `--user <uid>:<gid>` / `--userns=keep-id[:uid=,gid=]` | §3.3 |
| `-e <secrets_dir_env>=<mount_at>` | a container path, not a secret |
| `-e <NAME>` for each selected `kind = "config"` key without `file` | name only. The runtime copies the value from the client's environment, so the value is never in argv **[A5]**. |

And from the profile only: `-p <publish>…`, `--network <network>`, then `<image>`, then the container arguments.

- **The runtime client's environment** is `BASICS` (`src/app/local_delivery.rs:38-51`) plus the runtime's own variables (`DOCKER_HOST`, `DOCKER_CONTEXT`, `DOCKER_CONFIG`, `DOCKER_CERT_PATH`, `DOCKER_TLS_VERIFY`; for Podman `CONTAINER_HOST`, `CONTAINER_CONNECTION`, `CONTAINERS_CONF`, `XDG_RUNTIME_DIR`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`) plus the selected config keys. It never holds a secret-kind key, an `OP_*` variable or `OPV_RUN_OUTER`.
- **No secret-kind key reaches the container as a variable.** At load, every `kind = "secret"` key that a profile's environments and roles could deliver must have `file`. Otherwise the load fails with `ConfigInvalid` / `ContainerSecretWithoutFile` (§3.8). The step checks again: each `--key` is either a `--file` key or a config name in the plan, or it is a `Bug`.
- **The container's environment** is exactly the `-e` list. The runtime doesn't inherit the client's environment.
- **No `-t`.** Signal forwarding (sig-proxy) works without a TTY (`success/09`).

### 3.5 The RAM directory, the mount and cleanup on every exit path

The directory is today's `PrivateDir` (`src/ramdir.rs:147-218`):
- under `runtime_dir_support()` (`src/app/local_delivery.rs:196-217`): absolute, user-owned, tmpfs or ramfs;
- `opv-run.<pid>-<random>`, created 0700, never an existing path;
- files written by `write_file`: 0400, `O_EXCL`, `O_NOFOLLOW`, synced (`src/app/local_delivery.rs:243-279`).

It is bind-mounted read-only at `mount_at`. On WSL 2 + Docker Desktop, the container sees the same tmpfs (`success/08`).

**Needed change (D4):** today the step starts its child with `Command::status()` and doesn't register it as the running child (`src/app/local_delivery.rs:325-329`). The signal handler forwards only to a tracked child (`src/runner.rs:1976-1978`, `:2168-2190`). In container mode the step spawns the client, tracks it with `signals::track`, and registers the container name in a new `signals::register_container(program, name)` registry.

| Exit path | What happens | Evidence |
|---|---|---|
| The app exits (any code) | the client exits with the container's code; the step runs `<runtime> rm -f <name>` (idempotent, exit 0 when already gone) and drops the directory | `failures/07`, `failures/09`; `--rm` already removed it (`success/10`) |
| SIGINT / SIGTERM / SIGHUP / SIGQUIT to the step | the handler (`src/runner.rs:2037-2054`) forwards to the tracked client (SIGQUIT as SIGTERM), which sig-proxies to the container; after `SIGNAL_GRACE` (5 s, `src/runner.rs:311`) it SIGKILLs the client; **new:** then `rm -f <name>` (bounded, output discarded), because a killed client leaves the container running; then `run_cleanups()` removes the directory; exit 128 + signal | `success/09` (exit 143); `success/11` |
| Ctrl-C at the terminal | the foreground process group (outer opv, `op run`, the step, the client) gets SIGINT; the step's handler does the above | |
| A refusal or error before the client starts (probe, write failure) | `PrivateDir` is dropped (`src/ramdir.rs:213-218`), and nothing ran | |
| A panic in the step | unwinding drops `PrivateDir` (the release profile doesn't set `panic = "abort"`: no `panic` key in `Cargo.toml`); the container, if started, is caught by the next sweep | |
| The step is SIGKILLed, or power is lost | the files stay in RAM and the container keeps running. Removing the directory empties the container's view. The next `opv run` that delivers files sweeps both: directories of dead pids (`src/ramdir.rs:65-84`) and, **new**, `<runtime> ps -a --filter label=io.opv.uid=<uid> --format '{{.Names}} {{.Label "io.opv.run"}}'`, then `rm -f` for each dead pid. Logout clears `$XDG_RUNTIME_DIR`. | `success/11`, `13`, `17`, `18` |
| The outer `opv run` alone is killed | **pre-existing gap:** `run` keeps default signal handling (`src/main.rs:2667-2676`), so `op run`, the step and the container live on until the app exits. This is not new to containers (§11 R9). | |

**Debris on Docker Desktop:** if a bind source is missing, Docker Desktop creates it as a root-owned 0755 directory in the user's runtime directory (`failures/03`, `.host-ls`). The sweep leaves directories it doesn't own alone (`src/ramdir.rs:80`). The step must therefore never remove the directory before the client has exited, and it never does: drop order and the signal order above.

### 3.6 What is never done

- No value in argv: not the runtime's, not the step's (key names, paths and the plan only), not `ps` output. Tested by D3 (a property test over `run_argv`) and D8 (`calls.log`).
- No secret in an environment variable: not in the client's environment, not via `-e NAME=value`, not via `--env-file`. The only `-e` with `=` is the directory variable, whose value is a container path.
- No secret in an image layer. opv never runs `build`, `commit`, `cp` or `export`. Bind mounts are not part of a container's filesystem layers **[A6]**.
- No secret in an ordinary file. The only files are under the tmpfs `PrivateDir`. `--log-driver none` keeps the daemon from writing the app's output to its disk logs (`success/16`). opv writes no `cidfile` (the name is chosen up front).
- No fallback: no world-readable files, no `chmod`/`chown` to fit a container user, no `--user 0`, no environment-variable delivery when files can't be delivered.
- No container runs as root by opv's doing: `--user`/`keep-id` is always set, and no profile field can remove it.
- No MCP tool starts a container, writes a profile value, or returns anything but the preview.

### 3.7 Preview additions (metadata only)

`opv run <env> … --container <c> --preview [--json]` and `opv_delivery_preview` with a new optional `container` argument (a profile name) call the same builder (`src/app/delivery_preview.rs:121`). New fields (the existing ones are unchanged):

```json
{
  "transport": "container",
  "container": {
    "profile": "serve", "runtime": "docker", "image": "journeeze@sha256:…",
    "mount_at": "/run/secrets/journeeze", "command": ["serve"],
    "publish": ["127.0.0.1:18088:18088"], "network": "bridge",
    "environments": ["dev", "staging"], "roles": ["serve"],
    "runtime_on_path": "yes",
    "endpoint": "local",
    "uid_mapping": "host_user",
    "uid_mapping_reason": null,
    "container_user": "1000:1000",
    "env_names": ["JZ_VAULT_DIR"],
    "run": ["docker", "run", "--rm", "--name", "<name>", "--label", "io.opv.run=<pid>", "…",
            "--mount", "type=bind,src=<ramdir>,dst=/run/secrets/journeeze,readonly", "--user", "1000:1000",
            "-e", "JZ_VAULT_DIR=/run/secrets/journeeze", "journeeze@sha256:…", "serve"]
  },
  "container_profiles": ["migrate", "serve"],
  "keys": [{"key": "GITHUB_APP_PRIVATE_KEY", "destination": "file:github-app/private-key",
            "bytes": "verbatim", "staging_transform": "pem_private_key", "…": "…"}]
}
```

- `runtime_on_path`: found by looking on `PATH`, never by running it, like `ssh_present` (`src/app/delivery_preview.rs:229-234`).
- `endpoint` and `uid_mapping` come from the probe's read-only calls (§3.3). A probe that can't finish gives `unknown`, never `no` or a guessed mapping. This is the same rule as `prerequisites` (`src/app/delivery_preview.rs:236-253`).
- `bytes` is `verbatim` for every `file:` destination. `staging_transform` names a declared transform and says that it applies to target staging only (§5).
- The text form adds `transport: container profile serve (docker, image …, mounted read-only at …, runs as 1000:1000)` and `uid mapping: host_user | refused (<reason>) | unknown`.

### 3.8 New failures, as catalog causes

Every failure is a `Cause` (`docs/design/error-catalog.md` §2). Existing variants are reused where they fit. **New** marks new variants, fields and codes.

| Variant | Fields | Code | Exit | Retry | Message (example) | Do | Next |
|---|---|---|---|---|---|---|---|
| **`ContainerUnsupported`** (new) | runtime: Docker / Podman; why: **Rootless / UserNamespaceRemap / RemoteEndpoint{scheme} / DesktopOutsideWsl / HostUserIsRoot / MappingUnknown{call} / MappingChanged / NotVerified**; env; product; profile | **container_unsupported** | 6 | after_fix | "opv can't deliver files to this container: rootless Docker runs it as a user that isn't you, so it couldn't read them. Nothing was read from 1Password." | per why: Rootless → "use rootful Docker, or rootless Podman with keep-id"; Remap → "run Docker without userns-remap, or use Podman"; RemoteEndpoint → `Unset{DOCKER_HOST}` / "switch to this machine's daemon: docker context use default"; DesktopOutsideWsl → "run it from WSL 2 with Docker Desktop's WSL integration"; HostUserIsRoot → "run opv as your own user"; MappingUnknown → "<runtime>'s reply is shown above; opv doesn't recognise it"; MappingChanged → "the container runtime changed during the run"; NotVerified → "use Docker; opv hasn't verified Podman yet" | `opv run <env> --product <p> --role <r> --container <c> --preview` (Check) |
| `Unavailable` (new why and systems) | system: **Docker / Podman**; why: **DaemonNotRunning**; seen | provider_unavailable | 9 | safe | "the Docker daemon isn't running (Cannot connect to the Docker daemon …)" | "start Docker Desktop, or the docker service" | Rerun |
| `ToolMissing` (new tools) | tool: **docker / podman**; platform; shell | dependency_missing | 3 | after_fix | "docker isn't installed or isn't on PATH" | the typed install line (`src/host.rs:245` registry) | Rerun |
| `NotDeclared` (new kind) | kind: **ContainerProfile**; given; candidates; closest | unknown_profile | 2 | never | "no container profile 'srve' for journeeze" | — | Rerun with the unique closest (the kind's code is mapped next to `src/cause/mod.rs:1355`) |
| `Guard` (new guard) | **ContainerProfileRefuses{profile, asked, allowed}** | policy_refused | 6 | never | "container profile serve doesn't take environment prod (it takes dev, staging)" | "use a profile that allows it, or add it to the profile (opv config edit)" | `opv run <env> … --preview` |
| `Usage` | ConflictsWith{`--container`, `--remote`} | usage | 2 | never | "--container can't be used with --remote" | — | Rerun without one |
| `ConfigInvalid` (new checks) | **ContainerSecretWithoutFile{key, profile}**, **ContainerUserOnDocker{profile}**, **ContainerNeedsSecretsDir{profile}**, **ContainerImageUnpinned{profile, env}**; field rules Pattern / Missing / Reserved for `image` (non-empty, no whitespace, not starting with `-`), `mount_at` (absolute, not `/`, no `..`, not under `/proc`, `/sys`, `/dev`), `publish`, `network`, `runtime` | config_invalid | 2 | after_fix | "products.journeeze.keys.DATABASE_URL is a secret delivered to container profile serve but has no file: a container gets secrets only as files" | "add file = \"database/url\", or kind = \"config\" if it isn't a secret" | `opv config edit` |
| `RamDirUnavailable` | unchanged (purpose FileDelivery) | ram_dir_unavailable | 6 | after_fix | as today | as today | the run's preview |
| `PrivateDirFailed` | unchanged | private_dir_failed | 6 | after_fix | as today | as today | Rerun |
| `ChildStartFailed` | program: docker / podman | child_start_failed | 3 | after_fix | "docker couldn't be started" | "check that docker is on PATH" | Rerun |
| **`ContainerLeft`** (new) | runtime; name; seen | **container_left** | — (the app's exit code is kept, FR-4) | check_first | "container opv-journeeze-… is still there after the run" | "remove it: docker rm -f <name>" | Check: `docker ps -a --filter name=<name>` (a typed `Vendor` step) |
| `Interrupted` | unchanged | interrupted | 128+sig | safe | as today | — | Rerun |

- **Exit codes from the app.** `docker run` itself uses 125 (daemon or image: `failures/04`, `06`) and 127 (command not in the image: `failures/08`). The app can use those codes too. opv doesn't capture the client's stderr: that would put the app's output through opv. So the code is passed through as the app's (FR-4), and the probe catches what it can first. This limit is stated in §11 R7.
- **Internal steps never name themselves.** Every cause above renders against the person's `opv run` (`Outer`, `src/app/local_delivery.rs:126-148`), never `local-delivery` or `opv doctor` (X25).
- `human_required` is false for all of them (no handoff). The `--confirm` handoff stays `NeedsConfirm`.

### 3.9 Limits, stated plainly

- The container daemon, root on the host, and anyone in the `docker` group (root-equivalent) can read the directory.
- Container root can read the files (`success/07`). opv never runs the container as root, but an image could escalate inside the container through a setuid binary. That gives no more access to these files than the host user already has.
- Every process of the same host user can read the files and `docker exec` into the container while it runs, as today for a local process (`docs/design/local-delivery.md:41-56`).
- tmpfs pages can be swapped to disk. The app's own core dumps are the image's business (opv disables only its own: `src/runner.rs:1889-1890`).

### 3.10 Tests

**Recordings** (`tests/fixtures/docker/`, README there): 18 success and 9 failure cases recorded for this design. The README lists what is still to record before each refused row of §2 can change: native Docker Engine, rootless Docker, `userns-remap`, Docker Desktop outside WSL, a remote endpoint, Podman rootless and rootful. No test or simulator reply may stand in for those.

| Layer | What | Where |
|---|---|---|
| Unit (D3) | the probe's decision for each recorded reply: `success/01`+`02`+`14` on WSL → `HostUser{1000,1000}`; `failures/05` → `Unavailable{DaemonNotRunning}`; `null` without stderr → `MappingUnknown`; an option name not in the recorded set → `MappingUnknown`; `DOCKER_HOST=tcp://…` → `RemoteEndpoint`; euid 0 → `HostUserIsRoot`; Podman → `NotVerified` until recorded. `run_argv` golden output, and a property test: no environment value ever appears in argv | `src/app/container_tests.rs` |
| Unit (D1) | every load refusal of §3.8; the TOML example loads | `src/config.rs` tests |
| Unit (D2) | each new cause's code, exit, retry, text and `--json`; no step names `local-delivery` or `doctor` | `src/cause/render_tests.rs` |
| Integration (D8) | the real binary `opv local-delivery … --container <plan> -- …` with marker values in its environment and opv-sim's `docker` first on `PATH`: the consumer reads every serve file byte for byte (PEM with a trailing newline); no migration file; the client's environment holds no marker (the sim logs names); argv holds no marker; SIGTERM → exit 143, directory gone, container removed; SIGKILL of the step, then a second run → directory and container swept | `tests/container_delivery.rs` |
| Simulator (D8) | **a fake container runtime**: `opv-sim` gains `docker` (and `podman` once recorded). `world.json` `containers`: `flavour` (`desktop_wsl` from the recordings; others only after recording), `daemon` up or down, `images`, `running` (name, labels, pid). It answers `context inspect`, `info`, `version`, `ps`, `rm -f` only from recordings. `run` checks opv's flags (mount source exists, is opv's tmpfs directory, 0700, files 0400, owned by the uid; `--user` equals it; `--log-driver none`; no `-e NAME=value` other than the directory variable; no `--env-file`/`--privileged`/`--userns=host`), records the call, then runs the container arguments as a local child. Its environment is the `-e` names copied from the client, with the directory variable rewritten from `mount_at` to the source (a documented substitution, as the simulated `ssh` runs the remote side locally: `tests/sim/ssh.rs:251-257`). The exit code and SIGTERM are forwarded. Faults: `daemon_down` (`failures/05`, `06`), `image_absent` (`04`), `command_missing` (`08`), `client_killed_container_survives` (`success/11`) | `tests/sim/container.rs`, `tests/sim/opv_sim.rs` (`TOOLS`) |
| E2E (D8) | snapshots: the preview for the recorded flavour (text and JSON, CLI = MCP); each reachable refusal (`RemoteEndpoint`, `HostUserIsRoot` via the sim's reported euid, `MappingUnknown`, `NotVerified`, `DaemonNotRunning`, `ToolMissing{docker}`, `ContainerSecretWithoutFile`); a canary scan of stdout, stderr, the `--json` document, `calls.log` and the sim state | `tests/e2e/scenarios/container.rs`, `tests/e2e/coverage.rs` (variants not reachable until recorded, such as `Rootless` and `UserNamespaceRemap`, are listed as exempt with that reason) |
| Real tools | the tagged-release verification (§7); the simulator doesn't model `op run` (`tests/sim/op.rs:139` has no `run` arm) | evidence files |

## 4. Code pointers

| Concern | File | Today |
|---|---|---|
| Profile struct | `src/domain/model.rs` (next to `Remote`, `:161-186`; `Product.remotes`, `:153`) | — |
| Load rules | `src/config.rs` (next to `validate_remotes`, called at `:1160`, and `validate_local`, `:1575-1610`) | — |
| Probe, argv, sweep parsing | `src/app/container.rs` (new) | — |
| Step | `src/app/local_delivery.rs:283-350` | runs a process |
| Signals | `src/runner.rs:1893-2190` | directories only |
| Run wiring | `src/app/run.rs:152-158` (`Launch`), `:339-347` (delivery args), `:451-471` (`delivery_args`); `src/main.rs:698-728` (`Run` flags), `:2972-3048` (dispatch) | local and remote |
| Preview | `src/app/delivery_preview.rs:121-226`; MCP `src/mcp.rs:400-415` | local and remote |

## 5. Verbatim bytes for file keys

**What opv does today:**
- **Delivery writes what `op run` gave it**, unchanged: `value.as_bytes()` of the step's environment variable (`src/app/local_delivery.rs:304-317`). A multi-line value and a trailing newline arrive byte for byte (`tests/local_delivery.rs:203-221`). No rule or transform runs in `opv run` on the delivery path.
- **`pem_private_key` is a staging transform.** `rules::check` turns a multi-line PEM into one line before the always-on rules (`src/domain/rules.rs:288-296`; test `:858`). It runs for check, plan and sync (`src/domain/plan.rs:309`), never for delivery. A key with `file` and this transform therefore reaches a local file as the stored multi-line bytes, and a Fly target as one line.
- **The always-on rules** `single_line` and `no_surrounding_space` (`src/domain/rules.rs:297-302`) are applied by `plan::evaluate` **even when the environment has no target** (`src/domain/plan.rs:196-198`, `:309`). So a multi-line file key without a transform fails `opv check` in a run-only environment.
- **The tidy rewrites stored values.** `convention::normalized` trims a trailing `\n`, `\r` or space when the trimmed value passes the rules, for any key without a transform (`src/domain/convention.rs:273-302`). A person's run writes that back into 1Password (`src/app/tidy.rs` `tidy` → `onepassword_tidy::write`). A file key stored as `secret\n` would lose its newline: **this contradicts decision 3**.
- Values are environment variables, so they are UTF-8 without NUL. `std::env::vars()` (`src/app/local_delivery.rs:295`) panics on a non-UTF-8 variable. A binary file value isn't deliverable (§11 R10).

**Changes (D7):**
1. `convention::normalized` returns `None` for a key with `file`. The tidy never rewrites a file key's stored value.
2. `plan::evaluate`: for a key with `file` and no target (`opts.target == None`), `single_line` and `no_surrounding_space` aren't applied. `nonempty`, `max_len` and the prefix rules still are. Where a target stages the key, every rule and the transform apply to the **staged copy only**.
3. The preview shows `bytes: verbatim` and names any `staging_transform` (§3.7).
4. `docs/configuration.md`'s rules reference states the exception.

## 6. Fly: a separate migration app (design only)

**Today:** Fly delivers app secrets to every machine of the app as environment variables at boot. opv syncs them as `FLEET__<PRODUCT>__<KEY>` (or the target's `secret_name`). Journeeze's shim (`jz_host::fleet_secrets`, switched on by `JZ_VAULT_FROM_ENV=fleet`: `ced358d:crates/jz_host/src/fleet_secrets.rs:90-91`, `ced358d:fly.toml:23`) writes the delivered variables as 0400 files on tmpfs and re-execs itself without them (`ced358d:crates/jz_host/src/fleet_secrets.rs:281-316`). Journeeze runs on the infra repo's shared fleet, not on its own Fly app (`ced358d:fly.toml:1-10`). Its migration container gets only its catalog `migration_env` (`ced358d:crates/jz_host/src/fleet_secrets.rs:86-89`, a comment; the infra repo wasn't read **[A7]**).

**Design (decision 2): two Fly apps, two opv targets per environment.**

```toml
[environments.staging.targets.journeeze]            # the serving app
fly = { app = "journeeze-staging" }
products = ["journeeze"]
roles = ["serve"]                                    # new: which roles' keys this target receives

[environments.staging.targets.journeeze-migrate]    # the migration app
fly = { app = "journeeze-migrate-staging" }
products = ["journeeze"]
roles = ["migrate"]
```

1. **Targets take `roles`.** `sync` stages a key to a target only when `select` (`src/app/delivery_preview.rs:59-102`) would deliver it for one of the target's roles. This is the first time roles reach a target; today "Roles never reach `sync` or a target" (`docs/design/local-delivery.md:79`), so that sentence changes. Load rules fail closed:
   - a target that places a product whose keys declare roles must declare `roles`, as `run` needs `--role`;
   - a key whose roles exclude every role of a target is never staged there.
2. **The serving app never receives migration material**, not even in its init process's environment. The one-app limit (every machine's init gets every app secret) no longer applies to the serving app.
3. **The guest step** is the same `local-delivery`, with `--from-env <prefix>` mapping the target's secret names back to keys. It uses the `--role` of its app (`serve` on the serving app; `migrate` in the migration app's one-off machine). Missing or failing keys stop the start with a names-only message.
4. **Verbatim bytes through Fly env.** A Fly secret is an environment variable, and opv stages one line (`src/domain/rules.rs:288-298`). To keep decision 3 for Fly, a file key would be staged as base64 of the stored bytes under a separate name (for example `FLEET__JOURNEEZE__GITHUB_APP_PRIVATE_KEY__B64`), and `--from-env` would decode it. The shim keeps reading the existing name during migration. That is an owner decision for when Fly is implemented (§13 D7).
5. **`[[files]]` with `secret_name`** stays rejected: it lands in the guest's root filesystem, not in RAM.

### 6.1 Migration plan for the shim (human-authorized at every live step)

| Step | Who | Change | Exit criterion |
|---|---|---|---|
| 0 | opv | ship target `roles`, `local-delivery --from-env`, and the base64 file-key staging (if adopted) in a tagged release, with fixture tests: exact bytes including PEM and a trailing newline, migration keys absent from the serving app's synced set, canary values absent from logs | tests in CI; `opv plan` for both targets reviewed |
| 1 | Journeeze maintainers and infra | create the migration app; add opv to the image with a **second**, unused entrypoint; the shim stays the default | image builds; `opv run --preview` for both roles matches §1.1 |
| 2 | a person, staging | switch staging to the opv entrypoint (`JZ_VAULT_FROM_ENV` unset); keep the shim in the image | `MountedSecretStore` reads every §1.1 serve name, **including `github/webhook-secret`**; the serving app's secret list has no migrate key; evidence recorded |
| 3 | a person, production | canary one machine, then all | same checks; rollback is reverting the entrypoint |
| 4 | Journeeze maintainers | remove the shim and close its ADR exception | only after step 3 has run cleanly for an agreed period |

Each step can be reverted without touching values. Existing Fly secret names are kept (the base64 copies are additions).

## 7. Verification against the tagged release

The in-tree fixture proves the mechanism with the build under test (`tests/mounted_consumer.rs:1-8`). This run proves the **released artifact**, through real `op run` and a real container runtime, with Journeeze's real `MountedSecretStore` (`ced358d:crates/jz_secrets/src/lib.rs:11-47`). A person runs it, in their own terminal, after `v0.11.0` is published. No production value is used. The test values are markers entered by the person (human-only value entry), never credentials.

**Where evidence is recorded:** `docs/verification/v0.11.0-container-delivery.md` (the record) and `docs/verification/v0.11.0-container-delivery/` (raw files and the verifier's source). It goes in a PR to `dev`, linked from `CHANGELOG.md` `[0.11.0]` and from #136.

**Prerequisites:**
- Linux or WSL 2 with a user-owned tmpfs `$XDG_RUNTIME_DIR`; Docker Desktop with WSL integration (the recorded flavour). Native Docker Engine and rootless Podman runs are added as extra matrix rows only if their recordings have landed.
- `gh`, `op` signed in as the person, `jq`, `script`, a checkout of `journeeze-saas` at `ced358d`, Rust.
- A test vault holding a test product `jzverify` with a `verify` environment (no target). Its keys are the eleven names of §1.1 with the same `file` and `roles`, plus two container profiles: `serve` (roles serve) and `migrate` (roles migrate), `image = "opv-verify-136@sha256:<digest from V2>"`, `mount_at = "/run/secrets/journeeze"`.
- Marker values, entered by the person: those of `tests/mounted_consumer.rs:13-52`, including the multi-line PEM with a trailing newline and `test-marker-db-url\n` with a trailing newline. The migrate keys hold `test-marker-owner-url` and `test-marker-app-password`. All markers go in `E/markers.txt`, one per line. Whether 1Password stores a trailing newline as entered is **[A8]**; if it can't, the record says so.

**Steps** (`E/` is the evidence directory; every command's stdout, stderr and exit code go to the named file):

| # | Action | Evidence file | Pass |
|---|---|---|---|
| V1 | `gh release download v0.11.0 -R matt-cochran/1password-vault -p opv-x86_64-unknown-linux-musl -p SHA256SUMS -D E/bin`; `(cd E/bin && sha256sum -c --ignore-missing SHA256SUMS)`; `gh attestation verify E/bin/opv-x86_64-unknown-linux-musl -R matt-cochran/1password-vault`; `chmod +x` it; `E/bin/opv-x86_64-unknown-linux-musl --version`; put `E/bin` first on `PATH` as `opv` | `01-download.txt` | checksum OK, attestation verified, version `0.11.0` (asset names and checksums: `.github/workflows/release.yml:91-124`; attestation: `:153`, `:159`) |
| V2 | build the verifier (V-kit below); `docker build -t opv-verify-136 E/kit`; `docker image inspect --format '{{.Id}}' opv-verify-136` | `02-kit-build.txt` | the image id is recorded and used as the profile's digest |
| V3 | `docker version --format '{{json .}}'`; `docker info --format '{{json .SecurityOptions}}'`; `docker context inspect --format '{{json .Endpoints.docker.Host}}'` | `03-runtime.txt` | same shapes as `tests/fixtures/docker/success/01`, `02`, `14` |
| V4 | `opv run verify --product jzverify --role serve --container serve --preview --json`, the same for `migrate`; then the MCP `opv_delivery_preview` call with the same arguments (through `opv mcp serve` and a JSON-RPC client, as `tests/mcp_protocol.py` does) | `04-preview-serve.json`, `04-preview-migrate.json`, `04-mcp-serve.json` | `jq -S` of the CLI and MCP documents are identical; `uid_mapping` is `host_user`; every file key shows `bytes: verbatim`; `withheld_by_role` holds the other role's keys |
| V5 | `opv run verify --product jzverify --role serve --container serve -- check serve` | `05-serve.txt` | 9 lines `<name>: match`; `database/owner-url: absent`; `database/app-password: absent`; `../etc/passwd: refused`; `env: no marker`; exit 0 |
| V6 | the same with `--role migrate --container migrate -- check migrate` | `06-migrate.txt` | the 2 migrate names match; every serve name `absent`; exit 0 |
| V7 | refusals: `opv run verify --product jzverify --container serve -- check serve` (no `--role`: `choice_required`); `DOCKER_HOST=tcp://127.0.0.1:9 opv run verify --product jzverify --role serve --container serve -- check serve` (`container_unsupported`, remote endpoint) | `07-refusals.txt` | the expected codes; exits 2 and 6; each refusal says nothing was read |
| V8 | signal: start `opv run … --role serve --container serve -- hold` (the verifier sleeps); `pkill -TERM -f 'local-delivery'`; then `docker ps -a --filter label=io.opv.uid=$(id -u) --format '{{.Names}}'` and `ls -A "$XDG_RUNTIME_DIR" \| grep '^opv-run\.' \|\| true` | `08-sigterm.txt` | exit 143; no container; no directory |
| V9 | kill: the same with `pkill -KILL -f 'local-delivery'`; `docker ps …` (one container listed); then V5 again; `docker ps …` and `ls …` again | `09-sigkill.txt` | after the second run: no labelled container, no stale directory |
| V10 | canary scan while V8's container runs, and after: `docker inspect <name>` (Env, Args, Mounts); `docker inspect --format '{{.HostConfig.LogConfig.Type}}' <name>`; `ps -eo args`; the step's and the client's `/proc/<pid>/cmdline`; the client's `/proc/<pid>/environ` (the person's own process); `docker history --no-trunc opv-verify-136`; then `grep -c -F -f E/markers.txt` over all of these and over the whole terminal transcript (`script -q E/10-transcript.txt` around V4–V9) | `10-canary.txt` | zero marker hits; log type `none` |
| V11 | optional, owner-approved only: `opv run staging --product journeeze --role serve --container serve --confirm staging` with the real Journeeze image (pinned digest); `curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:18088/readyz` | `11-journeeze.txt` (status codes only) | `/readyz` 200; no value recorded |

**V-kit** (`docs/verification/v0.11.0-container-delivery/kit/`, committed with the evidence):
- `Cargo.toml`: a binary crate that depends on `jz_secrets` and `jz_core` by path, from a `journeeze-saas` worktree at `ced358d` (`git -C journeeze-saas worktree add <dir> ced358d`), plus `tokio` and `sha2`.
- `src/main.rs`, about 80 lines. With `MountedSecretStore::new($JZ_VAULT_DIR)`, mode `check serve|migrate`:
  - reads each §1.1 name and compares its SHA-256 to the marker digests compiled in (markers only, so their digests are public);
  - prints `<name>: match|differ|absent`;
  - reads `../etc/passwd` and expects `PermissionDenied` (`ced358d:crates/jz_secrets/src/lib.rs:23-34`);
  - checks that no environment variable equals a marker.
  Mode `hold` sleeps 60 s. It prints names and verdicts only.
- `Dockerfile`: `FROM debian:bookworm-slim@sha256:<pinned>`, copy the binary, `USER 10001` (as Journeeze: `ced358d:deploy/Dockerfile`), `ENTRYPOINT ["/usr/local/bin/opv-verify-136"]`.

**The record** (`docs/verification/v0.11.0-container-delivery.md`) states:
- who ran it, the date, the host flavour;
- the opv tag and binary SHA-256, the attestation result;
- the Docker versions, the kit's image id and the Journeeze commit;
- one table of V1–V11 with pass or fail and the evidence file;
- any deviation, with the reason.
It contains no value. The markers are listed, because they are not secrets.

## 8. Implementation plan

Each deliverable is one module or one feature in at most four files, with exact pointers. Estimates are hours for a careful worker who reads the pointers first.

| ID | Deliverable | owned_files | Prerequisites | Est. (h) | Acceptance criteria |
|---|---|---|---|---|---|
| D1 | Container profiles in the configuration | `src/domain/model.rs` (add `Container` next to `Remote` `:161-186`; `Product.containers` next to `remotes` `:153`), `src/config.rs` (add `validate_containers`; call it next to `validate_remotes` at `:1160`), `src/cause/config_check.rs` (4 new `ConfigCheck` variants) | — | 5 | The §3.1 TOML loads. Each load refusal of §3.8 has a unit test naming the dotted path: image empty, with whitespace, or starting `-`; `mount_at` relative, `/`, with `..`, or under `/proc` `/sys` `/dev`; unknown runtime; `container_user` with docker; empty or undeclared environments; undeclared roles; a deliverable secret key without `file`; file keys without `secrets_dir_env`; an unpinned image for a `confirm_env` environment (if §13 D5 is adopted). `cargo test` passes. |
| D2 | Catalog causes for containers | `src/cause/mod.rs` (`ContainerUnsupported`, `ContainerWhy`, `ContainerLeft`, `Guard::ContainerProfileRefuses`, `Unanswered::DaemonNotRunning`; codes `:1395-1445`, exits `:1450-1540`), `src/cause/subject.rs` (`System::{Docker,Podman}` `:94`, `NameKind::ContainerProfile` `:166`), `src/cause/render.rs` (text, Do, Next), `docs/design/error-catalog.md` (§4.10 rows, §4.11 new codes) | — | 5 | The code, exit and retry of every §3.8 row are tested. Render tests cover text and `--json` for each `why`. No step names `local-delivery` or `opv doctor`. Every Next round-trips through clap (existing contract test). `human_required` is false. |
| D3 | The probe, argv builder and sweep parser | `src/app/container.rs` (new: `probe`, `decide`, `run_argv`, `parse_labelled`), `src/app/container_tests.rs` (new), `src/app/mod.rs` (`pub mod container;`), `src/host.rs` (`Tool` entries for docker and podman, next to `op` at `:381`) | D2 | 6 | Unit tests read `tests/fixtures/docker/` files verbatim, and the §3.10 D3 cases pass. `run_argv` matches a golden list for the §3.1 profile. A property test with random marker values finds none in the argv. Podman returns `NotVerified` while `tests/fixtures/podman/` is absent. No call or template is used outside those recorded. |
| D4 | The step's container mode and signal cleanup | `src/app/local_delivery.rs` (container mode in `run` `:283-350`: plan parsing, second probe, `sweep_containers`, tracked spawn, `rm -f` after exit), `src/runner.rs` (`signals`: `register_container`/`unregister_container`; `stop_and_exit` `:2037` runs `rm -f` after `forward` and before `run_cleanups`; `track` usable by the step), `src/main.rs` (`LocalDelivery` gets `--container <plan>` at `:883-893` and `:2744-2771`) | D2, D3 | 6 | Unit tests: the plan round-trips; a key that is neither a file nor a planned config name is `Bug`; the client's environment has no secret key and no `OP_*`. Integration tests use a stub that only logs argv and env names, then runs the command (it prints no runtime output, so it invents none): SIGTERM gives 143, the directory is gone and `rm -f` was called; SIGKILL, then a rerun, sweeps. |
| D5 | `opv run --container` | `src/main.rs` (`Run` gets `--container <PROFILE>` `:698-728`; the conflict with `--remote`; preview pass-through `:2983-3005`), `src/app/run.rs` (`Launch::Container` `:152-158`; profile checks like `remote_profile` `:161-201`; the outer probe before `op run`; `container_args` next to `delivery_args` `:451-471`) | D1, D3, D4 | 4 | `opv run dev --role serve --container serve -- x` builds one `op run` call whose argv holds the plan and no value (FakeRunner, as `src/app/run.rs:561-631`). A refused probe makes no `op` call. `--container` with `--remote` is `usage`. `--confirm` is required for `confirm_env`. |
| D6 | Preview, MCP and user docs | `src/app/delivery_preview.rs` (§3.7 fields in `build_for` `:121-226` and `write_text` `:295-388`), `src/mcp.rs` (`container` argument of `opv_delivery_preview` `:400-415`, `:1174-1190`), `docs/mcp.md`, `docs/local-development.md` (a "Containers" section after `:87`) | D1, D3 | 4 | CLI and MCP documents are identical for the same arguments (existing parity test extended). An unknown probe gives `unknown`, never `no`. Each file key shows `bytes: verbatim`. The docs example runs as written against the simulator. |
| D7 | Verbatim bytes for file keys | `src/domain/convention.rs` (`normalized` `:263-303`), `src/domain/plan.rs` (`evaluate` `:290-330`), `docs/configuration.md` (rules reference `:665-680`) | — | 3 | A file key holding a multi-line PEM with a trailing newline passes `opv check` in a run-only environment. The tidy leaves `x\n` in a file key untouched and still trims a non-file key. With a target, a multi-line file key without a transform still fails `single_line`, and with `pem_private_key` it stages one line. |
| D8 | Fake container runtime, integration and E2E | `tests/sim/container.rs` (new), `tests/sim/opv_sim.rs` (`TOOLS` `:37-45`, dispatch), `tests/container_delivery.rs` (new), `tests/e2e/scenarios/container.rs` (new) and `tests/e2e/coverage.rs` (exemptions) | D4, D5, D6 | 8 | Every §3.10 integration, simulator and E2E case passes, and the snapshots are reviewed. A reply without a recording fails with exit 86 (`tests/sim/recordings.rs:9`). The canary scan finds no marker. The coverage gate lists every new variant, as reached or exempt with a reason. |

Critical path: D2 → D3 → D4 → D5 → D8 (29 h). D1, D6 and D7 run in parallel. Total: 41 h. The verification (§7) follows the release tag. Podman support is a follow-up deliverable that needs the README item 6 recordings first.

## 9. Self-vet: poka-yoke

| Mistake | How it is prevented | Kind |
|---|---|---|
| A secret passed as a container variable | load refuses a deliverable secret without `file`; the step refuses an unplanned key; `-e` only by name | Type and test |
| Docker flags smuggled through the person's words | words after `--` go after the image; everything before it comes from `run_argv` | Structure |
| The container runs as a user that can't read, so someone "fixes" it with 0444 | no code path changes modes; refusal with a reason instead | Structure and test |
| A probe reply misread as "no special options" | the parser accepts only recorded shapes; `null` is unknown (`failures/05`) | Test over recordings |
| A bind to a remote host's path | the endpoint must be `unix://` | Test |
| The directory removed before the client exits (Docker Desktop re-creates it as root: `failures/03`) | drop and signal order: client, then `rm -f`, then the directory | Test (D4) |
| A killed client leaves the container (`success/11`) | `rm -f` by name on every path, and the label sweep | Test (D4, D8) |
| Container output written to the daemon's disk logs (`success/16`) | `--log-driver none` always | Golden argv |
| The tidy changes a file key's stored bytes | `normalized` skips file keys | Test (D7) |
| A simulated reply nobody recorded | exit 86 (`tests/sim/recordings.rs:9`) | Existing guard |

## 10. Self-vet: security

Secret bytes must not reach MCP responses, agent context, argv, the environment, logs, or disk outside tmpfs.

| Channel | Control | Residual |
|---|---|---|
| MCP responses | no tool runs a container; the preview reads identifiers and three fixed-template runtime calls; every output passes the `OutputGuard` | Low |
| Agent context | the same as MCP for tools. An agent with a shell as the user can read the files or `docker exec` (R1) | **High, accepted** (decision Q7) |
| argv | the plan and `run_argv` hold names, paths, the image and labels; tested | Low |
| Environment | secrets live only in the step's environment (from `op run`) and never reach the client or container; `OP_*` is stripped (`src/app/local_delivery.rs:182`) | Medium: the step's `/proc/<pid>/environ` is readable by the same user (as today) |
| Logs | `--log-driver none`; opv logs names only; `op run` masks attached output | Low; the app's own logging is the app's |
| Disk outside tmpfs | host check (`statfs`) plus `success/08` (tmpfs inside the container on WSL 2 + Docker Desktop); no layers, no cidfile, no log file | Medium: swap; unrecorded flavours are refused |

## 11. Open risks

| # | Risk | Likelihood / impact | Mitigation or acceptance |
|---|---|---|---|
| R1 | Any process of the same host user, and any agent with that user's shell, can read the tmpfs files, the step's environment, and `docker exec` into the container | likely / high | accepted and documented (decision Q7); not a sandbox |
| R2 | The Docker daemon, host root and the `docker` group read the mount; container root reads it (`success/07`) | certain / high on a shared host | documented; opv never runs the container as root; use only on a host you control |
| R3 | SIGKILL of the step leaves the container running with the files until the next sweep (`success/11`) | unlikely / medium | the label sweep at the next file-delivery run; directory removal empties the mount (`success/13`); logout clears tmpfs |
| R4 | A probe/run race: the daemon or context changes between the step's probe and `docker run` | rare / medium | the step probes with the client's exact environment immediately before; the window is milliseconds |
| R5 | A local `unix://` socket forwarded from a remote daemon (`ssh -L`) passes the endpoint check | rare / high | not detectable from the client; documented. The source path wouldn't exist on the remote host; Docker there would create an empty directory or fail, so the app fails closed |
| R6 | A missing bind source becomes a root-owned directory on Docker Desktop (`failures/03`); a removal race would start the app with no secrets and leave debris the sweep won't touch | rare / low | ordering (§3.5); the app fails closed on missing secrets; the debris is empty and in tmpfs |
| R7 | Exit codes 125 and 127 can be Docker's or the app's (`failures/04`, `06`, `08`) | occasional / low | passed through as the app's (FR-4); the probe catches daemon and endpoint failures first; documented |
| R8 | Swap can write tmpfs pages to disk; the app's core dumps are not opv's | possible / medium | documented, as for local delivery |
| R9 | Killing only the outer `opv run` leaves `op run`, the step and the container running (`src/main.rs:2667-2676`) | occasional / medium | pre-existing; owner decision §13 D8 |
| R10 | A non-UTF-8 environment variable panics the step at `std::env::vars()` (`src/app/local_delivery.rs:295`); values with NUL or non-UTF-8 bytes can't be file keys | rare / low | pre-existing; switch to `vars_os` and refuse a non-UTF-8 file value by name (a small follow-up) |
| R11 | Whether `op run` preserves a trailing newline into the environment, and whether 1Password stores one as entered, is unverified **[A8]** | unknown / medium | §7 V5 tests it with `test-marker-db-url\n` |
| R12 | Native Docker Engine, rootless Docker, `userns-remap`, Podman and Docker Desktop outside WSL are unrecorded | certain / medium (refusals until recorded) | fail closed; the README to-record list |
| R13 | The image itself is trusted with the values | certain / high | the digest rule for `confirm_env` environments; reviewing the profile is the control |
| R14 | `-e NAME` copying a config value from the client relies on Docker's documented behaviour **[A5]** | low / low | D8's simulator checks that config values reach the container; V5 checks it for real |

## 12. Assumptions

- **A1** Journeeze's opv configuration is a 1Password manifest. No `secrets.toml` exists in `journeeze-saas` at `ced358d`.
- **A2** Rootful Docker Engine on native Linux reports the same `info`/`version` shapes and mounts tmpfs the same way as the recorded Docker Desktop engine. It stays refused until recorded.
- **A3** Docker Desktop outside WSL 2 may share host paths through a VM file-sharing layer. It is refused because nothing is recorded.
- **A4** Rootless Podman's `--userns=keep-id[:uid=,gid=]` maps the host user as documented, and `podman info` exposes `rootless` and `serviceIsRemote`. It stays `NotVerified` until recorded.
- **A5** `docker run -e NAME` (no `=`) copies `NAME` from the client's environment.
- **A6** Bind mounts are not part of a container's image layers or of `docker commit` output.
- **A7** The infra launcher's migration container gets only `migration_env`; the infra repo wasn't read.
- **A8** `op run` passes a stored trailing newline into the variable, and 1Password stores one when it is entered.
- **A9** The Journeeze image runs correctly as a uid other than 10001 under Docker's `--user` (it has no passwd entry for the host uid; its `/app` files are root-owned and world-readable from `COPY`). V11 checks it.

## 13. Owner decisions needed

| # | Decision | Recommendation |
|---|---|---|
| D1 | A reviewed container profile (`--container <profile>`) rather than `--container <runtime> -- <docker args>` | adopt (§3.1) |
| D2 | Allow `-- <args>` to replace the profile's `command` (container arguments only) | allow; they never reach the runtime's flag parser |
| D3 | Rootless Docker refused in 0.11.0. It could be supported by running as container root, which maps to the host user. | refuse; container root is the wrong default |
| D4 | Docker Desktop accepted only on WSL 2 (the recorded flavour) | adopt; widen per recording |
| D5 | A digest-pinned `image` required for `confirm_env` environments | adopt |
| D6 | File keys exempt from `single_line`/`no_surrounding_space` where no target stages them, and never tidied (§5) | adopt; it follows from decision 3 |
| D7 | Fly: stage file keys as base64 under a `__B64` name so Fly delivery is verbatim | decide when Fly is implemented |
| D8 | Close the outer-kill gap (R9), for example by having the step leave when its parent `op run` is gone | a follow-up issue; not container-specific |
| D9 | Target-level `roles` for the migration app (changes `docs/design/local-delivery.md:79`) | adopt with Fly |
| D10 | Evidence location `docs/verification/`; whether V11 (real Journeeze image, staging values) is run | adopt the location; V11 at the owner's discretion |
| D11 | Who records the Podman and native-Engine replies (README items 1–7), and whether Podman ships in 0.11.0 | record before the 0.11.0 tag, or ship Podman as `not_verified` |

## 14. What stays out of scope

- Remote development delivery (#139) has its own design: [remote delivery](remote-delivery.md).
- Kubernetes and Azure mounted delivery (#40–#42) are deferred.
- Windows and macOS file delivery stays refused: neither has a user-owned RAM filesystem opv can verify.
- Implementing Fly (§6) and retiring the shim are later releases.
