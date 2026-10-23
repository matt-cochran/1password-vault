# Provider operations under a target's deploy credentials (#234)

Status: draft for 0.17.0, revised 2026-10-23 after the DESIGN-FMECA vet
([provider-operations-fmeca.md](provider-operations-fmeca.md): ready with changes; every High
and Medium change is applied below, with vet risk ids in brackets). Awaiting the owner's
decisions (§8) and the spikes (§9). Issue #234 (Tracking CI). Nothing here is built. Citations
are against `v0170/design-234` (`22f51c94`; HEAD differs only by the design files).

## 1. Intent

Tracking CI runs under a target-scoped 1Password service account (values read; state read and
write). Its Fly target `staging` (app `mcproductlabs-tracking-staging`) already records
`deploy_credentials`, an app-scoped deploy token minted by `opv target credentials --create`
(`flyctl tokens create deploy --app <app> --name <name> --expiry 2160h`,
`src/adapters/fly/login.rs:87-98`) and stored as `op://<state_vault>/<item>`
(`src/app/target_credentials.rs:373`). `plan` and `sync` already sign in with it
(`src/app/signin.rs:326-363`).

Two more CI jobs need that same identity and nothing wider:

1. the **retained-image publisher** pushes `registry.fly.io/mcproductlabs-tracking-staging:<tag>`;
2. the **Machine reconciler** lists that app's Machines and points them at a retained image.

Today they cannot get it without copying the token (`opv run` takes product settings only, and a
shared key's `from` refuses an arbitrary `op://` reference). This design adds a **closed set of
reviewed provider operations** that opv runs itself, as the runtime that carries the value: opv
reads the target's deploy credentials once, runs the one platform tool the operation names with a
fixed argv, hands the token over by stdin (docker) or the child's environment (flyctl, which
offers nothing else), scrubs the output and removes what the tool stored on disk.

### 1.1 Non-goals

- **No secret export.** No operation prints, returns, writes to a caller's path, or puts in an env
  a caller controls, any credential or value. There is no `--print`, `--env-file` or `--output`.
- **No general exec.** The caller names an operation, never a program, an argv, a flag or a
  shell string. There is no `-- <cmd>` form and no passthrough of unknown flags.
- **No new identity, grant or role.** The operation uses exactly the item the target records; it
  never falls back to another target's credentials, the person's own `flyctl` login, a shell
  `FLY_API_TOKEN` or an organization token. opv invents no permission layer: what the token can do
  at Fly and what the service account can read in 1Password decide.
- **No 1Password writes, generation, rotation or import.** The operation reads one item. Minting
  stays with `opv target credentials`, which refuses re-minting
  (`src/app/target_credentials.rs:91-98`).
- **opv writes no secret to a file.** The one credential on disk is the registry auth that
  `docker login` itself stores in opv's private RAM directory, the same exception SR-4 already
  makes for `az` (§5.3, D2).
- **No build.** opv pushes an image the caller built and loaded into the local daemon.
- **Fly only in v1.** Another provider's operations are a later, separately reviewed addition.

## 2. Operations (v1, Fly)

Each operation is a row in a static table compiled into opv. Its programs, every argv word and
every slot are fixed; a slot takes only a value that passed its validator (§4). `<app>` is always
the target's `fly.app` from the configuration, never a caller input.

| Operation | Kind | Calls, in order (fixed argv) | Caller slots |
|---|---|---|---|
| `machines` | read | `flyctl machine list --app <app> --json` | none |
| `machine-update` | write | `flyctl machine list --app <app> --json`; `flyctl machine update <id> --app <app> --image <image> --yes` | `--machine <id>`, `--image registry.fly.io/<app>:<tag>` or `…@sha256:<64 hex>` |
| `registry-push` | write | before the read: `docker context inspect --format '{{.Endpoints.docker.Host}}'`, `docker image inspect --format '{{.Id}}' <image>`; after: `docker login registry.fly.io -u x --password-stdin`, `docker push <image>` | `--image registry.fly.io/<app>:<tag>` |

Rules:

- **O1.** Programs are the literal names `docker` and `flyctl`, resolved from `PATH` as every opv
  call is (`Command::new(call.program)`, `src/runner.rs:1781-1798`); no shell anywhere, so no
  expansion, globbing or word splitting.
- **O2.** Every argv word is a separate element. Caller values appear only in the slots shown and
  only after validation; none can begin with `-` (§4, P6). No argv word holds a credential.
- **O3.** `machine-update` changes only the image. It never passes `--env`, `--file-*`,
  `--command`, `--entrypoint`, `--metadata`, `--vm-*`, `--config`, `--dockerfile`,
  `--autostart`, `--autostop`, `--restart` or a build flag (all in `flyctl machine update --help`,
  v0.4.120). Whether flyctl applies defaults or reads a `fly.toml` when they are absent is S4.
- **O4.** `machine-update` first lists the app's Machines under the same token and refuses an id
  not in that listing (`MachineNotInApp`, a definite refusal before any write), so a mistyped id
  never becomes "outcome unknown".
- **O5.** The listing is deserialized into a typed struct of the projected fields only (`id`,
  `name`, `state`, `region`, image repository, tag and digest); never a `serde_json::Value`, so
  each Machine's `config.env` and metadata are skipped by serde and never printed [S11].
- **O6.** Adding an operation, a flag or a program is a code change reviewed like this one. No
  configuration extends the table.

## 3. Surface

### 3.1 CLI

```text
opv target op <env> --target <name> machines [--json]
opv target op <env> --target <name> machine-update --machine <id> --image <ref> [--confirm <env>]
opv target op <env> --target <name> registry-push  --image registry.fly.io/<app>:<tag> [--confirm <env>]
```

A new `TargetCmd::Op` beside `List` and `Credentials` (`src/main.rs:1640-1665`). The operation is
a clap `ValueEnum` and `--target` is a required clap argument (as for `Credentials`,
`src/main.rs:1658-1659`), so an unknown operation or a missing target is a `usage` error before
anything runs. Output: one value-free line per operation (`pushed registry.fly.io/<app>:<tag>
sha256:<digest>`, `updated machine <id> to <image>`), `--json` with the same fields, and one line
appended to the job summary through `step_summary` (`src/runner.rs:257`).

A `machine-update` that applied the image but failed its health wait is `outcome_unknown` (9);
the skill documents re-running `machines` as the reconciler's follow-up.

### 3.2 MCP and assistant

Not exposed as an MCP tool: the MCP server runs on a runner that refuses every write
(`src/mcp.rs:1-3`) and refuses 1Password writes under CI (`src/mcp.rs:544-553`). `opv explain` and
the skill describe the operations so an assistant can write the CI steps.

### 3.3 How the target is bound

The operation resolves `env` and `target` from the loaded configuration exactly as
`sync --target` does, and reads from that one target section only: the provider (must be Fly,
P3); `fly.app` (validated at load, `src/adapters/fly/config.rs:232-235`,
`src/config.rs:2701-2707`, and checked again against Docker's repository grammar for
`registry-push`, P6); `deploy_credentials` (must be present, P4). The caller supplies only the
names `env` and `target`; it cannot supply an app, a registry host, an item reference or a token.

### 3.4 Requirements touched

FR-40 lists the commands that read `deploy_credentials` ("`status`, `plan`, `sync`, `doctor
--env`", `docs/design/requirements.md:785`); `target op` is added. FR-40's "never reach … files
(except az's own private directory, SR-4)" and SR-4's exception
(`docs/design/requirements.md:1086-1090`) gain docker's private `DOCKER_CONFIG` in the same
wording as az's. Both amendments are D2; L4 writes them once approved [P3].

## 4. Admission: fail closed before any credential read

Admission runs in this order; the first failure wins; **no `op` call has been made** when it
refuses. P1–P6 are pure; P7–P10 add only credential-free local checks.

| # | Rule | Refusal (code, exit) |
|---|---|---|
| P1 | The environment exists | `NotDeclared { kind: Environment }` (`unknown_env`, 2; `src/cause/mod.rs:1883-1885`) |
| P2 | `--target` names a target of that environment | `NotDeclared { kind: Target }` (`unknown_target`, 2) |
| P3 | The target's provider offers the operation (v1: Fly) | `Guard::OperationRefused { WrongProvider }` (`policy_refused`, 6) |
| P4 | The target records `deploy_credentials` | `Guard::OperationRefused { NoDeployCredentials }` (6); step: `opv target credentials <env> --target <t> --create` |
| P5 | A write on an environment with `confirm_env` has `--confirm <env>` equal to it | `run::require_confirmation` as is (`src/app/run.rs:34-55`): `confirm_required` / `confirm_mismatch`. Stricter in timing than `sync`, whose guard runs after its reads (`src/app/sync.rs:649-657`) |
| P6 | Each slot matches its validator; the image repository is `registry.fly.io/<bound app>` | `Usage { ValueFormat }` (`usage`, 2), or `Guard::OperationRefused { ImageOutsideApp }` (6) |
| P7 | The program is on `PATH` (`docker` probe with `--version`, never touching the daemon) | `ToolMissing` (`dependency_missing`) |
| P8 | `registry-push`: a user-owned RAM-backed `$XDG_RUNTIME_DIR` (Linux; macOS and Windows refuse in v1) | `RamDirUnavailable { purpose: RegistryPush }` (`ram_dir_unavailable`) |
| P9 | `registry-push`: `DOCKER_CONTEXT` unset; the endpoint from `docker context inspect` (run with the person's own docker configuration, no credential involved) is `unix://…` | `Guard::OperationRefused { RemoteDockerDaemon }` (6) |
| P10 | `registry-push`: `docker image inspect <image>` against that endpoint finds the image | `Guard::OperationRefused { ImageNotLocal }` (6) |

Validators (P6), anchored, ASCII only, no `-` first:

- tag `^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`; digest `^sha256:[0-9a-f]{64}$`;
- image: exactly `registry.fly.io/` + bound app + (`:` tag | `@` digest); `registry-push` takes a
  tag only;
- bound app, for `registry-push`: Docker's path component
  `^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`, since `is_id` allows upper case and separator runs
  that Docker refuses [T2];
- machine id `^[0-9a-f]{14}$` (observed shape; S3 confirms; too narrow fails closed as `usage`).

After the read, failures are classified **by step**, not by parsing reply text [C13]:

| Step and outcome | Cause (exit) |
|---|---|
| Item missing, unreadable, wrong field type, duplicate or missing `FLY_API_TOKEN` | existing refusals of `read_deploy_credentials` (`src/adapters/onepassword.rs:983-1030`), surfaced as `deploy_credentials_failed` (7) |
| flyctl 401/403 (expired or revoked token) | `CredentialRejected { DeployCredentials }` (7), the existing Fly diagnosis (tested at `src/adapters/fly/mod.rs:948-964`) |
| `docker login` refused with the recorded `unauthorized` reply (S1) | `CredentialRejected { system: Docker, DeployCredentials }` (7); nothing was pushed |
| `docker login` fails otherwise (network, daemon) | `Unavailable` (`provider_unavailable`, 9); nothing was pushed |
| After login, `config.json` is not exactly the expected shape (§5.3 step 6) | directory removed; `Guard::OperationRefused { CredentialStoreEscaped }` (6), naming `docker logout registry.fly.io` under the person's own configuration |
| Machine id not in the app's listing | `Guard::OperationRefused { MachineNotInApp }` (6), before any write |
| `docker push` or `machine update` fails, times out or is killed | `WriteOutcomeUnknown` (`outcome_unknown`, 9), scrubbed excerpt, never retried |
| `docker push` exits 0 without a parsable `digest:` line | `UnexpectedOutput { during: AppliedWrite }`, as the token mint does (`src/adapters/fly/login.rs:122-144`) [T3] |
| `machines` read fails | existing read diagnosis (retries, `provider_unavailable`, `not_found`) |
| Private directory or seed file cannot be made or checked | `PrivateDirFailed` (`private_dir_failed`) |

New in the catalog, all in Step 0 [S3, P4]:

- `Guard::OperationRefused { env, target, operation, reason }`, code `policy_refused`, exit 6,
  retry `never`; reasons `WrongProvider { provider }`, `NoDeployCredentials`,
  `ImageOutsideApp { app }`, `RemoteDockerDaemon`, `ImageNotLocal { image }`,
  `CredentialStoreEscaped`, `MachineNotInApp { machine }`.
- `RamPurpose::RegistryPush` beside `FileDelivery` and `AzureDeployCredentials`
  (`src/cause/mod.rs:1770-1777`).
- `System::Docker` (label, render rows, codes) and `"docker" => System::Docker` in the runner's
  program-to-system map (`src/runner.rs:993-1008`). Without it no docker call can be observed,
  and every cause carrying `seen: Observed` (`CredentialRejected`, `WriteOutcomeUnknown`,
  `src/cause/mod.rs:691-695`, `:752-756`) could not be built.
- A `docker` `Tool` in `src/host.rs` (`version_args: ["--version"]`, pinned `NO_COLOR=1`).

**P4 differs from `sync`'s sign-in on purpose.** `deploy_sign_in` returns `Ok` without signing in
when the target has no `deploy_credentials`, and picks the only target when none is named
(`src/app/signin.rs:326-345`), so `sync` then runs under the machine's own `flyctl` login. An
operation must never do that. It uses a strict entry point, `signin::open_for_operation`, built
on the existing `sign_in_with` (`src/app/signin.rs:303-321`, no copy), that refuses both cases.

## 5. Credential handling, end to end

### 5.1 Common path

1. Admission (§4) passes.
2. The item is read once through `onepassword::read_deploy_credentials`, field `FLY_API_TOKEN`
   only (`src/adapters/fly/login.rs:18-22`), under the principal `DeployCredentials { vault, item,
   env, target }`, so any rejection names that item, never a person's login
   (`src/app/signin.rs:303-321`, `:355-362`).
3. The value is a zeroizing `SecretValue`, registered with the scrubber like every field read
   (`src/adapters/onepassword.rs:1134-1137`, `src/scrub.rs:7-12`); Fly's `FlyV1 …` shape is also a
   scrub pattern (`src/scrub.rs:328-330`).
4. It is dropped when the operation ends (`src/provider.rs:181-195`).

### 5.2 `machines` and `machine-update` (flyctl)

flyctl takes a token from `FLY_API_TOKEN`/`FLY_ACCESS_TOKEN` or `-t` (argv, forbidden by SR-3); it
has no stdin input. As in `plan`/`sync`, `open_for_operation` signs `FlyLogin` in and
`FlyLogin::env("flyctl")` puts the token in the child's environment only, both variables, so the
target's identity overrides any shell token (`src/adapters/fly/login.rs:1-4`, `:172-181`; merged
by `EnvRunner::extra`, `src/app/signin.rs:377-390`). No file is written. The calls run under the
deploy principal through the existing `as_principal` (`src/app/signin.rs:367-374`).
`machine-update` is a `Call::rollout()` write (`src/runner.rs:83-91`, `:325`), never retried
(`src/runner.rs:185-187`).

### 5.3 `registry-push` (docker)

`docker push` reads registry auth only from its configuration directory (no stdin, pipe or env
input; `DOCKER_AUTH_CONFIG` is not in the 27.5.1 CLI, vet §0.1). `docker login --password-stdin`
takes the token on stdin and stores it in that directory. The operation does **not** use
`FlyLogin` (whose `env` stays flyctl-only; a unit test pins `env("docker")` empty) [S4]:

1. **RAM check and sweep** (P8): a user-owned tmpfs/ramfs `$XDG_RUNTIME_DIR`; directories
   `opv-docker.<pid>-*` of dead runs are removed (`src/ramdir.rs:62-84`), as for Azure
   (`src/adapters/azure/login.rs:1-22`).
2. **Endpoint and image** (P9, P10), credential-free. The resolved `unix://` endpoint is passed as
   `DOCKER_HOST` to every later docker call, so the fresh `DOCKER_CONFIG` (which drops the
   person's `currentContext`) cannot send the push to another or absent daemon [S7].
3. **Private directory and seed.** `PrivateDir::create(base, "opv-docker.")`: a fresh path, mode
   0700 at creation, ownership and mode re-checked, registered for signal cleanup
   (`src/ramdir.rs:149-200`; `src/runner.rs:2201-2215`). Inside it opv writes a seed `config.json`
   holding **no secret**, `{"auths":{"opv.invalid":{}}}`, with `O_CREAT|O_EXCL|O_NOFOLLOW`, mode
   0600. A config that already holds an `auths` entry stops docker's credential-helper
   auto-detection, so `login` writes to the file store in this directory; with an empty directory
   and a `docker-credential-secretservice` on `PATH`, docker stores the token in the helper and
   records `credsStore` (proven offline on docker 27.5.1, vet §0.1). Docker keeps the seed's 0600.
4. **Read the item** under the deploy principal (§5.1) and hold the `SecretValue` in the
   operation; register `x:<token>` and its base64 as secrets first (docker's file holds that
   encoding; the scrubber matches each value's base64, not that composite, `src/scrub.rs:10-12`).
5. **Login.** `docker login registry.fly.io -u x --password-stdin`, the token as stdin from a
   `Zeroizing<Vec<u8>>` dropped right after the call (`Call::with_stdin`,
   `src/runner.rs:96-99`), with `DOCKER_CONFIG=<dir>`, `DOCKER_HOST=<endpoint>`, the isolated
   environment (§5.5), run explicitly inside `runner::under_deploy(principal, …)`
   (`src/runner.rs:935`), because `as_principal` applies only to programs the login gives an
   environment (`src/app/signin.rs:367-374`) [S3]. With a reachable daemon the daemon performs
   the login (vet §0.1), so the token reaches only the local daemon the push uses.
6. **Shape check** [S2]: `config.json` must have `auths["registry.fly.io"].auth` and neither
   `credsStore` nor `credHelpers`. Anything else (a future docker that ignores the seed): remove
   the directory and refuse `CredentialStoreEscaped`. This verifies the outcome, not only the
   precondition; a changed config format fails closed.
7. **Push.** `docker push <image>` as a write, same environment; opv parses the final
   `digest: sha256:<hex>` line for its report.
8. **Drop the directory** on every exit path: return, error (drop), SIGINT/SIGTERM (the handler
   removes registered directories after stopping the child; `src/ramdir.rs:213-218`). Removal
   retries apply on Windows only (`src/ramdir.rs:130-147`), which this Linux-only operation never
   reaches. A SIGKILL leaves the 0600 file in RAM until the next run's sweep or a reboot, the
   accepted Azure precedent [S9].

What still sees the token: the registry (twice: login and push) and the local root-equivalent
Docker daemon, inherent to `docker push` [S13].

### 5.4 Output and diagnostics

- Child stdout is never printed; opv prints its own value-free line (§3.1).
- stderr is held in memory (last 64 KiB, zeroized) and shown only as the failure excerpt or under
  `--verbose`, after every registered value and token pattern is replaced
  (`src/runner.rs:337`, `:593-625`; `src/scrub.rs:1-5`, `:412-420`).
- `--verbose` shows program and argv only, never stdin or env (`src/runner.rs:373-378`); argv
  holds no credential (O2). The resolved docker endpoint (a socket path) may appear there.
- JSON errors, the job summary and any evidence carry names, ids, image references and digests.

### 5.5 Child environment

Since opv 0.16.1 every non-`op` child loses `OP_SESSION*`, `OP_SERVICE_ACCOUNT_TOKEN` and
`OP_CONNECT_TOKEN` (`strip_session_vars` in `src/runner.rs`, commit `8ea32e30`, branch
`v0161/strip-sa-token`), so the 1Password token no longer reaches flyctl, az, kubectl or gh in any
command. Operation children go further, because they run in CI jobs that hold other tokens
(`GITHUB_TOKEN`, Actions runtime tokens, stray `FLY_*`, `DOCKER_AUTH_CONFIG`): they get
`env_clear()` plus an allowlist.

The allowlist **extends the existing `local_delivery::BASICS`** (`src/app/local_delivery.rs:38-51`:
`PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `TERM`, `COLORTERM`, `NO_COLOR`, `LANG`, `LANGUAGE`,
`TZ`, `TMPDIR`, and `LC_*`) with the NR-29 proxy and CA names (`HTTP_PROXY`, `HTTPS_PROXY`,
`NO_PROXY`, `ALL_PROXY` in both cases, `SSL_CERT_FILE`, `SSL_CERT_DIR`), `XDG_RUNTIME_DIR`, and on
Windows `SystemRoot`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `TEMP`, `TMP`, `PATHEXT`,
`ComSpec` (Go and flyctl need them) [S5, S6]. The list moves to one shared place (`src/host.rs`)
used by both local delivery and operations; there is no second copy. On top come the tool's
pinned variables (`src/adapters/fly/mod.rs:79`) and the operation's own (`FLY_API_TOKEN`,
`FLY_ACCESS_TOKEN` for flyctl; `DOCKER_CONFIG`, `DOCKER_HOST` for docker).

Mechanism: a scoped runner setting `runner::isolated_env(allow, || …)`, thread-local like
`under_deploy` (`src/runner.rs:935`, `:967-985`), read by `command_for`, which runs on the
caller's thread (`src/runner.rs:1541-1550`). No `Call` field changes. `sync`/`plan` keep their
inherited environment (already free of 1Password tokens).

## 6. Security analysis

| Id | Threat | Mitigation |
|---|---|---|
| X1 | argv injection: a caller value read as a flag or a second argument | closed table (O1, O6); slots validated, anchored, no leading `-` (P6); argv as elements, no shell |
| X2 | Shell expansion | no shell; `Command::new` with an argv vector (`src/runner.rs:1782`) |
| X3 | Unreviewed executable | program names fixed per operation; no caller program, path or plugin |
| X4 | Dangerous flag override (`--env`, `--file-local`, `--config`, `-t`, `--entrypoint`) | the template has no slot for any flag (O3) |
| X5 | Target confusion | app from the bound target (§3.3); image repository must equal it (P6); machine id must be in that app's listing (O4); the token is app-scoped at Fly (`--app` at mint, `src/adapters/fly/login.rs:93-95`) |
| X6 | Cross-target or ambient credential fallback | strict `open_for_operation` (P4), `--target` required; the login's env overrides shell Fly tokens (`src/adapters/fly/login.rs:172-181`); docker gets a fresh config, never the person's |
| X7 | Token on argv, stdout or diagnostics | stdin (docker) or child env (flyctl) only; stdout never echoed; stderr scrubbed by value, base64 forms, `x:token` composite and patterns |
| X8 | Env leakage to children | 1Password tokens stripped from every non-`op` child (`8ea32e30`); operation children allowlisted (§5.5) |
| X9 | opv writing a credential file | none: the seed holds no secret; docker writes the auth (§5.3); a source guard test asserts `provider_op` and `fly::operations` never write a `SecretValue` to a file |
| X10 | Credential persisted outside the run (keyring, helper) | seed config stops helper detection; post-login shape check fails closed (§5.3 steps 3, 6); a logging fake helper in e2e must never be called |
| X11 | Token sent to a remote or wrong daemon | `DOCKER_CONTEXT` refused; endpoint resolved and required `unix://`; pinned as `DOCKER_HOST` (P9) |
| X12 | Another same-user process reads the token | 0600 file in a 0700 user-owned RAM directory; core dumps off, inherited descriptors close-on-exec (`src/hardening.rs:1-40`); flyctl's env exposure is the same as `sync` today |
| X13 | `machine-update` changes more than the image | only `--image` passed (O3); S4 proves flyctl changes nothing else, also with a conflicting `fly.toml` in the working directory; if it reads one, the child runs in an empty private working directory |
| X14 | CI misuse: a job pushes to or updates production | opv adds no permission: reading the production item in 1Password is the authorization, which the owner grants or withholds; `--confirm` records intent only [S12, owner-accepted model] |
| X15 | A malicious or defective `docker`/`flyctl` | out of scope (owner principle), same trust as `sync`; this includes flyctl persisting an env token (former S5) |
| X16 | Settings or values changed through an operation | no product value read, no 1Password write; `plan`/`sync`/`run` paths untouched (the strict sign-in and `isolated_env` are separate entry points) |

Residual risks: a SIGKILL during `registry-push` leaves the auth in a RAM file until the next run
or reboot (Medium severity, Low probability; Azure precedent); the local Docker daemon sees the
token (inherent); the token's 90-day expiry breaks both jobs on day 91 with exit 7 naming the item
(pre-existing, as for `sync`; the render must match `sync`'s).

## 7. Feasibility

Verified in code (cited above): the deploy-credential read and its principal; Fly's env-only
token hand-off; the app-scoped mint; the private RAM directory, sweep and signal cleanup (reused);
no-shell spawning, stdin piping, stderr capture and scrubbing; `require_confirmation`; the catalog
entries reused; the observation map that needs `System::Docker`.

Verified with tools: flyctl v0.4.120 help for `machine list --json`, `machine update --image
--yes` and the excluded flags (it also shows defaults for `--autostart` and `--autostop`, hence
S4); docker 27.5.1 offline (vet §0.1): an empty `DOCKER_CONFIG` sends `login` to a helper on
`PATH`, a placeholder seed keeps it in the file at 0600, `DOCKER_CONTEXT` with a fresh config
fails at start.

Still unknown, listed with owners in §9: Fly's registry with a deploy token (S1), token scoping at
Fly (S2), Machine id shape (S3), what an `--image`-only update changes (S4), and Tracking CI's
runner and publisher (S6, Q1, Q2).

## 8. Decisions for the owner

Each decision below is written for a reader who has not seen the code.

**D1. How the registry push gets the token.** `docker push` cannot take a credential on stdin or
in its environment; it reads it from a `config.json` in a directory. So for one push the token
must sit in some file, and the question is who writes it and where.
- (a) *opv writes `config.json` with the token itself.* One child process. But opv would then
  write a secret to a file, which SR-4 forbids for opv outright.
- (b′) *opv writes a `config.json` with no secret (a placeholder entry), then runs
  `docker login -u x --password-stdin` with the token on stdin; docker writes the auth into that
  file.* This is exactly how the existing Azure sign-in works (`az login -p @<stdin>` into a
  private directory). The placeholder stops docker from moving the token into the machine's
  keyring, and opv checks the file afterwards and refuses if docker stored it anywhere else.
- (d) *`flyctl deploy --build-only --push`*: no file at all, but opv would run the caller's Docker
  build (Dockerfile, build arguments, context), a far wider contract.
- **Recommendation: (b′).** Cost: one more call (`docker login`), so the token goes to the
  registry twice; in return the login is a clean credential check before anything is pushed
  (exit 7 vs 9 without parsing error text).

**D2. Amend SR-4 and FR-40 for docker.** SR-4 today allows exactly one credential on disk: the
secret `az` itself stores in opv's private RAM directory. Docker needs the same allowance, or
`registry-push` cannot exist. Proposed text, same conditions as az's: "With Fly
`deploy_credentials`, `registry-push` lets the Docker CLI itself store the registry auth in opv's
per-run `DOCKER_CONFIG` (Linux: `$XDG_RUNTIME_DIR` on tmpfs, mode 0700; file 0600), removed on
every exit path and swept after a killed run; opv itself still writes no secret to any file."
FR-40 also adds `target op` to the commands that read `deploy_credentials`.
- **Recommendation: approve both.** Cost: a second named exception in SR-4.

**D3. A runner with no RAM runtime directory.** `registry-push` needs a user-owned tmpfs
`$XDG_RUNTIME_DIR` so docker's file never touches a disk. GitHub-hosted Ubuntu runners have one;
container jobs and some self-hosted runners do not. Options:
- (a) *Refuse there* (`ram_dir_unavailable`, nothing read) and document how to provide one, e.g.
  a container job with `--tmpfs /run/user/<uid>` and `XDG_RUNTIME_DIR` set to it.
- (b) *Fall back to a 0700 directory on disk* on such runners. Works everywhere, but the token
  would be written to disk, breaking SR-4's RAM-only rule for Linux and the Azure precedent.
- (c) *Make the runner's own `/dev/shm` an accepted base* when it is tmpfs and user-writable
  (it usually is in containers), still RAM, still 0700. Small extension of the RAM check.
- **Recommendation: (a) now, with the documented remedy; consider (c) only if S6 shows Tracking
  CI's runner lacks a runtime directory.** Cost of (a): that runner cannot publish until its job
  provides a tmpfs.

**D4. Which Machine operations ship.** (a) *list, and update image only*: the reconciler can see
the app and move each Machine to a retained image; nothing else. (b) also *`flyctl deploy --image`
with the repository's `fly.toml`*: closer to common CI, but the reviewed contract then includes a
whole config file the caller controls. (c) also start/stop/restart/destroy.
- **Recommendation: (a)**, confirmed by Q2 before building; add rows one review at a time.

**D5. Which images an operation may name.** (a) *only `registry.fly.io/<the target's app>`*: a
compromised CI job cannot point staging at an arbitrary public image, and a push cannot land in
another repository. (b) *any image*: more flexible, but the operation becomes "run anything on
the app".
- **Recommendation: (a).**

**D6. Command shape.** (a) *`opv target op <env> --target <t> <operation>`*, next to `target
credentials`, which minted the identity; not an MCP tool. (b) top-level `opv fly push` etc.
- **Recommendation: (a).**

**D7. Write gate.** Writes need `--confirm <env>` where the environment sets `confirm_env` (as
`run` and `sync`), and `--target` is always explicit. No other gate: access to the item in
1Password is the authorization; `--confirm` records intent, it does not authorize.
- **Recommendation: adopt.**

**D8. Platforms.** `registry-push` on Linux only in v1 (macOS and Windows refuse, like Azure on
macOS). flyctl operations run where flyctl runs, with the Windows variables of §5.5, checked in
the native Windows/macOS CI jobs.
- **Recommendation: adopt.**

**D9. Evidence.** Operations write nothing to 1Password (CI is values-read); they print and
summarize image, digest and Machine ids. A receipt for images would be a separate feature.
- **Recommendation: adopt.**

**D10. Shipping order.** The flyctl pair depends only on S2–S4; `registry-push` also depends on
Q1, S1 and S6, which are outside opv's control.
- (a) *one release with both* if all gates pass in time; (b) *ship `machines` and
  `machine-update` first*, `registry-push` when its gates pass.
- **Recommendation: (b) if any docker gate is still open when the flyctl lanes are done.** Cost:
  the publisher waits one release.

### 8.1 Owner decisions (2026-10-23)

- **Approved as recommended:** D1 (b′), D2 (the SR-4/FR-40 amendment), D3 (a), D4–D10.
- **Scope:** all three operations in 0.17.0, flyctl first. If Q1, S6 or the docker fixtures are
  still open when the flyctl lanes finish, `machines` and `machine-update` ship in 0.17.0 and
  `registry-push` follows in 0.17.x (D10).
- **Spikes S1–S4 are skipped.** The first real Tracking CI run serves as the spike. Because of
  that, the flyctl replies the simulator serves are built from flyctl's documented JSON and marked
  `"recorded": false` in their fixture file, an exception to the recordings-only rule
  (`tests/sim/opv_sim.rs:9-13`), until that run's replies replace them. The docker replies are
  recorded offline against a local fake registry (S1-off), with no credentials.
- **Q1, Q2 and S6** were asked on #234 on 2026-10-23. Their answers gate L3b and the docker half
  of L5.

## 9. Spikes and questions before implementation

| Id | What | Who | Blocks |
|---|---|---|---|
| S1 | `docker login registry.fly.io -u x --password-stdin` with the app-scoped deploy token: which password form (whole `FlyV1 …` string or part); push succeeds; record replies for an expired/revoked token and for another app's repository | owner, throwaway Fly app and minted token | `registry-push` |
| S1-off | The seed/helper probe (vet §0.1) on Tracking CI's docker version, then automated in e2e with a fake registry on 127.0.0.1 and a logging fake helper | opv lane L5 (no credentials) | `registry-push` |
| S2 | Deploy token accepted by `machine list`/`update` for its app, refused for another; record both | owner, throwaway Fly app | flyctl operations |
| S3 | Machine id shape | owner (live listing) or flyctl source | P6 |
| S4 | `--image`-only update leaves the Machine config unchanged (autostart, autostop, restart, services, env, compared with `flyctl machine status --json` before and after), run from a directory holding a `fly.toml` with conflicting settings | owner, throwaway Fly app | `machine-update` |
| S6 | In Tracking CI's actual job: a user-owned tmpfs `$XDG_RUNTIME_DIR`, a local Unix-socket daemon, the built image present in it | Tracking CI requester | `registry-push`, D3 |
| Q1 | Which tool publishes (`docker push` of a loaded image, or buildx/`build-push-action`, crane, skopeo, where the image is never in the daemon) | Tracking CI requester | docker half of L3/L5 |
| Q2 | Which flyctl calls the reconciler makes today | Tracking CI requester | flyctl rows of L3 |

Each owner spike is handed over as one script file and one short command, recording replies
straight into `tests/fixtures/fly/` and `tests/fixtures/docker/`. Former S5 (flyctl persisting an
env token to `~/.fly/config.yml`) is recorded as out of scope: it is flyctl's behaviour (X15).

## 10. Test plan

Seams: `FakeRunner` (`crate::runner::fake`), `FakeOp` (`src/adapters/fake_op.rs`), `opv-sim`
(`tests/sim/opv_sim.rs`) installed as `flyctl` and a new `docker`, with replies copied from
recordings only (`tests/sim/opv_sim.rs:9-13`), and the e2e matrix (`tests/e2e/matrix.rs`).

| Id | Acceptance item | Test |
|---|---|---|
| T1 | denied operations | each P1–P10 refusal: correct code and exit, and **zero** `op` calls in the call log |
| T2 | denied operations | forbidden inputs refused before any call: another app or host in `--image`, `-x`, a space, `$(…)`, `;`, a newline, a 129-char tag, an app name Docker refuses; `--machine` with `--app=x` or non-hex; extra words; an unknown operation |
| T3 | target isolation | two Fly targets with different items and apps: `--target a` reads only item A and every call carries `--app a`; a target without `deploy_credentials` refuses even when another target has some and a shell `FLY_API_TOKEN` is set |
| T4 | target isolation | a machine id listed only under app B is refused for target A after the listing, with no update call |
| T5 | redaction | marker token; sim replies echo it raw, base64 and as `x:TOKEN` base64 on stderr; excerpt, `--verbose`, `--json` and job summary hold none; `machines` stdout holds no `config.env` |
| T6 | redaction | the token appears in the call log only as stdin of `docker login` and in flyctl's env; no argv holds it; each child's env names (dumped by the sim) are exactly the allowlist plus the operation's own; `FlyLogin::env("docker")` is empty; source guard: no `SecretValue` written to a file, no `serde_json::Value` in `fly::operations` |
| T7 | cleanup | after success, login refusal, push failure, child kill and SIGTERM to opv (harness in `tests/hardening.rs`), no `opv-docker.*` directory remains; a stale directory of a dead pid is swept, a live one kept |
| T8 | cleanup and isolation | directory 0700 and `config.json` 0600 while the child runs; a pre-existing path or symlink at the seed name fails closed; a logging fake `docker-credential-secretservice` on `PATH` is never called; a docker stand-in that writes `credsStore` yields `CredentialStoreEscaped` and removes the directory |
| T9 | child failure | login `unauthorized` gives 7 with nothing pushed; login network failure 9; push and update failing with exit 1, timeout and kill give `outcome_unknown` (9) once, not retried; exit 0 without a digest gives `unexpected_output` |
| T10 | fail closed | missing item, missing field, wrong type, expired token, macOS/Windows for `registry-push`, no RAM runtime dir, `DOCKER_CONTEXT` set, a `tcp://` endpoint, image not in the daemon |
| T11 | CI writes | `confirm_env`: a write without `--confirm` is refused before the read; `machines` needs none |
| T12 | plan/sync/run compatibility | existing `plan`, `sync`, `run`, `status` scenarios and snapshots pass unchanged; a characterization test pins `deploy_sign_in`'s lenient behaviour |
| T13 | no 1Password writes | no `op item edit/create` in any operation's call log |
| T14 | coverage | every new cause path (including each `System::Docker` one) is a fault-matrix cell or an `UNREACHABLE` entry; `tests/observed_seal.rs` still passes |
| T15 | platforms | `flyctl version` under the allowlist in the native Windows and macOS CI jobs |

## 11. Delivery (lanes of at most ~400 changed lines, disjoint files)

**Step 0, interface commit (~200 lines)**, which every lane branches from: `Guard::OperationRefused`
and its reasons, `RamPurpose::RegistryPush`, `System::Docker` with catalog rows
(`src/cause/mod.rs`, `codes.rs`, `render.rs`, `subject.rs`), the `docker` entry in the runner's
system map and the `docker` `Tool` (`src/runner.rs`, `src/host.rs`), the shared allowlist moved
from `local_delivery::BASICS` to `src/host.rs`, and `src/app/provider_op.rs` with:

```rust
pub enum Operation { Machines, MachineUpdate, RegistryPush }
pub struct Request { pub env: String, pub target: String, pub op: Operation,
                     pub image: Option<String>, pub machine: Option<String>,
                     pub confirm: Option<String> }
pub struct Admitted { /* env, target, app, ItemRef, op, validated slots, docker endpoint */ }
pub fn admit(fleet: &Fleet, req: &Request, host: &Host) -> Result<Admitted, Error>;   // P1-P6, pure
pub fn preflight(a: &mut Admitted, r: &dyn CommandRunner) -> Result<(), Error>;       // P7-P10, no credential
pub fn execute(a: &Admitted, r: &dyn CommandRunner) -> Result<Report, Error>;         // §5
pub struct Report { /* value-free lines and JSON */ }
```

| Lane | Owns | Size | Gate |
|---|---|---|---|
| L1 admission | `src/app/provider_op.rs` (`admit`, `preflight`, validators; later the `execute` wiring), its tests (T1–T3, T10, T11) | ~350 | none |
| L2 runner isolation, strict sign-in | `src/runner.rs` (`isolated_env`, `env_clear` in `command_for`), `src/app/signin.rs` (`open_for_operation` on `sign_in_with`), `src/app/local_delivery.rs` (use the shared list), tests (T6 unit half, T12, T15) | ~250 | none |
| L3a Fly flyctl operations | `src/adapters/fly/operations.rs` (argv templates, typed listing projection, O4) | ~200 | Q2, S2, S3, S4 |
| L3b registry push | `src/adapters/fly/registry.rs` (seed, login, shape check, push, digest parse) | ~250 | Q1, S1, S6 |
| L4 surface and docs | `src/main.rs` (`TargetCmd::Op`), `docs/usage.md`, `docs/security.md`, `docs/design/requirements.md` (D2 text once approved), `docs/design/error-catalog.md` rows, the skill, CHANGELOG | ~300 | D2 |
| L5 simulation and e2e | `tests/sim/docker.rs` (new), `tests/sim/fly.rs` (`machine list/update`), `tests/sim/opv_sim.rs` (install `docker`), fixtures, scenarios, `tests/e2e/expected/surface.json` (T4–T9, T13, T14) | ~400 | fixtures of S1/S2 |

Order: Step 0; L1 and L2 at once (no fixtures needed); L3a and the flyctl half of L5 once S2–S4
pass; L3b and the docker half of L5 once Q1, S1 and S6 pass; L4 last; then L1 wires `execute`.
Each lane runs `cargo test` and the e2e suite with `CI=true` before it merges. Rollback: the
command is new and opt-in; the strict sign-in and `isolated_env` are separate entry points, so
removing it leaves `plan`/`sync`/`run` as they were.

## 12. Rejected alternatives

- **A credential export command** (`opv target token`): ruled out by the request; a printed token
  is outside opv's scrubbing and cleanup.
- **`opv run --target` injecting the deploy token into an arbitrary child**: general exec.
- **A configurable operation table in `secrets.toml`**: the contract would be the user's file
  (O6).
- **Copying the token into a product key**: a duplicate identity and a second copy to rotate.
- **opv writing the auth file itself** (former D1a): breaks SR-4 when docker offers stdin.

## 13. Vet responses

All vet findings are accepted and applied; each was re-checked against the code:
`docs/design/requirements.md:785` and `:1086-1090` (SR-4/FR-40 text), `src/runner.rs:993-1008`
(no `System` for `docker`), `src/app/signin.rs:367-374` (`as_principal` skips docker),
`src/provider.rs:181-195` (no token accessor), `src/app/local_delivery.rs:38-51` (`BASICS`),
`src/cause/mod.rs:1883-1885` (`unknown_env`/`unknown_target`). One refinement of C13: a failed
`docker login` is `CredentialRejected` (7) only for the recorded `unauthorized` reply; any other
login failure (network, daemon) is `Unavailable` (9), since calling it a rejected credential would
send the person to rotate a working token. Push failures are always `WriteOutcomeUnknown` (9), as
the vet proposes. The vet's conflict 4 (1Password token inherited by provider CLIs) is closed by
`8ea32e30`, so former D4 (allowlist for `sync` too) is no longer a decision.
