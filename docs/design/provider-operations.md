# Provider operations under a target's deploy credentials (#234)

Status: draft for 0.17.0, 2026-10-22; self-vetted, awaiting the DESIGN-FMECA vet and the owner's
decisions (§10). Issue #234 (Tracking CI). Nothing here is built. File and line citations are
against `v0170/design-234` at `22f51c94`.

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
fixed argv, hands the token over without argv or stdout, scrubs the output and removes anything
the tool needed on disk.

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
  and rotating stay with `opv target credentials` (`src/app/target_credentials.rs:91-96` refuses
  re-minting).
- **No build.** opv pushes an image the caller built and tagged; it never runs a Dockerfile.
- **Fly only in v1.** The contract is per provider; another provider's operations are a later,
  separately reviewed addition (§10 D2).

## 2. Operations (v1, Fly)

Each operation is a row in a static table compiled into opv. Its program, every argv word and
every slot are fixed; a slot takes only a value that passed its validator (§4). `<app>` is always
the target's `fly.app` from the configuration, never a caller input.

| Operation | Kind | Program and argv (fixed) | Caller slots |
|---|---|---|---|
| `registry-push` | write | `docker push <image>` | `--image registry.fly.io/<app>:<tag>` |
| `machines` | read | `flyctl machine list --app <app> --json` | none |
| `machine-update` | write | `flyctl machine list --app <app> --json`, then `flyctl machine update <id> --app <app> --image <image> --yes` | `--machine <id>`, `--image registry.fly.io/<app>:<tag>` or `…@sha256:<64 hex>` |

Rules:

- **O1.** Programs are the literal names `docker` and `flyctl`, resolved from `PATH` exactly as
  every opv call is (`Command::new(call.program)`, `src/runner.rs:1781-1798`); no shell is
  involved anywhere, so there is no expansion, globbing or word splitting.
- **O2.** Every argv word is a separate element. Caller values appear only in the slots shown and
  only after validation; none can begin with `-` (§4, P6).
- **O3.** `machine-update` changes only the image. It never passes `--env`, `--file-*`,
  `--command`, `--entrypoint`, `--metadata`, `--vm-*`, `--config`, `--dockerfile` or a build flag
  (all present in `flyctl machine update --help`, v0.4.120), so a caller cannot change what runs
  beyond the image or mount a local file into the Machine.
- **O4.** `machine-update` first lists the app's Machines under the same token and refuses an id
  that is not in that listing (`machine_not_in_app`), so a mistyped or foreign id never reaches an
  update call.
- **O5.** `machines` prints a value-free projection only: `id`, `name`, `state`, `region`, `image`
  (repository, tag, digest). The raw JSON is never printed: it carries each Machine's
  `config.env` and metadata.
- **O6.** Adding an operation, a flag or a program is a code change reviewed like this one. There is
  no configuration that extends the table.

## 3. Surface

### 3.1 CLI

```text
opv target op <env> --target <name> machines [--json]
opv target op <env> --target <name> registry-push  --image registry.fly.io/<app>:<tag> [--confirm <env>]
opv target op <env> --target <name> machine-update --machine <id> --image <ref>     [--confirm <env>]
```

A new `TargetCmd::Op` beside `List` and `Credentials` (`src/main.rs:1640-1665`); the operation is
a clap `ValueEnum`, so an unknown name is a `usage` error before anything else runs. `--target`
is required even when the environment has one target (P2). Output: one line per operation
(`pushed registry.fly.io/<app>:<tag> sha256:<digest>`, `updated machine <id> to <image>`) on
stdout; `--json` gives the same fields. A CI run also appends one value-free line to the job
summary through the existing `step_summary` effect (`src/runner.rs:257`).

### 3.2 MCP and assistant

Not exposed as an MCP tool. The MCP server runs on a runner that refuses every write
(`src/mcp.rs:2-3`) and refuses 1Password writes under CI (`src/mcp.rs:544-553`); an operation that
pushes or updates Machines does not belong there. `opv explain` and the skill describe the
operations so an assistant can write the CI steps; `opv ci workflow` can print them later (not in
v1).

### 3.3 How the target is bound

The operation resolves `env` and `target` from the loaded configuration (`secrets.toml` or the
manifest) exactly as `sync --target` does, then reads, from that one target section only:

- the provider (must be Fly: P3),
- `fly.app` (already validated at load: `^[A-Za-z0-9][A-Za-z0-9._-]*$`, never a flag;
  `src/adapters/fly/config.rs:232-235`, `src/config.rs:2701-2707`),
- `deploy_credentials` (must be present: P4).

The caller supplies only the names `env` and `target`. It cannot supply an app, a registry host,
an item reference or a token; the image's repository must equal the bound app (P6).

## 4. Admission: fail closed before any credential read

Admission is a pure function of the configuration, the command line and the process environment.
It runs in this order; the first failure wins; **no `op` call has been made** when it refuses.

| # | Rule | Refusal (code, exit) |
|---|---|---|
| P1 | The environment exists | `NotDeclared { kind: Environment }` (`not_declared`, 2) |
| P2 | `--target` is given and names a target of that environment | `ChoiceRequired { flag: "--target" }` / `NotDeclared { kind: Target }` (2) |
| P3 | The target's provider offers the operation (v1: Fly) | `Guard::OperationRefused { reason: WrongProvider }` (`policy_refused`, 6) |
| P4 | The target records `deploy_credentials` | `Guard::OperationRefused { reason: NoDeployCredentials }` (6); step: `opv target credentials <env> --target <t> --create` |
| P5 | A write operation on an environment with `confirm_env` has `--confirm <env>` equal to it | `NeedsConfirm` / `ConfirmMismatch` (`confirm_required` / `confirm_mismatch`), as `run` (`src/app/run.rs:34-55`) and `sync` (`src/app/sync.rs:650-656`) |
| P6 | Each slot matches its validator (below) and the image repository is `registry.fly.io/<bound app>` | `Usage { ValueFormat }` (`usage`, 2), or `Guard::OperationRefused { reason: ImageOutsideApp { app } }` (6) |
| P7 | `registry-push` only: a RAM-backed private directory can be made (Linux `$XDG_RUNTIME_DIR` on tmpfs/ramfs; macOS and Windows refuse in v1) | `RamDirUnavailable { purpose: RegistryPush }` (`ram_dir_unavailable`) |
| P8 | `registry-push` only: `DOCKER_HOST` is unset or `unix://…`; `DOCKER_CONTEXT` is unset | `Guard::OperationRefused { reason: RemoteDockerDaemon }` (6) |
| P9 | The program is on `PATH` | `ToolMissing` (`dependency_missing`), checked with the existing probe before the read |

Validators (P6), all anchored, ASCII only, no `-` first:

- tag: `^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$` (Docker's tag grammar);
- digest: `^sha256:[0-9a-f]{64}$`;
- image: exactly `registry.fly.io/` + bound app + (`:` tag | `@` digest); `registry-push` takes a
  tag only (a push names a tag);
- machine id: `^[0-9a-f]{14}$` (Fly's observed shape; S3 confirms before release, and widening it
  is a one-line change).

After admission, failures map to existing causes:

| Condition | Cause (exit) |
|---|---|
| Item missing, unreadable, wrong field type, duplicate or missing `FLY_API_TOKEN` | the existing deploy-credential read refusals (`src/adapters/onepassword.rs:983-1030`), surfaced as `deploy_credentials_failed` (7) by `deploy_failed` (`src/app/signin.rs:247-268`) |
| Token rejected or expired at Fly (flyctl 401/403) | `CredentialRejected { DeployCredentials }`, `deploy_credentials_failed` (7), the existing Fly diagnosis (`src/adapters/fly/mod.rs:951-964`) |
| Registry rejects the token (docker `unauthorized`/`denied`) | the same `CredentialRejected { DeployCredentials }` (7), from a new docker diagnosis keyed on recorded replies (S1) |
| Machine id not in the app's listing | `Guard::OperationRefused { reason: MachineNotInApp }` (6), after the read, before any write |
| Push or update fails, times out or is killed | `WriteOutcomeUnknown` (`outcome_unknown`, 9) with the scrubbed stderr excerpt; never retried |
| `machines` fails | the existing read diagnosis (retries, `provider_unavailable` 9, `not_found` for a missing app) |
| Private directory cannot be made or checked | `PrivateDirFailed` (`private_dir_failed`) |

One new guard, `Guard::OperationRefused { env, target, operation, reason }` with reasons
`WrongProvider { provider }`, `NoDeployCredentials`, `ImageOutsideApp { app }`,
`RemoteDockerDaemon`, `MachineNotInApp { machine }`; code `policy_refused`, exit 6, retry
`never`. One new `RamPurpose::RegistryPush` beside `FileDelivery` and `AzureDeployCredentials`
(`src/cause/mod.rs:1772-1777`). No other new cause.

**P4 differs from `sync`'s sign-in on purpose.** `deploy_sign_in` returns `Ok` without signing in
when the target has no `deploy_credentials`, and picks the environment's only target when none is
named (`src/app/signin.rs:332-344`): `sync` then runs under whatever `flyctl` login the machine
has. An operation must never do that (no cross-target fallback, no ambient identity), so it uses
a strict entry point, `signin::open_for_operation`, that refuses in both cases.

## 5. Credential handling, end to end

### 5.1 Common path

1. Admission (§4) passes.
2. `open_for_operation` reads the item once through the existing
   `onepassword::read_deploy_credentials` (`src/app/signin.rs:303-321`), fields `FLY_API_TOKEN`
   only (`src/adapters/fly/login.rs:18-22`), under the principal `DeployCredentials { vault, item,
   env, target }` so any rejection names that item, never a person's login
   (`src/app/signin.rs:355-362`).
3. The value lives only in `FlyLogin`'s `SecretValue` (zeroizing; `src/adapters/fly/login.rs:150-170`)
   and is already registered with the scrubber, because every field of every item read is
   (`src/scrub.rs:7-10`). Fly's token shape `FlyV1 …` is also a scrub pattern
   (`src/scrub.rs:329-330`).
4. The runner is dropped when the operation ends; dropping it drops the login and anything it
   kept (`src/provider.rs:181-195`).

The 1Password session itself (`OP_SERVICE_ACCOUNT_TOKEN` in CI) is the only credential the
caller provides, and it never reaches a provider child (§5.5).

### 5.2 `machines` and `machine-update` (flyctl)

flyctl takes its token from `FLY_API_TOKEN`/`FLY_ACCESS_TOKEN` or from `-t` (argv, forbidden by
SR-3). It has no stdin or pipe input for a token. So, exactly as `plan`/`sync` do today,
`FlyLogin::env("flyctl")` puts the token in **the child's environment only**, both variables, so
the target's identity overrides any shell token (`src/adapters/fly/login.rs:1-4`, `:172-181`;
merged per call by `EnvRunner::extra`, `src/app/signin.rs:377-390`). No file is written by opv.
This is the owner's "env where unavoidable" case and adds no new exposure: the same token already
reaches the same program this way in every `sync`.

`machine-update` is a `Call::rollout()` write (15-minute limit, progress line on stderr;
`src/runner.rs:83-91`, `:325`), never retried (`src/runner.rs:185-187`).

### 5.3 `registry-push` (docker)

`docker push` reads registry credentials only from its configuration directory (`config.json`
`auths`, or a credential helper that file names). There is no stdin, pipe or env input for them.
A credential therefore has to be on disk for the length of one push. The design confines it:

1. **Before the read**: P7 checks the RAM-backed base and sweeps `opv-docker.<pid>-*` directories
   whose run is gone (`src/ramdir.rs:62-84`), the same steps as Azure's sign-in directory
   (`src/adapters/azure/login.rs:1-22`).
2. **After the read**: `PrivateDir::create(base, "opv-docker.")` makes a fresh directory, never an
   existing path, mode 0700 at creation, ownership and mode re-checked, and registered for removal
   on SIGINT/SIGTERM (`src/ramdir.rs:149-173`, `:177-200`; signal list `src/runner.rs:2201-2215`).
3. opv writes `config.json` inside it with `O_CREAT|O_EXCL`, mode 0600, containing only
   `{"auths":{"registry.fly.io":{"auth":"<base64 of x:TOKEN>"}}}`. The composite string and its
   base64 are registered as secrets with the scrubber first (the registry matches each value's
   base64, not that of `x:`+value; `src/scrub.rs:10-12`). (D1 weighs this against `docker login
   --password-stdin`.)
4. `docker push <image>` runs with `DOCKER_CONFIG=<dir>` (from the operation, not the login), the
   isolated environment of §5.5, stdin `/dev/null`, stdout and stderr captured
   (`src/runner.rs:1778-1798`). opv parses the final `digest: sha256:<hex>` line for its report.
5. **On every exit path** the directory and `config.json` are removed: on return, on error (drop),
   on SIGINT/SIGTERM (the signal handler removes registered directories after stopping the
   child), with retries (`src/ramdir.rs:130-147`, `:213-218`). A SIGKILL leaves it in RAM until
   the next run's sweep or a reboot; on an ephemeral CI runner the VM is discarded.

Why a pre-written file and not `docker login`: the Docker CLI, when its config has no stored
auth, looks for a platform credential helper on `PATH` (`docker-credential-secretservice`,
`-pass`) and, if one exists, stores the login there, outside the private directory and outside
opv's cleanup. A `config.json` that already holds the auth skips that detection, so the token
never leaves the directory (inferred from the Docker CLI source; S1 verifies it).

What crosses to the Docker daemon: the CLI sends the auth with the push request to the daemon it
talks to. P8 keeps that daemon local (a Unix socket), so the token never travels to a remote
daemon. A fresh `DOCKER_CONFIG` also drops the user's docker contexts, which is why
`DOCKER_CONTEXT` is refused rather than silently ignored.

### 5.4 Output and diagnostics

- stdout of the child is never printed. opv prints its own value-free line (§3.1).
- stderr is held in memory (last 64 KiB, zeroized) and shown only as the failure excerpt or under
  `--verbose`, after every registered value and every token pattern is replaced
  (`src/runner.rs:337`, `:593-625`; `src/scrub.rs:1-5`, `:412-420`).
- `--verbose` shows program and argv only, never stdin or env (`src/runner.rs:373-375`). The argv
  holds no credential (O2), so it is safe to print.
- The JSON error, the job summary and any evidence carry names, ids, image references and
  digests, never a value.

### 5.5 Child environment

Today a captured child inherits opv's whole environment plus pinned variables and the call's own
(`src/runner.rs:1781-1798`); only `OP_SESSION*` is removed for non-`op` programs
(`src/runner.rs:1743-1775`, `src/app/account.rs:134-144`). So under CI a `flyctl` child also
inherits `OP_SERVICE_ACCOUNT_TOKEN` (not an `OP_SESSION` name). For an operation the child gets
an **allowlist** instead: `PATH`, `HOME`, `USER`, `LANG`/`LC_*`, `TMPDIR`, `XDG_RUNTIME_DIR`,
`SSL_CERT_FILE`, `SSL_CERT_DIR`, the proxy variables (NR-29), `DOCKER_HOST` when P8 allowed it,
plus the tool's pinned variables (`FLY_NO_UPDATE_CHECK`, `NO_COLOR`;
`src/adapters/fly/mod.rs:79`) and the operation's own (`FLY_API_TOKEN`, `FLY_ACCESS_TOKEN` for
flyctl; `DOCKER_CONFIG` for docker). Nothing else: no 1Password token, no `GITHUB_TOKEN`, no
Actions runtime tokens, no `DOCKER_AUTH_CONFIG`, no stray `FLY_*`.

Mechanism: a scoped runner setting, `runner::isolated_env(allow, || …)`, in the same style as
`runner::under_deploy` (`src/runner.rs:935`), read by `command_for`, which then calls
`env_clear()` before applying the allowlist. No `Call` literal changes (there are 44). Applying
the same allowlist to `sync`'s own flyctl calls is a separate decision (D4).

## 6. Security analysis

| Id | Threat | Mitigation |
|---|---|---|
| X1 | argv injection: a caller value read as a flag or a second argument | closed operation table (O1, O6); each slot validated, anchored, no leading `-` (P6); argv passed as elements, no shell (O1) |
| X2 | Shell expansion | no shell anywhere; `Command::new` with an argv vector (`src/runner.rs:1782`) |
| X3 | Unreviewed executable | program names fixed per operation; no caller-supplied program, path or plugin; unknown operation is a clap error |
| X4 | Dangerous flag override (`--env`, `--file-local`, `--config`, `-t`, `--entrypoint`) | the template has no slot for any flag; O3 lists what is never passed |
| X5 | Target confusion: pushing to or updating another app | app taken from the bound target (§3.3); image repository must equal it (P6); machine id must be in that app's listing (O4); the token is app-scoped at Fly (`--app` at mint, `src/adapters/fly/login.rs:93-95`), so even a bypass fails at Fly |
| X6 | Cross-target or ambient credential fallback | strict `open_for_operation` refuses a target without `deploy_credentials` and an implicit target (P2, P4); the login's env overrides shell Fly tokens (`src/adapters/fly/login.rs:172-181`) |
| X7 | Token on argv, stdout or in diagnostics | env (flyctl) or a 0600 file in a 0700 RAM directory (docker) only; child stdout never echoed; stderr scrubbed by value, base64 forms and patterns (§5.4) |
| X8 | Env leakage to children (the 1Password service-account token, CI tokens) | allowlisted child environment (§5.5) |
| X9 | Credential persistence after the run | RAM-only private directory, removed on return, error and signal; stale-run sweep; no `docker login`, so no credential helper store (§5.3) |
| X10 | Token sent to a remote Docker daemon | P8 refuses non-`unix://` `DOCKER_HOST` and any `DOCKER_CONTEXT` |
| X11 | Another same-user process reads the token | file mode 0600 in a 0700 directory owned by the user; core dumps disabled and inherited descriptors close-on-exec (`src/hardening.rs:1-40`). A same-user process could still read the child's environment; this is the existing `sync` exposure for flyctl and is not widened |
| X12 | CI misuse: a job that can run opv pushes to production | opv adds no permission: the job needs read access to the production item in 1Password, which the owner grants or withholds; `confirm_env` still requires `--confirm` (P5); the Fly token cannot reach another app |
| X13 | A malicious or compromised `docker`/`flyctl` on `PATH` | out of scope (owner principle: a defect inside a third-party tool is not opv's); same trust as `sync` |
| X14 | Value-state or settings change through an operation | none of the operations reads a product value or writes 1Password; `plan`/`sync` code paths are untouched except the strict sign-in entry point, which is new |

Residual risks, stated plainly: a SIGKILL during `registry-push` leaves the token in a RAM file
(mode 0600, user-only) until the next run or reboot (X9); the token is in the child's environment
for flyctl operations (X11, as today); the Docker daemon receives the token for the push (X10,
inherent to `docker push`).

## 7. Feasibility

Verified in code (cited above): how deploy credentials are read and held; that Fly's token goes
to flyctl by env only; that the mint is app-scoped; the private RAM directory, its permissions,
signal cleanup and sweep (reused, not new); the runner's no-shell spawning, stdin piping, stderr
capture and scrubbing; the confirm gate; the cause catalog entries reused. Verified with the
installed tools (flyctl v0.4.120, docker CLI): `flyctl machine list --app --json`,
`flyctl machine update --app --image --yes` and the flags O3 excludes; `docker push` takes no
credential input other than its config directory.

Inferred, needing a spike before or during implementation:

- **S1 (blocking `registry-push`)**: with a pre-written `config.json`, `docker push` to
  `registry.fly.io/<app>` authenticates with username `x` and the deploy token as password, and
  consults no credential helper (put a logging fake `docker-credential-secretservice` on `PATH`
  and confirm it is never invoked). Record the replies for success, `unauthorized` (expired or
  revoked token) and `denied` (another app's repository) as fixtures. If Fly's registry needs a
  different password form for a deploy token, §5.3 step 3 changes only the encoded string.
- **S2**: an app-scoped deploy token is accepted by `flyctl machine list` and `machine update` for
  its own app and refused for another app; record both replies.
- **S3**: Fly Machine id shape (P6 validator).
- **S4**: `flyctl machine update` with `--image` only leaves the rest of the Machine's
  configuration as it was and does not read a `fly.toml` in the working directory. If it does read
  one, the operation runs with the working directory set to an empty private directory (a small
  runner addition: `Call` has no working directory today, `src/runner.rs:63-71`).
- **S5**: flyctl writes no token it got from the environment to `~/.fly/config.yml` (true for
  `sync` today if it holds; the operation adds no new case).

S1 and S2 need a throwaway Fly app and a minted deploy token, run by the owner (live
credentials); the rest is reading flyctl's source.

## 8. Test plan

Seams: `FakeRunner` (`crate::runner::fake`) for unit tests, `FakeOp`
(`src/adapters/fake_op.rs`) for the item, `opv-sim` (`tests/sim/opv_sim.rs`) installed as
`flyctl` and a new `docker` for e2e, with replies copied from recordings only
(`tests/sim/opv_sim.rs:9-13`), and the e2e matrix (`tests/e2e/matrix.rs`).

| Id | Acceptance item | Test |
|---|---|---|
| T1 | denied operations | each P1–P9 refusal: correct code and exit, and the fake runner saw **zero** `op` calls (assert on the call log) |
| T2 | denied operations | every forbidden input is refused before any call: `--image` with another app, another host, `-x`, a space, `$(…)`, `;`, a newline, a 129-char tag; `--machine` with `--app=x`, non-hex; extra positional words; an unknown operation |
| T3 | target isolation | two Fly targets with different items and apps: `--target a` reads only item A and every call carries `--app a`; a target without `deploy_credentials` refuses even when another target has some, and even when a shell `FLY_API_TOKEN` is set |
| T4 | target isolation | machine id listed only under app B is refused for target A after the listing, with no update call |
| T5 | redaction | marker token in the item; sim replies echo it raw, base64 and as `x:TOKEN` base64 on stderr; failure excerpt, `--verbose`, `--json` and job summary contain none of them; stdout of `machines` contains no `config.env` |
| T6 | redaction | argv recorded by the sim for every call contains no token; the docker child's environment (dumped by the sim) holds `DOCKER_CONFIG` and no token, no `OP_SERVICE_ACCOUNT_TOKEN`, no `GITHUB_TOKEN`; the flyctl child's holds only the allowlist |
| T7 | cleanup | after success, failure, child kill and SIGTERM to opv (existing signal test harness in `tests/hardening.rs`), no `opv-docker.*` directory remains; a planted stale directory of a dead pid is swept; one of a live pid is kept |
| T8 | cleanup | the private directory is 0700 and `config.json` 0600 while the child runs (the sim stats them); a pre-existing path or symlink at the name makes creation fail closed |
| T9 | child failure | push and update failing with exit 1, a timeout and a kill each give `outcome_unknown` (9) with a scrubbed excerpt and are not retried; `unauthorized` gives `deploy_credentials_failed` (7) |
| T10 | fail closed | missing item, missing field, wrong field type, expired token reply, macOS/Windows host for `registry-push`, remote `DOCKER_HOST`, set `DOCKER_CONTEXT` |
| T11 | CI writes | `confirm_env` environment: write without `--confirm` refused before the read; `machines` (read) needs none |
| T12 | plan/sync/run compatibility | the existing `plan`, `sync`, `run` and `status` e2e scenarios and snapshots pass unchanged; `deploy_sign_in`'s lenient behaviour is unchanged (a characterization test pins it) |
| T13 | no 1Password writes | the call log of every operation scenario contains no `op item edit/create` |
| T14 | coverage | every new cause path is a fault-matrix cell or an `UNREACHABLE` entry with its reason |

## 9. Rejected alternatives

- **A credential export command** (`opv target token`): the request rules it out, and any printed
  token is outside opv's scrubbing and cleanup.
- **`opv run --target` with the deploy token injected into an arbitrary child**: general exec; the
  child could print or persist the token, and argv/flags are uncontrolled.
- **A configurable operation table in `secrets.toml`**: the contract would be the user's file, not
  reviewed code (O6).
- **Copying the token into a product key**: a duplicate identity and a second copy to rotate.

## 10. Decisions for the owner

**D1. How the registry push gets the credential.** `docker push` can only read registry
credentials from a configuration directory, so some file is unavoidable.
- (a) *opv writes `config.json` itself* into the private RAM directory, then runs `docker push`.
  One child, no login step, and docker never gets the chance to move the token into the desktop
  keyring. Trade-off: opv writes the credential file (0600, RAM, removed on exit).
- (b) *`docker login registry.fly.io -u x --password-stdin`* into the same directory, token on
  stdin, then `docker push`. The token goes over stdin as the principles prefer, but if a Docker
  credential helper is installed docker stores the token in the system keyring, where opv's
  cleanup cannot reach; opv would have to refuse whenever such a helper is on `PATH`.
- (c) *`flyctl auth docker`*: (b) with flyctl in front; same keyring risk, more moving parts.
- (d) *`flyctl deploy --build-only --push --local-only`*: no credential file at all, but opv would
  run the caller's Docker build (Dockerfile, build arguments, context): a far wider contract.
- **Recommendation: (a).** It is the only option whose cleanup opv fully controls.

**D2. Which Machine operations ship in v1.**
- (a) *`machines` (list) and `machine-update` (image only)*: the reconciler can see the app and
  move each Machine to a retained image; nothing else.
- (b) also *`flyctl deploy --image <ref> --app <app>`* with the repository's `fly.toml`: a full
  deploy (services, mounts, env from `fly.toml`), closer to what most CI does, but the reviewed
  contract then includes a whole config file the caller controls.
- (c) also start/stop/restart/destroy: more coverage, each a new write to review.
- **Recommendation: (a)**, and ask Tracking CI which flyctl calls its reconciler makes today
  before building; add others one reviewed row at a time.

**D3. Which images an operation may name.**
- (a) *only `registry.fly.io/<the target's app>`*: a stolen CI job cannot point staging at an
  arbitrary public image, and a push can never land in another repository.
- (b) *any image reference*: more flexible (public base images), but the operation becomes a way
  to run anything on the app.
- **Recommendation: (a).**

**D4. The child's environment.**
- (a) *allowlist for operation children* (§5.5); `sync` unchanged for now.
- (b) *(a), and the same allowlist for every target-CLI call* (flyctl, az, kubectl, gh in
  `sync`/`plan`): closes today's inheritance of `OP_SERVICE_ACCOUNT_TOKEN` by those tools, but
  touches every provider and needs its own compatibility pass (proxy, kube and az variables).
- (c) *denylist* of known token names: smaller change, misses tokens nobody listed.
- **Recommendation: (a) now; (b) as its own issue** (the inheritance is pre-existing, not created
  by this design).

**D5. Command shape.**
- (a) *`opv target op <env> --target <t> <operation>`*: sits with `target credentials`, which
  minted the identity; one subcommand to document and test.
- (b) *top-level `opv fly push` / `opv fly machine-update`*: shorter, but puts provider names in
  the top-level command set.
- **Recommendation: (a)**; not exposed over MCP (§3.2).

**D6. Write gate.** Write operations need `--confirm <env>` where the environment sets
`confirm_env`, exactly as `sync`, and `--target` is always explicit. No other gate: access to
the item in 1Password is the authorization. **Recommendation: adopt as written.**

**D7. Platforms for `registry-push`.** Linux (RAM directory) only in v1; macOS and Windows refuse
with `ram_dir_unavailable`, like Azure's sign-in on macOS. flyctl operations work everywhere
flyctl does. **Recommendation: adopt**; revisit if a non-Linux publisher appears.

**D8. Evidence.** Operations write nothing to 1Password (CI is values-read; no receipt). They
print and summarize image, digest and Machine ids. **Recommendation: adopt**; a delivery receipt
for images would be a separate feature.

## 11. Delivery (lanes of at most ~400 changed lines, disjoint files)

**Step 0, interface commit (~120 lines)**, which every lane branches from:
`Guard::OperationRefused` and its reasons, `RamPurpose::RegistryPush` and their catalog rows
(`src/cause/mod.rs`, `src/cause/codes.rs`, `src/cause/render.rs`); `src/app/provider_op.rs` with
the shapes below and `todo!()` bodies.

```rust
pub enum Operation { Machines, RegistryPush, MachineUpdate }
pub struct Request { pub env: String, pub target: String, pub op: Operation,
                     pub image: Option<String>, pub machine: Option<String>,
                     pub confirm: Option<String> }
pub struct Admitted { /* env, target, app, ItemRef, op, validated slots */ }
pub fn admit(fleet: &Fleet, req: &Request, host: &Host) -> Result<Admitted, Error>; // §4, pure
pub fn execute(a: &Admitted, r: &dyn CommandRunner) -> Result<Report, Error>;      // §5
pub struct Report { /* value-free lines and JSON */ }
```

| Lane | Owns | Size |
|---|---|---|
| L1 admission | `src/app/provider_op.rs` (`admit`, validators), its unit tests (T1–T3, T10, T11) | ~350 |
| L2 runner isolation and strict sign-in | `src/runner.rs` (`isolated_env`, `env_clear` in `command_for`), `src/app/signin.rs` (`open_for_operation`), their tests (T6 unit half, T12 characterization) | ~250 |
| L3 Fly operations | `src/adapters/fly/operations.rs` (argv templates, `machine list` projection, `config.json` writer, digest parse, docker diagnosis), `src/adapters/fly/mod.rs` (module line), `src/host.rs` (`docker` tool entry) | ~380 |
| L4 surface and docs | `src/main.rs` (`TargetCmd::Op`), `docs/usage.md`, `docs/security.md`, `docs/design/error-catalog.md` rows, the skill, CHANGELOG (the `execute` wiring stays in L1's file) | ~300 |
| L5 simulation and e2e | `tests/sim/docker.rs` (new), `tests/sim/fly.rs` (`machine list/update`), `tests/sim/opv_sim.rs` (install `docker`), fixtures from S1/S2, one e2e scenario, `tests/e2e/expected/surface.json` (T4–T9, T13, T14) | ~400 |

Order: S1–S4 first (fixtures); Step 0; L1, L2, L3, L5 in parallel; L4 last, then one joining
commit in `provider_op.rs` that wires `execute` to L2 and L3 (small, owned by L1). Each lane runs
`cargo test` and the e2e suite with `CI=true` before it merges (release gate under CI).

Rollback: the command is new and opt-in; removing it leaves `plan`/`sync` as they were, since the
strict sign-in is a separate entry point.

## 12. Self-vet and open questions

- **Smallest design?** Three operations, one new guard, one RAM purpose, one runner scope, one
  sign-in entry point; the private directory, scrubber, sign-in, diagnosis and confirm gate are
  reused. No configuration, no MCP tool, no 1Password write.
- **Fail closed before access?** P1–P9 are pure and precede the only `op` call; T1 asserts zero
  `op` calls on each refusal.
- **Q1.** Does Tracking CI's publisher use `docker push`, or `buildx --push`, `crane` or `skopeo`?
  v1 supports `docker push` of a locally tagged image only; another pusher is a new reviewed row.
- **Q2.** Does the reconciler need anything beyond list and image update (D2)?
- **Q3.** Should `machine-update` pass `--detach` or `--skip-health-checks`? v1 waits for health
  (flyctl's default), so a failed rollout is a failed command.
