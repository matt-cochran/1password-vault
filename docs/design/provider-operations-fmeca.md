# DESIGN-FMECA vet: provider operations (#234), `docs/design/provider-operations.md`

Reviewer: independent; did not write the design. Date: 2026-10-23. Method: the owner's
DESIGN-FMECA procedure (persona, objective, constraints, code-change-proposal requirements, three
phases, output format, verification checklist), applied as written.

Owner question: **is this design secure and actually feasible?**

**Short answer.** The shape is right and small: a closed, compiled table of three Fly operations,
admitted by a pure check before the one credential read, run without a shell, under the target's
own app-scoped token, with no new identity or role. The flyctl half (`machines`,
`machine-update`) can be built on today's code with small additions. **The registry half, as
written, cannot be built and should not be built in that form:**

- Its recommended credential hand-off (D1a: opv writes `config.json` itself) breaks two written
  requirements the design never mentions. SR-4 says "opv itself still writes no secret to any
  file" (`docs/design/requirements.md:1090`). FR-40 says deploy credentials never reach "files
  (except az's own private directory, SR-4)" (`requirements.md:785`). It also passes over a stdin
  route the tool does offer. The design rejected that route (D1b) for a reason that a seed file
  removes, and I checked that offline on docker 27.5.1 (§0.1).
- Its error mapping for `docker` is infeasible. `CredentialRejected` and `WriteOutcomeUnknown`
  carry an `Observed`. The runner builds one only for a program that maps to a `System`, and
  `docker` maps to none (`src/runner.rs:993-1008`). The deploy principal is also never applied to
  a program the login gives no environment (`src/app/signin.rs:367-374`).
- Nothing in the design hands the token to docker. `FlyLogin` gives it only to `flyctl`
  (`src/adapters/fly/login.rs:172-181`), and `DeployLogin` has no other accessor
  (`src/provider.rs:181-195`).
- Three unknowns about the consumer decide whether the operation is usable at all: whether
  Tracking CI's image is in the local daemon (Q1), whether its runner has a tmpfs runtime
  directory, and which daemon a fresh `DOCKER_CONFIG` talks to.

The fixes all reuse existing structures. After them, no High or Medium risk remains, provided
the live spikes in §Spikes pass. **Verdict: ready with changes.**

Evidence levels: **Proven** (standard practice, or opened and shown here), **Adapted**
(reasonable, not proven in this setting), **Speculative** (assumed, not validated). opv paths are
relative to `/home/mc/.cache/lanes/opv-0170-design-234`. The design cites rev `22f51c94`. HEAD
`48c71d87` differs from it only by the design file (`git diff --stat 22f51c94 HEAD`), so every
citation was checked at HEAD.

---

## 0. Claims checked against the code

| Design claim (§) | Verdict | Evidence |
|---|---|---|
| Deploy token minted with `tokens create deploy --app <app> --name <n> --expiry 2160h` (§1) | **Holds** | `src/adapters/fly/login.rs:87-98` (args at `:94`, `TOKEN_EXPIRY_HOURS` `:28`) |
| Stored as `op://<state_vault>/<item>` (§1) | **Holds** | `src/app/target_credentials.rs:373` |
| `plan`/`sync` sign in with it (§1) | **Holds** | `src/app/signin.rs:326-363` |
| Re-minting refused (§1.1) | **Holds** | `already_recorded`, `src/app/target_credentials.rs:91-98` |
| No shell; `Command::new(program)` with an argv vector (O1, X2) | **Holds** | `src/runner.rs:1781-1798` |
| `TargetCmd` beside `List`/`Credentials` (§3.1) | **Holds** | `src/main.rs:1640-1665` |
| Job summary through `step_summary` (§3.1) | **Holds** | `src/runner.rs:257` |
| MCP runner refuses writes; refuses 1Password writes under CI (§3.2) | **Holds** | `src/mcp.rs:1-3`, `:544-553` |
| `fly.app` validated `^[A-Za-z0-9][A-Za-z0-9._-]*$` (§3.3) | **Holds**, but this grammar is wider than Docker's repository grammar (lower case only; separators only between alphanumerics), so an app name that loads can still make an invalid image reference (risk L4) | `src/adapters/fly/config.rs:232-235`, `src/config.rs:2701-2707` |
| P1/P2 refusal codes `not_declared` (§4) | **Wrong code**: `NotDeclared` renders as `unknown_env` / `unknown_target`. `ChoiceRequired` can never fire if `--target` is a required clap argument, as it is for `Credentials` | `src/cause/mod.rs:1883-1885`; `src/main.rs:1658-1659` |
| P5 is the same gate as `run` and `sync` (§4) | **Holds**, and is stricter than `sync`, whose guard runs after its reads. Reuse `run::require_confirmation` as is | `src/app/run.rs:34-55`; `src/app/sync.rs:649-657` |
| `RamPurpose` has `FileDelivery`, `AzureDeployCredentials` (§4) | **Holds** | `src/cause/mod.rs:1770-1777` |
| `deploy_sign_in` is lenient: no credentials or an implicit sole target signs nothing in (§4) | **Holds**, and the point is well taken | `src/app/signin.rs:326-345` |
| One read of `FLY_API_TOKEN`, registered with the scrubber (§5.1) | **Holds** | `src/app/signin.rs:303-321`; `src/adapters/fly/login.rs:18-22`; registration `src/adapters/onepassword.rs:1134-1137`; `src/scrub.rs:7-12` |
| Token lives only in `FlyLogin`'s `SecretValue` (§5.1) | **Holds, and that is the gap**. `FlyLogin::env` returns the token only for `flyctl`, and the trait has no other accessor, so §5.3 has no way to get it to docker | `src/adapters/fly/login.rs:150-181`; `src/provider.rs:181-195` |
| `FlyV1 …` scrub pattern; base64 of each value matched, composites not (§5.1, §5.3) | **Holds** | `src/scrub.rs:328-330`; `:10-12` |
| flyctl takes the token from env or `-t` only (§5.2) | **Holds** (v0.4.120 `--help`: `-t, --access-token` global flag; no stdin option) | `flyctl machine update --help`, run here |
| `machine-update` is a `Call::rollout()` write, never retried (§5.2) | **Holds** | `src/runner.rs:83-91`, `:185-187`, `:325` |
| Private RAM dir: sweep, 0700 at creation, re-checked, signal cleanup (§5.3) | **Holds**. "With retries" applies on Windows only (`cfg!(windows)`), which does not matter for a Linux-only operation | `src/ramdir.rs:62-84`, `:149-200`, `:130-147`; `src/runner.rs:2201-2215` |
| "`docker push` … no stdin, pipe or env input" for credentials (§5.3) | **Holds for `push`. As an argument against D1b it is wrong**: `docker login --password-stdin` takes the token on stdin and writes it into the same directory (verified, §0.1). `DOCKER_AUTH_CONFIG` is not in the installed CLI (27.5.1: the string is absent from the binary), so env is not an option here | `docker login --help`; §0.1 |
| A config that already holds auth skips helper detection (§5.3, "inferred") | **Holds on docker 27.5.1**, now checked offline for both `push` and `login` (§0.1) | §0.1 |
| D1b would store the token in a keyring whenever a helper is on `PATH` (§10) | **Wrong**. A secret-free seed `config.json` with one placeholder `auths` entry stops the detection, and `login` then writes to the file store inside the private directory (§0.1) | §0.1 |
| stderr kept in memory, last 64 KiB, zeroized; scrubbed before display (§5.4) | **Holds** | `src/runner.rs:337`, `:593-625`; `src/scrub.rs:1-5` |
| `--verbose` shows argv only (§5.4) | **Holds** | `src/runner.rs:368-378` |
| Today only `OP_SESSION*` is stripped, so `OP_SERVICE_ACCOUNT_TOKEN` reaches `flyctl` in `sync` (§5.5) | **Holds** (pre-existing exposure) | `src/runner.rs:1743-1775`; `src/app/account.rs:134-144` |
| A scoped setting "in the style of `under_deploy`" read by `command_for` (§5.5) | **Feasible**. `under_deploy` is thread-local (`src/runner.rs:967-985`), and `command_for` runs on the caller's thread (`spawn_attempt`, `src/runner.rs:1541-1550`). But the design writes a new allowlist when one exists: `local_delivery::BASICS` (`src/app/local_delivery.rs:38-51`) | as cited |
| "No `Call` literal changes (there are 44)" (§5.5) | **Immaterial and not reproduced** (33 struct literals and 164 `Call::new` in `src/` by `rg`). Drop the number | — |
| Fly rejection diagnosis at `src/adapters/fly/mod.rs:951-964` (§4) | **The behaviour holds; the citation points at a test**, `a_rejected_deploy_token_is_the_deploy_credentials_never_a_sign_in` | `src/adapters/fly/mod.rs:948-964` |
| Docker `unauthorized` → `CredentialRejected { DeployCredentials }` (7); push failure → `WriteOutcomeUnknown` (9) (§4) | **Infeasible as written**. Both causes carry `seen: Observed`. Observation needs a `System` for the program, and `docker` has none. `EnvRunner::as_principal` applies the deploy principal only where `login.env(program)` is non-empty, which is never the case for docker | `src/cause/mod.rs:691-695`, `:752-756`; `src/runner.rs:993-1008`, `:1014-1020`; `src/app/signin.rs:367-374`; `src/cause/subject.rs:94-105` |
| "One new guard … No other new cause" (§4) | **Incomplete**: also a `System::Docker` (catalog label, render, codes), a `docker` `Tool` in `src/host.rs` (L3 lists it), and an observation mapping | as above |
| Core dumps off, inherited descriptors close-on-exec (X11) | **Holds** | `src/hardening.rs:1-40` |
| flyctl flags O3 excludes exist in `machine update --help` v0.4.120 (O3) | **Holds**. The help also shows **defaults** for `--autostart` (true) and `--autostop` ("off"), so S4 must prove these are not applied when the flags are absent | `flyctl machine update --help`, run here |
| SR-4 / FR-40 (not mentioned) | **Design gap**: D1a contradicts both as written. FR-40 also lists the commands that read deploy credentials ("`status`, `plan`, `sync`, `doctor --env`"), so `target op` must be added | `docs/design/requirements.md:785`, `:1086-1090` |
| Test seams: `opv-sim` by `argv[0]`, replies from recordings only (§8) | **Holds**; docker is not modelled yet (L5 adds it) | `tests/sim/opv_sim.rs:1-13` |

### 0.1 Offline docker probe (docker CLI 27.5.1, no daemon contacted for push, no network beyond 127.0.0.1)

All runs used `env -i` with a fresh `DOCKER_CONFIG` directory (mode 0700). A logging fake
`docker-credential-secretservice` was first on `PATH`. `DOCKER_HOST` pointed at a missing socket,
so the CLI fell back to logging in client-side. For `login`, a 20-line local fake registry on
127.0.0.1 accepted any Basic auth.

| Case | Helper invoked | Where the auth landed |
|---|---|---|
| `push`, empty config dir | **yes** (`get`) | — |
| `push`, config with `auths` for the host | no | — |
| `push`, config with only a placeholder `{"auths":{"opv.invalid":{}}}` | no | — |
| `login --password-stdin`, empty config dir | **yes** (`store`) | the helper; `config.json` got `"credsStore":"secretservice"` and no auth |
| `login --password-stdin`, seeded placeholder config (0600) | no | `config.json` in the private dir (`auths["localhost:5579"].auth`), **mode 0600 kept** (a 0644 seed stays 0644) |

Two more observations. With a reachable daemon, `login` is performed by the daemon ("Error
response from daemon"), so the token reaches the same local daemon that `push` uses. With a fresh
`DOCKER_CONFIG` and `DOCKER_CONTEXT` set, docker fails at start (`context "…" not found`): it
fails closed. One live check is still needed: Fly's registry with a deploy token (S1).

---

## Phase 1: Architecture Assessment

| Component | Purpose | Classification | Justification | Simpler Alternative | Risk if Removed |
|---|---|---|---|---|---|
| C1. Closed, compiled operation table (O1–O6) | Fixed program and argv per operation | **Essential** (Proven: an allowlisted command template) | The issue's "explicit reviewed contract"; removes argv injection by construction | None | General exec |
| C2. `opv target op <env> --target <t> <op>` (D5a) | Surface beside `target credentials` | **Essential** (Proven: existing subcommand pattern) | One place, clap `ValueEnum` refuses unknown names | — | No surface |
| C3. Pure admission P1–P9 before the read | Fail closed before credential access | **Essential** (Proven pattern; Adapted here) | Issue acceptance item 2/5 | — | Credential read on bad input |
| C4. Strict sign-in `open_for_operation` | No ambient or cross-target identity | **Essential** (Adapted) | `deploy_sign_in` is lenient by design (`signin.rs:332-345`) | A `strict: bool` on `deploy_sign_in` is a smaller diff but changes a shared path; keep a separate entry point **built on `sign_in_with`** (no copy) | Ambient `flyctl` login used silently |
| C5. `machines` (list, projected) | Reconciler sees Machine ids and images | **Essential** for the reconciler (Q2 to confirm) | Only safe way to show ids without `config.env` | — | Reconciler needs raw flyctl |
| C6. `machine-update` (image only) | Point a Machine at a retained image | **Essential** (Adapted: S4 open) | The issue's second consumer | — | No reconciler |
| C7. O4: list-before-update, `machine_not_in_app` | A definite refusal before a write | **Useful** (Proven) | Without it a mistyped id is a failed write, which the design maps to `outcome_unknown` (9), a misleading answer. Fly's own refusal is the backstop | Rely on Fly's 404 | Typos become "outcome unknown" |
| C8. `registry-push` operation | Push a locally tagged image under the app's token | **Essential** (Speculative until Q1/S1/S6) | The issue's first consumer | — | No publisher |
| C9. opv-written `config.json` holding the token (D1a) | Give docker the credential | **Unjustified as designed** | Contradicts SR-4/FR-40 text and the owner's "stdin where the tool offers it". The design's reason to avoid `docker login` (keyring capture) is removed by a secret-free seed (§0.1) | **D1b′**: opv writes a seed config with no secret, then `docker login registry.fly.io -u x --password-stdin`, then `docker push`. This is the Azure pattern exactly (`az login -p @<stdin>` into a private dir, `src/adapters/azure/login.rs:1-22`) | — |
| C10. Private RAM dir for docker's config | Bound where docker stores the auth | **Essential** (Proven: reused from Azure and #136) | Docker must store it somewhere | — | Credential on disk |
| C11. P8 `DOCKER_HOST`/`DOCKER_CONTEXT` refusal | Keep the auth on a local daemon | **Essential, incomplete** | A fresh `DOCKER_CONFIG` also drops the user's `currentContext`, so the push may reach a different or absent daemon | Resolve the user's endpoint first (`docker context inspect`, no credential) and pass it as `DOCKER_HOST` | Token to a remote daemon |
| C12. Child-env allowlist (`isolated_env`) | Stop `OP_SERVICE_ACCOUNT_TOKEN`/CI tokens reaching tools | **Essential** (Proven: #137 `declared_only`) | A third-party child must not get the 1Password token | **Reuse `local_delivery::BASICS`** plus NR-29 proxy/CA names and per-OS basics; no second list | 1Password token in a docker/flyctl child |
| C13. Docker diagnosis "keyed on recorded replies" | Exit 7 vs 9 for a push | **Simplify** | With D1b′ the `login` step is a definite credential check *before* any write: login refused → `CredentialRejected` (7); push failed → `WriteOutcomeUnknown` (9). No parsing of push errors for auth | Classify by step, not by reply text | Wrong exit codes |
| C14. `System::Docker` + `docker` `Tool` | Observation, diagnosis, install hints | **Essential, missing from the design** | Required for any `Observed` cause on a docker call | — | Causes cannot be built (`Cause::Bug` at best) |
| C15. `Guard::OperationRefused` with reasons | One new refusal family | **Essential** (Proven: existing `Guard` family) | — | — | — |
| C16. `--json` for `machines`, job summary line | Machine-readable output | **Useful** (Proven: existing effects) | Cheap | — | CI parses text |
| C17. `opv ci workflow` printing steps, MCP exposure | — | Already **deferred/excluded** by the design; agree | — | — | — |

### Revised Architecture

- **Components retained:** C1, C2, C3, C4 (on `sign_in_with`), C5, C6, C7, C8, C10, C15, C16.
- **Components simplified:** C12 (reuse `BASICS`); C13 (classify docker failures by step: login vs push).
- **Components removed:** C9 (opv never writes the token to a file; replaced by D1b′).
- **Components added (required for feasibility, not new behaviour):** C14 `System::Docker`; a
  token hand-off for docker that does not go through `FlyLogin` (registry-push reads the item
  through `read_deploy_credentials` under the deploy principal and holds the `SecretValue` itself:
  no flyctl runs in that operation); endpoint resolution and an image-present check for docker
  (C11, before the read).
- **Components demoted:** none. Note that `machines --json` and the summary line are Useful, not
  Essential.

---

## Phase 2: FMECA + poka-yoke + TRIZ

Domains: **S** security/runtime, **T** technical architecture, **U** UX, **P** project/delivery.
Scoring is qualitative. A failure mode is High if severity or probability is High, and Medium if
either is Medium.

### Iteration 1 Risk Table

| Id | Domain | Failure Mode | Cause | Effect | Severity | Probability | Mitigation (Poka-Yoke) | Observability | TRIZ Resolution | Residual Severity | Residual Probability |
|---|---|---|---|---|---|---|---|---|---|---|---|
| S1 | S | opv writes the deploy token to a file (D1a) | Design choice | Breaks SR-4 ("opv itself still writes no secret to any file") and FR-40; violates the owner's stdin-first principle; sets a precedent for opv-written credential files | Medium | High (it is the recommendation) | **D1b′**: seed `config.json` = `{"auths":{"opv.invalid":{}}}` created `O_CREAT\|O_EXCL\|O_NOFOLLOW`, 0600, no secret; `docker login registry.fly.io -u x --password-stdin` with the token on stdin (Zeroizing buffer); docker writes the auth into the private dir. Amend SR-4/FR-40 to name docker's private `DOCKER_CONFIG` beside az's, in the same wording | Unit: the fake runner's call log shows the token only in `stdin` of `docker login`; a source guard that `provider_op`/`fly::operations` never write a `SecretValue` to a file | #10 *Prior action* + #2 *Taking out*: the tool's own login writes the file; opv only prepares a secret-free directory | Low | Low |
| S2 | S | Docker stores the token outside the private dir (keyring / helper) | Helper auto-detection when the config holds no auth (§0.1); a future CLI change | Token survives the run in a store opv cannot clean | High | Low with the seed; **High without it** | The seed (S1). **After login, fail closed if `config.json` is not exactly the expected shape**: `auths["registry.fly.io"].auth` present, no `credsStore`, no `credHelpers`. Otherwise remove the dir and refuse (`OperationRefused { CredentialStoreEscaped }`) and tell the person to run `docker logout registry.fly.io` under their own config. Put no helper on `PATH`'s allowlist: there is none to add | The refusal code; e2e with a fake `docker-credential-secretservice` on `PATH` whose call log must stay empty (the §0.1 probe, automated) | #11 *Beforehand cushioning*: verify the outcome, not only the precondition | Medium → Low (with post-check) | Low |
| S3 | T | Docker failures cannot be raised as cataloged causes | No `System` for `docker`, so no `Observed`; the deploy principal is not applied to docker calls | `Cause::Bug`, or a person's-login diagnosis instead of the item's; wrong exit | Medium | High (certain as written) | Add `System::Docker` (label "Docker", render rows, codes) and map `docker` in the runner's observation; run every docker call of the operation inside `runner::under_deploy(principal, …)` explicitly (not via `as_principal`). Step 0 owns these so lanes do not collide in `runner.rs`/`cause/` | T14 coverage: each docker cause path is a fault-matrix cell; the `observed_seal` test still passes | — | Low | Low |
| S4 | T | No route from the item to docker's stdin | `FlyLogin` exposes the token only as flyctl env | Implementation invents an accessor on `FlyLogin`, or worse, `env("docker")` (token in docker's env) | Medium | High | `registry-push` does not use `FlyLogin`: it calls `onepassword::read_deploy_credentials(r, item, fly::login::FIELDS, Some(principal))` once and keeps the `SecretValue`; stdin bytes are a `Zeroizing<Vec<u8>>` dropped right after the login call. `FlyLogin::env` stays flyctl-only (a unit test pins `env("docker")` empty) | Unit test on the call log (one `op item get`, token only in login stdin) | — | Low | Low |
| S5 | S | 1Password service-account or CI tokens reach a provider child | Children inherit opv's environment (`runner.rs:1781-1798`) | A third-party tool, or anything it spawns, holds `OP_SERVICE_ACCOUNT_TOKEN` | High | High (today, for every child) | `isolated_env` with `env_clear()` and an allowlist that **extends `local_delivery::BASICS`**: NR-29 (`HTTP(S)_PROXY`, `NO_PROXY`, `ALL_PROXY` in both cases, `SSL_CERT_FILE`, `SSL_CERT_DIR`), `XDG_RUNTIME_DIR`; on Windows `SystemRoot`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `TEMP`, `TMP`, `PATHEXT`, `ComSpec`. One list, one module | T6: the sim dumps each child's env names; snapshot asserted | #3 *Local quality*: a strict environment for operation children only, `sync` unchanged (D4a) | Low | Low |
| S6 | T/U | Allowlist breaks flyctl off Linux | A Unix-shaped list; Go on Windows needs `SystemRoot`, and flyctl needs `USERPROFILE`/`APPDATA` for `~/.fly` | `machines`/`machine-update` fail on Windows (D7 says flyctl operations "work everywhere") | Medium | Medium | The per-OS entries in S5; run `flyctl version` under the allowlist in the existing native Windows/macOS CI jobs | CI job result | — | Low | Low |
| S7 | S/U | Push reaches a different or absent daemon | A fresh `DOCKER_CONFIG` drops `currentContext` (Docker Desktop for Linux, rootless, colima); P8 checks env only | "image does not exist locally" or "cannot connect" after the credential read; on a rootless host the CLI could even reach a different daemon on the default socket | Low | Medium (developer hosts); Low (GitHub-hosted) | Before the read: resolve the endpoint with `docker context inspect --format '{{.Endpoints.docker.Host}}'` under the person's own environment (no credential involved). Require `unix://`. Pass it as `DOCKER_HOST` to every docker call of the operation. Then **P10**: `docker image inspect --format '{{.Id}}' <image>` against that endpoint. A missing image is refused before the read (`OperationRefused { ImageNotLocal }`) | Refusal code; `--verbose` line shows the endpoint (a path, never a value) | #10 *Prior action* | Low | Low |
| S8 | S | Token on argv, stdout or diagnostics | — | Leak | High | Low (design holds) | As designed: argv templates, stdout never echoed, stderr scrubbed. Also register `x:<token>` and its base64 before login (docker's file holds that encoding) | T5/T6 | — | High | Low (accepted; Proven mechanism) |
| S9 | S | Token left behind after SIGKILL | RAM file survives until the next sweep or reboot | Same-user read of a 0600 file on a persistent host | Medium | Low | As designed (sweep `opv-docker.`), same as Azure (SR-4 precedent); on ephemeral runners the VM is discarded | Sweep is silent; T7 asserts it | — | Medium | Low (accepted precedent) |
| S10 | S | `machine update --image` changes more than the image | flyctl applies defaults (`--autostart` true, `--autostop` "off") when unspecified, or reads a `fly.toml` in the working directory | Production Machine silently loses autostop, services or env | High | Low (unverified; Speculative) | **S4 spike before L3**: diff `flyctl machine status --json` config before/after with only `--image` passed, from a directory holding a `fly.toml` with different settings. If it reads `fly.toml`, run the child with an empty private working dir (the design's own fallback). If flyctl later regresses, that is a third-party defect (owner principle): record it, not an opv risk | S4 fixture; e2e asserts the exact argv | — | High | Low (once S4 passes) |
| S11 | S | Untrusted listing JSON keeps `config.env` in memory | `machines`/O4 parse the full reply | Non-secret-by-Fly-model env values in un-zeroized `String`s | Low | Medium | Deserialize into a typed struct of the projected fields only (serde skips the rest); never `serde_json::Value`; the stdout buffer is zeroized | Source guard (no `Value` in `fly::operations`) | — | Low | Low |
| S12 | S | CI job with item access pushes to or updates production | The service account can read the production item | A compromised job changes production | High | Low | **Out of opv's scope by owner principle**: 1Password access is the authorization. `confirm_env` gives intent only, not authorization (a workflow sets `--confirm` statically) | — | — | High | Low (owner-accepted model) |
| S13 | S | Docker daemon sees the token | Inherent to `docker push` (and to `login`, which the daemon performs when reachable, §0.1) | Root-equivalent local daemon holds it briefly | Medium | Low | P8 plus S7 keep it on a local Unix socket; the daemon is already root-equivalent on that host | — | — | Medium | Low (inherent) |
| T1 | T | Wrong refusal codes in the contract | `unknown_env`/`unknown_target` misnamed `not_declared`; `ChoiceRequired` unreachable if clap requires `--target` | Docs and surface tests diverge from the code | Low | High | Fix §4's table; make `--target` a required clap argument and drop `ChoiceRequired` from P2 | `tests/e2e/expected/surface.json` | — | Low | Low |
| T2 | T | Image reference invalid for docker even though the app name loaded | `is_id` allows upper case and `_`/`.` runs; Docker repositories do not | Failure after the read | Low | Low | P6 also checks the bound app against Docker's path-component grammar `^[a-z0-9]+(?:(?:[._]\|__\|-+)[a-z0-9]+)*$` before the read | T2 refusal | — | Low | Low |
| T3 | T | Push succeeds but no `digest:` line | Output format change | Report without a digest, or a false failure | Low | Low | Exit 0 without a parsable digest is `UnexpectedOutput { during: AppliedWrite }` (as the token mint does, `login.rs:122-144`), never `outcome_unknown` and never a retry | Fault-matrix cell | — | Low | Low |
| U1 | U | Expired token (90-day expiry) breaks CI with no clear step | `--expiry 2160h`; re-minting is refused | Publisher and reconciler fail on day 91 | Medium | Medium | Not new (the same holds for `sync`), but the rejection's step must name the rotation path the owner already uses. Ensure the `deploy_credentials_failed` render for an operation is the same as for `sync` | Exit 7 with the item named | — | Low | Medium (pre-existing; outside this design) |
| P1 | P | Registry operation unusable for the real consumer | Tracking CI may build with buildx/`build-push-action` (image never in the local daemon) (Q1) | `registry-push` ships and is never used, or invites a wider operation later | Medium | Medium | **Gate L3/L5's docker half on Q1's answer.** If the image is not in the daemon, the row changes (e.g. `--load` first) before any code | Q1 answered in the issue | #1 *Segmentation*: ship the flyctl operations first if Q1 is open (see Phase 3) | Low | Low |
| P2 | P | No tmpfs runtime dir on Tracking CI's runner | Container jobs and some self-hosted runners have no user-owned tmpfs `$XDG_RUNTIME_DIR` | `registry-push` always refuses (`ram_dir_unavailable`) for the primary consumer | Medium | Medium (unverified) | **Spike S6** in the real job before L3. If it fails, the owner decides (see Conflicts, item 2); this review does not choose a disk fallback | Refusal code in the CI log | — | Low (after S6) | Low (after S6) |
| P3 | P | Requirements drift | SR-4 and FR-40 (`requirements.md:785`, `:1086-1090`) not amended; FR-40's list of commands that read deploy credentials omits `target op` | Contract and code disagree; future reviews flag a violation | Medium | High | L4 adds the amendments (text for owner approval): the docker private-directory exception beside az's, and `target op` in FR-40's reader list | Docs review; `tests/docs_commands.rs` if it checks command lists | — | Low | Low |
| P4 | P | Lane collisions in shared files | `System::Docker` touches `cause/` and runner observation; L2 also edits `runner.rs` | Merge conflicts, a late Step 0 change | Low | Medium | Put `System::Docker`, its catalog rows, the `docker` `Tool`, and the `OperationRefused` reasons (`ImageNotLocal`, `CredentialStoreEscaped`) in Step 0 | Lane merge | — | Low | Low |
| P5 | P | Live spikes stall the critical path | S1/S2/S4 need the owner, a throwaway Fly app and a minted token | Lanes wait | Low | Medium | Hand the owner one script file per spike (owner commands as files), recording replies straight into `tests/fixtures/fly/` and `tests/fixtures/docker/`. L1 and L2 do not depend on fixtures and start at once | Fixture files present | #15 *Dynamics*: start the independent lanes | Low | Low |

### Remaining Risks After Iteration 1

- **High:** none open. S8, S10 and S12 keep High *severity* with Low probability: S8 by Proven
  mechanisms, S10 conditional on S4, S12 out of scope by owner principle.
- **Medium:** S9 (accepted precedent, Medium severity / Low probability); S13 (inherent); U1
  (pre-existing, outside this design). None is reducible here without contradicting a constraint
  (S9, S13) or widening scope (U1).
- **Low:** all others after the changes.

### Iteration Summary

- **Key mitigations applied:** D1b′ (seeded config + `--password-stdin`); post-login shape check;
  `System::Docker` and an explicit deploy principal for docker; registry-push reads the item
  itself; allowlist reused from `BASICS` with NR-29 and per-OS names; endpoint resolution and an
  image-present check before the read; typed listing parse; requirements amendments.
- **Simplifications applied:** removed the opv-written credential file; replaced reply-text auth
  diagnosis with step classification (login refused = 7, push failed = 9); one allowlist instead
  of two.
- **Trade-offs introduced:** D1b′ adds one call (`docker login`), so the token travels to the
  registry once more. TRIZ #10: that call becomes the definite credential check before any write,
  which buys back the exit-code precision the design wanted from reply parsing. The endpoint
  resolution adds one credential-free call.
- **Stopping:** no High/Medium risk is reducible further within the constraints. A second
  iteration found no new failure mode introduced by the mitigations, except that the post-login
  shape check can itself fail on a future docker config format. That fails closed (refusal, dir
  removed), so its residual is Low.

---

## Phase 3: Systemic Risk Review

- **Calibration risk.** There are no scores or confidence signals in this design. The validators'
  calibration is the open point: the Machine-id shape (S3) and the image grammar are taken from
  observation, not a spec. Validate them with S3 and recorded fixtures. A too-narrow id regex fails
  closed with `usage`, which is safe.
- **Observability risk.** Bad decisions show as refusal codes before the read (T1 asserts zero
  `op` calls). A wrong credential shows as exit 7, an unknown write outcome as exit 9 with a
  scrubbed excerpt, and success as one value-free line plus the job summary. Two gaps: (1) the
  design gave no signal for "token escaped to a helper", and the post-login check (S2) adds one;
  (2) a `machine-update` that applied the image but failed health checks is exit 9, so the
  reconciler must re-run `machines` to learn the state. That is honest, but document it in the
  skill as the expected follow-up.
- **Complexity vs utility.** Proportionate: three rows, one guard family, one RAM purpose, one
  runner scope, one strict sign-in entry point, plus the missing `System::Docker`. The simplest
  viable version is the flyctl pair alone. Registry push carries most of the risk and all of the
  unknowns (Q1, S1, S6).
- **Oversimplification risk.** Not removing O4 (list-before-update) was deliberate: dropping it
  would turn typos into "outcome unknown". Not adding `fly deploy` (D2b) or arbitrary images
  (D3b) is correct.
- **Incremental delivery.** Recommended order: Step 0 (now with `System::Docker`), then L1/L2 and
  the flyctl part of L3/L5, shipping `machines` + `machine-update` once S2/S3/S4 pass. Then
  `registry-push` once Q1 and S1/S6 pass. Each step is additive and opt-in. Rollback is removing
  the subcommand, since the strict sign-in and `isolated_env` are separate entry points. The
  design's single release can still hold both if the spikes land in time. Splitting is a
  scheduling option, not a requirement.

### Final Outcome

All High and Medium risks introduced by this design are mitigated to Low by the changes below.
Three remain at Medium severity with Low probability: S9 (SIGKILL residue, same as the accepted
Azure precedent), S13 (daemon sees the token, inherent to `docker push`) and U1 (90-day expiry,
pre-existing). Mitigating them further would contradict a constraint (SR-4's precedent, the tool's
own design) or widen scope.

---

## Conflicts with owner principles

Each conflict is stated, not resolved.

1. **The design's D1a vs "stdin where the tool offers it".** The design recommends opv writing the
   credential file. `docker login --password-stdin` offers stdin, and the seed removes the
   design's objection. This review recommends D1b′, which follows the principle. The design's own
   recommendation is the part that conflicts, together with SR-4/FR-40. Either way SR-4 needs an
   owner-approved amendment, because docker must store the auth somewhere.
2. **No RAM directory on the consumer's runner (P2/S6).** If Tracking CI runs where there is no
   user-owned tmpfs `$XDG_RUNTIME_DIR` (a container job, some self-hosted runners), the only ways
   to ship `registry-push` there are a disk-backed private directory (contrary to SR-4's RAM-only
   rule for Linux) or not supporting that runner. Owner decision; this review proposes neither.
3. **S4 and S5 vs "a third-party defect is out of scope".** The design lists S5 (flyctl writing an
   env token to `~/.fly/config.yml`) as a spike. Under the principle it is flyctl's behaviour and
   should be recorded as out of scope, not spiked. I still recommend running S4 once. It is not
   mitigating a flyctl defect; it checks whether this design's contract ("changes only the image")
   is true at all. If the owner reads S4 as covered by the principle too, drop it and record it.
4. **Pre-existing leak vs "carry a value without exposing it" (D4).** Today `sync`/`plan` pass
   `OP_SERVICE_ACCOUNT_TOKEN` to `flyctl`, `az`, `kubectl` and `gh` (`runner.rs:1743-1775`). The
   design defers the fix to its own issue (D4a then b). I agree it is out of this design's scope,
   but it contradicts the principle now. Its priority is the owner's call.
5. **No conflict, for the record:** opv invents no role (access to the item is the
   authorization; `--confirm` is intent only); CI writes nothing to 1Password; argv carries no
   value; MCP exposes nothing.

---

## Required design changes

Apply in this order; each is tied to a risk id.

1. **(S1, S2) Replace D1a with D1b′.** Change §5.3 to read:
   1. RAM check and sweep.
   2. Endpoint resolution and `docker image inspect` (P10), before the read.
   3. `PrivateDir::create(base, "opv-docker.")`, and a seed `config.json` with no secret,
      exclusive create, 0600.
   4. Read the item.
   5. `docker login registry.fly.io -u x --password-stdin` under `under_deploy`, token on stdin.
   6. Shape check of `config.json` (auth present for `registry.fly.io`; no `credsStore`, no
      `credHelpers`), otherwise refuse and remove.
   7. `docker push` as a write.
   8. Drop the dir.

   Rewrite D1 accordingly. Option (b)'s "keyring" objection is answered by the seed (§0.1).
2. **(P3) Amend SR-4 and FR-40** in `docs/design/requirements.md` (owner approval): docker's
   per-run `DOCKER_CONFIG` beside az's `AZURE_CONFIG_DIR` as the tool-written exception; `target
   op` added to the commands that read `deploy_credentials`. Add both to L4.
3. **(S3) Add `System::Docker`** (subject, label, codes, render), map `docker` in the runner's
   observation, and add a `docker` `Tool` (`version_args: ["--version"]`, so the probe never needs
   the daemon). Move all of it into Step 0. Correct "No other new cause" in §4.
4. **(S4) State the token route:** `registry-push` reads the item itself through
   `read_deploy_credentials` with the deploy principal; `FlyLogin` stays flyctl-only. Classify
   failures by step: login refused → `CredentialRejected { DeployCredentials }` (7); push failed →
   `WriteOutcomeUnknown` (9). Remove "a new docker diagnosis keyed on recorded replies" except for
   the login refusal fixture.
5. **(S5, S6) Reuse `local_delivery::BASICS`** for `isolated_env`, extended with NR-29 proxy/CA
   names, `XDG_RUNTIME_DIR` and the Windows basics. Move the list to one shared place (the runner
   or `host`); do not keep two copies.
6. **(S7) Daemon endpoint and image check before the read** (P8 extended, new P10,
   `OperationRefused` reasons `ImageNotLocal`, `CredentialStoreEscaped`).
7. **(S10) Extend S4**: autostart/autostop/restart/services/env unchanged after an `--image`-only
   update, run from a directory holding a conflicting `fly.toml`.
8. **(S11) Typed projection** for `machines`/O4; no `serde_json::Value`.
9. **(T1, T2, T3) Contract fixes:**
   - `unknown_env`/`unknown_target` codes.
   - `--target` required in clap; drop `ChoiceRequired`.
   - Docker grammar check on the bound app.
   - Exit 0 without a digest is `UnexpectedOutput { AppliedWrite }`.
10. **(P1, P2) Make Q1 and S6 gates** for the docker half of L3/L5, and say so in §11. Answer Q2
    before L3's flyctl rows.
11. **Small corrections:**
    - The Fly diagnosis citation points at a test (`fly/mod.rs:948-964`).
    - Drop "(there are 44)".
    - Note that `ramdir` retries are Windows-only.
    - Reuse `run::require_confirmation` for P5.
    - Record S5 as out of scope (Conflicts, item 3).

## Spikes still required

| Id | What | Live? | Blocks |
|---|---|---|---|
| S1 | Fly registry accepts `docker login registry.fly.io -u x --password-stdin` with the app-scoped deploy token, and with which password form (the whole `FlyV1 …` string or a part). Push succeeds. Record the replies for an expired/revoked token (`unauthorized`) and for another app's repository (`denied`) | **Live** (owner, throwaway app) | `registry-push` |
| S1-offline | The §0.1 helper/seed probe on the docker CLI version Tracking CI uses; automate it in opv's e2e with a fake registry on 127.0.0.1 and a logging fake helper (no credentials needed) | Offline | `registry-push` |
| S2 | Deploy token accepted by `machine list`/`machine update` for its app, refused for another; record both | **Live** | flyctl operations |
| S3 | Machine id shape (validator) | Live listing or flyctl source | P6 |
| S4 | `--image`-only update leaves the Machine config unchanged; effect of a `fly.toml` in the working directory | **Live** | `machine-update` |
| S6 | In Tracking CI's actual job: a user-owned tmpfs `$XDG_RUNTIME_DIR`; a local Unix-socket daemon; the built image present in that daemon (Q1) | **Live** (Tracking CI) | `registry-push` |
| Q1/Q2 | Tracking CI's publisher tool and reconciler calls | Ask the requester | docker half / flyctl rows |

S5 (flyctl persisting an env token) is not listed: by owner principle it is flyctl's behaviour,
out of opv's scope (Conflicts, item 3).
