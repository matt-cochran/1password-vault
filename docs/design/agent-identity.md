# Agent identity: a read-only machine identity for unattended agents and CI (#338)

Status: design for 0.22.0 (branch `feat/0.22.0-agent-identity`), 2026-11-17, built on opv 0.21.0
(`fb8d3359`). **Revised after the DESIGN-FMECA vet** (`docs/design/agent-identity-review.md`,
verdict "ready with changes"). Every High and Medium change from the vet (R1–R9) is applied, and
so are R10, R11, the corrected code claims and the vet's simplification cuts. The owner's
decisions of 2026-11-17 are recorded as **decided** in §10. Nothing here is built.

Every "today" claim is checked against the code at `fb8d3359` and cites file:line. A claim
marked **unverified** is an assumption that spike S1 must confirm. A claim marked **proposed**
is behaviour this design adds.

Governing decision: [ADR-0001](../adr/0001-never-emit-a-secret-value-through-any-output.md),
rules R1–R5. ADR rules are written "ADR R1" in this document, to tell them apart from the vet's
R1–R11. Requirements kept: SR-1, SR-2, SR-3, SR-4, SR-5, SR-8, FR-11, FR-40, FR-69, NR-31. New
requirement: **FR-71 Agent identity** (§12). FR-70 is already used in code for #314
(`src/domain/access_plan.rs:74`) but has no entry in `requirements.md`, so this design does not
reuse that number.

Related designs: `session-reuse.md` (how agents borrow a person's session today),
`agent-signin-readiness.md`, `placements-and-access-boundaries.md` §6, `docs/reader-grants.md`.

## 1. The decision in one page

opv gets one more identity, built from the same code as the CI reader: the **agent identity**.

- It is a 1Password **service account** that is read-only on exactly the boundary vaults of one
  environment. These are the CI reader's grants (`Principal::CiReader`,
  `src/domain/access_plan.rs:140-151`). There is one per (project, environment, machine).
  1Password enforces read-only, and opv adds its existing service-account refusals on top.
- A person creates it once with **`opv access <env> --create --agent`**, which is the CI command
  with `--agent` in place of `--github <owner/repo>`. A production-tier environment also needs a
  typed `--confirm <env>`. The token goes into this machine's OS credential store. It never
  passes through the chat, argv, a repository file or the agent's environment.
- An opv process that runs **as the agent** reads the token itself, without any prompt and with
  a timeout. It holds it as a `SecretValue` and hands it only to its own `op` children. Captured
  calls use the existing `token_only` path (`src/runner.rs:1853-1880`). `op run`, which opv
  starts through a different path, gets the same isolation (§4.3, vet R1). `opv run`'s app never
  inherits the token (`src/app/local_delivery.rs:150-163`).
- Agents use `run`, `plan`, `ready`, `status` and `doctor`. Deploys (`sync`) stay with CI's
  deploy identity or a person, and opv refuses `sync` under the agent identity (owner, D12).
- The first release selects the agent identity only with **`OPV_IDENTITY=agent`** (rule 3).
  Automatic selection in agent mode (rule 4) follows one slice later (§5). Neither rule ever
  falls back to the person's session.
- `opv doctor` and `opv ready --json` (and through them MCP `opv_state`) carry one value-free
  `identity` row: which identity this run uses, where its token comes from, its expiry, its
  vault reach and its rate-limit headroom. That row also takes the place of a separate list
  command.
- The docs describe one model: **person, CI reader, CI deploy identity, agent identity.** All
  of them deliver the same way, none of them sees values, and only people change values.

**Decided residual (owner, D11).** An agent with a shell that runs as the same OS user can reach
the token. It can read the OS store, read the environment of the long-lived `op run` process
(§4.6), or make an authorized child print a value. opv's own output channels never carry the
token or a value. The docs state this plainly, and offer running the agent as a separate OS
user or in a container as optional hardening. Isolation is not a requirement.

## 2. Goals and non-goals

### Goals

| id | goal |
|---|---|
| G1 | An LLM agent, or a developer's automation, runs `opv run`, `opv plan`, `opv ready`, `opv status` and `opv doctor` unattended, with no person session and no human step. (No `sync`: owner, D12.) |
| G2 | The agent never sees a value or the token through anything opv emits (ADR R1, R5). opv never puts the token in the agent's environment, argv, the chat or a repository file (ADR R2, SR-3, SR-4). |
| G3 | The identity is read-only, and 1Password enforces it. Under it, opv adds refusals and has no write path (ADR R5, FR-11, SR-5). |
| G4 | The same primitive, command family and docs serve CI and agents. |
| G5 | Setup is one command a person runs once per environment and machine. Rotation is one command for every identity on the machine. |
| G6 | Every run can tell, value-free, which identity it uses and what it can reach. |

### Non-goals

- **No opv roles.** 1Password vault access stays the only permission system.
- **No agent writes, on any tier**, including `local`, `opv_import_local` and delivery evidence
  (D4, decided).
- **No agent deploys.** `sync` is refused under the agent identity (D12, decided).
- **No isolation requirement.** opv does not sandbox the agent from its own OS user. Running the
  agent as a separate OS user or in a container is documented as optional hardening (D11,
  decided).
- **No daemon, broker or wrapper** (`docs/design/session-reuse.md:18`; D8, decided).
- **No new MCP surface** (D7, decided).
- **No change to CI**, and no cloud targets (deferred).

## 3. What exists today (verified)

### 3.1 The CI reader and deploy identity

| Fact | Where |
|---|---|
| `opv access <env> --create --github <owner/repo>` creates the read-only CI reader. With `--target`, it creates that target's deploy identity instead. One owner command; the token is "never shown, typed or written to a file". | `src/app/access_create.rs:1-26` |
| `access::identity` computes the name, the grants, whether the account already exists, the account and the missing vaults from `op vault user list`. | `src/app/access.rs:191-279` |
| The CI reader is `{project}-{environment}-ci`, with `Permission::Read` on every boundary vault. | `src/domain/access_plan.rs:111-114`, `:140-151` |
| The deploy identity is `{project}-{environment}-{target}-deploy`: read on the boundary vaults, read and write on its state vault. | `src/domain/access_plan.rs:106-109`, `:119-139` |
| `require_person` guards the create; one confirmation lists every grant and the destination. | `src/app/access_create.rs:244`, `:274-311` |
| `op service-account create <name> --vault <id>:read_items … --expires-in 90d --raw`, run in the environment's account. | `src/app/access_create.rs:316-345` |
| The token goes into a `SecretValue` and is registered with the scrubber at once. An empty token is `SecretNotStored`, and the create is never re-run (X5). | `src/app/access_create.rs:346-363` |
| Optional binding proof: a token-only `op whoami` (`user_type == SERVICE_ACCOUNT`, account UUID) and `op vault list` (the exact vault set). | `src/app/reader_grants.rs:133-177`, `src/app/access_create.rs:366-376` |
| A lost token is reported with "remove it in 1Password". The expiry is recorded value-free in `secrets.bindings.toml`. The command ends with `Next:`. | `src/app/access_create.rs:377-425`, `src/domain/credential.rs:86-88` |
| 1Password fixes a service account's vaults at creation. | `docs/reader-grants.md:18-21` |
| op cannot list service accounts, and a vault's user list never shows one. op's `service-account` commands are only `create` and `ratelimit`. | `src/app/access_create.rs:351-353`, `src/app/access.rs:8-11`, `op service-account --help` (op 2.40.0) |
| `--rotate` makes `<old>-YYYYMMDD` with the same grants, checks it with a token-scoped `op vault list`, and ends with `Do:` revoke the old account. | `src/app/credentials_rotate.rs:1-18`, `:288-323` |
| FR-69: an expiry within 14 days is `credential_expiring`, a past one is `credential_expired`. Both are advisory. The #324 pending-rotation marker and `--revoked`. | `docs/usage.md:779-798` |
| op allows `read_items`, `write_items` and `share_items`. A service account can never be granted a Personal or Private vault. `op service-account ratelimit [<name or id>]` reports hourly and daily usage. | op 2.40.0 `--help`, run locally |

### 3.2 How opv recognises a service account

| Fact | Where |
|---|---|
| `Host::detect` sets `op_credential = Some(ServiceAccount)` when `OP_SERVICE_ACCOUNT_TOKEN` is set. Only the name is checked, never the value. `Host` is process-wide. | `src/host.rs:804-810` |
| `identity_on`: any `op_credential`, or CI, is `Identity::ReadOnly` before any call. | `src/app/tidy.rs:117-132` |
| `require_person_on` refuses `ReadOnly` as `NeedsOwnSession` (`own_session_required`, exit 7). | `src/app/tidy.rs:157-190`, `src/cause/mod.rs:2479` |
| `require_person` or `require_person_on` is called from **12** non-test files: `access_create`, `attest`, `config_store`, `credentials_rotate`, `generate`, `import`, `mcp`, `provision`, `set`, `structure`, `target_credentials` and `tidy`. | `grep -rln require_person src` (the vet's correction) |
| MCP `opv_import_local` refuses on `credential_in_environment`, which reads **environment variables only**. | `src/mcp.rs:1056`, `src/host.rs:1248-1266` |
| Agent markers are "presentation only, never a security control". `refuse_if_agent` turns away person-only commands. `person_only` covers only `apply` and `set`, and the TTY check follows it. | `src/host.rs:33-58`, `:164-175`; `src/main.rs:3149-3157`, `:4021-4059` |

### 3.3 How a token reaches `op`, and how it is kept from other children

| Fact | Where |
|---|---|
| **Captured** `op` calls whose env carries `OP_SERVICE_ACCOUNT_TOKEN` are `token_only`: the environment is cleared to the basics, `OP_*` other than the token is dropped, and `OP_BIOMETRIC_UNLOCK_ENABLED=false` and `OP_CACHE=false` are set. | `src/runner.rs:1853-1880` (`command_for`) |
| **Inherited** calls, `op run` among them, go through `ProcessRunner::inherited` instead. That path keeps the inherited environment, calls `add_op_session`, and sets neither the biometric nor the cache flag. | `src/runner.rs:2122-2131`, `:2160-2188` |
| A token in the call stops `OP_ACCOUNT` being added. | `src/runner.rs:1569-1580` |
| A child that is not `op` gets no `OP_SESSION*`, `OP_SERVICE_ACCOUNT_TOKEN` or `OP_CONNECT_TOKEN`. | `src/runner.rs:1812-1848` |
| `opv run` starts `op run -- <delivery step> <app>` through `run_inherited_clean`. | `src/app/run.rs:387-391`, `:407-423` |
| The delivery step builds the app's environment without any `OP_*`. It **spawns the app and waits** (`.status()`); it does not exec. `op run` and the delivery step therefore live as long as the app. | `src/app/local_delivery.rs:150-163`, `:445-452` |
| Credential variables in opv's own environment are registered with the scrubber at startup. | `src/scrub.rs:477-495` |
| opv itself is non-dumpable on Linux. `op` is a separate process, and the same user can read its `/proc/<pid>/environ`. | `src/hardening.rs:75`; `docs/design/session-reuse.md:263` |

### 3.4 Local agents today, and what readers can do

- An agent borrows the person's session: the desktop app, or the person starting it inside
  `opv login --account <ID> -- <agent>` (`docs/agent-setup.md:263`). That session can also write:
  it tidies items, and `opv_import_local` writes (`docs/agent-setup.md:304-319`).
- The CI "validation reader" runs `inventory`, `plan` and `ready`. `sync` belongs to the deploy
  identity (`docs/agent-setup.md:271-272`).
- `deploy_credentials` are stored in the target's state vault (`docs/usage.md:767`), and so is
  the plan ledger (`docs/usage.md:236`). A reader cannot read either.
- For agents, this means: `plan` and `status` against a target whose sign-in uses a
  `deploy_credentials` item report that credential as failed. Without the ledger, a Fly `plan`
  shows `unknown`. This matches the CI reader today. The exact causes are **unverified**, and
  S12's e2e scenario pins them.

## 4. Token custody

### 4.1 What must hold

| id | property | rule |
|---|---|---|
| C1 | The token never appears in opv's output, `--json`, MCP, logs, errors or opv's own files. | ADR R1, R3, SR-1 |
| C2 | opv never puts the token in argv, a plaintext file, the agent's environment or a non-`op` child's environment. | ADR R2, SR-3, SR-4 |
| C3 | The token is a `SecretValue` and is scrubber-registered from the moment it is read. | ADR R3, SR-2, SR-8 |
| C4 | No step needs a person once the identity is installed, and no read waits on a prompt. | owner; vet R6 |
| C5 | Creation and rotation are a person's acts. | ADR R5, FR-11 |
| C6 | One revoke in 1Password ends the identity. | SR-5 |

### 4.2 Options considered

| | Option | Verdict |
|---|---|---|
| E | Export `OP_SERVICE_ACCOUNT_TOKEN` in the agent's shell, as CI does | Rejected. `env` shows it, which breaks C2. |
| K | **OS credential store, read by each opv process** | **Chosen.** Unattended, and never in the environment or argv. Same-user reach is the decided residual (D11). |
| P | A 1Password item in the person's Private vault | Not unattended on its own. It is kept **only if S1 finds the WSL store volatile**, as the durable copy for `--install` (D2, D10). |
| W | An `opv agent -- <agent>` wrapper or broker | Declined (D8). It protects no more than K and adds a process. |

### 4.2.1 1Password platform options (2026-11)

Why a service account is the 0.22.0 primitive. The coordinator supplied these sources on
2026-11-17. The 1Password pages were not fetched again for this revision. The service-account
facts were checked against op 2.40.0's help (§3.1).

| Option | What it is | Verdict |
|---|---|---|
| Service accounts | GA in op 2.40. `read_items` by default, scope fixed at creation (`docs/reader-grants.md:18-21`), `--expires-in`. | **Chosen.** It is the CI reader's primitive already, and it works unattended on every platform. |
| Environments: local `.env` mount ([1password.dev/environments/local-env-file](https://www.1password.dev/environments/local-env-file)) | A named pipe served by the desktop app, which needs a person's authorization at each unlock. macOS and Linux only, so no Windows or WSL, and not for concurrent readers. | Rejected: not unattended, and missing on the owner's platform. |
| 1Password for Agents / for Claude | Human approval per request, and browser autofill. | Not applicable: it needs a human and does not serve CLI delivery. |
| Credential Broker, public preview/beta ([1password.dev/brokered-access/custom-workflow](https://www.1password.dev/brokered-access/custom-workflow)) | OIDC workload identity, with no stored token. JS SDK only, no op CLI support, aimed at CI. | Not usable from opv today. It is a candidate for a future source. |
| AI Agent Identity Kit ([1password.com/solutions/ai-agent-identity](https://1password.com/solutions/ai-agent-identity)) | `op agent identity issue` issues 10-minute tokens. The Local Agent Broker is "coming soon". | Not available yet. It is the most likely future source. |

**Design consequence.** Where the agent's token comes from is one small trait,
`AgentCredentialSource`. Its methods are: resolve for (account, project, env), returning a
`SecretValue` or a typed cause; describe, returning a value-free name, source and expiry for the
`identity` row; and an availability preflight. 0.22.0 ships one implementation: a
service-account token read from the OS store (S4). Selection (§5), refusals (§6), the runner
hand-off (§4.3) and the docs depend only on the trait and on `OpCredential::Agent`. A later
source that is short-lived and stores nothing (the Local Agent Broker or the Credential Broker)
can therefore replace it without touching any of them. That would remove the stored-token
residual (§4.6, point 1). It is follow-up work F3 (§14), not a 0.22.0 slice.

### 4.3 The flow (proposed)

1. **Create** (a person, in their own terminal). `opv access <env> --create --agent [--confirm
   <env>]` reuses `access_create`'s person check, identity computation, `not_in_account`
   refusal, confirmation and create effect (§7.1). After `op service-account create … --raw`,
   it does this:
   1. **Bind, always.** It runs the token-only `whoami` and `vault list` from
      `reader_grants::issued` (`src/app/reader_grants.rs:154-177`). The account UUID must equal
      the environment's account, and the vault set must equal the requested read set. If not,
      nothing is stored, and the person is told to remove the new account in 1Password
      (`src/app/access_create.rs:368-372`).
   2. **Store** the token in the OS store (§4.4), keyed `account_id/project/env` under service
      `opv`, through the platform API (never a CLI's argv).
   3. **Check end to end.** It reads the token back non-interactively and runs one token-scoped
      `op vault list`.
   4. **Record** the value-free index entry (§7.5) with `expires_on` = today + 90 days, then
      print (§7.2).
   If step 2 or 3 fails after the account exists, the lost-token rule applies
   (`src/app/access_create.rs:379-388`): opv names the account and says to remove it before
   running again, and it never re-runs the create (X5).
2. **Use, for captured calls** (`whoami`, `item get`, `vault list` and so on). opv resolves the
   identity **once per process, before its first `op` call** (§5). It reads the token
   non-interactively, with a 5-second timeout (vet R6), wraps it in a `SecretValue`, registers
   it, and attaches it to the runner. Each captured `op` call carries it in `Call.env` and takes
   `token_only` (`src/runner.rs:1853-1880`).
3. **Use, for `op run`** (vet R1). `ProcessRunner::inherited` gets a token branch. When the
   program is `op` and the call env holds `OP_SERVICE_ACCOUNT_TOKEN`, it:
   - removes every inherited `OP_SESSION*`, `OP_CONNECT_*` and `OP_ACCOUNT`;
   - skips `add_op_session`;
   - sets `OP_BIOMETRIC_UNLOCK_ENABLED=false` and `OP_CACHE=false`;
   - does **not** clear the environment, because `op run` passes it on to the app through the
     delivery step.
   A simulator test asserts the exact environment of `op run`.
4. **`opv run`'s app.** The delivery step strips every `OP_*` before it spawns the app
   (`src/app/local_delivery.rs:162`). The app never *inherits* the token. But the delivery step
   spawns the app and waits (`:445-452`), so `op run` stays alive, with the token in its
   environment, for the whole life of the app (§4.6, point 2).
5. **An agent that runs `env`** sees `OPV_IDENTITY=agent` at most.

### 4.4 Stores per platform (S1 gates the final choice)

| Platform | Working copy | Notes |
|---|---|---|
| macOS | Keychain (login keychain), generic password | Same-user tools can read it. The per-app access list is **not** treated as a control (vet R2): `op run`'s environment exposes the token anyway. |
| Windows | Credential Manager | Any same-user process can read it. |
| Linux desktop | Secret Service over D-Bus | A locked collection would prompt. opv never waits for that: it fails with `agent_store_locked`. |
| WSL, headless Linux | **Decided by S1** (D10): Secret Service when a daemon is present and survives a WSL VM stop. Otherwise the kernel user keyring as a fallback, with doctor `FAIL agent_store_volatile`. | The `@u` keyring is lost when the WSL VM stops (idle shutdown, `wsl --shutdown`, reboot). It may also be lost when the user's last process exits (**unverified**). |
| none usable | refused before create: `agent_store_unavailable` | Never a file fallback (SR-4). |

**Selection at create, reads from the record (fix, 2026-11-23).** File checks alone (WSL,
interop enabled, `powershell.exe` present) do not show that interop works: on the owner's
machine `powershell.exe` exited 1 after about 10 s with `UtilAcceptVsock: accept4 failed 110`,
and every agent-identity command failed as a "locked" store. `--create --agent` now runs the
interop store's `probe` (bounded by the 15-second write bound, no prompt) before choosing it;
when it does not answer, the Linux order applies (a Secret Service that answers and is
unlocked, else the kernel keyring with `agent_store_volatile`). `OPV_AGENT_STORE=wincred|
secret-service|kernel-keyring` overrides the choice; another value is `usage`. The index
records the store and, when it is not the platform's own, why (`store_reason`); doctor shows
both. Reads, rotation and removal open the recorded store only: when it is unusable they stop
with its own cause, `agent_store_interop_down` for interop (a code the script never uses, a
child that will not start, or one that outlives its bound), never another store's answer.

Library: the Rust `keyring` crate. Its backends, versions, non-interactive mode and headless
behaviour are **unverified** (S1).

### 4.5 What is enforced

- opv's output on every channel (ADR R1): canary e2e in S12.
- The agent's environment and argv (C2).
- Non-`op` children and the app's inherited environment (`src/runner.rs:1812-1848`,
  `src/app/local_delivery.rs:162`).
- opv's own memory and environ (`src/hardening.rs:75`).
- Repository files: the index (§7.5) lives under the user's config directory and holds no value.
- Store reads never prompt and never hang (C4).

### 4.6 What is not defended (accepted residuals, owner D11)

1. **The store.** A same-user shell can read the working copy (`secret-tool lookup`,
   `security find-generic-password -w`, PowerShell `CredRead`, `keyctl print`) and run `op`
   with it.
2. **`op run`'s environment.** `op run` is a separate process, normally dumpable, and lives as
   long as the app (§4.3, point 4). Its environment holds the token, so the same user can read
   it through `/proc/<pid>/environ` on Linux and WSL, or `ps eww` on macOS. The app, and any
   dependency it runs, can read its grandparent's environment. This is standard OS behaviour,
   not measured for `op` here. Follow-up F1 (§14) removes the long-lived holder.
3. **What an authorized child prints.** `opv run dev -- sh -c 'echo $DB_URL'`. `op run` masks
   known values (ADR R4), but masking is defense in depth only. ADR-0001 says: "What a child
   process prints is the child's responsibility".
4. **The person's other sessions.** An agent that can reach the person's desktop-app session,
   or that sets `OPV_IDENTITY=person`, can act as the person. Markers and TTY checks are not
   controls (`src/host.rs:33-38`; `script` fakes a TTY). The docs therefore say to start the
   agent where no person session reaches it: no desktop CLI integration in its terminal, and
   not inside `opv login --`.

What limits the damage: the identity is read-only and covers one environment. Production needs
a typed confirmation at create. It lasts 90 days, rotates with one command and is revoked once
per machine. opv itself never returns a value to the agent. Optional hardening (documented, not
required): run the agent as a separate OS user, or in a container that cannot reach the
person's OS store.

## 5. Which identity a run uses (proposed)

The identity is resolved **once per process, before the first `op` call**, for the account and
project of the run. The first matching rule wins:

| # | Condition | Identity | Ships |
|---|---|---|---|
| 1 | `OP_SERVICE_ACCOUNT_TOKEN` or `OP_CONNECT_*` is set | that credential (CI, today) | today |
| 2 | `OPV_IDENTITY=person` | the person's session | MVP |
| 3 | `OPV_IDENTITY=agent` | the agent identity, per environment | MVP |
| 4 | an agent marker, and **any** agent identity installed on this machine for this account and project | the agent identity, per environment | S17, after the MVP |
| 5 | otherwise | the person's session (today) | today |

Under rules 3 and 4, an environment with no agent identity of its own **stops** with
`agent_identity_not_installed` (exit 7, `human_required`, `Next:` the create command for the
person). It **never** falls back to the person's session (vet R4). So one process cannot use
the agent identity for `dev` and the person's write-capable session for `prod`. A multi-env
`ready`, and MCP, report that stop per environment and carry on with the others.

When the agent identity is selected:

- `Host::op_credential = Some(OpCredential::Agent)`, a new variant. It is set once, before any
  `Host::detect()` reader runs, so the roughly 51 call sites see one answer (vet R4).
- The env-only checks (`credential_in_environment` in `src/mcp.rs:1056`, `provision`) consult
  the selected identity instead (S7, FM4).
- `sync` is refused before any call with `own_session_required`. Its `Next:` says to run it in
  your own terminal or let CI's deploy job run it (D12).

**`!` commands (vet R10).** Claude Code's `!` shell carries the agent host's environment. With
`OPV_IDENTITY=agent` set there (and from S17 on, with `CLAUDECODE` alone), person commands typed
after `!` (`import`, `target credentials`, `access --create`) are refused. The refusal's `Next:`
says "run this in your own terminal". It **never** suggests `OPV_IDENTITY=person`.

## 6. Read-only enforcement

| Layer | What enforces it | Status |
|---|---|---|
| 1Password | `read_items` only, boundary vaults only. No `write_items`, no state vault, no `--can-create-vaults`, and it cannot be widened later (`docs/reader-grants.md:18-21`). | 1Password-enforced |
| Create binding | The token-only `whoami` and `vault list` must equal the request before the token is stored. | proposed; reuses `src/app/reader_grants.rs:154-177` |
| opv refusals | `ReadOnly`, then `own_session_required`, for every person write (the 12 callers in §3.2), plus `sync`. | exists for environment tokens; proposed for the loaded identity (S7) |
| Owner commands | `access --create/--rotate --agent` join `person_only`. | proposed. **UX only, not a control** (vet R9): the agent's own refusal is 1Password's. |

Read-only applies on every tier, `local` included (D4).

## 7. Admin UX (proposed, MVP)

The MVP is **create, use, rotate and the `identity` row** (the vet's cut). `--agent` takes the
place of `--github`.

| Command | Who | Effect |
|---|---|---|
| `opv access <env> --create --agent [--name <machine>] [--confirm <env>]` | person | create the identity and store it on this machine |
| `opv access [<env>] --rotate --agent [--revoked <name>]` | person | with `<env>`, that identity; **without, every agent identity recorded on this machine** (vet R8) |
| `opv doctor --env <env>`, `opv ready --json` | anyone, agents included | the `identity` row (§7.4), in place of a list command |

`--name` defaults to the hostname, lowercased, `[a-z0-9-]`, at most 32 characters. The account
is `{project}-{env}-agent-{machine}`. `--agent` conflicts with `--github`, `--github-env`,
`--secret-name`, `--target` and `--grant-receipt`. After the MVP: `--remove --agent` (S18), and,
only if S1 finds the store volatile, `--install --agent` with the Private-vault copy (S19).

### 7.1 Code path

`access_create::run_with_receipt` gets a destination,
`enum Destination { GitHub(GitHub), Machine(MachineStore) }`. Everything before the token exists
is shared. The GitHub preflight becomes the store preflight (`agent_store_unavailable`,
`agent_store_locked`), and `ci_secrets::store` becomes §4.3 steps 2 to 4. A new
`Principal::Agent { environment, machine }` gets `CiReader`'s grants. The production-tier
`--confirm` check goes before the prompt. `credentials_rotate::run_access` is generalised the
same way.

### 7.2 `--create --agent`

```
$ opv access dev --create --agent
Create 1Password service account "shop-dev-agent-laptop" (the read-only agent identity of dev on this machine), valid 90 days, with:
  vault 4bq2…: read
  vault x7hd…: read
and keep its token in this machine's macOS Keychain. The token is never shown.
It reads these vaults' values only to deliver them, and can never change them. An assistant running as you can still reach the token; see opv guide agent, "Agent identity".
Go ahead? [y/N] y
created "shop-dev-agent-laptop"; checked it reads exactly these 2 vaults; stored its token in macOS Keychain; nothing was printed
Set OPV_IDENTITY=agent in your assistant's environment to use it.
Next: opv doctor --env dev
```

| Refusal (before the prompt) | Code | Exit | Next / Do |
|---|---|---|---|
| no usable OS store | `agent_store_unavailable` | 3 | `Do:` the platform fix; no file fallback |
| store locked, or it would prompt | `agent_store_locked` | 7 | `Do:` unlock the login keyring, then run again |
| production-tier environment without `--confirm <env>` | `confirm_required` | 6 | the same command with `--confirm prod` |
| assistant marker, or no TTY | `person_only` / `terminal_required` | 6 | "run this in your own terminal" |
| service account or CI | `own_session_required` | 7 | `opv login <env>` |
| already installed here | `agent_identity_exists` | 6 | `Next: opv access dev --rotate --agent` |
| vault not in the account | `vault_not_in_account` | 4 | `opv vault locate <id>` |

### 7.3 `--rotate --agent`

```
$ opv access --rotate --agent
Replace 2 agent identities on this machine, each with a fresh one valid 90 days and the same read-only vaults:
  shop-dev-agent-laptop      -> shop-dev-agent-laptop-20261117      (dev, 2 vaults)
  shop-staging-agent-laptop  -> shop-staging-agent-laptop-20261117  (staging, 3 vaults)
Go ahead? [y/N] y
created and checked 2 successors; replaced both tokens in macOS Keychain; nothing was printed
Do: revoke these in 1Password (Developer > Service accounts); opv cannot: shop-dev-agent-laptop, shop-staging-agent-laptop
Next: opv doctor
```

Each successor's token replaces the old one only after it passes the token-scoped check. The
#324 marker is written per identity before each create. An interrupted run refuses that
identity with `secret_not_stored` and `--revoked <name>` (`docs/usage.md:798`) and carries on
with the rest. A production-tier identity in the batch needs `--confirm <env>` for that
environment, or it is skipped with a note.

### 7.4 The `identity` row: doctor, ready and MCP

**`opv doctor`**: a new `op identity` row after `op auth`, one per environment in scope.

| Situation | Row | JSON `state` |
|---|---|---|
| agent in use | `ok    op identity: agent shop-dev-agent-laptop (read-only; token from macOS Keychain; reads 2 of 2 vaults; expires 2027-02-15)` | `agent` |
| person | `ok    op identity: you (your 1Password app session)` | `person` |
| CI or environment token | `ok    op identity: service account from OP_SERVICE_ACCOUNT_TOKEN (read-only)` | `service_account` |
| expiring within 14 days | `warn  op identity: agent shop-dev-agent-laptop expires in 9 days` + `fix: opv access --rotate --agent` | `agent_expiring` |
| rate limit near (vet R7) | `warn  op identity: agent shop-dev-agent-laptop has used 92% of its hourly 1Password reads; CI may share this account's limit` | `rate_limit_near` |
| assistant marker with an env token | `warn  op identity: OP_SERVICE_ACCOUNT_TOKEN is in this process's environment, so an assistant here can read it with env; use opv access dev --create --agent` | `token_in_agent_env` |
| assistant marker on the person's session | `warn  op identity: an assistant is using your own 1Password session, which can write; for read-only runs: opv access dev --create --agent, then OPV_IDENTITY=agent` | `assistant_on_person_session` |
| no agent identity for this environment (rules 3 and 4) | `FAIL  op identity: no agent identity for dev on this machine` + `fix: opv access dev --create --agent` (person) | `agent_not_installed` |
| store locked or prompting | `FAIL  op identity: the login keyring is locked; opv never waits on its prompt` + `fix: unlock it` | `agent_store_locked` |
| volatile store (vet R5) | `FAIL  op identity: the token is in the kernel keyring, which WSL clears when it stops; unattended runs will break` + `fix:` the S1-decided store | `agent_store_volatile` |
| token rejected (revoked or expired) | `FAIL  op identity: agent shop-dev-agent-laptop was rejected by 1Password` + `fix: opv access dev --rotate --agent` | `agent_rejected` |

- "reads N of M vaults" comes from the token-scoped `op vault list`, compared with the
  configuration's read set. It never claims "writes none" (`docs/reader-grants.md:16`).
- The rate-limit figure comes from `op service-account ratelimit` under the token, as counts
  only. Whether it needs a name or ID argument under a token, and its JSON shape, are
  **unverified** (S1). When it cannot be read, the row omits the figure and never fails. A 429
  is diagnosed through the existing `Cause::RateLimited` (`src/cause/mod.rs:696`).

**`opv ready --json`**: an `identity` object per environment:
`{"kind": "agent", "name": "shop-dev-agent-laptop", "source": "macos_keychain",
"read_only": true, "expires_on": "2027-02-15", "reach": {"readable": 2, "expected": 2},
"rate_limit": {"hourly_used_pct": 92} | null, "state": "<a doctor state above>"}`. `kind` is one
of `agent`, `service_account`, `connect`, `person` or `none`. Expiry reuses FR-69's
`credential_expiring` and `credential_expired`, with the same 14-day threshold (vet R8). They
stay advisory and never count toward `--gate`.

**MCP**: no new tool and no new section (D7). `opv_state` `ready` and `accounts` carry the same
object, because each section is the CLI's `--json` document (`src/mcp.rs:5-7`).

The vet's R11 found that the old list command claimed to read titles only while showing another
machine's expiry. That command and its cross-machine rows are removed. 1Password's own
Developer > Service accounts page is the view across machines.

### 7.5 Local index (value-free)

`$XDG_CONFIG_HOME/opv/agent-identities.toml` (the platform config directory elsewhere). One
entry per identity on this machine holds `name`, `project`, `environment`, `account_id`,
`store`, `expires_on`, and, while a rotation is pending, `rotation_successor` and
`rotation_started_at`. It exists so `--rotate --agent` with no environment can enumerate
identities, and so expiry can be read without opening the store. It holds no value and no
digest (ADR R1), and it lives outside the repository. If S1 shows the store's own attributes
can be enumerated portably, the index shrinks to the rotation marker. That depends on the
`keyring` API, which is **unverified**.

## 8. CI and agents as one model

| Identity | Created with | Token lives | Lifetime | 1Password access | Runs | Writes 1Password |
|---|---|---|---|---|---|---|
| Person | `opv login` or the 1Password app | the app or the shell | session | what the person can open | everything | yes: the only identity that changes values |
| CI reader | `opv access <env> --create --github <repo>` | GitHub secret | 90 days | read, boundary vaults | inventory, plan, ready | never |
| CI deploy identity | `… --target <t> --create --github <repo>` | GitHub secret | 90 days | read boundary, read and write its state vault | sync, deploy | value-free delivery evidence only |
| Agent identity | `opv access <env> --create --agent` | this machine's OS store | 90 days | read, boundary vaults (the CI reader's grants) | run, plan, ready, status, doctor | never |

One sentence for every place it appears: **"Every identity delivers through the same path, and
none of them sees a value. Only a person changes values. 1Password vault access is the only
permission. Deploys belong to CI or a person."**

## 9. Docs and skill changes

| File | Change |
|---|---|
| `docs/agent-setup.md` | New section "Run unattended: the agent identity", after `:11-38`: the §8 table; the person's one command; `OPV_IDENTITY=agent` in the agent host's environment; how to check (`opv doctor --env <env> --json`); §4.6 word for word, including "an assistant running as you can reach the token", with a separate OS user or container as optional hardening; start the agent where no person session reaches it. "Sign-in and accounts" (`:248-266`) puts this path first. §7 CI (`:268-280`) links the table. The exit-7 row adds `agent_identity_not_installed`, `agent_store_locked` and `agent_rejected`, all the person's. |
| `docs/agent-skill.md` and `src/app/skill.rs` | At session start, read `identity`. When it is not `agent` and the user wants unattended runs, hand over the create command. Never run it, never read the OS store, never set `OPV_IDENTITY=person`, never run `sync` as the agent. |
| `docs/usage.md` | The admin row (`:44`) adds `--agent`. A new section "Agent identities" (create, rotate, the outputs in §7). The expiry section (`:779-800`) gets agent rows. The JSON contract gets `identity` and the new codes. |
| `README.md` | A "who can do what" line and the one-line setup. |
| `llms.txt` | Line 13 puts the agent identity first. |
| `docs/mcp.md` | `identity` in `ready` and `accounts`. |
| `docs/configuration.md` | `OPV_IDENTITY`. |
| `docs/design/requirements.md` | FR-71 (§12). FR-11 and SR-5 name the agent identity. |
| `CHANGELOG.md` | 0.22.0. |
| opv-site (read-only here) | `src/pages/assistants/index.astro` (main: the table, the command, the residual); `src/components/home/ForAgents.astro`; `src/components/home/Security.astro`; `src/components/home/HowItWorks.astro`; `src/components/home/Features.astro`; `src/pages/docs/index.astro`; `public/llms.txt`; `public/INSTALL.md`. |

## 10. Decisions

### Decided by the owner (2026-11-17)

| id | Decision |
|---|---|
| D1 | **Per machine.** One identity per (project, environment, machine). A lost machine is one revoke. |
| D4 | **Read-only everywhere.** No value writes on any tier, no tidy, no `opv_import_local` and no state-vault write. Only people change values. |
| D6 | **Production allowed**, but creating an agent identity for a production-tier environment needs a typed `--confirm <env>`. |
| D7 | **No new MCP surface.** `identity` rides in the existing `ready` and `accounts` documents. |
| D8 | **No wrapper.** Selection is `OPV_IDENTITY=agent` in the agent host's configuration. |
| D11 | **Shell residual accepted and documented.** A same-user agent with a shell can reach the token. The docs say so plainly. A separate OS user or a container is optional hardening, not a requirement. |
| D12 | **No sync for agents.** Agents use `run`, `plan`, `ready`, `status` and `doctor`. opv refuses `sync` under the agent identity, and deploys stay with CI's deploy identity or a person. |

### Adopted from the vet (by the coordinator's instruction)

| id | Decision |
|---|---|
| D3 | Sequencing: ship rule 3 (`OPV_IDENTITY=agent`) first and rule 4 (auto-select in agent mode) one slice later. Both stop instead of falling back. |
| D5 | **90 days, warn at 14** (FR-69 unchanged). `--rotate --agent` with no environment rotates every identity on the machine. |

### Gated by spike S1

**D2 and D10: the WSL and headless store, and whether a durable copy exists.** S1 measures
whether the kernel keyring and a Secret Service daemon survive a WSL VM stop.

- **If a persistent store works on stock WSL:** use it. There is no Private-vault copy and no
  `--install`, and S19 is dropped.
- **If only volatile stores work:** the supported WSL path is Secret Service (with setup
  documented). The kernel keyring stays a fallback, with doctor `FAIL agent_store_volatile`.
  S19 then adds the Private-vault durable copy and `--install --agent`, a person step after each
  WSL stop, which goes against "fully unattended". That trade-off goes back to you with S1's
  numbers.

**Recommendation:** decide after S1. Prefer a persistent store over adding the durable copy.

### Still open (follow-up, not in 0.22.0)

- **D9, narrower than one environment (`--product`).** Recommendation: a follow-up issue. It
  needs a product-scoped vault computation, because `CiNeeds` is per environment
  (`src/domain/access_plan.rs:51-55`).

## 11. Failure modes (revised after the vet)

Severity is H, M or L, with residual probability after mitigation in parentheses. Mitigations
are listed in order: prevention, then detection, then fail-fast.

| id | Failure mode | Sev (res P) | Prevention | Detection | Fail-fast |
|---|---|---|---|---|---|
| FM1 | opv prints the token | H (L) | `SecretValue` plus registration at every read | Canary e2e on stdout, stderr, `--json` and MCP (S12) | Scrubber (ADR R4) |
| FM2 | Token in the agent's environment | H (L) | Never exported; docs show no export | doctor `token_in_agent_env` | advisory |
| FM3 | `op run` uses the person's session or the app instead of the token (vet R1) | M (L) | Token branch in `inherited` (§4.3, point 3) | Sim assertion on `op run`'s environment | the `identity` row names the identity |
| FM4 | A write path misses the loaded identity (environment-only checks) | H (L) | One `OpCredential::Agent`, set once; S7 replaces the environment-only checks | Sim matrix over the 12 callers and `sync` | 1Password refuses: no `write_items` |
| FM5 | Over-granted account, or the wrong account | H (L) | Grants only from `Principal::Agent` = `CiReader` | Binding check before storing | nothing stored |
| FM6 | Agent mints or widens its own identity | H (**residual**, accepted D11) | `person_only` and the TTY check, as UX only (vet R9) | doctor `assistant_on_person_session` | 1Password: the agent identity cannot create service accounts; a person session can |
| FM7 | Same-user reads of the store, or `op run`'s environment (vet R2) | H (**residual**, accepted D11) | Read-only, one environment, production confirmed, 90 days; F1 removes the long-lived holder | 1Password service-account activity (**unverified** per plan) | revoke |
| FM8 | Token lost between create and store | M (L) | bind, store, check, then index; never retried (X5) | each step names the account | lost-token message |
| FM9 | No store, or a volatile store (vet R5) | M (M) | S1 gate; preflight | doctor `agent_store_volatile` | `agent_store_unavailable`; no file fallback |
| FM10 | A store prompt hangs an unattended run (vet R6) | M (L) | Non-interactive reads, 5-second timeout | doctor row | `agent_store_locked` (exit 7) |
| FM11 | Agent runs on the person's write-capable session | M (**residual**, accepted D11) | Rules 3 and 4 never fall back; docs say to keep person sessions out of the agent's terminal | doctor `assistant_on_person_session` | `agent_identity_not_installed` |
| FM12 | One process mixes the agent (dev) with the person (prod) (vet R4) | H (L) | Resolve once per process; an environment with no agent identity stops | multi-env `ready` test | `agent_identity_not_installed` |
| FM13 | Agent loops exhaust the account's shared rate limit (vet R7) | M (M) | docs; one identity per machine | doctor and ready `rate_limit_near` | `RateLimited` diagnosis (`src/cause/mod.rs:696`) |
| FM14 | Rotation churn and stale live accounts (vet R8) | M (L) | 90 days; one command rotates every identity; one `Do:` names every old account | FR-69 `credential_expiring` | `agent_rejected` → rotate |
| FM15 | Interrupted rotation | M (L) | #324 marker per identity | refusal names the successor | `--revoked <name>` |
| FM16 | Agent runs `sync` | M (L) | refused under the agent identity (D12) | refusal test | `own_session_required` |
| FM17 | Expired or revoked token | M (L) | 90 days, warning at 14 days | `credential_expiring` | `agent_rejected` with `Next:` rotate |
| FM18 | Docs tell an agent to fetch or paste the token | H (L) | one wording, checked against ADR-0001 | docs test: no `OP_SERVICE_ACCOUNT_TOKEN=` in the agent docs | none |
| FM19 | `!` commands under the agent are refused (vet R10) | L (L) | `Next:` "run this in your own terminal"; never `OPV_IDENTITY=person` | none | refusal |
| FM20 | Masking taken as permission | H (**residual**) | skill rules, ADR-0001 | `op run` masking | none |

## 12. Requirement FR-71: Agent identity (#338), proposed text

- `opv access <env> --create --agent [--confirm <env>]` creates one 1Password service account
  per (project, environment, machine). It has `read_items` on exactly the environment's boundary
  vaults. Production tier needs the typed confirmation. The token is stored in the OS credential
  store and never shown. It is a person's command.
- A run uses the identity only by §5's rules, resolved once per process. It never falls back to
  a person's session. Under it, opv writes nothing to 1Password on any tier and refuses `sync`.
- The token reaches only opv's own `op` children: captured calls through `token_only`, and
  `op run` with the person's session, Connect, `OP_ACCOUNT`, the biometric unlock and the cache
  removed. It is never in the agent's environment, argv or a file.
- Store reads never prompt: `agent_store_locked`, `agent_store_unavailable`,
  `agent_store_volatile`.
- `doctor`, `ready` and MCP report the identity, its source, expiry, vault reach and rate-limit
  headroom. Never a value, digest or length.
- Lifetime 90 days, warning at 14 (FR-69). `--rotate --agent` rotates one identity or all of
  them. opv never revokes; it says how.
- Documented residual: an agent with a shell that runs as the same OS user can reach the token.
- Constraints kept: ADR-0001 R1–R5, SR-1, SR-2, SR-3, SR-4, SR-5, SR-8, FR-11, FR-40, FR-69,
  NR-31.

## 13. Self-vet against ADR-0001

| Rule | How this design keeps it |
|---|---|
| ADR R1 | The token and values never reach output. The `identity` row holds names, ids, dates, counts and states. The index is value-free. |
| ADR R2 | The token goes to `op` only through the call's environment, and to the store through its API. Never argv, never a plaintext file. |
| ADR R3 | `SecretValue` plus registration at create and at every store read. |
| ADR R4 | No new path for child output. Masking is never what makes a path safe (§4.6). |
| ADR R5 | Read-only in 1Password and in opv, with `sync` refused. opv never returns a value to the agent. |

## 14. Delivery slices

The machine-readable form, with acceptance criteria and checks, is
`docs/design/agent-identity-slices.json`. A0 (the vet) is done: `agent-identity-review.md`.

### MVP (0.22.0)

| id | Title | h | Prereqs | Owned files |
|---|---|---|---|---|
| S1 | Spike: `keyring` backends and non-interactive reads; WSL store survival (gates D2/D10); `op service-account ratelimit` under a token; `--expires-in 90d`; service-account count limit | 3 | none | `docs/design/spike-338-findings.md` |
| S2 | Domain: `Principal::Agent`, `agent_account()`, `CiReader` grants, `AgentRecord` index type | 2 | none | `src/domain/access_plan.rs`, `src/domain/access_plan_tests.rs`, `src/domain/agent_identity.rs` |
| S3 | Causes and codes: `agent_identity_not_installed`, `agent_identity_exists`, `agent_rejected`, `agent_store_unavailable`, `agent_store_locked`, `agent_store_volatile` | 3 | none | `src/cause/mod.rs`, `src/cause/codes.rs`, `src/cause/render.rs`, `src/adapters/onepassword_diagnose.rs` |
| S4 | Credential-store adapter: the `AgentCredentialSource` trait (§4.2.1), a fake, the OS-store source over the backends S1 chose, non-interactive 5-second reads | 4 | S1, S3 | `src/adapters/credential_store.rs`, `src/adapters/credential_store_tests.rs`, `src/adapters/mod.rs`, `Cargo.toml`, `Cargo.lock` |
| S5 | Selection rules 1–3, resolved once per process; `OpCredential::Agent`; stop without fallback | 3 | S2, S4 | `src/identity.rs`, `src/host.rs`, `src/lib.rs` |
| S6 | Runner: token on captured calls (`token_only`) and on inherited `op run` (vet R1) | 3 | S5 | `src/runner.rs`, `src/app/signin.rs` |
| S7 | Refusal unification, `sync` refused under the agent, write-path matrix | 3 | S5 | `src/app/tidy.rs`, `src/mcp.rs`, `src/app/provision.rs`, `src/app/sync.rs`, `tests/agent_identity_refusals.rs` |
| S8 | `--create --agent`: `Destination` split, binding check, store, index, production `--confirm`, clap flags for create and rotate, `person_only` | 4 | S2, S3, S4 | `src/app/access_create.rs`, `src/app/access_create_tests.rs`, `src/app/agent_identity.rs`, `src/main.rs` |
| S9 | `--rotate --agent`, one or all on the machine; #324 marker per identity | 4 | S8 | `src/app/agent_identity_rotate.rs`, `src/app/credentials_rotate.rs` |
| S10 | Doctor `op identity` row: states, reach, expiry, rate limit, store states | 3 | S5, S6 | `src/app/doctor.rs`, `src/app/doctor_session.rs`, `src/adapters/onepassword_ratelimit.rs` |
| S11 | `ready` `identity` object, FR-69 agent expiry, schema and JSON (MCP follows) | 3 | S10 | `src/app/ready.rs`, `src/schema.rs`, `src/json.rs`, `src/domain/credential.rs`, `tests/surface_contract.rs` |
| S12 | opv-sim (create, whoami, vault list, ratelimit under a token); e2e with token and value canaries, `op run` environment, `plan`/`status` causes | 4 | S6, S8 | `tests/sim/op.rs`, `tests/sim/world.rs`, `tests/e2e/scenarios/agent_identity.rs`, `tests/e2e/main.rs` |
| S13 | Docs for agents: setup guide, skill, llms | 3 | S8, S10, S11 | `docs/agent-setup.md`, `docs/agent-skill.md`, `src/app/skill.rs`, `llms.txt` |
| S14 | Docs for people: usage, README, MCP, configuration, FR-71, changelog | 3 | S8, S9, S11 | `docs/usage.md`, `README.md`, `docs/mcp.md`, `docs/configuration.md`, `docs/design/requirements.md`, `CHANGELOG.md` |
| S15 | Release gate: `cargo test`, clippy, e2e with `CI=true` | 1.5 | S2–S14 | none |
| S16 | Owner step: create an agent identity on WSL, run `opv run dev -- cargo test` from an assistant with `OPV_IDENTITY=agent`, check that `env` shows no token | 0.5 | S15 | none |

The MVP is about 47 hours. Its critical path is S1 → S4 → S5 → S6 → S10 → S11 → S13 → S15 →
S16, about 24 hours. S2, S3 and S1 start together. S8 and S9 run beside S5 to S10, and S12
beside S10 and S11.

### After the MVP (0.22.x)

| id | Title | h | Prereqs | Owned files |
|---|---|---|---|---|
| S17 | Rule 4: auto-select in agent mode; once one identity is installed for the account and project, an environment without one stops | 3 | S15 | `src/identity.rs`, `tests/agent_identity_selection.rs` |
| S18 | `--remove --agent`: delete the store entry and index entry; `Do:` revoke | 2 | S15 | `src/app/agent_identity_remove.rs`, `src/main.rs` |
| S19 | **Only if S1 finds the WSL store volatile:** Private-vault durable copy and `--install --agent` | 4 | S15, S1 | `src/app/agent_identity_install.rs`, `src/app/agent_identity.rs` |
| S20 | opv-site pages (§9) | 2 | S13, S14 | opv-site files in §9 |

### Follow-up issues (not slices)

- **F1** (vet R2): resolve values with short-lived token-only `op` calls and spawn the delivery
  step directly, so no long-lived process holds the token. Masking then moves to opv's scrubber
  (ADR R4).
- **F2** (D9): `--product` scope.
- **F3** (§4.2.1): a broker-backed `AgentCredentialSource` (1Password Local Agent Broker or
  Credential Broker): short-lived tokens with nothing stored. It replaces the OS-store source
  and removes residual §4.6, point 1. It waits until the broker supports the op CLI on Linux,
  WSL, macOS and Windows.

## 15. Unverified, for S1

1. The `keyring` crate's backends, versions, non-interactive mode and headless or WSL behaviour.
2. Whether the kernel keyring and Secret Service survive a WSL VM stop, and whether `@u`
   survives the user's last process exiting.
3. `op service-account ratelimit` under a token: whether it needs an argument, and its output
   shape.
4. The 1Password service-account count limit per plan, and op's wording when it is reached.
5. Whether service-account activity reporting is on every plan (FM7 detection).
6. Whether `op` accepts a token by any channel other than the environment variable (that would
   shrink F1).
7. The exact `plan` and `status` causes under reader grants for targets with
   `deploy_credentials` in the state vault (pinned by S12).
