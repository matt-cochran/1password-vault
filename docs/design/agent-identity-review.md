# Review: agent identity design (#338), DESIGN-FMECA procedure

Reviewer: independent agent, 2026-11-17. Input: `docs/design/agent-identity.md` (draft), ADR-0001,
code at `fb8d3359` in this worktree. Read-only on code and on the design.

**Verdict: ready with changes.** The core idea holds: the agent identity is the CI reader with its
token kept in a different place, it reuses `access_create`, and 1Password enforces read-only. Two
mechanism claims about current code are wrong, and both matter: the `op run` path and the delivery
step's lifetime. Rule 4 of the selection table falls back to the person's session. G1 promises
`sync`, which CI-reader grants cannot deliver. Each is a design edit, not a rework, but three of them
need an owner decision (last section).

## Phase 1: architecture assessment

| Component | Purpose | Class | Evidence | Simpler alternative | Risk if removed |
|---|---|---|---|---|---|
| Agent service account with CI-reader grants | read-only, 1Password-enforced reach | Essential | Proven (`access_plan.rs:140-151`, op help) | none | no feature |
| `--create --agent` via a `Destination` split in `access_create` | one owner command | Essential | Adapted (`access_create.rs:236-425`) | none | admin UX |
| Binding check run on every create | catches an over-granted or wrong-account token | Essential | Proven (`reader_grants.rs:154-177`, contract from `reader_grants::contract`, `access_create.rs:219-221`) | none | FM5 undetected |
| OS-store working copy (`keyring`, 4 backends) | unattended token without env/argv | Essential | Adapted, keyutils/WSL is Speculative | none that meets C2 and C4 | E (env export) |
| Private-vault durable copy | reinstall after a keyutils loss | Useful, and needed only where the store is volatile | Adapted | OS store only, where it persists | a new account on every WSL boot |
| Cross-machine listing from the Private vault | see other machines' identities | Speculative | none | 1Password's own service-account page | low |
| Local registry `agent-identities.toml` | expiry, rotation marker | Useful, reducible | Speculative (relies on store attributes) | store-entry attributes plus the Private item | FM13 disappears |
| Selection rules 1-5, `OPV_IDENTITY` | which identity a run uses | Essential (1, 3, 4, 5); rule 2 Useful | Adapted | — | silent write-capable session |
| `OpCredential::Agent` and refusal unification (A6) | one answer to "is this a person?" | Essential | Adapted (`tidy.rs:117-190`, `mcp.rs:1056`) | — | FM4 |
| `--rotate`, `--install`, `--remove` with `--agent` | lifecycle | rotate Essential; install only for volatile stores; remove Useful | Adapted | remove = rotate's "Do: revoke" plus deleting the store entry | small |
| `opv access --agent` list/check | inspect | Useful | Adapted | the doctor/ready `identity` row already shows reach and expiry | small |
| 30-day lifetime and a new 7-day threshold | exposure window | Speculative | the agent can read the token anyway (§4.6.1) | 90 d / 14 d, the same as CI | none |
| Production gated by `--confirm` (D6) | deliberate step | Useful | Proven pattern | — | — |

**Revised architecture.** Retained: account, create, binding check, OS store, selection, A6, rotate,
doctor/ready identity. Simplified: lifetime to 90 d/14 d (reuses FR-69 unchanged), the registry
reduced to the rotation marker (or cut if A1 shows store attributes work), the list folded into
`ready`/`doctor` plus `opv access --agent` for this machine only. Demoted: cross-machine listing, and
the Private-vault copy and `--install`, which become conditional on A1 finding the store volatile.
Removed: none.

## Phase 2, iteration 1

| Domain | Failure mode | Cause | Effect | Sev | Prob | Mitigation (poka-yoke) | Observability | TRIZ | Res S | Res P |
|---|---|---|---|---|---|---|---|---|---|---|
| Runtime | R1: `op run` does not take `token_only` | `opv run` starts op through `ProcessRunner::inherited` (`runner.rs:2160-2188`), which keeps the inherited env, calls `add_op_session` and never sets `OP_BIOMETRIC_UNLOCK_ENABLED=false`; only captured calls use `command_for` (`runner.rs:1853-1880`) | `op run` carries the token and the person's session or desktop integration; which one op uses is unverified, so the wrong identity may be used | M | H | In `inherited`, when the call env holds `OP_SERVICE_ACCOUNT_TOKEN` and the program is `op`, remove `OP_SESSION*`, `OP_CONNECT_*` and `OP_ACCOUNT`, skip `add_op_session`, set biometric/cache off. Do **not** `env_clear` (op run passes the env to the app). Sim test asserts op run's env | sim e2e; `opv run --verbose` names the identity | — | L | L |
| Technical | R2: token sits in a long-lived process | the delivery step spawns the app and waits (`local_delivery.rs:452` `.status()`), so `op run`, a dumpable Go process, holds the token in `/proc/<pid>/environ` for the app's whole run; on macOS `ps eww` reads it too | any app or dependency the agent runs reads the token through its grandparent; the macOS Keychain ACL is bypassed | H | H | Correct §4.3.3 and §4.6, and drop the ACL as a control. Follow-up (TRIZ *preliminary action*/*segmentation*): resolve values with short-lived token-only `op` calls and spawn the delivery step directly, so no long-lived process holds the token; the cost is that `op run` masking must move to opv's scrubber (R4) | canary e2e: `/proc/$PPID/..` walk under `opv run` finds no token (after the follow-up) | preliminary action | H (accepted, same class as §4.6.1) | H |
| Delivery/UX | R3: `sync` in G1 cannot work | `deploy_credentials` live in the target's state vault (`docs/usage.md:767`), which the agent cannot read; `docs/agent-setup.md:278-279` gives sync to the deploy identity; the plan ledger is in the state vault (`usage.md:236`) | an agent `sync` fails with `deploy_credentials_failed`, `plan` shows `unknown`; an unrecorded agent sync makes CI's next plan report "changed outside opv" | M | H | Remove `sync` from G1: agent = reader (`run`, `plan`, `ready`, `status`, `doctor`). Any agent sync becomes an owner decision | `ready` target rows; plan `unknown` count | separation by role | L | L |
| Runtime | R4: per-environment fallback to the person's session | rule 4 needs "an installed identity for this environment", else rule 5; `Host::op_credential` is process-wide (`host.rs:804-810`, about 51 `Host::detect()` sites) | one agent process uses the agent for dev and the person's write-capable session for staging/prod, the production D6 excludes | H | M | Under an agent marker with any agent identity installed for the (account, project), an environment without one stops with `agent_identity_not_installed`; resolve once per process before the first op call; a test of multi-env `ready`/MCP | doctor row per env; `ready.identity` per env | — | L | L |
| Runtime | R5: WSL keyutils loss | the `@u` keyring is gone at every WSL VM stop (idle shutdown, `wsl --shutdown`, reboot); it may also go when the uid's last process exits (unverified) | every boot needs a person `--install` (TTY, Private-vault read); not unattended on the owner's own platform | M | H | A1 measures lifetime under real WSL idle. A gate: if volatile, D10-B (Secret Service) is the supported WSL path and keyutils becomes the fallback with a doctor FAIL `agent_store_volatile` | doctor `op identity` row: `not installed (cleared at boot)` | — | M (owner) | M |
| Runtime | R6: store prompts hang an unattended run | a locked Secret Service collection, or a macOS ACL after an opv upgrade changes the binary, opens a GUI prompt | the agent run blocks with no output | M | M | Store reads non-interactive with a timeout; `agent_store_locked` (exit 7) with the fix; never wait on a prompt | doctor FAIL row; the code in `ready` | — | L | L |
| Runtime | R7: service-account rate limits | 1Password rate-limits service-account reads per token and per account (`op service-account ratelimit` exists; exact numbers unverified) | agent loops (`opv run -- cargo test` repeatedly) exhaust the account quota that CI shares, so CI fails | M | M | doctor/ready read `op service-account ratelimit` under the token (value-free) and warn near the limit; diagnose via the existing `RateLimited` (`cause/mod.rs:696`); docs | doctor warn row; `rate_limited` count | — | L | M |
| UX/admin | R8: rotation churn | per (project, env, machine) × 30 d × a manual revoke (op has no delete: `op service-account` = create, ratelimit) | 12 identities means 12 rotations and 12 UI revokes a month; stale live accounts; the account cap (FM17) | M | H | 90 d/14 d as CI; `opv access --rotate --agent` with no env rotates every identity on this machine; the `Do:` line lists all old names in one place | `ready` `credential_expiring` | — | L | M |
| Technical | R9: "agent cannot write/mint" overclaimed | markers and the TTY are not controls (`host.rs:33-38`; `script` fakes a TTY); rule 2 `OPV_IDENTITY=person` is settable by the agent; a desktop-app session stays reachable | read-only holds only on runs that select the agent identity | H | M | Restate FM6 and FM11 as residuals; docs: start the agent where no person session reaches it (no desktop CLI integration in its terminal); doctor `assistant_on_person_session` stays | doctor warn | — | H (accepted) | L-M |
| UX | R10: owner's `! cmd` flow changes | Claude Code `!` commands carry `CLAUDECODE`, so rule 4 selects the agent and `require_person` commands (`import`, `target credentials`) that work today get `own_session_required` | owner confusion | L | H | the refusal's `Next:` says "run in your own terminal" (never `OPV_IDENTITY=person`); docs | — | — | L | L |
| UX | R11: §7.3 inconsistent | "titles and tags only; no field is read" but shows the other machine's expiry | wrong output or a hidden field read | L | H | put the expiry in the item title/tag, or read the text field and say so | — | — | L | L |

**Remaining after iteration 1.** High: R2 and R9, both accepted residuals of the same-user boundary
the design already states (§4.6), now including op run's environ. They need the owner's explicit
acceptance. Medium: R5 (the owner chooses the WSL store), R7 (probability stays M; detected). Low:
the rest. **Stop:** further mitigation of R2/R9 needs an OS-user or sandbox boundary, which the
design rules out (non-goal "No sandbox").

## Wrong or unverified claims about the code

- §4.3.2 and §3.3: "every op call … takes the existing `token_only` path" is wrong for `op run`
  (`runner.rs:2123-2131`, `:2160-2188`).
- §4.3.3: the delivery step "execs the app" and is "short-lived" is wrong. It spawns and waits
  (`local_delivery.rs:452`), and `op run` lives as long as the app.
- §3.2: `require_person` has callers in "8 files" is wrong. It has 12 non-test files: `attest`,
  `generate`, `provision`, `structure` and `tidy` are missing from the list.
- G1 `sync` conflicts with `docs/agent-setup.md:278-279` and `docs/usage.md:767`.
- §4.4: the macOS ACL as a "partial control" is unverified and is defeated by R2.
- §7.6: rebuilding the registry from store attributes depends on the `keyring` crate's API, which
  is unverified.
- Verified correct: `access_create.rs` cites (244, 274-311, 316-345, 346-363, 366-388, 397-425),
  `tidy.rs:117-190`, `host.rs:33-58`, `:164-175`, `:804-810`, `:1248-1266`, `mcp.rs:1056`,
  `runner.rs:1569-1580` and `:1812-1880`, `local_delivery.rs:162`, `sync.rs:1524-1527` and
  `:1609-1615`, `delivery.rs:440-447`, `scrub.rs:477-495`, `hardening.rs:75`,
  `reader-grants.md:18-21`, op 2.40.0 help.

## Phase 3

- **Calibration.** No scores are involved. "Read-only" rests on 1Password plus the always-on
  binding check (sound). The design's FM table has no probability or residual columns; this
  review supplies them.
- **Observability.** The doctor/ready `identity` row is the right single signal. Add rows for
  store-volatile/locked, rate-limit headroom and the per-env identity. Wrong-identity use (R1/R4)
  needs a sim assertion, because nothing in production reveals it.
- **Over-engineering.** About 55 h for a reader with a new token home. Cuts: lifetime and
  threshold (reuse FR-69), registry, cross-machine list; and `--install` plus the Private copy if
  A1 finds a persistent store on WSL. The simplest viable version is create, use, rotate and the
  doctor/ready row (A2-A7, A10-A11, A13-A14).
- **Incremental delivery.** Ships behind `OPV_IDENTITY=agent` first (rule 3 only), with rule 4
  (auto-select) one slice later. Rollback: delete the store entry, and runs fall back to today's
  behaviour. A1 must gate A3 and D10.

## Conflicts with owner requirements (owner decides)

1. **Same-user boundary (R2, R9).** An agent with a shell can read the token (store, op run's
   environ) and so the values. Requirement 1 holds for opv's channels, not against a misbehaving
   agent. Accept, or require a separate OS user or sandbox.
2. **WSL unattended (R5).** Keyutils means a person step per boot, against "fully unattended".
3. **Agent `sync` (R3).** It needs state-vault read and the provider deploy credential. No
   1Password write is involved, but the agent then holds a target-write credential.
4. **Read-only only when selected (R9).** The person's session stays reachable unless setup keeps
   it out of the agent's terminal.
