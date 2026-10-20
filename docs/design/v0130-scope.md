# opv 0.13.0 scope audit: #136 and #179

Audit only. Baseline `dev` = opv 0.12.3 (`6563d13`); Journeeze read at `ced358d` and `main` (`b332269`).

## #136 First-class SecretStore delivery (Journeeze)

0.8.0 and 0.9.0 closed most of it; what remains is proof and the Fly path.

| Requirement / criterion | Verdict | Evidence |
|---|---|---|
| OPV-owned local bridge, no wrapper, no env conversion | MET | `opv local-delivery` step under `op run`, `docs/design/local-delivery.md:14-28`; `docs/agent-skill.md:102-108` |
| Fixture consumer reads exact bytes via `MountedSecretStore` shape, only settings + dir in env | MET | `tests/mounted_consumer.rs:132,139,146`; `tests/local_delivery.rs:143,203,213` |
| Destination names match the consumer contract | MET | opv's rule (`^[a-z0-9]+(-[a-z0-9]+)*$`, ≤4 parts, `local-delivery.md:35`) is a strict subset of Journeeze's `path_for` (`jz_secrets/src/lib.rs:22-34`, unchanged on `main`) |
| Process roles; migration material never in serve mount | MET | `local-delivery.md:79`; `src/app/delivery_preview_tests.rs:200`; target `roles`, `delivery-transports.md` §4.4 |
| Metadata-only preview (CLI + MCP), unknown never shown as absent | MET | `docs/usage.md:426`; MCP `opv_state` section `delivery_preview` with `role` (`src/mcp.rs:609,1211`) |
| Structural MCP: preview/validate/reconcile, no value tool, person applies | MET | `opv_propose` is pure, `opv apply` is person-only (`src/mcp.rs:350`; `docs/usage.md:571`) |
| Idempotent provisioning, refuses conflicting targets | MET | `stale_plan` and the concurrency refusal on `apply` (`docs/usage.md:571`) |
| RAM-only dir, 0700/0400, `O_EXCL\|O_NOFOLLOW`, link resistance, fail closed | MET | `local-delivery.md:30-39`; `src/app/local_delivery_tests.rs:233,242`; `tests/local_delivery.rs:161,223` |
| Verbatim bytes (PEM, trailing newline) | MET | `delivery-transports.md` §4.5; `tests/local_delivery.rs:203,213` |
| Lifecycle tests: normal exit, signals, supervisor death, launch failure, partial delivery | PARTIAL | normal exit `tests/local_delivery.rs:152`; signal tests exist only for the Azure credential dir (`tests/cli.rs:1295-1381`), none for `opv-run.*`; no test of the SIGKILL→sweep path (`src/app/local_delivery.rs:321-324`), launch failure or a failed write partway through |
| Limits: same-UID, root, ptrace, inherited handles, swap, core dumps, reboot | PARTIAL | same-UID, SIGKILL and reboot are covered (`local-delivery.md:38,41-58`; `docs/local-development.md:112`); core dumps handled in code (`src/hardening.rs:21-55`) but not stated in the doc; root, ptrace, swap and inherited handles are not stated anywhere |
| Explicit platform matrix (WSL/Linux, containers, macOS/Windows, Fly) | PARTIAL | the facts are spread across `local-delivery.md:35`, `docs/local-development.md:71,89-112` and `delivery-transports.md` §7; there is no single matrix |
| Canary absence: stdout/stderr, argv, child env, MCP, reports, artifacts | PARTIAL | argv and env: `tests/local_delivery.rs:64-79,143`; MCP preview reads no value by construction. No test drives the `delivery_preview` MCP section or a `--role` run with canary values and scans every output channel |
| Existing env consumers unchanged | MET | `local-delivery.md:58` |
| Docs: CLI/MCP examples, trust model, troubleshooting, skill guidance | MET (matrix PARTIAL) | `docs/local-development.md:56-112`; `docs/mcp.md`; `docs/agent-skill.md:102` |
| Container transport reviewed | MET | Compose recipe `delivery-transports.md` §5; `tests/local_delivery.rs:284,298`; Kubernetes §6 |
| Fly transport and shim retirement plan | PARTIAL | plan exists (§7.3–7.4), but F1–F4 live check not run; migration app design only; shim stays |
| Consumer verification against a tagged release (phase 4) | NOT MET | the §12.1 V1–V17 run has no evidence: `docs/verification/` does not exist |
| Webhook secret delivered on the shared Fly host | MET upstream, stale here | Journeeze `main` now lists `GITHUB_WEBHOOK_SECRET` in the shim's `SERVE` (`fleet_secrets.rs:60-63`). `delivery-transports.md` §4.6 still calls it an outstanding external dependency |

### #136 remaining deliverables

| ID | Artifact | Files it owns | Acceptance | Hours (O/L/P) | Who |
|---|---|---|---|---|---|
| A1 | Local-delivery lifecycle tests | new `tests/local_delivery_lifecycle.rs` | INT, TERM and HUP to `opv run` leave no `opv-run.*`; after SIGKILL of the step, the next run sweeps it; a missing command leaves no dir; a failed write after the first file (read-only parent, planted component) leaves no dir and starts nothing. | 3/5/8 | Junior |
| A2 | Canary sweep for role-scoped file delivery | extend `tests/local_delivery.rs`, `tests/output_guard.rs` | Canary values through `--role serve` and `--role migrate`: absent from stdout/stderr, the step's `/proc/<pid>/cmdline`, the child env, the `opv_state delivery_preview` reply and `--preview --json`; migrate canaries absent from the serve dir | 2/4/6 | Junior |
| A3 | Limits and platform matrix | `docs/design/local-delivery.md` (new section), `docs/local-development.md` (link) | One table covering Linux, WSL, containers via Compose, macOS, Windows, Kubernetes and Fly: supported or refused, with the reason and the cause code. One table covering same-UID, root, ptrace, inherited fds (the step's FD_CLOEXEC), swap (tmpfs can swap; no `mlock`), core dumps (`hardening.rs`), hard links (a fresh dir plus `O_EXCL`) and reboot, each marked enforced, mitigated or unsupported. Fix §4.6 webhook staleness | 2/3/5 | agent (needs accurate claims, read code) |
| A4 | Tagged-release verification of file delivery | `docs/verification/v0.13.0-file-delivery.md` + evidence dir | §12.1 V1–V17 against the 0.13.0 tag, all pass, canary scan has zero hits | 4/8/16 | agent plus the owner (service accounts, kind cluster) |
| A5 | Fly file-delivery live check F1–F4 | `docs/design/delivery-transports.md` §7.3, `tests/fixtures/fly/` | Recorded replies answer F1–F4 on a throwaway app. | 3/6/12 | agent plus the owner (O8 authorization) |

Outside opv: the Fly migration app and shim-retirement steps (§7.4) are Journeeze/infra changes, each authorized by a person.

## #179 Application consistency across environments

Written against 0.11.0; 0.12.0 shipped presence, `except`, lifecycle and `--gate` (names from `assistant-guided-setup.md`, review L3). Two pieces are unwired, and the docs overclaim.

| Requirement / criterion | Verdict | Evidence |
|---|---|---|
| 1. Keys apply to all environments by default; exclusions | MET (named `except`) | `src/domain/presence.rs:23-45`; `docs/configuration.md:180-193`; `propose key` writes no list (`src/app/propose/key.rs:89-91`) |
| 1. `init --from` defaults to all | PARTIAL | its successor, `propose setup --names-from`, writes an explicit one-environment list (`src/app/propose/setup.rs:88-97`) |
| 1. New environment inherits "all" keys; fields created by structure plan | MET | `docs/configuration.md:775`; `opv propose env`, then `propose structure` |
| 2. `environment_gap` finding in `ready` / MCP | NOT MET | `presence::gaps` (`src/domain/presence.rs:53`) has no caller outside its test; nothing emits `environment_gap`, yet `docs/configuration.md:193,775` say it warns |
| 3. Retire: prune per environment in a safe order, honouring `confirm_env` | PARTIAL | `opv propose retire` only marks the key `retiring` (`src/app/propose/key.rs:135-137`) and points to `opv needs` (`src/main.rs:3962-3964`). The orchestrator `retire()` (`src/app/retire.rs:78`) says "Library only" and has no caller. Nothing sets `retiring_prune: true` (`src/domain/plan.rs:284`; `src/app/mod.rs:391`), so no command can prune a retiring key |
| 3. Archive 1Password fields; resumable; half-finished retirement in `ready` | NOT MET | the archive step exists only as an enum variant (`retire.rs:37`); `inventory` shows `retiring` (`src/domain/inventory.rs:282`), but `ready` has no finding for it |
| 3. Declaration deleted after pruning | Superseded | the shipped design keeps `lifecycle = "retired"` (`configuration.md:219`), which conflicts with the issue text |
| 4. Promotion gate exits non-zero on missing, placeholder or failed rule | MET (named `--gate`) | `docs/usage.md:551`; `src/app/ready.rs:1227-1232`; MCP `opv_state ready` |
| 4. CI recipe gating dev→staging→prod | PARTIAL | `examples/ci-change-detection/.github/workflows/opv-pr.yml:68` and `src/app/ci_workflow.rs:417` gate one environment; there is no promotion chain |
| 5. `needs` gate fails on undeclared reads | MET (named `--gate`) | `src/app/needs.rs:352`; `opv-pr.yml:64` |
| 6. Bulk extend (`--all-keys --env`) | NOT MET | no flag or intent exists. Only "all" keys are inherited, not keys with an explicit list |
| CLI/MCP parity, canary coverage | PARTIAL | only for the parts that ship (`opv_propose` retire/env/key, `opv_state ready`) |
| e2e against opv-sim covering the whole 4-step flow | NOT MET | separate snapshots exist (`flow_propose_env`, `flow_propose_retire`, `core_ready_gate`), but no chained scenario |
| README "How opv works": application × environment section | NOT MET | `README.md:16-36` covers delivery only; the model is in `configuration.md:180` |

Docs drift: `docs/usage.md:26,571,579` and `docs/configuration.md:219` claim retire prunes and archives; the code does neither.

### #179 remaining deliverables

| ID | Artifact | Files it owns | Acceptance | Hours (O/L/P) | Who |
|---|---|---|---|---|---|
| B1 | Wire `environment_gap` | `src/app/ready.rs`, the cause/catalog entry (`src/cause/`), `docs/usage.md` findings table, e2e snapshot | `ready` and `opv_state ready` list one non-blocking finding per (product, key, env) with `next` = `opv propose key <p/K> --env <env>` or an `except`; several gaps grouped into a count line; no change to the exit code | 3/5/8 | Junior (after decision D6) |
| B2 | Retire executor | `src/app/retire.rs` (caller side), `src/app/apply.rs`, `src/main.rs` retire path, `src/adapters/onepassword*.rs` (archive), `docs/usage.md`, `docs/configuration.md:219` | `opv apply <retire plan>` (person) runs the needs check, then prunes per environment in tier order with `retiring_prune`, refusing a `confirm_env` environment without confirmation, then archives, then sets `retired`. Re-running resumes. `ready` shows `retirement_incomplete` naming the remaining steps. CI never runs the archive step | 10/16/28 | agent plus design (D1, D2) |
| B3 | Docs reconciliation | `docs/usage.md:26,571,579`, `docs/configuration.md:193,219,775` | Docs say only what the code does. If B1 and B2 ship, update them in the same PRs instead | 1/1.5/2 | Junior |
| B4 | Bulk extend | `src/domain/intent.rs`, `src/app/propose/key.rs`, `src/config_edit.rs`, MCP intent schema, tests | One proposal adds `<env>` to every explicit-list key of a product (or of the project). "all" keys stay untouched. The diff is shown and a person applies it. Parity with MCP `opv_propose` | 4/6/10 | Junior once D3 is decided |
| B5 | Promotion-chain recipe | `examples/ci-change-detection/` (new workflow or job), `src/app/ci_workflow.rs` (optional), `tests/ci_examples.rs` | dev→staging→prod jobs, each gated on `opv ready <env> --gate`. The recipe test passes | 1/2/3 | Junior |
| B6 | README model section | `README.md` "How opv works" | One subsection: the application, keys present everywhere unless excepted, tiers, the gate, retire. Linked from `configuration.md:180`. `tests/docs_commands.rs` passes | 1/1.5/3 | Junior |
| B7 | Chained e2e scenario | `tests/e2e/scenarios/`, snapshots, `tests/e2e/coverage.rs` | In opv-sim, a key added in dev shows as missing in staging and prod; a new environment inherits it; retire prunes it, archives it and marks it retired; `ready <env> --gate` refuses. Passes with `CI=true` | 3/5/8 | Junior after B1, B2 |
| B8 | `setup --names-from` presence | `src/app/propose/setup.rs` | Follows D4 | 0.5/1/2 | Junior |

## Conflicts with owner principles

- **The retire archive step and the new environment's empty fields write to 1Password.** They must run only in a person's `opv apply`, never in CI ("CI never writes values to 1Password"). B2 has to split the work: CI may prune targets, which only reads 1Password; the archive step stays with the person. If the #179 wording "one approved plan … resumable" is read as a CI job, it conflicts.
- **#179 "archive the fields".** 1Password archives items, not fields; a field "archive" is a person's item edit (consistent with vault access as the only permission).
- **#136 Fly `--file-secret` (A5, later).** It stages a base64 copy of each value as a Fly secret. That is allowed only if the copy goes through stdin as today, never in argv. Fly's on-machine file location (F2) may be disk, which would break the RAM-only property. The check has to answer this before anything is built.

## Decisions only the owner can make

- **D1:** What "archive a field" means: move it to an `archived` section with a note, rename the field, or leave it and annotate. Say whether production prune in a retirement runs from the person's terminal or as a generated CI step.
- **D2:** Confirm that retire keeps `lifecycle = "retired"` (shipped) rather than deleting the declaration (#179 text). Edit #179 to match.
- **D3:** Confirm the shipped names `except` and `--gate` over `exclude` and `--fail-on-missing`. Name the bulk-extend surface (an intent kind `extend`, or `propose key --all-keys`).
- **D4:** `propose setup --names-from`: all environments, or keep one local-tier list?
- **D5:** Close #136 on opv's side once A1–A4 are done, and move the Fly migration app and shim retirement to a Journeeze/infra issue? Authorize the A5 throwaway Fly app (O8) and the A4 run (service accounts, kind).
- **D6:** Should `environment_gap` also print at load on every command, or only as a `ready` finding? The FMECA lists the risk of a warning flood (`assistant-guided-setup-fmeca.md:123`).

## Totals

| Issue | Optimistic | Likely | Pessimistic |
|---|---|---|---|
| #136 (A1–A5) | 14 | 26 | 47 |
| #179 (B1–B8) | 23.5 | 38 | 64 |

Critical path: D1/D2 → B2 → B7. A1–A3, B1 (after D6), B3, B5, B6 can start in parallel now.
