# Delivery: one source of truth, synced by CI into each platform's channels

Status: **design for 0.11.0 and 0.12.0** (#136). This document replaces the container-transport design of `3b8e180` (`3b8e180:docs/design/delivery-transports.md`): opv no longer starts containers.

| Release | Scope | Status |
|---|---|---|
| 0.11.0 | the channel model (§1); change detection, the drift check and the CI recipes (§2); the README section (§3); target `roles` and verbatim file bytes (§4); the local Docker Compose recipe (§5); Kubernetes ConfigMaps and mounted files (§6); config on Fly (§7); the webhook secret mapping; the remote-profile refusal for deployed environments (R1, §15); a tagged-release verification (§12) | designed for implementation |
| 0.12.0 | a Docker Swarm target (§8; moved from 0.11.0 by the owner, §15); a GCP Secret Manager store, a `vm` target and the portable VM startup step, tested in GCP (§9) | designed for implementation |
| later | an AWS Secrets Manager store; Fly file delivery; the 1Password Events API trigger | design only |

**Conventions**
- A **fact** carries a citation:
  - `path:line` with no commit means opv at `ab88b30`, the base of this branch; this commit changes no code;
  - `ced358d:path:line` means Journeeze (`journeeze-saas`);
  - `3b8e180:path` means the previous design commit on this branch;
  - a URL with a date cites public vendor documentation, as read on that date.
- Recorded tool output lives under `tests/fixtures/`. This commit adds:
  - `tests/fixtures/compose/` (Docker Compose 2.32.4);
  - `tests/fixtures/docker/swarm/` (Docker 27.5.1 / Engine 29.8.1; help text, and replies from a node outside a swarm);
  - `tests/fixtures/fly/help/` (flyctl 0.4.111 help text).
- No reply in this design is invented. §6.9, §8.9 and §9.8 list the replies still to record.
- **[An]** marks an assumption that nobody has verified. §13 lists each one with the check that settles it.

## 0. Owner decisions (2026-10-16/17)

These are binding. They are restated here because the delivery notes are not in git.

**Camp 1: one source of truth (2026-10-17).** opv works like Doppler or Infisical:
- 1Password is the single source of truth for both **config and secrets**.
- `opv sync` runs from CI and puts each kind into the platform's right channel.
- At runtime nothing reads 1Password, opv or git.
- A target that has no channel for a kind must say so (§1). Config is never silently `n/a`.

**The principle (2026-10-17).** 1Password is used only in two places: on a developer's machine (`opv run`) and in CI/CD (`opv sync`, signed in with a service account). Production and every deployed environment never need 1Password, opv or a 1Password credential at runtime. The running app reads only what its platform provides. It follows that:
- Kubernetes and Swarm delivery is set up by `opv sync` from CI.
- The tagged-release verification shows the sync running as CI runs it, then a workload reading its files with no 1Password access.
- Anything that puts `op`, a 1Password service-account token or opv into a runtime image, pod, task or VM is out of scope (§1.4).

**Change detection is a priority (2026-10-17).** When 1Password changes, CI must notice and sync. A scheduled drift check fails when a platform has drifted from 1Password (§2).

**Decoupling (2026-10-17).** Journeeze runs only on Fly today but must not be tightly coupled to Fly. Its contract is secrets as files under `JZ_VAULT_DIR` (`ced358d:crates/jz_secrets/src/lib.rs:1-4`, `ced358d:crates/jz_host/src/lib.rs:193-198`). That contract is the decoupling layer.

**Scope (2026-10-17):**
- a Docker Swarm target (§8);
- plain Docker on VMs in any cloud, where CI syncs into the cloud's secret manager and a startup step that is not opv fetches the values with the VM's own identity (§9). GCP comes first, in 0.12.0; AWS is design only;
- one scaling and rotation table (§10);
- the 0.11.0 / 0.12.0 split (§11).

**Revised 2026-10-17 (supersedes the first 2026-10-16 decision):**
- opv never starts or controls containers.
- The local mechanism is the existing wrapper. There is no `opv run shell`.
- Cloud secrets go into the platform's own store. Kubernetes file keys are Secret volume mounts.
- For Fly, investigate file delivery; where it isn't possible, Journeeze's shim stays.
- Journeeze keeps `MountedSecretStore`.

**Still standing from 2026-10-16:**
- A file key delivers the stored bytes verbatim; no transform applies at delivery.
- `GITHUB_WEBHOOK_SECRET` → `github/webhook-secret` in Journeeze's serve role.
- Fly migration credentials live in a separate migration app (design only).
- A verification run against the tagged release.
- The same-user isolation limit is documented for local delivery; macOS and Windows local file delivery stays refused.

## 1. The channel model

### 1.1 The contract

Every target declares, per key kind, **where that kind goes**, and whether it can deliver **files**. opv then routes each key by its kind, and never decides per key by chance.

| Target | Secret channel | Config channel | File capability | Status |
|---|---|---|---|---|
| Local `opv run` | process env, or files in a RAM dir | process env | native (tmpfs dir) | today |
| Fly | Fly secrets (staged, then deployed) | **Fly secrets too** (new): the only runtime channel opv can write through Fly's API, because `fly.toml [env]` needs a deploy of the app's config | **via the app**: env at boot, written to files by Journeeze's shim (`ced358d:crates/jz_host/src/fleet_secrets.rs:90`); native `[[files]]` only once §7.3 is answered | config new in 0.11.0 |
| Kubernetes | immutable versioned Secret | **immutable versioned ConfigMap** (new `kubernetes.config = "configmap"`); today: plain env `value` or the store | native: one projected volume (Secret and ConfigMap sources) | ConfigMap and files new in 0.11.0 |
| Docker Swarm | versioned Swarm secret (files at `/run/secrets/…`) | versioned Swarm config (files), or service env for config without `file` | native | new in 0.12.0 |
| GitHub Actions | repository/environment secrets | variables (`docs/configuration.md:427`) | none: a file key is delivered by name as a secret | today |
| Azure Container Apps | Key Vault versions bound by reference | app env, or the store (`azure.config`, `src/adapters/azure/config.rs:170-174`; `docs/configuration.md:338`) | none today; a Key Vault secret volume is design only **[A28]** | today |
| VMs (GCP) | Secret Manager, latest version | Secret Manager too, labelled `opv-kind=config`, read by the same startup step | native: the startup step writes tmpfs files | new in 0.12.0 |
| VMs (AWS) | Secrets Manager | SSM Parameter Store (`String`) **[A27]** | native, as for GCP | design only |
| VMs (Azure) | Key Vault | Key Vault (tagged `opv-kind=config`) | native, as for GCP | design only |

### 1.2 Today: config is silently `n/a`

- The staged store's config channel is an optional method that **defaults to none**: `StagedStore::variables` returns `None` unless a target overrides it, and "config is not delivered by this target" (`src/ports.rs:44-49`). Only GitHub overrides it (`docs/configuration.md:427`).
- `plan` gathers config values (`src/domain/plan.rs:420-428`), and a target that takes none shows them as `n/a`: "not delivered to the target (config keys, except GitHub variables …)" (`docs/usage.md:131`). Fly delivers no config at all.
- Pinned runtimes set config through `RuntimeChange::set` (`src/domain/runtime.rs:47-50`). Azure and Kubernetes already split config from secrets with `config = "env" | "store"` (`src/adapters/azure/config.rs:170-174`; `src/adapters/kubernetes/config.rs:85-93`; `docs/configuration.md:338`, `:461`).

### 1.3 How the contract appears in code

The contract becomes a **required** method on `TargetConfig` (`src/provider.rs`, next to `open` at `:366-373`). It has no default, so a new target can't compile without declaring all three:

```rust
pub struct Channels {
    pub secret: Channel,      // e.g. Channel::Store { label: "Kubernetes Secret" }
    pub config: Channel,      // Channel::Store / Variables / RuntimeEnv / None { why }
    pub files: FileCapability // Native { dir } / ViaApp { note } / None
}
fn channels(&self) -> Channels;   // no default body
```

- `Channel::None { why }` is a deliberate statement. Its row reads `not delivered (<target> has no config channel: <why>)`. It is never the plain `n/a`.
- `StagedStore::variables` (`src/ports.rs:44-49`) loses its default body. GitHub keeps its implementation; Fly implements config as Fly secrets (§7).
- `plan::evaluate` (`src/domain/plan.rs:420-428`) routes each ready key by `channels()`. A key whose kind has `Channel::None` adds a `no_channel` finding:
  - `plan` and `status` print one `warn` line;
  - `sync` **refuses** it (`Guard::NoChannel`, §1.5), unless the target spells out `config = "none"`. Then each run still prints a warn line, but the sync goes on.
- `FileCapability::None` means a file key is delivered on the secret channel by its name, with a one-time warn line: `file destination not honoured on <target>`.
- **Config is not secret (camp 1).** Several config channels are readable by more than the app: a plain env entry or a ConfigMap (§6.2), Swarm service env, which passes through the docker CLI's argv (§8.2), the VM's `.env` (§9.2), a GitHub variable. So:
  - `plan` and `status` show **each config key's channel** on its row, and in `--json` as `via` (§6.7), taken from the target's `Channels` label: `env`, `ConfigMap`, `Fly secret`, `Swarm config`, `Swarm env`, `Secret Manager`, `GitHub variable`. A person reviewing a plan sees where every setting lands.
  - **Anything sensitive must be declared `kind = "secret"`** (`docs/configuration.md:138`). opv cannot tell a sensitive text value from a harmless one, and doesn't guess.
  - A config key whose 1Password field is **concealed** keeps today's handling. Where the config channel is a readable variable store (GitHub variables), the target refuses it with `concealed-config` (`src/app/variables.rs:79-84`; `docs/configuration.md:427`). Everywhere else it is delivered with today's warning, `warning: <product/KEY> is concealed in 1Password but declared config; it is delivered as a plain environment value` (`src/app/status.rs:278-293`). The new Swarm env channel refuses it like GitHub (§8.2). The new ConfigMap, Fly and VM channels warn.
  - Rejected (FMECA FM-02): making env routing of config an explicit opt-in per target. It contradicts camp 1, which the owner chose: config is declared non-secret, and the declaration is the control.
- A contract test in `src/provider.rs` checks that every registered provider declares channels, and that a target configured with `config = "none"` maps to `Channel::None`.

### 1.4 Rejected alternatives

| Alternative | Why rejected |
|---|---|
| The container transport of `3b8e180` | the owner dropped it |
| **Anything that puts `op`, a service-account token or opv into a runtime image, pod, task or VM**: an init container or sidecar reading 1Password; the 1Password Kubernetes Operator or Connect in the cluster; a CSI driver with a 1Password provider; the earlier Fly guest step `opv local-delivery --from-env` (`3b8e180:docs/design/delivery-transports.md` §6 item 3); opv in Journeeze's image (same file, §6.1 step 1); `op` or opv in the VM startup step | **out of scope by the owner's principle.** Each would also hand the runtime a credential that can read the vault. |
| Config read at runtime from git (`fly.toml [env]` or a committed `.env`) | the owner decided camp 1: 1Password holds config too, and runtime reads neither 1Password nor git |
| Keeping config `n/a` by default | the owner ruled it out; a silent skip hides a real gap |
| `opv run shell` | the owner ruled it out |
| A compose-file readability check | not cheap and not reliable (§5.3) |

### 1.5 Causes for the channel model

| Situation | Variant | Code | Exit | Retry | Do | Next |
|---|---|---|---|---|---|---|
| a key's kind has no channel on the target | `Guard` **new** `NoChannel{target, kind, why}` | policy_refused | 6 | never | "set config = \"none\" on target <t> to deliver no config there, or pick a target with a config channel" | `opv plan <env> --target <t>` |
| `config = "none"` on a target that has a channel | none: allowed, with a warn line per run | — | — | — | — | — |

### 1.6 Machine-readable surfaces (no value on any of them)

One invariant covers every document opv emits for a machine or an agent: **no secret or config value appears in it.** Today it is written for the CLI (`docs/usage.md:680`), and the MCP server already shares the CLI's builders. This release adds fields and documents, so it names them all:

| Surface | Built by | New in this design |
|---|---|---|
| CLI `--json` (`plan`, `status`, `sync`, `delivery verify`, …) | `JsonRow` (`src/app/mod.rs:735-760`) and each command's document | `channel`, `via`, `delivered_as`, `form`, `path` (§6.7); the `changed` document (§2.2) |
| MCP tools (`opv mcp serve`, `src/mcp.rs`; for example `opv_deployment_plan`, `opv_delivery_preview`) | the same projections as the CLI, byte for byte (`src/app/agent_view.rs:1-6`); failures are the `--json` error object (`src/mcp.rs:11-16`) | the plan projection carries the new fields, each passed through `identifier` (`src/app/agent_view.rs:12-18`) |
| delivery receipts (`delivery_receipts/1`) and the delivery item's `source versions` field | `src/app/delivery.rs` (`record`) | `v1|<item_id>|<version>` lines: ids and integers (§2.2) |
| error documents (`--json` and MCP) | `src/cause/render.rs` | the §1.5, §2.6, §6.8, §8.8 and §9.6 rows |
| the VM map rendered from `plan --json` (§9.2) | CI | kind, id and destination only |

**Test (deliverable M5).** The existing marker scan (`tests/security.rs:1-27`: every fake value contains `S7MARKER`, so one substring check finds any of them) is extended to `changed --json`, to `plan`/`status --json` with file, ConfigMap and Fly-config rows, and to the MCP tools `opv_deployment_plan` and `opv_delivery_preview` through `tests/mcp_protocol.py`. No new serializer is added for MCP; a new field reaches MCP only through `agent_view`.

## 2. When sync runs: change detection, drift and CI

### 2.1 What exists today

| Command | Reads | Exit codes | Source |
|---|---|---|---|
| `opv status <env>` | 1Password values, target listing, bindings | 8 only for missing or failing keys; extras and drift alone exit 0 | `src/app/status.rs:5-6`; `docs/usage.md:108` |
| `opv delivery verify <env> [--product p]` | the delivery item, the values, the target's listing | 8 `delivery_unverified`, with states `ChangedOnTarget`, `ChangedInOnePassword`, `NotRecorded` and others | `docs/usage.md:16`, `:479-485`; `src/app/delivery.rs:589-609`; `docs/design/error-catalog.md:187` |
| `opv plan` / `sync --expect-plan` | values; the plan id covers the item's version, and "Any edit to the item changes it" | 6 for a stale plan | `docs/usage.md:213-232` |
| `opv ready` | every environment × product | findings | `docs/usage.md:18` |
| `opv ci workflow <env> --target <t>` | the configuration | prints a sync workflow | `docs/usage.md:17`; `src/app/ci_workflow.rs:1-12` |

The exit codes are 0, 2–9 and 70 (`docs/usage.md:887-896`). **No code says "the source changed since the last sync"**, and `status` doesn't fail on drift.

### 2.2 Detection by item version: `opv changed`

**The signal.**
- Every 1Password item has a `version` that 1Password bumps on every edit. opv's own model says so: "bumped by 1Password on every edit" (`src/adapters/onepassword.rs:74-76`).
- `op item list` returns it as metadata, without any field values: `"version": 1` next to `id`, `title`, `tags` and `vault` (`tests/fixtures/op/success/s05-item-list.stdout:1-15`).
- The manifest adapter already parses it (`Row.version`, `src/adapters/onepassword_manifest.rs:55-61`; the manifest's own version, `:507`).
- A sync already reads the environment's item version (`read_item_fields` returns it, `src/app/mod.rs:186-193`).

**What a sync must record (new).** The delivery item of each placement (`opv · delivery · <product> · <target>`, `src/app/delivery.rs:5-13`) gains one non-secret field, `source versions`. After a sync whose writes the target confirmed, the field holds one line per source item the plan read:
```text
v1|<item_id>|<version>
```
The source items are each boundary item of the environment that the placement draws from (FR-57; shared keys name their source's item, `src/app/delivery.rs:46-52`), plus the manifest item when the configuration lives in 1Password. Recording happens in `record`, next to the evidence lines (`src/app/delivery.rs:5-13`). The receipt schema stays `delivery_receipts/1`; the field is additive.

**The command.**
```text
opv changed <env> [--target <t>] [--product <p>] [--json]
```
- **Metadata only.** It never reads a value:
  - current versions: `op item list --vault <vault> --format json`, once per vault, picking the item ids it needs. It never runs `op item get` on a boundary item.
  - recorded versions: `op read "op://<state vault>/<delivery item>/source versions"`, which reads **that one field**. This matters because the delivery item also holds the evidence key (`src/app/delivery.rs:44-45`).
- **Per placement**, one state:

| State | Meaning | Exit contribution |
|---|---|---|
| `unchanged` | every source item's version equals the recorded one | 0 |
| `changed` | some item's version differs; the item ids and both version numbers are listed | **10** |
| `no_record` | no delivery item recorded for the placement (`delivery_items`, `src/domain/model.rs:240-243`), or the field is absent (an older opv synced it) | **10**, with `Next: opv bootstrap` when the delivery item itself is missing |
| `unreadable` | 1Password or the state vault couldn't be read | that error's own exit (4, 7 or 9), **never 0** |

- **Exit 10 is new:** `source_changed`, "the source changed since the last sync (or none is recorded)". It is not a failure; the next step is the sync. `Next: opv sync <env> --deploy` (or `opv plan <env>` for a `confirm_env` environment).
- **JSON:**
  ```json
  {"schema_version": 2, "ok": true, "environment": "prod", "changed": true,
   "placements": [{"product": "journeeze", "target": "k8s", "state": "changed",
     "items": [{"item_id": "…", "recorded": 41, "current": 42}]}],
   "next": "opv plan prod", "do": null}
  ```
  It holds ids and integers only.
- **Over-triggering is safe.** Any edit bumps the version, even of a field this environment doesn't use (`docs/usage.md:230`). A person's run may also tidy the layout (`docs/usage.md:60`). The resulting sync writes nothing when nothing differs (`docs/usage.md:259`).
- **No self-trigger loop.** CI's service account never writes to a **source** item: it never tidies (`docs/usage.md:60`). It does write the delivery item, in the target's state vault: the evidence lines already today (`record`, `src/app/delivery.rs:358`), and `source versions` from C2. That write bumps only the delivery item's own version. `opv changed` compares only the source items above, by id, never the delivery item or the `deploy_credentials` item that may share the state vault, so the write cannot make it report `changed`. C2 tests exactly that: a sync, then `changed` is `unchanged`.
- **Downstream CI must branch on exit 10.** A wrapper that treats every non-zero exit as failure fails on each legitimate change; one that ignores non-zero exits hides `unreadable`. The shipped example branches (§2.5), `opv ci workflow --on-change` emits that branch (C5), and the README section and `docs/usage.md` show it (C6).
- **A configuration file in git** (`secrets.toml`) triggers the sync through the workflow's `push` path instead (§2.5).

**Rejected:** comparing value fingerprints (what `delivery verify` does, `src/app/delivery.rs:9-16`). That reads every value; the version check needs none.

### 2.3 The drift check

Drift means the platform no longer holds what 1Password says.

- **`opv delivery verify <env> --json`** already exits 8 with `delivery_unverified` and names the state (`src/app/delivery.rs:589-609`). `ChangedOnTarget` is the drift; `ChangedInOnePassword` is the case §2.2 catches more cheaply. It reads values, which CI may do.
- **New: `opv status <env> --fail-on-drift`.** It exits 8 with a new code, `target_drift`, when any pinned binding shows drift. Today drift is a printed line only (`src/app/status.rs:634-661`). The text is unchanged; the exit code changes only under the flag.
- The scheduled job (§2.5) runs both and fails on either.

### 2.4 The 1Password Events API (investigated; not designed in)

Established from 1Password's reference (https://www.1password.dev/events-api/reference/, read 2026-10-17; `developer.1password.com/docs/events-api/reference/` redirects there):
- endpoints `POST /api/v2/auditevents`, `/api/v2/itemusages`, `/api/v2/signinattempts`, plus `GET /api/v2/auth/introspect`;
- a bearer token whose "features" select the endpoints;
- **polling with a cursor** (`ResetCursor`, then a saved `cursor` and `has_more`). No webhooks are described;
- item-usage records carry `item_uuid`, `vault_uuid`, `used_version`, `timestamp` and `action`. The actions include `server-update`, and are "only captured from client apps using 1Password 8.4.0 or later";
- audit events carry `action` (for example `update`), `object_type` (`item`, `vault`) and `object_uuid`.

**Needs a live check (never called here):**
- which plans include it (the page doesn't say);
- whether `server-update` fires for every edit, including CLI (`op`) and service-account writes;
- the latency;
- whether item usages cover the vaults opv uses ("items in shared vaults").

**Recommendation:** keep `opv changed` (polling item versions) as the 0.11.0 mechanism. It works on every plan, needs no new credential, and is exact. An Events API trigger would be a later, optional accelerator: a small poller that runs `opv changed` when it sees `server-update` for a watched `item_uuid`. It needs its own Events token in CI. Owner decision O16.

### 2.5 CI recipes (GitHub Actions)

These are shipped as `examples/ci-change-detection/` (deliverable C6). They follow the existing example's install and checksum steps (`examples/github-ci/sync-ci-secrets.yml:26-34`).

**Secrets handling:**
- **Two service accounts.** A **reader** (read-only on the environment's vaults and the state vault, as `opv access` creates it, `docs/usage.md:473`) runs `changed`, `plan` and the drift check. A **deployer**, held in a GitHub *environment* secret, runs `sync`. With required reviewers on that environment, its token is released only after approval.
- Tokens are referenced as `${{ secrets.… }}` and passed through `env:` only on the steps that need them. They are never echoed and never written to files.
- GitHub masks registered secrets in logs. opv also registers `OP_SERVICE_ACCOUNT_TOKEN` and scrubs it from its own output (`docs/how-opv-handles-failures.md:142`).
- The workflows print names, ids and states only. `opv … --json` holds no value (`docs/usage.md:680`).

```yaml
# .github/workflows/opv-sync-on-change.yml
name: opv: sync when 1Password changes
on:
  schedule: [{cron: "*/15 * * * *"}]       # the change check, every 15 minutes
  push: {branches: [main], paths: [secrets.toml]}
  workflow_dispatch:
permissions: {contents: read}
concurrency: {group: opv-sync, cancel-in-progress: false}
jobs:
  detect:
    runs-on: ubuntu-latest
    strategy: {matrix: {env: [staging, prod]}}
    outputs:
      staging: ${{ steps.c.outputs.staging }}
      prod: ${{ steps.c.outputs.prod }}
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/install-opv      # op CLI + opv, checksum-verified
      - id: c
        env: {OP_SERVICE_ACCOUNT_TOKEN: "${{ secrets.OPV_READER_TOKEN }}"}
        run: |
          set +e; opv changed ${{ matrix.env }} --json > changed.json; rc=$?; set -e
          case $rc in
            0)  echo "${{ matrix.env }}=no"  >> "$GITHUB_OUTPUT" ;;
            10) echo "${{ matrix.env }}=yes" >> "$GITHUB_OUTPUT" ;;
            *)  exit $rc ;;                       # unreadable is a failure, never "unchanged"
          esac
  sync-staging:                                   # confirm_env = false: apply directly
    needs: detect
    if: needs.detect.outputs.staging == 'yes' || github.event_name == 'push'
    runs-on: ubuntu-latest
    environment: staging
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/install-opv
      - env: {OP_SERVICE_ACCOUNT_TOKEN: "${{ secrets.OPV_DEPLOY_TOKEN }}"}
        run: opv sync staging --deploy
  plan-prod:                                      # confirm_env = true: a reviewed plan
    needs: detect
    if: needs.detect.outputs.prod == 'yes' || github.event_name == 'push'
    runs-on: ubuntu-latest
    outputs: {plan_id: "${{ steps.p.outputs.plan_id }}"}
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/install-opv
      - id: p
        env: {OP_SERVICE_ACCOUNT_TOKEN: "${{ secrets.OPV_READER_TOKEN }}"}
        run: |
          opv plan prod > plan.txt                # names only
          cat plan.txt >> "$GITHUB_STEP_SUMMARY"  # the reviewer reads this
          echo "plan_id=$(opv plan prod --json | jq -r .plan_id)" >> "$GITHUB_OUTPUT"
  sync-prod:
    needs: plan-prod
    runs-on: ubuntu-latest
    environment: production                       # required reviewers approve the summary's plan
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/install-opv
      - env: {OP_SERVICE_ACCOUNT_TOKEN: "${{ secrets.OPV_DEPLOY_TOKEN }}"}
        run: opv sync prod --deploy --expect-plan ${{ needs.plan-prod.outputs.plan_id }}
```

- On a guarded environment, `--expect-plan` stands in for `--confirm`. A sync refuses (exit 6) if anything changed after the review (`docs/usage.md:213-232`). The reviewer approves exactly the plan id in the job summary.
- `opv approve` is for assistant-prepared plans in a person's own terminal (`docs/usage.md:24`, `:234`). It isn't used in CI.

```yaml
# .github/workflows/opv-drift.yml
name: opv: drift check
on: {schedule: [{cron: "23 4 * * *"}], workflow_dispatch: {}}
permissions: {contents: read}
jobs:
  drift:
    runs-on: ubuntu-latest
    strategy: {fail-fast: false, matrix: {env: [staging, prod]}}
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/install-opv
      - env: {OP_SERVICE_ACCOUNT_TOKEN: "${{ secrets.OPV_READER_TOKEN }}"}
        run: |
          opv status ${{ matrix.env }} --fail-on-drift     # exit 8 target_drift on drift
          opv delivery verify ${{ matrix.env }} --json      # exit 8 delivery_unverified
```

- **`opv ci workflow`** (`src/app/ci_workflow.rs:24-40`) gains `--on-change`, which prints these two workflows for a configuration, filling the environment matrix and the confirm split from `confirm_env` (deliverable C5).
- **Schedule load** is 96 checks a day per environment, each one `op item list` per vault plus one `op read`. Service-account rate limits are **[A29]**. Therefore:
  - **The schedule is configurable:** `opv ci workflow --on-change --every <minutes>` (default 15) sets the cron (C5).
  - **One listing per vault per run.** `changed` already lists each vault once and takes every item id it needs from that one reply (§2.2); it never lists per item.
  - **A rate-limit reply is typed.** C1 classifies `op`'s rate-limit reply as `Unavailable{OnePassword, RateLimited{retry_after_seconds}}` (the existing `Unanswered::RateLimited`, `src/cause/mod.rs:378-380`; no adapter produces it today), exit 9, never `unchanged` **[A32]**. opv doesn't sleep inside a run. The detect step retries `changed` once after `retry_after_seconds` (capped at 120 s; 30 s when the reply names none) and otherwise fails; the next scheduled run is the back-off. C5's output carries that retry; the §2.5 listing shows the shape without it.

### 2.6 Causes and codes for §2

| Situation | Variant | Code | Exit | Retry | Do | Next |
|---|---|---|---|---|---|---|
| the source changed since the last sync | **`SourceChanged`** (new; a result, not an error: `ok: true`) | **source_changed** | **10** | — | — | `opv sync <env> --deploy`, or `opv plan <env>` on a guarded environment |
| no recorded source versions | `SourceChanged{no_record}` | source_changed | 10 | — | "run opv bootstrap to record delivery items" when none exist | `opv bootstrap` / the sync |
| drift under `--fail-on-drift` | **`TargetDrift`** (new) `{env, target, names}` | **target_drift** | 8 | after_fix | "re-run the sync to restore 1Password's values" | `opv sync <env> --deploy` |

Exit 10 joins the table in `docs/usage.md:887-896` and §4.11 of the catalog.

## 3. README draft (deliverable D-README)

Below is the README text for the owner to read. It goes into `README.md` as a new section after the introduction.

> ## How opv works: one source of truth, synced by CI
>
> 1Password holds everything your app is configured with: its settings and its secrets. Nothing else does. opv moves those values to where they are needed and never anywhere else.
>
> ```mermaid
> flowchart LR
>   OP[(1Password<br/>config + secrets)]
>   DEV[Your laptop<br/>opv run]
>   CI[CI/CD<br/>opv changed · opv sync · drift check]
>   K8S[Kubernetes<br/>Secrets · ConfigMaps · mounted files]
>   SW[Docker Swarm<br/>secrets · configs]
>   FLY[Fly.io<br/>Fly secrets]
>   VM[VMs<br/>cloud secret manager]
>   OP -- your own sign-in --> DEV
>   OP -- service account --> CI
>   CI --> K8S & SW & FLY & VM
> ```
>
> - **Local development:** `opv run dev -- <your command>` starts your app with the values it needs, as variables or as files in a private in-memory folder, and cleans up when it stops. Values never touch your disk.
> - **CI/CD:** a workflow runs `opv sync` with a 1Password service account. opv writes secrets and settings into each platform's own place: Kubernetes Secrets and ConfigMaps, Swarm secrets, Fly secrets, a cloud secret manager.
> - **Production never touches 1Password.** Your running app reads only what its platform gives it. There is no 1Password token, no opv, and no `op` in your images or servers.
> - **Staying in step:** a scheduled job runs `opv changed`, which notices when someone edits a value in 1Password and triggers the sync. Production syncs wait for a reviewer to approve the exact plan. A nightly drift check fails if a platform no longer matches 1Password.
>
> Copy the ready-made workflows: [examples/ci-change-detection](examples/ci-change-detection/).

## 4. Shared changes

### 4.1 The binding name stays the rendered name

A key keeps its rendered target name as its identity: its managed name (`src/app/mod.rs:1708-1721`), its store name (`src/adapters/kubernetes/mod.rs:256-259`) and its plan row (`src/app/mod.rs:735-760`). The file path and the channel are extra, names-only data. Moving a key between env and file, or between channels, creates no new value versions; one deploy moves the binding.

### 4.2 Plumbing

- `TargetConfig::open` (`src/provider.rs:366-373`) gains `files: &BTreeMap<String, FileMount>`. It is computed next to `managed_names` (`src/app/mod.rs:1700-1721`).
- `FileMount { product, path }` is a new names-only type in `src/domain/runtime.rs`.
- `channels()` (§1.3) replaces any ad hoc "does this target take config" check.

### 4.3 Plan id

`PlanIdInput` (`src/app/mod.rs:200-230`, `src/domain/provenance.rs:51`) adds each delivered name's channel and form: `secret`, `config`, or `file:<path>`. A plan reviewed under one routing never matches a sync under another.

### 4.4 Target-level `roles`

- `RawTarget` (`src/config.rs:724-742`) and `Target` (`src/domain/model.rs:226-244`) gain `roles`.
- In `plan::evaluate` (`src/domain/plan.rs:296-321`), a key whose `roles` miss the target's is not desired there, so `--deploy --prune` removes an existing binding (`docs/usage.md:261`).
- Load rules: a target that delivers a product whose keys declare roles must declare `roles`; each role must be declared by some key; an empty list is refused (as for keys, `src/config.rs:1704-1722`).
- This changes "roles never reach `sync` or a target" (`docs/design/local-delivery.md:79`; `src/domain/model.rs:115-116`).
- Migration material on Kubernetes and Swarm is out of scope; run migrations with `opv run --role migrate`. Fly's migration app uses the same field (§7.4).

### 4.5 Verbatim bytes for file keys

**Today:**
- Local delivery writes the bytes `op run` gives it, unchanged (`src/app/local_delivery.rs:304-317`; `tests/local_delivery.rs:203-221`).
- `pem_private_key` turns a multi-line PEM into one line (`src/domain/rules.rs:288-296`). `single_line` and `no_surrounding_space` (`:297-302`) apply in `plan::evaluate` even without a target (`src/domain/plan.rs:194-198`, `:309`), and the evaluated value is what gets staged.
- The tidy trims a trailing `\n`, `\r` or space (`src/domain/convention.rs:263-303`), which contradicts the verbatim decision.
- Non-UTF-8 values panic the local step at `std::env::vars()` (`src/app/local_delivery.rs:295`).

**Changes:**
1. `normalized` returns `None` for a key with `file`.
2. For a key with `file`, when there is no target or the target's `files` capability is `Native`, `single_line`, `no_surrounding_space` and the transform don't apply. `nonempty`, `max_len` and the prefix rules still do, and the staged value is the stored value. Targets that stage it as a variable keep every rule.
3. `docs/configuration.md` `:661-726` states the exception.
4. **One key, two forms, shown.** A file key delivered to a target whose `files` capability is not `Native` keeps every variable rule. Without a declared `transform`, a multi-line value or a trailing newline fails `single_line` or `no_surrounding_space` there (`src/domain/rules.rs:297-302`): a loud finding, not a silent change. With `transform = "pem_private_key"` declared, that target gets the one-line form while a `Native` target gets the stored bytes. `plan` shows the form on each row (text `file (verbatim)`, `env (pem_private_key)`, `env`; JSON `delivered_as` and `form`, §6.7), so the difference is visible at review. A `FileCapability::None` target adds the `file destination not honoured on <target>` warn line (§1.3); a `ViaApp` target (Fly) prints `file via the app (<note>)`.

### 4.6 Journeeze's mapping

| Key | Destination | Roles | Constant |
|---|---|---|---|
| `DATABASE_URL` | `database/url` | serve | `ced358d:crates/jz_host/src/lib.rs:92` |
| `GITHUB_APP_PRIVATE_KEY` | `github-app/private-key` | serve | `ced358d:crates/jz_github/src/lib.rs:67` |
| `GITHUB_WEBHOOK_SECRET` | `github/webhook-secret` | serve | `ced358d:crates/jz_github/src/events.rs:251`. **New in the mapping.** |
| `TYPESAFE_JEV_API_KEY` | `jev/api-key` | serve | `ced358d:crates/jz_jev/src/live.rs:24` |
| `BLOB_ACCESS_KEY_ID` | `blob/access-key-id` | serve | `ced358d:crates/jz_blob/src/s3.rs:20` |
| `BLOB_SECRET_ACCESS_KEY` | `blob/secret-access-key` | serve | `ced358d:crates/jz_blob/src/s3.rs:21` |
| `GUIDE_ASSET_SIGNING_KEY` | `guide-assets/signing-key` | serve | `ced358d:crates/jz_auth/src/asset_links.rs:13` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `otel/endpoint` | serve | `ced358d:crates/jz_host/src/telemetry.rs:24` |
| `OTEL_EXPORTER_OTLP_HEADERS` | `otel/headers` | serve | `ced358d:crates/jz_host/src/telemetry.rs:27` |
| `DATABASE_URL_UNPOOLED` | `database/owner-url` | migrate | `ced358d:crates/jz_host/src/lib.rs:203` |
| `JOURNEEZE_APP_PASSWORD` | `database/app-password` | migrate | `ced358d:crates/jz_host/src/lib.rs:204` |

- **Webhook secret.** The shim's `SERVE` list (`ced358d:crates/jz_host/src/fleet_secrets.rs:40-76`) lacks it, so on the shared Fly host it **is not delivered** today. This document states that rather than implying otherwise. opv's fixture consumer already expects it (`tests/mounted_consumer.rs:16-24`).
  - Adding it to opv's mapping (A3) is not enough on Fly: the shim must also list it. That one-line change is in Journeeze, made by its maintainers, and A3 names it as an external dependency. Until it lands, the webhook secret reaches Fly only as an env variable the shim ignores, and A3 says so rather than claiming delivery.
  - What proves what: `opv run … --preview --json` proves the mapping; V8 and V10 on kind prove file delivery of `github/webhook-secret` (no shim there); only a Journeeze-side test of `SERVE` plus the §7.4 staging step 3 prove it on Fly. V10/V14 can't, since the verification cluster runs no shim.
- **Reading.** `MountedSecretStore` reads with `tokio::fs::read`, so it follows symlinks, and maps every error to `NotFound` (`ced358d:crates/jz_secrets/src/lib.rs:40-45`). An unreadable file looks missing, which is why readability is checked before delivery (§5, §6.6, §8.4, §9.3).
- **The mapping lives in Journeeze's opv manifest** **[A1]**.

## 5. Local: the wrapper and the Docker Compose recipe

`opv run` writes file keys into a 0700 tmpfs directory as 0400 files (`src/app/local_delivery.rs:243-279`, `:296-320`) and sets the directory variable (`:186-189`). **There is no `--dir-env` on `opv run`** (`src/main.rs:697-728`). The variable comes from `[products.<p>.local] secrets_dir_env` (`src/app/run.rs:466-467`); see O5.

```toml
[products.journeeze.local]
environment = "declared_only"
secrets_dir_env = "OPV_SECRETS_DIR"
```

```yaml
# compose.yml (recorded verbatim as tests/fixtures/compose/recipe.yml)
services:
  serve:
    image: journeeze:local
    command: ["serve"]
    user: "${OPV_UID:?run this under opv run}:${OPV_GID:?run this under opv run}"
    environment: {JZ_VAULT_DIR: /run/secrets/journeeze}
    volumes:
      - {type: bind, source: "${OPV_SECRETS_DIR:?run this under opv run}", target: /run/secrets/journeeze, read_only: true}
    logging: {driver: none}
```

Run it with `opv run dev --product journeeze --role serve -- docker compose up`.

| Line | Why | Evidence |
|---|---|---|
| `user:` is the invoking user | another container uid is denied; container root reads the files anyway | `3b8e180:tests/fixtures/docker/failures/01-run-as-other-uid-denied.stderr`; `3b8e180:tests/fixtures/docker/success/05-run-as-host-user-reads.stdout`; `…/success/07-run-as-root-reads.stdout` |
| not `${UID}:${GID}` | `UID` isn't exported and `GID` doesn't exist, so compose renders `user: ':'` | `tests/fixtures/compose/05-bash-uid-not-in-environment.stdout:1-3`; `tests/fixtures/compose/06-naive-config-dir-set-uid-unset.stderr:1-2`, `.stdout:7` |
| `${…:?…}` | outside opv, compose refuses with exit 15 | `tests/fixtures/compose/03-recipe-config-outside-opv.stderr:1`; under opv `tests/fixtures/compose/02-recipe-config-under-opv.stdout:13-18` |
| long `type: bind` | the short form sets `create_host_path: true` (`tests/fixtures/compose/06-naive-config-dir-set-uid-unset.stdout:13-14`), and Docker Desktop then creates a root-owned source (`3b8e180:tests/fixtures/docker/failures/03-bind-source-missing.host-ls`) | as cited |
| `read_only` | the app can't write | `3b8e180:tests/fixtures/docker/failures/02-readonly-mount-write-refused.stderr` |
| `logging: none` | the default `json-file` driver writes output to disk | `3b8e180:tests/fixtures/docker/success/16-info-logging-driver.stdout` |
| RAM inside the container | the bind shows as tmpfs (WSL 2 with Docker Desktop) | `3b8e180:tests/fixtures/docker/success/08-mountinfo-in-container.stdout` |

**`OPV_UID` and `OPV_GID` (new).** Under `declared_only`, only `BASICS` pass through (`src/app/local_delivery.rs:36-49`, `:183`). A run that delivers files sets both variables, as the effective ids, in `child_env` (`:186-189`). O4.

**5.3 The readability check is rejected; the requirement is documented instead.**
- opv can't know the effective user: it comes from compose's interpolation, overrides and `.env`, or the image's `USER`.
- `docker compose config` prints interpolated values (`tests/fixtures/compose/02-recipe-config-under-opv.stdout:7-8`), so it could leak a value into opv's output.
- opv can't tell which command after `--` is compose.

Instead:
- the recipe fails closed outside opv;
- `docs/local-development.md` gets a Docker Compose section;
- `opv run --preview` prints `containers: run as <uid>:<gid> (OPV_UID:OPV_GID) to read these files`.

**Limits:** the same user, the Docker daemon, the `docker` group and container root can read the directory (`docs/design/local-delivery.md:41-56`). This is the **accepted residual** of local delivery (owner decision, §0; R4): the recipe stays fail-closed and `read_only`, and the limit stays documented. Narrowing it further (a dedicated delivery user, per-role subdirectories) is recorded as an open idea in §15, not designed.

## 6. Kubernetes: ConfigMaps and mounted files (0.11.0)

### 6.1 Today

- Secrets are immutable versioned Secrets `opv-<store>-<id>` (`src/adapters/kubernetes/mod.rs:5-10`; `immutable: true`, `src/adapters/kubernetes/store.rs:203`).
- They are bound as env `valueFrom.secretKeyRef` (`src/adapters/kubernetes/runtime.rs:10-11`, `:732-738`; `src/adapters/kubernetes/mod.rs:11-13`).
- Config is a plain `value` env entry, or goes through the store (`src/adapters/kubernetes/runtime.rs:740-742`; `docs/configuration.md:461`).
- Writes are a `kubectl replace` with `resourceVersion` (`:697-772`).
- The recorded shape is `tests/fixtures/kubernetes/deployment-get.json:47-69`.

### 6.2 Configuration

```toml
[environments.prod.targets.k8s]
kubernetes.context     = "prod-cluster"
kubernetes.namespace   = "journeeze"
kubernetes.deployment  = "journeeze"
kubernetes.env_name    = "FLEET__{PRODUCT}__{KEY}"
kubernetes.config      = "configmap"                # new value; "env" and "store" stay
kubernetes.secrets_dir = "/run/secrets/{product}"   # new: file keys become files here
roles = ["serve"]
```

- **`config = "configmap"`** (new, in `ConfigRoute`, `src/adapters/kubernetes/config.rs:85-93`). Each config value version becomes an immutable ConfigMap `opv-<store>-<id>`: `data.value`, the same labels and annotations as Secrets (`src/adapters/kubernetes/mod.rs:77-93`), `immutable: true`.
  - A config key without `file` is bound as env `valueFrom.configMapKeyRef {name, key: value}`. Like a plain env `value`, it is readable by anyone who can read the ConfigMap or the pod spec; that is why config is declared non-secret and each row shows its channel (§1.3).
  - A config key with `file` becomes a `configMap` source in the projected volume (§6.3).
  - ConfigMaps can be read back, so `plan` compares values exactly, as for Secrets (`src/adapters/kubernetes/store.rs`, the compare-before-write read).
  - `opv init` writes `configmap` for new targets. Existing targets keep `env` until changed; O1 decides whether the default flips.
- **`secrets_dir`** (new, optional). It goes into `Raw` (`src/adapters/kubernetes/config.rs:119-130`) and `KubernetesTarget` (`:96-107`).
  - Unset: no key is a file, exactly as today.
  - Set: every delivered key with `file` is mounted at `<dir>/<file>`, and only there.
  - `{product}` renders the product name (`_` → `-`). It is required when two products have file keys, and two products may not render the same directory.
  - Load rules in `Raw::checked` (`:140-172`): absolute and normalised; not `/`; not under `/proc`, `/sys`, `/dev` or `/var/run/secrets/kubernetes.io`; at most 255 bytes, with no `:` or whitespace.
  - A config key with `file` needs `config = "configmap"` or `"store"`.
  - No key's `file` may be a parent directory of another's within one product (`a` and `a/b`). The API server accepts that volume with only a `Warning:` and the pod never starts (K1: `failures/12-warning-replace-overlapping-paths`); `..`, absolute and duplicate paths it refuses itself (K-R2).
- **Channels:** secret → `Store{"Kubernetes Secret"}`; config → `Store{"ConfigMap"}`, `RuntimeEnv`, or `Store{"Kubernetes Secret"}`, per `config`; files → `Native` when `secrets_dir` is set, otherwise `None`.

### 6.3 The Deployment patch

```json
"volumes": [{"name": "opv-files-journeeze", "projected": {"defaultMode": 288, "sources": [
  {"secret":    {"name": "opv-fleet--journeeze--github-app-private-key-q3vz7kd2mx", "optional": false,
                 "items": [{"key": "value", "path": "github-app/private-key", "mode": 288}]}},
  {"configMap": {"name": "opv-fleet--journeeze--otel-resource-xk2m4n6p8q", "optional": false,
                 "items": [{"key": "value", "path": "otel/resource", "mode": 288}]}}
]}}],
"containers": [{"name": "journeeze",
  "env": [{"name": "LOG_LEVEL", "valueFrom": {"configMapKeyRef": {"name": "opv-log-level-h6tn4wbr5e", "key": "value"}}}],
  "volumeMounts": [{"name": "opv-files-journeeze", "mountPath": "/run/secrets/journeeze", "readOnly": true}]}]
```

- **Projected volume.** opv keeps one immutable object per value version, and a projected volume merges many objects, Secrets and ConfigMaps alike, into one directory **[A2]**. Rejected: one combined Secret per product, which breaks versioning and pruning; and `subPath` mounts.
- **`items[].path`** is the key's `file` **[A2]**; the key is `value` (`src/adapters/kubernetes/mod.rs:77`), the same under ExternalSecrets (`src/adapters/kubernetes/external.rs:163-165`).
- **Mode 0440 (288).** Files are root-owned, with the group of `fsGroup` **[A3]**. 0400 would block a non-root app; 0444 is rejected.
- **Who can read them (FMECA FM-08).** `fsGroup` is pod-wide, and Secret and ConfigMap projections have no per-file owner, so "0400 owned by the app's uid" is not available on Kubernetes. The reader set is narrowed by isolation instead:
  - the volume is per product (`opv-files-<product>`), and its `volumeMount` goes **only into the target's container** (`kubernetes.container`, `docs/configuration.md:396`). Another container in the pod, a sidecar for example, has no such path, even though it shares `fsGroup`;
  - opv never sets `fsGroup` (O2, O6); the person's manifest owns it. The docs recommend a group used by this product's container alone;
  - what remains readable, by design: processes inside the target container that run as root or in `fsGroup`, and node root (R1 in §14). V9 records `stat` and `id` in the app container and checks that a second container has no mount.
- **`readOnly: true`**, and `optional: false` on every source **[A7]**.
- **The volume is `opv-files-<product>`.** The `opv-files-` prefix is reserved (`docs/usage.md:261`).
- **A file key never keeps an env entry**: the same replace removes it. When a product's last file key goes, its volume and mount go too.
- **`bindings()`** (`src/adapters/kubernetes/runtime.rs:658-694`) reads file bindings from the volume items, and config env bindings from `configMapKeyRef` (beside `secret_ref`, `src/adapters/kubernetes/mod.rs:628-634`). Anything else is `Other`: a missing item, a mount that is missing, not read-only or at a different path, or a name that is still an env entry. `Other` shows as drift and is re-pinned under `--deploy`.
- **`fingerprint()`** (`:293-304`) and the reconcile comparison (`:788-797`) strip opv's volumes and mounts. They normalise server defaults **[A5]**: K1 found one, `projected.defaultMode: 420` when it is omitted; the §6.3 volume, every field explicit, is stored exactly as sent.

### 6.4 Rollout, refresh and clean-up

- **Write, then deploy**, as today (`docs/usage.md:246-249`).
- **Refresh is a rollout.** Kubernetes refreshes a projected object in running pods only when its content changes. opv's objects are immutable, and each version has a new name (`src/adapters/kubernetes/store.rs:203`). The kubelet doesn't watch immutable objects **[A4]**. A new version therefore changes the template, starts a rolling update and goes through the health wait (`src/adapters/kubernetes/runtime.rs:815-860`).
- **A missing source** leaves the pod in `ContainerCreating`, which isn't one of `STUCK_REASONS` **[A7]**. The rollout then fails at the progress deadline (`:315-327`). O10.
- **Logs (FMECA FM-03).** A secret is never written to a workload's log. opv can't enforce that on Kubernetes: a container's stdout always reaches the node's log files through the kubelet, and there is no per-workload log driver to check, so opv prints no warning here. The contract is the app's: read from files, never log a value. `docs/usage.md` states it (K6), and the verification canary scan includes `kubectl logs` and the node's `/var/log/pods` (V16).
- **Superseded-version clean-up already covers volumes and ConfigMaps.** Any string in the Deployment or any ReplicaSet keeps its object (`referenced_names`, `src/adapters/kubernetes/store.rs:257-284`). It is extended from Secrets to ConfigMaps by kind, with the same label selector. Rollback keeps working (`docs/usage.md:264`).

### 6.5 RBAC and ExternalSecrets

- **New rights, for `configmap` only:** `get`, `list`, `create`, `patch` and `delete` on configmaps. opv writes with `apply --server-side`, which the API server authorises as `patch`, and as `create` too for a new object (K1: `tests/fixtures/kubernetes/failures/10-*`); `auth can-i create` alone answers `yes` for an identity whose apply is refused. The same hole exists today for Secrets: `ACCESS` checks `create secrets` but not `patch secrets`. They are added to `ACCESS` (`src/adapters/kubernetes/runtime.rs:62-118`), and `delete configmaps` to `DEPLOY_RIGHTS` (`:133-137`).
- **Scope of those rights (FMECA FM-09).** They are granted by a namespaced Role in the target's namespace only, never a ClusterRole; the docs and the §12.1 kit say so. `resourceNames` can't narrow them: Kubernetes doesn't apply it to `create` or `list`, and opv's names change with every version. The added power is small, because a ConfigMap only takes effect once the Deployment points at it, and the identity can already change the Deployment. The detection is the nightly drift check (§2.3): an out-of-band ConfigMap, or a repointed binding, is `Other`/drift (§6.3), so `status --fail-on-drift` exits 8 `target_drift`. opv's own ConfigMaps are immutable, so their content can't be edited in place.
- Volume mounts need no pod RBAC; the kubelet mounts them (`:886-889`) **[A6]**.
- **ExternalSecrets:** the projected source names the ExternalSecret's target Secret, which has the same name (`src/adapters/kubernetes/external.rs:162`). Each ExternalSecret pins one Key Vault version (`:165`), so no live change follows a refresh. Clean-up is unchanged (`:655-661`).
- **Pod Security** `restricted` allows these volumes and `fsGroup` **[A11]**.

### 6.6 Readability preflight

The preflight reads the Deployment opv already reads (`src/adapters/kubernetes/mod.rs:542-554`), which holds no value.

| `fsGroup` | Effective `runAsUser` | Effective `runAsGroup` | Verdict |
|---|---|---|---|
| set | any | any | readable **[A3]** |
| unset | 0 | any | readable, **with a warn line** (the workload runs as root) |
| unset | set, not 0 | 0 | readable, **with a warn line** (the workload runs in group 0, which owns every mounted file) |
| unset | set, not 0 | set, not 0 | **unreadable** |
| unset | set, not 0 | unset | **unknown** |
| unset | unset | any | **unknown** |

Amended by K1 (`tests/fixtures/kubernetes/README.md`, K-R5 `imagegid`): with `runAsUser: 10001` and no `runAsGroup`, the primary group comes from the image's `/etc/passwd`, and is 0 when the image has no entry for the uid; the 0440 root:root files were then readable. So the verdict also reads the effective `runAsGroup`, and an unset one is unknown, not unreadable.

- It is a pure `files::readability`, run in `KubernetesTarget::preflight` (`src/adapters/kubernetes/config.rs:435`).
- `sync` refuses an unreadable or unknown verdict before writing; `plan`, `status` and `doctor` warn (`src/provider.rs:374-381`). O2.
- A root workload (FMECA FM-13) is readable, so nothing is refused, but every `plan`, `status` and `doctor` prints `warn: deployment <d> runs as root: every mounted file is readable by any process in the container; run as a non-root user with fsGroup`. `sync` prints it too and goes on.
- Journeeze runs as uid 10001 (`ced358d:deploy/Dockerfile:34`, `:43`), so it needs `fsGroup`.

### 6.7 Plan and status

```text
prod/k8s: would write: journeeze/GITHUB_APP_PRIVATE_KEY (FLEET__JOURNEEZE__GITHUB_APP_PRIVATE_KEY → file /run/secrets/journeeze/github-app/private-key)
prod/k8s: would write: journeeze/LOG_LEVEL (LOG_LEVEL → ConfigMap, env)
prod/k8s: would deploy: volume opv-files-journeeze, read-only at /run/secrets/journeeze (2 files; env entries removed: FLEET__JOURNEEZE__GITHUB_APP_PRIVATE_KEY)
warn: deployment journeeze sets no fsGroup and runs as 10001: the mounted files (0440, root-owned) would be unreadable
```

- `JsonRow` (`src/app/mod.rs:735-760`) gains `channel` (`secret` / `config`), `via` (the channel's label: `Kubernetes Secret`, `ConfigMap`, `env`, `Fly secret`, …; §1.3), `delivered_as` (`env` / `file`), `form` (`verbatim` for a file on a `Native` target, the transform's name when one applies, absent otherwise; §4.5) and `path`. The change is additive.
- `chain:` lines (`src/app/status.rs:666`; `src/adapters/kubernetes/runtime.rs:876-885`) cover files and ConfigMaps.

### 6.8 Causes

| Situation | Variant | Code | Exit | Retry | Do | Next |
|---|---|---|---|---|---|---|
| bad `secrets_dir` | `ConfigInvalid` `Pattern{ContainerPath}` (new id) | config_invalid | 2 | after_fix | "use an absolute path such as /run/secrets/{product}" | `opv config edit` |
| directory or volume-name collision | `ConfigInvalid` `Collision` | config_invalid | 2 | after_fix | "put {product} in secrets_dir" | `opv config edit` |
| a config key with `file` under `config = "env"` | `ConfigInvalid` new `ConfigFileNeedsObject{key}` | config_invalid | 2 | after_fix | "set config = \"configmap\"" | `opv config edit` |
| target `roles` missing, undeclared or empty | `ConfigInvalid` `Missing` / `Check{NotOneOf}` / `Check{EmptyRoles}` (`src/config.rs:1704-1708`) | config_invalid | 2 | after_fix | "add roles to the target" | `opv config edit` |
| the path, or a parent or child of it, is in use by a foreign volume | `Guard` new `MountPathInUse{workload, container, path, volume}` | policy_refused | 6 | never | "choose another secrets_dir, or remove volume <v>" | `opv plan …` |
| unreadable or unknown (§6.6) | new **`MountUnreadable`** `{workload, container, run_as, why: NoFsGroup / RunAsUnknown}` | **mount_unreadable** | 6 | after_fix | "set spec.template.spec.securityContext.fsGroup (any group, for example 10001), or runAsUser: 0. Nothing was written." | `opv plan …` |
| 422 on replace | `TargetRefused{Validation}` (`src/cause/mod.rs:1084`) + a new phrase in `src/adapters/kubernetes/diagnose.rs` | update_refused | 5 | after_fix | "kubectl's reply is shown above" | `opv doctor …` |
| missing configmap rights | `MissingRight{K8sRbac{verb, configmaps}}` (existing model) | permission_denied | 5 | after_fix | the typed grant | `opv doctor …` |
| a file key left as env after `apply` | `Bug` | internal_error | 70 | never | — | `opv version` |

`MountUnreadable` gets its own code because its fix is in the person's manifest. Swarm (§8.8) reuses it.

### 6.9 kubectl replies to record

These use kind, set up as in `tests/fixtures/kubernetes/success/README.md:3-5`. The simulator renders `get -o json` and `replace` from the world (`tests/sim/kube.rs:12-14`, `:310-367`).

| # | Command | For |
|---|---|---|
| K-R1 | `replace` with the §6.3 volume | nested paths, `mode`, `configMap` sources **[A2]** |
| K-R2 | `replace` with `path: ../x`, and with a duplicate path | the 422 text |
| K-R3 | `get deployment -o json` after K-R1 | server defaults **[A5]** |
| K-R4 | `get pods -o jsonpath=<PODS_PATH>` (`src/adapters/kubernetes/runtime.rs:56`) with a missing source | **[A7]** |
| K-R5 | `exec … stat -f -c %T`, `stat -L -c "%a %u %g"`, `id`: no `fsGroup` at uid 10001, `fsGroup: 10001`, root | **[A2]**, **[A3]** |
| K-R6 | `get replicasets -o json` after two deploys | references |
| K-R7 | `apply -f - --server-side --field-manager=opv -o name` of a ConfigMap; `auth can-i create configmaps` (yes and no); `delete configmap …` | the ConfigMap store; the simulator today infers non-Secret kinds from the Secret recordings (`tests/sim/kube.rs:12-14`) |

Until K-R2 and K-R4 exist, the simulator answers exit 86 (`tests/sim/recordings.rs:9`), and the coverage gate lists them as exempt. **The exemption is for work in progress only (FMECA FM-10).** K3, K4, K5 and K6 merge only when K1 is merged and its README marks **[A2]**, **[A3]**, **[A5]** and **[A7]** confirmed, or §6 has been amended where one was refuted; K6 merges only with K-R2 and K-R4 reached, not exempt.

### 6.10 Tests

| Layer | What | Where |
|---|---|---|
| Unit | volume golden JSON; `read_bindings` for each `Other` case; `readability`; `strip_managed`; a no-value property test | `src/adapters/kubernetes/files.rs`, `files_tests.rs` |
| Unit (FakeRunner) | `apply` on `deployment-get.json`: volume added, env entry removed, `K7` kept; ConfigMap write and compare | `runtime.rs`, `store.rs` tests |
| E2E | `e2e-prod` gets a Deployment from the recording (`tests/e2e/app/world.json` is empty today). The e2e k8s target (`tests/e2e/app/secrets.toml:35-41`) gets `secrets_dir`, `config = "configmap"` and `roles`. Snapshots and the canary scan. | `tests/e2e/scenarios/k8s_files.rs` |

## 7. Fly: config channel, files and the migration app

### 7.1 Config as Fly secrets (0.11.0)

- **Channel.** Fly's runtime env can be written through its API only as secrets. `[env]` in `fly.toml` belongs to the app's deployed configuration. Config keys therefore go to Fly secrets under the same name template (`src/adapters/fly/config.rs:45-53`), staged and deployed exactly like secrets (`docs/configuration.md:352`).
- **Comparison.** Fly hides values, so config gets the same digest-and-ledger treatment as secrets (`docs/usage.md:240`).
- **Opt-in by declaration.**
  - New `fly.config = "secrets" | "none"`.
  - Unset on a target that delivers config keys: `plan` and `status` warn `config not delivered: set fly.config` in 0.11.0. Today these keys are silently `n/a` (`docs/usage.md:131`), and turning them on for every Fly app on upgrade would stage new secrets and restart machines without anyone asking.
  - From 0.12.0, unset is refused (`NoChannel`). O15 decides this schedule.
- **Precedence.** A Fly secret and an `[env]` entry with the same name: which wins is **[A30]**. `plan` warns when a config key's name also appears in `fly.toml`'s `[env]`, if the file is present in the checkout.
- **Channels:** secret → `Store{"Fly secrets"}`; config → `Store{"Fly secrets"}` or `None{"fly.config = none"}`; files → `ViaApp{"the app writes env to files (Journeeze's shim)"}`.
- **Config stays config.** A Fly secret hides the value from `fly secrets list`, but the app still sees config as env at boot, so the §1.3 rules hold unchanged: each row shows `channel: config` and `Fly secret`, anything sensitive is `kind = "secret"`, and a concealed config field gets today's warning.

### 7.2 Files on Fly: established

- `--file-secret /path/inside/machine=SECRET`: "where SECRET is the name of the secret. The content of the secret must be base64 encoded." It exists on `machine run`, `machine update` and `deploy` (`tests/fixtures/fly/help/machine-run.stdout:59-66`, `tests/fixtures/fly/help/machine-update.stdout:57-64`, `tests/fixtures/fly/help/deploy.stdout:113-117`), in flyctl v0.4.111 (`tests/fixtures/fly/failures/12-version.stdout:1`).
- opv would stage a separate base64 copy (`…__FILE`) of each file key, which keeps the bytes verbatim in one line.
- Journeeze runs on the infra repo's shared fleet. Its launcher clears the environment (`ced358d:fly.toml:1-10`) and builds the machine configuration in `fly/shared-host/assemble.py` (not read **[A10]**). So `[[files]]` in Journeeze's own `fly.toml` wouldn't apply.

### 7.3 Files on Fly: needs a live check (a throwaway app; O8)

- F1: does `fly.toml` `[[files]] secret_name` behave like `--file-secret`? **[A9]**
- F2: where does the file land (the root filesystem, or RAM), with what mode and owner? Does `--rootfs-persist` (`tests/fixtures/fly/help/machine-run.stdout:104-107`) keep it? **[A9]**
- F3: are the bytes decoded exactly?
- F4: does `secrets deploy` rewrite the file?

Until these are answered, the shim stays (`ced358d:crates/jz_host/src/fleet_secrets.rs:90`, `ced358d:fly.toml:21-23`). It reads only platform-provided env.

### 7.4 Separate migration app (design only)

- Two targets per environment: `fly = { app = "journeeze-staging" }, roles = ["serve"]` and `fly = { app = "journeeze-migrate-staging" }, roles = ["migrate"]`, using the target `roles` of §4.4.
- No opv in either image.
- Shim retirement, every live step authorized by a person:
  1. the base64 staging;
  2. the launcher's `[[files]]`, with the shim still on;
  3. staging switches, and every serve name reads, **including `github/webhook-secret`**;
  4. a production canary, then all machines;
  5. remove the shim.

## 8. Docker Swarm target (0.12.0; moved from 0.11.0 by the owner, §15)

### 8.1 Recorded so far (read-only, no swarm)

- `docker secret create [OPTIONS] SECRET [file|-]` takes `--label` (`tests/fixtures/docker/swarm/help/secret-create.stdout:2`, `:8`).
- `docker config create [OPTIONS] CONFIG file|-` takes `--label` (`tests/fixtures/docker/swarm/help/config-create.stdout:2`, `:7`).
- `secret ls` takes `--filter` and `--format json` (`tests/fixtures/docker/swarm/help/secret-ls.stdout:10-16`); `secret rm` is at `tests/fixtures/docker/swarm/help/secret-rm.stdout:2`.
- `service update` takes `--secret-add` and `--secret-rm` (`tests/fixtures/docker/swarm/help/service-update.stdout:125-126`), `--config-add` and `--config-rm` (`:10-12`), `--env-add` and `--env-rm` (`:32-34`), `--detach` (`:20-21`), and the `--update-*` and `--rollback*` options (`:110-148`).
- `docker info --format '{{json .Swarm}}'` on a node outside a swarm prints `"LocalNodeState":"inactive","ControlAvailable":false` (`tests/fixtures/docker/swarm/01-info-swarm-inactive.stdout:1`).
- `secret ls` there fails with "This node is not a swarm manager", exit 1 (`tests/fixtures/docker/swarm/02-secret-ls-not-a-manager.stderr:1`). `service inspect` fails with a different wrapper (`tests/fixtures/docker/swarm/03-service-inspect-not-a-manager.stderr:1`).

### 8.2 Configuration and channels

```toml
[environments.prod.targets.swarm]
swarm.context     = "prod-manager"            # a docker context naming a manager (ssh:// or unix://)
swarm.service     = "journeeze_serve"
swarm.secret_name = "FLEET__{PRODUCT}__{KEY}"
swarm.secrets_dir = "/run/secrets/{product}"
swarm.files_owner = "10001:10001"             # optional; else a numeric user from the service
roles = ["serve"]
```

- **Channels:**
  - secret → versioned Swarm secrets (files; Swarm has no secret-to-env binding, so **every delivered secret needs `file`**, or the load fails);
  - config with `file` → versioned Swarm configs (files);
  - config without `file` → service env through `--env-add NAME=value`. That puts the config value in the docker CLI's argv on the CI runner and in `service inspect`, so a config key stored concealed is refused, as on GitHub (`docs/configuration.md:427`). Every other config key goes this way as declared, and its row shows `Swarm env` (§1.3);
  - files → `Native`.
- **Calls.** Every call carries `--context`, and `DOCKER_HOST`, `DOCKER_CONTEXT` and `DOCKER_CONFIG` are dropped from its environment. `ssh://` endpoints are normal here.
- **Paths.** `secrets_dir` must be under `/run/secrets` **[A13]**. Each key's Swarm `target` is the path relative to `/run/secrets`.

### 8.3 Store: versioned secrets and configs

| Operation | Call (values on stdin only) | Notes |
|---|---|---|
| list | `docker --context c secret ls --filter label=opv-managed=<env> --format json`; the same for `config ls` | names and labels; secret data is never returned **[A14]** |
| write | `docker --context c secret create --label opv-managed=<env> --label opv-key=<store> --label opv-version=… --label opv-written=… --label opv-env=… --label opv-plan=… opv-<store>-<id> -`; the same with `config create` | the Kubernetes name and id scheme (`src/adapters/kubernetes/mod.rs:262-281`); provenance as labels (`src/domain/provenance.rs:235-242`) |
| compare | secrets: the version ledger with keyed fingerprints, as on Fly (`docs/usage.md:240`); configs: `config inspect` returns the data **[A31]**, so the compare is exact | |
| delete | `secret rm` / `config rm` | refused by Swarm while in use **[A15]** |
| size | 500 KB **[A16]** | `Guard{ValueTooLarge}` |

### 8.4 Runtime

- **Read:** `service inspect <svc> --format '{{json .Spec}}'` and `'{{json .PreviousSpec}}'`. These hold names, targets and env, never secret data.
- **Bindings:** match entries by `File.Name` (secrets and configs) and by env name. An entry is `Pinned` when its name splits as `opv-<store>-<id>` and the owner and mode match.
- **Apply:** one `service update --detach=false` with `--secret-rm/--secret-add source=<new>,target=<rel>,uid=,gid=,mode=0400`, the `--config-*` equivalents, and `--env-add` **[A17]**.
  - **There is no compare-and-set through the CLI** **[A18]**. opv compares the Spec before and after, outside its own entries (the Kubernetes `changed_paths` idea, `src/adapters/kubernetes/runtime.rs:139-174`). A difference is `TargetRefused{ChangedOutsideOpv{after_apply: true}}` (`src/cause/mod.rs:1101-1104`), exit 5 `update_refused`, naming the changed Spec paths.
  - **Syncs for one target are serialized (FMECA FM-06).** The CI recipe already runs every sync in one concurrency group (`concurrency: {group: opv-sync}`, §2.5), and `opv ci workflow --on-change` keeps it. That leaves the window to actors outside opv, and the before/after comparison reports them. opv doesn't add a lock of its own: Swarm offers none to the CLI **[A18]**.
- **Owner:** `swarm.files_owner`, or else a numeric `ContainerSpec.User`. Anything else is `MountUnreadable{RunAsUnknown}`. Swarm sets the owner per file, so 0400 works **[A17]**.
- **Health:** poll `UpdateStatus` until `completed`. `paused` and `rollback_*` are unhealthy **[A19]**. Progress lines and the wait limit are as on Kubernetes (`src/adapters/kubernetes/runtime.rs:40-46`).

### 8.5 Rollout, scaling, clean-up

- The rollout follows the service's own `UpdateConfig`, which opv never changes.
- **Logs (FMECA FM-03).** A secret is never written to a workload's log. Unlike Kubernetes, a Swarm service declares its log driver (`TaskTemplate.LogDriver` in the Spec opv already reads **[A33]**). `plan` and `status` print one warn line when it is unset or writes to the node's disk (`json-file`, `local`, `journald`): `warn: service <svc> logs to <driver> on each node; a value it prints is kept on disk`. opv never changes it. The canary scan includes `docker service logs` (§12.3).
- New replicas get the current Spec.
- After a healthy update, opv deletes `opv-managed=<env>` secrets and configs that neither `Spec` nor `PreviousSpec` references, so `docker service rollback` keeps working. Swarm's own refusal to remove an object in use counts as "kept".

### 8.6 Permissions

Swarm has no RBAC: a client that reaches a manager's API controls the swarm. CI uses a dedicated context: `ssh://deploy@manager` with a CI-only key, or mutual TLS. `doctor` requires `ControlAvailable: true` (the recorded shape: `tests/fixtures/docker/swarm/01-info-swarm-inactive.stdout:1`). `deploy_credentials` doesn't apply, as on Kubernetes (`src/adapters/kubernetes/config.rs:223-233`).

### 8.7 Plan and status

These follow §6.7:
- `would write: journeeze/DATABASE_URL (FLEET__JOURNEEZE__DATABASE_URL → file /run/secrets/journeeze/database/url)`;
- `would deploy: service journeeze_serve (2 secrets, 1 config, 1 env repointed; files 10001:10001 0400)`;
- `chain: DATABASE_URL → Swarm secret opv-…-h6tn4wbr5e → file …`.

### 8.8 Causes

| Situation | Variant | Code | Exit | Retry | Do | Next |
|---|---|---|---|---|---|---|
| not a manager (recorded `02`, `03`) | `OwnerSetupRequired` new object `SwarmManager{context}` | owner_setup_required | 5 | after_fix | "point swarm.context at a manager node" | `opv doctor …` |
| daemon unreachable | `Unavailable{system: Docker (new), Network}` (text: `3b8e180:tests/fixtures/docker/failures/05-daemon-unreachable.stderr`, kept) | provider_unavailable | 9 | safe | "check the connection to <context>" | rerun |
| context missing | `NotFound{DockerContext, LocalContextMissing}` | resource_not_found | 5 | after_fix | "docker context create <c> --docker host=ssh://…" | `docker context ls` |
| service missing | `NotFound{Service, ConfigField{swarm.service}}` | resource_not_found | 5 | after_fix | "check swarm.service" | `docker --context c service ls` |
| lost create | reconcile by listing, else `CreateOutcomeUnknown{Check}` | create_outcome_unknown | 9 | check_first | — | `docker --context c secret ls --filter name=<n>` |
| update paused or rolled back | `TargetRefused{Unhealthy}` | target_unhealthy | 5 | after_fix | "the previous tasks keep serving; nothing pruned" | `docker --context c service ps <svc>` |
| Spec changed during the update | `TargetRefused{ChangedOutsideOpv{after_apply}}` | update_refused | 5 | check_first | — | `opv status <env>` |
| owner unknown | `MountUnreadable{RunAsUnknown}` | mount_unreadable | 6 | after_fix | "set swarm.files_owner, or a numeric user on the service" | `opv plan …` |
| a secret without `file`, a bad `secrets_dir`, or a concealed config bound to env | `ConfigInvalid` new `SwarmSecretWithoutFile{key}`, `Pattern{SwarmSecretsDir}`; the existing `concealed-config` refusal | config_invalid / findings | 2 / 8 | after_fix | as worded | `opv config edit` |
| too large | `Guard{ValueTooLarge}` | policy_refused | 6 | never | as today | as today |
| docker missing | `ToolMissing{docker}` | dependency_missing | 3 | after_fix | install line | rerun |

### 8.9 Recordings still needed (a single-node swarm; **`docker swarm init` needs the owner's approval first**, O13)

- **S-R1:** `swarm init`, and `swarm leave --force` at the end.
- **S-R2:** `secret create` (stdin), the same again (exists), and an oversize value **[A16]**; `config create` likewise.
- **S-R3:** `secret ls` and `config ls --format json`; `secret inspect` (no data **[A14]**); `config inspect` (data **[A31]**).
- **S-R4:** `service create --user 10001:10001 --secret source=…,target=journeeze/database/url,uid=10001,gid=10001,mode=0400 --config … --env …`, once with `--log-driver none`; `service inspect` (Spec) **[A13]**, **[A17]**, **[A33]**.
- **S-R5:** `service update --detach=false --secret-rm/--secret-add/--config-*/--env-add`; then `UpdateStatus`, `PreviousSpec` and `Version` **[A18]**, **[A19]**.
- **S-R6:** `docker exec` into a task: `stat -f -c %T`, `stat -c "%a %u %g"`, `id`.
- **S-R7:** `secret rm` while in use **[A15]**.
- **S-R8:** a failing update with `--update-failure-action pause` and with `rollback`.
- **S-R9:** `docker --context nonexistent info`.

Of `3b8e180`'s `tests/fixtures/docker/` set, this commit keeps only what the Swarm target reuses: `success/01-version`, `success/14-context-endpoint`, `failures/05-daemon-unreachable`, `failures/06-daemon-unreachable-run`. The rest stay citable at `3b8e180`.

### 8.10 Tests

- **Unit:** builders, Spec parsing over S-R4/S-R5, `PreviousSpec` references, owner rules.
- **Simulator:** `tests/sim/docker.rs` (new). It answers only from recordings, and anything else is exit 86. Register `docker` in `TOOLS` (`tests/sim/opv_sim.rs`) and in `SIMULATED` (`tests/e2e/matrix.rs:351`).
- **E2E:** `tests/e2e/scenarios/swarm.rs`.

## 9. Docker on VMs in any cloud (0.12.0: GCP first; AWS later)

### 9.1 Shape

```text
CI:   opv changed → opv sync prod        (service account → 1Password; CI's cloud identity → secret manager)
VM:   every boot → opv-vm-secrets (not opv; VM identity → secret manager → tmpfs, 0700/0400, container's uid)
            → docker run --user <uid> --mount type=bind,src=/run/opv-secrets/journeeze,dst=/run/secrets/journeeze,readonly
scale: the autoscaler boots VMs; each runs the same two steps
rotate: opv sync → the cloud's rolling restart or replace (vm.restart_hint)
```

### 9.2 The startup step: one script, three providers

`deploy/vm/opv-vm-secrets.sh` is POSIX `sh`. It is not opv, never touches 1Password, and contains no credential.

| | GCP | Azure | AWS |
|---|---|---|---|
| Identity | VM service account; token from `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` (`Metadata-Flavor: Google`) **[A20]** | managed identity via IMDS `http://169.254.169.254/metadata/identity/oauth2/token?resource=https://vault.azure.net` (`Metadata: true`) **[A20]** | instance role through the `aws` CLI chain **[A20]** |
| Secrets | `GET …/v1/projects/<p>/secrets/<id>/versions/latest:access` → `payload.data` (base64) **[A21]** | `GET https://<vault>.vault.azure.net/secrets/<name>?api-version=7.4` → `value` **[A21]** | `aws secretsmanager get-secret-value --secret-id <id> --query SecretBinary --output text` **[A21]** |
| Config | Secret Manager, the same call | Key Vault, the same call | `aws ssm get-parameter --name <n> --query Parameter.Value --output text` **[A27]** |
| Tools | `curl`, `jq`, `base64` | `curl`, `jq` | `aws`, `base64` |

The script:
1. **Arguments:** `--provider gcp|azure|aws --map <file> --dir <path> --owner <uid>:<gid>`, plus `--project`, `--vault` or `--region`.
2. **Directory:** `mount -t tmpfs -o size=1m,mode=0700,uid=<uid>,gid=<gid>,nosuid,nodev,noexec tmpfs <dir>`. It refuses a directory that is already mounted, and never writes to disk.
3. **Files:** the map has lines `<kind><TAB><id><TAB><dest>`.
   - `<dest>` is a relative path, checked with Journeeze's segment rule (`ced358d:crates/jz_secrets/src/lib.rs:23-34`), or `env:<NAME>` for a config key without `file`.
   - Each reply is fetched with `curl -fsS -o <file>.reply.tmp` and decoded into `<file>.tmp`, both created under `umask 377`. POSIX `sh` has no `pipefail`, so the script never judges a fetch by a pipeline's status (FMECA FM-01): a non-zero `curl` status, an empty body, or a failed decode exits non-zero **before** any `chown` or rename, and an `EXIT` trap removes every `.tmp` file. Only then `chown`, `chmod 0400` and rename into place. Parent directories are 0500.
   - `env:` lines go to `<dir>/.env` (0400), which the unit passes as `--env-file`. That file holds config only, which is readable through `docker inspect` once in the container's env; that is why config is declared non-secret (§1.3).
   - Values never appear in argv, the environment or a log.
4. **Failure:** any failure exits non-zero and names the id and the HTTP status (or `curl`'s exit code), never a value. A short or empty file is never installed. The container unit `Requires=` the step, so a VM never starts the app without its files.
5. **`--check`:** prints each path as present or absent, with its size.

**The map** is non-secret. CI renders it from `opv plan <env> --target <t> --json` (`target_name`, `channel`, `path`; §6.7).

**cloud-init** (`deploy/vm/cloud-init.yaml`, GCP):

```yaml
#cloud-config
write_files:
  - {path: /usr/local/sbin/opv-vm-secrets, permissions: "0755", content: "…the script…"}
  - path: /etc/opv-vm-secrets/journeeze.map
    content: |
      secret	fleet--journeeze--database-url	database/url
      secret	fleet--journeeze--github-app-private-key	github-app/private-key
      config	log-level	env:LOG_LEVEL
  - path: /etc/systemd/system/opv-vm-secrets.service
    content: |
      [Unit]
      Before=journeeze.service
      [Service]
      Type=oneshot
      RemainAfterExit=yes
      ExecStart=/usr/local/sbin/opv-vm-secrets --provider gcp --project my-proj --map /etc/opv-vm-secrets/journeeze.map --dir /run/opv-secrets/journeeze --owner 10001:10001
  - path: /etc/systemd/system/journeeze.service
    content: |
      [Unit]
      Requires=opv-vm-secrets.service docker.service
      After=opv-vm-secrets.service docker.service
      [Service]
      ExecStart=/usr/bin/docker run --rm --name journeeze --user 10001:10001 --log-driver none --env-file /run/opv-secrets/journeeze/.env --mount type=bind,src=/run/opv-secrets/journeeze,dst=/run/secrets/journeeze,readonly -e JZ_VAULT_DIR=/run/secrets/journeeze -p 18088:18088 journeeze@sha256:…
      ExecStop=/usr/bin/docker stop journeeze
runcmd: [[systemctl, daemon-reload], [systemctl, enable, --now, journeeze.service]]
```

- **systemd units run every boot**, while `runcmd` alone runs once per instance **[A22]**. tmpfs is empty after each reboot, so the step must run every boot.
- **Rejected:** a tiny binary. It is harder to audit on a VM and needs a build per architecture (O11).

### 9.3 Limits

The files are 0400, owned by the container's uid (§5's rule; `3b8e180:tests/fixtures/docker/failures/01-run-as-other-uid-denied.stderr`). VM root, the `docker` group and any process that can obtain the VM identity's token can read the values **[A20]**. That is the cloud's own model; it is documented.

### 9.4 The `vm` target and the GCP Secret Manager store

```toml
[stores.gcp-prod]
gcp_secret_manager = { project = "my-proj" }

[environments.prod.targets.vms]
vm.store        = "gcp-prod"
vm.secret_name  = "FLEET__{PRODUCT}__{KEY}"
vm.secrets_dir  = "/run/opv-secrets/{product}"
vm.restart_hint = "gcloud compute instance-groups managed rolling-action restart journeeze-mig --region us-central1"
roles = ["serve"]
```

**Store.** `gcp_secret_manager` is a new `StoreConfig` next to Key Vault (`src/adapters/azure/store.rs:159`; the binding table, `src/adapters/kubernetes/config.rs:109-113`). It implements `PinnedStore` (`src/ports.rs:66-93`):

| Operation | Call (values on stdin) |
|---|---|
| list | `gcloud secrets list --project p --filter='labels.opv-managed=<env>' --format=json(name,labels,annotations)` |
| read (exact compare, as Key Vault does: `docs/usage.md:240`) | `gcloud secrets versions access latest --secret <id> --out-file=-` **[A23]** |
| create | `gcloud secrets create <id> --replication-policy=automatic --labels=opv-managed=<env>,opv-key=<store>,opv-kind=<secret\|config> --data-file=-` |
| write | `gcloud secrets versions add <id> --data-file=-` |
| provenance | `gcloud secrets update <id> --update-annotations=opv-version=…,opv-written=…,opv-env=…,opv-plan=…` **[A24]** |
| superseded | disable versions older than the previous one; never destroy (O12) |
| prune | `gcloud secrets delete <id> --quiet`, only with `opv-managed=<env>` |

- **Names:** ids are `store_name` (`src/adapters/kubernetes/mod.rs:256-259`) **[A25]**. Values are bytes, so they stay verbatim.
- **Channels:** secret and config → `Store{"Secret Manager"}`; files → `Native` (written by the VM step).
- **Runtime.** `LatestRuntime` implements `PinnedRuntime` (`src/ports.rs:105-130`):
  - `bindings` pin each name to the latest enabled version;
  - `apply` is a no-op;
  - `await_healthy` is `Healthy`;
  - `sync --deploy` prints `Next: <restart_hint>` as a typed `Vendor` step. opv never restarts VMs.
- **Permissions:**
  - CI identity: `roles/secretmanager.admin`, or `secrets.create/get/list/update/delete` and `versions.add/access/list/enable/disable` **[A26]**;
  - VM identity: `roles/secretmanager.secretAccessor` on each managed secret;
  - `doctor` checks the CI side, and warns with the exact grant command for the VM side (as Azure does, `docs/usage.md:268`).
- **Output:** `chain: DATABASE_URL → GCP Secret Manager my-proj/fleet--journeeze--database-url (v7) → VM file /run/opv-secrets/journeeze/database/url`. The summary says `deployed no (VMs read it at their next start: <restart_hint>)`.

### 9.5 AWS (design only)

- **Secrets:** `aws secretsmanager create-secret --secret-binary fileb:///dev/stdin --tags …` and `put-secret-value` **[A27]**. `AWSCURRENT` and `AWSPREVIOUS` stay, so superseded handling is a no-op.
- **Config:** SSM `put-parameter --type String` **[A27]**.
- **Rights:** the CI role needs `secretsmanager:*Secret*`, `ssm:PutParameter/GetParameter`; the instance role needs `GetSecretValue` and `ssm:GetParameter` on the managed ARNs.

### 9.6 Causes (GCP)

| Situation | Variant | Code | Exit | Retry | Do | Next |
|---|---|---|---|---|---|---|
| not signed in | `NotSignedIn{Gcp}` (new system) | target_not_signed_in | 7 | after_fix | "gcloud auth login; in CI, the job's workload identity" | rerun |
| 403 | `MissingRight{GcpIam{role, resource}}` (new grant model) | permission_denied | 5 | after_fix | "ask an owner to grant <role> on <resource> to <principal>" | `opv doctor …` |
| API disabled | `OwnerSetupRequired{CloudApi{secretmanager.googleapis.com}}` | owner_setup_required | 5 | after_fix | "gcloud services enable secretmanager.googleapis.com --project p" | `opv doctor …` |
| project or secret missing | `NotFound` | resource_not_found | 5 | after_fix | "check the store's project" | `gcloud secrets list --project p` |
| network, 429, 5xx | `Unavailable{Gcp, …}` | provider_unavailable | 9 | safe | — | rerun |
| lost `versions add` | `WriteOutcomeUnknown` (reconciled by listing versions) | outcome_unknown | 9 | safe | — | rerun |
| gcloud missing | `ToolMissing{gcloud}` | dependency_missing | 3 | after_fix | install line | rerun |
| the VM identity lacks access | an `AccessFinding` warning (`src/domain/runtime.rs:80-86`) | — | — | — | the grant command | — |
| a secret key without `file` | `ConfigInvalid` new `VmSecretWithoutFile{key}` | config_invalid | 2 | after_fix | as worded | `opv config edit` |

The script's own failures are not opv causes. It prints a fixed text per case to journald, with no value and no token.

### 9.7 Rotation

1. `opv sync` writes a new version.
2. The person or CI runs `restart_hint`: a rolling restart or replace of the managed instance group, the scale set or the Auto Scaling group.
3. Each VM fetches the latest version at boot.
4. The next sync disables versions older than the previous one.

By hand, `systemctl restart opv-vm-secrets journeeze` refreshes one VM.

### 9.8 Recordings (a throwaway GCP project, run by the owner; O14)

- **G-R1:** `gcloud version`; `auth list --format=json`, with and without an account.
- **G-R2:** `secrets create --data-file=-`, and the same again.
- **G-R3:** `versions add`, `versions list`, `versions access latest --out-file=-` (marker), `versions disable` **[A23]**.
- **G-R4:** `secrets list --filter=labels…`; `secrets update --update-annotations` **[A24]**.
- **G-R5:** `secrets delete --quiet`; access to a missing secret.
- **G-R6:** without rights; with the API disabled; with an unknown project.
- **G-R7:** `HTTPS_PROXY=http://127.0.0.1:9 gcloud secrets list`.
- **G-R8:** on a GCE VM: the metadata token reply, the REST `:access` reply (marker), and the script's `--check` **[A20]**, **[A21]**.

### 9.9 Tests

- `tests/sim/gcloud.rs` answers from G-R1 to G-R7 only, plus E2E scenarios.
- `tests/vm_step.rs` runs the script with a fake `curl` answering from G-R8. It checks the modes, the owner, that no value reaches argv or the environment (`/proc/<pid>/cmdline` and `environ` snapshots), and the traversal refusal. It also checks the failure path (FMECA FM-01): a fake `curl` that answers 403, one that exits 18 after a partial body, an empty body and an undecodable body each exit non-zero naming the id, and leave no file and no `.tmp` behind. Root-only parts are skipped and the test says so.

## 10. Scaling and rotation on every platform

| Platform | Secrets | Config | A new replica gets them by | Rotation | Old versions | 1Password at runtime |
|---|---|---|---|---|---|---|
| Local `opv run` | env or tmpfs files | env | each run reads anew | stop and rerun | none | the developer's own session |
| Local Compose | the run's tmpfs dir, bind-mounted | env | `--scale` shares the run's dir | rerun under `opv run` | none | the developer's own session |
| Kubernetes | immutable Secret per version, projected volume or env | immutable ConfigMap per version | pods mount the template's objects | `opv sync --deploy` → template change → rolling update → health wait | kept while any ReplicaSet references them (`src/adapters/kubernetes/store.rs:257-271`) | none |
| Swarm | Swarm secret per version (files) | Swarm config per version, or service env | tasks get the current Spec | `opv sync --deploy` → `service update` per `UpdateConfig` → `UpdateStatus` | kept while `Spec` or `PreviousSpec` references them | none |
| VMs (GCP; AWS and Azure later) | secret manager, latest | secret manager (GCP), SSM (AWS) | each boot runs the startup step | `opv sync` → `restart_hint` (rolling) | GCP: current and previous enabled; AWS and Key Vault keep history | none |
| Fly | Fly secrets (env at boot; the shim writes files) | Fly secrets (new) | each machine boots with the app's secrets | `opv sync --deploy` → `secrets deploy` restarts machines | n/a | none |
| Azure Container Apps | Key Vault, by reference | app env or the store | new replicas of the revision | `opv sync --deploy` → new revision | Key Vault history | none |
| GitHub Actions | secrets | variables | each workflow run reads them | `opv sync` (live at once) | n/a | none |

## 11. Implementation plan

Each deliverable has at most four owned files, exact pointers and named tests. Hours assume reading the pointers first.

### 11.1 opv 0.11.0

Docker Swarm moved to 0.12.0 (owner, §15), so S1–S5 and the Swarm causes are in §11.2. R1 (the remote-profile refusal, §15) is new here; it is a deliverable id, not risk R1 of §14. Changes from the FMECA review are marked with their FM number (§14.1).

| ID | Deliverable | owned_files | Prereq. | h | Acceptance criteria |
|---|---|---|---|---|---|
| M1 | `Channels` contract | `src/provider.rs` (`channels()` required, next to `open` `:366-373`; `Channels`, `Channel`, `FileCapability`; the contract test), `src/ports.rs` (`variables` loses its default, `:44-49`), the four `config.rs` adapters (Fly `:231`, Azure `:452`, GitHub `:304`, Kubernetes `:392`: declare today's channels only) | — | 4 | Every provider declares channels; a provider without them doesn't compile. Today's behaviour is unchanged (all existing tests pass). The contract test lists each provider's table and matches §1.1's "today" column. |
| M2 | Route by channel, and `NoChannel` | `src/domain/plan.rs` (config branch `:420-428`), `src/app/mod.rs` (`json_target` `:904-913`, `JsonRow` `:735-760`: `channel`, `via`, `delivered_as`, `form`), `src/cause/mod.rs` (`Guard::NoChannel`), `src/cause/render.rs` | M1 | 4 | A config key on a `Channel::None` target: `plan` and `status` print the warn line, `sync` refuses with `policy_refused`, and `config = "none"` gives a warn only. No row says plain `n/a` for config. **FM-02:** every config row, text and `--json`, names its channel (`env`, `ConfigMap`, `Fly secret`, `GitHub variable`, …); a concealed config field is still refused on GitHub variables and still warned elsewhere (snapshots of both). |
| M3 | Target `roles` | `src/domain/model.rs` (`:226-244`), `src/config.rs` (`:724-742`, `:1704-1722`), `src/domain/plan.rs` (`:296-321`), `docs/design/local-delivery.md` (`:79`) | — | 4 | Disjoint roles mean not desired, and prune would remove the binding. Load refusals: missing, undeclared, empty. Targets without role keys are unchanged. |
| M4 | Verbatim bytes, `FileMount`, plumbing, plan id | `src/domain/convention.rs` (`:263-303`), `src/domain/runtime.rs` (`FileMount`), `src/app/mod.rs` (`open_target` `:1696-1704`, `file_mounts` next to `:1708-1721`, plan id `:200-230`); `src/domain/plan.rs` `evaluate` is shared, so M4 follows M2 and M3 | M2, M3 | 6 | A multi-line PEM with a trailing newline in a file key passes `check` without a target and stages verbatim to a `Native` target. The tidy keeps `x\n` in a file key and still trims a non-file key. Fly keeps `single_line` and `pem_private_key`. The plan id differs by channel and form. **FM-07:** the same file key shows `file (verbatim)` on a `Native` target and `env (pem_private_key)` on Fly in one plan; without a declared transform, Fly reports the `single_line` finding instead of changing the value. |
| M5 | No-value test over every machine-readable surface (§1.6) | `tests/security.rs`, `tests/mcp_protocol.py`, `src/app/agent_view.rs` (the plan projection carries `channel`, `via`, `delivered_as`, `form`, `path` through `identifier`) | M2, M4, C1 | 3 | **FM-04:** the `S7MARKER` scan passes over `changed --json`, `plan`/`status --json` with file, ConfigMap and Fly-config rows, and the MCP tools `opv_deployment_plan` and `opv_delivery_preview`; the MCP plan document equals the CLI's byte for byte. |
| C1 | `opv changed` | `src/app/changed.rs` (new: versions via `op item list` per vault, the field via `op read`, states, exit 10), `src/main.rs` (subcommand next to `Delivery` `:760`), `src/cause/mod.rs` (`SourceChanged`, exit 10, `source_changed`), `docs/usage.md` (commands table `:16-18`, exit codes `:887-896`) | — | 6 | FakeRunner: unchanged → 0; a version bump → 10 naming the item; a missing field or delivery item → 10 `no_record`; an `op` failure → its own exit, never 0. No `op item get` and no value-bearing call appears in the recorded calls. JSON matches §2.2. **FM-12:** one `op item list` per vault per run however many items it watches; a rate-limit reply → exit 9 `Unavailable{RateLimited}` with the retry time when given **[A32]**. |
| C2 | Record source versions on sync | `src/app/delivery.rs` (`record`, near the evidence lines `:5-13`; the new field `source versions`), `src/app/sync.rs` (pass the item versions read, `read_item_fields` `src/app/mod.rs:186-193`), `docs/design/delivery-receipts.md` | C1 | 3 | After a confirmed sync the delivery item holds one `v1|<item_id>|<version>` line per source item. An unconfirmed sync records nothing. **FM-05:** `opv changed` then reports `unchanged`, also when the delivery item and the `deploy_credentials` item share the state vault with a source's vault listing. |
| C3 | `status --fail-on-drift` | `src/app/status.rs` (drift `:634-661`, exit), `src/main.rs` (flag), `src/cause/mod.rs` (`TargetDrift`, `target_drift`) | — | 2 | With drift and the flag, exit 8 `target_drift`; without the flag the exit code is unchanged (snapshot). |
| C4 | e2e coverage for C1–C3 | `tests/e2e/scenarios/changed.rs` (new), `tests/e2e/app/world.json` (item versions), `tests/e2e/coverage.rs` | C1–C3 | 4 | Snapshots for each `changed` state, the drift exit, and the canary scan. |
| C5 | `opv ci workflow --on-change` | `src/app/ci_workflow.rs` (`run` `:24-40`, `Job`), `src/main.rs` (flags at `CiCmd::Workflow` `:3550`) | C1, C3 | 4 | Prints the two §2.5 workflows for the configuration, with `confirm_env` environments planned and gated. It is a golden test, and `actionlint` passes on the output. **FM-11:** the detect step branches 0 / 10 / other. **FM-12:** `--every <minutes>` sets the cron (default 15); exit 9 with a retry time retries `changed` once, capped at 120 s. **FM-06:** every sync job is in one concurrency group. |
| C6 | CI example and README section | `examples/ci-change-detection/` (README, both workflows, `install-opv` action), `README.md` (the §3 text), `docs/usage.md` (a "When sync runs" section) | C1, C3 | 3 | The examples equal C5's output for the example configuration, and `actionlint` passes. The README section reads as in §3 and its links resolve. **FM-11:** the example README and `docs/usage.md` show the exit-10 branch and say why "any non-zero is a failure" is wrong for `changed`. |
| A3 | Webhook secret in Journeeze's mapping | the Journeeze opv manifest (a person's edit), `docs/local-development.md` (example) | — | 1 | `opv run dev --product journeeze --role serve --preview --json` lists `github/webhook-secret`; `tests/mounted_consumer.rs:16-24` passes. **FM-15:** the Journeeze-side `SERVE` edit (`ced358d:crates/jz_host/src/fleet_secrets.rs:40-76`) is filed with its maintainers as an external dependency, and nothing in opv's docs claims Fly delivery of the webhook secret until it lands (§4.6). |
| A4 | `OPV_UID`/`OPV_GID` and the compose docs | `src/app/local_delivery.rs` (`child_env` `:174-191`), `src/app/delivery_preview.rs` (the `containers:` line), `docs/local-development.md` (after `:87`), `tests/fixtures/compose/README.md` | O4 | 3 | A file-delivering run's child has both ids; a run without files has neither. The preview prints the line. The docs' compose file equals `tests/fixtures/compose/recipe.yml`. **FM-14:** the docs state the same-user limit as the accepted residual (§5). |
| F1 | Config on Fly | `src/adapters/fly/config.rs` (`fly.config` near `:45-99`; `channels`), `src/adapters/fly/store.rs` (or the staged store: config through `variables` → secrets), `docs/configuration.md` (`:347-352`) | M2 | 4 | `fly.config = "secrets"` stages config keys like secrets (FakeRunner, stdin only). Unset warns. `none` warns per run. The ledger covers config names. **FM-02:** config rows show `Fly secret`; a concealed config field gets today's warning. |
| K1 | kubectl recordings K-R1–K-R7 | `tests/fixtures/kubernetes/success/`, `…/failures/`, READMEs | kind | 4 | Recorded as in `tests/fixtures/kubernetes/success/README.md:3-5`. **[A2]**, **[A3]**, **[A5]**, **[A7]** confirmed or refuted in the README, and §6 amended where refuted. The cluster is deleted. |
| K2 | `secrets_dir` and `config = "configmap"` config | `src/adapters/kubernetes/config.rs` (`ConfigRoute` `:85-93`, `Raw` `:119-130`, `checked` `:140-172`, `KubernetesTarget` `:96-107`, `INIT_FIELDS` `:49-80`, `channels`) | M1, M4 | 3 | The §6.2 load rules each have a unit test naming the field. `opv init` writes `configmap`. (No recording gate: nothing here depends on K-R1–K-R7.) |
| K3 | ConfigMap store | `src/adapters/kubernetes/store.rs` (kind parameter: Secret or ConfigMap, same name scheme; `referenced_names` `:257-284` already kind-agnostic), `src/adapters/kubernetes/runtime.rs` (`ACCESS` `:62-118` and `DEPLOY_RIGHTS` `:133-137` gain configmaps), `store_tests.rs` | K1, K2 | 4 | A ConfigMap write sends the value on stdin only, compares exactly, and cleans up superseded versions like Secrets. The configmaps rights appear in `doctor` and preflight. **FM-09:** `doctor` names them as rights of a namespaced Role. **FM-10:** merges only after the K1 gate of §6.9. |
| K4 | Pure volume functions | `src/adapters/kubernetes/files.rs` (new), `files_tests.rs` (new), `src/adapters/kubernetes/mod.rs` (`:25-29`) | K1, K2 | 5 | Golden JSON = §6.3. `read_bindings` handles each `Other` case on the K-R3 shape. `readability` = §6.6. `mount_conflict`. A no-value property test. **FM-13:** `readability` returns readable-as-root as its own verdict. **FM-10:** merges only after the K1 gate. |
| K5 | Wire into `KubeDeployment` and the preflight | `src/adapters/kubernetes/runtime.rs` (`new` `:213-232`, `bindings` `:658-694`, `apply` `:697-772`, `fingerprint` `:293-304`, reconcile `:788-797`, `chain` `:876-885`), `src/adapters/kubernetes/config.rs` (`preflight` `:435`) | K3, K4, X1 | 6 | FakeRunner on `deployment-get.json`: the volume is added, the env entry removed, `configMapKeyRef` used for config, `K7` kept. The bindings read back. Mutate refuses unreadable with no `apply` call; Read warns. Existing tests pass. **FM-08:** the mount is added to the target's container only; a second container gets none. **FM-13:** a root workload syncs and prints the root warn line. **FM-10:** merges only after the K1 gate. |
| K6 | Kubernetes output, docs, E2E | `src/app/sync.rs` (`would …` near `:2011`), `tests/e2e/scenarios/k8s_files.rs` (new) with `tests/e2e/app/`, `docs/usage.md` (`:232-267`), `docs/configuration.md` (`:398`, `:461`) | K5, M2 | 7 | The §6.7 lines appear. The §6.10 snapshots are reviewed. The canary scan is clean. **FM-10:** K-R2 and K-R4 are reached, not exempt. **FM-03:** `docs/usage.md` states the no-log contract. **FM-08/FM-09:** `docs/configuration.md` says the volume mounts into the target's container only, recommends an `fsGroup` used by that container alone, and grants the configmap rights by a namespaced Role. |
| X1 | Shared new causes (Kubernetes) | `src/cause/mod.rs` (`MountUnreadable`, `Guard::MountPathInUse`, `ConfigCheck::ConfigFileNeedsObject`, `PatternId::ContainerPath`), `src/cause/render.rs`, `src/adapters/kubernetes/diagnose.rs` (the 422 phrase), `docs/design/error-catalog.md` (§4.4–§4.12) | K1 | 4 | Every §6.8 row is tested for code, exit, retry, text and JSON. K-R2 diagnoses as `update_refused`. |
| R1 | Remote profiles refuse deployed environments (O9, §15) | `src/config.rs` (`validate_remotes` `:1452`), `src/cause/config_check.rs` (new `ConfigCheck::RemoteEnvironmentHasTarget{profile, env, target}`), `docs/configuration.md` (`:174`), `tests/e2e/app/secrets.toml` (`:120-128`) | — | 3 | Load refuses a `[products.<p>.remotes.<r>]` profile whose `environments` include one with any target (Fly, Kubernetes, Azure, GitHub, Swarm, VM): `config_invalid`, exit 2, naming the profile, the environment and one target. A profile over target-less environments loads unchanged. The e2e profile moves to a target-less environment (R12 in §14 closes). |
| V1 | Tagged-release verification | `docs/verification/v0.11.0-file-delivery.md` + directory | the tag | 6 | §12.1 passes, or its deviations are recorded. **FM-03:** V16 includes pod and node logs. **FM-08:** V9 includes the sidecar check. |

**0.11.0 sequencing**
- Critical path: M1 → M2 → M4 → K2 → K4 → K5 → K6 (35 h), with M3, K1 → X1 and K3 alongside; then V1 on the tag.
- Change detection (C1 → C2 → C4; C3, C5, C6) is independent (22 h). M5 follows C1 and M4 (3 h).
- F1 follows M2 (4 h). R1, A3 and A4 have no prerequisite in this table.
- **Total 93 h.** Before this revision the rows summed to 110 h (the text said about 113 h). Swarm S1–S5 (26 h) and X1's Swarm causes (1 h) moved to 0.12.0; R1 adds 3 h; the FMECA changes add 7 h (M4 +1, M5 3, C1 +1, C5 +1, K6 +1).

### 11.2 opv 0.12.0 (Swarm, and GCP first)

| ID | Deliverable | owned_files | Prereq. | h | Acceptance criteria |
|---|---|---|---|---|---|
| S1 | Swarm recordings S-R1–S-R9 (**after O13**) | `tests/fixtures/docker/swarm/` | O13 | 3 | Recorded with markers; **[A12]**–**[A19]**, **[A31]** and **[A33]** confirmed or refuted in the README, and §8 amended where refuted; the swarm is left. |
| S2 | Swarm config and wrapper | `src/adapters/swarm/config.rs` (new; pattern `src/adapters/kubernetes/config.rs:30-280`), `src/adapters/swarm/mod.rs` (new: names, the `docker --context` wrapper with a scoped env as in `src/adapters/kubernetes/mod.rs:384-410`), `src/adapters/mod.rs`, `src/provider.rs` (registry) | M1, M4 | 5 | §8.2 parses. Load refusals are tested. `DOCKER_HOST`, `DOCKER_CONTEXT` and `DOCKER_CONFIG` never reach a call. **FM-02:** config rows show `Swarm config` or `Swarm env`. (No recording gate: nothing here depends on S-R1–S-R9.) |
| S3 | Swarm store (secrets and configs) | `src/adapters/swarm/store.rs` (new), `store_tests.rs` | S1, S2 | 5 | Tests over S-R2, S-R3, S-R7. Values go on stdin only. Clean-up keeps `PreviousSpec` references. **FM-10:** merges only after S1's README marks the assumptions it uses confirmed, or §8 is amended. |
| S4 | Swarm runtime | `src/adapters/swarm/runtime.rs` (new), `runtime_tests.rs` | S1, S3, X2 | 7 | Over S-R4, S-R5, S-R8: the argv, health states, `ChangedOutsideOpv`, the owner rules, `--env-add` for config only. **FM-06:** a Spec change outside opv's entries after the update is exit 5 `update_refused` naming the paths. **FM-03:** the log-driver warn line for an unset or on-disk driver; none for `none`. **FM-10:** merges only after the S1 gate. |
| S5 | Swarm diagnosis, simulator, E2E | `src/adapters/swarm/diagnose.rs` (new), `tests/sim/docker.rs` (new) + `tests/sim/opv_sim.rs` `TOOLS`, `tests/e2e/scenarios/swarm.rs` (new), `tests/e2e/matrix.rs` (`:110-125`, `:351`) | S4, X2 | 7 | The recorded not-a-manager and unreachable replies diagnose as in §8.8. E2E plan, sync, status and canary pass. An unrecorded call is exit 86. |
| X2 | Swarm causes (moved out of X1) | `src/cause/mod.rs` (`ConfigCheck::SwarmSecretWithoutFile`, `PatternId::SwarmSecretsDir`, `System::Docker`, object `SwarmManager`), `src/cause/render.rs`, `docs/design/error-catalog.md` | S1 | 2 | Every §8.8 row is tested for code, exit, retry, text and JSON. |
| S6 | Swarm verification | `docs/verification/v0.12.0-swarm.md` + directory | the tag, O13 | 3 | §12.3 passes, or its deviations are recorded. |
| G1 | gcloud recordings G-R1–G-R8 | `tests/fixtures/gcloud/` | O14 | 4 | Recorded with markers; **[A20]**–**[A26]** confirmed or refuted; the project is deleted. |
| G2 | GCP store config and names | `src/adapters/gcp/config.rs` (new; beside `src/adapters/azure/store.rs:159`), `src/adapters/gcp/mod.rs` (the `gcloud` wrapper), `src/host.rs` (`Tool` gcloud near `:381`) | M1 | 4 | `[stores.x] gcp_secret_manager` parses; name rules are tested; doctor lists gcloud. |
| G3 | GCP store operations | `src/adapters/gcp/store.rs` (new), `store_tests.rs` | G1, G2 | 6 | Over G-R2 to G-R5. Stdin only. Versions older than the previous one are disabled. `opv-kind` labels are set. |
| G4 | GCP diagnosis and causes | `src/adapters/gcp/diagnose.rs` (new), `src/cause/mod.rs` (`System::Gcp`, `GrantModel::GcpIam`, `CloudApi`), `src/cause/render.rs`, `docs/design/error-catalog.md` | G1 | 4 | Every §9.6 row is tested from G-R6 and G-R7. |
| G5 | `vm` target and `LatestRuntime` | `src/adapters/vm/config.rs` (new), `src/adapters/vm/runtime.rs` (new), `src/adapters/mod.rs`, `src/provider.rs` | G3 | 5 | `--deploy` prints `Next: <restart_hint>`. The channels are declared. A secret without `file` is refused. The `chain:` lines appear. **FM-02:** config rows show `Secret Manager`, delivered as `env` or `file`. |
| G6 | VM startup script and cloud-init | `deploy/vm/opv-vm-secrets.sh`, `deploy/vm/cloud-init.yaml`, `deploy/vm/README.md`, `tests/vm_step.rs` | G1 | 7 | The GCP branch writes tmpfs files (dir 0700, files 0400, `--owner`) and `.env`. No value appears in argv or env snapshots. Traversal is refused. Failure exits non-zero naming the id. `--check` prints presence and size only. The Azure and AWS branches are marked "unverified". **FM-01:** the fetch uses `curl -fsS`; a 403, a partial body (curl exit 18), an empty body and an undecodable body each exit non-zero before any `chown` or rename, and leave no file and no `.tmp`; no fetch is judged by a pipeline's status. |
| G7 | GCP simulator and E2E | `tests/sim/gcloud.rs`, `tests/sim/opv_sim.rs`, `tests/e2e/scenarios/gcp_vm.rs`, `tests/e2e/matrix.rs` | G4, G5 | 6 | Plan, sync, status, 403, API disabled and canary pass from recordings. |
| G8 | GCP verification | `docs/verification/v0.12.0-gcp-vm.md` + directory | the tag | 6 | §12.2 passes, or its deviations are recorded, including step 8 (**FM-01**: a blocked metadata server leaves the app stopped). |

**0.12.0 sequencing**
- Swarm (waits for O13): S2 → S3 → S4 → S5 (24 h; S1 and X2 alongside), then S6 on the tag. Swarm total 32 h.
- GCP (waits for O14): G1 → G3 → G5 → G7 (21 h), then G8 on the tag. GCP total 42 h.
- The two tracks share nothing but M1 and M4, which ship in 0.11.0; either can slip without the other.
- **Total 74 h** (was 40 h): Swarm S1–S5 (26 h) and X2 (2 h) moved in; the FMECA changes add 6 h (S4 +1, S6 3, G6 +1, G8 +1).

**Later:** AWS (the G2–G4 pattern, plus G6's branch verified), Fly files after F1–F4, and the Events API trigger (O16).

## 12. Verification against the tagged releases

### 12.1 0.11.0

**What it proves.**
- The release artifact syncs the way CI runs it: a 1Password service account, `CI=true`, no person's session.
- Workloads then read their files with **no 1Password access**: no `op`, no opv and no token in the image, pod or task, and the service account is revoked before the final restart.
- `opv changed` triggers on an edit.
- The drift check fails on drift.
- The local Compose run works.

Evidence goes in `docs/verification/v0.11.0-file-delivery.md` and its directory. The markers are those of `tests/mounted_consumer.rs:13-52`, plus a config marker.

**Prerequisites:**
- kind and kubectl, with kind in `~/.local/bin` and a throwaway cluster (the owner allowed this); versions as in `tests/fixtures/kubernetes/failures/README.md:9-12`;
- `gh`, `jq`, `script`, and a `journeeze-saas` worktree at `ced358d`;
- a test vault with `journeeze`, environments `verify` and `verify-nofsgroup`, the eleven §4.6 keys plus `LOG_LEVEL` (config), and a state vault;
- two service accounts, reader and deployer, created by the person and exported only in the CI-like shell.

**Kit:**
- `opv-verify-136`, about 80 lines against `jz_secrets` at `ced358d`: `check serve|migrate` prints `<name>: match|differ|absent` by SHA-256, refuses `../etc/passwd` (`ced358d:crates/jz_secrets/src/lib.rs:32`), compares `LOG_LEVEL`, and reports any marker in the environment. `loop` repeats it.
- A Dockerfile: pinned debian-slim, `USER 10001`, nothing else.
- `k8s/`:
  - namespace;
  - ServiceAccount `opv-ci` with a namespaced Role (no ClusterRole) of exactly `ACCESS` plus configmaps (§6.5), and its own context;
  - `jzverify` with `automountServiceAccountToken: false`, `fsGroup: 10001`, and a second `sidecar` container (the same image, `sleep`);
  - `jzverify-nofsgroup` with `runAsUser: 10001`.
- `compose.yml` (the §5 recipe).

**Steps.** Everything runs inside `script -q E/transcript.txt`.

| # | Action | Pass |
|---|---|---|
| V1 | `gh release download v0.11.0`, `sha256sum -c`, `gh attestation verify`, `--version` (`.github/workflows/release.yml:91-124`, `:153`, `:159`) | verified; `0.11.0` |
| V2 | `kind create cluster --name opv-verify-136`; build and `kind load docker-image`; `kubectl apply -f k8s/` | the Deployments exist |
| V3 | CI-like shell (`env -i … CI=true OP_SERVICE_ACCOUNT_TOKEN=<reader>`): `opv changed verify --json` before any sync | exit 10, `no_record` |
| V4 | `opv doctor`, then `opv plan verify --json` | checks OK; 9 serve rows `file`; `LOG_LEVEL` `channel: config` (ConfigMap); migrate keys not desired |
| V5 | with the deployer token: `opv sync verify --deploy --expect-plan <id>` | exit 0, healthy |
| V6 | `opv changed verify` | exit 0 `unchanged` |
| V7 | `kubectl get deployment -o json \| jq`; `kubectl get secret,configmap -l opv-managed=verify -o name` | the §6.3 shape; no file-key env; no migrate object |
| V8 | `kubectl logs deploy/jzverify` | 9 `match` (PEM, `db-url\n`); `LOG_LEVEL` matches; migrate absent; traversal refused; no marker in env |
| V9 | `kubectl exec … stat -f -c %T; stat -L -c "%a %u %g" …; id; command -v op opv \|\| echo none; ls /var/run/secrets/kubernetes.io`; then `kubectl exec -c sidecar … ls /run/secrets/journeeze` | `tmpfs`; `440 0 10001`; `none`; no token; the sidecar has no such path (§6.3) |
| V10 | the person edits the webhook marker; `opv changed verify` (exit 10, naming the item); `opv sync verify --deploy`; logs | the new Secret version; healthy; `match`; the old version kept for the old ReplicaSet; `changed` is then 0 |
| V11 | drift: `kubectl set env deployment/jzverify LOG_LEVEL=tampered`; `opv status verify --fail-on-drift`; `opv delivery verify verify --json`; then `opv sync verify --deploy` | exit 8 `target_drift`; exit 8 `delivery_unverified`; the sync restores it |
| V12 | `opv sync verify-nofsgroup --deploy` | `mount_unreadable`, exit 6, nothing written |
| V13 | (Swarm moved to 0.12.0: §12.3) | — |
| V14 | **no 1Password at runtime:** revoke both service accounts; `kubectl rollout restart`; then logs | all `match` |
| V15 | local: `opv run dev … -- docker compose run --rm serve`; `docker compose config` outside opv | the verdicts; exit 15 outside |
| V16 | canary scan over the transcript, Deployments, ReplicaSets, events, `kubectl logs` of every pod and the kind node's `/var/log/pods` (`docker exec <node> grep -r`), for the markers and their base64 forms | zero hits outside the stores' own data |
| V17 | `kind delete cluster` | gone |

### 12.2 0.12.0: GCP VMs

1. In a throwaway project, CI-like: `opv changed` (exit 10), then `opv sync`, then render the map from `plan --json`.
2. Create an instance template with the §9.2 cloud-init and a VM service account with `secretAccessor` only; a managed instance group of size 2.
3. Check on each VM: `journalctl -u opv-vm-secrets` (no value), `--check`, the kit's verdicts, `findmnt` (`tmpfs`), `stat` (`400 10001 10001`), and `command -v op opv` (none).
4. Rotate: edit a marker, `opv changed` (10), `opv sync`, `restart_hint`, and the new digest matches.
5. Scale to 3: the new VM matches.
6. Revoke the service accounts, recreate a VM: it still matches.
7. Run the canary scan over the transcript, the serial console, the instance logs and `journalctl -u opv-vm-secrets`.
8. On one VM, block the metadata server (`iptables`) and restart the step: it exits non-zero naming the id, `--check` shows the path absent, and `journeeze.service` doesn't start (FMECA FM-01).
9. Delete the project.

### 12.3 0.12.0: Docker Swarm

On a single-node swarm (O13), with an environment `verify-swarm` in the test vault and the kit's `swarm/` directory:
1. V3–V10 of §12.1 against `verify-swarm`.
2. `docker exec` into a task: `stat -f -c %T`, `stat -c "%a %u %g"`, `id`: files `400 10001 10001` on tmpfs.
3. `plan` warns about the service's log driver unless the kit sets `--log-driver none` (§8.5).
4. Revoke the service accounts; `docker service update --force`; all `match`.
5. The canary scan over the transcript, `service inspect` and `docker service logs`.
6. `docker swarm leave --force`.

## 13. Assumptions

| # | Assumption | Settled by |
|---|---|---|
| A1 | Journeeze's opv configuration is a 1Password manifest | its maintainers |
| A2 | A projected volume merges Secrets and ConfigMaps into one directory; nested `items[].path` is allowed and `..` isn't; Secret-backed volumes are tmpfs | K-R1, K-R2, K-R5; V9. **K1: confirmed**; overlapping file/directory paths are not refused (§6.2) |
| A3 | Without `fsGroup` the files are `0:0`; with it, the group is `fsGroup`, which is also supplementary for the processes | K-R5; V9. **K1: confirmed**; §6.6 amended for a primary group of 0 |
| A4 | The kubelet doesn't refresh immutable objects; a template change rolls out | K-R6; V10 |
| A5 | The API server adds defaults to the stored volume | K-R3. **K1: confirmed**, only `projected.defaultMode: 420` |
| A6 | Pods need no RBAC to mount Secrets or ConfigMaps | V8 |
| A7 | A missing projected source leaves the pod `ContainerCreating` | K-R4. **K1: confirmed** for a missing Secret and a missing ConfigMap |
| A8 | 1Password keeps a trailing newline, and `opv sync` preserves it | V8 |
| A9 | `[[files]] secret_name` equals `--file-secret`; placement, mode and refresh are unknown | F1–F4 |
| A10 | The infra launcher builds Journeeze's machine configuration | the infra repo |
| A11 | Pod Security `restricted` allows projected volumes and `fsGroup` | V2, with a labelled namespace |
| A12 | Swarm secrets and configs are immutable; secrets are tmpfs files under `/run/secrets` | S-R2, S-R6 |
| A13 | A Swarm secret `target` may be a nested relative path | S-R4 |
| A14 | Swarm never returns secret data | S-R3 |
| A15 | Swarm refuses to remove an object in use | S-R7 |
| A16 | The Swarm size limit is 500 KB | S-R2 |
| A17 | `--secret-add …uid=,gid=,mode=` sets owner and mode | S-R4, S-R6 |
| A18 | The docker CLI has no compare-and-set on `service update` (no version flag appears in `tests/fixtures/docker/swarm/help/service-update.stdout`) | S-R5 |
| A19 | `UpdateStatus.State` takes the values `completed`, `paused` and `rollback_*`; `Version.Index` increases | S-R5, S-R8 |
| A20 | The metadata and IMDS endpoints and the AWS CLI chain work as described; `curl`, `jq` and `base64` are on stock images; every process on the VM can reach the metadata server | G-R8 |
| A21 | The §9.2 read calls return the stated fields | G-R8 (GCP); later for Azure and AWS |
| A22 | `runcmd` runs once per instance; enabled systemd units run every boot | G8 reboot test |
| A23 | `versions access --out-file=-` writes raw bytes to stdout | G-R3 |
| A24 | Annotations accept the stamp's values | G-R4 |
| A25 | Secret ids allow `store_name`'s alphabet | G-R2 |
| A26 | The listed IAM permissions suffice | G-R6 |
| A27 | The AWS CLI reads `fileb:///dev/stdin`; SSM `String` parameters suit config | later AWS recordings |
| A28 | Azure Container Apps can mount Key Vault secrets as files | an Azure spike (not planned) |
| A29 | A 15-minute schedule of `op item list` and `op read` stays within service-account rate limits | V3–V10 timing, and the 1Password documentation on limits |
| A30 | Precedence between a Fly secret and `[env]` of the same name | a Fly spike, part of O8 |
| A31 | `docker config inspect` returns a config's data | S-R3 |
| A32 | `op` signals a service-account rate limit in a reply opv can recognise, optionally with a retry time | the 1Password documentation on limits; a recorded reply if one can be provoked, otherwise C1 classifies only what the documentation states |
| A33 | A Swarm service's Spec carries its log driver as `TaskTemplate.LogDriver`, absent when the daemon default applies | S-R4 |

## 14. Open risks

| # | Risk | Likelihood / impact | Mitigation or acceptance |
|---|---|---|---|
| R1 | Kubernetes: `get secrets` in the namespace, node root or `exec` reads values | certain / high | the platform's model; opv needs only §6.5 |
| R2 | Swarm: any manager-API client controls the swarm | certain / high | a CI-only context and key |
| R3 | VMs: root, the `docker` group or the identity token reads values | certain / high | the cloud's model; per-secret `secretAccessor` |
| R4 | Local: the same user, the daemon and container root read the directory | likely / high | accepted and documented |
| R5 | Enabling `secrets_dir` or `configmap` on an existing Kubernetes target removes env entries the app may still read | likely on first use / high | opt-in; `plan` lists the removals |
| R6 | Enabling `fly.config` stages new secrets and restarts machines | likely on first use / medium | opt-in, with a warn line first (O15) |
| R7 | `opv changed` over-triggers on any edit, tidy included | certain / low | the sync is idempotent (`docs/usage.md:259`) |
| R8 | A sync that wrote but wasn't confirmed records no versions, so `changed` keeps saying `changed` | occasional / low | the next sync confirms and records; it is safe to re-run |
| R9 | Swarm has no compare-and-set **[A18]** | rare / medium | before and after comparison |
| R10 | A missing mounted object stalls a rollout until the deadline | rare / medium | opv writes first; O10 |
| R11 | Non-UTF-8 or NUL values can't be file keys (`src/app/local_delivery.rs:295`) | rare / low | pre-existing |
| R12 | The e2e app has a remote profile for `prod` (`tests/e2e/app/secrets.toml:120-128`), which may conflict with the principle | possible / medium | O9 |
| R13 | 0.11.0 is 93 h and 0.12.0 is 74 h, built on assumptions the recordings settle | likely / medium | Swarm moved to 0.12.0 (§15); K3–K6 and S3–S4 merge only after their recordings (§6.9, §11; FM-10); C5 and C6 can slip without touching the rest |
| R14 | Service-account rate limits under a 15-minute schedule **[A29]** | possible / medium | `--every`, one listing per vault, a typed rate-limit reply and one retry (§2.5; FM-12) |
| R15 | A workload logs a value, and the node keeps it on disk | possible / high | the app's contract (§6.4); the Swarm log-driver warning (§8.5); the canary scan over pod, node and service logs (V16, §12.3) |
| R16 | A sensitive value declared `config` is readable through its channel (env, ConfigMap, argv, `.env`) | possible / high | camp 1: config is declared non-secret; each row shows its channel; sensitive values are `kind = "secret"`; concealed config refused or warned as today (§1.3; FM-02) |

### 14.1 FMECA review (2026-10-17)

A camp-1 FMECA of this design (`.delivery/v0110-fmeca-136-camp1/1792224193645/analysis-report.md` in the design worktree, not in git; run against `e21d19e`) proposed fifteen changes. Each claim was checked against the design and the code before it was applied.

| FM | Changed | As proposed, or adjusted |
|---|---|---|
| FM-01 | §9.2, §9.9, §12.2 step 8; G6, G8 | as proposed: `curl -fsS`, no pipeline status, `EXIT` trap |
| FM-02 | §1.3, §6.2, §7.1, §8.2, §9.2; M2, F1, S2, G5; R16 | **manager's decision:** env routing of config is **not** made opt-in (camp 1 declares config non-secret, and the owner chose camp 1). Instead every row shows its channel, sensitive values are `kind = "secret"`, and concealed config keeps today's handling: refused on GitHub variables (and Swarm env), warned elsewhere |
| FM-03 | §6.4, §8.5, §8.9, §12.1 V16, §12.3; K6, S4, V1; A33, R15 | adjusted: Kubernetes has no per-workload log driver, so no warning there; the warning is Swarm-only |
| FM-04 | new §1.6; new deliverable M5 | adjusted: an MCP server does exist (`src/mcp.rs`, sharing `src/app/agent_view.rs` with the CLI); the review found none. M5 extends the existing marker scan to it |
| FM-05 | §2.2; C2 | as proposed: the CI service account writes the delivery item (it already writes evidence), never a source item |
| FM-06 | §8.4; C5, S4 | as proposed; the CI concurrency group already existed (§2.5) |
| FM-07 | §4.5; M4 | adjusted: without a declared transform the divergence is a loud `single_line` finding, not silent; the warn line applies to `FileCapability::None` only |
| FM-08 | §6.3, §12.1 V9; K5, K6, V1 | adjusted: `fsGroup` is pod-wide and projections have no per-file owner, so "per-product `fsGroup`, 0400 with that owner" is not possible; the mount goes into the target's container only |
| FM-09 | §6.5, §12.1 kit; K3, K6 | adjusted: `resourceNames` can't restrict `create` or `list`; namespaced Role plus the nightly drift check |
| FM-10 | §6.9; K3–K6, S3, S4; R13 | adjusted: the gate is on K3–K6 and S3–S4, not K2 and S2, which use no recording |
| FM-11 | §2.2; C5, C6 | as proposed |
| FM-12 | §2.5; C1, C5; A32, R14 | adjusted: the listing was already once per vault; no adapter produces `RateLimited` today, so C1 adds it |
| FM-13 | §6.6; K4, K5 | as proposed |
| FM-14 | §5, §15 | as proposed: restated as the accepted residual; narrowing it is an open idea |
| FM-15 | §4.6; A3 | adjusted: the verification cluster runs no shim, so V10/V14 can't prove the Fly path; the Journeeze `SERVE` edit is an external dependency of A3 |

## 15. Decisions on the open questions (2026-10-17)

**By the owner:**

- **O9: remote SSH profiles.** A remote profile may only allow environments that have no deployment target. Config load refuses a profile that allows an environment with a target (Fly, Kubernetes, Azure, GitHub, Swarm, VM), because that environment's values must reach it only through the CI sync. This is a 0.11.0 deliverable (R1).
- **O13: Swarm recordings.** A temporary single-node swarm on the development machine is approved for recording (`docker swarm init`, then `docker swarm leave --force`). Nothing is pulled or exposed.
- **O14: GCP project.** Decided when 0.12.0 starts.
- **Scope.** Docker Swarm (S1–S5) moves to 0.12.0 alongside the VM work. 0.11.0 is the channel model, change detection with its CI recipe and README, Kubernetes ConfigMaps and file mounts, Fly config, the webhook mapping, verbatim files, R1 and verification.

**Open (from the FMECA, FM-14; not designed):** narrowing who can read the local RAM directory below "the same user": a dedicated low-privilege delivery user, or one subdirectory per role. Today's limit stays the accepted residual (§5, R4).

**Taken as recommended (technical; the owner may overrule):**

| | Decision |
|---|---|
| O1 | Kubernetes file delivery is opt-in through `secrets_dir`. ConfigMaps are used for newly created targets only; existing targets keep plain env config until they opt in. |
| O2 | When the pod's ability to read the files can't be established (no `fsGroup` or `runAsUser`), sync refuses (`mount_unreadable`) and names the one manifest line that fixes it. |
| O3 | Target-level `roles` are adopted, so migration material never reaches a serving target. |
| O4 | `OPV_UID` and `OPV_GID` are added for local file runs (not secrets). |
| O5 | No `--dir-env` flag: the directory variable comes from `secrets_dir_env` in config only. |
| O6 | opv doesn't set the app's directory variable (`JZ_VAULT_DIR`). The app's manifest owns it. |
| O7 | 0.11.0 is verified locally with kind and a CI-like shell; GitHub Actions comes later. |
| O8 | The Fly live file check is deferred. The Journeeze shim stays until it's done. |
| O10 | Accept the rollout deadline. No new `list events` permission. |
| O11 | The VM startup step is a POSIX shell script. |
| O12 | GCP versions older than the previous one are disabled, never destroyed. |
| O15 | An unset `fly.config` warns in 0.11.0 and is refused in 0.12.0. |
| O16 | An Events API trigger comes later, as an optional accelerator to `opv changed`. |
| O17 | New exit code 10 (`source_changed`). |

## 16. Owner decisions needed (as originally listed)

| # | Decision | Options | Recommendation |
|---|---|---|---|
| O1 | Kubernetes defaults: files by opt-in `secrets_dir`; config route for existing targets | opt-in / automatic; keep `env` / flip to `configmap` | opt-in files; `configmap` for new targets only |
| O2 | `sync` when Kubernetes readability is unknown | refuse / warn / opv sets `fsGroup` / 0444 | refuse |
| O3 | Target-level `roles` | adopt / no | adopt |
| O4 | `OPV_UID`/`OPV_GID` in local file runs | add / docs only | add |
| O5 | `--dir-env` on `opv run` | flag / config only | config only |
| O6 | opv sets the app's directory variable on Deployments and services | yes / no | no |
| O7 | Where V1–V17 run | local kind and swarm / GitHub Actions | local |
| O8 | A throwaway Fly app for F1–F4 and A30 | authorize / defer | defer; the shim stays |
| O9 | Remote profiles for deployed environments | allow / refuse at load | decide separately |
| O10 | `list events` to fail fast on a missing mounted object | add / accept the deadline | accept |
| O11 | VM step as a script or a binary | script / binary | script |
| O12 | GCP superseded versions | disable older than previous / keep / destroy | disable |
| O13 | Approve `docker swarm init` for S-R1–S-R9 | approve / not now | approve |
| O14 | A throwaway GCP project for G-R1–G-R8 and G8 | approve / not now | approve before 0.12.0 |
| O15 | Fly config switch-on: unset `fly.config` warns in 0.11.0 and is refused in 0.12.0 | this schedule / default `secrets` now / refuse now | this schedule |
| O16 | An Events API trigger (needs an Events token in CI, a Business plan, and a live check of `server-update` coverage) | later / never | later, as an accelerator to `opv changed` |
| O17 | Exit 10 `source_changed` as a non-failure result code | adopt / reuse exit 8 | adopt: CI must tell "changed" from "broken" |
