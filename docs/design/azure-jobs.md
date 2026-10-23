# Azure target: Container Apps Jobs beside their app (#238)

Status: post-spike, ready for vet, 2026-10-23. Nothing here is built. Spike S-238 ran in the
sandbox resource group `opv-spike-rg` (§8). Every Azure behaviour of jobs below is verified there
and cited by its finding id (J1–J12 in `spike-238-azure-jobs-findings.md`). The recorded outputs
are in `tests/fixtures/azure/jobs/`. Claims about opv cite `file:line` on `dev` at `291c0b16`.

## 1. Problem, scope, non-goals

An Azure target names one Container App (`azure.container_app`, `src/adapters/azure/config.rs:48`,
`:121`). A common pattern runs a Container Apps **Job** beside each app, for example a pre-deploy
config-validation job whose template copies the app's env, including `secretRef:` variables. After a
rotation in 1Password, `opv sync --deploy` re-pins the app (`containerapp.rs:643-717`), but the job
keeps its old Key Vault reference. `opv status` and `opv delivery verify` read only the app
(`containerapp.rs:638-641`). So the job runs against stale values, and nothing reports it.

**In scope.** A job that must hold the same managed names as its app: the same Key Vault references
pinned to the same versions, and the same env-routed config values. The issue's acceptance:

- A1. A rotated key reaches the app and its job(s) in one `opv sync <env> --deploy`.
- A2. `opv delivery verify` reports `drifted_on_target` when a job's copy differs.
- A3. `opv doctor` warns when a job's identity cannot read the Key Vault, and prints the
  role-assignment command, as it does for apps (`containerapp.rs:887-890`, `:924-932`; `preflight.rs:689-708`).
- A4 (added after the spike, J3). `opv sync --deploy` refuses to update a job whose identity cannot
  read the vault, before it updates the job or the app, and names the grant command. Azure accepts
  that update, and only the job's next execution fails, silently.

**Non-goals.** opv does not start job executions or wait for them, and does not trigger or schedule
jobs. It does not assign identities or create role assignments: it prints the command, as for apps.
It does not support a job in another resource group or subscription than its app. It does not
support a job without an app (see D1). It adds no `az` simulator to `tests/sim` (there is none for
Azure: `tests/e2e/coverage.rs:74`). It does not work around third-party (`az`, Azure) defects. It
never uses `az containerapp job secret set` or `--set-env-vars`, because those put values in argv
(SR-3).

## 2. What opv does for an app today (the base both options reuse)

- **Config.** `AzureTarget` holds `subscription, key_vault, resource_group, container_app,
  container, identity, env_name_template, config, vault_uri` (`config.rs:42-58`). The raw section is
  `deny_unknown_fields` (`config.rs:116-129`). Every identifier goes through `check_ident`
  (`config.rs:289-306`).
- **Ports.** `open` returns `Ports::Pinned { store: KeyVault, runtime: ContainerApp }`
  (`config.rs:465-492`). Core sees only `PinnedRuntime` (`src/ports.rs:112-148`):
  `bindings, apply, await_healthy, check_access, config_in_store, describe, inspect_hint, chain,
  release, deploy_preview`.
- **Bindings.** `snapshot_from` reads the managed container's env (`container_index`,
  `containerapp.rs:341-371`). A `value` becomes `Plain{sha256}`, and a `secretRef` to an `opv-`
  secret whose `keyVaultUrl` is `<vaultUri>/secrets/<name>/<version>` becomes `Pinned`. The
  unmanaged fingerprint is the SHA-256 of the spec with managed env entries, `opv-` secrets and
  read-only fields removed (`containerapp.rs:380-400`, `:443-486`).
- **Apply.** It re-reads the app and refuses with `Refusal::ChangedOutsideOpv` when the fingerprint
  moved (`containerapp.rs:657-671`). It edits the fresh spec: per-version secret names
  (`secret_name`, `containerapp.rs:989-996`) so a repin is a template change (P1 Q16). It keeps the
  serving revision's secrets (`serving_refs`, `:543-552`) and sends the whole document with
  `containerapp update --yaml /dev/stdin` (`:676-690`). Values never go in argv (module doc
  `:12-15`).
- **Health.** The new revision must be `Provisioned`, `Running`/`ScaledToZero`, `Healthy` and
  `latestReadyRevisionName` (`containerapp.rs:719-784`). A refused update is read back: if Azure
  applied nothing, the cause is `TargetRefused`; otherwise it is `WriteOutcomeUnknown`
  (`:247-278`).
- **Sync order.** The sync writes Key Vault versions (`src/app/sync.rs:1717-1726`) and records
  delivery evidence at those versions (`:1735-1764`). It reads the bindings and drift (`:1774-1778`)
  and applies with read-back on exit 9 (`apply_reconciled`, `:1847`, `:2052-2082`). It then waits
  for health (`:1860`) and releases, then deletes, pruned entries (`:1938-1943`). An Azure update
  is never retried (NR-2).
- **Doctor.** The lines are `az, az login, azure subscription, key vault, container app, app
  identity access` (`preflight.rs:43-50`, `:514-557`). The access line is advisory: P1 Q14 showed
  Azure refuses an app update whose identity cannot read the vault before any rollout
  (`preflight.rs:689-708`). `check_access` resolves the principal (system, or user-assigned via the
  app, else `identity show`, `containerapp.rs:583-636`). It then checks an access policy or an RBAC
  role at vault scope and names `az keyvault set-policy` or `az role assignment create`
  (`:856-935`).
- **Guards.** `src/app` and `src/domain` name no provider (`src/app/mod.rs:2128-2145`,
  `:2313-2334`). The Azure adapter has no `host::lost_call` caller (`rg` finds only
  `src/adapters/fly/mod.rs:712` and `src/adapters/kubernetes/mod.rs:171`). Every `az` failure goes
  through `az::failed` (`src/adapters/azure/az.rs`), so job calls add no `lost_call` caller.

**A gap found while reading (it affects A2 for either option).** `delivery verify` takes each name's
version from `store.list()` (`src/app/delivery.rs:1304-1307`, `:1322-1332`). Both pinned stores
list `version: None`: Key Vault (`keyvault.rs:163-172`, P1 Q2) and Kubernetes
(`src/adapters/kubernetes/store.rs:499-519`). `name_state` turns a missing version into
`missing_on_target` (`src/domain/delivery.rs:352-360`). `sync` fills the versions in from its reads
(`src/app/mod.rs:446-452`), but verify does not. So on a pinned target, verify cannot answer
`verified` or `drifted_on_target` today. No test covers verify on a pinned target
(`src/app/azure_tests.rs` and `pinned_tests.rs` have none). Lane L1 (§10) starts with a failing
test that proves the gap, then fixes it in provider-neutral code. See D4.

## 3. Option 1: a job target (`azure.container_app_job`)

**Config.** This is a second target whose `azure` section names `container_app_job = "<job>"`
instead of `container_app` (exactly one of the two). `opv target add --azure-container-app-job`
writes it (an `INIT_FIELDS` entry, `config.rs:134`).

```toml
[environments.prod.targets.api-validate.azure]
subscription = "…"; key_vault = "kv-myapp-prod"; resource_group = "rg-myapp"
container_app_job = "job-myapp-validate"; identity = "system"; env_name = "FLEET__{PRODUCT}__{KEY}"
```

**Blocker in current code.** A job that mirrors its app uses the app's Key Vault and template.
`same_target` calls two Azure targets with the same `key_vault` and `env_name_template` the same
target (`config.rs:436-443`). `check_shared_targets` refuses that in one environment, and across
environments too (`src/config.rs:2504-2549`). The rule exists because each target prunes the names
it manages (FR-8). The app target's `--prune --deploy` would delete a Key Vault entry after
releasing only *its own* references (`sync.rs:1938-1943`), and the job target would still bind
that entry. Option 1 therefore needs one of these:
(a) a separate vault or template for the job, which duplicates every secret and breaks "same env
as the app";
(b) relaxing FR-8 for app/job pairs plus cross-target prune coordination, which is a core change
across placements.
Neither is small, and (b) is exactly the failure FR-8 prevents.

**Sync path.** The runtime is a job adapter with no revision. `PinnedRuntime::apply` must return a
`Revision` (`ports.rs:116`), so the job would need a synthetic one, and core prints "deployed
revision …" (`sync.rs` after `:1860`). `--deploy` then reports "next execution uses the new values"
(the issue's wording). A1 holds only because one `opv sync <env>` syncs every target of the
environment. The app and job are independent placements, so a failure on one leaves the other done.
That is plain per-target partial failure, with no ordering between them.

**Verify / drift.** Each target has its own placement, receipt and delivery item. That means a
second `state_vault_id` item and `opv apply` for it, and A2 comes per target once L1 lands.
**Doctor.** The target's own lines, with "job identity access" in place of "app identity access".
**Benefit.** A person can sync the job alone (`--target api-validate`), run the validation, then
sync the app. Option 2 gives no pause between job and app inside one run (D3).

## 4. Option 2: companion jobs on the app target (`azure.companion_jobs`)

**Config.**

```toml
[environments.prod.targets.api.azure]
# … existing fields …
companion_jobs = ["job-myapp-validate"]   # optional; same resource group and subscription
```

- `RawAzure` gains `#[serde(default)] companion_jobs: Vec<String>`. Each name is checked like
  `container_app` (`check_ident`, `config.rs:298-300`). A duplicate is `FieldRule::DuplicateKey`.
- `azure.identity` applies to each job (D5): `system` means each job's **own** system-assigned
  identity, which is a different principal from the app's. A user-assigned id must be attached to
  every job.
- `azure.container` applies to each job (D6): the job must have a container of that name, or
  exactly one container when the field is unset. The error is the app's `ConfigCheck::NotOneOf`
  (`containerapp.rs:353-366`).
- `same_target` also returns true when two Azure targets share a resource group and any companion
  job (`config.rs:436-443`), so FR-8 refuses two targets writing one job.

**Structure (adapter only; no core change for sync).** There are two new files under
`src/adapters/azure/`:

- `job.rs`: `ContainerAppJob`, one job as a runtime. It has:
  - `show` (`containerapp job show`): bindings come from here only, never from an execution, whose
    template names one `cappjob-<job>` secret (J10). `secrets: null` reads as empty (J2).
  - `snapshot` and `edit`.
  - `update` (`containerapp job update --yaml /dev/stdin`, core, J1). The document is on stdin
    only, and unmanaged secrets are sent back as `show` returned them, without values (J6).
  - `settle`: read `provisioningState` from the update's reply, which was `Succeeded` every time
    (J11). `Failed` refuses, and `InProgress` is polled like `settled_app`.
  - `release`, `principal` and `access` (below).

  The job's read-only fields are `provisioningState`, `outboundIpAddresses`, `eventStreamEndpoint`
  and `systemData`. A job has no etag, so the fingerprint applies as for the app (J2). `job.rs`
  reuses the app's helpers, made `pub(super)` in `containerapp.rs`: `secret_name, env_refs, upsert,
  fingerprint, diff_paths, is_opv_secret, policy_grants_get`, and the RBAC/policy half of
  `check_access`. The user-assigned key match stays case-insensitive (`containerapp.rs:603`), since
  Azure lower-cases `resourcegroups` in the key (J12).
- `companions.rs`: `AppWithJobs`, which implements `PinnedRuntime` over one `ContainerApp` and N
  `ContainerAppJob`. `open` (`config.rs:465-492`) returns it only when `companion_jobs` is
  non-empty. Otherwise the target is byte-identical to today, so the characterization tests and
  P0 argv stay unchanged.

**Bindings (what core sees).** For each managed name, `AppWithJobs::bindings` merges the
per-resource bindings. If the app and every job agree, it reports that binding. Otherwise it
reports the first job (config order) whose binding differs from the app's, and a job that lacks the
name makes the name absent. Core then works unchanged:

- `pinned_diff` re-pins a name whose merged binding is not the target version
  (`sync.rs:2232-2273`).
- `drift` flags a pin to a version other than the store's current one (`:2265-2268`).
- `status --fail-on-drift` raises `TargetDrift` (`status.rs:208-224`, `:813-814`).
- verify (after L1) sees the job's version, so it reports `drifted_on_target` or
  `missing_on_target`.

The unmanaged fingerprint is the SHA-256 of the app's fingerprint followed by each job's, in config
order. `RawSpec` holds `{"app": <spec>, "jobs": {"<job>": <spec>}}`. It holds no values, only
Key Vault references and env-routed config, as today (`src/domain/runtime.rs:44-46`). No job
reply held a value (J7).

**Sync path and ordering (D2; recommended: jobs first, then the app, one apply).**
`AppWithJobs::apply(change, snap)`:

1. Re-read every resource and compare each one's own fingerprint with the snapshot. Any difference
   refuses with `TargetRefused{ChangedOutsideOpv{after_apply:false}}` naming that resource, as the
   app does today (`containerapp.rs:653-671`). Nothing is written.
2. For each job, compute **its own** sub-change: the pins whose job binding is not the target, the
   config whose digest differs, and the unbinds present. A job with an empty sub-change is not
   updated, so there is no write without a change.
3. **Access gate (A4, J3).** Each job that will be updated, and will hold an `opv-` Key Vault
   reference afterwards, gets the job's `access` check: the same reads as `check_access`
   (`containerapp.rs:856-935`) against the job's principal. A job with no system identity, an
   unattached user-assigned id, or no read grant refuses the whole apply before any job or app
   update. The cause is `MissingRight` naming the job's identity and the command (see "Catalog").
   This check is read-only, and its reads are retried like every read.
4. **Fresh grant (J5).** When the grant that passes step 3 has a `createdOn` less than 10 minutes
   old (from the `role assignment list` reply, J4), the apply goes on, and `runner.note` says: "the
   Key Vault grant to the identity of container app job J is N min old; Azure can take a few
   minutes to apply it, so an execution started before HH:MM UTC may fail to read its secrets". opv
   neither waits (it starts no executions) nor refuses (the update is correct). The spike saw 28 s
   too early and 2 min 18 s enough. The 10 minutes is Azure's documented worst case, not measured.
   An access-policy vault records no time, so it gets no note.
5. Edit each job document as `edit` does (`containerapp.rs:489-537`): per-version `opv-` secret
   names with `keyVaultUrl` and `identity`, and env `secretRef`s. Jobs do not need per-version names
   (J8), but opv keeps them so app and job share one `secret_name` and one binding reader. Update,
   then settle (J11). For each job, `runner.note` reports "container app job J pins NAMES; its next
   execution uses them".
6. Apply the app's sub-change as today and return its new revision. If the app has nothing to
   change, return its current `latestRevisionName`, and core confirms that revision is healthy (the
   existing no-change path, `sync.rs:1848-1852`).

Without `--deploy` nothing is applied, so jobs stay pending like the app (FR-29): the issue's
"every sync" means every deploying sync (D3). `--prune --deploy`: `AppWithJobs::release` releases
every job, then the app, before any Key Vault delete (`sync.rs:1938`). No resource keeps a
reference to an entry opv deletes (FR-32).

A job has no serving revision to protect, and a running execution keeps the values it started with
even when its secret is removed (J9). So superseded `opv-` secrets are removed in the same job
update, and jobs need no `serving_refs`.

**Partial failure** (no update is retried, NR-2):

| Where it stops | State | Error | Next run |
|---|---|---|---|
| access gate (step 3) | KV versions written (not live, FR-29); no job or app updated | `MissingRight{grantee: job k's identity, grant: Rbac{Key Vault Secrets User, vault} or AccessPolicy{get}}` | after the grant, deploys everything |
| job k refused (Azure applied nothing) | KV versions written; jobs before k updated; app untouched | `Partial{done:["container app job J1 (pinned)", …], then: TargetRefused{subject: job k, why: Validation}}` (`cause/mod.rs:767-774`; render `render.rs:2113`) | re-pins job k and the app |
| job k outcome unknown | as above, job k unknown | `Partial{…, then: WriteOutcomeUnknown{job k}}`; `apply_reconciled` reads the merged bindings back. The app is not done, so `left(now)` is non-empty and the run stays unknown (`sync.rs:2061-2081`) | reconciles from what it reads |
| job settles `Failed` | job holds the new references | `TargetRefused{job k, Validation}` in `Partial` | re-applies |
| app refused or unknown after the jobs | jobs ahead of the app | `Partial{done: jobs, then: <app cause as today>}` | re-pins the app only |
| app revision unhealthy or timed out | jobs and the app's template at the new versions; old revision serves | today's `Refusal::Unhealthy` / `InProgress` (`sync.rs:1862-1880`); the job notes were already printed | as today |

**Catalog.** Core's `partial()` merges an adapter's `Partial.done` list (`sync.rs:222-240`), so
no new cause is needed. There are two catalog changes, both provider-neutral:

- `ResourceKind::ContainerAppJob` (`src/cause/subject.rs:245-265`), rendered "container app job"
  with the listing hint `az containerapp job list` (`render.rs:810`, `:3771`).
- `MissingRight` gains `grantee: Option<Principal>` (`cause/mod.rs:699-707`). Today its grant
  action and words take the principal from `seen`, the caller (`render.rs:3598-3614`). That would
  tell the *deploy identity* to get the role, while the job's identity needs it. With
  `grantee: Some(Principal::AppIdentity{name: "container app job J (principal P)"})`
  (`subject.rs:280`, not built anywhere in production today), the action names the right
  principal. `None` keeps every existing message byte-identical. The cause is built from opv's own
  `role assignment list` reply through `preflight::unusable` (`preflight.rs:280`), the way
  `ChangedOutsideOpv` is (`containerapp.rs:657-671`).

`NotFound{named_by: azure.companion_jobs}` for a missing job copies `preflight.rs:445-452`.

**Why jobs first.** (a) A job update changes no serving traffic. (b) The pre-deploy validation job
then holds the candidate values. (c) A job failure stops before the app changes. (d) When the app's
new revision is unhealthy, the jobs match the app's *template*, which is what `status` already
reports for the app in that state. The alternative (app first, jobs after the revision is healthy)
keeps jobs on proven values only. It has to write from inside `await_healthy`, and a job failure
there leaves the job stale after a healthy deploy, which is the bug this issue reports.

**Preflight and doctor.** `preflight::run` (`preflight.rs:68-95`) shows each job after the app. A
job that is missing gets `NotFound`, `InProgress` is waited for under `Mutate`
(`settled_app`, `:476-510`), and `Failed` is a warning. Doctor appends two lines per job after "app
identity access" (`preflight.rs:514-557`):

- `container app job <J>`: it exists, its container matches, and its provisioning state.
- `job <J> identity access`: a `warn` verdict like `access` (`:689-708`), with the principal
  taken from the job. Doctor stays a warning, but `sync --deploy` refuses on the same finding
  (step 3). A missing system identity names `az containerapp job identity assign -g <rg> -n <J>
  --system-assigned` (core, J1). A missing grant names the same `az role assignment create …
  --role "Key Vault Secrets User" --scope <vault id>` (or `set-policy`) as
  `containerapp.rs:887-890`, `:924-932`, which worked verbatim for a job principal (J4). A grant
  younger than 10 minutes adds step 4's note.

`status` and `plan` (`PreflightMode::Read`) print the access finding as a `warn` line, so a person
sees it before deploying. `DOCTOR_CHECKS` stays static for the "not checked" lines
(`preflight.rs:43-50`), and job line names are built per job.

## 5. Verify and drift (both options): what L1 changes

`verify_target` gets the observed version of a pinned target from `runtime.bindings()`
(`Binding::Pinned{version}`) and no longer reads it from `store.list()` (`delivery.rs:1304-1332`).
This is provider-neutral, goes through the `PinnedRuntime` port, and names no provider. It covers
Kubernetes too. After a sync without `--deploy`, the runtime still binds the old version while the
receipt records the new one. That name is `drifted_on_target` with `deployed: "staged"` (`:1346-1352`).
The target does not serve the recorded version (D4). With Option 2 the merged bindings make a
job's stale copy `drifted_on_target`, which is A2.

## 6. Security analysis

- **No new value path.** Job documents travel only on stdin (`--yaml /dev/stdin`), exactly as the
  app's (`containerapp.rs:676-690`). Argv holds names and ids
  only, because `az` logs argv to `~/.azure/commands` (P1 Q12). The value-carrying `job secret set`
  and `--set-env-vars` are never called. On native Windows the write uses the existing named-pipe
  hand-off (`handoff.rs`).
- **Output.** `job show` and `job update` replies are parsed and never printed. They carry no
  secret value, and no marker reached `~/.azure` (J7). A plain secret that opv does not own is
  sent back without its value, and Azure keeps it (J6), so the pre-spike rule "refuse a job that
  has its own plain secrets" is dropped.
- **Silent failure closed.** Azure accepts a job reference the identity cannot read (J3), and a
  failed execution gives no reason (J3, J10). The access gate (step 3) turns that into a refusal
  that names the grant, before anything is deployed.
- **Permissions.** 1Password vault access stays the only permission system that opv adds. Azure
  rights are the operator's: the deploy identity needs write (Contributor) on each job as well as
  the app, which `docs/configuration.md:388` must say. opv never creates role assignments or
  identities. It prints the command (A3). A job's system identity is a new principal. Granting it
  Key Vault Secrets User at vault scope lets the job read every secret in the vault, the same
  breadth the app has today. Doctor's existing "scope broader than needed" wording applies.
- **CI** reads 1Password and delivers. It never writes values to 1Password, and this design changes
  neither.
- **Blast radius.** The companion list is explicit and checked at load. opv touches only managed
  env names and `opv-` secrets of named jobs, behind the same unmanaged fingerprint.

## 7. Recommendation

**Option 2 (`companion_jobs`)**, jobs updated first inside the app's `--deploy`, plus L1. Reasons:

1. It fits the stated pattern: the job holds its app's environment, so the app target already owns
   exactly the right managed set, vault and template.
2. It needs no FR-8 relaxation. Option 1 is refused by `check_shared_targets`
   (`src/config.rs:2504-2549`) unless it duplicates the vault or adds cross-target prune
   coordination, and it brings a synthetic job "revision".
3. It needs no core change for sync, status or drift. Everything sits behind `PinnedRuntime` in
   `src/adapters/azure`, so the provider guards hold. The only core change, L1, fixes a gap that
   exists anyway.
4. It needs one placement, one receipt and no extra `state_vault_id` item or `opv apply`.

The spike changed nothing in this choice (no finding favours §3). It added the access gate (D7)
and the fresh-grant note (D8), and removed one safety rule and the `az rest` fallback.
Cost: there is no pause between the job and the app inside one run (D3), and a standalone job is
not covered (D1). About 1,350 changed lines over five lanes.

## 8. Spike S-238: done

The owner ran it on 2026-10-23. Scripts (R1–R5 read-only, W1–W11 writes, cleanup with a trap,
redaction) and raw outputs stay in the session scratchpad, outside the repository. Cleanup ran, the
resource group matched its baseline, and no marker reached `~/.azure` or the outputs.
`spike-238-azure-jobs-findings.md` has the findings. Their effect on this design:

| Finding | Pre-spike assumption | Now |
|---|---|---|
| J1 `job update --yaml` is core | `az rest` fallback | dropped |
| J3 an unreadable reference is accepted; only the execution fails | doctor advisory, gate "if needed" | access gate before any update (step 3, D7) |
| J5 a listed grant takes ~0.5–2.3 min to apply | not considered | fresh-grant note, no wait (step 4, D8) |
| J6 an unmanaged plain secret is kept when sent without its value | refuse such jobs | rule dropped |
| J8 repointing `keyVaultUrl` alone is seen by the next execution | per-version names needed | kept only to share code with the app |
| J9 a running execution keeps its start values | maybe keep the superseded secret | removed in the same update |
| J10 executions reference one `cappjob-<job>` secret | — | bindings from `job show` only |
| J11 the update returns settled | poll `provisioningState` | read it from the reply |
| J2, J12 shapes (no etag, `secrets: null`, lower-case `resourcegroups`) | — | read-only list, null secrets, case-insensitive key |

## 9. Test plan

- **Adapter unit tests** (in `job.rs`, `FakeRunner` + `tests/fixtures/azure/jobs/`, the pattern
  of `containerapp.rs:1139-1200`):
  - the snapshot reads `Pinned`/`Plain`/`Other`, and `secrets: null` reads as empty;
  - the fingerprint ignores managed entries and the job's read-only fields;
  - the update sends the whole document on stdin with no value in argv, and an unmanaged plain
    secret goes back without a value;
  - settle reads the reply's state;
  - refused vs unknown read-back, the container rule, the lower-case `resourcegroups` key;
  - the access findings name the job and the command;
  - a `createdOn` under 10 minutes yields the note.
- **Composite tests** (in `companions.rs`): the merge rule (agree, a job differs, a job lacks a
  name), the per-resource sub-change, no update for an unchanged job, jobs before the app, the
  access gate refusing with no update sent (A4), the `Partial` done lists in §4's table, and
  release before delete.
- **End to end** (`src/app/azure_tests.rs`: the stateful `Sim` of `op` and `az`, `:1-8`). Extend
  it with jobs, then: a rotation reaches app and job in one deploy (A1); job drift shows in `status`
  and `--fail-on-drift` exits 8 (as `:705-762`); the interruption matrix covers job calls (extend
  `:918`, `:956`); `values_never_reach_argv` and `sync_output_holds_no_value` cover job documents
  (`:1034`, `:1073`); prune leaves no job reference to a deleted entry (as `:983`). A target without
  `companion_jobs` keeps its exact argv.
- **Verify** (L1, `src/app/pinned_tests.rs`): verify on a pinned target says `verified` after a
  deploy, `drifted_on_target` after the binding moves, and `missing_on_target` when unbound; then
  A2 with a job in `azure_tests.rs`.
- **Doctor** (in-file tests of `preflight.rs`, from `:729`): the job lines, the missing identity
  text, and the role command for a job principal (A3).
- **Catalog** (`src/cause/render_tests.rs`): `MissingRight` with a `grantee` names that principal
  in the action and the words, and without one every existing render stays byte-identical.
- **Release gate:** e2e with `CI=true` and `cargo test` before the release PR.

## 10. Delivery lanes (≤ ~400 changed lines each, disjoint files)

| Lane | Files | Lines | After |
|---|---|---|---|
| S-238 | done: `tests/fixtures/azure/jobs/`, findings doc | — | — |
| L1 pinned verify | `src/app/delivery.rs`, `src/app/pinned_tests.rs` | ~180 | none (parallel to S-238) |
| L2 job runtime | `src/adapters/azure/job.rs` (new), `containerapp.rs` (helper visibility only), `src/cause/{mod,subject,render,codes}.rs` + `render_tests.rs` (job kind, `MissingRight.grantee`), `mod.rs` (`pub mod job;`) | ~450, split below | none |
| L3 companions | `src/adapters/azure/companions.rs` (new), `config.rs` (field, parse, `same_target`, `open`), `mod.rs` (one line, after L2), `src/app/azure_tests.rs` | ~400 | L2 |
| L4 doctor/preflight | `src/adapters/azure/preflight.rs` | ~220 | L3 |
| L5 docs | `docs/configuration.md` (Azure section, deploy-identity rights), `docs/design/multi-cloud-targets.md` (§11 note) | ~80 | L3 |

L1 ∥ L2 → L3 → L4 ∥ L5. `mod.rs` is the only file two lanes touch, and they touch it in sequence.
L2 is split in this order: L2a is the catalog (`src/cause/*`, ~80); L2b is the read side of
`job.rs` (show, snapshot, principal, access, ~200); L2c is the write side (edit, update, settle,
release, ~200).

## 11. Decisions for the owner

**D1. One target per job (Option 1) or jobs listed on the app's target (Option 2)?**
In practice, Option 1 makes a job its own destination with its own receipt, so you can sync and run
the job before you sync the app. Today opv refuses two targets sharing one Key Vault and naming
scheme, because each would delete what the other still uses. So Option 1 needs either a second vault
holding copies of every secret, or a core change that coordinates deletes across targets. Option 2
makes the job follow its app: one sync, one receipt, and the job is updated whenever the app is.
**Recommend Option 2.** Cost: no "job only, then app" step, and a job with no app is not covered
(it becomes Option 1 later if a real case appears).

**D2. Within one deploy, update the jobs before or after the app?**
Before (recommended): a validation job already has the new values when the app rolls out. If the
app's new revision fails, the jobs are on the new values while the old revision serves, which is the
state `status` already shows for the app's template. After: jobs only ever get values the app proved
healthy. But a job failure then leaves the job stale after a good deploy (this issue's bug), and opv
has to write during its health wait. **Recommend before.**

**D3. Are jobs updated only on `--deploy`?**
Yes, in the recommended design. Without `--deploy`, new Key Vault versions are invisible to the app
(FR-29), and jobs behave the same, so the two never differ because of a non-deploying sync. The
alternative (always re-pin jobs) would let a validation job see staged values before any deploy. It
breaks the rule that nothing goes live without `--deploy`. **Recommend deploy-only.** Cost: there is
no built-in "validate first" pause. CI can run the job after `opv sync --deploy` has updated it, or
the owner can ask for D1's Option 1 later.

**D4. Fix `delivery verify` on pinned targets (L1) as part of this work?**
Read as it stands, verify on Azure (and Kubernetes) cannot say a name is verified or drifted, because
it never reads the version the app binds (§2). The fix reads the binding. A name staged but not yet
deployed then reads `drifted_on_target` (`deployed: staged`), meaning the target does not serve the
recorded version. **Recommend yes, first, as its own PR** (it also deserves its own issue). Cost:
~180 lines in core, and verify output changes for existing Kubernetes and Azure users.

**D5. Do jobs use the app's `azure.identity` setting?**
Recommended: yes. `system` means each job's own identity, which doctor checks separately. A
user-assigned id must be attached to each job. The alternative is a per-job identity field. Cost of
the recommendation: a job with a different user-assigned identity than its app is not supported.

**D6. Does `azure.container` also pick the job's container?**
Recommended: yes, with the same rule (that name, or the only container). Alternative: a per-job
table `{ name, container }`. Cost: a job whose container is named differently needs that later
extension.

**D7. Refuse to update a job whose identity cannot read the vault (new, from J3).**
In practice: the spike showed Azure accepts such a job update, and the job's next run then fails
without saying why. With the gate, `opv sync --deploy` stops before it changes the job or the app.
It names the job's identity and the exact `az role assignment create` (or `set-policy`) command to
run. The Key Vault versions it wrote stay staged, as always. The options are to refuse (recommended)
or to warn and go on, as doctor does. **Recommend refuse.** Cost: two extra reads per job per
deploy (a few seconds). Also, a deploy refuses in cases where Azure itself would have accepted the
change.

**D8. Right after a new grant: warn, do not wait (new, from J5).**
A grant appears at once but took up to about 2 minutes to work, and opv cannot test it as the job.
Recommended: when the grant is under 10 minutes old, the deploy goes on and prints one line saying a
run started before a given time may fail. The alternatives are to wait up to 10 minutes (it slows
every first deploy and proves nothing) or to refuse until then. **Recommend warn.** Cost: a run
started within those minutes can still fail, and the note names the time.

Spike writes (formerly D7) are approved, done and cleaned up. Two marker secrets remain soft-deleted
in the sandbox vault until its retention ends or you purge them.
