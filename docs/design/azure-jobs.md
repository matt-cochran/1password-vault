# Azure target: Container Apps Jobs beside their app (#238)

Status: PRE-SPIKE draft, 2026-10-23. Nothing here is built. The owner chooses between §3 and §4
after Spike S-238 (§8) has run in the sandbox resource group `opv-spike-rg`. `az` was not signed in
when this was written, so every Azure behaviour of **jobs** below is *documented, not verified*
(marked **[doc]**) until the spike records it. Claims about opv cite `file:line` on `dev` at
`291c0b16`.

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

- `job.rs`: `ContainerAppJob`, one job as a runtime. It has `show` (`containerapp job show`),
  `snapshot`, `edit`, `update` (`containerapp job update --yaml /dev/stdin`, value on stdin only
  **[doc]**; the fallback if the spike refuses `--yaml` is `az rest --method patch --body
  @/dev/stdin`), `settle` (poll `provisioningState`), `release` and `principal`. It reuses the app's
  helpers, made `pub(super)` in `containerapp.rs`: `secret_name, env_refs, upsert, fingerprint,
  diff_paths, is_opv_secret, policy_grants_get`, and the RBAC/policy half of `check_access`.
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
Key Vault references and env-routed config, as today (`src/domain/runtime.rs:44-46`). The spike
confirms `job show` returns no secret value (S-238 R6).

**Sync path and ordering (D2; recommended: jobs first, then the app, one apply).**
`AppWithJobs::apply(change, snap)`:

1. Re-read every resource and compare each one's own fingerprint with the snapshot. Any difference
   refuses with `TargetRefused{ChangedOutsideOpv{after_apply:false}}` naming that resource, as the
   app does today (`containerapp.rs:653-671`). Nothing is written.
2. For each job, compute **its own** sub-change: the pins whose job binding is not the target, the
   config whose digest differs, and the unbinds present. A job with an empty sub-change is not
   updated, so there is no write without a change. Edit the job document as `edit` does
   (`containerapp.rs:489-537`): per-version `opv-` secret names with `keyVaultUrl` and `identity`,
   and env `secretRef`s. Update, then settle (`provisioningState` leaves `InProgress`; `Failed`
   refuses; **[doc]**, S-238 W8). Once each job is settled, `runner.note` reports "container app
   job J pins NAMES; its next execution uses them".
3. Apply the app's sub-change as today and return its new revision. If the app has nothing to
   change, return its current `latestRevisionName`, and core confirms that revision is healthy (the
   existing no-change path, `sync.rs:1848-1852`).

Without `--deploy` nothing is applied, so jobs stay pending like the app (FR-29): the issue's
"every sync" means every deploying sync (D3). `--prune --deploy`: `AppWithJobs::release` releases
every job, then the app, before any Key Vault delete (`sync.rs:1938`). No resource keeps a
reference to an entry opv deletes (FR-32).

A job has no serving revision to protect. Superseded `opv-` secrets are removed in the same job
update, unless S-238 W7 shows that a running execution re-resolves secrets. Then the previous one is
kept until the next sync, like `serving_refs`.

**Partial failure** (no update is retried, NR-2):

| Where it stops | State | Error (all existing causes) | Next run |
|---|---|---|---|
| job k refused (Azure applied nothing) | KV versions written; jobs before k updated; app untouched | `Partial{done:["container app job J1 (pinned)", …], then: TargetRefused{subject: job k, why: Validation}}` (`cause/mod.rs:767-774`; render `render.rs:2113`) | re-pins job k and the app |
| job k outcome unknown | as above, job k unknown | `Partial{…, then: WriteOutcomeUnknown{job k}}`; `apply_reconciled` reads the merged bindings back. The app is not done, so `left(now)` is non-empty and the run stays unknown (`sync.rs:2061-2081`) | reconciles from what it reads |
| job settles `Failed` | job holds the new references | `TargetRefused{job k, Validation}` in `Partial` | re-applies |
| app refused or unknown after the jobs | jobs ahead of the app | `Partial{done: jobs, then: <app cause as today>}` | re-pins the app only |
| app revision unhealthy or timed out | jobs and the app's template at the new versions; old revision serves | today's `Refusal::Unhealthy` / `InProgress` (`sync.rs:1862-1880`); the job notes were already printed | as today |

Core's `partial()` merges an adapter's `Partial.done` list (`sync.rs:222-240`), so the adapter adds
no new cause. The only new catalog item is `ResourceKind::ContainerAppJob`
(`src/cause/subject.rs:245-265`), rendered "container app job" with the listing hint
`az containerapp job list` (`render.rs:810`, `:3771`). `NotFound{named_by:
azure.companion_jobs}` for a missing job copies `preflight.rs:445-452`.

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
- `job <J> identity access`: the same advisory verdict as `access` (`:689-708`), with the
  principal taken from the job. A missing system identity names `az containerapp job identity
  assign -g <rg> -n <J> --system-assigned` **[doc]**. A missing grant names the same `az role
  assignment create … --role "Key Vault Secrets User" --scope <vault id>` (or `set-policy`) as
  `containerapp.rs:887-890`, `:924-932`.

If S-238 W3 shows a job accepts an unreadable reference without failing the update (the app does
fail it, P1 Q14), the job's access check gates its update in `sync` (refuse with `MissingRight`,
`cause/mod.rs:699-707`). Advisory is not enough there. `DOCTOR_CHECKS` stays static for the "not
checked" lines (`preflight.rs:43-50`), and job line names are built per job.

## 5. Verify and drift (both options): what L1 changes

`verify_target` gets the observed version of a pinned target from `runtime.bindings()`
(`Binding::Pinned{version}`) and no longer reads it from `store.list()` (`delivery.rs:1304-1332`).
This is provider-neutral, goes through the `PinnedRuntime` port, and names no provider. It covers
Kubernetes too. After a sync without `--deploy`, the runtime still binds the old version while the
receipt records the new one. That name is `drifted_on_target` with `deployed: "staged"` (`:1346-1352`).
The target does not serve the recorded version (D4). With Option 2 the merged bindings make a
job's stale copy `drifted_on_target`, which is A2.

## 6. Security analysis

- **No new value path.** Job documents travel only on stdin (`--yaml /dev/stdin`, or `az rest
  --body @/dev/stdin`), exactly as the app's (`containerapp.rs:676-690`). Argv holds names and ids
  only, because `az` logs argv to `~/.azure/commands` (P1 Q12). The value-carrying `job secret set`
  and `--set-env-vars` are never called. On native Windows the write uses the existing named-pipe
  hand-off (`handoff.rs`).
- **Output.** `job show` and `job update` replies are parsed and never printed. The spike confirms
  they carry no secret value (S-238 R6/W2). A plain secret that opv does not own is sent back
  without its value. That depends on Azure keeping the value (the P1 Q5 analog). Until S-238 W5
  proves this for jobs, L2 refuses to update a job that has an unmanaged plain secret, rather than
  risk clearing it.
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

Cost: there is no pause between the job and the app inside one run (D3), and a standalone job is
not covered (D1). About 1,300 changed lines over five lanes, plus the spike.

## 8. Spike S-238 (owner runs it; marker values only)

Rules: every call carries `--subscription "$SUB" --only-show-errors`, with
`AZURE_EXTENSION_USE_DYNAMIC_INSTALL=no` (R7, NR-7). Values are only markers
(`opv-spike-marker-j*`), and they reach `az` on stdin. Each phase is one script file the owner runs
with one short command, and the outputs go to a scratch folder and are scrubbed before they reach
`tests/fixtures/azure/`. Variables: `RG=opv-spike-rg`, `KV`, `ENV` and `APP` from R2/R3, and
`JOB=opv-spike-job`. No Azure answer below is expected to choose between §3 and §4. They decide
whether a design is safe and what its checks are. D1 rests on §3's code facts.

**Read-only (R).**

| # | Command | Decides |
|---|---|---|
| R1 | `az version -o json`; `az containerapp job --help` | job commands are core, no extension prompt (Q13 analog) |
| R2 | `az resource list -g $RG -o json` | what P1 left (Key Vault, environment, app): reuse it, since an environment took ~19 min (P1) |
| R3 | `az containerapp env list -g $RG -o json`; `az keyvault show -n $KV -o json`; `az containerapp show -g $RG -n $APP -o json` | `$ENV`, vault id/URI, RBAC or policy model |
| R4 | `az containerapp job list -g $RG -o json` | expected empty; the list shape for `render.rs` hint |
| R5 | `az containerapp job update --help`; `az containerapp job identity --help` | `--yaml` on update exists (else `az rest` fallback); identity verbs for doctor text |

**Minimal writes in `$RG` (W), in order.**

| # | Command | Decides |
|---|---|---|
| W1 | `printf %s opv-spike-marker-j1 \| az keyvault secret set --vault-name $KV --name OPV-SPIKE-JOB --file /dev/stdin --encoding utf-8 --tags opv-managed=spike --query id -o tsv` | version v1 URI |
| W2 | `az containerapp job create -g $RG -n $JOB --environment $ENV --trigger-type Manual --replica-timeout 300 --replica-retry-limit 0 --parallelism 1 --replica-completion-count 1 --image mcr.microsoft.com/k8se/quickstart-jobs:latest --cpu 0.25 --memory 0.5Gi --mi-system-assigned -o json`, then `az containerapp job show -g $RG -n $JOB -o json` | job JSON shape: `configuration.secrets`, `template.containers[].env`, `identity.principalId`, `provisioningState`, the status fields for the job's `READ_ONLY` list, and whether there is an etag (Q8 analog) |
| W3 | `job show` → add `{name: opv-<h>, keyVaultUrl: <v1>, identity: system}` and env `SPIKE_VAL` `secretRef` → `az containerapp job update -g $RG -n $JOB --yaml /dev/stdin -o json` **before** any grant; record exit, duration, `provisioningState`; then `az containerapp job start -g $RG -n $JOB` and `az containerapp job execution list -g $RG -n $JOB -o json` | **Q14 analog**: refused at update (doctor stays advisory) or accepted and failing at execution (sync gates on job access, §4) |
| W4 | `az role assignment create --assignee-object-id <job principal> --assignee-principal-type ServicePrincipal --role "Key Vault Secrets User" --scope <kv id>`; `az role assignment list --assignee <principal> --scope <kv id> --include-inherited --include-groups -o json` | doctor's printed command works verbatim for a job principal; record shape |
| W5 | update the job (stdin) to add a plain secret `plain1` (marker j-plain) and env from it; then resend `show`'s document, in which `plain1` has no value; run an execution that prints `printf %s "$PLAIN1" \| wc -c` | **Q5 analog**: Azure keeps an unmanaged plain secret sent without value (else L2 refuses jobs that have one) |
| W6 | write v2 (`…-j2`, other length); update only `keyVaultUrl` → v2 (same secret name); start; read the byte count. Then rename the secret per version; start; read again | **Q6/Q16 analog**: each execution resolves the current template's pinned version; whether per-version names are needed (kept anyway for uniformity) |
| W7 | template command `sleep 120; printf %s "$SPIKE_VAL" \| wc -c`; start; while it runs, repin to v3; read that execution's count | whether a running execution keeps its start-time value, so superseded `opv-` secrets may go in the same update |
| W8 | `job show` every 5 s around W3/W6 updates | `provisioningState` values and timing during and after an update; whether the job's settle step must wait |
| W9 | `az containerapp job logs show -g $RG -n $JOB --execution <e> --container <c>` (else `az monitor log-analytics query` on `ContainerAppConsoleLogs_CL`) | how the spike reads the byte counts (counts only) |
| W10 | `az identity create -g $RG -n opv-spike-uami`; `az containerapp job identity assign -g $RG -n $JOB --user-assigned <id>`; `job show` | user-assigned principal under `identity.userAssignedIdentities` (the `principal()` path transfers) |
| W11 | `grep -rlF opv-spike-marker ~/.azure` | **Q12 analog**: no marker in `az`'s files |

**Cleanup (C).** `az containerapp job delete -g $RG -n $JOB --yes`; `az role assignment delete
--ids <W4 id>`; `az identity delete -g $RG -n opv-spike-uami`; `az keyvault secret delete
--vault-name $KV --name OPV-SPIKE-JOB` (soft delete; purging is the owner's call, D7); then re-run
R2 and diff it against the first R2.

**Record into `tests/fixtures/azure/`** (subscription, tenant, principal ids, IPs and hosts replaced,
as in P1): `containerapp-job-show.json` (W2), `containerapp-job-show-keyvault-ref.json` (after W4),
`containerapp-job-update.json`, `containerapp-job-show-inprogress.json` (W8, if seen),
`containerapp-job-execution-list.json` (W3), `containerapp-job-show-user-assigned.json` (W10), and
`containerapp-job-update-no-access.txt` (W3 exit code and scrubbed stderr, kept as evidence only;
the Azure strategy matches no phrases, `diagnose.rs:3-8`). Findings go to
`docs/design/spike-238-azure-jobs-findings.md` in the P1 table form.

## 9. Test plan

- **Adapter unit tests** (in `job.rs`, `FakeRunner` + the S-238 fixtures, the pattern of
  `containerapp.rs:1139-1200`): the snapshot reads `Pinned`/`Plain`/`Other`, the fingerprint
  ignores managed entries and read-only fields, the update sends the whole document on stdin with
  no value in argv, refused vs unknown read-back, the container rule, the user-assigned principal,
  and the access findings name the job and the command.
- **Composite tests** (in `companions.rs`): the merge rule (agree, a job differs, a job lacks a
  name), the per-resource sub-change, no update for an unchanged job, jobs before the app, the
  `Partial` done lists in §4's table, and release before delete.
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
- **Release gate:** e2e with `CI=true` and `cargo test` before the release PR.

## 10. Delivery lanes (≤ ~400 changed lines each, disjoint files)

| Lane | Files | Lines | After |
|---|---|---|---|
| S-238 | none in `src`; fixtures + findings doc | ~150 | owner `az login` |
| L1 pinned verify | `src/app/delivery.rs`, `src/app/pinned_tests.rs` | ~180 | none (parallel to S-238) |
| L2 job runtime | `src/adapters/azure/job.rs` (new), `containerapp.rs` (helper visibility only), `src/cause/subject.rs`, `src/cause/render.rs`, `mod.rs` (`pub mod job;`), job fixtures | ~400 | S-238 |
| L3 companions | `src/adapters/azure/companions.rs` (new), `config.rs` (field, parse, `same_target`, `open`), `mod.rs` (one line, after L2), `src/app/azure_tests.rs` | ~400 | L2 |
| L4 doctor/preflight | `src/adapters/azure/preflight.rs` | ~220 | L3 |
| L5 docs | `docs/configuration.md` (Azure section, deploy-identity rights), `docs/design/multi-cloud-targets.md` (§11 note) | ~80 | L3 |

L1 ∥ S-238 → L2 → L3 → L4 ∥ L5. `mod.rs` is the only file two lanes touch, and they touch it in
sequence. If L2 goes over 400 lines, it splits into a read side (show, snapshot, principal) and a
write side (edit, update, settle, release) in that order.

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

**D7. Approve the spike's writes in `opv-spike-rg`.** These are one job, one user-assigned identity,
one role assignment and marker versions of one Key Vault secret, all deleted at the end. The secret
stays soft-deleted for the vault's retention period unless you purge it (opv itself never purges).
