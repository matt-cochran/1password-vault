# Azure target: Container Apps Jobs beside their app (#238)

Status: post-spike, revised per the DESIGN-FMECA vet (`azure-jobs-fmeca.md`, "ready with
changes"), 2026-10-23. Nothing here is built. Open owner decisions: D4′, D7, D8, D9 (§11).

The Azure behaviour of jobs is verified in the spike (J1–J12 in `spike-238-azure-jobs-findings.md`,
recorded outputs in `tests/fixtures/azure/jobs/`). Claims about opv cite this branch after
`v0161/integrate` was merged into it (`e1a31ee5`), so they include the #241 verify fix. §12
answers the vet's findings that this revision does not take as written.

## 1. Problem, scope, non-goals

An Azure target names one Container App (`azure.container_app`, `src/adapters/azure/config.rs:48`,
`:121`). A common pattern runs a Container Apps **Job** beside each app, for example a pre-deploy
config-validation job whose template copies the app's env, including `secretRef:` variables. After a
rotation, `opv sync --deploy` re-pins the app (`containerapp.rs:643-717`), but the job keeps its old
Key Vault reference. `status` and `delivery verify` read only the app (`containerapp.rs:638-641`).

**Acceptance.**

- **A1.** A rotated key reaches the app and its jobs in one `opv sync <env> --deploy`.
- **A2.** `opv delivery verify` reports `drifted_on_target` when a job's copy differs.
- **A3.** `opv doctor` warns when a job's identity cannot read the Key Vault, and prints the
  role-assignment command, as for apps (`containerapp.rs:887-890`, `:924-932`;
  `preflight.rs:689-708`).
- **A4** (from J3). `opv sync --deploy` refuses to update a job whose identity provably cannot read
  the vault, before it updates any job or the app. The refusal names the job's identity (principal
  id) and the role or access policy it needs. Its Next is `opv doctor --env <env>`, which prints
  the exact `az role assignment create` or `az keyvault set-policy` command (A3). The command text
  is built in one place (§4, M3).

**Non-goals.** opv does not:
- start, wait for or schedule job executions;
- assign identities or create role assignments (it prints the command);
- support a job in another resource group or subscription than its app, or a job with no app (D1);
- add an `az` simulator (`tests/e2e/coverage.rs:74`);
- work around `az` or Azure defects;
- call `az containerapp job secret set` or `--set-env-vars` (values in argv, SR-3).

## 2. What opv does for an app today

- **Config.** The `AzureTarget` fields are at `config.rs:42-58`. `RawAzure` is
  `deny_unknown_fields` (`:116-129`), and identifiers are checked with `check_ident`
  (`:289-306`). `open` returns `Ports::Pinned{KeyVault, ContainerApp}` (`:465-492`).
- **Core's view.** Core sees only `PinnedRuntime` (`src/ports.rs:112-148`). Its doc says
  `check_access` "never gates a deploy" (`:119`). L3 amends that sentence: the app stays advisory
  (P1 Q14), and a job is gated inside `apply` (J3).
- **App runtime.**
  - Bindings and fingerprint: `container_index`, `strip`, `snapshot_from`
    (`containerapp.rs:341-371`, `:380-400`, `:443-486`).
  - Apply: a fingerprint re-check (`:653-671`), `edit` with per-version names (`:489-537`,
    `:989-996`), `serving_refs` (`:543-552`), and `update --yaml /dev/stdin` (`:676-690`).
  - Health: `:719-784`. Refused versus unknown read-back: `:247-278`.
  - Principal and access: `principal` (`:583-636`) and `check_access` (`:856-935`). Access
    recognises the three `READ_ROLES` by name (`:90-94`) and lists with `--assignee <principal>`
    (`:903-915`).

  All of these are `ContainerApp` methods bound to `container_app` and to "container app" wording.
- **Sync order.** Store writes and evidence (`src/app/sync.rs:1717-1764`), then bindings and drift
  (`:1774-1778`). Then apply when anything is pending (`:1845-1847`, `apply_reconciled`
  `:2052-2082`), otherwise the no-change path (`:1848-1852`). Then health (`:1860-1880`), the
  "deployed revision" line (`:1883-1891`), and release then delete (`:1938-1943`). No Azure update
  is retried (NR-2).
- **Guards.** `src/app` and `src/domain` name no provider (`src/app/mod.rs:2128-2145`,
  `:2313-2334`). `host::lost_call` callers are pinned to Fly, Kubernetes and `host.rs`
  (`tests/observed_seal.rs:42-77`). Job code reports failures through `az::failed` and
  `preflight::unusable` (`preflight.rs:280`), which take the runner's observation (seal at
  `observed_seal.rs:79-96`).
- **Verify after #241.** `verify_target` fills each expected name's version from `store.read`,
  which is Key Vault's current version (`src/app/delivery.rs:1313-1322`). Tests:
  `a_freshly_synced_azure_target_is_verified` and
  `a_key_vault_version_added_outside_opv_is_drift_on_verify` (`src/app/azure_tests.rs:709`,
  `:718`). Verify never reads the runtime's binding, so a stale app or job pin verifies as
  `verified`. **A2 needs L1′ (§5).**

## 3. Option 1: a job target (`azure.container_app_job`)

This would be a second target whose `azure` section names `container_app_job` instead of
`container_app`. A job that mirrors its app shares the app's vault and `env_name`. `same_target`
treats that as the same target (`config.rs:436-443`), and `check_shared_targets` refuses it, both
within one environment and across environments (`src/config.rs:2503-2552`). Each target prunes what
it manages (FR-8). The app target's prune releases only its own references (`sync.rs:1938-1943`),
so it would delete an entry the job still uses.

Option 1 therefore needs either a second vault holding copies of every secret, or relaxing FR-8
with cross-target prune coordination. It also needs a synthetic job "revision", because `apply`
returns one (`ports.rs:116`). Its only gain is syncing the job alone before the app (D1, D3).

## 4. Option 2: companion jobs on the app target (`azure.companion_jobs`)

```toml
[environments.prod.targets.api.azure]
# … existing fields …
companion_jobs = ["job-myapp-validate"]   # optional; same resource group and subscription
```

**Config.**
- `RawAzure` gains `#[serde(default)] companion_jobs: Vec<String>`. Each name passes
  `check_ident` (`config.rs:298-300`), and a duplicate is `FieldRule::DuplicateKey`.
- `azure.identity` applies to each job (D5). `system` means each job's own identity, which is a
  different principal from the app's.
- `azure.container` applies to each job (D6), with the app's rule and error
  (`containerapp.rs:353-366`).
- `same_target` also matches two targets that share a resource group and a companion job. That
  case gets its own `shared_target_error` text: "targets X and Y both list container app job J"
  (`config.rs:445-450`).
- `opv target add --azure-companion-jobs a,b` writes the TOML array (D9).

**Ways out** (documented in `docs/configuration.md`, L5).
- *Urgent rotation while a job is refused (M5).* Remove the job from `companion_jobs`, deploy the
  app alone, then re-add the job after its grant.
- *Removing a job for good.* opv forgets a job that is no longer listed. Before removing it,
  delete its `opv-` env entries and secrets, or keep it listed until a `--prune --deploy` has run.
  Otherwise a later prune deletes Key Vault entries the job still references, and its next
  execution fails silently (J3).

**Structure (M4: one engine, two resource descriptors; no core change for sync).**
- `resource.rs` (new) holds resource-generic functions extracted from `containerapp.rs`:
  `show`, `container_index`, `strip`, `snapshot_from`, `edit`, `principal`, `access`, and the
  refused/unknown read-back. They take a descriptor: the kind (app or job), the name and resource
  group, the `az` noun (`containerapp` or `containerapp job`), the read-only fields, and the
  identity-assign command.
- `ContainerApp` becomes a thin caller. `containerapp.rs`'s own tests and the P0 argv
  characterization must pass **unchanged**: that is the proof the extraction changed nothing.
- `job.rs` is the job descriptor plus what only a job has:
  - read-only fields `provisioningState`, `outboundIpAddresses`, `eventStreamEndpoint`,
    `systemData`; no etag (J2); `secrets: null` reads as empty (J2);
  - settle from the update reply's `provisioningState` (J11). `Failed` refuses, and `InProgress`
    (never observed) is polled like `settled_app`;
  - superseded `opv-` secrets removed in the same update (J9), so no `serving_refs`;
  - bindings from `job show` only, never from an execution, whose template names one
    `cappjob-<job>` secret (J10);
  - unmanaged secrets sent back without values (J6).
- `companions.rs` (new) holds `AppWithJobs: PinnedRuntime` over the app and its jobs. `open`
  returns it only when `companion_jobs` is non-empty; otherwise the target is byte-identical to
  today.

**Bindings (H1: the merge rule).** For each managed name:
1. The app and every job agree: report that binding.
2. They disagree: read the name's **current Key Vault version** with the value-free
   `keyvault secret show --name <n> --query id -o tsv`. This is the read `confirm_version` makes
   (`keyvault.rs:396-420`), factored out as `current_version` (L2c). The reply is the id, and no
   value is asked for or kept.
3. Report the binding of a resource **not** at that version: the app's if the app is among them,
   otherwise the first such job in config order. A name missing from any resource is absent.
4. If every resource is at the current version but they still disagree (for example on the secret
   name), report the app's binding.

A stale resource then yields `Pinned{old}`. Core re-pins it (`pinned_diff`, `sync.rs:2232-2273`),
flags drift (`:2265-2268`, `TargetDrift` via `status.rs:208-224`), and verify reports it after
L1′. Step 2 of apply then updates only the resources that are behind. When a disagreement is
resolved, `runner.note` names the resource and the two version ids (L2): "container app job J
binds NAME at …; Key Vault is at …". The fingerprint is the SHA-256 of the app's fingerprint
followed by each job's. `RawSpec` holds `{"app": …, "jobs": {…}}`, with no values (J7).

**Apply (D2: jobs first).** `AppWithJobs::apply(change, snap)`:

1. **Re-check.** Re-read every resource and compare its own fingerprint with the snapshot. Any
   difference is `TargetRefused{ChangedOutsideOpv}` naming that resource (`containerapp.rs:653-671`),
   and nothing is written.
2. **Sub-changes.** Compute each resource's own sub-change (pins not at target, config with a
   different digest, unbinds present). A resource whose sub-change is empty is not updated.
3. **Access gate (A4, D7; M1: Graph-free and three-valued).** It runs for each job that will be
   updated and will hold an `opv-` reference. The list is
   `role assignment list --assignee-object-id <P> --scope <vault id> --include-inherited
   --include-groups --fill-principal-name false -o json`. Unlike `--assignee` and the default
   `--fill-principal-name`, this form makes no Microsoft Graph query (az 2.91.0 help).
   - **Granted:** a `READ_ROLES` assignment at the vault or above, or an access policy with `get`.
     Go on.
   - **Missing (definite only):**
     - no system identity, or the user-assigned id is not attached;
     - an access-policy vault with no `get` for the principal;
     - the list succeeded and holds no assignment at the vault or above.

     The whole apply is refused before any update, with `MissingRight{grantee}` (Catalog).
   - **Undetermined:** the list is refused or fails after its retries, or it holds only roles opv
     does not know (custom roles, secret-scope grants). Go on, with `runner.note`: "could not
     confirm that container app job J's identity can read Key Vault K (<reason>); its next execution
     may fail; check with `opv doctor --env <env>`."

   The app's doctor argv stays as it is (P0). The shared `access` function takes the assignee form
   as a parameter. Switching the app to the Graph-free form is a separate, later change.
4. **Fresh grant (D8; J5).** If the deciding RBAC assignment's `createdOn` is under 10 minutes old,
   go on, and `runner.note` reuses the existing wording "a new grant can take a few minutes to
   apply" (`containerapp.rs:929-930`). It adds: "an execution of J started before HH:MM UTC may
   fail to read its secrets". This covers direct RBAC grants only; an access policy has no time,
   and a group grant's time is the group's (L9). The spike saw 28 s too early and 2 min 18 s
   enough. The 10 minutes is Azure's documented propagation bound (Adapted).
5. **Jobs.** For each job, in config order: edit (per-version names kept to share `secret_name`
   with the app, J8), update on stdin, and settle (J11). Then note "container app job J pins NAMES;
   its next execution uses them".
6. **App.** A non-empty app sub-change is applied as today, and apply returns the new revision. If
   only jobs changed, note "container app A unchanged; only its jobs changed" and return its current
   `latestRevisionName`. Core then takes the apply path (`pending` is non-empty, `sync.rs:1845`),
   waits for that revision's health, and prints "deployed revision <current>: NAMES"
   (`:1883-1891`). The note comes first, so the line is not misread (L1).

Without `--deploy` nothing is applied, and jobs stay pending like the app (FR-29, D3).
`--prune --deploy` calls `AppWithJobs::release` on every job, then the app, before any Key Vault
delete (`sync.rs:1938`, FR-32).

**Partial failure** (no update is retried, NR-2). "Next run" follows the merge rule above.

| Stops at | State | Error | Next run |
|---|---|---|---|
| access gate, Missing | KV versions written (not live); nothing updated | `MissingRight{grantee: job k identity}` | after the grant: all resources agree on the old version, so it re-pins and updates all |
| job k refused (Azure applied nothing) | jobs < k at current; job k and app old | `Partial{done: jobs < k, then: TargetRefused{job k, Validation}}` (`cause/mod.rs:767-774`) | the app is behind and is reported. It updates job k and the app only |
| job k outcome unknown | jobs < k at current; job k unknown; app old | `Partial{…, then: WriteOutcomeUnknown{job k}}`. The read-back sees the app behind, so `left(now)` is non-empty and the run stays unknown (`sync.rs:2061-2081`) | updates whatever is behind: the app, and job k if it did not land |
| app refused or unknown, after the jobs | jobs at current; app old (or unknown) | `Partial{done: jobs, then: <app cause as today>}`. If the app landed, the read-back finds all agreeing at current and reports "applied" correctly | re-pins the app only |
| app revision unhealthy or timed out | app template and jobs at current; old revision serves | as today (`sync.rs:1862-1880`) | as today: no-change path, health re-checked |

There is no row for a job that settles `Failed`. That state was never observed (J11). The job's
bindings would already be at the target, so the next run would not touch it. Preflight warns on a
`Failed` job, as it does for the app.

**Catalog (M3).** The adapter's `Partial` reaches the person unchanged, as the GitHub adapter's
does (`src/adapters/github/gh.rs:510-529`), with Next `plan_read` for `scope: None`. Two
provider-neutral changes:

- **`ResourceKind::ContainerAppJob`** (`src/cause/subject.rs:245`): words "container app job"
  next to `render.rs:810`, and listing hint `az containerapp job list` next to `:3771`.
- **`MissingRight` gains `#[serde(skip_serializing_if = "Option::is_none")] grantee:
  Option<Principal>`** (`cause/mod.rs:699`).
  - The coverage gate drops a field whose attribute starts `#[serde(skip`
    (`tests/e2e/coverage.rs:2381-2392`), so the 12 e2e snapshots and the JSON contract stay as
    they are.
  - When `grantee` is set, `Action::Grant` and `grant_words` use it instead of `seen.principal()`
    (`render.rs:3598-3614`). The job's grantee is `Principal::AppIdentity{name: "container app
    job J (principal P)"}` (`subject.rs:280`; no production code builds it today).
  - The cause is built from opv's own `role assignment list` reply through
    `preflight::unusable`.
  - Files: the six production constructors that add `grantee: None` are
    `src/adapters/onepassword.rs:697`, `onepassword_diagnose_items.rs:107`,
    `azure/preflight.rs:379`, `kubernetes/diagnose.rs:156`, `kubernetes/mod.rs:220` and
    `cause/codes.rs:628`. The exhaustive pattern `render.rs:2059` adds the field. Tests:
    `onepassword_diagnose_items_tests.rs:200,223,240`, `render_tests.rs:372,3040,4126` and
    `app/ready_tests.rs:52`.
- `NotFound{named_by: azure.companion_jobs}` for a missing job copies `preflight.rs:445-452`.

**Preflight and doctor.**
- `preflight::run` (`preflight.rs:68-95`) shows each job after the app. A missing job is
  `NotFound`; under `Mutate` an `InProgress` job is waited for (`settled_app`, `:476-510`); `Failed`
  is a warning.
- Doctor (`:514-557`) adds two lines per job:
  - `container app job <J>`;
  - `job <J> identity access`. This is a warning built with the step-3 result. Missing prints
    `az containerapp job identity assign -g <rg> -n <J> --system-assigned` (J1), or the role or
    policy command of `containerapp.rs:887-890`, `:924-932`, which worked for a job principal
    (J4). Undetermined says which read could not decide. A grant under 10 minutes old adds the
    step-4 note.
- `status` and `plan` print the access result as a `warn` line. `DOCTOR_CHECKS` stays static
  (`preflight.rs:43-50`); job line names are built per job.

**Deploy identity's rights** (L5 docs; `docs/configuration.md:388` today names only Key Vault
Secrets Officer and Contributor on the app). It also needs:
- Contributor on each companion job;
- `Microsoft.Authorization/roleAssignments/read` at the vault scope, for the gate.

Key Vault Secrets Officer's control-plane actions are documented to include
`Microsoft.Authorization/*/read`. That is Adapted, and follow-up F1 (§8) checks it.

## 5. Verify and drift: L1′ (H2)

L1′ is an overlay on #241, not a replacement. After #241 fills Key Vault's current version
(`delivery.rs:1313-1322`), `verify_target` reads `runtime.bindings()` once for a `Ports::Pinned`
target. For each expected name with recorded evidence:

- **Binding at another version.** If the binding is `Pinned` at a version other than the
  evidence's `store_version`, that version becomes `listed_version`, so the name is
  `drifted_on_target` (`src/domain/delivery.rs:362-364`). If Key Vault's current version equals the
  recorded one, the name is also marked `pending`, so `deployed` reads `"staged"`
  (`delivery.rs:1359-1366`).
- **No binding.** `listed_version` is `None`, so the name is `missing_on_target`.
- **`Plain` or `Other` binding.** #241's result stands.

Both #241 tests stay. The overlay is provider-neutral, uses the `PinnedRuntime` port, and covers
Kubernetes too. Behaviour change (D4′): right after a sync without `--deploy`, verify reports the
rotated names as `drifted_on_target` with `deployed: "staged"`, where #241 alone says `verified`.
With Option 2, the merged bindings make a stale job `drifted_on_target`, which meets A2.

## 6. Security analysis

- **No new value path.**
  - Job documents travel on stdin only (`--yaml /dev/stdin`, or the Windows pipe in
    `handoff.rs`), as the app's do (`containerapp.rs:676-690`). Argv holds names and ids (P1 Q12).
  - The merge rule's extra read is the existing `--query id -o tsv` form: no value is asked for
    or kept (I2-1).
  - `values_never_reach_argv` and `sync_output_holds_no_value` extend to job documents (§9).
- **Output.** Replies are parsed, never printed, and held no value (J7). Unmanaged secrets go back
  without values, and Azure keeps them (J6).
- **Silent failure closed.** Azure accepts an unreadable reference on a job, and a failed
  execution gives no reason (J3, J10). The gate (step 3) turns a provable lack of access into a
  refusal before anything is deployed.
  - **Evidence (M2).** That W3 and W4b failed for lack of access is **Adapted**. Their reference
    and length check were identical to W5's, which passed after the grant took effect, but W5's
    template also added a plain secret and a second check, and executions give no reason. The gate
    does not rest on that inference. It enforces Container Apps' documented prerequisite that the
    identity named on a Key Vault reference can read the secret, which Azure enforces synchronously
    for apps (P1 Q14). Because it refuses only on definite negatives, a wrong inference cannot cause
    a false refusal.
- **Permissions.** 1Password vault access stays the only permission system opv adds. Azure rights
  remain the operator's (§4 deploy identity). opv creates no grants or identities. A job's system
  identity is a new principal, and Key Vault Secrets User at vault scope gives it the same breadth
  the app has today.
- **CI** reads 1Password and delivers. It never writes values to 1Password; unchanged.

## 7. Recommendation

**Option 2 (`companion_jobs`), jobs updated first inside the app's `--deploy`, with the gate and
L1′.**
- It matches "the job runs with its app's environment": the same managed set, vault and template.
- It needs no FR-8 relaxation and no synthetic revision.
- Core needs no change for sync, status or drift: everything sits behind `PinnedRuntime`, and the
  merge rule keeps a stale resource visible to core.
- There is one placement and one receipt.

The vet confirmed the choice. Its two High findings (the merge rule and L1) are fixed above.
Cost: no "job only, then app" pause (D3), no standalone job (D1), and about 1,450 changed lines in
seven lanes (§10).

## 8. Spike S-238: done; one read-only follow-up

The spike ran on 2026-10-23 with cleanup, and the resource group matched its baseline afterwards
(findings J1–J12).

| Finding | Effect here |
|---|---|
| J1 `job update --yaml` and job identity commands are core | stdin update; no `az rest` fallback |
| J2, J12 no etag, `secrets: null`, lower-case `resourcegroups` | job read-only fields; null as empty; case-insensitive key (`containerapp.rs:603`) |
| J3 an unreadable reference is accepted; only the execution fails | gate (step 3); evidence Adapted (§6) |
| J4 doctor's grant command works for a job principal; the list has `createdOn` | step 3 and step 4 data |
| J5 a listed grant took between 28 s and 2 min 18 s to work | note, no wait (D8) |
| J6 an unmanaged plain secret is kept | the pre-spike refusal rule is dropped |
| J8 repointing `keyVaultUrl` alone reaches the next execution | per-version names kept only to share code |
| J9 a running execution keeps its start values | superseded secrets removed in the same update |
| J10 executions reference `cappjob-<job>` | bindings from `job show` only |
| J11 updates return settled (20–29 s) | settle from the reply |

**F1 (read-only, before L2b).** J4 ran as a person. Repeat its list as the sandbox's *deploy
service principal*, signed in through a private `AZURE_CONFIG_DIR`, using the app's
already-granted principal:

1. `az role assignment list --assignee-object-id <app principal> --scope <vault id>
   --include-inherited --include-groups --fill-principal-name false -o json`
2. The same with `--assignee <app principal>`.

What it decides: (1) answering proves the gate's read works with the documented deploy rights
(otherwise L5 names the extra role); (2) failing confirms the Graph dependency M1 avoids. Record (1)
into `tests/fixtures/azure/jobs/` after redaction.

## 9. Test plan

- **Engine extraction (L2b, L2c).** `containerapp.rs` tests and the P0 argv characterization pass
  unchanged.
- **Job unit tests** (`job.rs`, `FakeRunner` with `tests/fixtures/azure/jobs/`):
  - snapshot and `secrets: null`; read-only fields;
  - stdin-only update; an unmanaged plain secret sent back without its value;
  - settle from the reply;
  - refused and unknown read-back;
  - the `resourcegroups` key;
  - the access result for each Granted, Missing and Undetermined case, with the Graph-free argv;
  - the `createdOn` note;
  - `current_version` asks only for `--query id`.
- **Composite tests** (`companions.rs`):
  - the merge rule: agree; job ahead; app ahead; name missing; several stale;
  - the per-resource sub-change; the gate refusing with no update sent;
  - the "app unchanged" note;
  - release before delete;
  - every row of the partial-failure table followed by a **second run**, which must update exactly
    the resources that are behind (H1).
- **End to end** (`src/app/azure_tests.rs` `Sim`). Extend it with jobs:
  - A1;
  - job drift in `status` and `--fail-on-drift` exit 8;
  - the interruption matrix over job calls (as `:918`, `:956`);
  - `values_never_reach_argv` and `sync_output_holds_no_value` on job documents;
  - prune leaves no job reference;
  - a target without `companion_jobs` issues exactly today's argv.
- **Verify (L1′).** Both #241 tests are kept. Add: a binding moved → `drifted_on_target`;
  unbound → `missing_on_target`; a sync without `--deploy` → `drifted_on_target` with
  `deployed: "staged"`. Then, in L3, A2 with a job.
- **Catalog** (`render_tests.rs`): `grantee` Some names that principal in action and words; `None`
  is byte-identical; the e2e snapshots are unchanged.
- **Doctor** (`preflight.rs` tests from `:729`): the job lines, A3 text, Undetermined text.
- **Config:** the companion list, duplicate names, shared-job `same_target` text, the D9 flag.
- **Release gate:** e2e with `CI=true` and `cargo test` before the release PR.

## 10. Delivery lanes (vet order)

| Lane | Owned files | Lines | After |
|---|---|---|---|
| L0 merge | none (`v0161/integrate` into the 0.17 integration branch; done on this branch as `e1a31ee5`) | 0 | — |
| L1′ verify overlay | `src/app/delivery.rs`, `src/app/azure_tests.rs` | ~100 | L0 |
| L2a catalog | `src/cause/{mod,subject,render,codes}.rs`, `render_tests.rs`; `grantee: None` in `src/adapters/onepassword.rs`, `onepassword_diagnose_items{,_tests}.rs`, `kubernetes/{diagnose,mod}.rs`, `azure/preflight.rs`, `src/app/ready_tests.rs` | ~120 | L0 (∥ L1′) |
| L2b engine, read side | `src/adapters/azure/resource.rs` (new), `containerapp.rs` (thin caller), `job.rs` (new; read side), `mod.rs` | ~250 | L2a, F1 |
| L2c engine, write side | `resource.rs`, `job.rs` (edit, update, settle, release), `keyvault.rs` (`current_version` from `confirm_version`) | ~250 | L2b |
| L3 companions | `companions.rs` (new), `config.rs` (field, parse, `same_target`, error text, `open`, D9 flag), `mod.rs`, `src/ports.rs` (`:119` doc), `src/app/azure_tests.rs`, `tests/e2e/expected/surface.json` (the flag) | ~400 | L2c, L1′ |
| L4 doctor and preflight | `src/adapters/azure/preflight.rs` | ~200 | L3 |
| L5 docs | `docs/configuration.md` (field, deploy rights, ways out), `docs/design/multi-cloud-targets.md` (§11 note) | ~100 | L3 (∥ L4) |

Order: L0 → L1′ ∥ L2a → L2b → L2c → L3 → L4 ∥ L5.
- Shared files run in sequence: `azure_tests.rs` (L1′ → L3), `preflight.rs` (L2a → L4), `mod.rs`
  (L2b → L3).
- Before L2a starts, check that no other open 0.17 lane edits the Kubernetes or 1Password files
  it touches.

## 11. Decisions for the owner

**D1. Jobs listed on the app's target (Option 2), not one target per job (Option 1).**
- *In practice:* the job follows its app. There is one sync and one receipt, and the job is updated
  whenever the app is deployed. Option 1 would make a job its own destination, but opv refuses two
  targets on one vault and naming scheme, because each would delete what the other uses.
- *Recommend* Option 2.
- *Cost:* no job-only sync, and a job without an app is not covered.

**D2. Within one deploy, update the jobs before the app.**
- *In practice:* a validation job already holds the new values when the app rolls out. If any step
  fails, the next run finds whatever is behind, the app included, and updates only that.
- *Recommend* before.
- *Cost:* when the app's new revision fails, the jobs run on the new values while the old app
  revision serves, until it is fixed.

**D3. Jobs change only on `--deploy`.**
- *In practice:* a sync without `--deploy` changes nothing live, for jobs and the app alike.
- *Recommend* deploy-only.
- *Cost:* no built-in "validate first, then deploy" pause. Run the job after the deploy, or ask
  for Option 1 later.

**D4′. `delivery verify` also checks what the app and its jobs actually point at (open).**
- *In practice:* today (after #241) verify compares the Key Vault version with the receipt, so an
  app or job still pointing at an old version passes. With L1′, verify reports such a name as
  `drifted_on_target`. That includes the time between a sync without `--deploy` and the deploy,
  where it shows `deployed: "staged"`. This applies to Azure and Kubernetes.
- *Recommend* yes. It is the only way A2 holds.
- *Cost:* about 100 lines in core. Pipelines that verify after a non-deploying sync see
  "changed / staged" instead of "verified".

**D5. Jobs use the app's `azure.identity` setting.**
- *In practice:* `system` means each job's own identity. A user-assigned id must be attached to
  each job.
- *Recommend* yes.
- *Cost:* a job with a different user-assigned identity than its app is not supported.

**D6. `azure.container` also picks the job's container.**
- *Recommend* yes, with the same rule.
- *Cost:* a differently named job container needs a later per-job table.

**D7. Refuse a deploy when a job's identity provably cannot read the vault (open).**
- *In practice:* Azure accepts such a job and its next run fails without a reason. opv checks
  first. When the answer is certainly "no access", it stops before changing anything and names the
  identity and role (`opv doctor` prints the command). When it cannot tell, it deploys and warns.
  The way out for an urgent rotation is to remove the job from the list for one deploy.
- *Recommend* refuse on certain "no", warn on unknown.
- *Cost:* two reads per job per deploy. The deploy identity needs read access to role assignments
  on the vault. A job with a custom role passes with a warning, unchecked.

**D8. Right after a new grant, warn instead of waiting (open).**
- *In practice:* a grant shows at once but took up to about 2 minutes to work, and opv cannot test
  it as the job. Under 10 minutes old, the deploy goes on with a line saying that a run started
  before a given time may fail.
- *Recommend* warn.
- *Cost:* such a run can still fail. The note covers direct role grants only.

**D9. `opv target add --azure-companion-jobs a,b` in 0.17.x (open).**
- *In practice:* one comma-separated option, written as the TOML list. This is safe because job
  names cannot contain commas (the identifier rule), and the file is checked when it loads.
- *Recommend* the flag, in L3.
- *Cost:* about 30 lines, plus one new flag in the CLI surface snapshot. Without it, the list is
  edited by hand.

### 11.1 Owner decisions (2026-10-23)

All recommendations approved: D1 (Option 2, `companion_jobs` on the app target), D2 (jobs before the app), D3 (jobs change only on `--deploy`), D4′ (verify checks the app's and jobs' bindings, on Azure and Kubernetes), D5 (jobs use the app's `azure.identity`), D6 (`azure.container` picks the job's container), D7 (refuse a job update when its identity certainly cannot read the vault; warn when undecidable), D8 (warn, not wait, after a grant under 10 minutes old), D9 (`--azure-companion-jobs a,b` on `opv target add` and `propose target`). Ships in 0.17.x, after 0.17.0.

## 12. Vet responses (findings not taken as written)

- **Citation corrections in vet item 7** (`render.rs:2113` → `:4089`, `:3771` → `:3709`): **not
  applied.** The vet read those lines at `291c0b16`. This document cites the branch after the
  merge, where `render.rs:2113` is the `Refusal::Validation` words of `TargetRefused` and `:3771` is
  `ResourceKind::ContainerApp => vendor("az", &["containerapp", "list"])` (checked at `e1a31ee5`).
  The citation base is now stated in the header. The vet's `Partial` render location (`:4089`) is
  correct and is not cited here.
- **`MissingRight` constructor list** (vet M3/L2a): **adjusted.** `kubernetes/config.rs:1690` is a
  test `matches!` pattern with `..`, after `#[cfg(test)]` at `:946`, so it needs no change. The
  production sites are the six constructors plus the exhaustive pattern `render.rs:2059` (§4
  Catalog): seven files.
- **I2-4, app argv:** the app's doctor keeps `--assignee` in this work, to leave P0 untouched. The
  shared `access` takes the form as a parameter, and moving the app to the Graph-free form is a
  separate change.

Everything else in `azure-jobs-fmeca.md` is taken as written: H1, H2, M1–M5, L1–L3, L5, L6, L9,
L10, I2-1–I2-3.
