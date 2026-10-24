# DESIGN-FMECA vet: Azure Container Apps Jobs (#238), `docs/design/azure-jobs.md`

Reviewer: independent; did not write the design or run the spike. Date: 2026-10-23. Method: the
owner's DESIGN-FMECA procedure (persona, objective, constraints, code-change-proposal
requirements, three phases, output format, verification checklist), applied as written.

Owner question: **is this design secure and actually feasible?**

**Short answer.** The choice is right: companion jobs on the app target (Option 2), updated
jobs first inside `--deploy`, with an access gate before any job update. It needs no FR-8
relaxation. It stays behind `PinnedRuntime`, and it adds no value path: documents go on stdin
only, and no job reply held a marker (J7). The spike is sound and the fixtures are clean. Two
parts do not work as written, and both fixes are small:

- **The bindings merge rule hides a stale app (High).** On disagreement it reports "the first job
  whose binding differs from the app's". A jobs-first run that stops after updating a job leaves
  that job ahead of the app. The next run then sees the job's binding, which is the target
  version, and decides nothing needs changing. The app stays on the old version, `status` shows
  no drift, and the run exits 0. If the job's write outcome was unknown, the read-back
  (`apply_reconciled`) reports "the update was applied" and confirms the *old* app revision as
  deployed. The design's own partial-failure table assumes the opposite ("re-pins the app
  only").
- **A2 is not met, and L1 is obsolete.** #241 is fixed on `v0161/integrate` by reading Key
  Vault's current version (`store.read`), not the runtime's binding. A job pinned to an old
  version therefore verifies as `verified`. L1 as designed (read the version from
  `runtime.bindings()` *instead of* the store) would also undo #241's test that a Key Vault
  version added outside opv is drift. L1 must become a small overlay on top of #241, built after
  `v0161/integrate` is merged into the 0.17 line.

There are four Medium findings:

- **The gate's read can fail under a CI service principal.** `role assignment list --assignee`
  queries Microsoft Graph. The gate must also not refuse on a result it cannot interpret.
- **The W3 inference holds, but only as Adapted evidence.**
- **`MissingRight.grantee` touches more files than lane L2a lists**, needs a
  serialization rule, and does not by itself print the `az` command that A4 promises.
- **`job.rs` cannot reuse the app's code by "helper visibility only".**

After the required changes no High or Medium risk remains. **Verdict: ready with changes.** No
owner principle is violated. One owner decision is re-opened (D4, now about what verify reports
after a sync without `--deploy`).

Evidence levels: **Proven** (standard practice, or opened and shown here), **Adapted**
(reasonable, not proven in this setting), **Speculative** (assumed, not validated). opv paths are
relative to `/home/mc/.cache/lanes/opv-0170-design-238` (HEAD `35b8f6a2`). The design cites `dev`
at `291c0b16`. Between the two, `src/adapters/azure/*`, `src/app/sync.rs`, `src/app/delivery.rs`
and `src/ports.rs` are unchanged (`git diff --stat 291c0b16 HEAD`), so those were checked at HEAD.
`src/cause/{mod,render,subject}.rs` and `src/config.rs` changed, so those were checked at
`291c0b16` (`git show 291c0b16:<path>`) and at HEAD where a line matters. The #241 fix was read at
`v0161/integrate` (`8b94fa64`), which is **not** an ancestor of this lane's HEAD or of `dev`.

---

## 0. Claims checked against the code and the evidence

| Design claim (§) | Verdict | Evidence |
|---|---|---|
| `AzureTarget` fields; `RawAzure` is `deny_unknown_fields`; `check_ident` on ids (§2) | **Holds** | `src/adapters/azure/config.rs:42-58`, `:116-129`, `:289-306` |
| `open` returns `Ports::Pinned{KeyVault, ContainerApp}` (§2) | **Holds** | `config.rs:465-492` |
| `PinnedRuntime` methods (§2) | **Holds**. Its doc also says `check_access` is "Advisory only (R6): used by doctor, **never gates a deploy**". The design adds a deploy gate built from the same reads and does not mention the doc or R6 | `src/ports.rs:112-148`, `:119` |
| Snapshot, fingerprint, edit, serving refs, per-version names, stdin update (§2) | **Holds** | `containerapp.rs:341-371`, `:380-400`, `:443-486`, `:489-537`, `:543-552`, `:989-996`, `:676-701`; module doc `:12-15` |
| Refused vs unknown read-back (§2) | **Holds** | `containerapp.rs:247-278` |
| Sync order: KV write, evidence, bindings, `apply_reconciled`, health, release then delete (§2) | **Holds** | `src/app/sync.rs:1717-1764`, `:1774-1778`, `:1845-1847`, `:2052-2082`, `:1860-1880`, `:1938-1943` |
| Doctor lines and the advisory access line (§2) | **Holds** | `preflight.rs:43-50`, `:514-557`, `:689-708` |
| `check_access` resolves the principal and names `set-policy` / `role assignment create` (§2) | **Holds**, but it recognises the three built-in roles **by name** only (`READ_ROLES`). It lists with `--assignee <principal>` and the default `--fill-principal-name true`. az 2.91.0 `role assignment list --help` (run here) says both query **Microsoft Graph**, and that `--assignee-object-id` exists "to bypass Microsoft Graph query in case the logged-in account has no permission". The spike's J4 ran as a user (`createdByType: User`), not as a CI service principal | `containerapp.rs:90-94`, `:583-636`, `:856-935` (args `:903-915`) |
| Guards: `src/app`/`src/domain` name no provider (§2) | **Holds**. `core_modules_name_no_provider` checks `src/app`, `src/domain`, `src/config*`, `src/config.rs`, `config_store.rs` and `config_edit.rs`, and exempts `init.rs` and `*_tests.rs`. So extending `src/app/azure_tests.rs` is allowed. `use_cases_name_no_target_adapter` matches `fly::` only. A provider-neutral `src/app/delivery.rs` change passes both | `src/app/mod.rs:2128-2145`, `:2280-2334` |
| No Azure `host::lost_call` caller; job calls add none (§2) | **Holds**. The J7 seal pins the callers to exactly `fly/mod.rs`, `kubernetes/mod.rs` and `host.rs`. `job.rs`/`companions.rs` must keep using `az::failed`/`az::take_failure` | `tests/observed_seal.rs:42-77`; `rg lost_call src` |
| `MissingRight` built from opv's own reply through `preflight::unusable`, as `ChangedOutsideOpv` is (§4 Catalog) | **Holds**. `unusable` takes the runner's observation of the latest call (`take_unusable_reply` or `take_observed`), so the seal (`only_the_runner_builds_an_observed`) is respected | `preflight.rs:277-291`; `containerapp.rs:657-671`; `tests/observed_seal.rs:79-96` |
| `MissingRight`'s grant action takes the principal from `seen` (§4) | **Holds**: `Action::Grant{principal: seen.principal()}` and `grant_words(grant, seen.principal(), …)`. But `grant_words` renders **words** ("ask an owner to grant the role … on … to app identity …"), never an `az role assignment create` command. So the refusal alone does not "name the grant command" (A4). Its Next is `doctor`, which does print the command | `src/cause/render.rs:3598-3614` (HEAD), `:848-889` |
| `Principal::AppIdentity` exists and no production code builds it (§4) | **Holds** (rendered as "app identity {name}") | `src/cause/subject.rs:280-282`; `render.rs:775` |
| "`None` keeps every existing message byte-identical" (§4) | **Text: holds. JSON: unspecified.** 12 committed e2e snapshots carry a `MissingRight` subject. The coverage gate identifies a variant by its exact field set, read from `src/cause/mod.rs`, and drops a field whose attribute line starts `#[serde(skip`. So `grantee` needs `#[serde(skip_serializing_if = "Option::is_none")]`. Otherwise every `MissingRight` document gains `"grantee": null`, and those snapshots and the JSON contract change | `tests/e2e/coverage.rs:2381-2392`, `:2448-2475`; `rg -l '"right"' tests/e2e/snapshots` (12) |
| L2a touches `src/cause/*` only (§10) | **Incomplete**. Adding a field means adding `grantee: None` at every constructor: `adapters/onepassword.rs`, `onepassword_diagnose_items.rs`, `kubernetes/{mod,diagnose,config}.rs`, `azure/preflight.rs`, `cause/codes.rs`, plus tests (`app/ready_tests.rs`, `onepassword_diagnose_items_tests.rs`, `cause/render_tests.rs`) | `rg 'MissingRight \{' src` |
| `ResourceKind` list and hints (§4) | **Holds**; only `render.rs` matches on it exhaustively. **Two citations are wrong**: `render.rs:2113` is `Guard::NotManagedByOpv`, not the `Partial` render (that is `:4089` at HEAD), and the listing hint is `:3709` at `291c0b16`, not `:3771` | `git show 291c0b16:src/cause/render.rs` `:810`, `:2111-2115`, `:3709`, `:3769-3773` |
| Core's `partial()` merges an adapter's `Partial.done` (§4) | **Holds**, but the apply path does not go through it: `apply_reconciled(…)?` returns the adapter's own `Partial` (`scope: None`). The GitHub adapter has the same precedent, and `scope: None` renders `plan_read` as Next | `sync.rs:222-245`, `:1847`; `src/adapters/github/gh.rs:510-529`; `render.rs:4089-4120` |
| `same_target` / `check_shared_targets` refuse a second target on the same vault and template (§3) | **Holds** (within and across environments) | `config.rs:436-443`; `git show 291c0b16:src/config.rs` `:2504-2549` |
| `Binding` and `pinned_diff`/drift behaviour (§4) | **Holds**: a name is current only if it is `Pinned` at the target version. Drift is flagged only for a `Pinned` at a version other than the store's current one. `Other` re-pins but is never drift | `src/domain/runtime.rs:23-31`; `sync.rs:2231-2273` |
| **Merge rule** "first job whose binding differs from the app's" → "core then works unchanged" (§4) | **Does not hold** (H1). With a job ahead of the app, the merged binding equals the target, `pin` stays empty, the no-change path runs, and the app is never re-pinned. The read-back after an unknown job write takes `left(now)` as empty and confirms the app's **old** `latestRevisionName` | `sync.rs:2254-2272`, `:1845-1852`, `:2066-2081` |
| "When nothing changes for the app, core confirms the current revision (the existing no-change path, `sync.rs:1848-1852`)" (§4 step 6) | **Wrong path**. If only a job changed, `pending` is non-empty, so core takes the apply path. It then prints `deployed revision <unchanged app revision>: NAMES` and sets `report.deployed` | `sync.rs:1845-1847`, `:1883-1891` |
| `delivery verify` gap (§2, D4, L1) | **True at `291c0b16`; fixed on `v0161/integrate` in a different way.** The fix fills each expected name's version from `store.read` (Key Vault's current version) and drops the value. Its tests: `a_freshly_synced_azure_target_is_verified` and `a_key_vault_version_added_outside_opv_is_drift_on_verify`. A runtime binding is never read, so a stale job (or app) pin verifies as `verified`: **A2 is not met**. L1's "read from `runtime.bindings()`" in place of the store would turn the second test into `verified` | `git show v0161/integrate:src/app/delivery.rs` `:1295-1330`; `…:src/app/azure_tests.rs` `:709-730`; `src/domain/delivery.rs:352-366` |
| "After a sync without `--deploy` … `drifted_on_target` with `deployed: staged`" (§5) | **Not under the #241 fix**: Key Vault's `list` sets `pending: false`, so `deployed` reads `"deployed"`. It would hold only with the binding overlay (H2) | `src/adapters/azure/keyvault.rs:161-176`; `v0161 delivery.rs` `deployed` match |
| Fault matrix / `UNREACHABLE` (brief) | **Holds**. The gate is per variant. Every cause the design raises (`MissingRight`, `TargetRefused`, `Partial`, `NotFound`, `WriteOutcomeUnknown`, `Unavailable`) is an existing variant that other cells reach. Azure has no simulator (`HandoffPipeContested` reason), so no new cell is discovered. No `UNREACHABLE` entry is needed **if** `grantee` is skip-serialized (above) | `tests/e2e/coverage.rs:1-10`, `:44-104` |
| Deploy-identity rights must be documented (§6) | **Holds, and more is needed**: `docs/configuration.md:388` names only "Key Vault Secrets Officer on that vault and Contributor on that Container App". The gate also needs `Microsoft.Authorization/roleAssignments/read` at vault scope. To my knowledge the Key Vault data roles include `Microsoft.Authorization/*/read` (Adapted; check). It also needs Contributor on each job | `docs/configuration.md:388` |
| "Doctor's existing 'scope broader than needed' wording applies" (§6) | **No such wording exists** in `src/` | `rg -i 'broader' src` |
| `opv target add --azure-…` for the new field | **Not covered**: `InitField` writes TOML basic strings only, so a list field needs an `init_lines` extension or a hand edit | `src/provider.rs:211-240` |

### 0.1 Spike evidence re-read (raw logs, not copied)

`out/w-writes.log` and `out/results.txt` match the findings table: W3 accepted (exit 0, 21 s), W3
and W4b executions `Failed`, W5–W7 `Succeeded`, W11 0 marker hits, and the resource group back to
its baseline. Two refinements:

- **J3/J5 "the same template succeeded".** Not exactly. W5's document adds `plain1` and a second
  length check (`W3-doc.json` vs `W5-show-with-plain.json`). The Key Vault reference
  (`opv-w3` → v1, `identity: system`) and the `SPIKE_VAL` length check are **identical**, and the
  failed executions have no `endTime`, which fits a replica that never started. Attributing W3/W4b
  to missing access is therefore well supported but still **Adapted** (two samples, no reason
  field). The gate does not depend on that inference (§Phase 3).
- **J4 ran as a person.** The grant listing was read by the spike user. A CI service principal
  without Graph rights is untested (M1).

---

## Phase 1 — Architecture Assessment

| Component | Purpose | Classification | Justification | Simpler Alternative | Risk if Removed |
|---|---|---|---|---|---|
| C1. `azure.companion_jobs` on the app target (Option 2) | Jobs follow their app's managed set | **Essential** (Proven fit: same vault, template and names) | Option 1 is refused by FR-8 unless it duplicates the vault or coordinates prune across targets (`src/config.rs:2504-2549` at `291c0b16`) | — | Issue unsolved |
| C2. `ContainerAppJob` runtime (`job.rs`) | Read, edit and update one job | **Essential** (Proven by J1–J12) | Bindings and fingerprint must come from `job show` (J10) | Must **share** the app's snapshot/edit/strip/container/principal/access code, not copy it: they are `ContainerApp` methods bound to `container_app`, with messages that name "container app" | — |
| C3. `AppWithJobs` composite `PinnedRuntime` | Keep core unchanged | **Essential** (Adapted) | No core change for sync and status | — | Core change across placements |
| C3a. Merge rule "first differing job" | One binding per name for core | **Unjustified as written** (H1) | Masks a stale app when a job is ahead | **On disagreement, report the resource that is not at Key Vault's current version** (one value-free `secret show --query id` per disagreeing name, the read `keyvault.rs:396-420` already makes); if none or several, the app's | Silent stale app |
| C4. Jobs first, then the app (D2) | Order inside one apply | **Essential** (Adapted) | The alternative writes inside `await_healthy` and can leave a job stale after a healthy deploy | — | — |
| C5. Access gate before any update (A4, D7) | Turn J3's silent failure into a refusal | **Essential** (Proven need: J3 accepted an unreadable reference; Adapted cause of the failure) | The app does not need it (Q14); a job does | Must refuse **only on a definite negative**; an undetermined check warns (M1) | Next execution fails with no reason (J3) |
| C6. Fresh-grant note (D8) | Tell the person a new grant may not be in effect yet | **Useful** (Adapted: 2 samples; the 10 min figure is from documentation, not measured) | Cheap: `createdOn` is already in the reply | Already half-present: the doctor text says "a new grant can take a few minutes to apply" (`containerapp.rs:929`) | A confusing failed run within minutes of a grant |
| C7. `MissingRight.grantee: Option<Principal>` | Ask the right principal for the grant | **Essential** for C5 (Proven: the render uses `seen.principal()`) | Without it opv tells the deploy identity to get the job's role | — | Wrong advice |
| C8. `ResourceKind::ContainerAppJob` | Subject words and hint | **Essential** (Proven pattern) | — | — | Job errors read as "container app" |
| C9. Doctor/preflight job lines (A3) | Advisory visibility | **Essential** (acceptance A3) | — | — | A3 unmet |
| C10. L1: verify reads bindings **instead of** the store | A2 on pinned targets | **Obsolete as designed** | #241 already fixed verify by store version; replacing it regresses #241's test | **Overlay**: keep #241's store version; when the runtime's binding of a name is `Pinned` at a version other than the recorded one, use that version (→ `drifted_on_target`), and an unbound name is `missing_on_target` | A2 unmet |
| C11. Per-version `opv-` secret names kept on jobs | One `secret_name` and one binding reader | **Useful** (J8: not needed by Azure) | Shared code | — | Divergent naming |
| C12. Option 1 (job target) | Job-only sync | **Unjustified now** (agree with the design) | FR-8; synthetic revision | Later, if a real standalone job appears | — |

### Revised Architecture

- **Components retained:** C1, C2, C3, C4, C5, C6, C7, C8, C9, C11.
- **Components simplified:** C2: one resource-generic implementation extracted from
  `containerapp.rs`, not a copy. C5: three-valued result (granted / missing / undetermined), listed
  with `--assignee-object-id … --fill-principal-name false`. C6: one line that reuses the existing
  "a new grant can take a few minutes" wording.
- **Components replaced:** C3a by the current-version merge rule. C10 by the binding overlay on
  #241.
- **Components removed:** C12 (stays out).
- **Components demoted:** C6 to Useful (keep only because it is about 20 lines on data already
  read).

---

## Phase 2 — FMECA + poka-yoke + TRIZ

Domains: **R** runtime, **T** technical architecture, **U** UX, **P** project/delivery, **S**
security. A failure mode is High if its severity or probability is High.

### Iteration 1 Risk Table

| Id | Domain | Failure Mode | Cause | Effect | Severity | Probability | Mitigation (Poka-Yoke) | Observability | TRIZ Resolution | Residual Severity | Residual Probability |
|---|---|---|---|---|---|---|---|---|---|---|---|
| H1 | R/T | After any jobs-first stop, the app is never re-pinned and nothing reports it | Merge rule (§4) reports a job ahead of the app as the name's binding. A stop can come from the app refusing (e.g. Q14, app identity without access), the app's outcome unknown, job k+1 refused, or Ctrl-C | The app serves the old version indefinitely. `status`, `--fail-on-drift` and verify are clean, and the run exits 0. After an unknown job write, `apply_reconciled` prints "the update was applied" and confirms the old app revision | High | High (any failure after the first job) | **Prevention:** on disagreement, report the binding of the resource that is *not* at Key Vault's current version. Read that with the existing value-free `keyvault secret show --name n --query id -o tsv`, only when resources disagree. If several resources differ, report the app's when it is among them. A stale resource then yields `Pinned{old}`: core re-pins (`pin`), flags drift, and the per-resource sub-change (step 2) updates only what is behind. **Test:** composite tests for every row of §4's partial-failure table, each followed by a second run that must update exactly the stale resources | `status` drift line and exit 8; verify `drifted_on_target` (after H2); the second run's "container app job J pins …" note | *Prior action*: resolve the disagreement in the adapter with one read, rather than teaching core about N resources | Low | Low |
| H2 | T/P | A2 unmet; L1 regresses #241 | L1 was written before #241 landed. The fix reads `store.read`, not bindings. L1 replaces the store version with the binding | A stale job verifies as `verified`. With L1 as written, a Key Vault version changed outside opv verifies as `verified` too | High | High | **Prevention:** (1) merge `v0161/integrate` into the 0.17 line before L1. (2) L1 becomes an overlay in `verify_target`: after #241's fill, read `runtime.bindings()` once for a `Ports::Pinned` target; for each expected name, a `Pinned` binding at a version ≠ the evidence's `store_version` sets `listed_version` to that version, and a missing binding sets it to `None`. (3) Keep both #241 tests and add: binding moved → `drifted_on_target`; unbound → `missing_on_target`; with a job (after L3) → A2. Provider-neutral; names no provider | the two #241 tests plus the new ones; `verify --json` `names[].state` | *Combine*: both observations feed one `listed_version`, and whichever disagrees with the record wins | Low | Low |
| M1 | R/U | The gate refuses a correct deploy, or cannot run under CI | `--assignee` and the default `--fill-principal-name` query Graph (az 2.91 help); a CI service principal often has no Graph read. Custom roles and secret-scope grants are unknown to `READ_ROLES`. The deploy identity may lack `roleAssignments/read` at vault scope | Every deploy of a target with jobs fails (exit 9 via read failure, or a false `MissingRight`). Today the same read is only an advisory doctor line | Medium | Medium | **Prevention:** for the job check, use `--assignee-object-id <principal> --fill-principal-name false` (the app's argv stays as it is unless the owner accepts a P0 argv change). The result is three-valued. **Granted**: go. **Missing**, refuse with `MissingRight{grantee}`, when the evidence is definite: no system identity; user-assigned id not attached; an access-policy vault with no `get` for the principal; or the list *succeeded* and holds no assignment of any role at the vault or above. **Undetermined** (list refused or failed after retries, or only role names opv does not know): proceed, with a `runner.note` naming the job, the check that could not decide, and `opv doctor --env <env>`. **Docs:** the deploy identity's rights (role-assignment read at vault scope, Contributor on each job). **Live check:** one read-only rerun of R/W4's list as the sandbox's deploy service principal (no writes) | the note; doctor's line; the refusal's grantee | *Partial action*: refuse only where opv knows, warn where it cannot know | Low | Low |
| M2 | R | Gate premise wrong (W3 failed for another reason) | Execution failure has no reason (J3, J10) | A refusal that blocks a deploy for the wrong reason | Medium | Low | The gate does not rest on the inference. It enforces Container Apps' documented prerequisite for a Key Vault reference (the identity must be able to read it), the same prerequisite Q14 shows Azure enforcing for apps. With M1's definite-negative rule it refuses only when the identity provably lacks any grant. Fix the findings' wording ("same reference and check", not "same template") | refusal names grantee and role | — | Low | Low |
| M3 | P/U | Catalog change larger than planned; A4's "command" missing | `grantee` is a new field on a variant with 7 production constructors in 7 files (12 e2e snapshots); `grant_words` renders words only | Lane L2a overruns its files, snapshot churn or a coverage-gate failure, and a refusal without the command | Medium | High (certain as written) | **Prevention:** `#[serde(skip_serializing_if = "Option::is_none")]` on `grantee` (the coverage gate then reads the same field set, `coverage.rs:2381`). List every constructor file in L2a. Either render the `az role assignment create --assignee-object-id <P> --assignee-principal-type ServicePrincipal --role "…" --scope <vault id>` text when `grantee` is an `AppIdentity` with RBAC (render.rs already holds `az` hints), or restate A4 as "names the grantee and the role; its Next, doctor, prints the command". Pick one in the design | render_tests: `grantee` Some/None; e2e snapshots unchanged | — | Low | Low |
| M4 | T | A second, divergent implementation of the app's read/edit code | "Helpers made `pub(super)`" does not cover `snapshot_from`, `edit`, `strip`, `container_index`, `principal`, `check_access`, which are `ContainerApp` methods using `self.target.container_app` | Drift between app and job behaviour, which the code-change rules forbid | Medium | Medium | **Prevention:** L2 first extracts resource-generic functions (resource kind and name, its read-only field list, the container rule, the principal source) from `containerapp.rs`, and makes `ContainerApp` a thin caller. Proof: `containerapp.rs`'s own tests and the P0 argv characterization are unchanged | unchanged test output; diff review | *Segmentation*: one engine, two resource descriptors | Low | Low |
| M5 | U | A gated job blocks an urgent rotation from reaching the app | The gate refuses the whole apply (D7) | A leaked key stays live on the app until the job's grant is fixed | Medium | Low | Keep the refusal (the safe default). Its Do/notes say the escape: remove the job from `azure.companion_jobs` to deploy the app alone. Document it in `docs/configuration.md` | the refusal text | *Separation in time*: deploy the app now, re-add the job after the grant | Low | Low |
| L1 | U | Misleading "deployed revision" for a job-only change | Core prints `deployed revision <app's current>: NAMES` (`sync.rs:1886`); §4 step 6 cites the wrong path | The person thinks the app was redeployed | Low | Medium | Correct §4 step 6. The adapter prints "container app A unchanged; container app job J pins NAMES" before core's line. No core change | the notes | — | Low | Low |
| L2 | U | `status` names the target, not which resource is stale | One merged binding per name | The person must look at each job | Low | Medium | `AppWithJobs::chain` (port default today) or a `runner.note` per stale resource: "container app job J binds v…" | the status line | — | Low | Low |
| L3 | R | A job removed from `companion_jobs` keeps `opv-` references, and a later `--prune --deploy` deletes their entries | opv forgets an unlisted job | The removed job's next execution fails, silently (J3) | Medium | Low | Document: before removing a job from the list, remove its `opv-` env and secrets, or keep it listed until the prune. FR-32 applies only to resources opv knows | docs | — | Low | Low |
| L4 | S | A value reaches argv or output | — | — | High | Low | Already prevented: whole documents on `--yaml /dev/stdin` and the Windows pipe (`az.rs:89-110`, `handoff.rs`); replies parsed, never printed; J7, W11 0 hits. Extend `values_never_reach_argv` and `sync_output_holds_no_value` to job documents (§9 has it) | those tests | — | High | Low |
| L5 | T | `job show` gains a field that moves on its own and breaks the fingerprint | az/Azure version change | `ChangedOutsideOpv` on every deploy | Medium | Low | Same as the app today: the read-only list from J2. The refusal lists the changed paths (`changed_paths`), so a new field is visible at once | refusal paths | — | Medium | Low |
| L6 | U | `same_target` refusal for a shared job says "both use Key Vault …" | `shared_target_error` text (`config.rs:445-450`) | A confusing message | Low | Low | Give the job case its own text: "targets X and Y both list container app job J" | config test | — | Low | Low |
| L7 | U/P | No `opv target add` / MCP path for the list | `InitField` writes TOML basic strings only (`provider.rs:211-240`) | A hand edit (an assistant can still edit the file; no value involved) | Low | High | A repeatable `--azure-companion-job <J>` written as a TOML array, or state "hand-edited in 0.17" (owner choice, D9 below) | `target add --help` | — | Low | Low |
| L8 | P | Lane conflicts | `src/app/azure_tests.rs` is changed by #241 (v0161), L1's A2 test and L3; `delivery.rs` by #241 and L1 | Merge conflicts, a lost #241 test | Medium | Medium | Merge `v0161/integrate` first; L1 → L3 in sequence on `azure_tests.rs` (§Lane plan) | CI | — | Low | Low |
| L9 | U | Fresh-grant note wrong for group-based or access-policy grants | `createdOn` is the group's assignment time; policies have no time | A missing or early note | Low | Low | State it: the note covers direct RBAC grants only. Cite the Azure documentation for the 10 minutes in the design (Adapted) | — | — | Low | Low |
| L10 | T | R6 / port doc contradicted | `ports.rs:119` "never gates a deploy" | Readers trust a false invariant | Low | High | Amend the doc comment and R6's note: the app stays advisory (Q14); a job is gated inside `apply` (J3) | doc review | — | Low | Low |

### Remaining Risks After Iteration 1

- High: none (H1, H2 mitigated by prevention; L4 is High severity, Low probability, already prevented by existing structures).
- Medium: none after mitigation. L5 stays Medium severity, Low probability, as it is for the app today.
- Low: H1, H2, M1–M5, L1–L10 residuals.

### Iteration Summary (1)

- Key mitigations: current-version merge rule (H1); binding overlay on #241 (H2); three-valued,
  Graph-free access check (M1); skip-serialized `grantee` with the full file list and a decided
  A4 wording (M3); one shared engine for app and job (M4).
- Simplifications: L1 shrinks from a replacement (~180 lines) to an overlay (about 60–100 lines
  with tests). C6 reuses existing wording.
- Trade-offs: H1 adds one value-free Key Vault read per disagreeing name, only on disagreement. M1
  lets an undetermined check proceed with a warning. That is the price of not refusing correct
  deploys, and doctor still shows the line.
- Continue: the mitigations themselves need checking (Iteration 2).

### Iteration 2 Risk Table (risks introduced by the mitigations)

| Id | Domain | Failure Mode | Cause | Effect | Severity | Probability | Mitigation (Poka-Yoke) | Observability | TRIZ Resolution | Residual Severity | Residual Probability |
|---|---|---|---|---|---|---|---|---|---|---|---|
| I2-1 | S | H1's extra Key Vault read fetches a value | `secret show` returns the value to `az` | A value in memory or output | High | Low | Use only the existing `--query id -o tsv` form (as `confirm_version`, `keyvault.rs:396-420`): the reply is the id, and nothing is printed or kept. No new read shape | `values_never_reach_argv`/`sync_output_holds_no_value` | — | High | Low |
| I2-2 | U | H2 changes verify for Kubernetes and Azure users | A sync without `--deploy` records evidence at versions the runtime does not bind yet | Such a placement now reads `drifted_on_target` where #241 says `verified` | Medium | High | Owner decision D4′ (below). If kept, the reason says the version is staged, not deployed (the `deployed` field can come from the overlay: binding ≠ record ⇒ `staged`) | verify output | *Another dimension*: the state says drifted, and `deployed` says why | Low | Medium |
| I2-3 | R | M1's "undetermined → proceed" lets a job without access through | Custom role without `getSecret`, or a list that failed | J3's silent failure for that job | Medium | Low | The note names the job and doctor, and says the next execution may fail. Doctor's line stays. Reading role definitions for custom roles is possible later; it is not built speculatively | the note | — | Medium | Low |
| I2-4 | P | `--assignee-object-id` changes argv for apps too | Shared check (M4) | P0 argv characterization fails | Low | Medium | The shared function takes the argv form as a parameter, or the owner accepts the app change too (it removes the same Graph dependency from doctor) | characterization tests | — | Low | Low |

### Remaining Risks After Iteration 2

- High: none.
- Medium: none at Medium/Medium or above. I2-2 is an owner choice (D4′), Low severity once
  `deployed` says "staged". I2-3 and L5 are Medium severity at Low probability, both visible.
- Low: the rest.

### Iteration Summary (2)

- Mitigations hold without new structures: the extra read reuses an existing value-free form, and
  the overlay reuses `listed_version`.
- Stop: no High or Medium-probability risk remains. Further mitigation (reading role definitions,
  a job-execution probe) would either add speculative components or require opv to start
  executions, which is a non-goal.

---

## Phase 3 — Systemic Risk Review

- **Calibration risk.**
  - The gate's evidence is Adapted (W3/W4b failures attributed to access, two samples), but the
    gate enforces a prerequisite, not a measured property. With M1 it refuses only on
    definite negatives, so a miscalibrated inference cannot cause a false refusal.
  - The fresh-grant window (28 s too early, 2 min 18 s enough, "10 min documented") is
    calibration-light. It only changes a note, never an outcome. That is the right weight for
    two samples.
  - No numeric score drives a decision.
- **Observability risk.**
  - *Bad decisions* (H1): without the fix there is no signal at all. With it, drift and verify
    show the stale resource, and the second run's note names it.
  - *Premature completion*: today `apply_reconciled` can declare success on an old revision. The
    current-version merge makes `left(now)` non-empty in that case.
  - *Policy regressions*: the provider guards, the J7 seal and the coverage gate (with
    `skip_serializing_if`) all keep running unchanged. Add a composite test asserting that a target
    without `companion_jobs` issues the exact app argv (§9 has it).
- **Complexity vs utility.**
  - Option 2 is the simplest version that meets A1–A4: one field, one runtime, one composite, and
    no core change for sync.
  - The fresh-grant note is the only optional part.
  - L1 gets smaller, not larger.
- **Oversimplification risk.**
  - Dropping the gate (doctor-only) would reintroduce J3's silent failure, which is the issue's
    own complaint.
  - Dropping the per-resource sub-change would write every job on every deploy.
  - Both stay.
- **Incremental delivery.**
  - L2 (job runtime, unit-tested on fixtures) can land without being reachable: `open` returns
    `AppWithJobs` only when the list is non-empty, and the list does not parse until L3.
  - Rollback is removing the field from the configuration. The target is then byte-identical to
    today (§4, `open`).
  - L1′ is independent of jobs and ships first.

### Final Outcome

All High and Medium risks are mitigated to Low by the required changes below, which reuse
existing structures (the value-free `secret show --query id` read, `listed_version`, the
`Partial`/`MissingRight` causes, `preflight::unusable`). What remains is Medium severity at Low
probability (I2-3, L5, L4 at High severity). It is visible through notes, doctor and refusal
paths, and further mitigation would add speculative components.

---

## Conflicts with owner principles

None. Checked one by one:

- **1Password vault access is the only permission system.** opv adds no role, grant or required
  path. The gate reads Azure's own grants and refuses only where Azure would silently break the
  job. It prints the grant for a person to run (C5, C7). This is a target precondition, not an
  opv permission.
- **CI never writes values to 1Password.** Unchanged. The design writes only Key Vault and Azure
  resources, as today.
- **Values only through stdin or a pipe, output scrubbed.** Holds for job documents
  (`--yaml /dev/stdin`, Windows pipe). H1's added read is a `--query id` read.
  `job secret set` and `--set-env-vars` are excluded (§1).
- **Third-party defects out of scope.** The Graph lookup in `--assignee` is documented `az`
  behaviour, not a defect. Avoiding it with `--assignee-object-id` is ordinary use of the tool.
- **Reject speculative components.** No speculative component remains. C6 is demoted to Useful
  and kept because it is cheap and works on data already read.

One owner decision is re-opened (D4′). The owner's goal that every capability ships in the CLI
and MCP is touched by L7 (D9).

---

## Required design changes

1. **§4 Bindings (H1).** Replace the merge rule. When the app and its jobs disagree on a name,
   read that name's current Key Vault version (value-free `--query id`) and report the binding of
   a resource that is not at it: the app's if the app is among those, otherwise the first such
   job. A missing name in any resource makes the name absent. Rewrite the partial-failure table's
   "Next run" column against this rule. Drop "job settles `Failed` … re-applies": with the job at
   the target, the next run does not touch it, and preflight warns on `Failed`; this row is
   unobserved (J11).
2. **§2 gap, §5, D4, L1 (H2).**
   - State that #241 is fixed on `v0161/integrate` by store version, and that this does not meet
     A2.
   - Redefine L1 as the binding overlay described in H2, built after `v0161/integrate` is merged
     into the 0.17 line, keeping both #241 tests.
   - Re-pose D4 as D4′: "on a pinned target, verify reports a name whose runtime binding differs
     from the recorded version as `drifted_on_target` (`deployed: staged`), including right after
     a sync without `--deploy`. Kubernetes too."
3. **§4 step 3 (M1).** Make the gate three-valued and Graph-free, as in M1. Name the deploy
   identity's extra rights in `docs/configuration.md`. Add one read-only check, as a deploy
   service principal, of `role assignment list --assignee-object-id … --fill-principal-name false`.
4. **§4 Catalog, §10 L2a (M3).**
   - `grantee` with `#[serde(skip_serializing_if = "Option::is_none")]`.
   - List every `MissingRight` constructor file in L2a.
   - Either render the `az role assignment create` text for an `AppIdentity` grantee under RBAC,
     or restate A4 to say the command comes from doctor (the refusal's Next).
5. **§4 Structure, §10 L2 (M4).** Replace "helper visibility only" with an extraction of
   resource-generic functions from `containerapp.rs`. App tests and P0 argv must not change.
6. **§4 step 6 (L1 risk).** Correct the path claim. The adapter notes "container app A unchanged"
   when only jobs changed.
7. **Small corrections.**
   - Citations: `render.rs:2113` → `:4089` (Partial); `:3771` → the listing hints (`:3709` at
     `291c0b16`).
   - Remove the non-existent "scope broader than needed" wording.
   - J3/J5 "same template" → "same reference and check".
   - `ports.rs:119` and R6: the app stays advisory, and a job is gated in `apply`.
   - `shared_target_error` text for a shared job.
   - Docs for removing a job from the list (L3) and the escape for an urgent rotation (M5).
8. **New owner decision D9 (L7).** Is there a repeatable `--azure-companion-job` on
   `opv target add` in 0.17, or is the field hand-edited for now?

## Lane plan

It **holds with changes**:

| Lane | Change |
|---|---|
| L0 (new, no code) | Merge `v0161/integrate` into the 0.17 integration branch before L1 and L3 (it touches `src/app/delivery.rs` and `src/app/azure_tests.rs`) |
| L1′ pinned verify overlay | `src/app/delivery.rs`, `src/app/azure_tests.rs` (#241's tests live there now) and/or `pinned_tests.rs`; ~60–100 lines; first |
| L2a catalog | adds the `MissingRight` constructor files: `adapters/onepassword.rs`, `onepassword_diagnose_items{,_tests}.rs`, `kubernetes/{mod,diagnose,config}.rs`, `azure/preflight.rs`, `cause/codes.rs`, `app/ready_tests.rs` (one-line `grantee: None` each). `azure/preflight.rs` is L4's file too, and the two run in sequence, so that is fine. Check that no other open 0.17 lane edits the Kubernetes/1Password files at the same time |
| L2b/L2c | include the `containerapp.rs` extraction (more than visibility); likely ~250 each, not ~200 |
| L3 | after L1′ on `azure_tests.rs` (the A2 job test is here); includes the current-version merge read |
| L4, L5 | unchanged; L5 adds the deploy-identity rights, the removal and escape notes |

Order: L0 → L1′ ∥ L2a → L2b → L2c → L3 → L4 ∥ L5. With the changes, the design is ready for owner
approval of D1–D3, D5–D8, D4′ and D9.
