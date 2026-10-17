# The error catalog: every failure is a typed cause, rendered once

Status: implemented in 0.10.0 (branch feat/error-catalog); owner decisions in §12.4. Issues in scope: #157 and #159 (wrong causes), and the output audit's 300 findings. It replaces how opv builds and renders every error, and how it scrubs every output. The output-audit evidence behind it is summarised in §1; the full inventory (86 situations, 26 step rules, 300 findings mapped) is kept with the review record.

## 1. Problem

Nine read-only audits of every user-facing output, plus a live run of 95 CLI scenarios, 74 help screens and 33 MCP calls, found **300 problems: 43 S1, 128 S2 and 129 S3.**
- **S1** means a wrong cause, harmful advice, a loop, a nonexistent command or a false claim.
- **S2** means a missing action, a wrong code or an unnamed object.
- **S3** means wording.

They are not 300 separate mistakes. They are a handful of mechanisms, repeated at about 770 places that build an error:

| Mechanism | How it shows up | Examples |
|---|---|---|
| Each call site decides the cause of an external failure itself (49 places interpret a failed `op` call) | the likeliest guess is presented as fact | #157: a missing session reported as "vault not in account"; an expired `az` session as "check your role"; a refused write as "not available to this identity" |
| Steps are free text, and `split_step` parses them | `Next:` loops, drops flags, or names a command that doesn't exist; prose becomes "fill in and run" | `Next: opv account list` from `opv account list`; `--skip` dropped from adopt's `--apply`; `--project .` rejected as not runnable |
| Steps are chosen by hand-written heuristics | guesses | "the first candidate", "the first target", `--confirm` added by opv itself |
| `code`, `retry` and `human_required` come from a per-code table, not from the situation | one code covers a safe branch and a person-only branch | `config_changed`, `tidy_conflict` and `item_changed` are each wrong for one branch |
| A write whose outcome is unknown is described as failed | duplicates when the person follows the advice | vaults, items, service accounts and deploy tokens created twice; secret-bearing orphans |
| The MCP server has its own hint tables | MCP and the CLI disagree, and MCP drops the real step | 30 MCP findings |
| Scrubbing covers only the failed tool's stderr | safety depends on each call site being careful | — |

80% of today's error constructions give no cause code at all, and 102 put their next step inside the message text.

## 2. Principles

1. **Closed causes, open subjects.** *Why* something failed comes from a closed set (§4). *What* it is about comes from typed, specific fields: the vault ID, the account, the target, the app, the key, the file and line, the right that is missing. A message is specific because its fields are specific, not because a call site wrote good prose.
2. **Five parts per message.** Each part has its own rule:

   | Part | Content | Constrained by |
   |---|---|---|
   | Cause | why it failed (one variant) | the closed enum |
   | Subject | what it is about | typed fields, every one shown |
   | Evidence | what opv saw: the call it made, in which account, the result, and the upstream reply | diagnosis output; scrubbed |
   | Do | what the person (or agent) does first | a typed action, filled from the subject |
   | Next | the command to run after | a typed step, validated against the real CLI |

3. **Diagnose before blaming.** An external failure becomes a cause only through that system's diagnosis (§5). When the diagnosis can't tell, the cause is `Unrecognized`, and the upstream reply is the main evidence. opv never presents a guess as fact.
4. **One output policy, three formats.** Terminal text, the `--json` document and the MCP answer carry the same content from the same `Cause`. They differ only in format. MCP is the `--json` document.
5. **Derived, not declared.** The exit code, retry class and `human_required` come from the cause and its step, so they can't contradict each other.
6. **Every byte out is scrubbed in one place** (§8). No call site can forget.

## 3. Architecture

```text
call site ──(typed facts)──► Cause ◄──(Observed)── Diagnose (per system: op, flyctl, az, kubectl, gh, ssh)
                               │
                 Error { cause, evidence: Option<Upstream>, context: Invocation }
                               │
                    Render ─┬─ Text (terminal, TUI)
                            └─ Document (--json, MCP)
                               │
                        OutputGuard (scrubbing choke point) ──► stdout / stderr / MCP / TUI
```

| Component | Module | Replaces |
|---|---|---|
| `Cause` enum and its subject types | `src/cause/mod.rs`, `src/cause/subject.rs` | the free-text `Msg` and `Error` category constructors; `with_code`; most `with_next`/`with_do` |
| Typed steps: `Action`, `Next`, `Invocation` | `src/cause/step.rs` | `split_step`, `is_runnable`, `is_rerun_phrase`, `default_step`, `rerun_command`, the 102 embedded `next:` lines, doctor's `CONFIG_FIX`, ready's `error_finding` step rebuild |
| Diagnosis strategies | `src/cause/diagnose/{op,fly,az,kube,gh,ssh}.rs` | `onepassword::diagnose`/`session_error` at 49 places, each adapter's `failure()`/`diagnose()`, and the `signed_out` phrase lists |
| Upstream evidence | `src/cause/evidence.rs` (moves `scrub::Excerpt`) | `Excerpt::render` (`az said: …`) |
| Renderers | `src/cause/render.rs` | `report_with`, `envelope`, `error_object`; the MCP `code_hint`, `preview_failure`, `access_failure`, `structure_failure` and `generate_action` tables |
| Output guard | `src/output.rs` | `PipeSafe`; per-site scrubbing |
| Process hardening | `src/hardening.rs` | `signals::no_core_dumps` (moved, and run first for every command) |

`Error` stays the type every function returns. It becomes `Error { cause: Cause, evidence: Option<Upstream> }`, and its exit code, retry class and `human_required` are derived from `cause`. The old category variants (`Error::Config(Msg)` and the rest) are removed at the end of the migration (§10); no free-text constructor survives.

## 4. The catalog

Each variant lists:
- its typed fields;
- its stable `code`;
- its exit code (the category);
- its retry class: `safe` (re-run as is), `after_fix` (re-run once the Do is done), `never` (the command itself must change) or `check_first` (something may already exist; Next is a read);
- its Do and Next.

`human_required` is derived (§6.3). `[R..]` cites the situations in the review inventory.

Where a code's meaning is unchanged, the code keeps today's name. New codes are marked **new**; codes no longer used are listed in §4.11.

### 4.1 Configuration (exit 2)

| Variant | Fields | Code | Retry | Do | Next |
|---|---|---|---|---|---|
| `ConfigNotFound` | searched_from: Path; env: Option<Env> | config_not_found | after_fix | — | `opv init <env>` when env is known, else `opv init --help` [R01] |
| `ConfigSourceMismatch` | command: CommandId; manifest: ManifestRef | **config_source_mismatch** | never | "<command> works on a secrets.toml; this project's configuration is the 1Password manifest <title>" | `opv config edit`, or the command's manifest route [R02] |
| `ConfigUnreadable` | path; io: IoKind; given_by: Flag/EnvVar/Discovered | config_unreadable | after_fix | named by given_by | rerun [R03] |
| `ConfigInvalid` | source: ConfigSource; at: Location{line, col}; field: DottedPath; rule: FieldRule | config_invalid | after_fix | built from (field, rule) (§4.12) | rerun [R04–R08, R12] |
| `RecordMissing` | what: Boundary{env, product} / StateVault{env, target}; source | boundary_missing / state_vault_missing | after_fix | — | file: `opv bootstrap`; manifest: `opv structure plan` [R09, R10] |
| `StateVaultTooWide` | env; target; vault; shared_with; source; at | state_vault_wider_than_values | after_fix | "delete state_vault_id from [environments.E.targets.T]" | `opv bootstrap` [R11] |
| `ConfigNotEditable` | source; reason: Generated{path} / UnsupportedLayout{section} / ManifestItemAsBoundary{env, boundary}; pending_ids | **config_not_editable** | never | per reason | `opv config edit` [R15] |
| `CopiesDiffer` | file; manifest | **copies_differ** | never | "update the file (opv config export --toml > <file>) or the manifest (opv config edit)" | none: the person picks the direction [R16] |
| `ManifestProblem` | state: NotFound{project, from} / Ambiguous{candidates, reason} / Exists{title, local_file} | manifest_not_found / manifest_ambiguous / manifest_exists | per state | per state | `opv projects`; `opv config check --file <f>`; `opv config edit` [R17–R19] |
| `InventoryIncomplete` | unlisted: Vec<(Account, Cause)> | inventory_incomplete | after_fix | "sign in to account <id>" | `opv login --account <id> --no-record -- <rerun>` [R20] |

### 4.2 Names and usage (exit 2)

| Variant | Fields | Code | Retry | Do | Next |
|---|---|---|---|---|---|
| `NotDeclared` | kind: NameKind (Env, Target, Product, Key, Role, RemoteProfile, Mode, HelpTopic); given; scope; candidates; closest: Option | unknown_env / unknown_product / undeclared_key / **unknown_target** / **unknown_role** / **unknown_profile** | never | — | a unique `closest` only: the same command with it substituted, and a write turned into its read; otherwise a listing [R21] |
| `Ambiguous` | kind; given; candidates (with what tells them apart) | **ambiguous_name** | never | "name it as <product>/<KEY>" | a listing [R22] |
| `ChoiceRequired` | flag: Product/Role/…; candidates; launch | **choice_required** | never | "pick one of …" | only with exactly one candidate [R23] |
| `NothingInScope` | env; what: NoProductHasKeys / NoTargetDelivers{target} / NoTargets{products} | no_target / **nothing_in_scope** | never | "declare one: opv add …" | `opv target add --help` / `opv status <env>` [R24, R25] |
| `Usage` | problem: UnknownFlag{flag, closest} / MisplacedBeforeDashDash{flag} / ConflictsWith{a, b} / ValueFormat{flag, format} / NeedsFlag{flag, needs} / UseInstead{command} | usage | never | — | the corrected command when known, else `<cmd> --help` [R26] |
| `AlreadyDeclared` | kind; env; name | **already_declared** | never | — | `opv config edit` [R27] |

### 4.3 Sessions, accounts and credentials (exit 7)

| Variant | Fields | Code | Retry | Do | Next |
|---|---|---|---|---|---|
| `NotSignedIn` | system: System; account: Option<Account>; state: SignedOut / Expired / AppLocked / AppPromptUnanswered{waited} | op_not_signed_in / **target_not_signed_in** | after_fix | app states: "unlock the 1Password app and approve its prompt"; targets: the typed vendor sign-in | 1Password: `opv login --account <id> -- <rerun>`; targets: rerun [R28, R29, R35] |
| `AccountNotOnMachine` | account; selected_by: AccountSource{path or var}; add_route: Cli / App{platform} | account_not_registered | after_fix | App: "add it in the 1Password app and turn on CLI integration"; Cli: "add it at op's prompt" | Cli: `opv login --add` (an email only in `--account`); App: `opv login` [R30] |
| `AccountAmbiguous` | given; source; candidates: Vec<{id, email, shorthand}> | account_ambiguous | after_fix | "pick the account by its email" | `opv account list`; never `opv account use <first>` [R31] |
| `InOtherAccount` | vault: VaultId; item: Option<ItemId>; selected: Account; owning: Option<Account>; unasked: Vec<Account>; searched: bool, the other accounts were listed and asked (§12.4, #153a); env | ids_not_in_account | after_fix | "select the owning account (opv account use <id>), or fix vault_id for <env>"; with no owner found, "sign in to <unasked> to look for vault <vault> there, or fix vault_id for <env>"; searched with every account asked, "no 1Password account on this machine holds vault <vault>: fix vault_id for <env> with a vault of account <selected>"; not searched (op listed no accounts), "find the account that holds vault <vault>, or fix vault_id for <env>" | `opv account use <owning>`; with accounts not asked, `opv login --account <first unasked> --no-record -- opv vault locate <vault>` (handoff); searched with every account asked, `op vault list --account <selected>`; not searched, `opv vault locate <vault>` [R32] |
| `NeedsOwnSession` | command: Invocation; identity: ServiceAccount / Connect / Ci / DeployCredentials / Unconfirmed | **own_session_required** | never (in this run) | "run it in your own terminal, signed in as yourself, without <variable>" | the exact command, as a person-only handoff [R33] |
| `CredentialRejected` | system; credential: CredentialRef (ServiceAccountToken{var} / Connect{vars} / DeployCredentials{item, env, target} / ShellToken{var} / StoreAuth{store}); problem: Rejected / Incomplete{missing_fields} / Unreadable{cause}; needs: Vec<Permission> | deploy_credentials_failed / **credential_rejected** | after_fix | "replace <credential> with one that has <needs>"; ShellToken: "unset <var> in this shell" | `opv doctor --env E --target T`, which checks this credential [R36–R38] |

### 4.4 Access and resources (exit 5 for targets, 4 for 1Password)

| Variant | Fields | Code | Retry | Do | Next |
|---|---|---|---|---|---|
| `MissingRight` | system; principal: Principal (Person{account} / ServicePrincipal{id} / AppIdentity / StoreIdentity / ServiceAccount{name}); resource: ResourceRef{kind, name, scope}; right: Right; grant: GrantModel (Rbac{role, scope} / AccessPolicy / NetworkRule / VaultPermission / RepoPermission / K8sRbac{verb, resource}) | permission_denied / vault_no_access | after_fix | the typed grant for that model, addressed to that principal: "ask an owner to grant <role> on <scope> to <principal>" | `opv doctor --env E --target T`, which checks it [R39] |
| `OwnerSetupRequired` | system; object: GitHubEnvironment{repo, env} / ClusterOperator{name} | owner_setup_required | after_fix | the typed owner action | a read that checks this cause (`opv ready`), else none [R41, R44] |
| `StoreNotReady` | store: ResourceRef; reason: Option<String>, the condition's reason code when it names one, never its message | owner_setup_required | after_fix | "ask a cluster admin to make <store> ready (its reason: <reason_code>)", or without the clause when it names no code | a read that checks this cause (`opv ready`), else none [R41, R44] |
| `NotFound` | system; resource: ResourceRef; named_by: ConfigField{path} / Flag{flag}; state: Missing / SoftDeleted / LocalContextMissing | item_not_found / **resource_not_found** | after_fix | Missing: "check <field> (opv config edit)"; SoftDeleted: the typed recover command; LocalContextMissing: "get credentials for <context> on this machine" | the vendor listing [R42, R43, R34] |

### 4.5 Target outcomes and opv's guards (exit 5, or 6 for policy)

| Variant | Fields | Code | Retry | Do | Next |
|---|---|---|---|---|---|
| `TargetRefused` | system; subject; serving: Option<Revision>; why: Validation / Quota / Unhealthy{new_revision} / NoRevision | update_refused / target_unhealthy | after_fix | per why (authorization goes to `MissingRight`) | `opv doctor --env E --target T` [R45, R47, R48] |
| `Guard` | guard: Guard (ValueTooLarge{key, limit, store} / NotManagedByOpv{name, store} / CredentialAsOption{option} / ProviderHidesValues{provider} / ImmutableWithoutRotate{key} / GenerateRefused{key, reason} / RemoteProfileRefuses{profile, asked, allowed} / …) | policy_refused | never | per guard | per guard [R46, R64, R79] |

### 4.6 Outcomes, availability and budgets

| Variant | Fields | Code | Exit | Retry | Do | Next |
|---|---|---|---|---|---|---|
| `CreateOutcomeUnknown` | system; kind: CreateKind; name; scope; refind: ByTitle / Check{command}; secret_bearing: bool | **create_outcome_unknown** | 9 | ByTitle: safe; Check: check_first | secret_bearing: "if <check> lists <name>, revoke it: its secret was never stored" | ByTitle: rerun; otherwise the check, never the create [R49] |
| `WriteOutcomeUnknown` | system; step; subject | outcome_unknown | 9 | safe | — | rerun ("the change may already be applied") [R50] |
| `Unavailable` | system; call; why: Timeout / RateLimited{retry_after} / ServerError{status} / Network; attempts | provider_unavailable | 9 | safe | "check <status page> or the network" | rerun [R51]. Reads only. |
| `BudgetSpent` | step; budget; writes_started: bool | **budget_spent** | 9 | after_fix | — | rerun with `--timeout <2 × budget>` [R52] |
| `Partial` | done: Vec<WrittenObject>; approval_used: Option<PlanId>; then: Box<Cause> | the inner code | inner | check_first | the inner Do, plus "already written: …" | a read showing what remains (`opv plan …`, `opv structure plan`); never the write, never the used approval [R53] |
| `Interrupted` | signal; step; writes_started | interrupted | 128+n | safe | — | rerun [R54] |
| `ChangedBeforeWrite` | object: StoreObject | config_changed / tidy_conflict / item_changed | 2 / 4 | safe | — | rerun exactly [R13] |
| `ConcurrentEdit` | object: StoreObject | **concurrent_edit** | 4 | check_first | "check <object>'s history in 1Password and keep the right version" | a read, never the write [R14] |
| `ReadBackMissing` | vault; item; fields; by: CommandId | tidy_unverified | 4 | after_fix | "restore <fields> from the item's history in 1Password" | the writing command [R55] |

### 4.7 External tools (exit 3, or 4/5)

| Variant | Fields | Code | Retry | Do | Next |
|---|---|---|---|---|---|
| `ToolMissing` | tool: Tool; platform; shell | dependency_missing | after_fix | the typed install line | rerun [R56] |
| `ToolUnusable` | tool; path; why: NotExecutable / WslInteropOff / TooOld{have, min} / VersionUnreadable / SpawnFailed{io} / WindowsExeFromWsl | **tool_unusable** | after_fix | per why | `opv doctor` [R57] |
| `UnexpectedOutput` | system; call; at; during: Read | **unexpected_output** | never | "update <tool> (opv doctor checks its version)" | `opv doctor` [R58] |
| `Unrecognized` | system; call; account: Option | **unrecognized_failure** | after_fix | "<tool>'s reply is shown above; opv does not recognise it" | `opv doctor --env E` [R59] |

### 4.8 Person-only steps and local inputs (exit 6, or 8)

| Variant | Fields | Code | Retry | Do | Next |
|---|---|---|---|---|---|
| `NeedsTerminal` | command: Invocation; why: NoTty / Ci | terminal_required | never | "run it in your own terminal" | the exact command, as a handoff [R60] |
| `NeedsConfirm` | env; command: Invocation | confirm_required | never | "make sure <env> is the environment you mean (agents: ask the user)" | a handoff: the same command plus `--confirm <env>` [R61] |
| `ConfirmMismatch` | given; env | confirm_mismatch | never | "check which environment you meant" | `opv plan <env>` [R62] |
| `ValuesNeeded` | env; rows: Vec<{product, key, target, state}> | findings / keys_blocking | after_fix | per state: "fill in <product/KEY> in 1Password" | `opv open <first blocking> --env <env>`; never a sync [R63] |
| `Declined` | prompt; command | **declined** | safe | — | rerun (exit 0) [R65] |
| `LocalFileTooOpen` | path; kind; mode; want | **file_too_open** | after_fix | `chmod 600 <path>` | rerun [R66] |
| `InputInvalid` | path; kind: Dotenv / Recipe / Receipt; at; field; rule | **input_invalid** | after_fix | "edit <path> at line L: <rule>" | rerun [R67, R68, R83] |

### 4.9 Approvals and plans (exit 6)

| Variant | Fields | Code | Retry | Do | Next |
|---|---|---|---|---|---|
| `ApprovalMissing` | plan_id; scope: PlanScope | approval_required | after_fix | "approve it in your own terminal" | a handoff: `opv approve <id>` plus every scope flag [R69] |
| `ApprovalUsed` | plan_id; scope; partial: bool | **approval_used** | never | "review what remains and approve its new plan" | `opv plan <scope>`; never `--approved <used id>` [R70] |
| `PlanChanged` | old_id; new_id; scope | stale_plan | never | "review the new plan" | `opv plan <scope>` (the approval route is a handoff to `opv approve <new_id>`) [R71] |
| `PlanUnknown` | plan_id; kind | **plan_unknown** | never | — | `opv plan <env>` / `opv structure plan` [R72] |

### 4.10 Platform, delivery and internal

| Variant | Fields | Code | Exit | Retry | Do | Next |
|---|---|---|---|---|---|---|
| `RamDirUnavailable` | host: Local / Remote{profile, user, host}; why: Unset / NotAbsolute / NotOwned / NotTmpfs / NoneOnPlatform{os}; purpose | ram_dir_unavailable | 6 | after_fix | per why and host | `opv run <env> --product <p> [--remote <r>] --preview` [R74] |
| `PrivateDirFailed` | dir; io | **private_dir_failed** | 6 | after_fix | "check free space and permissions in <dir>" | rerun [R75] |
| `RemoteUnreachable` | profile; user; host; port | **remote_unreachable** | 5 | after_fix | "check the connection and that the host presents the key pinned in profile <p>" | the same pinned check opv uses: `ssh -F none -o StrictHostKeyChecking=yes -o UserKnownHostsFile=<pinned file> -p <port> <user>@<host> true`. Only an exit 255 *before* the receiver's handshake is this cause; after the handshake, 255 is the remote app's own exit [R77] |
| `RemoteVersionMismatch` | profile; local_version; remote_protocol | **remote_version_mismatch** | 3 | after_fix | "install opv <version> on <host> at <opv path>" | rerun [R78] |
| `ChildStartFailed` | program; workdir; io; host | **child_start_failed** | 3 | after_fix | local: "check that <program> is on PATH"; remote: "check command and workdir of remote profile <p> (opv config edit)" | rerun [R80] |
| `DeliveryUnverified` | env; target; product; state: NotRecorded / Superseded{receipt} / OtherAccount{account} / ChangedOnTarget / ChangedInOnePassword / Unverifiable{cause} | **delivery_unverified** | 8 | after_fix | per state | per state [R82, R84] |
| `TargetDrift` | env; target; names: Vec<String> | **target_drift** | 8 | after_fix | "re-run the sync to restore 1Password's values" | `opv plan <env> --target <t>` |
| `Bug` | site: InvariantId (static) | **internal_error** | 70 | never | "report this as an opv bug: <issues URL>" | `opv version` [R85] |

`McpClientProtocolFailed` [R86] is not an opv cause: it is the MCP transport's own error, reported by the MCP library.

### 4.11 Codes

- **New:** config_source_mismatch, config_unreadable, config_not_editable, copies_differ, unknown_target, unknown_role, unknown_profile, ambiguous_name, choice_required, nothing_in_scope, already_declared, target_not_signed_in, own_session_required, credential_rejected, resource_not_found, create_outcome_unknown, budget_spent, concurrent_edit, tool_unusable, unexpected_output, unrecognized_failure, declined, file_too_open, input_invalid, approval_used, plan_unknown, private_dir_failed, remote_unreachable, remote_version_mismatch, child_start_failed, delivery_unverified, target_drift, internal_error.
- **Removed:** source_error, target_error, auth_required, desktop_app_unavailable (now a `NotSignedIn` state), op_unexpected (now `unrecognized_failure`), duplicate_scope (now `input_invalid`), credential_rejected for op's prompt (now `NotSignedIn`), and the MCP-only codes.
- **Exit 70 (internal error)** is new; it follows `EX_SOFTWARE`.

Under FR-60 (one way only) nothing keeps the old names. The `--json` `schema_version` becomes 2.

### 4.12 Field rules (`ConfigInvalid`)

`FieldRule` is an enum, so the configuration's Do is built from the field and the rule, and never derived from the line text:
- `Pattern{id}`: each pattern has a plain-words description ("key names use A–Z, 0–9 and _"), never a regex in text;
- `Reserved{set}`;
- `Empty`;
- `Type{expected}`;
- `Unknown{suggestion}`: "rename confrm_env to confirm_env";
- `Missing`;
- `ConflictsWith{field}`;
- `DuplicateKey`;
- `RemovedForm{form, replacement}`;
- `NoEnvironment`;
- `ModeUnmapped{env, mode, allowed}`, checked at load;
- `Collision{rendered, other}`.

## 5. Diagnosis: one strategy per external system

```rust
pub trait Diagnose {
    /// Turn what opv observed about one failed call into a cause.
    fn diagnose(&self, call: &CallId, seen: &Observed, probe: &dyn Probe) -> Cause;
}
pub struct Observed { exit: ExitClass, timed_out: bool, stderr: ScrubbedLines, during: Read | Write{idempotent: bool, kind} }
```

One implementation each for `op`, `flyctl`, `az`, `kubectl`, `gh` and `ssh` lives **in that system's own adapter module** (`src/adapters/<provider>/diagnose.rs`, and `src/adapters/onepassword/diagnose.rs`), so a provider stays one module (FR-37). These are the only places that classify an external failure.

**Sealing (corrected after review).** `#[non_exhaustive]` doesn't stop construction inside the crate. Instead:
- External-system variants hold a field of type `Observed`.
- `Observed` has a private constructor in `src/runner.rs`, and only the runner hands one out, for a call that actually failed.
- A call site that never made the call has no `Observed`, so it can't build an external cause.
- A compile-fail test (`trybuild`) proves it.

**Creates are their own runner effect.** `CommandRunner::create(call, CreateKind)` is the only way to run a non-idempotent create, so no call site can label a create idempotent. Any unknown outcome of it is `CreateOutcomeUnknown`: a timeout, a lost reply, a spent budget or an interruption.

**Recordings first.** Fly and Azure have no recorded failure output today. Before writing their diagnosis, each gets a spike that records real failures (signed out, expired, forbidden, not found, rate-limited), per CONTRIBUTING; kubectl and ssh are recorded likewise.

Rules for each strategy:
- **Phrase tables** become data per system (`signed_out`, `not_found`, `forbidden`, `rate_limited`, …). Each table has fixture tests built from recorded output (CONTRIBUTING: recordings, never invented JSON).
- **Probes** (such as `op whoami` and `wake`, or `az account get-access-token`, which checks the token rather than the local profile) run here, once, with the run's budget.
- **The principal is known.** The runner reports whether a deploy credential or a shell token was in effect, so the advice addresses that credential, not the person's own sign-in (finding class: Fly, GitHub and Azure under deploy credentials).
- **Environment overrides are named.** Each strategy knows the variables that silently override what the person typed:
  - `op`: `OP_ACCOUNT` acts as `--account` on every command, so `op signout --all` then fails with a flag conflict; `OP_SESSION_*`; `OP_SERVICE_ACCOUNT_TOKEN`.
  - `flyctl`: `FLY_API_TOKEN` and `FLY_ACCESS_TOKEN` override `flyctl auth login`.
  - `gh`: `GH_TOKEN` and `GITHUB_TOKEN` make `gh auth login` refuse.
  - `az`: `AZURE_*` service-principal variables.

  A failure one of them causes becomes `CredentialRejected{credential: ShellToken{var}}`, or a `Guard` naming the variable and how to unset it for one command (`env -u OP_ACCOUNT op signout --all`). It's never blamed on the person's flags. These quirks are recorded with the tool's version in `docs/design/spike-op-behaviours.md` and the other spike files.
- **Writes declare their kind.** `Write{idempotent: false, kind: CreateKind}` makes an unknown outcome a `CreateOutcomeUnknown` with a check, never "did not create".
- **When nothing matches:** `Unrecognized`, with the reply shown in full.
  - It records what the probes did establish (`established: signed_in, account, …`), so it is never vaguer than the facts.
  - Its evidence is the tool's error line plus the tail, not only the tail.
  - Phrases are matched on the raw text, before scrubbing changes it.
  - Its Next is the rerun with `--verbose`, plus the issue link; never `opv doctor` unless doctor checks that call.

## 6. Steps: Do and Next are typed

```rust
pub enum Next {
    Rerun,                         // the Invocation as typed, every flag kept
    Run(Command),                  // a built opv command
    Check(Command),                // a read that answers "did it happen?"
    Handoff(Command),              // only a person runs it (approve, --confirm, login)
    Vendor(VendorCommand),         // a typed vendor command (flyctl auth login, ssh -p …)
    None(NoNextReason),            // CopiesDiffer: the person picks the direction
}
pub enum Action { /* typed, rendered from a table: Grant{…}, FillValue{…}, Unset{var}, Chmod{…}, … */ }
```

### 6.1 `Invocation` and `Command`

- **`Invocation`** is built once in `main` from the parsed CLI: the subcommand, its arguments and every flag, global flags such as `--config` and `--json` included. `Rerun` renders it exactly. `invocation.with(...)` changes only the named argument; for example `NotDeclared` with a unique closest match substitutes that one word. The rebuilt command keeps every other flag, so dropping `--skip`, `--rotate`, `--target`, `--config` or `--project` can't happen. That rules out the whole X1 class.
- **The child command is never rendered.** Arguments after `--` (`opv run … -- <command>`, `opv login … -- <command>`) are opaque: `Rerun` of `run` stays the read it is today (`opv check …`), and a `login --` step names `-- <command>`, never the child's words.
- **`Cmd`** (simplified after review: no builder per subcommand) is one struct: the subcommand path plus arguments. `Cmd::to_argv()` must round-trip through the real clap definition, which a test checks for every step the catalog can render. Global flags carry over from the invocation.
- **MCP origin.** A tool call has no command line, so it is rendered as the CLI command that does the same work, with every known name filled in and `--json` (owner decision, 2026-10-16: MCP is the `--json` document, so a tool's `error` is byte for byte the CLI's, Rerun included). `Invocation::from_mcp` remains for tests only.
- **No step override on `Error`.** There is no `with_next`/`with_do`. Doctor, ready and the TUI show an error's own step, never their own (07.06, 07.07).
- **Internal steps** (`local-delivery`, `remote-send`, `remote-receive`) carry the invocation of the person's `opv run`, passed down to them. Their errors never point at themselves or at `opv doctor` (X25).

### 6.2 Rules the types make impossible to break

- **No guessed candidate.** `NotDeclared` produces a substitute only from `closest`, which is `Some` only for a unique close match.
- **opv never confirms for the person.** `--confirm`, `--approved`, `--expect-plan` and `--prune-immutable` can appear only inside a `Handoff`.
- **No blind re-run after an unknown create.** `CreateOutcomeUnknown` with `refind: Check` has no `Rerun` arm.
- **No re-run of a used approval.** `Partial` and `ApprovalUsed` produce only `Check`/`Run` reads.

### 6.3 `human_required` is derived

`human_required` is true exactly when the step needs a person:
- a `Handoff`;
- an `Action` marked person-only: Grant, FillValue, Approve, AddAccountInApp, OwnerSetup, Revoke, PickBetween, Confirm;
- or one of the variants `NeedsTerminal`, `NeedsOwnSession`, `NeedsConfirm`, `ApprovalMissing`.

It can't disagree with the step, and the CLI and MCP can't disagree with each other.

It is **guidance, not enforcement**. An agent with a shell can run anything the person can; §9 says what actually stops an agent.

### 6.4 Which steps a situation refuses

A `Next` must not be refused in the current situation (X8). One predicate, `Situation::refuses(&Cmd)`, is checked before rendering any step, **on error and success paths alike** (05.01 was a success step). It covers every X8 condition, plus "a deploy credential or shell token is in effect, so no vendor sign-in". The table:
- under CI, or with no terminal: no `opv login` and no handoff rendered as runnable;
- under a service account or Connect: no `opv login`;
- on a manifest project: no file-only command (`bootstrap`, `init --file`);
- on the wrong platform: no `login --add` where the app holds the accounts;
- a hidden internal command;
- a transport that can't carry it (`-- <command>` with `--remote`);
- an argument of the wrong type (`opv explain <env name>`);
- under deploy credentials or a shell token: no vendor sign-in.

A refused step is rendered as the Do ("in your own terminal: …"), and `Next` falls back to the variant's read. This is code, tested per row of the table.

## 7. Rendering

### 7.1 Terminal

```
opv: vault atqr2ek… is not in 1Password account 6AINMAIK…
  checked: op vault get atqr2ek… in account 6AINMAIK… (signed in as you@example.com)
╭─ 1Password CLI (op 2.31.0) replied, exit 1
│ [ERROR] "atqr2ek…" isn't a vault in this account.
╰─ (scrubbed; op's own advice removed)
Do: find the account that holds it, or fix vault_id for environment staging in secrets.toml
Next: opv vault locate atqr2ek…
```

- **Line 1** is the cause template filled from the subject.
- **The `checked:` line** is opv's own evidence: what it ran, in which account, as whom.
- **The box is the upstream reply** (§7.3).
- **`Do:` comes before `Next:`**, and `Next:` is always the last line.
- **Colour** reinforces but never carries meaning: the box body is dimmed and the source name coloured when stderr is a terminal and `NO_COLOR` is unset. In a non-UTF-8 locale the box falls back to ASCII (`--- op replied (exit 1) ---`, `| `).
- **Remote receiver** messages are labelled `opv on <host> (remote)`.

### 7.2 Document (`--json` and MCP)

```json
{"schema_version": 2, "ok": false, "exit_code": 4,
 "error": {"code": "ids_not_in_account", "category": "auth", "message": "vault atqr2ek… is not in 1Password account 6AINMAIK…",
           "subject": {"vault": "atqr2ek…", "account": "6AINMAIK…", "environment": "staging"},
           "evidence": {"checked": "op vault get atqr2ek…", "account": "6AINMAIK…",
                        "upstream": {"source": "op", "tool": "1Password CLI", "version": "2.31.0", "exit": 1,
                                     "said": ["[ERROR] \"atqr2ek…\" isn't a vault in this account."], "removed_advice": true}},
           "retry": "after_fix", "human_required": false,
           "do": "find the account that holds it, or fix vault_id for environment staging in secrets.toml",
           "next": "opv vault locate atqr2ek…", "next_kind": "run"}}
```

MCP returns exactly this `error` object (plus `ok: false`), with no separate hint table. (`human_required` is false here: an agent can run `opv vault locate` itself; §6.3.) `next_kind` (`rerun`, `run`, `check`, `handoff`, `vendor`, `none`) tells an agent whether it may run the step itself (`run`, `check`, `rerun`) or must hand it to the person (`handoff`, or any step when `human_required` is true).

### 7.3 The upstream reply block

- **Source** names the service and the tool ("1Password CLI", "Fly API via flyctl", "Azure CLI", "kubectl", "GitHub CLI", "ssh", "opv on <host>"), with the version when `doctor` already knows it.
- **`checked:` is opv's call**, rendered from a typed `CallId`: names and IDs only, never a value and never `op run`'s child arguments.
- **Body:** at most five lines, after scrubbing (§8), with control characters and terminal escape sequences removed (§9.4). Lines are cut at 240 characters.
- **`--verbose` passes it all (owner decision).** With `--verbose`, the box holds the tool's complete reply, scrubbed and stripped the same way, with no line or length limit. `--verbose` already prints each external call opv makes; each call's full reply now follows it. MCP tools take the same `verbose` flag.
- **Untrusted text is marked, not withheld.** Text written by a third party (a tool's reply, a Kubernetes condition message, the remote app's output) is identical in every channel. In the document it sits under `evidence.upstream` with `"untrusted": true`, so an agent treats it as data, never as instructions.
- **Removed advice is marked.** When the vendor's own advice is cut (for example op's "run `op signin --help`"), the footer says so.

## 8. Scrubbing in layers, under one guard

**Corrected after review.** Value-matching every output byte corrupts output. A 4-byte stored value `true` turns `"ok": true` into `"ok": ********`, breaking `--json`. It also masks opv's own names (an environment called `production`, when a setting holds that word), which is the generic-message failure this design exists to prevent. So scrubbing has three layers:

1. **Typed fields are clean by construction.** Subjects, steps and document fields are opv's own names and IDs (environment, target, key, vault ID, path). They come from configuration and typed sources and are never value-matched, so they're never masked.
2. **Untrusted text is value-matched at render time, before serialization.** The upstream evidence lines, and any other free-text leaf that came from outside (a vendor message, a dotenv line), are matched against every registered value. Masking happens inside the string, before the JSON is built, so documents stay valid.
3. **A byte backstop at the guard, for secrets only.** The `OutputGuard` still sees every byte written, whether stdout, stderr, the MCP serializer, the TUI renderer or the remote receiver's stderr.
   - It masks registered **secret-kind values of 8 bytes or more** (not settings, not short values), and known token patterns.
   - It strips escape and bidi sequences, buffering by line.
   - It is a last line of defence; a hit at this layer means a typed path leaked, and the canary test treats it as a failure.

Commands get a `&mut dyn Write` that is the guard. Nothing writes to `std::io::stdout()` directly; a test enforces that (§11).

**Test `json_stays_valid_under_registry`:** with values such as `true`, `prod` and a key's own name registered, every command's `--json` output still parses, and every typed name still appears.

**What is registered:**
1. Every field value of every 1Password item opv reads in the run. This is the one `op item get` path, already registered today. A boundary's item is read once and all its fields go in, so the whole item is protected for the run.
2. Every value opv creates or transforms (`SecretValue`).
3. **New:** at startup, the values of credential variables in opv's environment: `OP_SERVICE_ACCOUNT_TOKEN`, `OP_SESSION_*`, `OP_CONNECT_TOKEN`, `FLY_API_TOKEN`, `FLY_ACCESS_TOKEN`, `GH_TOKEN`, `GITHUB_TOKEN`, `AZURE_CLIENT_SECRET`, `ARM_CLIENT_SECRET`. Kube bearer tokens are caught by pattern, not by reading kubeconfig files.
4. **New, on the remote receiver:** every value in its payload.

**Matching (existing, kept):**
- raw, JSON-escaped, base64, base64url and percent-encoded forms;
- each line of a multi-line value;
- the longest match first;
- values shorter than 4 bytes only as whole words.

**Patterns (existing, extended)** catch credentials opv never held: `FlyV1 …`, `ghp_`/`gho_`/`github_pat_`, JWTs, PEM blocks, connection strings with a password, Azure SAS signatures, kube bearer tokens.

**Mask:** a fixed `********`, whatever the value's length (replaces `__SECRET__`).

**Scope:** a CLI run's registry lives for the process. The MCP server clears its registry after every tool call, which it already does.

**Over-masking is limited to untrusted text.** opv's own names are never masked (layer 1). `opv doctor` warns when a registered secret equals a declared name.

**Memory protection** (§9.2) applies to the registry's storage.

## 9. Security

### 9.1 What actually stops an agent

The channel doesn't. An agent with a shell runs `opv … --json` and sees what MCP would show, and terminal UIs only add friction. So the output policy is the same everywhere (§2.4), and protection rests on four things:
1. **Values never appear in any output** (§8).
2. **1Password's own authorization**: the app's biometric or password prompt on a new session and on writes.
3. **Least-privilege identities**: service accounts, deploy tokens, the grants `opv access` computes.
4. **Provider-side protection**: GitHub environment rules and required reviewers, Azure RBAC.

`human_required`, the terminal requirement and approvals are guidance and gates against unattended mistakes. The docs say plainly that they aren't a security boundary against an agent running as the same user (as `docs/design/local-delivery.md` and `remote-delivery.md` already do).

### 9.2 Values in memory

- **The first statement of `main`, for every command, separate from signal handling.** This covers `opv run`, the MCP server, `local-delivery`, `remote-send` and `remote-receive` (today four of these skip it):
  - Linux: `prctl(PR_SET_DUMPABLE, 0)`, which also stops core dumps through a pipe handler (systemd-coredump, apport, WSL's capture), and ptrace and `/proc/<pid>/mem` access by other same-user processes. Plus the **soft** `RLIMIT_CORE = 0` only, so `opv run`'s child (the person's app) keeps its own core-dump behaviour. If the host sets `fs.suid_dumpable=2`, dumps of non-dumpable processes are still possible; `opv doctor` reports that setting.
  - macOS: `RLIMIT_CORE = 0`, and `ptrace(PT_DENY_ATTACH)`.
  - Windows: `SetErrorMode` and opting out of Windows Error Reporting memory collection for the process.
- **No page locking (owner decision, after review).** The same values also pass through unlocked buffers (`op`'s output, JSON parsing, adapter strings), so locking the registry alone would give false assurance. Crash dumps are stopped by the non-dumpable process. Values are zeroized on drop. Swap is the host's concern: the docs recommend encrypted swap, as they already treat root and the kernel as out of scope.
- **Not protected:** root, kernel-level memory capture, a debugger attached before the process makes itself non-dumpable. Stated as a limit.

### 9.3 Steps are never injection paths

- `Next` and `Do` are rendered from typed fields. Every name that reaches a step is validated at its source (configuration names, IDs `^[A-Za-z0-9][A-Za-z0-9._-]*$`) and quoted with `shell_word`.
- Upstream text never reaches a step, only the evidence box.

### 9.4 Upstream text is displayed, never interpreted

The evidence box strips:
- C0 and C1 control characters, other than tab;
- ANSI and OSC escape sequences. OSC 8 links and OSC 52 clipboard writes could make a crafted upstream reply rewrite the terminal or the clipboard.
- bidirectional overrides (U+202A–202E, U+2066–2069).

This applies to every channel; JSON escapes but doesn't strip, so stripping is explicit.

### 9.5 Upstream text in MCP

It's included, scrubbed the same way, and identical to the CLI in default and `--verbose` modes (owner decision). Hiding it from MCP protected nothing (§9.1). It is marked `untrusted: true` (§7.3). Two tests cover it:
- **The canary test** (§11) runs marker values and fake tokens of every known format through every failure path and checks that no channel shows them.
- **The control-character test** checks that no channel passes escapes through.

## 10. Migration

Each phase builds and passes the full test suite. The old API is removed in the same release (FR-60), so there's no parallel path.

1. **Core.** `src/cause` (the enum, subjects, `Next`/`Action`/`Invocation`/`Cmd`, renderers), `OutputGuard`, hardening, scrubber changes.
   - `Error` gains `cause`. The old constructors become deprecated functions that build `Cause::Legacy{category, msg}`.
   - **Legacy is not a parallel path:** it is one arm of the single renderer from the first change, so there is never a second renderer.
   - `Msg::mentions` and `Error::text()` go in this phase, so tests assert on causes, not prose.
   - A ratchet test counts Legacy uses and may only go down. **Promotion from `dev` to `staging` is gated on the ratchet reaching zero**, so no release ships half-migrated.
   - `schema_version` becomes 2 with the first new code, and a test ties the version to the code set.
2. **Diagnosis strategies**, one system per change: `op` first (it carries #157's class), then gh, kubectl, ssh, flyctl and az, each after its recordings exist (§5). Each removes that system's phrase lists and `failure()`/`diagnose()` from the adapter.
3. **Call sites, area by area** (the nine audit areas). Each change converts its area's `Legacy` uses and fixes its area's audit findings, citing the finding IDs in the commit.
4. **Renderers take over.** MCP drops its hint tables; `report_with`, `envelope`, `split_step`, `is_runnable`, `default_step` and doctor's/ready's step rebuilds are deleted.
5. **Close.** `Cause::Legacy` is deleted (the ratchet reaches zero), the `--json` `schema_version` becomes 2, and the error table in `docs/usage.md` and `opv schema` are generated from the enum.

**Not catalog work** (data and logic bugs found by the audit), fixed in the same release with their own tests:
- the TUI reads a pre-0.7 configuration shape, parses error documents as data, and reads fields `access`/`history` never emit;
- `opv_sync`'s pending/held projection;
- `.opv` discovery climbing out of the project: it stops at the repository root (§12.4);
- the skill refresh writing `$HOME` on every command: only installers and `opv skill install` write it (§12.4);
- `history`'s stamp capability;
- `status`'s concealed-config warning;
- `access`'s vault-as-environment argument;
- `--secret-name` validation before any create.

### 10.1 Poka-yoke for the S1 findings outside the error path

Eleven of the 43 S1 findings are not errors, so a message catalog alone wouldn't prevent them:
- **The TUI misreads command documents** (07.01–07.05);
- **`opv_sync`'s lists are always empty** (08.01);
- **`access` passes a vault ID as an environment** (07.10);
- **`status` and `history` claim things nobody checked** (01.01, 01.03);
- **success-path `Next:` lines drop flags** (05.04 and siblings).

They share two mechanisms, and each gets a structural fix:

1. **Typed documents, not `Value` lookups.**
   - Every `--json` document is a Rust struct with `Serialize` and `Deserialize`, defined once next to the command that produces it.
   - The TUI and the MCP projections deserialize command output into those same structs (`deny_unknown_fields` off, required fields required), never `v["name"]`/`e.get(p.section())`.
   - A document with `ok: false` deserializes as the error document, never as data.
   - Test `documents_round_trip`: for each command, its real output from the fake-backed test fixtures deserializes into the struct the consumers use. A renamed or reshaped field fails to compile, or fails this test, instead of silently reading as "nothing".
2. **Success-path steps and claims are typed too.**
   - "Next:" lines on success (adopt's `--apply`, bootstrap's `--ci-reader` commands, `access --create`) use the same `Next`/`Command`/`Invocation` builders as errors, so the X1 flag rules hold there too.
   - Claims such as "keeps no write stamps", "is delivered" and "all clear" come from typed facts: a provider capability (`stamps: bool`), the row's final state after `variables::plan`, and doctor's warnings counted. They are not inferred from an absent value.
   - Test `success_steps_parse`: every success "Next:" is fed through clap, the same check as errors.

## 11. Enforcement tests (poka-yoke by detection)

| Test | Fails when |
|---|---|
| `every_variant_renders` | a variant lacks a fixture (exhaustive `match` over a fixture builder) |
| `every_subject_field_is_shown` | a rendered message omits any fixture identifier of its variant (the specificity guard) |
| `every_next_parses` | a rendered `Run`/`Check`/`Handoff`/`Rerun` step isn't accepted by the real clap definition (`cli_command().try_get_matches_from`) |
| `rerun_keeps_every_flag` | an invocation using every global and scope flag loses one in any variant's step |
| `no_loop` | `Next` equals the failing invocation while the retry class isn't `safe`, and no person-only Do precedes it |
| `refused_steps_are_not_next` | for each refusal-table row (CI, service account, manifest, platform), a variant renders a refused command as `Next` |
| `human_required_matches_step` | `human_required` disagrees with the step's handoff and person-only action |
| `no_raw_errors` | a source file outside `src/cause` constructs a free-text error, or `Cause::Legacy` uses exceed the ratchet |
| `external_causes_only_from_diagnosis` | compile-time (private constructors), plus a grep test for good measure |
| `diagnosis_fixtures` | per system, each recorded failure (fixtures) maps to the expected variant |
| `no_direct_stdout` | a file writes to `std::io::stdout()`/`stderr()`/`println!` outside `src/output.rs` |
| `canary_never_escapes` | a marker value or fake token (per pattern) appears in any channel's output on any failure path |
| `escapes_are_stripped` | an ANSI, OSC or bidi sequence in upstream text reaches any channel |
| `documents_round_trip` | a command's real `--json` output doesn't deserialize into the typed struct its consumers (TUI, MCP) use |
| `success_steps_parse` | a success-path "Next:" isn't accepted by clap, or drops a flag the invocation carried |
| `docs_table_is_generated` | `docs/usage.md`'s error table differs from the enum |
| `hardening_runs_first` | a process path (each command, MCP, the internal steps) holds a value without `PR_SET_DUMPABLE=0` (Linux integration test reading `/proc/self/status`) |

## 12. Self-vetting

### 12.1 Poka-yoke against the audit's step rules (X1–X26)

**Type** means the compiler prevents it; **Test** means a test detects it; **Diagnose** means one strategy owns it; **Guard** means the output choke point does.

| Rule | Mechanism | Residual |
|---|---|---|
| X1 rebuilt commands keep every flag | Type: `Invocation`/`Command` | Low |
| X2 never guess a candidate | Type: `closest` is unique or `None` | Low |
| X3 no write on a guessed object | Type: `NotDeclared` substitutes a write's read | Low |
| X4 opv never confirms or approves | Type: those flags exist only in `Handoff` | Low |
| X5 check first after an unknown create | Type: no `Rerun` arm; Diagnose: writes declare idempotence | Low |
| X6 idempotent unknown is safe, not "nothing changed" | Type: `WriteOutcomeUnknown` vs `Unavailable` (reads only) | Low |
| X7 no loops | Test: `no_loop`; Type: internal steps carry the outer invocation | Low |
| X8 no refused step as Next | Test: refusal table plus `refused_steps_are_not_next` | Medium → Low once the table covers every audit case; new refusals need a row |
| X9, X11 human_required and Do present | Type: derived (§6.3); Test | Low |
| X10 `do` before `next`, and agent-safe | Type | Low |
| X12 no repeated or embedded steps | Type: no free text, so no "then run …" in templates; Test: a template lint | Low |
| X13 diagnose before blaming | Diagnose; `Unrecognized` when unsure | Medium: phrase tables can miss new vendor wording. Detection: recorded fixtures, and every `Unrecognized` is visible with the full reply |
| X14 retry follows the situation | Type: retry class on the variant drives the runner's retry | Low |
| X15 one situation, one code | Type | Low |
| X16 source-aware | Type: `ConfigSource` in subjects | Low |
| X17 name the object | Test: `every_subject_field_is_shown` | Low |
| X18 no internal vocabulary | Type: display tables for enums; Test: lint for `FR-`, `#1`, snake_case slugs and regex characters in templates | Low |
| X19 names only | Guard plus Type (no free-text fields) | Low |
| X20 partial failures say what was written | Type: `Partial` | Low |
| X21 platform-aware routes | Type: `AddRoute`, `InstallHint` | Low |
| X22 principal-aware advice | Diagnose: the runner reports the principal | Medium → Low once each adapter reports deploy credentials (a phase-2 checklist item) |
| X23 validate before gates | Test per command with gates | Medium: per-command discipline; the gate helpers take validated types only |
| X24 MCP from the same cause | Type: one renderer | Low |
| X25 internal steps | Type | Low |
| X26 never claim more than was checked | Type: claims are fields (`writes_started`, `nothing_written` derived from the runner), not prose | Medium: success text is outside the catalog (§10), so it needs review |

### 12.2 Security vetting

| Threat | Mechanism | Residual |
|---|---|---|
| A value read from 1Password reaches any output | Guard: registry plus choke point; Test: canary over every channel | Low |
| A credential opv never read (shell token, vendor token) is echoed by a tool | Guard: startup registration of credential variables plus patterns | Low–Medium: unknown token formats; detection by the canary corpus, extended per provider |
| A crash dump or swap holds values | Hardening first in every process (non-dumpable, soft core limit), zeroize on drop; no page locking | Low for crash dumps; swap is the host's (encrypted swap documented); root and kernel are out of scope |
| A terminal-escape or clipboard injection through an upstream reply | Strip in the evidence box (§9.4); Test | Low |
| A shell injection through a rendered Next | Typed fields validated at source plus `shell_word` | Low |
| An agent acting where a person should | §9.1: real controls are 1Password authorization, identities, provider rules; `human_required` is guidance | Accepted, and stated |
| MCP and CLI disagreeing about what is shown | One renderer | Low |
| An over-masked message hides the cause | Masking only matches registered values and patterns; names come from configuration | Low: accepted direction |
| The remote receiver's messages carry values back | Guard on the receiver plus payload registration | Low |

### 12.3 Corrections from the FMECA review

The review is kept with the review record. It reached the verdict "implement with listed changes", and these changes are applied above:
- **§8:** layered scrubbing (full-byte value scrubbing corrupted JSON and masked opv's own names).
- **§5:**
  - external causes sealed by an `Observed` token from the runner (`#[non_exhaustive]` didn't seal anything inside the crate);
  - diagnosis kept in each adapter (FR-37);
  - creates as their own runner effect;
  - recordings before diagnosis for Fly, Azure, kubectl and ssh;
  - `Unrecognized` carries established facts and points at `--verbose`, not doctor.
- **§6.1:**
  - the child command is never rendered;
  - MCP has its own invocation origin;
  - `Cmd` simplified to one struct with a clap round-trip;
  - no step override on `Error`.
- **§6.4:** one refusal predicate for error and success steps, covering every X8 condition plus deploy credentials and shell tokens.
- **§4.10:** the `RemoteUnreachable` check uses the same pinned SSH options (the first draft's bare `ssh` bypassed host-key pinning).
- **§9.2:** hardening is the first statement of `main`, with the soft core limit only; `suid_dumpable` is reported.
- **§10:**
  - Legacy is one arm of the single renderer;
  - the ratchet reaching zero gates promotion to `staging`;
  - the `schema_version` bump is tied to the code set.
- **§8:** kubeconfig and `SSH_AUTH_SOCK` registration removed.

Small corrections:
- an ID shown abbreviated in prose is never abbreviated in a step;
- `checked:` names the account ID, never an email;
- `Declined` exits 0 and is a notice, not an error;
- `ConfigInvalid.field` comes from the validator, never parsed from the line;
- `closest` is a newtype that only a unique match constructs;
- `EnvName` and `VaultId` are distinct types, so a vault ID can't be passed as an environment (07.10);
- `opv ui` propagates the child's exit code (07.05).

Still open, with the review's position and the owner's earlier decision (§12.4).

### 12.4 Owner decisions

- **`.opv` discovery stops at the repository root.** It never reads a `.opv` above the git top level; outside a repository, it reads only the current directory.
- **Azure diagnosis is deferred for 0.10.0 (2026-10-16).** There are no new Azure recordings. The Azure strategy classifies only what the 2026-10-08 spike recorded and the runner-level facts (timeouts, spawn failures, principal). Every other Azure failure is `Unrecognized`, with Azure's full scrubbed reply. Azure phrases are added when a sandbox recording exists.
- **The agent skill is refreshed only on install:** by `install.sh`, the npm postinstall, and `opv skill install`. No other command writes `$HOME`; `opv doctor` and `opv skill status` report an outdated copy.
- **A vault in another account names that account (#153a, 2026-10-16).** Whenever `InOtherAccount` is diagnosed, opv looks the vault up in the machine's other accounts, using the same read-only probe as `opv vault locate`, which never prompts or signs in. `owning` is then the account that holds the vault. It stays empty only when no account that could be asked holds it, and the message then says which accounts could not be asked. `searched` tells "every other account was asked and none holds it" (the vault ID is wrong for the environment, so the step is the selected account's vault list, never `opv vault locate`, which would repeat the search) from "op listed no accounts, so nothing was searched" (the step stays `opv vault locate`).

### 12.5 Open questions for review

1. **Exit code 70 for internal errors**, a new exit code.
2. **`schema_version` 2 and the code renames (§4.11).** Under FR-60 there are no aliases; consumers of the JSON contract (CI wrappers, the TUI) are updated in the same release.

## 13. End-to-end verification: a simulated world, faults injected, every message snapshotted

The unit and enforcement tests (§11) prove the catalog's rules. This section proves the shipped binary prints the right thing in each real situation.

### 13.1 Where the fakes plug in: the command-line boundary

The fakes stand in for the external tools (`op`, `flyctl`, `az`, `kubectl`, `gh`, `ssh`), not for opv's own provider traits. Mocking a provider trait would skip the adapters' parsing and the diagnosis strategies (§5), which is the code that turns a tool's reply into a cause and produced #157. Faking at the boundary runs every line opv owns, and the shipped binary carries no test-only branch (FR-60).

- **`opv-sim`** is a test-only binary (`tests/sim/`, built by the test harness, never shipped). It installs itself under each tool's name in a temporary `bin` directory that comes first on `PATH`.
- **Its state is a scenario directory**:
  - `world.json`: accounts, sessions, vaults, and items as their `op item get` JSON documents; Fly apps and their secrets; Key Vaults; namespaces; repositories and environments; remote hosts.
  - `faults.toml`: the injected faults (§13.3).
- **The simulated `op` is the "1Password in a file" idea.** It answers `op item get` from the stored document, applies edits to it, and enforces sessions, accounts and per-vault permissions. opv's real 1Password code runs unchanged against it.
- **Replies are recorded, not invented** (CONTRIBUTING): each tool's success and failure shapes come from `tests/fixtures/<tool>/` recordings, so the simulator is only as good as the recordings. The live spikes for Fly, Azure, kubectl and ssh (§5) come first. A manual contract check reruns the recordings against the real tools when a vendor CLI changes.
- **The simulated `ssh`** runs the remote side locally, as `tests/remote_delivery.rs` already does, with faults for host-key mismatch, refused authentication, a drop mid-payload and a drop mid-run.

### 13.2 The test application

`tests/e2e/app/` is one fixture project:
- a `secrets.toml` with two environments (one with `confirm_env`);
- products with secret, setting, shared (`from`), personal, role-scoped and file keys;
- a target for each provider, and a remote profile;
- its `world.json`, with the 1Password documents holding marker values (never real credentials);
- a manifest-backed copy of the same project, for the configuration-in-1Password routes.

### 13.3 The fault matrix

Each external call opv makes is identified by a `CallId`, the same one the evidence box shows. A fault targets calls by `CallId` and occurrence (first, every, or the n-th). The fault kinds:
- 1Password: signed out, app locked, app prompt unanswered, account not on this machine, resource in another account;
- service-account or deploy token rejected;
- forbidden, not found, soft-deleted;
- rate-limited, server error, timeout;
- malformed output;
- **applied but reply lost**, the unknown-outcome case: the simulator changes its world, then fails;
- interrupted mid-call;
- tool missing, tool too old.

The matrix is generated: every command × every `CallId` that command makes in its scenario × every fault applicable to that call. Each cell:
1. runs the real binary in text and `--json` mode, with `OPV_NO_SKILL=1`, a scratch `HOME` and no real credentials;
2. checks the catalog rules on the result:
   - the cause is the one the fault implies;
   - `Next:` parses and doesn't loop;
   - no step is refused in the situation;
   - `human_required` matches the step;
   - no canary value appears;
   - no escape sequence passes through;
   - `--json` is one valid document;
3. **snapshots** stdout, stderr, the document and the exit code under `tests/e2e/snapshots/` (the `insta` crate or an equivalent).

Snapshots are the record that every message was reviewed. A wording change shows up as a reviewable diff in its PR, and a new message can't arrive without one.

For unknown outcomes, the harness also follows the printed `Next:` once, and checks that it converges: the world has exactly one of the created object and no orphan, or the orphan is named in the Do.

### 13.4 Coverage gates

- Every `Cause` variant is reached by at least one cell or scenario snapshot (`tests/e2e/coverage.rs`). Variants no end-to-end run can reach (`Bug`, and the few with no recording or simulator support) are exempt and listed there with their reason.
- Every `CallId` in the code is exercised by at least one fault.
- Every MCP tool is driven through the same scenarios over JSON-RPC (the `tests/mcp_protocol.py` approach). Its documents are snapshotted next to the CLI's, and a test checks the tool's `error` equals the CLI's `--json` `error`.

### 13.5 Regression scenarios for the reported issues

These are written first, as failing scenarios, before the code that fixes them:
- **#157:** access while signed out; access with one vault outside the account; login while signed in but the vault list failing.
- **#159:** `bootstrap --rebind staging --rebind prod --dry-run --json` with both value vaults outside the account. It must print one JSON document, report `create` for both boundaries, and attribute any failure to its call in `--verbose`. The report's "setup vault" message comes from no bootstrap code, so this scenario finds where it does come from (likely the automatic sign-in retry in `main`).
- **The live-run audit's 95 scenarios**, converted into simulator scenarios.
