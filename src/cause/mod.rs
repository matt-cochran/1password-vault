//! The error catalog (design `docs/design/error-catalog.md`): every failure opv reports is a
//! [`Cause`] — a closed set of variants whose fields are typed subjects ([`subject`]) — plus
//! optional [`Upstream`] evidence. The stable `code`, the exit code and the retry class are
//! derived here from the variant; the message, Do and Next are rendered by `render` from the
//! same variant, so nothing about a failure is written as free text at a call site.
//!
//! This module is the contract the rest of the catalog builds against: the types and their
//! derived classifications. Rendering (`render`, `evidence`) and steps (`step`) are separate
//! modules.

pub mod codes;
pub mod config_check;
pub mod evidence;
pub mod render;
pub mod situation;
pub mod step;
pub mod subject;

use std::path::PathBuf;

pub use config_check::{ConfigCheck, Declared, StoreNameProblem};
pub use subject::*;

// --- external calls ------------------------------------------------------------------------

/// Which external call failed: the program and its subcommand words, names only (never a
/// value, never `op run`'s child arguments). Rendered in the evidence's `checked:` line.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub struct CallId {
    pub system: System,
    /// The program as run (`op`, `flyctl`, `az`, `kubectl`, `gh`, `ssh`).
    pub program: String,
    /// Subcommand words and identifier arguments (`vault get <vault id>`), names only.
    pub words: Vec<String>,
}

/// What the runner observed about one failed call. Only the runner builds one, for a call it
/// actually made and that failed (design §5 "Sealing"): external-system variants carry it, so
/// a call site that made no call cannot build an external cause. The constructor is
/// crate-visible and its single legitimate caller is the runner; a guard test enforces that.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Observed {
    call: CallId,
    exit: ExitClass,
    /// Who was acting when the call failed (person, deploy credentials, a shell token).
    principal: Principal,
    /// How many times the runner made the call: a read is retried (B: the count a cause
    /// names is the one the retry notices showed, never a guess).
    #[serde(skip)]
    attempts: u32,
    #[serde(skip)]
    _sealed: (),
}

impl Observed {
    /// For the runner only (see the type's documentation).
    #[doc(hidden)]
    pub(crate) fn from_failed_call(call: CallId, exit: ExitClass, principal: Principal) -> Self {
        Self {
            call,
            exit,
            principal,
            attempts: 1,
            _sealed: (),
        }
    }
    /// For the runner only: the same observation, made on the call's `n`-th attempt.
    #[doc(hidden)]
    pub(crate) fn on_attempt(self, n: u32) -> Self {
        Self {
            attempts: n.max(1),
            ..self
        }
    }
    /// For the runner only, like [`Observed::from_failed_call`]: a call it made that
    /// answered (`exit`, normally exit 0) with a reply the call site cannot use (A1:
    /// `UnexpectedOutput`, `WriteOutcomeUnknown`, `TargetRefused`, `CreateOutcomeUnknown`).
    #[doc(hidden)]
    pub(crate) fn from_unusable_reply(call: CallId, exit: ExitClass, principal: Principal) -> Self {
        Self {
            call,
            exit,
            principal,
            attempts: 1,
            _sealed: (),
        }
    }
    pub fn call(&self) -> &CallId {
        &self.call
    }
    pub fn exit(&self) -> ExitClass {
        self.exit
    }
    pub fn principal(&self) -> &Principal {
        &self.principal
    }
    /// How many times the runner made the call (1 unless a read was retried).
    pub fn attempts(&self) -> u32 {
        self.attempts
    }
}

/// How a failed call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExitClass {
    Code {
        code: i32,
    },
    Signal {
        signal: i32,
    },
    TimedOut,
    SpawnFailed,
    /// The call ran but opv could not collect its reply (a pipe failed, or opv could not
    /// wait for it): its outcome is unknown, and it neither timed out nor was killed.
    Lost,
}

impl ExitClass {
    /// Why a call that ended this way never answered: opv's timeout, a signal, or a lost
    /// reply. `None` when the call did answer (an exit code) or never started. Every
    /// diagnosis takes its unfinished-call reason from here, so a killed or lost call is
    /// never reported as a timeout (D6, X26).
    pub fn unanswered(self) -> Option<Unanswered> {
        match self {
            ExitClass::TimedOut => Some(Unanswered::Timeout),
            ExitClass::Signal { signal } => Some(Unanswered::Killed { signal }),
            ExitClass::Lost => Some(Unanswered::Lost),
            ExitClass::Code { .. } | ExitClass::SpawnFailed => None,
        }
    }
}

/// The upstream tool's reply, shown in the evidence box (§7.3). Scrubbed and stripped before
/// it is stored here; marked untrusted in every channel.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Upstream {
    pub source: System,
    /// "1Password CLI", "Fly API via flyctl", …
    pub tool: String,
    pub version: Option<String>,
    pub exit: ExitClass,
    /// Every line of the reply, already scrubbed. The box and `evidence.upstream` show the
    /// error line plus the tail, or all of it under `--verbose` ([`evidence::shown_lines`]).
    pub said: Vec<String>,
    /// The reply was longer than the runner keeps ([`crate::runner::STDERR_CAP`]): only
    /// its end is in `said`, and every channel says so.
    pub truncated: bool,
    /// The vendor's own advice was cut (it conflicts with opv's steps).
    pub removed_advice: bool,
    /// Always true: third-party text is data, never instructions.
    pub untrusted: bool,
}

// --- steps -----------------------------------------------------------------------------------

/// The command line the person (or an MCP tool call) ran, as parsed. `Rerun` renders it
/// exactly, with every flag; arguments after `--` are opaque and never rendered (design §6.1).
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct Invocation {
    pub origin: Origin,
    /// Subcommand path (`["run"]`, `["target", "add"]`).
    pub command: Vec<String>,
    /// Every flag and positional argument before `--`, in order, as the person gave them.
    pub args: Vec<String>,
    /// The person passed a child command after `--` (run, login); never rendered.
    pub has_child: bool,
}

/// Where the invocation came from.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Origin {
    #[default]
    Cli,
    Mcp {
        tool: String,
    },
}

/// One opv command a step names: the subcommand path plus arguments. `step::to_argv`
/// round-trips it through the real clap definition (tested for every renderable step).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Cmd {
    pub command: Vec<String>,
    pub args: Vec<String>,
}

/// A vendor command a step names (a sign-in, an install, a pinned connectivity check).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct VendorCmd {
    pub program: String,
    pub args: Vec<String>,
}

/// What to run next (design §6).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", content = "command", rename_all = "snake_case")]
pub enum Next {
    /// The invocation as typed, every flag kept.
    Rerun,
    /// An opv command opv built.
    Run(Cmd),
    /// A read that answers "did it happen?" or "what remains?".
    Check(Cmd),
    /// Only a person runs it (approve, `--confirm`, login in their own terminal).
    Handoff(Cmd),
    /// A typed vendor command.
    Vendor(VendorCmd),
    /// No command: the person decides (for example, which copy of a configuration wins).
    None(NoNext),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoNext {
    PersonPicksDirection,
    NothingToRun,
}

/// What must be done before Next, typed so `human_required` can be derived (design §6.3).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    /// Fill a value in 1Password.
    FillValue {
        product: ProductName,
        key: KeyName,
        env: EnvName,
    },
    /// A grant someone with access must make.
    Grant {
        principal: Principal,
        resource: ResourceRef,
        grant: GrantModel,
    },
    /// Sign in at a vendor (typed command shown as the step).
    SignIn {
        system: System,
        account: Option<AccountId>,
    },
    /// Unlock the 1Password app and approve its prompt.
    UnlockApp,
    /// Add an account (in the app or at op's prompt).
    AddAccount { account: AccountRef },
    /// Pick between candidates that only a person can tell apart.
    PickBetween,
    /// Approve a plan in the person's own terminal.
    Approve { plan: PlanId },
    /// Confirm the environment.
    Confirm { env: EnvName },
    /// Revoke an orphan whose secret was never stored.
    Revoke { kind: CreateKind, name: String },
    /// Owner setup at a provider (a GitHub environment, an operator).
    OwnerSetup { object: ResourceRef },
    /// Unset an overriding variable for the command.
    Unset { var: VarName },
    /// Change a file's mode.
    Chmod { path: PathBuf, mode: u32 },
    /// Edit a configuration field.
    EditConfig {
        source: ConfigSource,
        field: DottedPath,
    },
    /// Edit an input file that holds secret values; only a person opens it.
    EditInput { path: PathBuf },
    /// Install or update a tool.
    Install { tool: String },
    /// Free of person-only meaning: check something named by the subject.
    Inspect,
}

impl Action {
    /// True when only a person may do it (design §6.3).
    pub fn person_only(&self) -> bool {
        matches!(
            self,
            Action::FillValue { .. }
                | Action::Grant { .. }
                | Action::SignIn { .. }
                | Action::UnlockApp
                | Action::AddAccount { .. }
                | Action::PickBetween
                | Action::Approve { .. }
                | Action::Confirm { .. }
                | Action::Revoke { .. }
                | Action::OwnerSetup { .. }
                | Action::EditInput { .. }
        )
    }
}

// --- the catalog ----------------------------------------------------------------------------

/// Why a configuration field is invalid (§4.12); the Do is built from (field, rule).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum FieldRule {
    Syntax,
    Pattern {
        id: PatternId,
    },
    Reserved {
        set: Vec<String>,
    },
    Empty,
    Type {
        expected: &'static str,
    },
    Unknown {
        suggestion: Option<String>,
    },
    Missing,
    ConflictsWith {
        field: DottedPath,
    },
    DuplicateKey,
    RemovedForm {
        form: &'static str,
        replacement: String,
    },
    NoEnvironment,
    ModeUnmapped {
        env: EnvName,
        mode: String,
        allowed: Vec<String>,
    },
    Collision {
        rendered: String,
        other: DottedPath,
    },
    /// A check between fields (`config_check`), with its own words.
    Check {
        check: ConfigCheck,
    },
}

/// What a `NotFound` resource's state is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotFoundState {
    Missing,
    SoftDeleted,
    LocalContextMissing,
}

/// Why the 1Password or target session is missing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SessionState {
    SignedOut,
    Expired,
    AppLocked,
    AppPromptUnanswered {
        waited_seconds: u64,
    },
    /// A live session exists, but for another account on the same sign-in address (#160).
    OtherAccount {
        live: AccountId,
    },
    /// A 1Password write found no session of the person's own: a sign-in made inside an
    /// earlier opv command (such as its --dry-run) ended with that command (#150).
    EndedWithEarlierCommand,
}

/// Why a provider didn't answer (reads only).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "why", rename_all = "snake_case")]
pub enum Unanswered {
    Timeout,
    /// The call was ended by this signal before it answered (not opv's own timeout).
    Killed {
        signal: i32,
    },
    /// The call ran but its reply was lost (see [`ExitClass::Lost`]).
    Lost,
    RateLimited {
        retry_after_seconds: Option<u64>,
    },
    ServerError {
        status: u16,
    },
    Network,
}

/// How opv will find a possibly-created object again (X5).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", content = "check", rename_all = "snake_case")]
pub enum Refind {
    /// opv finds it again by title on the next run: re-running is safe.
    ByTitle,
    /// A person checks with this command before anything is re-created.
    Check(Cmd),
    /// A person checks with this vendor command (the object lives only at the vendor, such
    /// as a Fly deploy token: `flyctl tokens list --app <app>`).
    Vendor(VendorCmd),
}

/// Every failure opv reports. Grouped as in design §4.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "cause", rename_all = "snake_case")]
pub enum Cause {
    // §4.1 configuration
    ConfigNotFound {
        searched_from: PathBuf,
        env: Option<EnvName>,
        /// The 1Password manifest search that found nothing too, when one ran (03.20: only
        /// the selected account is searched).
        manifest: Option<ManifestSearch>,
    },
    ConfigSourceMismatch {
        command: CommandId,
        manifest: String,
    },
    ConfigUnreadable {
        path: PathBuf,
        io: IoKind,
        given_by: GivenBy,
    },
    ConfigInvalid {
        source: ConfigSource,
        at: Option<Location>,
        field: DottedPath,
        rule: FieldRule,
    },
    BoundaryMissing {
        env: EnvName,
        product: ProductName,
        source: ConfigSource,
    },
    StateVaultMissing {
        env: EnvName,
        target: TargetName,
        source: ConfigSource,
    },
    StateVaultTooWide {
        env: EnvName,
        target: TargetName,
        vault: VaultId,
        shared_with: Vec<TargetName>,
        source: ConfigSource,
        at: Option<Location>,
    },
    ConfigNotEditable {
        source: ConfigSource,
        reason: NotEditable,
    },
    CopiesDiffer {
        file: PathBuf,
        manifest: String,
    },
    ManifestNotFound {
        project: String,
        account: Option<AccountId>,
    },
    ManifestAmbiguous {
        candidates: Vec<String>,
        person_picks: bool,
    },
    ManifestExists {
        title: String,
        local_file: Option<PathBuf>,
    },
    InventoryIncomplete {
        unlisted: Vec<AccountId>,
    },

    // §4.2 names and usage
    NotDeclared {
        kind: NameKind,
        given: String,
        candidates: Vec<String>,
        closest: Option<Closest>,
    },
    /// A key that is not declared for one environment (R21): "key X is not declared for
    /// environment E".
    KeyNotDeclared {
        key: KeyName,
        env: EnvName,
        product: Option<ProductName>,
    },
    Ambiguous {
        kind: NameKind,
        given: String,
        candidates: Vec<String>,
    },
    ChoiceRequired {
        flag: String,
        candidates: Vec<String>,
    },
    NothingInScope {
        env: EnvName,
        what: Scope,
    },
    Usage {
        problem: UsageProblem,
    },
    AlreadyDeclared {
        kind: NameKind,
        name: String,
    },

    // §4.3 sessions, accounts, credentials
    NotSignedIn {
        system: System,
        account: Option<AccountId>,
        state: SessionState,
    },
    AccountNotOnMachine {
        account: AccountRef,
        selected_by: AccountSource,
        in_app: bool,
    },
    AccountAmbiguous {
        given: String,
        candidates: Vec<AccountId>,
    },
    /// Several 1Password accounts are on this machine and this project names none (no
    /// `.opv`, no `OP_ACCOUNT`, no `--account`): opv never uses op's default, so a person
    /// picks one. Public code `account_required`.
    AccountRequired {
        accounts: Vec<AccountChoice>,
    },
    InOtherAccount {
        vault: VaultId,
        item: Option<ItemId>,
        selected: AccountId,
        /// The account on this machine that holds the vault, found by the read-only search
        /// of the other accounts (#153a).
        owning: Option<AccountId>,
        /// The other accounts that could not be asked (not signed in, or the check did not
        /// finish), when none that could be asked holds the vault (#153a).
        unasked: Vec<AccountId>,
        /// The machine's other accounts were listed and looked through (#153a): with no
        /// `owning` and nothing `unasked`, no account on this machine holds the vault. False
        /// when no search was made (op did not list the accounts), so nothing is known.
        searched: bool,
        env: Option<EnvName>,
        seen: Observed,
    },
    NeedsOwnSession {
        command: CommandId,
        identity: Principal,
    },
    CredentialRejected {
        system: System,
        credential: CredentialRef,
        problem: CredentialProblem,
        seen: Observed,
    },

    // §4.4 access and resources
    MissingRight {
        system: System,
        resource: ResourceRef,
        right: Right,
        grant: GrantModel,
        env: Option<EnvName>,
        target: Option<TargetName>,
        seen: Observed,
    },
    OwnerSetupRequired {
        system: System,
        object: ResourceRef,
    },
    NotFound {
        system: System,
        resource: ResourceRef,
        named_by: NamedBy,
        state: NotFoundState,
        seen: Observed,
    },

    // §4.5 target outcomes and guards
    TargetRefused {
        system: System,
        subject: ResourceRef,
        why: Refusal,
        env: Option<EnvName>,
        target: Option<TargetName>,
        seen: Observed,
    },
    Guard {
        guard: Guard,
    },
    /// A mounted secrets volume the workload cannot read, or whose readability is unknown
    /// (delivery-transports §6.6): the fix is in the person's own manifest, so it has its
    /// own code. Raised by the Kubernetes and Swarm preflights (K5/K6, §8.8).
    MountUnreadable {
        workload: String,
        container: String,
        run_as: Option<u32>,
        why: MountWhy,
        env: EnvName,
        target: TargetName,
    },

    // §4.6 outcomes, availability, budgets
    CreateOutcomeUnknown {
        system: System,
        kind: CreateKind,
        name: String,
        refind: Refind,
        seen: Observed,
    },
    WriteOutcomeUnknown {
        system: System,
        subject: ResourceRef,
        seen: Observed,
    },
    Unavailable {
        system: System,
        why: Unanswered,
        attempts: u32,
        seen: Observed,
    },
    BudgetSpent {
        budget_seconds: u64,
        writes_started: bool,
    },
    Partial {
        done: Vec<String>,
        approval_used: Option<PlanId>,
        /// What the used approval covered: Next reads what remains in that same scope.
        approval_scope: Option<PlanScope>,
        then: Box<Cause>,
    },
    Interrupted {
        signal: i32,
        writes_started: bool,
    },
    ChangedBeforeWrite {
        object: StoreObject,
    },
    ConcurrentEdit {
        object: StoreObject,
    },
    ReadBackMissing {
        vault: VaultId,
        item: ItemId,
        fields: Vec<FieldName>,
        /// The command that wrote, as a command line (never split from text: F2).
        by: Cmd,
    },

    // §4.7 external tools
    ToolMissing {
        tool: String,
        /// The platform and shell the install line is for.
        #[serde(serialize_with = "platform_word")]
        platform: crate::host::Platform,
        #[serde(serialize_with = "shell_kind")]
        shell: crate::host::Shell,
        /// Under CI the install line is the CI job's.
        ci: bool,
    },
    ToolUnusable {
        tool: String,
        why: Unusable,
    },
    /// A call that answered, but with output opv cannot use (A1): unparseable, or empty
    /// where a value was due (a minted token).
    UnexpectedOutput {
        system: System,
        at: Option<Location>,
        problem: OutputProblem,
        /// A read's reply, or the reply of a write the provider applied (exit 0).
        during: During,
        seen: Observed,
    },
    Unrecognized {
        system: System,
        established: Vec<String>,
        env: Option<EnvName>,
        target: Option<TargetName>,
        seen: Observed,
    },

    // §4.8 person-only steps, local inputs
    NeedsTerminal {
        why: NoTerminal,
    },
    NeedsConfirm {
        env: EnvName,
    },
    ConfirmMismatch {
        given: String,
        env: EnvName,
    },
    ValuesNeeded {
        env: EnvName,
        rows: Vec<ValueRow>,
    },
    /// A write refused because values are missing or fail their rule (exit 6,
    /// `keys_blocking`); `ValuesNeeded` is the finding of a read (exit 8).
    KeysBlocking {
        env: EnvName,
        rows: Vec<ValueRow>,
    },
    LocalFileTooOpen {
        path: PathBuf,
        mode: u32,
        want: u32,
    },
    InputInvalid {
        path: PathBuf,
        kind: InputKind,
        at: Option<Location>,
        field: String,
        rule: FieldRule,
    },

    // §4.9 approvals and plans
    ApprovalMissing {
        plan: PlanId,
        scope: PlanScope,
    },
    ApprovalUsed {
        plan: PlanId,
        scope: PlanScope,
        partial: bool,
    },
    PlanChanged {
        old: PlanId,
        new: PlanId,
        scope: PlanScope,
    },
    PlanUnknown {
        plan: String,
        /// The scope the plan id was given for, when the invocation says.
        scope: Option<PlanScope>,
    },

    // §4.10 platform, delivery, internal
    RamDirUnavailable {
        remote: Option<ProfileName>,
        why: RamDir,
        /// What the folder was for: the settings file, or az's deploy sign-in (R74).
        purpose: RamPurpose,
        /// The run whose preview checks the folder again, when known.
        env: Option<EnvName>,
        product: Option<ProductName>,
    },
    PrivateDirFailed {
        dir: PathBuf,
        io: IoKind,
    },
    RemoteUnreachable {
        profile: ProfileName,
        user: String,
        host: String,
        port: u16,
        /// The file holding the host key pinned in the profile, as opv's own check uses it.
        known_hosts: PathBuf,
        /// The profile's identity file, which the pinned check uses too.
        identity_file: Option<PathBuf>,
    },
    /// The connection ended or stalled after the payload was sent: ssh itself exits 255
    /// mid-session (recorded: "closed by remote host", "server not responding"), so a 255
    /// after the handshake is not always the remote app's own exit.
    RemoteDisconnected {
        profile: ProfileName,
        host: String,
        during: RemotePhase,
    },
    RemoteVersionMismatch {
        profile: ProfileName,
        remote_protocol: u32,
    },
    ChildStartFailed {
        program: String,
        workdir: Option<PathBuf>,
        io: IoKind,
        remote: Option<ProfileName>,
    },
    DeliveryUnverified {
        env: EnvName,
        target: TargetName,
        product: ProductName,
        state: Unverified,
    },
    /// A pinned target's binding no longer matches 1Password (C3): `status --fail-on-drift`
    /// reports it as a finding (exit 8, `target_drift`).
    TargetDrift {
        env: EnvName,
        target: TargetName,
        /// The store names that drifted, in the order `status` prints them.
        names: Vec<String>,
    },
    /// A source item changed since the last sync, or no recorded source versions exist
    /// (`delivery-transports` §2.2). A result, not a failure: `ok: true`, exit 10; the
    /// step it names is the sync (or `opv bootstrap` when no delivery item is recorded).
    SourceChanged {
        env: EnvName,
        /// No `source versions` recorded for the placement: its delivery item is missing,
        /// or an older opv synced it and never wrote the field.
        no_record: bool,
    },
    /// opv's own local input or output failed (writing a file, finding the working folder,
    /// its own executable or the home folder, writing to stdout).
    LocalIo {
        op: LocalOp,
        path: PathBuf,
        io: IoKind,
    },
    /// An external store (a ClusterSecretStore) is not ready; `reason` is the condition's
    /// reason code (a CamelCase word) when it names one, never its message.
    StoreNotReady {
        store: ResourceRef,
        reason: Option<String>,
    },
    /// Another process connected to opv's private hand-off pipe for a vendor CLI: opv
    /// refused it and sent nothing.
    HandoffPipeContested {
        system: System,
    },
    /// A configuration change opv proposed (and did not write) would be invalid (F2).
    ConfigProposalInvalid {
        source: ConfigSource,
        field: DottedPath,
        rule: FieldRule,
        /// The field is in opv's proposed change only, not in the file it changes: the
        /// person cannot remove it, so the Do names only what they can change (R2-4).
        from_proposal: bool,
    },
    /// An input file (a dotenv file, a setup recipe, a receipt) could not be read (F4).
    InputUnreadable {
        path: PathBuf,
        kind: InputKind,
        io: IoKind,
    },
    /// A 1Password item opv was pointed at has a layout opv cannot use (F4).
    ItemUnusable {
        vault: Option<VaultId>,
        title: String,
        problem: ItemProblem,
    },
    /// A secret-bearing object was made at the provider, but its secret was never stored
    /// (A22): nobody holds it, so it is revoked, never made again (X5).
    SecretNotStored {
        system: System,
        kind: CreateKind,
        name: String,
        env: EnvName,
        /// The target the run named, when it named one (a CI reader names none).
        target: Option<TargetName>,
        /// The provider's own listing that shows the object, when there is one.
        refind: Option<VendorCmd>,
    },
    /// A source-only product (FR-47) named on its own: it holds shared values for other
    /// products' keys and is never run, checked or planned by itself.
    SourceOnly {
        product: ProductName,
        env: Option<EnvName>,
        /// A product that reads it, when one does: the step names it instead.
        reader: Option<ProductName>,
    },
    /// The person's own item for `env` is not set up (`then`: its vault or item not found),
    /// so the personal `keys` a run needs have no value (FR-55, J6). Code, exit code, retry
    /// and steps are `then`'s.
    PersonalNotSetUp {
        env: EnvName,
        keys: Vec<ProductKey>,
        then: Box<Cause>,
    },
    /// No 1Password vault or item, or more than one, has exactly this title (a lookup in a
    /// listing that answered, never a failed call).
    TitleLookup {
        /// `Vault` or `Item`.
        kind: ResourceKind,
        title: String,
        /// The vault searched, for an item.
        vault: Option<VaultId>,
        /// How many have the title: 0, or more than one.
        matches: usize,
        /// The candidates by title and ID: the listing's for none, the matches for several.
        candidates: Vec<String>,
    },
    Bug {
        site: &'static str,
    },
}

/// The manifest search behind a `ConfigNotFound`: the repository tag it looked for (none
/// without a remote) and the one account it searched.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ManifestSearch {
    pub repo: Option<String>,
    pub account: Option<AccountId>,
}

/// Why an item cannot be used as it is (F4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemProblem {
    /// The item with this title is another category than opv needs.
    WrongCategory,
    /// More than one object has this title.
    DuplicateTitle,
}

/// Why opv does not generate a key's value (R64, F2): each reason has its own step.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum GenerateRefusal {
    /// A prefix rule says the provider issues it.
    ProviderIssued,
    /// The rules give no byte length.
    NoByteCount,
    /// The rules give a byte count outside 16..=1024, or both forms.
    ByteCountOutOfRange,
    /// A personal key: each person keeps their own value.
    Personal,
    /// A shared key: its value comes from the key it reads from (`PRODUCT/KEY`).
    Shared { from: String },
    /// Its field already holds a value; generate never replaces one.
    HasValue,
}

impl GenerateRefusal {
    /// The reason in words.
    pub fn words(&self) -> &'static str {
        match self {
            GenerateRefusal::ProviderIssued => "its prefix rule says the provider issues it",
            GenerateRefusal::NoByteCount => {
                "its rules give no byte length (base64_bytes or hex_bytes), so the provider issues it"
            }
            GenerateRefusal::ByteCountOutOfRange => {
                "its rules must give one of base64_bytes or hex_bytes, between 16 and 1024"
            }
            GenerateRefusal::Personal => "it is a personal key, so each person has their own value",
            GenerateRefusal::Shared { .. } => {
                "it is a shared key, so its value comes from the key it reads from"
            }
            GenerateRefusal::HasValue => {
                "its field already holds a value, and opv generate never replaces one (rotation is a reviewed step)"
            }
        }
    }
}

/// `ToolMissing.platform` in the document (`host::Platform` has no serde form of its own).
fn platform_word<S: serde::Serializer>(p: &crate::host::Platform, s: S) -> Result<S::Ok, S::Error> {
    use crate::host::Platform;
    s.serialize_str(match p {
        Platform::Linux => "linux",
        Platform::Wsl => "wsl",
        Platform::MacOs => "macos",
        Platform::Windows => "windows",
        Platform::Other => "other",
    })
}

/// `ToolMissing.shell` in the document.
fn shell_kind<S: serde::Serializer>(sh: &crate::host::Shell, s: S) -> Result<S::Ok, S::Error> {
    use crate::host::Shell;
    s.serialize_str(match sh {
        Shell::Posix => "posix",
        Shell::Fish => "fish",
        Shell::PowerShell => "powershell",
        Shell::Other => "other",
    })
}

/// Supporting enums of the catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IoKind {
    NotFound,
    PermissionDenied,
    IsADirectory,
    /// A symbolic link (or another kind of file) where opv reads and writes only a plain file
    /// (a symlinked `.opv`): opv never writes through it.
    NotAPlainFile,
    Other,
}

impl From<std::io::ErrorKind> for IoKind {
    fn from(k: std::io::ErrorKind) -> Self {
        match k {
            std::io::ErrorKind::NotFound => IoKind::NotFound,
            std::io::ErrorKind::PermissionDenied => IoKind::PermissionDenied,
            std::io::ErrorKind::IsADirectory => IoKind::IsADirectory,
            _ => IoKind::Other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum NotEditable {
    /// Generated from `generator`, when opv knows what generates it (A22).
    Generated {
        generator: Option<PathBuf>,
    },
    UnsupportedLayout {
        section: String,
    },
    ManifestItemAsBoundary {
        env: EnvName,
        boundary: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "what", rename_all = "snake_case")]
pub enum Scope {
    NoProductHasKeys,
    NoTargetDelivers {
        target: TargetName,
    },
    /// The target delivers no secret, so there is no delivery to verify.
    NoSecretDelivered {
        target: TargetName,
    },
    NoTargets {
        products: Vec<ProductName>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum UsageProblem {
    UnknownFlag {
        flag: String,
        closest: Option<Closest>,
    },
    MisplacedBeforeDashDash {
        flag: String,
    },
    ConflictsWith {
        a: String,
        b: String,
    },
    ValueFormat {
        flag: String,
        format: &'static str,
    },
    /// One entry of a repeatable option is malformed (`--rotate`, `--prune-immutable`).
    EntryFormat {
        flag: String,
        entry: String,
        format: &'static str,
    },
    NeedsFlag {
        flag: String,
        needs: String,
    },
    UseInstead {
        command: Cmd,
    },
    /// A file the command would write already exists; `--force` replaces it (F4).
    FileExists {
        path: PathBuf,
    },
    /// A removed form (FR-60): what was removed, and the command that does it now.
    Removed {
        what: &'static str,
        instead: Cmd,
    },
    /// A command line the parser refused: its own first line (it names the argument it
    /// could not place), and the subcommand path whose help to read (empty: `opv --help`).
    Rejected {
        message: String,
        help: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum CredentialProblem {
    Rejected {
        needs: Vec<String>,
    },
    Incomplete {
        missing_fields: Vec<FieldName>,
    },
    Unreadable,
    /// A variable in the environment overrides what the person typed (OP_ACCOUNT, GH_TOKEN…).
    OverriddenByEnvironment {
        var: VarName,
    },
    /// A field of the credential's item has another type than the one it must be.
    WrongType {
        field: FieldName,
        expected: FieldType,
    },
    /// A field of the credential's item is there more than once, so opv cannot tell which.
    DuplicateField {
        field: FieldName,
    },
}

/// One of the person's own 1Password accounts, shown so they can choose
/// (`AccountRequired`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AccountChoice {
    pub email: String,
    /// The sign-in address (`my.1password.com`).
    pub address: String,
    pub id: AccountId,
}

/// The 1Password field type a credential's field must have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    /// A concealed (password) field.
    Concealed,
    /// A plain text field.
    Text,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "why", rename_all = "snake_case")]
pub enum Refusal {
    Validation,
    Quota,
    Unhealthy {
        new_revision: String,
        serving: Option<String>,
    },
    NoRevision,
    /// The app is not running (a dead app).
    NotRunning,
    /// A change is still in progress at the provider: opv's own `revision` still rolling
    /// out, or (`None`) someone else's change.
    InProgress {
        revision: Option<String>,
    },
    /// Settings opv does not manage changed outside opv: before opv's write (nothing
    /// written), or while opv's write was applied (`after_apply`: opv's change is live).
    /// `paths`: the changed settings, as JSON paths (never their values).
    ChangedOutsideOpv {
        paths: Vec<String>,
        after_apply: bool,
    },
    /// The app runs more than one revision at a time; opv pins by replacing the one active
    /// revision (NR-25), so only single-revision mode is written to.
    RevisionMode {
        mode: String,
        resource_group: String,
        subscription: String,
    },
}

/// What was wrong with a call's output (`UnexpectedOutput`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum OutputProblem {
    /// It could not be parsed (JSON, a version line).
    Unparseable,
    /// It was empty where a value was due (`what`: "deploy token").
    Empty { what: &'static str },
    /// It held `what`, but in a form opv cannot use (a version ID that is not one).
    InvalidValue { what: &'static str },
}

/// Which call gave the reply of an `UnexpectedOutput`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum During {
    /// A read: nothing was changed.
    Read,
    /// A write the provider applied (it exited 0): the change is made, only its reply is
    /// unusable.
    AppliedWrite,
}

/// Which of opv's own local operations failed (`LocalIo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalOp {
    Read,
    Write,
    CreateDir,
    CurrentDir,
    CurrentExe,
    HomeDir,
    Stdout,
    /// Standard input (a prompt's answer).
    Stdin,
    /// The MCP session with its client over standard input and output: the handshake.
    McpHandshake,
    /// The MCP session after the handshake.
    McpSession,
    /// The operating system's random source (F2).
    RandomSource,
}

/// Why a mounted secrets volume would be unreadable or is of unknown readability
/// (delivery-transports §6.6): the workload sets no `fsGroup`, or its effective group is
/// unknown. Shared by the Kubernetes and Swarm preflights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MountWhy {
    NoFsGroup,
    RunAsUnknown,
}

/// opv's own refusals that are not person-only steps (§4.5).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "guard", rename_all = "snake_case")]
pub enum Guard {
    ValueTooLarge {
        product: ProductName,
        key: KeyName,
        env: EnvName,
        limit: u64,
    },
    NotManagedByOpv {
        name: String,
    },
    CredentialAsOption {
        option: String,
    },
    ProviderHidesValues {
        system: System,
    },
    ImmutableWithoutRotate {
        key: KeyName,
    },
    GenerateRefused {
        product: ProductName,
        key: KeyName,
        env: EnvName,
        reason: GenerateRefusal,
    },
    RemoteProfileRefuses {
        profile: ProfileName,
        asked: String,
        allowed: Vec<String>,
    },
    /// The `secrets_dir` path, or a parent or child of it, is already a volume of the
    /// workload (delivery-transports §6.4): opv's secrets volume cannot go there.
    MountPathInUse {
        workload: String,
        container: String,
        path: String,
        volume: String,
        env: EnvName,
        target: TargetName,
    },
    Declined,
    /// A key's kind has no channel on the target (design §1.3, §1.5): `sync` refuses it
    /// (`policy_refused`, exit 6, retry never) unless the target declares
    /// `config = "none"`.
    NoChannel {
        target: TargetName,
        kind: &'static str,
        why: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "why", rename_all = "snake_case")]
pub enum Unusable {
    NotExecutable,
    WslInteropOff,
    TooOld {
        have: String,
        min: String,
    },
    VersionUnreadable,
    SpawnFailed {
        io: IoKind,
    },
    WindowsExeFromWsl,
    /// It kept a secret opv gave it unencrypted on disk (az's service principal store on
    /// Windows); opv removed it with its private folder.
    StoredSecretUnencrypted,
    /// This build of it leaves out a feature the command needs (opv without its MCP server).
    FeatureNotBuilt {
        feature: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoTerminal {
    NoTty,
    Ci,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ValueRow {
    pub product: ProductName,
    pub key: KeyName,
    pub target: Option<TargetName>,
    pub state: ValueState,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ValueState {
    Missing,
    /// The value fails `rule`; `reason` says why, in the rule's own fixed words (never the
    /// value), when the caller knows it (A4: sync's refusal keeps the rule's reason).
    RuleFailed {
        rule: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    StoredAsText,
    ConcealedConfig,
    FieldNotCreated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    Dotenv,
    SetupRecipe,
    Receipt,
    /// An environment's deploy credentials item in 1Password (`path`: its `op://`
    /// reference, empty when not known).
    DeployCredentials,
}

/// What an in-memory folder was needed for (R74).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RamPurpose {
    /// A key's settings file (`file = …`), delivered to a run.
    FileDelivery,
    /// az's private configuration folder for a sign-in with deploy credentials.
    AzureDeployCredentials,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "why", rename_all = "snake_case")]
pub enum RamDir {
    Unset,
    NotAbsolute,
    NotOwned,
    NotTmpfs,
    NoneOnPlatform { os: &'static str },
}

/// When a remote session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemotePhase {
    /// Before the receiver confirmed the payload: nothing was delivered.
    Delivery,
    /// While the app ran: the receiver stops it and removes its directory.
    Running,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Unverified {
    NotRecorded,
    Superseded { receipt: PathBuf },
    OtherAccount { account: AccountId },
    ChangedOnTarget,
    ChangedInOnePassword,
    Unverifiable,
}

// --- derived classification -------------------------------------------------------------

/// The exit code for internal errors (`EX_SOFTWARE`).
pub const EXIT_INTERNAL: i32 = 70;

impl Cause {
    /// This cause with the environment it belongs to filled in when the adapter that
    /// classified it did not know it (an overview knows the environment's name). An `env`
    /// already set is never replaced, and a `Partial`'s `then` is reached. This only
    /// annotates the subject: code, exit code, retry class and steps stay the cause's.
    pub fn in_env(mut self, env: &str) -> Cause {
        use Cause::*;
        match &mut self {
            InOtherAccount { env: e, .. }
            | MissingRight { env: e, .. }
            | TargetRefused { env: e, .. }
            | Unrecognized { env: e, .. }
            | RamDirUnavailable { env: e, .. }
            | SourceOnly { env: e, .. } => {
                if e.is_none() {
                    *e = Some(EnvName::new(env));
                }
            }
            Partial { then, .. } => {
                let inner = then.as_ref().clone().in_env(env);
                **then = inner;
            }
            _ => {}
        }
        self
    }

    /// This cause with its target name filled in when it was left empty (a Kubernetes
    /// preflight refusal is raised where the target's name is unknown, design §6.6).
    pub fn in_target(mut self, name: &str) -> Cause {
        match &mut self {
            Cause::MountUnreadable { target, .. }
            | Cause::Guard {
                guard: Guard::MountPathInUse { target, .. },
            } if target.as_str().is_empty() => *target = TargetName::new(name),
            _ => {}
        }
        self
    }

    /// The stable machine-readable code (public contract, `schema_version` 2).
    pub fn code(&self) -> &'static str {
        use Cause::*;
        match self {
            ConfigNotFound { .. } => "config_not_found",
            ConfigSourceMismatch { .. } => "config_source_mismatch",
            ConfigUnreadable { .. } => "config_unreadable",
            ConfigInvalid { .. } => "config_invalid",
            BoundaryMissing { .. } => "boundary_missing",
            StateVaultMissing { .. } => "state_vault_missing",
            StateVaultTooWide { .. } => "state_vault_wider_than_values",
            ConfigNotEditable { .. } => "config_not_editable",
            CopiesDiffer { .. } => "copies_differ",
            ManifestNotFound { .. } => "manifest_not_found",
            ManifestAmbiguous { .. } => "manifest_ambiguous",
            ManifestExists { .. } => "manifest_exists",
            InventoryIncomplete { .. } => "inventory_incomplete",
            NotDeclared { kind, .. } => match kind {
                NameKind::Environment => "unknown_env",
                NameKind::Target => "unknown_target",
                NameKind::Product => "unknown_product",
                NameKind::Key => "undeclared_key",
                NameKind::Role => "unknown_role",
                NameKind::RemoteProfile => "unknown_profile",
                NameKind::Mode | NameKind::HelpTopic => "usage",
            },
            KeyNotDeclared { .. } => "undeclared_key",
            Ambiguous { .. } => "ambiguous_name",
            ChoiceRequired { .. } => "choice_required",
            NothingInScope { what, .. } => match what {
                Scope::NoTargets { .. } => "no_target",
                _ => "nothing_in_scope",
            },
            Usage { .. } => "usage",
            AlreadyDeclared { .. } => "already_declared",
            NotSignedIn { system, .. } => match system {
                System::OnePassword => "op_not_signed_in",
                _ => "target_not_signed_in",
            },
            AccountNotOnMachine { .. } => "account_not_registered",
            AccountAmbiguous { .. } => "account_ambiguous",
            AccountRequired { .. } => "account_required",
            InOtherAccount { .. } => "ids_not_in_account",
            NeedsOwnSession { .. } => "own_session_required",
            CredentialRejected { credential, .. } => match credential {
                CredentialRef::DeployCredentials { .. } => "deploy_credentials_failed",
                _ => "credential_rejected",
            },
            MissingRight { system, .. } => match system {
                System::OnePassword => "vault_no_access",
                _ => "permission_denied",
            },
            OwnerSetupRequired { .. } => "owner_setup_required",
            NotFound {
                system, resource, ..
            } => match (system, resource.kind) {
                (System::OnePassword, ResourceKind::Item) => "item_not_found",
                _ => "resource_not_found",
            },
            TargetRefused { why, .. } => match why {
                Refusal::Unhealthy { .. } => "target_unhealthy",
                // Only the app's owner changes its revision mode: a person's step.
                Refusal::RevisionMode { .. } => "owner_setup_required",
                _ => "update_refused",
            },
            Guard { guard } => match guard {
                self::Guard::Declined => "declined",
                _ => "policy_refused",
            },
            MountUnreadable { .. } => "mount_unreadable",
            CreateOutcomeUnknown { .. } => "create_outcome_unknown",
            WriteOutcomeUnknown { .. } => "outcome_unknown",
            Unavailable { .. } => "provider_unavailable",
            BudgetSpent { .. } => "budget_spent",
            Partial { then, .. } | PersonalNotSetUp { then, .. } => then.code(),
            Interrupted { .. } => "interrupted",
            ChangedBeforeWrite { object } => match object {
                StoreObject::File { .. } | StoreObject::Manifest { .. } => "config_changed",
                StoreObject::Item { .. } => "item_changed",
                StoreObject::Resource { .. } => "target_changed",
            },
            ConcurrentEdit { .. } => "concurrent_edit",
            ReadBackMissing { .. } => "tidy_unverified",
            ToolMissing { .. } => "dependency_missing",
            ToolUnusable { .. } => "tool_unusable",
            UnexpectedOutput { .. } => "unexpected_output",
            Unrecognized { .. } => "unrecognized_failure",
            NeedsTerminal { .. } => "terminal_required",
            NeedsConfirm { .. } => "confirm_required",
            ConfirmMismatch { .. } => "confirm_mismatch",
            ValuesNeeded { .. } => "findings",
            KeysBlocking { .. } => "keys_blocking",
            LocalFileTooOpen { .. } => "file_too_open",
            InputInvalid { .. } => "input_invalid",
            ApprovalMissing { .. } => "approval_required",
            ApprovalUsed { .. } => "approval_used",
            PlanChanged { .. } => "stale_plan",
            PlanUnknown { .. } => "plan_unknown",
            RamDirUnavailable { .. } => "ram_dir_unavailable",
            PrivateDirFailed { .. } => "private_dir_failed",
            RemoteUnreachable { .. } => "remote_unreachable",
            RemoteDisconnected { .. } => "remote_disconnected",
            RemoteVersionMismatch { .. } => "remote_version_mismatch",
            ChildStartFailed { .. } => "child_start_failed",
            DeliveryUnverified { .. } => "delivery_unverified",
            TargetDrift { .. } => "target_drift",
            SourceChanged { .. } => "source_changed",
            LocalIo { .. } => "local_io_failed",
            StoreNotReady { .. } => "owner_setup_required",
            HandoffPipeContested { .. } => "handoff_refused",
            ConfigProposalInvalid { .. } => "config_invalid",
            InputUnreadable { .. } => "input_unreadable",
            ItemUnusable { .. } => "item_unusable",
            SecretNotStored { .. } => "secret_not_stored",
            SourceOnly { .. } => "source_only",
            TitleLookup { matches: 0, .. } => "title_not_found",
            TitleLookup { .. } => "title_ambiguous",
            Bug { .. } => "internal_error",
        }
    }

    /// The process exit code (public contract; the category of the cause).
    pub fn exit_code(&self) -> i32 {
        use Cause::*;
        match self {
            ConfigNotFound { .. }
            | ConfigSourceMismatch { .. }
            | ConfigUnreadable { .. }
            | ConfigInvalid { .. }
            | BoundaryMissing { .. }
            | StateVaultMissing { .. }
            | StateVaultTooWide { .. }
            | ConfigNotEditable { .. }
            | CopiesDiffer { .. }
            | ManifestNotFound { .. }
            | ManifestAmbiguous { .. }
            | ManifestExists { .. }
            | NotDeclared { .. }
            | KeyNotDeclared { .. }
            | Ambiguous { .. }
            | ChoiceRequired { .. }
            | NothingInScope { .. }
            | Usage { .. }
            | AlreadyDeclared { .. }
            | InputInvalid { .. }
            | ConfigProposalInvalid { .. }
            | InputUnreadable { .. }
            | SourceOnly { .. }
            | TitleLookup { .. }
            | AccountRequired { .. } => 2,
            ToolMissing { .. }
            | ToolUnusable { .. }
            | RemoteVersionMismatch { .. }
            | ChildStartFailed { .. } => 3,
            InventoryIncomplete { .. }
            | ChangedBeforeWrite {
                object: StoreObject::Item { .. },
            }
            | ConcurrentEdit { .. }
            | ReadBackMissing { .. }
            | ItemUnusable { .. } => 4,
            ChangedBeforeWrite {
                object: StoreObject::Resource { .. },
            } => 5,
            ChangedBeforeWrite { .. } => 2,
            MissingRight { system, .. }
            | NotFound { system, .. }
            | UnexpectedOutput { system, .. }
            | Unrecognized { system, .. } => {
                if *system == System::OnePassword {
                    4
                } else {
                    5
                }
            }
            OwnerSetupRequired { .. }
            | StoreNotReady { .. }
            | TargetRefused { .. }
            | RemoteUnreachable { .. }
            | RemoteDisconnected { .. } => 5,
            Guard {
                guard: self::Guard::Declined,
            } => 0,
            Guard { .. }
            | MountUnreadable { .. }
            | NeedsTerminal { .. }
            | NeedsConfirm { .. }
            | ConfirmMismatch { .. }
            | LocalFileTooOpen { .. }
            | ApprovalMissing { .. }
            | ApprovalUsed { .. }
            | PlanChanged { .. }
            | PlanUnknown { .. }
            | RamDirUnavailable { .. }
            | PrivateDirFailed { .. }
            | LocalIo { .. }
            | KeysBlocking { .. }
            | HandoffPipeContested { .. } => 6,
            NotSignedIn { .. }
            | AccountNotOnMachine { .. }
            | AccountAmbiguous { .. }
            | InOtherAccount { .. }
            | NeedsOwnSession { .. }
            | CredentialRejected { .. } => 7,
            ValuesNeeded { .. } | DeliveryUnverified { .. } | TargetDrift { .. } => 8,
            SourceChanged { .. } => 10,
            CreateOutcomeUnknown { .. }
            | WriteOutcomeUnknown { .. }
            | Unavailable { .. }
            | BudgetSpent { .. }
            | SecretNotStored { .. } => 9,
            Partial { then, .. } | PersonalNotSetUp { then, .. } => then.exit_code(),
            Interrupted { signal, .. } => 128 + signal,
            Bug { .. } => EXIT_INTERNAL,
        }
    }

    /// Whether re-running the same command can help (§4).
    pub fn retry(&self) -> RetryClass {
        use Cause::*;
        match self {
            PersonalNotSetUp { then, .. } => then.retry(),
            WriteOutcomeUnknown { .. }
            | Unavailable { .. }
            | Interrupted { .. }
            | ChangedBeforeWrite { .. }
            | Guard {
                guard: self::Guard::Declined,
            } => RetryClass::Safe,
            CreateOutcomeUnknown {
                refind: Refind::ByTitle,
                ..
            } => RetryClass::Safe,
            CreateOutcomeUnknown { .. } | Partial { .. } | ConcurrentEdit { .. } => {
                RetryClass::CheckFirst
            }
            NotDeclared { .. }
            | KeyNotDeclared { .. }
            | Ambiguous { .. }
            | ChoiceRequired { .. }
            | NothingInScope { .. }
            | Usage { .. }
            | AlreadyDeclared { .. }
            | ConfigSourceMismatch { .. }
            | ConfigNotEditable { .. }
            | CopiesDiffer { .. }
            | ManifestExists { .. }
            | NeedsOwnSession { .. }
            | Guard { .. }
            | NeedsTerminal { .. }
            | NeedsConfirm { .. }
            | ConfirmMismatch { .. }
            | ApprovalUsed { .. }
            | PlanChanged { .. }
            | PlanUnknown { .. }
            | UnexpectedOutput { .. }
            | ConfigProposalInvalid { .. }
            | SecretNotStored { .. }
            | SourceOnly { .. }
            | SourceChanged { .. }
            | Bug { .. } => RetryClass::Never,
            _ => RetryClass::AfterFix,
        }
    }

    /// The external call this cause was diagnosed from, when it came from one.
    pub fn observed(&self) -> Option<&Observed> {
        use Cause::*;
        match self {
            InOtherAccount { seen, .. }
            | CredentialRejected { seen, .. }
            | MissingRight { seen, .. }
            | NotFound { seen, .. }
            | TargetRefused { seen, .. }
            | CreateOutcomeUnknown { seen, .. }
            | WriteOutcomeUnknown { seen, .. }
            | Unavailable { seen, .. }
            | UnexpectedOutput { seen, .. }
            | Unrecognized { seen, .. } => Some(seen),
            Partial { then, .. } | PersonalNotSetUp { then, .. } => then.observed(),
            _ => None,
        }
    }
}

/// The retry class (§4). `CheckFirst` means something may already exist: Next is a read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryClass {
    Safe,
    AfterFix,
    Never,
    CheckFirst,
}

impl RetryClass {
    /// The document's `retry` word.
    pub fn as_str(self) -> &'static str {
        match self {
            RetryClass::Safe => "safe",
            RetryClass::AfterFix => "after_fix",
            RetryClass::Never => "never",
            RetryClass::CheckFirst => "check_first",
        }
    }
}

#[cfg(test)]
#[path = "contract_tests.rs"]
mod tests;

// --- diagnosis (design §5) ----------------------------------------------------------------

/// What the call site knows about a failed call, for the system's diagnosis strategy. Every
/// strategy (`src/adapters/<system>/diagnose.rs`, `src/app/remote_diagnose.rs`) exposes
/// `pub fn diagnose(seen: Observed, stderr: &str, ctx: &DiagnoseContext) -> Cause`. `stderr`
/// is the call's raw stderr (phrases match before scrubbing; it never leaves the
/// strategy except through the scrubbed evidence box). A strategy that cannot tell returns
/// `Cause::Unrecognized` with what it did establish.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiagnoseContext {
    pub env: Option<EnvName>,
    pub target: Option<TargetName>,
    /// The resource the call was about, when the call site knows it.
    pub resource: Option<ResourceRef>,
    /// Where the resource's name came from, for `NotFound`'s Do.
    pub named_by: Option<NamedBy>,
    /// The call was a non-idempotent create of this kind (an unknown outcome is then
    /// `CreateOutcomeUnknown`, never a plain failure).
    pub create: Option<(CreateKind, String, Refind)>,
    /// The call was a write (an unknown outcome is `WriteOutcomeUnknown`).
    pub write: bool,
    /// The account the call was made in (1Password).
    pub account: Option<AccountId>,
    /// The `.opv` file the account came from, when the configuration named none (FR-40):
    /// the account's source is that file, not the environment.
    pub account_from: Option<PathBuf>,
}
