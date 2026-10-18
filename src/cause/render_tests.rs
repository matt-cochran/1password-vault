//! Rendering every cause (design §4, §6, §7). One assertion each.

use std::path::PathBuf;

use super::super::evidence::{BOX_LINES, upstream_box};
use super::*;
use crate::host::{AgentMarker, Platform, Shell};

fn seen(principal: Principal) -> Observed {
    Observed::from_failed_call(
        CallId {
            system: System::OnePassword,
            program: "op".into(),
            words: vec!["vault".into(), "get".into(), "vlt-atqr".into()],
        },
        ExitClass::Code { code: 1 },
        principal,
    )
}

fn person() -> Observed {
    seen(Principal::Person {
        account: Some(AccountId::new("ACC-6AIN")),
    })
}

fn inv() -> Invocation {
    Invocation {
        origin: Origin::Cli,
        command: vec!["sync".into()],
        args: vec!["prod".into(), "--target".into(), "web".into()],
        has_child: false,
    }
}

/// An invocation carrying a flag only a person may pass.
fn confirmed_inv() -> Invocation {
    Invocation {
        args: vec![
            "prod".into(),
            "--target".into(),
            "web".into(),
            "--confirm".into(),
            "prod".into(),
        ],
        ..inv()
    }
}

fn file_source() -> ConfigSource {
    ConfigSource::File {
        path: PathBuf::from("cfg/secrets.toml"),
        given_by: GivenBy::Discovered,
    }
}

fn res(kind: ResourceKind, name: &str) -> ResourceRef {
    ResourceRef {
        kind,
        name: ResourceName::new(name),
        scope: Some("scope-east".into()),
    }
}

fn sync_scope() -> PlanScope {
    PlanScope::Sync {
        env: EnvName::new("prod"),
        targets: vec![TargetName::new("web"), TargetName::new("worker")],
        product: Some(ProductName::new("api")),
        deploy: true,
        prune: true,
        rotate: vec![ProductKey {
            product: ProductName::new("api"),
            key: KeyName::new("SIGNING_KEY"),
        }],
    }
}

fn fly_app_field() -> NamedBy {
    NamedBy::ConfigField {
        path: DottedPath(
            ["environments", "prod", "targets", "web", "fly", "app"]
                .map(String::from)
                .to_vec(),
        ),
    }
}

fn pinned_hosts() -> PathBuf {
    PathBuf::from("/home/me/.config/opv/known_hosts")
}

fn check_cmd() -> Cmd {
    Cmd {
        command: vec!["access".into()],
        args: vec!["prod".into()],
    }
}

/// One fixture per variant, with the identifiers its message or Do must name.
fn fixtures() -> Vec<(Cause, Vec<&'static str>)> {
    use Cause::*;
    vec![
        (
            ConfigNotFound {
                searched_from: PathBuf::from("/work/shop"),
                env: Some(EnvName::new("env-stage")),
                manifest: Some(ManifestSearch {
                    repo: Some("repo-xyz".into()),
                    account: Some(AccountId::new("ACC-XYZ")),
                }),
            },
            vec!["/work/shop", "env-stage", "repo-xyz", "ACC-XYZ"],
        ),
        (
            ConfigSourceMismatch {
                command: CommandId("bootstrap".into()),
                manifest: "man-shop".into(),
            },
            vec!["bootstrap", "man-shop"],
        ),
        (
            ConfigUnreadable {
                path: PathBuf::from("cfg/other.toml"),
                io: IoKind::PermissionDenied,
                given_by: GivenBy::Flag {
                    flag: "--config".into(),
                },
            },
            vec!["cfg/other.toml", "--config"],
        ),
        (
            ConfigInvalid {
                source: file_source(),
                at: Some(Location { line: 12, col: 3 }),
                field: DottedPath(vec!["environments".into(), "prod".into(), "confrm".into()]),
                rule: FieldRule::Unknown {
                    suggestion: Some("confirm_env".into()),
                },
            },
            vec![
                "cfg/secrets.toml",
                "environments.prod.confrm",
                "line 12",
                "confirm_env",
            ],
        ),
        (
            ContractStale {
                path: Some(PathBuf::from("contract.json")),
            },
            vec!["contract.json"],
        ),
        (
            ValueInTextField {
                field: DottedPath(vec!["guidance".into()]),
                detector: "known_prefix",
            },
            vec!["guidance", "known_prefix"],
        ),
        (
            BoundaryMissing {
                env: EnvName::new("env-prod"),
                product: ProductName::new("prod-api"),
                source: file_source(),
            },
            vec!["env-prod", "prod-api", "cfg/secrets.toml"],
        ),
        (
            StateVaultMissing {
                env: EnvName::new("env-prod"),
                target: TargetName::new("tgt-web"),
                source: file_source(),
            },
            vec!["env-prod", "tgt-web", "cfg/secrets.toml"],
        ),
        (
            StateVaultTooWide {
                env: EnvName::new("env-prod"),
                target: TargetName::new("tgt-web"),
                vault: VaultId::new("vlt-state"),
                shared_with: vec![TargetName::new("tgt-worker")],
                source: file_source(),
                at: Some(Location { line: 21, col: 1 }),
            },
            vec![
                "env-prod",
                "tgt-web",
                "vlt-state",
                "tgt-worker",
                "cfg/secrets.toml",
                "line 21",
            ],
        ),
        (
            ConfigNotEditable {
                source: file_source(),
                reason: NotEditable::UnsupportedLayout {
                    section: "sec-odd".into(),
                },
            },
            vec!["cfg/secrets.toml", "sec-odd"],
        ),
        (
            CopiesDiffer {
                file: PathBuf::from("cfg/copy.toml"),
                manifest: "man-shop".into(),
            },
            vec!["cfg/copy.toml", "man-shop"],
        ),
        (
            BindingsUnapplied {
                environments: vec![EnvName::new("env-prod")],
            },
            vec!["env-prod"],
        ),
        (
            ManifestNotFound {
                project: "proj-shop".into(),
                account: Some(AccountId::new("ACC-6AIN")),
            },
            vec!["proj-shop", "ACC-6AIN"],
        ),
        (
            ManifestAmbiguous {
                candidates: vec!["man-one".into(), "man-two".into()],
                person_picks: true,
            },
            vec!["man-one", "man-two"],
        ),
        (
            ManifestExists {
                title: "man-shop".into(),
                local_file: Some(PathBuf::from("cfg/secrets.toml")),
            },
            vec!["man-shop", "cfg/secrets.toml"],
        ),
        (
            InventoryIncomplete {
                unlisted: vec![AccountId::new("ACC-ONE"), AccountId::new("ACC-TWO")],
            },
            vec!["ACC-ONE", "ACC-TWO"],
        ),
        (
            NotDeclared {
                kind: NameKind::Environment,
                given: "prdo".into(),
                candidates: vec!["prod".into(), "stage".into()],
                closest: Closest::unique(&["prod"]),
            },
            vec!["prdo", "prod", "stage"],
        ),
        (
            Ambiguous {
                kind: NameKind::Key,
                given: "API_KEY".into(),
                candidates: vec!["api/API_KEY".into(), "web/API_KEY".into()],
            },
            vec!["API_KEY", "api/API_KEY", "web/API_KEY"],
        ),
        (
            ChoiceRequired {
                flag: "--product".into(),
                candidates: vec!["prod-api".into(), "prod-web".into()],
            },
            vec!["--product", "prod-api", "prod-web"],
        ),
        (
            NothingInScope {
                env: EnvName::new("env-prod"),
                what: Scope::NoTargetDelivers {
                    target: TargetName::new("tgt-web"),
                },
            },
            vec!["env-prod", "tgt-web"],
        ),
        (
            Usage {
                problem: UsageProblem::ConflictsWith {
                    a: "--opt-a".into(),
                    b: "--opt-b".into(),
                },
            },
            vec!["--opt-a", "--opt-b"],
        ),
        (
            AlreadyDeclared {
                kind: NameKind::Target,
                name: "tgt-web".into(),
            },
            vec!["target", "tgt-web"],
        ),
        (
            NotSignedIn {
                system: System::OnePassword,
                account: Some(AccountId::new("ACC-6AIN")),
                state: SessionState::Expired,
            },
            vec!["1Password", "ACC-6AIN"],
        ),
        (
            AccountNotOnMachine {
                account: AccountRef::Shorthand("acct-short".into()),
                selected_by: AccountSource::DotOpv {
                    path: PathBuf::from("/work/shop/.opv"),
                },
                in_app: true,
            },
            vec!["acct-short", "/work/shop/.opv"],
        ),
        (
            AccountAmbiguous {
                given: "acct-given".into(),
                candidates: vec![AccountId::new("ACC-ONE"), AccountId::new("ACC-TWO")],
            },
            vec!["acct-given", "ACC-ONE", "ACC-TWO"],
        ),
        (
            InOtherAccount {
                vault: VaultId::new("vlt-atqr"),
                item: Some(ItemId::new("itm-1")),
                selected: AccountId::new("ACC-6AIN"),
                owning: Some(AccountId::new("ACC-OWNS")),
                unasked: Vec::new(),
                searched: false,
                env: Some(EnvName::new("env-stage")),
                seen: person(),
            },
            vec!["vlt-atqr", "itm-1", "ACC-6AIN", "ACC-OWNS", "env-stage"],
        ),
        (
            NeedsOwnSession {
                command: CommandId("approve".into()),
                identity: Principal::ShellToken {
                    var: VarName::new("OP_SERVICE_ACCOUNT_TOKEN"),
                },
            },
            vec!["approve", "OP_SERVICE_ACCOUNT_TOKEN"],
        ),
        (
            CredentialRejected {
                system: System::Fly,
                credential: CredentialRef::DeployCredentials {
                    vault: VaultId::new("vlt-state"),
                    item: ItemId::new("itm-deploy"),
                    env: EnvName::new("env-prod"),
                    target: TargetName::new("tgt-web"),
                },
                problem: CredentialProblem::Rejected {
                    needs: vec!["deploy rights".into()],
                },
                seen: person(),
            },
            vec![
                "Fly",
                "vlt-state",
                "itm-deploy",
                "env-prod",
                "tgt-web",
                "deploy rights",
            ],
        ),
        (
            MissingRight {
                system: System::Azure,
                resource: res(ResourceKind::KeyVault, "kv-shop"),
                right: Right::SecretsWrite,
                grant: GrantModel::Rbac {
                    role: "Key Vault Secrets Officer".into(),
                    scope: "scope-kv".into(),
                },
                env: Some(EnvName::new("env-prod")),
                target: Some(TargetName::new("tgt-web")),
                seen: seen(Principal::ServicePrincipal {
                    client_id: "sp-client-1".into(),
                }),
            },
            vec![
                "Azure",
                "kv-shop",
                "scope-east",
                "write secrets",
                "Key Vault Secrets Officer",
                "scope-kv",
                "sp-client-1",
            ],
        ),
        (
            OwnerSetupRequired {
                system: System::GitHub,
                object: res(ResourceKind::GitHubEnvironment, "gh-env-prod"),
            },
            vec!["GitHub", "gh-env-prod", "scope-east"],
        ),
        (
            NotFound {
                system: System::Fly,
                resource: res(ResourceKind::FlyApp, "app-shop"),
                named_by: fly_app_field(),
                state: NotFoundState::Missing,
                seen: person(),
            },
            vec![
                "Fly",
                "app-shop",
                "scope-east",
                "environments.prod.targets.web.fly.app",
            ],
        ),
        (
            TargetRefused {
                system: System::Azure,
                subject: res(ResourceKind::ContainerApp, "ca-shop"),
                why: Refusal::Unhealthy {
                    new_revision: "rev-new".into(),
                    serving: Some("rev-old".into()),
                },
                env: Some(EnvName::new("env-prod")),
                target: Some(TargetName::new("tgt-web")),
                seen: person(),
            },
            vec!["Azure", "ca-shop", "rev-new", "rev-old"],
        ),
        (
            Guard {
                guard: super::super::Guard::RemoteProfileRefuses {
                    profile: ProfileName::new("prof-box"),
                    asked: "mode-x".into(),
                    allowed: vec!["mode-a".into(), "mode-b".into()],
                },
            },
            vec!["prof-box", "mode-x", "mode-a", "mode-b"],
        ),
        (
            Guard {
                guard: super::super::Guard::NoChannel {
                    target: TargetName::new("tgt-web"),
                    kind: "config",
                    why: "set fly.config".into(),
                },
            },
            vec!["tgt-web", "config", "set fly.config"],
        ),
        (
            CreateOutcomeUnknown {
                system: System::OnePassword,
                kind: CreateKind::ServiceAccount,
                name: "sa-web-deploy".into(),
                refind: Refind::Check(check_cmd()),
                seen: person(),
            },
            vec![
                "1Password",
                "service account",
                "sa-web-deploy",
                "opv access prod",
            ],
        ),
        (
            WriteOutcomeUnknown {
                system: System::Kubernetes,
                subject: res(ResourceKind::Namespace, "ns-shop"),
                seen: person(),
            },
            vec!["Kubernetes", "ns-shop"],
        ),
        (
            Unavailable {
                system: System::GitHub,
                why: Unanswered::ServerError { status: 503 },
                attempts: 3,
                seen: person(),
            },
            vec!["GitHub", "503", "3 attempts"],
        ),
        (
            BudgetSpent {
                budget_seconds: 77,
                writes_started: true,
            },
            vec!["77"],
        ),
        (
            Partial {
                done: vec!["vault shop-prod".into()],
                approval_used: Some(PlanId::new("sp-used")),
                approval_scope: Some(sync_scope()),
                then: Box::new(BudgetSpent {
                    budget_seconds: 77,
                    writes_started: true,
                }),
            },
            vec!["vault shop-prod", "sp-used", "77"],
        ),
        (
            Interrupted {
                signal: 2,
                writes_started: false,
            },
            vec!["signal 2"],
        ),
        (
            ChangedBeforeWrite {
                object: StoreObject::File {
                    path: PathBuf::from("cfg/secrets.toml"),
                },
            },
            vec!["cfg/secrets.toml"],
        ),
        (
            ConcurrentEdit {
                object: StoreObject::Item {
                    vault: VaultId::new("vlt-atqr"),
                    item: ItemId::new("itm-1"),
                },
            },
            vec!["vlt-atqr", "itm-1"],
        ),
        (
            ReadBackMissing {
                vault: VaultId::new("vlt-atqr"),
                item: ItemId::new("itm-1"),
                fields: vec![FieldName::new("fld-api")],
                by: Cmd {
                    command: vec!["tidy".into()],
                    args: vec!["prod".into()],
                },
            },
            vec!["vlt-atqr", "itm-1", "fld-api", "tidy"],
        ),
        (
            ToolMissing {
                tool: "op".into(),
                platform: Platform::MacOs,
                shell: Shell::Posix,
                ci: false,
            },
            vec!["op", "brew install 1password-cli"],
        ),
        (
            ToolUnusable {
                tool: "az".into(),
                why: Unusable::TooOld {
                    have: "2.40.0".into(),
                    min: "2.50.0".into(),
                },
            },
            vec!["az", "2.40.0", "2.50.0"],
        ),
        (
            UnexpectedOutput {
                system: System::OnePassword,
                at: Some(Location { line: 4, col: 9 }),
                problem: OutputProblem::Unparseable,
                during: During::Read,
                seen: person(),
            },
            vec!["op", "1Password", "line 4"],
        ),
        (
            Unrecognized {
                system: System::OnePassword,
                established: vec!["signed in".into()],
                env: Some(EnvName::new("env-prod")),
                target: None,
                seen: person(),
            },
            vec!["op", "1Password", "signed in"],
        ),
        (
            NeedsTerminal {
                why: NoTerminal::Ci,
            },
            vec!["CI"],
        ),
        (
            PersonOnly {
                command: check_cmd(),
                marker: AgentMarker::ClaudeCode,
            },
            vec!["opv access prod", "CLAUDECODE"],
        ),
        (
            NeedsConfirm {
                env: EnvName::new("env-prod"),
            },
            vec!["env-prod"],
        ),
        (
            ConfirmMismatch {
                given: "prdo".into(),
                env: EnvName::new("env-prod"),
            },
            vec!["prdo", "env-prod"],
        ),
        (
            ValuesNeeded {
                env: EnvName::new("env-prod"),
                rows: vec![ValueRow {
                    product: ProductName::new("prod-api"),
                    key: KeyName::new("OPENAI_API_KEY"),
                    target: Some(TargetName::new("tgt-web")),
                    state: ValueState::Missing,
                }],
            },
            vec!["env-prod", "prod-api/OPENAI_API_KEY", "tgt-web"],
        ),
        (
            LocalFileTooOpen {
                path: PathBuf::from("/home/me/.opv-cred"),
                mode: 0o644,
                want: 0o600,
            },
            vec!["/home/me/.opv-cred", "0644", "0600"],
        ),
        (
            InputInvalid {
                path: PathBuf::from("app/.env"),
                kind: InputKind::Dotenv,
                at: Some(Location { line: 7, col: 1 }),
                field: "BAD KEY".into(),
                rule: FieldRule::Pattern {
                    id: PatternId::KeyName,
                },
            },
            vec![
                "app/.env",
                "line 7",
                "BAD KEY",
                "upper-case letters, digits and _",
            ],
        ),
        (
            ApprovalMissing {
                plan: PlanId::new("sp-9f3"),
                scope: sync_scope(),
            },
            vec!["sp-9f3"],
        ),
        (
            ApprovalUsed {
                plan: PlanId::new("sp-9f3"),
                scope: sync_scope(),
                partial: true,
            },
            vec!["sp-9f3"],
        ),
        (
            PlanChanged {
                old: PlanId::new("sp-old"),
                new: PlanId::new("sp-new"),
                scope: sync_scope(),
            },
            vec!["sp-old", "sp-new"],
        ),
        (
            PlanUnknown {
                plan: "sp-what".into(),
                scope: None,
            },
            vec!["sp-what"],
        ),
        (
            RamDirUnavailable {
                remote: Some(ProfileName::new("prof-box")),
                why: RamDir::NotTmpfs,
                purpose: RamPurpose::FileDelivery,
                env: Some(EnvName::new("env-prod")),
                product: Some(ProductName::new("prod-api")),
            },
            vec!["prof-box", "tmpfs"],
        ),
        (
            PrivateDirFailed {
                dir: PathBuf::from("/run/user/1000"),
                io: IoKind::Other,
            },
            vec!["/run/user/1000"],
        ),
        (
            RemoteUnreachable {
                profile: ProfileName::new("prof-box"),
                user: "deployer".into(),
                host: "box.example".into(),
                port: 2222,
                known_hosts: pinned_hosts(),
                identity_file: None,
            },
            vec!["prof-box", "deployer", "box.example", "2222"],
        ),
        (
            RemoteDisconnected {
                profile: ProfileName::new("prof-box"),
                host: "box.example".into(),
                during: RemotePhase::Running,
            },
            vec!["prof-box", "box.example"],
        ),
        (
            RemoteVersionMismatch {
                profile: ProfileName::new("prof-box"),
                remote_protocol: 41,
            },
            vec!["prof-box", "41"],
        ),
        (
            ChildStartFailed {
                program: "node-app".into(),
                workdir: Some(PathBuf::from("/srv/app")),
                io: IoKind::NotFound,
                remote: Some(ProfileName::new("prof-box")),
            },
            vec!["node-app", "/srv/app", "prof-box"],
        ),
        (
            DeliveryUnverified {
                env: EnvName::new("env-prod"),
                target: TargetName::new("tgt-web"),
                product: ProductName::new("prod-api"),
                state: Unverified::OtherAccount {
                    account: AccountId::new("ACC-OTHER"),
                },
            },
            vec!["env-prod", "tgt-web", "prod-api", "ACC-OTHER"],
        ),
        (
            TargetDrift {
                env: EnvName::new("env-prod"),
                target: TargetName::new("tgt-web"),
                names: vec!["prod-api/KEY_X (KEY_X)".to_string()],
            },
            vec!["env-prod", "tgt-web", "prod-api/KEY_X (KEY_X)"],
        ),
        (
            SourceChanged {
                env: EnvName::new("env-prod"),
                no_record: true,
            },
            vec!["env-prod", "bootstrap"],
        ),
        (
            KeyNotDeclared {
                key: KeyName::new("KEY_X"),
                env: EnvName::new("env-prod"),
                product: Some(ProductName::new("prod-api")),
            },
            vec!["KEY_X", "env-prod", "prod-api"],
        ),
        (
            KeysBlocking {
                env: EnvName::new("env-prod"),
                rows: vec![ValueRow {
                    product: ProductName::new("prod-api"),
                    key: KeyName::new("KEY_X"),
                    target: None,
                    state: ValueState::Missing,
                }],
            },
            vec!["env-prod", "prod-api/KEY_X"],
        ),
        (
            LocalIo {
                op: LocalOp::Write,
                path: PathBuf::from("/work/secrets.toml"),
                io: IoKind::PermissionDenied,
            },
            vec!["/work/secrets.toml"],
        ),
        (
            StoreNotReady {
                store: res(ResourceKind::ExternalStore, "store-op"),
                reason: Some("InvalidProviderConfig".into()),
            },
            vec!["store-op", "InvalidProviderConfig"],
        ),
        (
            HandoffPipeContested {
                system: System::Azure,
            },
            vec!["Azure"],
        ),
        (
            ConfigProposalInvalid {
                source: file_source(),
                field: DottedPath(vec!["products".into(), "prod-api".into()]),
                rule: FieldRule::Missing,
                from_proposal: false,
            },
            vec!["cfg/secrets.toml", "nothing was written"],
        ),
        (
            InputUnreadable {
                path: PathBuf::from("/work/in.env"),
                kind: InputKind::Dotenv,
                io: IoKind::PermissionDenied,
            },
            vec!["/work/in.env"],
        ),
        (
            ItemUnusable {
                vault: Some(VaultId::new("vlt-atqr")),
                title: "title-xyz".into(),
                problem: ItemProblem::WrongCategory,
            },
            vec!["vlt-atqr", "title-xyz"],
        ),
        (
            SecretNotStored {
                system: System::Fly,
                kind: CreateKind::DeployToken,
                name: "tok-web".into(),
                env: EnvName::new("prod"),
                target: Some(TargetName::new("web")),
                refind: None,
            },
            vec!["tok-web", "Fly"],
        ),
        (
            AccountRequired {
                accounts: vec![
                    AccountChoice {
                        email: "me@one.example".into(),
                        address: "my.1password.com".into(),
                        id: AccountId::new("ACC-ONE"),
                    },
                    AccountChoice {
                        email: "me@two.example".into(),
                        address: "my.1password.com".into(),
                        id: AccountId::new("ACC-TWO"),
                    },
                ],
            },
            vec!["me@one.example", "ACC-ONE", "ACC-TWO"],
        ),
        (
            SourceOnly {
                product: ProductName::new("shared-xyz"),
                env: Some(EnvName::new("prod")),
                reader: Some(ProductName::new("reader-xyz")),
            },
            vec!["shared-xyz", "reader-xyz"],
        ),
        (
            TitleLookup {
                kind: ResourceKind::Item,
                title: "title-xyz".into(),
                vault: Some(VaultId::new("vlt-atqr")),
                matches: 0,
                candidates: vec!["cand-xyz (id-xyz)".into()],
            },
            vec!["title-xyz", "vlt-atqr", "cand-xyz", "id-xyz"],
        ),
        (
            PersonalNotSetUp {
                env: EnvName::new("env-dev"),
                keys: vec![ProductKey {
                    product: ProductName::new("prod-api"),
                    key: KeyName::new("MY_TOKEN"),
                }],
                then: Box::new(TitleLookup {
                    kind: ResourceKind::Item,
                    title: "title-xyz".into(),
                    vault: Some(VaultId::new("vlt-atqr")),
                    matches: 0,
                    candidates: Vec::new(),
                }),
            },
            vec!["env-dev", "prod-api/MY_TOKEN", "title-xyz"],
        ),
        (Bug { site: "site-xyz" }, vec!["site-xyz"]),
        (
            GateFailed {
                env: EnvName::new("env-prod"),
                keys: vec![(
                    ProductName::new("prod-api"),
                    KeyName::new("OPENAI_API_KEY"),
                    "absent",
                )],
            },
            vec!["env-prod", "prod-api", "OPENAI_API_KEY", "absent"],
        ),
        (
            MountUnreadable {
                workload: "work-xyz".into(),
                container: "cont-xyz".into(),
                run_as: Some(10001),
                why: MountWhy::NoFsGroup,
                env: EnvName::new("env-dev"),
                target: TargetName::new("tgt-web"),
            },
            vec!["work-xyz", "cont-xyz", "10001"],
        ),
        (
            NeedsUndeclared {
                names: vec!["API_KEY".into(), "DB_URL".into()],
            },
            vec!["API_KEY", "DB_URL"],
        ),
    ]
}

/// The variant's position; exhaustive, so a new variant fails to compile here until it gets
/// a fixture above.
fn ordinal(c: &Cause) -> usize {
    use Cause::*;
    match c {
        ConfigNotFound { .. } => 0,
        ConfigSourceMismatch { .. } => 1,
        ConfigUnreadable { .. } => 2,
        ConfigInvalid { .. } => 3,
        ContractStale { .. } => 82,
        BoundaryMissing { .. } => 4,
        StateVaultMissing { .. } => 5,
        StateVaultTooWide { .. } => 6,
        ConfigNotEditable { .. } => 7,
        CopiesDiffer { .. } => 8,
        BindingsUnapplied { .. } => 81,
        ManifestNotFound { .. } => 9,
        ManifestAmbiguous { .. } => 10,
        ManifestExists { .. } => 11,
        InventoryIncomplete { .. } => 12,
        NotDeclared { .. } => 13,
        Ambiguous { .. } => 14,
        ChoiceRequired { .. } => 15,
        NothingInScope { .. } => 16,
        Usage { .. } => 17,
        AlreadyDeclared { .. } => 18,
        NotSignedIn { .. } => 19,
        AccountNotOnMachine { .. } => 20,
        AccountAmbiguous { .. } => 21,
        InOtherAccount { .. } => 22,
        NeedsOwnSession { .. } => 23,
        CredentialRejected { .. } => 24,
        MissingRight { .. } => 25,
        OwnerSetupRequired { .. } => 26,
        NotFound { .. } => 27,
        TargetRefused { .. } => 28,
        Guard {
            guard: super::super::Guard::NoChannel { .. },
        } => 76,
        Guard { .. } => 29,
        CreateOutcomeUnknown { .. } => 30,
        WriteOutcomeUnknown { .. } => 31,
        Unavailable { .. } => 32,
        BudgetSpent { .. } => 33,
        Partial { .. } => 34,
        Interrupted { .. } => 35,
        ChangedBeforeWrite { .. } => 36,
        ConcurrentEdit { .. } => 37,
        ReadBackMissing { .. } => 38,
        ToolMissing { .. } => 39,
        ToolUnusable { .. } => 40,
        UnexpectedOutput { .. } => 41,
        Unrecognized { .. } => 42,
        NeedsTerminal { .. } => 43,
        PersonOnly { .. } => 77,
        NeedsConfirm { .. } => 44,
        ConfirmMismatch { .. } => 45,
        ValuesNeeded { .. } => 46,
        LocalFileTooOpen { .. } => 47,
        InputInvalid { .. } => 48,
        ApprovalMissing { .. } => 49,
        ApprovalUsed { .. } => 50,
        PlanChanged { .. } => 51,
        PlanUnknown { .. } => 52,
        RamDirUnavailable { .. } => 53,
        PrivateDirFailed { .. } => 54,
        RemoteUnreachable { .. } => 55,
        RemoteDisconnected { .. } => 56,
        RemoteVersionMismatch { .. } => 57,
        ChildStartFailed { .. } => 58,
        DeliveryUnverified { .. } => 59,
        SourceChanged { .. } => 74,
        Bug { .. } => 60,
        KeyNotDeclared { .. } => 61,
        KeysBlocking { .. } => 62,
        LocalIo { .. } => 63,
        StoreNotReady { .. } => 64,
        HandoffPipeContested { .. } => 65,
        ConfigProposalInvalid { .. } => 66,
        InputUnreadable { .. } => 67,
        ItemUnusable { .. } => 68,
        SecretNotStored { .. } => 69,
        AccountRequired { .. } => 70,
        SourceOnly { .. } => 71,
        TitleLookup { .. } => 72,
        PersonalNotSetUp { .. } => 73,
        TargetDrift { .. } => 75,
        MountUnreadable { .. } => 76,
        ValueInTextField { .. } => 78,
        GateFailed { .. } => 79,
        NeedsUndeclared { .. } => 80,
    }
}

const VARIANTS: usize = 83;

fn causes() -> Vec<Cause> {
    fixtures().into_iter().map(|(c, _)| c).collect()
}

fn upstream(lines: usize, removed_advice: bool) -> Upstream {
    Upstream {
        source: System::OnePassword,
        tool: "1Password CLI".into(),
        version: Some("op 2.31.0".into()),
        exit: ExitClass::Code { code: 1 },
        said: (1..=lines).map(|i| format!("[ERROR] line {i}")).collect(),
        removed_advice,
        truncated: false,
        untrusted: true,
    }
}

fn in_other_account() -> Cause {
    Cause::InOtherAccount {
        vault: VaultId::new("atqr2ek"),
        item: None,
        selected: AccountId::new("6AINMAIK"),
        owning: None,
        unasked: Vec::new(),
        searched: false,
        env: Some(EnvName::new("staging")),
        seen: person(),
    }
}

/// #153a: the vault located in account `OWNS1` by the search of the other accounts.
fn in_owned_account() -> Cause {
    match in_other_account() {
        Cause::InOtherAccount {
            vault,
            item,
            selected,
            env,
            seen,
            ..
        } => Cause::InOtherAccount {
            vault,
            item,
            selected,
            owning: Some(AccountId::new("OWNS1")),
            unasked: Vec::new(),
            searched: true,
            env,
            seen,
        },
        other => other,
    }
}

/// #153a: no account the search could ask holds the vault; `UNASK1` could not be asked.
fn in_no_askable_account() -> Cause {
    match in_other_account() {
        Cause::InOtherAccount {
            vault,
            item,
            selected,
            env,
            seen,
            ..
        } => Cause::InOtherAccount {
            vault,
            item,
            selected,
            owning: None,
            unasked: vec![AccountId::new("UNASK1")],
            searched: true,
            env,
            seen,
        },
        other => other,
    }
}

/// #153a: the search asked every other account on the machine and none holds the vault.
fn in_no_account_on_the_machine() -> Cause {
    match in_other_account() {
        Cause::InOtherAccount {
            vault,
            item,
            selected,
            env,
            seen,
            ..
        } => Cause::InOtherAccount {
            vault,
            item,
            selected,
            owning: None,
            unasked: Vec::new(),
            searched: true,
            env,
            seen,
        },
        other => other,
    }
}

#[test]
fn a_source_changed_sync_is_a_run() {
    let cause = Cause::SourceChanged {
        env: EnvName::new("env-prod"),
        no_record: false,
    };
    assert_eq!(
        crate::cause::render::next_kind_actor(&cause.step(&inv()).1).0,
        crate::json::NextKind::Run
    );
}

#[test]
fn a_login_handoff_is_an_authorize_for_the_person() {
    let n = Next::Handoff(Cmd {
        command: vec!["login".into()],
        args: Vec::new(),
    });
    assert_eq!(
        next_kind_actor(&n),
        (
            crate::json::NextKind::Authorize,
            crate::json::NextActor::Person
        )
    );
}

#[test]
fn a_vendor_step_is_a_run_for_the_person() {
    let n = Next::Vendor(VendorCmd {
        program: "op".into(),
        args: vec!["signin".into()],
    });
    assert_eq!(
        next_kind_actor(&n),
        (crate::json::NextKind::Run, crate::json::NextActor::Person)
    );
}

#[test]
fn every_variant_has_a_fixture() {
    let mut seen: Vec<usize> = causes().iter().map(ordinal).collect();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen, (0..VARIANTS).collect::<Vec<_>>());
}

#[test]
fn every_variant_renders() {
    let bad: Vec<&str> = causes()
        .iter()
        .filter(|c| {
            let text = render_text(c, None, &inv(), false, true, false);
            !(text.starts_with("opv: ")
                && text.lines().last().is_some_and(|l| l.starts_with("Next: ")))
        })
        .map(Cause::code)
        .collect();
    assert_eq!(bad, Vec::<&str>::new());
}

#[test]
fn every_subject_field_is_shown() {
    let mut missing = Vec::new();
    for (c, ids) in fixtures() {
        let shown = format!("{} {}", c.message(), c.do_text(&inv()).unwrap_or_default());
        for id in ids {
            if !shown.contains(id) {
                missing.push(format!("{}: {id}", c.code()));
            }
        }
    }
    assert_eq!(missing, Vec::<String>::new());
}

#[test]
fn a_do_has_words_exactly_when_it_has_an_action() {
    let bad: Vec<&str> = causes()
        .iter()
        .filter(|c| c.step(&inv()).0.is_some() != c.do_text(&inv()).is_some())
        .map(Cause::code)
        .collect();
    assert_eq!(bad, Vec::<&str>::new());
}

#[test]
fn no_message_tells_the_reader_to_run_something() {
    let bad: Vec<String> = causes()
        .iter()
        .map(Cause::message)
        .filter(|m| m.contains("then run") || m.contains("opv:") || m.contains('\n'))
        .collect();
    assert_eq!(bad, Vec::<String>::new());
}

#[test]
fn a_vault_in_another_account_names_the_vault_and_the_checked_account() {
    let text = render_text(&in_other_account(), None, &inv(), false, true, false);
    let first = text.lines().next().unwrap_or_default();
    assert_eq!(
        first,
        "opv: vault atqr2ek (environment staging) is not in 1Password account 6AINMAIK"
    );
}

#[test]
fn a_vault_in_another_account_shows_the_checked_account_id() {
    let text = render_text(&in_other_account(), None, &inv(), false, true, false);
    assert!(
        text.contains("  checked: op vault get vlt-atqr in account 6AINMAIK (exit 1)\n"),
        "{text}"
    );
}

#[test]
fn a_vault_in_another_account_next_locates_the_vault() {
    let (_, next) = in_other_account().step(&inv());
    assert_eq!(
        next,
        Next::Run(Cmd {
            command: vec!["vault".into(), "locate".into()],
            args: vec!["atqr2ek".into()],
        })
    );
}

#[test]
fn human_required_matches_step() {
    let bad: Vec<&str> = causes()
        .iter()
        .filter(|c| {
            let (action, next) = c.step(&inv());
            let derived = matches!(next, Next::Handoff(_))
                || action.is_some_and(|a| a.person_only())
                || matches!(
                    c,
                    Cause::NeedsTerminal { .. }
                        | Cause::NeedsOwnSession { .. }
                        | Cause::NeedsConfirm { .. }
                        | Cause::ApprovalMissing { .. }
                        | Cause::CredentialRejected { .. }
                );
            derived != c.human_required(&inv())
        })
        .map(Cause::code)
        .collect();
    assert_eq!(bad, Vec::<&str>::new());
}

/// Rerunning unchanged loops unless re-running is safe or a Do changes something first.
#[test]
fn no_loop() {
    let bad: Vec<&str> = causes()
        .iter()
        .filter(|c| {
            let (action, next) = c.step(&inv());
            next == Next::Rerun && c.retry() != RetryClass::Safe && action.is_none()
        })
        .map(Cause::code)
        .collect();
    assert_eq!(bad, Vec::<&str>::new());
}

#[test]
fn never_retry_never_reruns() {
    let bad: Vec<&str> = causes()
        .iter()
        .filter(|c| c.retry() == RetryClass::Never && c.step(&inv()).1 == Next::Rerun)
        .map(Cause::code)
        .collect();
    assert_eq!(bad, Vec::<&str>::new());
}

#[test]
fn create_unknown_never_reruns() {
    let c = Cause::CreateOutcomeUnknown {
        system: System::OnePassword,
        kind: CreateKind::Vault,
        name: "shop-prod".into(),
        refind: Refind::Check(check_cmd()),
        seen: person(),
    };
    assert_eq!(c.step(&inv()).1, Next::Check(check_cmd()));
}

#[test]
fn partial_and_used_approvals_only_read() {
    let bad: Vec<&str> = causes()
        .iter()
        .filter(|c| matches!(c, Cause::Partial { .. } | Cause::ApprovalUsed { .. }))
        .filter(|c| !matches!(c.step(&inv()).1, Next::Check(_) | Next::Run(_)))
        .map(Cause::code)
        .collect();
    assert_eq!(bad, Vec::<&str>::new());
}

#[test]
fn person_only_flags_appear_only_in_a_handoff() {
    let bad: Vec<&str> = causes()
        .iter()
        .filter(|c| match c.step(&confirmed_inv()).1 {
            Next::Run(cmd) | Next::Check(cmd) => {
                cmd.args.iter().any(|a| a.starts_with("--confirm"))
            }
            Next::Rerun | Next::Handoff(_) | Next::Vendor(_) | Next::None(_) => false,
        })
        .map(Cause::code)
        .collect();
    assert_eq!(bad, Vec::<&str>::new());
}

fn misspelt_env() -> Cause {
    Cause::NotDeclared {
        kind: NameKind::Environment,
        given: "prdo".into(),
        candidates: vec!["prod".into()],
        closest: Closest::unique(&["prod"]),
    }
}

fn invoked(command: &[&str], args: &[&str]) -> Invocation {
    Invocation {
        command: command.iter().map(|w| w.to_string()).collect(),
        args: args.iter().map(|a| a.to_string()).collect(),
        ..inv()
    }
}

fn next_line(c: &Cause, i: &Invocation) -> Option<String> {
    next_text(&c.step(i).1, i)
}

#[test]
fn a_unique_closest_name_is_substituted_into_a_read_keeping_every_flag() {
    let i = invoked(&["status"], &["prdo", "--json"]);
    assert_eq!(
        next_line(&misspelt_env(), &i).as_deref(),
        Some("opv status prod --json")
    );
}

#[test]
fn a_misspelt_sync_becomes_its_plan_with_the_scope_flags() {
    let i = invoked(
        &["sync"],
        &[
            "prdo",
            "--target",
            "web",
            "--deploy",
            "--prune",
            "--product",
            "api",
            "--rotate",
            "api/K",
        ],
    );
    assert_eq!(
        next_line(&misspelt_env(), &i).as_deref(),
        Some("opv plan prod --target web --product api --rotate api/K")
    );
}

#[test]
fn a_misspelt_sync_never_carries_its_confirmation_into_the_plan() {
    let i = invoked(&["sync"], &["prdo", "--confirm", "prdo", "--approved=sp-1"]);
    assert_eq!(
        next_line(&misspelt_env(), &i).as_deref(),
        Some("opv plan prod")
    );
}

#[test]
fn a_misspelt_bootstrap_becomes_its_dry_run() {
    let i = invoked(&["bootstrap"], &["--rebind", "prdo"]);
    assert_eq!(
        next_line(&misspelt_env(), &i).as_deref(),
        Some("opv bootstrap --rebind prod --dry-run")
    );
}

#[test]
fn a_misspelt_target_add_becomes_its_dry_run() {
    let i = invoked(&["target", "add"], &["prdo", "site", "--fly-app", "site-x"]);
    assert_eq!(
        next_line(&misspelt_env(), &i).as_deref(),
        Some("opv target add prod site --fly-app site-x --dry-run")
    );
}

#[test]
fn a_misspelt_write_without_a_read_form_lists_the_names() {
    let i = invoked(&["generate"], &["prdo", "api/K"]);
    assert_eq!(
        misspelt_env().step(&i).1,
        Next::Check(Cmd {
            command: vec!["config".into(), "describe".into()],
            args: vec![],
        })
    );
}

#[test]
fn without_a_unique_closest_name_next_is_a_listing() {
    let c = Cause::NotDeclared {
        kind: NameKind::Target,
        given: "wbe".into(),
        candidates: vec!["web".into(), "web2".into()],
        closest: Closest::unique(&["web", "web2"]),
    };
    assert_eq!(
        c.step(&inv()).1,
        Next::Check(Cmd {
            command: vec!["target".into(), "list".into()],
            args: vec![],
        })
    );
}

#[test]
fn next_is_the_last_line_after_do() {
    let text = render_text(
        &in_other_account(),
        Some(&upstream(2, true)),
        &inv(),
        false,
        true,
        false,
    );
    let last_two: Vec<&str> = text.lines().rev().take(2).map(|l| &l[..4]).collect();
    assert_eq!(last_two, vec!["Next", "Do: "]);
}

#[test]
fn the_box_attributes_the_reply_to_its_tool() {
    let b = upstream_box(&upstream(1, false), false, true);
    assert_eq!(
        b.lines().next(),
        Some("╭─ 1Password CLI (op 2.31.0) replied, exit 1")
    );
}

#[test]
fn the_box_says_when_advice_was_removed() {
    let b = upstream_box(&upstream(1, true), false, true);
    assert_eq!(
        b.lines().last(),
        Some("╰─ (scrubbed; 1Password CLI's own advice removed)")
    );
}

#[test]
fn the_box_shows_at_most_five_lines() {
    let b = upstream_box(&upstream(9, false), false, true);
    assert_eq!(
        b.lines().filter(|l| l.starts_with("│ [ERROR]")).count(),
        BOX_LINES
    );
}

/// op's reply as it is when it says more than the box holds: its `[ERROR]` line first, then
/// `n - 1` lines of detail.
fn long_reply(n: usize) -> Upstream {
    let mut up = upstream(1, false);
    up.said = std::iter::once("[ERROR] 2026/10/16 10:00:00 refused".to_string())
        .chain((1..n).map(|i| format!("detail {i}")))
        .collect();
    up
}

#[test]
fn the_box_keeps_the_error_line_of_a_long_reply() {
    let b = upstream_box(&long_reply(30), false, true);
    assert_eq!(
        b.lines().nth(1),
        Some("│ [ERROR] 2026/10/16 10:00:00 refused")
    );
}

#[test]
fn the_box_ends_a_long_reply_with_its_tail() {
    let b = upstream_box(&long_reply(30), false, true);
    assert_eq!(b.lines().rev().nth(1), Some("│ detail 29"));
}

#[test]
fn the_box_marks_where_lines_were_left_out() {
    let b = upstream_box(&long_reply(30), false, true);
    assert_eq!(b.lines().nth(2), Some("│ … 25 lines left out"));
}

#[test]
fn the_box_counts_the_lines_left_out_in_its_footer() {
    let b = upstream_box(&long_reply(30), false, true);
    assert_eq!(
        b.lines().last(),
        Some("╰─ (scrubbed; 25 more lines with --verbose)")
    );
}

#[test]
fn the_box_shows_the_tail_alone_when_the_error_line_is_in_it() {
    let mut up = long_reply(30);
    up.said[0] = "warning: preview".into();
    up.said[27] = "Error: refused".into();
    let b = upstream_box(&up, false, true);
    assert_eq!(b.lines().nth(1), Some("│ … 25 lines left out"));
}

#[test]
fn the_box_shows_a_whole_long_reply_when_verbose() {
    let b = upstream_box(&long_reply(300), true, true);
    assert_eq!(b.lines().filter(|l| l.starts_with("│ ")).count(), 300);
}

#[test]
fn the_box_keeps_long_lines_whole_when_verbose() {
    let mut up = upstream(1, false);
    up.said = vec!["x".repeat(1000)];
    let b = upstream_box(&up, true, true);
    assert_eq!(b.lines().nth(1).map(|l| l.chars().count()), Some(2 + 1000));
}

#[test]
fn the_box_says_a_truncated_reply_was_cut() {
    let mut up = upstream(1, false);
    up.truncated = true;
    let b = upstream_box(&up, true, true);
    assert_eq!(
        b.lines().last(),
        Some("╰─ (scrubbed; longer than 64 KiB, only its end was kept)")
    );
}

#[test]
fn the_document_keeps_the_error_line_of_a_long_reply() {
    let d = document(&in_other_account(), Some(&long_reply(30)), &inv(), false);
    assert_eq!(
        d["evidence"]["upstream"]["said"][0],
        serde_json::json!("[ERROR] 2026/10/16 10:00:00 refused")
    );
}

#[test]
fn the_document_counts_the_lines_left_out() {
    let d = document(&in_other_account(), Some(&long_reply(30)), &inv(), false);
    assert_eq!(d["evidence"]["upstream"]["omitted"], serde_json::json!(25));
}

#[test]
fn the_document_carries_a_whole_long_reply_when_verbose() {
    let d = document(&in_other_account(), Some(&long_reply(300)), &inv(), true);
    assert_eq!(
        d["evidence"]["upstream"]["said"].as_array().map(Vec::len),
        Some(300)
    );
}

#[test]
fn the_document_leaves_nothing_out_when_verbose() {
    let d = document(&in_other_account(), Some(&long_reply(300)), &inv(), true);
    assert_eq!(d["evidence"]["upstream"]["omitted"], serde_json::json!(0));
}

#[test]
fn the_document_says_a_reply_was_truncated() {
    let mut up = upstream(1, false);
    up.truncated = true;
    let d = document(&in_other_account(), Some(&up), &inv(), true);
    assert_eq!(
        d["evidence"]["upstream"]["truncated"],
        serde_json::json!(true)
    );
}

#[test]
fn the_box_shows_every_line_when_verbose() {
    let b = upstream_box(&upstream(9, false), true, true);
    assert_eq!(b.lines().filter(|l| l.starts_with("│ ")).count(), 9);
}

#[test]
fn the_box_cuts_long_lines() {
    let mut up = upstream(1, false);
    up.said = vec!["x".repeat(1000)];
    let b = upstream_box(&up, false, true);
    assert_eq!(
        b.lines().nth(1).map(|l| l.chars().count()),
        Some(2 + 240 + 1)
    );
}

#[test]
fn the_box_falls_back_to_ascii() {
    let b = upstream_box(&upstream(1, false), false, false);
    assert_eq!(
        b,
        "--- 1Password CLI (op 2.31.0) replied, exit 1 ---\n| [ERROR] line 1\n--- (scrubbed) ---\n"
    );
}

#[test]
fn the_box_strips_escape_sequences() {
    let mut up = upstream(1, false);
    up.said = vec!["\u{1b}]52;c;Zm9v\u{7}evil \u{1b}[31mred\u{202e}".into()];
    let b = upstream_box(&up, false, true);
    assert_eq!(b.lines().nth(1), Some("│ evil red"));
}

#[test]
fn the_document_marks_upstream_text_untrusted() {
    let mut up = upstream(1, false);
    up.untrusted = false;
    let d = document(&in_other_account(), Some(&up), &inv(), false);
    assert_eq!(
        d["evidence"]["upstream"]["untrusted"],
        serde_json::json!(true)
    );
}

#[test]
fn the_document_carries_at_most_five_upstream_lines() {
    let d = document(
        &in_other_account(),
        Some(&upstream(9, false)),
        &inv(),
        false,
    );
    assert_eq!(
        d["evidence"]["upstream"]["said"].as_array().map(Vec::len),
        Some(BOX_LINES)
    );
}

#[test]
fn the_document_subject_leaves_out_the_observed_call() {
    let d = document(&in_other_account(), None, &inv(), false);
    assert_eq!(
        d["subject"],
        serde_json::json!({"vault": "atqr2ek", "item": null, "selected": "6AINMAIK", "owning": null, "unasked": [], "searched": false, "env": "staging"})
    );
}

#[test]
fn the_document_names_the_checked_account() {
    let d = document(&in_other_account(), None, &inv(), false);
    assert_eq!(d["evidence"]["account"], serde_json::json!("6AINMAIK"));
}

#[test]
fn the_document_kinds_a_handoff() {
    let c = Cause::ApprovalMissing {
        plan: PlanId::new("sp-9f3"),
        scope: PlanScope::Structural,
    };
    let d = document(&c, None, &inv(), false);
    assert_eq!(
        (d["next"].clone(), d["human_required"].clone()),
        (
            serde_json::json!({
                "kind": "apply",
                "actor": "person",
                "command": "opv approve sp-9f3"
            }),
            serde_json::json!(true)
        )
    );
}

#[test]
fn the_document_category_follows_the_exit_code() {
    let d = document(&in_other_account(), None, &inv(), false);
    assert_eq!(d["category"], serde_json::json!("auth"));
}

#[test]
fn every_variant_documents_its_code() {
    let bad: Vec<&str> = causes()
        .iter()
        .filter(|c| document(c, None, &inv(), false)["code"] != serde_json::json!(c.code()))
        .map(Cause::code)
        .collect();
    assert_eq!(bad, Vec::<&str>::new());
}

#[test]
fn an_mcp_rerun_names_the_tool() {
    let i = Invocation {
        origin: Origin::Mcp {
            tool: "opv_sync".into(),
        },
        ..inv()
    };
    assert_eq!(rerun_text(&i), "call opv_sync again");
}

#[test]
fn a_rerun_never_renders_the_child_command() {
    let i = Invocation {
        command: vec!["run".into()],
        args: vec!["dev".into()],
        has_child: true,
        ..inv()
    };
    assert_eq!(rerun_text(&i), "opv run dev -- <command>");
}

// --- contract v2: what rendering found missing ------------------------------------------------

fn fixture(ordinal_of: usize) -> Cause {
    causes()
        .into_iter()
        .find(|c| ordinal(c) == ordinal_of)
        .unwrap_or(Cause::Bug { site: "none" })
}

/// Any cause's Next as a command line, under the default invocation.
fn next_of(c: &Cause) -> Option<String> {
    next_line(c, &inv())
}

#[test]
fn a_missing_right_checks_its_environment_and_target() {
    assert_eq!(
        next_of(&fixture(25)).as_deref(),
        Some("opv doctor --env env-prod --target tgt-web")
    );
}

#[test]
fn a_refused_target_checks_its_environment_and_target() {
    assert_eq!(
        next_of(&fixture(28)).as_deref(),
        Some("opv doctor --env env-prod --target tgt-web")
    );
}

#[test]
fn an_unrecognized_failure_checks_the_environment_it_knows() {
    assert_eq!(
        next_of(&fixture(42)).as_deref(),
        Some("opv doctor --env env-prod")
    );
}

#[test]
fn a_missing_approval_hands_off_every_scope_flag() {
    let c = Cause::ApprovalMissing {
        plan: PlanId::new("sp-9f3"),
        scope: sync_scope(),
    };
    assert_eq!(
        next_of(&c).as_deref(),
        Some(
            "opv approve sp-9f3 --sync prod --deploy --prune --target web --target worker --product api --rotate api/SIGNING_KEY"
        )
    );
}

#[test]
fn a_structural_approval_hands_off_the_plan_id_alone() {
    let c = Cause::ApprovalMissing {
        plan: PlanId::new("sp-9f3"),
        scope: PlanScope::Structural,
    };
    assert_eq!(next_of(&c).as_deref(), Some("opv approve sp-9f3"));
}

const SCOPED_PLAN: &str =
    "opv plan prod --target web --target worker --product api --rotate api/SIGNING_KEY";

#[test]
fn a_used_approval_reads_the_plan_of_the_same_scope() {
    assert_eq!(next_of(&fixture(50)).as_deref(), Some(SCOPED_PLAN));
}

#[test]
fn a_changed_plan_reads_the_plan_of_the_same_scope() {
    assert_eq!(next_of(&fixture(51)).as_deref(), Some(SCOPED_PLAN));
}

#[test]
fn a_target_drift_plans_the_environment_and_target() {
    assert_eq!(
        next_of(&fixture(75)).as_deref(),
        Some("opv plan env-prod --target tgt-web")
    );
}

#[test]
fn an_unknown_plan_of_a_known_scope_reads_that_scope() {
    let c = Cause::PlanUnknown {
        plan: "sp-what".into(),
        scope: Some(PlanScope::Structural),
    };
    assert_eq!(next_of(&c).as_deref(), Some("opv structure plan"));
}

#[test]
fn a_partial_run_on_an_approval_reads_what_remains_in_its_scope() {
    assert_eq!(next_of(&fixture(34)).as_deref(), Some(SCOPED_PLAN));
}

#[test]
fn an_unreachable_remote_is_checked_against_the_pinned_host_key() {
    assert_eq!(
        next_of(&fixture(55)).as_deref(),
        Some(
            "ssh -F none -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/home/me/.config/opv/known_hosts -p 2222 deployer@box.example true"
        )
    );
}

#[test]
fn a_pattern_rule_is_never_shown_as_a_regular_expression() {
    let c = Cause::ConfigInvalid {
        source: file_source(),
        at: None,
        field: DottedPath(vec!["environments".into(), "prod".into(), "targets".into()]),
        rule: FieldRule::Pattern {
            id: PatternId::TargetName,
        },
    };
    let shown = format!("{} {}", c.message(), c.do_text(&inv()).unwrap_or_default());
    assert!(!shown.contains(['^', '$', '[', '*']), "{shown}");
}

#[test]
fn a_target_name_rule_reads_as_plain_words() {
    assert_eq!(
        PatternId::TargetName.words(),
        "lower-case letters, digits and -, starting with a letter"
    );
}

fn mount_unreadable() -> Cause {
    Cause::MountUnreadable {
        workload: "work-xyz".into(),
        container: "cont-xyz".into(),
        run_as: Some(10001),
        why: MountWhy::NoFsGroup,
        env: EnvName::new("env-dev"),
        target: TargetName::new("tgt-web"),
    }
}

fn mount_path_in_use() -> Cause {
    Cause::Guard {
        guard: Guard::MountPathInUse {
            workload: "work-xyz".into(),
            container: "cont-xyz".into(),
            path: "/run/secrets/prod-api".into(),
            volume: "foreign-vol".into(),
            env: EnvName::new("env-prod"),
            target: TargetName::new("tgt-web"),
        },
    }
}

fn config_file_needs_object() -> Cause {
    Cause::ConfigInvalid {
        source: file_source(),
        at: None,
        field: DottedPath(vec![
            "environments".into(),
            "prod".into(),
            "targets".into(),
            "web".into(),
            "kubernetes".into(),
            "config".into(),
        ]),
        rule: FieldRule::Check {
            check: ConfigCheck::ConfigFileNeedsObject {
                key: "TLS_CERT".into(),
            },
        },
    }
}

fn container_path_rule() -> Cause {
    Cause::ConfigInvalid {
        source: file_source(),
        at: None,
        field: DottedPath(vec![
            "environments".into(),
            "prod".into(),
            "targets".into(),
            "web".into(),
            "secrets_dir".into(),
        ]),
        rule: FieldRule::Pattern {
            id: PatternId::ContainerPath,
        },
    }
}

#[test]
fn a_mount_unreadable_has_its_own_code() {
    assert_eq!(mount_unreadable().code(), "mount_unreadable");
}

#[test]
fn a_mount_unreadable_exits_6() {
    assert_eq!(mount_unreadable().exit_code(), 6);
}

#[test]
fn a_mount_unreadable_retries_after_the_fix() {
    assert_eq!(mount_unreadable().retry(), RetryClass::AfterFix);
}

#[test]
fn a_mount_unreadable_names_the_workload_container_and_user() {
    let m = mount_unreadable().message();
    assert!(
        m.contains("work-xyz") && m.contains("cont-xyz") && m.contains("10001"),
        "{m}"
    );
}

#[test]
fn a_mount_unreadable_documents_its_code() {
    let d = document(&mount_unreadable(), None, &inv(), false);
    assert_eq!(d["code"], serde_json::json!("mount_unreadable"));
}

#[test]
fn a_mount_path_in_use_is_a_policy_refusal() {
    assert_eq!(mount_path_in_use().code(), "policy_refused");
}

#[test]
fn a_mount_path_in_use_exits_6() {
    assert_eq!(mount_path_in_use().exit_code(), 6);
}

#[test]
fn a_mount_path_in_use_never_retries() {
    assert_eq!(mount_path_in_use().retry(), RetryClass::Never);
}

#[test]
fn a_mount_path_in_use_names_the_workload_path_and_volume() {
    let m = mount_path_in_use().message();
    assert!(
        m.contains("work-xyz") && m.contains("/run/secrets/prod-api") && m.contains("foreign-vol"),
        "{m}"
    );
}

#[test]
fn a_mount_path_in_use_documents_its_code() {
    let d = document(&mount_path_in_use(), None, &inv(), false);
    assert_eq!(d["code"], serde_json::json!("policy_refused"));
}

#[test]
fn a_config_file_needs_object_is_config_invalid() {
    assert_eq!(config_file_needs_object().code(), "config_invalid");
}

#[test]
fn a_config_file_needs_object_exits_2() {
    assert_eq!(config_file_needs_object().exit_code(), 2);
}

#[test]
fn a_config_file_needs_object_retries_after_the_fix() {
    assert_eq!(config_file_needs_object().retry(), RetryClass::AfterFix);
}

#[test]
fn a_config_file_needs_object_names_the_key() {
    assert!(config_file_needs_object().message().contains("TLS_CERT"));
}

#[test]
fn a_config_file_needs_object_asks_for_a_configmap() {
    let d = config_file_needs_object()
        .do_text(&inv())
        .unwrap_or_default();
    assert!(d.contains("set config = \"configmap\""), "{d}");
}

#[test]
fn a_config_file_needs_object_documents_its_code() {
    let d = document(&config_file_needs_object(), None, &inv(), false);
    assert_eq!(d["code"], serde_json::json!("config_invalid"));
}

#[test]
fn a_container_path_rule_is_config_invalid() {
    assert_eq!(container_path_rule().code(), "config_invalid");
}

#[test]
fn a_container_path_rule_exits_2() {
    assert_eq!(container_path_rule().exit_code(), 2);
}

#[test]
fn a_container_path_rule_retries_after_the_fix() {
    assert_eq!(container_path_rule().retry(), RetryClass::AfterFix);
}

#[test]
fn a_container_path_rule_reads_as_plain_words() {
    assert_eq!(
        PatternId::ContainerPath.words(),
        "an absolute path such as /run/secrets/{product}"
    );
}

#[test]
fn a_container_path_rule_asks_for_an_absolute_path() {
    let d = container_path_rule().do_text(&inv()).unwrap_or_default();
    assert!(
        d.contains("use an absolute path such as /run/secrets/{product}"),
        "{d}"
    );
}

#[test]
fn a_container_path_rule_documents_its_code() {
    let d = document(&container_path_rule(), None, &inv(), false);
    assert_eq!(d["code"], serde_json::json!("config_invalid"));
}

fn missing_op(platform: Platform, ci: bool) -> Cause {
    Cause::ToolMissing {
        tool: "op".into(),
        platform,
        shell: Shell::PowerShell,
        ci,
    }
}

#[test]
fn a_missing_tool_on_windows_gets_the_windows_install_line() {
    assert_eq!(
        missing_op(Platform::Windows, false)
            .do_text(&inv())
            .as_deref(),
        Some("install: winget install AgileBits.1Password.CLI")
    );
}

#[test]
fn a_missing_tool_under_ci_gets_the_ci_install_line() {
    assert_eq!(
        missing_op(Platform::Linux, true).do_text(&inv()),
        Some(crate::host::OP_CLI.ci.to_string())
    );
}

#[test]
fn a_missing_tool_opv_does_not_know_is_named_plainly() {
    let c = Cause::ToolMissing {
        tool: "frobctl".into(),
        platform: Platform::Linux,
        shell: Shell::Posix,
        ci: false,
    };
    assert_eq!(
        c.do_text(&inv()).as_deref(),
        Some("install frobctl and make sure it is on PATH")
    );
}

#[test]
fn a_missing_tool_documents_its_platform() {
    let d = document(&missing_op(Platform::MacOs, false), None, &inv(), false);
    assert_eq!(d["subject"]["platform"], serde_json::json!("macos"));
}

#[test]
fn a_resource_named_by_a_flag_says_to_check_that_flag() {
    let c = Cause::NotFound {
        system: System::Fly,
        resource: res(ResourceKind::FlyApp, "app-shop"),
        named_by: NamedBy::Flag {
            flag: "--fly-app".into(),
        },
        state: NotFoundState::Missing,
        seen: person(),
    };
    assert_eq!(
        c.do_text(&inv()).as_deref(),
        Some("check the name given with --fly-app, which names Fly app app-shop in scope-east")
    );
}

#[test]
fn a_too_wide_state_vault_in_a_manifest_is_edited_in_the_manifest() {
    let c = Cause::StateVaultTooWide {
        env: EnvName::new("prod"),
        target: TargetName::new("web"),
        vault: VaultId::new("vlt"),
        shared_with: vec![TargetName::new("worker")],
        source: ConfigSource::Manifest {
            title: "man-shop".into(),
            vault: VaultId::new("vman"),
            project: "shop".into(),
        },
        at: None,
    };
    assert_eq!(
        c.do_text(&inv()).as_deref(),
        Some(
            "delete state_vault_id from [environments.prod.targets.web] in the manifest man-shop (opv config edit) so opv makes a vault for this target alone"
        )
    );
}

#[test]
fn an_unavailable_ram_dir_previews_the_run_it_belongs_to() {
    assert_eq!(
        next_of(&fixture(53)).as_deref(),
        Some("opv run env-prod --product prod-api --remote prof-box --preview")
    );
}

fn too_large() -> Cause {
    Cause::Guard {
        guard: Guard::ValueTooLarge {
            product: ProductName::new("api"),
            key: KeyName::new("CERT"),
            env: EnvName::new("prod"),
            limit: 25_000,
        },
    }
}

#[test]
fn a_value_too_large_is_filled_in_by_a_person() {
    assert_eq!(
        too_large().step(&inv()).0,
        Some(Action::FillValue {
            product: ProductName::new("api"),
            key: KeyName::new("CERT"),
            env: EnvName::new("prod"),
        })
    );
}

#[test]
fn a_refused_generate_is_filled_in_by_a_person() {
    let c = Cause::Guard {
        guard: Guard::GenerateRefused {
            product: ProductName::new("api"),
            key: KeyName::new("CERT"),
            env: EnvName::new("prod"),
            reason: GenerateRefusal::ProviderIssued,
        },
    };
    assert!(c.human_required(&inv()));
}

#[test]
fn a_command_is_rendered_from_its_argv_with_each_word_quoted() {
    let c = Cmd {
        command: vec!["open".into()],
        args: vec!["api/KEY".into(), "--env".into(), "my env".into()],
    };
    let want = if cfg!(windows) {
        "opv open api/KEY --env \"my env\""
    } else {
        "opv open api/KEY --env 'my env'"
    };
    assert_eq!(cmd_text(&c), want);
}

#[test]
fn a_vault_in_another_account_needs_no_person() {
    assert!(!in_other_account().human_required(&inv()));
}

#[test]
fn a_located_vault_names_the_account_that_holds_it() {
    assert_eq!(
        in_owned_account().message(),
        "vault atqr2ek (environment staging) is not in 1Password account 6AINMAIK; it is in account OWNS1"
    );
}

#[test]
fn a_located_vault_says_to_select_its_account_or_fix_the_vault_id() {
    assert_eq!(
        in_owned_account().do_text(&inv()).unwrap_or_default(),
        "select account OWNS1 (opv account use OWNS1), or fix vault_id for environment staging"
    );
}

#[test]
fn a_located_vault_next_selects_its_account() {
    let (_, next) = in_owned_account().step(&inv());
    assert_eq!(
        next,
        Next::Run(Cmd {
            command: vec!["account".into(), "use".into()],
            args: vec!["OWNS1".into()],
        })
    );
}

#[test]
fn a_located_vault_leaves_the_choice_to_a_person() {
    assert!(in_owned_account().human_required(&inv()));
}

#[test]
fn a_located_vault_keeps_its_code() {
    assert_eq!(in_owned_account().code(), "ids_not_in_account");
}

#[test]
fn a_vault_no_askable_account_holds_names_the_accounts_not_asked() {
    assert_eq!(
        in_no_askable_account().message(),
        "vault atqr2ek (environment staging) is not in 1Password account 6AINMAIK or in any other account opv could ask; account UNASK1 could not be asked"
    );
}

#[test]
fn a_vault_no_askable_account_holds_says_to_sign_in_to_look_there() {
    assert_eq!(
        in_no_askable_account().do_text(&inv()).unwrap_or_default(),
        "sign in to account UNASK1 to look for vault atqr2ek there, or fix vault_id for environment staging"
    );
}

#[test]
fn a_vault_no_askable_account_holds_next_signs_in_for_the_search_only() {
    let (_, next) = in_no_askable_account().step(&inv());
    assert_eq!(
        next,
        Next::Handoff(Cmd {
            command: vec!["login".into()],
            args: [
                "--account",
                "UNASK1",
                "--no-record",
                "--",
                "opv",
                "vault",
                "locate",
                "atqr2ek",
            ]
            .map(String::from)
            .to_vec(),
        })
    );
}

#[test]
fn a_vault_no_account_on_the_machine_holds_says_so() {
    assert_eq!(
        in_no_account_on_the_machine().message(),
        "vault atqr2ek (environment staging) is not in 1Password account 6AINMAIK or in any other account on this machine"
    );
}

#[test]
fn a_vault_no_account_on_the_machine_holds_says_to_fix_the_vault_id() {
    assert_eq!(
        in_no_account_on_the_machine()
            .do_text(&inv())
            .unwrap_or_default(),
        "no 1Password account on this machine holds vault atqr2ek: fix vault_id for environment staging with a vault of account 6AINMAIK"
    );
}

#[test]
fn a_vault_no_account_on_the_machine_holds_next_lists_the_selected_accounts_vaults() {
    let (_, next) = in_no_account_on_the_machine().step(&inv());
    assert_eq!(
        next,
        Next::Vendor(VendorCmd {
            program: "op".into(),
            args: ["vault", "list", "--account", "6AINMAIK"]
                .map(String::from)
                .to_vec(),
        })
    );
}

#[test]
fn a_vault_no_account_on_the_machine_holds_needs_no_person() {
    assert!(!in_no_account_on_the_machine().human_required(&inv()));
}

#[test]
fn a_vault_in_another_account_not_searched_still_steps_to_vault_locate() {
    let (_, next) = in_other_account().step(&inv());
    assert_eq!(
        next,
        Next::Run(Cmd {
            command: vec!["vault".into(), "locate".into()],
            args: vec!["atqr2ek".into()],
        })
    );
}

// --- FOLLOWUPS section A: one regression test per item, each citing it -------------------

fn person_at_terminal() -> Situation {
    Situation {
        ci: false,
        terminal: true,
        identity: Principal::Person { account: None },
        config_source: file_source(),
        platform: Platform::Linux,
        op: super::super::situation::OpFlavour::Native,
        remote: false,
        deploy_credentials_or_shell_token: false,
    }
}

fn under_ci() -> Situation {
    Situation {
        ci: true,
        terminal: false,
        ..person_at_terminal()
    }
}

fn cli(words: &[&str]) -> Invocation {
    Invocation::from_cli(&words.iter().map(|w| w.to_string()).collect::<Vec<_>>())
}

fn fly_seen() -> Observed {
    Observed::from_failed_call(
        CallId {
            system: System::Fly,
            program: "flyctl".into(),
            words: vec!["secrets".into(), "list".into()],
        },
        ExitClass::TimedOut,
        Principal::Person { account: None },
    )
}

fn not_signed_in(system: System) -> Cause {
    Cause::NotSignedIn {
        system,
        account: None,
        state: SessionState::SignedOut,
    }
}

fn next_in(c: &Cause, inv: &Invocation) -> String {
    next_text(&c.step_in(inv, &person_at_terminal()).1, inv).unwrap_or_default()
}

/// A1: an empty minted token is named as such, not as unreadable output.
#[test]
fn a1_an_empty_minted_token_is_named() {
    let c = Cause::UnexpectedOutput {
        system: System::Fly,
        at: None,
        problem: OutputProblem::Empty {
            what: "deploy token",
        },
        during: During::Read,
        seen: fly_seen(),
    };
    assert!(
        c.message().contains("an empty deploy token"),
        "{}",
        c.message()
    );
}

/// A1: a dead app is a refusal of its own.
#[test]
fn a1_a_dead_app_says_it_is_not_running() {
    let c = Cause::TargetRefused {
        system: System::Fly,
        subject: res(ResourceKind::FlyApp, "app-web"),
        why: Refusal::NotRunning,
        env: None,
        target: None,
        seen: fly_seen(),
    };
    assert!(c.message().contains("is not running"), "{}", c.message());
}

/// A3: opv's own local I/O names the path.
#[test]
fn a3_local_io_names_the_path() {
    let c = Cause::LocalIo {
        op: LocalOp::Write,
        path: PathBuf::from("/work/secrets.toml"),
        io: IoKind::PermissionDenied,
    };
    assert_eq!(
        c.message(),
        "opv could not write /work/secrets.toml: permission denied"
    );
}

/// A4: sync's refusal keeps exit 6 (`keys_blocking`).
#[test]
fn a4_keys_blocking_exits_6() {
    let c = Cause::KeysBlocking {
        env: EnvName::new("prod"),
        rows: vec![],
    };
    assert_eq!((c.code(), c.exit_code()), ("keys_blocking", 6));
}

fn blocking_row(state: ValueState) -> ValueRow {
    ValueRow {
        product: ProductName::new("web"),
        key: KeyName::new("API_KEY"),
        target: None,
        state,
    }
}

/// A4: sync's refusal keeps the rule's reason, so the person knows what to correct.
#[test]
fn a4_keys_blocking_names_the_rules_reason() {
    let c = Cause::KeysBlocking {
        env: EnvName::new("prod"),
        rows: vec![blocking_row(ValueState::RuleFailed {
            rule: "prefix",
            reason: Some("expected prefix sk-".into()),
        })],
    };
    assert!(
        c.message().contains("rule prefix: expected prefix sk-"),
        "{}",
        c.message()
    );
}

/// A missing value's Do says to click Edit: 1Password hides an empty field until then.
#[test]
fn values_needed_for_a_missing_value_says_to_click_edit() {
    let c = Cause::ValuesNeeded {
        env: EnvName::new("prod"),
        rows: vec![blocking_row(ValueState::Missing)],
    };
    let d = c
        .do_text_in(&inv(), &person_at_terminal())
        .unwrap_or_default();
    assert!(d.contains("click Edit"), "{d}");
}

/// A value stored as text is visible, so its Do has no click-Edit hint.
#[test]
fn values_needed_for_a_visible_value_has_no_click_edit_hint() {
    let c = Cause::ValuesNeeded {
        env: EnvName::new("prod"),
        rows: vec![blocking_row(ValueState::StoredAsText)],
    };
    let d = c
        .do_text_in(&inv(), &person_at_terminal())
        .unwrap_or_default();
    assert!(!d.contains("click Edit"), "{d}");
}

/// A5: a malformed entry of a repeatable option is named.
#[test]
fn a5_a_malformed_entry_is_named() {
    let c = Cause::Usage {
        problem: UsageProblem::EntryFormat {
            flag: "--rotate".into(),
            entry: "apiKEY".into(),
            format: "product/KEY",
        },
    };
    assert!(c.message().contains("--rotate apiKEY"), "{}", c.message());
}

/// A6 (R21): an undeclared key names the environment.
#[test]
fn a6_an_undeclared_key_names_its_environment() {
    let c = Cause::KeyNotDeclared {
        key: KeyName::new("API_KEY"),
        env: EnvName::new("prod"),
        product: None,
    };
    assert_eq!(
        c.message(),
        "key API_KEY is not declared for environment prod"
    );
}

/// A7: a store's reason is shown only as a code word, never as free text.
#[test]
fn a7_a_store_reason_that_is_not_a_code_is_never_echoed() {
    let c = Cause::StoreNotReady {
        store: res(ResourceKind::ExternalStore, "op-store"),
        reason: Some("token=abc is wrong".into()),
    };
    assert!(!c.message().contains("abc"), "{}", c.message());
}

/// A7: a deployment that changed before the write is a target object.
#[test]
fn a7_a_deployment_changed_before_the_write_is_a_target_change() {
    let c = Cause::ChangedBeforeWrite {
        object: StoreObject::Resource {
            resource: res(ResourceKind::Deployment, "web"),
            changed: Vec::new(),
        },
    };
    assert_eq!((c.code(), c.exit_code()), ("target_changed", 5));
}

/// J2: a deployment changed before the write names what changed in it.
#[test]
fn a_deployment_changed_before_the_write_names_the_changed_paths() {
    let c = Cause::ChangedBeforeWrite {
        object: StoreObject::Resource {
            resource: res(ResourceKind::Deployment, "web"),
            changed: vec!["/spec/template/spec/containers/0/image".into()],
        },
    };
    assert!(
        c.message()
            .contains("/spec/template/spec/containers/0/image")
    );
}

/// J4: a deployment is named with its namespace as a namespace.
#[test]
fn a_deployment_names_its_namespace() {
    let r = ResourceRef {
        kind: ResourceKind::Deployment,
        name: ResourceName::new("app"),
        scope: Some("e2e-prod".into()),
    };
    assert_eq!(resource_words(&r), "deployment app in namespace e2e-prod");
}

/// J2: a rollout still running when opv stopped waiting names its revision.
#[test]
fn a_rollout_still_in_progress_names_its_revision() {
    let c = Cause::TargetRefused {
        system: System::Kubernetes,
        subject: res(ResourceKind::Deployment, "web"),
        why: Refusal::InProgress {
            revision: Some("rev-42".into()),
        },
        env: None,
        target: None,
        seen: person(),
    };
    assert!(c.message().contains("rev-42"));
}

/// A7: a Key Vault secret is a resource kind of its own.
#[test]
fn a7_a_key_vault_secret_is_named_as_one() {
    let r = ResourceRef {
        kind: ResourceKind::KeyVaultSecret,
        name: ResourceName::new("DB-URL"),
        scope: None,
    };
    assert_eq!(resource_words(&r), "Key Vault secret DB-URL");
}

/// A7: the hand-off pipe's refusal is a cause of its own.
#[test]
fn a7_a_contested_handoff_pipe_is_refused() {
    let c = Cause::HandoffPipeContested {
        system: System::Azure,
    };
    assert_eq!(c.code(), "handoff_refused");
}

/// A8: with colour, the upstream box is dimmed.
#[test]
fn a8_colour_dims_the_upstream_box() {
    let text = render_text(
        &in_other_account(),
        Some(&upstream(1, false)),
        &inv(),
        false,
        true,
        true,
    );
    assert!(text.contains("\x1b[2m"), "{text}");
}

/// A9 (X4): a re-run never repeats a used approval; it is the read.
#[test]
fn a9_a_rerun_never_repeats_the_approval() {
    let c = Cause::WriteOutcomeUnknown {
        system: System::Fly,
        subject: res(ResourceKind::FlyApp, "app-web"),
        seen: fly_seen(),
    };
    let inv = cli(&["opv", "sync", "prod", "--approved", "ab12cd34"]);
    assert_eq!(next_in(&c, &inv), "opv plan prod");
}

/// A9 (X4): nor a confirmation or an expected plan.
#[test]
fn a9_a_rerun_never_repeats_a_confirmation() {
    let c = Cause::Interrupted {
        signal: 2,
        writes_started: false,
    };
    let inv = cli(&[
        "opv",
        "sync",
        "prod",
        "--confirm",
        "prod",
        "--expect-plan",
        "ab12cd34",
    ]);
    let next = next_in(&c, &inv);
    assert!(
        !next.contains("--confirm") && !next.contains("--expect-plan"),
        "{next}"
    );
}

/// A10: under CI, a Fly sign-in is the job's token, not `flyctl auth login`.
#[test]
fn a10_under_ci_fly_sign_in_is_the_token() {
    let d = not_signed_in(System::Fly)
        .do_text_in(&inv(), &under_ci())
        .unwrap_or_default();
    assert!(
        d.contains("FLY_API_TOKEN") && !d.contains("flyctl auth login"),
        "{d}"
    );
}

/// A10: under CI, a 1Password sign-in is the service account token, never `opv login`.
#[test]
fn a10_under_ci_1password_sign_in_is_the_service_account_token() {
    let d = not_signed_in(System::OnePassword)
        .do_text_in(&inv(), &under_ci())
        .unwrap_or_default();
    assert!(d.contains("OP_SERVICE_ACCOUNT_TOKEN"), "{d}");
}

/// A10: under CI, Next is never `opv login`.
#[test]
fn a10_under_ci_next_is_never_opv_login() {
    let c = not_signed_in(System::OnePassword);
    let next = next_text(&c.step_in(&inv(), &under_ci()).1, &inv()).unwrap_or_default();
    assert!(!next.contains("login"), "{next}");
}

/// A10: `Usage`'s help step passes the refusal predicate (a hidden command's own help is
/// never a step).
#[test]
fn a10_a_help_step_is_never_a_hidden_command() {
    let c = Cause::Usage {
        problem: UsageProblem::ConflictsWith {
            a: "--a".into(),
            b: "--b".into(),
        },
    };
    let inv = Invocation {
        command: vec!["local-delivery".into()],
        args: vec![],
        ..inv()
    };
    assert!(!next_in(&c, &inv).contains("local-delivery"));
}

/// A11 (X11): a choice among several names the listing, never `none`.
#[test]
fn a11_a_choice_among_several_lists_them() {
    let c = Cause::ChoiceRequired {
        flag: "--target".into(),
        candidates: vec!["web".into(), "worker".into()],
    };
    assert_eq!(next_in(&c, &inv()), "opv target list");
}

/// A11: the one candidate keeps the child command's placeholder.
#[test]
fn a11_the_one_candidate_keeps_the_child_placeholder() {
    let c = Cause::ChoiceRequired {
        flag: "--product".into(),
        candidates: vec!["api".into()],
    };
    let inv = cli(&["opv", "run", "prod", "--", "node", "app.js"]);
    assert!(next_in(&c, &inv).ends_with("-- <command>"));
}

/// A11: `NeedsConfirm` keeps the child command's placeholder.
#[test]
fn a11_needs_confirm_keeps_the_child_placeholder() {
    let c = Cause::NeedsConfirm {
        env: EnvName::new("prod"),
    };
    let inv = cli(&["opv", "run", "prod", "--", "node", "app.js"]);
    assert_eq!(
        next_in(&c, &inv),
        "opv run prod --confirm prod -- <command>"
    );
}

/// A12: an unrecognised ssh failure re-runs with `--verbose`, never `opv doctor`.
#[test]
fn a12_an_unrecognised_ssh_failure_reruns_verbose() {
    let c = Cause::Unrecognized {
        system: System::Ssh,
        established: vec![],
        env: None,
        target: None,
        seen: fly_seen(),
    };
    let inv = cli(&["opv", "run", "prod", "--remote", "box"]);
    assert!(next_in(&c, &inv).contains("--verbose"));
}

/// A12: the pinned ssh check uses the profile's identity file alone.
#[test]
fn a12_the_pinned_ssh_check_uses_the_identity_file() {
    let c = Cause::RemoteUnreachable {
        profile: ProfileName::new("box"),
        user: "deployer".into(),
        host: "box.example".into(),
        port: 22,
        known_hosts: pinned_hosts(),
        identity_file: Some(PathBuf::from("/home/me/.ssh/box")),
    };
    assert!(next_in(&c, &inv()).contains("-i /home/me/.ssh/box -o IdentitiesOnly=yes"));
}

fn unverified(state: Unverified) -> Cause {
    Cause::DeliveryUnverified {
        env: EnvName::new("prod"),
        target: TargetName::new("web"),
        product: ProductName::new("api"),
        state,
    }
}

/// A13: a superseded delivery has a Do naming the later receipt.
#[test]
fn a13_a_superseded_delivery_names_the_later_receipt() {
    let d = unverified(Unverified::Superseded {
        receipt: PathBuf::from("/tmp/receipt.json"),
    })
    .do_text(&inv())
    .unwrap_or_default();
    assert!(d.contains("/tmp/receipt.json"), "{d}");
}

/// A13: a delivery from another account steps to signing in to it.
#[test]
fn a13_another_account_steps_to_signing_in_to_it() {
    let c = unverified(Unverified::OtherAccount {
        account: AccountId::new("ACC-B"),
    });
    assert_eq!(next_in(&c, &inv()), "opv login --account ACC-B");
}

/// A13: "this target delivers no secret" is a scope of its own.
#[test]
fn a13_a_target_that_delivers_no_secret_says_so() {
    let c = Cause::NothingInScope {
        env: EnvName::new("prod"),
        what: Scope::NoSecretDelivered {
            target: TargetName::new("web"),
        },
    };
    assert!(
        c.message().contains("delivers no secret"),
        "{}",
        c.message()
    );
}

/// A14: an existing manifest with a local copy checks that copy.
#[test]
fn a14_an_existing_manifest_checks_the_local_copy() {
    let c = Cause::ManifestExists {
        title: "opv shop".into(),
        local_file: Some(PathBuf::from("secrets.toml")),
    };
    assert_eq!(next_in(&c, &inv()), "opv config check --file secrets.toml");
}

/// A14: a missing manifest has a Do.
#[test]
fn a14_a_missing_manifest_has_a_do() {
    let c = Cause::ManifestNotFound {
        project: "shop".into(),
        account: None,
    };
    assert!(c.do_text(&inv()).is_some());
}

/// A14: differing copies need a person's judgement, but no person-only step.
#[test]
fn a14_differing_copies_are_not_human_required() {
    let c = Cause::CopiesDiffer {
        file: PathBuf::from("secrets.toml"),
        manifest: "opv shop".into(),
    };
    assert!(!c.human_required(&inv()));
}

/// A14: one ambiguous manifest is singular.
#[test]
fn a14_one_manifest_matches_in_the_singular() {
    let c = Cause::ManifestAmbiguous {
        candidates: vec!["opv shop".into()],
        person_picks: false,
    };
    assert_eq!(
        c.message(),
        "1 1Password manifest matches this project: opv shop"
    );
}

/// A14: a configuration file that does not exist steps to `opv doctor`.
#[test]
fn a14_a_missing_config_file_steps_to_doctor() {
    let c = Cause::ConfigUnreadable {
        path: PathBuf::from("nope.toml"),
        io: IoKind::NotFound,
        given_by: GivenBy::Flag {
            flag: "--config".into(),
        },
    };
    assert_eq!(next_in(&c, &inv()), "opv doctor");
}

/// A15: a partial failure with nothing written never says "already written: ".
#[test]
fn a15_nothing_written_is_never_listed() {
    let c = Cause::Partial {
        done: vec![],
        approval_used: None,
        approval_scope: None,
        then: Box::new(Cause::Interrupted {
            signal: 2,
            writes_started: true,
        }),
    };
    assert!(!render_text(&c, None, &inv(), false, true, false).contains("already written"));
}

/// A16: a missing namespace is not answered with the context listing.
#[test]
fn a16_a_missing_namespace_does_not_list_contexts() {
    let c = Cause::NotFound {
        system: System::Kubernetes,
        resource: res(ResourceKind::Namespace, "apps"),
        named_by: NamedBy::Flag {
            flag: "--namespace".into(),
        },
        state: NotFoundState::Missing,
        seen: fly_seen(),
    };
    assert_eq!(next_in(&c, &inv()), "kubectl get namespaces");
}

/// A16: a Kubernetes sign-in refreshes the context's credentials.
#[test]
fn a16_a_kubernetes_sign_in_refreshes_the_context() {
    let c = Cause::NotSignedIn {
        system: System::Kubernetes,
        account: Some(AccountId::new("prod-aks")),
        state: SessionState::Expired,
    };
    let d = c.do_text(&inv()).unwrap_or_default();
    assert!(d.contains("credentials of kube context prod-aks"), "{d}");
}

/// A16: a missing Kubernetes right names the verb and kind once.
#[test]
fn a16_a_missing_kubernetes_right_reads_once() {
    let c = Cause::MissingRight {
        system: System::Kubernetes,
        resource: ResourceRef {
            kind: ResourceKind::Namespace,
            name: ResourceName::new("secrets"),
            scope: Some("apps".into()),
        },
        right: Right::Verb {
            verb: "get".into(),
            resource: "secrets".into(),
        },
        grant: GrantModel::K8sRbac {
            verb: "get".into(),
            resource: "secrets".into(),
            namespace: Some("apps".into()),
        },
        env: None,
        target: None,
        seen: fly_seen(),
    };
    assert_eq!(
        c.message(),
        "you may not get secrets in namespace apps (Kubernetes)"
    );
}

/// A17: a soft-deleted Key Vault is recovered in its subscription.
#[test]
fn a17_key_vault_recovery_names_the_subscription() {
    let c = Cause::NotFound {
        system: System::Azure,
        resource: ResourceRef {
            kind: ResourceKind::KeyVault,
            name: ResourceName::new("kv-shop"),
            scope: Some("subscription sub-1".into()),
        },
        named_by: NamedBy::Flag {
            flag: "--vault".into(),
        },
        state: NotFoundState::SoftDeleted,
        seen: fly_seen(),
    };
    let d = c.do_text(&inv()).unwrap_or_default();
    assert!(d.contains("--subscription sub-1"), "{d}");
}

fn soft_deleted_secret() -> Cause {
    Cause::NotFound {
        system: System::Azure,
        resource: ResourceRef::key_vault_secret("kv-shop", "DB-URL", "sub-1"),
        named_by: NamedBy::Flag {
            flag: "--vault".into(),
        },
        state: NotFoundState::SoftDeleted,
        seen: fly_seen(),
    }
}

/// 06.29 regression: a soft-deleted Key Vault secret's recover Do names the subscription.
#[test]
fn a17_key_vault_secret_recovery_names_the_subscription() {
    let d = soft_deleted_secret().do_text(&inv()).unwrap_or_default();
    assert!(
        d.contains(
            "az keyvault secret recover --vault-name kv-shop --name DB-URL --subscription sub-1"
        ),
        "{d}"
    );
}

/// 06.29 regression: the Next that lists deleted secrets reads the same subscription.
#[test]
fn a17_key_vault_secret_recovery_next_reads_the_subscription() {
    let (_, next) = soft_deleted_secret().step_in(&inv(), &person_at_terminal());
    assert_eq!(
        next_text(&next, &inv()).unwrap_or_default(),
        "az keyvault secret list-deleted --vault-name kv-shop --subscription sub-1"
    );
}

/// I5: a revision-mode refusal is the owner's step, naming set-mode.
#[test]
fn i5_revision_mode_do_names_set_mode() {
    let c = Cause::TargetRefused {
        system: System::Azure,
        subject: res(ResourceKind::ContainerApp, "app-web"),
        why: Refusal::RevisionMode {
            mode: "multiple".into(),
            resource_group: "rg-1".into(),
            subscription: "sub-1".into(),
        },
        env: None,
        target: None,
        seen: fly_seen(),
    };
    let d = c.do_text(&inv()).unwrap_or_default();
    assert!(
        d.contains("az containerapp revision set-mode --mode single --resource-group rg-1 --name app-web --subscription sub-1"),
        "{d}"
    );
}

/// I5: changed settings are listed, at most five, with a count of the rest.
#[test]
fn i5_changed_outside_opv_lists_at_most_five_paths() {
    let paths: Vec<String> = (1..=7).map(|i| format!("p{i}")).collect();
    let c = Cause::TargetRefused {
        system: System::Azure,
        subject: res(ResourceKind::ContainerApp, "app-web"),
        why: Refusal::ChangedOutsideOpv {
            paths,
            after_apply: false,
        },
        env: None,
        target: None,
        seen: fly_seen(),
    };
    assert!(
        c.message()
            .contains("(changed: p1, p2, p3, p4, p5 and 2 more)"),
        "{}",
        c.message()
    );
}

/// I5: an invalid value in a reply is named as one, not as an empty reply.
#[test]
fn i5_an_invalid_value_in_a_reply_is_named() {
    let c = Cause::UnexpectedOutput {
        system: System::Azure,
        at: None,
        problem: OutputProblem::InvalidValue { what: "version id" },
        during: During::Read,
        seen: fly_seen(),
    };
    assert!(
        c.message().contains("with a version id opv cannot use"),
        "{}",
        c.message()
    );
}

/// I5: an unusable reply to an applied write says the change was made.
#[test]
fn i5_an_unusable_reply_to_an_applied_write_says_it_was_applied() {
    let c = Cause::UnexpectedOutput {
        system: System::Azure,
        at: None,
        problem: OutputProblem::Unparseable,
        during: During::AppliedWrite,
        seen: fly_seen(),
    };
    assert!(
        c.message().contains("the change was applied at Azure"),
        "{}",
        c.message()
    );
}

/// I5 (R74): az's missing in-memory folder is named for its sign-in, not a settings file.
#[test]
fn i5_ram_dir_for_azure_names_the_sign_in() {
    let c = Cause::RamDirUnavailable {
        remote: None,
        why: RamDir::NotTmpfs,
        purpose: RamPurpose::AzureDeployCredentials,
        env: None,
        product: None,
    };
    assert!(
        c.message()
            .contains("for az's sign-in with deploy credentials"),
        "{}",
        c.message()
    );
}

/// I5 (R74): on macOS the Azure way out is another machine, never a settings-file change.
#[test]
fn i5_ram_dir_for_azure_on_macos_points_to_another_machine() {
    let c = Cause::RamDirUnavailable {
        remote: None,
        why: RamDir::NoneOnPlatform { os: "macOS" },
        purpose: RamPurpose::AzureDeployCredentials,
        env: None,
        product: None,
    };
    let d = c.do_text(&inv()).unwrap_or_default();
    assert!(d.contains("from a Linux or Windows machine"), "{d}");
}

/// I5: az storing the secret unencrypted is its own cause, not a folder failure.
#[test]
fn i5_unencrypted_store_is_a_tool_cause() {
    let c = Cause::ToolUnusable {
        tool: "az".into(),
        why: Unusable::StoredSecretUnencrypted,
    };
    assert!(c.message().contains("unencrypted"), "{}", c.message());
}

/// I5: a malformed ID in the deploy credentials item is fixed in 1Password, in that item.
#[test]
fn i5_invalid_deploy_credential_field_is_fixed_in_the_item() {
    let c = Cause::InputInvalid {
        path: PathBuf::from("op://ops/azure-prod"),
        kind: InputKind::DeployCredentials,
        at: None,
        field: "AZURE_CLIENT_ID".into(),
        rule: FieldRule::Pattern {
            id: PatternId::Guid,
        },
    };
    let d = c.do_text(&inv()).unwrap_or_default();
    assert!(
        d.contains("in 1Password, open the deploy credentials item op://ops/azure-prod and change AZURE_CLIENT_ID to a GUID"),
        "{d}"
    );
}

/// A17: an unanswered provider names its status page.
#[test]
fn a17_unavailable_names_the_status_page() {
    let c = Cause::Unavailable {
        system: System::Fly,
        why: Unanswered::Timeout,
        attempts: 3,
        seen: fly_seen(),
    };
    let d = c.do_text(&inv()).unwrap_or_default();
    assert!(d.contains("https://status.flyio.net"), "{d}");
}

/// D6 (X26): a killed call is never reported as a timeout.
#[test]
fn d6_a_killed_unavailable_read_does_not_say_it_timed_out() {
    let c = Cause::Unavailable {
        system: System::Fly,
        why: Unanswered::Killed { signal: 15 },
        attempts: 1,
        seen: fly_seen(),
    };
    assert!(!c.message().contains("timed out"), "{}", c.message());
}

/// D6 (X26): a lost reply is reported as lost.
#[test]
fn d6_a_lost_unavailable_read_says_its_reply_was_lost() {
    let c = Cause::Unavailable {
        system: System::Fly,
        why: Unanswered::Lost,
        attempts: 1,
        seen: fly_seen(),
    };
    assert!(c.message().contains("reply was lost"), "{}", c.message());
}

/// D6: the runner's lost reply is its own exit class, never a timeout or a signal.
#[test]
fn d6_a_lost_exit_class_is_unanswered_because_lost() {
    assert_eq!(ExitClass::Lost.unanswered(), Some(Unanswered::Lost));
}

fn doctor_inv(args: &[&str]) -> Invocation {
    Invocation {
        origin: Origin::Cli,
        command: vec!["doctor".into()],
        args: args.iter().map(|a| a.to_string()).collect(),
        has_child: false,
    }
}

fn unrecognized_op() -> Cause {
    Cause::Unrecognized {
        system: System::OnePassword,
        established: Vec::new(),
        env: Some(EnvName::new("dev")),
        target: None,
        seen: person(),
    }
}

/// E1: under `opv doctor`, an unrecognised reply steps to the same check with the whole
/// reply, not back to `opv doctor`.
#[test]
fn e1_unrecognized_under_doctor_steps_to_the_verbose_check() {
    let (_, next) =
        unrecognized_op().step_in(&doctor_inv(&["--env", "dev"]), &person_at_terminal());
    assert_eq!(
        next,
        Next::Run(Cmd {
            command: vec!["doctor".into()],
            args: vec!["--env".into(), "dev".into(), "--verbose".into()],
        })
    );
}

/// E1: an unusable reply under `opv doctor` does not step back to `opv doctor`.
#[test]
fn e1_unexpected_output_under_doctor_does_not_step_to_plain_doctor() {
    let c = Cause::UnexpectedOutput {
        system: System::OnePassword,
        at: None,
        problem: OutputProblem::Unparseable,
        during: During::Read,
        seen: person(),
    };
    let (_, next) = c.step_in(&doctor_inv(&[]), &person_at_terminal());
    assert_ne!(next, Next::Run(cmd(&["doctor"], &[])));
}

/// E1: once the whole reply is shown, the step under `opv doctor` is its help.
#[test]
fn e1_unrecognized_under_verbose_doctor_steps_to_its_help() {
    let (_, next) = unrecognized_op().step_in(
        &doctor_inv(&["--env", "dev", "--verbose"]),
        &person_at_terminal(),
    );
    assert_eq!(next, Next::Check(cmd(&["doctor"], &["--help"])));
}

/// 09.85: a key typo given to `opv open` steps to the declared key, opened.
#[test]
fn n09_85_an_open_key_typo_steps_to_the_close_key() {
    let c = Cause::NotDeclared {
        kind: NameKind::Key,
        given: "web/API_KY".into(),
        candidates: vec!["web/API_KEY".into()],
        closest: Closest::unique(&["web/API_KEY"]),
    };
    let inv = Invocation {
        origin: Origin::Cli,
        command: vec!["open".into()],
        args: vec!["web/API_KY".into(), "--env".into(), "prod".into()],
        has_child: false,
    };
    assert_eq!(
        c.step_in(&inv, &person_at_terminal()).1,
        Next::Run(cmd(&["open"], &["web/API_KEY", "--env", "prod"]))
    );
}

/// A18 (01.12): only the person knows which environment they meant.
#[test]
fn a18_confirm_mismatch_needs_a_person() {
    let c = Cause::ConfirmMismatch {
        given: "prd".into(),
        env: EnvName::new("prod"),
    };
    assert!(c.human_required(&inv()));
}

/// A19 (R26): a usage error of sync steps to the environment's plan, not `--help`.
#[test]
fn a19_a_sync_usage_error_steps_to_the_plan() {
    let c = Cause::Usage {
        problem: UsageProblem::NeedsFlag {
            flag: "--prune-immutable".into(),
            needs: "--prune".into(),
        },
    };
    assert_eq!(next_in(&c, &inv()), "opv plan prod");
}

/// A20 (X1): a built step keeps the invocation's `--config`.
#[test]
fn a20_a_built_step_keeps_the_config_flag() {
    let c = Cause::BoundaryMissing {
        env: EnvName::new("prod"),
        product: ProductName::new("api"),
        source: file_source(),
    };
    let inv = cli(&["opv", "sync", "prod", "--config", "cfg/secrets.toml"]);
    assert_eq!(next_in(&c, &inv), "opv bootstrap --config cfg/secrets.toml");
}

/// A21: a rejected credential needs a person to replace it.
#[test]
fn a21_a_rejected_credential_needs_a_person() {
    let c = Cause::CredentialRejected {
        system: System::Fly,
        credential: CredentialRef::ShellToken {
            var: VarName::new("FLY_API_TOKEN"),
        },
        problem: CredentialProblem::Rejected { needs: vec![] },
        seen: fly_seen(),
    };
    assert!(c.human_required(&inv()));
}

/// A21: a person's unanswered op keeps the hint to approve the app's prompt.
#[test]
fn a21_unavailable_op_hints_at_the_app_prompt() {
    let c = Cause::Unavailable {
        system: System::OnePassword,
        why: Unanswered::Timeout,
        attempts: 1,
        seen: person(),
    };
    let d = c.do_text(&inv()).unwrap_or_default();
    assert!(d.contains("approve the 1Password app's prompt"), "{d}");
}

/// A21: no account at all on the machine has its own words.
#[test]
fn a21_no_account_at_all_has_its_own_words() {
    let c = Cause::AccountNotOnMachine {
        account: AccountRef::Any,
        selected_by: AccountSource::OpDefault,
        in_app: false,
    };
    assert_eq!(
        c.message(),
        "no 1Password account is added to op on this machine"
    );
}

// --- FOLLOWUPS F, D, E1: one regression test per item, each citing it -------------------

fn no_terminal() -> Situation {
    Situation {
        terminal: false,
        ..person_at_terminal()
    }
}

fn next_under(c: &Cause, inv: &Invocation, sit: &Situation) -> String {
    next_text(&c.step_in(inv, sit).1, inv).unwrap_or_default()
}

/// F1 (X11): a refused step falls back to the command's help, never to an empty Next.
#[test]
fn f1_a_refused_setup_falls_back_to_its_help() {
    let c = Cause::NeedsTerminal {
        why: NoTerminal::Ci,
    };
    let inv = cli(&["opv", "setup", "--product", "api"]);
    assert_eq!(next_under(&c, &inv, &under_ci()), "opv setup --help");
}

/// E1: a kube context that needs a credential refresh never steps back to the same read
/// when this run has no terminal.
#[test]
fn e1_kube_signed_out_without_a_terminal_does_not_rerun_the_read() {
    let inv = cli(&["opv", "plan", "prod"]);
    assert_eq!(
        next_under(&not_signed_in(System::Kubernetes), &inv, &no_terminal()),
        "opv doctor --env prod"
    );
}

/// E1: under CI a kube sign-in is the job's own credential, not a refresh by a person.
#[test]
fn e1_kube_signed_out_under_ci_names_the_ci_credential() {
    let inv = cli(&["opv", "plan", "prod"]);
    assert!(
        not_signed_in(System::Kubernetes)
            .do_text_in(&inv, &under_ci())
            .unwrap_or_default()
            .contains("give this CI job a kubeconfig")
    );
}

fn generate_refused(reason: GenerateRefusal) -> Cause {
    Cause::Guard {
        guard: Guard::GenerateRefused {
            product: ProductName::new("web"),
            key: KeyName::new("TOKEN"),
            env: EnvName::new("prod"),
            reason,
        },
    }
}

fn partial(then: Cause, done: &[&str]) -> Cause {
    Cause::Partial {
        done: done.iter().map(|d| d.to_string()).collect(),
        approval_used: None,
        approval_scope: None,
        then: Box::new(then),
    }
}

fn secret_not_stored(refind: Option<VendorCmd>) -> Cause {
    Cause::SecretNotStored {
        system: System::Fly,
        kind: CreateKind::DeployToken,
        name: "tok-web".into(),
        env: EnvName::new("prod"),
        target: Some(TargetName::new("web")),
        refind,
    }
}

/// F2 (R21): `opv add` into an undeclared environment steps to declaring it.
#[test]
fn f2_an_undeclared_environment_from_add_steps_to_env_add() {
    let c = Cause::NotDeclared {
        kind: NameKind::Environment,
        given: "staging".into(),
        candidates: vec!["prod".into()],
        closest: None,
    };
    assert_eq!(
        next_in(&c, &cli(&["opv", "add", "staging", "web/KEY"])),
        "opv env add staging"
    );
}

/// F2: a proposed configuration that would be invalid says nothing was written.
#[test]
fn f2_an_invalid_proposal_says_nothing_was_written() {
    let c = Cause::ConfigProposalInvalid {
        source: file_source(),
        field: DottedPath(vec!["products".into(), "web".into()]),
        rule: FieldRule::Missing,
        from_proposal: false,
    };
    assert!(c.message().contains("nothing was written"));
}

/// F2 (R64): a shared key steps to generating its source.
#[test]
fn f2_a_shared_key_steps_to_generating_its_source() {
    let c = generate_refused(GenerateRefusal::Shared {
        from: "api/TOKEN".into(),
    });
    assert_eq!(
        next_in(&c, &cli(&["opv", "generate", "prod", "web/TOKEN"])),
        "opv generate prod api/TOKEN"
    );
}

/// F2 (R64): a byte count out of range steps to the configuration.
#[test]
fn f2_a_byte_count_out_of_range_steps_to_config_edit() {
    let c = generate_refused(GenerateRefusal::ByteCountOutOfRange);
    assert_eq!(
        next_in(&c, &cli(&["opv", "generate", "prod", "web/TOKEN"])),
        "opv config edit"
    );
}

/// F2 (R64): a field that already holds a value steps to the reviewed rotation plan.
#[test]
fn f2_a_field_with_a_value_steps_to_the_rotation_plan() {
    let c = generate_refused(GenerateRefusal::HasValue);
    assert_eq!(
        next_in(&c, &cli(&["opv", "generate", "prod", "web/TOKEN"])),
        "opv plan prod --rotate web/TOKEN"
    );
}

/// F2 (R46): a provider that hides values steps to adopt's help for the environment.
#[test]
fn f2_a_provider_that_hides_values_steps_to_adopt_help() {
    let c = Cause::Guard {
        guard: Guard::ProviderHidesValues {
            system: System::Fly,
        },
    };
    assert_eq!(
        next_in(
            &c,
            &cli(&["opv", "adopt", "staging", "--from", "target:portfolio"])
        ),
        "opv adopt staging --help"
    );
}

/// F2: the command that wrote keeps a path with a space as one word.
#[test]
fn f2_a_read_back_by_a_path_with_a_space_keeps_it_one_word() {
    let c = Cause::ReadBackMissing {
        vault: VaultId::new("vlt-atqr"),
        item: ItemId::new("itm-1"),
        fields: vec![FieldName::new("web/KEY")],
        by: Cmd {
            command: vec!["adopt".into()],
            args: vec!["dev".into(), "--from".into(), "my values.env".into()],
        },
    };
    let want = if cfg!(windows) {
        "opv adopt dev --from \"my values.env\""
    } else {
        "opv adopt dev --from 'my values.env'"
    };
    assert_eq!(next_in(&c, &inv()), want);
}

/// F2: the operating system's random source is named as such.
#[test]
fn f2_a_random_source_failure_is_named() {
    let c = Cause::LocalIo {
        op: LocalOp::RandomSource,
        path: PathBuf::new(),
        io: IoKind::Other,
    };
    assert!(c.message().contains("random source"));
}

/// F3: a plan id may never have been approved, so a change never says it was.
#[test]
fn f3_a_changed_plan_does_not_claim_an_approval() {
    let c = Cause::PlanChanged {
        old: PlanId::new("aaaa1111"),
        new: PlanId::new("bbbb2222"),
        scope: PlanScope::Structural,
    };
    assert!(!c.message().contains("approved"));
}

/// F3: next to what was already written, a change before the rest never says "wrote nothing".
#[test]
fn f3_a_partial_change_before_write_does_not_say_nothing_was_written() {
    let c = partial(
        Cause::ChangedBeforeWrite {
            object: StoreObject::File {
                path: PathBuf::from("cfg/secrets.toml"),
            },
        },
        &["vault prod-web"],
    );
    assert!(!c.message().contains("wrote nothing"));
}

/// F3: an unknown plan id names the kind of plan it was given as.
#[test]
fn f3_an_unknown_plan_names_its_kind() {
    let c = Cause::PlanUnknown {
        plan: "zz".into(),
        scope: Some(PlanScope::Structural),
    };
    assert!(c.message().contains("structure plan"));
}

/// F4: an input file that cannot be read has its own code.
#[test]
fn f4_an_unreadable_input_file_is_input_unreadable() {
    let c = Cause::InputUnreadable {
        path: PathBuf::from("/work/in.env"),
        kind: InputKind::Dotenv,
        io: IoKind::NotFound,
    };
    assert_eq!(c.code(), "input_unreadable");
}

/// F4: an item of the wrong category is an item problem, not an input problem.
#[test]
fn f4_an_item_of_the_wrong_category_is_item_unusable() {
    let c = Cause::ItemUnusable {
        vault: None,
        title: "app".into(),
        problem: ItemProblem::WrongCategory,
    };
    assert_eq!(c.code(), "item_unusable");
}

/// F4: setup's near product name is the person's own command to run.
#[test]
fn f4_setups_near_product_is_a_handoff() {
    let c = Cause::NotDeclared {
        kind: NameKind::Product,
        given: "apu".into(),
        candidates: vec!["api".into(), "web".into()],
        closest: Some(Closest::unique(&["api"]).expect("one")),
    };
    let inv = cli(&["opv", "setup", "--product", "apu"]);
    assert_eq!(
        next_kind_actor(&c.step_in(&inv, &person_at_terminal()).1).0,
        crate::json::NextKind::Apply
    );
}

/// F4: an unknown `--product` is `unknown_product`.
#[test]
fn f4_an_unknown_product_is_unknown_product() {
    let c = Cause::NotDeclared {
        kind: NameKind::Product,
        given: "apu".into(),
        candidates: vec!["api".into()],
        closest: None,
    };
    assert_eq!(c.code(), "unknown_product");
}

/// F4: what remains after a partial setup is read by doctor, not a structure plan.
#[test]
fn f4_a_partial_setup_steps_to_doctor() {
    let c = partial(
        Cause::Interrupted {
            signal: 2,
            writes_started: true,
        },
        &["item app"],
    );
    assert_eq!(next_in(&c, &cli(&["opv", "setup"])), "opv doctor");
}

/// F4: a file that exists is replaced only by the person's own `--force`.
#[test]
fn f4_a_file_that_exists_hands_off_with_force() {
    let c = Cause::Usage {
        problem: UsageProblem::FileExists {
            path: PathBuf::from("secrets.toml"),
        },
    };
    assert_eq!(
        next_in(&c, &cli(&["opv", "init", "dev"])),
        "opv init dev --force"
    );
}

/// A22: a secret-bearing object whose secret was never stored is revoked by a person.
#[test]
fn a22_a_secret_never_stored_is_revoked_by_a_person() {
    assert!(secret_not_stored(None).human_required_in(&inv(), &person_at_terminal()));
}

/// A22: its Next is the provider's own listing that finds it, never a second mint (X5).
#[test]
fn a22_a_secret_never_stored_steps_to_the_vendor_refind() {
    let refind = VendorCmd {
        program: "flyctl".into(),
        args: vec![
            "tokens".into(),
            "list".into(),
            "--app".into(),
            "app-web".into(),
        ],
    };
    assert_eq!(
        next_in(&secret_not_stored(Some(refind)), &inv()),
        "flyctl tokens list --app app-web"
    );
}

/// A22: a generated configuration whose generator is unknown says so without a made-up path.
#[test]
fn a22_a_generated_config_without_a_known_generator_names_none() {
    let c = Cause::ConfigNotEditable {
        source: file_source(),
        reason: NotEditable::Generated { generator: None },
    };
    assert!(c.message().ends_with("it is generated"));
}

/// A22: a partial `target credentials --create` steps to its show form.
#[test]
fn a22_a_partial_credentials_create_steps_to_its_show() {
    let c = partial(
        Cause::Interrupted {
            signal: 2,
            writes_started: true,
        },
        &["deploy token tok-web"],
    );
    assert_eq!(
        next_in(
            &c,
            &cli(&[
                "opv",
                "target",
                "credentials",
                "prod",
                "--target",
                "web",
                "--create"
            ])
        ),
        "opv target credentials prod --target web"
    );
}

/// C8: a partial `mcp install` steps to the inner failure's own Next, never a structure plan.
#[test]
fn a_partial_mcp_install_steps_to_the_inner_next() {
    let c = partial(
        Cause::Usage {
            problem: UsageProblem::ValueFormat {
                flag: "--name".into(),
                format: "letters, digits, '-' or '_'",
            },
        },
        &["claude"],
    );
    assert_eq!(
        next_in(&c, &cli(&["opv", "mcp", "install", "--client", "all"])),
        "opv mcp install --help"
    );
}

/// D3 (A14): a built step keeps the invocation's `--project` when it takes one.
#[test]
fn d3_a_built_step_keeps_the_project_flag() {
    let c = Cause::ConfigNotFound {
        searched_from: PathBuf::from("/work"),
        env: Some(EnvName::new("prod")),
        manifest: None,
    };
    assert_eq!(
        next_in(&c, &cli(&["opv", "access", "prod", "--project", "acme"])),
        "opv init prod --project acme"
    );
}

// --- I6 ---

fn op_vault_missing() -> Cause {
    Cause::NotFound {
        system: System::OnePassword,
        resource: res(ResourceKind::Vault, "vlt-gone"),
        named_by: NamedBy::Flag {
            flag: "--vault".into(),
        },
        state: NotFoundState::Missing,
        seen: person(),
    }
}

/// I6: a missing vault under `vault locate` never steps to `vault locate` again.
#[test]
fn i6_a_missing_vault_under_vault_locate_does_not_step_to_itself() {
    let inv = Invocation {
        origin: Origin::Cli,
        command: vec!["vault".into(), "locate".into()],
        args: vec!["vlt-gone".into()],
        has_child: false,
    };
    let (_, next) = op_vault_missing().step_in(&inv, &person_at_terminal());
    assert_ne!(next, Next::Run(cmd(&["vault", "locate"], &["vlt-gone"])));
}

/// I6: elsewhere, a missing vault still steps to `vault locate`.
#[test]
fn i6_a_missing_vault_elsewhere_steps_to_vault_locate() {
    let (_, next) = op_vault_missing().step_in(&inv(), &person_at_terminal());
    assert_eq!(next, Next::Run(cmd(&["vault", "locate"], &["vlt-gone"])));
}

/// I6: an unset field's Do says to set it, never to check a value nobody wrote.
#[test]
fn i6_an_unset_field_is_to_be_set() {
    let c = Cause::NotFound {
        system: System::OnePassword,
        resource: res(ResourceKind::PersonalVault, "Private, Employee, Personal"),
        named_by: NamedBy::UnsetField {
            path: DottedPath(vec![
                "environments".into(),
                "dev".into(),
                "personal_vault".into(),
            ]),
        },
        state: NotFoundState::Missing,
        seen: person(),
    };
    let d = c.do_text(&inv()).unwrap_or_default();
    assert!(d.starts_with("set environments.dev.personal_vault"), "{d}");
}

fn deploy_item_problem(problem: CredentialProblem) -> Cause {
    Cause::CredentialRejected {
        system: System::OnePassword,
        credential: CredentialRef::DeployCredentials {
            vault: VaultId::new("ops"),
            item: ItemId::new("fly-prod"),
            env: EnvName::new("prod"),
            target: TargetName::new("web"),
        },
        problem,
        seen: person(),
    }
}

/// I6: a field of the wrong type is named with the type it must be.
#[test]
fn i6_a_wrong_type_field_names_the_type_it_must_be() {
    let c = deploy_item_problem(CredentialProblem::WrongType {
        field: FieldName::new("FLY_API_TOKEN"),
        expected: FieldType::Concealed,
    });
    assert!(
        c.message().contains("is not a concealed (password) field"),
        "{}",
        c.message()
    );
}

/// I6: a duplicate field's Do keeps one.
#[test]
fn i6_a_duplicate_field_keeps_one() {
    let c = deploy_item_problem(CredentialProblem::DuplicateField {
        field: FieldName::new("FLY_API_TOKEN"),
    });
    let d = c.do_text(&inv()).unwrap_or_default();
    assert!(d.starts_with("keep one field FLY_API_TOKEN"), "{d}");
}

fn not_stored(kind: CreateKind, target: Option<&str>) -> Cause {
    Cause::SecretNotStored {
        system: System::OnePassword,
        kind,
        name: "sa-ci".into(),
        env: EnvName::new("prod"),
        target: target.map(TargetName::new),
        refind: None,
    }
}

/// I6: without a target, the Next names none (never an empty `--target`).
#[test]
fn i6_a_service_account_without_a_target_steps_to_access() {
    let (_, next) =
        not_stored(CreateKind::ServiceAccount, None).step_in(&inv(), &person_at_terminal());
    assert_eq!(next, Next::Check(cmd(&["access"], &["prod"])));
}

/// I6: a deploy token's Next is its target's credentials.
#[test]
fn i6_a_deploy_token_steps_to_its_target_credentials() {
    let (_, next) =
        not_stored(CreateKind::DeployToken, Some("web")).step_in(&inv(), &person_at_terminal());
    assert_eq!(
        next,
        Next::Check(cmd(
            &["target", "credentials"],
            &["prod", "--target", "web"]
        ))
    );
}

/// I6: a symlinked `.opv` is named as such, not as an input or output error.
#[test]
fn i6_a_symlinked_dot_opv_is_named() {
    let c = Cause::LocalIo {
        op: LocalOp::Write,
        path: PathBuf::from("/work/shop/.opv"),
        io: IoKind::NotAPlainFile,
    };
    assert!(c.message().contains("symbolic link"), "{}", c.message());
}

/// I6: several accounts and none chosen keeps the public code `account_required`.
#[test]
fn i6_account_required_keeps_its_code() {
    let c = Cause::AccountRequired { accounts: vec![] };
    assert_eq!(c.code(), "account_required");
}

/// I6: and its Do is the person's pick, never a guessed account.
#[test]
fn i6_account_required_is_a_persons_pick() {
    let (action, _) =
        Cause::AccountRequired { accounts: vec![] }.step_in(&inv(), &person_at_terminal());
    assert_eq!(action, Some(Action::PickBetween));
}

/// E (snapshot review): a refused right in a target's namespace names that namespace, and
/// the kube context it is in only as the context.
#[test]
fn a_missing_right_in_a_namespace_names_the_namespace_and_its_context() {
    let c = Cause::MissingRight {
        system: System::Kubernetes,
        resource: ResourceRef {
            kind: ResourceKind::Namespace,
            name: ResourceName::new("e2e-prod"),
            scope: Some("context e2e-cluster".into()),
        },
        right: Right::Verb {
            verb: "list".into(),
            resource: "secrets".into(),
        },
        grant: GrantModel::K8sRbac {
            verb: "list".into(),
            resource: "secrets".into(),
            namespace: Some("e2e-prod".into()),
        },
        env: None,
        target: None,
        seen: fly_seen(),
    };
    assert_eq!(
        c.message(),
        "you may not list secrets in namespace e2e-prod (context e2e-cluster, Kubernetes)"
    );
}

/// F (snapshot review): a failed rule names the rule and why the value fails it apart.
#[test]
fn an_empty_value_names_its_rule_and_that_it_is_empty() {
    let s = value_state(&ValueState::RuleFailed {
        rule: "nonempty",
        reason: Some("empty".into()),
    });
    assert_eq!(s, "does not meet its rule nonempty: it is empty");
}

/// F (snapshot review): one allowed choice is named alone, never "one of prod".
#[test]
fn one_allowed_choice_is_named_alone() {
    assert_eq!(one_of(&["prod".to_string()]), "prod");
}

#[test]
fn several_allowed_choices_are_one_of_them() {
    assert_eq!(
        one_of(&["dev".to_string(), "prod".to_string()]),
        "one of dev, prod"
    );
}

/// C (snapshot review): an unrecognised failure with no reply to show never points at one.
#[test]
fn an_unrecognised_failure_without_a_reply_says_the_tool_wrote_none() {
    let c = Cause::Unrecognized {
        system: System::OnePassword,
        established: vec![],
        env: None,
        target: None,
        seen: seen(Principal::Person { account: None }),
    };
    let doc = document(&c, None, &inv(), false);
    assert_eq!(
        doc["do"],
        "op wrote no reply (exit 1), so opv cannot tell why it failed; check op on its own"
    );
}

/// D (snapshot review): a disconnected remote hands back the run with every flag, its
/// confirmation included, as the person's own step (X1, X4).
#[test]
fn a_remote_disconnect_hands_back_the_run_with_its_confirmation() {
    let c = Cause::RemoteDisconnected {
        profile: ProfileName::new("prof-box"),
        host: "box.example".into(),
        during: RemotePhase::Running,
    };
    let inv = Invocation {
        command: vec!["run".into()],
        args: vec![
            "prod".into(),
            "--product".into(),
            "web".into(),
            "--remote".into(),
            "builder".into(),
            "--confirm".into(),
            "prod".into(),
        ],
        has_child: false,
        ..inv()
    };
    assert_eq!(
        next_in(&c, &inv),
        "opv run prod --product web --remote builder --confirm prod"
    );
}

/// D (snapshot review): a generated configuration is fixed in its generator, so no opv
/// command is Next (retry never), never `opv config edit` on the same file.
#[test]
fn a_generated_configuration_names_no_opv_command_as_next() {
    let c = Cause::ConfigNotEditable {
        source: file_source(),
        reason: NotEditable::Generated { generator: None },
    };
    let inv = Invocation {
        command: vec!["env".into()],
        args: vec!["add".into(), "staging".into()],
        ..inv()
    };
    assert_eq!(c.step(&inv).1, Next::None(NoNext::NothingToRun));
}

/// D (snapshot review): an invalid proposal (retry never) names no command, never the
/// command's help.
#[test]
fn an_invalid_proposal_names_no_command_as_next() {
    let c = Cause::ConfigProposalInvalid {
        source: file_source(),
        field: DottedPath(vec!["products".into(), "web".into()]),
        rule: FieldRule::Missing,
        from_proposal: false,
    };
    assert_eq!(c.step(&inv()).1, Next::None(NoNext::NothingToRun));
}

/// R2-4 (snapshot review): a boundary that `init --add-env` proposed, not one in the file,
/// is fixed by declaring the product's keys for the environment, never by removing it.
#[test]
fn an_unused_boundary_in_the_proposal_names_only_declaring_the_product_keys() {
    let c = Cause::ConfigProposalInvalid {
        source: file_source(),
        field: DottedPath(vec![
            "environments".into(),
            "staging".into(),
            "boundaries".into(),
            "web".into(),
        ]),
        rule: FieldRule::Check {
            check: ConfigCheck::BoundaryUnused {
                env: "staging".into(),
                products: vec!["web".into()],
            },
        },
        from_proposal: true,
    };
    assert_eq!(
        c.do_text(&inv()).as_deref(),
        Some("declare product web's keys for staging: add \"staging\" to their environments")
    );
}

/// D (snapshot review): an unreadable input names its kind once ("the .env file").
#[test]
fn an_unreadable_input_says_the_once() {
    let c = Cause::InputUnreadable {
        path: PathBuf::from("missing.env"),
        kind: InputKind::Dotenv,
        io: IoKind::NotFound,
    };
    assert!(!c.message().contains("the the"));
}

/// R2-3 (snapshot review): an unreadable input is fixed by hand, not by a command, so Next reruns.
#[test]
fn an_unreadable_input_reruns_the_command() {
    let c = Cause::InputUnreadable {
        path: PathBuf::from("missing.env"),
        kind: InputKind::Dotenv,
        io: IoKind::NotFound,
    };
    assert_eq!(c.step(&inv()).1, Next::Rerun);
}

/// L1: a built plan step keeps the global `--timeout` flag with its value.
#[test]
fn l1_a_built_step_keeps_the_timeout_flag_with_its_value() {
    let c = Cause::ConfigInvalid {
        source: file_source(),
        at: None,
        field: DottedPath(vec!["environments".into(), "prod".into(), "targets".into()]),
        rule: FieldRule::Pattern {
            id: PatternId::TargetName,
        },
    };
    let inv = cli(&["opv", "sync", "prod", "--timeout", "60"]);
    assert_eq!(next_in(&c, &inv), "opv plan prod --timeout 60");
}

/// L1: a built plan step keeps an inline `--timeout=60`.
#[test]
fn l1_a_built_step_keeps_an_inline_timeout_flag() {
    let c = Cause::ConfigInvalid {
        source: file_source(),
        at: None,
        field: DottedPath(vec!["environments".into(), "prod".into(), "targets".into()]),
        rule: FieldRule::Pattern {
            id: PatternId::TargetName,
        },
    };
    let inv = cli(&["opv", "sync", "prod", "--timeout=60"]);
    assert_eq!(next_in(&c, &inv), "opv plan prod --timeout=60");
}

/// L5: a malformed `.env` holds secret values only a person may open, so fixing it
/// is a person's step before the same command runs again.
#[test]
fn l5_invalid_dotenv_needs_a_person() {
    let c = Cause::InputInvalid {
        path: PathBuf::from("app/.env"),
        kind: InputKind::Dotenv,
        at: Some(Location { line: 7, col: 1 }),
        field: "BAD KEY".into(),
        rule: FieldRule::Pattern {
            id: PatternId::KeyName,
        },
    };
    assert!(c.human_required(&inv()));
}

/// L5: a setup recipe holds no secret value, so an agent may fix it too.
#[test]
fn l5_invalid_setup_recipe_needs_no_person() {
    let c = Cause::InputInvalid {
        path: PathBuf::from("opv.recipe"),
        kind: InputKind::SetupRecipe,
        at: Some(Location { line: 3, col: 1 }),
        field: "steps".into(),
        rule: FieldRule::Syntax,
    };
    assert!(!c.human_required(&inv()));
}

// ---- L10: an overview fills the environment a cause never knew -----------------------

fn unrecognized_without_env() -> Cause {
    Cause::Unrecognized {
        system: System::Fly,
        established: Vec::new(),
        env: None,
        target: None,
        seen: person(),
    }
}

/// L10: a cause that never knew its environment takes the one the overview knows.
#[test]
fn l10_in_env_fills_an_unset_environment() {
    let c = unrecognized_without_env().in_env("prod");
    let env = match c {
        Cause::Unrecognized { env, .. } => env,
        other => panic!("not Unrecognized: {other:?}"),
    };
    assert_eq!(env, Some(EnvName::new("prod")));
}

/// L10: an environment the cause already carries is never replaced.
#[test]
fn l10_in_env_keeps_an_environment_already_set() {
    let c = Cause::Unrecognized {
        system: System::Fly,
        established: Vec::new(),
        env: Some(EnvName::new("staging")),
        target: None,
        seen: person(),
    }
    .in_env("prod");
    let env = match c {
        Cause::Unrecognized { env, .. } => env,
        other => panic!("not Unrecognized: {other:?}"),
    };
    assert_eq!(env, Some(EnvName::new("staging")));
}

/// L10: the environment reaches a cause wrapped in `Partial`'s `then`.
#[test]
fn l10_in_env_reaches_a_partial_then() {
    let c = Cause::Partial {
        done: Vec::new(),
        approval_used: None,
        approval_scope: None,
        then: Box::new(unrecognized_without_env()),
    }
    .in_env("prod");
    let env = match c {
        Cause::Partial { then, .. } => match *then {
            Cause::Unrecognized { env, .. } => env,
            other => panic!("not Unrecognized: {other:?}"),
        },
        other => panic!("not Partial: {other:?}"),
    };
    assert_eq!(env, Some(EnvName::new("prod")));
}

/// R2-2 (snapshot review): a local child that did not start re-runs as `-- <command>`, so
/// the Do says which command goes there.
#[test]
fn a_child_that_did_not_start_names_the_command_to_give() {
    let c = Cause::ChildStartFailed {
        program: "/nonexistent/cmd".into(),
        workdir: None,
        io: IoKind::NotFound,
        remote: None,
    };
    let run = Invocation {
        command: vec!["run".into()],
        args: vec!["dev".into(), "--product".into(), "web".into()],
        has_child: true,
        ..inv()
    };
    assert_eq!(
        c.do_text(&run).as_deref(),
        Some(
            "check that /nonexistent/cmd is on PATH; <command> is /nonexistent/cmd and its arguments"
        )
    );
}

/// R2-7: a file delivery that has no runtime folder names the folder to configure.
#[test]
fn a_file_delivery_without_a_runtime_folder_names_xdg_runtime_dir() {
    let c = Cause::RamDirUnavailable {
        remote: None,
        why: RamDir::Unset,
        purpose: RamPurpose::FileDelivery,
        env: None,
        product: None,
    };
    assert!(
        c.do_text(&inv())
            .unwrap_or_default()
            .contains("XDG_RUNTIME_DIR")
    );
}

/// R2-8: a value missing after adopt points at the item, not the item's history.
#[test]
fn a_value_missing_after_adopt_checks_the_item() {
    let c = Cause::ReadBackMissing {
        vault: VaultId::new("vlt-atqr"),
        item: ItemId::new("itm-1"),
        fields: vec![FieldName::new("web/KEY")],
        by: Cmd {
            command: vec!["adopt".into()],
            args: vec!["dev".into()],
        },
    };
    assert!(
        c.do_text(&inv())
            .unwrap_or_default()
            .starts_with("check item ")
    );
}

/// R2-8: a value missing after tidy is restored from the item's history.
#[test]
fn a_value_missing_after_tidy_is_restored_from_history() {
    let c = Cause::ReadBackMissing {
        vault: VaultId::new("vlt-atqr"),
        item: ItemId::new("itm-1"),
        fields: vec![FieldName::new("web/KEY")],
        by: Cmd {
            command: vec!["tidy".into()],
            args: vec!["dev".into()],
        },
    };
    assert!(
        c.do_text(&inv())
            .unwrap_or_default()
            .starts_with("restore ")
    );
}
