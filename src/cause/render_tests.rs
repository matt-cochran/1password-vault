//! Rendering every cause (design §4, §6, §7). One assertion each.

use std::path::PathBuf;

use super::super::evidence::{BOX_LINES, upstream_box};
use super::*;
use crate::host::{Platform, Shell};

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
            },
            vec!["/work/shop", "env-stage"],
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
                by: CommandId("tidy".into()),
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
                reason: "InvalidProviderConfig".into(),
            },
            vec!["store-op", "InvalidProviderConfig"],
        ),
        (
            HandoffPipeContested {
                system: System::Azure,
            },
            vec!["Azure"],
        ),
        (Bug { site: "site-xyz" }, vec!["site-xyz"]),
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
        BoundaryMissing { .. } => 4,
        StateVaultMissing { .. } => 5,
        StateVaultTooWide { .. } => 6,
        ConfigNotEditable { .. } => 7,
        CopiesDiffer { .. } => 8,
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
        Bug { .. } => 60,
        KeyNotDeclared { .. } => 61,
        KeysBlocking { .. } => 62,
        LocalIo { .. } => 63,
        StoreNotReady { .. } => 64,
        HandoffPipeContested { .. } => 65,
    }
}

const VARIANTS: usize = 66;

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
        untrusted: true,
    }
}

fn in_other_account() -> Cause {
    Cause::InOtherAccount {
        vault: VaultId::new("atqr2ek"),
        item: None,
        selected: AccountId::new("6AINMAIK"),
        owning: None,
        env: Some(EnvName::new("staging")),
        seen: person(),
    }
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
    assert_eq!(b.lines().filter(|l| l.starts_with("│ ")).count(), BOX_LINES);
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
        serde_json::json!({"vault": "atqr2ek", "item": null, "selected": "6AINMAIK", "owning": null, "env": "staging"})
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
        (
            d["next_kind"].clone(),
            d["next"].clone(),
            d["human_required"].clone()
        ),
        (
            serde_json::json!("handoff"),
            serde_json::json!("opv approve sp-9f3"),
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
            why: "it is issued by a vendor",
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
    assert_eq!(cmd_text(&c), "opv open api/KEY --env 'my env'");
}

#[test]
fn a_vault_in_another_account_needs_no_person() {
    assert!(!in_other_account().human_required(&inv()));
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
        reason: "token=abc is wrong".into(),
    };
    assert!(!c.message().contains("abc"), "{}", c.message());
}

/// A7: a deployment that changed before the write is a target object.
#[test]
fn a7_a_deployment_changed_before_the_write_is_a_target_change() {
    let c = Cause::ChangedBeforeWrite {
        object: StoreObject::Resource {
            resource: res(ResourceKind::Deployment, "web"),
        },
    };
    assert_eq!((c.code(), c.exit_code()), ("target_changed", 5));
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
