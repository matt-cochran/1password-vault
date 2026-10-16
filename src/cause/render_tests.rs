//! Rendering every cause (design §4, §6, §7). One assertion each.

use std::path::PathBuf;

use super::super::evidence::{BOX_LINES, upstream_box};
use super::*;

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
            },
            vec!["env-prod", "tgt-web", "vlt-state", "tgt-worker"],
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
                state: NotFoundState::Missing,
                seen: person(),
            },
            vec!["Fly", "app-shop", "scope-east"],
        ),
        (
            TargetRefused {
                system: System::Azure,
                subject: res(ResourceKind::ContainerApp, "ca-shop"),
                why: Refusal::Unhealthy {
                    new_revision: "rev-new".into(),
                    serving: Some("rev-old".into()),
                },
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
                tool: "flyctl".into(),
            },
            vec!["flyctl"],
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
                seen: person(),
            },
            vec!["op", "1Password", "line 4"],
        ),
        (
            Unrecognized {
                system: System::OnePassword,
                established: vec!["signed in".into()],
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
                rule: FieldRule::Pattern { id: "key_name" },
            },
            vec!["app/.env", "line 7", "BAD KEY", "key name"],
        ),
        (
            ApprovalMissing {
                plan: PlanId::new("sp-9f3"),
            },
            vec!["sp-9f3"],
        ),
        (
            ApprovalUsed {
                plan: PlanId::new("sp-9f3"),
                partial: true,
            },
            vec!["sp-9f3"],
        ),
        (
            PlanChanged {
                old: PlanId::new("sp-old"),
                new: PlanId::new("sp-new"),
            },
            vec!["sp-old", "sp-new"],
        ),
        (
            PlanUnknown {
                plan: "sp-what".into(),
            },
            vec!["sp-what"],
        ),
        (
            RamDirUnavailable {
                remote: Some(ProfileName::new("prof-box")),
                why: RamDir::NotTmpfs,
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
    }
}

const VARIANTS: usize = 61;

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
            let text = render_text(c, None, &inv(), false, true);
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
    let text = render_text(&in_other_account(), None, &inv(), false, true);
    let first = text.lines().next().unwrap_or_default();
    assert_eq!(
        first,
        "opv: vault atqr2ek (environment staging) is not in 1Password account 6AINMAIK"
    );
}

#[test]
fn a_vault_in_another_account_shows_the_checked_account_id() {
    let text = render_text(&in_other_account(), None, &inv(), false, true);
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

#[test]
fn a_unique_closest_name_is_substituted_keeping_every_flag() {
    let c = Cause::NotDeclared {
        kind: NameKind::Environment,
        given: "prdo".into(),
        candidates: vec!["prod".into()],
        closest: Closest::unique(&["prod"]),
    };
    let i = Invocation {
        args: vec!["prdo".into(), "--target".into(), "web".into()],
        ..inv()
    };
    assert_eq!(
        next_text(&c.step(&i).1, &i).as_deref(),
        Some("opv sync prod --target web")
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
