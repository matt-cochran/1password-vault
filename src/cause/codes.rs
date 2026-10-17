//! The public error codes, generated from the catalog (design §4.11, §10 step 5): one
//! example of every cause and of every variant of a cause that has a code of its own, and
//! the table `opv schema` and `docs/usage.md` print from them. No code is written by hand
//! here: [`table`] reads each example's [`Cause::code`], exit code, retry class and
//! `human_required`; only the one-line meaning of a code is prose ([`meaning`]).

use std::path::PathBuf;

use super::situation::{OpFlavour, Situation};
use super::*;
use crate::host::{Platform, Shell};

/// One public code: every exit code, retry class and `human_required` its causes have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRow {
    pub code: &'static str,
    pub exits: Vec<i32>,
    pub retry: Vec<RetryClass>,
    pub human_required: Vec<bool>,
    pub meaning: &'static str,
}

/// Every public code, in exit-code order (then by name).
pub fn table() -> Vec<CodeRow> {
    let inv = Invocation::from_cli(&["opv".to_string(), "status".into(), "prod".into()]);
    let sit = Situation {
        ci: false,
        terminal: true,
        identity: Principal::Person { account: None },
        config_source: ConfigSource::File {
            path: PathBuf::from("secrets.toml"),
            given_by: GivenBy::Discovered,
        },
        platform: Platform::Linux,
        op: OpFlavour::Native,
        remote: false,
        deploy_credentials_or_shell_token: false,
    };
    let mut rows: Vec<CodeRow> = Vec::new();
    for c in examples() {
        let code = c.code();
        let row = match rows.iter_mut().find(|r| r.code == code) {
            Some(r) => r,
            None => {
                rows.push(CodeRow {
                    code,
                    exits: Vec::new(),
                    retry: Vec::new(),
                    human_required: Vec::new(),
                    meaning: meaning(code),
                });
                rows.last_mut().expect("just pushed")
            }
        };
        let exit = c.exit_code();
        if !row.exits.contains(&exit) {
            row.exits.push(exit);
        }
        let retry = c.retry();
        if !row.retry.contains(&retry) {
            row.retry.push(retry);
        }
        let human = c.human_required_in(&inv, &sit);
        if !row.human_required.contains(&human) {
            row.human_required.push(human);
        }
    }
    for r in &mut rows {
        r.exits.sort_unstable();
        r.human_required.sort_unstable();
    }
    rows.sort_by(|a, b| (a.exits[0], a.code).cmp(&(b.exits[0], b.code)));
    rows
}

/// What a code means, in one line. Every code [`examples`] produces has one (a test).
pub fn meaning(code: &str) -> &'static str {
    match code {
        "config_not_found" => {
            "no secrets.toml in this folder or a parent, and no 1Password manifest for this checkout"
        }
        "config_source_mismatch" => {
            "the command works on a secrets.toml, but this project's configuration is a 1Password manifest"
        }
        "config_unreadable" => "the configuration file could not be read",
        "config_invalid" => {
            "secrets.toml, the manifest or a change opv proposed breaks a field rule"
        }
        "boundary_missing" => {
            "a product has a key desired in an environment whose boundary (vault and item) is not recorded"
        }
        "state_vault_missing" => "a target has no state vault recorded for its delivery evidence",
        "state_vault_wider_than_values" => {
            "a state vault shared by targets could be readable more widely than the values its evidence describes; a person gives one target its own"
        }
        "config_not_editable" => {
            "the configuration cannot be edited in place (generated, or a layout opv does not write)"
        }
        "copies_differ" => {
            "a committed secrets.toml and the manifest differ; a person picks which is right"
        }
        "manifest_not_found" => {
            "no 1Password manifest has the project's title (OPV_PROJECT or .opv)"
        }
        "manifest_ambiguous" => {
            "several 1Password manifests match; a person keeps one and archives the others"
        }
        "manifest_exists" => {
            "a manifest for this project already exists; change it with opv config edit"
        }
        "inventory_incomplete" => {
            "one or more 1Password accounts could not be listed, so the project inventory is incomplete; a project missing from it is not evidence that it does not exist"
        }
        "unknown_env" => "the environment is not declared",
        "unknown_target" => "the target is not declared for the environment",
        "unknown_product" => "the product is not declared",
        "undeclared_key" => "the key is not declared (for this environment)",
        "unknown_role" => "no key declares the process role",
        "unknown_profile" => "the remote profile is not declared",
        "usage" => "the command line is not valid (unknown flag, missing argument, a removed form)",
        "ambiguous_name" => "the name matches more than one declared name",
        "choice_required" => "the command needs a flag to choose between several candidates",
        "no_target" => "the environment has no deployment target (run-only)",
        "nothing_in_scope" => "nothing in the environment matches the scope the command was given",
        "already_declared" => "the name is already declared",
        "op_not_signed_in" => "not signed in to 1Password",
        "target_not_signed_in" => "not signed in to the target CLI",
        "account_not_registered" => {
            "the 1Password account is not added to this 1Password CLI; a person adds it (opv login --add, or in the app)"
        }
        "account_ambiguous" => {
            "an email or sign-in address names several 1Password accounts; a person picks one by its account ID"
        }
        "account_required" => {
            "several 1Password accounts are on this machine and none is chosen for this project; a person picks one with opv login --account"
        }
        "ids_not_in_account" => {
            "an environment's recorded vault is not in the selected 1Password account; a person selects the owning account or rebinds the environment"
        }
        "own_session_required" => {
            "the command writes 1Password, which only a person signed in with their own session may do (not a service account, Connect or deploy credentials)"
        }
        "deploy_credentials_failed" => {
            "the environment's deploy credentials in 1Password were rejected or are incomplete; nothing was changed"
        }
        "credential_rejected" => "a credential (a token, a sign-in) was not accepted",
        "vault_no_access" => "the signed-in identity cannot open the 1Password vault",
        "permission_denied" => {
            "signed in to the target, but this identity lacks a role or right there (or a network rule keeps it out); a person with access grants it"
        }
        "owner_setup_required" => {
            "the target lacks something only its owner sets up (a GitHub environment, a ready external store, a single-revision app)"
        }
        "item_not_found" => {
            "the 1Password item is not in the vault (moved, archived, deleted, or a wrong item_id)"
        }
        "resource_not_found" => "the vault, app, namespace or other resource named is not there",
        "target_unhealthy" => {
            "the new revision did not become healthy; the previous one keeps serving"
        }
        "update_refused" => {
            "the target refused the update and applied nothing; re-running repeats the refusal"
        }
        "declined" => "the person declined at opv's prompt; nothing was changed",
        "policy_refused" => {
            "opv refused the operation (a value too large, a name opv does not manage, a credential given as an option, ...)"
        }
        "create_outcome_unknown" => {
            "a create may or may not have happened; find it before creating again"
        }
        "outcome_unknown" => "a change may or may not have been applied; re-running is safe",
        "provider_unavailable" => {
            "a provider did not answer after its retries; nothing was changed"
        }
        "budget_spent" => "the run's --timeout budget was spent",
        "interrupted" => {
            "interrupted by SIGINT (130), SIGHUP (129), SIGQUIT (131) or SIGTERM (143)"
        }
        "config_changed" => {
            "the configuration changed while opv was editing it; nothing was written and re-running is safe"
        }
        "item_changed" => {
            "the 1Password item changed while opv was writing it; nothing was written and re-running is safe"
        }
        "target_changed" => {
            "the target's object changed while opv was writing it; nothing was written and re-running is safe"
        }
        "concurrent_edit" => {
            "another edit landed together with opv's; check the history before acting again"
        }
        "tidy_unverified" => {
            "opv wrote the 1Password item but the item read back lacks a field opv wrote or kept; a person restores it from the item's history"
        }
        "dependency_missing" => "op or the target CLI is not installed or not on PATH",
        "tool_unusable" => {
            "op or the target CLI is installed but cannot be used (an unreadable version, a Windows op.exe from WSL, ...)"
        }
        "unexpected_output" => "a tool answered with output opv cannot use",
        "unrecognized_failure" => {
            "a tool failed for a reason opv does not recognise; what opv did establish is named"
        }
        "terminal_required" => "the command needs the person's own interactive terminal",
        "confirm_required" => "the environment sets confirm_env; a person passes --confirm <env>",
        "confirm_mismatch" => "--confirm names another environment",
        "findings" => {
            "keys are missing or failing a rule (values are filled in 1Password by a person)"
        }
        "keys_blocking" => {
            "a write refused: keys are missing or failing a rule; nothing was written"
        }
        "file_too_open" => "a local file opv reads is readable by others",
        "input_invalid" => "an input file (a dotenv file, a setup recipe, a receipt) breaks a rule",
        "approval_required" => {
            "the plan has no unused, unexpired approval; a person runs opv approve <plan_id> in their own terminal"
        }
        "approval_used" => "the approval was already used; read what remains, never re-run with it",
        "stale_plan" => {
            "the plan changed since it was reviewed (the item, the target or the configuration); nothing was changed"
        }
        "plan_unknown" => "no plan has this id",
        "ram_dir_unavailable" => {
            "a private RAM-backed folder is needed (Azure deploy credentials, a file opv run delivers) and none is usable; nothing was read or changed"
        }
        "private_dir_failed" => "opv could not make its private folder",
        "remote_unreachable" => {
            "the remote profile's host could not be reached over SSH (with its pinned host key)"
        }
        "remote_disconnected" => {
            "the SSH connection to the remote host ended or stalled after the payload was sent"
        }
        "remote_version_mismatch" => "opv on the remote host speaks another protocol version",
        "child_start_failed" => "the command opv run starts could not be started",
        "delivery_unverified" => {
            "a placement no longer holds what opv delivered, or could not be checked"
        }
        "source_changed" => {
            "a source item changed since the last sync, or no source versions are recorded; the next step is the sync"
        }
        "local_io_failed" => {
            "opv's own local input or output failed (a file, the current folder, standard output, ...)"
        }
        "handoff_refused" => {
            "another process connected to opv's private hand-off pipe; opv refused it and sent nothing"
        }
        "input_unreadable" => {
            "an input file (a dotenv file, a setup recipe, a receipt) could not be read"
        }
        "item_unusable" => "a 1Password item opv was pointed at has a layout opv cannot use",
        "secret_not_stored" => {
            "a secret-bearing object was made at the provider, but its secret was never stored; it is revoked, never made again"
        }
        "source_only" => {
            "the product is source-only: it holds shared values for other products' keys and is never run, checked or planned on its own"
        }
        "title_not_found" => "no 1Password vault or item has exactly this title",
        "title_ambiguous" => "more than one 1Password vault or item has exactly this title",
        "internal_error" => "opv hit an internal error; report it",
        _ => "",
    }
}

/// One example of every cause, then the variants of a cause whose code, exit code or
/// retry class differs from its example's.
pub fn examples() -> Vec<Cause> {
    let base = one_of_each();
    let mut out = base.clone();
    for c in &base {
        out.extend(variants(c));
    }
    out
}

/// `c` changed by `f`.
fn varied(c: &Cause, f: impl FnOnce(&mut Cause)) -> Cause {
    let mut v = c.clone();
    f(&mut v);
    v
}

fn variants(c: &Cause) -> Vec<Cause> {
    use Cause::*;
    match c {
        NotDeclared { .. } => [
            NameKind::Target,
            NameKind::Product,
            NameKind::Key,
            NameKind::Role,
            NameKind::RemoteProfile,
            NameKind::Mode,
            NameKind::HelpTopic,
        ]
        .into_iter()
        .map(|k| {
            varied(c, |v| {
                if let NotDeclared { kind, .. } = v {
                    *kind = k;
                }
            })
        })
        .collect(),
        NothingInScope { .. } => vec![varied(c, |v| {
            if let NothingInScope { what, .. } = v {
                *what = Scope::NoTargets {
                    products: vec![ProductName::new("api")],
                };
            }
        })],
        NotSignedIn { .. } => vec![varied(c, |v| {
            if let NotSignedIn { system, .. } = v {
                *system = System::Fly;
            }
        })],
        CredentialRejected { .. } => vec![varied(c, |v| {
            if let CredentialRejected { credential, .. } = v {
                *credential = CredentialRef::ShellToken {
                    var: VarName::new("FLY_API_TOKEN"),
                };
            }
        })],
        MissingRight { .. } => vec![varied(c, |v| {
            if let MissingRight { system, .. } = v {
                *system = System::OnePassword;
            }
        })],
        NotFound { .. } => [ResourceKind::Item, ResourceKind::Vault]
            .into_iter()
            .map(|k| {
                varied(c, |v| {
                    if let NotFound {
                        system, resource, ..
                    } = v
                    {
                        *system = System::OnePassword;
                        resource.kind = k;
                    }
                })
            })
            .collect(),
        UnexpectedOutput { .. } | Unrecognized { .. } => vec![varied(c, |v| {
            if let UnexpectedOutput { system, .. } | Unrecognized { system, .. } = v {
                *system = System::Fly;
            }
        })],
        TargetRefused { .. } => [
            Refusal::Validation,
            Refusal::RevisionMode {
                mode: "multiple".into(),
                resource_group: "rg-shop".into(),
                subscription: "sub-shop".into(),
            },
        ]
        .into_iter()
        .map(|r| {
            varied(c, |v| {
                if let TargetRefused { why, .. } = v {
                    *why = r;
                }
            })
        })
        .collect(),
        Guard { .. } => vec![Guard {
            guard: super::Guard::Declined,
        }],
        // L5: a dotenv file is a person's to fix; a setup recipe is not.
        InputInvalid { .. } => vec![varied(c, |v| {
            if let InputInvalid { kind, .. } = v {
                *kind = InputKind::SetupRecipe;
            }
        })],
        CreateOutcomeUnknown { .. } => vec![varied(c, |v| {
            if let CreateOutcomeUnknown { refind, .. } = v {
                *refind = Refind::ByTitle;
            }
        })],
        Interrupted { .. } => [1, 3, 15]
            .into_iter()
            .map(|s| {
                varied(c, |v| {
                    if let Interrupted { signal, .. } = v {
                        *signal = s;
                    }
                })
            })
            .collect(),
        ChangedBeforeWrite { .. } => [
            StoreObject::Manifest {
                title: "opv · shop".into(),
                vault: VaultId::new("vlt-shop"),
            },
            StoreObject::Item {
                vault: VaultId::new("vlt-shop"),
                item: ItemId::new("itm-shop"),
            },
            StoreObject::Resource {
                resource: res(ResourceKind::Deployment, "dep-shop"),
                changed: vec!["/spec/replicas".into()],
            },
        ]
        .into_iter()
        .map(|o| {
            varied(c, |v| {
                if let ChangedBeforeWrite { object } = v {
                    *object = o;
                }
            })
        })
        .collect(),
        TitleLookup { .. } => vec![varied(c, |v| {
            if let TitleLookup { matches, .. } = v {
                *matches = 2;
            }
        })],
        _ => Vec::new(),
    }
}

/// One example of every cause (the renderer's own fixtures, design §11).
fn one_of_each() -> Vec<Cause> {
    use Cause::*;
    vec![
        ConfigNotFound {
            searched_from: PathBuf::from("/work/shop"),
            env: Some(EnvName::new("env-stage")),
            manifest: Some(ManifestSearch {
                repo: Some("repo-xyz".into()),
                account: Some(AccountId::new("ACC-XYZ")),
            }),
        },
        ConfigSourceMismatch {
            command: CommandId("bootstrap".into()),
            manifest: "man-shop".into(),
        },
        ConfigUnreadable {
            path: PathBuf::from("cfg/other.toml"),
            io: IoKind::PermissionDenied,
            given_by: GivenBy::Flag {
                flag: "--config".into(),
            },
        },
        ConfigInvalid {
            source: file_source(),
            at: Some(Location { line: 12, col: 3 }),
            field: DottedPath(vec!["environments".into(), "prod".into(), "confrm".into()]),
            rule: FieldRule::Unknown {
                suggestion: Some("confirm_env".into()),
            },
        },
        BoundaryMissing {
            env: EnvName::new("env-prod"),
            product: ProductName::new("prod-api"),
            source: file_source(),
        },
        StateVaultMissing {
            env: EnvName::new("env-prod"),
            target: TargetName::new("tgt-web"),
            source: file_source(),
        },
        StateVaultTooWide {
            env: EnvName::new("env-prod"),
            target: TargetName::new("tgt-web"),
            vault: VaultId::new("vlt-state"),
            shared_with: vec![TargetName::new("tgt-worker")],
            source: file_source(),
            at: Some(Location { line: 21, col: 1 }),
        },
        ConfigNotEditable {
            source: file_source(),
            reason: NotEditable::UnsupportedLayout {
                section: "sec-odd".into(),
            },
        },
        CopiesDiffer {
            file: PathBuf::from("cfg/copy.toml"),
            manifest: "man-shop".into(),
        },
        ManifestNotFound {
            project: "proj-shop".into(),
            account: Some(AccountId::new("ACC-6AIN")),
        },
        ManifestAmbiguous {
            candidates: vec!["man-one".into(), "man-two".into()],
            person_picks: true,
        },
        ManifestExists {
            title: "man-shop".into(),
            local_file: Some(PathBuf::from("cfg/secrets.toml")),
        },
        InventoryIncomplete {
            unlisted: vec![AccountId::new("ACC-ONE"), AccountId::new("ACC-TWO")],
        },
        NotDeclared {
            kind: NameKind::Environment,
            given: "prdo".into(),
            candidates: vec!["prod".into(), "stage".into()],
            closest: Closest::unique(&["prod"]),
        },
        Ambiguous {
            kind: NameKind::Key,
            given: "API_KEY".into(),
            candidates: vec!["api/API_KEY".into(), "web/API_KEY".into()],
        },
        ChoiceRequired {
            flag: "--product".into(),
            candidates: vec!["prod-api".into(), "prod-web".into()],
        },
        NothingInScope {
            env: EnvName::new("env-prod"),
            what: Scope::NoTargetDelivers {
                target: TargetName::new("tgt-web"),
            },
        },
        Usage {
            problem: UsageProblem::ConflictsWith {
                a: "--opt-a".into(),
                b: "--opt-b".into(),
            },
        },
        AlreadyDeclared {
            kind: NameKind::Target,
            name: "tgt-web".into(),
        },
        NotSignedIn {
            system: System::OnePassword,
            account: Some(AccountId::new("ACC-6AIN")),
            state: SessionState::Expired,
        },
        AccountNotOnMachine {
            account: AccountRef::Shorthand("acct-short".into()),
            selected_by: AccountSource::DotOpv {
                path: PathBuf::from("/work/shop/.opv"),
            },
            in_app: true,
        },
        AccountAmbiguous {
            given: "acct-given".into(),
            candidates: vec![AccountId::new("ACC-ONE"), AccountId::new("ACC-TWO")],
        },
        InOtherAccount {
            vault: VaultId::new("vlt-atqr"),
            item: Some(ItemId::new("itm-1")),
            selected: AccountId::new("ACC-6AIN"),
            owning: Some(AccountId::new("ACC-OWNS")),
            env: Some(EnvName::new("env-stage")),
            unasked: Vec::new(),
            searched: false,
            seen: person(),
        },
        NeedsOwnSession {
            command: CommandId("approve".into()),
            identity: Principal::ShellToken {
                var: VarName::new("OP_SERVICE_ACCOUNT_TOKEN"),
            },
        },
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
        OwnerSetupRequired {
            system: System::GitHub,
            object: res(ResourceKind::GitHubEnvironment, "gh-env-prod"),
        },
        NotFound {
            system: System::Fly,
            resource: res(ResourceKind::FlyApp, "app-shop"),
            named_by: fly_app_field(),
            state: NotFoundState::Missing,
            seen: person(),
        },
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
        Guard {
            guard: super::Guard::RemoteProfileRefuses {
                profile: ProfileName::new("prof-box"),
                asked: "mode-x".into(),
                allowed: vec!["mode-a".into(), "mode-b".into()],
            },
        },
        CreateOutcomeUnknown {
            system: System::OnePassword,
            kind: CreateKind::ServiceAccount,
            name: "sa-web-deploy".into(),
            refind: Refind::Check(check_cmd()),
            seen: person(),
        },
        WriteOutcomeUnknown {
            system: System::Kubernetes,
            subject: res(ResourceKind::Namespace, "ns-shop"),
            seen: person(),
        },
        Unavailable {
            system: System::GitHub,
            why: Unanswered::ServerError { status: 503 },
            attempts: 3,
            seen: person(),
        },
        BudgetSpent {
            budget_seconds: 77,
            writes_started: true,
        },
        Partial {
            done: vec!["vault shop-prod".into()],
            approval_used: Some(PlanId::new("sp-used")),
            approval_scope: Some(sync_scope()),
            then: Box::new(BudgetSpent {
                budget_seconds: 77,
                writes_started: true,
            }),
        },
        Interrupted {
            signal: 2,
            writes_started: false,
        },
        ChangedBeforeWrite {
            object: StoreObject::File {
                path: PathBuf::from("cfg/secrets.toml"),
            },
        },
        ConcurrentEdit {
            object: StoreObject::Item {
                vault: VaultId::new("vlt-atqr"),
                item: ItemId::new("itm-1"),
            },
        },
        ReadBackMissing {
            vault: VaultId::new("vlt-atqr"),
            item: ItemId::new("itm-1"),
            fields: vec![FieldName::new("fld-api")],
            by: Cmd {
                command: vec!["tidy".into()],
                args: vec!["prod".into()],
            },
        },
        ToolMissing {
            tool: "op".into(),
            platform: Platform::MacOs,
            shell: Shell::Posix,
            ci: false,
        },
        ToolUnusable {
            tool: "az".into(),
            why: Unusable::TooOld {
                have: "2.40.0".into(),
                min: "2.50.0".into(),
            },
        },
        UnexpectedOutput {
            system: System::OnePassword,
            at: Some(Location { line: 4, col: 9 }),
            problem: OutputProblem::Unparseable,
            during: During::Read,
            seen: person(),
        },
        Unrecognized {
            system: System::OnePassword,
            established: vec!["signed in".into()],
            env: Some(EnvName::new("env-prod")),
            target: None,
            seen: person(),
        },
        NeedsTerminal {
            why: NoTerminal::Ci,
        },
        NeedsConfirm {
            env: EnvName::new("env-prod"),
        },
        ConfirmMismatch {
            given: "prdo".into(),
            env: EnvName::new("env-prod"),
        },
        ValuesNeeded {
            env: EnvName::new("env-prod"),
            rows: vec![ValueRow {
                product: ProductName::new("prod-api"),
                key: KeyName::new("OPENAI_API_KEY"),
                target: Some(TargetName::new("tgt-web")),
                state: ValueState::Missing,
            }],
        },
        LocalFileTooOpen {
            path: PathBuf::from("/home/me/.opv-cred"),
            mode: 0o644,
            want: 0o600,
        },
        InputInvalid {
            path: PathBuf::from("app/.env"),
            kind: InputKind::Dotenv,
            at: Some(Location { line: 7, col: 1 }),
            field: "BAD KEY".into(),
            rule: FieldRule::Pattern {
                id: PatternId::KeyName,
            },
        },
        ApprovalMissing {
            plan: PlanId::new("sp-9f3"),
            scope: sync_scope(),
        },
        ApprovalUsed {
            plan: PlanId::new("sp-9f3"),
            scope: sync_scope(),
            partial: true,
        },
        PlanChanged {
            old: PlanId::new("sp-old"),
            new: PlanId::new("sp-new"),
            scope: sync_scope(),
        },
        PlanUnknown {
            plan: "sp-what".into(),
            scope: None,
        },
        RamDirUnavailable {
            remote: Some(ProfileName::new("prof-box")),
            why: RamDir::NotTmpfs,
            purpose: RamPurpose::FileDelivery,
            env: Some(EnvName::new("env-prod")),
            product: Some(ProductName::new("prod-api")),
        },
        PrivateDirFailed {
            dir: PathBuf::from("/run/user/1000"),
            io: IoKind::Other,
        },
        RemoteUnreachable {
            profile: ProfileName::new("prof-box"),
            user: "deployer".into(),
            host: "box.example".into(),
            port: 2222,
            known_hosts: pinned_hosts(),
            identity_file: None,
        },
        RemoteDisconnected {
            profile: ProfileName::new("prof-box"),
            host: "box.example".into(),
            during: RemotePhase::Running,
        },
        RemoteVersionMismatch {
            profile: ProfileName::new("prof-box"),
            remote_protocol: 41,
        },
        ChildStartFailed {
            program: "node-app".into(),
            workdir: Some(PathBuf::from("/srv/app")),
            io: IoKind::NotFound,
            remote: Some(ProfileName::new("prof-box")),
        },
        DeliveryUnverified {
            env: EnvName::new("env-prod"),
            target: TargetName::new("tgt-web"),
            product: ProductName::new("prod-api"),
            state: Unverified::OtherAccount {
                account: AccountId::new("ACC-OTHER"),
            },
        },
        SourceChanged {
            env: EnvName::new("env-prod"),
            no_record: false,
        },
        KeyNotDeclared {
            key: KeyName::new("KEY_X"),
            env: EnvName::new("env-prod"),
            product: Some(ProductName::new("prod-api")),
        },
        KeysBlocking {
            env: EnvName::new("env-prod"),
            rows: vec![ValueRow {
                product: ProductName::new("prod-api"),
                key: KeyName::new("KEY_X"),
                target: None,
                state: ValueState::Missing,
            }],
        },
        LocalIo {
            op: LocalOp::Write,
            path: PathBuf::from("/work/secrets.toml"),
            io: IoKind::PermissionDenied,
        },
        StoreNotReady {
            store: res(ResourceKind::ExternalStore, "store-op"),
            reason: Some("InvalidProviderConfig".into()),
        },
        HandoffPipeContested {
            system: System::Azure,
        },
        ConfigProposalInvalid {
            source: file_source(),
            field: DottedPath(vec!["products".into(), "prod-api".into()]),
            rule: FieldRule::Missing,
            from_proposal: false,
        },
        InputUnreadable {
            path: PathBuf::from("/work/in.env"),
            kind: InputKind::Dotenv,
            io: IoKind::PermissionDenied,
        },
        ItemUnusable {
            vault: Some(VaultId::new("vlt-atqr")),
            title: "title-xyz".into(),
            problem: ItemProblem::WrongCategory,
        },
        SecretNotStored {
            system: System::Fly,
            kind: CreateKind::DeployToken,
            name: "tok-web".into(),
            env: EnvName::new("prod"),
            target: Some(TargetName::new("web")),
            refind: None,
        },
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
        SourceOnly {
            product: ProductName::new("shared-xyz"),
            env: Some(EnvName::new("prod")),
            reader: Some(ProductName::new("reader-xyz")),
        },
        TitleLookup {
            kind: ResourceKind::Item,
            title: "title-xyz".into(),
            vault: Some(VaultId::new("vlt-atqr")),
            matches: 0,
            candidates: vec!["cand-xyz (id-xyz)".into()],
        },
        PersonalNotSetUp {
            env: EnvName::new("env-dev"),
            keys: vec![ProductKey {
                product: ProductName::new("prod-api"),
                key: KeyName::new("MY_TOKEN"),
            }],
            then: Box::new(TitleLookup {
                kind: ResourceKind::Item,
                title: "title-xyz".into(),
                vault: None,
                matches: 0,
                candidates: Vec::new(),
            }),
        },
        Bug { site: "site-xyz" },
    ]
}

/// The observation the examples carry (only the runner builds one; it never reaches a
/// rendered error, since the examples are only classified).
fn seen(principal: Principal) -> Observed {
    crate::runner::catalog_example_observed(principal)
}

fn person() -> Observed {
    seen(Principal::Person {
        account: Some(AccountId::new("ACC-6AIN")),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every string `Cause::code` can return, read from its source.
    fn codes_in_source() -> Vec<String> {
        let src = include_str!("mod.rs");
        let start = src.find("pub fn code(&self)").expect("Cause::code");
        let end = start
            + src[start..]
                .find("pub fn exit_code")
                .expect("Cause::exit_code");
        let body = &src[start..end];
        let mut out: Vec<String> = body
            .split('"')
            .skip(1)
            .step_by(2)
            .map(str::to_string)
            .collect();
        out.sort();
        out.dedup();
        out
    }

    #[test]
    fn every_code_the_catalog_returns_has_an_example() {
        let mut have: Vec<String> = table().iter().map(|r| r.code.to_string()).collect();
        have.sort();
        assert_eq!(have, codes_in_source());
    }

    #[test]
    fn every_code_has_a_meaning() {
        let missing: Vec<&str> = table()
            .iter()
            .filter(|r| r.meaning.is_empty())
            .map(|r| r.code)
            .collect();
        assert!(missing.is_empty(), "{missing:?}");
    }

    #[test]
    fn every_code_is_listed_once() {
        let codes: Vec<&str> = table().iter().map(|r| r.code).collect();
        let mut unique = codes.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), codes.len());
    }
}
