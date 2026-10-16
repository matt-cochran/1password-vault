//! Rendering every [`Cause`] (design §4, §6, §7): its first line ([`Cause::message`]), its Do
//! and Next ([`Cause::step`]), the derived `human_required` (§6.3), the terminal text
//! ([`render_text`]) and the `--json`/MCP `error` object ([`document`]).
//!
//! Every word comes from the variant's typed fields; upstream text only ever reaches the
//! evidence box ([`super::evidence`]), never a message or a step (§9.3).

use super::evidence;
use super::*;
use crate::error::shell_word;

/// Flags only a person may add (§6.2): a command carrying one is always a `Handoff`.
const PERSON_ONLY_FLAGS: [&str; 4] = [
    "--confirm",
    "--approved",
    "--expect-plan",
    "--prune-immutable",
];

/// The issue tracker a `Bug` points at.
const ISSUES_URL: &str = "https://github.com/matt-cochran/1password-vault/issues";

// --- small builders ------------------------------------------------------------------------

fn cmd(words: &[&str], args: &[&str]) -> Cmd {
    Cmd {
        command: words.iter().map(|w| w.to_string()).collect(),
        args: args.iter().map(|a| a.to_string()).collect(),
    }
}

fn vendor(program: &str, args: &[&str]) -> Next {
    Next::Vendor(VendorCmd {
        program: program.to_string(),
        args: args.iter().map(|a| a.to_string()).collect(),
    })
}

/// `opv <command words> <args>`, each word quoted with `shell_word`. A local stand-in until
/// the step module's `Cmd` rendering lands.
pub fn cmd_text(c: &Cmd) -> String {
    std::iter::once("opv".to_string())
        .chain(c.command.iter().chain(c.args.iter()).map(|w| shell_word(w)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn vendor_text(v: &VendorCmd) -> String {
    std::iter::once(shell_word(&v.program))
        .chain(v.args.iter().map(|w| shell_word(w)))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The invocation as typed (`Rerun`): every flag kept, the child command never rendered.
pub fn rerun_text(inv: &Invocation) -> String {
    match &inv.origin {
        Origin::Mcp { tool } => format!("call {tool} again"),
        Origin::Cli => {
            let mut s = cmd_text(&inv_cmd(inv));
            if inv.has_child {
                s.push_str(" -- <command>");
            }
            s
        }
    }
}

/// The invocation as a [`Cmd`].
fn inv_cmd(inv: &Invocation) -> Cmd {
    Cmd {
        command: inv.command.clone(),
        args: inv.args.clone(),
    }
}

fn carries_person_only_flag(c: &Cmd) -> bool {
    c.args.iter().any(|a| {
        PERSON_ONLY_FLAGS
            .iter()
            .any(|f| a == f || a.starts_with(&format!("{f}=")))
    })
}

/// A command opv built from the invocation: a `Run`, or a `Handoff` when it carries a flag
/// only a person may pass (§6.2).
fn run_or_handoff(c: Cmd) -> Next {
    if carries_person_only_flag(&c) {
        Next::Handoff(c)
    } else {
        Next::Run(c)
    }
}

/// The invocation with one word replaced (`given` or `flag=given`); `None` when it is absent.
fn substituted(inv: &Invocation, given: &str, with: &str) -> Option<Cmd> {
    let mut c = inv_cmd(inv);
    let mut hit = false;
    for a in c.args.iter_mut() {
        if a == given {
            *a = with.to_string();
            hit = true;
        } else if let Some((flag, value)) = a.split_once('=') {
            if value == given {
                *a = format!("{flag}={with}");
                hit = true;
            } else if flag == given {
                *a = format!("{with}={value}");
                hit = true;
            }
        }
    }
    hit.then_some(c)
}

/// The environment the invocation names: its first argument when that is not a flag.
fn inv_env(inv: &Invocation) -> Option<&str> {
    inv.args
        .first()
        .map(String::as_str)
        .filter(|a| !a.starts_with('-'))
}

/// `opv plan <env>` (a read), or `opv structure plan` when no environment is known.
fn plan_read(inv: &Invocation) -> Next {
    match inv_env(inv) {
        Some(env) => Next::Check(cmd(&["plan"], &[env])),
        None => Next::Check(cmd(&["structure", "plan"], &[])),
    }
}

fn help_of(inv: &Invocation) -> Next {
    let mut c = Cmd {
        command: inv.command.clone(),
        args: vec!["--help".into()],
    };
    if c.command.is_empty() {
        c.command.push("help".into());
        c.args.clear();
    }
    Next::Check(c)
}

fn doctor_for(principal: Option<&Principal>, credential: Option<&CredentialRef>) -> Next {
    let scoped = match (principal, credential) {
        (Some(Principal::DeployCredentials { env, target, .. }), _)
        | (_, Some(CredentialRef::DeployCredentials { env, target, .. })) => {
            Some((env.as_str(), target.as_str()))
        }
        _ => None,
    };
    match scoped {
        Some((env, target)) => Next::Run(cmd(&["doctor"], &["--env", env, "--target", target])),
        None => Next::Run(cmd(&["doctor"], &[])),
    }
}

fn list(items: &[String]) -> String {
    items.join(", ")
}

fn list_of<T: std::fmt::Display>(items: &[T]) -> String {
    items
        .iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn plural(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

fn at_words(at: &Option<Location>) -> String {
    match at {
        Some(l) => format!(" at line {}, column {}", l.line, l.col),
        None => String::new(),
    }
}

// --- words for subject types ----------------------------------------------------------------

fn io_words(io: IoKind) -> &'static str {
    match io {
        IoKind::NotFound => "it does not exist",
        IoKind::PermissionDenied => "permission denied",
        IoKind::IsADirectory => "it is a folder, not a file",
        IoKind::Other => "an input or output error",
    }
}

fn name_kind(k: NameKind) -> &'static str {
    match k {
        NameKind::Environment => "environment",
        NameKind::Target => "target",
        NameKind::Product => "product",
        NameKind::Key => "key",
        NameKind::Role => "process role",
        NameKind::RemoteProfile => "remote profile",
        NameKind::Mode => "mode",
        NameKind::HelpTopic => "help topic",
    }
}

fn name_listing(k: NameKind, inv: &Invocation) -> Next {
    match k {
        NameKind::Target => Next::Check(cmd(&["target", "list"], &[])),
        NameKind::Environment
        | NameKind::Product
        | NameKind::Key
        | NameKind::Role
        | NameKind::RemoteProfile => Next::Check(cmd(&["config", "describe"], &[])),
        NameKind::Mode => help_of(inv),
        NameKind::HelpTopic => Next::Check(cmd(&["help"], &[])),
    }
}

fn source_words(s: &ConfigSource) -> String {
    match s {
        ConfigSource::File { path, given_by } => match given_by {
            GivenBy::Flag { flag } => format!("{} (given by {flag})", path.display()),
            GivenBy::EnvVar { var } => format!("{} (given by {var})", path.display()),
            GivenBy::Discovered => path.display().to_string(),
        },
        ConfigSource::Manifest {
            title,
            vault,
            project,
        } => format!("the 1Password manifest {title} of project {project} (vault {vault})"),
    }
}

fn account_ref(a: &AccountRef) -> String {
    match a {
        AccountRef::Id(id) => id.to_string(),
        AccountRef::Email(e) => e.clone(),
        AccountRef::Shorthand(s) => s.clone(),
    }
}

fn account_source(s: &AccountSource) -> String {
    match s {
        AccountSource::DotOpv { path } => format!("the .opv file {}", path.display()),
        AccountSource::EnvVar { var } => format!("the variable {var}"),
        AccountSource::Flag => "--account".to_string(),
        AccountSource::Environment { env } => format!("environment {env}"),
        AccountSource::OpDefault => "op's default account".to_string(),
    }
}

fn principal_words(p: &Principal) -> String {
    match p {
        Principal::Person { account: Some(a) } => format!("you (account {a})"),
        Principal::Person { account: None } => "you".to_string(),
        Principal::ServiceAccount { name } => format!("service account {name}"),
        Principal::ServicePrincipal { client_id } => format!("service principal {client_id}"),
        Principal::AppIdentity { name } => format!("app identity {name}"),
        Principal::StoreIdentity { name } => format!("store identity {name}"),
        Principal::DeployCredentials { item, env, target } => {
            format!("deploy credentials {item} of target {target} in environment {env}")
        }
        Principal::ShellToken { var } => format!("the token in {var}"),
    }
}

fn principal_var(p: &Principal) -> Option<&VarName> {
    match p {
        Principal::ShellToken { var } => Some(var),
        Principal::Person { .. }
        | Principal::ServiceAccount { .. }
        | Principal::ServicePrincipal { .. }
        | Principal::AppIdentity { .. }
        | Principal::StoreIdentity { .. }
        | Principal::DeployCredentials { .. } => None,
    }
}

fn resource_kind(k: ResourceKind) -> &'static str {
    match k {
        ResourceKind::Vault => "vault",
        ResourceKind::Item => "item",
        ResourceKind::PersonalVault => "personal vault",
        ResourceKind::FlyApp => "Fly app",
        ResourceKind::KeyVault => "Key Vault",
        ResourceKind::ContainerApp => "container app",
        ResourceKind::Namespace => "namespace",
        ResourceKind::Deployment => "deployment",
        ResourceKind::KubeContext => "kube context",
        ResourceKind::Repository => "repository",
        ResourceKind::GitHubEnvironment => "GitHub environment",
        ResourceKind::ExternalStore => "external store",
    }
}

fn resource_words(r: &ResourceRef) -> String {
    match &r.scope {
        Some(scope) => format!("{} {} in {scope}", resource_kind(r.kind), r.name),
        None => format!("{} {}", resource_kind(r.kind), r.name),
    }
}

fn right_words(r: &Right) -> String {
    match r {
        Right::Read => "read".into(),
        Right::Write => "write".into(),
        Right::Edit => "edit".into(),
        Right::List => "list".into(),
        Right::Manage => "manage".into(),
        Right::CreateServiceAccount => "create service accounts".into(),
        Right::EnvironmentsWrite => "write environments".into(),
        Right::SecretsWrite => "write secrets".into(),
        Right::Verb { verb, resource } => format!("{verb} {resource}"),
    }
}

fn grant_words(
    grant: &GrantModel,
    principal: &Principal,
    resource: &ResourceRef,
    right: &Right,
) -> String {
    let who = principal_words(principal);
    let what = resource_words(resource);
    let right = right_words(right);
    match grant {
        GrantModel::Rbac { role, scope } => {
            format!("ask an owner to grant the role {role} on {scope} to {who}")
        }
        GrantModel::AccessPolicy { permissions } => format!(
            "ask an owner to add an access policy on {what} giving {who} {}",
            permissions.join(", ")
        ),
        GrantModel::NetworkRule => {
            format!("ask an owner to allow this network in the network rules of {what}")
        }
        GrantModel::VaultPermission => {
            format!("ask a 1Password admin to give {who} {right} access to {what}")
        }
        GrantModel::RepoPermission => {
            format!("ask a repository admin to give {who} {right} access to {what}")
        }
        GrantModel::K8sRbac {
            verb,
            resource: kind,
            namespace,
        } => match namespace {
            Some(ns) => format!("ask a cluster admin to let {who} {verb} {kind} in namespace {ns}"),
            None => format!("ask a cluster admin to let {who} {verb} {kind}"),
        },
        GrantModel::OnePasswordRole => {
            format!("ask a 1Password admin to give {who} a role that may {right} {what}")
        }
    }
}

fn credential_words(c: &CredentialRef) -> String {
    match c {
        CredentialRef::ServiceAccountToken { var } => format!("the service account token in {var}"),
        CredentialRef::Connect {
            host_var,
            token_var,
        } => {
            format!("the Connect server set by {host_var} and {token_var}")
        }
        CredentialRef::DeployCredentials {
            vault,
            item,
            env,
            target,
        } => format!(
            "deploy credentials {item} (vault {vault}) of target {target} in environment {env}"
        ),
        CredentialRef::ShellToken { var } => format!("the token in {var}"),
        CredentialRef::StoreAuth { store } => format!("the credentials of store {store}"),
        CredentialRef::SshIdentity { path: Some(p) } => format!("the SSH key {}", p.display()),
        CredentialRef::SshIdentity { path: None } => "the keys in the SSH agent".to_string(),
    }
}

fn store_object(o: &StoreObject) -> String {
    match o {
        StoreObject::File { path } => format!("the file {}", path.display()),
        StoreObject::Manifest { title, vault } => {
            format!("the 1Password manifest {title} (vault {vault})")
        }
        StoreObject::Item { vault, item } => format!("item {item} in vault {vault}"),
    }
}

fn create_kind(k: CreateKind) -> &'static str {
    match k {
        CreateKind::Vault => "vault",
        CreateKind::Item => "item",
        CreateKind::ItemWithSecrets => "item with secrets",
        CreateKind::Manifest => "manifest",
        CreateKind::ServiceAccount => "service account",
        CreateKind::DeployToken => "deploy token",
        CreateKind::GitHubEnvironment => "GitHub environment",
    }
}

fn input_kind(k: InputKind) -> &'static str {
    match k {
        InputKind::Dotenv => "the .env file",
        InputKind::SetupRecipe => "the setup recipe",
        InputKind::Receipt => "the delivery receipt",
    }
}

/// What is wrong with a field (`<field> <phrase>`), and the fix (§4.12). Pattern ids are
/// shown as words, never as a regular expression.
fn rule_words(field: &str, rule: &FieldRule) -> (String, String) {
    match rule {
        FieldRule::Syntax => (
            format!("{field} is not valid syntax"),
            format!("fix the syntax of {field}"),
        ),
        FieldRule::Pattern { id } => {
            let what = id.replace(['_', '-'], " ");
            (
                format!("{field} is not a valid {what}"),
                format!("change {field} to a valid {what}"),
            )
        }
        FieldRule::Reserved { set } => (
            format!("{field} uses a reserved name (reserved: {})", list(set)),
            format!("rename {field} to a name outside {}", list(set)),
        ),
        FieldRule::Empty => (format!("{field} is empty"), format!("fill in {field}")),
        FieldRule::Type { expected } => (
            format!("{field} must be {expected}"),
            format!("make {field} {expected}"),
        ),
        FieldRule::Unknown { suggestion } => (
            format!("{field} is not a known setting"),
            match suggestion {
                Some(s) => format!("rename {field} to {s}"),
                None => format!("remove {field}"),
            },
        ),
        FieldRule::Missing => (
            format!("{field} is required but missing"),
            format!("add {field}"),
        ),
        FieldRule::ConflictsWith { field: other } => (
            format!("{field} cannot be set together with {other}"),
            format!("keep only one of {field} and {other}"),
        ),
        FieldRule::DuplicateKey => (
            format!("{field} is set more than once"),
            format!("keep one {field}"),
        ),
        FieldRule::RemovedForm { form, replacement } => (
            format!("{field} uses the removed form {form}"),
            format!("replace {form} with {replacement} in {field}"),
        ),
        FieldRule::NoEnvironment => (
            format!("{field} names no environment"),
            format!("declare an environment for {field}"),
        ),
        FieldRule::ModeUnmapped { env, mode, allowed } => (
            format!(
                "{field} sets mode {mode} for environment {env}, which is not one of {}",
                list(allowed)
            ),
            format!(
                "set {field} to one of {} for environment {env}",
                list(allowed)
            ),
        ),
        FieldRule::Collision { rendered, other } => (
            format!("{field} becomes {rendered}, the same name as {other}"),
            format!("rename {field} or {other}"),
        ),
    }
}

fn vendor_sign_in(system: System) -> Option<VendorCmd> {
    let (program, args): (&str, &[&str]) = match system {
        System::Fly => ("flyctl", &["auth", "login"]),
        System::Azure => ("az", &["login"]),
        System::GitHub => ("gh", &["auth", "login"]),
        System::OnePassword | System::Kubernetes | System::Ssh | System::RemoteOpv => {
            return None;
        }
    };
    Some(VendorCmd {
        program: program.into(),
        args: args.iter().map(|a| a.to_string()).collect(),
    })
}

fn session_words(system: System, account: &Option<AccountId>, state: &SessionState) -> String {
    let acct = match account {
        Some(a) => format!(" account {a}"),
        None => String::new(),
    };
    let sys = system.label();
    match state {
        SessionState::SignedOut => format!("you are not signed in to {sys}{acct}"),
        SessionState::Expired => format!("your session for {sys}{acct} has expired"),
        SessionState::AppLocked => {
            format!("the 1Password app is locked, so {sys}{acct} cannot be read")
        }
        SessionState::AppPromptUnanswered { waited_seconds } => format!(
            "the 1Password app's prompt for {sys}{acct} went unanswered for {waited_seconds} seconds"
        ),
        SessionState::OtherAccount { live } => {
            format!("{sys} is signed in to account {live}, not{acct}")
        }
    }
}

fn unanswered_words(w: &Unanswered) -> String {
    match w {
        Unanswered::Timeout => "it timed out".into(),
        Unanswered::RateLimited {
            retry_after_seconds: Some(s),
        } => format!("it limited the request rate (it asked to wait {s} seconds)"),
        Unanswered::RateLimited {
            retry_after_seconds: None,
        } => "it limited the request rate".into(),
        Unanswered::ServerError { status } => format!("it answered with server error {status}"),
        Unanswered::Network => "the network failed".into(),
    }
}

fn value_state(s: &ValueState) -> String {
    match s {
        ValueState::Missing => "missing".into(),
        ValueState::RuleFailed { rule } => format!("does not meet its rule: {rule}"),
        ValueState::StoredAsText => "stored as plain text, not concealed".into(),
        ValueState::ConcealedConfig => "a setting stored concealed".into(),
        ValueState::FieldNotCreated => "its field does not exist yet".into(),
    }
}

fn value_fix(s: &ValueState) -> &'static str {
    match s {
        ValueState::Missing | ValueState::FieldNotCreated => "fill in",
        ValueState::RuleFailed { .. } => "correct",
        ValueState::StoredAsText => "store as a concealed field",
        ValueState::ConcealedConfig => "store as a plain text field",
    }
}

fn ram_dir_words(w: &RamDir) -> String {
    match w {
        RamDir::Unset => "none is configured".into(),
        RamDir::NotAbsolute => "the configured folder is not an absolute path".into(),
        RamDir::NotOwned => "the configured folder is not owned by you".into(),
        RamDir::NotTmpfs => "the configured folder is not held in memory (tmpfs)".into(),
        RamDir::NoneOnPlatform { os } => format!("{os} has none"),
    }
}

fn unverified_words(s: &Unverified) -> String {
    match s {
        Unverified::NotRecorded => "no delivery is recorded".into(),
        Unverified::Superseded { receipt } => {
            format!(
                "a later delivery replaced it (receipt {})",
                receipt.display()
            )
        }
        Unverified::OtherAccount { account } => {
            format!("it was delivered from 1Password account {account}")
        }
        Unverified::ChangedOnTarget => "the values on the target changed since".into(),
        Unverified::ChangedInOnePassword => "the values in 1Password changed since".into(),
        Unverified::Unverifiable => "the target does not let opv check".into(),
    }
}

fn exit_program(seen: &Observed) -> &str {
    &seen.call().program
}

// --- the catalog: message, Do and Next ------------------------------------------------------

/// The Do and Next of one cause, with the Do's words.
struct Plan {
    action: Option<Action>,
    do_text: Option<String>,
    next: Next,
}

fn plan(action: Option<(Action, String)>, next: Next) -> Plan {
    let (action, do_text) = match action {
        Some((a, t)) => (Some(a), Some(t)),
        None => (None, None),
    };
    Plan {
        action,
        do_text,
        next,
    }
}

fn inspect(text: impl Into<String>) -> Option<(Action, String)> {
    Some((Action::Inspect, text.into()))
}

impl Cause {
    /// The first line (design §4, §7.1): a template filled from the variant's fields.
    pub fn message(&self) -> String {
        use Cause::*;
        match self {
            ConfigNotFound { searched_from, env } => match env {
                Some(env) => format!(
                    "no opv configuration for environment {env} was found in {} or any folder above it",
                    searched_from.display()
                ),
                None => format!(
                    "no opv configuration was found in {} or any folder above it",
                    searched_from.display()
                ),
            },
            ConfigSourceMismatch { command, manifest } => format!(
                "opv {} works on a secrets.toml, but this project's configuration is the 1Password manifest {manifest}",
                command.0
            ),
            ConfigUnreadable { path, io, given_by } => {
                let by = match given_by {
                    GivenBy::Flag { flag } => format!(" (given by {flag})"),
                    GivenBy::EnvVar { var } => format!(" (given by {var})"),
                    GivenBy::Discovered => String::new(),
                };
                format!(
                    "cannot read the configuration file {}{by}: {}",
                    path.display(),
                    io_words(*io)
                )
            }
            ConfigInvalid {
                source,
                at,
                field,
                rule,
            } => {
                let (what, _) = rule_words(&field.to_string(), rule);
                format!("{}{}: {what}", source_words(source), at_words(at))
            }
            BoundaryMissing {
                env,
                product,
                source,
            } => format!(
                "no boundary vault is recorded for product {product} in environment {env} in {}",
                source_words(source)
            ),
            StateVaultMissing {
                env,
                target,
                source,
            } => format!(
                "no state vault is recorded for target {target} of environment {env} in {}",
                source_words(source)
            ),
            StateVaultTooWide {
                env,
                target,
                vault,
                shared_with,
            } => format!(
                "the state vault {vault} of target {target} in environment {env} is shared with targets {}, so it is wider than the values it holds",
                list_of(shared_with)
            ),
            ConfigNotEditable { source, reason } => match reason {
                NotEditable::Generated { path } => format!(
                    "opv does not edit {}: it is generated from {}",
                    source_words(source),
                    path.display()
                ),
                NotEditable::UnsupportedLayout { section } => format!(
                    "opv cannot edit section [{section}] of {}: its layout is not one opv writes",
                    source_words(source)
                ),
                NotEditable::ManifestItemAsBoundary { env, boundary } => format!(
                    "opv cannot edit {}: environment {env} uses the manifest item {boundary} as its boundary",
                    source_words(source)
                ),
            },
            CopiesDiffer { file, manifest } => format!(
                "{} and the 1Password manifest {manifest} differ",
                file.display()
            ),
            ManifestNotFound { project, account } => match account {
                Some(a) => format!("no 1Password manifest for project {project} in account {a}"),
                None => format!("no 1Password manifest for project {project}"),
            },
            ManifestAmbiguous {
                candidates,
                person_picks: _,
            } => format!(
                "{} match this project: {}",
                plural(
                    candidates.len(),
                    "1Password manifest",
                    "1Password manifests"
                ),
                list(candidates)
            ),
            ManifestExists { title, local_file } => match local_file {
                Some(f) => format!(
                    "a 1Password manifest named {title} already exists (the local copy is {})",
                    f.display()
                ),
                None => format!("a 1Password manifest named {title} already exists"),
            },
            InventoryIncomplete { unlisted } => format!(
                "the account inventory is incomplete: {} could not be listed",
                if unlisted.len() == 1 {
                    format!("account {}", unlisted[0])
                } else {
                    format!("accounts {}", list_of(unlisted))
                }
            ),
            NotDeclared {
                kind,
                given,
                candidates,
                closest: _,
            } => {
                let k = name_kind(*kind);
                if candidates.is_empty() {
                    format!("{k} {given} is not declared, and none is")
                } else {
                    format!(
                        "{k} {given} is not declared (declared: {})",
                        list(candidates)
                    )
                }
            }
            Ambiguous {
                kind,
                given,
                candidates,
            } => format!(
                "{} {given} matches more than one: {}",
                name_kind(*kind),
                list(candidates)
            ),
            ChoiceRequired { flag, candidates } => {
                format!("this command needs {flag}, one of {}", list(candidates))
            }
            NothingInScope { env, what } => match what {
                Scope::NoProductHasKeys => {
                    format!("no product in environment {env} declares a key")
                }
                Scope::NoTargetDelivers { target } => {
                    format!("target {target} of environment {env} delivers no product")
                }
                Scope::NoTargets { products } => format!(
                    "environment {env} has no target for products {}",
                    list_of(products)
                ),
            },
            Usage { problem } => match problem {
                UsageProblem::UnknownFlag { flag, closest: _ } => format!("unknown option {flag}"),
                UsageProblem::MisplacedBeforeDashDash { flag } => {
                    format!("{flag} belongs before --, not after it")
                }
                UsageProblem::ConflictsWith { a, b } => {
                    format!("{a} and {b} cannot be used together")
                }
                UsageProblem::ValueFormat { flag, format } => {
                    format!("{flag} expects {format}")
                }
                UsageProblem::NeedsFlag { flag, needs } => format!("{flag} needs {needs}"),
                UsageProblem::UseInstead { command } => {
                    format!("this is done with {} instead", cmd_text(command))
                }
            },
            AlreadyDeclared { kind, name } => {
                format!("{} {name} is already declared", name_kind(*kind))
            }
            NotSignedIn {
                system,
                account,
                state,
            } => session_words(*system, account, state),
            AccountNotOnMachine {
                account,
                selected_by,
                in_app,
            } => format!(
                "1Password account {} (chosen by {}) is not added {}",
                account_ref(account),
                account_source(selected_by),
                if *in_app {
                    "to the 1Password app on this machine"
                } else {
                    "to op on this machine"
                }
            ),
            AccountAmbiguous { given, candidates } => format!(
                "account {given} matches more than one 1Password account: {}",
                list_of(candidates)
            ),
            InOtherAccount {
                vault,
                item,
                selected,
                owning,
                env,
                seen: _,
            } => {
                let what = match item {
                    Some(i) => format!("item {i} in vault {vault}"),
                    None => format!("vault {vault}"),
                };
                let of_env = match env {
                    Some(e) => format!(" (environment {e})"),
                    None => String::new(),
                };
                match owning {
                    Some(o) => format!(
                        "{what}{of_env} is not in 1Password account {selected}; it is in account {o}"
                    ),
                    None => format!("{what}{of_env} is not in 1Password account {selected}"),
                }
            }
            NeedsOwnSession { command, identity } => format!(
                "opv {} must be used in your own session, not as {}",
                command.0,
                principal_words(identity)
            ),
            CredentialRejected {
                system,
                credential,
                problem,
                seen: _,
            } => {
                let cred = credential_words(credential);
                let sys = system.label();
                match problem {
                    CredentialProblem::Rejected { needs } if needs.is_empty() => {
                        format!("{sys} rejected {cred}")
                    }
                    CredentialProblem::Rejected { needs } => {
                        format!("{sys} rejected {cred}: it needs {}", list(needs))
                    }
                    CredentialProblem::Incomplete { missing_fields } => format!(
                        "{cred} for {sys} is incomplete: fields {} are missing",
                        list_of(missing_fields)
                    ),
                    CredentialProblem::Unreadable => format!("{cred} for {sys} cannot be read"),
                    CredentialProblem::OverriddenByEnvironment { var } => {
                        format!("{var} in this shell overrides {cred} for {sys}")
                    }
                }
            }
            MissingRight {
                system,
                resource,
                right,
                grant: _,
                seen,
            } => format!(
                "{} may not {} {} at {}",
                principal_words(seen.principal()),
                right_words(right),
                resource_words(resource),
                system.label()
            ),
            OwnerSetupRequired { system, object } => format!(
                "{} at {} needs setting up by an owner",
                resource_words(object),
                system.label()
            ),
            NotFound {
                system,
                resource,
                state,
                seen: _,
            } => match state {
                NotFoundState::Missing => format!(
                    "{} was not found at {}",
                    resource_words(resource),
                    system.label()
                ),
                NotFoundState::SoftDeleted => format!(
                    "{} is deleted at {} and can still be recovered",
                    resource_words(resource),
                    system.label()
                ),
                NotFoundState::LocalContextMissing => format!(
                    "{} for {} is not set up on this machine",
                    resource_words(resource),
                    system.label()
                ),
            },
            TargetRefused {
                system,
                subject,
                why,
                seen: _,
            } => {
                let sys = system.label();
                let what = resource_words(subject);
                match why {
                    Refusal::Validation => {
                        format!("{sys} refused the update to {what}: it failed validation")
                    }
                    Refusal::Quota => {
                        format!("{sys} refused the update to {what}: a quota is reached")
                    }
                    Refusal::Unhealthy {
                        new_revision,
                        serving,
                    } => match serving {
                        Some(s) => format!(
                            "the new revision {new_revision} of {what} at {sys} is unhealthy; revision {s} still serves"
                        ),
                        None => format!(
                            "the new revision {new_revision} of {what} at {sys} is unhealthy"
                        ),
                    },
                    Refusal::NoRevision => format!("{sys} made no new revision of {what}"),
                }
            }
            Guard { guard } => match guard {
                self::Guard::ValueTooLarge { key, limit } => format!(
                    "the value of {key} is larger than {limit} bytes, the most the target stores"
                ),
                self::Guard::NotManagedByOpv { name } => {
                    format!("{name} was not created by opv, so opv does not change it")
                }
                self::Guard::CredentialAsOption { option } => format!(
                    "{option} would put a credential on the command line, so opv refuses it"
                ),
                self::Guard::ProviderHidesValues { system } => format!(
                    "{} does not show stored values, so opv cannot compare them",
                    system.label()
                ),
                self::Guard::ImmutableWithoutRotate { key } => {
                    format!("{key} cannot change in place: it changes only when rotated")
                }
                self::Guard::GenerateRefused { key, why } => {
                    format!("opv does not generate {key}: {why}")
                }
                self::Guard::RemoteProfileRefuses {
                    profile,
                    asked,
                    allowed,
                } => format!(
                    "remote profile {profile} does not allow {asked}; it allows {}",
                    list(allowed)
                ),
                self::Guard::Declined => "you declined, so nothing changed".to_string(),
            },
            CreateOutcomeUnknown {
                system,
                kind,
                name,
                refind: _,
                seen: _,
            } => format!(
                "opv cannot tell whether {} created the {} {name}",
                system.label(),
                create_kind(*kind)
            ),
            WriteOutcomeUnknown {
                system,
                subject,
                seen: _,
            } => format!(
                "opv cannot tell whether the change to {} at {} was applied",
                resource_words(subject),
                system.label()
            ),
            Unavailable {
                system,
                why,
                attempts,
                seen: _,
            } => format!(
                "{} did not answer after {}: {}",
                system.label(),
                plural(*attempts as usize, "attempt", "attempts"),
                unanswered_words(why)
            ),
            BudgetSpent {
                budget_seconds,
                writes_started,
            } => {
                if *writes_started {
                    format!(
                        "opv stopped at its {budget_seconds}-second time limit, after writes had started"
                    )
                } else {
                    format!(
                        "opv stopped at its {budget_seconds}-second time limit, before any write"
                    )
                }
            }
            Partial {
                done,
                approval_used,
                then,
            } => {
                let mut s = format!("{}; already written: {}", then.message(), list(done));
                if let Some(p) = approval_used {
                    s.push_str(&format!("; approval {p} is used up"));
                }
                s
            }
            Interrupted {
                signal,
                writes_started,
            } => {
                if *writes_started {
                    format!("interrupted by signal {signal} after writes had started")
                } else {
                    format!("interrupted by signal {signal} before any write")
                }
            }
            ChangedBeforeWrite { object } => format!(
                "{} changed while opv was working, so opv wrote nothing",
                store_object(object)
            ),
            ConcurrentEdit { object } => format!(
                "{} was changed by someone else during opv's write",
                store_object(object)
            ),
            ReadBackMissing {
                vault,
                item,
                fields,
                by,
            } => format!(
                "after opv {}, fields {} of item {item} in vault {vault} were missing when read back",
                by.0,
                list_of(fields)
            ),
            ToolMissing { tool } => format!("{tool} is not installed, or not on PATH"),
            ToolUnusable { tool, why } => match why {
                Unusable::NotExecutable => format!("{tool} is not executable"),
                Unusable::WslInteropOff => {
                    format!("{tool} is a Windows program and WSL interop is turned off")
                }
                Unusable::TooOld { have, min } => {
                    format!("{tool} {have} is too old; opv needs {min} or later")
                }
                Unusable::VersionUnreadable => format!("opv cannot read the version of {tool}"),
                Unusable::SpawnFailed { io } => {
                    format!("{tool} could not be started: {}", io_words(*io))
                }
                Unusable::WindowsExeFromWsl => {
                    format!("{tool} is the Windows build, used from WSL")
                }
            },
            UnexpectedOutput { system, at, seen } => format!(
                "opv could not read the reply of {} from {}{}",
                exit_program(seen),
                system.label(),
                at_words(at)
            ),
            Unrecognized {
                system,
                established,
                seen,
            } => {
                if established.is_empty() {
                    format!(
                        "{} failed at {} in a way opv does not recognise",
                        exit_program(seen),
                        system.label()
                    )
                } else {
                    format!(
                        "{} failed at {} in a way opv does not recognise (opv checked: {})",
                        exit_program(seen),
                        system.label(),
                        list(established)
                    )
                }
            }
            NeedsTerminal { why } => match why {
                NoTerminal::NoTty => {
                    "this step needs a person at a terminal, and there is none".into()
                }
                NoTerminal::Ci => {
                    "this step needs a person at a terminal, and this is a CI run".into()
                }
            },
            NeedsConfirm { env } => {
                format!("changing environment {env} needs a person's confirmation")
            }
            ConfirmMismatch { given, env } => {
                format!("the confirmation {given} does not match environment {env}")
            }
            ValuesNeeded { env, rows } => {
                let named = rows
                    .iter()
                    .map(|r| {
                        let on = match &r.target {
                            Some(t) => format!(" for target {t}"),
                            None => String::new(),
                        };
                        format!("{}/{}{on} ({})", r.product, r.key, value_state(&r.state))
                    })
                    .collect::<Vec<_>>();
                format!(
                    "environment {env} needs {}: {}",
                    plural(rows.len(), "value", "values"),
                    named.join(", ")
                )
            }
            LocalFileTooOpen { path, mode, want } => format!(
                "{} has mode {mode:04o}; opv needs {want:04o} or stricter",
                path.display()
            ),
            InputInvalid {
                path,
                kind,
                at,
                field,
                rule,
            } => {
                let (what, _) = rule_words(field, rule);
                format!(
                    "{} {}{}: {what}",
                    input_kind(*kind),
                    path.display(),
                    at_words(at)
                )
            }
            ApprovalMissing { plan } => format!("plan {plan} is not approved yet"),
            ApprovalUsed { plan, partial } => {
                if *partial {
                    format!(
                        "approval {plan} is already used, and only part of its plan was applied"
                    )
                } else {
                    format!("approval {plan} is already used")
                }
            }
            PlanChanged { old, new } => {
                format!("the plan changed since it was approved: {old} is now {new}")
            }
            PlanUnknown { plan } => format!("no plan {plan} is known"),
            RamDirUnavailable { remote, why } => match remote {
                Some(p) => format!(
                    "no in-memory folder for the settings file on the host of remote profile {p}: {}",
                    ram_dir_words(why)
                ),
                None => format!(
                    "no in-memory folder for the settings file on this machine: {}",
                    ram_dir_words(why)
                ),
            },
            PrivateDirFailed { dir, io } => format!(
                "cannot make a private folder in {}: {}",
                dir.display(),
                io_words(*io)
            ),
            RemoteUnreachable {
                profile,
                user,
                host,
                port,
            } => format!("cannot reach {user}@{host} port {port} (remote profile {profile})"),
            RemoteDisconnected {
                profile,
                host,
                during,
            } => match during {
                RemotePhase::Delivery => format!(
                    "the connection to {host} (remote profile {profile}) ended before delivery finished; nothing was delivered"
                ),
                RemotePhase::Running => format!(
                    "the connection to {host} (remote profile {profile}) ended while the app ran; the app was stopped and its folder removed"
                ),
            },
            RemoteVersionMismatch {
                profile,
                remote_protocol,
            } => format!(
                "opv on the host of remote profile {profile} speaks protocol {remote_protocol}, which this opv {} does not",
                env!("CARGO_PKG_VERSION")
            ),
            ChildStartFailed {
                program,
                workdir,
                io,
                remote,
            } => {
                let in_dir = match workdir {
                    Some(d) => format!(" in {}", d.display()),
                    None => String::new(),
                };
                let on = match remote {
                    Some(p) => format!(" on the host of remote profile {p}"),
                    None => String::new(),
                };
                format!("cannot start {program}{in_dir}{on}: {}", io_words(*io))
            }
            DeliveryUnverified {
                env,
                target,
                product,
                state,
            } => format!(
                "opv cannot confirm that product {product} is delivered to target {target} in environment {env}: {}",
                unverified_words(state)
            ),
            Bug { site } => format!("opv hit an internal error ({site})"),
        }
    }

    /// The Do and Next (design §4, §6.2).
    pub fn step(&self, inv: &Invocation) -> (Option<Action>, Next) {
        let p = self.plan(inv);
        (p.action, p.next)
    }

    /// The Do in words, filled from the subject; `None` when there is no Do.
    pub fn do_text(&self, inv: &Invocation) -> Option<String> {
        self.plan(inv).do_text
    }

    /// True exactly when the step needs a person (design §6.3).
    pub fn human_required(&self, inv: &Invocation) -> bool {
        let (action, next) = self.step(inv);
        matches!(next, Next::Handoff(_))
            || action.is_some_and(|a| a.person_only())
            || matches!(
                self,
                Cause::NeedsTerminal { .. }
                    | Cause::NeedsOwnSession { .. }
                    | Cause::NeedsConfirm { .. }
                    | Cause::ApprovalMissing { .. }
            )
    }

    fn plan(&self, inv: &Invocation) -> Plan {
        use Cause::*;
        match self {
            ConfigNotFound {
                searched_from: _,
                env,
            } => plan(
                None,
                match env {
                    Some(e) => Next::Run(cmd(&["init"], &[e.as_str()])),
                    None => Next::Check(cmd(&["init"], &["--help"])),
                },
            ),
            ConfigSourceMismatch {
                command: _,
                manifest,
            } => plan(
                inspect(format!(
                    "change the manifest {manifest} with opv config edit"
                )),
                Next::Run(cmd(&["config", "edit"], &[])),
            ),
            ConfigUnreadable {
                path,
                io: _,
                given_by,
            } => plan(
                inspect(match given_by {
                    GivenBy::Flag { flag } => format!("check the path given with {flag}"),
                    GivenBy::EnvVar { var } => format!("check the path in {var}"),
                    GivenBy::Discovered => {
                        format!("check that you can read {}", path.display())
                    }
                }),
                Next::Rerun,
            ),
            ConfigInvalid {
                source,
                at,
                field,
                rule,
            } => {
                let (_, fix) = rule_words(&field.to_string(), rule);
                let place = match source {
                    ConfigSource::File { path, .. } => {
                        format!("in {}{}", path.display(), at_words(at))
                    }
                    ConfigSource::Manifest { title, .. } => {
                        format!("in the manifest {title} (opv config edit)")
                    }
                };
                plan(
                    Some((
                        Action::EditConfig {
                            source: source.clone(),
                            field: field.clone(),
                        },
                        format!("{fix} {place}"),
                    )),
                    Next::Rerun,
                )
            }
            BoundaryMissing { source, .. } | StateVaultMissing { source, .. } => plan(
                None,
                match source {
                    ConfigSource::File { .. } => Next::Run(cmd(&["bootstrap"], &[])),
                    ConfigSource::Manifest { .. } => Next::Check(cmd(&["structure", "plan"], &[])),
                },
            ),
            StateVaultTooWide {
                env,
                target,
                vault: _,
                shared_with: _,
            } => plan(
                inspect(format!(
                    "delete state_vault_id from [environments.{env}.targets.{target}] so opv makes a vault for this target alone"
                )),
                Next::Run(cmd(&["bootstrap"], &[])),
            ),
            ConfigNotEditable { source, reason } => plan(
                inspect(match reason {
                    NotEditable::Generated { path } => format!(
                        "change {} instead, and generate the configuration again",
                        path.display()
                    ),
                    NotEditable::UnsupportedLayout { section } => {
                        format!(
                            "edit section [{section}] of {} by hand",
                            source_words(source)
                        )
                    }
                    NotEditable::ManifestItemAsBoundary { env, boundary } => format!(
                        "give environment {env} a boundary vault of its own instead of {boundary}"
                    ),
                }),
                Next::Run(cmd(&["config", "edit"], &[])),
            ),
            CopiesDiffer { file, manifest } => plan(
                Some((
                    Action::PickBetween,
                    format!(
                        "decide which is right: update {} (opv config export --toml > {}) or the manifest {manifest} (opv config edit)",
                        file.display(),
                        shell_word(&file.display().to_string())
                    ),
                )),
                Next::None(NoNext::PersonPicksDirection),
            ),
            ManifestNotFound { .. } => plan(None, Next::Check(cmd(&["projects"], &[]))),
            ManifestAmbiguous {
                candidates,
                person_picks,
            } => plan(
                person_picks.then(|| {
                    (
                        Action::PickBetween,
                        format!("pick the project's manifest among {}", list(candidates)),
                    )
                }),
                Next::Check(cmd(&["projects"], &[])),
            ),
            ManifestExists { .. } => plan(None, Next::Run(cmd(&["config", "edit"], &[]))),
            InventoryIncomplete { unlisted } => match unlisted.first() {
                Some(first) => {
                    let mut args = vec![
                        "--account".to_string(),
                        first.to_string(),
                        "--no-record".to_string(),
                        "--".to_string(),
                        "opv".to_string(),
                    ];
                    args.extend(inv.command.iter().cloned());
                    args.extend(inv.args.iter().cloned());
                    plan(
                        Some((
                            Action::SignIn {
                                system: System::OnePassword,
                                account: Some(first.clone()),
                            },
                            format!("sign in to account {}", list_of(unlisted)),
                        )),
                        Next::Handoff(Cmd {
                            command: vec!["login".into()],
                            args,
                        }),
                    )
                }
                None => plan(None, Next::Check(cmd(&["account", "list"], &[]))),
            },
            NotDeclared {
                kind,
                given,
                candidates: _,
                closest,
            } => plan(
                None,
                match closest
                    .as_ref()
                    .and_then(|c| substituted(inv, given, c.as_str()))
                {
                    Some(c) => run_or_handoff(c),
                    None => name_listing(*kind, inv),
                },
            ),
            Ambiguous {
                kind,
                given: _,
                candidates,
            } => plan(
                inspect(format!("name it in full, as one of {}", list(candidates))),
                name_listing(*kind, inv),
            ),
            ChoiceRequired { flag, candidates } => match candidates.as_slice() {
                [only] => {
                    let mut c = inv_cmd(inv);
                    c.args.push(flag.clone());
                    c.args.push(only.clone());
                    plan(None, run_or_handoff(c))
                }
                _ => plan(
                    Some((
                        Action::PickBetween,
                        format!("pick one of {} and pass it with {flag}", list(candidates)),
                    )),
                    Next::None(NoNext::NothingToRun),
                ),
            },
            NothingInScope { env, what } => match what {
                Scope::NoProductHasKeys => plan(
                    inspect(format!(
                        "declare a key for environment {env} (opv add --help)"
                    )),
                    Next::Check(cmd(&["status"], &[env.as_str()])),
                ),
                Scope::NoTargetDelivers { target } => plan(
                    inspect(format!(
                        "give target {target} a product to deliver (opv config edit)"
                    )),
                    Next::Check(cmd(&["status"], &[env.as_str()])),
                ),
                Scope::NoTargets { products } => plan(
                    inspect(format!(
                        "declare a target in environment {env} for {}",
                        list_of(products)
                    )),
                    Next::Check(cmd(&["target", "add"], &["--help"])),
                ),
            },
            Usage { problem } => plan(
                None,
                match problem {
                    UsageProblem::UnknownFlag {
                        flag,
                        closest: Some(c),
                    } => match substituted(inv, flag, c.as_str()) {
                        Some(cmd) => run_or_handoff(cmd),
                        None => help_of(inv),
                    },
                    UsageProblem::UseInstead { command } => run_or_handoff(command.clone()),
                    UsageProblem::UnknownFlag { closest: None, .. }
                    | UsageProblem::MisplacedBeforeDashDash { .. }
                    | UsageProblem::ConflictsWith { .. }
                    | UsageProblem::ValueFormat { .. }
                    | UsageProblem::NeedsFlag { .. } => help_of(inv),
                },
            ),
            AlreadyDeclared { .. } => plan(None, Next::Run(cmd(&["config", "edit"], &[]))),
            NotSignedIn {
                system,
                account,
                state,
            } => {
                let app = matches!(
                    state,
                    SessionState::AppLocked | SessionState::AppPromptUnanswered { .. }
                );
                let action = if app {
                    (
                        Action::UnlockApp,
                        "unlock the 1Password app and approve its prompt".to_string(),
                    )
                } else {
                    let acct = match account {
                        Some(a) => format!(" account {a}"),
                        None => String::new(),
                    };
                    let how = match vendor_sign_in(*system) {
                        Some(v) => format!(": {}", vendor_text(&v)),
                        None => String::new(),
                    };
                    (
                        Action::SignIn {
                            system: *system,
                            account: account.clone(),
                        },
                        format!("sign in to {}{acct}{how}", system.label()),
                    )
                };
                let next = if *system == System::OnePassword {
                    let mut args = Vec::new();
                    if let Some(a) = account {
                        args.push("--account".to_string());
                        args.push(a.to_string());
                    }
                    args.push("--".into());
                    args.push("opv".into());
                    args.extend(inv.command.iter().cloned());
                    args.extend(inv.args.iter().cloned());
                    Next::Handoff(Cmd {
                        command: vec!["login".into()],
                        args,
                    })
                } else {
                    Next::Rerun
                };
                plan(Some(action), next)
            }
            AccountNotOnMachine {
                account,
                selected_by: _,
                in_app,
            } => {
                let text = if *in_app {
                    format!(
                        "add account {} in the 1Password app and turn on its CLI integration",
                        account_ref(account)
                    )
                } else {
                    format!("add account {} at op's prompt", account_ref(account))
                };
                let next = if *in_app {
                    Next::Handoff(cmd(&["login"], &[]))
                } else {
                    match account {
                        AccountRef::Email(e) => {
                            Next::Handoff(cmd(&["login"], &["--add", "--account", e]))
                        }
                        AccountRef::Id(_) | AccountRef::Shorthand(_) => {
                            Next::Handoff(cmd(&["login"], &["--add"]))
                        }
                    }
                };
                plan(
                    Some((
                        Action::AddAccount {
                            account: account.clone(),
                        },
                        text,
                    )),
                    next,
                )
            }
            AccountAmbiguous { given, candidates } => plan(
                Some((
                    Action::PickBetween,
                    format!(
                        "pick the account {given} means by its ID: {}",
                        list_of(candidates)
                    ),
                )),
                Next::Check(cmd(&["account", "list"], &[])),
            ),
            InOtherAccount {
                vault,
                item: _,
                selected: _,
                owning,
                env,
                seen: _,
            } => {
                let fix = match env {
                    Some(e) => format!("fix vault_id for environment {e}"),
                    None => "fix the vault ID in the configuration".to_string(),
                };
                let text = match owning {
                    Some(o) => format!("use account {o} (opv account use {o}), or {fix}"),
                    None => format!("find the account that holds vault {vault}, or {fix}"),
                };
                plan(
                    inspect(text),
                    Next::Run(cmd(&["vault", "locate"], &[vault.as_str()])),
                )
            }
            NeedsOwnSession {
                command: _,
                identity,
            } => {
                let without = match principal_var(identity) {
                    Some(v) => format!(", without {v}"),
                    None => String::new(),
                };
                plan(
                    inspect(format!(
                        "run it in your own terminal, signed in as yourself{without}"
                    )),
                    Next::Handoff(inv_cmd(inv)),
                )
            }
            CredentialRejected {
                system: _,
                credential,
                problem,
                seen,
            } => {
                let cred = credential_words(credential);
                let action = match problem {
                    CredentialProblem::OverriddenByEnvironment { var } => (
                        Action::Unset { var: var.clone() },
                        format!("unset {var} for this command"),
                    ),
                    CredentialProblem::Rejected { needs } if !needs.is_empty() => (
                        Action::Inspect,
                        format!("replace {cred} with one that has {}", list(needs)),
                    ),
                    CredentialProblem::Rejected { .. } => {
                        (Action::Inspect, format!("replace {cred} with a valid one"))
                    }
                    CredentialProblem::Incomplete { missing_fields } => (
                        Action::Inspect,
                        format!("add fields {} to {cred}", list_of(missing_fields)),
                    ),
                    CredentialProblem::Unreadable => {
                        (Action::Inspect, format!("check that {cred} is readable"))
                    }
                };
                let action = match (credential, &action.0) {
                    (CredentialRef::ShellToken { var }, Action::Inspect) => (
                        Action::Unset { var: var.clone() },
                        format!("unset {var} in this shell"),
                    ),
                    _ => action,
                };
                plan(
                    Some(action),
                    doctor_for(Some(seen.principal()), Some(credential)),
                )
            }
            MissingRight {
                system: _,
                resource,
                right,
                grant,
                seen,
            } => plan(
                Some((
                    Action::Grant {
                        principal: seen.principal().clone(),
                        resource: resource.clone(),
                        grant: grant.clone(),
                    },
                    grant_words(grant, seen.principal(), resource, right),
                )),
                doctor_for(Some(seen.principal()), None),
            ),
            OwnerSetupRequired { system, object } => {
                let text = match object.kind {
                    ResourceKind::GitHubEnvironment => format!(
                        "ask a repository admin to create {}",
                        resource_words(object)
                    ),
                    ResourceKind::ExternalStore => format!(
                        "ask a cluster admin to make {} ready",
                        resource_words(object)
                    ),
                    ResourceKind::Vault
                    | ResourceKind::Item
                    | ResourceKind::PersonalVault
                    | ResourceKind::FlyApp
                    | ResourceKind::KeyVault
                    | ResourceKind::ContainerApp
                    | ResourceKind::Namespace
                    | ResourceKind::Deployment
                    | ResourceKind::KubeContext
                    | ResourceKind::Repository => format!(
                        "ask an owner at {} to set up {}",
                        system.label(),
                        resource_words(object)
                    ),
                };
                plan(
                    Some((
                        Action::OwnerSetup {
                            object: object.clone(),
                        },
                        text,
                    )),
                    Next::Check(cmd(&["ready"], &[])),
                )
            }
            NotFound {
                system,
                resource,
                state,
                seen: _,
            } => {
                let what = resource_words(resource);
                let name = resource.name.as_str();
                let text = match state {
                    NotFoundState::Missing => {
                        format!("check the configuration field that names {what} (opv config edit)")
                    }
                    NotFoundState::SoftDeleted => match (system, resource.kind) {
                        (System::Azure, ResourceKind::KeyVault) => {
                            format!(
                                "recover it: az keyvault recover --name {}",
                                shell_word(name)
                            )
                        }
                        _ => format!("recover {what} at {}", system.label()),
                    },
                    NotFoundState::LocalContextMissing => {
                        format!("get credentials for {what} on this machine")
                    }
                };
                let next = match (system, state) {
                    (System::Azure, NotFoundState::SoftDeleted) => {
                        vendor("az", &["keyvault", "list-deleted"])
                    }
                    (System::Kubernetes, _) => vendor("kubectl", &["config", "get-contexts"]),
                    (System::Fly, _) => vendor("flyctl", &["apps", "list"]),
                    (System::Azure, _) => match resource.kind {
                        ResourceKind::ContainerApp => vendor("az", &["containerapp", "list"]),
                        _ => vendor("az", &["keyvault", "list"]),
                    },
                    (System::GitHub, _) => vendor("gh", &["repo", "list"]),
                    (System::OnePassword, _) => match (resource.kind, &resource.scope) {
                        (ResourceKind::Vault, _) => Next::Run(cmd(&["vault", "locate"], &[name])),
                        (_, Some(vault)) => vendor("op", &["item", "list", "--vault", vault]),
                        (_, None) => vendor("op", &["vault", "list"]),
                    },
                    (System::Ssh | System::RemoteOpv, _) => Next::None(NoNext::NothingToRun),
                };
                plan(inspect(text), next)
            }
            TargetRefused {
                system,
                subject,
                why,
                seen,
            } => {
                let what = resource_words(subject);
                let text = match why {
                    Refusal::Validation => {
                        format!(
                            "check the settings of {what} against {}'s rules",
                            system.label()
                        )
                    }
                    Refusal::Quota => format!("free or raise the quota for {what}"),
                    Refusal::Unhealthy { new_revision, .. } => format!(
                        "check why revision {new_revision} of {what} fails its health checks in its logs"
                    ),
                    Refusal::NoRevision => format!("check the deployment history of {what}"),
                };
                plan(inspect(text), doctor_for(Some(seen.principal()), None))
            }
            Guard { guard } => match guard {
                self::Guard::ValueTooLarge { key, limit } => plan(
                    inspect(format!(
                        "shorten the value of {key} in 1Password to {limit} bytes or less"
                    )),
                    Next::None(NoNext::NothingToRun),
                ),
                self::Guard::NotManagedByOpv { name } => plan(
                    inspect(format!("leave {name} as it is, or manage it outside opv")),
                    Next::None(NoNext::NothingToRun),
                ),
                self::Guard::CredentialAsOption { option } => plan(
                    inspect(format!("keep the credential in 1Password, not in {option}")),
                    help_of(inv),
                ),
                self::Guard::ProviderHidesValues { system } => plan(
                    inspect(format!(
                        "compare the values at {} yourself if you need to",
                        system.label()
                    )),
                    Next::None(NoNext::NothingToRun),
                ),
                self::Guard::ImmutableWithoutRotate { key } => plan(
                    inspect(format!("rotate {key} if it must change")),
                    help_of(inv),
                ),
                self::Guard::GenerateRefused { key, .. } => plan(
                    inspect(format!("fill in {key} in 1Password yourself")),
                    Next::None(NoNext::NothingToRun),
                ),
                self::Guard::RemoteProfileRefuses {
                    profile, allowed, ..
                } => plan(
                    inspect(format!(
                        "use one of {} with remote profile {profile}, or change the profile (opv config edit)",
                        list(allowed)
                    )),
                    Next::Run(cmd(&["config", "edit"], &[])),
                ),
                self::Guard::Declined => plan(None, Next::Rerun),
            },
            CreateOutcomeUnknown {
                system: _,
                kind,
                name,
                refind,
                seen: _,
            } => match refind {
                Refind::ByTitle => plan(None, Next::Rerun),
                Refind::Check(check) => {
                    let action = if kind.secret_bearing() {
                        (
                            Action::Revoke {
                                kind: *kind,
                                name: name.clone(),
                            },
                            format!(
                                "if {} lists {name}, revoke it: its secret was never stored",
                                cmd_text(check)
                            ),
                        )
                    } else {
                        (
                            Action::Inspect,
                            format!(
                                "check with {} whether {name} exists before creating it again",
                                cmd_text(check)
                            ),
                        )
                    };
                    plan(Some(action), Next::Check(check.clone()))
                }
            },
            WriteOutcomeUnknown { .. } => plan(None, Next::Rerun),
            Unavailable { system, .. } => plan(
                inspect(format!(
                    "check the status page of {} or the network",
                    system.label()
                )),
                Next::Rerun,
            ),
            BudgetSpent {
                budget_seconds,
                writes_started: _,
            } => {
                let mut c = inv_cmd(inv);
                let mut args = Vec::with_capacity(c.args.len() + 2);
                let mut skip = false;
                for a in c.args.drain(..) {
                    if skip {
                        skip = false;
                        continue;
                    }
                    if a == "--timeout" {
                        skip = true;
                        continue;
                    }
                    if a.starts_with("--timeout=") {
                        continue;
                    }
                    args.push(a);
                }
                args.push("--timeout".into());
                args.push(budget_seconds.saturating_mul(2).to_string());
                c.args = args;
                plan(None, run_or_handoff(c))
            }
            Partial {
                done,
                approval_used: _,
                then,
            } => {
                let inner = then.plan(inv);
                let written = format!("already written: {}", list(done));
                let action = match (inner.action, inner.do_text) {
                    (Some(a), Some(t)) => Some((a, format!("{t} ({written})"))),
                    _ => inspect(format!("review what remains ({written})")),
                };
                plan(action, plan_read(inv))
            }
            Interrupted { .. } => plan(None, Next::Rerun),
            ChangedBeforeWrite { .. } => plan(None, Next::Rerun),
            ConcurrentEdit { object } => {
                let next = match object {
                    StoreObject::Item { .. } => match inv_env(inv) {
                        Some(env) => Next::Check(cmd(&["status"], &[env])),
                        None => Next::Check(cmd(&["status"], &[])),
                    },
                    StoreObject::File { .. } | StoreObject::Manifest { .. } => {
                        Next::Check(cmd(&["config", "describe"], &[]))
                    }
                };
                plan(
                    Some((
                        Action::PickBetween,
                        format!(
                            "check the history of {} and keep the right version",
                            store_object(object)
                        ),
                    )),
                    next,
                )
            }
            ReadBackMissing {
                vault: _,
                item,
                fields,
                by,
            } => plan(
                inspect(format!(
                    "restore {} from the history of item {item} in 1Password",
                    list_of(fields)
                )),
                Next::Run(Cmd {
                    command: by.0.split_whitespace().map(str::to_string).collect(),
                    args: vec![],
                }),
            ),
            ToolMissing { tool } => plan(
                Some((
                    Action::Install { tool: tool.clone() },
                    format!("install {tool} and make sure it is on PATH"),
                )),
                Next::Rerun,
            ),
            ToolUnusable { tool, why } => {
                let action = match why {
                    Unusable::NotExecutable => (
                        Action::Install { tool: tool.clone() },
                        format!("reinstall {tool} so it is executable"),
                    ),
                    Unusable::WslInteropOff => (
                        Action::Inspect,
                        format!("turn on WSL interop, or install the Linux build of {tool}"),
                    ),
                    Unusable::TooOld { min, .. } => (
                        Action::Install { tool: tool.clone() },
                        format!("update {tool} to {min} or later"),
                    ),
                    Unusable::VersionUnreadable => (
                        Action::Install { tool: tool.clone() },
                        format!("reinstall {tool}"),
                    ),
                    Unusable::SpawnFailed { .. } => (
                        Action::Inspect,
                        format!("check that {tool} can be started from this shell"),
                    ),
                    Unusable::WindowsExeFromWsl => (
                        Action::Install { tool: tool.clone() },
                        format!("install the Linux build of {tool} inside WSL"),
                    ),
                };
                plan(Some(action), Next::Run(cmd(&["doctor"], &[])))
            }
            UnexpectedOutput { seen, .. } => {
                let tool = exit_program(seen).to_string();
                plan(
                    Some((
                        Action::Install { tool: tool.clone() },
                        format!("update {tool} (opv doctor checks its version)"),
                    )),
                    Next::Run(cmd(&["doctor"], &[])),
                )
            }
            Unrecognized { seen, .. } => plan(
                inspect(format!(
                    "read the reply of {} shown above; opv does not recognise it",
                    exit_program(seen)
                )),
                match inv_env(inv) {
                    Some(env) => Next::Run(cmd(&["doctor"], &["--env", env])),
                    None => Next::Run(cmd(&["doctor"], &[])),
                },
            ),
            NeedsTerminal { why: _ } => plan(
                inspect("run it in your own terminal"),
                Next::Handoff(inv_cmd(inv)),
            ),
            NeedsConfirm { env } => {
                let mut c = inv_cmd(inv);
                c.args.push("--confirm".into());
                c.args.push(env.to_string());
                plan(
                    Some((
                        Action::Confirm { env: env.clone() },
                        format!(
                            "make sure {env} is the environment you mean (agents: ask the user)"
                        ),
                    )),
                    Next::Handoff(c),
                )
            }
            ConfirmMismatch { given: _, env } => plan(
                inspect("check which environment you meant"),
                Next::Check(cmd(&["plan"], &[env.as_str()])),
            ),
            ValuesNeeded { env, rows } => match rows.first() {
                Some(first) => {
                    let name = format!("{}/{}", first.product, first.key);
                    plan(
                        Some((
                            Action::FillValue {
                                product: first.product.clone(),
                                key: first.key.clone(),
                                env: env.clone(),
                            },
                            format!(
                                "{} {name} in 1Password for environment {env}",
                                value_fix(&first.state)
                            ),
                        )),
                        Next::Run(cmd(&["open"], &[&name, "--env", env.as_str()])),
                    )
                }
                None => plan(None, Next::Check(cmd(&["status"], &[env.as_str()]))),
            },
            LocalFileTooOpen {
                path,
                mode: _,
                want,
            } => plan(
                Some((
                    Action::Chmod {
                        path: path.clone(),
                        mode: *want,
                    },
                    format!("chmod {want:o} {}", shell_word(&path.display().to_string())),
                )),
                Next::Rerun,
            ),
            InputInvalid {
                path,
                kind: _,
                at,
                field,
                rule,
            } => {
                let (_, fix) = rule_words(field, rule);
                plan(
                    Some((
                        Action::EditConfig {
                            source: ConfigSource::File {
                                path: path.clone(),
                                given_by: GivenBy::Discovered,
                            },
                            field: DottedPath(vec![field.clone()]),
                        },
                        format!("edit {}{}: {fix}", path.display(), at_words(at)),
                    )),
                    Next::Rerun,
                )
            }
            ApprovalMissing { plan: id } => plan(
                Some((
                    Action::Approve { plan: id.clone() },
                    format!("approve plan {id} in your own terminal"),
                )),
                Next::Handoff(cmd(&["approve"], &[id.as_str()])),
            ),
            ApprovalUsed { plan: id, .. } => plan(
                inspect(format!(
                    "review what remains after approval {id} and approve its new plan"
                )),
                plan_read(inv),
            ),
            PlanChanged { old: _, new } => plan(
                inspect(format!("review the new plan {new}")),
                plan_read(inv),
            ),
            PlanUnknown { .. } => plan(None, plan_read(inv)),
            RamDirUnavailable { remote, why } => {
                let host = match remote {
                    Some(p) => format!("the host of remote profile {p}"),
                    None => "this machine".to_string(),
                };
                let text = match why {
                    RamDir::Unset => format!("configure an in-memory folder on {host}"),
                    RamDir::NotAbsolute => {
                        format!("make the in-memory folder on {host} an absolute path")
                    }
                    RamDir::NotOwned => format!("use an in-memory folder on {host} that you own"),
                    RamDir::NotTmpfs => format!("use a tmpfs folder on {host}"),
                    RamDir::NoneOnPlatform { os } => {
                        format!("deliver the settings without a file on {os} ({host})")
                    }
                };
                let next = if inv.command.first().map(String::as_str) == Some("run") {
                    let mut c = inv_cmd(inv);
                    c.args.push("--preview".into());
                    if carries_person_only_flag(&c) {
                        Next::Handoff(c)
                    } else {
                        Next::Check(c)
                    }
                } else {
                    Next::Run(cmd(&["doctor"], &[]))
                };
                plan(inspect(text), next)
            }
            PrivateDirFailed { dir, io: _ } => plan(
                inspect(format!(
                    "check free space and permissions in {}",
                    dir.display()
                )),
                Next::Rerun,
            ),
            RemoteUnreachable {
                profile,
                user,
                host,
                port,
            } => {
                let port = port.to_string();
                let dest = format!("{user}@{host}");
                plan(
                    inspect(format!(
                        "check the connection to {host}, and that it presents the host key pinned in remote profile {profile}"
                    )),
                    vendor(
                        "ssh",
                        &[
                            "-F",
                            "none",
                            "-o",
                            "StrictHostKeyChecking=yes",
                            "-p",
                            &port,
                            &dest,
                            "true",
                        ],
                    ),
                )
            }
            RemoteDisconnected {
                profile: _,
                host,
                during: _,
            } => plan(
                inspect(format!("check the connection to {host}")),
                Next::Rerun,
            ),
            RemoteVersionMismatch { profile, .. } => plan(
                Some((
                    Action::Install { tool: "opv".into() },
                    format!(
                        "install opv {} on the host of remote profile {profile}",
                        env!("CARGO_PKG_VERSION")
                    ),
                )),
                Next::Rerun,
            ),
            ChildStartFailed {
                program,
                workdir: _,
                io: _,
                remote,
            } => plan(
                inspect(match remote {
                    Some(p) => format!(
                        "check the command and workdir of remote profile {p} (opv config edit)"
                    ),
                    None => format!("check that {program} is on PATH"),
                }),
                Next::Rerun,
            ),
            DeliveryUnverified {
                env,
                target,
                product: _,
                state,
            } => match state {
                Unverified::NotRecorded
                | Unverified::Superseded { .. }
                | Unverified::ChangedOnTarget
                | Unverified::ChangedInOnePassword => plan(
                    None,
                    Next::Check(cmd(&["plan"], &[env.as_str(), "--target", target.as_str()])),
                ),
                Unverified::OtherAccount { account } => plan(
                    inspect(format!("check that account {account} is the one you mean")),
                    Next::Check(cmd(&["account", "list"], &[])),
                ),
                Unverified::Unverifiable => plan(None, Next::None(NoNext::NothingToRun)),
            },
            Bug { site: _ } => plan(
                inspect(format!("report this as an opv bug: {ISSUES_URL}")),
                Next::Check(cmd(&["version"], &[])),
            ),
        }
    }
}

// --- output ----------------------------------------------------------------------------------

/// `next_kind` of the document.
pub fn next_kind(n: &Next) -> &'static str {
    match n {
        Next::Rerun => "rerun",
        Next::Run(_) => "run",
        Next::Check(_) => "check",
        Next::Handoff(_) => "handoff",
        Next::Vendor(_) => "vendor",
        Next::None(_) => "none",
    }
}

/// The Next as a command line; `None` when there is nothing to run.
pub fn next_text(n: &Next, inv: &Invocation) -> Option<String> {
    match n {
        Next::Rerun => Some(rerun_text(inv)),
        Next::Run(c) | Next::Check(c) | Next::Handoff(c) => Some(cmd_text(c)),
        Next::Vendor(v) => Some(vendor_text(v)),
        Next::None(_) => None,
    }
}

fn none_words(n: NoNext) -> &'static str {
    match n {
        NoNext::PersonPicksDirection => "none: you decide which copy is right",
        NoNext::NothingToRun => "none",
    }
}

/// The account the evidence names, when the cause names one.
fn cause_account(cause: &Cause) -> Option<&AccountId> {
    match cause {
        Cause::InOtherAccount { selected, .. } => Some(selected),
        Cause::Partial { then, .. } => cause_account(then),
        _ => None,
    }
}

/// The category, by exit code.
pub fn category(exit_code: i32) -> &'static str {
    match exit_code {
        0 => "declined",
        2 => "config",
        3 => "dependency",
        4 => "source",
        5 => "target",
        6 => "policy",
        7 => "auth",
        8 => "findings",
        9 => "unknown",
        EXIT_INTERNAL => "internal",
        n if n > 128 => "interrupted",
        _ => "unknown",
    }
}

/// The terminal text (§7.1): `opv: <message>`, the `checked:` line, the upstream box,
/// `Do: …`, and `Next: …` last. Ends with a newline.
pub fn render_text(
    cause: &Cause,
    upstream: Option<&Upstream>,
    inv: &Invocation,
    verbose: bool,
    utf8: bool,
) -> String {
    let mut s = format!("opv: {}\n", cause.message());
    if let Some(seen) = cause.observed() {
        s.push_str("  ");
        s.push_str(&evidence::checked_line(seen, cause_account(cause)));
        s.push('\n');
    }
    if let Some(up) = upstream {
        s.push_str(&evidence::upstream_box(up, verbose, utf8));
    }
    let p = cause.plan(inv);
    if let Some(d) = p.do_text {
        s.push_str(&format!("Do: {d}\n"));
    }
    let next = match (&p.next, next_text(&p.next, inv)) {
        (_, Some(t)) => t,
        (Next::None(n), None) => none_words(*n).to_string(),
        (_, None) => "none".to_string(),
    };
    s.push_str(&format!("Next: {next}\n"));
    s
}

fn without_seen(v: &mut serde_json::Value) {
    if let Some(o) = v.as_object_mut() {
        o.remove("seen");
        o.remove("cause");
        if let Some(then) = o.get_mut("then") {
            without_seen(then);
        }
    }
}

/// The `error` object of the `--json` document and the MCP answer (§7.2).
pub fn document(
    cause: &Cause,
    upstream: Option<&Upstream>,
    inv: &Invocation,
    verbose: bool,
) -> serde_json::Value {
    let mut subject = serde_json::to_value(cause).unwrap_or(serde_json::Value::Null);
    without_seen(&mut subject);
    let seen = cause.observed();
    let p = cause.plan(inv);
    serde_json::json!({
        "code": cause.code(),
        "category": category(cause.exit_code()),
        "message": cause.message(),
        "subject": subject,
        "evidence": {
            "checked": seen.map(evidence::call_words),
            "account": seen
                .and_then(|s| evidence::checked_account(s, cause_account(cause)))
                .map(|a| a.to_string()),
            "upstream": upstream.map(|u| evidence::upstream_value(u, verbose)),
        },
        "retry": cause.retry(),
        "human_required": cause.human_required(inv),
        "do": p.do_text,
        "next": next_text(&p.next, inv),
        "next_kind": next_kind(&p.next),
    })
}

#[cfg(test)]
#[path = "render_tests.rs"]
mod tests;
