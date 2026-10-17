//! Rendering every [`Cause`] (design §4, §6, §7): its first line ([`Cause::message`]), its Do
//! and Next ([`Cause::step`]), the derived `human_required` (§6.3), the terminal text
//! ([`render_text`]) and the `--json`/MCP `error` object ([`document`]).
//!
//! Every word comes from the variant's typed fields; upstream text only ever reaches the
//! evidence box ([`super::evidence`]), never a message or a step (§9.3).

use super::evidence;
use super::situation::{RefusedBecause, Situation};
use super::*;
use crate::error::shell_word;

/// Flags only a person may add (§6.2): a command carrying one is always a `Handoff`.
const PERSON_ONLY_FLAGS: [&str; 4] = [
    "--confirm",
    "--approved",
    "--expect-plan",
    "--prune-immutable",
];

/// ANSI dim and reset, for the upstream box when the terminal takes colour (A8).
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

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

/// The command line of a [`Cmd`]: its argv ([`Cmd::to_argv`]), each word quoted with
/// `shell_word`.
///
/// A trailing `--` marks where the person's own child command goes (`opv run … --
/// <command>`): it renders as `-- <command>`, never as a child's words (design §6.1).
pub fn cmd_text(c: &Cmd) -> String {
    let argv = c.to_argv();
    let (words, child) = match argv.split_last() {
        Some((last, rest)) if last == "--" => (rest, true),
        _ => (argv.as_slice(), false),
    };
    let mut s = words
        .iter()
        .map(|w| shell_word(w))
        .collect::<Vec<_>>()
        .join(" ");
    if child {
        s.push_str(" -- <command>");
    }
    s
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

/// The read of a plan scope: `opv plan <env>` with every scope flag `plan` takes, or
/// `opv structure plan`.
fn scope_read(scope: &PlanScope) -> Next {
    match scope {
        PlanScope::Structural => Next::Check(cmd(&["structure", "plan"], &[])),
        PlanScope::Sync {
            env,
            targets,
            product,
            deploy: _,
            prune: _,
            rotate,
        } => {
            let mut args = vec![env.to_string()];
            push_target_product_rotate(&mut args, targets, product, rotate);
            Next::Check(Cmd {
                command: vec!["plan".into()],
                args,
            })
        }
    }
}

/// `opv approve <id>` with every scope flag (a handoff: only a person approves).
fn approve_handoff(plan: &PlanId, scope: &PlanScope) -> Next {
    let mut args = vec![plan.to_string()];
    if let PlanScope::Sync {
        env,
        targets,
        product,
        deploy,
        prune,
        rotate,
    } = scope
    {
        args.push("--sync".into());
        args.push(env.to_string());
        if *deploy {
            args.push("--deploy".into());
        }
        if *prune {
            args.push("--prune".into());
        }
        push_target_product_rotate(&mut args, targets, product, rotate);
    }
    Next::Handoff(Cmd {
        command: vec!["approve".into()],
        args,
    })
}

fn push_target_product_rotate(
    args: &mut Vec<String>,
    targets: &[TargetName],
    product: &Option<ProductName>,
    rotate: &[ProductKey],
) {
    for t in targets {
        args.push("--target".into());
        args.push(t.to_string());
    }
    if let Some(p) = product {
        args.push("--product".into());
        args.push(p.to_string());
    }
    for k in rotate {
        args.push("--rotate".into());
        args.push(k.to_string());
    }
}

/// `opv doctor`, scoped to the environment and target when the cause knows them, else to
/// the deploy credentials that acted.
fn doctor_scoped(
    env: &Option<EnvName>,
    target: &Option<TargetName>,
    principal: Option<&Principal>,
) -> Next {
    match (env, target) {
        (Some(e), Some(t)) => Next::Run(cmd(
            &["doctor"],
            &["--env", e.as_str(), "--target", t.as_str()],
        )),
        (Some(e), None) => Next::Run(cmd(&["doctor"], &["--env", e.as_str()])),
        (None, _) => doctor_for(principal, None),
    }
}

/// Flags of `sync` that `plan` takes too, with whether each takes a value.
const SYNC_FLAGS_PLAN_KEEPS: [(&str, bool); 7] = [
    ("--target", true),
    ("--product", true),
    ("--rotate", true),
    ("--json", false),
    ("--config", true),
    ("--timeout", true),
    ("--verbose", false),
];

/// The read form of a command, so a substituted name never lands in a write (§4.2): `sync`
/// becomes `plan` with the scope flags `plan` takes, `bootstrap` and `target add` get
/// `--dry-run`, `run` gets `--preview`; a read stays as it is. `None`: a write with no read
/// form (or a command opv cannot place), so Next is a listing instead.
fn read_form(c: Cmd) -> Option<Cmd> {
    let path = c.command.join(" ");
    match path.as_str() {
        "sync" => {
            let mut args = Vec::new();
            let mut words = c.args.iter();
            while let Some(a) = words.next() {
                let flag = a.split_once('=').map_or(a.as_str(), |(f, _)| f);
                if !a.starts_with('-') {
                    args.push(a.clone());
                    continue;
                }
                match SYNC_FLAGS_PLAN_KEEPS.iter().find(|(f, _)| *f == flag) {
                    Some((_, true)) if !a.contains('=') => {
                        args.push(a.clone());
                        if let Some(v) = words.next() {
                            args.push(v.clone());
                        }
                    }
                    Some(_) => args.push(a.clone()),
                    None => {
                        if sync_flag_takes_value(flag) && !a.contains('=') {
                            words.next();
                        }
                    }
                }
            }
            Some(Cmd {
                command: vec!["plan".into()],
                args,
            })
        }
        "bootstrap" | "target add" => Some(with_flag(c, "--dry-run")),
        "run" => Some(with_flag(c, "--preview")),
        _ => {
            // 09.85: `open` writes nothing (it shows a 1Password link), so a unique close
            // key is substituted into it as `explain` does, never refused for its browser.
            let effect = crate::schema::EFFECTS.iter().find(|e| e.command == path)?;
            matches!(effect.effect, "reads" | "none" | "opens_browser").then_some(c)
        }
    }
}

/// `sync` flags (other than those `plan` keeps) that take a value.
fn sync_flag_takes_value(flag: &str) -> bool {
    matches!(
        flag,
        "--confirm" | "--expect-plan" | "--receipt" | "--prune-immutable" | "--approved"
    )
}

/// E1: under `opv doctor`, a step to `opv doctor` sends the person straight back to the
/// report they are reading. The step forward is the same check with the tool's whole reply
/// (`--verbose`); once that is shown too, the command's help.
fn beyond_doctor(next: Next, inv: &Invocation) -> Next {
    let to_doctor = matches!(&next, Next::Run(c) | Next::Check(c) if c.command == ["doctor"]);
    if !to_doctor || !matches!(inv.command.as_slice(), [c] if c == "doctor") {
        return next;
    }
    if inv.args.iter().any(|a| a == "--verbose") {
        return help_of(inv);
    }
    Next::Run(with_flag(without_consent(inv_cmd(inv)), "--verbose"))
}

fn with_flag(mut c: Cmd, flag: &str) -> Cmd {
    if !c.args.iter().any(|a| a == flag) {
        c.args.push(flag.into());
    }
    c
}

fn help_of(inv: &Invocation) -> Next {
    // R26 (A19): a usage error of sync or plan steps to the plan of its environment.
    if matches!(inv.command.as_slice(), [c] if c == "sync" || c == "plan")
        && let Some(env) = inv_env(inv)
    {
        return Next::Check(cmd(&["plan"], &[env]));
    }
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

/// A vendor command as a [`Cmd`], so [`Situation::refuses`] can check it.
fn vendor_as_cmd(v: &VendorCmd) -> Cmd {
    Cmd {
        command: vec![v.program.clone()],
        args: v.args.clone(),
    }
}

/// The sign-in advice when the situation refuses an interactive sign-in (A10): under CI
/// the job's own credential, under a shell token the token itself.
fn sign_in_advice(system: System, why: RefusedBecause) -> String {
    match why {
        RefusedBecause::ShellToken => format!(
            "the token set in this shell is used for {} instead of a sign-in: replace it with a valid one, or unset it to sign in as yourself",
            system.label()
        ),
        RefusedBecause::ServiceAccount => "the service account or Connect credential in this shell decides the 1Password account: check that it is valid".to_string(),
        _ => match system {
            System::OnePassword => "give this CI job a 1Password service account token in OP_SERVICE_ACCOUNT_TOKEN (opv ci workflow prints a job that reads it)".to_string(),
            System::Fly => "set FLY_API_TOKEN in this CI job from the target's deploy credentials (opv ci workflow prints that step)".to_string(),
            System::GitHub => "set GH_TOKEN in this CI job from the target's deploy credentials (opv ci workflow prints that step)".to_string(),
            System::Azure => "sign this CI job in with the target's deploy credentials, a service principal (opv ci workflow prints that step)".to_string(),
            System::Kubernetes => "give this CI job a kubeconfig whose context carries its own credentials".to_string(),
            System::Ssh | System::RemoteOpv => "give this CI job the remote profile's ssh key".to_string(),
        },
    }
}

/// The read that shows whether the run can sign in: `opv doctor`, scoped to the
/// invocation's environment when it names one.
fn signed_in_check(inv: &Invocation) -> Next {
    match inv_env(inv) {
        Some(env) => Next::Run(cmd(&["doctor"], &["--env", env])),
        None => Next::Run(cmd(&["doctor"], &[])),
    }
}

/// `c` without `--json`, to compare a step with the invocation.
fn without_json(mut c: Cmd) -> Cmd {
    c.args.retain(|a| a != "--json");
    c
}

/// Whether the situation refuses `next`, with the command as shown. A handoff is a
/// person's own step, and a re-run is the person's own command, already run without a
/// terminal: the lack of one here refuses neither.
fn refusal(next: &Next, inv: &Invocation, sit: &Situation) -> Option<(RefusedBecause, String)> {
    let (checked, shown, persons_own) = match next {
        Next::Rerun => {
            if !matches!(inv.origin, Origin::Cli) {
                return None;
            }
            let mut c = inv_cmd(inv);
            if inv.has_child {
                c.args.push("--".into());
            }
            (c, rerun_text(inv), true)
        }
        Next::Run(c) | Next::Check(c) => (c.clone(), cmd_text(c), false),
        Next::Handoff(c) => (c.clone(), cmd_text(c), true),
        Next::Vendor(v) => (vendor_as_cmd(v), vendor_text(v), false),
        Next::None(_) => return None,
    };
    match sit.refuses(&checked) {
        Some(RefusedBecause::NoTerminal) if persons_own => None,
        Some(why) => Some((why, shown)),
        None => None,
    }
}

/// Whether `a` is one of the flags only a person may pass, in either form.
fn person_only_flag(a: &str) -> Option<bool> {
    PERSON_ONLY_FLAGS.iter().find_map(|f| {
        if a == *f {
            Some(true)
        } else if a.starts_with(&format!("{f}=")) {
            Some(false)
        } else {
            None
        }
    })
}

/// `c` without any flag only a person may pass (and its value).
fn without_consent(mut c: Cmd) -> Cmd {
    let mut args = Vec::with_capacity(c.args.len());
    let mut words = c.args.drain(..);
    while let Some(a) = words.next() {
        match person_only_flag(&a) {
            Some(true) => {
                words.next();
            }
            Some(false) => {}
            None => args.push(a),
        }
    }
    drop(words);
    c.args = args;
    c
}

/// A re-run of an invocation that carried a person's consent (A9, X4): never the consent
/// again. Its read when it writes (`sync` → `plan`), else the command without it.
fn rerun_without_consent(inv: &Invocation) -> Next {
    let stripped = without_consent(inv_cmd(inv));
    match read_form(stripped.clone()) {
        Some(c) if c != stripped => Next::Check(c),
        _ => Next::Run(stripped),
    }
}

/// `next` with the invocation's global `--config <path>` when it is a command opv built
/// that lacks it (A20, X1). It goes before a `--`, never into a child command.
fn with_global_config(next: Next, inv: &Invocation) -> Next {
    if !matches!(inv.origin, Origin::Cli) {
        return next;
    }
    let config = flag_given(inv, "--config");
    // D3 (A14): `--project` is a per-command flag; it rides along only between commands
    // that take it with the same meaning (a project name).
    let project = if takes_project(&inv.command) {
        flag_given(inv, "--project")
    } else {
        Vec::new()
    };
    if config.is_empty() && project.is_empty() {
        return next;
    }
    let add = |mut c: Cmd| {
        if c.command.is_empty() {
            return c;
        }
        let for_this = [
            ("--config", &config),
            (
                "--project",
                if takes_project(&c.command) {
                    &project
                } else {
                    &Vec::new()
                },
            ),
        ];
        for (flag, given) in for_this {
            let end = c
                .args
                .iter()
                .position(|a| a == "--")
                .unwrap_or(c.args.len());
            let has = c.args[..end]
                .iter()
                .any(|a| a == flag || a.starts_with(&format!("{flag}=")));
            if !has && !given.is_empty() {
                c.args.splice(end..end, given.iter().cloned());
            }
        }
        c
    };
    match next {
        Next::Run(c) => Next::Run(add(c)),
        Next::Check(c) => Next::Check(add(c)),
        Next::Handoff(c) => Next::Handoff(add(c)),
        other => other,
    }
}

/// The last `flag <value>` (or `flag=value`) of the invocation, as its words.
fn flag_given(inv: &Invocation, flag: &str) -> Vec<String> {
    let mut given = Vec::new();
    let mut words = inv.args.iter();
    while let Some(a) = words.next() {
        if a == flag {
            if let Some(v) = words.next() {
                given = vec![a.clone(), v.clone()];
            }
        } else if a.starts_with(&format!("{flag}=")) {
            given = vec![a.clone()];
        }
    }
    given
}

/// The commands whose `--project` names the project (D3); `skill install` and `mcp serve`
/// take a path under the same name, so they are not among them.
fn takes_project(command: &[String]) -> bool {
    let path: Vec<&str> = command.iter().map(String::as_str).collect();
    matches!(
        path.as_slice(),
        ["access"]
            | ["bootstrap"]
            | ["explain"]
            | ["init"]
            | ["target", "add"]
            | ["config", "import"]
    )
}

/// `c` with the child placeholder (`-- <command>`) when the invocation had a child
/// command (A11): its words are never stored, only that it was there.
fn with_child(mut c: Cmd, inv: &Invocation) -> Cmd {
    if inv.has_child && !c.args.iter().any(|a| a == "--") {
        c.args.push("--".into());
    }
    c
}

/// The listing that shows what a choice flag may take (A11).
fn flag_listing(flag: &str, inv: &Invocation) -> Next {
    match flag {
        "--target" => Next::Check(cmd(&["target", "list"], &[])),
        "--account" => Next::Check(cmd(&["account", "list"], &[])),
        "--env" | "--product" | "--role" | "--remote" | "--key" => {
            Next::Check(cmd(&["config", "describe"], &[]))
        }
        _ => match inv_env(inv) {
            Some(env) => Next::Check(cmd(&["status"], &[env])),
            None => Next::Check(cmd(&["config", "describe"], &[])),
        },
    }
}

/// The subscription of an Azure resource, from its scope (`subscription <id>`).
/// ` (changed: a, b, …)` for the settings named, at most five; empty for none.
fn changed_words(paths: &[String]) -> String {
    const SHOWN: usize = 5;
    match paths.len() {
        0 => String::new(),
        n if n <= SHOWN => format!(" (changed: {})", paths.join(", ")),
        n => format!(
            " (changed: {} and {} more)",
            paths[..SHOWN].join(", "),
            n - SHOWN
        ),
    }
}

fn subscription_of(r: &ResourceRef) -> Option<&str> {
    r.subscription()
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

/// `prod` for one choice, `one of dev, prod` for several.
pub(crate) fn one_of(items: &[String]) -> String {
    match items {
        [one] => one.clone(),
        many => format!("one of {}", list(many)),
    }
}

fn list_of<T: std::fmt::Display>(items: &[T]) -> String {
    items
        .iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// `account <id>`, or `accounts <id>, <id>`.
fn accounts_words(ids: &[AccountId]) -> String {
    match ids {
        [one] => format!("account {one}"),
        _ => format!("accounts {}", list_of(ids)),
    }
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
        IoKind::NotAPlainFile => {
            "it is a symbolic link or another kind of file, and opv writes only a plain file there"
        }
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
        AccountRef::Unnamed => "you use".to_string(),
        AccountRef::Any => "any account".to_string(),
    }
}

fn account_source(s: &AccountSource) -> String {
    match s {
        AccountSource::DotOpv { path } => format!("the .opv file {}", path.display()),
        AccountSource::EnvVar { var } => format!("the variable {var}"),
        AccountSource::Flag => "--account".to_string(),
        AccountSource::Environment { env } => format!("environment {env}"),
        AccountSource::OpDefault => "op's default account".to_string(),
        AccountSource::Argument => "the command line".to_string(),
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
        Principal::DeployCredentials {
            vault,
            item,
            env,
            target,
        } => {
            format!(
                "deploy credentials {item} (vault {vault}) of target {target} in environment {env}"
            )
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
        ResourceKind::KeyVaultSecret => "Key Vault secret",
        ResourceKind::Subscription => "subscription",
        ResourceKind::Secret => "Secret",
    }
}

fn resource_words(r: &ResourceRef) -> String {
    match &r.scope {
        // J4: a namespaced Kubernetes object's scope is its namespace's bare name.
        Some(ns) if matches!(r.kind, ResourceKind::Deployment | ResourceKind::Secret) => {
            format!("{} {} in namespace {ns}", resource_kind(r.kind), r.name)
        }
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
        StoreObject::Resource { resource, changed } => {
            format!("{}{}", resource_words(resource), changed_words(changed))
        }
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

/// `me@a.example (my.1password.com, AID1); …`, or how to add one when there is none.
fn account_choices(accounts: &[AccountChoice]) -> String {
    if accounts.is_empty() {
        return "none (add one in the 1Password app)".into();
    }
    accounts
        .iter()
        .map(|a| {
            let email = if a.email.is_empty() { "-" } else { &a.email };
            format!("{email} ({}, {})", a.address, a.id)
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn field_type_words(t: FieldType) -> &'static str {
    match t {
        FieldType::Concealed => "a concealed (password) field",
        FieldType::Text => "a text field",
    }
}

fn input_kind(k: InputKind) -> &'static str {
    match k {
        InputKind::Dotenv => "the .env file",
        InputKind::SetupRecipe => "the setup recipe",
        InputKind::Receipt => "the delivery receipt",
        InputKind::DeployCredentials => "the deploy credentials item",
    }
}

/// `the deploy credentials item op://v/i` (or without the reference when not known), and
/// `the .env file <path>` for a file.
fn input_words(kind: InputKind, path: &std::path::Path) -> String {
    if path.as_os_str().is_empty() {
        input_kind(kind).to_string()
    } else {
        format!("{} {}", input_kind(kind), path.display())
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
            let words = id.words();
            (
                format!("{field} must be {words}"),
                format!("change {field} to {words}"),
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
        FieldRule::Check { check } => (check.problem(field), check.fix(field)),
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
    // Kubernetes signs in per kube context; its "account" is the context (A16).
    let acct = match (account, system) {
        (Some(a), System::Kubernetes) => format!(" context {a}"),
        (Some(a), _) => format!(" account {a}"),
        (None, _) => String::new(),
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
        SessionState::EndedWithEarlierCommand => format!(
            "this 1Password write needs your own session for {sys}{acct}, which this run does \
             not have: a sign-in made inside an earlier opv command (such as its --dry-run) \
             ends with that command and does not carry over; nothing was written"
        ),
    }
}

fn unanswered_words(w: &Unanswered) -> String {
    match w {
        Unanswered::Timeout => "it timed out".into(),
        Unanswered::Killed { signal } => {
            format!("it was stopped by signal {signal} before it answered")
        }
        Unanswered::Lost => "its reply was lost before opv could read it".into(),
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
        ValueState::RuleFailed { rule, reason } => match reason {
            // The rule's name and why the value fails it, told apart (F: "rule: nonempty,
            // empty" read as one thing).
            Some(reason) if reason == crate::domain::rules::REASON_EMPTY => {
                format!("does not meet its rule {rule}: it is empty")
            }
            Some(reason) => format!("does not meet its rule {rule}: {reason}"),
            None => format!("does not meet its rule {rule}"),
        },
        ValueState::StoredAsText => "stored as plain text, not concealed".into(),
        ValueState::ConcealedConfig => "a setting stored concealed".into(),
        ValueState::FieldNotCreated => "its field does not exist yet".into(),
    }
}

/// The rows of a values finding, each `product/key[ for target t] (state)`.
fn value_rows(rows: &[ValueRow]) -> String {
    rows.iter()
        .map(|r| {
            let on = match &r.target {
                Some(t) => format!(" for target {t}"),
                None => String::new(),
            };
            format!("{}/{}{on} ({})", r.product, r.key, value_state(&r.state))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn local_op(op: LocalOp) -> &'static str {
    match op {
        LocalOp::Read => "read",
        LocalOp::Write => "write",
        LocalOp::CreateDir => "create the folder",
        LocalOp::CurrentDir => "find the current folder",
        LocalOp::CurrentExe => "find its own program file",
        LocalOp::HomeDir => "find your home folder",
        LocalOp::Stdout => "write to standard output",
        LocalOp::Stdin => "read standard input",
        LocalOp::McpHandshake => {
            "complete the MCP handshake with its client over standard input and output"
        }
        LocalOp::McpSession => {
            "keep the MCP session with its client over standard input and output"
        }
        LocalOp::RandomSource => "read the operating system's random source",
    }
}

/// A condition's reason code as shown: a CamelCase word only (names only, X19); anything
/// else is upstream free text and is never echoed.
fn reason_code(reason: &str) -> &str {
    let word = !reason.is_empty()
        && reason.len() <= 64
        && reason.chars().all(|c| c.is_ascii_alphanumeric());
    if word { reason } else { "unrecognised" }
}

/// A value 1Password shows only in edit mode: an empty field (found live, 0.9.x). The
/// person looking for it must click Edit on the item first.
fn hidden_when_empty(s: &ValueState) -> bool {
    match s {
        ValueState::Missing | ValueState::FieldNotCreated => true,
        ValueState::RuleFailed { rule, .. } => *rule == "nonempty",
        ValueState::StoredAsText | ValueState::ConcealedConfig => false,
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

/// The install line for `tool` on this platform, from the tool's own definition (FR-26):
/// the CI job's line under CI, else the platform's.
fn install_line(tool: &str, platform: crate::host::Platform, ci: bool) -> String {
    use crate::host::Platform;
    match crate::host::tool(tool) {
        Some(t) => match (ci, platform) {
            (true, _) => t.ci,
            (false, Platform::MacOs) => t.macos,
            (false, Platform::Windows) => t.windows,
            (false, Platform::Linux | Platform::Wsl | Platform::Other) => t.linux,
        }
        .to_string(),
        None => format!("install {tool} and make sure it is on PATH"),
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
    /// The step the variant chose was refused in this situation and moved into the Do
    /// for a person (design §6.4): `human_required` is then true.
    refused: bool,
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
        refused: false,
    }
}

/// The Do and Next of a refused `opv generate`, per reason (F2, R64).
fn generate_refused(
    product: &ProductName,
    key: &KeyName,
    env: &EnvName,
    reason: &GenerateRefusal,
) -> Plan {
    let fill = |words: String| {
        Some((
            Action::FillValue {
                product: product.clone(),
                key: key.clone(),
                env: env.clone(),
            },
            words,
        ))
    };
    let pk = format!("{product}/{key}");
    let open = Next::Check(cmd(&["open"], &[pk.as_str(), "--env", env.as_str()]));
    match reason {
        GenerateRefusal::ProviderIssued | GenerateRefusal::NoByteCount => plan(
            fill(format!(
                "get {pk} for environment {env} from the provider that issues it, and type it in 1Password"
            )),
            open,
        ),
        GenerateRefusal::Personal => plan(
            fill(format!("each person types their own {pk} in 1Password")),
            open,
        ),
        GenerateRefusal::Shared { from } => plan(
            inspect(format!("generate {from}, the key {pk} reads from")),
            Next::Run(cmd(&["generate"], &[env.as_str(), from.as_str()])),
        ),
        GenerateRefusal::ByteCountOutOfRange => plan(
            inspect(format!(
                "give {pk} one of base64_bytes or hex_bytes, between 16 and 1024"
            )),
            Next::Run(cmd(&["config", "edit"], &[])),
        ),
        GenerateRefusal::HasValue => plan(
            inspect(format!(
                "leave {pk} as it is, or rotate it with a reviewed sync"
            )),
            Next::Check(cmd(&["plan"], &[env.as_str(), "--rotate", pk.as_str()])),
        ),
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
            ConfigNotFound {
                searched_from,
                env,
                manifest,
            } => {
                let manifest = match manifest {
                    None => String::new(),
                    Some(ManifestSearch {
                        repo: Some(repo),
                        account: Some(a),
                    }) => {
                        format!(", and no 1Password manifest in account {a} is tagged for {repo}")
                    }
                    Some(ManifestSearch {
                        repo: Some(repo),
                        account: None,
                    }) => format!(", and no 1Password manifest is tagged for {repo}"),
                    Some(ManifestSearch { repo: None, .. }) => {
                        ", and there is no repository remote to match a 1Password manifest by"
                            .to_string()
                    }
                };
                match env {
                    Some(env) => format!(
                        "no opv configuration for environment {env} was found in {} or any folder above it{manifest}",
                        searched_from.display()
                    ),
                    None => format!(
                        "no opv configuration was found in {} or any folder above it{manifest}",
                        searched_from.display()
                    ),
                }
            }
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
                source: _,
                at: _,
            } => format!(
                "the state vault {vault} of target {target} in environment {env} is shared with targets {}, so it is wider than the values it holds",
                list_of(shared_with)
            ),
            ConfigNotEditable { source, reason } => match reason {
                NotEditable::Generated { generator } => match generator {
                    Some(g) => format!(
                        "opv does not edit {}: it is generated from {}",
                        source_words(source),
                        g.display()
                    ),
                    None => format!(
                        "opv does not edit {}: it is generated",
                        source_words(source)
                    ),
                },
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
                "{} this project: {}",
                plural(
                    candidates.len(),
                    "1Password manifest matches",
                    "1Password manifests match"
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
            KeyNotDeclared { key, env, product } => match product {
                Some(p) => format!("key {p}/{key} is not declared for environment {env}"),
                None => format!("key {key} is not declared for environment {env}"),
            },
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
                Scope::NoSecretDelivered { target } => format!(
                    "target {target} of environment {env} delivers no secret, so there is no delivery to verify"
                ),
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
                UsageProblem::EntryFormat {
                    flag,
                    entry,
                    format,
                } => format!("{flag} {entry} is not valid: {flag} expects {format}"),
                UsageProblem::NeedsFlag { flag, needs } => format!("{flag} needs {needs}"),
                UsageProblem::UseInstead { command } => {
                    format!("this is done with {} instead", cmd_text(command))
                }
                UsageProblem::FileExists { path } => format!(
                    "{} already exists, and opv replaces it only with --force",
                    path.display()
                ),
                UsageProblem::Removed { what, .. } => what.to_string(),
                UsageProblem::Rejected { message, .. } => message.clone(),
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
            } => {
                let place = if *in_app {
                    "to the 1Password app on this machine"
                } else {
                    "to op on this machine"
                };
                match account {
                    AccountRef::Unnamed => {
                        format!("the 1Password account to use is not added {place}")
                    }
                    AccountRef::Any => format!("no 1Password account is added {place}"),
                    _ => format!(
                        "1Password account {} (chosen by {}) is not added {place}",
                        account_ref(account),
                        account_source(selected_by),
                    ),
                }
            }
            AccountAmbiguous { given, candidates } => format!(
                "account {given} matches more than one 1Password account: {}",
                list_of(candidates)
            ),
            AccountRequired { accounts } => format!(
                "{} 1Password accounts are on this machine and this project names none; opv uses only the account you choose, never op's default: {}",
                accounts.len(),
                account_choices(accounts)
            ),
            InOtherAccount {
                vault,
                item,
                selected,
                owning,
                unasked,
                searched,
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
                    None if !unasked.is_empty() => format!(
                        "{what}{of_env} is not in 1Password account {selected} or in any other account opv could ask; {} could not be asked",
                        accounts_words(unasked)
                    ),
                    // #153a: every other account was asked and none holds it.
                    None if *searched => format!(
                        "{what}{of_env} is not in 1Password account {selected} or in any other account on this machine"
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
                    CredentialProblem::WrongType { field, expected } => format!(
                        "field {field} of {cred} for {sys} is not {}",
                        field_type_words(*expected)
                    ),
                    CredentialProblem::DuplicateField { field } => format!(
                        "field {field} is in {cred} for {sys} more than once, so opv cannot tell which to use"
                    ),
                }
            }
            MissingRight {
                system: System::Kubernetes,
                resource,
                right:
                    Right::Verb {
                        verb,
                        resource: kind,
                    },
                seen,
                ..
            } => match &resource.scope {
                // The namespace itself is the subject (`namespace_ref`): its scope is the
                // kube context it is in, never a namespace.
                Some(context)
                    if resource.kind == ResourceKind::Namespace
                        && context.starts_with("context ") =>
                {
                    format!(
                        "{} may not {verb} {kind} in namespace {} ({context}, Kubernetes)",
                        principal_words(seen.principal()),
                        resource.name
                    )
                }
                // A16: the verb and kind name the right; the namespace is where.
                Some(ns) => format!(
                    "{} may not {verb} {kind} in namespace {ns} (Kubernetes)",
                    principal_words(seen.principal())
                ),
                None => format!(
                    "{} may not {verb} {kind} (Kubernetes)",
                    principal_words(seen.principal())
                ),
            },
            MissingRight {
                system,
                resource,
                right,
                grant: _,
                env: _,
                target: _,
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
                named_by: _,
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
                env: _,
                target: _,
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
                    Refusal::NotRunning => format!("{what} at {sys} is not running"),
                    Refusal::InProgress { revision: None } => format!(
                        "{sys} refused the update to {what}: another change is still in progress"
                    ),
                    Refusal::InProgress { revision: Some(r) } => format!(
                        "revision {r} of {what} at {sys} is still rolling out; opv pruned nothing"
                    ),
                    Refusal::ChangedOutsideOpv { paths, after_apply } => {
                        let changed = changed_words(paths);
                        if *after_apply {
                            format!(
                                "{what} at {sys} was changed outside opv while opv's update was applied{changed}; opv's update is live, alongside that change"
                            )
                        } else {
                            format!(
                                "{what} at {sys} was changed outside opv since opv read it{changed}, so opv did not overwrite it"
                            )
                        }
                    }
                    Refusal::RevisionMode { mode, .. } => format!(
                        "{what} at {sys} runs in {mode} revision mode; opv writes only to an app in single revision mode"
                    ),
                }
            }
            Guard { guard } => match guard {
                self::Guard::ValueTooLarge {
                    product,
                    key,
                    env,
                    limit,
                } => format!(
                    "the value of {product}/{key} in environment {env} is larger than {limit} bytes, the most the target stores"
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
                self::Guard::GenerateRefused {
                    product,
                    key,
                    env,
                    reason,
                } => format!(
                    "opv does not generate {product}/{key} for environment {env}: {}",
                    reason.words()
                ),
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
            PersonalNotSetUp { env, keys, then } => format!(
                "{}; your personal item for environment {env} holds {}",
                then.message(),
                list_of(keys)
            ),
            Partial {
                done,
                approval_used,
                approval_scope: _,
                then,
            } => {
                let mut s = match then.as_ref() {
                    // F3: next to what was already written, "opv wrote nothing" is false.
                    ChangedBeforeWrite { object } if !done.is_empty() => format!(
                        "{} changed while opv was working, so opv stopped before writing the rest",
                        store_object(object)
                    ),
                    other => other.message(),
                };
                if !done.is_empty() {
                    s.push_str(&format!("; already written: {}", list(done)));
                }
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
                "after {}, fields {} of item {item} in vault {vault} were missing when read back",
                cmd_text(by),
                list_of(fields)
            ),
            ToolMissing { tool, .. } => format!("{tool} is not installed, or not on PATH"),
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
                Unusable::StoredSecretUnencrypted => format!(
                    "{tool} stored the service principal's secret unencrypted on disk; opv removed it and stopped before any change"
                ),
                Unusable::FeatureNotBuilt { feature } => {
                    format!("this build of {tool} has no {feature} feature")
                }
            },
            UnexpectedOutput {
                system,
                at,
                problem,
                during,
                seen,
            } => {
                let line = match problem {
                    OutputProblem::Unparseable => format!(
                        "opv could not read the reply of {} from {}{}",
                        exit_program(seen),
                        system.label(),
                        at_words(at)
                    ),
                    OutputProblem::Empty { what } => format!(
                        "{} answered from {} with an empty {what}{}",
                        exit_program(seen),
                        system.label(),
                        at_words(at)
                    ),
                    OutputProblem::InvalidValue { what } => format!(
                        "{} answered from {} with a {what} opv cannot use{}",
                        exit_program(seen),
                        system.label(),
                        at_words(at)
                    ),
                };
                match during {
                    During::Read => line,
                    During::AppliedWrite => {
                        format!("{line}; the change was applied at {}", system.label())
                    }
                }
            }
            Unrecognized {
                system,
                established,
                env: _,
                target: _,
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
            KeysBlocking { env, rows } => format!(
                "opv wrote nothing to environment {env}: it needs {}: {}",
                plural(rows.len(), "value", "values"),
                value_rows(rows)
            ),
            ValuesNeeded { env, rows } => format!(
                "environment {env} needs {}: {}",
                plural(rows.len(), "value", "values"),
                value_rows(rows)
            ),
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
                format!("{}{}: {what}", input_words(*kind, path), at_words(at))
            }
            ApprovalMissing { plan, scope: _ } => format!("plan {plan} is not approved yet"),
            ApprovalUsed {
                plan,
                scope: _,
                partial,
            } => {
                if *partial {
                    format!(
                        "approval {plan} is already used, and only part of its plan was applied"
                    )
                } else {
                    format!("approval {plan} is already used")
                }
            }
            // F3: the plan id was made by a read; it may never have been approved.
            PlanChanged { old, new, scope: _ } => {
                format!("the plan changed since it was made: {old} is now {new}")
            }
            // F3: the kind of plan the id was given as.
            PlanUnknown { plan, scope } => match scope {
                Some(PlanScope::Structural) => format!("no structure plan {plan} is known"),
                Some(PlanScope::Sync { env, .. }) => {
                    format!("no sync plan {plan} is known for environment {env}")
                }
                None => format!("no plan {plan} is known"),
            },
            RamDirUnavailable {
                remote,
                why,
                purpose,
                ..
            } => {
                let what = match purpose {
                    RamPurpose::FileDelivery => "the settings file",
                    RamPurpose::AzureDeployCredentials => "az's sign-in with deploy credentials",
                };
                match remote {
                    Some(p) => format!(
                        "no in-memory folder for {what} on the host of remote profile {p}: {}",
                        ram_dir_words(why)
                    ),
                    None => format!(
                        "no in-memory folder for {what} on this machine: {}",
                        ram_dir_words(why)
                    ),
                }
            }
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
                ..
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
            SourceChanged { env, no_record } => {
                if *no_record {
                    format!(
                        "no source versions are recorded for environment {env}: run opv bootstrap to record delivery items"
                    )
                } else {
                    format!("the source items of environment {env} changed since the last sync")
                }
            }
            LocalIo { op, path, io } => {
                if path.as_os_str().is_empty() {
                    format!("opv could not {}: {}", local_op(*op), io_words(*io))
                } else {
                    format!(
                        "opv could not {} {}: {}",
                        local_op(*op),
                        path.display(),
                        io_words(*io)
                    )
                }
            }
            StoreNotReady { store, reason } => match reason {
                Some(reason) => format!(
                    "{} is not ready (reason: {})",
                    resource_words(store),
                    reason_code(reason)
                ),
                None => format!("{} is not ready", resource_words(store)),
            },
            HandoffPipeContested { system } => format!(
                "another process connected to opv's private pipe for {}'s CLI and was refused; nothing was sent to it",
                system.label()
            ),
            ConfigProposalInvalid {
                source,
                field,
                rule,
                ..
            } => {
                let (what, _) = rule_words(&field.to_string(), rule);
                format!(
                    "the change opv proposed for {} would be invalid, so nothing was written: {what}",
                    source_words(source)
                )
            }
            InputUnreadable { path, kind, io } => format!(
                "opv could not read {} {}: {}",
                input_kind(*kind),
                path.display(),
                io_words(*io)
            ),
            ItemUnusable {
                vault,
                title,
                problem,
            } => {
                let place = match vault {
                    Some(v) => format!("item {title} in vault {v}"),
                    None => format!("item {title}"),
                };
                match problem {
                    ItemProblem::WrongCategory => {
                        format!("the {place} is not a Secure Note, so opv leaves it unchanged")
                    }
                    ItemProblem::DuplicateTitle => {
                        format!("more than one object in 1Password is titled {title}")
                    }
                }
            }
            SecretNotStored {
                system, kind, name, ..
            } => format!(
                "{} made the {} {name}, but its secret was never stored, so nobody holds it",
                system.label(),
                create_kind(*kind)
            ),
            SourceOnly { product, .. } => format!(
                "product {product} is source-only (source_only = true): it holds shared values \
                 for other products' keys and is never run on its own"
            ),
            TitleLookup {
                kind,
                title,
                vault,
                matches,
                candidates,
            } => {
                let place = match vault {
                    Some(v) => format!(" in vault {v}"),
                    None => String::new(),
                };
                let listed = if candidates.is_empty() {
                    "there are none to choose from".to_string()
                } else {
                    format!("candidates: {}", list(candidates))
                };
                match matches {
                    0 => format!(
                        "no {} is titled {title:?}{place} (exact, case-sensitive match); {listed}",
                        resource_kind(*kind)
                    ),
                    n => format!(
                        "{n} {}s are titled {title:?}{place}; {listed}",
                        resource_kind(*kind)
                    ),
                }
            }
            Bug { site } => format!("opv hit an internal error ({site})"),
        }
    }

    /// The Do and Next (design §4, §6.2) in this run's situation.
    pub fn step(&self, inv: &Invocation) -> (Option<Action>, Next) {
        self.step_in(inv, &Situation::current())
    }

    /// The Do and Next in `sit` (design §6.4).
    pub fn step_in(&self, inv: &Invocation, sit: &Situation) -> (Option<Action>, Next) {
        let p = self.plan_in(inv, sit);
        (p.action, p.next)
    }

    /// The Do in words, filled from the subject; `None` when there is no Do.
    pub fn do_text(&self, inv: &Invocation) -> Option<String> {
        self.do_text_in(inv, &Situation::current())
    }

    /// The Do in words in `sit`.
    pub fn do_text_in(&self, inv: &Invocation, sit: &Situation) -> Option<String> {
        self.plan_in(inv, sit).do_text
    }

    /// True exactly when the step needs a person (design §6.3).
    pub fn human_required(&self, inv: &Invocation) -> bool {
        self.human_required_in(inv, &Situation::current())
    }

    /// `human_required` in `sit`: a step the situation refused is a person's.
    pub fn human_required_in(&self, inv: &Invocation, sit: &Situation) -> bool {
        let p = self.plan_in(inv, sit);
        matches!(p.next, Next::Handoff(_))
            || p.refused
            || p.action.is_some_and(|a| a.person_only())
            || matches!(
                self,
                Cause::NeedsTerminal { .. }
                    | Cause::NeedsOwnSession { .. }
                    | Cause::NeedsConfirm { .. }
                    | Cause::ApprovalMissing { .. }
                    | Cause::CredentialRejected { .. }
            )
    }

    /// The plan in this run's situation.
    fn plan(&self, inv: &Invocation) -> Plan {
        self.plan_in(inv, &Situation::current())
    }

    /// The variant's plan, then the rules every step obeys whatever the variant chose:
    /// a re-run never repeats a person's consent (X4, A9), a built command keeps the
    /// global `--config` (X1, A20), and no step the situation refuses is rendered as the
    /// Next (X8, A10).
    fn plan_in(&self, inv: &Invocation, sit: &Situation) -> Plan {
        let mut p = self.plan_raw(inv);
        if matches!(p.next, Next::Rerun)
            && matches!(inv.origin, Origin::Cli)
            && carries_person_only_flag(&inv_cmd(inv))
        {
            p.next = rerun_without_consent(inv);
        }
        p.next = beyond_doctor(p.next, inv);
        p.next = with_global_config(p.next, inv);
        if let Cause::NotSignedIn { system, .. } = self
            && let Some(v) = vendor_sign_in(*system)
            && let Some(why) = sit.refuses(&vendor_as_cmd(&v))
        {
            p.do_text = Some(sign_in_advice(*system, why));
            p.refused = true;
            if matches!(p.next, Next::Rerun) {
                p.next = signed_in_check(inv);
            }
        } else if let Cause::NotSignedIn { system, .. } = self
            && (sit.ci || !sit.terminal)
            && matches!(p.next, Next::Rerun)
            && vendor_sign_in(*system).is_none()
            && *system != System::OnePassword
        {
            // E1: a sign-in with no command of its own (a kube context's credential refresh)
            // cannot happen in this run, so the same read again would loop. Under CI the Do is
            // the job's own credential; Next is the read that shows whether the sign-in took.
            if sit.ci {
                p.do_text = Some(sign_in_advice(*system, RefusedBecause::Ci));
                p.refused = true;
            }
            let check = signed_in_check(inv);
            if !matches!(&check, Next::Run(c) if without_json(c.clone()) == without_json(inv_cmd(inv)))
            {
                p.next = check;
            }
        }
        if let Some((why, shown)) = refusal(&p.next, inv, sit) {
            p = self.refused(p, why, &shown, inv, sit);
        }
        p
    }

    /// `p` with its refused Next moved into the Do, and Next falling back to a read.
    fn refused(
        &self,
        mut p: Plan,
        why: RefusedBecause,
        shown: &str,
        inv: &Invocation,
        sit: &Situation,
    ) -> Plan {
        let sign_in = matches!(
            self,
            Cause::NotSignedIn { .. } | Cause::InventoryIncomplete { .. }
        );
        let words = match why {
            _ if sign_in
                && matches!(
                    why,
                    RefusedBecause::Ci
                        | RefusedBecause::ServiceAccount
                        | RefusedBecause::ShellToken
                ) =>
            {
                let system = match self {
                    Cause::NotSignedIn { system, .. } => *system,
                    _ => System::OnePassword,
                };
                p.do_text = None;
                Some(sign_in_advice(system, why))
            }
            RefusedBecause::Ci => Some(format!("outside CI, in your own terminal: {shown}")),
            RefusedBecause::NoTerminal => Some(format!("in your own terminal: {shown}")),
            RefusedBecause::ServiceAccount => Some(format!(
                "in your own session, without the service account or Connect credential: {shown}"
            )),
            RefusedBecause::ShellToken => Some(sign_in_advice(System::OnePassword, why)),
            RefusedBecause::ManifestProject => Some(format!(
                "this project's configuration is a 1Password manifest, so {shown} does not apply"
            )),
            RefusedBecause::Platform => Some(format!(
                "add the account in the 1Password app and turn on its CLI integration (not {shown})"
            )),
            RefusedBecause::RemoteChild => Some(format!(
                "a remote profile runs its own command: {shown} works only without --remote"
            )),
            RefusedBecause::HiddenCommand => None,
        };
        if let Some(w) = words {
            p.do_text = Some(match p.do_text.take() {
                Some(d) => format!("{d}; {w}"),
                None => w,
            });
        }
        p.refused |= !matches!(
            why,
            RefusedBecause::HiddenCommand | RefusedBecause::ManifestProject
        );
        p.next = self.fallback(why, shown, inv, sit);
        p
    }

    /// The read a refused step falls back to (design §6.4).
    fn fallback(
        &self,
        why: RefusedBecause,
        shown: &str,
        inv: &Invocation,
        sit: &Situation,
    ) -> Next {
        let candidate = match (why, self) {
            (RefusedBecause::ManifestProject, _) if shown.starts_with("opv bootstrap") => {
                Some(Next::Check(cmd(&["structure", "plan"], &[])))
            }
            (_, Cause::NotSignedIn { .. } | Cause::CredentialRejected { .. }) => {
                Some(signed_in_check(inv))
            }
            _ => {
                let stripped = without_consent(inv_cmd(inv));
                read_form(stripped.clone())
                    .filter(|c| *c != inv_cmd(inv))
                    .map(Next::Check)
            }
        };
        // F1, X11: a refused step never leaves Next empty. The read of the same scope first,
        // then the command's help, then opv's own help (a read nothing refuses).
        let help = help_of(inv);
        let top = Next::Check(cmd(&["help"], &[]));
        candidate
            .into_iter()
            .chain([help, top])
            .map(|n| with_global_config(n, inv))
            .find(|n| refusal(n, inv, sit).is_none())
            .unwrap_or(Next::None(NoNext::NothingToRun))
    }

    fn plan_raw(&self, inv: &Invocation) -> Plan {
        use Cause::*;
        match self {
            PersonalNotSetUp { then, .. } => then.plan_raw(inv),
            ConfigNotFound {
                searched_from: _,
                env,
                manifest: _,
            } => plan(
                // P3: the first-run router's other starting paths.
                inspect(
                    "start one with opv init, run opv setup when the project ships opv.setup.toml, \
                     point to one with --config <path>, or list the manifests in your other \
                     accounts with opv projects",
                ),
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
            ConfigUnreadable { path, io, given_by } => plan(
                inspect(match given_by {
                    GivenBy::Flag { flag } => format!("check the path given with {flag}"),
                    GivenBy::EnvVar { var } => format!("check the path in {var}"),
                    GivenBy::Discovered => {
                        format!("check that you can read {}", path.display())
                    }
                }),
                match io {
                    IoKind::NotFound => Next::Run(cmd(&["doctor"], &[])),
                    _ => Next::Rerun,
                },
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
                    rerun_as_read(inv),
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
                source,
                at,
            } => {
                let place = match source {
                    ConfigSource::File { path, .. } => {
                        format!(" in {}{}", path.display(), at_words(at))
                    }
                    ConfigSource::Manifest { title, .. } => {
                        format!(" in the manifest {title} (opv config edit)")
                    }
                };
                plan(
                    Some((
                        Action::EditConfig {
                            source: source.clone(),
                            field: DottedPath(vec![
                                "environments".into(),
                                env.to_string(),
                                "targets".into(),
                                target.to_string(),
                                "state_vault_id".into(),
                            ]),
                        },
                        format!(
                            "delete state_vault_id from [environments.{env}.targets.{target}]{place} so opv makes a vault for this target alone"
                        ),
                    )),
                    match source {
                        ConfigSource::File { .. } => Next::Run(cmd(&["bootstrap"], &[])),
                        ConfigSource::Manifest { .. } => {
                            Next::Check(cmd(&["structure", "plan"], &[]))
                        }
                    },
                )
            }
            ConfigNotEditable { source, reason } => {
                let next = match reason {
                    // The fix is in the generator's input, outside opv; its configuration is
                    // generated again from there (retry never: no opv command makes progress).
                    NotEditable::Generated { .. } => Next::None(NoNext::NothingToRun),
                    _ => Next::Run(cmd(&["config", "edit"], &[])),
                };
                plan(
                    inspect(match reason {
                    NotEditable::Generated { generator } => match generator {
                        Some(g) => format!(
                            "change {} instead, and generate the configuration again",
                            g.display()
                        ),
                        None => "change its generator's input instead, and generate the configuration again".to_string(),
                    },
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
                    next,
                )
            }
            // A14: the person picks the direction, but no step is person-only.
            CopiesDiffer { file, manifest } => plan(
                Some((
                    Action::Inspect,
                    format!(
                        "decide which is right: update {} (opv config export --toml > {}) or the manifest {manifest} (opv config edit)",
                        file.display(),
                        shell_word(&file.display().to_string())
                    ),
                )),
                Next::None(NoNext::PersonPicksDirection),
            ),
            ManifestNotFound { project, account } => plan(
                inspect(match account {
                    Some(a) => format!(
                        "check that project {project} is the one you mean, and that account {a} holds its manifest"
                    ),
                    None => format!("check that project {project} is the one you mean"),
                }),
                Next::Check(cmd(&["projects"], &[])),
            ),
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
            ManifestExists { local_file, .. } => plan(
                None,
                match local_file {
                    Some(f) => Next::Check(Cmd {
                        command: vec!["config".into(), "check".into()],
                        args: vec!["--file".into(), f.display().to_string()],
                    }),
                    None => Next::Run(cmd(&["config", "edit"], &[])),
                },
            ),
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
            } => {
                let path: Vec<&str> = inv.command.iter().map(String::as_str).collect();
                let substitute = closest
                    .as_ref()
                    .and_then(|c| substituted(inv, given, c.as_str()));
                let next = match (kind, path.as_slice(), substitute) {
                    // F2 (R21): `opv add` into an undeclared environment declares it first.
                    (NameKind::Environment, ["add"], _) => {
                        Next::Run(cmd(&["env", "add"], &[given.as_str()]))
                    }
                    // F4: setup is a person's guided command; the near name is theirs to run.
                    (_, ["setup"], Some(c)) => Next::Handoff(c),
                    (_, _, Some(c)) => match read_form(c) {
                        Some(c) => run_or_handoff(c),
                        None => name_listing(*kind, inv),
                    },
                    (_, _, None) => name_listing(*kind, inv),
                };
                plan(None, next)
            }
            KeyNotDeclared { key, env, .. } => plan(
                inspect(format!(
                    "declare {key} for environment {env} (opv add), or use a key it declares"
                )),
                Next::Check(cmd(&["config", "describe"], &[])),
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
                    plan(None, run_or_handoff(with_child(c, inv)))
                }
                // A11: the listing of what may be picked, never `none`.
                _ => plan(
                    Some((
                        Action::PickBetween,
                        format!("pick one of {} and pass it with {flag}", list(candidates)),
                    )),
                    flag_listing(flag, inv),
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
                Scope::NoSecretDelivered { .. } => {
                    plan(None, Next::Check(cmd(&["status"], &[env.as_str()])))
                }
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
                    UsageProblem::UseInstead { command }
                    | UsageProblem::Removed {
                        instead: command, ..
                    } => run_or_handoff(command.clone()),
                    UsageProblem::Rejected { help, .. } => {
                        let mut command = help.clone();
                        command.push("--help".into());
                        Next::Check(Cmd {
                            command,
                            args: Vec::new(),
                        })
                    }
                    // F4: replacing a file is the person's call.
                    UsageProblem::FileExists { .. } => {
                        Next::Handoff(with_child(with_flag(inv_cmd(inv), "--force"), inv))
                    }
                    UsageProblem::UnknownFlag { closest: None, .. }
                    | UsageProblem::MisplacedBeforeDashDash { .. }
                    | UsageProblem::ConflictsWith { .. }
                    | UsageProblem::ValueFormat { .. }
                    | UsageProblem::EntryFormat { .. }
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
                } else if *system == System::Kubernetes {
                    // A16: a kubeconfig credential refresh, per context.
                    (
                        Action::SignIn {
                            system: *system,
                            account: account.clone(),
                        },
                        match account {
                            Some(c) => format!(
                                "refresh the credentials of kube context {c} with the sign-in of its auth provider"
                            ),
                            None => "refresh the credentials of the current kube context with the sign-in of its auth provider".to_string(),
                        },
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
                    // `opv login` itself, or an MCP call with no command line to repeat: the
                    // step is the login alone, never a login inside a login.
                    if matches!(inv.origin, crate::cause::Origin::Cli)
                        && !inv.command.is_empty()
                        && inv.command.first().map(String::as_str) != Some("login")
                    {
                        args.push("--".into());
                        args.push("opv".into());
                        args.extend(inv.command.iter().cloned());
                        args.extend(inv.args.iter().cloned());
                    }
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
                let who = match account {
                    AccountRef::Unnamed => "the account you use".to_string(),
                    AccountRef::Any => "a 1Password account (any one you use)".to_string(),
                    a => format!("account {}", account_ref(a)),
                };
                let text = if *in_app {
                    format!("add {who} in the 1Password app and turn on its CLI integration")
                } else {
                    format!("add {who} at op's prompt")
                };
                let next = if *in_app {
                    Next::Handoff(cmd(&["login"], &[]))
                } else {
                    match account {
                        AccountRef::Email(e) => {
                            Next::Handoff(cmd(&["login"], &["--add", "--account", e]))
                        }
                        AccountRef::Id(_)
                        | AccountRef::Shorthand(_)
                        | AccountRef::Unnamed
                        | AccountRef::Any => Next::Handoff(cmd(&["login"], &["--add"])),
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
            // Never a guessed account (X2): the person picks, in their own terminal.
            AccountRequired { .. } => plan(
                Some((
                    Action::PickBetween,
                    "pick the project's account: run opv login --account <email or account ID> in your own terminal".to_string(),
                )),
                Next::Check(cmd(&["account", "list"], &[])),
            ),
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
                selected,
                owning,
                unasked,
                searched,
                env,
                seen: _,
            } => {
                let fix = match env {
                    Some(e) => format!("fix vault_id for environment {e}"),
                    None => "fix the vault ID in the configuration".to_string(),
                };
                match (owning, unasked.first()) {
                    // #153a: the account that holds it is known; a person picks between
                    // selecting it and fixing the configuration.
                    (Some(o), _) => plan(
                        Some((
                            Action::PickBetween,
                            format!("select account {o} (opv account use {o}), or {fix}"),
                        )),
                        Next::Run(cmd(&["account", "use"], &[o.as_str()])),
                    ),
                    // No account opv could ask holds it: sign in to the first it could not
                    // ask, for this check only, and look again.
                    (None, Some(first)) => plan(
                        Some((
                            Action::SignIn {
                                system: System::OnePassword,
                                account: Some(first.clone()),
                            },
                            format!(
                                "sign in to {} to look for vault {vault} there, or {fix}",
                                accounts_words(unasked)
                            ),
                        )),
                        Next::Handoff(cmd(
                            &["login"],
                            &[
                                "--account",
                                first.as_str(),
                                "--no-record",
                                "--",
                                "opv",
                                "vault",
                                "locate",
                                vault.as_str(),
                            ],
                        )),
                    ),
                    // #153a: the search already asked every other account and none holds
                    // it, so `vault locate` would only repeat it: the vault ID is wrong for
                    // this environment, and the selected account's listing shows the right one.
                    (None, None) if *searched => plan(
                        inspect(format!(
                            "no 1Password account on this machine holds vault {vault}: {fix} with a vault of account {selected}"
                        )),
                        vendor("op", &["vault", "list", "--account", selected.as_str()]),
                    ),
                    (None, None) => plan(
                        inspect(format!("find the account that holds vault {vault}, or {fix}")),
                        Next::Run(cmd(&["vault", "locate"], &[vault.as_str()])),
                    ),
                }
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
                    CredentialProblem::WrongType { field, expected } => (
                        Action::Inspect,
                        format!(
                            "make field {field} of {cred} {} in 1Password",
                            field_type_words(*expected)
                        ),
                    ),
                    CredentialProblem::DuplicateField { field } => (
                        Action::Inspect,
                        format!("keep one field {field} in {cred} and remove the others"),
                    ),
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
                env,
                target,
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
                doctor_scoped(env, target, Some(seen.principal())),
            ),
            OwnerSetupRequired { system, object } => {
                let text = match object.kind {
                    ResourceKind::GitHubEnvironment => match &object.scope {
                        // The typed owner action (design §4.4): the admin's exact call.
                        Some(repo) => format!(
                            "ask a repository admin to create {} (gh api -X PUT \
                             repos/{repo}/environments/{})",
                            resource_words(object),
                            object.name
                        ),
                        None => format!(
                            "ask a repository admin to create {}",
                            resource_words(object)
                        ),
                    },
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
                    | ResourceKind::Repository
                    | ResourceKind::KeyVaultSecret
                    | ResourceKind::Secret
                    | ResourceKind::Subscription => format!(
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
                named_by,
                state,
                seen: _,
            } => {
                let what = resource_words(resource);
                let name = resource.name.as_str();
                let text = match state {
                    NotFoundState::Missing => match named_by {
                        NamedBy::ConfigField { path } => {
                            format!("check {path}, which names {what} (opv config edit)")
                        }
                        NamedBy::Flag { flag } => {
                            format!("check the name given with {flag}, which names {what}")
                        }
                        // The field is unset: opv looked for its default names, so the fix
                        // is to set it, never to "check" a value nobody wrote.
                        NamedBy::UnsetField { path } => format!(
                            "set {path} to the name to use (opv config edit); with it unset, opv looked for {what}"
                        ),
                    },
                    NotFoundState::SoftDeleted => match (system, resource.kind) {
                        (System::Azure, ResourceKind::KeyVault) => {
                            let mut line = format!(
                                "recover it: az keyvault recover --name {}",
                                shell_word(name)
                            );
                            if let Some(sub) = subscription_of(resource) {
                                line.push_str(&format!(" --subscription {}", shell_word(sub)));
                            }
                            line
                        }
                        (System::Azure, ResourceKind::KeyVaultSecret) => {
                            match resource.key_vault() {
                                Some(vault) => {
                                    let mut line = format!(
                                        "recover it: az keyvault secret recover --vault-name {} --name {}",
                                        shell_word(vault),
                                        shell_word(name)
                                    );
                                    if let Some(sub) = subscription_of(resource) {
                                        line.push_str(&format!(
                                            " --subscription {}",
                                            shell_word(sub)
                                        ));
                                    }
                                    line
                                }
                                None => format!("recover {what} at {}", system.label()),
                            }
                        }
                        _ => format!("recover {what} at {}", system.label()),
                    },
                    NotFoundState::LocalContextMissing => {
                        format!("get credentials for {what} on this machine")
                    }
                };
                let next = match (system, state) {
                    (System::Azure, NotFoundState::SoftDeleted) => match resource.kind {
                        ResourceKind::KeyVaultSecret => {
                            match (resource.key_vault(), subscription_of(resource)) {
                                (Some(vault), Some(sub)) => vendor(
                                    "az",
                                    &[
                                        "keyvault",
                                        "secret",
                                        "list-deleted",
                                        "--vault-name",
                                        vault,
                                        "--subscription",
                                        sub,
                                    ],
                                ),
                                (Some(vault), None) => vendor(
                                    "az",
                                    &["keyvault", "secret", "list-deleted", "--vault-name", vault],
                                ),
                                (None, _) => vendor("az", &["keyvault", "list"]),
                            }
                        }
                        _ => match subscription_of(resource) {
                            Some(sub) => {
                                vendor("az", &["keyvault", "list-deleted", "--subscription", sub])
                            }
                            None => vendor("az", &["keyvault", "list-deleted"]),
                        },
                    },
                    // A16: the context listing only for a missing context.
                    (System::Kubernetes, NotFoundState::LocalContextMissing) => {
                        vendor("kubectl", &["config", "get-contexts"])
                    }
                    (System::Kubernetes, _) => match (resource.kind, &resource.scope) {
                        (ResourceKind::KubeContext, _) => {
                            vendor("kubectl", &["config", "get-contexts"])
                        }
                        (ResourceKind::ExternalStore, _) => {
                            vendor("kubectl", &["get", "clustersecretstores"])
                        }
                        (ResourceKind::Deployment, Some(ns)) => {
                            vendor("kubectl", &["get", "deployments", "--namespace", ns])
                        }
                        _ => vendor("kubectl", &["get", "namespaces"]),
                    },
                    (System::Fly, _) => vendor("flyctl", &["apps", "list"]),
                    (System::Azure, _) => match resource.kind {
                        ResourceKind::ContainerApp => vendor("az", &["containerapp", "list"]),
                        ResourceKind::Subscription => vendor("az", &["account", "list"]),
                        _ => match subscription_of(resource) {
                            Some(sub) => vendor("az", &["keyvault", "list", "--subscription", sub]),
                            None => vendor("az", &["keyvault", "list"]),
                        },
                    },
                    (System::GitHub, _) => vendor("gh", &["repo", "list"]),
                    (System::OnePassword, _) => match (resource.kind, &resource.scope) {
                        // Under `vault locate` itself, the step is op's own listing, never
                        // the same command again.
                        (ResourceKind::Vault, _) if inv.command == ["vault", "locate"] => {
                            vendor("op", &["vault", "list"])
                        }
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
                env,
                target,
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
                    Refusal::NotRunning => format!("check the logs of {what} for why it stopped"),
                    Refusal::InProgress { revision: None } => {
                        format!("wait for the change in progress on {what} to finish")
                    }
                    Refusal::InProgress {
                        revision: Some(r),
                    } => format!("wait for revision {r} of {what} to finish rolling out"),
                    Refusal::ChangedOutsideOpv {
                        after_apply: false,
                        ..
                    } => format!(
                        "check who changed {what} and whether opv's values should replace theirs"
                    ),
                    Refusal::ChangedOutsideOpv {
                        after_apply: true,
                        ..
                    } => format!("check who changed {what} and that both changes belong there"),
                    Refusal::RevisionMode {
                        resource_group,
                        subscription,
                        ..
                    } => format!(
                        "ask an owner of {what} to switch it to single revision mode: az containerapp revision set-mode --mode single --resource-group {} --name {} --subscription {}",
                        shell_word(resource_group),
                        shell_word(subject.name.as_str()),
                        shell_word(subscription)
                    ),
                };
                // Only an owner of the app changes its revision mode; opv never does.
                let action = match why {
                    Refusal::RevisionMode { .. } => Some((
                        Action::OwnerSetup {
                            object: subject.clone(),
                        },
                        text,
                    )),
                    _ => inspect(text),
                };
                plan(action, doctor_scoped(env, target, Some(seen.principal())))
            }
            Guard { guard } => match guard {
                self::Guard::ValueTooLarge {
                    product,
                    key,
                    env,
                    limit,
                } => plan(
                    Some((
                        Action::FillValue {
                            product: product.clone(),
                            key: key.clone(),
                            env: env.clone(),
                        },
                        format!(
                            "shorten the value of {product}/{key} for environment {env} in 1Password to {limit} bytes or less"
                        ),
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
                // F2 (R46): the values come from the person, never from the provider.
                self::Guard::ProviderHidesValues { system: _ } => plan(
                    inspect(
                        "put the values in a private dotenv file (chmod 600) or type them in 1Password",
                    ),
                    match (inv.command.as_slice(), inv_env(inv)) {
                        ([c], Some(env)) if c == "adopt" => {
                            Next::Check(cmd(&["adopt"], &[env, "--help"]))
                        }
                        _ => help_of(inv),
                    },
                ),
                self::Guard::ImmutableWithoutRotate { key } => plan(
                    inspect(format!("rotate {key} if it must change")),
                    help_of(inv),
                ),
                self::Guard::GenerateRefused {
                    product,
                    key,
                    env,
                    reason,
                } => generate_refused(product, key, env, reason),
                self::Guard::RemoteProfileRefuses {
                    profile, allowed, ..
                } => plan(
                    inspect(format!(
                        "use {} with remote profile {profile}, or change the profile (opv config edit)",
                        one_of(allowed)
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
                Refind::Vendor(check) => {
                    let text = vendor_text(check);
                    let action = if kind.secret_bearing() {
                        (
                            Action::Revoke {
                                kind: *kind,
                                name: name.clone(),
                            },
                            format!(
                                "if {text} lists {name}, revoke it: its secret was never stored"
                            ),
                        )
                    } else {
                        (
                            Action::Inspect,
                            format!(
                                "check with {text} whether {name} exists before creating it again"
                            ),
                        )
                    };
                    plan(Some(action), Next::Vendor(check.clone()))
                }
            },
            WriteOutcomeUnknown { .. } => plan(None, Next::Rerun),
            Unavailable { system, seen, .. } => {
                // A17: the status page link; A21: a person's op may be waiting on the app.
                let page = match crate::host::tool(exit_program(seen)) {
                    Some(t) if !t.status_page.is_empty() => format!(
                        "check {}'s status page ({}) or the network",
                        system.label(),
                        t.status_page
                    ),
                    _ => format!("check the status page of {} or the network", system.label()),
                };
                let text = match (system, seen.principal()) {
                    (System::OnePassword, Principal::Person { .. }) => format!(
                        "approve the 1Password app's prompt if it shows one; otherwise {page}"
                    ),
                    _ => page,
                };
                plan(inspect(text), Next::Rerun)
            }
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
                approval_scope,
                then,
            } => {
                let inner = then.plan_raw(inv);
                // A15: an empty `done` names nothing as written.
                let action = match (inner.action, inner.do_text, done.is_empty()) {
                    (Some(a), Some(t), true) => Some((a, t)),
                    (Some(a), Some(t), false) => {
                        Some((a, format!("{t} (already written: {})", list(done))))
                    }
                    (_, _, true) => inspect("review what remains"),
                    (_, _, false) => inspect(format!(
                        "review what remains (already written: {})",
                        list(done)
                    )),
                };
                let path: Vec<&str> = inv.command.iter().map(String::as_str).collect();
                let next = match (approval_scope, path.as_slice()) {
                    (Some(scope), _) => scope_read(scope),
                    // A22: what `target credentials` made is read back with its show form.
                    (None, ["target", "credentials"]) => {
                        let mut c = without_consent(inv_cmd(inv));
                        c.args.retain(|a| a != "--create");
                        Next::Check(c)
                    }
                    // F4: setup's remaining steps are read by doctor, not a structure plan.
                    (None, ["setup"]) => Next::Run(cmd(&["doctor"], &[])),
                    // C8: `mcp install`'s own failure (a usage conflict) steps to its own
                    // Next, never a structure plan.
                    (None, ["mcp", "install"]) => inner.next,
                    (None, _) => plan_read(inv),
                };
                plan(action, next)
            }
            Interrupted { .. } => plan(None, Next::Rerun),
            ChangedBeforeWrite { .. } => plan(None, Next::Rerun),
            ConcurrentEdit { object } => {
                let next = match object {
                    StoreObject::Item { .. } | StoreObject::Resource { .. } => match inv_env(inv) {
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
            } => {
                let text = if by.command == ["tidy"] {
                    format!(
                        "restore {} from the history of item {item} in 1Password",
                        list_of(fields)
                    )
                } else {
                    format!(
                        "check item {item} in 1Password: another edit may have removed {} after opv wrote {}",
                        list_of(fields),
                        if fields.len() == 1 { "it" } else { "them" }
                    )
                };
                plan(inspect(text), Next::Run(by.clone()))
            }
            ToolMissing {
                tool,
                platform,
                shell: _,
                ci,
            } => plan(
                Some((
                    Action::Install { tool: tool.clone() },
                    install_line(tool, *platform, *ci),
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
                    Unusable::StoredSecretUnencrypted => (
                        Action::Install { tool: tool.clone() },
                        format!(
                            "update {tool} to a build that encrypts its stored credentials (AZURE_CORE_ENCRYPT_TOKEN_CACHE)"
                        ),
                    ),
                    Unusable::FeatureNotBuilt { feature } => (
                        Action::Install { tool: tool.clone() },
                        format!("install a release build of {tool}, which has the {feature} feature"),
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
            Unrecognized {
                system,
                env,
                target,
                seen,
                ..
            } => plan(
                inspect(format!(
                    "read the reply of {} shown above; opv does not recognise it",
                    exit_program(seen)
                )),
                match system {
                    // A12: opv doctor does not check ssh; the full reply does.
                    System::Ssh => {
                        let c = with_flag(without_consent(inv_cmd(inv)), "--verbose");
                        match read_form(c.clone()) {
                            Some(r) if r != c => Next::Check(with_flag(r, "--verbose")),
                            _ => Next::Run(c),
                        }
                    }
                    _ => doctor_scoped(env, target, Some(seen.principal())),
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
                let c = with_child(c, inv);
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
            // A18 (01.12): only the person knows which environment they meant.
            ConfirmMismatch { given: _, env } => plan(
                Some((
                    Action::Confirm { env: env.clone() },
                    "check which environment you meant".to_string(),
                )),
                Next::Check(cmd(&["plan"], &[env.as_str()])),
            ),
            ValuesNeeded { env, rows } | KeysBlocking { env, rows } => match rows.first() {
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
                                "{} {name} in 1Password for environment {env}{}",
                                value_fix(&first.state),
                                if rows.iter().any(|r| hidden_when_empty(&r.state)) {
                                    " (click Edit on the item: it hides empty fields until then)"
                                } else {
                                    ""
                                }
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
                kind: InputKind::DeployCredentials,
                field,
                rule,
                ..
            } => {
                // A field of a 1Password item, which only a person edits.
                let (_, fix) = rule_words(field, rule);
                plan(
                    inspect(format!(
                        "in 1Password, open {} and {fix}",
                        input_words(InputKind::DeployCredentials, path)
                    )),
                    Next::Rerun,
                )
            }
            InputInvalid {
                path,
                kind: InputKind::Dotenv,
                at,
                field,
                rule,
            } => {
                // A `.env` holds secret values only a person may open, so the Do is a
                // person's edit of that file.
                let (_, fix) = rule_words(field, rule);
                plan(
                    Some((
                        Action::EditInput { path: path.clone() },
                        format!("edit {}{}: {fix}", path.display(), at_words(at)),
                    )),
                    Next::Rerun,
                )
            }
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
            ApprovalMissing { plan: id, scope } => plan(
                Some((
                    Action::Approve { plan: id.clone() },
                    format!("approve plan {id} in your own terminal"),
                )),
                approve_handoff(id, scope),
            ),
            ApprovalUsed {
                plan: id, scope, ..
            } => plan(
                inspect(format!(
                    "review what remains after approval {id} and approve its new plan"
                )),
                scope_read(scope),
            ),
            PlanChanged { old: _, new, scope } => plan(
                inspect(format!("review the new plan {new}")),
                scope_read(scope),
            ),
            PlanUnknown { scope, .. } => plan(
                None,
                match scope {
                    Some(s) => scope_read(s),
                    None => plan_read(inv),
                },
            ),
            RamDirUnavailable {
                remote,
                why,
                purpose: RamPurpose::AzureDeployCredentials,
                ..
            } => {
                // az keeps the service principal's secret in its configuration folder, so
                // opv signs in only where that folder is held in memory (06.49): the way
                // out is this machine's runtime folder, or a machine that has one; never a
                // change to how everyone deploys the environment.
                let host = match remote {
                    Some(p) => format!("the host of remote profile {p}"),
                    None => "this machine".to_string(),
                };
                let text = match why {
                    RamDir::Unset => format!(
                        "start a login session with a runtime folder (XDG_RUNTIME_DIR) on {host}; on WSL, enable systemd in /etc/wsl.conf"
                    ),
                    RamDir::NotAbsolute => {
                        format!("set XDG_RUNTIME_DIR on {host} to an absolute path")
                    }
                    RamDir::NotOwned => {
                        format!("set XDG_RUNTIME_DIR on {host} to a runtime folder you own")
                    }
                    RamDir::NotTmpfs => {
                        format!("set XDG_RUNTIME_DIR on {host} to a tmpfs folder")
                    }
                    RamDir::NoneOnPlatform { os } => format!(
                        "deploy to Azure with deploy credentials from a Linux or Windows machine; {os} has no in-memory folder for az's sign-in"
                    ),
                };
                plan(inspect(text), Next::Rerun)
            }
            RamDirUnavailable {
                remote,
                why,
                purpose: RamPurpose::FileDelivery,
                env,
                product,
            } => {
                let host = match remote {
                    Some(p) => format!("the host of remote profile {p}"),
                    None => "this machine".to_string(),
                };
                let text = match why {
                    RamDir::Unset => format!(
                        "start a login session with a runtime folder (XDG_RUNTIME_DIR) on {host}; on WSL, enable systemd in /etc/wsl.conf"
                    ),
                    RamDir::NotAbsolute => {
                        format!("set XDG_RUNTIME_DIR on {host} to an absolute path")
                    }
                    RamDir::NotOwned => {
                        format!("set XDG_RUNTIME_DIR on {host} to a runtime folder you own")
                    }
                    RamDir::NotTmpfs => {
                        format!("set XDG_RUNTIME_DIR on {host} to a tmpfs folder")
                    }
                    RamDir::NoneOnPlatform { os } => {
                        format!("deliver the settings without a file on {os} ({host})")
                    }
                };
                let next = if let (Some(env), Some(product)) = (env, product) {
                    let mut args = vec![
                        env.to_string(),
                        "--product".to_string(),
                        product.to_string(),
                    ];
                    if let Some(p) = remote {
                        args.push("--remote".into());
                        args.push(p.to_string());
                    }
                    args.push("--preview".into());
                    Next::Check(Cmd {
                        command: vec!["run".into()],
                        args,
                    })
                } else if inv.command.first().map(String::as_str) == Some("run") {
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
                known_hosts,
                identity_file,
            } => {
                let mut args: Vec<String> = ["-F", "none", "-o", "StrictHostKeyChecking=yes", "-o"]
                    .iter()
                    .map(|a| a.to_string())
                    .collect();
                args.push(format!("UserKnownHostsFile={}", known_hosts.display()));
                // A12: the profile's identity file, as opv's own connection uses it.
                if let Some(key) = identity_file {
                    args.push("-i".into());
                    args.push(key.display().to_string());
                    args.push("-o".into());
                    args.push("IdentitiesOnly=yes".into());
                }
                args.push("-p".into());
                args.push(port.to_string());
                args.push(format!("{user}@{host}"));
                args.push("true".into());
                plan(
                    inspect(format!(
                        "check the connection to {host}, and that it presents the host key pinned in remote profile {profile}"
                    )),
                    Next::Vendor(VendorCmd {
                        program: "ssh".into(),
                        args,
                    }),
                )
            }
            RemoteDisconnected {
                profile: _,
                host,
                during: _,
            } => {
                let next = if inv.has_child {
                    Next::Rerun
                } else {
                    run_or_handoff(inv_cmd(inv))
                };
                plan(inspect(format!("check the connection to {host}")), next)
            }
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
                    // The Next re-run shows the child as `<command>` (§6.1), so the Do says
                    // what goes there: the program that failed to start, with its arguments.
                    None if inv.has_child && matches!(inv.origin, Origin::Cli) => format!(
                        "check that {program} is on PATH; <command> is {program} and its arguments"
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
                // 01.06: a delivery never made is a scoped plan away.
                Unverified::NotRecorded => plan(
                    None,
                    Next::Check(cmd(&["plan"], &[env.as_str(), "--target", target.as_str()])),
                ),
                Unverified::Superseded { receipt } => plan(
                    inspect(format!(
                        "verify the later delivery instead: its receipt is {}",
                        receipt.display()
                    )),
                    Next::Check(cmd(&["plan"], &[env.as_str(), "--target", target.as_str()])),
                ),
                Unverified::ChangedOnTarget | Unverified::ChangedInOnePassword => plan(
                    None,
                    Next::Check(cmd(&["plan"], &[env.as_str(), "--target", target.as_str()])),
                ),
                Unverified::OtherAccount { account } => plan(
                    inspect(format!("check that account {account} is the one you mean")),
                    Next::Handoff(cmd(&["login"], &["--account", account.as_str()])),
                ),
                Unverified::Unverifiable => plan(None, Next::None(NoNext::NothingToRun)),
            },
            SourceChanged { env, no_record } => {
                if *no_record {
                    plan(
                        inspect("run opv bootstrap to record delivery items"),
                        Next::Handoff(cmd(&["bootstrap"], &[])),
                    )
                } else {
                    plan(None, Next::Run(cmd(&["sync"], &[env.as_str(), "--deploy"])))
                }
            }
            LocalIo {
                path,
                io: IoKind::NotAPlainFile,
                ..
            } => plan(
                inspect(format!(
                    "replace {} with a plain file: remove the link (or other file) there, and opv writes a new one",
                    path.display()
                )),
                Next::Rerun,
            ),
            LocalIo { op, path, io: _ } => plan(
                inspect(match op {
                    LocalOp::Stdout => {
                        "check where standard output goes (a closed pipe, a full disk)".to_string()
                    }
                    LocalOp::Stdin => "answer at the prompt, or run this in a terminal".to_string(),
                    LocalOp::McpHandshake | LocalOp::McpSession => {
                        "check that the assistant's client starts opv mcp serve and speaks MCP over standard input and output".to_string()
                    }
                    LocalOp::CurrentDir => "check that the current folder still exists".to_string(),
                    LocalOp::HomeDir => "check that HOME is set".to_string(),
                    LocalOp::CurrentExe => {
                        "check that opv's own program file is still in place".to_string()
                    }
                    LocalOp::Read | LocalOp::Write | LocalOp::CreateDir => {
                        format!("check free space and permissions of {}", path.display())
                    }
                    LocalOp::RandomSource => {
                        "check that this system's random source (getrandom, /dev/urandom) is available".to_string()
                    }
                }),
                Next::Rerun,
            ),
            StoreNotReady { store, reason } => plan(
                Some((
                    Action::OwnerSetup {
                        object: store.clone(),
                    },
                    match reason {
                        Some(reason) => format!(
                            "ask a cluster admin to make {} ready (its reason: {})",
                            resource_words(store),
                            reason_code(reason)
                        ),
                        None => format!(
                            "ask a cluster admin to make {} ready",
                            resource_words(store)
                        ),
                    },
                )),
                Next::Check(cmd(&["ready"], &[])),
            ),
            HandoffPipeContested { .. } => plan(
                inspect(
                    "check the processes running as you, and treat this machine as untrusted until you know which one connected",
                ),
                Next::Rerun,
            ),
            ConfigProposalInvalid {
                source: _,
                field,
                rule,
                from_proposal,
            } => {
                let field = field.to_string();
                let fix = match rule {
                    FieldRule::Check { check } if *from_proposal => check.proposal_fix(&field),
                    _ => None,
                }
                .unwrap_or_else(|| rule_words(&field, rule).1);
                // Retry never: the same proposal meets the same configuration, so Next names
                // no command; the Do is the change that lets the command run again.
                plan(inspect(fix), Next::None(NoNext::NothingToRun))
            }
            InputUnreadable { path, kind, io: _ } => plan(
                inspect(format!(
                    "check that {} {} exists and you can read it",
                    input_kind(*kind),
                    path.display()
                )),
                Next::Rerun,
            ),
            ItemUnusable { title, problem, .. } => plan(
                inspect(match problem {
                    ItemProblem::WrongCategory => format!(
                        "rename or move the item {title} in 1Password, or name another title"
                    ),
                    ItemProblem::DuplicateTitle => {
                        format!("rename the duplicate {title} in 1Password, or name another title")
                    }
                }),
                Next::Rerun,
            ),
            SecretNotStored {
                system,
                kind,
                name,
                env,
                target,
                refind,
            } => plan(
                Some((
                    Action::Revoke {
                        kind: *kind,
                        name: name.clone(),
                    },
                    format!(
                        "revoke the {} {name} at {}: its secret is lost, and making another one leaves this one behind",
                        create_kind(*kind),
                        system.label()
                    ),
                )),
                match refind {
                    Some(v) => Next::Vendor(v.clone()),
                    None => {
                        // The read that shows the object again, per kind; the target only
                        // when the run named one.
                        let mut args = vec![env.as_str()];
                        if let Some(t) = target {
                            args.extend(["--target", t.as_str()]);
                        }
                        match kind {
                            CreateKind::DeployToken => {
                                Next::Check(cmd(&["target", "credentials"], &args))
                            }
                            CreateKind::ServiceAccount => Next::Check(cmd(&["access"], &args)),
                            _ => Next::Run(cmd(&["doctor"], &["--env", env.as_str()])),
                        }
                    }
                },
            ),
            SourceOnly {
                product,
                env,
                reader,
            } => {
                let substitute = reader
                    .as_ref()
                    .and_then(|q| substituted(inv, product.as_str(), q.as_str()))
                    .and_then(read_form);
                let next = match (substitute, env) {
                    (Some(c), _) => run_or_handoff(c),
                    (None, Some(e)) => {
                        let mut args = vec![e.as_str()];
                        if let Some(q) = reader {
                            args.extend(["--product", q.as_str()]);
                        }
                        Next::Check(cmd(&["check"], &args))
                    }
                    (None, None) => Next::Check(cmd(&["config", "describe"], &[])),
                };
                plan(
                    reader
                        .as_ref()
                        .and_then(|q| inspect(format!("name a product that reads it, such as {q}"))),
                    next,
                )
            }
            TitleLookup {
                kind,
                title,
                matches,
                ..
            } => plan(
                inspect(match matches {
                    0 => format!(
                        "create the {} {title:?} in 1Password (opv creates it only for a person signed in with their own account), or give the exact title of one that exists",
                        resource_kind(*kind)
                    ),
                    _ => format!(
                        "rename all but one {} titled {title:?} in 1Password",
                        resource_kind(*kind)
                    ),
                }),
                Next::Rerun,
            ),
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
        Cause::Partial { then, .. } | Cause::PersonalNotSetUp { then, .. } => cause_account(then),
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
///
/// `colour` (A8, §7.1) is the terminal's colour support, which the caller decides (stderr
/// is a terminal, `NO_COLOR` unset, `--color`): with it the upstream box is dimmed. Colour
/// only reinforces; the words are the same without it.
pub fn render_text(
    cause: &Cause,
    upstream: Option<&Upstream>,
    inv: &Invocation,
    verbose: bool,
    utf8: bool,
    colour: bool,
) -> String {
    let mut s = format!("opv: {}\n", cause.message());
    if let Some(seen) = cause.observed() {
        s.push_str("  ");
        s.push_str(&evidence::checked_line(seen, cause_account(cause)));
        s.push('\n');
    }
    if let Some(up) = upstream {
        let boxed = evidence::upstream_box(up, verbose, utf8);
        if colour {
            for line in boxed.lines() {
                s.push_str(&format!("{DIM}{line}{RESET}\n"));
            }
        } else {
            s.push_str(&boxed);
        }
    }
    let p = cause.plan(inv);
    if let Some(d) = do_with_reply(cause, upstream.is_some(), p.do_text) {
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

/// The Do as printed beside the evidence (C): an unrecognised failure points at the tool's
/// reply only when the reply box is there; a tool that wrote nothing is told as such.
pub fn do_with_reply(cause: &Cause, has_reply: bool, do_text: Option<String>) -> Option<String> {
    match cause {
        Cause::Unrecognized { seen, .. } if !has_reply => Some(format!(
            "{} wrote no reply ({}), so opv cannot tell why it failed; check {} on its own",
            exit_program(seen),
            evidence::exit_words(seen.exit()),
            exit_program(seen)
        )),
        _ => do_text,
    }
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
        "do": do_with_reply(cause, upstream.is_some(), p.do_text),
        "next": next_text(&p.next, inv),
        "next_kind": next_kind(&p.next),
    })
}

#[cfg(test)]
#[path = "render_tests.rs"]
mod tests;

/// The invocation re-run after a configuration fix, as its read when it writes (H10: a broken
/// configuration after `sync` names `plan`, never the write); a read re-runs as typed.
fn rerun_as_read(inv: &Invocation) -> Next {
    match read_form(inv_cmd(inv)) {
        Some(c) if c != inv_cmd(inv) => Next::Check(c),
        _ => Next::Rerun,
    }
}
