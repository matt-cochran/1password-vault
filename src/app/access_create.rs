//! `opv access <env> [--target <name>] --create --github <owner/repo> [--github-env <env>]`
//! (0.9.0): create the least-privilege 1Password service account an environment's CI job
//! needs and store its token as a GitHub Actions secret, in one owner command, without the
//! token ever being shown, typed or written to a file.
//!
//! The identity is exactly what `opv access` computes ([`super::access::identity`]): a
//! target's deploy identity (boundary read, its own state vault read and write), or with
//! no `--target` the environment's read-only CI reader. Steps, in order:
//!
//! 1. Preflight, read-only: the GitHub CLI's sign-in, the repository, and the
//!    environment (`--github-env`). A vault the selected 1Password account cannot find
//!    refuses before anything is created: the account could not be granted it.
//! 2. One confirmation, showing the account name, every grant, the repository, the GitHub
//!    environment and the secret name. A missing GitHub environment is created after it
//!    (an environment is configuration, not a secret).
//! 3. `op service-account create <name> --vault <id>:<perms>… --expires-in 90d --raw`, in
//!    the account the vaults were checked in, through the runner's create effect: a refusal
//!    is diagnosed from op's reply, and an unknown outcome is checked with `opv access`,
//!    never re-run (X5). Its stdout (the token, shown once by 1Password) is held only in a
//!    zeroizing [`SecretValue`] registered with the run's scrubber.
//! 4. The GitHub secret is set with the token on stdin ([`crate::adapters::ci_secrets`]).
//!
//! `opv access <env> --create --agent [--name <machine>] [--confirm <env>]` (#338, design
//! `agent-identity.md` §4.3, §7.1, §7.2) shares every step before the token exists, with
//! the environment's CI-reader grants under the name `{project}-{env}-agent-{machine}`. Its
//! destination is this machine's OS credential store ([`Destination::Machine`]): the store
//! preflight replaces GitHub's, a production-tier environment needs `--confirm <env>`, and
//! an identity already installed here is `agent_identity_exists`. After the create: bind
//! (the token's own `op whoami` account and `op vault list` must equal the request, or
//! nothing is stored), store, read back and check, then record the value-free index entry
//! ([`super::agent_identity`]). A lost token is never re-created (X5); the message names it.
//!
//! An owner command: it needs a person's own terminal and 1Password session (never a
//! service account, Connect, CI or an assistant without a terminal). The old service
//! account is never touched: keep it until the new token has produced verified delivery
//! evidence, then remove it in 1Password.

use std::io::Write;

use super::setup::Interaction;
use super::write_err;
use crate::adapters::onepassword_diagnose::diagnose;
use crate::cause::render::cmd_text;
use crate::cause::{
    AccountId, Cause, Cmd, CreateKind, DiagnoseContext, EnvName, Guard, Refind, System, TargetName,
    Unusable, Upstream, UsageProblem,
};
use crate::domain::SecretValue;
use crate::domain::access_plan::Permission;
use crate::error::Error;
use crate::runner::{Call, CommandRunner, CreateOutcome};

/// Where the token goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHub {
    /// `owner/repo`.
    pub repo: String,
    /// The GitHub environment the job declares; `None`: a repository secret.
    pub environment: Option<String>,
    /// The secret's name (`OP_SERVICE_ACCOUNT_TOKEN` by default).
    pub secret: String,
}

/// The default secret name: the variable `op` reads a service-account token from.
pub const SECRET: &str = "OP_SERVICE_ACCOUNT_TOKEN";

/// The lifetime requested from 1Password (`--expires-in 90d`), recorded value-free beside
/// the contract when the token is stored (#296).
const VALIDITY_DAYS: i64 = 90;

fn valid_repo(s: &str) -> bool {
    let mut parts = s.split('/');
    let ok = |p: Option<&str>| {
        p.is_some_and(|p| {
            !p.is_empty()
                && p.len() <= 100
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        })
    };
    ok(parts.next()) && ok(parts.next()) && parts.next().is_none()
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}

/// A GitHub Actions secret name (07.14): letters, digits or `_`, not starting with a digit
/// or `GITHUB_`. GitHub refuses anything else only after the service account exists.
fn valid_secret_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !s.as_bytes()[0].is_ascii_digit()
        && !s.starts_with("GITHUB_")
}

fn usage(flag: &str, format: &'static str) -> Error {
    Cause::Usage {
        problem: UsageProblem::ValueFormat {
            flag: flag.to_string(),
            format,
        },
    }
    .into()
}

/// `--github` and `--github-env` of a federated identity (#297, #323), before the
/// repository's OIDC subject is read with them: the same formats `access --create` takes.
pub(crate) fn check_repo_and_env(repo: &str, environment: &str) -> Result<(), Error> {
    if !valid_repo(repo) {
        return Err(usage("--github", "owner/repo"));
    }
    if !valid_name(environment) {
        return Err(usage("--github-env", "letters, digits, '-' or '_'"));
    }
    Ok(())
}

/// Check the arguments before any call (X23: before anything irreversible).
pub fn check(gh: &GitHub) -> Result<(), Error> {
    if !valid_repo(&gh.repo) {
        return Err(usage("--github", "owner/repo"));
    }
    if gh.environment.as_deref().is_some_and(|e| !valid_name(e)) {
        return Err(usage("--github-env", "letters, digits, '-' or '_'"));
    }
    if !valid_secret_name(&gh.secret) {
        return Err(usage(
            "--secret-name",
            "letters, digits or '_', not starting with a digit or GITHUB_",
        ));
    }
    Ok(())
}

/// The read that shows whether a service account with this identity's name exists (X5):
/// `opv access <env> [--target <t>]` lists every service account that reads its vaults.
fn check_command(env: &str, target: Option<&str>) -> Cmd {
    let mut args = vec![env.to_string()];
    if let Some(t) = target {
        args.extend(["--target".to_string(), t.to_string()]);
    }
    Cmd {
        command: vec!["access".into()],
        args,
    }
}

/// Run `op service-account create` once, through the runner's create effect (07.12, X5):
/// its stdout (the token), or the diagnosed cause. An unknown outcome is
/// `CreateOutcomeUnknown` with a check first, never a re-run: a second create would make a
/// second account, and the first one's token is already lost.
fn create(
    r: &dyn CommandRunner,
    call: &Call,
    ctx: &DiagnoseContext,
) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
    let seen = match r.create(call, CreateKind::ServiceAccount) {
        Ok(CreateOutcome::Done(o)) => return Ok(o.stdout),
        Ok(CreateOutcome::Refused(_)) => crate::runner::take_observed(),
        Ok(CreateOutcome::OutcomeUnknown(seen)) => Some(seen),
        Err(e) => {
            return Err(Cause::ToolUnusable {
                tool: "op".into(),
                why: Unusable::SpawnFailed {
                    io: e.kind().into(),
                },
            }
            .into());
        }
    };
    let (said, truncated) = crate::scrub::Excerpt::parts(crate::runner::take_failure_excerpt());
    // The runner observes every call that failed; a runner that did not cannot be diagnosed.
    let Some(seen) = seen else {
        return Err(Cause::Bug {
            site: "access --create: a refused create the runner did not observe",
        }
        .into());
    };
    let exit = seen.exit();
    // 07.13: a refusal is classified by op's reply (a sign-in, an account, a missing
    // right), and shown; nothing was created.
    // The session strategy: `service-account create` is no item call, and it keeps the
    // context's check-first refind for an unknown outcome.
    let cause = diagnose(seen, &said.join("\n"), ctx);
    Err(if said.is_empty() {
        cause.into()
    } else {
        Error::with_evidence(
            cause,
            Upstream {
                source: crate::cause::System::OnePassword,
                tool: "1Password CLI".into(),
                version: None,
                exit,
                said,
                removed_advice: false,
                truncated,
                untrusted: true,
            },
        )
    })
}

/// Which identity to create, and where its token goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    pub env: &'a str,
    /// The target's deploy identity; `None`: the environment's CI reader.
    pub target: Option<&'a str>,
    /// The project naming the service account.
    pub project: &'a str,
    pub github: GitHub,
}

/// Where the new token goes (design `agent-identity.md` §7.1). Everything before the token
/// exists is shared; the destination decides its preflight, its line in the question and
/// what happens to the token.
pub enum Destination<'a> {
    /// A GitHub Actions secret: the CI reader or a deploy identity.
    GitHub(&'a GitHub),
    /// This machine's OS credential store: the environment's read-only agent identity.
    Machine(&'a Machine<'a>),
}

/// This machine, as the destination of an agent identity's token (#338).
pub struct Machine<'a> {
    /// `--name`, or this host's name: the account's machine part, sanitized.
    pub name: &'a str,
    /// `--confirm <env>`, which a production-tier environment needs (D6).
    pub confirm: Option<&'a str>,
    /// Where the token is kept.
    pub store: &'a dyn crate::adapters::credential_store::AgentCredentialSource,
    /// The value-free index of agent identities ([`super::agent_identity`], §7.5).
    pub index: &'a std::path::Path,
    /// Print one JSON document instead of lines.
    pub json: bool,
}

/// `opv access <env> --create --agent`: the environment's read-only agent identity on
/// this machine.
pub struct AgentRequest<'a> {
    pub env: &'a str,
    /// The project naming the service account.
    pub project: &'a str,
    pub machine: Machine<'a>,
}

/// Create the identity and store its token. `ui` asks the one question and shows progress.
pub fn run(
    fleet: &crate::domain::Fleet,
    req: &Request<'_>,
    r: &dyn CommandRunner,
    ui: &mut dyn Interaction,
    out: &mut dyn Write,
) -> Result<(), Error> {
    run_with_receipt(fleet, req, r, ui, out, None)
}

/// Opt-in immutable reader issuance evidence; never authenticates existing identities by name.
pub fn run_with_receipt(
    fleet: &crate::domain::Fleet,
    req: &Request<'_>,
    r: &dyn CommandRunner,
    ui: &mut dyn Interaction,
    out: &mut dyn Write,
    receipt_path: Option<&std::path::Path>,
) -> Result<(), Error> {
    let to = Destination::GitHub(&req.github);
    run_to(
        fleet,
        req.env,
        req.target,
        req.project,
        &to,
        r,
        ui,
        out,
        receipt_path,
    )
}

/// Create the environment's read-only agent identity and keep its token on this machine
/// (design `agent-identity.md` §4.3, §7.2): bind, store, check, then index.
pub fn run_agent(
    fleet: &crate::domain::Fleet,
    req: &AgentRequest<'_>,
    r: &dyn CommandRunner,
    ui: &mut dyn Interaction,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let to = Destination::Machine(&req.machine);
    run_to(fleet, req.env, None, req.project, &to, r, ui, out, None)
}

/// What the machine destination found before the question (§7.2's refusals all come first).
struct MachinePrep {
    /// The machine part of the account name.
    slug: String,
    source: crate::adapters::credential_store::SourceDescription,
    key: crate::adapters::credential_store::AgentKey,
    /// The account's immutable ID, from the person's own `op whoami`.
    account_uuid: String,
}

/// The destination's preflight result.
enum Prepared {
    GitHub { env_missing: bool },
    Machine(MachinePrep),
}

/// The machine part `name` gives the account, or `None` when nothing usable is left.
fn machine_slug(project: &str, env: &str, name: &str) -> Option<String> {
    let account = crate::domain::access_plan::agent_account(project, env, name);
    account
        .strip_prefix(&format!("{project}-{env}-agent-"))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// D6: a production-tier (or `confirm_env`) environment needs `--confirm <env>`, checked
/// before any call and so before the question.
fn require_confirm(
    fleet: &crate::domain::Fleet,
    env: &str,
    confirm: Option<&str>,
) -> Result<(), Error> {
    let e = fleet.environment(env)?;
    let guarded = e.tier == crate::domain::Tier::Production || e.confirm_env;
    match confirm {
        Some(c) if c != env => Err(Cause::ConfirmMismatch {
            given: c.to_string(),
            env: EnvName::new(env),
        }
        .into()),
        None if guarded => Err(Cause::NeedsConfirm {
            env: EnvName::new(env),
        }
        .into()),
        _ => Ok(()),
    }
}

/// The account's immutable ID from the person's own session (`op whoami`): the binding
/// check compares the new token's account with it. Without one, nothing is created.
fn person_account_uuid(r: &dyn CommandRunner, env: &str) -> Result<String, Error> {
    #[derive(serde::Deserialize)]
    struct Who {
        account_uuid: String,
    }
    let call = Call::new("op", &["whoami", "--format", "json"]);
    let uuid = match r.read(&call, &[]) {
        Ok(crate::runner::Outcome::Done(o)) if o.status == 0 => {
            serde_json::from_slice::<Who>(&o.stdout)
                .ok()
                .map(|w| w.account_uuid)
        }
        _ => None,
    };
    uuid.filter(|a| a.len() == 26 && a.bytes().all(|b| b.is_ascii_alphanumeric()))
        .ok_or_else(|| super::reader_grants::refusal(env, "immutable_account_id_required"))
}

/// The machine preflight (§7.2): the store first, then the account, then an identity that
/// is already installed here (`agent_identity_exists`; replacing one is `--rotate`).
fn prepare_machine(
    m: &Machine<'_>,
    slug: String,
    env: &str,
    project: &str,
    service_account: &str,
    r: &dyn CommandRunner,
) -> Result<MachinePrep, Error> {
    use crate::adapters::credential_store::AgentKey;
    let account_uuid = person_account_uuid(r, env)?;
    let key = AgentKey::new(
        AccountId::new(account_uuid.clone()),
        project,
        EnvName::new(env),
    )
    .ok_or_else(|| usage("--project", "letters, digits, '-' or '_'"))?;
    let exists = |name: String| -> Error {
        Cause::AgentIdentityExists {
            env: EnvName::new(env),
            name,
        }
        .into()
    };
    if let Some(e) = super::agent_identity::load(m.index)?.find(&account_uuid, project, env) {
        return Err(exists(e.record.account_name.clone()));
    }
    // An entry the index lost (an interrupted create): never overwritten by a create.
    if m.store.resolve(&key)?.is_some() {
        return Err(exists(service_account.to_string()));
    }
    Ok(MachinePrep {
        slug,
        source: m.store.describe(),
        key,
        account_uuid,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_to(
    fleet: &crate::domain::Fleet,
    env: &str,
    target: Option<&str>,
    project: &str,
    to: &Destination<'_>,
    r: &dyn CommandRunner,
    ui: &mut dyn Interaction,
    out: &mut dyn Write,
    receipt_path: Option<&std::path::Path>,
) -> Result<(), Error> {
    let contract = receipt_path
        .map(|_| super::reader_grants::contract(fleet, env))
        .transpose()?;
    if receipt_path.is_some() && target.is_some() {
        return Err(super::reader_grants::refusal(
            env,
            "deploy_identity_not_supported",
        ));
    }
    if let Some(path) = receipt_path {
        super::reader_grants::preflight_destination(path)?;
    }
    // Arguments, before any call (X23).
    let slug = match to {
        Destination::GitHub(gh) => {
            check(gh)?;
            None
        }
        Destination::Machine(m) => {
            let slug = machine_slug(project, env, m.name)
                .ok_or_else(|| usage("--name", "letters, digits or '-'"))?;
            require_confirm(fleet, env, m.confirm)?;
            Some(slug)
        }
    };
    super::tidy::require_person(r, "opv access --create")?;
    // The store answers before anything else is asked of 1Password (§7.2).
    if let Destination::Machine(m) = to {
        m.store.preflight()?;
    }
    let mut id = super::access::identity(fleet, env, target, project, r)?;
    if let (Destination::Machine(_), Some(slug)) = (to, &slug) {
        // `Principal::Agent` takes exactly the CI reader's grants, under its own name.
        let name = crate::domain::access_plan::agent_account(project, env, slug);
        for g in &mut id.grants {
            g.principal = crate::domain::access_plan::Principal::Agent {
                environment: env.to_string(),
                machine: slug.clone(),
            };
            g.service_account = name.clone();
            g.permission = Permission::Read;
        }
        id.service_account = name;
        // op lists no service account, so the CI reader's presence says nothing here.
        id.already_present = false;
    }
    if let Some(c) = &contract {
        let requested: std::collections::BTreeSet<_> = id
            .grants
            .iter()
            .filter(|g| g.permission == Permission::Read)
            .map(|g| g.vault_id.as_str())
            .collect();
        let expected: std::collections::BTreeSet<_> =
            c.vaults.iter().map(|g| g.vault_id.as_str()).collect();
        if requested != expected || requested.len() != id.grants.len() {
            return Err(super::reader_grants::refusal(
                env,
                "native_create_request_mismatch",
            ));
        }
    }
    // #157: the vault's own diagnosed cause (another account, or none), with op's reply;
    // a service account created here could not be granted it, so nothing is created.
    if let Some(vault) = id.not_in_account.first() {
        return Err(vault.error());
    }
    // In the account the vaults were checked in (#157), never op's default.
    let er = crate::app::signin::EnvRunner::with_account(r, id.account.clone());
    // Preflight: everything the token's journey needs, before 1Password shows it once.
    use crate::adapters::ci_secrets;
    let prepared = match to {
        Destination::GitHub(gh) => {
            if !ci_secrets::signed_in(r)? {
                return Err(ci_secrets::not_signed_in());
            }
            let env_missing =
                ci_secrets::environment_missing(r, &gh.repo, gh.environment.as_deref())?;
            Prepared::GitHub { env_missing }
        }
        Destination::Machine(m) => Prepared::Machine(prepare_machine(
            m,
            slug.clone().unwrap_or_default(),
            env,
            project,
            &id.service_account,
            &er,
        )?),
    };
    // The one question.
    let who = match (to, target) {
        (Destination::Machine(_), _) => {
            format!("the read-only agent identity of {env} on this machine")
        }
        (_, Some(t)) => format!("the deploy identity of {env}/{t}"),
        (_, None) => format!("the read-only CI reader of {env}"),
    };
    ui.show(&format!(
        "Create 1Password service account {:?} ({who}), valid 90 days, with:",
        id.service_account
    ))?;
    for g in &id.grants {
        let perm = match g.permission {
            Permission::Read => "read",
            Permission::ReadWrite => "read and write",
        };
        ui.show(&format!("  vault {}: {perm}", g.vault_id))?;
    }
    let mut place = String::new();
    match (to, &prepared) {
        (Destination::GitHub(gh), Prepared::GitHub { env_missing }) => {
            place = match &gh.environment {
                Some(e) if *env_missing => format!("{} environment {e} (created now)", gh.repo),
                Some(e) => format!("{} environment {e}", gh.repo),
                None => format!("{} (repository secret)", gh.repo),
            };
            ui.show(&format!(
                "and store its token as the GitHub secret {} in {place}. The token is never shown.",
                gh.secret
            ))?;
        }
        (_, Prepared::Machine(prep)) => {
            let store = super::agent_identity::store_name(prep.source.store);
            ui.show(&format!(
                "and keep its token in this machine's {store}. The token is never shown."
            ))?;
            ui.show(
                "It reads these vaults' values only to deliver them, and can never change them. \
                 An assistant running as you can still reach the token; see opv guide agent, \
                 \"Agent identity\".",
            )?;
            if prep.source.volatile_cause(None).is_some() {
                ui.show(&format!(
                    "Note: {} is cleared when this machine (or WSL) stops; unattended runs \
                     break after that.",
                    prep.source.store.label()
                ))?;
            }
        }
        _ => {}
    }
    if id.already_present {
        ui.show(&format!(
            "An account named {:?} already reads these vaults: this makes a second one. Keep the \
             old one until the new token has produced verified delivery evidence (opv delivery \
             verify), then remove the old one in 1Password.",
            id.service_account
        ))?;
    }
    if !ui.confirm("Go ahead?")? {
        return Err(Cause::Guard {
            guard: Guard::Declined,
        }
        .into());
    }
    if let (Destination::GitHub(gh), Prepared::GitHub { env_missing: true }) = (to, &prepared)
        && let Some(e) = gh.environment.as_deref()
    {
        ci_secrets::create_environment(r, &gh.repo, e)?;
    }
    // The token: created, held in memory only, then handed to its destination.
    let mut args: Vec<String> = vec![
        "service-account".into(),
        "create".into(),
        id.service_account.clone(),
    ];
    for g in &id.grants {
        let perm = match g.permission {
            Permission::Read => "read_items",
            Permission::ReadWrite => "read_items,write_items",
        };
        args.extend(["--vault".into(), format!("{}:{perm}", g.vault_id)]);
    }
    args.extend(["--expires-in".into(), "90d".into(), "--raw".into()]);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let check = check_command(env, target);
    let ctx = DiagnoseContext {
        env: Some(EnvName::new(env)),
        target: target.map(TargetName::new),
        create: Some((
            CreateKind::ServiceAccount,
            id.service_account.clone(),
            Refind::Check(check.clone()),
        )),
        write: true,
        account: id.account.clone().map(AccountId::new),
        ..DiagnoseContext::default()
    };
    let raw = create(&er, &Call::new("op", &argv), &ctx)?;
    let token = SecretValue::new(String::from_utf8_lossy(&raw).trim().to_string());
    drop(raw);
    // From here on, any output that might echo it is scrubbed (SR-1).
    crate::scrub::register_secret(token.expose());
    if token.expose().is_empty() {
        // 07.13, C20: the account exists and its token is lost (1Password shows it once):
        // it is revoked, never made again (X5). op has no listing of service accounts, so
        // there is no vendor refind.
        return Err(Cause::SecretNotStored {
            system: System::OnePassword,
            kind: CreateKind::ServiceAccount,
            name: id.service_account.clone(),
            env: EnvName::new(env),
            target: target.map(TargetName::new),
            refind: None,
        }
        .into());
    }
    let hub = match (to, prepared) {
        (Destination::Machine(m), Prepared::Machine(prep)) => {
            return keep_on_machine(m, prep, env, project, &id, token, r, ui, out);
        }
        (Destination::GitHub(gh), _) => *gh,
        _ => {
            return Err(Cause::Bug {
                site: "access --create: a destination prepared as another",
            }
            .into());
        }
    };
    // A token-scoped native call binds the closed create request to the actual immutable
    // account/user IDs. Never parse identity out of a token or match a mutable name.
    let issued = if let Some(contract) = contract {
        match super::reader_grants::issued(&contract, &token, r) {
            Ok(receipt) => Some(receipt),
            Err(error) => {
                ui.show("The new identity could not be verified; no receipt or GitHub secret was saved. Remove the new account in 1Password before trying again.")?;
                return Err(error);
            }
        }
    } else {
        None
    };
    let stored = ci_secrets::store(
        r,
        &hub.repo,
        hub.environment.as_deref(),
        &hub.secret,
        &token,
    );
    drop(token);
    if let Err(e) = stored {
        // The account exists and its token is lost (1Password shows it once): say so
        // whatever GitHub's cause is, before it is reported.
        ui.show(&format!(
            "Service account {:?} was created, but its token could not be stored: remove it in \
             1Password (Developer > Service accounts) before running this again.",
            id.service_account
        ))?;
        return Err(e);
    }
    if let (Some(path), Some(receipt)) = (receipt_path, issued) {
        let digest = super::reader_grants::save(path, &receipt)?;
        writeln!(out, "reader grant receipt SHA256: {digest}; approve and pin it separately in trusted CI configuration")
            .map_err(write_err)?;
    }
    // #296: the value-free expiry of the service account just created, beside the contract,
    // once its token has been stored and read back. A manifest project has no bindings
    // sibling (and a fleet parsed from nothing has no file), so nothing is recorded there.
    if let crate::cause::ConfigSource::File { path, .. } = &fleet.read_from.0
        && path.is_file()
    {
        let key = match target {
            Some(t) => crate::domain::credential::ci_identity_expires_path(env, t),
            None => crate::domain::credential::ci_reader_expires_path(env),
        };
        super::target_credentials::record_minted_expiry(path, &key, Some(VALIDITY_DAYS))?;
    }
    writeln!(
        out,
        "created {:?} and stored its token as {} in {place}; nothing was printed",
        id.service_account, hub.secret
    )
    .map_err(write_err)?;
    // 07.16: a typed command, filled from what is known. A deploy identity's delivery leaves
    // evidence; the CI reader's is checked by who reads its vaults.
    let next = match target {
        Some(t) => {
            writeln!(out, "After the next CI run, check its delivery evidence:")
                .map_err(write_err)?;
            Cmd {
                command: vec!["delivery".into(), "verify".into()],
                args: vec![env.to_string(), "--target".into(), t.to_string()],
            }
        }
        None => check,
    };
    writeln!(out, "Next: {}", cmd_text(&next)).map_err(write_err)
}

/// The line for a token that exists only in memory after a step failed (§4.3, FM8): it
/// names the account, says opv does not create it again (X5) and how to start over.
fn token_lost(name: &str, store: &str) -> String {
    format!(
        "Service account {name:?} was created, but its token could not be kept in {store}. \
         1Password shows a token only once, so opv does not try again: remove {name:?} in \
         1Password (Developer > Service accounts), then run this again."
    )
}

/// §4.3 steps 1.1 to 1.4, after the account exists: bind (nothing stored on a mismatch),
/// store, check end to end, then record the value-free index entry and print (§7.2).
#[allow(clippy::too_many_arguments)]
fn keep_on_machine(
    m: &Machine<'_>,
    prep: MachinePrep,
    env: &str,
    project: &str,
    id: &super::access::Identity,
    token: SecretValue,
    r: &dyn CommandRunner,
    ui: &mut dyn Interaction,
    out: &mut dyn Write,
) -> Result<(), Error> {
    use super::reader_grants::{Contract, VaultGrant};
    let name = &id.service_account;
    let store = super::agent_identity::store_name(prep.source.store);
    let contract = Contract {
        environment: env.to_string(),
        role: "agent".into(),
        account_id: prep.account_uuid.clone(),
        vaults: id
            .grants
            .iter()
            .map(|g| VaultGrant {
                vault_id: g.vault_id.clone(),
                permissions: vec!["read_items".into()],
            })
            .collect(),
        can_create_vaults: false,
    };
    let vaults = contract.vaults.len();
    // 1. Bind, always (FM5): the token's own account and vault set, before it is kept.
    if let Err(e) = super::reader_grants::issued(&contract, &token, r) {
        drop(token);
        ui.show(&format!(
            "Service account {name:?} was created, but under its token it is not exactly what \
             was asked (account {} and these {vaults} vaults, read only), so nothing was \
             stored: remove {name:?} in 1Password (Developer > Service accounts) before \
             running this again.",
            prep.account_uuid
        ))?;
        return Err(e);
    }
    // 2. Store, once (X5: the create is never re-run).
    let stored = m.store.store(&prep.key, &token);
    drop(token);
    if let Err(e) = stored {
        ui.show(&token_lost(name, store))?;
        return Err(e);
    }
    // 3. Check end to end: read back non-interactively, then a token-scoped call.
    let checked = match m.store.resolve(&prep.key) {
        Ok(Some(back)) => super::reader_grants::issued(&contract, &back, r).map(|_| ()),
        Ok(None) => Err(Cause::AgentStoreUnavailable {
            store: prep.source.store,
        }
        .into()),
        Err(e) => Err(e),
    };
    if let Err(e) = checked {
        // A token that does not read back is no identity: its entry goes, so nothing
        // half-made is left for the next run to find.
        let _ = m.store.delete(&prep.key);
        ui.show(&token_lost(name, store))?;
        return Err(e);
    }
    // 4. Record the value-free index entry (§7.5).
    let today = super::retire::today();
    let expires_on = crate::domain::credential::add_days(&today, VALIDITY_DAYS).unwrap_or_default();
    let entry = super::agent_identity::IndexEntry {
        project: project.to_string(),
        account_id: prep.account_uuid.clone(),
        record: crate::domain::agent_identity::AgentRecord {
            account_name: name.clone(),
            environment: env.to_string(),
            machine: prep.slug.clone(),
            store: super::agent_identity::store_id(prep.source.store),
            created_on: today,
            expires_on: expires_on.clone(),
            rotation_successor: None,
        },
    };
    if let Err(e) = super::agent_identity::record(m.index, entry) {
        ui.show(&format!(
            "Service account {name:?} was created and its token is kept and checked in \
             {store}, but this machine's list of agent identities could not be written."
        ))?;
        return Err(e);
    }
    let reads = if vaults == 1 {
        "exactly this vault".to_string()
    } else {
        format!("exactly these {vaults} vaults")
    };
    let done = format!(
        "created {name:?}; checked it reads {reads}; stored its token in {store}; nothing was printed"
    );
    let set = "Set OPV_IDENTITY=agent in your assistant's environment to use it.";
    let next = Cmd {
        command: vec!["doctor".into()],
        args: vec!["--env".into(), env.to_string()],
    };
    if m.json {
        ui.show(&done)?;
        ui.show(set)?;
        let doc = serde_json::json!({
            "created": name,
            "kind": "agent",
            "environment": env,
            "machine": prep.slug,
            "store": super::agent_identity::store_id(prep.source.store),
            "read_only": true,
            "vaults": vaults,
            "expires_on": expires_on,
            "use": "OPV_IDENTITY=agent",
            "next": cmd_text(&next),
        });
        return writeln!(out, "{doc}").map_err(write_err);
    }
    writeln!(out, "{done}").map_err(write_err)?;
    writeln!(out, "{set}").map_err(write_err)?;
    writeln!(out, "Next: {}", cmd_text(&next)).map_err(write_err)
}

#[cfg(test)]
#[path = "access_create_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "expiry_recording_tests.rs"]
mod expiry_recording_tests;
