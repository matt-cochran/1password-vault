//! `opv target credentials <env> --target <name> --create` (FR-40): mint a target's
//! least-privilege deploy credential at the provider and store it straight into a new
//! 1Password item, recording `deploy_credentials` in the local configuration. The token is
//! never shown, copied or pasted: it is held only in a zeroizing [`SecretValue`] and sent to
//! `op item create` on stdin.
//!
//! An owner command: it needs a person's own terminal and 1Password session (never a service
//! account, Connect, CI or an assistant without a terminal). Steps, in order:
//!
//! 1. [`require_person`]: a person's 1Password session, never a service account.
//! 2. Refuse before any provider call when the target already records `deploy_credentials`
//!    (rotation is a separate reviewed step), or when the provider cannot mint one.
//! 3. The provider's read-only [`Provider::mint_preflight`] (a missing sign-in or CLI), and
//!    a check that the configuration can take the reference (never a token that cannot be
//!    recorded).
//! 4. One confirmation, showing the credential name, its 90-day validity, the target, the
//!    state vault and item title, and that the token is never shown.
//! 5. [`Provider::mint_deploy_credential`], then one `op item create` with the fields on
//!    stdin only ([`create_item_with_secret_fields`]).
//! 6. Record `deploy_credentials = "op://<state_vault>/<item>"` on the target, keeping the
//!    file's comments and refusing a generated or concurrently changed configuration.
//!
//! Every failure is a catalog cause (design §4); one after the mint says what was already
//! made, and its Next is a read, never the mint again (X5, X20).

use std::io::Write;
use std::path::Path;

use super::setup::Interaction;
use super::tidy::require_person;
use super::write_err;
use crate::adapters::onepassword_init as init_op;
use crate::cause::{
    Cause, Cmd, ConfigSource, GivenBy, Guard, Invocation, NameKind, NotEditable, Origin, Refind,
    UsageProblem, VendorCmd,
};
use crate::domain::{Fleet, SecretValue, Target};
use crate::error::Error;
use crate::provider::Provider;
use crate::runner::CommandRunner;

/// The validity requested from the provider, in the confirmation: 90 days.
const VALIDITY_DAYS: u32 = 90;

/// The target `name` of environment `env`. A misspelt name is `NotDeclared` listing the
/// targets, and an environment without one is `NothingInScope` ([`super::target`]).
fn target_of<'a>(fleet: &'a Fleet, env: &str, name: &str) -> Result<&'a Target, Error> {
    let (environment, _) = super::target(fleet, env, name)?;
    environment.targets.get(name).ok_or_else(|| {
        Cause::Bug {
            site: "target_credentials::target_of",
        }
        .into()
    })
}

/// An opv command as a typed step (design §10.1).
fn opv(command: &[&str], args: &[&str]) -> Cmd {
    Cmd {
        command: command.iter().map(|w| w.to_string()).collect(),
        args: args.iter().map(|w| w.to_string()).collect(),
    }
}

/// `opv target credentials <env> --target <name> --create`: the command a credential step
/// leads to while the target records none.
pub(crate) fn create_cmd(env: &str, name: &str) -> Cmd {
    opv(
        &["target", "credentials"],
        &[env, "--target", name, "--create"],
    )
}

/// `opv doctor --env <env> --target <name>`: the read once a credential is recorded.
fn doctor_cmd(env: &str, name: &str) -> Cmd {
    opv(&["doctor"], &["--env", env, "--target", name])
}

/// The refusal for a provider that cannot mint a deploy credential here: an existing
/// credential is recorded through the configuration instead.
fn cannot_mint() -> Error {
    Cause::Usage {
        problem: UsageProblem::UseInstead {
            command: opv(&["config", "edit"], &[]),
        },
    }
    .into()
}

/// The refusal for a target that already records `deploy_credentials`: rotating one is a
/// separate reviewed step, done in the configuration.
fn already_recorded(env: &str, name: &str) -> Error {
    Cause::AlreadyDeclared {
        kind: NameKind::Target,
        name: format!("{name} of environment {env} with deploy_credentials"),
    }
    .into()
}

/// An error's headline, for the summary line of `show` (06.06): a cause's own message, else
/// the first line of the text.
fn headline(e: &Error) -> String {
    e.to_string()
}

/// What `show` ends with: an optional `Do:` and one `Next:` (A3).
struct Step {
    action: Option<String>,
    next: String,
}

/// The step of a preflight failure, rendered against `create` rather than against `show`
/// itself: once the cause is fixed, what runs next is the `--create` (the target's state
/// decides the step, never the command that only reported it).
fn step_toward(e: &Error, create: &Cmd) -> Step {
    let inv = Invocation {
        origin: Origin::Cli,
        command: create.command.clone(),
        args: create.args.clone(),
        has_child: false,
    };
    let doc = crate::error::document(e, &inv, false);
    Step {
        action: doc["do"].as_str().map(str::to_string),
        next: doc["next"].as_str().unwrap_or("none").to_string(),
    }
}

/// The current state: whether the target records `deploy_credentials`, and which provider
/// can mint one.
pub fn show(
    fleet: &Fleet,
    env: &str,
    name: &str,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let target = target_of(fleet, env, name)?;
    let provider = target.config.provider();
    let recorded = match &target.deploy_credentials {
        Some(item) => item.to_string(),
        None => "none".to_string(),
    };
    let preflight = provider.mint_preflight(r);
    let mint = match &preflight {
        Some(Ok(())) => format!("{} can mint one (signed in)", provider.label()),
        Some(Err(e)) => format!(
            "{} can mint one once this is fixed: {}",
            provider.label(),
            headline(e)
        ),
        None => format!("{} cannot mint one here", provider.label()),
    };
    writeln!(out, "{env}/{name}: deploy_credentials {recorded}; {mint}").map_err(write_err)?;
    let create = create_cmd(env, name);
    let text = |c: &Cmd| crate::cause::render::cmd_text(c);
    // The one step that can work from here: `--create` refuses a recorded credential and a
    // provider that cannot mint, and needs the provider's sign-in first.
    let step = if target.deploy_credentials.is_some() {
        Step {
            action: None,
            next: text(&doctor_cmd(env, name)),
        }
    } else {
        match preflight {
            Some(Ok(())) => Step {
                action: None,
                next: text(&create),
            },
            Some(Err(e)) => step_toward(&e, &create),
            None => step_toward(&cannot_mint(), &create),
        }
    };
    if let Some(a) = &step.action {
        writeln!(out, "Do: {a}").map_err(write_err)?;
    }
    writeln!(out, "Next: {}", step.next).map_err(write_err)
}

/// Where the configuration at `config` is, as the catalog names it.
fn file_source(config: &Path) -> ConfigSource {
    ConfigSource::File {
        path: config.to_path_buf(),
        given_by: GivenBy::Discovered,
    }
}

/// The section `deploy_credentials` is recorded in.
fn target_section(env: &str, name: &str) -> String {
    format!("environments.{env}.targets.{name}")
}

/// Before anything is minted: the configuration at `config` can take `deploy_credentials`
/// on this target. A generated file, or a target opv cannot edit, is refused here, so no
/// token is made that could not be recorded (06.08).
pub(crate) fn recordable(config: &Path, env: &str, name: &str) -> Result<(), Error> {
    let text = std::fs::read_to_string(config).map_err(|e| Cause::ConfigUnreadable {
        path: config.to_path_buf(),
        io: e.kind().into(),
        given_by: GivenBy::Discovered,
    })?;
    if super::bootstrap::is_generated(&text) {
        return Err(Cause::ConfigNotEditable {
            source: file_source(config),
            reason: NotEditable::Generated { generator: None },
        }
        .into());
    }
    let doc = super::bootstrap::parse_doc(&text)?;
    let editable = doc
        .get("environments")
        .and_then(|e| e.get(env))
        .and_then(|e| e.get("targets"))
        .and_then(|t| t.get(name))
        .is_some_and(|t| t.is_table());
    if !editable {
        return Err(Cause::ConfigNotEditable {
            source: file_source(config),
            reason: NotEditable::UnsupportedLayout {
                section: target_section(env, name),
            },
        }
        .into());
    }
    Ok(())
}

/// A failure after the provider token was minted (and perhaps stored): the cause says what
/// was already made (`done`), and its Next is a read, never the mint again (X5, X20; 06.08,
/// 06.09). `Err` gives the error back when it has no cause.
pub(crate) fn after_mint(e: Error, done: Vec<String>) -> Result<Error, Error> {
    let Some((then, _)) = e.cause() else {
        return Err(e);
    };
    let then = then.clone();
    Ok(Cause::Partial {
        done,
        approval_used: None,
        approval_scope: None,
        then: Box::new(then),
    }
    .into())
}

/// The failure to record `deploy_credentials` after the token was minted and stored: what
/// exists, and the line to add by hand (06.08). A refusal with no cause means opv could not
/// edit the target's section.
pub(crate) fn not_recorded(
    e: Error,
    config: &Path,
    env: &str,
    name: &str,
    done: Vec<String>,
) -> Error {
    match after_mint(e, done.clone()) {
        Ok(e) => e,
        Err(_) => Cause::Partial {
            done,
            approval_used: None,
            approval_scope: None,
            then: Box::new(Cause::ConfigNotEditable {
                source: file_source(config),
                reason: NotEditable::UnsupportedLayout {
                    section: target_section(env, name),
                },
            }),
        }
        .into(),
    }
}

/// The failure to store a token that was already minted (C21), never a step that mints
/// again (X5). A store whose outcome is unknown may hold the token: a `Partial` naming the
/// minted token around that cause, whose step finds the item. A store that was refused
/// left the token with nobody: `SecretNotStored`, revoked at the provider and found by its
/// own listing (A22).
fn stored_failed(
    e: Error,
    minted: &str,
    credential: &str,
    env: &str,
    name: &str,
    provider: &dyn Provider,
    target: &Target,
) -> Error {
    match e.cause() {
        Some((Cause::CreateOutcomeUnknown { .. }, _)) => {
            after_mint(e, vec![minted.to_string()]).unwrap_or_else(|e| e)
        }
        _ => Cause::SecretNotStored {
            system: crate::provider::system_of(provider),
            kind: crate::cause::CreateKind::DeployToken,
            name: credential.to_string(),
            env: crate::cause::EnvName::new(env),
            target: Some(crate::cause::TargetName::new(name)),
            refind: provider.mint_refind(target.config.as_ref()),
        }
        .into(),
    }
}

/// Mint and store the credential, then record its reference on the target.
#[allow(clippy::too_many_arguments)]
pub fn run(
    fleet: &Fleet,
    config: &Path,
    env: &str,
    name: &str,
    project: &str,
    r: &dyn CommandRunner,
    ui: &mut dyn Interaction,
    out: &mut dyn Write,
) -> Result<(), Error> {
    require_person(r, "opv target credentials --create")?;
    let target = target_of(fleet, env, name)?;
    let provider = target.config.provider();
    if target.deploy_credentials.is_some() {
        return Err(already_recorded(env, name));
    }
    // The capability gate and the provider's own read-only check, before asking anything.
    // A preflight failure is the provider's cause as it is: nothing was created (06.07).
    match provider.mint_preflight(r) {
        Some(Ok(())) => {}
        Some(Err(e)) => return Err(e),
        None => return Err(cannot_mint()),
    }
    // The configuration must be able to take the reference before a token exists (06.08).
    recordable(config, env, name)?;
    let credential = format!("opv-{project}-{env}-{name}");
    let item_title = format!("{project} · {name} · {env} deploy credentials");
    let locator = target.config.target_locator();
    // The one question.
    ui.show(&format!(
        "Mint a least-privilege {} deploy credential for {locator}:",
        provider.label()
    ))?;
    ui.show(&format!(
        "  name: {credential} (valid {VALIDITY_DAYS} days)"
    ))?;
    ui.show(&format!(
        "  store: a new 1Password item {item_title:?} in state vault {}",
        target.state_vault_id
    ))?;
    ui.show("The token is never shown, copied or pasted.")?;
    if !ui.confirm("Go ahead?")? {
        // Nothing was made; Next is the same command (06.45).
        return Err(Cause::Guard {
            guard: Guard::Declined,
        }
        .into());
    }
    // The token: created, held only in a zeroizing SecretValue, then sent to 1Password on
    // stdin.
    let fields = match provider.mint_deploy_credential(target.config.as_ref(), &credential, r) {
        Some(Ok(fields)) => fields,
        Some(Err(e)) => return Err(e),
        None => return Err(cannot_mint()),
    };
    let field_refs: Vec<(&str, &SecretValue)> = fields
        .iter()
        .map(|(label, value)| (label.as_str(), value))
        .collect();
    let tag = format!("opv-deploy:{project}/{env}/{name}");
    let tags = vec![tag.clone()];
    let minted = format!(
        "{} deploy token {credential} for {locator}",
        provider.label()
    );
    // The stored item is found again by its tag, never by minting again (C21, X5).
    let refind = Refind::Vendor(VendorCmd {
        program: "op".into(),
        args: [
            "item",
            "list",
            "--vault",
            target.state_vault_id.as_str(),
            "--tags",
            tag.as_str(),
        ]
        .map(str::to_string)
        .to_vec(),
    });
    let item = init_op::create_item_with_secret_fields(
        r,
        &target.state_vault_id,
        &item_title,
        &tags,
        &field_refs,
        refind,
    )
    .map_err(|e| stored_failed(e, &minted, &credential, env, name, provider, target))?;
    drop(fields);
    // Only the item's reference is recorded; the token itself stays in 1Password.
    let reference = format!("op://{}/{}", target.state_vault_id, item.id);
    super::declare::set_target_deploy_credentials(r, config, env, name, &reference).map_err(
        |e| {
            let done = vec![
                minted.clone(),
                format!(
                    "1Password item {} in vault {}, to record as deploy_credentials = \
                     {reference:?} under [{}]",
                    item.id,
                    target.state_vault_id,
                    target_section(env, name)
                ),
            ];
            not_recorded(e, config, env, name, done)
        },
    )?;
    writeln!(
        out,
        "minted {credential:?} and stored it as item {} in vault {}; nothing was printed",
        item.id, target.state_vault_id
    )
    .map_err(write_err)?;
    writeln!(
        out,
        "Next: {}",
        crate::cause::render::cmd_text(&doctor_cmd(env, name))
    )
    .map_err(write_err)
}

#[cfg(test)]
#[path = "target_credentials_tests.rs"]
mod tests;
