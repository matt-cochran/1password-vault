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
//! 3. The provider's read-only [`Provider::mint_preflight`] (a missing sign-in or CLI).
//! 4. One confirmation, showing the credential name, its 90-day validity, the target, the
//!    state vault and item title, and that the token is never shown.
//! 5. [`Provider::mint_deploy_credential`], then one `op item create` with the fields on
//!    stdin only ([`create_item_with_secret_fields`]).
//! 6. Record `deploy_credentials = "op://<state_vault>/<item>"` on the target, keeping the
//!    file's comments and refusing a generated or concurrently changed configuration.

use std::io::Write;
use std::path::Path;

use super::setup::Interaction;
use super::tidy::require_person;
use super::write_err;
use crate::adapters::onepassword_init as init_op;
use crate::domain::{Fleet, SecretValue, Target};
use crate::error::{Code, Error};
use crate::provider::Provider;
use crate::runner::CommandRunner;

/// The validity requested from the provider, in the confirmation: 90 days.
const VALIDITY_DAYS: u32 = 90;

/// The target `name` of environment `env`, or a configuration error naming it.
/// A misspelt name is a usage error listing the targets ([`super::target`]); `no_target`
/// is kept for an environment that has none.
fn target_of<'a>(fleet: &'a Fleet, env: &str, name: &str) -> Result<&'a Target, Error> {
    let (environment, _) = super::target(fleet, env, name)?;
    environment.targets.get(name).ok_or_else(|| {
        Error::Config(format!("environment {env}: no target named {name:?}").into())
            .with_code(Code::Usage)
    })
}

/// The refusal for a provider that cannot mint a deploy credential here.
fn cannot_mint(provider: &dyn Provider, env: &str, name: &str) -> Error {
    Error::Policy(
        format!(
            "{} targets do not mint deploy credentials here; create the credential at the \
             provider and record its item as deploy_credentials on the target (opv config \
             edit)",
            provider.label()
        )
        .into(),
    )
    .with_code(Code::PolicyRefused)
    .with_do(format!(
        "create the credential at the provider and store it in a 1Password item, then add \
         deploy_credentials = \"op://<vault>/<item>\" under [environments.{env}.targets.{name}]"
    ))
    .with_next("opv config edit")
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
        Some(Err(_)) => format!("{} can mint one (sign in first)", provider.label()),
        None => format!("{} cannot mint one here", provider.label()),
    };
    writeln!(out, "{env}/{name}: deploy_credentials {recorded}; {mint}").map_err(write_err)?;
    let create = format!(
        "opv target credentials {} --target {} --create",
        crate::error::shell_word(env),
        crate::error::shell_word(name)
    );
    // The one step that can work from here: `--create` refuses a recorded credential and a
    // provider that cannot mint, and needs the provider's sign-in first.
    let step = if target.deploy_credentials.is_some() {
        crate::error::Step {
            action: None,
            next: format!(
                "opv doctor --env {} --target {}",
                crate::error::shell_word(env),
                crate::error::shell_word(name)
            ),
        }
    } else {
        match preflight {
            Some(Ok(())) => crate::error::Step {
                action: None,
                next: create,
            },
            Some(Err(e)) => e.step(&create, &create),
            None => cannot_mint(provider, env, name).step(&create, &create),
        }
    };
    write!(out, "{}", crate::error::step_lines(&step)).map_err(write_err)
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
        return Err(Error::Policy(
            format!(
                "{} in {env} already has deploy_credentials; rotating one is a separate \
                 reviewed step. Mint a new credential at the provider, then record its item \
                 as deploy_credentials on the target (opv config edit).",
                target.name
            )
            .into(),
        )
        .with_code(Code::PolicyRefused)
        .with_next("opv config edit"));
    }
    // The capability gate and the provider's own read-only check, before asking anything.
    match provider.mint_preflight(r) {
        Some(Ok(())) => {}
        Some(Err(e)) => return Err(e.map_text(|t| format!("{t}; nothing was created"))),
        None => return Err(cannot_mint(provider, env, name)),
    }
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
        return Err(Error::Policy("Stopped. Nothing was created.".into()));
    }
    // The token: created, held only in a zeroizing SecretValue, then sent to 1Password on
    // stdin.
    let fields = match provider.mint_deploy_credential(target.config.as_ref(), &credential, r) {
        Some(Ok(fields)) => fields,
        Some(Err(e)) => return Err(e),
        None => return Err(cannot_mint(provider, env, name)),
    };
    let field_refs: Vec<(&str, &SecretValue)> = fields
        .iter()
        .map(|(label, value)| (label.as_str(), value))
        .collect();
    let tags = vec![format!("opv-deploy:{project}/{env}/{name}")];
    let item = init_op::create_item_with_secret_fields(
        r,
        &target.state_vault_id,
        &item_title,
        &tags,
        &field_refs,
    )
    .map_err(|e| {
        let hint = provider
            .mint_cleanup_hint()
            .map(str::to_string)
            .unwrap_or_else(|| format!("check the provider for a credential named {credential:?}"));
        e.map_text(|t| {
            format!(
                "{t}\n  the credential {credential:?} was minted but could not be stored; \
                 revoke it at the provider: {hint}"
            )
        })
    })?;
    drop(fields);
    // Only the item's reference is recorded; the token itself stays in 1Password.
    let reference = format!("op://{}/{}", target.state_vault_id, item.id);
    super::declare::set_target_deploy_credentials(r, config, env, name, &reference).map_err(
        |e| {
            if e.code() == Code::ConfigChanged {
                e.map_text(|t| {
                    format!(
                        "{t}\n  add this line under [environments.{env}.targets.{name}] by \
                         hand: deploy_credentials = {reference:?}"
                    )
                })
            } else {
                e
            }
        },
    )?;
    writeln!(
        out,
        "minted {credential:?} and stored it as item {} in vault {}; nothing was printed",
        item.id, target.state_vault_id
    )
    .map_err(write_err)?;
    writeln!(out, "Next: opv doctor --env {env} --target {name}").map_err(write_err)
}

#[cfg(test)]
#[path = "target_credentials_tests.rs"]
mod tests;
