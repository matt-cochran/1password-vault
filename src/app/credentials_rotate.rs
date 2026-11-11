//! Rotation of CI credentials as one person-run step (#296): replace the service account a
//! CI job signs in with, or the deploy credential a target uses, in one owner command. The
//! successor's token is minted, stored in place (GitHub secret or 1Password item), and its
//! value-free expiry recorded; the old credential is never touched, because opv cannot
//! revoke it — the person does that in 1Password or at the provider, and every success
//! prints how.
//!
//! - [`run_access`]: create a successor of the identity `super::access_create` computed,
//!   named `<original>-YYYYMMDD`, store its token as the same GitHub secret on stdin, and
//!   verify the token with one `op vault list` in that child's own environment. The GitHub
//!   secret must already exist: rotation replaces what a CI job reads, it never sets up a
//!   job that has none.
//! - [`run_target`]: mint a fresh deploy credential for a target that already records
//!   `deploy_credentials`, write it into the existing item (fresh read, one `op item edit`
//!   on stdin, read back), and record the new expiry.
//!
//! Every step keeps the token in a zeroizing [`SecretValue`], never in argv (SR-3), and a
//! failed secret write is an unknown outcome that is read back, never retried (X5).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use super::setup::Interaction;
use super::write_err;
use crate::adapters::ci_secrets;
use crate::adapters::onepassword;
use crate::adapters::onepassword_diagnose::diagnose;
use crate::adapters::onepassword_init;
use crate::adapters::onepassword_tidy;
use crate::cause::{
    Cause, Cmd, CreateKind, DiagnoseContext, EnvName, FieldName, ItemId, Refind, System,
    TargetName, Unusable, Upstream, UsageProblem, VaultId,
};
use crate::domain::access::analyse;
use crate::domain::access_plan::Grant;
use crate::domain::convention::{Op, TidyPlan};
use crate::domain::{Boundary, Environment, Fleet, ItemRef, SecretValue};
use crate::error::Error;
use crate::host::Host;
use crate::runner::{Call, CommandRunner, CreateOutcome, Outcome};

/// The lifetime requested from 1Password (or a provider), in days: 90, matching the create
/// paths and the value recorded as expiry (#296).
const VALIDITY_DAYS: i64 = 90;

/// The successor's date suffix, `YYYYMMDD`.
fn date_suffix() -> String {
    crate::app::retire::today().replace('-', "")
}

/// `opv access <env> [--target <t>] --create`: the command that sets up what rotation
/// replaces.
fn access_create_cmd(env: &str, target: Option<&str>) -> Cmd {
    let mut args = vec![env.to_string()];
    if let Some(t) = target {
        args.extend(["--target".to_string(), t.to_string()]);
    }
    args.push("--create".to_string());
    Cmd {
        command: vec!["access".into()],
        args,
    }
}

/// `opv access <env> [--target <t>]`: the read that shows the identity again.
fn access_check_cmd(env: &str, target: Option<&str>) -> Cmd {
    let mut args = vec![env.to_string()];
    if let Some(t) = target {
        args.extend(["--target".to_string(), t.to_string()]);
    }
    Cmd {
        command: vec!["access".into()],
        args,
    }
}

/// `opv target credentials <env> --target <name> --rotate`: the command that wrote.
fn rotate_cmd(env: &str, name: &str) -> Cmd {
    Cmd {
        command: vec!["target".into(), "credentials".into()],
        args: vec![
            env.to_string(),
            "--target".into(),
            name.to_string(),
            "--rotate".into(),
        ],
    }
}

/// `opv doctor --env <env> --target <name>`: the read once the item holds the new token.
fn doctor_cmd(env: &str, name: &str) -> Cmd {
    Cmd {
        command: vec!["doctor".into()],
        args: vec![
            "--env".into(),
            env.to_string(),
            "--target".into(),
            name.to_string(),
        ],
    }
}

/// The refusal for a target that records no `deploy_credentials`: rotation replaces one,
/// and the command that makes the first is `--create`.
fn no_recorded_credential(env: &str, name: &str) -> Error {
    Cause::Usage {
        problem: UsageProblem::UseInstead {
            command: super::target_credentials::create_cmd(env, name),
        },
    }
    .into()
}

/// The refusal for a provider that cannot mint a deploy credential here.
fn cannot_mint() -> Error {
    Cause::Usage {
        problem: UsageProblem::UseInstead {
            command: Cmd {
                command: vec!["config".into(), "edit".into()],
                args: Vec::new(),
            },
        },
    }
    .into()
}

/// Run `op service-account create` once, through the runner's create effect (07.12, X5):
/// its stdout (the token), or the diagnosed cause. An unknown outcome is
/// `CreateOutcomeUnknown` with a check first, never a re-run (see `access_create`).
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
    let Some(seen) = seen else {
        return Err(Cause::Bug {
            site: "access --rotate: a refused create the runner did not observe",
        }
        .into());
    };
    let exit = seen.exit();
    let cause = diagnose(seen, &said.join("\n"), ctx);
    Err(if said.is_empty() {
        cause.into()
    } else {
        Error::with_evidence(
            cause,
            Upstream {
                source: System::OnePassword,
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

/// Whether a service account already named `successor` reads any of `grants`' vaults
/// (NR-1): a successor this or an earlier interrupted run made, so rotation must not make a
/// second one.
fn successor_exists(r: &dyn CommandRunner, grants: &[Grant], successor: &str) -> bool {
    grants.iter().any(|g| {
        onepassword_init::vault_users(r, &g.vault_id, &Host::detect)
            .ok()
            .flatten()
            .is_some_and(|users| {
                analyse("", &g.vault_id, false, Some(&users))
                    .service_accounts
                    .iter()
                    .any(|s| s.name == successor)
            })
    })
}

/// Verify a freshly stored service-account token with one `op vault list`, the token in
/// that child's environment only (never argv, SR-3).
fn verify_token(
    r: &dyn CommandRunner,
    token: &SecretValue,
    env: &str,
    target: Option<&str>,
) -> Result<(), Error> {
    let child_env = [("OP_SERVICE_ACCOUNT_TOKEN", token.expose())];
    let call = Call {
        env: &child_env,
        ..Call::new("op", &["vault", "list", "--format", "json"])
    };
    match r.read(&call, &[]) {
        Ok(Outcome::Done(_)) => Ok(()),
        Ok(Outcome::Refused(_)) | Ok(Outcome::Unknown { .. }) => {
            let ctx = DiagnoseContext {
                env: Some(EnvName::new(env)),
                target: target.map(TargetName::new),
                ..DiagnoseContext::default()
            };
            match crate::runner::take_observed() {
                Some(seen) => Err(diagnose(seen, "", &ctx).into()),
                None => Err(Cause::Bug {
                    site: "credentials_rotate: a failed verification read left no observation",
                }
                .into()),
            }
        }
        Err(e) => Err(Cause::ToolUnusable {
            tool: "op".into(),
            why: Unusable::SpawnFailed {
                io: e.kind().into(),
            },
        }
        .into()),
    }
}

/// Rotate the service account a CI job signs in with (`opv access --rotate`). Same
/// parameters as [`super::access_create::run`].
pub fn run_access(
    fleet: &Fleet,
    req: &super::access_create::Request<'_>,
    r: &dyn CommandRunner,
    ui: &mut dyn Interaction,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let (env, target, project, gh) = (req.env, req.target, req.project, &req.github);
    super::access_create::check(gh)?;
    super::tidy::require_person(r, "opv access --rotate")?;
    let id = super::access::identity(fleet, env, target, project, r)?;
    if let Some(vault) = id.not_in_account.first() {
        return Err(vault.error());
    }
    // Preflight: everything the token's journey needs, before 1Password shows it once.
    if !ci_secrets::signed_in(r)? {
        return Err(ci_secrets::not_signed_in());
    }
    let env_missing = ci_secrets::environment_missing(r, &gh.repo, gh.environment.as_deref())?;
    // R2: rotation replaces a secret a CI job already reads; it never creates the first.
    if !ci_secrets::secret_exists(r, &gh.repo, gh.environment.as_deref(), &gh.secret)? {
        return Err(Cause::Usage {
            problem: UsageProblem::UseInstead {
                command: access_create_cmd(env, target),
            },
        }
        .into());
    }
    let successor = format!("{}-{}", id.service_account, date_suffix());
    // The account the vaults were checked in, for every `op` call of the rotation.
    let er = crate::app::signin::EnvRunner::with_account(r, id.account.clone());
    // NR-1: an interrupted earlier run may have made the successor already; making another
    // would leave two. The one that exists has no token anyone holds, so it is revoked.
    if successor_exists(&er, &id.grants, &successor) {
        return Err(Cause::SecretNotStored {
            system: System::OnePassword,
            kind: CreateKind::ServiceAccount,
            name: successor,
            env: EnvName::new(env),
            target: target.map(TargetName::new),
            refind: None,
        }
        .into());
    }
    // The one question.
    let who = match target {
        Some(t) => format!("the deploy identity of {env}/{t}"),
        None => format!("the read-only CI reader of {env}"),
    };
    ui.show(&format!("Rotate the 1Password service account of {who}:",))?;
    ui.show(&format!(
        "  new account: {successor:?} (valid {VALIDITY_DAYS} days), replacing {:?}",
        id.service_account
    ))?;
    for g in &id.grants {
        let perm = match g.permission {
            crate::domain::access_plan::Permission::Read => "read",
            crate::domain::access_plan::Permission::ReadWrite => "read and write",
        };
        ui.show(&format!("  vault {}: {perm}", g.vault_id))?;
    }
    let place = match &gh.environment {
        Some(e) if env_missing => format!("{} environment {e} (created now)", gh.repo),
        Some(e) => format!("{} environment {e}", gh.repo),
        None => format!("{} (repository secret)", gh.repo),
    };
    ui.show(&format!(
        "and replace the GitHub secret {} in {place}. The token is never shown.",
        gh.secret
    ))?;
    if !ui.confirm("Go ahead?")? {
        return Err(Cause::Guard {
            guard: crate::cause::Guard::Declined,
        }
        .into());
    }
    if let (true, Some(e)) = (env_missing, gh.environment.as_deref()) {
        ci_secrets::create_environment(r, &gh.repo, e)?;
    }
    // The token: created, held in memory only, then sent to GitHub on stdin.
    let mut args: Vec<String> = vec!["service-account".into(), "create".into(), successor.clone()];
    for g in &id.grants {
        let perm = match g.permission {
            crate::domain::access_plan::Permission::Read => "read_items",
            crate::domain::access_plan::Permission::ReadWrite => "read_items,write_items",
        };
        args.extend(["--vault".into(), format!("{}:{perm}", g.vault_id)]);
    }
    args.extend(["--expires-in".into(), "90d".into(), "--raw".into()]);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let check = access_check_cmd(env, target);
    let ctx = DiagnoseContext {
        env: Some(EnvName::new(env)),
        target: target.map(TargetName::new),
        create: Some((
            CreateKind::ServiceAccount,
            successor.clone(),
            Refind::Check(check),
        )),
        write: true,
        account: id.account.clone().map(crate::cause::AccountId::new),
        ..DiagnoseContext::default()
    };
    // In the account the vaults were checked in, never op's default.
    let raw = create(&er, &Call::new("op", &argv), &ctx)?;
    let token = SecretValue::new(String::from_utf8_lossy(&raw).trim().to_string());
    drop(raw);
    // From here on, any output that might echo it is scrubbed (SR-1).
    crate::scrub::register_secret(token.expose());
    if token.expose().is_empty() {
        return Err(Cause::SecretNotStored {
            system: System::OnePassword,
            kind: CreateKind::ServiceAccount,
            name: successor,
            env: EnvName::new(env),
            target: target.map(TargetName::new),
            refind: None,
        }
        .into());
    }
    let stored = ci_secrets::store(r, &gh.repo, gh.environment.as_deref(), &gh.secret, &token);
    if let Err(e) = stored {
        // R3: a failed secret write is an unknown outcome; read it back (never retried),
        // and name the successor so the person can revoke it.
        drop(token);
        let _ = ci_secrets::secret_exists(r, &gh.repo, gh.environment.as_deref(), &gh.secret);
        return Err(super::target_credentials::after_mint(
            e,
            vec![format!("the 1Password service account {successor:?}")],
        ));
    }
    // Verify the new token actually works before anything says so.
    if let Err(e) = verify_token(r, &token, env, target) {
        drop(token);
        return Err(super::target_credentials::after_mint(
            e,
            vec![format!(
                "the GitHub secret {} replaced with the token of the service account {successor:?}",
                gh.secret
            )],
        ));
    }
    // #296, #304: the value-free expiry and grant receipt of the service account just
    // created, beside the contract, once its token has been stored and verified (a
    // manifest project has no bindings sibling, and it is said).
    let recorded = super::access_receipt::record(
        fleet,
        r,
        &token,
        &super::access_receipt::Issue {
            env,
            target,
            service_account: &successor,
            grants: &id.grants,
            issued_by: crate::domain::grant_receipt::IssuedBy::Rotate,
            validity_days: VALIDITY_DAYS,
        },
        out,
    );
    drop(token);
    recorded?;
    writeln!(
        out,
        "rotated {successor:?}: replaced the GitHub secret {} in {place}; nothing was printed",
        gh.secret
    )
    .map_err(write_err)?;
    writeln!(
        out,
        "Do: revoke the old service account {:?} in 1Password (Developer > Service accounts); op cannot delete service accounts",
        id.service_account
    )
    .map_err(write_err)?;
    writeln!(
        out,
        "Next: {}",
        crate::cause::render::cmd_text(&access_check_cmd(env, target))
    )
    .map_err(write_err)
}

/// Rotate a target's deploy credential (`opv target credentials --rotate`). Same parameters
/// as [`super::target_credentials::run`].
#[allow(clippy::too_many_arguments)]
pub fn run_target(
    fleet: &Fleet,
    config: &Path,
    env: &str,
    name: &str,
    project: &str,
    r: &dyn CommandRunner,
    ui: &mut dyn Interaction,
    out: &mut dyn Write,
) -> Result<(), Error> {
    super::tidy::require_person(r, "opv target credentials --rotate")?;
    // Resolve the target with the same refusal as `target credentials` (X2).
    super::target(fleet, env, name)?;
    let environment = fleet.environment(env)?;
    let target = environment.targets.get(name).ok_or_else(|| -> Error {
        Cause::Bug {
            site: "credentials_rotate::run_target",
        }
        .into()
    })?;
    let provider = target.config.provider();
    let Some(reference) = target.deploy_credentials.clone() else {
        return Err(no_recorded_credential(env, name));
    };
    // The capability gate and the provider's own read-only check, before asking anything.
    match provider.mint_preflight(r) {
        Some(Ok(())) => {}
        Some(Err(e)) => return Err(e),
        None => return Err(cannot_mint()),
    }
    // The configuration must be able to take the new expiry before a token exists (06.08).
    super::target_credentials::recordable(config, env, name)?;
    let credential = format!("opv-{project}-{env}-{name}");
    let locator = target.config.target_locator();
    let by = rotate_cmd(env, name);
    // The one question.
    ui.show(&format!(
        "Rotate the least-privilege {} deploy credential for {locator}:",
        provider.label()
    ))?;
    ui.show(&format!(
        "  name: {credential} (valid {VALIDITY_DAYS} days)"
    ))?;
    ui.show(&format!(
        "  store: replace the fields of 1Password item {reference}"
    ))?;
    ui.show("The token is never shown, copied or pasted.")?;
    if !ui.confirm("Go ahead?")? {
        return Err(Cause::Guard {
            guard: crate::cause::Guard::Declined,
        }
        .into());
    }
    let fields = match provider.mint_deploy_credential(target.config.as_ref(), &credential, r) {
        Some(Ok(fields)) => fields,
        Some(Err(e)) => return Err(e),
        None => return Err(cannot_mint()),
    };
    let minted = format!(
        "{} deploy token {credential} for {locator}",
        provider.label()
    );
    // Fresh read, one `op item edit` on stdin, read back: the same verified write the other
    // 1Password commands use. A failure after the mint says what exists (X5, X20).
    write_item(r, environment, &reference, &fields, &by)
        .map_err(|e| super::target_credentials::after_mint(e, vec![minted.clone()]))?;
    drop(fields);
    // #296: the value-free expiry of the credential just minted, beside the contract.
    super::target_credentials::record_minted_expiry(
        config,
        &crate::domain::credential::deploy_expires_path(env, name),
        provider.minted_lifetime_days(),
    )?;
    writeln!(
        out,
        "rotated {credential:?} in item {reference}; nothing was printed"
    )
    .map_err(write_err)?;
    if let Some(hint) = provider.mint_cleanup_hint() {
        writeln!(out, "Do: {hint}").map_err(write_err)?;
    }
    writeln!(
        out,
        "Next: {}",
        crate::cause::render::cmd_text(&doctor_cmd(env, name))
    )
    .map_err(write_err)
}

/// Two values equal, compared in constant time (never printed).
fn same(a: &SecretValue, b: &SecretValue) -> bool {
    use subtle::ConstantTimeEq;
    a.expose().as_bytes().ct_eq(b.expose().as_bytes()).into()
}

/// Write the freshly minted `fields` into the existing deploy-credentials item
/// `reference`: one fresh read, one `op item edit` with the whole item (values on stdin
/// only, SR-3), then a fresh read back that checks every field holds what was minted.
/// Exactly the verified writer the other 1Password commands use.
fn write_item(
    r: &dyn CommandRunner,
    env: &Environment,
    reference: &ItemRef,
    fields: &BTreeMap<String, SecretValue>,
    by: &Cmd,
) -> Result<(), Error> {
    let boundary = Boundary {
        vault_id: reference.vault.clone(),
        item_id: reference.item.clone(),
    };
    let item = onepassword::read_whole_fresh(r, env, &boundary)?;
    let (layout, _stamp) = onepassword_tidy::parse(item.raw())?;
    let mut ops = Vec::new();
    for (label, value) in fields {
        if let Some(index) = layout.fields.iter().position(|f| f.label == *label) {
            ops.push(Op::SetValue {
                index,
                value: SecretValue::new(value.expose().to_string()),
            });
        }
    }
    let plan = TidyPlan {
        ops,
        changes: Vec::new(),
        kept: false,
    };
    let template = onepassword_tidy::apply(item.raw(), &plan)?;
    let echoed = onepassword_tidy::write(r, env, &boundary, &template)?;
    drop(template);
    drop(echoed);
    // The final fresh read decides: every minted field must hold its value.
    let after = onepassword::read_whole_fresh(r, env, &boundary)?;
    let after_layout = onepassword_tidy::parse(after.raw())?.0;
    let mut missing: Vec<FieldName> = Vec::new();
    for (label, value) in fields {
        let found = after_layout.fields.iter().find(|f| f.label == *label);
        if !found.is_some_and(|f| same(&f.value, value)) {
            missing.push(FieldName::new(label.clone()));
        }
    }
    if !missing.is_empty() {
        return Err(Cause::ReadBackMissing {
            vault: VaultId::new(reference.vault.clone()),
            item: ItemId::new(reference.item.clone()),
            fields: missing,
            by: by.clone(),
        }
        .into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "credentials_rotate_tests.rs"]
mod tests;
