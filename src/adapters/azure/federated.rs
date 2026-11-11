//! Create or reuse a target's federated CI deploy identity (#297,
//! `docs/design/azure-oidc.md`): `opv target credentials <env> --target <t> --create
//! --federated --github <repo> --github-env <e>`, in the person's own `az` session.
//!
//! No secret exists at any step: an app registration and its service principal, the
//! target's least-privilege grants, and one federated credential that trusts exactly the
//! subject `repo:<repo>:environment:<e>`. Every step reads first and creates only what is
//! missing, so a re-run after an interruption converges (NR-1); a create that never answered
//! is `WriteOutcomeUnknown`, and the re-run's read finds it (NR-2).
//!
//! | Step | Read | Create when missing |
//! |---|---|---|
//! | the person | `account show -o json` (a `user`, never a service principal) | — |
//! | the subscription | `account show --subscription <s> -o none` | — |
//! | app | `ad app list --display-name <name> -o json` | `ad app create --display-name <name> -o json` |
//! | principal | `ad sp list --filter "appId eq '<app>'" -o json` | `ad sp create --id <app> -o json` |
//! | vault | `keyvault show -n <vault> --subscription <s> -o json` | RBAC: Key Vault Secrets Officer; access policy: `keyvault set-policy` |
//! | app, jobs | `role assignment list --assignee-object-id <oid> --scope <id> …` | `role assignment create … --role Contributor` |
//! | trust | `ad app federated-credential list --id <app> -o json` | `ad app federated-credential create --id <app> --parameters <json>` |
//!
//! The output shapes follow the Azure CLI's documented JSON; the live-spike recordings in
//! `tests/fixtures/azure/oidc/` replace the hand-written replies of the tests when they exist.

use serde_json::{Value, json};

use super::AzureTarget;
use super::az::{self, Effect, ONLY_SHOW_ERRORS};
use crate::cause::{Cause, DiagnoseContext, During, SessionState, System, UsageProblem};
use crate::domain::FederatedIdentity;
use crate::error::Error;
use crate::runner::CommandRunner;

/// GitHub Actions' OIDC token issuer, the only issuer the federated credential trusts.
pub const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
/// The audience `azure/login` requests its token for.
pub const AUDIENCE: &str = "api://AzureADTokenExchange";
/// Entra ID's limit on an app registration's display name and a federated credential's name.
const NAME_LIMIT: usize = 120;

/// `subject`'s words, lowercased, with every run of other characters one `-` (Entra ID
/// accepts letters, digits, `-` and `_` in a federated credential's name).
fn slug(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    out.trim_end_matches('-').chars().take(NAME_LIMIT).collect()
}

/// The app registration's display name: the container app and the trusted subject, so two
/// targets or two GitHub environments never share one identity.
pub fn app_name(t: &AzureTarget, subject: &str) -> String {
    let tail = subject.strip_prefix("repo:").unwrap_or(subject);
    slug(&format!("opv-{}-{tail}", t.container_app))
}

/// The federated credential's name, from the subject it trusts.
pub fn credential_name(subject: &str) -> String {
    slug(&format!(
        "github-{}",
        subject.strip_prefix("repo:").unwrap_or(subject)
    ))
}

/// `/subscriptions/<s>/resourceGroups/<g>/providers/Microsoft.App/<kind>/<name>`.
fn app_resource_id(t: &AzureTarget, kind: &str, name: &str) -> String {
    format!(
        "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.App/{kind}/{name}",
        t.subscription, t.resource_group
    )
}

/// One read, its stdout parsed as JSON (NR-6: output that is not JSON is refused).
fn read_json(r: &dyn CommandRunner, op: &'static str, args: &[&str]) -> Result<Value, Error> {
    let outcome = az::invoke(r, Effect::Read, op, args, None, &[])?;
    let out = az::read_output(r, DiagnoseContext::default(), outcome)?;
    super::preflight::reply_json(&out.stdout, op, During::Read)
}

/// One create, its stdout parsed as JSON when it prints any. Never retried (NR-2).
fn write_json(r: &dyn CommandRunner, op: &'static str, args: &[&str]) -> Result<Value, Error> {
    let outcome = az::invoke(r, Effect::Write, op, args, None, &[])?;
    let out = az::write_output(r, DiagnoseContext::default(), outcome)?;
    if out.stdout.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Null);
    }
    super::preflight::reply_json(&out.stdout, op, During::AppliedWrite)
}

/// The field `key` of `v` as a string, or the refusal of an output opv cannot use (NR-6).
fn field(v: &Value, key: &'static str, op: &'static str) -> Result<String, Error> {
    v[key]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| super::preflight::missing_in_reply(op, key))
}

/// The tenant of the person's own sign-in. A service principal (a CI sign-in, or deploy
/// credentials) is refused: creating identities and granting roles is a person's step.
fn person_tenant(r: &dyn CommandRunner) -> Result<String, Error> {
    let account = read_json(
        r,
        "account show",
        &["account", "show", "-o", "json", ONLY_SHOW_ERRORS],
    )?;
    if account.pointer("/user/type").and_then(Value::as_str) != Some("user") {
        return Err(Cause::NotSignedIn {
            system: System::Azure,
            account: None,
            state: SessionState::SignedOut,
            selected_by: None,
        }
        .into());
    }
    field(&account, "tenantId", "account show")
}

/// The app registration named `name`: the one that exists, else a new one. Two with that
/// name are refused, never guessed between.
fn app(r: &dyn CommandRunner, name: &str) -> Result<String, Error> {
    let listed = read_json(
        r,
        "ad app list",
        &[
            "ad",
            "app",
            "list",
            "--display-name",
            name,
            "-o",
            "json",
            ONLY_SHOW_ERRORS,
        ],
    )?;
    let ids: Vec<String> = listed
        .as_array()
        .ok_or_else(|| super::preflight::invalid_in_reply("ad app list", "the list"))?
        .iter()
        .filter_map(|a| a["appId"].as_str().map(str::to_string))
        .collect();
    match ids.as_slice() {
        [one] => Ok(one.clone()),
        [] => {
            let made = write_json(
                r,
                "ad app create",
                &["ad", "app", "create", "--display-name", name, "-o", "json", ONLY_SHOW_ERRORS],
            )?;
            field(&made, "appId", "ad app create")
        }
        many => Err(Cause::Usage {
            problem: UsageProblem::Rejected {
                message: format!(
                    "Entra ID has {} app registrations named {name} ({}); delete or rename all but one",
                    many.len(),
                    many.join(", ")
                ),
                help: vec!["target".into(), "credentials".into()],
            },
        }
        .into()),
    }
}

/// The object id of `app_id`'s service principal: the one that exists, else a new one.
fn principal(r: &dyn CommandRunner, app_id: &str) -> Result<String, Error> {
    let filter = format!("appId eq '{app_id}'");
    let listed = read_json(
        r,
        "ad sp list",
        &[
            "ad",
            "sp",
            "list",
            "--filter",
            &filter,
            "-o",
            "json",
            ONLY_SHOW_ERRORS,
        ],
    )?;
    if let Some(id) = listed
        .as_array()
        .and_then(|a| a.first())
        .and_then(|sp| sp["id"].as_str())
    {
        return Ok(id.to_string());
    }
    let made = write_json(
        r,
        "ad sp create",
        &[
            "ad",
            "sp",
            "create",
            "--id",
            app_id,
            "-o",
            "json",
            ONLY_SHOW_ERRORS,
        ],
    )?;
    field(&made, "id", "ad sp create")
}

/// Grant `role` at `scope` to the service principal `oid`, unless it already holds it there.
fn grant(
    r: &dyn CommandRunner,
    t: &AzureTarget,
    oid: &str,
    role: &str,
    scope: &str,
) -> Result<(), Error> {
    let held = read_json(
        r,
        "role assignment list",
        &[
            "role",
            "assignment",
            "list",
            "--assignee-object-id",
            oid,
            "--scope",
            scope,
            "--subscription",
            &t.subscription,
            "--fill-principal-name",
            "false",
            "-o",
            "json",
            ONLY_SHOW_ERRORS,
        ],
    )?;
    let already = held.as_array().is_some_and(|a| {
        a.iter().any(|x| {
            x["roleDefinitionName"].as_str() == Some(role)
                && x["scope"]
                    .as_str()
                    .is_some_and(|s| s.eq_ignore_ascii_case(scope))
        })
    });
    if already {
        return Ok(());
    }
    write_json(
        r,
        "role assignment create",
        &[
            "role",
            "assignment",
            "create",
            "--assignee-object-id",
            oid,
            "--assignee-principal-type",
            "ServicePrincipal",
            "--role",
            role,
            "--scope",
            scope,
            "--subscription",
            &t.subscription,
            "-o",
            "json",
            ONLY_SHOW_ERRORS,
        ],
    )
    .map(drop)
}

/// The target's least-privilege grants (docs/configuration.md, deploy identity): write the
/// vault's secrets, update the app and each companion job, and read the role assignments at
/// the vault when companion jobs are checked.
fn grants(r: &dyn CommandRunner, t: &AzureTarget, app_id: &str, oid: &str) -> Result<(), Error> {
    let vault = read_json(
        r,
        "keyvault show",
        &[
            "keyvault",
            "show",
            "-n",
            &t.key_vault,
            "--subscription",
            &t.subscription,
            "-o",
            "json",
            ONLY_SHOW_ERRORS,
        ],
    )?;
    let vault_id = field(&vault, "id", "keyvault show")?;
    let rbac = vault
        .pointer("/properties/enableRbacAuthorization")
        .and_then(Value::as_bool)
        != Some(false);
    if rbac {
        grant(r, t, oid, "Key Vault Secrets Officer", &vault_id)?;
    } else {
        // An access-policy vault: `set-policy` replaces this principal's entry, so a re-run
        // writes the same permissions again (convergent).
        write_json(
            r,
            "keyvault set-policy",
            &[
                "keyvault",
                "set-policy",
                "-n",
                &t.key_vault,
                "--subscription",
                &t.subscription,
                "--spn",
                app_id,
                "--secret-permissions",
                "get",
                "list",
                "set",
                "delete",
                "recover",
                "-o",
                "none",
                ONLY_SHOW_ERRORS,
            ],
        )?;
    }
    grant(
        r,
        t,
        oid,
        "Contributor",
        &app_resource_id(t, "containerApps", &t.container_app),
    )?;
    for job in &t.companion_jobs {
        grant(r, t, oid, "Contributor", &app_resource_id(t, "jobs", job))?;
    }
    if !t.companion_jobs.is_empty() && rbac {
        grant(r, t, oid, "Reader", &vault_id)?;
    }
    Ok(())
}

/// The federated credential that trusts `subject`: the one that exists, else a new one.
fn trust(r: &dyn CommandRunner, app_id: &str, subject: &str) -> Result<(), Error> {
    let listed = read_json(
        r,
        "ad app federated-credential list",
        &[
            "ad",
            "app",
            "federated-credential",
            "list",
            "--id",
            app_id,
            "-o",
            "json",
            ONLY_SHOW_ERRORS,
        ],
    )?;
    let trusted = listed.as_array().is_some_and(|a| {
        a.iter().any(|c| {
            c["subject"].as_str() == Some(subject) && c["issuer"].as_str() == Some(GITHUB_ISSUER)
        })
    });
    if trusted {
        return Ok(());
    }
    // Ids and the subject only: the parameters hold no secret, so argv is fine (SR-3).
    let parameters = json!({
        "name": credential_name(subject),
        "issuer": GITHUB_ISSUER,
        "subject": subject,
        "audiences": [AUDIENCE],
    })
    .to_string();
    write_json(
        r,
        "ad app federated-credential create",
        &[
            "ad",
            "app",
            "federated-credential",
            "create",
            "--id",
            app_id,
            "--parameters",
            &parameters,
            "-o",
            "json",
            ONLY_SHOW_ERRORS,
        ],
    )
    .map(drop)
}

/// Create or reuse `t`'s federated CI deploy identity trusting exactly `subject`, and return
/// its non-secret ids.
pub fn mint(
    t: &AzureTarget,
    subject: &str,
    r: &dyn CommandRunner,
) -> Result<FederatedIdentity, Error> {
    let tenant_id = person_tenant(r)?;
    // NR-7: the subscription the grants go to must be visible to this sign-in; az's own
    // reply says why when it is not (a wrong id, or no role on it).
    if !az::sees_subscription(r, &t.subscription)? {
        return Err(match az::take_failure() {
            Some((seen, up)) => az::classified(seen, up, &DiagnoseContext::default()),
            None => az::unobserved(r),
        });
    }
    let app_id = app(r, &app_name(t, subject))?;
    let oid = principal(r, &app_id)?;
    grants(r, t, &app_id, &oid)?;
    trust(r, &app_id, subject)?;
    Ok(FederatedIdentity {
        tenant_id,
        client_id: app_id,
        subscription_id: t.subscription.clone(),
    })
}

#[cfg(test)]
#[path = "federated_tests.rs"]
mod tests;
