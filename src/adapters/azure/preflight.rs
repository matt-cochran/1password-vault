//! Azure preflight (NR-23, NR-25), the vault URI (NR-6) and the `doctor` lines (FR-26,
//! FR-33, R6).
//!
//! Preflight is read-only and runs in this order, before the command's first Azure read
//! (`status`, `plan`: before 1Password too; `sync`: once its blocking keys are refused);
//! the first failure stops the command with nothing changed in Azure:
//!
//! | step | argv | on failure |
//! |---|---|---|
//! | subscription | `account show --subscription <s> -o none` (probe, exit status only) | signed out: `az login`; signed in: the subscription this account cannot see |
//! | vault | `keyvault show -n <vault> -o json` | `keyvault show-deleted -n <vault>` exit 0: the recover command; else not found |
//! | vault data plane | `keyvault secret list --vault-name <vault> -o none` | firewall or private endpoint: network access; else the role grant |
//! | app | `containerapp show -g <rg> -n <app> -o json` | revision mode not single: refused; `InProgress`: `sync` waits with progress within the run budget, `status`/`plan` never wait (a `warn` line); `Failed`: a `warn` line, then proceeds (R11) |
//!
//! Every call but the probes carries `--only-show-errors --subscription <s>` (R7, NR-7).
//! The vault's `properties.vaultUri` is validated and kept for the rest of the run, so
//! sovereign clouds get their own Key Vault host and the vault is read once.

use std::collections::BTreeSet;
use std::time::Duration;

use serde_json::Value;

use super::AzureTarget;
use super::az::{self, AZ_CLI, Effect};
use super::containerapp::{self, ContainerApp, POLL_EVERY, PROGRESS_EVERY, WAIT_MAX};
use crate::adapters::probe::{parse_version, spawn_tool};
use crate::cause::{
    Cause, DiagnoseContext, DottedPath, During, GrantModel, Location, NamedBy, NotFoundState,
    Observed, OutputProblem, Refusal, ResourceKind, ResourceName, ResourceRef, Right, System,
    Unusable,
};
use crate::error::Error;
use crate::host::Host;
use crate::ports::PinnedRuntime;
use crate::provider::{Check, Preflight, PreflightMode, Verdict};
use crate::runner::{Call, CommandRunner, Outcome, Output, Wait};

/// Oldest Azure CLI opv is tested with: `doctor` warns below it.
pub const AZ_TESTED_MIN: (u64, u64, u64) = (2, 60, 0);

/// The `doctor` lines of an Azure target, in order.
pub const DOCTOR_CHECKS: &[&str] = &[
    "az",
    "az login",
    "azure subscription",
    "key vault",
    "container app",
    "app identity access",
];

/// The target's Container App, as the subject of a cause.
pub(crate) fn app_ref(t: &AzureTarget) -> ResourceRef {
    ResourceRef {
        kind: ResourceKind::ContainerApp,
        name: ResourceName::new(&t.container_app),
        scope: Some(format!(
            "resource group {} (subscription {})",
            t.resource_group, t.subscription
        )),
    }
}

/// The preflight of an Azure target (NR-23, NR-25). Keeps the vault URI for `open`. A
/// Container App whose last update failed is a warning: its previous revision keeps
/// serving and opv applies a fresh one (R11). An update in progress is waited for under
/// [`PreflightMode::Mutate`] and is a warning under [`PreflightMode::Read`].
pub fn run(
    t: &AzureTarget,
    r: &dyn CommandRunner,
    mode: PreflightMode,
) -> Result<Preflight, Error> {
    t.vault_uri.set(store_checks(&t.vault_ref(), r)?);
    let app = match mode {
        PreflightMode::Mutate => settled_app(t, r)?,
        PreflightMode::Read => app(t, r)?,
    };
    let warn = |detail: &str| Check {
        name: format!("container app {}", t.container_app).into(),
        outcome: Ok(Verdict::Warn(detail.into())),
    };
    let mut pre = Preflight::default();
    match provisioning(&app) {
        "InProgress" => pre.checks.push(warn(
            "an update is in progress (provisioningState InProgress); this shows the state \
             before it finishes",
        )),
        "Failed" => pre.checks.push(warn(
            "its last update failed (provisioningState Failed); the previous revision keeps \
             serving, and opv will apply a fresh one",
        )),
        _ => {}
    }
    Ok(pre)
}

/// The vault URI kept by [`run`], or read now (one `keyvault show`) when no preflight ran.
pub fn vault_uri_of(t: &AzureTarget, r: &dyn CommandRunner) -> Result<String, Error> {
    if let Some(uri) = t.vault_uri.get() {
        return Ok(uri.to_string());
    }
    let uri = vault_uri(&vault(&t.vault_ref(), r)?, &t.key_vault)?;
    t.vault_uri.set(uri.clone());
    Ok(uri)
}

/// `properties.vaultUri` of a `keyvault show` object, validated before any use (NR-6):
/// `https://`, a plain DNS host whose first label is the vault name and at least three
/// labels, nothing after the host but one optional `/`. Returned without the trailing `/`.
/// The value is never echoed: a hostile one names only what is wrong with it.
pub fn vault_uri(show: &Value, vault: &str) -> Result<String, Error> {
    // A vaultUri opv cannot use is a reply it cannot use (A1); its value is never echoed.
    let bad = || invalid_in_reply(VAULT_SHOW, "properties.vaultUri");
    let raw = show
        .pointer("/properties/vaultUri")
        .and_then(Value::as_str)
        .ok_or_else(|| missing_in_reply(VAULT_SHOW, "properties.vaultUri"))?;
    let rest = raw.strip_prefix("https://").ok_or_else(bad)?;
    let host = rest.strip_suffix('/').unwrap_or(rest);
    let labels: Vec<&str> = host.split('.').collect();
    let plain = host.len() <= 253
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if !plain {
        return Err(bad());
    }
    if labels.len() < 3 || !labels[0].eq_ignore_ascii_case(vault) {
        return Err(bad());
    }
    Ok(format!("https://{host}"))
}

/// One Key Vault and the subscription it is read in, with the configuration fields that
/// name them (for messages): an `azure` section's or a `[stores.<name>]` table's.
pub struct Vault {
    pub name: String,
    pub subscription: String,
    /// e.g. `azure.key_vault`, `stores.prod-vault.azure_key_vault`.
    pub vault_field: String,
    /// e.g. `azure.subscription`.
    pub subscription_field: String,
}

/// The vault's preflight (NR-25): the subscription is visible, the vault exists and its
/// data plane answers this account. Returns its validated `vaultUri` (NR-6).
pub fn store_checks(v: &Vault, r: &dyn CommandRunner) -> Result<String, Error> {
    subscription(v, r)?;
    let show = vault(v, r)?;
    let uri = vault_uri(&show, &v.name)?;
    vault_answers(v, r, &show)?;
    Ok(uri)
}

/// `base` plus `--only-show-errors` (R7) and `--subscription` (NR-7).
fn scoped<'s>(subscription: &'s str, base: &[&'s str]) -> Vec<&'s str> {
    let mut v = base.to_vec();
    v.extend([az::ONLY_SHOW_ERRORS, "--subscription", subscription]);
    v
}

fn read(
    subscription: &str,
    r: &dyn CommandRunner,
    op: &str,
    base: &[&str],
    refused: &[i32],
) -> Result<Outcome, Error> {
    az::invoke(
        r,
        Effect::Read,
        op,
        &scoped(subscription, base),
        None,
        refused,
    )
}

/// A Key Vault, as the subject of a cause.
fn vault_ref(v: &Vault) -> ResourceRef {
    ResourceRef {
        kind: ResourceKind::KeyVault,
        name: ResourceName::new(&v.name),
        scope: Some(format!("subscription {}", v.subscription)),
    }
}

/// A configuration field (`azure.key_vault`, `stores.prod-vault.azure_key_vault`) as the
/// place a resource's name came from.
fn named_by(field: &str) -> NamedBy {
    NamedBy::ConfigField {
        path: DottedPath(field.split('.').map(String::from).collect()),
    }
}

/// A call about vault `v`, for its diagnosis.
fn vault_ctx(v: &Vault) -> DiagnoseContext {
    DiagnoseContext {
        resource: Some(vault_ref(v)),
        named_by: Some(named_by(&v.vault_field)),
        ..DiagnoseContext::default()
    }
}

fn parse(out: &Output, op: &str) -> Result<Value, Error> {
    unreadable_json(&out.stdout, op)
}

/// The `keyvault show` reply the vault URI comes from.
const VAULT_SHOW: &str = "keyvault show";

/// `stdout` of `az <what>` as JSON, or the reply opv cannot read (A1): only the position
/// is kept, since serde_json's message can quote the input.
pub(crate) fn unreadable_json<T: serde::de::DeserializeOwned>(
    stdout: &[u8],
    what: &str,
) -> Result<T, Error> {
    reply_json(stdout, what, During::Read)
}

/// `stdout` of `az <what>` as JSON, `during` the call it answered: a read, or a write az
/// applied, whose unreadable reply says the change is made.
pub(crate) fn reply_json<T: serde::de::DeserializeOwned>(
    stdout: &[u8],
    what: &str,
    during: During,
) -> Result<T, Error> {
    serde_json::from_slice(stdout).map_err(|e| {
        let at = Location {
            line: u32::try_from(e.line()).unwrap_or(u32::MAX),
            col: u32::try_from(e.column()).unwrap_or(u32::MAX),
        };
        unusable(what, |seen| {
            unusable_reply(Some(at), OutputProblem::Unparseable, during, seen)
        })
    })
}

/// `az` answered with a reply opv cannot use.
fn unusable_reply(
    at: Option<Location>,
    problem: OutputProblem,
    during: During,
    seen: Observed,
) -> Cause {
    Cause::UnexpectedOutput {
        system: System::Azure,
        at,
        problem,
        during,
        seen,
    }
}

/// `az <what>` (a read) answered without `field`, which opv needs from its reply.
pub(crate) fn missing_in_reply(what: &str, field: &'static str) -> Error {
    bad_reply(what, OutputProblem::Empty { what: field }, During::Read)
}

/// `az <what>` (a read) answered with `field` in a form opv cannot use.
pub(crate) fn invalid_in_reply(what: &str, field: &'static str) -> Error {
    bad_reply(
        what,
        OutputProblem::InvalidValue { what: field },
        During::Read,
    )
}

/// `az <what>` answered `during` a call with a reply that has `problem`.
pub(crate) fn bad_reply(what: &str, problem: OutputProblem, during: During) -> Error {
    unusable(what, |seen| unusable_reply(None, problem, during, seen))
}

/// The cause of the latest `az <what>` call (`what`: its leading words, such as
/// `containerapp show`), built on the runner's own observation of it (design §4.6, A1):
/// the call that answered with a reply opv cannot use, or, when it failed, its failure.
pub(crate) fn unusable(what: &str, cause: impl FnOnce(Observed) -> Cause) -> Error {
    let words: Vec<&str> = what.split_whitespace().collect();
    let seen = crate::runner::take_unusable_reply(&Call::new(az::PROGRAM, &words))
        .or_else(crate::runner::take_observed);
    match seen {
        Some(seen) => cause(seen).into(),
        None => Cause::Bug {
            site: "azure: an az reply the runner did not observe",
        }
        .into(),
    }
}

/// The signed-in account can see the subscription (NR-7). One probe when it can; a
/// second (`az account show`) tells a sign-out from a subscription it cannot see.
fn subscription(v: &Vault, r: &dyn CommandRunner) -> Result<(), Error> {
    if az::sees_subscription(r, &v.subscription)? {
        return Ok(());
    }
    // The failed probe's observation and reply, kept through the sign-in check.
    let taken = az::take_failure();
    if !crate::runner::diagnosing(|| az::signed_in(r))? {
        return Err(az::report(az::signed_out(), taken.and_then(|(_, up)| up)));
    }
    // Signed in, but this subscription is not visible: az's reply says why (a wrong
    // subscription id or no role on it); opv shows it rather than guess (§12.4).
    let ctx = DiagnoseContext::default();
    Err(match taken {
        Some((seen, up)) => az::classified(seen, up, &ctx),
        None => az::unobserved(r),
    })
}

/// `keyvault show`: the vault exists in the subscription (NR-25). On failure a read-only
/// `keyvault show-deleted` tells a soft-deleted vault (the recover command) from one that
/// is missing or unreadable.
fn vault(v: &Vault, r: &dyn CommandRunner) -> Result<Value, Error> {
    const OP: &str = "keyvault show";
    let (kv, s) = (v.name.as_str(), v.subscription.as_str());
    match read(
        s,
        r,
        OP,
        &["keyvault", "show", "-n", kv, "-o", "json"],
        &[3],
    )? {
        Outcome::Done(out) => parse(&out, OP),
        // Exit 3 is az's "no such resource" (Q3, Q4): `show-deleted` tells a soft-deleted
        // vault from a missing one.
        Outcome::Refused(out) if out.status == 3 => {
            let Some((seen, up)) = az::take_failure() else {
                return Err(az::unobserved(r));
            };
            const DELETED: &str = "keyvault show-deleted";
            let probe = ["keyvault", "show-deleted", "-n", kv, "-o", "none"];
            let state = match crate::runner::diagnosing(|| read(s, r, DELETED, &probe, &[1, 3]))? {
                Outcome::Done(_) => NotFoundState::SoftDeleted,
                Outcome::Refused(_) => NotFoundState::Missing,
                // The probe never answered: the vault's state is unknown.
                Outcome::Unknown { .. } => return Err(az::classified(seen, up, &vault_ctx(v))),
            };
            let missing = Cause::NotFound {
                system: System::Azure,
                resource: vault_ref(v),
                named_by: named_by(&v.vault_field),
                state,
                seen,
            };
            Err(az::report(missing, up))
        }
        Outcome::Refused(_) | Outcome::Unknown { .. } => Err(az::failed(r, vault_ctx(v))),
    }
}

/// `keyvault secret list -o none`: the vault's data plane answers this account (NR-25).
/// A refusal is network access when the vault restricts it, else a missing role.
fn vault_answers(v: &Vault, r: &dyn CommandRunner, vault: &Value) -> Result<(), Error> {
    const OP: &str = "keyvault secret list";
    let (kv, s) = (v.name.as_str(), v.subscription.as_str());
    let base = [
        "keyvault",
        "secret",
        "list",
        "--vault-name",
        kv,
        "-o",
        "none",
    ];
    match read(s, r, OP, &base, &[])? {
        Outcome::Done(_) => Ok(()),
        Outcome::Unknown { .. } => Err(az::failed(r, vault_ctx(v))),
        // The vault exists and the same sign-in just read it (`keyvault show`), so its data
        // plane refusing is a network rule or a missing grant; the vault's own settings
        // say which grant model applies (06.16, 06.17), and the right is asked of whoever
        // made the call (06.19).
        Outcome::Refused(_) => {
            let Some((seen, up)) = az::take_failure() else {
                return Err(az::unobserved(r));
            };
            let missing = Cause::MissingRight {
                system: System::Azure,
                resource: vault_ref(v),
                right: Right::List,
                grant: grant_model(vault),
                env: None,
                target: None,
                seen,
                grantee: None,
            };
            Err(az::report(missing, up))
        }
    }
}

/// How access to a vault is granted: its network rules when it keeps unknown networks out,
/// else an access policy when it does not use Azure RBAC (`enableRbacAuthorization`
/// false), else the Key Vault Secrets Officer role on the vault.
fn grant_model(vault: &Value) -> GrantModel {
    if network_restricted(vault) {
        return GrantModel::NetworkRule;
    }
    let rbac = vault
        .pointer("/properties/enableRbacAuthorization")
        .and_then(Value::as_bool);
    if rbac == Some(false) {
        return GrantModel::AccessPolicy {
            permissions: ["get", "list", "set", "delete", "recover"]
                .map(String::from)
                .to_vec(),
        };
    }
    GrantModel::Rbac {
        role: "Key Vault Secrets Officer".into(),
        scope: vault["id"].as_str().unwrap_or_default().to_string(),
    }
}

/// Public network access disabled, or a firewall that denies by default.
fn network_restricted(vault: &Value) -> bool {
    let is = |ptr: &str, v: &str| {
        vault
            .pointer(ptr)
            .and_then(Value::as_str)
            .is_some_and(|x| x.eq_ignore_ascii_case(v))
    };
    is("/properties/publicNetworkAccess", "Disabled")
        || is("/properties/networkAcls/defaultAction", "Deny")
}

/// `containerapp show`: the app exists and runs in single-revision mode.
fn app(t: &AzureTarget, r: &dyn CommandRunner) -> Result<Value, Error> {
    const OP: &str = "containerapp show";
    let (a, rg, s) = (
        t.container_app.as_str(),
        t.resource_group.as_str(),
        t.subscription.as_str(),
    );
    let base = ["containerapp", "show", "-g", rg, "-n", a, "-o", "json"];
    let resource = app_ref(t);
    let app = match read(s, r, OP, &base, &[3])? {
        Outcome::Done(out) => parse(&out, OP)?,
        // Exit 3 is az's "no such resource" (Q3).
        Outcome::Refused(out) if out.status == 3 => {
            let Some((seen, up)) = az::take_failure() else {
                return Err(az::unobserved(r));
            };
            let missing = Cause::NotFound {
                system: System::Azure,
                resource,
                named_by: named_by("azure.container_app"),
                state: NotFoundState::Missing,
                seen,
            };
            return Err(az::report(missing, up));
        }
        Outcome::Refused(_) | Outcome::Unknown { .. } => {
            let ctx = DiagnoseContext {
                resource: Some(resource),
                named_by: Some(named_by("azure.container_app")),
                ..DiagnoseContext::default()
            };
            return Err(az::failed(r, ctx));
        }
    };
    containerapp::single_revision_mode(t, &app, None)?;
    Ok(app)
}

fn provisioning(app: &Value) -> &str {
    app.pointer("/properties/provisioningState")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
}

/// The app once no update is in progress (NR-25): polls every [`POLL_EVERY`] up to
/// [`WAIT_MAX`], never past the run budget (NR-4), with a progress line at least every
/// [`PROGRESS_EVERY`].
fn settled_app(t: &AzureTarget, r: &dyn CommandRunner) -> Result<Value, Error> {
    let wait = Wait::new(r, WAIT_MAX);
    let mut reported: Option<Duration> = None;
    loop {
        let app = app(t, r)?;
        if provisioning(&app) != "InProgress" {
            return Ok(app);
        }
        let waited = wait.elapsed(r);
        if wait.over(r, POLL_EVERY) {
            // Someone else's update is still running, as opv's own `containerapp show`
            // says; nothing was changed (NR-25).
            return Err(unusable("containerapp show", |seen| Cause::TargetRefused {
                system: System::Azure,
                subject: app_ref(t),
                why: Refusal::InProgress { revision: None },
                env: None,
                target: None,
                seen,
            }));
        }
        let note = if reported.is_none_or(|at| waited.saturating_sub(at) >= PROGRESS_EVERY) {
            reported = Some(waited);
            format!(
                "waiting for container app {} to finish its current update (provisioningState \
                 InProgress), {} s",
                t.container_app,
                waited.as_secs()
            )
        } else {
            String::new()
        };
        wait.pause(r, POLL_EVERY, &note);
    }
}

/// `doctor` lines of an Azure target, in [`DOCTOR_CHECKS`] order. Once `az`, the sign-in
/// or the subscription fails, the later lines say they were not checked.
pub fn doctor(t: &AzureTarget, r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Vec<Check> {
    let (mut checks, uri) = store_doctor_with_uri(&t.vault_ref(), r, host);
    if checks[..3].iter().any(|c| c.outcome.is_err()) {
        // Gated: the key vault line already says why; the app lines say the same.
        let why = match &checks[3].outcome {
            Ok(Verdict::Warn(m)) => m.trim_start_matches("not checked: ").to_string(),
            _ => "the lines above did not pass".to_string(),
        };
        for name in &DOCTOR_CHECKS[checks.len()..] {
            checks.push(not_checked(name, &why));
        }
        return checks;
    }
    let app_ok = match app(t, r) {
        Ok(app) => {
            checks.push(Check {
                name: "container app".into(),
                outcome: Ok(app_verdict(t, &app)),
            });
            true
        }
        Err(e) => {
            checks.push(Check {
                name: "container app".into(),
                outcome: Err(e),
            });
            false
        }
    };
    checks.push(match (uri, app_ok) {
        (Some(uri), true) => Check {
            name: "app identity access".into(),
            outcome: Ok(access(t, r, uri)),
        },
        _ => not_checked(
            "app identity access",
            "needs the key vault and container app lines above to pass",
        ),
    });
    checks
}

/// The `doctor` lines of a Key Vault store: the first four of [`DOCTOR_CHECKS`].
pub const STORE_CHECKS: &[&str] = &["az", "az login", "azure subscription", "key vault"];

/// `doctor` lines of a Key Vault, in [`STORE_CHECKS`] order.
pub fn store_doctor(v: &Vault, r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Vec<Check> {
    store_doctor_with_uri(v, r, host).0
}

/// [`store_doctor`] and the vault URI when the key vault line passed. Once `az`, the
/// sign-in or the subscription fails, the later lines say they were not checked.
fn store_doctor_with_uri(
    v: &Vault,
    r: &dyn CommandRunner,
    host: &dyn Fn() -> Host,
) -> (Vec<Check>, Option<String>) {
    let mut checks = Vec::new();
    let mut push = |name: &'static str, outcome: Result<Verdict, Error>| {
        let ok = outcome.is_ok();
        checks.push(Check {
            name: name.into(),
            outcome,
        });
        ok
    };
    let gate = if !push("az", az_version(r, host)) {
        Some("az is not available (see the az line)")
    } else if !push("az login", az_login(r)) {
        Some("not signed in to Azure (see the az login line)")
    } else if !push(
        "azure subscription",
        subscription(v, r).map(|()| {
            Verdict::Ok(format!(
                "{} ({}) is visible to this account",
                v.subscription, v.subscription_field
            ))
        }),
    ) {
        Some("the subscription is not visible (see the azure subscription line)")
    } else {
        None
    };
    if let Some(why) = gate {
        let done = checks.len();
        for name in &STORE_CHECKS[done..] {
            checks.push(not_checked(name, why));
        }
        return (checks, None);
    }
    let uri = vault(v, r).and_then(|show| {
        let uri = vault_uri(&show, &v.name)?;
        vault_answers(v, r, &show)?;
        Ok(uri)
    });
    let kv = &v.name;
    match uri {
        Ok(uri) => {
            checks.push(Check {
                name: "key vault".into(),
                outcome: Ok(Verdict::Ok(format!("{kv} answers at {uri}"))),
            });
            (checks, Some(uri))
        }
        Err(e) => {
            checks.push(Check {
                name: "key vault".into(),
                outcome: Err(e),
            });
            (checks, None)
        }
    }
}

fn not_checked(name: &'static str, why: &str) -> Check {
    Check {
        name: name.into(),
        outcome: Ok(Verdict::Warn(format!("not checked: {why}"))),
    }
}

/// `az version -o json`: only the `azure-cli` version is read, and printed only when it is
/// a plain version number.
fn az_version(r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Result<Verdict, Error> {
    let o = spawn_tool(r, AZ_CLI, host, &["version", "-o", "json"])?;
    if o.status != 0 {
        return Err(Cause::ToolUnusable {
            tool: az::PROGRAM.to_string(),
            why: Unusable::VersionUnreadable,
        }
        .into());
    }
    let (a, b, c) = AZ_TESTED_MIN;
    let version = serde_json::from_slice::<Value>(&o.stdout)
        .ok()
        .and_then(|j| j["azure-cli"].as_str().map(String::from))
        .and_then(|v| parse_version(&v).map(|n| (v, n)));
    Ok(match version {
        Some((v, n)) if n >= AZ_TESTED_MIN => Verdict::Ok(format!("version {v}")),
        Some((v, _)) => Verdict::Warn(format!(
            "version {v}; opv is tested with az {a}.{b}.{c} or later (older releases may lack \
             the commands opv uses)\n  next: az upgrade"
        )),
        None => Verdict::Warn(format!(
            "present, version not recognised; opv is tested with az {a}.{b}.{c} or later"
        )),
    })
}

fn az_login(r: &dyn CommandRunner) -> Result<Verdict, Error> {
    match az::signed_in(r)? {
        true => Ok(Verdict::Ok("signed in".into())),
        false => Err(az::signed_out().into()),
    }
}

/// The app's state as a doctor verdict: an update in progress or a failed last update is
/// a warning (sync waits for the first and replaces the second, R11).
fn app_verdict(t: &AzureTarget, app: &Value) -> Verdict {
    let (a, rg) = (&t.container_app, &t.resource_group);
    match provisioning(app) {
        "InProgress" => Verdict::Warn(format!(
            "{a} in {rg} is being updated (provisioningState InProgress); opv sync waits for \
             that update to finish"
        )),
        "Failed" => Verdict::Warn(format!(
            "the last update of {a} in {rg} failed (provisioningState Failed); its previous \
             revision keeps serving, and opv sync --deploy applies a fresh one"
        )),
        _ => Verdict::Ok(format!("{a} in {rg}, single revision mode")),
    }
}

/// The app identity's read access to the vault (R6): advisory, so a finding or a check
/// that could not run is a warning, never a failure. Deploys are gated by revision health.
fn access(t: &AzureTarget, r: &dyn CommandRunner, uri: String) -> Verdict {
    t.vault_uri.set(uri);
    let ca = ContainerApp::new(r, t, BTreeSet::new());
    let advisory = "advisory: a revision that cannot read its secrets never becomes ready, and \
                    the previous one keeps serving";
    match ca.check_access(std::slice::from_ref(&t.key_vault)) {
        Ok(findings) => match findings.first() {
            None => Verdict::Ok(format!(
                "the app identity can read secrets in Key Vault {}",
                t.key_vault
            )),
            Some(f) => Verdict::Warn(format!("{}\n  {advisory}", f.reason)),
        },
        Err(e) => Verdict::Warn(format!("could not check ({e})\n  {advisory}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cause::Invocation;
    use crate::runner::fake::FakeRunner;
    use serde_json::json;

    const SUB: &str = "00000000-0000-0000-0000-000000000000";

    fn target() -> AzureTarget {
        AzureTarget {
            subscription: SUB.into(),
            key_vault: "kv-opv-fixture".into(),
            resource_group: "opv-fixture-rg".into(),
            container_app: "opv-fixture-app".into(),
            container: None,
            identity: "system".into(),
            env_name_template: "FLEET__{PRODUCT}__{KEY}".into(),
            config: super::super::ConfigRoute::Env,
            companion_jobs: Vec::new(),
            vault_uri: Default::default(),
        }
    }

    fn fixture(name: &str) -> Value {
        let path = format!("{}/tests/fixtures/azure/{name}", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn out(v: &Value) -> Output {
        Output::success(serde_json::to_vec(v).unwrap())
    }

    fn vault_show() -> Value {
        fixture("keyvault-show.json")
    }

    fn app_show() -> Value {
        fixture("containerapp-show.json")
    }

    /// The recorded app with `provisioningState` replaced (R10: edited recon output).
    fn app_in(state: &str) -> Value {
        let mut v = app_show();
        v["properties"]["provisioningState"] = json!(state);
        v
    }

    fn ok() -> Output {
        Output::success("")
    }

    /// subscription visible, vault shown, vault answers, then `app`.
    fn healthy_with(app: &Value) -> Vec<Output> {
        vec![ok(), out(&vault_show()), ok(), out(app)]
    }

    fn preflight_on(responses: Vec<Output>) -> (FakeRunner, Result<Preflight, Error>) {
        let r = FakeRunner::new(responses);
        let res = run(&target(), &r, PreflightMode::Mutate);
        (r, res)
    }

    /// The error as reported: its message and its `Next:` line.
    fn err_text(res: Result<Preflight, Error>) -> String {
        crate::error::report(&res.unwrap_err())
    }

    #[test]
    fn preflight_passes_on_a_settled_app() {
        let (_, res) = preflight_on(healthy_with(&app_show()));
        assert!(res.is_ok());
    }

    #[test]
    fn preflight_keeps_the_vault_uri_read_from_azure() {
        let r = FakeRunner::new(healthy_with(&app_show()));
        let t = target();
        run(&t, &r, PreflightMode::Mutate).unwrap();
        assert_eq!(
            t.vault_uri.get(),
            Some("https://kv-opv-fixture.vault.azure.net")
        );
    }

    #[test]
    fn open_after_preflight_reads_the_vault_once() {
        let r = FakeRunner::new(healthy_with(&app_show()));
        let t = target();
        run(&t, &r, PreflightMode::Mutate).unwrap();
        vault_uri_of(&t, &r).unwrap();
        let shows = r
            .calls
            .borrow()
            .iter()
            .filter(|c| c.args.starts_with(&["keyvault".into(), "show".into()]))
            .count();
        assert_eq!(shows, 1);
    }

    #[test]
    fn vault_uri_without_preflight_is_read_from_keyvault_show() {
        let r = FakeRunner::new([out(&vault_show())]);
        assert_eq!(
            vault_uri_of(&target(), &r).unwrap(),
            "https://kv-opv-fixture.vault.azure.net"
        );
    }

    /// NR-7: the account probe asks for the configured subscription.
    #[test]
    fn preflight_checks_the_configured_subscription() {
        let (r, _) = preflight_on(healthy_with(&app_show()));
        assert_eq!(
            r.calls.borrow()[0].args,
            [
                "account",
                "show",
                "--subscription",
                SUB,
                "-o",
                "none",
                "--only-show-errors"
            ]
        );
    }

    #[test]
    fn every_preflight_resource_read_carries_the_subscription() {
        let (r, _) = preflight_on(healthy_with(&app_show()));
        assert!(
            r.calls.borrow()[1..]
                .iter()
                .all(|c| c.args.ends_with(&["--subscription".into(), SUB.into()]))
        );
    }

    #[test]
    fn preflight_signed_out_names_az_login() {
        let (_, res) = preflight_on(vec![Output::failure(1), Output::failure(1)]);
        assert!(err_text(res).contains("az login"));
    }

    #[test]
    fn soft_deleted_vault_names_the_recover_command() {
        let (_, res) = preflight_on(vec![ok(), Output::failure(3), ok()]);
        assert!(err_text(res).contains("az keyvault recover --name kv-opv-fixture"));
    }

    #[test]
    fn missing_vault_names_the_fields_to_check() {
        let (_, res) = preflight_on(vec![ok(), Output::failure(3), Output::failure(3)]);
        assert!(err_text(res).contains("check azure.key_vault, which names Key Vault"));
    }

    fn firewalled() -> Value {
        let mut v = vault_show();
        v["properties"]["networkAcls"] =
            json!({"defaultAction": "Deny", "bypass": "AzureServices"});
        v
    }

    /// The Do of a catalog error, as rendered.
    fn do_of(res: Result<Preflight, Error>) -> String {
        res.err()
            .and_then(|e| {
                e.cause()
                    .and_then(|(c, _)| c.do_text(&Invocation::default()))
            })
            .unwrap_or_default()
    }

    /// The vault is found, then its data plane refuses every attempt.
    fn refused_by(vault: &Value) -> Vec<Output> {
        let mut responses = vec![ok(), out(vault)];
        responses.extend(crate::runner::fake::failed_read(1));
        responses
    }

    /// 06.17: a firewall refusal is a missing right (a network rule), not a target error.
    #[test]
    fn firewalled_vault_refusal_is_permission_denied() {
        let (_, res) = preflight_on(refused_by(&firewalled()));
        assert_eq!(res.err().map(|e| e.code_str()), Some("permission_denied"));
    }

    #[test]
    fn firewalled_vault_asks_for_the_network_rule() {
        let (_, res) = preflight_on(refused_by(&firewalled()));
        assert!(do_of(res).contains("network rules of Key Vault"));
    }

    #[test]
    fn vault_refusing_this_account_names_the_role_grant() {
        let (_, res) = preflight_on(refused_by(&vault_show()));
        assert!(do_of(res).contains("the role Key Vault Secrets Officer"));
    }

    /// 06.16: an access-policy vault gets an access policy, not a role assignment.
    #[test]
    fn access_policy_vault_refusal_asks_for_an_access_policy() {
        let (_, res) = preflight_on(refused_by(&fixture(
            "constructed/keyvault-show-access-policy.json",
        )));
        assert!(do_of(res).contains("add an access policy on Key Vault"));
    }

    /// 06.19: under deploy credentials the grant is asked for them, not for "you".
    #[test]
    fn vault_refusal_under_deploy_credentials_addresses_them() {
        let r = FakeRunner::new(refused_by(&vault_show()));
        let deploy = crate::cause::Principal::DeployCredentials {
            vault: crate::cause::VaultId::new("vlt-deploy"),
            item: crate::cause::ItemId::new("azure-deploy"),
            env: crate::cause::EnvName::new("prod"),
            target: crate::cause::TargetName::new("web"),
        };
        let res = crate::runner::under_deploy(deploy, || run(&target(), &r, PreflightMode::Mutate));
        assert!(do_of(res).contains("to deploy credentials azure-deploy"));
    }

    #[test]
    fn vault_refusing_this_account_is_permission_denied() {
        let (_, res) = preflight_on(refused_by(&vault_show()));
        assert_eq!(res.err().map(|e| e.code_str()), Some("permission_denied"));
    }

    /// Signed in, but the subscription is not visible: az's reply says why (a wrong id or
    /// no role); opv shows it rather than guess from az's wording (§12.4).
    #[test]
    fn an_invisible_subscription_shows_azs_reply_unrecognized() {
        let (_, res) = preflight_on(vec![Output::failure(1), ok()]);
        assert_eq!(
            res.err().map(|e| e.code_str()),
            Some("unrecognized_failure")
        );
    }

    #[test]
    fn preflight_failure_makes_no_write() {
        let mut responses = vec![ok(), out(&vault_show())];
        responses.extend(crate::runner::fake::failed_read(1));
        let (r, _) = preflight_on(responses);
        assert!(!r.argv_contains("update") && !r.argv_contains("set"));
    }

    #[test]
    fn multiple_revision_mode_is_refused_with_the_set_mode_command() {
        let mut app = app_show();
        app["properties"]["configuration"]["activeRevisionsMode"] = json!("Multiple");
        let (_, res) = preflight_on(healthy_with(&app));
        assert_eq!(
            res.err().map(|e| e.code_str()),
            Some("owner_setup_required")
        );
    }

    /// I5: the Do of a multiple-revision app is the owner's set-mode command, scoped to the
    /// app's subscription.
    #[test]
    fn multiple_revision_mode_do_names_the_set_mode_command() {
        let mut app = app_show();
        app["properties"]["configuration"]["activeRevisionsMode"] = json!("Multiple");
        let (_, res) = preflight_on(healthy_with(&app));
        assert!(
            do_of(res).contains(&format!(
                "az containerapp revision set-mode --mode single --resource-group opv-fixture-rg --name opv-fixture-app --subscription {SUB}"
            ))
        );
    }

    #[test]
    fn missing_app_names_the_field_to_check() {
        let (_, res) = preflight_on(vec![ok(), out(&vault_show()), ok(), Output::failure(3)]);
        assert!(err_text(res).contains("check azure.container_app, which names container app"));
    }

    #[test]
    fn app_update_in_progress_is_waited_for() {
        let mut responses = healthy_with(&app_in("InProgress"));
        responses.push(out(&app_show()));
        let (_, res) = preflight_on(responses);
        assert!(res.is_ok());
    }

    #[test]
    fn waiting_for_an_app_update_reports_progress() {
        let mut responses = healthy_with(&app_in("InProgress"));
        responses.push(out(&app_show()));
        let r = FakeRunner::new(responses);
        run(&target(), &r, PreflightMode::Mutate).unwrap();
        assert_eq!(
            *r.notes.borrow(),
            [
                "waiting for container app opv-fixture-app to finish its current update \
              (provisioningState InProgress), 0 s"
            ]
        );
    }

    /// The wait is bounded by the run budget (NR-4): the next poll never starts once it
    /// is spent.
    #[test]
    fn waiting_for_an_app_update_stops_at_the_run_budget() {
        let polls = (0..10).map(|_| out(&app_in("InProgress")));
        let mut responses = vec![ok(), out(&vault_show()), ok()];
        responses.extend(polls);
        let r = FakeRunner::new(responses);
        r.budget.set(Duration::from_secs(12));
        let res = run(&target(), &r, PreflightMode::Mutate);
        assert!(res.is_err() && r.calls.borrow().len() < 13, "{res:?}");
    }

    /// Read commands never wait on an update in progress (NR-25): one read of the app.
    #[test]
    fn read_mode_reads_an_app_in_progress_once() {
        let r = FakeRunner::new(healthy_with(&app_in("InProgress")));
        run(&target(), &r, PreflightMode::Read).unwrap();
        assert_eq!(r.calls.borrow().len(), 4);
    }

    #[test]
    fn read_mode_reports_an_app_in_progress_as_a_warning() {
        let r = FakeRunner::new(healthy_with(&app_in("InProgress")));
        let pre = run(&target(), &r, PreflightMode::Read).unwrap();
        let line = pre.checks[0]
            .outcome
            .as_ref()
            .unwrap()
            .line(&pre.checks[0].name);
        assert!(
            line.starts_with("warn  container app opv-fixture-app: an update is in progress"),
            "{line}"
        );
    }

    #[test]
    fn app_update_that_never_finishes_is_refused_as_in_progress_after_the_wait() {
        let polls =
            (0..=WAIT_MAX.as_secs() / POLL_EVERY.as_secs()).map(|_| out(&app_in("InProgress")));
        let mut responses = vec![ok(), out(&vault_show()), ok()];
        responses.extend(polls);
        let (_, res) = preflight_on(responses);
        assert!(err_text(res).contains("another change is still in progress"));
    }

    /// R11: a failed last update is not a broken app; opv proceeds and says so.
    #[test]
    fn failed_last_update_proceeds_with_a_warning() {
        let (_, res) = preflight_on(healthy_with(&app_in("Failed")));
        let line = res.unwrap().checks[0]
            .outcome
            .as_ref()
            .unwrap()
            .line("container app");
        assert!(
            line.starts_with("warn  container app: its last update failed"),
            "{line}"
        );
    }

    // ---- vault URI (NR-6) ----

    fn uri_of(uri: &str) -> Result<String, Error> {
        let mut v = vault_show();
        v["properties"]["vaultUri"] = json!(uri);
        vault_uri(&v, "kv-opv-fixture")
    }

    #[test]
    fn vault_uri_drops_the_trailing_slash() {
        assert_eq!(
            uri_of("https://kv-opv-fixture.vault.azure.net/").unwrap(),
            "https://kv-opv-fixture.vault.azure.net"
        );
    }

    #[test]
    fn sovereign_cloud_vault_uri_is_kept() {
        assert_eq!(
            uri_of("https://kv-opv-fixture.vault.azure.cn/").unwrap(),
            "https://kv-opv-fixture.vault.azure.cn"
        );
    }

    #[test]
    fn plain_http_vault_uri_is_refused() {
        assert!(
            uri_of("http://kv-opv-fixture.vault.azure.net/").map_err(|e| e.code_str())
                == Err("unexpected_output")
        );
    }

    #[test]
    fn vault_uri_with_a_path_is_refused() {
        assert!(
            uri_of("https://kv-opv-fixture.vault.azure.net/x/").map_err(|e| e.code_str())
                == Err("unexpected_output")
        );
    }

    #[test]
    fn vault_uri_of_another_vault_is_refused() {
        assert!(
            uri_of("https://other.vault.azure.net/").map_err(|e| e.code_str())
                == Err("unexpected_output")
        );
    }

    #[test]
    fn missing_vault_uri_is_refused() {
        let mut v = vault_show();
        v["properties"].as_object_mut().unwrap().remove("vaultUri");
        assert!(
            vault_uri(&v, "kv-opv-fixture").map_err(|e| e.code_str()) == Err("unexpected_output")
        );
    }

    // ---- doctor ----

    fn version_out() -> Output {
        out(&fixture("az-version.json"))
    }

    fn doctor_on(responses: Vec<Output>) -> Vec<(String, Result<Verdict, String>)> {
        let r = FakeRunner::new(responses);
        let host = Host::detect();
        doctor(&target(), &r, &|| host)
            .into_iter()
            .map(|c| {
                (
                    c.name.to_string(),
                    c.outcome.map_err(|e| crate::error::report(&e)),
                )
            })
            .collect()
    }

    fn line(lines: &[(String, Result<Verdict, String>)], name: &str) -> Result<Verdict, String> {
        lines.iter().find(|(n, _)| n == name).unwrap().1.clone()
    }

    /// A doctor run where everything answers, ending with `roles` for the access check.
    fn all_pass(roles: &str) -> Vec<Output> {
        vec![
            version_out(),
            ok(),
            ok(),
            out(&vault_show()),
            ok(),
            out(&app_show()),
            out(&app_show()),
            out(&vault_show()),
            out(&fixture(roles)),
        ]
    }

    #[test]
    fn doctor_prints_the_lines_in_order() {
        let names: Vec<String> = doctor_on(all_pass("role-assignment-list.json"))
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(names, DOCTOR_CHECKS);
    }

    #[test]
    fn doctor_shows_the_az_version() {
        let lines = doctor_on(all_pass("role-assignment-list.json"));
        assert_eq!(line(&lines, "az"), Ok(Verdict::Ok("version 2.90.0".into())));
    }

    #[test]
    fn doctor_warns_below_the_tested_az_version() {
        let mut v = fixture("az-version.json");
        v["azure-cli"] = json!("2.59.1");
        let mut responses = all_pass("role-assignment-list.json");
        responses[0] = out(&v);
        let lines = doctor_on(responses);
        assert!(
            matches!(line(&lines, "az"), Ok(Verdict::Warn(m)) if m.contains("tested with az 2.60.0 or later"))
        );
    }

    #[test]
    fn doctor_without_az_names_the_install_command() {
        let r = FakeRunner::default();
        r.push_io_error(std::io::ErrorKind::NotFound);
        let host = Host::detect();
        let checks = doctor(&target(), &r, &|| host);
        // R56: the catalog's ToolMissing, whose Do is the install line.
        assert!(matches!(&checks[0].outcome, Err(e) if e.code_str() == "dependency_missing"));
    }

    #[test]
    fn doctor_signed_out_of_azure_names_az_login() {
        let lines = doctor_on(vec![version_out(), Output::failure(1)]);
        assert!(matches!(line(&lines, "az login"), Err(m) if m.contains("az login")));
    }

    #[test]
    fn doctor_signed_out_marks_the_later_lines_not_checked() {
        let lines = doctor_on(vec![version_out(), Output::failure(1)]);
        assert!(
            matches!(line(&lines, "key vault"), Ok(Verdict::Warn(m)) if m.starts_with("not checked"))
        );
    }

    #[test]
    fn doctor_names_the_reachable_vault_uri() {
        let lines = doctor_on(all_pass("role-assignment-list.json"));
        assert_eq!(
            line(&lines, "key vault"),
            Ok(Verdict::Ok(
                "kv-opv-fixture answers at https://kv-opv-fixture.vault.azure.net".into()
            ))
        );
    }

    #[test]
    fn doctor_warns_on_a_failed_last_app_update() {
        let mut responses = all_pass("role-assignment-list.json");
        responses[5] = out(&app_in("Failed"));
        let lines = doctor_on(responses);
        assert!(
            matches!(line(&lines, "container app"), Ok(Verdict::Warn(m)) if m.contains("applies a fresh one"))
        );
    }

    #[test]
    fn doctor_access_passes_with_a_read_role() {
        let lines = doctor_on(all_pass("role-assignment-list.json"));
        assert!(matches!(
            line(&lines, "app identity access"),
            Ok(Verdict::Ok(_))
        ));
    }

    /// R6: a missing grant is a warning with the exact grant command, never a failure.
    #[test]
    fn doctor_missing_access_warns_with_grant_command() {
        let lines = doctor_on(all_pass("role-assignment-list-empty.json"));
        assert!(
            matches!(line(&lines, "app identity access"), Ok(Verdict::Warn(m)) if m.contains(
            "az role assignment create --assignee-object-id 22222222-2222-2222-2222-222222222222"
        ) && m.contains("--role \"Key Vault Secrets User\""))
        );
    }

    #[test]
    fn doctor_access_check_that_cannot_run_is_a_warning() {
        let mut responses = all_pass("role-assignment-list.json");
        responses.truncate(6);
        responses.extend(crate::runner::fake::failed_read(1));
        responses.push(ok());
        let lines = doctor_on(responses);
        assert!(
            matches!(line(&lines, "app identity access"), Ok(Verdict::Warn(m)) if m.starts_with("could not check"))
        );
    }
}
