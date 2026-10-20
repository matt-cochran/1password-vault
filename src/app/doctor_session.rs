//! `opv doctor`'s two session rows (#203, `docs/design/session-reuse.md` §3.3, §7.2):
//! `op app integration` and `op shell session`.
//!
//! Detection reads the host first ([`classify_static`], pure), then runs at most one
//! `op whoami` with every `OP_SESSION*` emptied. The shell row runs one `op account list` and
//! one `op vault list` under the shell's variable (FMECA H3: never `whoami`). Neither prompts,
//! and neither keeps an identity, a vault name or a value: exit status, the presence of
//! `user_type`, and op's signed-out wording only.

use super::desktop_integration::{DesktopIntegration, NoIntegration};
use crate::adapters::onepassword::OP;
use crate::adapters::onepassword_manifest::{self as manifest, Account, Discovery};
use crate::host::Host;
use crate::runner::{Call, CommandRunner, PROBE_TIMEOUT};

/// The `OP_SESSION*` exported in this shell, by name only (§3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellSession {
    Live { var: String },
    Expired { var: String },
}

/// One doctor row (§3.3); `doctor.rs` maps it onto its own row after `op auth`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorRow {
    pub name: &'static str,
    pub status: RowStatus,
    pub text: String,
    pub fix: Option<String>,
    pub state: &'static str,
    pub reason: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowStatus {
    Ok,
    Warn,
    Skip,
}

/// The integration's state on this host (§3.2): [`classify_static`], then one probe.
pub fn detect(host: &Host, r: &dyn CommandRunner) -> DesktopIntegration {
    if let Some(found) = classify_static(host) {
        return found;
    }
    let vars = if host.op_session_in_env() {
        super::account::session_var_names()
    } else {
        Vec::new()
    };
    probe_app(r, &vars)
}

/// §3.2 steps 1-4, from the host alone; `None` when a probe must decide. Pure.
///
/// FMECA M2: Linux with a graphical session but no 1Password app process is
/// `Unavailable { NoApp }`, not `Available`, so nobody without the app is told to unlock it.
pub fn classify_static(host: &Host) -> Option<DesktopIntegration> {
    use crate::host::Platform;
    let unavailable = |reason| Some(DesktopIntegration::Unavailable { reason });
    if host.ci || host.op_credential.is_some() {
        return Some(DesktopIntegration::NotApplicable);
    }
    if host.op_biometric_override() == Some(false) {
        return unavailable(NoIntegration::DisabledByEnv);
    }
    match host.platform {
        Platform::Wsl if !host.op_is_windows_exe() => unavailable(NoIntegration::WslLinuxOp),
        Platform::Linux | Platform::Other if !host.graphical_session() => {
            unavailable(NoIntegration::Headless)
        }
        Platform::Linux | Platform::Other if !host.desktop_app_running() => {
            unavailable(NoIntegration::NoApp)
        }
        _ => None,
    }
}

/// The integration as far as the host alone tells, for the sign-in wording and the expiry
/// cause (§4.1, §4.3), which never probe: [`classify_static`], and where it leaves the answer
/// to the probe, `Available` on the hosts whose `op` talks to the app (macOS, Windows, WSL
/// with `op.exe`). `None` on Linux with the app running, where only the probe can tell.
pub fn host_integration(host: &Host) -> Option<DesktopIntegration> {
    classify_static(host).or_else(|| {
        super::account::app_holds_accounts(host.platform, host.op_is_windows_exe())
            .then_some(DesktopIntegration::Available)
    })
}

/// §3.2 steps 5-7: `op whoami --format json` with each of `vars` emptied, so only the app
/// can answer (I1). Exit status and the presence of `user_type` only (O2); the identity is
/// never kept. Emptying stands in for removing: op reads an empty `OP_SESSION_*` as unset
/// (inferred, like `os.Getenv`).
fn probe_app(r: &dyn CommandRunner, vars: &[String]) -> DesktopIntegration {
    let emptied: Vec<(&str, &str)> = vars.iter().map(|v| (v.as_str(), "")).collect();
    let call = Call {
        env: &emptied,
        ..Call::new(OP, &["whoami", "--format", "json"])
    };
    match r.probe(&call, PROBE_TIMEOUT) {
        Ok(o) if o.status == 0 => match has_user_type(&o.stdout) {
            Some(false) => DesktopIntegration::Active,
            // A CLI session answered with no variable (I1 is wrong here), or op printed
            // something opv does not read: report, don't guess.
            Some(true) | None => DesktopIntegration::Unknown,
        },
        // The probe's failure is expected and explains nothing later (NR-31).
        Ok(_) => {
            let _ = crate::runner::take_failure();
            DesktopIntegration::Available
        }
        // op missing, or the probe did not finish (step 7).
        Err(_) => {
            let _ = crate::runner::take_failure();
            DesktopIntegration::Unknown
        }
    }
}

/// Whether `op whoami --format json`'s object has a `user_type`; `None` when it is not a
/// JSON object. Every other field is skipped unread.
fn has_user_type(stdout: &[u8]) -> Option<bool> {
    #[derive(serde::Deserialize)]
    struct Who {
        #[serde(default)]
        user_type: Option<serde::de::IgnoredAny>,
    }
    serde_json::from_slice::<Who>(stdout)
        .ok()
        .map(|w| w.user_type.is_some())
}

/// The shell's exported session for `account`, when one is in the environment.
///
/// FMECA H3: decided by `op vault list --format json` under the variable (the #167 rule,
/// `setup.rs`), never by `whoami`, which a stale variable can still answer. `Live` when the
/// list succeeds, `Expired` when op says no one is signed in; `None` when no variable is set,
/// none belongs to `account`, or op's answer was anything else (an outage, a timeout).
pub fn shell_session(
    host: &Host,
    r: &dyn CommandRunner,
    account: Option<&str>,
) -> Option<ShellSession> {
    if !host.op_session_in_env() {
        return None;
    }
    shell_session_in(r, account, &super::account::session_var_names())
}

/// [`shell_session`] for the given variable names (tests pass their own).
pub(crate) fn shell_session_in(
    r: &dyn CommandRunner,
    account: Option<&str>,
    vars: &[String],
) -> Option<ShellSession> {
    if vars.is_empty() {
        return None;
    }
    // One listing maps each variable to its account (FMECA M3, `session_var_owner`).
    let listed = match manifest::discover(r) {
        Discovery::Listed(l) => Some(l),
        _ => {
            let _ = crate::runner::take_failure();
            None
        }
    };
    let (var, owner) = session_var_for(vars, listed.as_deref(), account)?;
    let mut args = vec!["vault", "list", "--format", "json"];
    if let Some(a) = &owner {
        args.extend(["--account", a.as_str()]);
    }
    match r.probe(&Call::new(OP, &args), PROBE_TIMEOUT) {
        Ok(o) if o.status == 0 => Some(ShellSession::Live { var }),
        Ok(_) => {
            let signed_out =
                crate::runner::take_failure().is_some_and(|f| says_signed_out(f.stderr()));
            signed_out.then_some(ShellSession::Expired { var })
        }
        Err(_) => {
            let _ = crate::runner::take_failure();
            None
        }
    }
}

/// The variable that holds `account`'s session, and that account's ID for `--account`.
/// With no account: the only variable, or else the first one an account owns. Without a
/// listing, only a lone variable is taken (FMECA M3).
fn session_var_for(
    vars: &[String],
    listed: Option<&[Account]>,
    account: Option<&str>,
) -> Option<(String, Option<String>)> {
    let owner_of = |v: &str| {
        listed
            .and_then(|l| super::account::session_var_owner(v, l))
            .map(|a| a.account_uuid.clone())
    };
    let account = account.map(str::trim).filter(|a| !a.is_empty());
    let pick = match (account, listed) {
        (Some(a), Some(l)) => {
            let id = manifest::resolve(l, a).ok()?;
            vars.iter()
                .find(|v| owner_of(v).as_deref() == Some(id.as_str()))
        }
        (None, Some(_)) if vars.len() > 1 => vars
            .iter()
            .find(|v| owner_of(v).is_some())
            .or_else(|| vars.first()),
        (_, _) if vars.len() == 1 => vars.first(),
        _ => None,
    }?;
    Some((pick.clone(), owner_of(pick)))
}

/// op's signed-out wordings ([`crate::host::OP_CLI`]), searched in place.
fn says_signed_out(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    crate::host::OP_CLI
        .signed_out
        .iter()
        .any(|p| s.contains(&p.to_ascii_lowercase()))
}

/// Doctor's two rows for `account` (the environment's, when doctor is scoped to one):
/// [`detect`], [`shell_session`], then [`rows`].
pub fn doctor_rows(host: &Host, r: &dyn CommandRunner, account: Option<&str>) -> Vec<DoctorRow> {
    let integration = detect(host, r);
    let shell = shell_session(host, r, account);
    rows(integration, shell.as_ref(), host)
}

/// The doctor row names (§3.3).
pub const APP_ROW: &str = "op app integration";
pub const SHELL_ROW: &str = "op shell session";

/// The rows for doctor (§3.3). Neither ever fails; `op auth` stays the failing row.
pub fn rows(
    integration: DesktopIntegration,
    shell: Option<&ShellSession>,
    host: &Host,
) -> Vec<DoctorRow> {
    let refresh = super::login_shell::refresh_command(host.shell, None);
    let app = |status, text: String, state, reason| DoctorRow {
        name: APP_ROW,
        status,
        text,
        fix: None,
        state,
        reason,
    };
    let mut rows = vec![match integration {
        DesktopIntegration::Active => app(
            RowStatus::Ok,
            "on; commands here reuse the 1Password app's unlock".into(),
            "active",
            None,
        ),
        DesktopIntegration::Available => app(
            RowStatus::Warn,
            "not confirmed; approve 1Password's prompt at the next command, or turn on \
             Developer > Integrate with 1Password CLI"
                .into(),
            "available",
            None,
        ),
        DesktopIntegration::Unavailable { reason } => app(
            RowStatus::Ok,
            format!(
                "unavailable ({}); sign in once per shell: {refresh}",
                why(reason)
            ),
            "unavailable",
            Some(reason_code(reason)),
        ),
        DesktopIntegration::NotApplicable => app(
            RowStatus::Skip,
            "not applicable (CI, a service account or Connect signs in)".into(),
            "not_applicable",
            None,
        ),
        DesktopIntegration::Unknown => {
            app(RowStatus::Warn, "could not tell".into(), "unknown", None)
        }
    }];
    if let Some(session) = shell {
        let (var, live) = match session {
            ShellSession::Live { var } => (var, true),
            ShellSession::Expired { var } => (var, false),
        };
        rows.push(if host.agent_mode().is_some() {
            DoctorRow {
                name: SHELL_ROW,
                status: RowStatus::Warn,
                text: format!(
                    "an assistant started from this shell inherits it ({var}, {})",
                    if live { "live" } else { "expired" }
                ),
                fix: None,
                state: "inherited_by_assistant",
                reason: None,
            }
        } else if live {
            DoctorRow {
                name: SHELL_ROW,
                status: RowStatus::Ok,
                text: format!("live in this shell ({var})"),
                fix: None,
                state: "live",
                reason: None,
            }
        } else {
            DoctorRow {
                name: SHELL_ROW,
                status: RowStatus::Warn,
                text: format!("expired or signed out ({var})"),
                fix: Some(refresh.clone()),
                state: "expired",
                reason: None,
            }
        });
    }
    rows
}

/// §3.3 `<why>`.
fn why(reason: NoIntegration) -> &'static str {
    match reason {
        NoIntegration::WslLinuxOp => "WSL with the Linux op",
        NoIntegration::Headless => "no graphical session",
        NoIntegration::DisabledByEnv => "OP_BIOMETRIC_UNLOCK_ENABLED=false",
        NoIntegration::NoApp => "the 1Password app is not running",
    }
}

/// The JSON `reason` (the serde name of [`NoIntegration`]).
fn reason_code(reason: NoIntegration) -> &'static str {
    match reason {
        NoIntegration::WslLinuxOp => "wsl_linux_op",
        NoIntegration::Headless => "headless",
        NoIntegration::DisabledByEnv => "disabled_by_env",
        NoIntegration::NoApp => "no_app",
    }
}

#[cfg(test)]
#[path = "doctor_session_tests.rs"]
mod tests;
