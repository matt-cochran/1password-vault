//! Which steps a situation refuses (design `docs/design/error-catalog.md` §6.4, X8).
//!
//! Every rendered step — on the error and success paths alike — is checked against
//! [`Situation::refuses`] before it is shown. A refused step is rendered as the `Do`
//! ("in your own terminal: …") and `Next` falls back to the variant's read.
//!
//! The predicate is one table: each row of §6.4 names a condition, the commands it covers
//! and the [`RefusedBecause`] it yields. It is code, tested per row.

use super::{Cmd, ConfigSource, Principal};
use crate::host::Platform;

/// Which `op` the run talks to: the plain native CLI, a CLI integrated with the 1Password
/// app, or the Windows `op.exe` reached from WSL (which uses the Windows app).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpFlavour {
    Native,
    App,
    WindowsExe,
}

/// The condition under which a step is refused (design §6.4). Closed on purpose: a renderer
/// matches on it to turn the step into the `Do`, so a new refusal is a new variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusedBecause {
    /// The run is under CI: no interactive command is rendered as runnable.
    Ci,
    /// There is no terminal: no interactive command is rendered as runnable.
    NoTerminal,
    /// A service-account or Connect credential is in effect: no `opv login`.
    ServiceAccount,
    /// The project's configuration is a manifest: no file-only command.
    ManifestProject,
    /// The 1Password app holds the accounts: no `opv login --add`.
    Platform,
    /// A hidden internal command must never be rendered as a step.
    HiddenCommand,
    /// A remote transport cannot carry a child command (`-- <command>` with `--remote`).
    RemoteChild,
    /// A deploy credential or a shell token is in effect: no vendor sign-in.
    ShellToken,
}

/// The facts about the current run that decide whether a step may be rendered. Built once
/// per run; every field is a fact opv already established, never free text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Situation {
    /// The run is under CI (`CI`/`GITHUB_ACTIONS`).
    pub ci: bool,
    /// Stdin and stdout are both a terminal.
    pub terminal: bool,
    /// Who is acting (advice addresses this principal).
    pub identity: Principal,
    /// Where the configuration came from: a file or the project's manifest.
    pub config_source: ConfigSource,
    /// The detected platform.
    pub platform: Platform,
    /// Which `op` the run talks to.
    pub op: OpFlavour,
    /// The run is a remote delivery.
    pub remote: bool,
    /// A deploy credential or a shell token is in effect.
    pub deploy_credentials_or_shell_token: bool,
}

impl Situation {
    /// The situation of this run, from the detected host ([`crate::host::Host::detect`]):
    /// CI, a terminal, a non-interactive 1Password credential, the platform, the `op`
    /// flavour and any provider token, all by name. Deterministic in this crate's unit
    /// tests (the fixed test host). Where the configuration came from is not known here: a
    /// file is assumed unless [`note_config_source`] recorded the manifest.
    pub fn current() -> Self {
        use crate::host::{Host, OpCredential};
        let host = Host::detect();
        let identity = match host.op_credential {
            Some(c @ (OpCredential::ServiceAccount | OpCredential::Connect)) => {
                Principal::ServiceAccount {
                    name: c.var().to_string(),
                }
            }
            None => Principal::Person { account: None },
        };
        let tokens = crate::adapters::registry::credential_vars();
        Situation {
            ci: host.ci,
            terminal: host.interactive,
            identity,
            config_source: CONFIG_SOURCE.get().cloned().unwrap_or(ConfigSource::File {
                path: std::path::PathBuf::new(),
                given_by: super::GivenBy::Discovered,
            }),
            platform: host.platform,
            op: if host.op_is_windows_exe() {
                OpFlavour::WindowsExe
            } else {
                OpFlavour::Native
            },
            remote: false,
            deploy_credentials_or_shell_token: host.token(&tokens).is_some(),
        }
    }

    /// The one predicate every rendered step is checked against (design §6.4, X8).
    ///
    /// The rows are checked in a fixed order. Hidden internal commands and a remote run
    /// with a child transport are refused whatever the run's other facts, because no
    /// situation makes them renderable.
    pub fn refuses(&self, cmd: &Cmd) -> Option<RefusedBecause> {
        if is_hidden(cmd) {
            return Some(RefusedBecause::HiddenCommand);
        }
        if is_remote_child(cmd) {
            return Some(RefusedBecause::RemoteChild);
        }
        if self.deploy_credentials_or_shell_token && is_vendor_signin(cmd) {
            return Some(RefusedBecause::ShellToken);
        }
        // A vendor sign-in is a browser or device flow: a CI job cannot complete it (A10).
        if self.ci && is_vendor_signin(cmd) {
            return Some(RefusedBecause::Ci);
        }
        if is_interactive_only(cmd) && !is_help(cmd) {
            if self.ci {
                return Some(RefusedBecause::Ci);
            }
            if !self.terminal {
                return Some(RefusedBecause::NoTerminal);
            }
            if is_login(cmd) && self.is_service_account() {
                return Some(RefusedBecause::ServiceAccount);
            }
        }
        if matches!(self.config_source, ConfigSource::Manifest { .. }) && is_file_only(cmd) {
            return Some(RefusedBecause::ManifestProject);
        }
        if is_login_add(cmd) && self.platform_holds_accounts() {
            return Some(RefusedBecause::Platform);
        }
        None
    }

    /// A service account or Connect credential decides its own account: `opv login` can
    /// neither pick one nor record one. `Principal::ServiceAccount` carries both.
    fn is_service_account(&self) -> bool {
        matches!(self.identity, Principal::ServiceAccount { .. })
    }

    /// The 1Password app holds the accounts on macOS and Windows, and for the Windows
    /// `op.exe` reached from WSL: `login --add` must go through the app there.
    fn platform_holds_accounts(&self) -> bool {
        matches!(self.platform, Platform::MacOs | Platform::Windows)
            || matches!(self.op, OpFlavour::App | OpFlavour::WindowsExe)
    }
}

/// Where this run's configuration came from, once it is known (set by configuration
/// loading; read by [`Situation::current`]).
static CONFIG_SOURCE: std::sync::OnceLock<ConfigSource> = std::sync::OnceLock::new();

/// Record where this run's configuration came from, so steps the source refuses (a
/// file-only command on a manifest project) are never rendered. The first call wins.
pub fn note_config_source(source: ConfigSource) {
    let _ = CONFIG_SOURCE.set(source);
}

/// Commands that must never be rendered as a step.
fn is_hidden(cmd: &Cmd) -> bool {
    matches!(
        cmd.command.first().map(String::as_str),
        Some("local-delivery" | "remote-send" | "remote-receive")
    )
}

/// A remote profile pins its own command, so `-- <command>` cannot ride along.
fn is_remote_child(cmd: &Cmd) -> bool {
    cmd.args.iter().any(|a| a == "--remote") && cmd.args.iter().any(|a| a == "--")
}

/// Commands only a person runs: their advice is a handoff, never a `Run`.
fn is_interactive_only(cmd: &Cmd) -> bool {
    matches!(
        cmd.command.first().map(String::as_str),
        Some("login" | "approve" | "setup")
    )
}

/// `opv <command> --help` reads the command's help: nothing about it needs a person (F1).
fn is_help(cmd: &Cmd) -> bool {
    cmd.args.iter().any(|a| a == "--help")
}

fn is_login(cmd: &Cmd) -> bool {
    cmd.command.first().map(String::as_str) == Some("login")
}

/// File-only commands: they write or compare a `secrets.toml`, which a manifest project
/// does not have.
fn is_file_only(cmd: &Cmd) -> bool {
    let path: Vec<&str> = cmd.command.iter().map(String::as_str).collect();
    match path.as_slice() {
        ["bootstrap"] => true,
        ["init"] => has_flag(cmd, "--file"),
        ["config", "check"] => has_flag(cmd, "--file"),
        _ => false,
    }
}

fn is_login_add(cmd: &Cmd) -> bool {
    is_login(cmd) && has_flag(cmd, "--add")
}

fn has_flag(cmd: &Cmd, flag: &str) -> bool {
    cmd.args.iter().any(|a| a == flag)
}

/// A vendor sign-in is refused while a deploy credential or a shell token overrides it.
/// The words are matched across the command path and its arguments, so a caller may pass
/// either `["flyctl", "auth", "login"]` or `["flyctl"]` + `["auth", "login"]`.
fn is_vendor_signin(cmd: &Cmd) -> bool {
    const SIGN_INS: &[&[&str]] = &[
        &["flyctl", "auth", "login"],
        &["gh", "auth", "login"],
        &["az", "login"],
    ];
    let words: Vec<&str> = cmd
        .command
        .iter()
        .chain(cmd.args.iter())
        .map(String::as_str)
        .collect();
    SIGN_INS.iter().any(|sign_in| {
        words
            .windows(sign_in.len())
            .any(|window| window == *sign_in)
    })
}

#[cfg(test)]
#[path = "situation_tests.rs"]
mod situation_tests;
