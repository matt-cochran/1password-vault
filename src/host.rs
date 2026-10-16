//! Platform and shell detection for remediation text (FR-26).
//!
//! When opv cannot finish it prints the exact next command for this platform, so it needs
//! to know the platform, the user's shell, and whether it runs under CI. Detection is
//! deterministic and goes through the [`HostEnv`] seam so every case can be tested:
//!
//! 1. CI: `CI` or `GITHUB_ACTIONS` truthy (set, and not empty, `false` or `0`, any case).
//!    Remediation names `OP_SERVICE_ACCOUNT_TOKEN` and never an interactive command.
//! 2. Platform: `windows` / `macos` by the compile-time OS; on Linux, WSL when
//!    `/proc/sys/kernel/osrelease` contains `microsoft` or `WSL` (any case), or
//!    `WSL_DISTRO_NAME` is set.
//! 3. Shell: the basename of `$SHELL` (`.exe` stripped): `fish`, `pwsh`/`powershell`, or a
//!    POSIX shell (`bash`, `zsh`, `sh`, `dash`, `ksh`). Unset: PowerShell on Windows, POSIX
//!    elsewhere. Any other shell (nu, tcsh, csh, ...): PowerShell on Windows (its default),
//!    [`Shell::Other`] elsewhere. (The sign-in hint, `opv login <env>`, is the same in every shell.)
//! 4. Non-interactive credentials, by name only: 1Password `OP_SERVICE_ACCOUNT_TOKEN`, or
//!    Connect (`OP_CONNECT_HOST` / `OP_CONNECT_TOKEN`); each provider's own
//!    (`Provider::credential_vars`, e.g. `FLY_API_TOKEN`). With one set, failures are never
//!    answered with an interactive sign-in command.
//!
//! Credential variables are tested by name only; their values are never read (SR-1).
//! Messages are text, never prompts (FR-9). Detection runs only on failure paths.

use std::fmt;
use std::path::PathBuf;

use crate::adapters::registry;
use crate::cause::Cause;
use crate::error::Error;
use crate::runner::{CommandRunner, READ_ATTEMPTS};

/// Where detection reads its facts. [`ProcessEnv`] is the real one; tests use
/// [`FakeEnv`].
pub trait HostEnv {
    /// `std::env::consts::OS` (`linux`, `macos`, `windows`, ...).
    fn os(&self) -> &str;
    /// True when the variable is set and non-empty. Implementations must not keep the value.
    fn is_set(&self, name: &str) -> bool;
    /// The value of a non-secret flag variable (`CI`, `GITHUB_ACTIONS`). Never called for a
    /// credential variable.
    fn flag(&self, name: &str) -> Option<String>;
    /// `$SHELL`, if set (a path, not a secret).
    fn shell(&self) -> Option<String>;
    /// Contents of `/proc/sys/kernel/osrelease`, if readable.
    fn kernel_osrelease(&self) -> Option<String>;
    /// True when the first `op` on `PATH` is a Windows executable (`MZ` header), as in WSL
    /// with `op` linked to the Windows `op.exe`. Implementations never run `op`; only the
    /// file found on `PATH` is inspected. Default false.
    fn op_is_windows_exe(&self) -> bool {
        false
    }
    /// True when stdin and stdout are both a terminal (a person at the keyboard).
    fn interactive(&self) -> bool {
        false
    }
}

/// The running process's environment.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessEnv;

impl HostEnv for ProcessEnv {
    fn os(&self) -> &str {
        std::env::consts::OS
    }

    fn is_set(&self, name: &str) -> bool {
        std::env::var_os(name).is_some_and(|v| !v.is_empty())
    }

    fn flag(&self, name: &str) -> Option<String> {
        std::env::var_os(name).map(|v| v.to_string_lossy().into_owned())
    }

    fn shell(&self) -> Option<String> {
        std::env::var_os("SHELL").map(|v| v.to_string_lossy().into_owned())
    }

    fn kernel_osrelease(&self) -> Option<String> {
        std::fs::read_to_string("/proc/sys/kernel/osrelease").ok()
    }

    fn op_is_windows_exe(&self) -> bool {
        std::env::var_os("PATH").is_some_and(|paths| op_on_path_is_windows_exe(&paths))
    }

    fn interactive(&self) -> bool {
        use std::io::IsTerminal;
        std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
    }
}

/// A fixed environment for tests.
#[cfg(any(test, feature = "fake"))]
#[derive(Debug, Clone, Default)]
pub struct FakeEnv {
    pub os: String,
    /// (name, value): credential values in tests are dummies.
    pub set: Vec<(String, String)>,
    pub shell: Option<String>,
    pub osrelease: Option<String>,
    /// The first `op` on `PATH` is a Windows executable (WSL with `op.exe`).
    pub op_windows_exe: bool,
    /// Stdin and stdout are a terminal.
    pub tty: bool,
}

#[cfg(any(test, feature = "fake"))]
impl FakeEnv {
    pub fn new(os: &str) -> Self {
        Self {
            os: os.into(),
            ..Self::default()
        }
    }

    pub fn shell(mut self, s: &str) -> Self {
        self.shell = Some(s.into());
        self
    }

    /// Set `name` to `true`.
    pub fn var(mut self, name: &str) -> Self {
        self.set.push((name.into(), "true".into()));
        self
    }

    pub fn var_val(mut self, name: &str, value: &str) -> Self {
        self.set.push((name.into(), value.into()));
        self
    }

    pub fn osrelease(mut self, s: &str) -> Self {
        self.osrelease = Some(s.into());
        self
    }

    /// The `op` on `PATH` is a Windows executable (WSL with `op.exe`).
    pub fn op_windows_exe(mut self) -> Self {
        self.op_windows_exe = true;
        self
    }

    /// Stdin and stdout are a terminal.
    pub fn tty(mut self) -> Self {
        self.tty = true;
        self
    }
}

#[cfg(any(test, feature = "fake"))]
impl HostEnv for FakeEnv {
    fn os(&self) -> &str {
        &self.os
    }
    fn is_set(&self, name: &str) -> bool {
        self.set.iter().any(|(n, v)| n == name && !v.is_empty())
    }
    fn flag(&self, name: &str) -> Option<String> {
        self.set
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    }
    fn shell(&self) -> Option<String> {
        self.shell.clone()
    }
    fn kernel_osrelease(&self) -> Option<String> {
        self.osrelease.clone()
    }
    fn op_is_windows_exe(&self) -> bool {
        self.op_windows_exe
    }
    fn interactive(&self) -> bool {
        self.tty
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Wsl,
    MacOs,
    Windows,
    /// Any other OS; treated like Linux for commands.
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    /// bash, zsh, sh and other POSIX shells: `$(...)` command substitution.
    Posix,
    /// fish: `(...)` command substitution, no `$(`.
    Fish,
    PowerShell,
    /// A shell opv has no syntax for (nu, tcsh, csh, ...): generic guidance only.
    Other,
}

/// A CLI opv runs, and the one install line per platform for it (FR-26). The 1Password
/// CLI is [`OP_CLI`]; each provider declares its own next to its adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tool {
    /// The program name on PATH.
    pub program: &'static str,
    /// Under CI.
    pub ci: &'static str,
    pub macos: &'static str,
    pub windows: &'static str,
    /// Linux, WSL and any other platform.
    pub linux: &'static str,
    /// The service behind the CLI, in messages: "1Password", "Fly".
    pub vendor: &'static str,
    /// The service's status page, named when it does not respond (NR-28).
    pub status_page: &'static str,
    /// Environment added to every captured call of this program (NR-7, NR-11): it
    /// neutralises user configuration that changes output or prompts. Never proxy or CA
    /// variables (NR-29).
    pub pinned_env: &'static [(&'static str, &'static str)],
    /// Stable phrases this CLI prints on stderr for an object that does not exist (S2): a
    /// read failing with one is refused at once, never retried.
    pub not_found: &'static [&'static str],
    /// Stable phrases this CLI prints on stderr when no one is signed in: not transient,
    /// so a read failing with one is refused at once, never retried (found live: three
    /// "retrying op item list" lines before every first sign-in).
    pub signed_out: &'static [&'static str],
    /// Other names the program is installed under, for runnable `Next:` lines (`fly`).
    pub aliases: &'static [&'static str],
    /// The arguments that print its own version locally, without contacting its service
    /// or checking for updates (`opv version`, #131).
    pub version_args: &'static [&'static str],
}

/// Every CLI opv runs: the 1Password CLI, then each registered provider's
/// (`Provider::tools`), so adding a provider needs no change here or in the runner.
pub fn tools() -> impl Iterator<Item = &'static Tool> {
    std::iter::once(&OP_CLI).chain(
        registry::PROVIDERS
            .iter()
            .flat_map(|p| p.tools().iter().copied()),
    )
}

/// The CLI whose program name is `program`, if opv runs it.
pub fn tool(program: &str) -> Option<&'static Tool> {
    tools().find(|t| t.program == program)
}

impl Tool {
    /// NR-28: a read of this service still unanswered after its last attempt (timed out,
    /// killed or lost every time). A read changes nothing, so re-running is safe: exit 9.
    /// The cause comes from this system's diagnosis of the call the runner observed (§5).
    pub fn outage(&self, step: &str) -> Error {
        match crate::runner::take_observed() {
            Some(seen) => diagnose_unanswered(seen).into(),
            None => self.unobserved(step, false),
        }
    }

    /// A read of this service that never answered after its retries (NR-28), before or
    /// after this run wrote to a target: the read itself changed nothing, so it is the
    /// outage either way ([`Tool::outage`]); re-running repeats only idempotent writes.
    pub fn unanswered(&self, r: &dyn CommandRunner, step: &str) -> Error {
        match crate::runner::take_observed() {
            Some(seen) => diagnose_unanswered(seen).into(),
            None => self.unobserved(step, r.writes_started()),
        }
    }

    /// An unanswered call the runner kept no observation of: a [`CommandRunner`] that
    /// reported the call unanswered without the runner's engine (an in-memory world that
    /// loses calls). It is recorded as lost ([`lost_call`]) and diagnosed like any other
    /// unanswered read (NR-28, exit 9).
    pub(crate) fn unobserved(&self, _step: &str, _writes_started: bool) -> Error {
        match lost_call(self.program) {
            Some(failed) => diagnose_unanswered(failed.seen).into(),
            None => Cause::Bug {
                site: "runner: an unanswered call left no observation",
            }
            .into(),
        }
    }

    /// A call of this service the spent run budget never let start (`--timeout`, NR-4,
    /// R52): opv's own limit, never the target's refusal. Its Next is the same command with
    /// twice the budget.
    pub fn budget_spent(&self, r: &dyn CommandRunner, e: &std::io::Error) -> Error {
        let _ = e;
        Cause::BudgetSpent {
            budget_seconds: run_budget_seconds(&crate::error::invocation()),
            writes_started: r.writes_started(),
        }
        .into()
    }

    /// The one install line of this tool for `platform`, or the CI job's under CI (FR-26):
    /// the line both [`Host::install_hint`] and the catalog's `ToolMissing` show.
    pub fn install_line(&self, platform: Platform, ci: bool) -> &'static str {
        match (ci, platform) {
            (true, _) => self.ci,
            (false, Platform::MacOs) => self.macos,
            (false, Platform::Windows) => self.windows,
            (false, Platform::Linux | Platform::Wsl | Platform::Other) => self.linux,
        }
    }
}

/// The run budget (`--timeout`) of `inv` in seconds: the flag as given, else the default.
fn run_budget_seconds(inv: &crate::cause::Invocation) -> u64 {
    let mut args = inv.args.iter();
    while let Some(a) = args.next() {
        let value = match a.strip_prefix("--timeout") {
            Some("") => args.next().map(String::as_str),
            Some(rest) => rest.strip_prefix('='),
            None => None,
        };
        if let Some(secs) = value.and_then(|v| v.parse().ok()) {
            return secs;
        }
    }
    crate::runner::DEFAULT_RUN_TIMEOUT.as_secs()
}

/// The cause of a call that never answered, from its own system's diagnosis (§5).
/// The latest call of `program`, which its [`CommandRunner`] reported unanswered (an
/// `Outcome::Unknown`) without the runner observing it: recorded through the runner as a
/// lost reply ([`crate::cause::ExitClass::Lost`], no stderr), so its system's diagnosis
/// sees what the caller saw: no answer. The runners opv ships observe every attempt
/// themselves (B1); only in-memory doubles reach this.
pub(crate) fn lost_call(program: &str) -> Option<crate::runner::Failure> {
    crate::runner::record_streamed(program, &[], crate::cause::ExitClass::Lost, b"");
    crate::runner::take_failure()
}

fn diagnose_unanswered(seen: crate::cause::Observed) -> Cause {
    use crate::adapters::{azure, fly, github, kubernetes, onepassword_diagnose};
    use crate::cause::{DiagnoseContext, System, Unanswered};
    let ctx = DiagnoseContext::default();
    let cause = match seen.call().system {
        System::OnePassword => onepassword_diagnose::diagnose(seen, "", &ctx),
        System::Fly => fly::diagnose::diagnose(seen, "", &ctx),
        System::Azure => azure::diagnose::diagnose(seen, "", &ctx),
        System::Kubernetes => kubernetes::diagnose::diagnose(seen, "", &ctx),
        System::GitHub => github::diagnose::diagnose(seen, "", &ctx),
        system @ (System::Ssh | System::RemoteOpv) => Cause::Unavailable {
            system,
            why: seen.exit().unanswered().unwrap_or(Unanswered::Timeout),
            attempts: READ_ATTEMPTS,
            seen,
        },
    };
    // Only called once every read attempt went unanswered: the count is the runner's.
    match cause {
        Cause::Unavailable {
            system, why, seen, ..
        } => Cause::Unavailable {
            system,
            why,
            attempts: READ_ATTEMPTS,
            seen,
        },
        other => other,
    }
}

/// The catalog's [`Cause::ToolMissing`] for `tool` on this host (R56): its install line is
/// [`Tool::install_line`], so the platform lines live in one place.
pub fn tool_missing(tool: &Tool) -> Cause {
    let host = Host::detect();
    Cause::ToolMissing {
        tool: tool.program.to_string(),
        platform: host.platform,
        shell: host.shell,
        ci: host.ci,
    }
}

/// The 1Password CLI.
pub const OP_CLI: Tool = Tool {
    program: "op",
    ci: "install op in the CI job (GitHub Actions: uses: 1password/install-cli-action)",
    macos: "install: brew install 1password-cli",
    windows: "install: winget install AgileBits.1Password.CLI",
    linux: "install op from https://developer.1password.com/docs/cli/get-started/ \
            (apt, dnf or the zip for this Linux distribution)",
    vendor: "1Password",
    status_page: "https://status.1password.com",
    pinned_env: &[("NO_COLOR", "1")],
    not_found: &["isn't an item", "isn't a vault"],
    signed_out: &[
        "You are not currently signed in",
        // `op whoami` and other calls with an account but no session (found live).
        "could not find session token",
        // An expired session still in the environment (found live: a signed-in shell
        // left idle over 30 minutes), and op's other signed-out wordings.
        "session expired",
        "account is not signed in",
        "Invalid session token",
        "session token not set in environment",
        "invalid session:",
    ],
    aliases: &[],
    version_args: &["--version"],
};

/// A non-interactive 1Password credential in the environment (by name; value never read).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCredential {
    /// `OP_SERVICE_ACCOUNT_TOKEN`.
    ServiceAccount,
    /// `OP_CONNECT_HOST` / `OP_CONNECT_TOKEN`.
    Connect,
}

impl OpCredential {
    /// The variable holding the token.
    pub fn var(self) -> &'static str {
        match self {
            OpCredential::ServiceAccount => "OP_SERVICE_ACCOUNT_TOKEN",
            OpCredential::Connect => "OP_CONNECT_TOKEN",
        }
    }

    /// `service-account` / `Connect`, for messages.
    pub fn label(self) -> &'static str {
        match self {
            OpCredential::ServiceAccount => "service-account",
            OpCredential::Connect => "Connect",
        }
    }
}

/// The detected host: platform, shell, CI, and which non-interactive credentials are set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Host {
    pub platform: Platform,
    pub shell: Shell,
    pub ci: bool,
    /// A non-interactive 1Password credential, if set (service account wins over Connect).
    pub op_credential: Option<OpCredential>,
    /// Stdin and stdout are a terminal: `opv login` can sign in here (P7).
    pub interactive: bool,
    /// Which of [`registry::credential_vars`] are set, one bit each (by name; values are
    /// never read). Read with [`Host::token`].
    tokens: u64,
    /// The `op` found on `PATH` is a Windows executable (WSL with `op.exe`).
    op_windows_exe: bool,
}

impl Host {
    /// Detect from the running process. Callers do this only on failure paths.
    ///
    /// In this crate's unit tests it returns a fixed host instead (Linux, bash, no CI, no
    /// credentials; or the one set with [`with_test_host`]), so no test depends on the
    /// developer's or the CI runner's environment.
    pub fn detect() -> Self {
        #[cfg(test)]
        {
            TEST_HOST.with(|h| {
                h.get()
                    .unwrap_or_else(|| Self::from_env(&FakeEnv::new("linux").shell("/bin/bash")))
            })
        }
        #[cfg(not(test))]
        {
            Self::from_env(&ProcessEnv)
        }
    }

    /// Detect from `env` (the testable seam). See the module docs for the rules.
    pub fn from_env(env: &dyn HostEnv) -> Self {
        let truthy = |name: &str| {
            env.flag(name).is_some_and(|v| {
                let v = v.trim().to_ascii_lowercase();
                !v.is_empty() && v != "false" && v != "0"
            })
        };
        let ci = truthy("CI") || truthy("GITHUB_ACTIONS");
        let platform = match env.os() {
            "windows" => Platform::Windows,
            "macos" => Platform::MacOs,
            "linux" => {
                let wsl_kernel = env.kernel_osrelease().is_some_and(|r| {
                    let r = r.to_ascii_lowercase();
                    r.contains("microsoft") || r.contains("wsl")
                });
                if wsl_kernel || env.is_set("WSL_DISTRO_NAME") {
                    Platform::Wsl
                } else {
                    Platform::Linux
                }
            }
            _ => Platform::Other,
        };
        // An empty `$SHELL` counts as unset.
        let named = env.shell().filter(|s| !s.trim().is_empty()).map(|s| {
            let base = s
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            let base = base.strip_suffix(".exe").unwrap_or(&base).to_string();
            match base.as_str() {
                "fish" => Shell::Fish,
                "pwsh" | "powershell" => Shell::PowerShell,
                "bash" | "zsh" | "sh" | "dash" | "ksh" => Shell::Posix,
                _ if platform == Platform::Windows => Shell::PowerShell,
                _ => Shell::Other,
            }
        });
        let shell = named.unwrap_or(match platform {
            Platform::Windows => Shell::PowerShell,
            _ => Shell::Posix,
        });
        let op_credential = if env.is_set("OP_SERVICE_ACCOUNT_TOKEN") {
            Some(OpCredential::ServiceAccount)
        } else if env.is_set("OP_CONNECT_HOST") || env.is_set("OP_CONNECT_TOKEN") {
            Some(OpCredential::Connect)
        } else {
            None
        };
        let tokens = registry::credential_vars()
            .iter()
            .enumerate()
            .filter(|(_, n)| env.is_set(n))
            .fold(0, |bits, (i, _)| bits | 1 << i);
        let op_windows_exe = platform == Platform::Wsl && env.op_is_windows_exe();
        Host {
            platform,
            shell,
            ci,
            op_credential,
            interactive: env.interactive(),
            tokens,
            op_windows_exe,
        }
    }

    /// True when the `op` on `PATH` is the Windows `op.exe` (WSL with `op` linked to it).
    /// Reads then go through the Windows 1Password app, which is where the session and the
    /// accounts live, so opv must not tell the person to add an account at op's own prompt.
    /// Never true off WSL.
    pub fn op_is_windows_exe(&self) -> bool {
        self.op_windows_exe
    }

    /// The first of a provider's `vars` that is set, by name (FR-26).
    pub fn token(&self, vars: &[&'static str]) -> Option<&'static str> {
        let all = registry::credential_vars();
        vars.iter().copied().find(|v| {
            all.iter()
                .position(|a| a == v)
                .is_some_and(|i| self.tokens & 1 << i != 0)
        })
    }

    /// The sign-in command, `opv login <env>` (or `opv login` when no environment is
    /// known), the same on every platform and shell, or `None` when no interactive sign-in
    /// applies (under CI, or with a non-interactive 1Password credential set). It signs in
    /// to the account that environment uses (FR-40); no token is printed or evaluated.
    pub fn signin_command(&self, env: Option<&str>) -> Option<String> {
        if self.ci || self.op_credential.is_some() {
            return None;
        }
        Some(match env {
            Some(e) if !e.is_empty() => format!("opv login {e}"),
            _ => "opv login".to_string(),
        })
    }

    /// The sign-in step as a message line led by `lead` (`sign in`, `then sign in`):
    /// `sign in: opv login prod`.
    pub fn signin_line(&self, lead: &str, env: Option<&str>) -> Option<String> {
        self.signin_command(env).map(|c| format!("{lead}: {c}"))
    }

    /// One line telling the user how to install `tool` on this platform.
    pub fn install_hint(&self, tool: Tool) -> String {
        // Installed but not on PATH (#77): say where, not "install it again".
        if !self.ci
            && let Some(found) = installed_off_path(tool.program, self.platform)
        {
            return self.off_path_hint(&tool, &found);
        }
        tool.install_line(self.platform, self.ci).into()
    }

    /// `tool` is installed at `found` but its folder is not on PATH: how to add it, in this
    /// platform's and shell's own words.
    fn off_path_hint(&self, tool: &Tool, found: &std::path::Path) -> String {
        let dir = found
            .parent()
            .map(|d| d.display().to_string())
            .unwrap_or_default();
        match self.platform {
            Platform::Windows => format!(
                "{} is installed at {} but its folder is not on PATH: add {dir} to PATH \
                     (Settings > System > About > Advanced system settings > Environment \
                     Variables), then open a new terminal",
                tool.program,
                found.display()
            ),
            // fish has no `export PATH=…` (02.29): its own command adds the folder.
            _ if self.shell == Shell::Fish => format!(
                "{} is installed at {} but not on PATH: add it with fish_add_path {dir}, \
                     then open a new terminal",
                tool.program,
                found.display()
            ),
            _ => format!(
                "{} is installed at {} but not on PATH: add it, for example with \
                     export PATH=\"{dir}:$PATH\" in your shell profile, then open a new terminal",
                tool.program,
                found.display()
            ),
        }
    }
}

/// True when the first `op` on `paths` (a `PATH` value) is a Windows executable. Shares
/// [`crate::runner::windows_binary`] with the WSL `local_run_supported` check; never runs
/// `op`.
fn op_on_path_is_windows_exe(paths: &std::ffi::OsStr) -> bool {
    for dir in std::env::split_paths(paths) {
        let path = dir.join("op");
        if path.is_file() {
            return crate::runner::windows_binary(&path).unwrap_or(false);
        }
    }
    false
}

/// The places a CLI is commonly installed outside a default PATH, per platform.
fn known_locations(
    program: &str,
    platform: Platform,
    home: Option<&std::path::Path>,
) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    match platform {
        Platform::Windows => {
            if let Some(local) = std::env::var_os("LOCALAPPDATA") {
                dirs.push(
                    PathBuf::from(&local)
                        .join("Microsoft")
                        .join("WinGet")
                        .join("Links"),
                );
            }
            dirs.push(PathBuf::from(r"C:\Program Files\1Password CLI"));
            dirs.push(PathBuf::from(r"C:\Program Files\GitHub CLI"));
        }
        _ => {
            if let Some(h) = home {
                dirs.push(h.join(".local").join("bin"));
                dirs.push(h.join("bin"));
                dirs.push(h.join(".fly").join("bin"));
            }
            dirs.extend(
                [
                    "/usr/local/bin",
                    "/opt/homebrew/bin",
                    "/usr/bin",
                    "/snap/bin",
                ]
                .map(PathBuf::from),
            );
        }
    }
    let exe = if platform == Platform::Windows {
        format!("{program}.exe")
    } else {
        program.to_string()
    };
    dirs.into_iter().map(|d| d.join(&exe)).collect()
}

/// Where `program` is installed when it is not on PATH: the first known location holding a
/// file of that name. `None` when it is on PATH or found nowhere.
// Like Host::detect, fake-host unit tests must not inspect the developer's
// installed tools. The discovery algorithm is covered with explicit temporary
// homes and PATHs by off_path_tests below; binaries/integration tests use the real
// wrapper unchanged.
#[cfg(test)]
pub fn installed_off_path(_program: &str, _platform: Platform) -> Option<PathBuf> {
    None
}

#[cfg(not(test))]
pub fn installed_off_path(program: &str, platform: Platform) -> Option<PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    installed_off_path_in(
        program,
        platform,
        std::env::var_os("PATH").as_deref(),
        home.as_deref(),
    )
}

/// [`installed_off_path`] with `PATH` and the home directory given (testable).
fn installed_off_path_in(
    program: &str,
    platform: Platform,
    path: Option<&std::ffi::OsStr>,
    home: Option<&std::path::Path>,
) -> Option<PathBuf> {
    let on_path = path.is_some_and(|p| {
        std::env::split_paths(p)
            .any(|d| d.join(program).is_file() || d.join(format!("{program}.exe")).is_file())
    });
    if on_path {
        return None;
    }
    known_locations(program, platform, home)
        .into_iter()
        .find(|p| p.is_file())
}

#[cfg(test)]
mod off_path_tests {
    use super::*;

    fn home_with_local_op() -> tempfile::TempDir {
        let home = tempfile::tempdir().unwrap();
        let bin = home.path().join(".local").join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("op-opvtest"), b"").unwrap();
        home
    }

    #[test]
    fn a_tool_in_a_known_place_off_path_is_found() {
        let home = home_with_local_op();
        let found = installed_off_path_in(
            "op-opvtest",
            Platform::Linux,
            Some(std::ffi::OsStr::new("/nonexistent")),
            Some(home.path()),
        );
        assert_eq!(found, Some(home.path().join(".local/bin/op-opvtest")));
    }

    #[test]
    fn a_tool_on_path_is_not_reported() {
        let home = home_with_local_op();
        let bin = home.path().join(".local").join("bin");
        let found = installed_off_path_in(
            "op-opvtest",
            Platform::Linux,
            Some(bin.as_os_str()),
            Some(home.path()),
        );
        assert_eq!(found, None);
    }

    #[test]
    fn a_tool_found_nowhere_is_not_reported() {
        let home = tempfile::tempdir().unwrap();
        let found = installed_off_path_in(
            "op-opvtest",
            Platform::Linux,
            Some(std::ffi::OsStr::new("/nonexistent")),
            Some(home.path()),
        );
        assert_eq!(found, None);
    }
}

#[cfg(test)]
thread_local! {
    static TEST_HOST: std::cell::Cell<Option<Host>> = const { std::cell::Cell::new(None) };
}

/// Run `f` with [`Host::detect`] returning `host` on this thread (unit tests only).
#[cfg(test)]
pub(crate) fn with_test_host<T>(host: Host, f: impl FnOnce() -> T) -> T {
    TEST_HOST.with(|h| h.set(Some(host)));
    let out = f();
    TEST_HOST.with(|h| h.set(None));
    out
}

/// One `opv` found on `PATH` (Task I).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpvCopy {
    /// A native opv binary.
    Binary(PathBuf),
    /// The npm `bin` wrapper (`.../@matthew-cochran/opv/bin/opv.js`). It runs the
    /// canonical binary when its version matches the package, so it is not a second
    /// copy. `version` is the package version, when readable.
    NpmWrapper {
        path: PathBuf,
        version: Option<String>,
    },
}

#[cfg(test)]
thread_local! {
    static TEST_PATH: std::cell::RefCell<Option<Vec<OpvCopy>>> =
        const { std::cell::RefCell::new(None) };
}

/// Run `f` with [`opv_copies_on_path`] returning `copies` on this thread (unit tests).
#[cfg(test)]
pub(crate) fn with_test_path<T>(copies: Vec<OpvCopy>, f: impl FnOnce() -> T) -> T {
    TEST_PATH.with(|p| *p.borrow_mut() = Some(copies));
    let out = f();
    TEST_PATH.with(|p| *p.borrow_mut() = None);
    out
}

/// True when `file` resolves to the npm package's `bin/opv.js`.
fn is_npm_wrapper(file: &std::path::Path) -> bool {
    let parts: Vec<_> = file
        .components()
        .rev()
        .take(4)
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    parts == ["opv.js", "bin", "opv", "@matthew-cochran"]
}

/// The `version` in the `package.json` that sits above a wrapper's `bin/` directory.
#[cfg_attr(test, allow(dead_code))]
fn wrapper_version(file: &std::path::Path) -> Option<String> {
    let manifest = file.parent()?.parent()?.join("package.json");
    let text = std::fs::read_to_string(manifest).ok()?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;
    json.get("version")?.as_str().map(str::to_owned)
}

/// Every distinct `opv` (`opv.exe` on Windows) in the directories on `PATH`, in `PATH`
/// order. Symlinks to the same file count once, and the npm wrapper is reported as a
/// wrapper, not as a native copy.
///
/// `doctor` uses this (Task I) to warn when the shell could run a different copy from
/// the one npm or `install.sh` installed.
pub fn opv_copies_on_path() -> Vec<OpvCopy> {
    #[cfg(test)]
    {
        // Unit tests control the candidates; without an explicit list there are none, so
        // no test depends on the developer's or the CI runner's PATH.
        TEST_PATH.with(|p| p.borrow().clone()).unwrap_or_default()
    }
    #[cfg(not(test))]
    {
        let name = if cfg!(windows) { "opv.exe" } else { "opv" };
        let Some(path) = std::env::var_os("PATH") else {
            return Vec::new();
        };
        let mut out: Vec<OpvCopy> = Vec::new();
        let mut seen: Vec<PathBuf> = Vec::new();
        for dir in std::env::split_paths(&path) {
            if dir.as_os_str().is_empty() {
                continue;
            }
            let candidate = dir.join(name);
            if !candidate.is_file() {
                continue;
            }
            let key = candidate
                .canonicalize()
                .unwrap_or_else(|_| candidate.clone());
            if seen.contains(&key) {
                continue;
            }
            seen.push(key.clone());
            if is_npm_wrapper(&key) {
                out.push(OpvCopy::NpmWrapper {
                    version: wrapper_version(&key),
                    path: candidate,
                });
            } else {
                out.push(OpvCopy::Binary(candidate));
            }
        }
        out
    }
}

#[cfg(test)]
mod copy_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn npm_package_entry_point_is_a_wrapper() {
        assert!(is_npm_wrapper(Path::new(
            "/usr/lib/node_modules/@matthew-cochran/opv/bin/opv.js"
        )));
    }

    #[test]
    fn a_binary_named_opv_is_not_a_wrapper() {
        assert!(!is_npm_wrapper(Path::new("/home/x/.local/bin/opv")));
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Platform::Linux => "Linux",
            Platform::Wsl => "WSL",
            Platform::MacOs => "macOS",
            Platform::Windows => "Windows",
            Platform::Other => "this OS",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(env: FakeEnv) -> Host {
        Host::from_env(&env)
    }

    /// The real environment seam runs without panicking (its result depends on the host).
    #[test]
    fn process_env_detection_runs() {
        let _ = Host::from_env(&ProcessEnv);
        assert!(!ProcessEnv.os().is_empty());
    }

    #[test]
    fn ci_is_detected_from_ci_or_github_actions() {
        for var in ["CI", "GITHUB_ACTIONS"] {
            let h = host(FakeEnv::new("linux").shell("/bin/bash").var(var));
            assert!(h.ci, "{var}");
            assert_eq!(h.signin_command(Some("dev")), None, "{var}");
        }
        assert!(!host(FakeEnv::new("linux")).ci);
    }

    #[test]
    fn wsl_is_detected_from_kernel_or_distro_name() {
        for rel in [
            "6.6.87.2-microsoft-standard-WSL2\n",
            "4.4.0-19041-Microsoft",
            "5.15.0-wsl",
        ] {
            let h = host(FakeEnv::new("linux").osrelease(rel));
            assert_eq!(h.platform, Platform::Wsl, "{rel}");
        }
        let h = host(FakeEnv::new("linux").var("WSL_DISTRO_NAME"));
        assert_eq!(h.platform, Platform::Wsl);
        let h = host(FakeEnv::new("linux").osrelease("6.8.0-45-generic"));
        assert_eq!(h.platform, Platform::Linux);
        // The kernel file is consulted only on Linux.
        let h = host(FakeEnv::new("macos").osrelease("microsoft"));
        assert_eq!(h.platform, Platform::MacOs);
    }

    #[test]
    fn shell_from_dollar_shell_with_platform_defaults() {
        let cases = [
            ("linux", Some("/bin/bash"), Shell::Posix),
            ("linux", Some("/usr/bin/zsh"), Shell::Posix),
            ("macos", Some("/bin/zsh"), Shell::Posix),
            ("linux", Some("/usr/bin/fish"), Shell::Fish),
            ("macos", Some("/opt/homebrew/bin/fish"), Shell::Fish),
            ("linux", Some("/usr/bin/pwsh"), Shell::PowerShell),
            ("linux", None, Shell::Posix),
            ("linux", Some("/usr/bin/nu"), Shell::Other),
            ("macos", Some("/bin/tcsh"), Shell::Other),
            ("linux", Some("/bin/csh"), Shell::Other),
            (
                "windows",
                Some(r"C:\Windows\System32\cmd.exe"),
                Shell::PowerShell,
            ),
            ("windows", None, Shell::PowerShell),
            (
                "windows",
                Some(r"C:\Program Files\Git\usr\bin\bash.exe"),
                Shell::Posix,
            ),
            ("windows", Some("/usr/bin/bash"), Shell::Posix),
        ];
        for (os, sh, want) in cases {
            let mut env = FakeEnv::new(os);
            env.shell = sh.map(String::from);
            assert_eq!(host(env).shell, want, "{os} {sh:?}");
        }
    }

    /// The same `opv login <env>` on every platform and shell: no eval, no token.
    #[test]
    fn signin_command_is_opv_login_on_every_shell() {
        let shells = [
            FakeEnv::new("linux").shell("/bin/bash"),
            FakeEnv::new("linux").shell("/usr/bin/fish"),
            FakeEnv::new("windows"),
            FakeEnv::new("linux").shell("/usr/bin/nu"),
        ];
        let got: Vec<_> = shells
            .into_iter()
            .map(|e| host(e).signin_command(Some("prod")))
            .collect();
        assert_eq!(got, vec![Some("opv login prod".to_string()); 4]);
    }

    #[test]
    fn signin_command_without_an_environment_is_plain_opv_login() {
        let h = host(FakeEnv::new("linux").shell("/bin/bash"));
        assert_eq!(
            h.signin_line("sign in", None).as_deref(),
            Some("sign in: opv login")
        );
    }

    #[test]
    fn op_credential_by_name_service_account_then_connect() {
        let h = |e: FakeEnv| host(e).op_credential;
        assert_eq!(h(FakeEnv::new("linux")), None);
        assert_eq!(
            h(FakeEnv::new("linux").var_val("OP_SERVICE_ACCOUNT_TOKEN", "")),
            None,
            "empty is unset"
        );
        assert_eq!(
            h(FakeEnv::new("linux").var("OP_SERVICE_ACCOUNT_TOKEN")),
            Some(OpCredential::ServiceAccount)
        );
        for v in ["OP_CONNECT_HOST", "OP_CONNECT_TOKEN"] {
            assert_eq!(
                h(FakeEnv::new("linux").var(v)),
                Some(OpCredential::Connect),
                "{v}"
            );
        }
        assert_eq!(
            h(FakeEnv::new("linux")
                .var("OP_CONNECT_HOST")
                .var("OP_SERVICE_ACCOUNT_TOKEN")),
            Some(OpCredential::ServiceAccount)
        );
    }

    /// A non-interactive credential means no interactive sign-in command, ever.
    #[test]
    fn no_signin_command_with_a_non_interactive_credential() {
        for v in [
            "OP_SERVICE_ACCOUNT_TOKEN",
            "OP_CONNECT_HOST",
            "OP_CONNECT_TOKEN",
        ] {
            let h = host(FakeEnv::new("linux").shell("/bin/bash").var(v));
            assert_eq!(h.signin_line("sign in", Some("prod")), None, "{v}");
        }
    }

    #[test]
    fn token_is_the_first_set_variable_of_the_given_ones() {
        let all = registry::credential_vars();
        let h = host(FakeEnv::new("linux").var(all[1]).var(all[0]));
        assert_eq!(h.token(&all[..2]), Some(all[0]));
    }

    #[test]
    fn token_is_none_when_no_given_variable_is_set() {
        let all = registry::credential_vars();
        assert_eq!(host(FakeEnv::new("linux")).token(&all), None);
    }

    /// `CI` counts only when truthy; `GITHUB_ACTIONS=true` counts.
    #[test]
    fn ci_requires_a_truthy_value() {
        for v in ["", "false", "FALSE", "0", " 0 "] {
            let h = host(FakeEnv::new("linux").var_val("CI", v));
            assert!(!h.ci, "CI={v:?}");
        }
        for v in ["true", "1", "yes", "TRUE"] {
            let h = host(FakeEnv::new("linux").var_val("CI", v));
            assert!(h.ci, "CI={v:?}");
        }
        assert!(host(FakeEnv::new("linux").var_val("GITHUB_ACTIONS", "true")).ci);
        assert!(!host(FakeEnv::new("linux").var_val("GITHUB_ACTIONS", "false")).ci);
    }

    /// CI keeps the service-account wording even on a terminal.
    #[test]
    fn interactive_ci_has_no_signin_line() {
        let h = host(FakeEnv::new("linux").shell("/bin/bash").tty().var("CI"));
        assert_eq!(h.signin_line("sign in", Some("prod")), None);
    }

    #[test]
    fn install_hint_per_platform() {
        let hints: Vec<String> = [
            FakeEnv::new("macos"),
            FakeEnv::new("windows"),
            FakeEnv::new("linux").var("WSL_DISTRO_NAME"),
            FakeEnv::new("linux").var("CI"),
        ]
        .into_iter()
        .map(|e| host(e).install_hint(OP_CLI))
        .collect();
        assert_eq!(
            hints,
            [OP_CLI.macos, OP_CLI.windows, OP_CLI.linux, OP_CLI.ci]
        );
    }

    /// 02.29: under fish the off-PATH hint is fish's own command, never `export PATH=`.
    #[test]
    fn off_path_hint_under_fish_uses_fish_add_path() {
        let h = host(FakeEnv::new("linux").shell("/usr/bin/fish"));
        let hint = h.off_path_hint(&OP_CLI, std::path::Path::new("/home/me/.local/bin/op"));
        assert!(hint.contains("fish_add_path /home/me/.local/bin"), "{hint}");
    }

    /// The catalog's ToolMissing and the hint read the same per-platform line.
    #[test]
    fn install_line_is_the_platform_line() {
        assert_eq!(OP_CLI.install_line(Platform::MacOs, false), OP_CLI.macos);
    }

    /// 02.06: a spent run budget is opv's own limit (budget_spent), never a target refusal.
    #[test]
    fn a_spent_budget_is_budget_spent() {
        let r = crate::runner::fake::FakeRunner::default();
        let e = OP_CLI.budget_spent(&r, &std::io::Error::from(std::io::ErrorKind::TimedOut));
        assert_eq!(e.code_str(), "budget_spent");
    }

    /// 02.06: the budget comes from the invocation's `--timeout`, so Next doubles it.
    #[test]
    fn the_run_budget_is_the_timeout_flag() {
        let inv = crate::cause::Invocation::from_cli(&[
            "opv".into(),
            "--timeout".into(),
            "40".into(),
            "sync".into(),
            "prod".into(),
        ]);
        assert_eq!(super::run_budget_seconds(&inv), 40);
    }

    /// The Windows `op.exe` is named only in WSL, where reads go through the Windows app.
    #[test]
    fn op_is_windows_exe_is_named_only_in_wsl() {
        let wsl = host(
            FakeEnv::new("linux")
                .var("WSL_DISTRO_NAME")
                .op_windows_exe(),
        );
        assert!(wsl.op_is_windows_exe());
    }

    #[test]
    fn plain_wsl_linux_op_is_not_windows_exe() {
        let wsl = host(FakeEnv::new("linux").var("WSL_DISTRO_NAME"));
        assert!(!wsl.op_is_windows_exe());
    }

    #[test]
    fn plain_linux_is_never_a_windows_exe() {
        let linux = host(FakeEnv::new("linux").op_windows_exe());
        assert!(!linux.op_is_windows_exe());
    }

    /// The detection reads the `MZ` header of the `op` found on `PATH`, never running it.
    #[test]
    fn op_on_path_is_windows_exe_reads_the_mz_header() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("op"), b"MZ\x90\x00").unwrap();
        assert!(op_on_path_is_windows_exe(dir.path().as_os_str()));
    }
}
