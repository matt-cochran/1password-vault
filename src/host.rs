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
//!    [`Shell::Other`] elsewhere, which gets a generic `op signin` hint, never POSIX syntax.
//! 4. Non-interactive credentials, by name only: 1Password `OP_SERVICE_ACCOUNT_TOKEN`, or
//!    Connect (`OP_CONNECT_HOST` / `OP_CONNECT_TOKEN`); Fly `FLY_API_TOKEN` /
//!    `FLY_ACCESS_TOKEN`. With one set, failures are never answered with an interactive
//!    sign-in command.
//!
//! Credential variables are tested by name only; their values are never read (SR-1).
//! Messages are text, never prompts (FR-9). Detection runs only on failure paths.

use std::fmt;
use std::path::PathBuf;

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

/// A tool opv runs, for install guidance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Op,
    Flyctl,
}

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

/// How the user can sign `op` in from this shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignIn {
    /// The exact command for this shell.
    Command(&'static str),
    /// A shell opv has no syntax for: point at `op signin` and its help.
    Generic,
}

/// The detected host: platform, shell, CI, and which non-interactive credentials are set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Host {
    pub platform: Platform,
    pub shell: Shell,
    pub ci: bool,
    /// A non-interactive 1Password credential, if set (service account wins over Connect).
    pub op_credential: Option<OpCredential>,
    /// `FLY_API_TOKEN` or `FLY_ACCESS_TOKEN`, whichever is set (that order), by name.
    pub fly_token: Option<&'static str>,
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
        let fly_token = ["FLY_API_TOKEN", "FLY_ACCESS_TOKEN"]
            .into_iter()
            .find(|n| env.is_set(n));
        Host {
            platform,
            shell,
            ci,
            op_credential,
            fly_token,
        }
    }

    /// How to sign `op` in from this shell, or `None` when no interactive sign-in applies
    /// (under CI, or with a non-interactive 1Password credential set).
    pub fn signin(&self) -> Option<SignIn> {
        if self.ci || self.op_credential.is_some() {
            return None;
        }
        Some(match self.shell {
            Shell::Posix => SignIn::Command("eval $(op signin)"),
            Shell::Fish => SignIn::Command("eval (op signin)"),
            Shell::PowerShell => SignIn::Command("Invoke-Expression $(op signin)"),
            Shell::Other => SignIn::Generic,
        })
    }

    /// The exact sign-in command, when there is one for this shell.
    pub fn signin_command(&self) -> Option<&'static str> {
        match self.signin()? {
            SignIn::Command(c) => Some(c),
            SignIn::Generic => None,
        }
    }

    /// The sign-in step as a message line led by `lead` (`sign in`, `then sign in`):
    /// `sign in: eval $(op signin)`, or for an unknown shell
    /// ``sign in with `op signin` (see `op signin --help` for your shell)``.
    pub fn signin_line(&self, lead: &str) -> Option<String> {
        Some(match self.signin()? {
            SignIn::Command(c) => format!("{lead}: {c}"),
            SignIn::Generic => {
                format!("{lead} with `op signin` (see `op signin --help` for your shell)")
            }
        })
    }

    /// One line telling the user how to install `tool` on this platform.
    pub fn install_hint(&self, tool: Tool) -> String {
        if self.ci {
            return match tool {
                Tool::Op => "install op in the CI job (GitHub Actions: \
                             uses: 1password/install-cli-action)"
                    .into(),
                Tool::Flyctl => "install flyctl in the CI job (GitHub Actions: \
                                 uses: superfly/flyctl-actions/setup-flyctl@master)"
                    .into(),
            };
        }
        let cmd = match (tool, self.platform) {
            (Tool::Op, Platform::MacOs) => "brew install 1password-cli",
            (Tool::Op, Platform::Windows) => "winget install AgileBits.1Password.CLI",
            (Tool::Op, _) => {
                return "install op from https://developer.1password.com/docs/cli/get-started/ \
                        (apt, dnf or the zip for this Linux distribution)"
                    .into();
            }
            (Tool::Flyctl, Platform::MacOs) => "brew install flyctl",
            (Tool::Flyctl, Platform::Windows) => "iwr https://fly.io/install.ps1 -useb | iex",
            (Tool::Flyctl, _) => "curl -L https://fly.io/install.sh | sh",
        };
        format!("install: {cmd}")
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

#[cfg(test)]
thread_local! {
    static TEST_PATH: std::cell::RefCell<Option<Vec<PathBuf>>> =
        const { std::cell::RefCell::new(None) };
}

/// Run `f` with [`distinct_opv_on_path`] returning `paths` on this thread (unit tests).
#[cfg(test)]
pub(crate) fn with_test_path<T>(paths: Vec<PathBuf>, f: impl FnOnce() -> T) -> T {
    TEST_PATH.with(|p| *p.borrow_mut() = Some(paths));
    let out = f();
    TEST_PATH.with(|p| *p.borrow_mut() = None);
    out
}

/// Every distinct file named `opv` (`opv.exe` on Windows) found in the directories on
/// `PATH`, in `PATH` order. Symlinks to the same file count once.
///
/// `doctor` uses this (Task I) to warn when the shell could run a different copy from
/// the one npm or `install.sh` installed.
pub fn distinct_opv_on_path() -> Vec<PathBuf> {
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
        let mut out: Vec<PathBuf> = Vec::new();
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
            seen.push(key);
            out.push(candidate);
        }
        out
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
            assert_eq!(h.signin_command(), None, "{var}");
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

    #[test]
    fn signin_command_per_shell() {
        let bash = host(FakeEnv::new("linux").shell("/bin/bash"));
        assert_eq!(bash.signin_command(), Some("eval $(op signin)"));
        let fish = host(FakeEnv::new("linux").shell("/usr/bin/fish"));
        assert_eq!(fish.signin_command(), Some("eval (op signin)"));
        let ps = host(FakeEnv::new("windows"));
        assert_eq!(ps.signin_command(), Some("Invoke-Expression $(op signin)"));
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
            assert_eq!(h.signin(), None, "{v}");
            assert_eq!(h.signin_line("sign in"), None, "{v}");
        }
    }

    #[test]
    fn fly_token_by_name() {
        assert_eq!(host(FakeEnv::new("linux")).fly_token, None);
        assert_eq!(
            host(FakeEnv::new("linux").var("FLY_ACCESS_TOKEN")).fly_token,
            Some("FLY_ACCESS_TOKEN")
        );
        assert_eq!(
            host(
                FakeEnv::new("linux")
                    .var("FLY_ACCESS_TOKEN")
                    .var("FLY_API_TOKEN")
            )
            .fly_token,
            Some("FLY_API_TOKEN")
        );
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

    /// Unknown shells get no POSIX syntax, only the generic `op signin` pointer.
    #[test]
    fn unknown_shell_gets_generic_signin_hint() {
        for sh in ["/usr/bin/nu", "/bin/tcsh", "/bin/csh", "/usr/bin/xonsh"] {
            let h = host(FakeEnv::new("linux").shell(sh));
            assert_eq!(h.signin(), Some(SignIn::Generic), "{sh}");
            assert_eq!(h.signin_command(), None, "{sh}");
            let l = h.signin_line("sign in").unwrap();
            assert_eq!(
                l,
                "sign in with `op signin` (see `op signin --help` for your shell)"
            );
            assert!(!l.contains("$(") && !l.contains("eval"), "{l}");
        }
    }

    #[test]
    fn install_hint_per_platform() {
        let h = |os: &str| host(FakeEnv::new(os));
        assert_eq!(
            h("macos").install_hint(Tool::Op),
            "install: brew install 1password-cli"
        );
        assert_eq!(
            h("windows").install_hint(Tool::Op),
            "install: winget install AgileBits.1Password.CLI"
        );
        assert!(
            h("linux")
                .install_hint(Tool::Op)
                .contains("developer.1password.com")
        );
        assert_eq!(
            h("macos").install_hint(Tool::Flyctl),
            "install: brew install flyctl"
        );
        assert_eq!(
            h("linux").install_hint(Tool::Flyctl),
            "install: curl -L https://fly.io/install.sh | sh"
        );
        let wsl = host(FakeEnv::new("linux").var("WSL_DISTRO_NAME"));
        assert_eq!(
            wsl.install_hint(Tool::Flyctl),
            "install: curl -L https://fly.io/install.sh | sh"
        );
        assert_eq!(
            h("windows").install_hint(Tool::Flyctl),
            "install: iwr https://fly.io/install.ps1 -useb | iex"
        );
        let ci = host(FakeEnv::new("linux").var("CI"));
        assert!(ci.install_hint(Tool::Op).contains("install-cli-action"));
        assert!(ci.install_hint(Tool::Flyctl).contains("setup-flyctl"));
    }
}
