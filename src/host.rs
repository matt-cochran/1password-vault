//! Platform and shell detection for remediation text (FR-26).
//!
//! When opv cannot finish it prints the exact next command for this platform, so it needs
//! to know the platform, the user's shell, and whether it runs under CI. Detection is
//! deterministic and goes through the [`HostEnv`] seam so every case can be tested:
//!
//! 1. CI: `CI` or `GITHUB_ACTIONS` set and non-empty. Remediation names
//!    `OP_SERVICE_ACCOUNT_TOKEN` and never an interactive command.
//! 2. Platform: `windows` / `macos` by the compile-time OS; on Linux, WSL when
//!    `/proc/sys/kernel/osrelease` contains `microsoft` or `WSL` (any case), or
//!    `WSL_DISTRO_NAME` is set.
//! 3. Shell: the basename of `$SHELL` (`.exe` stripped): `fish`, `pwsh`/`powershell`, or a
//!    POSIX shell (`bash`, `zsh`, `sh`, `dash`, `ksh`). Unset or unknown: PowerShell on
//!    Windows, POSIX elsewhere.
//!
//! Only variable names are tested for credentials (`OP_SERVICE_ACCOUNT_TOKEN`); their values
//! are never read (SR-1). Messages are text, never prompts (FR-9).

use std::fmt;

/// Where detection reads its facts. [`ProcessEnv`] is the real one; tests use
/// [`FakeEnv`].
pub trait HostEnv {
    /// `std::env::consts::OS` (`linux`, `macos`, `windows`, ...).
    fn os(&self) -> &str;
    /// True when the variable is set and non-empty. Implementations must not keep the value.
    fn is_set(&self, name: &str) -> bool;
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
    pub set: Vec<String>,
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

    pub fn var(mut self, name: &str) -> Self {
        self.set.push(name.into());
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
        self.set.iter().any(|n| n == name)
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
}

/// A tool opv runs, for install guidance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Op,
    Flyctl,
}

/// The detected host: platform, shell, CI, and whether a service account token is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Host {
    pub platform: Platform,
    pub shell: Shell,
    pub ci: bool,
    /// `OP_SERVICE_ACCOUNT_TOKEN` is set and non-empty (its value is never read).
    pub service_account_token: bool,
}

impl Host {
    /// Detect from the running process.
    pub fn detect() -> Self {
        Self::from_env(&ProcessEnv)
    }

    /// Detect from `env` (the testable seam). See the module docs for the rules.
    pub fn from_env(env: &dyn HostEnv) -> Self {
        let ci = env.is_set("CI") || env.is_set("GITHUB_ACTIONS");
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
        let named = env.shell().and_then(|s| {
            let base = s
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            let base = base.strip_suffix(".exe").unwrap_or(&base).to_string();
            match base.as_str() {
                "fish" => Some(Shell::Fish),
                "pwsh" | "powershell" => Some(Shell::PowerShell),
                "bash" | "zsh" | "sh" | "dash" | "ksh" => Some(Shell::Posix),
                _ => None,
            }
        });
        let shell = named.unwrap_or(match platform {
            Platform::Windows => Shell::PowerShell,
            _ => Shell::Posix,
        });
        Host {
            platform,
            shell,
            ci,
            service_account_token: env.is_set("OP_SERVICE_ACCOUNT_TOKEN"),
        }
    }

    /// The command that signs `op` in and exports the session into this shell, or `None`
    /// under CI (no interactive sign-in there).
    pub fn signin_command(&self) -> Option<&'static str> {
        if self.ci {
            return None;
        }
        Some(match self.shell {
            Shell::Posix => "eval $(op signin)",
            Shell::Fish => "eval (op signin)",
            Shell::PowerShell => "Invoke-Expression $(op signin)",
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
            ("linux", Some("/usr/bin/nu"), Shell::Posix),
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
    fn service_account_token_presence_only() {
        assert!(host(FakeEnv::new("linux").var("OP_SERVICE_ACCOUNT_TOKEN")).service_account_token);
        assert!(!host(FakeEnv::new("linux")).service_account_token);
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
