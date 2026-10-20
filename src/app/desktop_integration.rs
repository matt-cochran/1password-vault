//! Sign-in reuse across commands (#203, `docs/design/session-reuse.md` §7.1): the shared
//! types the doctor rows, the sign-in wording and `opv login --shell` read. Types only;
//! detection is [`super::doctor_session`], the shell export is [`super::login_shell`].

/// Whether `op` here reuses the 1Password desktop app's unlock (design §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DesktopIntegration {
    /// A `whoami` with every `OP_SESSION*` removed succeeded: the app's session.
    Active,
    /// The integration can work here; the next real call raises the app's prompt.
    Available,
    /// It cannot work here, for `reason`.
    Unavailable { reason: NoIntegration },
    /// CI, a service account or Connect: no person's sign-in to reuse.
    NotApplicable,
    /// op is missing, the probe timed out, or its answer was not one opv expects.
    Unknown,
}

/// Why the app integration cannot work on this host (design §3.2 steps 2-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoIntegration {
    WslLinuxOp,
    Headless,
    DisabledByEnv,
}

/// What one successful `op signin` produced (V1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignInKind {
    /// It printed nothing: the app integration holds the session.
    App,
    /// It printed a session assignment.
    Token,
}

/// What fd 1 is (§5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StdoutKind {
    Pipe,
    Terminal,
    File,
    Other,
}
