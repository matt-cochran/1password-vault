//! Native owner-terminal integration for guided setup, never called by automation commands.
use super::setup::{Backend, Interaction};
use crate::cause::{
    Cause, CommandId, DiagnoseContext, ExitClass, Guard, NoTerminal, Principal, System, Unusable,
    Upstream, VarName,
};
use crate::domain::SecretValue;
use crate::error::Error;
use crate::runner::{Call, CommandRunner, Outcome, Output, ProcessRunner};
use regex::Regex;
use std::io::{self, IsTerminal, Write};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

#[derive(Default)]
pub struct Runtime {
    runner: ProcessRunner,
    session: Vec<(String, SecretValue)>,
    account: Option<String>,
    /// The opv command this sign-in serves (`login`, `setup`, or the command that found the
    /// session ended), named in failures (FR-50). `None`: `setup`.
    command: Option<String>,
}
impl Runtime {
    /// This runtime, naming `command` in its sign-in failures (FR-50).
    pub fn for_command(mut self, command: &str) -> Self {
        self.command = Some(command.to_string());
        self
    }
    fn command_name(&self) -> &str {
        self.command.as_deref().unwrap_or("setup")
    }
    /// The session variables this runtime's sign-in produced (for [`crate::runner::use_op_session`]).
    pub fn into_session(self) -> Vec<(String, SecretValue)> {
        self.session
    }
    pub fn with_account(account: Option<&str>) -> Self {
        Self {
            account: account.map(str::to_owned),
            ..Self::default()
        }
    }
    fn environment(&self) -> Vec<(&str, &str)> {
        let mut env: Vec<_> = self
            .session
            .iter()
            .map(|(k, v)| (k.as_str(), v.expose()))
            .collect();
        if let Some(account) = &self.account {
            env.push(("OP_ACCOUNT", account));
        }
        env.extend([("OP_DEBUG", "false"), ("OP_RUN_NO_MASKING", "false")]);
        env
    }
    fn spawn_child(&self, command: &[String]) -> Result<i32, Error> {
        let default;
        let command = if command.is_empty() {
            #[cfg(windows)]
            {
                default = vec!["powershell.exe".into(), "-NoLogo".into()];
            }
            #[cfg(not(windows))]
            {
                default = vec![
                    std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into()),
                    "-i".into(),
                ];
            }
            &default
        } else {
            command
        };
        let args: Vec<_> = command[1..].iter().map(String::as_str).collect();
        self.runner
            .run_inherited(&command[0], &args, &self.environment())
            .map_err(|e| {
                Cause::ChildStartFailed {
                    program: command[0].clone(),
                    workdir: None,
                    io: e.kind().into(),
                    remote: None,
                }
                .into()
            })
    }
}

/// The runtime's runner with its environment (its own session, its account) on every call;
/// a variable the call sets itself (the probe's emptied `OP_ACCOUNT`) replaces the
/// runtime's. Only [`Backend::session_for`]'s probes go through it.
struct WithEnv<'a> {
    inner: &'a ProcessRunner,
    env: Vec<(&'a str, &'a str)>,
}

impl WithEnv<'_> {
    fn merged<'e>(&'e self, call: &Call<'e>) -> Vec<(&'e str, &'e str)> {
        let mut env: Vec<_> = self
            .env
            .iter()
            .filter(|(k, _)| !call.env.iter().any(|(c, _)| c == k))
            .copied()
            .collect();
        env.extend(call.env.iter().copied());
        env
    }
}

impl CommandRunner for WithEnv<'_> {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
        let env = self.merged(call);
        self.inner.read(&Call { env: &env, ..*call }, refused)
    }
    fn write(&self, call: &Call) -> io::Result<Outcome> {
        let env = self.merged(call);
        self.inner.write(&Call { env: &env, ..*call })
    }
    fn probe(&self, call: &Call, limit: std::time::Duration) -> io::Result<Output> {
        let env = self.merged(call);
        self.inner.probe(&Call { env: &env, ..*call }, limit)
    }
    fn pause(&self, d: std::time::Duration, note: &str) {
        self.inner.pause(d, note)
    }
    fn note(&self, line: &str) {
        self.inner.note(line)
    }
    fn writes_started(&self) -> bool {
        self.inner.writes_started()
    }
    fn run_inherited(&self, program: &str, args: &[&str], env: &[(&str, &str)]) -> io::Result<i32> {
        self.inner.run_inherited(program, args, env)
    }
}

/// `op` subcommands that change 1Password. Everything else setup runs only reads.
fn op_writes(args: &[&str]) -> bool {
    matches!(
        args,
        ["item", "create" | "edit" | "delete", ..]
            | ["vault", "create", ..]
            | ["account", "add", ..]
    )
}

/// `op` could not be started (04.14, 05.29): not on PATH is `ToolMissing` with this
/// platform's install line (R56); otherwise `ToolUnusable` (R57), never an `ErrorKind` name.
fn dependency(error: io::Error) -> Error {
    let why = match error.kind() {
        io::ErrorKind::NotFound => return crate::host::tool_missing(&crate::host::OP_CLI).into(),
        io::ErrorKind::PermissionDenied => Unusable::NotExecutable,
        kind => Unusable::SpawnFailed { io: kind.into() },
    };
    Cause::ToolUnusable {
        tool: crate::host::OP_CLI.program.to_string(),
        why,
    }
    .into()
}

pub fn session_assignment(output: &[u8]) -> Result<Option<(String, SecretValue)>, Error> {
    // op signed in but printed a session line opv's fixed pattern does not accept: opv's
    // parser is behind op's output, so it is opv's to fix. Nothing was evaluated or shown.
    let fail = || -> Error {
        Cause::Bug {
            site: "op signin printed a session line opv does not recognise",
        }
        .into()
    };
    let text = std::str::from_utf8(output).map_err(|_| fail())?;
    let pattern = Regex::new(r#"^export[ \t]+(OP_SESSION(?:_[A-Za-z0-9_]+)?)=(?:"([A-Za-z0-9._/+=-]+)"|'([A-Za-z0-9._/+=-]+)'|([A-Za-z0-9._/+=-]+));?[ \t]*$"#).expect("fixed session pattern");
    let mut session = None;
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let capture = pattern.captures(line).ok_or_else(fail)?;
        if session.is_some() {
            return Err(fail());
        }
        let token = capture
            .get(2)
            .or_else(|| capture.get(3))
            .or_else(|| capture.get(4))
            .expect("one token");
        session = Some((
            capture[1].to_owned(),
            SecretValue::new(token.as_str().to_owned()),
        ));
    }
    Ok(session)
}

/// The session variables to keep from one `op signin` assignment. With an account, only
/// the account's own `OP_SESSION_<account>`: a later login to another account adds its own
/// and both stay usable, each selected by `OP_ACCOUNT` (FR-40). Without one, also the
/// generic `OP_SESSION`, so op finds the session when no account selects it.
pub fn session_vars(
    account: Option<&str>,
    name: String,
    value: SecretValue,
) -> Vec<(String, SecretValue)> {
    let mut vars = Vec::new();
    if account.is_none() && name != "OP_SESSION" {
        vars.push((
            "OP_SESSION".to_string(),
            SecretValue::new(value.expose().to_string()),
        ));
    }
    vars.push((name, value));
    vars
}

impl Backend for Runtime {
    fn add_account(&mut self, email: Option<&str>, shorthand: &str) -> Result<(), Error> {
        let mut command = Command::new("op");
        command.args(["account", "add", "--signin", "--shorthand", shorthand]);
        if let Some(e) = email {
            command.args(["--email", e]);
        }
        command.env_remove("OP_SESSION").env("OP_DEBUG", "false");
        let output = run_prompted(&mut command)
            .map_err(|f| f.error("adding the account", email, self.command_name()))?;
        if let Some((name, value)) = session_assignment(&output)? {
            self.session = session_vars(None, name, value);
        }
        Ok(())
    }
    fn use_account(&mut self, account: Option<&str>) {
        self.account = account.map(str::to_owned);
    }
    fn current_account(&self) -> Option<String> {
        self.account.clone()
    }
    fn session_for(&self, account: &str) -> super::setup::SessionCheck {
        // This runtime's own session (an account just added) goes with the probe.
        let runner = WithEnv {
            inner: &self.runner,
            env: self.environment(),
        };
        crate::adapters::onepassword_diagnose::session_for(
            &runner,
            &crate::cause::AccountId::new(account),
        )
    }
    fn account_label(&self, account: &str) -> String {
        use crate::adapters::onepassword_manifest as manifest;
        let listed = self
            .call(&["account", "list", "--format", "json"], None)
            .ok()
            .filter(|o| o.status == 0)
            .and_then(|o| serde_json::from_slice::<Vec<manifest::Account>>(&o.stdout).ok())
            .unwrap_or_default();
        manifest::resolve(&listed, account)
            .ok()
            .and_then(|uuid| listed.into_iter().find(|a| a.account_uuid == uuid))
            .map(|a| a.email)
            .filter(|e| !e.is_empty())
            .unwrap_or_else(|| account.to_string())
    }
    fn child(&self, command: &[String]) -> Result<i32, Error> {
        self.spawn_child(command)
    }
    fn probe(&self, args: &[&str]) -> Result<Output, Error> {
        let env = self.environment();
        let call = Call {
            program: "op",
            args,
            stdin: None,
            env: &env,
            limit: None,
        };
        let out = self
            .runner
            .probe(&call, crate::runner::PROBE_TIMEOUT)
            .map_err(dependency)?;
        if out.status != 0 {
            // A failed status check is the answer; its stderr never attaches elsewhere.
            let _ = crate::runner::take_failure_excerpt();
        }
        Ok(out)
    }
    fn native(&self) -> Result<(), Error> {
        super::run::ensure_native(&self.runner)
    }
    fn call(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Output, Error> {
        let env = self.environment();
        let call = Call {
            program: "op",
            args,
            stdin,
            env: &env,
            limit: None,
        };
        // G1 (X5): setup's `item create` is a non-idempotent create: one that never
        // answered may have made the item, which a re-run finds again by its title.
        if let ["item", "create", rest @ ..] = args {
            let title = rest
                .iter()
                .position(|a| *a == "--title")
                .and_then(|i| rest.get(i + 1))
                .copied()
                .unwrap_or_default();
            return match self
                .runner
                .create(&call, crate::cause::CreateKind::ItemWithSecrets)
                .map_err(dependency)?
            {
                crate::runner::CreateOutcome::Done(o)
                | crate::runner::CreateOutcome::Refused(o) => Ok(o),
                crate::runner::CreateOutcome::OutcomeUnknown(seen) => {
                    Err(Cause::CreateOutcomeUnknown {
                        system: crate::cause::System::OnePassword,
                        kind: crate::cause::CreateKind::ItemWithSecrets,
                        name: title.to_string(),
                        refind: crate::cause::Refind::ByTitle,
                        seen,
                    }
                    .into())
                }
            };
        }
        // Reads retry within the run budget (NR-3); a save is never retried (NR-2).
        let outcome = if op_writes(args) {
            self.runner.write(&call)
        } else {
            self.runner.read(&call, &[])
        }
        .map_err(dependency)?;
        match outcome {
            Outcome::Done(o) | Outcome::Refused(o) => Ok(o),
            // A failed save keeps its exit code: setup reports it and the owner reruns.
            Outcome::Unknown {
                status: Some(status),
                ..
            } => Ok(Output {
                status,
                stdout: Zeroizing::new(Vec::new()),
            }),
            // 05.08: diagnosed by what the call was doing (§5): an unanswered read is
            // `Unavailable` (nothing changed), an unanswered save `WriteOutcomeUnknown`.
            Outcome::Unknown { .. } => Err(unanswered(op_writes(args), self.account.as_deref())),
        }
    }
    fn sign_in(&mut self, account: Option<&str>, add_account: bool) -> Result<(), Error> {
        if let Some(account) = account {
            self.account = Some(account.to_owned());
        }
        // A fresh sign-in starts from no session and no `OP_ACCOUNT` (#142, #153): see
        // `signin_command`. The new session stays in this process.
        let mut command = super::setup::signin_command(
            account,
            add_account,
            std::env::vars_os().map(|(name, _)| name),
        );
        let what = if add_account {
            "adding the account"
        } else {
            "signing in"
        };
        let output =
            run_prompted(&mut command).map_err(|f| f.error(what, account, self.command_name()))?;
        if !add_account && let Some((name, value)) = session_assignment(&output)? {
            self.session = session_vars(self.account.as_deref(), name, value);
        }
        Ok(())
    }
}

/// The cause of an `op` call that never answered, from op's diagnosis of the call the
/// runner observed; `write`: the call was a save.
fn unanswered(write: bool, account: Option<&str>) -> Error {
    let Some(seen) = crate::runner::take_observed() else {
        return crate::host::OP_CLI.unobserved("op", write);
    };
    let ctx = DiagnoseContext {
        write,
        account: account.map(crate::cause::AccountId::new),
        ..DiagnoseContext::default()
    };
    crate::adapters::onepassword_diagnose::diagnose(seen, "", &ctx).into()
}

/// Why [`run_prompted`] failed: the classified op failure, or an opv-side error (op
/// missing) already worded.
pub enum PromptFailure {
    /// The classified failure, op's own error messages (as op printed them) and its exit
    /// code (128 + n for signal n).
    Op(super::signin_filter::Failure, Vec<String>, Option<i32>),
    Spawn(Error),
}

impl PromptFailure {
    fn error(self, what: &str, account: Option<&str>, command: &str) -> Error {
        match self {
            PromptFailure::Op(f, messages, exit) => with_said(
                f.error_said(what, account, command, &messages, exit),
                &messages,
                exit,
            ),
            PromptFailure::Spawn(e) => e,
        }
    }
}

/// `e` with op's own last message kept as its cause's evidence (#142), unless it carries
/// evidence already.
fn with_said(e: Error, messages: &[String], exit: Option<i32>) -> Error {
    let Some(line) = said(messages) else {
        return e;
    };
    match e.cause() {
        Some((cause, None)) => Error::with_evidence(cause.clone(), evidence(line, exit)),
        _ => e,
    }
}

/// op's reply `line` (already scrubbed by [`said`]) as the evidence of a failed prompt.
fn evidence(line: String, exit: Option<i32>) -> Upstream {
    Upstream {
        source: System::OnePassword,
        tool: "1Password CLI".to_string(),
        version: None,
        exit: match exit {
            Some(code) if code > 128 => ExitClass::Signal { signal: code - 128 },
            Some(code) => ExitClass::Code { code },
            None => ExitClass::SpawnFailed,
        },
        said: vec![line],
        removed_advice: false,
        truncated: false,
        untrusted: true,
    }
}

/// op's last error message, scrubbed and cut to one short line, for the person to see what
/// 1Password itself reported (#142: a failure opv words alone can hide the cause). op's
/// error lines carry no typed secret; the scrubber removes any token-shaped text anyway.
fn said(messages: &[String]) -> Option<String> {
    let last = messages.iter().rev().find(|m| !m.trim().is_empty())?;
    let line: String = crate::scrub::scrub(last.lines().next().unwrap_or_default())
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    (!line.trim().is_empty()).then_some(line)
}

/// Run an op command that prompts the owner (`op signin`, `op account add`): stdin stays
/// the terminal, stderr is shown through [`super::signin_filter::Filter`] (the prompts as
/// they come, op's error lines kept back and classified, FR-50), stdout (the session
/// assignment) is captured and never shown.
fn run_prompted(command: &mut Command) -> Result<Zeroizing<Vec<u8>>, PromptFailure> {
    command
        .stdin(Stdio::inherit())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|e| PromptFailure::Spawn(dependency(e)))?;
    let mut stderr = child.stderr.take().expect("piped stderr");
    let pump = std::thread::spawn(move || {
        super::signin_filter::Filter::pump(&mut stderr, &mut io::stderr().lock())
    });
    let output = crate::runner::read_to_end_zeroizing(child.stdout.take().expect("piped stdout"))
        .map_err(|e| PromptFailure::Spawn(dependency(e)))?;
    let status = child
        .wait()
        .map_err(|e| PromptFailure::Spawn(dependency(e)))?;
    let messages = pump.join().ok().and_then(Result::ok).unwrap_or_default();
    if status.success() {
        return Ok(output);
    }
    // The prompt line op left open ends here, before opv's own message.
    let _ = writeln!(io::stderr());
    let exit = exit_code(&status);
    Err(PromptFailure::Op(
        super::signin_filter::classify(&messages, exit),
        messages,
        exit,
    ))
}

/// The exit code, or 128 + the signal that ended the child (130 for Ctrl-C).
fn exit_code(status: &std::process::ExitStatus) -> Option<i32> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return Some(128 + sig);
        }
    }
    status.code()
}

pub struct Console;
impl Console {
    /// `command` (`setup`, `login` or `config edit`) needs the owner's own terminal. The
    /// catalog's handoff is the command line as typed, every argument kept (review #8, I3).
    pub fn require_terminal(command: &str) -> Result<(), Error> {
        let ci = std::env::var_os("CI").is_some_and(|v| !v.is_empty() && v != "false" && v != "0")
            || std::env::var_os("GITHUB_ACTIONS").is_some_and(|v| v == "true");
        if ci {
            return Err(terminal_refusal(NoTerminal::Ci));
        }
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Err(terminal_refusal(NoTerminal::NoTty));
        }
        for key in [
            "OP_SERVICE_ACCOUNT_TOKEN",
            "OP_CONNECT_HOST",
            "OP_CONNECT_TOKEN",
        ] {
            if std::env::var_os(key).is_some_and(|v| !v.is_empty()) {
                return Err(own_session_refusal(command, key));
            }
        }
        Ok(())
    }
}

/// `opv <command>` under a service-account or Connect credential in `var` (R33): it runs
/// in the person's own session, without the variable; automation keeps its credential.
pub(crate) fn own_session_refusal(command: &str, var: &str) -> Error {
    Cause::NeedsOwnSession {
        command: CommandId(command.to_string()),
        identity: Principal::ShellToken {
            var: VarName::new(var),
        },
    }
    .into()
}

/// The refusal of a command that needs a person at a terminal (R60): the catalog's handoff
/// is the command line the user typed.
pub(crate) fn terminal_refusal(why: NoTerminal) -> Error {
    Cause::NeedsTerminal { why }.into()
}

/// The person stopped at a prompt (05.31, R65): a decision, not a fault to fix.
fn declined() -> Error {
    Cause::Guard {
        guard: Guard::Declined,
    }
    .into()
}

/// The terminal could not be written or read while prompting: it is gone.
fn terminal_lost() -> Error {
    terminal_refusal(NoTerminal::NoTty)
}

impl Interaction for Console {
    fn show(&mut self, message: &str) -> Result<(), Error> {
        show_on(&mut io::stdout(), message)
    }
    fn confirm(&mut self, question: &str) -> Result<bool, Error> {
        confirm_on(&mut io::stdout(), question)
    }
    fn secret(&mut self, title: &str) -> Result<SecretValue, Error> {
        secret_prompt(title)
    }
    fn choose(&mut self, question: &str, choices: &[String]) -> Result<String, Error> {
        choose_on(&mut io::stdout(), question, choices)
    }
}

/// The console of `opv login` (C17, #159): its progress and prompts go to stderr, so
/// stdout carries only the child's output (`opv login -- opv … --json` is one document).
pub struct LoginConsole;

impl Interaction for LoginConsole {
    fn show(&mut self, message: &str) -> Result<(), Error> {
        show_on(&mut io::stderr(), message)
    }
    fn confirm(&mut self, question: &str) -> Result<bool, Error> {
        confirm_on(&mut io::stderr(), question)
    }
    fn secret(&mut self, title: &str) -> Result<SecretValue, Error> {
        secret_prompt(title)
    }
    fn choose(&mut self, question: &str, choices: &[String]) -> Result<String, Error> {
        choose_on(&mut io::stderr(), question, choices)
    }
}

fn show_on(out: &mut dyn Write, message: &str) -> Result<(), Error> {
    writeln!(out, "{message}").map_err(|_| terminal_lost())
}

fn secret_prompt(title: &str) -> Result<SecretValue, Error> {
    // Masked, not hidden (0.9.0): the person sees that a paste landed, never its length.
    super::masked::prompt(title)?.ok_or_else(declined)
}

fn confirm_on(out: &mut dyn Write, question: &str) -> Result<bool, Error> {
    write!(out, "{question} [y/N] ").map_err(|_| terminal_lost())?;
    out.flush().map_err(|_| terminal_lost())?;
    let mut answer = String::new();
    if io::stdin()
        .read_line(&mut answer)
        .map_err(|_| terminal_lost())?
        == 0
    {
        return Err(declined());
    }
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn choose_on(out: &mut dyn Write, question: &str, choices: &[String]) -> Result<String, Error> {
    let lost = |_: io::Error| terminal_lost();
    writeln!(out, "{question}").map_err(lost)?;
    for (index, choice) in choices.iter().enumerate() {
        writeln!(out, "  {}. {choice}", index + 1).map_err(lost)?;
    }
    loop {
        write!(out, "Enter a number (or press Enter to stop): ").map_err(lost)?;
        out.flush().map_err(lost)?;
        let mut answer = String::new();
        let size = io::stdin()
            .read_line(&mut answer)
            .map_err(|_| terminal_lost())?;
        if size == 0 || answer.trim().is_empty() {
            return Err(declined());
        }
        if let Ok(number) = answer.trim().parse::<usize>()
            && let Some(choice) = number.checked_sub(1).and_then(|n| choices.get(n))
        {
            return Ok(choice.clone());
        }
        writeln!(out, "Choose one of the numbered choices above.").map_err(lost)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn captures_account_variable_without_evaluating_help_comments() {
        let input =
            Zeroizing::new(b"# help\nexport OP_SESSION_example=\"synthetic-token\";\n".to_vec());
        let (name, token) = session_assignment(&input).unwrap().unwrap();
        assert_eq!(name, "OP_SESSION_example");
        assert_eq!(token.expose(), "synthetic-token");
        assert!(!format!("{token:?}").contains("synthetic-token"));
    }
    #[test]
    fn refuses_shell_code_and_duplicate_assignments_without_echoing_them() {
        for input in [
            "export OP_SESSION=$(echo synthetic-private)",
            "export OP_SESSION=x\necho synthetic-private",
            "export OP_SESSION=x\nexport OP_SESSION=y",
        ] {
            let error = session_assignment(input.as_bytes()).err().unwrap();
            assert!(!error.to_string().contains("synthetic-private"));
        }
    }
    /// FR-40: logging in to a second account keeps the first account's session.
    #[test]
    fn account_login_keeps_only_the_account_session_variable() {
        let vars = session_vars(
            Some("work.1password.com"),
            "OP_SESSION_work".into(),
            SecretValue::new("synthetic-token".into()),
        );
        let names: Vec<_> = vars.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["OP_SESSION_work"]);
    }
    #[test]
    fn default_account_login_also_sets_the_generic_session_variable() {
        let vars = session_vars(
            None,
            "OP_SESSION_me".into(),
            SecretValue::new("synthetic-token".into()),
        );
        let names: Vec<_> = vars.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["OP_SESSION", "OP_SESSION_me"]);
    }
    #[test]
    fn empty_output_supports_desktop_authentication() {
        assert!(session_assignment(b"").unwrap().is_none());
    }
}

#[cfg(test)]
mod said_tests {
    use super::said;

    #[test]
    fn a_failed_sign_in_shows_1passwords_last_message() {
        let m = vec![
            "first".to_string(),
            "You are not currently signed in.".to_string(),
        ];
        assert_eq!(
            said(&m).as_deref(),
            Some("You are not currently signed in.")
        );
    }

    #[test]
    fn a_session_token_in_1passwords_message_is_scrubbed() {
        let m = vec!["export OP_SESSION_my=abcDEF1234567890secret".to_string()];
        assert!(
            !said(&m)
                .unwrap_or_default()
                .contains("abcDEF1234567890secret")
        );
    }

    // #142: a cataloged sign-in failure keeps op's own message as its evidence.
    #[test]
    fn a_cataloged_sign_in_failure_shows_1passwords_message() {
        let failed: crate::error::Error = crate::cause::Cause::NotSignedIn {
            system: crate::cause::System::OnePassword,
            account: None,
            state: crate::cause::SessionState::SignedOut,
        }
        .into();
        let m = vec!["[ERROR] You are not currently signed in.".to_string()];
        let e = super::with_said(failed, &m, Some(1));
        assert_eq!(
            e.cause().and_then(|(_, up)| up).map(|u| u.said.clone()),
            Some(vec!["[ERROR] You are not currently signed in.".to_string()])
        );
    }

    #[test]
    fn no_message_adds_nothing() {
        assert_eq!(said(&[]), None);
    }
}

#[cfg(test)]
mod terminal_tests {
    use super::{own_session_refusal, terminal_refusal};
    use crate::cause::{Cause, Invocation, Next, NoTerminal};

    fn cause_of(e: &crate::error::Error) -> Cause {
        e.cause().expect("a catalog cause").0.clone()
    }

    #[test]
    fn a_refusal_without_a_terminal_is_terminal_required() {
        assert_eq!(
            cause_of(&terminal_refusal(NoTerminal::NoTty)).code(),
            "terminal_required"
        );
    }

    #[test]
    fn login_refusal_next_keeps_the_environment() {
        let inv = Invocation::from_cli(&["opv".into(), "login".into(), "prod".into()]);
        assert_eq!(
            cause_of(&terminal_refusal(NoTerminal::NoTty)).step(&inv).1,
            Next::Handoff(crate::cause::Cmd {
                command: vec!["login".into()],
                args: vec!["prod".into()],
            })
        );
    }

    #[test]
    fn a_service_account_refusal_is_own_session_required() {
        assert_eq!(
            cause_of(&own_session_refusal("setup", "OP_SERVICE_ACCOUNT_TOKEN")).code(),
            "own_session_required"
        );
    }

    #[test]
    fn a_service_account_refusal_says_to_run_without_the_variable() {
        let inv = Invocation::from_cli(&["opv".into(), "setup".into()]);
        let c = cause_of(&own_session_refusal("setup", "OP_SERVICE_ACCOUNT_TOKEN"));
        assert!(
            c.do_text(&inv)
                .is_some_and(|d| d.contains("without OP_SERVICE_ACCOUNT_TOKEN")),
            "{:?}",
            c.do_text(&inv)
        );
    }

    // 05.31: stopping at a prompt is `declined`, with no "fix the cause above".
    #[test]
    fn stopping_at_a_prompt_is_declined() {
        assert_eq!(cause_of(&super::declined()).code(), "declined");
    }

    // 05.30: a command that cannot start is named, without an internal tag.
    #[test]
    fn a_command_that_cannot_start_names_the_program() {
        let e = super::Runtime::default()
            .spawn_child(&["opv-test-no-such-program".to_string()])
            .unwrap_err();
        assert!(
            cause_of(&e)
                .message()
                .contains("cannot start opv-test-no-such-program"),
            "{}",
            cause_of(&e).message()
        );
    }

    // 05.08: an unanswered read is the outage, not "run opv setup again".
    #[test]
    fn an_unanswered_read_without_an_observed_call_is_never_outcome_unknown() {
        assert_eq!(
            super::unanswered(false, None).code_str(),
            "provider_unavailable"
        );
    }
}
