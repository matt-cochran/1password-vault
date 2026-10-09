//! Native owner-terminal integration for guided setup, never called by automation commands.
use super::setup::{Backend, Interaction};
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
}
impl Runtime {
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
        self.runner.run_inherited(&command[0], &args, &self.environment()).map_err(|e| Error::Dependency(format!("[LOGIN-COMMAND] Cannot start the requested command ({:?}). Check its installation and arguments.", e.kind()).into()))
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

fn dependency(error: io::Error) -> Error {
    if error.kind() == io::ErrorKind::NotFound {
        crate::adapters::onepassword::op_missing(&crate::host::Host::detect())
    } else {
        Error::Dependency(format!(
            "Cannot execute the 1Password CLI ({:?}). Check its installation and executable permissions.",
            error.kind()
        ).into())
    }
}

pub fn session_assignment(output: &[u8]) -> Result<Option<(String, SecretValue)>, Error> {
    let fail = || {
        Error::Auth("1Password returned an unexpected sign-in response. Nothing was evaluated or printed. Run op signin --help for this CLI version.".into())
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
    fn use_account(&mut self, account: Option<&str>) {
        self.account = account.map(str::to_owned);
    }
    fn child(&self, command: &[String]) -> Result<i32, Error> {
        self.spawn_child(command)
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
            Outcome::Unknown { reason, .. } => Err(Error::Unknown(format!(
                "1Password did not answer in time ({reason}). Fields already saved are kept. Run opv setup again to check and resume."
            ).into())),
        }
    }
    fn sign_in(&mut self, account: Option<&str>, add_account: bool) -> Result<(), Error> {
        let mut command = Command::new("op");
        command.args(if add_account {
            vec!["account", "add"]
        } else {
            vec!["signin", "--force"]
        });
        if let Some(account) = account {
            self.account = Some(account.to_owned());
            command.env("OP_ACCOUNT", account);
            if !add_account {
                command.args(["--account", account]);
            }
        }
        // Generic sessions can be stale. Account-specific sessions are selected by op;
        // --force asks it to emit a fresh assignment, which stays in this process.
        command.env_remove("OP_SESSION").env("OP_DEBUG", "false");
        command
            .stdin(Stdio::inherit())
            .stderr(Stdio::inherit())
            .stdout(Stdio::piped());
        let mut child = command.spawn().map_err(dependency)?;
        let output =
            crate::runner::read_to_end_zeroizing(child.stdout.take().expect("piped stdout"))
                .map_err(dependency)?;
        let status = child.wait().map_err(dependency)?;
        if !status.success() {
            return Err(Error::Auth("1Password could not sign in. Check the account and password at its prompts, then rerun opv setup. Session output was not printed.".into()));
        }
        if !add_account && let Some((name, value)) = session_assignment(&output)? {
            self.session = session_vars(self.account.as_deref(), name, value);
        }
        Ok(())
    }
}

pub struct Console;
impl Console {
    /// `command` (`setup`, `login` or `config edit`) needs the owner's own terminal; the
    /// refusal names that command, and `next` is the command line as typed, with the
    /// user's own arguments (review #8, I3).
    pub fn require_terminal(command: &str, next: &str) -> Result<(), Error> {
        if !io::stdin().is_terminal()
            || !io::stdout().is_terminal()
            || std::env::var_os("CI").is_some_and(|v| !v.is_empty() && v != "false" && v != "0")
            || std::env::var_os("GITHUB_ACTIONS").is_some_and(|v| v == "true")
        {
            return Err(terminal_refusal(command, next));
        }
        for key in [
            "OP_SERVICE_ACCOUNT_TOKEN",
            "OP_CONNECT_HOST",
            "OP_CONNECT_TOKEN",
        ] {
            if std::env::var_os(key).is_some_and(|v| !v.is_empty()) {
                return Err(Error::Policy(format!(
                    "A service-account or Connect credential is active. Use a separate owner terminal for opv {command}; existing automation authentication is unchanged."
                ).into())
                .with_code(crate::error::Code::TerminalRequired)
                .with_do(format!("ask the user to run this in their own terminal, without {key} set"))
                .with_next(next.to_string()));
            }
        }
        Ok(())
    }
}

/// The refusal of `opv <command>` without an interactive terminal: it names that command,
/// and `next` is the command line the user typed.
pub(crate) fn terminal_refusal(command: &str, next: &str) -> Error {
    let what = match command {
        "login" => "opv login signs in at 1Password's own prompts, so it".to_string(),
        "setup" => "Guided setup (opv setup)".to_string(),
        "config edit" => {
            "opv config edit opens your editor and asks before saving, so it".to_string()
        }
        other => format!("opv {other}"),
    };
    Error::Policy(format!(
        "{what} needs your own interactive terminal. Automation signs in with OP_SERVICE_ACCOUNT_TOKEN and uses init, doctor, check, item skeleton, run and sync with declared configuration."
    ).into())
    .with_code(crate::error::Code::TerminalRequired)
    .with_do("ask the user to run this in their own terminal")
    .with_next(next.to_string())
}

#[cfg(test)]
mod terminal_tests {
    use super::terminal_refusal;

    #[test]
    fn config_edit_refusal_names_config_edit() {
        let e = terminal_refusal("config edit", "opv config edit");
        assert!(
            e.to_string().contains("opv config edit opens your editor"),
            "{e}"
        );
    }

    #[test]
    fn login_refusal_next_keeps_the_environment() {
        let e = terminal_refusal("login", "opv login prod");
        assert_eq!(e.next_step(), Some("opv login prod"));
    }
}

impl Interaction for Console {
    fn show(&mut self, message: &str) -> Result<(), Error> {
        println!("{message}");
        Ok(())
    }
    fn confirm(&mut self, question: &str) -> Result<bool, Error> {
        print!("{question} [y/N] ");
        io::stdout()
            .flush()
            .map_err(|_| Error::Dependency("Cannot write the setup prompt.".into()))?;
        let mut answer = String::new();
        if io::stdin()
            .read_line(&mut answer)
            .map_err(|_| Error::Dependency("Cannot read the setup answer.".into()))?
            == 0
        {
            return Err(Error::Policy(
                "Setup stopped. No further changes made.".into(),
            ));
        }
        Ok(matches!(
            answer.trim().to_ascii_lowercase().as_str(),
            "y" | "yes"
        ))
    }
    fn secret(&mut self, title: &str) -> Result<SecretValue, Error> {
        let value = rpassword::prompt_password(format!("{title} (hidden; Enter to skip): ")).map_err(|_| Error::Dependency("Cannot read hidden input. Use your own interactive terminal, or fill this field privately in 1Password.".into()))?;
        Ok(SecretValue::new(value))
    }
    fn choose(&mut self, question: &str, choices: &[String]) -> Result<String, Error> {
        println!("{question}");
        for (index, choice) in choices.iter().enumerate() {
            println!("  {}. {choice}", index + 1);
        }
        loop {
            print!("Enter a number (or press Enter to stop): ");
            io::stdout()
                .flush()
                .map_err(|_| Error::Dependency("Cannot write the choice prompt.".into()))?;
            let mut answer = String::new();
            let size = io::stdin()
                .read_line(&mut answer)
                .map_err(|_| Error::Dependency("Cannot read the choice.".into()))?;
            if size == 0 || answer.trim().is_empty() {
                return Err(Error::Policy(
                    "Setup stopped. No further changes made.".into(),
                ));
            }
            if let Ok(number) = answer.trim().parse::<usize>()
                && let Some(choice) = number.checked_sub(1).and_then(|n| choices.get(n))
            {
                return Ok(choice.clone());
            }
            println!("Choose one of the numbered choices above.");
        }
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
