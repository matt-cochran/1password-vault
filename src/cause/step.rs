//! Steps (design `docs/design/error-catalog.md` §6): the invocation a person (or an MCP
//! tool call) ran, the opv commands a step names, and what to run next. The types are
//! declared in [`super`]; this module is their behaviour.
//!
//! The child command after `--` is opaque: `run` and `login` take one, and its words are
//! never stored, so `Rerun` can never leak or re-run them (design §6.1).

use super::{Cmd, Invocation, Origin};

/// Global options that take a value. Used only to find the subcommand path when global
/// options are written before it (`opv --config PATH run …`).
const GLOBAL_VALUE_FLAGS: [&str; 3] = ["--config", "--timeout", "--color"];

impl Invocation {
    /// The invocation a command line produced: the subcommand path, then every flag and
    /// positional argument before `--`, in order, exactly as the person gave them.
    ///
    /// `argv` may include the program word (`opv`); it is dropped. Words after `--` are
    /// opaque and never stored.
    pub fn from_cli(argv: &[String]) -> Self {
        let argv = match argv.first() {
            Some(first) if is_program(first) => &argv[1..],
            _ => argv,
        };
        let end = argv.iter().position(|w| w == "--").unwrap_or(argv.len());
        let (command, args) = split_command(argv, end);
        Self {
            origin: Origin::Cli,
            command,
            args,
            has_child: end + 1 < argv.len(),
        }
    }

    /// The invocation an MCP tool call produced: there is no command line, so the origin
    /// names the tool and the arguments are kept as given.
    pub fn from_mcp(tool: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            origin: Origin::Mcp { tool: tool.into() },
            command: Vec::new(),
            args,
            has_child: false,
        }
    }

    /// The command line to run opv again exactly: every flag kept, in order, and never a
    /// word of the child command.
    pub fn rerun_argv(&self) -> Vec<String> {
        let mut argv = match &self.origin {
            Origin::Cli => vec!["opv".to_string()],
            Origin::Mcp { tool } => vec![tool.clone()],
        };
        argv.extend(self.command.iter().cloned());
        argv.extend(self.args.iter().cloned());
        argv
    }

    /// The same invocation with one word changed; every other word is untouched.
    pub fn with_arg(&self, old: &str, new: &str) -> Self {
        let mut out = self.clone();
        if let Some(slot) = out.args.iter_mut().find(|w| w.as_str() == old) {
            *slot = new.to_string();
            return out;
        }
        if let Some(slot) = out.command.iter_mut().find(|w| w.as_str() == old) {
            *slot = new.to_string();
        }
        out
    }
}

impl Cmd {
    /// The argv to run this command: `opv`, its subcommand path, then its arguments.
    pub fn to_argv(&self) -> Vec<String> {
        let mut argv = vec!["opv".to_string()];
        argv.extend(self.command.iter().cloned());
        argv.extend(self.args.iter().cloned());
        argv
    }
}

/// Whether `word` is the program word rather than a subcommand or argument.
fn is_program(word: &str) -> bool {
    let name = word.rsplit(['/', '\\']).next().unwrap_or(word);
    name == "opv" || name == "opv.exe"
}

/// Split the words before `--` into the subcommand path and the rest, both in the order
/// given. The path is the longest prefix that is a known opv command.
fn split_command(argv: &[String], end: usize) -> (Vec<String>, Vec<String>) {
    let Some(start) = command_start(argv, end) else {
        return (Vec::new(), argv[..end].to_vec());
    };
    let mut command = Vec::new();
    let mut at = start;
    while at < end {
        let mut candidate = command.clone();
        candidate.push(argv[at].clone());
        if !is_command_path(&candidate) {
            break;
        }
        command = candidate;
        at += 1;
    }
    let mut args = argv[..start].to_vec();
    args.extend_from_slice(&argv[at..end]);
    (command, args)
}

/// The index where a known top-level subcommand starts, skipping global options and their
/// values written before it.
fn command_start(argv: &[String], end: usize) -> Option<usize> {
    let mut at = 0;
    while at < end {
        let word = &argv[at];
        if word.starts_with('-') {
            let takes_value = GLOBAL_VALUE_FLAGS.contains(&word.as_str());
            at += usize::from(takes_value) + 1;
            continue;
        }
        return is_command_path(std::slice::from_ref(word)).then_some(at);
    }
    None
}

/// Whether `path` is a prefix of a command in the real command registry.
fn is_command_path(path: &[String]) -> bool {
    crate::schema::EFFECTS.iter().any(|effect| {
        let words: Vec<&str> = effect
            .command
            .split_whitespace()
            .filter(|w| !w.starts_with('-'))
            .collect();
        words.len() >= path.len() && words.iter().zip(path).all(|(a, b)| *a == b.as_str())
    })
}

#[cfg(test)]
#[path = "step_tests.rs"]
mod tests;
