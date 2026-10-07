use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use opv::Error;
use opv::app::{config_export, doctor, explain, run as run_cmd, skeleton, status, sync};
use opv::config;
use opv::runner::ProcessRunner;

const EXAMPLES: &str = "\
Examples:
  opv item skeleton staging          # add the missing (empty) fields to the 1Password item
  opv status staging                 # one row per product and key; fill what is missing
  opv fly plan staging               # what a sync would stage, hold and prune
  opv fly sync staging --deploy      # stage on Fly, deploy only if something changed
  opv run dev --product api -- cargo run   # local run with the product's secrets

Exit codes:
  0 ok, 2 configuration or usage, 3 dependency (op or flyctl missing), 4 1Password,
  5 Fly, 6 refused (policy), 7 authentication, 8 findings (status, fly plan).
  `run` exits with the command's own exit code.";

/// Sync secrets from 1Password into runtime targets.
///
/// Values live in 1Password and are consumed by the runtime; opv only connects the
/// two and never prints, logs or writes a secret value. <ENV> is the name of an
/// environment defined in the configuration (for example staging or prod).
#[derive(Parser)]
#[command(
    name = "opv",
    bin_name = "opv",
    version,
    about,
    long_about,
    after_long_help = EXAMPLES
)]
struct Cli {
    /// Path to the fleet configuration.
    ///
    /// Without this option, `secrets.toml` is looked for in the current directory and
    /// then each parent directory, and the first one found is used.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check the configuration, op and its sign-in, and flyctl and its sign-in.
    Doctor,
    /// Show one row per product and key with its 1Password and Fly state (names only).
    ///
    /// Exits 8 when any key is missing, of the wrong kind or failing a rule.
    Status {
        /// Environment name from the configuration (for example staging or prod).
        env: String,
        /// Print one machine-readable JSON document instead of the table.
        #[arg(long)]
        json: bool,
    },
    /// Run a command with the product's secrets in its environment, via `op run`.
    ///
    /// Exits with the child's own exit code, so a child code can equal an opv
    /// category code (for example 2); opv's own errors print `opv: ...` on
    /// stderr.
    Run {
        /// Environment name from the configuration (for example dev or staging).
        env: String,
        /// Product whose declared keys are passed to the command (fleet profile only;
        /// a simple-profile file takes none and passes every declared key).
        #[arg(long)]
        product: Option<String>,
        /// Command and arguments, after `--`.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Fly.io target commands.
    #[command(subcommand)]
    Fly(FlyCmd),
    /// Configuration commands.
    #[command(subcommand)]
    Config(ConfigCmd),
    /// 1Password item commands.
    #[command(subcommand)]
    Item(ItemCmd),
    /// Explain one declared key from the configuration alone; never reads a value.
    ///
    /// Prints the op:// reference, kind, Fly name, rules, immutable and guidance, and the
    /// `op item get` command to inspect the item yourself. Makes no 1Password or Fly call.
    Explain {
        /// The key as PRODUCT/KEY.
        #[arg(value_name = "PRODUCT/KEY")]
        target: String,
        /// Environment name; may be omitted when only one environment is declared.
        #[arg(long)]
        env: Option<String>,
    },
}

#[derive(Subcommand)]
enum FlyCmd {
    /// Show what a sync would stage, hold and prune; changes nothing.
    ///
    /// Exits 8 when any row (missing, wrong kind, failing a rule) would block a sync.
    Plan {
        /// Environment name from the configuration (for example staging or prod).
        env: String,
        /// Print one machine-readable JSON document instead of the table.
        #[arg(long)]
        json: bool,
    },
    /// Stage the managed secrets on the environment's Fly app.
    ///
    /// Refuses (exit 6) and stages nothing when any key is missing, of the wrong kind or
    /// failing a rule. Nothing is deployed or removed without the flags below.
    Sync {
        /// Environment name from the configuration (for example staging or prod).
        env: String,
        /// Deploy when a staged digest changed, a prune happened, or a managed name is
        /// still pending (Staged/Partial) on Fly from an earlier run.
        #[arg(long)]
        deploy: bool,
        /// Unset managed names that are not desired in this environment. Immutable keys
        /// are never pruned unless named with --prune-immutable.
        #[arg(long)]
        prune: bool,
        /// Stage an immutable key even though it is present on Fly (repeatable).
        #[arg(long, value_name = "PRODUCT/KEY")]
        rotate: Vec<String>,
        /// Let --prune unset this immutable key (repeatable).
        #[arg(long, value_name = "PRODUCT/KEY")]
        prune_immutable: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Print the config-kind (non-secret) values as JSON.
    Export {
        /// Environment name from the configuration (for example staging or prod).
        env: String,
        /// Output JSON (required; the only format).
        #[arg(long, required = true)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ItemCmd {
    /// Add every missing declared field to the item, empty; the only 1Password write.
    Skeleton {
        /// Environment name from the configuration (for example staging or prod).
        env: String,
    },
}

/// Stdout that stops writing once the reader has gone (`status | head`): a `BrokenPipe`
/// is swallowed, later writes are dropped, and the command still returns its own result
/// instead of a dependency error. Other write errors are passed through.
struct PipeSafe<W: Write> {
    inner: W,
    closed: bool,
}

impl<W: Write> Write for PipeSafe<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.closed {
            return Ok(buf.len());
        }
        match self.inner.write(buf) {
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                self.closed = true;
                Ok(buf.len())
            }
            other => other,
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        match self.inner.flush() {
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                self.closed = true;
                Ok(())
            }
            other => other,
        }
    }
}

fn main() -> ExitCode {
    // clap prints usage errors itself and exits 2 (shared with configuration errors).
    let cli = Cli::parse();
    let mut stdout = PipeSafe {
        inner: io::stdout().lock(),
        closed: false,
    };
    let res = run(cli, &mut stdout);
    let _ = stdout.flush();
    match res {
        // `run` reports the child's exit code verbatim (FR-4); everything else yields 0.
        Ok(0) => ExitCode::SUCCESS,
        Ok(code) => ExitCode::from(exit_byte(code)),
        Err(e) => {
            // Error messages never contain secret values or child output (SR-1).
            let _ = writeln!(io::stderr(), "opv: {e}");
            ExitCode::from(exit_byte(e.exit_code()))
        }
    }
}

fn run(cli: Cli, out: &mut dyn Write) -> Result<i32, Error> {
    let r = ProcessRunner::default();
    // A missing config is a configuration error for the command, not an early exit, so
    // `doctor` still runs its other checks on a fresh machine.
    let loaded = match &cli.config {
        Some(path) => config::load(path),
        None => match std::env::current_dir() {
            Err(e) => Err(Error::Config(format!(
                "cannot read the current directory: {e}"
            ))),
            Ok(start) => match config::discover(&start) {
                Some(found) => {
                    let _ = writeln!(io::stderr(), "using {}", found.display());
                    config::load(&found)
                }
                None => Err(Error::Config(format!(
                    "no secrets.toml found in {} or any parent directory; pass --config <path>",
                    start.display()
                ))),
            },
        },
    };
    if let Cmd::Run {
        env,
        product,
        command,
    } = &cli.cmd
    {
        return run_cmd::run_for(&loaded?, env, product.as_deref(), command, &r);
    }
    run_other(cli.cmd, loaded, &r, out).map(|()| 0)
}

fn run_other(
    cmd: Cmd,
    loaded: Result<opv::domain::Fleet, Error>,
    r: &ProcessRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    match cmd {
        Cmd::Run { .. } => unreachable!("handled by run"),
        Cmd::Doctor => doctor::run(loaded, r, out),
        Cmd::Status { env, json } => status::run_with(&loaded?, &env, r, out, json),
        Cmd::Fly(FlyCmd::Plan { env, json }) => sync::plan_with(&loaded?, &env, r, out, json),
        Cmd::Fly(FlyCmd::Sync {
            env,
            deploy,
            prune,
            rotate,
            prune_immutable,
        }) => {
            let opts = sync::SyncOpts {
                deploy,
                prune,
                rotate,
                prune_immutable,
            };
            sync::run(&loaded?, &env, r, out, &opts)
        }
        Cmd::Config(ConfigCmd::Export { env, json: _ }) => {
            config_export::run(&loaded?, &env, r, out)
        }
        Cmd::Item(ItemCmd::Skeleton { env }) => skeleton::run(&loaded?, &env, r, out),
        Cmd::Explain { target, env } => explain::run(&loaded?, &target, env.as_deref(), out),
    }
}

/// Clamp an exit code to the 1..=255 range a process can report; failures never become 0.
fn exit_byte(code: i32) -> u8 {
    match u8::try_from(code) {
        Ok(0) | Err(_) => 1,
        Ok(b) => b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Closed(usize);
    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            self.0 += 1;
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }

    #[test]
    fn pipe_safe_swallows_broken_pipe_and_stops_writing() {
        let mut w = PipeSafe {
            inner: Closed(0),
            closed: false,
        };
        writeln!(w, "a").unwrap();
        writeln!(w, "b").unwrap();
        w.flush().unwrap();
        assert!(w.closed);
        assert_eq!(w.inner.0, 1, "no write after the pipe closed");
    }

    #[test]
    fn pipe_safe_passes_other_errors_through() {
        struct Full;
        impl Write for Full {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::StorageFull.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut w = PipeSafe {
            inner: Full,
            closed: false,
        };
        assert!(writeln!(w, "a").is_err());
    }

    /// Usage reads `opv` whatever argv[0] is (Windows passes `opv.exe`).
    #[test]
    fn usage_uses_pinned_bin_name() {
        for argv0 in ["opv.exe", r"C:\bin\opv.exe", "/usr/bin/opv"] {
            let e = match Cli::try_parse_from([argv0, "run", "--help"]) {
                Err(e) => e,
                Ok(_) => panic!("--help must not parse"),
            };
            let t = e.render().to_string();
            assert!(t.contains("Usage: opv run"), "{argv0}: {t}");
            assert!(!t.contains("opv.exe"), "{argv0}: {t}");
        }
    }

    #[test]
    fn help_has_no_requirement_ids_and_has_examples() {
        use clap::CommandFactory;
        let mut cmd = Cli::command();
        let mut texts = vec![cmd.render_long_help().to_string()];
        for sub in cmd.get_subcommands_mut() {
            texts.push(sub.render_long_help().to_string());
            for s in sub.get_subcommands_mut() {
                texts.push(s.render_long_help().to_string());
            }
        }
        let re = regex::Regex::new(r"\b(FR|SR)-\d").unwrap();
        for t in &texts {
            assert!(!re.is_match(t), "requirement id in help: {t}");
        }
        assert!(texts[0].contains("Examples:"), "{}", texts[0]);
        for step in ["item skeleton", "status", "fly plan", "fly sync", "run "] {
            assert!(texts[0].contains(step), "{step}: {}", texts[0]);
        }
        assert!(texts[0].contains("7 authentication"), "{}", texts[0]);
        assert!(texts.iter().all(|t| !t.contains("expect-no-change")));
    }
}
