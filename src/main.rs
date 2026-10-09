use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::parser::ValueSource;
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use opv::Error;
use opv::app::{config_export, doctor, explain, init, run as run_cmd, skeleton, status, sync};
use opv::config;
use opv::runner::{Budget, ProcessRunner};

mod colour;
mod completions;

const QUICK_START: &str = "\
Start here:
  opv setup                        Guided setup for a new project
  opv init dev --vault V --item I  Use a 1Password item you already set up
  opv doctor                       Find a setup problem and its next step
  opv session                      Sign in once for your terminal

Everyday use:
  opv check dev --product api      Check that your app's settings are ready
  opv run dev --product api -- npm run dev

Deployment:
  opv plan staging                 Preview changes
  opv sync staging --deploy        Save settings and deploy

Every command is listed above. Use opv <command> --help for its options and examples.";

const EXAMPLES: &str = "\
Examples:
  opv setup                        # guided owner setup; resumes saved progress
  opv session                      # authenticated owner terminal; type exit to leave
  opv item skeleton staging        # add the missing (empty) fields to the 1Password item
  opv status staging               # one row per product and key; fill what is missing
  opv plan staging                 # what a sync would write, hold and prune
  opv sync staging --deploy        # write to the environment's target, deploy only if something changed
  opv check dev --product api      # local keys saved? names only, no target touched
  opv run dev --product api -- cargo run   # local run with the product's secrets

Exit codes:
  0 ok, 2 configuration or usage, 3 dependency (op or the target CLI (flyctl, az,
  kubectl) missing), 4 1Password, 5 target (Fly, Azure, Kubernetes), 6 refused (policy),
  7 authentication, 8 findings (status, plan, check),
  9 outcome unknown (a change may or may not have been applied) or provider
  unavailable; safe to re-run,
  130/143 interrupted (Ctrl-C / SIGTERM); safe to re-run.
  `run` exits with the command's own exit code.

Environment:
  OPV_CONFIG   default for --config
  OPV_PRODUCT  default for --product on check, run, doctor, explain, status and plan
               (never sync)
  NO_COLOR     no colour under --color auto

Docs: https://github.com/matt-cochran/1password-vault/blob/main/docs/usage.md
AI assistants: https://github.com/matt-cochran/1password-vault/blob/main/llms.txt";

const SYNC_EXAMPLES: &str = "\
Examples:
  opv plan staging                       # preview first; changes nothing
  opv sync staging                       # write changed settings; no deploy
  opv sync staging --deploy              # write, then deploy only if something changed
  opv sync staging --deploy --prune      # also remove managed names no longer declared
  opv sync prod --rotate api/SIGNING_KEY # replace an immutable key that is already set
  opv sync prod --deploy --confirm prod  # an environment with confirm_env = true
  opv sync prod --product api --deploy   # only api's names; other products untouched
  opv sync staging --json                # the run report as one JSON document";

const RUN_EXAMPLES: &str = "\
Examples:
  opv run dev --product api -- npm run dev    # start the app with api's settings
  opv run dev -- cargo test                   # simple profile: every declared key
  opv run staging --product api -- ./migrate  # use staging's values locally
  export OPV_PRODUCT=api; opv run dev -- npm run dev   # product from the environment";

const CHECK_EXAMPLES: &str = "\
Examples:
  opv check dev --product api          # are api's keys saved and valid?
  opv check dev                        # simple profile: every declared key
  opv check dev --product api --json   # names and states for scripts";

const INIT_EXAMPLES: &str = "\
Examples:
  opv init dev --vault myapp-dev --item app            # run-only environment
  opv init prod --vault myapp-prod --item app --fly-app myapp
  opv init prod --vault fleet-prod --item fleet --profile fleet --force";

const EXPLAIN_EXAMPLES: &str = "\
Examples:
  opv explain OPENAI_API_KEY                 # the one product that declares it
  opv explain api/OPENAI_API_KEY             # pick a product when several declare it
  opv explain api/OPENAI_API_KEY --env prod  # when several environments exist";

const DOCTOR_EXAMPLES: &str = "\
Examples:
  opv doctor                           # every check, every environment
  opv doctor --env dev                 # only what dev needs, plus one read of its item
  opv doctor --env prod --product api  # one product's keys
  opv doctor --json                    # the same checks as one JSON document";

const STATUS_EXAMPLES: &str = "\
Examples:
  opv status                           # one line per environment
  opv status staging                   # one row per key: 1Password and the target
  opv status prod --product api        # one product's rows and findings
  opv status prod --json               # the same, for scripts
  opv status prod || opv item skeleton prod   # add missing fields when status finds gaps";

const PLAN_EXAMPLES: &str = "\
Examples:
  opv plan staging                     # what a sync would write, hold and prune
  opv plan prod --product api          # one product's rows and findings
  opv plan prod --json                 # the same, for scripts
  opv plan prod && opv sync prod --deploy     # sync only when nothing blocks it";

/// Use 1Password settings in local apps and deployment targets.
///
/// Values live in 1Password and are consumed by the runtime; opv only connects the
/// two and never prints, logs or saves a secret value to a local file. <ENV> is the name of an
/// environment defined in the configuration (for example staging or prod).
#[derive(Parser)]
#[command(
    name = "opv",
    bin_name = "opv",
    version,
    after_help = QUICK_START,
    after_long_help = EXAMPLES
)]
struct Cli {
    /// Path to secrets.toml.
    ///
    /// Without this option (or OPV_CONFIG), `secrets.toml` is looked for in the current
    /// directory and then each parent directory, and the first one found is used. The
    /// path in use is printed on stderr as `using <path>` unless given with --config.
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        env = "OPV_CONFIG",
        help_heading = "Global options"
    )]
    config: Option<PathBuf>,
    /// Stop after this many seconds in total.
    ///
    /// Every call to op or the target CLI (flyctl, az, kubectl) must finish inside this
    /// budget; a read that fails is retried only while time remains.
    #[arg(
        long,
        global = true,
        value_name = "SECS",
        help_heading = "Global options",
        default_value_t = 900,
        value_parser = clap::value_parser!(u64).range(1..=86_400)
    )]
    timeout: u64,
    /// Print one line per call to op or the target CLI on stderr: program, arguments,
    /// duration and outcome, then the call's own error output with secrets masked and the
    /// size of its result (never values).
    #[arg(long, global = true, help_heading = "Global options")]
    verbose: bool,
    /// Colour state words (ok, warn, FAIL, saved, missing...): auto colours only on a
    /// terminal with NO_COLOR unset; JSON and values are never coloured.
    #[arg(
        long,
        global = true,
        value_name = "WHEN",
        value_enum,
        default_value_t = colour::ColorChoice::Auto,
        help_heading = "Global options"
    )]
    color: colour::ColorChoice,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Set up local credentials with a guided, resumable owner flow.
    ///
    /// Finds opv.setup.toml in this directory or a parent. Handles sign-in, creates
    /// missing fields, explains where each value comes from and saves progress.
    /// Requires your own interactive terminal. Never deploys or applies infrastructure.
    Setup {
        /// Project setup recipe; contains names and instructions, never credentials.
        #[arg(long, value_name = "PATH")]
        recipe: Option<PathBuf>,
        /// 1Password account to use when signing in.
        #[arg(long)]
        account: Option<String>,
        /// Product to set up; otherwise the guide asks when several are declared.
        #[arg(long)]
        product: Option<String>,
    },
    /// Sign in once for a terminal or a command; no token copying or shell exports.
    ///
    /// With no command, opens an owner terminal. Exit that terminal to end the session.
    /// With a command after --, returns its exit code. Requires your interactive terminal.
    #[command(
        after_help = "Examples:\n  opv session                      # signed-in terminal; type exit to leave\n  opv session -- opv check dev     # one signed-in command, then back"
    )]
    Session {
        /// 1Password account to sign in to (sign-in address, email or account ID);
        /// without it, op's default account is used.
        #[arg(long)]
        account: Option<String>,
        /// Command and arguments to run signed in, after `--`; without one, opens a
        /// signed-in terminal.
        #[arg(
            value_name = "COMMAND",
            trailing_var_arg = true,
            allow_hyphen_values = true
        )]
        command: Vec<String>,
    },
    /// Find setup problems and show the next step.
    ///
    /// Checks configuration, CLI installation and sign-in. --env limits checks to
    /// what that environment needs, including whether op can start local commands, and
    /// reads its item once to check the keys as `check` does (names only, never values).
    #[command(after_help = DOCTOR_EXAMPLES)]
    Doctor {
        /// Check only this environment.
        #[arg(long)]
        env: Option<String>,
        /// Limit configuration checks to one product; requires --env. [env: OPV_PRODUCT]
        #[arg(long, requires = "env")]
        product: Option<String>,
        /// Print one JSON document (check names, states and next steps) instead of lines.
        #[arg(long)]
        json: bool,
    },
    /// Check whether your required settings are ready; contacts no deployment target.
    #[command(after_help = CHECK_EXAMPLES)]
    Check {
        /// Environment name from the configuration (for example dev).
        env: String,
        /// Product whose keys are checked (fleet profile only; required there).
        /// [env: OPV_PRODUCT]
        #[arg(long)]
        product: Option<String>,
        /// Print names and states as JSON, never values.
        #[arg(long)]
        json: bool,
    },
    /// Inspect settings in 1Password and on the deployment target (names only).
    ///
    /// Exits 8 when any key is missing, of the wrong kind or failing a rule. Without
    /// <ENV>, prints one summary line per environment.
    #[command(after_help = STATUS_EXAMPLES)]
    Status {
        /// Environment name from the configuration (for example staging or prod); without
        /// it, one line per environment.
        env: Option<String>,
        /// Only this product's rows, totals and findings (fleet profile only).
        /// [env: OPV_PRODUCT]
        #[arg(long, requires = "env")]
        product: Option<String>,
        /// Print one machine-readable JSON document instead of the table.
        #[arg(long, requires = "env")]
        json: bool,
    },
    /// Run your app with the selected product's 1Password settings.
    ///
    /// Exits with the child's own exit code, so a child code can equal an opv
    /// category code (for example 2); opv's own errors print `opv: ...` on
    /// stderr.
    #[command(after_help = RUN_EXAMPLES)]
    Run {
        /// Environment name from the configuration (for example dev or staging).
        env: String,
        /// Product whose declared keys are passed to the command (fleet profile only;
        /// a simple-profile file takes none and passes every declared key).
        /// [env: OPV_PRODUCT]
        #[arg(long)]
        product: Option<String>,
        /// Command and arguments, after `--`.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Preview deployment changes without changing anything.
    ///
    /// Exits 8 when any row (missing, wrong kind, failing a rule) would block a sync.
    #[command(after_help = PLAN_EXAMPLES)]
    Plan(PlanArgs),
    /// Save managed settings on the configured deployment target.
    ///
    /// Refuses (exit 6) and stages nothing when any key is missing, of the wrong kind or
    /// failing a rule. Nothing is deployed or removed without the flags below.
    /// Preview first with opv plan <ENV>.
    #[command(after_help = SYNC_EXAMPLES)]
    Sync(SyncArgs),
    /// Configuration commands.
    #[command(subcommand)]
    Config(ConfigCmd),
    /// 1Password item commands.
    #[command(subcommand)]
    Item(ItemCmd),
    /// Explain one declared key from the configuration alone; never reads a value.
    ///
    /// Prints the op:// reference, kind, target name, rules, immutable and guidance, and
    /// the `op item get` command to inspect the item yourself. Makes no 1Password or
    /// target call.
    #[command(after_help = EXPLAIN_EXAMPLES)]
    Explain {
        /// The key. A bare KEY resolves to the one product that declares it (to
        /// OPV_PRODUCT/KEY when OPV_PRODUCT is set); when several do, they are listed.
        /// An unknown name suggests the closest declared ones.
        #[arg(value_name = "[PRODUCT/]KEY")]
        target: String,
        /// Environment name; may be omitted when only one environment is declared.
        #[arg(long)]
        env: Option<String>,
    },
    /// Generate configuration from a 1Password item you have already set up.
    ///
    /// Looks the vault and item up by title once, reads the item's field names and types
    /// (never its values) and writes IDs, key names and kinds. Writes nothing to 1Password.
    /// Does not use --config or OPV_CONFIG.
    #[command(after_help = INIT_EXAMPLES)]
    Init {
        /// Environment name to declare (for example staging or prod).
        env: String,
        /// Vault title, matched exactly.
        #[arg(long)]
        vault: String,
        /// Item title in that vault, matched exactly.
        #[arg(long)]
        item: String,
        /// Fly app of the environment (not looked up; flyctl is not called). Omit it for a
        /// run-only environment used for local development.
        #[arg(long, value_name = "APP")]
        fly_app: Option<String>,
        /// Profile to write; without it, it follows the item's shape.
        #[arg(long, value_parser = ["simple", "fleet"])]
        profile: Option<String>,
        /// Overwrite an existing secrets.toml.
        #[arg(long)]
        force: bool,
    },
    /// Print a shell completion script for commands and options.
    #[command(after_help = completions::INSTALL)]
    Completions {
        /// Shell to write the script for.
        #[arg(value_enum)]
        shell: completions::Shell,
    },
}

/// Arguments of `plan`.
#[derive(Args)]
struct PlanArgs {
    /// Environment name from the configuration (for example staging or prod).
    env: String,
    /// Only this product's rows, totals and findings (fleet profile only).
    /// [env: OPV_PRODUCT]
    #[arg(long)]
    product: Option<String>,
    /// Print one machine-readable JSON document instead of the table.
    #[arg(long)]
    json: bool,
}

/// Arguments of `sync`.
#[derive(Args)]
struct SyncArgs {
    /// Environment name from the configuration (for example staging or prod).
    env: String,
    /// Deploy when a staged digest changed, a prune happened, or a managed name is
    /// still pending (Staged/Partial) on the target from an earlier run.
    #[arg(long)]
    deploy: bool,
    /// Unset managed names that are not desired in this environment. Immutable keys
    /// are never pruned unless named with --prune-immutable.
    #[arg(long)]
    prune: bool,
    /// Stage an immutable key even though it is present on the target (repeatable).
    #[arg(long, value_name = "PRODUCT/KEY")]
    rotate: Vec<String>,
    /// Let --prune unset this immutable key (repeatable).
    #[arg(long, value_name = "PRODUCT/KEY")]
    prune_immutable: Vec<String>,
    /// Write, prune and deploy only this product's names (fleet profile only). A deploy
    /// still restarts the whole app. OPV_PRODUCT is never used here.
    #[arg(long)]
    product: Option<String>,
    /// The environment's name again; required when it sets confirm_env = true.
    #[arg(long, value_name = "ENV")]
    confirm: Option<String>,
    /// Print the run report as one JSON document (names only) instead of text.
    #[arg(long)]
    json: bool,
}

impl From<SyncArgs> for sync::SyncOpts {
    fn from(a: SyncArgs) -> Self {
        Self {
            deploy: a.deploy,
            prune: a.prune,
            rotate: a.rotate,
            prune_immutable: a.prune_immutable,
            product: a.product,
            confirm: a.confirm,
            json: a.json,
        }
    }
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Print the config-kind (non-secret) values as JSON.
    Export {
        /// Environment name from the configuration (for example staging or prod).
        env: String,
        /// Output JSON (the default and only format; accepted for scripts that pass it).
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ItemCmd {
    /// Add every missing declared field to the item, empty (a signed-in person's runs do this too).
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

/// Where the configuration path came from, for the `using` line and `init`'s refusal.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ConfigSource {
    Flag,
    Env,
    Discovered,
}

fn main() -> ExitCode {
    // clap prints usage errors itself (exit 2, shared with configuration errors); opv adds
    // the `Next:` line (NR-19).
    let matches = match Cli::command().try_get_matches() {
        Ok(m) => m,
        Err(e) => return usage_error(e),
    };
    let config_source = match matches.value_source("config") {
        Some(ValueSource::EnvVariable) => ConfigSource::Env,
        Some(_) => ConfigSource::Flag,
        None => ConfigSource::Discovered,
    };
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => return usage_error(e),
    };
    let rerun = rerun_command(&cli.cmd);
    opv::runner::signals::set_rerun(&rerun);
    let mut stdout = PipeSafe {
        inner: io::stdout().lock(),
        closed: false,
    };
    let paint = colour::enabled(
        cli.color,
        io::IsTerminal::is_terminal(&io::stdout()),
        std::env::var_os("NO_COLOR"),
    ) && cli.cmd.has_state_words();
    let res = if paint {
        let mut painter = colour::Painter::new(&mut stdout);
        let res = run(cli, config_source, &mut painter);
        let _ = painter.flush();
        res
    } else {
        run(cli, config_source, &mut stdout)
    };
    let _ = stdout.flush();
    match res {
        // `run` reports the child's exit code verbatim (FR-4); everything else yields 0.
        Ok(0) => ExitCode::SUCCESS,
        Ok(code) => ExitCode::from(exit_byte(code)),
        Err(e) => {
            // Error messages never contain secret values (SR-1). The failed call's stderr
            // follows the error's first line only as a scrubbed excerpt of at most 5 lines
            // (NR-31); the `Next:` line is always the last line (NR-19).
            let excerpt = opv::runner::take_failure_excerpt();
            let fallback = e.default_next(&rerun);
            let _ = write!(
                io::stderr(),
                "{}",
                opv::error::report(&e, &fallback, excerpt.as_ref())
            );
            ExitCode::from(exit_byte(e.exit_code()))
        }
    }
}

/// A clap usage error (or the help shown for a missing command, exit 2), then the `Next:`
/// line naming the help to read (NR-19); `--help` and `--version` print as clap prints them
/// and exit 0.
fn usage_error(e: clap::Error) -> ExitCode {
    use clap::error::ErrorKind;
    if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
        e.exit();
    }
    let _ = e.print();
    let cmd = Cli::command();
    let sub = std::env::args()
        .skip(1)
        .find(|a| cmd.get_subcommands().any(|s| s.get_name() == a));
    let help = match sub {
        Some(s) => format!("opv {s} --help"),
        None => "opv --help".to_string(),
    };
    let _ = write!(io::stderr(), "{}", opv::error::next_line(&help));
    ExitCode::from(exit_byte(e.exit_code()))
}

/// The command line as typed, for "run it again" next steps. Arguments are names, flags
/// and paths, never values (SR-3); `run` and `session` carry the user's own command, which
/// is never repeated.
fn rerun_command(cmd: &Cmd) -> String {
    if matches!(cmd, Cmd::Run { .. } | Cmd::Session { .. }) {
        return "the same command".to_string();
    }
    let mut parts = vec!["opv".to_string()];
    parts.extend(std::env::args().skip(1).map(|a| shell_word(&a)));
    parts.join(" ")
}

/// `a`, single-quoted when the shell would split or expand it.
fn shell_word(a: &str) -> String {
    let plain = !a.is_empty()
        && a.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:@,+%".contains(c));
    if plain {
        a.to_string()
    } else {
        format!("'{}'", a.replace('\'', "'\\''"))
    }
}

impl Cmd {
    /// Text output with state words worth colouring (never JSON, never values).
    fn has_state_words(&self) -> bool {
        match self {
            Cmd::Doctor { json, .. } => !json,
            Cmd::Check { json, .. } | Cmd::Status { json, .. } => !json,
            Cmd::Plan(a) => !a.json,
            _ => false,
        }
    }
}

/// `--product`, or else `OPV_PRODUCT` (non-empty) under the fleet profile; the simple
/// profile takes no product, so the variable is ignored there. Returns the product and
/// whether it came from the variable.
fn product_or_env(
    flag: Option<String>,
    env: Option<String>,
    fleet_profile: bool,
) -> (Option<String>, bool) {
    match (flag, env) {
        (Some(p), _) => (Some(p), false),
        (None, Some(p)) if fleet_profile && !p.is_empty() => (Some(p), true),
        _ => (None, false),
    }
}

/// Apply `OPV_PRODUCT` to the commands that take a product (never `sync`), and say so on
/// stderr.
fn apply_product_env(cmd: &mut Cmd, loaded: &Result<opv::domain::Fleet, Error>) {
    let fleet_profile = matches!(loaded, Ok(f) if !f.is_simple());
    let env = std::env::var("OPV_PRODUCT").ok();
    let used = match cmd {
        Cmd::Check { product, .. }
        | Cmd::Run { product, .. }
        | Cmd::Plan(PlanArgs { product, .. })
        | Cmd::Status {
            env: Some(_),
            product,
            ..
        } => {
            let (p, used) = product_or_env(product.take(), env, fleet_profile);
            *product = p;
            used.then(|| product.clone()).flatten()
        }
        Cmd::Doctor {
            env: Some(_),
            product,
            ..
        } => {
            let (p, used) = product_or_env(product.take(), env, fleet_profile);
            *product = p;
            used.then(|| product.clone()).flatten()
        }
        Cmd::Explain { target, .. } if !target.contains('/') => {
            match product_or_env(None, env, fleet_profile) {
                (Some(p), true) => {
                    *target = format!("{p}/{target}");
                    Some(p)
                }
                _ => None,
            }
        }
        _ => None,
    };
    if let Some(p) = used {
        let _ = writeln!(io::stderr(), "product {p} (from OPV_PRODUCT)");
    }
}

fn run(cli: Cli, config_source: ConfigSource, out: &mut dyn Write) -> Result<i32, Error> {
    if let Cmd::Completions { shell } = &cli.cmd {
        completions::write(*shell, &mut Cli::command(), out);
        return Ok(0);
    }
    if let Cmd::Session { account, command } = &cli.cmd {
        use opv::app::{setup, setup_runtime};
        use setup::Interaction;
        setup_runtime::Console::require_terminal("session")?;
        let mut runtime = setup_runtime::Runtime::with_account(account.as_deref());
        let mut console = setup_runtime::Console;
        setup::prepare(account.as_deref(), &mut runtime, &mut console)?;
        if command.is_empty() {
            console.show("Signed in. This terminal can run opv setup, check and run. Type exit to leave the session.")?;
        }
        return runtime.child(command);
    }
    if let Cmd::Setup {
        recipe,
        account,
        product,
    } = &cli.cmd
    {
        use opv::app::{setup, setup_recipe, setup_runtime};
        setup_runtime::Console::require_terminal("setup")?;
        let start = std::env::current_dir()
            .map_err(|_| Error::Config("Cannot locate the current directory.".into()))?;
        let recipe = recipe
            .clone()
            .or_else(|| setup_recipe::discover(&start))
            .ok_or_else(|| setup_recipe::missing(&start))?;
        return setup::run(
            &recipe,
            cli.config.as_deref(),
            account.as_deref(),
            product.as_deref(),
            &mut setup_runtime::Runtime::with_account(account.as_deref()),
            &mut setup_runtime::Console,
        );
    }
    let r = ProcessRunner::new(
        Budget::starting_now(std::time::Duration::from_secs(cli.timeout)),
        cli.verbose,
    );
    // `run` keeps default signal behaviour: the user's command under `op run` handles its
    // own signals and its exit code is passed through (FR-4). `setup` and `session` are
    // interactive and returned above.
    if !matches!(cli.cmd, Cmd::Run { .. }) {
        opv::runner::signals::install().map_err(|e| {
            Error::Dependency(format!("cannot install signal handlers: {e}").into())
        })?;
    }
    if let Cmd::Init { .. } = &cli.cmd {
        return run_init(cli, config_source, &r, out).map(|()| 0);
    }
    // A missing config is a configuration error for the command, not an early exit, so
    // `doctor` still runs its other checks on a fresh machine.
    let loaded = match &cli.config {
        Some(path) => {
            if config_source == ConfigSource::Env {
                let _ = writeln!(io::stderr(), "using {} (from OPV_CONFIG)", path.display());
            }
            config::load(path)
        }
        None => match std::env::current_dir() {
            Err(e) => Err(Error::Config(
                format!("cannot read the current directory: {e}").into(),
            )),
            Ok(start) => match config::discover(&start) {
                Some(found) => {
                    let _ = writeln!(io::stderr(), "using {}", found.display());
                    config::load(&found)
                }
                None => Err(config::not_found(&start)),
            },
        },
    };
    let mut cmd = cli.cmd;
    apply_product_env(&mut cmd, &loaded);
    if let Cmd::Run {
        env,
        product,
        command,
    } = &cmd
    {
        return run_cmd::run_for(&loaded?, env, product.as_deref(), command, &r);
    }
    run_other(cmd, loaded, &r, out).map(|()| 0)
}

fn run_other(
    cmd: Cmd,
    loaded: Result<opv::domain::Fleet, Error>,
    r: &ProcessRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    match cmd {
        Cmd::Setup { .. } => unreachable!("handled before configuration discovery"),
        Cmd::Session { .. } => unreachable!("handled before configuration discovery"),
        Cmd::Run { .. } => unreachable!("handled by run"),
        Cmd::Init { .. } => unreachable!("handled by run_init"),
        Cmd::Completions { .. } => unreachable!("handled by run"),
        Cmd::Doctor { env, product, json } => {
            doctor::run_scoped_as(loaded, env.as_deref(), product.as_deref(), json, r, out)
        }
        Cmd::Check { env, product, json } => {
            opv::app::local::check(&loaded?, &env, product.as_deref(), r, out, json)
        }
        Cmd::Status {
            env: None,
            product: _,
            json: _,
        } => status::overview(&loaded?, r, out),
        Cmd::Status {
            env: Some(env),
            product,
            json,
        } => status::run_scoped(&loaded?, &env, product.as_deref(), r, out, json),
        Cmd::Plan(a) => sync::plan_scoped(&loaded?, &a.env, a.product.as_deref(), r, out, a.json),
        Cmd::Sync(a) => {
            let env = a.env.clone();
            sync::run(&loaded?, &env, r, out, &a.into())
        }
        Cmd::Config(ConfigCmd::Export { env, json: _ }) => {
            config_export::run(&loaded?, &env, r, out)
        }
        Cmd::Item(ItemCmd::Skeleton { env }) => skeleton::run(&loaded?, &env, r, out),
        Cmd::Explain { target, env } => explain::run(&loaded?, &target, env.as_deref(), out),
    }
}

/// `init` writes `./secrets.toml`; it reads no configuration, so it runs before discovery.
fn run_init(
    cli: Cli,
    config_source: ConfigSource,
    r: &ProcessRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let Cmd::Init {
        env,
        vault,
        item,
        fly_app,
        profile,
        force,
    } = cli.cmd
    else {
        unreachable!("called for init only")
    };
    if cli.config.is_some() {
        let how = if config_source == ConfigSource::Env {
            "OPV_CONFIG is set; unset it for init"
        } else {
            "--config is not used"
        };
        return Err(Error::Config(
            format!("init writes secrets.toml in the current directory; {how}").into(),
        ));
    }
    let dir = std::env::current_dir()
        .map_err(|e| Error::Config(format!("cannot read the current directory: {e}").into()))?;
    let args = init::InitArgs {
        env,
        vault,
        item,
        fly_app,
        profile: profile.as_deref().map(init::parse_profile).transpose()?,
        force,
    };
    init::run(&args, &dir, r, out)
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
    fn product_flag_wins_over_opv_product() {
        let got = product_or_env(Some("api".into()), Some("web".into()), true);
        assert_eq!(got, (Some("api".into()), false));
    }

    #[test]
    fn opv_product_applies_under_the_fleet_profile() {
        let got = product_or_env(None, Some("web".into()), true);
        assert_eq!(got, (Some("web".into()), true));
    }

    #[test]
    fn opv_product_is_ignored_under_the_simple_profile() {
        assert_eq!(
            product_or_env(None, Some("web".into()), false),
            (None, false)
        );
    }

    #[test]
    fn empty_opv_product_is_ignored() {
        assert_eq!(
            product_or_env(None, Some(String::new()), true),
            (None, false)
        );
    }

    #[test]
    fn json_output_is_never_painted() {
        let cli = Cli::try_parse_from(["opv", "status", "prod", "--json"]).unwrap();
        assert!(!cli.cmd.has_state_words());
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
        for step in ["item skeleton", "status", "plan ", "sync ", "run "] {
            assert!(texts[0].contains(step), "{step}: {}", texts[0]);
        }
        assert!(texts[0].contains("7 authentication"), "{}", texts[0]);
        assert!(texts.iter().all(|t| !t.contains("expect-no-change")));
    }
}
