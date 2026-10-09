use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::parser::ValueSource;
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use opv::Error;
use opv::app::{
    add, config_export, doctor, explain, init, run as run_cmd, signin, skeleton, status, sync,
};
use opv::config;
use opv::runner::{Budget, CommandRunner, ProcessRunner};

mod colour;
mod completions;

const QUICK_START: &str = "\
Start here:
  opv setup                        Guided setup for a new project
  opv init dev --vault V --item I  Use a 1Password item you already set up
  opv doctor                       Find a setup problem and its next step
  opv login dev                    Sign in to 1Password for an environment
  opv guide agent                  Setup guide for AI assistants (this version)

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
  opv login prod                   # signed-in terminal for prod's account; type exit to leave
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
AI assistants: opv guide agent (matches this version), or
  https://github.com/matt-cochran/1password-vault/blob/main/llms.txt";

// Subcommand help (H9): the about line, usage, two or three examples, the command's own
// options, then the details and more examples. Global options are listed once, in
// `opv --help`; subcommands end with one line naming them (see `cli_command`). Examples
// are agent-safe (S3): none runs a write after `||` or `&&`.

/// The line that ends every subcommand's help in place of the global options.
const GLOBAL_LINE: &str = "Global options: --config <PATH> --timeout <SECS> --verbose --color <WHEN> (details: opv --help)";

/// The layout of subcommand help: examples before the options, details after them.
const SUB_TEMPLATE: &str = "\
{about-with-newline}
{usage-heading} {usage}

{before-help}{all-args}{after-help}";

const SETUP_QUICK: &str = "\
Examples:
  opv setup                  # guided setup; resumes saved progress
  opv setup --product api    # set up one product";

const SETUP_MORE: &str = "\
Finds opv.setup.toml in this directory or a parent. Handles sign-in, creates missing fields,
explains where each value comes from and saves progress. Needs your own interactive
terminal (an AI assistant hands this command to the user). Never deploys or applies
infrastructure.";

const LOGIN_QUICK: &str = "\
Examples:
  opv login prod                             # signed-in terminal for prod; type exit to leave
  opv login                                  # the one account all environments use, or choose
  opv login prod -- opv check prod           # one signed-in command, then back";

const LOGIN_MORE: &str = "\
Signs in to the account the environment uses (its `account` setting). Without an
environment: the one account every environment uses, or a choice when they differ. With a
command after --, runs it signed in and returns its exit code. No token is printed and
nothing needs eval. Needs your own interactive terminal (an AI assistant hands this command
to the user).";

const DOCTOR_QUICK: &str = "\
Examples:
  opv doctor                 # every check, every environment
  opv doctor --env dev       # only what dev needs, plus one read of its item
  opv doctor --json          # the same checks as one JSON document";

const DOCTOR_MORE: &str = "\
Checks configuration, CLI installation and sign-in. --env limits the checks to what that
environment needs, including whether op can start local commands, and reads its item once
to check the keys as `check` does (names only, never values). Changes nothing.

More examples:
  opv doctor --env prod --product api   # one product's keys";

const CHECK_QUICK: &str = "\
Examples:
  opv check dev --product api          # are api's keys saved and valid?
  opv check dev                        # simple profile: every declared key
  opv check dev --product api --json   # names and states for scripts";

const CHECK_MORE: &str = "\
Reads the environment's item once (names, kinds and rule results, never values) and contacts
no deployment target. Exits 8 when a key needs fixing.";

const STATUS_QUICK: &str = "\
Examples:
  opv status                   # one line per environment
  opv status staging           # one row per key: 1Password and the target
  opv status prod --json       # the same, for scripts";

const STATUS_MORE: &str = "\
Changes nothing. Exits 8 when any key is missing, of the wrong kind or failing a rule;
opv explain <product>/<KEY> --env <ENV> shows how to fix one.

More examples:
  opv status prod --product api   # one product's rows and findings";

const RUN_QUICK: &str = "\
Examples:
  opv run dev --product api -- npm run dev    # start the app with api's settings
  opv run dev -- cargo test                   # simple profile: every declared key
  opv run staging --product api -- ./migrate  # use staging's values locally";

const RUN_MORE: &str = "\
Removes every declared key name from the inherited environment, then adds the selected
product's references through op run. Exits with the child's own exit code, so a child code
can equal an opv category code (for example 2); opv's own errors print `opv: ...` on stderr.

More examples:
  export OPV_PRODUCT=api; opv run dev -- npm run dev   # product from the environment";

const PLAN_QUICK: &str = "\
Examples:
  opv plan staging                 # what a sync would write, hold and prune
  opv plan prod --product api      # one product's rows and findings
  opv plan prod --json             # the same, for scripts";

const PLAN_MORE: &str = "\
Changes nothing. Exits 8 when any row (missing, wrong kind, failing a rule) would block a
sync, and ends with the exact sync command to run once it is clean.";

const SYNC_QUICK: &str = "\
Examples:
  opv plan staging                       # preview first; changes nothing
  opv sync staging --deploy              # write, then deploy only if something changed
  opv sync prod --deploy --confirm prod  # an environment with confirm_env = true";

const SYNC_MORE: &str = "\
Refuses (exit 6) and stages nothing when any key is missing, of the wrong kind or failing a
rule; on a guarded environment the same refusal says --confirm is needed too. Nothing is
deployed or removed without --deploy or --prune.

More examples:
  opv sync staging                       # write changed settings; no deploy
  opv sync staging --deploy --prune      # also remove managed names no longer declared
  opv sync prod --rotate api/SIGNING_KEY # replace an immutable key that is already set
  opv sync prod --product api --deploy   # only api's names; other products untouched";

const EXPORT_QUICK: &str = "\
Examples:
  opv config export staging        # config-kind values as one JSON object";

const EXPORT_MORE: &str = "\
Prints the values of config-kind keys by design, never secrets. Refuses (exit 6) when a
config key is stored concealed or a secret key as text.";

const SKELETON_QUICK: &str = "\
Examples:
  opv item skeleton staging        # add the missing declared fields, empty";

const SKELETON_MORE: &str = "\
The only opv command that writes to 1Password: it adds missing fields, empty, and never
fills or changes one. Needs an identity that may edit the item; an AI assistant asks the
user first.";

const ADD_QUICK: &str = "\
Examples:
  opv add api/STRIPE_KEY --kind secret --env dev,prod --rule prefix=sk_
  opv add LOG_LEVEL --kind config --rule enum=debug,info,warn   # simple profile
  opv add api/STRIPE_KEY --env staging          # include a declared key in staging";

const ADD_MORE: &str = "\
Edits the configuration in place (comments and order kept) and validates it like a
hand-written one before writing: a name that collides on a target, an unknown rule or a bad
rule value is refused. Makes no 1Password or target call. Then add the value in 1Password
(opv item skeleton <env> adds the empty field).

More examples:
  opv add api/JWT_KEY --kind secret --rule base64_bytes=32 --immutable \\
      --guidance \"32 random bytes, base64\"";

const EXPLAIN_QUICK: &str = "\
Examples:
  opv explain OPENAI_API_KEY                 # the one product that declares it
  opv explain api/OPENAI_API_KEY             # pick a product when several declare it
  opv explain api/OPENAI_API_KEY --env prod  # when several environments exist";

const EXPLAIN_MORE: &str = "\
Prints the op:// reference, kind, target name, rules, immutable and guidance, and the
`op item get` command to inspect the item yourself. Makes no 1Password or target call.";

const INIT_QUICK: &str = "\
Examples:
  opv init dev --vault myapp-dev --item app                    # run-only environment
  opv init prod --vault myapp-prod --item app --fly-app myapp  # deploys to Fly
  opv init staging --vault myapp-staging --item app --add-env  # add to the configuration";

const INIT_MORE: &str = "\
Reads the item's field names and types once (never values) and writes IDs, key names and
kinds to ./secrets.toml; writes nothing to 1Password and looks nothing up on the target.
--config and OPV_CONFIG are used only with --add-env. Fields: docs/configuration.md#targets.";

const COMPLETIONS_QUICK: &str = "\
Examples:
  opv completions bash > ~/.local/share/bash-completion/completions/opv
  opv completions fish > ~/.config/fish/completions/opv.fish";

const GUIDE_QUICK: &str = "\
Examples:
  opv guide agent              # the setup guide for AI assistants, for this version";

const GUIDE_MORE: &str = "\
Prints a guide embedded in this binary, so it matches the commands this version has. Links
point at the docs of the same release.";

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
    #[command(before_help = SETUP_QUICK, after_help = SETUP_MORE)]
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
    /// Sign in to 1Password for an environment, then open a signed-in terminal.
    #[command(before_help = LOGIN_QUICK, after_help = LOGIN_MORE)]
    Login {
        /// Environment name from the configuration (for example dev or prod).
        env: Option<String>,
        /// Command and arguments to run signed in, after `--`; without one, opens a
        /// signed-in terminal.
        #[arg(value_name = "COMMAND", last = true)]
        command: Vec<String>,
    },
    /// Find setup problems and show the next step.
    #[command(before_help = DOCTOR_QUICK, after_help = DOCTOR_MORE)]
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
    #[command(before_help = CHECK_QUICK, after_help = CHECK_MORE)]
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
    #[command(before_help = STATUS_QUICK, after_help = STATUS_MORE)]
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
    #[command(before_help = RUN_QUICK, after_help = RUN_MORE)]
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
    #[command(before_help = PLAN_QUICK, after_help = PLAN_MORE)]
    Plan(PlanArgs),
    /// Save managed settings on the configured deployment target.
    #[command(before_help = SYNC_QUICK, after_help = SYNC_MORE)]
    Sync(SyncArgs),
    /// Configuration commands.
    #[command(subcommand)]
    Config(ConfigCmd),
    /// 1Password item commands.
    #[command(subcommand)]
    Item(ItemCmd),
    /// Explain one declared key from the configuration alone; never reads a value.
    #[command(before_help = EXPLAIN_QUICK, after_help = EXPLAIN_MORE)]
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
    #[command(before_help = INIT_QUICK, after_help = INIT_MORE)]
    Init {
        /// Environment name to declare (for example staging or prod).
        env: String,
        /// Vault title, matched exactly.
        #[arg(long)]
        vault: String,
        /// Item title in that vault, matched exactly.
        #[arg(long)]
        item: String,
        /// Deployment target of the environment; its options follow (--<target>-<field>).
        /// Inferred from those options when omitted; omit both for a run-only environment
        /// used for local development. Nothing is looked up.
        #[arg(long, value_name = "PROVIDER")]
        target: Option<String>,
        /// Add this environment to the existing secrets.toml (found like other commands:
        /// --config, OPV_CONFIG or the nearest one) instead of writing a new file; comments
        /// are kept, and every declared key the item has includes the environment.
        #[arg(long, conflicts_with_all = ["force", "profile"])]
        add_env: bool,
        /// Profile to write; without it, it follows the item's shape.
        #[arg(long, value_parser = ["simple", "fleet"])]
        profile: Option<String>,
        /// Overwrite an existing secrets.toml.
        #[arg(long)]
        force: bool,
    },
    /// Declare a key in secrets.toml, or add environments to a declared key.
    ///
    /// Edits the file in place (comments and order kept) and validates it like a
    /// hand-written one before writing: a name that collides on a target, an unknown rule
    /// or a bad rule value is refused. Makes no 1Password or target call.
    #[command(before_help = ADD_QUICK, after_help = ADD_MORE)]
    Add {
        /// The key: PRODUCT/KEY (fleet profile) or KEY (simple profile).
        #[arg(value_name = "[PRODUCT/]KEY")]
        name: String,
        /// secret (a concealed field) or config (a text field); required for a new key.
        #[arg(long, value_parser = ["secret", "config"])]
        kind: Option<String>,
        /// Environments that need the key (repeat or comma-separate); default: every
        /// declared environment.
        #[arg(long, value_delimiter = ',')]
        env: Vec<String>,
        /// A rule as name=value (prefix=sk_, base64_bytes=32, enum=debug,info) or a flag
        /// rule by name (https_url); repeatable.
        #[arg(long, value_name = "NAME[=VALUE]")]
        rule: Vec<String>,
        /// Where the value comes from, shown by explain and setup.
        #[arg(long)]
        guidance: Option<String>,
        /// Staged only when absent on the target unless rotated.
        #[arg(long)]
        immutable: bool,
    },
    /// Print a shell completion script for commands and options.
    #[command(before_help = COMPLETIONS_QUICK, after_help = completions::INSTALL)]
    Completions {
        /// Shell to write the script for.
        #[arg(value_enum)]
        shell: completions::Shell,
    },
    /// Print a guide that matches this version of opv (for AI assistants: agent).
    #[command(before_help = GUIDE_QUICK, after_help = GUIDE_MORE)]
    Guide {
        /// The guide to print.
        #[arg(value_enum)]
        topic: GuideTopic,
    },
}

/// Guides embedded in the binary (A10).
#[derive(Clone, Copy, clap::ValueEnum)]
enum GuideTopic {
    /// Setting opv up in a user's project, for AI assistants: rules, steps, exit codes.
    Agent,
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
    /// The environment's name again; required when it sets confirm_env = true.
    #[arg(long, value_name = "ENV")]
    confirm: Option<String>,
    /// Write, prune and deploy only this product's names (fleet profile only). A deploy
    /// still restarts the whole app. OPV_PRODUCT is never used here.
    #[arg(long)]
    product: Option<String>,
    /// Print the run report as one JSON document (names only) instead of text.
    #[arg(long)]
    json: bool,
    /// Stage an immutable key even though it is present on the target (repeatable).
    #[arg(long, value_name = "PRODUCT/KEY", hide_short_help = true)]
    rotate: Vec<String>,
    /// Let --prune unset this immutable key (repeatable).
    #[arg(long, value_name = "PRODUCT/KEY", hide_short_help = true)]
    prune_immutable: Vec<String>,
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
    #[command(before_help = EXPORT_QUICK, after_help = EXPORT_MORE)]
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
    /// Add every missing declared field to the item, empty; the only 1Password write.
    #[command(before_help = SKELETON_QUICK, after_help = SKELETON_MORE)]
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

/// The command line: the derived [`Cli`] plus each provider's `init` options
/// (`--<provider>-<field>`), taken from the plug-in contract so a new provider adds its
/// options without a change here (H3).
fn command_line() -> clap::Command {
    use opv::adapters::registry;
    use opv::provider::init_flag;
    Cli::command().mut_subcommand("init", |mut c| {
        c = c.mut_arg("target", |a| {
            a.value_parser(clap::builder::PossibleValuesParser::new(
                registry::PROVIDERS
                    .iter()
                    .filter(|p| !p.init_fields().is_empty())
                    .map(|p| p.section()),
            ))
        });
        // One line per provider in the help (H9: --help fits on one screen); each option is
        // a hidden argument, so clap still parses and completes it.
        let mut summary = String::from("Target options (* required with that --target):");
        for p in registry::PROVIDERS.iter().filter(|p| !p.init_fields().is_empty()) {
            let flags: Vec<String> = p
                .init_fields()
                .iter()
                .map(|f| {
                    let star = if f.required { "*" } else { "" };
                    format!("--{}{star}", init_flag(*p, f))
                })
                .collect();
            summary.push_str(&format!("\n  {:<11} {}", p.section(), flags.join(" ")));
            for f in p.init_fields() {
                let flag = init_flag(*p, f);
                c = c.arg(
                    clap::Arg::new(flag.clone())
                        .long(flag)
                        .value_name(f.field.to_ascii_uppercase())
                        .help(f.help)
                        .hide(true),
                );
            }
        }
        let more = c.get_after_help().map(|a| a.to_string()).unwrap_or_default();
        c = c.after_help(format!("{summary}\n\n{more}"));
        c
    })
}

/// The provider options given to `init`, by option name.
fn init_fields(matches: &clap::ArgMatches) -> std::collections::BTreeMap<String, String> {
    use opv::adapters::registry;
    use opv::provider::init_flag;
    let Some(m) = matches.subcommand_matches("init") else {
        return Default::default();
    };
    registry::PROVIDERS
        .iter()
        .flat_map(|p| p.init_fields().iter().map(move |f| init_flag(*p, f)))
        .filter_map(|flag| {
            m.get_one::<String>(&flag)
                .map(|v| (flag.clone(), v.clone()))
        })
        .collect()
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
    let matches = match cli_command().try_get_matches() {
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
    let init_options = init_fields(&matches);
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
        let res = run(cli, config_source, &init_options, &mut painter);
        let _ = painter.flush();
        res
    } else {
        run(cli, config_source, &init_options, &mut stdout)
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

/// The command tree as parsed and shown (H9): every subcommand uses [`SUB_TEMPLATE`], hides
/// the global options (listed once in `opv --help`) and ends with [`GLOBAL_LINE`].
/// Completions use the plain tree, so they still complete the global options.
fn cli_command() -> clap::Command {
    let mut cmd = command_line();
    // Global options reach the subcommands when the tree is built.
    cmd.build();
    let globals: Vec<clap::Id> = cmd
        .get_arguments()
        .filter(|a| a.is_global_set())
        .map(|a| a.get_id().clone())
        .collect();
    for sub in cmd.get_subcommands_mut() {
        *sub = shorten(std::mem::take(sub), &globals);
    }
    cmd
}

/// One subcommand (and its own subcommands) laid out as [`cli_command`] describes.
fn shorten(sub: clap::Command, globals: &[clap::Id]) -> clap::Command {
    let mut sub = sub.mut_args(|a| {
        if globals.contains(a.get_id()) {
            a.hide(true)
        } else {
            a
        }
    });
    if sub.has_subcommands() {
        for s in sub.get_subcommands_mut() {
            *s = shorten(std::mem::take(s), globals);
        }
        return sub;
    }
    let after = match sub.get_after_help() {
        Some(a) => format!("{a}\n\n{GLOBAL_LINE}"),
        None => GLOBAL_LINE.to_string(),
    };
    sub.help_template(SUB_TEMPLATE).after_help(after)
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
    let cmd = cli_command();
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
/// and paths, never values (SR-3); `run` and `login` carry the user's own command, which
/// is never repeated.
fn rerun_command(cmd: &Cmd) -> String {
    if matches!(cmd, Cmd::Run { .. } | Cmd::Login { .. }) {
        return "the same command".to_string();
    }
    let mut parts = vec!["opv".to_string()];
    parts.extend(std::env::args().skip(1).map(|a| shell_word(&a)));
    parts.join(" ")
}

/// The read-only command that loads the configuration again for the same environment, the
/// `Next:` step once a configuration error is fixed (H10). A writing command is never
/// repeated: `sync` becomes `plan`, `run` becomes `check`, `item skeleton` and `config
/// export` become `doctor --env`. `config` is the `--config` path when one was given.
fn recheck_command(cmd: &Cmd, config: Option<&std::path::Path>) -> String {
    let mut c = "opv".to_string();
    if let Some(p) = config {
        c.push_str(" --config ");
        c.push_str(&shell_word(&p.display().to_string()));
    }
    let with_product = |verb: &str, env: &str, product: &Option<String>| match product {
        Some(p) => format!("{verb} {} --product {}", shell_word(env), shell_word(p)),
        None => format!("{verb} {}", shell_word(env)),
    };
    let tail = match cmd {
        Cmd::Sync(a) => with_product("plan", &a.env, &a.product),
        Cmd::Plan(a) => with_product("plan", &a.env, &a.product),
        Cmd::Run { env, product, .. } | Cmd::Check { env, product, .. } => {
            with_product("check", env, product)
        }
        Cmd::Status {
            env: Some(env),
            product,
            ..
        } => with_product("status", env, product),
        Cmd::Explain { target, env } => match env {
            Some(e) => format!("explain {} --env {}", shell_word(target), shell_word(e)),
            None => format!("explain {}", shell_word(target)),
        },
        Cmd::Item(ItemCmd::Skeleton { env }) | Cmd::Config(ConfigCmd::Export { env, .. }) => {
            format!("doctor --env {}", shell_word(env))
        }
        _ => "status".to_string(),
    };
    format!("{c} {tail}")
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
    /// The environment the command acts on, and whether it reaches the deployment target
    /// (and so signs in with the environment's deploy credentials, FR-40).
    fn env(&self) -> Option<(&str, signin::Reach)> {
        use signin::Reach;
        match self {
            Cmd::Check { env, .. }
            | Cmd::Run { env, .. }
            | Cmd::Config(ConfigCmd::Export { env, .. })
            | Cmd::Item(ItemCmd::Skeleton { env }) => Some((env, Reach::Store)),
            Cmd::Status { env: Some(env), .. } => Some((env, Reach::Target)),
            Cmd::Plan(a) => Some((&a.env, Reach::Target)),
            Cmd::Sync(a) => Some((&a.env, Reach::Target)),
            Cmd::Doctor { env: Some(env), .. } => Some((env, Reach::Target)),
            _ => None,
        }
    }

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

fn run(
    cli: Cli,
    config_source: ConfigSource,
    init_options: &std::collections::BTreeMap<String, String>,
    out: &mut dyn Write,
) -> Result<i32, Error> {
    if let Cmd::Completions { shell } = &cli.cmd {
        completions::write(*shell, &mut command_line(), out);
        return Ok(0);
    }
    if let Cmd::Guide { topic } = &cli.cmd {
        match topic {
            GuideTopic::Agent => opv::app::guide::run(out)?,
        }
        return Ok(0);
    }
    if let Cmd::Login { env, command } = &cli.cmd {
        use opv::app::{login, setup_runtime};
        setup_runtime::Console::require_terminal("login")?;
        let fleet = find_config(cli.config.as_ref(), config_source).transpose()?;
        return login::run(
            fleet.as_ref(),
            env.as_deref(),
            command,
            &mut setup_runtime::Runtime::default(),
            &mut setup_runtime::Console,
        );
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
    // own signals and its exit code is passed through (FR-4). `setup` and `login` are
    // interactive and returned above.
    if !matches!(cli.cmd, Cmd::Run { .. }) {
        opv::runner::signals::install().map_err(|e| {
            Error::Dependency(format!("cannot install signal handlers: {e}").into())
        })?;
    }
    if let Cmd::Init { add_env: false, .. } = &cli.cmd {
        return run_init(cli, config_source, init_options, &r, out).map(|()| 0);
    }
    // A missing config is a configuration error for the command, not an early exit, so
    // `doctor` still runs its other checks on a fresh machine.
    if let Cmd::Init { add_env: true, .. } | Cmd::Add { .. } = &cli.cmd {
        let path = config_path(cli.config.as_deref(), config_source);
        return run_edit(cli.cmd, &path?, init_options, &r, out).map(|()| 0);
    }
    let loaded = find_config(cli.config.as_ref(), config_source).unwrap_or_else(|| {
        Err(config::not_found(
            &std::env::current_dir().unwrap_or_default(),
        ))
    });
    let mut cmd = cli.cmd;
    // A file that does not load: re-check it with a read-only command (H10).
    let loaded = match loaded {
        Err(e) if !matches!(cmd, Cmd::Doctor { .. }) => {
            let flag = (config_source == ConfigSource::Flag)
                .then_some(cli.config.as_deref())
                .flatten();
            Err(e.or_next(|| recheck_command(&cmd, flag)))
        }
        other => other,
    };
    apply_product_env(&mut cmd, &loaded);
    // Every call for the environment uses its 1Password account, and commands that reach
    // the target sign in with its deploy credentials for this run only (FR-40). Dropped
    // (signed out, its private directory removed) when this function returns.
    // `doctor --env` reports a failed deploy sign-in as one check and keeps going.
    let mut deploy_failure = None;
    let env_runner = match (&loaded, cmd.env()) {
        (Ok(fleet), Some((env, _))) if matches!(cmd, Cmd::Doctor { .. }) => {
            let (runner, failed) = signin::open_for_doctor(fleet, env, &r);
            deploy_failure = failed;
            Some(runner)
        }
        (Ok(fleet), Some((env, reach))) => Some(signin::open(fleet, env, &r, reach)?),
        _ => None,
    };
    let runner: &dyn CommandRunner = match &env_runner {
        Some(e) => e,
        None => &r,
    };
    if let Cmd::Run {
        env,
        product,
        command,
    } = &cmd
    {
        return run_cmd::run_for(&loaded?, env, product.as_deref(), command, runner);
    }
    run_other(cmd, loaded, runner, deploy_failure, out).map(|()| 0)
}

/// The configuration: `--config` / `OPV_CONFIG`, else the nearest `secrets.toml` from the
/// current directory up (printed as `using <path>`). `None` when none was found.
fn find_config(
    config: Option<&PathBuf>,
    config_source: ConfigSource,
) -> Option<Result<opv::domain::Fleet, Error>> {
    match config {
        Some(path) => {
            if config_source == ConfigSource::Env {
                let _ = writeln!(io::stderr(), "using {} (from OPV_CONFIG)", path.display());
            }
            Some(config::load(path))
        }
        None => match std::env::current_dir() {
            Err(e) => Some(Err(Error::Config(
                format!("cannot read the current directory: {e}").into(),
            ))),
            Ok(start) => config::discover(&start).map(|found| {
                let _ = writeln!(io::stderr(), "using {}", found.display());
                config::load(&found)
            }),
        },
    }
}

fn run_other(
    cmd: Cmd,
    loaded: Result<opv::domain::Fleet, Error>,
    r: &dyn CommandRunner,
    deploy_failure: Option<Error>,
    out: &mut dyn Write,
) -> Result<(), Error> {
    match cmd {
        Cmd::Setup { .. } => unreachable!("handled before configuration discovery"),
        Cmd::Login { .. } => unreachable!("handled before configuration discovery"),
        Cmd::Run { .. } => unreachable!("handled by run"),
        Cmd::Init { .. } => unreachable!("handled by run_init"),
        Cmd::Add { .. } => unreachable!("handled by run_edit"),
        Cmd::Completions { .. } | Cmd::Guide { .. } => unreachable!("handled by run"),
        Cmd::Doctor { env, product, json } => {
            let scope = doctor::Request {
                env: env.as_deref(),
                product: product.as_deref(),
                json,
                deploy_failure,
            };
            doctor::run_request(loaded, scope, r, out)
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

/// The configuration file to use: `--config` / `OPV_CONFIG`, else the nearest
/// `secrets.toml` from the current directory up. Prints `using <path>` on stderr unless
/// the path came from `--config`.
fn config_path(flag: Option<&std::path::Path>, source: ConfigSource) -> Result<PathBuf, Error> {
    match flag {
        Some(path) => {
            if source == ConfigSource::Env {
                let _ = writeln!(io::stderr(), "using {} (from OPV_CONFIG)", path.display());
            }
            Ok(path.to_path_buf())
        }
        None => {
            let start = std::env::current_dir().map_err(|e| {
                Error::Config(format!("cannot read the current directory: {e}").into())
            })?;
            let found = config::discover(&start).ok_or_else(|| config::not_found(&start))?;
            let _ = writeln!(io::stderr(), "using {}", found.display());
            Ok(found)
        }
    }
}

/// `init` writes `./secrets.toml`; it reads no configuration, so it runs before discovery.
fn run_init(
    cli: Cli,
    config_source: ConfigSource,
    init_options: &std::collections::BTreeMap<String, String>,
    r: &ProcessRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    if cli.config.is_some() {
        let Cmd::Init {
            env,
            vault,
            item,
            target,
            profile,
            force,
            ..
        } = &cli.cmd
        else {
            unreachable!("called for init only")
        };
        let how = if config_source == ConfigSource::Env {
            "OPV_CONFIG is set; unset it for init"
        } else {
            "--config is not used"
        };
        // The same init without --config (and with OPV_CONFIG unset for this one command).
        let mut again = format!(
            "opv init {} --vault {} --item {}",
            shell_word(env),
            shell_word(vault),
            shell_word(item)
        );
        if let Some(t) = &target {
            again.push_str(&format!(" --target {}", shell_word(t)));
        }
        for (flag, value) in init_options {
            again.push_str(&format!(" --{flag} {}", shell_word(value)));
        }
        if let Some(p) = &profile {
            again.push_str(&format!(" --profile {p}"));
        }
        if *force {
            again.push_str(" --force");
        }
        if config_source == ConfigSource::Env {
            again = format!("env -u OPV_CONFIG {again}");
        }
        return Err(Error::Config(
            format!(
                "init writes secrets.toml in the current directory; {how} (to add an \
                 environment to that file, pass --add-env)"
            )
            .into(),
        )
        .with_next(again));
    }
    let dir = std::env::current_dir()
        .map_err(|e| Error::Config(format!("cannot read the current directory: {e}").into()))?;
    init::run(&init_args(cli.cmd, init_options)?, &dir, r, out)
}

/// `add` and `init --add-env`: edit the configuration file at `path` in place.
fn run_edit(
    cmd: Cmd,
    path: &std::path::Path,
    init_options: &std::collections::BTreeMap<String, String>,
    r: &ProcessRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    match cmd {
        Cmd::Add {
            name,
            kind,
            env,
            rule,
            guidance,
            immutable,
        } => add::run(
            &add::AddArgs {
                name,
                kind,
                envs: env,
                rules: rule,
                guidance,
                immutable,
            },
            path,
            out,
        ),
        cmd @ Cmd::Init { .. } => init::add_env(&init_args(cmd, init_options)?, path, r, out),
        _ => unreachable!("called for add and init --add-env only"),
    }
}

fn init_args(
    cmd: Cmd,
    init_options: &std::collections::BTreeMap<String, String>,
) -> Result<init::InitArgs, Error> {
    let Cmd::Init {
        env,
        vault,
        item,
        target,
        add_env: _,
        profile,
        force,
    } = cmd
    else {
        unreachable!("called for init only")
    };
    Ok(init::InitArgs {
        env,
        vault,
        item,
        target,
        fields: init_options.clone(),
        profile: profile.as_deref().map(init::parse_profile).transpose()?,
        force,
    })
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

    /// FR-40: `session` was renamed to `login` with no alias; it is a usage error (exit 2).
    #[test]
    fn session_is_no_longer_a_command() {
        let e = Cli::try_parse_from(["opv", "session"]).err().unwrap();
        assert_eq!(e.exit_code(), 2);
    }

    #[test]
    fn login_takes_an_environment_and_a_command_after_dashes() {
        let cli =
            Cli::try_parse_from(["opv", "login", "prod", "--", "opv", "check", "prod"]).unwrap();
        let Cmd::Login { env, command } = cli.cmd else {
            panic!("not login")
        };
        assert_eq!(
            (env.as_deref(), command),
            (
                Some("prod"),
                vec!["opv".into(), "check".into(), "prod".into()]
            )
        );
    }

    #[test]
    fn login_without_an_environment_parses() {
        let cli = Cli::try_parse_from(["opv", "login"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::Login { env: None, .. }));
    }

    #[test]
    fn json_output_is_never_painted() {
        let cli = Cli::try_parse_from(["opv", "status", "prod", "--json"]).unwrap();
        assert!(!cli.cmd.has_state_words());
    }

    /// Every leaf subcommand's (name, long help, short help), as `opv <cmd> --help` / `-h`
    /// print them.
    fn leaf_helps() -> Vec<(String, String, String)> {
        fn walk(cmd: &mut clap::Command, prefix: &str, out: &mut Vec<(String, String, String)>) {
            for sub in cmd.get_subcommands_mut().filter(|s| s.get_name() != "help") {
                let name = format!("{prefix}{}", sub.get_name());
                if sub.has_subcommands() {
                    walk(sub, &format!("{name} "), out);
                } else {
                    let long = sub.render_long_help().to_string();
                    let short = sub.render_help().to_string();
                    out.push((name, long, short));
                }
            }
        }
        let mut out = Vec::new();
        walk(&mut cli_command(), "", &mut out);
        out
    }

    /// H9: `--help` fits on one screen (the pass-1 sync help was 68 lines).
    #[test]
    fn subcommand_long_help_is_at_most_50_lines() {
        for (name, long, _) in leaf_helps() {
            assert!(long.lines().count() <= 50, "{name}: {long}");
        }
    }

    /// H9: `-h` is shorter still.
    #[test]
    fn subcommand_short_help_is_at_most_35_lines() {
        for (name, _, short) in leaf_helps() {
            assert!(short.lines().count() <= 35, "{name}: {short}");
        }
    }

    /// H9: two or three examples come before the options.
    #[test]
    fn subcommand_help_shows_examples_before_the_options() {
        for (name, long, _) in leaf_helps() {
            let examples = long.find("Examples:\n  opv ");
            let options = long.find("Options:");
            assert!(examples.is_some() && examples < options, "{name}: {long}");
        }
    }

    /// H9: the global options are one line in subcommand help, not 25.
    #[test]
    fn subcommand_help_ends_with_the_global_options_line() {
        for (name, long, _) in leaf_helps() {
            assert!(long.trim_end().ends_with(GLOBAL_LINE), "{name}: {long}");
        }
    }

    /// H9: the root help still documents the global options in full.
    #[test]
    fn root_help_documents_the_global_options() {
        let long = cli_command().render_long_help().to_string();
        assert!(long.contains("[env: OPV_CONFIG"), "{long}");
    }

    /// S3: an example never runs a write after `||` or `&&` (an agent copying it would write
    /// on an auth or unknown failure).
    #[test]
    fn no_help_example_chains_a_writing_command() {
        let writes = ["item skeleton", "sync", "init", "setup"];
        let mut texts = vec![cli_command().render_long_help().to_string()];
        texts.extend(leaf_helps().into_iter().map(|(_, long, _)| long));
        for t in &texts {
            for line in t.lines() {
                let chained = line
                    .split("||")
                    .skip(1)
                    .chain(line.split("&&").skip(1))
                    .any(|after| writes.iter().any(|w| after.contains(w)));
                assert!(!chained, "{line}");
            }
        }
    }

    /// H10: a configuration error after `sync` is re-checked with `plan`, never by writing.
    #[test]
    fn config_error_next_for_sync_is_plan() {
        let cli =
            Cli::try_parse_from(["opv", "sync", "prod", "--deploy", "--product", "api"]).unwrap();
        assert_eq!(
            recheck_command(&cli.cmd, None),
            "opv plan prod --product api"
        );
    }

    /// H10: the re-check keeps an explicit --config path.
    #[test]
    fn config_error_next_keeps_the_config_flag() {
        let cli = Cli::try_parse_from(["opv", "status", "prod"]).unwrap();
        assert_eq!(
            recheck_command(&cli.cmd, Some(std::path::Path::new("ops/secrets.toml"))),
            "opv --config ops/secrets.toml status prod"
        );
    }

    /// A10: the agent guide is a command.
    #[test]
    fn guide_agent_parses() {
        assert!(Cli::try_parse_from(["opv", "guide", "agent"]).is_ok());
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
