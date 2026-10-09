use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::parser::ValueSource;
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use opv::Error;
use opv::app::{
    STATES_HELP, add, config_cmd, config_export, doctor, explain, init, open, run as run_cmd,
    signin, skeleton, status, sync,
};
use opv::config;
use opv::config_store;
use opv::runner::{Budget, CommandRunner, ProcessRunner};

mod colour;
mod completions;

const QUICK_START: &str = "\
Start here:
  opv setup                        Guided setup for a new project
  opv init dev --vault V --item I  Use a 1Password item you already set up
  opv login dev                    Sign in to 1Password for an environment
  opv doctor                       Find a setup problem and its next step
  opv guide agent                  Setup guide for AI assistants (this version)

Everyday use:
  opv check dev --product api      Check that your app's settings are ready
  opv run dev --product api -- npm run dev
  opv open api/KEY --env dev       Open a key's item in 1Password to fill it in
  opv add api/KEY --kind secret    Declare a new key
  opv config edit                  Change the configuration (file or 1Password)
  opv projects                     Projects whose configuration lives in 1Password

Deployment:
  opv plan staging                 Preview changes; prints a plan id
  opv sync staging --deploy --expect-plan <id>   Apply exactly that plan, then deploy

Every command is listed above. Use opv <command> --help for its options and examples,
and opv help states for what each state word means.";

const EXAMPLES: &str = "\
Examples:
  opv setup                        # guided owner setup; resumes saved progress
  opv login prod                   # signed-in terminal for prod's account; type exit to leave
  opv add api/KEY --kind secret    # declare a key, in secrets.toml or the manifest
  opv item skeleton staging        # add the missing (empty) fields to the 1Password item
  opv status staging               # one row per product and key; fill what is missing
  opv status --all                 # every project in 1Password, one line per environment
  opv plan staging                 # what a sync would write, hold and prune, and its plan id
  opv sync prod --expect-plan ID   # exactly the plan reviewed (add --deploy to deploy)
  opv config edit                  # change the configuration; refuses a concurrent edit
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
  OPV_PROJECT  project whose manifest in 1Password to use (title opv · <name>)
  OP_ACCOUNT   1Password account to find a manifest in (an environment's own
               `account` setting is used for its reads)
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
Changes nothing. Problems come first, each with its reason and a link to its item in
1Password. Exits 8 when any key is missing, of the wrong kind or failing a rule; opv explain
<product>/<KEY> --env <ENV> shows how to fix one. Without <ENV>, one line per environment,
run-only ones included.

More examples:
  opv status prod --product api   # one product's rows and findings
  opv status --all                # every project whose configuration lives in 1Password";

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
sync, and ends with the exact sync command to run once it is clean. A clean plan prints its
plan id: opv sync <ENV> --expect-plan <id> applies exactly that plan or refuses (exit 6).";

const SYNC_QUICK: &str = "\
Examples:
  opv plan staging                       # preview first; changes nothing
  opv sync staging --deploy              # write, then deploy only if something changed
  opv sync prod --deploy --confirm prod  # an environment with confirm_env = true";

const SYNC_MORE: &str = "\
Refuses (exit 6) and stages nothing when a key is missing, of the wrong kind or failing a
rule, naming a missing --confirm too. Nothing is deployed or removed without --deploy/--prune.

More examples:
  opv sync prod --deploy --expect-plan 674d43e2  # exactly the plan opv plan showed
  opv sync staging --deploy --prune      # also remove managed names no longer declared
  opv sync prod --rotate api/SIGNING_KEY # replace an immutable key that is already set";

const EXPORT_QUICK: &str = "\
Examples:
  opv config export                # the configuration as TOML (file or manifest)
  opv config export --json         # the configuration as JSON
  opv config export staging --json # staging's config-kind values (reads 1Password)";

const EXPORT_MORE: &str = "\
Without <ENV>, prints the configuration itself: IDs, names, kinds and rules, never a value.
With <ENV>, prints the values of config-kind keys by design, never secrets; refuses (exit 6)
when a config key is stored concealed or a secret key as text.";

const IMPORT_QUICK: &str = "\
Examples:
  opv config import --vault myapp-dev              # secrets.toml found from here
  opv config import --file infra/secrets.toml --vault shared --project api --path apps/api";

const IMPORT_MORE: &str = "\
Validates the file, then saves it as the manifest \"opv · <project>\" in the vault, tagged
with this repository's git remote (and --path directories in a monorepo). Never deletes the
file; Next: says how to check and remove it. An AI assistant asks the user first.";

const EDIT_QUICK: &str = "\
Examples:
  opv config edit                  # the configuration in $VISUAL or $EDITOR
  EDITOR=nano opv config edit";

const EDIT_MORE: &str = "\
Works on a manifest and on a file. Edits a private temporary copy, validates it, shows the
diff and asks once; saves only if nobody changed it meanwhile (else re-opens on the new
version). Needs your own interactive terminal.";

const CONFIG_CHECK_QUICK: &str = "\
Examples:
  opv config check --file secrets.toml   # exit 8 with a diff when the copy differs";

const CONFIG_CHECK_MORE: &str = "\
Compares a committed copy with the project's manifest (for review in CI). Changes nothing.";

const PROJECTS_QUICK: &str = "\
Examples:
  opv projects                 # name, vault, repo and paths
  opv projects --long          # also environment names (one read per project)
  opv projects --json          # the same, for scripts";

const PROJECTS_MORE: &str = "\
One metadata listing per signed-in 1Password account; names only, never a value. Changes
nothing. opv status --all checks every project's environments.";

const SKELETON_QUICK: &str = "\
Examples:
  opv item skeleton staging        # add the missing declared fields, empty";

const SKELETON_MORE: &str = "\
Adds missing fields, empty, and never fills or changes one. A signed-in person's other runs
tidy the item the same way; this is the explicit form. Needs an identity that may edit
the item; an AI assistant asks the user first.";

const ADD_QUICK: &str = "\
Examples:
  opv add api/STRIPE_KEY --kind secret --env dev,prod --rule prefix=sk_
  opv add LOG_LEVEL --kind config --rule enum=debug,info,warn   # simple profile
  opv add api/STRIPE_KEY --env staging          # include a declared key in staging";

const ADD_MORE: &str = "\
Edits the configuration where it lives (secrets.toml, or the project's manifest in
1Password) with comments and order kept, and validates it like a hand-written one first: a
name colliding on a target or a bad rule is refused and nothing is written. Never reads an
item or a target. Then opv item skeleton <env> adds the empty field to fill in 1Password.

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

const COMPLETIONS_QUICK: &str = "\
Examples:
  opv completions bash > ~/.local/share/bash-completion/completions/opv
  opv completions fish > ~/.config/fish/completions/opv.fish";

const OPEN_QUICK: &str = "\
Examples:
  opv open api/DATABASE_URL --env prod   # open prod's item where DATABASE_URL is typed
  opv open DATABASE_URL                  # the one product and environment declaring it
  opv open api/DATABASE_URL --print      # print the link only (SSH, CI or agents)";

const OPEN_MORE: &str = "\
Prints the key's section and field and the item's private link, then opens the link with
the desktop's opener. Over SSH, under CI, without a display or with --print it only prints
the link. Never reads a value.";

const SCHEMA_QUICK: &str = "\
Examples:
  opv schema                       # the whole description
  opv schema | jq '.error_codes[].code'";

const SCHEMA_MORE: &str = "\
Generated from the installed binary, so it matches the version you run: commands, flags,
exit codes, error codes and JSON documents. Agents read it instead of scraping --help.";

const HELP_QUICK: &str = "\
Examples:
  opv help states                  # what each state word means
  opv help sync                    # the same as opv sync --help";

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
    after_long_help = EXAMPLES,
    disable_help_subcommand = true
)]
struct Cli {
    /// Path to secrets.toml.
    ///
    /// Without this option (or OPV_CONFIG), the configuration is found in this order:
    /// OPV_PROJECT (a manifest in 1Password), `secrets.toml` in the current directory or a
    /// parent, a `.opv` file naming the project, then the manifest tagged with this
    /// checkout's git remote. What is used is printed on stderr as `using ...` unless given
    /// with --config.
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
        #[arg(long)]
        product: Option<String>,
        /// Print one machine-readable JSON document instead of the table (without <ENV>,
        /// one entry per environment; with --all, per project).
        #[arg(long)]
        json: bool,
        /// One line per environment for every project manifest visible in 1Password. Costs
        /// one manifest read per project plus one item read per environment (reads are
        /// retried); a project that cannot be read is one line with its reason.
        #[arg(long, conflicts_with = "env")]
        all: bool,
    },
    /// List the projects whose configuration lives in 1Password (names only).
    ///
    /// One metadata listing per signed-in account shows each manifest's vault, repos and
    /// paths; --long also reads each manifest once for its environment names.
    #[command(before_help = PROJECTS_QUICK, after_help = PROJECTS_MORE)]
    Projects {
        /// Read each manifest for its environment names.
        #[arg(long)]
        long: bool,
        /// Print one JSON document instead of lines.
        #[arg(long)]
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
        /// Print the explanation as one JSON document.
        #[arg(long)]
        json: bool,
    },
    /// Open a key's item in 1Password, the place its value is typed; never reads a value.
    #[command(before_help = OPEN_QUICK, after_help = OPEN_MORE)]
    Open {
        /// The key, resolved as `opv explain` resolves it. [env: OPV_PRODUCT]
        #[arg(value_name = "[PRODUCT/]KEY")]
        target: String,
        /// Environment name; may be omitted when only one environment is declared.
        #[arg(long)]
        env: Option<String>,
        /// Print the link only; do not start a browser or the 1Password app.
        #[arg(long)]
        print: bool,
        /// Print the key's section, field and link as one JSON document; opens nothing.
        #[arg(long)]
        json: bool,
    },
    /// Print help for a command, or a topic: `opv help states` defines every state word.
    #[command(before_help = HELP_QUICK)]
    Help {
        /// `states`, or a command name (for example `sync` or `item skeleton`).
        #[arg(value_name = "TOPIC")]
        topic: Vec<String>,
    },
    /// Generate configuration from a 1Password item you have already set up.
    #[command(before_help = INIT_QUICK)]
    Init {
        /// Environment name to declare (for example staging or prod).
        env: String,
        /// Vault title, matched exactly.
        #[arg(long)]
        vault: String,
        /// Item title in that vault, matched exactly; its field names and types are read
        /// once, never its values.
        #[arg(long)]
        item: String,
        /// Deployment target of the environment; its options follow (--<target>-<field>).
        /// Inferred from those options when omitted; omit both for a run-only environment
        /// used for local development. Nothing is looked up.
        #[arg(long, value_name = "PROVIDER")]
        target: Option<String>,
        /// Add this environment to the existing configuration (a secrets.toml or the
        /// project's manifest, found like other commands) instead of writing a new one;
        /// comments are kept, and every declared key the item has includes the environment.
        #[arg(long, conflicts_with_all = ["force", "profile"])]
        add_env: bool,
        /// Profile to write, simple or fleet; without it, it follows the item's shape.
        #[arg(long, value_parser = ["simple", "fleet"], hide_possible_values = true)]
        profile: Option<String>,
        /// Overwrite an existing secrets.toml.
        #[arg(long)]
        force: bool,
        /// Print what was written (names and kinds) as one JSON document.
        #[arg(long)]
        json: bool,
        /// Write ./secrets.toml even for a new project (without it, a new project's
        /// configuration is saved as a manifest in the item's vault).
        #[arg(long)]
        file: bool,
        /// Project name of a new manifest; defaults to the repository's name.
        #[arg(long, conflicts_with = "file")]
        project: Option<String>,
    },
    /// Declare a key in the configuration, or add environments to a declared key.
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
        /// Print what was written (the key, its kind and environments) as one JSON document.
        #[arg(long)]
        json: bool,
    },
    /// Print a shell completion script for commands and options.
    #[command(before_help = COMPLETIONS_QUICK, after_help = completions::INSTALL)]
    Completions {
        /// Shell to write the script for.
        #[arg(value_enum)]
        shell: completions::Shell,
    },
    /// Describe this opv as JSON: commands, flags, exit codes, error codes, documents.
    #[command(before_help = SCHEMA_QUICK, after_help = SCHEMA_MORE)]
    Schema,
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
    /// Apply only the plan `opv plan` showed with this id; refused (exit 6) if anything
    /// changed since. Also satisfies confirm_env.
    #[arg(long, value_name = "PLAN_ID")]
    expect_plan: Option<String>,
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
            expect_plan: a.expect_plan,
        }
    }
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Print the configuration (no secrets), or with <ENV> its config-kind values as JSON.
    #[command(before_help = EXPORT_QUICK, after_help = EXPORT_MORE)]
    Export {
        /// Environment whose config-kind (non-secret) values are printed as JSON; without
        /// it, the configuration itself is printed.
        env: Option<String>,
        /// Output JSON.
        #[arg(long, conflicts_with = "toml")]
        json: bool,
        /// Output the configuration as TOML (the default without <ENV>).
        #[arg(long, conflicts_with = "env")]
        toml: bool,
    },
    /// Save a secrets.toml as this project's manifest in 1Password (never deletes the file).
    #[command(before_help = IMPORT_QUICK, after_help = IMPORT_MORE)]
    Import {
        /// The file to import; defaults to the secrets.toml found from here.
        #[arg(long, value_name = "PATH")]
        file: Option<PathBuf>,
        /// Vault to create the manifest in (title or ID).
        #[arg(long)]
        vault: String,
        /// Project name; defaults to the repository's name.
        #[arg(long)]
        project: Option<String>,
        /// Monorepo directory this project covers, relative to the repository root
        /// (repeatable).
        #[arg(long = "path", value_name = "DIR")]
        paths: Vec<String>,
    },
    /// Edit the configuration in $VISUAL/$EDITOR, validate, show the diff and save once
    /// confirmed; refuses (and re-opens) when someone changed it meanwhile.
    #[command(before_help = EDIT_QUICK, after_help = EDIT_MORE)]
    Edit,
    /// Compare a committed copy with the project's manifest; exit 8 with a diff when they
    /// differ (for review in CI).
    #[command(before_help = CONFIG_CHECK_QUICK, after_help = CONFIG_CHECK_MORE)]
    Check {
        /// The committed copy.
        #[arg(long, value_name = "PATH")]
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum ItemCmd {
    /// Add every missing declared field to the item, empty (a signed-in person's runs do this too).
    #[command(before_help = SKELETON_QUICK, after_help = SKELETON_MORE)]
    Skeleton {
        /// Environment name from the configuration (for example staging or prod).
        env: String,
        /// Print the fields added as one JSON document.
        #[arg(long)]
        json: bool,
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
            a.hide_possible_values(true)
                .value_parser(clap::builder::PossibleValuesParser::new(
                    registry::PROVIDERS
                        .iter()
                        .filter(|p| !p.init_fields().is_empty())
                        .map(|p| p.section()),
                ))
        });
        // One line per provider in the help (H9: --help fits on one screen); each option is
        // a hidden argument, so clap still parses and completes it.
        let mut summary = String::from("Target options (* required with that --target):");
        for p in registry::PROVIDERS
            .iter()
            .filter(|p| !p.init_fields().is_empty())
        {
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
        c = match c.get_after_help().map(|a| a.to_string()) {
            Some(more) => c.after_help(format!("{summary}\n\n{more}")),
            None => c.after_help(summary),
        };
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
    let help = help_command();
    let json = cli.cmd.json_mode();
    opv::runner::signals::set_rerun(&rerun);
    opv::runner::signals::set_json(json.is_some());
    let mut stdout = PipeSafe {
        inner: io::stdout().lock(),
        closed: false,
    };
    // `--json`: the command's document is buffered and framed once the result is known
    // (A1), so stdout carries exactly one document whatever happens.
    let mut body: Vec<u8> = Vec::new();
    let paint = colour::enabled(
        cli.color,
        io::IsTerminal::is_terminal(&io::stdout()),
        std::env::var_os("NO_COLOR"),
    ) && cli.cmd.has_state_words();
    let res = if json.is_some() {
        run(cli, config_source, &init_options, &mut body)
    } else if paint {
        let mut painter = colour::Painter::new(&mut stdout);
        let res = run(cli, config_source, &init_options, &mut painter);
        let _ = painter.flush();
        res
    } else {
        run(cli, config_source, &init_options, &mut stdout)
    };
    let step = res.as_ref().err().map(|e| e.step(&rerun, &help));
    if let Some(raw) = json {
        let framed = match (&res, &step) {
            (Err(e), Some(step)) => opv::json::finish(&body, Err((e, step)), raw),
            _ => opv::json::finish(&body, Ok(()), raw),
        };
        let _ = stdout.write_all(&framed);
    }
    let _ = stdout.flush();
    match res {
        // `run` reports the child's exit code verbatim (FR-4); everything else yields 0.
        Ok(0) => ExitCode::SUCCESS,
        Ok(code) => ExitCode::from(exit_byte(code)),
        Err(e) => {
            // Error messages never contain secret values (SR-1). The failed call's stderr
            // follows the error's first line only as a scrubbed excerpt of at most 5 lines
            // (NR-31); `Do:` (when a person must act) and the runnable `Next:` line are
            // always last (NR-19, A3). Under `--json` the same text still goes to stderr.
            let excerpt = opv::runner::take_failure_excerpt();
            let step = step.unwrap_or_else(|| e.step(&rerun, &help));
            let _ = write!(
                io::stderr(),
                "{}",
                opv::error::report_with(&e, &step, excerpt.as_ref())
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
    let help = help_command();
    let _ = write!(io::stderr(), "{}", opv::error::next_line(&help));
    // `--json` asked for one document on stdout even when the command line is wrong (A1).
    if std::env::args().skip(1).any(|a| a == "--json") {
        let text = e.render().to_string();
        let message = text
            .lines()
            .next()
            .unwrap_or_default()
            .trim_start_matches("error: ")
            .to_string();
        let code = opv::error::Code::Usage;
        let step = opv::error::Step {
            action: None,
            next: help,
        };
        let doc = serde_json::json!({
            "schema_version": opv::json::SCHEMA_VERSION,
            "ok": false,
            "exit_code": e.exit_code(),
            "next": step.next,
            "do": null,
            "error": opv::error::error_object(
                code.as_str(),
                "usage",
                &message,
                Vec::new(),
                code.retry(),
                code.human_required(),
                &step,
            ),
        });
        let _ = writeln!(io::stdout(), "{doc}");
    }
    ExitCode::from(exit_byte(e.exit_code()))
}

/// `opv <command> --help` for the subcommand on the command line, else `opv --help`.
fn help_command() -> String {
    let cmd = cli_command();
    let sub = std::env::args()
        .skip(1)
        .find(|a| cmd.get_subcommands().any(|s| s.get_name() == a));
    match sub {
        Some(s) => format!("opv {s} --help"),
        None => "opv --help".to_string(),
    }
}

/// The command line as typed, for "run it again" next steps. Arguments are names, flags
/// and paths, never values (SR-3); `run` and `login` carry the user's own command, which
/// is never repeated: for `run` the step is the `check` of the same keys, for `login` a
/// plain `opv login` for the same environment.
fn rerun_command(cmd: &Cmd) -> String {
    match cmd {
        Cmd::Run { env, product, .. } => {
            let mut c = format!("opv check {}", shell_word(env));
            if let Some(p) = product {
                c.push_str(&format!(" --product {}", shell_word(p)));
            }
            return c;
        }
        Cmd::Login { env, .. } => {
            return match env {
                Some(e) => format!("opv login {}", shell_word(e)),
                None => "opv login".to_string(),
            };
        }
        _ => {}
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
        Cmd::Explain { target, env, .. } => match env {
            Some(e) => format!("explain {} --env {}", shell_word(target), shell_word(e)),
            None => format!("explain {}", shell_word(target)),
        },
        Cmd::Item(ItemCmd::Skeleton { env, .. })
        | Cmd::Config(ConfigCmd::Export { env: Some(env), .. }) => {
            format!("doctor --env {}", shell_word(env))
        }
        _ => "status".to_string(),
    };
    format!("{c} {tail}")
}

use opv::error::shell_word;

impl Cmd {
    /// The environment the command acts on, and whether it reaches the deployment target
    /// (and so signs in with the environment's deploy credentials, FR-40).
    fn env(&self) -> Option<(&str, signin::Reach)> {
        use signin::Reach;
        match self {
            Cmd::Check { env, .. }
            | Cmd::Run { env, .. }
            | Cmd::Config(ConfigCmd::Export { env: Some(env), .. })
            | Cmd::Item(ItemCmd::Skeleton { env, .. }) => Some((env, Reach::Store)),
            Cmd::Status { env: Some(env), .. } => Some((env, Reach::Target)),
            Cmd::Plan(a) => Some((&a.env, Reach::Target)),
            Cmd::Sync(a) => Some((&a.env, Reach::Target)),
            Cmd::Doctor { env: Some(env), .. } => Some((env, Reach::Target)),
            _ => None,
        }
    }

    /// `Some(raw)` when stdout is one JSON document (A1): `--json`, or a command that only
    /// prints JSON. `raw` keeps a successful document unframed (`config export`).
    fn json_mode(&self) -> Option<bool> {
        let json = match self {
            Cmd::Doctor { json, .. }
            | Cmd::Check { json, .. }
            | Cmd::Status { json, .. }
            | Cmd::Projects { json, .. }
            | Cmd::Explain { json, .. }
            | Cmd::Open { json, .. }
            | Cmd::Init { json, .. }
            | Cmd::Add { json, .. }
            | Cmd::Item(ItemCmd::Skeleton { json, .. }) => *json,
            Cmd::Plan(a) => a.json,
            Cmd::Sync(a) => a.json,
            Cmd::Schema => true,
            // With <ENV> (config-kind values) or --json (the configuration) the document is
            // printed as is; without either, the configuration is TOML text.
            Cmd::Config(ConfigCmd::Export { env, json, .. }) => {
                return (env.is_some() || *json).then_some(true);
            }
            _ => false,
        };
        json.then_some(false)
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
        | Cmd::Status { product, .. } => {
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
        Cmd::Explain { target, .. } | Cmd::Open { target, .. } if !target.contains('/') => {
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
    if let Cmd::Schema = &cli.cmd {
        let doc = opv::schema::describe(&cli_command(), env!("CARGO_PKG_VERSION"));
        writeln!(out, "{doc}")
            .map_err(|e| Error::Dependency(format!("cannot write output ({})", e.kind()).into()))?;
        return Ok(0);
    }
    if let Cmd::Help { topic } = &cli.cmd {
        return help(topic, out).map(|()| 0);
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
        let fleet = match find_config(cli.config.as_ref(), config_source).transpose()? {
            Some(f) => Some(f),
            None => manifest_for_login(&cli, config_source),
        };
        let start = std::env::current_dir().unwrap_or_default();
        let fallback = config_store::pointer_account(&start);
        return login::run_or(
            fleet.as_ref(),
            fallback.as_deref(),
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
    match &cli.cmd {
        Cmd::Projects { long, json } => {
            return config_cmd::projects(&r, *long, *json, out).map(|()| 0);
        }
        Cmd::Status {
            all: true, json, ..
        } => return config_cmd::status_all(&r, *json, out).map(|()| 0),
        Cmd::Config(ConfigCmd::Import { .. }) | Cmd::Config(ConfigCmd::Check { .. }) => {
            return run_config_manifest(cli, &r, out).map(|()| 0);
        }
        _ => {}
    }
    // A missing config is a configuration error for the command, not an early exit, so
    // `doctor` still runs its other checks on a fresh machine.
    let found = request(&cli, config_source, false).and_then(|req| config_store::locate(&req, &r));
    if let Ok(f) = &found
        && let Some(line) = f.announce()
    {
        let _ = writeln!(io::stderr(), "{line}");
    }
    let source = found.as_ref().ok().map(|f| f.store().describe());
    if let (Cmd::Config(ConfigCmd::Edit), Ok(f)) = (&cli.cmd, &found) {
        use opv::app::setup_runtime;
        setup_runtime::Console::require_terminal("config edit")?;
        return config_cmd::edit(f, &r, &mut config_cmd::TerminalUi, out).map(|()| 0);
    }
    if let (
        Cmd::Config(ConfigCmd::Export {
            env: None, json, ..
        }),
        Ok(f),
    ) = (&cli.cmd, &found)
    {
        let format = if *json {
            config_cmd::Format::Json
        } else {
            config_cmd::Format::Toml
        };
        return config_cmd::export(f, format, &r, out).map(|()| 0);
    }
    // `add` and `init --add-env` edit the configuration where it lives, file or manifest
    // (FR-44), with the same validation and concurrency refusal.
    if let Cmd::Init { add_env: true, .. } | Cmd::Add { .. } = &cli.cmd {
        return run_edit(cli.cmd, &found?, init_options, &r, out).map(|()| 0);
    }
    let manifest = matches!(found, Ok(config_store::Found::Manifest(_)));
    let loaded = found.and_then(|f| f.load(&r));
    let mut cmd = cli.cmd;
    // A file that does not load: re-check it with a read-only command (H10). A manifest
    // has no file to fix in place: `opv config edit` opens it (FR-44).
    let loaded = match loaded {
        Err(e @ Error::Config(_)) if manifest => Err(e.or_next(|| "opv config edit".into())),
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
    run_other(cmd, loaded, source.as_deref(), runner, deploy_failure, out).map(|()| 0)
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

/// `opv login` in a project whose configuration lives in 1Password (FR-44): the manifest,
/// when op can already read it (an unlocked desktop app or a live session), so the
/// environment's own `account` is used; else `None` and login falls back to the `.opv`
/// account or op's default. Quiet: a failure here is not the command's error.
fn manifest_for_login(cli: &Cli, config_source: ConfigSource) -> Option<opv::domain::Fleet> {
    let r = ProcessRunner::new(
        Budget::starting_now(std::time::Duration::from_secs(cli.timeout.min(30))),
        false,
    );
    let fleet = request(cli, config_source, false)
        .and_then(|req| config_store::locate(&req, &r))
        .and_then(|f| f.load(&r))
        .ok();
    let _ = opv::runner::take_failure_excerpt();
    fleet
}

/// The discovery request from the command line and the environment (FR-25, FR-44).
fn request(
    cli: &Cli,
    config_source: ConfigSource,
    manifest_only: bool,
) -> Result<config_store::Request, Error> {
    let start = std::env::current_dir()
        .map_err(|e| Error::Config(format!("cannot read the current directory: {e}").into()))?;
    let given = match config_source {
        ConfigSource::Env => config_store::Given::Env,
        _ => config_store::Given::Flag,
    };
    Ok(config_store::Request {
        start,
        config: cli.config.clone().map(|p| (p, given)),
        project: config_store::project_env(),
        manifest_only,
        account: config_store::account_env(),
    })
}

/// `config import` and `config check`: they compare a file with the manifest, so the
/// manifest is found without the `secrets.toml` walk-up (and without --config).
fn run_config_manifest(cli: Cli, r: &ProcessRunner, out: &mut dyn Write) -> Result<(), Error> {
    let dir = std::env::current_dir()
        .map_err(|e| Error::Config(format!("cannot read the current directory: {e}").into()))?;
    match cli.cmd {
        Cmd::Config(ConfigCmd::Import {
            file,
            vault,
            project,
            paths,
        }) => {
            let file = match file {
                Some(f) => f,
                None => config::discover(&dir).ok_or_else(|| {
                    Error::Config(
                        format!(
                            "no secrets.toml found in {} or any parent directory",
                            dir.display()
                        )
                        .into(),
                    )
                    .with_next("opv config import --file <path> --vault <vault>")
                })?,
            };
            let args = config_cmd::ImportArgs {
                file,
                vault,
                project,
                paths,
            };
            config_cmd::import(&args, &dir, r, out)
        }
        Cmd::Config(ConfigCmd::Check { file }) => {
            let req = config_store::Request {
                start: dir,
                config: None,
                project: config_store::project_env(),
                manifest_only: true,
                account: config_store::account_env(),
            };
            let found = config_store::locate(&req, r)?;
            config_cmd::check(&found, &file, r, out)
        }
        _ => unreachable!("called for config import and check only"),
    }
}

fn run_other(
    cmd: Cmd,
    loaded: Result<opv::domain::Fleet, Error>,
    source: Option<&str>,
    r: &dyn CommandRunner,
    deploy_failure: Option<opv::app::signin::DeployFailure>,
    out: &mut dyn Write,
) -> Result<(), Error> {
    match cmd {
        Cmd::Setup { .. } => unreachable!("handled before configuration discovery"),
        Cmd::Login { .. } => unreachable!("handled before configuration discovery"),
        Cmd::Run { .. } => unreachable!("handled by run"),
        Cmd::Init { .. } => unreachable!("handled by run_init"),
        Cmd::Add { .. } => unreachable!("handled by run_edit"),
        Cmd::Completions { .. }
        | Cmd::Guide { .. }
        | Cmd::Projects { .. }
        | Cmd::Schema
        | Cmd::Help { .. } => {
            unreachable!("handled by run")
        }
        Cmd::Doctor { env, product, json } => {
            let scope = doctor::Request {
                env: env.as_deref(),
                product: product.as_deref(),
                json,
                source,
                deploy_failure,
            };
            doctor::run_request(loaded, scope, r, out)
        }
        Cmd::Check { env, product, json } => {
            opv::app::local::check(&loaded?, &env, product.as_deref(), r, out, json)
        }
        Cmd::Status {
            env: None,
            product,
            json,
            ..
        } => status::overview(&loaded?, product.as_deref(), r, out, json),
        Cmd::Status {
            env: Some(env),
            product,
            json,
            ..
        } => status::run_scoped(&loaded?, &env, product.as_deref(), r, out, json),
        Cmd::Plan(a) => sync::plan_scoped(&loaded?, &a.env, a.product.as_deref(), r, out, a.json),
        Cmd::Sync(a) => {
            let env = a.env.clone();
            sync::run(&loaded?, &env, r, out, &a.into())
        }
        Cmd::Config(ConfigCmd::Export { env: Some(env), .. }) => {
            config_export::run(&loaded?, &env, r, out)
        }
        // Reached only when discovery failed: its error is the result.
        Cmd::Config(_) => loaded.map(|_| ()),
        Cmd::Item(ItemCmd::Skeleton { env, json }) => {
            skeleton::run_as(&loaded?, &env, r, out, json)
        }
        Cmd::Explain { target, env, json } => {
            explain::run_as(&loaded?, &target, env.as_deref(), out, json)
        }
        Cmd::Open {
            target,
            env,
            print,
            json,
        } => {
            // `--json` prints the link and never opens anything.
            let opener = if print || json {
                None
            } else {
                open::opener(&opv::host::ProcessEnv)
            };
            open::run_as(&loaded?, &target, env.as_deref(), opener, r, out, json)
        }
    }
}

/// `opv help [TOPIC...]`: `states` prints the state vocabulary (H5); a command path prints
/// that command's full help; nothing prints the top-level help.
fn help(topic: &[String], out: &mut dyn Write) -> Result<(), Error> {
    let write = |out: &mut dyn Write, text: &str| {
        writeln!(out, "{}", text.trim_end())
            .map_err(|e| Error::Dependency(format!("cannot write output ({})", e.kind()).into()))
    };
    if topic.len() == 1 && topic[0] == "states" {
        return write(out, STATES_HELP);
    }
    let mut cmd = cli_command();
    // Built first, so a subcommand's usage line reads `opv <command>`.
    cmd.build();
    let mut current = &mut cmd;
    for t in topic {
        let names: Vec<String> = current
            .get_subcommands()
            .map(|c| c.get_name().to_string())
            .collect();
        match current.find_subcommand_mut(t) {
            Some(sub) => current = sub,
            None => {
                return Err(Error::Config(
                    format!("no help topic {t:?}; topics: states, {}", names.join(", ")).into(),
                )
                .with_next("opv --help"));
            }
        }
    }
    let text = current.render_long_help().to_string();
    write(out, &text)
}

/// `init` writes `./secrets.toml`; it reads no configuration, so it runs before discovery.
fn run_init(
    cli: Cli,
    config_source: ConfigSource,
    init_options: &std::collections::BTreeMap<String, String>,
    r: &ProcessRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let json = matches!(cli.cmd, Cmd::Init { json: true, .. });
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
        if json {
            again.push_str(" --json");
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
        .with_code(opv::error::Code::Usage)
        .with_next(again));
    }
    let dir = std::env::current_dir()
        .map_err(|e| Error::Config(format!("cannot read the current directory: {e}").into()))?;
    let (file, project) = match &cli.cmd {
        Cmd::Init { file, project, .. } => (*file, project.clone()),
        _ => unreachable!("called for init only"),
    };
    let args = init_args(cli.cmd, init_options)?;
    // A project that already has a secrets.toml keeps it; a new one gets a manifest
    // unless --file asks for the file (FR-44).
    if file || config::discover(&dir).is_some() {
        init::run_as(&args, &dir, r, out, json)
    } else {
        init::run_manifest(&args, project.as_deref(), &dir, r, out, json)
    }
}

/// `add` and `init --add-env`: edit the configuration where it was found (a file or a
/// manifest) in place, through its [`config_store::ConfigStore`].
fn run_edit(
    cmd: Cmd,
    found: &config_store::Found,
    init_options: &std::collections::BTreeMap<String, String>,
    r: &ProcessRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let store = found.store();
    match cmd {
        Cmd::Add {
            name,
            kind,
            env,
            rule,
            guidance,
            immutable,
            json,
        } => add::run(
            &add::AddArgs {
                name,
                kind,
                envs: env,
                rules: rule,
                guidance,
                immutable,
                json,
            },
            store,
            r,
            out,
        ),
        cmd @ Cmd::Init { json, .. } => {
            init::add_env_as(&init_args(cmd, init_options)?, store, r, out, json)
        }
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
        file: _,
        project: _,
        json: _,
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

    /// H11: the overview takes --json and --product without an environment.
    #[test]
    fn status_overview_accepts_json_and_product() {
        assert!(Cli::try_parse_from(["opv", "status", "--json", "--product", "api"]).is_ok());
    }

    /// H5: `opv help states` prints the state vocabulary.
    #[test]
    fn help_states_prints_the_vocabulary() {
        let mut out = Vec::new();
        help(&["states".to_string()], &mut out).unwrap();
        assert!(String::from_utf8(out).unwrap().starts_with("SOURCE: "));
    }

    #[test]
    fn help_with_a_command_prints_its_help() {
        let mut out = Vec::new();
        help(&["open".to_string()], &mut out).unwrap();
        assert!(String::from_utf8(out).unwrap().contains("Usage: opv open"));
    }

    #[test]
    fn help_with_an_unknown_topic_is_a_config_error() {
        assert!(matches!(
            help(&["nope".to_string()], &mut Vec::new()),
            Err(Error::Config(_))
        ));
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

    /// A4: every runnable command is in `opv schema`, with its effect, so the description
    /// cannot drift from the clap definitions.
    #[test]
    fn schema_lists_every_command_with_an_effect() {
        fn leaves(cmd: &clap::Command, prefix: &str, out: &mut Vec<String>) {
            for sub in cmd.get_subcommands() {
                let path = format!("{prefix}{}", sub.get_name());
                if sub.has_subcommands() {
                    leaves(sub, &format!("{path} "), out);
                } else {
                    out.push(path);
                }
            }
        }
        let mut want = Vec::new();
        leaves(&cli_command(), "", &mut want);
        let doc = opv::schema::describe(&cli_command(), "test");
        let got: Vec<String> = doc["commands"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| !c["effect"].is_null())
            .map(|c| c["name"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(got, want);
    }

    /// A4: every flag effect in the schema table names a flag that exists.
    #[test]
    fn schema_flag_effects_name_existing_flags() {
        let doc = opv::schema::describe(&cli_command(), "test");
        let found = doc["commands"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|c| c["flags"].as_array().unwrap())
            .filter(|f| !f["effect"].is_null())
            .count();
        assert_eq!(found, opv::schema::FLAG_EFFECTS.len());
    }

    /// A1: every command with `--json` frames its stdout.
    #[test]
    fn every_json_flag_selects_json_mode() {
        let mut missing = Vec::new();
        for args in [
            &["opv", "doctor", "--json"][..],
            &["opv", "check", "dev", "--json"],
            &["opv", "status", "--json"],
            &["opv", "status", "prod", "--json"],
            &["opv", "plan", "prod", "--json"],
            &["opv", "sync", "prod", "--json"],
            &["opv", "explain", "KEY", "--json"],
            &[
                "opv", "init", "dev", "--vault", "v", "--item", "i", "--json",
            ],
            &["opv", "item", "skeleton", "prod", "--json"],
            &["opv", "config", "export", "prod"],
            &["opv", "schema"],
            &["opv", "projects", "--json"],
            &["opv", "status", "--all", "--json"],
            &["opv", "add", "api/KEY", "--kind", "secret", "--json"],
            &["opv", "config", "export", "--json"],
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            if cli.cmd.json_mode().is_none() {
                missing.push(args.join(" "));
            }
        }
        assert!(missing.is_empty(), "{missing:?}");
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
