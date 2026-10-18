use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::parser::ValueSource;
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use opv::Error;
use opv::app::{
    STATES_HELP, add, config_cmd, config_export, doctor, explain, init, open, run as run_cmd,
    signin, skeleton, status, sync, target_cmd, target_credentials,
};
use opv::config;
use opv::config_store;
use opv::runner::{Budget, CommandRunner, ProcessRunner};

mod colour;
mod completions;

const QUICK_START: &str = "\
Start here:
  opv setup                        Guided setup for a new project
  opv init dev                     Set up 1Password for this project (or --vault V --item I)
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

/// [`EXAMPLES`] with the registered providers and their CLIs filled in (FR-37).
fn examples() -> String {
    use opv::adapters::registry;
    EXAMPLES
        .replace("{TARGET_CLIS}", &registry::programs().join(", "))
        .replace("{TARGETS}", &registry::labels().join(", "))
}

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
  0 ok, 2 configuration or usage, 3 dependency (op or the target CLI missing:
  {TARGET_CLIS}), 4 1Password,
  5 target ({TARGETS}), 6 refused (policy),
  7 authentication, 8 findings (status, plan, check),
  9 outcome unknown (a change may or may not have been applied) or provider
  unavailable; safe to re-run,
  70 internal error (an opv bug; please report it),
  128 + signal when interrupted (130 Ctrl-C, 143 SIGTERM, 129 SIGHUP, 131 SIGQUIT);
  safe to re-run.
  `run` exits with the command's own exit code.

Environment:
  OPV_CONFIG   default for --config
  OPV_PROJECT  project whose manifest in 1Password to use (title opv · <name>)
  OP_ACCOUNT   1Password account to find a manifest in (an environment's own
               `account` setting is used for its reads)
  OPV_PRODUCT  default for --product on check, run, open, explain, status, plan and
               doctor --env (never sync, never doctor without --env)
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
to check the keys as `check` does (names only, never values). Each target of the
environment (or each --target) gets its own lines, `<target>: <check>`: its CLI, its deploy
credentials and whether its state vault is visible. Never writes anything,
whoever is signed in: an item not in opv's layout is read as it is, and doctor names
opv tidy <ENV>, the explicit repair.

More examples:
  opv doctor --env prod --product api   # one product's keys
  opv doctor --env prod --target web    # one target's checks";

const CHECK_QUICK: &str = "\
Examples:
  opv check dev --product api          # are api's keys saved and valid?
  opv check dev                        # one product: no --product needed
  opv check dev --product api --json   # names and states for scripts";

const CHECK_MORE: &str = "\
Reads the environment's item once (names, kinds and rule results, never values) and contacts
no deployment target; may tidy the 1Password layout when you're signed in (opv doctor --env
<ENV> never does). Exits 8 when a key needs fixing.";

const STATUS_QUICK: &str = "\
Examples:
  opv status                   # one line per environment
  opv status staging           # one row per key: 1Password and the target
  opv status prod --json       # the same, for scripts";

const STATUS_MORE: &str = "\
Changes nothing on your targets; may tidy the 1Password layout when you're signed in.
Problems come first, each with its reason and a link to its item in 1Password. Exits 8 when
any key is missing or failing a rule; opv explain
<product>/<KEY> --env <ENV> shows how to fix one. Without <ENV>, one line per environment,
run-only ones included.

More examples:
  opv status prod --product api   # one product's rows and findings
  opv status --all                # every project whose configuration lives in 1Password";

const RUN_QUICK: &str = "\
Examples:
  opv run dev --product api -- npm run dev    # start the app with api's settings
  opv run dev -- cargo test                   # one product: no --product needed
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
Changes nothing on your targets; may tidy the 1Password layout when you're signed in.
Exits 8 when any row (missing, failing a rule) would block a sync. A clean plan prints its
plan id and ends with opv sync <ENV> --deploy --expect-plan <id>, which applies exactly that
plan or refuses (exit 6).";

const SYNC_QUICK: &str = "\
Examples:
  opv plan staging                       # preview first; changes nothing on the target
  opv sync staging --deploy              # write, then deploy only if something changed
  opv sync prod --deploy --confirm prod  # an environment with confirm_env = true";

const SYNC_MORE: &str = "\
Refuses (exit 6), staging nothing, on a missing or failing key or a missing --confirm.
No deploy or removal without --deploy/--prune (--prune-immutable for an immutable key).
  opv sync prod --expect-plan 674d43e2  # exactly the plan opv plan showed (meets confirm_env)
  opv sync prod --rotate api/SIGNING_KEY # replace an immutable key that is already set";

const EXPORT_QUICK: &str = "\
Examples:
  opv config export                # the configuration as TOML (file or manifest)
  opv config export --json         # the configuration as JSON
  opv config export staging --json # staging's config-kind values (reads 1Password)";

const EXPORT_MORE: &str = "\
Without <ENV>, prints the configuration itself: IDs, names, kinds and rules, never a value.
With <ENV>, prints the values of config-kind keys by design, never secrets. A config key
stored in a concealed field is accepted and delivered as a plain value, but opv never prints
its value (opv status warns about it once).";

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
  opv config check --file secrets.toml   # exit 2 with a diff when the copy differs";

const CONFIG_CHECK_MORE: &str = "\
Compares a committed copy with the project's manifest (for review in CI). Changes nothing.";

const PROJECTS_QUICK: &str = "\
Examples:
  opv projects                 # name, vault, repo and paths
  opv projects --long          # also environment names (one read per project)
  opv projects --json          # the same, for scripts
  opv projects --account you@example.com   # one 1Password account only";

const PROJECTS_MORE: &str = "\
One metadata listing per 1Password account (only --account's, or OP_ACCOUNT's, which
opv login --account sets for its command); names only, never a value. Changes nothing.
An account that cannot be listed makes the inventory incomplete: the listed projects are
still shown, \"complete\" is false, and opv exits 4 with inventory_incomplete, since a
project missing from it may only be in that account. opv status --all checks every
project's environments.";

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
  opv add api/LOG_LEVEL --kind config --rule enum=debug,info,warn
  opv add api/STRIPE_KEY --env staging          # include a declared key in staging";

const ADD_MORE: &str = "\
Edits secrets.toml or the project's manifest in place (comments kept), validated like a
hand-written one; reads no item or target. Then opv item skeleton <env> adds the empty field.";

const EXPLAIN_QUICK: &str = "\
Examples:
  opv explain OPENAI_API_KEY                 # the one product that declares it
  opv explain api/OPENAI_API_KEY             # pick a product when several declare it
  opv explain api/OPENAI_API_KEY --env prod  # when several environments exist
  opv explain --target web --env prod        # a target's provider, products and identity";

const EXPLAIN_MORE: &str = "\
Prints the op:// reference, kind, source, boundary (vault and item), every delivering
named target, the deploy and CI service accounts, rules, immutable and guidance, and the
`op item get` command to inspect the item yourself. `--target` prints a target's provider
and locator, products, deploy credentials, state vault and deploy account. Makes no
1Password or target call.";

const INIT_QUICK: &str = "\
Examples:
  opv init dev --product api            # run-only; vault myapp-api-dev, item \"myapp · api · dev values\"
  opv init prod --product api           # then: opv target add prod web --fly-app myapp
  opv init dev --product api --from .env --apply   # start from an existing .env (without --apply: the plan)";

const ADOPT_QUICK: &str = "\
Examples:
  opv adopt staging --from .env.staging          # what would come in; nothing written
  opv adopt staging --from .env.staging --apply  # write the imports, verified";

const ADOPT_MORE: &str = "\
Each found name maps to a declared key (its target name, else its bare name); each key's
rules normalise both sides before comparing. A filled 1Password field is never replaced
unless named with --replace (immutable keys also need --rotate); the old value is kept in
the section \"opv · kept\". Values are never printed. --from target:<name> reads that target's Key Vault,
Kubernetes and GitHub variables; Fly and GitHub secrets cannot be read back. It never syncs,
deploys or deletes the source.";

#[cfg(feature = "ui")]
const UI_QUICK: &str = "\
Examples:
  opv ui                       # every environment x product; enter to open, s to sync, q to quit
  OPV_UI_TEXT=1 opv ui         # the same information as text (screen readers, dumb terminals)";

const HISTORY_QUICK: &str = "\
Examples:
  opv history prod             # last write per key of every target: time, plan id, opv version
  opv history prod --target web  # only that target
  opv history prod --json      # the same as one document (names and versions only)";

const TIDY_QUICK: &str = "\
Examples:
  opv tidy dev                 # put dev's 1Password item in opv's layout (one verified edit)
  opv tidy dev --json          # the same; what changed as one document (names only)";

const ACCESS_QUICK: &str = "\
Examples:
  opv access                     # every target's needs and who can read each vault
  opv access prod --target web    # one target's deploy identity and its missing grants
  opv access prod --json          # the same as one document";

const READY_QUICK: &str = "\
Examples:
  opv ready                      # every environment × product, findings, the next step
  opv ready --json --save r.json # the receipt for an assistant or a handoff";

const VERSION_QUICK: &str = "\
Examples:
  opv version                  # opv, op and each provider CLI, with versions
  opv version --json           # the same, for support and CI";

const GENERATE_QUICK: &str = "\
Examples:
  opv generate dev api/SESSION_KEY             # a key with base64_bytes = 32: 32 random bytes
  opv generate prod api/SESSION_KEY api/CSRF_KEY";

const VAULT_LOCATE_QUICK: &str = "\
Examples:
  opv vault locate zu64e5fmaxlklvyajhwkkdgldy   # which account holds this vault
  opv vault locate zu64e5fmaxlklvyajhwkkdgldy --json";

const MCP_SERVE_QUICK: &str = "\
Examples:
  opv mcp serve --project /abs/path/to/project   # what an assistant's MCP client runs";

const MCP_INSTALL_QUICK: &str = "\
Examples:
  opv mcp install                        # this project, for Claude Code and Codex
  opv mcp install --client claude        # only the project's .mcp.json";

const BOOTSTRAP_QUICK: &str = "\
Examples:
  opv bootstrap --dry-run      # each boundary and state vault: ok, create or ids_not_in_account
  opv bootstrap                # create missing vaults and items, record their IDs";

const BOOTSTRAP_MORE: &str = "\
Records every missing ID, and nothing else. Each boundary an environment needs, without
boundaries.<b>, gets a vault <project>-<b>-<env> and an item \"<project> · <b> · <env> values\"
in the selected 1Password account (found when they exist); each target without
state_vault_id gets a vault <project>-<env>-<target>-state. Their IDs are recorded in
secrets.toml. Recorded IDs the account cannot see stop with ids_not_in_account: select the
owning account, or pass --rebind <env>. Then every declared field is added, empty. Nothing
is synced, deployed or given a value. Next: opv ready";

const TARGET_ADD_QUICK: &str = "\
Examples:
  opv target add prod p-overflow --fly-app p-overflow-prod --products p
  opv target add staging site --fly-app site-staging --dry-run";

const TARGET_ADD_MORE: &str = "\
Writes [environments.<env>.targets.<name>] and finds or creates its state vault
<project>-<env>-<target>-state; keeps comments, validates first, refuses a concurrent change.";

const TARGET_LIST_QUICK: &str = "\
Examples:
  opv target list                     # every declared target
  opv target list --env prod --json   # one environment as one document";

const TARGET_CREDENTIALS_QUICK: &str = "\
Examples:
  opv target credentials staging --target web --create   # mint and store the credential
  opv target credentials staging --target web            # show the recorded state";

const TARGET_CREDENTIALS_MORE: &str = "\
Only Fly targets can be minted for: --create mints a Fly deploy token for the target's app
and stores it in a new 1Password item in the target's state vault, then records
deploy_credentials on the target. The token is never shown, copied or pasted. One
confirmation names the credential, its 90-day validity, the target and the item;
declining creates nothing. For an Azure, Kubernetes or GitHub target, create its deploy
identity at the provider, store it in 1Password, and record the item with
`opv target add --deploy-credentials op://<vault>/<item>`.
Without --create, prints whether deploy_credentials is recorded and whether the provider
can mint one. A person's own terminal and 1Password session are required.";

const ENV_ADD_QUICK: &str = "\
Examples:
  opv env add staging           # declare the environment in secrets.toml
  opv env add staging --json    # the same report an assistant gets over MCP";

const STRUCTURE_PLAN_QUICK: &str = "\
Examples:
  opv structure plan           # names, states and the plan_id, to review
  opv structure plan --json    # exactly the opv_structure_plan document";

const CONFIG_DESCRIBE_QUICK: &str = "\
Examples:
  opv config describe           # environments, keys and targets, names only
  opv config describe --json    # exactly the opv_configuration document";

const ACCOUNT_LIST_QUICK: &str = "\
Examples:
  opv account list           # accounts, which is selected, what to do next
  opv account list --json    # the same for scripts and AI assistants";

const ACCOUNT_USE_QUICK: &str = "\
Examples:
  opv account use owner@example.com   # record this project's account in .opv";

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

const SKILL_INSTALL_QUICK: &str = "\
Examples:
  opv skill install --user --target all   # this user, for Claude Code and Codex
  opv skill install --project . --json    # this project's agent folders, as JSON";

const SKILL_STATUS_QUICK: &str = "\
Examples:
  opv skill status           # each installed copy, its version and whether it is current
  opv skill status --json    # the same for scripts and AI assistants";

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
    after_long_help = examples(),
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
    /// Every call to op or the target's CLI must finish inside this budget. Each call also
    /// has its own limit: a read attempt is killed after 60 seconds, a write after 2
    /// minutes, and a write that waits for a rollout after 15 minutes. A read that fails is
    /// retried only while time remains.
    #[arg(
        long,
        global = true,
        value_name = "SECS",
        help_heading = "Global options",
        default_value_t = 1800,
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
    #[command(
        before_help = LOGIN_QUICK,
        after_help = LOGIN_MORE,
        aliases = ["signin", "sign-in", "auth"]
    )]
    Login {
        /// Environment name from the configuration (for example dev or prod).
        env: Option<String>,
        /// 1Password account (email or ID) this project uses; kept in .opv. Asked for when
        /// several accounts are on this machine.
        #[arg(long)]
        account: Option<String>,
        /// Add a 1Password account to this CLI first (with --account: that email), at
        /// 1Password's own prompt.
        #[arg(long)]
        add: bool,
        /// Sign in to --account for this login only and leave .opv unchanged (a one-off look
        /// into another account, such as opv vault locate).
        #[arg(long, requires = "account")]
        no_record: bool,
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
        /// Check only this named target of the environment (repeatable); requires --env.
        #[arg(long = "target", value_name = "NAME", requires = "env")]
        target: Vec<String>,
        /// Print one JSON document (check names, states and next steps) instead of lines.
        #[arg(long)]
        json: bool,
        /// Also look for likely-wrong values: the same secret in two environments, a
        /// placeholder, stray whitespace, localhost where it deploys. Reads every
        /// environment's item; values are compared, never shown.
        #[arg(long)]
        settings: bool,
    },
    /// Check whether your required settings are ready; contacts no deployment target.
    #[command(before_help = CHECK_QUICK, after_help = CHECK_MORE)]
    Check {
        /// Environment name from the configuration (for example dev).
        env: String,
        /// Product whose keys are checked; optional when exactly one product has keys here.
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
        /// Only this product's rows, totals and findings.
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
        /// Only this named target of the environment (repeatable). Without it, every
        /// target, in name order.
        #[arg(long = "target", value_name = "NAME", requires = "env")]
        target: Vec<String>,
        /// Exit 8 with `target_drift` when a pinned binding on the target no longer matches
        /// 1Password. Without it, drift stays a printed line and the exit code is unchanged.
        #[arg(long, requires = "env")]
        fail_on_drift: bool,
    },
    /// List the projects whose configuration lives in 1Password (names only).
    ///
    /// One metadata listing per signed-in account shows each manifest's vault, repos and
    /// paths; --long also reads each manifest once for its environment names.
    #[command(before_help = PROJECTS_QUICK, after_help = PROJECTS_MORE)]
    Projects {
        /// List only this 1Password account (email, account ID or sign-in address);
        /// defaults to OP_ACCOUNT, which opv login --account sets for its command.
        #[arg(long, value_name = "ACCOUNT")]
        account: Option<String>,
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
        /// Product whose declared keys are passed to the command; optional when exactly one
        /// product has keys desired in the environment.
        /// [env: OPV_PRODUCT]
        #[arg(long)]
        product: Option<String>,
        /// Deliver only keys that declare this process role (and keys without roles).
        #[arg(long, value_name = "ROLE")]
        role: Option<String>,
        /// Print what this run would deliver; reads no value and runs nothing.
        #[arg(long)]
        preview: bool,
        /// With --preview: print one JSON document.
        #[arg(long, requires = "preview")]
        json: bool,
        /// Run on a reviewed remote profile ([products.<p>.remotes.<name>]): the values go
        /// over pinned SSH and the profile's pinned command runs there. Takes no command.
        #[arg(long, value_name = "PROFILE")]
        remote: Option<String>,
        /// The environment's name again; required when it sets confirm_env = true.
        #[arg(long, value_name = "ENV", hide_short_help = true)]
        confirm: Option<String>,
        /// Command and arguments, after `--`.
        #[arg(
            required_unless_present_any = ["preview", "remote"],
            trailing_var_arg = true,
            allow_hyphen_values = true
        )]
        command: Vec<String>,
    },
    /// Preview deployment changes without changing anything.
    #[command(before_help = PLAN_QUICK, after_help = PLAN_MORE)]
    Plan(PlanArgs),
    /// Save managed settings on the configured deployment target.
    #[command(before_help = SYNC_QUICK, after_help = SYNC_MORE)]
    Sync(SyncArgs),
    /// 1Password accounts: which ones this machine's CLI knows, and the project's.
    #[command(subcommand)]
    Account(AccountCmd),
    /// Generate self-made secrets (base64_bytes / hex_bytes keys) straight into 1Password.
    ///
    /// The value comes from the operating system's CSPRNG and goes only into the 1Password
    /// field (one verified edit); it is never shown, logged or written elsewhere. A field
    /// that already has a value is never replaced; provider-issued keys are refused.
    #[command(before_help = GENERATE_QUICK)]
    Generate {
        /// Environment name from the configuration.
        env: String,
        /// The keys, as product/KEY.
        #[arg(required = true, value_name = "PRODUCT/KEY")]
        keys: Vec<String>,
    },
    /// 1Password vaults: find which account holds one (read-only).
    #[command(subcommand)]
    Vault(VaultCmd),
    /// opv's MCP server for coding assistants: serve it, or register it with an assistant.
    #[command(subcommand)]
    Mcp(McpCmd),
    /// Delivery receipts: whether a product's target still holds what opv delivered.
    #[command(subcommand)]
    Delivery(DeliveryCmd),
    /// Whether a source item changed since the last sync (read-only; exit 10 when it did).
    #[command(before_help = CHANGED_QUICK)]
    Changed {
        /// Environment name from the configuration (for example prod).
        env: String,
        /// Only this product.
        #[arg(long)]
        product: Option<String>,
        /// Only this target (repeatable); default: every target that delivers the product.
        #[arg(long)]
        target: Vec<String>,
        /// Print one JSON document instead of lines.
        #[arg(long)]
        json: bool,
    },
    /// Print a ready-to-commit GitHub Actions workflow (YAML) for one target (read-only).
    #[command(subcommand)]
    Ci(CiCmd),
    /// Declare a named deployment target of an environment, or list the declared ones.
    #[command(subcommand)]
    Target(TargetCmd),
    /// Declare an environment in secrets.toml, like the MCP `opv_declare_environment` tool.
    #[command(subcommand)]
    Env(EnvCmd),
    /// Plan or apply this project's 1Password structure, like the MCP structure tools.
    #[command(subcommand)]
    Structure(StructureCmd),
    /// Bring values that exist elsewhere into the environment's 1Password item, after review.
    #[command(before_help = ADOPT_QUICK, after_help = ADOPT_MORE)]
    Adopt {
        /// Environment whose item receives the values.
        env: String,
        /// A private dotenv file, or `target:<name>` to read what that target can show.
        #[arg(long, value_name = "FILE|target:NAME")]
        from: String,
        /// Take the found value for this key although 1Password holds another (repeatable).
        #[arg(long, value_name = "PRODUCT/KEY")]
        replace: Vec<String>,
        /// Allow --replace on this immutable key (repeatable).
        #[arg(long, value_name = "PRODUCT/KEY")]
        rotate: Vec<String>,
        /// Leave this key out of the import although it would be imported (repeatable).
        #[arg(long, value_name = "PRODUCT/KEY")]
        skip: Vec<String>,
        /// Write the plan to 1Password (without it, nothing is written).
        #[arg(long)]
        apply: bool,
        /// Print one JSON document instead of lines.
        #[arg(long)]
        json: bool,
    },
    /// Browse and manage every environment, product and key in a terminal UI (values never
    /// shown); actions run the same opv commands, behind plan and confirmation.
    #[cfg(feature = "ui")]
    #[command(before_help = UI_QUICK)]
    Ui,
    /// What opv last wrote to an environment's target, per key: when, by which plan, and
    /// whether it changed outside opv since (read-only, values never shown).
    #[command(before_help = HISTORY_QUICK)]
    History {
        /// Environment name from the configuration (for example prod).
        env: String,
        /// Only this target of the environment (omit: every target, each labelled).
        #[arg(long, value_name = "NAME")]
        target: Option<String>,
        /// Print one JSON document instead of lines.
        #[arg(long)]
        json: bool,
    },
    /// Put an environment's 1Password item in opv's layout: one verified edit, nothing
    /// deleted (a signed-in person only; `doctor` never writes and names this command).
    #[command(before_help = TIDY_QUICK)]
    Tidy {
        /// Environment name from the configuration (for example prod).
        env: String,
        /// Print one JSON document instead of lines.
        #[arg(long)]
        json: bool,
    },
    /// Who can read each environment's vault, and the command for a read-only CI reader
    /// (read-only; people are counted, never named).
    #[command(before_help = ACCESS_QUICK)]
    Access {
        /// Only this environment.
        env: Option<String>,
        /// Only this target's deploy identity (omits the CI reader).
        #[arg(long, value_name = "NAME")]
        target: Option<String>,
        /// Project name for the service accounts; defaults to the repository's name.
        #[arg(long, value_name = "NAME")]
        project: Option<String>,
        /// Create the identity (the target's deploy identity, or without --target the CI
        /// reader) and store its token as a GitHub secret; your own terminal only. The
        /// token is never shown, typed or written to a file.
        #[arg(long, requires_all = ["env", "github"])]
        create: bool,
        /// With --create: the GitHub repository (owner/repo) whose secret receives the token.
        #[arg(long, value_name = "OWNER/REPO", requires = "create")]
        github: Option<String>,
        /// With --create: the GitHub environment the CI job declares (created if missing);
        /// without it, a repository secret.
        #[arg(long, value_name = "NAME", requires = "create")]
        github_env: Option<String>,
        /// With --create: the secret's name.
        #[arg(
            long,
            value_name = "NAME",
            default_value = "OP_SERVICE_ACCOUNT_TOKEN",
            requires = "create"
        )]
        secret_name: String,
        /// Print one JSON document instead of lines.
        #[arg(long)]
        json: bool,
    },
    /// What is ready, what is not, and who does what next: one receipt (read-only).
    #[command(before_help = READY_QUICK)]
    Ready {
        /// Only this environment.
        env: Option<String>,
        /// Print the receipt as one JSON document.
        #[arg(long)]
        json: bool,
        /// Also save the receipt (names, IDs and codes only) to this file, to resume later.
        #[arg(long, value_name = "FILE")]
        save: Option<PathBuf>,
        /// Fail (exit 8, `gate_failed`) when a present key is not in value state `set` or
        /// its delivery evidence is older than its source item; `expires` is advisory.
        #[arg(long)]
        gate: bool,
    },
    /// Internal: the remote delivery step `opv run --remote` starts under `op run` (#139).
    #[command(name = "remote-send", hide = true)]
    RemoteSend {
        #[arg(long)]
        plan: String,
    },
    /// Internal: the receiver on the remote host; reads its payload from stdin (#139).
    #[command(name = "remote-receive", hide = true)]
    RemoteReceive,
    /// Internal: the local delivery step `opv run` starts under `op run` (#136, #137).
    #[command(name = "local-delivery", hide = true)]
    LocalDelivery {
        #[arg(long = "key")]
        keys: Vec<String>,
        #[arg(long)]
        declared_only: bool,
        #[arg(long)]
        dir_env: Option<String>,
        #[arg(long = "file")]
        files: Vec<String>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// opv's version and every CLI it runs, with their versions (read-only; no sign-in).
    ///
    /// One bounded local version probe per CLI (1Password, then each provider's); the
    /// configuration here, if any, says which ones this project uses. `opv --version`
    /// prints opv's version line only.
    #[command(before_help = VERSION_QUICK)]
    Version {
        /// Print one JSON document instead of lines.
        #[arg(long)]
        json: bool,
    },
    /// Create every missing boundary vault, item and state vault, record their IDs, and add
    /// the empty fields.
    #[command(before_help = BOOTSTRAP_QUICK, after_help = BOOTSTRAP_MORE)]
    Bootstrap {
        /// The configuration file to complete; defaults to the secrets.toml found from here.
        #[arg(long, value_name = "PATH")]
        file: Option<PathBuf>,
        /// Project name for vault and item titles; defaults to the repository's name.
        #[arg(long)]
        project: Option<String>,
        /// Show what would be created or checked; change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Replace this environment's recorded boundary IDs with vaults and items in the
        /// selected account (repeatable). Values are not moved.
        #[arg(long, value_name = "ENV")]
        rebind: Vec<String>,
        /// Also print the owner's command for a read-only CI service account for every
        /// boundary vault of this environment.
        #[arg(long, value_name = "ENV")]
        ci_reader: Option<String>,
        /// Print one JSON document (each environment's boundaries and state vaults) instead
        /// of lines.
        #[arg(long)]
        json: bool,
    },
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
        #[arg(value_name = "[PRODUCT/]KEY", required_unless_present = "target_name")]
        target: Option<String>,
        /// Explain this named target instead of a key: its provider and locator,
        /// products, deploy credentials, state vault and deploy service account.
        #[arg(long = "target", value_name = "NAME", conflicts_with = "target")]
        target_name: Option<String>,
        /// Environment name; may be omitted when only one environment is declared.
        #[arg(long)]
        env: Option<String>,
        /// Project name for the service account names; defaults to the repository's name.
        #[arg(long)]
        project: Option<String>,
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
    /// Write the configuration from an environment's 1Password item (created if missing).
    #[command(before_help = INIT_QUICK)]
    Init {
        /// Environment name to declare (for example staging or prod).
        env: String,
        /// Vault title, matched exactly; defaults to <project>-<product>-<env> (created if
        /// missing; <product> is core without --product).
        #[arg(long)]
        vault: Option<String>,
        /// Item title in that vault, matched exactly; its field names and types are read
        /// once, never its values. Defaults to "<project> · <product> · <env> values".
        #[arg(long)]
        item: Option<String>,
        /// Product the item's unsectioned fields belong to (the app's role, such as api);
        /// required when it has any. Each named section is a product of its own.
        #[arg(long)]
        product: Option<String>,
        /// Add this environment to the existing configuration (a secrets.toml or the
        /// project's manifest, found like other commands) instead of writing a new one;
        /// comments are kept, and every declared key the item has includes the environment.
        #[arg(long, conflicts_with = "force")]
        add_env: bool,
        /// Overwrite an existing secrets.toml. Hidden from help (H9): the refusal names it.
        #[arg(long, hide_short_help = true, hide_long_help = true)]
        force: bool,
        /// Print what was written (names and kinds) as one JSON document.
        #[arg(long, hide_long_help = true)]
        json: bool,
        /// Write ./secrets.toml even for a new project (without it, a new project's
        /// configuration is saved as a manifest in the item's vault).
        #[arg(long)]
        file: bool,
        /// Project name of a new manifest; defaults to the repository's name.
        #[arg(long, conflicts_with = "file")]
        project: Option<String>,
        /// 1Password account (email or ID) when several are on this machine; kept in .opv.
        #[arg(long)]
        account: Option<String>,
        /// Start from a private .env: declare every key (kind by name; --config-key or
        /// --secret-key KEY to change one) and, with --apply, import the values, verified.
        #[arg(
            long,
            value_name = "FILE",
            conflicts_with = "add_env",
            requires = "product"
        )]
        from: Option<std::path::PathBuf>,
        /// With --from: declare this key as config whatever its name (repeatable).
        #[arg(
            long,
            value_name = "KEY",
            requires = "from",
            hide_short_help = true,
            hide_long_help = true
        )]
        config_key: Vec<String>,
        /// With --from: declare this key as secret whatever its name (repeatable).
        #[arg(
            long,
            value_name = "KEY",
            requires = "from",
            hide_short_help = true,
            hide_long_help = true
        )]
        secret_key: Vec<String>,
        /// With --from: create, declare and import (without it: the plan only).
        #[arg(long, requires = "from", hide_short_help = true, hide_long_help = true)]
        apply: bool,
    },
    /// Declare a key in the configuration, or add environments to a declared key.
    #[command(before_help = ADD_QUICK, after_help = ADD_MORE)]
    Add {
        /// The key: PRODUCT/KEY, or a bare KEY that exactly one product declares.
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
        /// Read the value of another key, PRODUCT/KEY (a shared value).
        #[arg(long, value_name = "PRODUCT/KEY")]
        from: Option<String>,
        /// Each person's own value, in their own item (local environments only).
        #[arg(long)]
        personal: bool,
        /// The same value in several environments is intended (no settings warning).
        #[arg(long)]
        allow_same_value: bool,
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
    /// Install the opv agent skill where coding agents look, and report installed copies.
    #[command(subcommand)]
    Skill(SkillCmd),
}

/// Guides embedded in the binary (A10).
#[derive(Clone, Copy, clap::ValueEnum)]
enum GuideTopic {
    /// Setting opv up in a user's project, for AI assistants: rules, steps, exit codes.
    Agent,
}

#[derive(Subcommand)]
enum SkillCmd {
    /// Install the embedded agent skill where coding agents look for it.
    #[command(before_help = SKILL_INSTALL_QUICK)]
    Install {
        /// Which agents' skill folders to write.
        #[arg(long, value_enum, default_value_t = SkillTarget::All)]
        target: SkillTarget,
        /// Install into the user's home (HOME, else USERPROFILE).
        #[arg(long, conflicts_with = "project")]
        user: bool,
        /// Install into this project's root; default: the git top level.
        #[arg(long, value_name = "DIR")]
        project: Option<PathBuf>,
        /// Replace a copy that was edited by hand.
        #[arg(long)]
        force: bool,
        /// Print one JSON document instead of lines.
        #[arg(long)]
        json: bool,
    },
    /// Report the installed agent skill copies, their version and state.
    #[command(before_help = SKILL_STATUS_QUICK)]
    Status {
        /// Print one JSON document instead of lines.
        #[arg(long)]
        json: bool,
    },
}

/// `--target` of `opv skill install`.
#[derive(Clone, Copy, clap::ValueEnum)]
enum SkillTarget {
    /// Claude Code (`.claude/skills/opv/SKILL.md`).
    Claude,
    /// Codex and other `.agents` clients (`.agents/skills/opv/SKILL.md`).
    Codex,
    /// Both, the default.
    All,
}

impl SkillTarget {
    /// The library targets this selection writes.
    fn targets(self) -> Vec<opv::app::skill::Target> {
        use opv::app::skill::{self, Target};
        match self {
            SkillTarget::Claude => vec![Target::Claude],
            SkillTarget::Codex => vec![Target::Codex],
            SkillTarget::All => skill::ALL.to_vec(),
        }
    }
}

/// Arguments of `plan`.
#[derive(Args)]
struct PlanArgs {
    /// Environment name from the configuration (for example staging or prod).
    env: String,
    /// Only this product's rows, totals and findings.
    /// [env: OPV_PRODUCT]
    #[arg(long)]
    product: Option<String>,
    /// Print one machine-readable JSON document instead of the table.
    #[arg(long)]
    json: bool,
    /// Only this named target of the environment (repeatable). Without it, every target,
    /// in name order, under one plan id.
    #[arg(long = "target", value_name = "NAME")]
    target: Vec<String>,
    /// Plan to replace this immutable key even though it is present (repeatable). Part of
    /// the plan id, so a plan with rotation never shares an id with one without.
    #[arg(long, value_name = "PRODUCT/KEY", hide_short_help = true)]
    rotate: Vec<String>,
}

/// Arguments of `sync`.
#[derive(Args)]
struct SyncArgs {
    /// Environment name from the configuration (for example staging or prod).
    env: String,
    /// Deploy when something staged changed, was pruned, or is pending from an earlier run.
    #[arg(long)]
    deploy: bool,
    /// Unset managed names that are not desired in this environment. Immutable keys
    /// are never pruned unless named with --prune-immutable.
    #[arg(long)]
    prune: bool,
    /// The environment's name again; required when it sets confirm_env = true.
    #[arg(long, value_name = "ENV")]
    confirm: Option<String>,
    /// Write, prune and deploy only this product's names (a deploy restarts the whole app).
    #[arg(long)]
    product: Option<String>,
    /// Apply only the plan opv plan showed with this id (exit 6 if it changed since).
    #[arg(long, value_name = "PLAN_ID")]
    expect_plan: Option<String>,
    /// Write the delivery receipts this sync mints (names, ids and times) to FILE; needs
    /// the environment's state_vault_id.
    #[arg(
        long,
        value_name = "FILE",
        hide_short_help = true,
        hide_long_help = true
    )]
    receipt: Option<std::path::PathBuf>,
    /// Print the run report as one JSON document (names only) instead of text.
    #[arg(long)]
    json: bool,
    /// Stage an immutable key even though it is present on the target (repeatable).
    #[arg(long, value_name = "PRODUCT/KEY", hide_short_help = true)]
    rotate: Vec<String>,
    /// Let --prune unset this immutable key (repeatable).
    #[arg(
        long,
        value_name = "PRODUCT/KEY",
        hide_short_help = true,
        hide_long_help = true
    )]
    prune_immutable: Vec<String>,
    /// Only this named target of the environment (repeatable). Without it, every target,
    /// in name order, under one plan id.
    #[arg(long = "target", value_name = "NAME")]
    target: Vec<String>,
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
            receipt: a.receipt,
            targets: a.target,
        }
    }
}

#[derive(Subcommand)]
enum DeliveryCmd {
    /// Check, read-only, that each placement (product and target) still holds the binding
    /// set opv delivered, and name its revision (values never shown).
    #[command(before_help = DELIVERY_VERIFY_QUICK)]
    Verify {
        /// Environment name from the configuration (for example prod).
        env: String,
        /// Only this product.
        #[arg(long)]
        product: Option<String>,
        /// Only this target (repeatable); default: every target that delivers the product.
        #[arg(long)]
        target: Vec<String>,
        /// A receipt kept from `opv sync --receipt`: it must be the current delivery.
        #[arg(long, value_name = "FILE")]
        receipt: Option<std::path::PathBuf>,
        /// Print one JSON document instead of lines.
        #[arg(long)]
        json: bool,
    },
}

const DELIVERY_VERIFY_QUICK: &str = "\
Examples:
  opv sync prod --product api --receipt api.receipt.json       # deliver, and keep the receipt
  opv delivery verify prod --product api                       # each placement: verified, changed, or not delivered
  opv delivery verify prod --product api --target web          # one placement
  opv delivery verify prod --receipt api.receipt.json --json   # the kept receipt is still current?";

const CHANGED_QUICK: &str = "\
Examples:
  opv changed prod                       # did any source item change since the last sync?
  opv changed prod --product api         # only api's placements
  opv changed prod --json                # one JSON document; exit 10 when something changed";

#[derive(Subcommand)]
enum CiCmd {
    /// Print a ready-to-commit GitHub Actions workflow (YAML) that syncs one target, so an
    /// assistant never writes the workflow from scratch.
    #[command(before_help = CI_WORKFLOW_QUICK)]
    Workflow {
        /// Environment name from the configuration (for example prod).
        #[arg(required_unless_present_any = ["on_change", "drift"])]
        env: Option<String>,
        /// Target name whose provider setup step and sync command the workflow uses.
        #[arg(
            long,
            value_name = "NAME",
            required_unless_present_any = ["on_change", "drift"],
            conflicts_with_all = ["on_change", "drift"]
        )]
        target: Option<String>,
        /// GitHub environment the job declares (`environment:`); without it, none.
        #[arg(long, value_name = "ENVIRONMENT", conflicts_with_all = ["on_change", "drift"])]
        github_env: Option<String>,
        /// Let the job deploy after syncing (adds --deploy to the sync command).
        #[arg(long, conflicts_with_all = ["on_change", "drift"])]
        deploy: bool,
        /// Print §2.5's change-detection workflow, one job per environment with a target.
        #[arg(long, conflicts_with_all = ["drift", "target", "github_env", "deploy"])]
        on_change: bool,
        /// Print §2.5's nightly drift-check workflow for the same environments.
        #[arg(long, conflicts_with_all = ["on_change", "target", "github_env", "deploy"])]
        drift: bool,
        /// Minutes between change checks (`--on-change` only); a divisor of 60, at most 59.
        #[arg(
            long,
            value_name = "MINUTES",
            default_value = "15",
            value_parser = every_minutes,
            requires = "on_change"
        )]
        every: u8,
    },
}

const CI_WORKFLOW_QUICK: &str = "\
Examples:
  opv ci workflow prod --target web                     # print the workflow for one target
  opv ci workflow prod --target web --github-env prod   # run the job in the prod environment
  opv ci workflow prod --target web --deploy            # let the job deploy after syncing
  opv ci workflow --on-change                           # the change workflow, every 15 minutes
  opv ci workflow --on-change --every 30                # ... on a 30-minute cron
  opv ci workflow --drift                               # the nightly drift check";

/// `--every <minutes>`: a divisor of 60 (so the cron repeats every hour), at most 59.
fn every_minutes(s: &str) -> Result<u8, String> {
    let n: u8 = s
        .parse()
        .map_err(|_| "a whole number of minutes".to_string())?;
    if (1..=59).contains(&n) && 60 % n == 0 {
        Ok(n)
    } else {
        Err("a divisor of 60 between 1 and 59".to_string())
    }
}

#[derive(Subcommand)]
enum TargetCmd {
    /// Declare one named deployment target of an environment: writes the configuration and
    /// creates the target's state vault.
    #[command(before_help = TARGET_ADD_QUICK, after_help = TARGET_ADD_MORE)]
    Add {
        /// Environment name from the configuration (for example prod).
        env: String,
        /// New target name (^[a-z][a-z0-9-]*$); there is no default.
        name: String,
        /// Provider section: fly, azure, kubernetes or github; inferred from its options
        /// (for example --fly-app) when omitted.
        #[arg(long, value_name = "PROVIDER")]
        provider: Option<String>,
        /// Products this target delivers (repeat or comma-separate); without it, every
        /// non-source-only product.
        #[arg(long, value_delimiter = ',')]
        products: Vec<String>,
        /// A process role this target delivers (repeat or comma-separate), written as its
        /// `roles`; required when a delivered product's keys declare roles. Names only.
        #[arg(long = "role", value_name = "ROLE", value_delimiter = ',')]
        roles: Vec<String>,
        /// The item holding this target's least-privilege deploy identity
        /// (op://<vault>/<item>).
        #[arg(long, value_name = "OP_REF")]
        deploy_credentials: Option<String>,
        /// Project naming the state vault; defaults to the repository's name.
        #[arg(long)]
        project: Option<String>,
        /// Show what would be written and created; change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Print one JSON document instead of lines.
        #[arg(long)]
        json: bool,
    },
    /// List the declared deployment targets (read-only).
    #[command(before_help = TARGET_LIST_QUICK)]
    List {
        /// Only this environment.
        #[arg(long)]
        env: Option<String>,
        /// Print one JSON array instead of lines.
        #[arg(long)]
        json: bool,
    },
    /// Mint a Fly target's least-privilege deploy token and store it in 1Password (only
    /// Fly targets can be minted for; the others show their recorded state).
    #[command(before_help = TARGET_CREDENTIALS_QUICK, after_help = TARGET_CREDENTIALS_MORE)]
    Credentials {
        /// Environment name from the configuration (for example prod).
        env: String,
        /// The target to mint the credential for (^[a-z][a-z0-9-]*$).
        #[arg(long)]
        target: String,
        /// Mint the credential and store it; without it, print the recorded state.
        #[arg(long)]
        create: bool,
    },
}

#[derive(Subcommand)]
enum EnvCmd {
    /// Declare an environment in secrets.toml; its vaults and items come from the approved
    /// structure (same guarantee as the MCP `opv_declare_environment` tool).
    #[command(before_help = ENV_ADD_QUICK)]
    Add {
        /// New environment name (^[a-z][a-z0-9-]*$).
        environment: String,
        /// Print the same report an assistant gets over MCP, instead of lines.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum StructureCmd {
    /// Plan the 1Password structure this configuration declares (read-only): names and a
    /// plan_id only, no value and no write.
    #[command(before_help = STRUCTURE_PLAN_QUICK)]
    Plan {
        /// Print exactly the document the MCP `opv_structure_plan` tool returns.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum VaultCmd {
    /// Which of the 1Password accounts this CLI knows holds a vault (names and IDs only).
    ///
    /// Asks each account with `op vault get` (exit status only). An account that is not
    /// signed in is reported unknown, never "not there"; its next step signs in to it for
    /// this check only, without changing the project's .opv.
    #[command(before_help = VAULT_LOCATE_QUICK)]
    Locate {
        /// The vault ID, as opv access or a configuration names it.
        #[arg(value_name = "VAULT_ID")]
        vault: String,
        /// Print one JSON document instead of lines.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum McpCmd {
    /// Run the MCP server over stdio for one project (started by the assistant's client).
    ///
    /// Tools: readiness, configuration and target metadata, plan previews, declarations and
    /// the structure plan (docs/mcp.md). Never accepts or returns a secret value.
    /// Start it without op session, service-account or Connect credentials.
    #[command(before_help = MCP_SERVE_QUICK)]
    Serve {
        /// The trusted project directory, chosen by the person (absolute).
        #[arg(long, value_name = "DIR")]
        project: PathBuf,
    },
    /// Register `opv mcp serve` for a project with Claude Code (.mcp.json) and/or Codex.
    ///
    /// Merges into the existing configuration: other servers and settings are kept, and an
    /// entry of the same name that runs something else is refused unless --force.
    #[command(before_help = MCP_INSTALL_QUICK)]
    Install {
        /// Which assistant's configuration to write.
        #[arg(long, value_enum, default_value_t = McpClient::All)]
        client: McpClient,
        /// The project directory; default: the git top level, else this directory.
        #[arg(long, value_name = "DIR")]
        project: Option<PathBuf>,
        /// The server's name in the client configuration.
        #[arg(long, default_value = "opv")]
        name: String,
        /// Replace an existing entry of that name that runs something else.
        #[arg(long)]
        force: bool,
        /// Print one JSON document instead of lines.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum McpClient {
    /// Claude Code: the project's .mcp.json.
    Claude,
    /// Codex: $CODEX_HOME/config.toml, else ~/.codex/config.toml.
    Codex,
    /// Both.
    All,
}

#[derive(Subcommand)]
enum AccountCmd {
    /// List the 1Password accounts this CLI knows and which one this project uses (read-only).
    #[command(before_help = ACCOUNT_LIST_QUICK)]
    List {
        /// Show which account this value (email, account ID or sign-in address) selects.
        #[arg(long)]
        account: Option<String>,
        /// Print one JSON document (accounts, selection, findings) instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Record the account this project uses in .opv (no prompt, no sign-in).
    #[command(before_help = ACCOUNT_USE_QUICK)]
    Use {
        /// Email, account ID, shorthand or sign-in address of an account this CLI knows.
        who: String,
        /// Print one JSON document instead of a line.
        #[arg(long)]
        json: bool,
    },
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
    /// Compare a committed copy with the project's manifest; exit 2 with a diff when they
    /// differ (for review in CI).
    #[command(before_help = CONFIG_CHECK_QUICK, after_help = CONFIG_CHECK_MORE)]
    Check {
        /// The committed copy.
        #[arg(long, value_name = "PATH")]
        file: PathBuf,
    },
    /// Print the declared configuration metadata (environments, keys, targets), names only;
    /// same document as the MCP `opv_configuration` tool.
    #[command(before_help = CONFIG_DESCRIBE_QUICK)]
    Describe {
        /// Print exactly the document the MCP `opv_configuration` tool returns.
        #[arg(long)]
        json: bool,
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

/// The command line: the derived [`Cli`] plus each provider's `opv target add` options
/// (`--<provider>-<field>`), taken from the plug-in contract so a new provider adds its
/// options without a change here (H3).
fn command_line() -> clap::Command {
    Cli::command().mut_subcommand("target", |t| t.mut_subcommand("add", provider_options))
}

/// Every provider's options as hidden arguments plus one summary line per provider in
/// `opv target add`'s help (H3, I6).
fn provider_options(mut c: clap::Command) -> clap::Command {
    use opv::adapters::registry;
    use opv::provider::init_flag;
    let mut summary = String::from("Provider options (* required for that --provider):");
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
    match c.get_after_help().map(|a| a.to_string()) {
        Some(more) => c.after_help(format!("{summary}\n\n{more}")),
        None => c.after_help(summary),
    }
}

/// The provider options given to `target add`, by option name.
fn target_fields(matches: &clap::ArgMatches) -> std::collections::BTreeMap<String, String> {
    use opv::adapters::registry;
    use opv::provider::init_flag;
    let Some(m) = matches
        .subcommand_matches("target")
        .and_then(|t| t.subcommand_matches("add"))
    else {
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
    // §9.2: harden before anything else, for every command, before parsing arguments.
    opv::hardening::harden();
    // Credentials in opv's own environment are secrets for the whole run: the output guard
    // masks them wherever they would appear (design §8).
    opv::scrub::register_credential_env();
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
    // The agent skill is written only on install (install.sh, the npm postinstall and `opv
    // skill install`); no other command writes $HOME. `opv doctor` and `opv skill status`
    // report a copy older than this binary (design §12.4).
    //
    // The invocation every catalog error renders its steps against, built once from the
    // parsed command line (design §6.1), and how the failure is shown: `--verbose` passes
    // the tool's whole scrubbed reply, and the reply box is drawn in UTF-8 only when the
    // terminal's locale is (§7.3).
    let render = Render {
        inv: None,
        verbose: cli.verbose,
        utf8: locale_is_utf8(),
        // D2 (A8): the error is coloured only where stderr is a terminal that takes it.
        colour: colour::enabled(
            cli.color,
            io::IsTerminal::is_terminal(&io::stderr()),
            std::env::var_os("NO_COLOR"),
        ),
    };
    let target_options = target_fields(&matches);
    let json = cli.cmd.json_mode();
    opv::runner::signals::set_json(json.is_some());
    // The MCP server owns stdin and stdout for the whole session: it runs before opv takes
    // the stdout lock below, which its runtime's writer thread would otherwise wait on
    // forever (found by the protocol smoke test).
    if let Cmd::Mcp(McpCmd::Serve { project }) = &cli.cmd {
        return match mcp_serve(project) {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => {
                let _ = write!(opv::output::stderr(), "{}", render.text(&e));
                ExitCode::from(exit_byte(e.exit_code()))
            }
        };
    }
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
    // A person at a terminal whose 1Password session is gone is signed in at op's own
    // prompt and the command runs once more (found live: an idle session stopped `opv
    // check` with only "run opv login"). Never for --json, scripts, CI or a service
    // account, and never for login and setup, which sign in themselves.
    let may_sign_in = json.is_none() && !matches!(cli.cmd, Cmd::Login { .. } | Cmd::Setup { .. });
    let mut first = Some(cli);
    let mut signed_in = false;
    let res = loop {
        let cli = match first.take() {
            Some(c) => c,
            None => match Cli::from_arg_matches(&matches) {
                Ok(c) => c,
                Err(e) => return usage_error(e),
            },
        };
        // Every byte opv writes passes the output guard (design §8). The guard sits above
        // the painter, so it never strips the colours opv adds itself.
        let res = if json.is_some() {
            run(cli, config_source, &target_options, &mut body)
        } else if paint {
            let mut guard = opv::output::OutputGuard::new(colour::Painter::new(&mut stdout));
            let res = run(cli, config_source, &target_options, &mut guard);
            let _ = guard.flush();
            res
        } else {
            let mut guard = opv::output::OutputGuard::new(&mut stdout);
            let res = run(cli, config_source, &target_options, &mut guard);
            let _ = guard.flush();
            res
        };
        let signed_out = matches!(&res, Err(e) if e.code_str() == "op_not_signed_in");
        if may_sign_in && signed_out && !signed_in {
            match sign_in_here() {
                // Once: a second failure is reported as it is.
                Ok(true) => {
                    signed_in = true;
                    continue;
                }
                Ok(false) => {}
                // Why the sign-in failed, in opv's words (FR-50), instead of the first error.
                Err(e) => break Err(e),
            }
        }
        break res;
    };
    if let Some(raw) = json {
        let inv = render.inv.clone().unwrap_or_else(opv::error::invocation);
        let framed = match &res {
            Err(e) => opv::json::finish_with(&body, Err(e), raw, &inv, render.verbose),
            Ok(_) => opv::json::finish(&body, Ok(()), raw),
        };
        let _ = opv::output::OutputGuard::new(&mut stdout).write_all(&framed);
    }
    let _ = stdout.flush();
    match res {
        // `run` reports the child's exit code verbatim (FR-4); everything else yields 0.
        Ok(0) => ExitCode::SUCCESS,
        Ok(code) => ExitCode::from(exit_byte(code)),
        Err(e) => {
            // Error messages never contain secret values (SR-1). The failed call's reply
            // is the cause's scrubbed evidence box (NR-31, §7.3); `Do:` (when a person must
            // act) and the `Next:` line are always last (NR-19, A3). Under `--json` the
            // same text still goes to stderr.
            let _ = write!(opv::output::stderr(), "{}", render.text(&e));
            ExitCode::from(exit_byte(e.exit_code()))
        }
    }
}

/// How a failure is shown: the invocation its steps are rendered against (the process's
/// own, [`opv::error::invocation`], when `None`: an internal step renders against the
/// person's `opv run`, X25), and what the person asked for (`--verbose`) or the terminal
/// supports (UTF-8). Built once in [`main`].
struct Render {
    inv: Option<opv::cause::Invocation>,
    verbose: bool,
    utf8: bool,
    /// Whether stderr takes colour (`--color`, a terminal, `NO_COLOR`), A8.
    colour: bool,
}

impl Render {
    /// The failure's text for stderr: its cause through the one renderer, with this run's
    /// invocation, `--verbose`, UTF-8 support and colour.
    fn text(&self, e: &Error) -> String {
        let inv = self.inv.clone().unwrap_or_else(opv::error::invocation);
        opv::error::render_text(e, &inv, self.verbose, self.utf8, self.colour)
    }
}

/// Whether the terminal's locale is UTF-8: the first set of `LC_ALL`, `LC_CTYPE` and
/// `LANG` names it (Windows terminals are). Otherwise the reply box falls back to ASCII.
fn locale_is_utf8() -> bool {
    if cfg!(windows) {
        return true;
    }
    ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
        .is_some_and(|v| {
            let v = v.to_ascii_lowercase();
            v.contains("utf-8") || v.contains("utf8")
        })
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
    let args: Vec<String> = std::env::args().skip(1).collect();
    // L6: `opv run ... --json` without `--preview` is the usage problem `--json needs
    // --preview`, not clap's `MissingRequiredArgument` list.
    if let Some(cause) = json_without_preview(&e, &args) {
        return usage_cause(cause, true);
    }
    // `opv sync <env> --dry-run`: the dry run of a sync is its plan (09.21), named with every
    // flag plan keeps; clap's own tip ("use -- --dry-run") does not apply to sync.
    if e.kind() == ErrorKind::UnknownArgument
        && args.iter().any(|a| a == "--dry-run")
        && let Some(plan) = sync_as_plan(&args)
    {
        return usage_cause(
            opv::cause::Cause::Usage {
                problem: opv::cause::UsageProblem::UseInstead { command: plan },
            },
            args.iter().any(|a| a == "--json"),
        );
    }
    // 09.03, 09.83: a misspelt subcommand clap suggests, or a subcommand's flag given
    // before it: the corrected command, when it parses.
    if let Some(command) = corrected_command(&e, &args) {
        return usage_cause(
            opv::cause::Cause::Usage {
                problem: opv::cause::UsageProblem::UseInstead { command },
            },
            args.iter().any(|a| a == "--json"),
        );
    }
    let json = args.iter().any(|a| a == "--json");
    // FR-60: a removed form names its replacement exactly.
    if let Some(instead) = removed_init_target(&args) {
        return usage_cause(
            opv::cause::Cause::Usage {
                problem: opv::cause::UsageProblem::Removed {
                    what: "opv init writes no target since 0.7.0: --target, --target-name and \
                           the provider options were removed; add the target with opv target add",
                    instead,
                },
            },
            json,
        );
    }
    // Any other command line clap refuses: clap's own first line (it names the argument it
    // could not place), and the help of the deepest subcommand named (M10).
    let text = e.render().to_string();
    let message = clap_message(&text);
    usage_cause(
        opv::cause::Cause::Usage {
            problem: opv::cause::UsageProblem::Rejected {
                message,
                help: help_path(&args),
            },
        },
        json,
    )
}

/// L6: `opv run ... --json` without `--preview`, which clap reports as
/// `MissingRequiredArgument`. The words before `--` name `run` and `--json` and no
/// `--preview`; the cause is the same `--json needs --preview` `misplaced_run_flag` builds.
fn json_without_preview(e: &clap::Error, args: &[String]) -> Option<opv::cause::Cause> {
    use clap::error::ErrorKind;
    use opv::cause::{Cause, UsageProblem};
    if e.kind() != ErrorKind::MissingRequiredArgument {
        return None;
    }
    let before_dashes = args.iter().take_while(|a| a.as_str() != "--");
    let mut run = false;
    let mut json = false;
    for word in before_dashes {
        match word.as_str() {
            "run" => run = true,
            "--json" => json = true,
            "--preview" => return None,
            _ => {}
        }
    }
    if !run || !json {
        return None;
    }
    Some(Cause::Usage {
        problem: UsageProblem::NeedsFlag {
            flag: "--json".into(),
            needs: "--preview".into(),
        },
    })
}

/// L6: clap's rendered error text as the `Rejected` message. The `error: ` prefix goes;
/// when the first line ends with `:`, the indented non-empty lines after it are joined
/// with `, ` and appended after a space, so a list never renders empty. Stops at the
/// first blank line (before clap's `Usage:` block).
fn clap_message(rendered: &str) -> String {
    let mut lines = rendered.lines();
    let first = lines
        .next()
        .unwrap_or_default()
        .trim_start_matches("error: ")
        .to_string();
    if !first.ends_with(':') {
        return first;
    }
    let items: Vec<&str> = lines
        .take_while(|line| !line.trim().is_empty())
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if items.is_empty() {
        first
    } else {
        format!("{first} {}", items.join(", "))
    }
}

/// The command `args` meant, when clap's error names a fix that parses (09.03, 09.83): the
/// subcommand clap suggests for a misspelt one (`stauts` → `status`), or a flag of the
/// subcommand typed before it (`--json check prod` → `check prod --json`). `None` when no
/// single correction parses.
fn corrected_command(e: &clap::Error, args: &[String]) -> Option<opv::cause::Cmd> {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    let one = |kind| match e.get(kind) {
        Some(ContextValue::String(s)) => Some(s.clone()),
        Some(ContextValue::Strings(v)) if v.len() == 1 => v.first().cloned(),
        _ => None,
    };
    let end = args.iter().position(|a| a == "--").unwrap_or(args.len());
    let fixed: Vec<String> = match e.kind() {
        ErrorKind::InvalidSubcommand => {
            let typo = one(ContextKind::InvalidSubcommand)?;
            let suggested = match e.get(ContextKind::SuggestedSubcommand) {
                Some(ContextValue::String(s)) => s.clone(),
                Some(ContextValue::Strings(v)) => {
                    opv::app::suggest::closest(&typo, v.iter().map(String::as_str))?.to_string()
                }
                _ => return None,
            };
            let at = args[..end].iter().position(|a| *a == typo)?;
            let mut fixed = args.to_vec();
            fixed[at] = suggested;
            fixed
        }
        ErrorKind::UnknownArgument => {
            let flag = one(ContextKind::InvalidArg)?;
            let flag = flag.split('=').next().unwrap_or_default().to_string();
            let root = cli_command();
            let first_sub = args[..end]
                .iter()
                .position(|a| root.find_subcommand(a).is_some())?;
            let at = args[..first_sub]
                .iter()
                .position(|a| a.split('=').next() == Some(flag.as_str()))?;
            let mut fixed = args.to_vec();
            let moved = fixed.remove(at);
            let end = fixed.iter().position(|a| a == "--").unwrap_or(fixed.len());
            fixed.insert(end, moved);
            fixed
        }
        _ => return None,
    };
    let argv = std::iter::once("opv".to_string()).chain(fixed.iter().cloned());
    cli_command().try_get_matches_from(argv).ok()?;
    // The subcommand words, then everything else, as the catalog's typed command.
    let root = cli_command();
    let mut cmd = &root;
    let (mut command, mut rest) = (Vec::new(), Vec::new());
    for a in fixed {
        match cmd.find_subcommand(&a) {
            Some(sub) if rest.iter().all(|r: &String| r.starts_with('-')) => {
                command.push(a);
                cmd = sub;
            }
            _ => rest.push(a),
        }
    }
    Some(opv::cause::Cmd {
        command,
        args: rest,
    })
}

/// A usage error opv diagnoses itself before the command runs: the cause through the one
/// renderer (stderr), and with `--json` its document on stdout.
fn usage_cause(cause: opv::cause::Cause, json: bool) -> ExitCode {
    let inv = opv::cause::Invocation::from_cli(&std::env::args().collect::<Vec<_>>());
    let _ = write!(
        opv::output::stderr(),
        "{}",
        opv::cause::render::render_text(&cause, None, &inv, false, locale_is_utf8(), false)
    );
    if json {
        let error = opv::cause::render::document(&cause, None, &inv, false);
        let doc = serde_json::json!({
            "schema_version": opv::json::SCHEMA_VERSION,
            "ok": false,
            "exit_code": cause.exit_code(),
            "next": error["next"].clone(),
            "do": error["do"].clone(),
            "error": error,
        });
        let _ = writeln!(opv::output::stdout(), "{doc}");
    }
    ExitCode::from(exit_byte(cause.exit_code()))
}

/// `opv init` given a target option removed in 0.7.0 (`--target`, `--target-name`, a
/// provider option; FR-56, FR-60): the refusal and its replacement, `opv target add` with
/// the same environment, name and options (its help when the name is not given).
fn removed_init_target(args: &[String]) -> Option<opv::cause::Cmd> {
    use opv::adapters::registry;
    use opv::provider::init_flag;
    let at = args.iter().position(|a| a == "init")?;
    let root = cli_command();
    let init = root.find_subcommand("init")?;
    let takes_value = |flag: &str| {
        init.get_arguments()
            .any(|a| a.get_long() == Some(flag) && a.get_action().takes_values())
    };
    let options: Vec<String> = registry::PROVIDERS
        .iter()
        .flat_map(|p| p.init_fields().iter().map(move |f| init_flag(*p, f)))
        .collect();
    let (mut env, mut name, mut provider) = (None, None, None);
    let mut given = Vec::new();
    let mut rest = args[at + 1..].iter();
    while let Some(a) = rest.next() {
        let Some(flag) = a.strip_prefix("--") else {
            env.get_or_insert_with(|| a.clone());
            continue;
        };
        let (flag, inline) = match flag.split_once('=') {
            Some((f, v)) => (f, Some(v.to_string())),
            None => (flag, None),
        };
        let removed =
            flag == "target" || flag == "target-name" || options.iter().any(|o| o == flag);
        if !removed {
            if inline.is_none() && takes_value(flag) {
                rest.next();
            }
            continue;
        }
        let value = inline.or_else(|| rest.next().cloned()).unwrap_or_default();
        match flag {
            "target" => provider = Some(value),
            "target-name" => name = Some(value),
            _ => given.extend([format!("--{flag}"), value]),
        }
    }
    if name.is_none() && provider.is_none() && given.is_empty() {
        return None;
    }
    let args = match (env, name) {
        (Some(env), Some(name)) => {
            let mut a = vec![env, name];
            if let Some(p) = provider {
                a.extend(["--provider".to_string(), p]);
            }
            a.extend(given);
            a
        }
        _ => vec!["--help".to_string()],
    };
    Some(opv::cause::Cmd {
        command: vec!["target".into(), "add".into()],
        args,
    })
}

/// The deepest subcommand `args` name, in order (`config check`, M10): the help a refused
/// command line points to. Empty for none (`opv --help`).
fn help_path(args: &[String]) -> Vec<String> {
    let root = cli_command();
    let mut cmd = &root;
    let mut path = Vec::new();
    for a in args {
        if let Some(sub) = cmd.get_subcommands().find(|s| s.get_name() == a) {
            path.push(a.clone());
            cmd = sub;
        }
    }
    path
}

/// The read form of a typed `opv sync …`: `opv plan` with its environment and every flag
/// `plan` takes (`--product`, `--target`, `--rotate`, `--json` and the global options),
/// in the order given. Flags only a sync takes (`--deploy`, `--prune`, `--confirm`,
/// `--expect-plan`, …) and words opv does not know (`--dry-run`) are
/// dropped. `None` when `args` is not a sync of a named environment.
fn sync_as_plan(args: &[String]) -> Option<opv::cause::Cmd> {
    const KEEP_VALUE: [&str; 6] = [
        "--product",
        "--target",
        "--rotate",
        "--config",
        "--timeout",
        "--color",
    ];
    const KEEP: [&str; 2] = ["--json", "--verbose"];
    let at = args.iter().position(|a| a == "sync")?;
    let root = cli_command();
    let sync = root.find_subcommand("sync")?;
    let takes_value = |long: &str| {
        sync.get_arguments()
            .any(|a| a.get_long() == Some(long) && a.get_action().takes_values())
    };
    let mut kept = Vec::new();
    let mut env = false;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if i - 1 == at {
            continue;
        }
        if a == "--" {
            break;
        }
        if !a.starts_with('-') {
            env |= i - 1 > at;
            kept.push(a.clone());
            continue;
        }
        let (flag, inline) = match a.split_once('=') {
            Some((f, _)) => (f, true),
            None => (a.as_str(), false),
        };
        let keep = KEEP_VALUE.contains(&flag) || KEEP.contains(&flag);
        if keep {
            kept.push(a.clone());
        }
        let value_follows =
            !inline && (KEEP_VALUE.contains(&flag) || takes_value(flag.trim_start_matches("--")));
        if value_follows && let Some(v) = args.get(i) {
            if keep {
                kept.push(v.clone());
            }
            i += 1;
        }
    }
    env.then(|| opv::cause::Cmd {
        command: vec!["plan".into()],
        args: kept,
    })
}

/// `opv run ... --verbos -- cmd`: clap takes a word it does not know as an option of
/// `run` as the start of the child command. A COMMAND whose first word starts with `-` and
/// did not come right after `--` is refused before anything runs (M8): the word is not an
/// option of `opv run` (02.09: it was before `--`, so its place is not the problem), or it
/// is `--json`, which `run` takes only with `--preview`. The child's words are never
/// repeated (SR-3); the step is `opv run --help`.
fn misplaced_run_flag(command: &[String], argv: &[String]) -> Option<Error> {
    use opv::cause::{Cause, UsageProblem};
    let first = command.first().filter(|w| w.starts_with('-'))?;
    let after_dashes = argv
        .iter()
        .position(|a| a == "--")
        .and_then(|i| argv.get(i + 1));
    if after_dashes == Some(first) {
        return None;
    }
    let problem = if first == "--json" {
        UsageProblem::NeedsFlag {
            flag: "--json".into(),
            needs: "--preview".into(),
        }
    } else {
        UsageProblem::UnknownFlag {
            flag: first.clone(),
            closest: None,
        }
    };
    Some(Cause::Usage { problem }.into())
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
            | Cmd::Changed { env, .. }
            | Cmd::Config(ConfigCmd::Export { env: Some(env), .. })
            | Cmd::Item(ItemCmd::Skeleton { env, .. })
            | Cmd::Tidy { env, .. } => Some((env, Reach::Store)),
            Cmd::Status { env: Some(env), .. } | Cmd::History { env, .. } => {
                Some((env, Reach::Target))
            }
            Cmd::Plan(a) => Some((&a.env, Reach::Target)),
            Cmd::Sync(a) => Some((&a.env, Reach::Target)),
            Cmd::Doctor { env: Some(env), .. } => Some((env, Reach::Target)),
            Cmd::Adopt { env, from, .. } if from == "target" || from.starts_with("target:") => {
                Some((env, Reach::Target))
            }
            Cmd::Adopt { env, .. } => Some((env, Reach::Store)),
            _ => None,
        }
    }

    /// The one `--target` the command names (FR-56), whose deploy credentials it signs in
    /// with; `None`: the environment's only target, when it has one. A run over several
    /// targets signs in per target itself (`app::target_runners`).
    fn target(&self) -> Option<&str> {
        match self {
            Cmd::History { target, .. } => return target.as_deref(),
            Cmd::Adopt { from, .. } => {
                return from.strip_prefix("target:").filter(|n| !n.is_empty());
            }
            _ => {}
        }
        let targets = match self {
            Cmd::Status { target, .. } => target,
            Cmd::Plan(a) => &a.target,
            Cmd::Sync(a) => &a.target,
            _ => return None,
        };
        match targets.as_slice() {
            [one] => Some(one),
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
            | Cmd::Version { json }
            | Cmd::Mcp(McpCmd::Install { json, .. })
            | Cmd::Vault(VaultCmd::Locate { json, .. })
            | Cmd::Explain { json, .. }
            | Cmd::Open { json, .. }
            | Cmd::Init { json, .. }
            | Cmd::Add { json, .. }
            | Cmd::Item(ItemCmd::Skeleton { json, .. })
            | Cmd::Bootstrap { json, .. }
            | Cmd::Ready { json, .. }
            | Cmd::History { json, .. }
            | Cmd::Tidy { json, .. }
            | Cmd::Access { json, .. }
            | Cmd::Delivery(DeliveryCmd::Verify { json, .. })
            | Cmd::Changed { json, .. }
            | Cmd::Target(TargetCmd::Add { json, .. })
            | Cmd::Target(TargetCmd::List { json, .. })
            | Cmd::Adopt { json, .. }
            | Cmd::Account(AccountCmd::List { json, .. })
            | Cmd::Account(AccountCmd::Use { json, .. })
            | Cmd::Skill(SkillCmd::Install { json, .. })
            | Cmd::Skill(SkillCmd::Status { json, .. }) => *json,
            Cmd::Plan(a) => a.json,
            Cmd::Sync(a) => a.json,
            Cmd::Schema => true,
            // With <ENV> (config-kind values) or --json (the configuration) the document is
            // printed as is; without either, the configuration is TOML text.
            Cmd::Config(ConfigCmd::Export { env, json, .. }) => {
                return (env.is_some() || *json).then_some(true);
            }
            Cmd::Env(EnvCmd::Add { json, .. })
            | Cmd::Structure(StructureCmd::Plan { json })
            | Cmd::Config(ConfigCmd::Describe { json }) => return json.then_some(true),
            // `run --preview --json` prints exactly the builder's document (no framing).
            Cmd::Run {
                preview: true,
                json: true,
                ..
            } => return Some(true),
            // #159: `opv login … -- opv … --json` that fails before its child runs (the
            // sign-in or the vault list) still answers with that command's one JSON document,
            // so error.code is readable. On success the child writes its own; login adds none.
            Cmd::Login { command, .. } => login_child_json(command),
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

/// `--product`, or else `OPV_PRODUCT` when it is non-empty. Returns the product and
/// whether it came from the variable.
fn product_or_env(flag: Option<String>, env: Option<String>) -> (Option<String>, bool) {
    match (flag, env) {
        (Some(p), _) => (Some(p), false),
        (None, Some(p)) if !p.is_empty() => (Some(p), true),
        _ => (None, false),
    }
}

/// Apply `OPV_PRODUCT` to the commands that take a product (never `sync`), and say so on
/// stderr.
fn apply_product_env(cmd: &mut Cmd, loaded: &Result<opv::domain::Fleet, Error>) {
    // Without a loaded configuration there is no product to default to.
    if loaded.is_err() {
        return;
    }
    let env = std::env::var("OPV_PRODUCT").ok();
    let used = match cmd {
        Cmd::Check { product, .. }
        | Cmd::Run { product, .. }
        | Cmd::Plan(PlanArgs { product, .. })
        | Cmd::Status { product, .. } => {
            let (p, used) = product_or_env(product.take(), env);
            *product = p;
            used.then(|| product.clone()).flatten()
        }
        Cmd::Doctor {
            env: Some(_),
            product,
            ..
        } => {
            let (p, used) = product_or_env(product.take(), env);
            *product = p;
            used.then(|| product.clone()).flatten()
        }
        Cmd::Explain {
            target: Some(t), ..
        } if !t.contains('/') => match product_or_env(None, env) {
            (Some(p), true) => {
                *t = format!("{p}/{t}");
                Some(p)
            }
            _ => None,
        },
        Cmd::Open { target, .. } if !target.contains('/') => match product_or_env(None, env) {
            (Some(p), true) => {
                *target = format!("{p}/{target}");
                Some(p)
            }
            _ => None,
        },
        _ => None,
    };
    if let Some(p) = used {
        let _ = writeln!(io::stderr(), "product {p} (from OPV_PRODUCT)");
    }
}

fn run(
    cli: Cli,
    config_source: ConfigSource,
    target_options: &std::collections::BTreeMap<String, String>,
    out: &mut dyn Write,
) -> Result<i32, Error> {
    if let Cmd::Completions { shell } = &cli.cmd {
        completions::write(*shell, &mut command_line(), out);
        return Ok(0);
    }
    // #139: the remote steps need no configuration, account or 1Password: the sender's
    // values come from `op run`, the receiver's from its stdin.
    if let Cmd::RemoteSend { plan } = &cli.cmd {
        // The plan is built by the person's own `opv run --remote`, never typed: one that
        // does not parse is opv's fault, and the step never names the hidden command (X25).
        let plan: opv::app::remote_delivery::Plan =
            serde_json::from_str(plan).map_err(|_| -> Error {
                opv::cause::Cause::Bug {
                    site: "remote-send received a plan it cannot read",
                }
                .into()
            })?;
        return opv::app::remote_delivery::send(&plan);
    }
    if let Cmd::RemoteReceive = &cli.cmd {
        return opv::app::remote_delivery::receive(Box::new(io::stdin()));
    }
    if let Cmd::Run { command, .. } = &cli.cmd {
        let argv: Vec<String> = std::env::args().collect();
        if let Some(e) = misplaced_run_flag(command, &argv) {
            return Err(e);
        }
    }
    if let Cmd::Schema = &cli.cmd {
        let doc = opv::schema::describe(&cli_command(), env!("CARGO_PKG_VERSION"));
        writeln!(out, "{doc}").map_err(write_err)?;
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
    if let Cmd::Skill(cmd) = &cli.cmd {
        return run_skill(cmd, out).map(|()| 0);
    }
    if let Cmd::Login {
        env,
        command,
        account,
        add,
        no_record,
    } = &cli.cmd
    {
        use opv::app::{login, setup_runtime};
        setup_runtime::Console::require_terminal("login")?;
        let here = std::env::current_dir().unwrap_or_default();
        let probe = ProcessRunner::new(
            Budget::starting_now(std::time::Duration::from_secs(cli.timeout)),
            cli.verbose,
        );
        // One runtime: an account added and signed in here keeps its session for the login.
        let mut runtime = setup_runtime::Runtime::default().for_command("login");
        let chosen = login::choose_account_with(
            &probe,
            account.as_deref(),
            *add,
            &here,
            &mut runtime,
            &mut setup_runtime::LoginConsole,
            !*no_record,
        )?;
        // #153: this login only, in the chosen account, whatever the project records.
        if *no_record {
            return login::run_or(
                None,
                chosen.as_deref(),
                None,
                command,
                &mut runtime,
                &mut setup_runtime::LoginConsole,
            );
        }
        // #142: before 1Password's prompt, say what in this machine's setup can make a
        // sign-in go to the wrong account (names only; never a value).
        for f in opv::app::account::gather(&probe, account.as_deref())
            .findings
            .iter()
            .filter(|f| {
                matches!(
                    f.code.as_str(),
                    "shared_sign_in_address"
                        | "session_for_other_account"
                        | "stale_session_variable"
                )
            })
        {
            let _ = writeln!(io::stderr(), "note ({}): {}", f.code, f.message);
        }
        // C18 (#159): the child's own `--config`/`--file` names the configuration (and so
        // the account) when login was given none; it is never looked up from the git remote.
        let child_config = cli
            .config
            .is_none()
            .then(|| login_child_config(command))
            .flatten();
        let fleet = match child_config {
            Some(path) => config::load_given(&path, given_by(ConfigSource::Flag)).ok(),
            None => match find_config(cli.config.as_ref(), config_source).transpose()? {
                Some(f) => Some(f),
                None => manifest_for_login(&cli, config_source),
            },
        };
        // H2 (#160): the chosen account is the one signed in to, and `.opv` records it only
        // after that sign-in succeeded.
        let fallback = chosen
            .clone()
            .or_else(|| config_store::pointer_account(&here));
        let record = chosen
            .as_deref()
            .filter(|_| login::records(&here, true))
            .map(|uuid| (here.as_path(), uuid));
        return login::run_recording(
            fleet.as_ref(),
            fallback.as_deref(),
            env.as_deref(),
            command,
            record,
            &mut runtime,
            &mut setup_runtime::LoginConsole,
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
        let start = std::env::current_dir().map_err(cwd_err)?;
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
    // FR-40, NR-7: the account recorded for this checkout (.opv) or OP_ACCOUNT; a manifest
    // found in another account replaces it below. Never op's default when one is known.
    // FR-40, NR-7: one order everywhere (OP_ACCOUNT, else .opv), resolved to an account ID;
    // never under a service-account or Connect credential.
    let here = std::env::current_dir().unwrap_or_default();
    r.use_account(config_store::selected_account_id(&r, &here)?);
    // `run` keeps default signal behaviour: the user's command under `op run` handles its
    // own signals and its exit code is passed through (FR-4). `setup` and `login` are
    // interactive and returned above.
    if !matches!(cli.cmd, Cmd::Run { .. }) {
        // The operating system refused a signal handler: nothing opv can step to.
        opv::runner::signals::install().map_err(|_| {
            Error::from(opv::cause::Cause::Bug {
                site: "main: the signal handlers could not be installed",
            })
        })?;
    }
    if let Cmd::Init { add_env: false, .. } = &cli.cmd {
        return run_init(cli, config_source, &r, out).map(|()| 0);
    }
    match &cli.cmd {
        Cmd::Env(EnvCmd::Add { environment, json }) => {
            return opv::app::structure_cmd::env_add(&r, &here, environment, *json, out)
                .map(|()| 0);
        }
        Cmd::Structure(StructureCmd::Plan { json }) => {
            // Read and write the project's own 1Password account, never op's default.
            r.use_account(Some(opv::app::structure::scope(&here, &r)?.account));
            return opv::app::structure_cmd::plan(&r, &here, *json, out).map(|()| 0);
        }
        Cmd::Projects {
            account,
            long,
            json,
        } => {
            let account = account.clone().or_else(config_store::account_env);
            return config_cmd::projects(&r, account.as_deref(), *long, *json, out).map(|()| 0);
        }
        #[cfg(feature = "ui")]
        Cmd::Ui => {
            let exe = std::env::current_exe().map_err(exe_err)?;
            let source = opv::ui::run::Exe {
                exe,
                config: cli.config.clone(),
            };
            return opv::ui::run::run(source, out);
        }
        Cmd::Bootstrap {
            file,
            project,
            dry_run,
            rebind,
            ci_reader,
            json,
        } => {
            let here = std::env::current_dir().unwrap_or_default();
            let path = match file.clone().or_else(|| cli.config.clone()) {
                Some(p) => p,
                None => match config_store::walk_up(&here, "secrets.toml") {
                    Some(p) => p,
                    None => return Err(bootstrap_without_file(&cli, config_source, &r, &here)),
                },
            };
            let project = match project {
                Some(p) => p.clone(),
                None => config_store::default_project(
                    None,
                    config_store::git_repo(&r).as_deref(),
                    &here,
                )?,
            };
            let opts = opv::app::bootstrap::Opts {
                dry_run: *dry_run,
                rebind: rebind.iter().cloned().collect(),
                ci_reader: ci_reader.clone(),
                json: *json,
            };
            return opv::app::bootstrap::run(&path, &project, &opts, &r, out).map(|()| 0);
        }
        Cmd::LocalDelivery {
            keys,
            declared_only,
            dir_env,
            files,
            command,
        } => {
            let files = files
                .iter()
                .map(|f| {
                    f.split_once('=')
                        .map(|(k, p)| (k.to_string(), p.to_string()))
                        .ok_or_else(|| -> Error {
                            opv::cause::Cause::Bug {
                                site: "local-delivery received a --file without KEY=path",
                            }
                            .into()
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let d = opv::app::local_delivery::Delivery {
                keys: keys.clone(),
                declared_only: *declared_only,
                files,
                dir_env: dir_env.clone(),
                command: command.clone(),
            };
            return opv::app::local_delivery::run(&d);
        }
        Cmd::Mcp(McpCmd::Serve { .. }) => unreachable!("served before stdout is locked"),
        Cmd::Mcp(McpCmd::Install {
            client,
            project,
            name,
            force,
            json,
        }) => {
            return mcp_install(&r, *client, project.as_deref(), name, *force, *json, out)
                .map(|()| 0);
        }
        Cmd::Vault(VaultCmd::Locate { vault, json }) => {
            return opv::app::vault_locate::run(&r, vault, *json, out).map(|()| 0);
        }
        Cmd::Version { json } => {
            let here = std::env::current_dir().unwrap_or_default();
            return opv::app::version::run(&r, cli.config.as_deref(), &here, *json, out)
                .map(|()| 0);
        }
        Cmd::Account(AccountCmd::List { account, json }) => {
            return opv::app::account::list(&r, account.as_deref(), *json, out).map(|()| 0);
        }
        Cmd::Account(AccountCmd::Use { who, json }) => {
            return opv::app::account::use_command(&r, who, *json, out).map(|()| 0);
        }
        Cmd::Status {
            all: true,
            json,
            product,
            ..
        } => {
            let (product, used) =
                product_or_env(product.clone(), std::env::var("OPV_PRODUCT").ok());
            if used && let Some(p) = &product {
                let _ = writeln!(io::stderr(), "product {p} (from OPV_PRODUCT)");
            }
            let account = config_store::account_env();
            return config_cmd::status_all(&r, account.as_deref(), product.as_deref(), *json, out)
                .map(|()| 0);
        }
        Cmd::Config(ConfigCmd::Import { .. }) | Cmd::Config(ConfigCmd::Check { .. }) => {
            return run_config_manifest(cli, &r, out).map(|()| 0);
        }
        _ => {}
    }
    // A missing config is a configuration error for the command, not an early exit, so
    // `doctor` still runs its other checks on a fresh machine.
    let found = request(&cli, config_source, false).and_then(|req| config_store::locate(&req, &r));
    // A manifest found in a chosen account: every later op call uses that account.
    if let Ok(config_store::Found::Manifest(m)) = &found
        && m.account.is_some()
    {
        r.use_account(m.account.clone());
    }
    if let Ok(f) = &found
        && let Some(line) = f.announce(cli.verbose)
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
    if let Cmd::Init { add_env: true, .. } | Cmd::Add { .. } | Cmd::Target(TargetCmd::Add { .. }) =
        &cli.cmd
    {
        return run_edit(cli.cmd, &found?, target_options, &r, out).map(|()| 0);
    }
    // `target credentials` mints the provider token and records the new item's reference in
    // the local secrets.toml (a manifest has no file to edit): FR-40.
    if let Cmd::Target(TargetCmd::Credentials {
        env,
        target,
        create,
    }) = &cli.cmd
    {
        let found = found?;
        let fleet = found.load(&r)?;
        if !create {
            return target_credentials::show(&fleet, env, target, &r, out).map(|()| 0);
        }
        // Refused before the terminal gate and before anything is minted: `--create`
        // records the new item's reference in a secrets.toml, which a manifest project
        // does not have, so no fix makes this command succeed there (02.01).
        let path = match &found {
            config_store::Found::File { store, .. } => store.path.clone(),
            config_store::Found::Manifest(m) => return Err(credentials_need_a_file(&m.title)),
        };
        opv::app::setup_runtime::Console::require_terminal("target credentials --create")?;
        let project =
            opv::app::personal::project_name(&r, &std::env::current_dir().unwrap_or_default());
        return target_credentials::run(
            &fleet,
            &path,
            env,
            target,
            &project,
            &r,
            &mut opv::app::setup_runtime::Console,
            out,
        )
        .map(|()| 0);
    }
    // D2 (A10): steps a manifest project refuses (file-only commands) are never rendered.
    if let Ok(config_store::Found::Manifest(m)) = &found {
        opv::cause::situation::note_config_source(opv::cause::ConfigSource::Manifest {
            title: m.title.clone(),
            vault: opv::cause::VaultId::new(&m.vault_id),
            project: m
                .title
                .strip_prefix("opv · ")
                .unwrap_or(&m.title)
                .to_string(),
        });
    }
    // The project's account (its manifest's, or the one recorded in .opv): `doctor`
    // without --env checks the sign-in of that account, never op's default (FR-40).
    let run_account = match &found {
        Ok(config_store::Found::Manifest(m)) => m.account.clone(),
        _ => None,
    }
    .or(config_store::selected_account_id(
        &r,
        &account_start(match &found {
            Ok(config_store::Found::File { store, .. }) => Some(store.path.as_path()),
            _ => None,
        }),
    )?);
    r.use_account(run_account.clone());
    let loaded = found.and_then(|f| f.load(&r));
    let mut cmd = cli.cmd;
    // 09.03b: no configuration at all starts the environment the command named.
    let env_named = cmd.env().map(|(e, _)| e.to_string());
    let loaded = loaded.map_err(|e| init_for(e, env_named.as_deref()));
    apply_product_env(&mut cmd, &loaded);
    // Every call for the environment uses its 1Password account, and commands that reach
    // the target sign in with its deploy credentials for this run only (FR-40). Dropped
    // (signed out, its private directory removed) when this function returns.
    // `doctor --env` signs in per target itself, so one target's failed sign-in never
    // stops another; the runner here only carries the environment's account.
    let env_runner = match (&loaded, cmd.env()) {
        (Ok(fleet), Some((env, _))) if matches!(cmd, Cmd::Doctor { .. }) => Some(
            signin::open_targeted(fleet, env, None, &r, signin::Reach::Store)?,
        ),
        (Ok(fleet), Some((env, reach))) => {
            Some(signin::open_targeted(fleet, env, cmd.target(), &r, reach)?)
        }
        (_, None) if matches!(cmd, Cmd::Doctor { .. }) && run_account.is_some() => {
            Some(signin::EnvRunner::with_account(&r, run_account))
        }
        _ => None,
    };
    let runner: &dyn CommandRunner = match &env_runner {
        Some(e) => e,
        None => &r,
    };
    if let Cmd::Run {
        env,
        product,
        role,
        preview,
        json,
        remote,
        confirm,
        command,
    } = &cmd
    {
        if *preview {
            if !command.is_empty() {
                return Err(opv::cause::Cause::Usage {
                    problem: opv::cause::UsageProblem::ConflictsWith {
                        a: "--preview".into(),
                        b: "-- <command>".into(),
                    },
                }
                .into());
            }
            opv::app::delivery_preview::preview_for(
                &loaded?,
                env,
                product.as_deref(),
                role.as_deref(),
                remote.as_deref(),
                *json,
                runner,
                out,
            )?;
            return Ok(0);
        }
        let fleet = loaded?;
        if let Some(profile) = remote {
            if !command.is_empty() {
                return Err(opv::cause::Cause::Usage {
                    problem: opv::cause::UsageProblem::ConflictsWith {
                        a: "--remote".into(),
                        b: "-- <command>".into(),
                    },
                }
                .into());
            }
            // #139: values leave this machine only when a person runs it in their terminal;
            // no MCP tool or flag runs a remote delivery. 09.42: the profile is checked first.
            run_cmd::check_remote(&fleet, env, product.as_deref(), role.as_deref(), profile)?;
            opv::app::setup_runtime::Console::require_terminal("run --remote")?;
            let mut retry = confirm_retry(env, product.as_deref(), role.as_deref());
            retry.push_str(&format!(" --remote {}", shell_word(profile)));
            run_cmd::require_confirmation(&fleet, env, confirm.as_deref(), &retry)?;
            return run_cmd::run_remote(
                &fleet,
                env,
                product.as_deref(),
                role.as_deref(),
                profile,
                runner,
            );
        }
        // The child's words are never repeated (SR-3, 02.10): they may hold a credential.
        let retry = format!(
            "{} -- <command>",
            confirm_retry(env, product.as_deref(), role.as_deref())
        );
        run_cmd::require_confirmation(&fleet, env, confirm.as_deref(), &retry)?;
        return run_cmd::run_for(
            &fleet,
            env,
            product.as_deref(),
            role.as_deref(),
            command,
            runner,
        );
    }
    if let Cmd::Changed {
        env,
        product,
        target,
        json,
    } = &cmd
    {
        let fleet = loaded?;
        return opv::app::changed::run(&fleet, env, product.as_deref(), target, runner, *json, out);
    }
    run_other(cmd, loaded, source.as_deref(), runner, out).map(|()| 0)
}

/// `opv run <env> --confirm <env>` with the run's `--product` and `--role`: the person's
/// confirmed run. The caller adds `--remote <profile>` or `-- <command>`, never the
/// child's own words.
fn confirm_retry(env: &str, product: Option<&str>, role: Option<&str>) -> String {
    let mut retry = format!("opv run {} --confirm {}", shell_word(env), shell_word(env));
    if let Some(p) = product {
        retry.push_str(&format!(" --product {}", shell_word(p)));
    }
    if let Some(r) = role {
        retry.push_str(&format!(" --role {}", shell_word(r)));
    }
    retry
}

/// `opv skill install` / `opv skill status`: the agent skill embedded in this binary
/// (FR-52). No configuration, no subprocess and no secret value is involved.
fn run_skill(cmd: &SkillCmd, out: &mut dyn Write) -> Result<(), Error> {
    use opv::app::skill;
    let version = env!("CARGO_PKG_VERSION");
    match cmd {
        SkillCmd::Install {
            target,
            user,
            project,
            force,
            json,
        } => {
            let root = skill_root(*user, project.as_deref(), *target, *force)?;
            let installed = skill::install(&root, &target.targets(), version, *force)?;
            if *json {
                writeln!(out, "{}", skill::install_document(&installed)?).map_err(write_err)?;
            } else {
                for (_, path) in &installed.written {
                    writeln!(out, "installed {} (opv {version})", path.display())
                        .map_err(write_err)?;
                }
                for (_, path) in &installed.kept {
                    writeln!(
                        out,
                        "kept {}: edited by hand; --force replaces it",
                        path.display()
                    )
                    .map_err(write_err)?;
                }
                writeln!(out, "Next: opv guide agent").map_err(write_err)?;
            }
        }
        SkillCmd::Status { json } => {
            let copies = skill::status(&skill::roots(), version);
            if *json {
                writeln!(out, "{}", skill::status_document(&copies)?).map_err(write_err)?;
            } else {
                write_skill_status(&copies, out)?;
            }
        }
    }
    Ok(())
}

/// The text lines of `opv skill status`: one per copy, then, for each scope with an
/// unedited copy older than this binary, the install that updates that scope (FR-52,
/// 02.11: a project copy is updated with `--project <root>`, never `--user`). The skill is
/// written only on install, so an outdated copy stays outdated until then (design §12.4).
fn write_skill_status(copies: &[opv::app::skill::Copy], out: &mut dyn Write) -> Result<(), Error> {
    if copies.is_empty() {
        writeln!(out, "no agent skill installed\nNext: opv skill install").map_err(write_err)?;
        return Ok(());
    }
    for copy in copies {
        let state = if copy.edited {
            "edited"
        } else if copy.current {
            "current"
        } else {
            "older"
        };
        writeln!(
            out,
            "{} {} {} opv {} {state}",
            copy.scope,
            copy.target.as_str(),
            copy.path.display(),
            copy.version.as_deref().unwrap_or("unknown"),
        )
        .map_err(write_err)?;
    }
    for update in opv::app::skill::update_commands(copies) {
        writeln!(out, "run {update} to update").map_err(write_err)?;
    }
    Ok(())
}

/// The root `opv skill install` writes under: the home for `--user`, the given project
/// directory, or this checkout's git top level.
///
/// With no home directory (a container, a systemd unit or a CI job) the step is the same
/// install into the current directory, named by its absolute path so it runs as typed
/// (02.02: `--project .` was never treated as runnable), with `--target` and `--force` kept.
/// No catalog cause names a missing home directory yet, so this stays Legacy.
fn skill_root(
    user: bool,
    project: Option<&std::path::Path>,
    target: SkillTarget,
    force: bool,
) -> Result<PathBuf, Error> {
    if user {
        return opv::app::skill::user_root().ok_or_else(|| {
            let here = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            home_missing(&here, target, force)
        });
    }
    Ok(project
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(opv::app::skill::project_root))
}

/// `opv skill install --user` with neither HOME nor USERPROFILE set (02.02): the install
/// goes into this project instead, named by its absolute path so it runs as typed.
fn home_missing(here: &std::path::Path, target: SkillTarget, force: bool) -> Error {
    let mut args = vec!["--project".to_string(), here.display().to_string()];
    match target {
        SkillTarget::Claude => args.extend(["--target".into(), "claude".into()]),
        SkillTarget::Codex => args.extend(["--target".into(), "codex".into()]),
        SkillTarget::All => {}
    }
    if force {
        args.push("--force".into());
    }
    opv::cause::Cause::Usage {
        problem: opv::cause::UsageProblem::UseInstead {
            command: opv::cause::Cmd {
                command: vec!["skill".into(), "install".into()],
                args,
            },
        },
    }
    .into()
}

/// opv's own local input or output failed (`LocalIo`): the folder, its program file, the
/// home folder or the output stream. No path is named; the operation says which.
fn local_io(op: opv::cause::LocalOp, kind: io::ErrorKind) -> Error {
    opv::cause::Cause::LocalIo {
        op,
        path: PathBuf::new(),
        io: kind.into(),
    }
    .into()
}

/// A failed write to the output stream, for every write in this file (02.29: one cause).
fn write_err(e: io::Error) -> Error {
    local_io(opv::cause::LocalOp::Stdout, e.kind())
}

/// The current directory cannot be read (deleted under the shell, or no permission).
fn cwd_err(e: io::Error) -> Error {
    local_io(opv::cause::LocalOp::CurrentDir, e.kind())
}

/// The path of this opv binary cannot be found.
fn exe_err(e: io::Error) -> Error {
    local_io(opv::cause::LocalOp::CurrentExe, e.kind())
}

/// Where a given configuration path came from (C13, 03.12): an unreadable file names the
/// flag or the variable that gave it.
fn given_by(config_source: ConfigSource) -> opv::cause::GivenBy {
    match config_source {
        ConfigSource::Flag => opv::cause::GivenBy::Flag {
            flag: "--config".into(),
        },
        ConfigSource::Env => opv::cause::GivenBy::EnvVar {
            var: opv::cause::VarName::new("OPV_CONFIG"),
        },
        ConfigSource::Discovered => opv::cause::GivenBy::Discovered,
    }
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
            Some(config::load_given(path, given_by(config_source)))
        }
        None => match std::env::current_dir() {
            Err(e) => Some(Err(cwd_err(e))),
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
    let start = std::env::current_dir().map_err(cwd_err)?;
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
    let dir = std::env::current_dir().map_err(cwd_err)?;
    match cli.cmd {
        Cmd::Config(ConfigCmd::Import {
            file,
            vault,
            project,
            paths,
        }) => {
            let file = match file {
                Some(f) => f,
                // The command must change (it needs --file), so the step is its help, never
                // the same command again (02.12).
                None => config::discover(&dir).ok_or_else(|| import_needs_file(&dir))?,
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
                start: dir.clone(),
                config: None,
                project: config_store::project_env(),
                manifest_only: true,
                account: config_store::account_env(),
            };
            // The file is right here; what is missing is the manifest to compare it with (M9).
            let found = config_store::locate(&req, r).map_err(|e| match e.code_str() {
                "config_not_found" => manifest_missing_for_check(&dir),
                _ => e,
            })?;
            config_cmd::check(&found, &file, r, out)
        }
        _ => unreachable!("called for config import and check only"),
    }
}

/// `opv config import` without `--file` and with no secrets.toml here or above (02.12).
fn import_needs_file(dir: &std::path::Path) -> Error {
    opv::cause::Cause::Usage {
        problem: opv::cause::UsageProblem::NeedsFlag {
            flag: format!(
                "opv config import (no secrets.toml in {} or any folder above it)",
                dir.display()
            ),
            needs: "--file <path>".into(),
        },
    }
    .into()
}

/// `config check --file F` with no manifest for this checkout (M9): the project it looked
/// for (OPV_PROJECT, else the folder's name) and the account it looked in.
fn manifest_missing_for_check(dir: &std::path::Path) -> Error {
    let project = config_store::project_env()
        .or_else(|| config_store::default_project(None, None, dir).ok())
        .unwrap_or_else(|| dir.display().to_string());
    opv::cause::Cause::ManifestNotFound {
        project,
        account: config_store::account_env().map(opv::cause::AccountId::new),
    }
    .into()
}

/// `opv target credentials --create` on a manifest project (02.01): it records the new
/// item's reference in a secrets.toml, so it does not apply to a manifest; nothing was
/// minted. The step is the manifest's own editor, never the same command again.
fn credentials_need_a_file(manifest: &str) -> Error {
    opv::cause::Cause::ConfigSourceMismatch {
        command: opv::cause::CommandId("target credentials --create".into()),
        manifest: manifest.to_string(),
    }
    .into()
}

/// `opv bootstrap` with no secrets.toml here or above (02.15): when this project's
/// configuration is a 1Password manifest, bootstrap (which completes a secrets.toml) does
/// not apply to it; otherwise there is no configuration at all. Never `opv init --file`,
/// which would start a second configuration beside a manifest.
fn bootstrap_without_file(
    cli: &Cli,
    config_source: ConfigSource,
    r: &dyn CommandRunner,
    here: &std::path::Path,
) -> Error {
    let found = request(cli, config_source, true).and_then(|req| config_store::locate(&req, r));
    // The lookup's own failure is not this command's error.
    let _ = opv::runner::take_failure_excerpt();
    let _ = opv::runner::take_observed();
    match found {
        Ok(config_store::Found::Manifest(m)) => opv::cause::Cause::ConfigSourceMismatch {
            command: opv::cause::CommandId("bootstrap".into()),
            manifest: m.title,
        }
        .into(),
        _ => opv::cause::Cause::ConfigNotFound {
            searched_from: here.to_path_buf(),
            env: None,
            manifest: None,
        }
        .into(),
    }
}

fn run_other(
    cmd: Cmd,
    loaded: Result<opv::domain::Fleet, Error>,
    source: Option<&str>,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    match cmd {
        Cmd::Setup { .. } => unreachable!("handled before configuration discovery"),
        Cmd::Login { .. } => unreachable!("handled before configuration discovery"),
        Cmd::Run { .. } => unreachable!("handled by run"),
        Cmd::Changed { .. } => unreachable!("handled by run"),
        Cmd::Init { .. } => unreachable!("handled by run_init"),
        Cmd::Add { .. } => unreachable!("handled by run_edit"),
        Cmd::Target(TargetCmd::Add { .. }) => unreachable!("handled by run_edit"),
        Cmd::Target(TargetCmd::Credentials { .. }) => unreachable!("handled by run"),
        Cmd::Completions { .. }
        | Cmd::Guide { .. }
        | Cmd::Skill(_)
        | Cmd::Projects { .. }
        | Cmd::Account(_)
        | Cmd::Bootstrap { .. }
        | Cmd::Version { .. }
        | Cmd::Mcp(_)
        | Cmd::Vault(_)
        | Cmd::Env(_)
        | Cmd::Structure(_)
        | Cmd::LocalDelivery { .. }
        | Cmd::RemoteSend { .. }
        | Cmd::RemoteReceive
        | Cmd::Schema
        | Cmd::Help { .. } => {
            unreachable!("handled by run")
        }
        #[cfg(feature = "ui")]
        Cmd::Ui => unreachable!("handled by run"),
        Cmd::Doctor {
            env,
            product,
            target,
            json,
            settings,
        } => {
            let scope = doctor::Request {
                env: env.as_deref(),
                product: product.as_deref(),
                json,
                source,
                targets: &target,
                settings,
            };
            doctor::run_request(loaded, scope, r, out)
        }
        Cmd::Check { env, product, json } => {
            opv::app::local::check(&loaded?, &env, product.as_deref(), r, out, json)
        }
        Cmd::Adopt {
            env,
            from,
            replace,
            rotate,
            skip,
            apply,
            json,
        } => {
            let fleet = loaded?;
            let source = opv::app::import::source_from(&fleet, &env, &from)?;
            let opts = opv::app::import::Opts {
                source,
                replace,
                rotate,
                skip,
                dry_run: !apply,
                json,
            };
            opv::app::import::run(&fleet, &env, &opts, r, out)
        }
        Cmd::History { env, target, json } => {
            opv::app::history::run(&loaded?, &env, target.as_deref(), r, json, out)
        }
        Cmd::Target(TargetCmd::List { env, json }) => {
            target_cmd::list(&loaded?, &target_cmd::ListArgs { env, json }, out)
        }
        Cmd::Tidy { env, json } => opv::app::repair::run(&loaded?, &env, r, json, out),
        Cmd::Access {
            env: Some(env),
            target,
            project,
            create: true,
            github: Some(repo),
            github_env,
            secret_name,
            ..
        } => {
            opv::app::setup_runtime::Console::require_terminal("access --create")?;
            let dir = std::env::current_dir().unwrap_or_default();
            let project = match project.as_deref() {
                Some(name) => config_store::default_project(Some(name), None, &dir)?,
                None => opv::app::personal::project_name(r, &dir),
            };
            let req = opv::app::access_create::Request {
                env: &env,
                target: target.as_deref(),
                project: &project,
                github: opv::app::access_create::GitHub {
                    repo,
                    environment: github_env,
                    secret: secret_name,
                },
            };
            opv::app::access_create::run(
                &loaded?,
                &req,
                r,
                &mut opv::app::setup_runtime::Console,
                out,
            )
        }
        Cmd::Access {
            env,
            target,
            project,
            json,
            ..
        } => opv::app::access::run(
            &loaded?,
            env.as_deref(),
            target.as_deref(),
            project.as_deref(),
            r,
            json,
            out,
        ),
        Cmd::Generate { env, keys } => opv::app::generate::run(&loaded?, &env, &keys, r, out),
        Cmd::Delivery(DeliveryCmd::Verify {
            env,
            product,
            target,
            receipt,
            json,
        }) => opv::app::delivery::verify(
            &loaded?,
            &env,
            product.as_deref(),
            &target,
            receipt.as_deref(),
            r,
            json,
            out,
        ),
        Cmd::Ci(CiCmd::Workflow {
            env,
            target,
            github_env,
            deploy,
            on_change,
            drift,
            every,
        }) => {
            if on_change {
                opv::app::ci_workflow::run_on_change(&loaded?, every, out)
            } else if drift {
                opv::app::ci_workflow::run_drift(&loaded?, out)
            } else {
                match (env.as_deref(), target.as_deref()) {
                    (Some(env), Some(target)) => opv::app::ci_workflow::run(
                        &loaded?,
                        env,
                        target,
                        github_env.as_deref(),
                        deploy,
                        out,
                    ),
                    _ => Err(opv::cause::Cause::Usage {
                        problem: opv::cause::UsageProblem::NeedsFlag {
                            flag: "ci workflow".into(),
                            needs: "an environment and --target, or --on-change/--drift".into(),
                        },
                    }
                    .into()),
                }
            }
        }
        Cmd::Ready {
            env,
            json,
            save,
            gate,
        } => opv::app::ready::run(
            &loaded?,
            source,
            env.as_deref(),
            r,
            json,
            save.as_deref(),
            gate,
            out,
        ),
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
            target,
            fail_on_drift,
            ..
        } => status::run_targeted(
            &loaded?,
            &env,
            &target,
            product.as_deref(),
            r,
            out,
            json,
            fail_on_drift,
        )
        // An adapter's cause names the environment the command ran for (L10 follow-up).
        .map_err(|e| e.in_env(&env)),
        Cmd::Plan(a) => sync::plan_rotating(
            &loaded?,
            &a.env,
            &a.target,
            a.product.as_deref(),
            &a.rotate,
            r,
            out,
            a.json,
        )
        .map_err(|e| e.in_env(&a.env)),
        Cmd::Sync(a) => {
            let env = a.env.clone();
            sync::run(&loaded?, &env, r, out, &a.into()).map_err(|e| e.in_env(&env))
        }
        Cmd::Config(ConfigCmd::Export { env: Some(env), .. }) => {
            config_export::run(&loaded?, &env, r, out)
        }
        Cmd::Config(ConfigCmd::Describe { json }) => {
            opv::app::structure_cmd::config_describe(&loaded?, json, out)
        }
        // Reached only when discovery failed: its error is the result.
        Cmd::Config(_) => loaded.map(|_| ()),
        Cmd::Item(ItemCmd::Skeleton { env, json }) => {
            skeleton::run_as(&loaded?, &env, r, out, json)
        }
        Cmd::Explain {
            target,
            target_name,
            env,
            project,
            json,
        } => {
            let asked = match &target_name {
                Some(name) => explain::Asked::Target(name),
                None => explain::Asked::Key(target.as_deref().unwrap_or_default()),
            };
            let project = match project {
                Some(p) => p.clone(),
                None => {
                    let here = std::env::current_dir().unwrap_or_default();
                    opv::app::personal::project_name(r, &here)
                }
            };
            explain::run_request(&loaded?, &asked, env.as_deref(), &project, out, json)
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
    let write =
        |out: &mut dyn Write, text: &str| writeln!(out, "{}", text.trim_end()).map_err(write_err);
    if topic.len() == 1 && topic[0] == "states" {
        return write(out, STATES_HELP);
    }
    let mut cmd = cli_command();
    // Built first, so a subcommand's usage line reads `opv <command>`.
    cmd.build();
    let mut current = &mut cmd;
    for (depth, t) in topic.iter().enumerate() {
        // The topics a person can ask for here: visible commands only, and `states` at
        // the top level only (02.22).
        let mut names: Vec<String> = Vec::new();
        if depth == 0 {
            names.push("states".into());
        }
        names.extend(
            current
                .get_subcommands()
                .filter(|c| !c.is_hide_set())
                .map(|c| c.get_name().to_string()),
        );
        match current.find_subcommand_mut(t) {
            Some(sub) if !sub.is_hide_set() => current = sub,
            _ => {
                return Err(opv::cause::Cause::NotDeclared {
                    kind: opv::cause::NameKind::HelpTopic,
                    given: t.clone(),
                    candidates: names,
                    closest: None,
                }
                .into());
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
    r: &ProcessRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let json = matches!(cli.cmd, Cmd::Init { json: true, .. });
    // init writes ./secrets.toml (with --file, or when one exists here) or a manifest, and
    // never the configuration --config names: `--add-env` adds an environment to that one.
    // The step is init's help, which says so, never a rebuilt command that drops flags
    // (02.13).
    if cli.config.is_some() {
        return Err(init_takes_no_config(config_source));
    }
    let dir = std::env::current_dir().map_err(cwd_err)?;
    let (file, project, account) = match &cli.cmd {
        Cmd::Init {
            file,
            project,
            account,
            ..
        } => (*file, project.clone(), account.clone()),
        _ => unreachable!("called for init only"),
    };
    // --from without --apply: the plan only, before any 1Password call or file (#90).
    if let Cmd::Init {
        from: Some(_),
        apply: false,
        ..
    } = &cli.cmd
    {
        let args = init_args(cli.cmd, r, &dir)?;
        let from = args.from.as_ref().expect("matched --from");
        let imported = init::read_from(from)?;
        let again = init_from_again(&args, file, project.as_deref());
        return init::plan_from(&args, &imported, &again, out, json);
    }
    // FR-40, NR-7: every op call of init goes to one chosen account, never op's default
    // when several accounts are on this machine; a choice given here is recorded in .opv.
    let given = account
        .clone()
        .or_else(|| config_store::pointer_account(&dir))
        .or_else(config_store::account_env);
    let chosen = config_store::pick_account(r, given)?;
    if account.is_some()
        && let Some(a) = &chosen
    {
        let path = config_store::record_account(&dir, a)?;
        if !json {
            writeln!(
                out,
                "using 1Password account {a}; recorded in {} (commit it)",
                path.display()
            )
            .map_err(write_err)?;
        }
    }
    let scoped = signin::EnvRunner::with_account(r, chosen);
    let args = init_args(cli.cmd, &scoped, &dir)?;
    // A project that already has a secrets.toml keeps it; a new one gets a manifest
    // unless --file asks for the file (FR-44).
    if file || config::discover(&dir).is_some() {
        init::run_as(&args, &dir, &scoped, out, json)
    } else {
        init::run_manifest(&args, project.as_deref(), &dir, &scoped, out, json)
    }
}

/// `opv init` given `--config` or `OPV_CONFIG` (02.13).
fn init_takes_no_config(config_source: ConfigSource) -> Error {
    let given = if config_source == ConfigSource::Env {
        "OPV_CONFIG"
    } else {
        "--config"
    };
    opv::cause::Cause::Usage {
        problem: opv::cause::UsageProblem::ConflictsWith {
            a: "opv init".into(),
            b: given.into(),
        },
    }
    .into()
}

/// The `opv init … --from <file> --apply` that carries out a `--from` plan (#90).
fn init_from_again(args: &init::InitArgs, file: bool, project: Option<&str>) -> String {
    let from = args.from.as_ref().expect("called with --from");
    let mut c = format!(
        "opv init {} --vault {} --item {}",
        shell_word(&args.env),
        shell_word(&args.vault),
        shell_word(&args.item)
    );
    if let Some(p) = &args.product {
        c.push_str(&format!(" --product {}", shell_word(p)));
    }
    if file {
        c.push_str(" --file");
    }
    if let Some(p) = project {
        c.push_str(&format!(" --project {}", shell_word(p)));
    }
    c.push_str(&format!(
        " --from {}",
        shell_word(&from.path.display().to_string())
    ));
    for k in &from.config {
        c.push_str(&format!(" --config-key {k}"));
    }
    for k in &from.secret {
        c.push_str(&format!(" --secret-key {k}"));
    }
    c.push_str(" --apply");
    c
}

/// `add` and `init --add-env`: edit the configuration where it was found (a file or a
/// manifest) in place, through its [`config_store::ConfigStore`].
fn run_edit(
    cmd: Cmd,
    found: &config_store::Found,
    target_options: &std::collections::BTreeMap<String, String>,
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
            from,
            personal,
            allow_same_value,
            json,
        } => add::run(
            &add::AddArgs {
                name,
                kind,
                envs: env,
                rules: rule,
                guidance,
                immutable,
                from,
                personal,
                allow_same_value,
                json,
            },
            store,
            r,
            out,
        ),
        cmd @ Cmd::Init { json, .. } => {
            let dir = std::env::current_dir().map_err(cwd_err)?;
            init::add_env_as(&init_args(cmd, r, &dir)?, store, r, out, json)
        }
        Cmd::Target(TargetCmd::Add {
            env,
            name,
            provider,
            products,
            roles,
            deploy_credentials,
            project,
            dry_run,
            json,
        }) => target_cmd::add(
            &target_cmd::AddArgs {
                env,
                name,
                provider,
                fields: target_options.clone(),
                products,
                roles,
                deploy_credentials,
                project,
                dry_run,
                json,
            },
            store,
            r,
            out,
        ),
        _ => unreachable!("called for add, init --add-env and target add only"),
    }
}

/// The init arguments, with the vault and item titles defaulted to the boundary titles
/// (FR-57) of `--product` (else `core`) and the project name (`--project`, else the
/// repository's, else the directory's) when not given: `opv init dev --product api` alone
/// is enough.
fn init_args(
    cmd: Cmd,
    r: &dyn opv::runner::CommandRunner,
    dir: &std::path::Path,
) -> Result<init::InitArgs, Error> {
    let Cmd::Init {
        env,
        vault,
        item,
        product,
        add_env: _,
        force,
        file: _,
        project,
        json: _,
        account: _,
        from,
        config_key,
        secret_key,
        apply,
    } = cmd
    else {
        unreachable!("called for init only")
    };
    let (vault, item) = match (vault, item) {
        (Some(v), Some(i)) => (v, i),
        (vault, item) => {
            let repo = config_store::git_repo(r);
            let name = config_store::default_project(project.as_deref(), repo.as_deref(), dir)?;
            let boundary = product.as_deref().unwrap_or(init::SHARED_BOUNDARY);
            (
                vault.unwrap_or_else(|| opv::domain::naming::boundary_vault(&name, boundary, &env)),
                item.unwrap_or_else(|| opv::domain::naming::boundary_item(&name, boundary, &env)),
            )
        }
    };
    Ok(init::InitArgs {
        env,
        vault,
        item,
        product,
        force,
        from: from.map(|path| init::FromFile {
            path,
            config: config_key,
            secret: secret_key,
            apply,
        }),
    })
}

/// Sign in to this checkout's 1Password account (its `.opv`, else `OP_ACCOUNT`, else op's
/// choice) at op's own prompt, for the rest of this process; `false` when no person is at
/// a terminal to do it (no TTY, CI, a service account or Connect) or the sign-in failed,
/// so the original error stands. The password goes only to op; the session stays in this
/// process ([`opv::runner::use_op_session`]).
fn sign_in_here() -> Result<bool, Error> {
    use opv::app::setup::Backend as _;
    use opv::app::setup_runtime::{Console, Runtime};
    if Console::require_terminal("").is_err() || !io::IsTerminal::is_terminal(&io::stderr()) {
        return Ok(false);
    }
    let here = std::env::current_dir().unwrap_or_default();
    // The account of the op call that found no session (0.9.0), else the selected one.
    let account =
        opv::runner::signed_out_account().or_else(|| config_store::selected_account(&here));
    eprintln!(
        "You are not signed in to 1Password (a session also ends after 30 minutes idle). Sign \
         in to go on; your password goes only to 1Password's prompt."
    );
    let command = std::env::args().nth(1).unwrap_or_else(|| "opv".into());
    let mut runtime = Runtime::with_account(account.as_deref()).for_command(&command);
    runtime.sign_in(account.as_deref(), false)?;
    opv::runner::use_op_session(runtime.into_session());
    Ok(true)
}

/// `--project` of `opv mcp serve` / `opv mcp install` is not a directory opv can enter.
fn project_dir_err() -> Error {
    opv::cause::Cause::Usage {
        problem: opv::cause::UsageProblem::ValueFormat {
            flag: "--project".into(),
            format: "an existing directory opv can enter",
        },
    }
    .into()
}

/// Clamp an exit code to the 1..=255 range a process can report; failures never become 0.
fn exit_byte(code: i32) -> u8 {
    match u8::try_from(code) {
        Ok(0) | Err(_) => 1,
        Ok(b) => b,
    }
}

/// `opv mcp serve --project <dir>`: the MCP server over stdio, until the client closes it.
#[cfg(feature = "mcp")]
fn mcp_serve(project: &std::path::Path) -> Result<i32, Error> {
    use rmcp::{ServiceExt, transport::stdio};
    // The MCP transport's own failures are not configuration errors (02.27): the client's
    // standard input broke off (no handshake, or the session ended with an error).
    let fail = |op: opv::cause::LocalOp| {
        Error::from(opv::cause::Cause::LocalIo {
            op,
            path: PathBuf::new(),
            io: opv::cause::IoKind::Other,
        })
    };
    let project = project
        .canonicalize()
        .ok()
        .filter(|p| p.is_dir() && std::env::set_current_dir(p).is_ok())
        .ok_or_else(project_dir_err)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| {
            Error::from(opv::cause::Cause::Bug {
                site: "main: the MCP runtime could not start",
            })
        })?;
    rt.block_on(async {
        let server = opv::mcp::Server::new(project)
            .serve(stdio())
            .await
            .map_err(|_| fail(opv::cause::LocalOp::McpHandshake))?;
        server
            .waiting()
            .await
            .map_err(|_| fail(opv::cause::LocalOp::McpSession))?;
        Ok::<_, Error>(0)
    })
}

#[cfg(not(feature = "mcp"))]
fn mcp_serve(_project: &std::path::Path) -> Result<i32, Error> {
    // Every release build has the MCP server; this build leaves it out (J5).
    Err(opv::cause::Cause::ToolUnusable {
        tool: "opv".into(),
        why: opv::cause::Unusable::FeatureNotBuilt { feature: "mcp" },
    }
    .into())
}

/// `opv mcp install`: register `<this opv> mcp serve --project <dir>` with the chosen
/// assistants (FR-61).
fn mcp_install(
    r: &dyn CommandRunner,
    client: McpClient,
    project: Option<&std::path::Path>,
    name: &str,
    force: bool,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    use opv::app::mcp_install::{self as mi, Registered};
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(opv::cause::Cause::Usage {
            problem: opv::cause::UsageProblem::ValueFormat {
                flag: "--name".into(),
                format: "letters, digits, '-' or '_'",
            },
        }
        .into());
    }
    let here = std::env::current_dir().unwrap_or_default();
    let project = match project {
        Some(p) => p.to_path_buf(),
        None => config_store::git_toplevel(r).unwrap_or(here),
    };
    let project = project
        .canonicalize()
        .ok()
        .filter(|p| p.is_dir())
        .ok_or_else(project_dir_err)?;
    let exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_err(exe_err)?;
    // npm's bundled copy lives under node_modules and moves on every upgrade: register the
    // shared install that npm's postinstall and install.sh keep current instead.
    let exe = if exe.components().any(|c| c.as_os_str() == "node_modules") {
        match opv::app::mcp_install::shared_install().filter(|p| p.is_file()) {
            Some(shared) => shared,
            None => {
                let _ = writeln!(
                    io::stderr(),
                    "note: this opv runs from npm's bundled copy ({}), which moves on upgrade; \
                     run npm rebuild -g @matthew-cochran/opv --allow-scripts=@matthew-cochran/opv, \
                     then opv mcp install again",
                    exe.display()
                );
                exe
            }
        }
    } else {
        exe
    };
    let command = exe.display().to_string();
    let args = mi::server_args(&project);
    let mut done: Vec<Registered> = Vec::new();
    if matches!(client, McpClient::Claude | McpClient::All) {
        let path = project.join(".mcp.json");
        done.push(mi::register("claude", &path, |t| {
            mi::merge_claude(t, &path, name, &command, &args, force)
        })?);
    }
    if matches!(client, McpClient::Codex | McpClient::All) {
        let codex = mi::codex_config().and_then(|path| {
            mi::register("codex", &path, |t| {
                mi::merge_codex(t, &path, name, &command, &args, force)
            })
        });
        match codex {
            Ok(registered) => done.push(registered),
            // R53/X20: an earlier client is already registered; the failure names it (as
            // "already written") instead of dropping the record with the raw failure.
            Err(e) if !done.is_empty() => {
                let Error::Catalog(then, upstream) = e;
                return Err(Error::Catalog(
                    Box::new(opv::cause::Cause::Partial {
                        done: done.iter().map(|d| d.client.to_string()).collect(),
                        scope: None,
                        then,
                    }),
                    upstream,
                ));
            }
            Err(e) => return Err(e),
        }
    }
    if json {
        let doc = serde_json::json!({
            "schema_version": opv::json::SCHEMA_VERSION,
            "server": {"name": name, "command": command, "args": args},
            "registered": done,
            "next": "restart the assistant, then ask it to call opv_ready",
        });
        return writeln!(out, "{doc}").map_err(write_err);
    }
    for d in &done {
        writeln!(out, "{} {} ({})", d.action, d.path.display(), d.client).map_err(write_err)?;
    }
    writeln!(
        out,
        "opv's MCP server runs as: {command} {}\nRestart the assistant to load it; it never sees a secret value. Start it without op session, service-account or Connect credentials.",
        args.join(" ")
    )
    .map_err(write_err)
}

/// 09.03b: a missing configuration for a command that names environment `env` steps to
/// `opv init <env>`, never another environment.
fn init_for(e: Error, env: Option<&str>) -> Error {
    let Some(env) = env else {
        return e;
    };
    match e.cause() {
        Some((
            opv::cause::Cause::ConfigNotFound {
                searched_from,
                env: None,
                manifest,
            },
            _,
        )) => opv::cause::Cause::ConfigNotFound {
            searched_from: searched_from.clone(),
            env: Some(opv::cause::EnvName::new(env)),
            manifest: manifest.clone(),
        }
        .into(),
        _ => e,
    }
}

/// Where the `.opv` pointer of this run is looked up (C9, 09.08): the configuration file's
/// own folder, so `--config other/secrets.toml` uses that project's account; else the
/// working folder.
fn account_start(config: Option<&std::path::Path>) -> PathBuf {
    config
        .and_then(std::path::Path::parent)
        .filter(|d| !d.as_os_str().is_empty())
        .and_then(|d| std::fs::canonicalize(d).ok())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default())
}

/// The words of the opv command `opv login` runs, before any `--` of its own; `None` when
/// the child is not opv.
fn login_child_opv_words(command: &[String]) -> Option<&[String]> {
    let (program, args) = command.split_first()?;
    let name = program.rsplit(['/', '\\']).next().unwrap_or(program);
    if name != "opv" && name != "opv.exe" {
        return None;
    }
    let end = args.iter().position(|w| w == "--").unwrap_or(args.len());
    Some(&args[..end])
}

/// #159: whether the command `opv login` runs is opv asking for one JSON document (`--json`
/// among its own words, before any `--` of its own).
fn login_child_json(command: &[String]) -> bool {
    login_child_opv_words(command).is_some_and(|args| args.iter().any(|w| w == "--json"))
}

/// C18 (#159): the configuration file the opv command `opv login` runs names with
/// `--config` or `--file` (either `--flag PATH` or `--flag=PATH`), so login signs in to
/// that file's account instead of looking up a manifest from the git remote.
fn login_child_config(command: &[String]) -> Option<PathBuf> {
    let args = login_child_opv_words(command)?;
    args.iter().enumerate().find_map(|(i, w)| {
        for flag in ["--config", "--file"] {
            if w == flag {
                return args.get(i + 1).map(PathBuf::from);
            }
            if let Some(v) = w.strip_prefix(flag).and_then(|r| r.strip_prefix('=')) {
                return Some(PathBuf::from(v));
            }
        }
        None
    })
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

    fn corrected(line: &str) -> Option<String> {
        let args = words(line);
        let argv = std::iter::once("opv".to_string()).chain(args.iter().cloned());
        let e = cli_command().try_get_matches_from(argv).unwrap_err();
        corrected_command(&e, &args).map(|c| opv::cause::render::cmd_text(&c))
    }

    #[test]
    fn a_misspelt_subcommand_is_corrected_to_the_one_clap_suggests() {
        // 09.83.
        assert_eq!(corrected("stauts prod").as_deref(), Some("opv status prod"));
    }

    #[test]
    fn a_subcommand_flag_before_the_subcommand_moves_after_it() {
        // 09.03.
        assert_eq!(
            corrected("--json check prod").as_deref(),
            Some("opv check prod --json")
        );
    }

    #[test]
    fn a_missing_configuration_steps_to_init_of_the_named_environment() {
        // 09.03b.
        let e = init_for(
            opv::config::not_found(std::path::Path::new("/nowhere")),
            Some("prod"),
        );
        assert!(e.to_string().contains("environment prod"), "{e}");
    }

    #[test]
    fn the_account_pointer_is_looked_up_beside_the_given_configuration() {
        // C9 (09.08): `--config other/secrets.toml` reads `other`'s `.opv`.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("secrets.toml");
        assert_eq!(
            account_start(Some(&file)),
            std::fs::canonicalize(dir.path()).unwrap()
        );
    }

    #[test]
    fn login_reads_the_childs_file_flag_for_its_configuration() {
        // C18 (#159): the child's `--file` names the configuration, not the git remote.
        let child = words("opv bootstrap --file fleet.toml --dry-run");
        assert_eq!(
            login_child_config(&child),
            Some(PathBuf::from("fleet.toml"))
        );
    }

    #[test]
    fn login_reads_the_childs_config_flag_with_an_equals_sign() {
        // C18 (#159).
        let child = words("opv --config=a/secrets.toml check dev");
        assert_eq!(
            login_child_config(&child),
            Some(PathBuf::from("a/secrets.toml"))
        );
    }

    #[test]
    fn login_ignores_a_file_flag_after_the_childs_own_double_dash() {
        // C18: words after the child's `--` belong to its own child.
        let child = words("opv run dev -- tool --file x");
        assert_eq!(login_child_config(&child), None);
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
        let got = product_or_env(Some("api".into()), Some("web".into()));
        assert_eq!(got, (Some("api".into()), false));
    }

    #[test]
    fn opv_product_applies_when_no_flag_is_given() {
        let got = product_or_env(None, Some("web".into()));
        assert_eq!(got, (Some("web".into()), true));
    }

    #[test]
    fn empty_opv_product_is_ignored() {
        assert_eq!(product_or_env(None, Some(String::new())), (None, false));
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
        let Cmd::Login { env, command, .. } = cli.cmd else {
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

    /// The names people guess for signing in reach `login` (hidden aliases).
    #[test]
    fn sign_in_guesses_are_login() {
        let parsed: Vec<bool> = ["signin", "sign-in", "auth"]
            .iter()
            .map(|a| {
                matches!(
                    Cli::try_parse_from(["opv", a, "prod"]).map(|c| c.cmd),
                    Ok(Cmd::Login { .. })
                )
            })
            .collect();
        assert_eq!(parsed, [true, true, true]);
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

    /// 02.22: an unknown help topic is a name that is not declared, not a configuration
    /// error.
    #[test]
    fn help_with_an_unknown_topic_is_an_unknown_name() {
        let e = help(&["nope".to_string()], &mut Vec::new()).unwrap_err();
        assert_eq!(e.code_str(), "usage");
    }

    /// 02.22: hidden internal commands are never offered as help topics.
    #[test]
    fn help_topics_never_list_a_hidden_command() {
        let e = help(&["nope".to_string()], &mut Vec::new()).unwrap_err();
        assert!(!e.to_string().contains("remote-send"), "{e}");
    }

    /// 02.22: `states` is a topic only at the top level.
    #[test]
    fn nested_help_topics_do_not_offer_states() {
        let e = help(&["config".into(), "nope".into()], &mut Vec::new()).unwrap_err();
        assert!(!e.to_string().contains("states"), "{e}");
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
            for sub in cmd
                .get_subcommands_mut()
                .filter(|s| s.get_name() != "help" && !s.is_hide_set())
            {
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
            for sub in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
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

    fn words(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    /// M10: a usage error in a nested subcommand points to that subcommand's help.
    #[test]
    fn usage_help_names_the_nested_subcommand() {
        assert_eq!(
            help_path(&words("config check --json")),
            ["config", "check"]
        );
    }

    /// M9: config check names the missing manifest, not a missing file. (The wording now
    /// comes from the catalog cause, so the test pins the code.)
    #[test]
    fn config_check_without_a_manifest_names_the_manifest() {
        let e = manifest_missing_for_check(std::path::Path::new("/work/app"));
        assert_eq!(e.code_str(), "manifest_not_found");
    }

    /// C8: a differing copy exits 2, so config check's help says 2, never the old 8.
    #[test]
    fn config_check_help_names_the_exit_code_for_a_difference() {
        let (_, _, short) = leaf_helps()
            .into_iter()
            .find(|(name, _, _)| name == "config check")
            .expect("config check is a leaf");
        assert!(short.contains("exit 2 with a diff"), "{short}");
    }

    /// M8: `--json` before `--` without `--preview` is refused, never run as the child
    /// command. (It used to repeat the child's words in its Next; 02.10/SR-3.)
    #[test]
    fn run_refuses_json_before_the_dashes_without_preview() {
        let argv = words("opv run dev --product api --json -- true");
        let e = misplaced_run_flag(&words("--json -- true"), &argv).unwrap();
        assert_eq!(e.to_string(), "--json needs --preview");
    }

    /// L6: `opv run dev --json` without `--preview` is the usage problem `--json needs
    /// --preview`, not clap's "required arguments were not provided" with an empty list.
    #[test]
    fn run_json_without_preview_names_json_needing_preview() {
        let e = Cli::try_parse_from(["opv", "run", "dev", "--json"])
            .err()
            .unwrap();
        let cause = json_without_preview(&e, &words("run dev --json")).unwrap();
        assert_eq!(Error::from(cause).to_string(), "--json needs --preview");
    }

    /// L6: the same diagnosis holds when a child command follows the dashes.
    #[test]
    fn run_json_without_preview_before_a_child_names_json_needing_preview() {
        let e = Cli::try_parse_from(["opv", "run", "dev", "--json", "--", "true"])
            .err()
            .unwrap();
        let cause = json_without_preview(&e, &words("run dev --json -- true")).unwrap();
        assert_eq!(Error::from(cause).to_string(), "--json needs --preview");
    }

    /// L6: a clap list message keeps its items rather than ending on the colon.
    #[test]
    fn clap_message_keeps_the_items_of_a_list() {
        assert_eq!(
            clap_message(
                "error: the following required arguments were not provided:\n  --preview\n\nUsage: opv run\n"
            ),
            "the following required arguments were not provided: --preview"
        );
    }

    /// L6: a one-line clap message is unchanged but for the `error: ` prefix.
    #[test]
    fn clap_message_of_a_one_line_error_drops_the_prefix() {
        assert_eq!(
            clap_message("error: unexpected argument 'x' found\n"),
            "unexpected argument 'x' found"
        );
    }

    /// 02.09: a misspelt flag placed before `--` is named as unknown, not blamed on its
    /// place.
    #[test]
    fn run_names_a_misspelt_flag_as_unknown() {
        let argv = words("opv run dev --verbos -- true");
        let e = misplaced_run_flag(&words("--verbos -- true"), &argv).unwrap();
        assert_eq!(e.to_string(), "unknown option --verbos");
    }

    /// 02.01 (S1): `target credentials --create` on a manifest project never names
    /// itself as the step.
    #[test]
    fn credentials_create_on_a_manifest_points_at_the_manifest_editor() {
        let e = credentials_need_a_file("opv · app");
        assert_eq!(e.next_text().unwrap_or_default(), "opv config edit");
    }

    /// 02.01 (S1): no fix makes the same command succeed on a manifest, so it is never
    /// retried.
    #[test]
    fn credentials_create_on_a_manifest_is_never_retried() {
        let e = credentials_need_a_file("opv · app");
        let (cause, _) = e.cause().unwrap();
        assert_eq!(cause.retry(), opv::cause::RetryClass::Never);
    }

    /// C13 (03.12): a configuration path from OPV_CONFIG is named by that variable.
    #[test]
    fn a_config_path_from_opv_config_is_given_by_the_variable() {
        assert_eq!(
            given_by(ConfigSource::Env),
            opv::cause::GivenBy::EnvVar {
                var: opv::cause::VarName::new("OPV_CONFIG")
            }
        );
    }

    /// C22 (06.47): `target credentials` help says only Fly targets can be minted for.
    #[test]
    fn target_credentials_help_says_only_fly_mints() {
        let help = leaf_helps()
            .into_iter()
            .find(|(name, _, _)| name == "target credentials")
            .map(|(_, long, _)| long)
            .unwrap_or_default();
        assert!(
            help.contains("Only Fly targets can be minted for"),
            "{help}"
        );
    }

    /// 02.02 (S1): with no home directory the step installs into this project by its
    /// absolute path, so it runs as typed instead of repeating the refused command.
    #[test]
    fn skill_install_without_a_home_names_the_project_by_its_path() {
        let e = home_missing(std::path::Path::new("/work/app"), SkillTarget::All, false);
        assert_eq!(
            e.next_text().unwrap_or_default(),
            "opv skill install --project /work/app"
        );
    }

    /// 02.10: a confirm refusal for `opv run` never repeats the child's words.
    #[test]
    fn confirm_retry_never_holds_the_child_command() {
        assert_eq!(
            confirm_retry("prod", Some("api"), None),
            "opv run prod --confirm prod --product api"
        );
    }

    /// 02.12: `config import` with no file to find needs `--file`: a usage refusal, never
    /// the same command again.
    #[test]
    fn config_import_without_a_file_is_a_usage_refusal() {
        assert_eq!(
            import_needs_file(std::path::Path::new("/work/app")).code_str(),
            "usage"
        );
    }

    /// 02.13: init refuses --config without claiming it writes secrets.toml.
    #[test]
    fn init_with_config_names_the_conflict() {
        assert_eq!(
            init_takes_no_config(ConfigSource::Flag).to_string(),
            "opv init and --config cannot be used together"
        );
    }

    /// approval-removal (design §25.3): no approval path remains; `opv approve` is not a
    /// command.
    #[test]
    fn approve_is_an_unknown_subcommand() {
        let parsed = cli_command().try_get_matches_from(["opv", "approve", "sp-0123456789abcdef"]);
        assert_eq!(
            parsed.err().map(|e| e.kind()),
            Some(clap::error::ErrorKind::InvalidSubcommand)
        );
    }

    /// 09.21: `sync --dry-run` is its plan, global options kept.
    #[test]
    fn sync_dry_run_is_its_plan() {
        let plan = sync_as_plan(&words("--config ops/s.toml sync prod --dry-run --json")).unwrap();
        assert_eq!(
            opv::cause::render::cmd_text(&plan),
            "opv plan --config ops/s.toml prod --json"
        );
    }

    /// 02.15: bootstrap with no secrets.toml and no manifest reports a missing
    /// configuration, never a guess that starts a second one.
    #[test]
    fn bootstrap_without_any_configuration_is_config_not_found() {
        let r = opv::runner::fake::FakeRunner::new(Vec::new());
        for _ in 0..40 {
            r.push_io_error(io::ErrorKind::NotFound);
        }
        let cli = Cli::try_parse_from(["opv", "bootstrap"]).unwrap();
        let e = bootstrap_without_file(
            &cli,
            ConfigSource::Discovered,
            &r,
            std::path::Path::new("/work"),
        );
        assert_eq!(e.code_str(), "config_not_found");
    }

    /// 02.08: the --timeout help names the real per-call limits.
    #[test]
    fn timeout_help_says_a_write_is_killed_after_two_minutes() {
        let cmd = Cli::command();
        let help = cmd
            .get_arguments()
            .find(|a| a.get_id() == "timeout")
            .and_then(|a| a.get_long_help())
            .map(ToString::to_string)
            .unwrap_or_default();
        assert!(help.contains("a write after 2 minutes"), "{help}");
    }

    /// 02.16: init and target add say they also create 1Password vaults or items.
    #[test]
    fn schema_says_init_also_writes_1password() {
        let doc = opv::schema::describe(&cli_command(), "test");
        let init = doc["commands"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "init")
            .unwrap()
            .clone();
        assert_eq!(init["also_writes_1password"], true);
    }

    /// A failure whose upstream reply has eight lines (more than the box shows).
    fn eight_line_failure() -> Error {
        use opv::cause::{Cause, ExitClass, System, Upstream};
        Error::with_evidence(
            Cause::Bug { site: "test" },
            Upstream {
                source: System::OnePassword,
                tool: "1Password CLI".into(),
                version: None,
                exit: ExitClass::Code { code: 1 },
                said: (1..=8).map(|i| format!("line {i}")).collect(),
                removed_advice: false,
                truncated: false,
                untrusted: true,
            },
        )
    }

    fn render_with(verbose: bool, utf8: bool) -> Render {
        Render {
            inv: Some(opv::cause::Invocation::from_cli(&words("opv status prod"))),
            verbose,
            utf8,
            colour: false,
        }
    }

    fn rendered(verbose: bool, utf8: bool) -> String {
        render_with(verbose, utf8).text(&eight_line_failure())
    }

    /// --verbose shows the tool's whole scrubbed reply (design §7.3, owner decision).
    #[test]
    fn verbose_failure_text_shows_the_whole_upstream_reply() {
        assert!(rendered(true, true).contains("line 8"));
    }

    #[test]
    fn failure_text_without_verbose_leaves_out_the_middle_of_the_reply() {
        assert!(!rendered(false, true).contains("line 2"));
    }

    #[test]
    fn failure_text_in_a_non_utf8_locale_draws_an_ascii_box() {
        assert!(!rendered(false, false).contains('╭'));
    }

    #[test]
    fn verbose_failure_document_carries_the_whole_upstream_reply() {
        let inv = opv::cause::Invocation::from_cli(&words("opv status prod"));
        let error = opv::error::document(&eight_line_failure(), &inv, true);
        assert_eq!(
            error["evidence"]["upstream"]["said"]
                .as_array()
                .map(Vec::len),
            Some(8)
        );
    }

    #[test]
    fn run_accepts_a_child_word_with_a_dash_after_the_dashes() {
        let argv = words("opv run dev -- -x");
        assert!(misplaced_run_flag(&words("-x"), &argv).is_none());
    }

    /// I6: every flag a command parses is in the schema, the registry-built (hidden)
    /// provider options of `init` included.
    #[test]
    fn schema_lists_every_flag_including_provider_options() {
        fn leaves<'a>(
            cmd: &'a clap::Command,
            prefix: &str,
            out: &mut Vec<(String, &'a clap::Command)>,
        ) {
            for sub in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
                let path = format!("{prefix}{}", sub.get_name());
                if sub.has_subcommands() {
                    leaves(sub, &format!("{path} "), out);
                } else {
                    out.push((path, sub));
                }
            }
        }
        let root = cli_command();
        let mut cmds = Vec::new();
        leaves(&root, "", &mut cmds);
        let doc = opv::schema::describe(&root, "test");
        let listed: std::collections::BTreeSet<(String, String)> = doc["commands"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|c| {
                let name = c["name"].as_str().unwrap().to_string();
                c["flags"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(move |f| (name.clone(), f["name"].as_str().unwrap().to_string()))
            })
            .collect();
        let missing: Vec<(String, String)> = cmds
            .iter()
            .flat_map(|(path, c)| {
                c.get_arguments()
                    .filter(|a| !a.is_positional() && !a.is_global_set())
                    .filter_map(|a| a.get_long())
                    .filter(|l| !matches!(*l, "help" | "version"))
                    .map(move |l| (path.clone(), format!("--{l}")))
            })
            .filter(|f| !listed.contains(f))
            .collect();
        assert!(missing.is_empty(), "{missing:?}");
    }

    /// I6: the provider options come from the registry, so a new provider is listed too.
    #[test]
    fn schema_lists_each_provider_option_of_target_add_with_its_provider() {
        use opv::adapters::registry::PROVIDERS;
        let doc = opv::schema::describe(&cli_command(), "test");
        let add = doc["commands"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "target add")
            .unwrap();
        let listed = add["flags"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["provider"].is_string())
            .count();
        let want: usize = PROVIDERS.iter().map(|p| p.init_fields().len()).sum();
        assert_eq!(listed, want);
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
            &["opv", "skill", "install", "--json"],
            &["opv", "skill", "status", "--json"],
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

    /// FR-52: `opv skill status` points at the command that refreshes an older copy.
    #[test]
    fn skill_status_names_the_update_command_for_an_older_copy() {
        let copies = vec![opv::app::skill::Copy {
            scope: "user".into(),
            root: PathBuf::from("/home/x"),
            target: opv::app::skill::Target::Claude,
            path: PathBuf::from("/home/x/.claude/skills/opv/SKILL.md"),
            version: Some("0.1.0".into()),
            edited: false,
            current: false,
        }];
        let mut out = Vec::new();
        write_skill_status(&copies, &mut out).unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("run opv skill install --user --target claude to update")
        );
    }

    #[test]
    fn skill_status_has_no_update_hint_when_every_copy_is_current() {
        let copies = vec![opv::app::skill::Copy {
            scope: "user".into(),
            root: PathBuf::from("/home/x"),
            target: opv::app::skill::Target::Claude,
            path: PathBuf::from("/home/x/.claude/skills/opv/SKILL.md"),
            version: Some("9.9.9".into()),
            edited: false,
            current: true,
        }];
        let mut out = Vec::new();
        write_skill_status(&copies, &mut out).unwrap();
        assert!(!String::from_utf8(out).unwrap().contains("to update"));
    }

    /// 05.35: with no copy installed, status says so and names the install.
    #[test]
    fn skill_status_with_no_copy_names_the_install() {
        let mut out = Vec::new();
        write_skill_status(&[], &mut out).unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("Next: opv skill install")
        );
    }
}
