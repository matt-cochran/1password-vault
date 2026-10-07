use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use secretctl::Error;
use secretctl::app::{config_export, doctor, run as run_cmd, skeleton, status, sync};
use secretctl::config;
use secretctl::runner::ProcessRunner;

/// Sync secrets from 1Password into runtime targets.
///
/// Exit codes: 0 ok, 2 configuration or usage, 3 dependency or authentication,
/// 4 1Password, 5 Fly, 6 policy refusal, 8 findings.
#[derive(Parser)]
#[command(name = "secretctl", version, about)]
struct Cli {
    /// Path to the fleet configuration.
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        default_value = "secrets.toml"
    )]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check configuration, op, 1Password sign-in and flyctl (FR-3).
    Doctor,
    /// One row per product × key with 1Password and Fly state; names only (FR-17).
    Status { env: String },
    /// Run a command with the product's secrets in its environment via `op run` (FR-4).
    ///
    /// Exits with the child's own exit code, so a child code can equal a secretctl
    /// category code (for example 2); secretctl errors print `secretctl: ...` on stderr.
    Run {
        env: String,
        /// Product whose declared keys are passed to the command.
        #[arg(long)]
        product: String,
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
}

#[derive(Subcommand)]
enum FlyCmd {
    /// Show what a sync would stage, hold and prune; changes nothing (FR-5).
    ///
    /// Exits 8 when any row (missing, wrong kind, failing a rule) would block a sync.
    Plan { env: String },
    /// Stage managed secrets on the Fly app (FR-6..FR-8, FR-16).
    Sync {
        env: String,
        /// Deploy when a staged digest changed, a prune happened, or a managed name is
        /// still pending (Staged/Partial) on Fly from an earlier run.
        #[arg(long)]
        deploy: bool,
        /// Unset managed names that are not desired in this environment.
        #[arg(long)]
        prune: bool,
        /// Stage an immutable key even though it is present on Fly (repeatable).
        #[arg(long, value_name = "PRODUCT/KEY")]
        rotate: Vec<String>,
        /// Fail (exit 8) if staging changed any digest.
        #[arg(long)]
        expect_no_change: bool,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Print config-kind values as JSON (FR-18).
    Export {
        env: String,
        /// Output JSON (required; the only format).
        #[arg(long, required = true)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ItemCmd {
    /// Add missing declared fields to the item, empty; the only 1Password write (FR-19).
    Skeleton { env: String },
}

fn main() -> ExitCode {
    // clap prints usage errors itself and exits 2 (shared with configuration errors).
    let cli = Cli::parse();
    let mut stdout = std::io::stdout().lock();
    let res = run(cli, &mut stdout);
    let _ = stdout.flush();
    match res {
        // `run` reports the child's exit code verbatim (FR-4); everything else yields 0.
        Ok(0) => ExitCode::SUCCESS,
        Ok(code) => ExitCode::from(exit_byte(code)),
        Err(e) => {
            // Error messages never contain secret values or child output (SR-1).
            eprintln!("secretctl: {e}");
            ExitCode::from(exit_byte(e.exit_code()))
        }
    }
}

fn run(cli: Cli, out: &mut dyn Write) -> Result<i32, Error> {
    let r = ProcessRunner;
    let loaded = config::load(&cli.config);
    if let Cmd::Run {
        env,
        product,
        command,
    } = &cli.cmd
    {
        return run_cmd::run(&loaded?, env, product, command, &r);
    }
    run_other(cli.cmd, loaded, &r, out).map(|()| 0)
}

fn run_other(
    cmd: Cmd,
    loaded: Result<secretctl::domain::Fleet, Error>,
    r: &ProcessRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    match cmd {
        Cmd::Run { .. } => unreachable!("handled by run"),
        Cmd::Doctor => doctor::run(loaded, r, out),
        Cmd::Status { env } => status::run(&loaded?, &env, r, out),
        Cmd::Fly(FlyCmd::Plan { env }) => sync::plan(&loaded?, &env, r, out),
        Cmd::Fly(FlyCmd::Sync {
            env,
            deploy,
            prune,
            rotate,
            expect_no_change,
        }) => {
            let opts = sync::SyncOpts {
                deploy,
                prune,
                rotate,
                expect_no_change,
            };
            sync::run(&loaded?, &env, r, out, &opts)
        }
        Cmd::Config(ConfigCmd::Export { env, json: _ }) => {
            config_export::run(&loaded?, &env, r, out)
        }
        Cmd::Item(ItemCmd::Skeleton { env }) => skeleton::run(&loaded?, &env, r, out),
    }
}

/// Clamp an exit code to the 1..=255 range a process can report; failures never become 0.
fn exit_byte(code: i32) -> u8 {
    match u8::try_from(code) {
        Ok(0) | Err(_) => 1,
        Ok(b) => b,
    }
}
