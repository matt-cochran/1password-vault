use std::process::ExitCode;

use clap::Parser;
use secretctl::Error;

/// Sync secrets from 1Password into runtime targets.
#[derive(Parser)]
#[command(name = "secretctl", version, about)]
struct Cli {}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Error messages never contain secret values (SR-1).
            eprintln!("secretctl: {e}");
            ExitCode::from(exit_byte(e.exit_code()))
        }
    }
}

fn run(_cli: Cli) -> Result<(), Error> {
    Ok(())
}

/// Clamp an exit code to the 1..=255 range a process can report; failures never become 0.
fn exit_byte(code: i32) -> u8 {
    match u8::try_from(code) {
        Ok(0) | Err(_) => 1,
        Ok(b) => b,
    }
}
