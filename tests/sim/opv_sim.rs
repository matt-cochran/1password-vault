//! `opv-sim`: a test-only stand-in for `op`, `flyctl`, `kubectl`, `gh` and `ssh` (design
//! §13.1), never shipped. One binary answers as whichever tool `argv[0]` names; it is
//! installed under each name in a temporary `bin` directory that comes first on `PATH`:
//!
//! ```text
//! opv-sim install <bin dir>     # links op, flyctl, fly, kubectl, gh, ssh and az to itself
//! ```
//!
//! Its state is the scenario directory named by `OPV_SIM_WORLD`: `world.json` (see each
//! tool's module for its part), `faults.toml` ([`faults`]), and the simulator's own
//! `sim-state.json` and `calls.log`. Every failure reply is copied from a recording under
//! `tests/fixtures/` with the world's names substituted; a reply nobody recorded fails with
//! exit 86 naming the missing recording, and a command it does not model with exit 87
//! (`opv-sim: unsupported …`), so a test never passes on invented text.

mod args;
mod faults;
mod fly;
mod gh;
mod jsonpath;
mod kube;
mod op;
mod recordings;
mod ssh;
mod world;

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use faults::Kind;
use recordings::Reply;
use ssh::Action;
use world::World;

/// The names `install` links, and the program each one is.
const TOOLS: &[(&str, &str)] = &[
    ("op", "op"),
    ("flyctl", "flyctl"),
    ("fly", "flyctl"),
    ("kubectl", "kubectl"),
    ("gh", "gh"),
    ("ssh", "ssh"),
    ("az", "az"),
];

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let name = argv
        .first()
        .map(|a| {
            Path::new(a)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        })
        .unwrap_or_default();
    let args = argv.get(1..).unwrap_or_default().to_vec();
    let program = TOOLS.iter().find(|(n, _)| *n == name).map(|(_, p)| *p);
    let code = match program {
        Some(p) => simulate(p, &args),
        None => admin(&args),
    };
    std::process::exit(code);
}

/// `opv-sim install <dir>`: link every tool name to this binary, leaving out a tool with a
/// `tool_missing` fault (when `OPV_SIM_WORLD` is set).
fn admin(args: &[String]) -> i32 {
    match args {
        [cmd, dir] if cmd == "install" => {
            let faults = std::env::var_os(world::WORLD_VAR)
                .map(|d| faults::load(Path::new(&d)).unwrap_or_default())
                .unwrap_or_default();
            let me = match std::env::current_exe() {
                Ok(p) => p,
                Err(e) => return fail(&format!("cannot find this binary: {e}")),
            };
            let dir = Path::new(dir);
            if let Err(e) = std::fs::create_dir_all(dir) {
                return fail(&format!("cannot create {}: {e}", dir.display()));
            }
            for (name, program) in TOOLS {
                if faults::missing_tool(&faults, program) {
                    continue;
                }
                let link = dir.join(name);
                let _ = std::fs::remove_file(&link);
                #[cfg(unix)]
                let made = std::os::unix::fs::symlink(&me, &link);
                #[cfg(not(unix))]
                let made = std::fs::copy(&me, &link).map(|_| ());
                if let Err(e) = made {
                    return fail(&format!("cannot link {}: {e}", link.display()));
                }
            }
            0
        }
        _ => fail("usage: opv-sim install <bin dir> (or run it as op, flyctl, kubectl, gh or ssh)"),
    }
}

fn fail(msg: &str) -> i32 {
    eprintln!("opv-sim: {msg}");
    2
}

fn words(program: &str, args: &[String]) -> Vec<String> {
    match program {
        "op" => op::call_words(args),
        "flyctl" => fly::call_words(args),
        "kubectl" => kube::call_words(args),
        "gh" => gh::call_words(args),
        "ssh" => ssh::call_words(args),
        _ => args::words(args, &[]),
    }
}

/// The recorded failure for `kind` on this call.
fn fault_reply(program: &str, kind: Kind, world: &World, args: &[String]) -> Action {
    Action::Reply(match program {
        "op" => op::fault(kind, world, args),
        "flyctl" => fly::fault(kind, world, args),
        "kubectl" => kube::fault(kind, world, args),
        "gh" => gh::fault(kind, world, args),
        "ssh" => return ssh::fault(kind, world, args),
        _ => Reply::no_recording(&format!("{} on {program}", kind.name()), program),
    })
}

/// The call answered from the world.
fn answer(program: &str, world: &mut World, args: &[String]) -> Action {
    Action::Reply(match program {
        "op" => op::run(world, args),
        "flyctl" => fly::run(world, args),
        "kubectl" => kube::run(world, args),
        "gh" => gh::run(world, args),
        "ssh" => return ssh::run(world, args),
        // Azure recordings are deferred (#40-#42): az is "not installed".
        _ => Reply {
            code: 127,
            ..Reply::default()
        },
    })
}

fn simulate(program: &str, args: &[String]) -> i32 {
    let mut world = match World::open() {
        Ok(w) => w,
        Err(e) => return fail(&e),
    };
    let w = words(program, args);
    world.log(&format!("{program} {}", args.join(" ")));
    let faults = match faults::load(&world.dir) {
        Ok(f) => f,
        Err(e) => return fail(&e),
    };
    let hit = faults::hit(&world, &faults, program, &w);
    let action = match hit.as_ref().map(|f| f.kind) {
        Some(Kind::ToolMissing) => return 127,
        Some(Kind::Timeout) => {
            let secs = hit.and_then(|f| f.seconds).unwrap_or(3600);
            drop(world);
            std::thread::sleep(Duration::from_secs(secs));
            return 124;
        }
        Some(Kind::MalformedOutput) => {
            // Answered, not applied: only the output is damaged.
            match answer(program, &mut world, args) {
                Action::Reply(r) if r.code != 0 => {
                    eprintln!(
                        "opv-sim: malformed_output on a call that fails without it (exit {}): \
                         no output to damage",
                        r.code
                    );
                    return recordings::NO_OUTPUT;
                }
                Action::Reply(mut r) => {
                    let half = r.stdout.len() / 2;
                    r.stdout.truncate(half);
                    Action::Reply(r)
                }
                other => other,
            }
        }
        Some(Kind::AppliedButReplyLost) if program != "ssh" => {
            let _ = answer(program, &mut world, args);
            if let Err(e) = world.save() {
                return fail(&e);
            }
            drop(world);
            die();
        }
        Some(kind) => fault_reply(program, kind, &world, args),
        None => {
            let a = answer(program, &mut world, args);
            if let Err(e) = world.save() {
                return fail(&e);
            }
            a
        }
    };
    let reply = match action {
        Action::Reply(r) => r,
        Action::Remote(remote) => {
            drop(world);
            ssh::execute(remote)
        }
    };
    let _ = std::io::stdout().write_all(&reply.stdout);
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().write_all(&reply.stderr);
    reply.code
}

/// The reply is lost: the process dies by SIGKILL, printing nothing.
fn die() -> ! {
    #[cfg(unix)]
    // SAFETY: sends a signal to this process.
    unsafe {
        libc::kill(libc::getpid(), libc::SIGKILL);
    }
    std::process::abort()
}
