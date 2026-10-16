//! Replies taken from the recordings under `tests/fixtures/` (CONTRIBUTING: recordings, never
//! invented output). A recording's markers and recorded identifiers are replaced by the
//! world's values; nothing else in its text changes.

use std::path::PathBuf;

/// Exit code of a reply the simulator has no recording for: the test fails loudly instead
/// of passing on invented text.
pub const NO_RECORDING: i32 = 86;
/// Exit code for a command the simulator does not model.
pub const UNSUPPORTED: i32 = 87;

/// One process reply: what the simulated tool prints and its exit code.
#[derive(Debug, Clone, Default)]
pub struct Reply {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub code: i32,
}

impl Reply {
    /// Exit 0 with `stdout`.
    pub fn ok(stdout: impl Into<Vec<u8>>) -> Self {
        Self {
            stdout: stdout.into(),
            ..Self::default()
        }
    }

    /// Exit 0, nothing printed (a success whose output opv never reads and nobody recorded).
    pub fn silent() -> Self {
        Self::default()
    }

    /// Exit 0 with `value` as one line of JSON.
    pub fn json(value: &serde_json::Value) -> Self {
        let mut out = serde_json::to_vec(value).expect("a JSON value serializes");
        out.push(b'\n');
        Self::ok(out)
    }

    /// Nothing recorded for `what`: a distinctive failure naming the missing recording.
    pub fn no_recording(what: &str, dir: &str) -> Self {
        Self {
            stderr: format!(
                "opv-sim: no recording for {what}; record the real reply under \
                 tests/fixtures/{dir}/ before simulating it (CONTRIBUTING: recordings, never \
                 invented output)\n"
            )
            .into_bytes(),
            code: NO_RECORDING,
            ..Self::default()
        }
    }

    /// A command the simulator does not model.
    pub fn unsupported(program: &str, args: &[String]) -> Self {
        Self {
            stderr: format!("opv-sim: unsupported {program} {}\n", args.join(" ")).into_bytes(),
            code: UNSUPPORTED,
            ..Self::default()
        }
    }
}

/// The fixtures directory: `OPV_SIM_FIXTURES`, else this checkout's `tests/fixtures`.
fn root() -> PathBuf {
    std::env::var_os("OPV_SIM_FIXTURES")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures")))
}

/// The recording `case` (a path under the fixtures directory without its extension, such
/// as `op/failures/05-signed-out-whoami`), with each `(recorded, world)` pair substituted in
/// stdout and stderr in order. A missing `.exit` file is a missing recording.
pub fn recorded(case: &str, subs: &[(&str, String)]) -> Reply {
    let base = root().join(case);
    let read = |ext: &str| std::fs::read_to_string(base.with_extension(ext)).ok();
    let Some(code) = read("exit").and_then(|c| c.trim().parse::<i32>().ok()) else {
        return Reply::no_recording(&format!("recording {case}.exit (file missing)"), case);
    };
    let fill = |text: String| {
        subs.iter()
            .fold(text, |t, (from, to)| t.replace(from, to))
            .into_bytes()
    };
    Reply {
        stdout: fill(read("stdout").unwrap_or_default()),
        stderr: fill(read("stderr").unwrap_or_default()),
        code,
    }
}

/// A recording kept as a pair of `stderr-<case>.txt` / `exit-<case>.txt` files (the older
/// layout of `tests/fixtures/github/`).
pub fn recorded_pair(dir: &str, case: &str, subs: &[(&str, String)]) -> Reply {
    let dir = root().join(dir);
    let read = |name: String| std::fs::read_to_string(dir.join(name)).ok();
    let Some(code) = read(format!("exit-{case}.txt")).and_then(|c| c.trim().parse::<i32>().ok())
    else {
        return Reply::no_recording(
            &format!("recording exit-{case}.txt (file missing)"),
            "github",
        );
    };
    let stderr = subs.iter().fold(
        read(format!("stderr-{case}.txt")).unwrap_or_default(),
        |t, (from, to)| t.replace(from, to),
    );
    Reply {
        stderr: stderr.into_bytes(),
        code,
        ..Reply::default()
    }
}

/// A recorded success document (a whole file under the fixtures directory).
pub fn fixture(path: &str) -> Option<String> {
    std::fs::read_to_string(root().join(path)).ok()
}
