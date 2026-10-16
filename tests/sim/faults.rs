//! `faults.toml`: the injected faults (design §13.3). A fault targets calls by program and
//! subcommand words (the `CallId` idea: `op` + `item get`) and by occurrence:
//!
//! ```toml
//! [[fault]]
//! program = "op"          # op, flyctl, kubectl, gh, ssh (fly is flyctl)
//! call = "item get"       # leading words of the call, flags left out; omitted: any call
//! kind = "signed_out"
//! occurrence = "first"    # "first", "every" (the default) or the n-th matching call (3)
//! seconds = 3600          # timeout only: how long to hang before giving up
//! ```

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::world::World;

/// What a fault does to the call it hits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// The account the call names has no session, and no other account has one.
    SignedOut,
    /// The account the call names has no session while another account has one (#160).
    OtherAccountSession,
    /// The account the call names is not on this machine.
    AccountNotOnMachine,
    /// A token in effect (service account, `FLY_API_TOKEN`, `GH_TOKEN`) is rejected.
    CredentialRejected,
    Forbidden,
    NotFound,
    /// The network or the service cannot be reached.
    Unreachable,
    RateLimited,
    ServerError,
    /// The call never answers: it hangs until killed (or `seconds` pass).
    Timeout,
    /// The call succeeds with its output cut in half.
    MalformedOutput,
    /// The write is applied to the world, then the process dies without a reply.
    AppliedButReplyLost,
    /// The tool is not installed: left out by `opv-sim install`, exit 127 if run anyway.
    ToolMissing,
    // ssh only (tests/fixtures/ssh/failures).
    HostKeyMismatch,
    HostKeyUnknown,
    ConnectionRefused,
    ConnectTimeout,
    /// The session drops while the remote command runs.
    DropMidRun,
    ServerUnresponsive,
    RemoteCommandMissing,
}

impl Kind {
    pub fn name(self) -> String {
        serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Occurrence {
    Named(String),
    Nth(u64),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fault {
    pub program: String,
    #[serde(default)]
    pub call: Option<String>,
    pub kind: Kind,
    #[serde(default)]
    pub occurrence: Option<Occurrence>,
    #[serde(default)]
    pub seconds: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    fault: Vec<Fault>,
}

/// The faults of the scenario directory (none when it has no `faults.toml`).
pub fn load(dir: &std::path::Path) -> Result<Vec<Fault>, String> {
    let path = dir.join("faults.toml");
    match std::fs::read_to_string(&path) {
        Ok(text) => toml::from_str::<File>(&text)
            .map(|f| f.fault)
            .map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

/// `fly` and `flyctl` are one program.
fn same_program(fault: &str, program: &str) -> bool {
    let norm = |p: &str| {
        if p == "fly" {
            "flyctl".to_string()
        } else {
            p.to_string()
        }
    };
    norm(fault) == norm(program)
}

/// The fault that hits this call, if any. Every fault whose program and words match counts
/// the call (in `sim-state.json`), whether or not it fires this time.
pub fn hit(world: &World, faults: &[Fault], program: &str, words: &[String]) -> Option<Fault> {
    let mut state = world.state();
    let mut fired = None;
    for (i, f) in faults.iter().enumerate() {
        if !same_program(&f.program, program) {
            continue;
        }
        let wanted: Vec<&str> = f.call.as_deref().unwrap_or("").split_whitespace().collect();
        if wanted.len() > words.len() || wanted.iter().zip(words).any(|(w, a)| w != a) {
            continue;
        }
        let key = format!("fault{i}");
        let n = state["counts"][&key].as_u64().unwrap_or(0) + 1;
        state["counts"][&key] = json!(n);
        let fires = match &f.occurrence {
            None => true,
            Some(Occurrence::Named(s)) if s == "every" => true,
            Some(Occurrence::Named(s)) if s == "first" => n == 1,
            Some(Occurrence::Named(_)) => false,
            Some(Occurrence::Nth(k)) => n == *k,
        };
        if fires && fired.is_none() {
            fired = Some(f.clone());
        }
    }
    world.set_state(&state);
    fired
}

/// Whether `program` is left out of the PATH directory: a `tool_missing` fault on any of
/// its calls, every time.
pub fn missing_tool(faults: &[Fault], program: &str) -> bool {
    faults.iter().any(|f| {
        same_program(&f.program, program)
            && f.kind == Kind::ToolMissing
            && f.call.as_deref().unwrap_or("").trim().is_empty()
            && matches!(&f.occurrence, None | Some(Occurrence::Named(_)))
            && !matches!(&f.occurrence, Some(Occurrence::Named(s)) if s == "first")
    })
}
