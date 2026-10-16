//! The scenario directory: `world.json` (the state every simulated tool answers from and
//! writes to), `faults.toml`, and the simulator's own bookkeeping (`sim-state.json`, the
//! fault occurrence counters, and `calls.log`, one line per call, argv only). Every call
//! holds an exclusive lock on the directory while it reads and writes them, so concurrent
//! calls see each other's writes.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

/// The environment variable naming the scenario directory.
pub const WORLD_VAR: &str = "OPV_SIM_WORLD";

/// The scenario directory and its loaded state.
pub struct World {
    pub dir: PathBuf,
    pub doc: Value,
    /// The world as loaded, to tell whether a call changed it.
    loaded: Value,
    _lock: Lock,
}

impl World {
    /// Lock and load the scenario directory named by [`WORLD_VAR`].
    pub fn open() -> Result<Self, String> {
        let dir = std::env::var_os(WORLD_VAR)
            .map(PathBuf::from)
            .ok_or_else(|| format!("{WORLD_VAR} is not set (the scenario directory)"))?;
        let lock = Lock::take(&dir.join(".lock"))?;
        let path = dir.join("world.json");
        let doc = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b)
                .map_err(|e| format!("{} is not valid JSON: {e}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => json!({}),
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        Ok(Self {
            dir,
            loaded: doc.clone(),
            doc,
            _lock: lock,
        })
    }

    /// Write `world.json` back when the call changed it.
    pub fn save(&self) -> Result<(), String> {
        if self.doc == self.loaded {
            return Ok(());
        }
        let path = self.dir.join("world.json");
        let tmp = self.dir.join(".world.json.tmp");
        let body = serde_json::to_vec_pretty(&self.doc).map_err(|e| e.to_string())?;
        std::fs::write(&tmp, body).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &path).map_err(|e| format!("cannot write {}: {e}", path.display()))
    }

    /// Append one line to `calls.log`.
    pub fn log(&self, line: &str) {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("calls.log"))
        {
            let _ = writeln!(f, "{line}");
        }
    }

    /// The simulator's bookkeeping (`sim-state.json`).
    pub fn state(&self) -> Value {
        std::fs::read(self.dir.join("sim-state.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_else(|| json!({}))
    }

    /// Replace the bookkeeping.
    pub fn set_state(&self, state: &Value) {
        let _ = std::fs::write(
            self.dir.join("sim-state.json"),
            serde_json::to_vec_pretty(state).unwrap_or_default(),
        );
    }

    /// The object at JSON pointer `pointer`, created as `{}` (with its parents) when missing.
    pub fn object_at(&mut self, pointer: &str) -> &mut serde_json::Map<String, Value> {
        let mut at = &mut self.doc;
        for key in pointer.split('/').filter(|k| !k.is_empty()) {
            if !at.is_object() {
                *at = json!({});
            }
            at = at
                .as_object_mut()
                .expect("made an object")
                .entry(unescape(key))
                .or_insert_with(|| json!({}));
        }
        if !at.is_object() {
            *at = json!({});
        }
        at.as_object_mut().expect("made an object")
    }

    /// The array at `pointer`, created as `[]` (with its parents) when missing.
    pub fn array_at(&mut self, pointer: &str) -> &mut Vec<Value> {
        let (parent, key) = pointer.rsplit_once('/').unwrap_or(("", pointer));
        let slot = self
            .object_at(parent)
            .entry(unescape(key))
            .or_insert_with(|| json!([]));
        if !slot.is_array() {
            *slot = json!([]);
        }
        slot.as_array_mut().expect("made an array")
    }

    /// A fresh identifier with `prefix`, unique within this scenario directory.
    pub fn new_id(&self, prefix: &str) -> String {
        let mut state = self.state();
        let n = state["next_id"].as_u64().unwrap_or(1);
        state["next_id"] = json!(n + 1);
        self.set_state(&state);
        let digits = 26usize.saturating_sub(prefix.len());
        format!("{prefix}{n:0digits$}")
    }

    /// A timestamp that moves on with every call that asks for one (no wall clock, so runs
    /// are reproducible).
    pub fn stamp(&self) -> String {
        let mut state = self.state();
        let n = state["clock"].as_u64().unwrap_or(0) + 1;
        state["clock"] = json!(n);
        self.set_state(&state);
        format!(
            "2026-10-16T{:02}:{:02}:{:02}Z",
            n / 3600 % 24,
            n / 60 % 60,
            n % 60
        )
    }
}

/// One JSON-pointer key: `~1` is `/` (an `owner/name` repository), `~0` is `~`.
fn unescape(key: &str) -> String {
    key.replace("~1", "/").replace("~0", "~")
}

/// An exclusive `flock` on a file in the scenario directory, released on drop (and by the
/// kernel when the process dies).
struct Lock(File);

impl Lock {
    fn take(path: &Path) -> Result<Self, String> {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: flock on a file descriptor this process owns.
            if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return Err(format!("cannot lock {}", path.display()));
            }
        }
        Ok(Self(f))
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: as above.
            unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}
