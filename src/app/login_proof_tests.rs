//! #353: every accept and refuse case of the `opv login` proof, over a fake process table
//! and a private temporary directory. Values are dummies.

use super::*;
use std::cell::RefCell;
use std::collections::HashMap;

/// Process IDs of the fake tree: init → shell → login → bash → provision.
const INIT: u32 = 1;
const SHELL: u32 = 100;
const LOGIN: u32 = 200;
const BASH: u32 = 300;
const ME: u32 = 400;
const TTY: u64 = 34816;
const OPV: &str = "/usr/local/bin/opv";

#[derive(Clone)]
struct Fake {
    me: RefCell<u32>,
    procs: RefCell<HashMap<u32, (ProcStat, PathBuf)>>,
    /// Command names that differ from the executable's file name.
    comms: RefCell<HashMap<u32, String>>,
}

impl Fake {
    /// The tree with this process as the login (for [`issue`]).
    fn tree() -> Self {
        let mut procs = HashMap::new();
        let at = |ppid, start, exe: &str| {
            (
                ProcStat {
                    ppid,
                    start,
                    tty: TTY,
                },
                PathBuf::from(exe),
            )
        };
        procs.insert(INIT, at(0, 1, "/sbin/init"));
        procs.insert(SHELL, at(INIT, 10, "/bin/bash"));
        procs.insert(LOGIN, at(SHELL, 20, OPV));
        procs.insert(BASH, at(LOGIN, 30, "/bin/bash"));
        procs.insert(ME, at(BASH, 40, OPV));
        Fake {
            me: RefCell::new(LOGIN),
            procs: RefCell::new(procs),
            comms: RefCell::new(HashMap::new()),
        }
    }
    /// Act as `pid` from now on.
    fn as_pid(&self, pid: u32) -> &Self {
        *self.me.borrow_mut() = pid;
        self
    }
    fn set(&self, pid: u32, f: impl FnOnce(&mut ProcStat, &mut PathBuf)) {
        let mut procs = self.procs.borrow_mut();
        let (s, e) = procs.get_mut(&pid).expect("a fake process");
        f(s, e);
    }
    fn kill(&self, pid: u32) {
        self.procs.borrow_mut().remove(&pid);
    }
}

impl Procs for Fake {
    fn this_pid(&self) -> u32 {
        *self.me.borrow()
    }
    fn stat(&self, pid: u32) -> Option<ProcStat> {
        self.procs.borrow().get(&pid).map(|(s, _)| *s)
    }
    fn exe(&self, pid: u32) -> Option<PathBuf> {
        let procs = self.procs.borrow();
        let (_, e) = procs.get(&pid)?;
        // An empty path models a non-dumpable process, whose `exe` link is hidden.
        (!e.as_os_str().is_empty()).then(|| e.clone())
    }
    fn comm(&self, pid: u32) -> Option<String> {
        let procs = self.procs.borrow();
        let (_, e) = procs.get(&pid)?;
        let name = self.comms.borrow().get(&pid).cloned().unwrap_or_else(|| {
            e.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        });
        Some(name.chars().take(15).collect())
    }
}

const VAR: &str = "OP_SESSION_ACC6AIN";
const TOKEN: &str = "dummy-session-token-for-tests";

fn login_session() -> Vec<(String, SecretValue)> {
    vec![(VAR.into(), SecretValue::new(TOKEN.into()))]
}

/// A runtime directory, a fake tree and a proof the login issued in it.
struct World {
    _tmp: tempfile::TempDir,
    runtime: PathBuf,
    procs: Fake,
    issued: Issued,
}

fn world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let runtime = tmp.path().to_path_buf();
    let procs = Fake::tree();
    let issued = issue(&login_session(), Ok(&runtime), &procs).unwrap();
    procs.as_pid(ME);
    World {
        _tmp: tmp,
        runtime,
        procs,
        issued,
    }
}

fn here(var: &str, value: &str) -> Vec<(String, Zeroizing<String>)> {
    vec![(var.into(), Zeroizing::new(value.into()))]
}

fn claim<'a>(proof: Option<&'a str>, sessions: &'a [(String, Zeroizing<String>)]) -> Claim<'a> {
    Claim {
        proof,
        sessions,
        interactive: true,
        agent: false,
    }
}

impl World {
    fn verify_with(&self, c: &Claim<'_>) -> Result<(), SessionProof> {
        verify(c, Ok(&self.runtime), &self.procs)
    }
    /// The login's own child, as issued.
    fn verify(&self) -> Result<(), SessionProof> {
        let s = here(VAR, TOKEN);
        self.verify_with(&claim(Some(self.issued.value()), &s))
    }
    fn record_path(&self) -> PathBuf {
        self.issued.dir().join(RECORD)
    }
}

#[test]
fn the_logins_own_child_at_its_terminal_is_accepted() {
    assert_eq!(world().verify(), Ok(()));
}

#[test]
fn a_session_without_a_proof_is_refused_as_no_proof() {
    let w = world();
    let s = here(VAR, TOKEN);
    assert_eq!(w.verify_with(&claim(None, &s)), Err(SessionProof::NoProof));
}

#[test]
fn an_assistant_marker_is_refused_even_with_a_valid_proof() {
    let w = world();
    let s = here(VAR, TOKEN);
    let c = Claim {
        agent: true,
        ..claim(Some(w.issued.value()), &s)
    };
    assert_eq!(w.verify_with(&c), Err(SessionProof::Agent));
}

#[test]
fn a_non_terminal_is_refused_even_with_a_valid_proof() {
    let w = world();
    let s = here(VAR, TOKEN);
    let c = Claim {
        interactive: false,
        ..claim(Some(w.issued.value()), &s)
    };
    assert_eq!(w.verify_with(&c), Err(SessionProof::NoTerminal));
}

#[test]
fn a_forged_nonce_is_refused() {
    let w = world();
    let (id, rest) = w.issued.value().split_once('.').unwrap();
    let (_, tag) = rest.split_once('.').unwrap();
    let forged = format!("{id}.{}.{tag}", "ab".repeat(32));
    let s = here(VAR, TOKEN);
    assert_eq!(
        w.verify_with(&claim(Some(&forged), &s)),
        Err(SessionProof::Forged)
    );
}

#[test]
fn a_proof_naming_a_directory_that_does_not_exist_is_refused_as_missing() {
    let w = world();
    let (_, rest) = w.issued.value().split_once('.').unwrap();
    let other = format!("{LOGIN}-deadbeef.{rest}");
    let s = here(VAR, TOKEN);
    assert_eq!(
        w.verify_with(&claim(Some(&other), &s)),
        Err(SessionProof::Missing)
    );
}

#[test]
fn a_proof_with_a_path_in_it_is_refused_as_malformed() {
    let w = world();
    let s = here(VAR, TOKEN);
    let bad = format!("../{LOGIN}-ab.{}.{}", "00".repeat(32), "00".repeat(32));
    assert_eq!(
        w.verify_with(&claim(Some(&bad), &s)),
        Err(SessionProof::Malformed)
    );
}

#[test]
fn a_different_session_value_is_refused_as_wrong_session() {
    let w = world();
    let s = here(VAR, "another-dummy-session-token");
    assert_eq!(
        w.verify_with(&claim(Some(w.issued.value()), &s)),
        Err(SessionProof::WrongSession)
    );
}

#[test]
fn an_inherited_session_beside_the_logins_own_is_refused_as_wrong_session() {
    let w = world();
    let mut s = here(VAR, TOKEN);
    s.extend(here("OP_SESSION_OTHER", "inherited-dummy-token"));
    assert_eq!(
        w.verify_with(&claim(Some(w.issued.value()), &s)),
        Err(SessionProof::WrongSession)
    );
}

#[test]
fn a_process_outside_the_logins_tree_is_refused_as_not_an_ancestor() {
    let w = world();
    // Another terminal's opv, a child of the outer shell, not of the login.
    w.procs.set(ME, |s, _| s.ppid = SHELL);
    assert_eq!(w.verify(), Err(SessionProof::NotAncestor));
}

#[test]
fn a_proof_whose_login_has_exited_is_refused_as_stale() {
    let w = world();
    w.procs.kill(LOGIN);
    assert_eq!(w.verify(), Err(SessionProof::Stale));
}

#[test]
fn a_proof_whose_login_pid_was_reused_is_refused_as_stale() {
    let w = world();
    w.procs.set(LOGIN, |s, _| s.start = 999);
    assert_eq!(w.verify(), Err(SessionProof::Stale));
}

#[test]
fn a_proof_whose_pid_now_runs_another_program_is_refused_as_stale() {
    let w = world();
    w.procs.set(LOGIN, |_, e| *e = PathBuf::from("/bin/bash"));
    assert_eq!(w.verify(), Err(SessionProof::Stale));
}

#[test]
fn an_upgraded_opv_binary_mid_login_still_matches() {
    let w = world();
    w.procs
        .set(LOGIN, |_, e| *e = PathBuf::from(format!("{OPV} (deleted)")));
    assert_eq!(w.verify(), Ok(()));
}

#[test]
fn another_controlling_terminal_is_refused() {
    let w = world();
    w.procs.set(ME, |s, _| s.tty = TTY + 1);
    assert_eq!(w.verify(), Err(SessionProof::OtherTerminal));
}

#[test]
fn a_record_others_can_read_is_refused_as_unsafe() {
    use std::os::unix::fs::PermissionsExt;
    let w = world();
    std::fs::set_permissions(w.record_path(), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(w.verify(), Err(SessionProof::UnsafeRecord));
}

#[test]
fn a_record_replaced_by_a_link_is_refused_as_unsafe() {
    let w = world();
    let elsewhere = w.runtime.join("elsewhere");
    std::fs::rename(w.record_path(), &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, w.record_path()).unwrap();
    assert_eq!(w.verify(), Err(SessionProof::UnsafeRecord));
}

#[test]
fn a_removed_record_is_refused_as_missing() {
    let w = world();
    std::fs::remove_file(w.record_path()).unwrap();
    assert_eq!(w.verify(), Err(SessionProof::Missing));
}

#[test]
fn an_invalid_runtime_directory_is_refused() {
    let w = world();
    let s = here(VAR, TOKEN);
    let c = claim(Some(w.issued.value()), &s);
    assert_eq!(
        verify(&c, Err(SessionProof::RuntimeDir), &w.procs),
        Err(SessionProof::RuntimeDir)
    );
}

#[test]
fn dropping_the_proof_removes_its_record() {
    let w = world();
    let dir = w.issued.dir().to_path_buf();
    drop(w.issued);
    assert!(!dir.exists());
}

#[test]
fn a_tag_changed_in_the_proof_is_refused_as_wrong_session() {
    let w = world();
    let mut parts: Vec<String> = w.issued.value().split('.').map(String::from).collect();
    parts[2] = "cd".repeat(32);
    let changed = parts.join(".");
    let s = here(VAR, TOKEN);
    assert_eq!(
        w.verify_with(&claim(Some(&changed), &s)),
        Err(SessionProof::WrongSession)
    );
}

#[test]
fn the_record_holds_no_digest_of_the_session() {
    let w = world();
    let tag = w.issued.value().split('.').nth(2).unwrap();
    let body = std::fs::read_to_string(w.record_path()).unwrap();
    assert!(!body.contains(tag));
}

#[test]
fn the_record_holds_no_session_value() {
    let w = world();
    let body = std::fs::read_to_string(w.record_path()).unwrap();
    assert!(!body.contains(TOKEN));
}

#[test]
fn the_record_holds_no_nonce() {
    let w = world();
    let nonce = w.issued.value().split('.').nth(1).unwrap();
    let body = std::fs::read_to_string(w.record_path()).unwrap();
    assert!(!body.contains(nonce));
}

#[test]
fn no_proof_is_issued_without_a_fresh_session() {
    let tmp = tempfile::tempdir().unwrap();
    let r = issue(&[], Ok(tmp.path()), &Fake::tree());
    assert_eq!(r.err(), Some(SessionProof::NoProof));
}

#[test]
fn no_proof_is_issued_without_a_controlling_terminal() {
    let tmp = tempfile::tempdir().unwrap();
    let procs = Fake::tree();
    procs.set(LOGIN, |s, _| s.tty = 0);
    let r = issue(&login_session(), Ok(tmp.path()), &procs);
    assert_eq!(r.err(), Some(SessionProof::NoTerminal));
}

#[test]
fn proc_stat_with_parentheses_in_the_name_parses() {
    let line = "4242 (my (odd) name) S 4000 4242 4000 34816 4242 4194304 0 0 0 0 0 0 0 0 20 0 1 0 987654 0 0";
    assert_eq!(
        parse_stat(line),
        Some(ProcStat {
            ppid: 4000,
            start: 987654,
            tty: 34816
        })
    );
}

/// #353 on WSL: `opv login` clears PR_SET_DUMPABLE, so the kernel hides its `exe` link from
/// the provisioning process; the proof must still be accepted from the command name.
#[test]
fn a_non_dumpable_login_whose_exe_is_hidden_is_accepted_by_command_name() {
    let w = world();
    let name = PathBuf::from(OPV)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    w.procs.set(LOGIN, |_, e| *e = PathBuf::new());
    w.procs.comms.borrow_mut().insert(LOGIN, name);
    assert_eq!(w.verify(), Ok(()));
}

#[test]
fn a_hidden_exe_with_another_command_name_is_refused_as_stale() {
    let w = world();
    w.procs.set(LOGIN, |_, e| *e = PathBuf::new());
    w.procs.comms.borrow_mut().insert(LOGIN, "bash".into());
    assert_eq!(w.verify(), Err(SessionProof::Stale));
}

#[test]
fn a_hidden_exe_with_a_reused_pid_is_still_refused_as_stale() {
    let w = world();
    w.procs.set(LOGIN, |s, e| {
        *e = PathBuf::new();
        s.start = 999;
    });
    assert_eq!(w.verify(), Err(SessionProof::Stale));
}
