//! `sync` through the staged flow (stage, list B, unset, deploy) against a stateful fake of
//! the 1Password and target CLIs, end to end through the real adapters: the interruption
//! matrix (NR-1) and the exit code of every interrupted run (NR-2, NR-28).
//!
//! [`Sim`] keeps the app's secrets as the target lists them (digest and status) and what
//! the running machines hold. As recorded in D0, a staged import shows `Staged` with its
//! new digest until a deploy, re-staging an identical value changes nothing, and a staged
//! unset leaves the list at once. Call `k` of a run can be made to fail with an unknown
//! outcome, after its effect for writes or before it.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io;
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::sync::{self, SyncOpts};
use super::testutil::*;
use crate::domain::Fleet;
use crate::error::Error;
use crate::runner::{Call, CommandRunner, Outcome, Output};

/// Declared for staging only, so a sync of prod prunes it.
const OLD: &str = "FLEET__ALLUMATA__OLD_KEY";
const OPENAI_V2: &str = "sk-proj-FIXTUREVALUE-2";

fn fleet_old() -> Fleet {
    fleet_with(
        r#"
[products.allumata.keys.OLD_KEY]
kind = "secret"
environments = ["staging"]
"#,
    )
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Fail {
    /// The outcome is lost after the call took effect (a write) or was answered (a read).
    After,
    /// The call never reached the target.
    Before,
}

#[derive(Default)]
struct World {
    item: Vec<u8>,
    /// What the store lists: name → (value, staged and not deployed).
    listed: BTreeMap<String, (String, bool)>,
    /// What the machines run with.
    live: BTreeMap<String, String>,
}

#[derive(Default)]
struct Sim {
    world: RefCell<World>,
    calls: Cell<usize>,
    fail_at: Cell<Option<(usize, Fail)>>,
    wrote: Cell<bool>,
}

fn digest(v: &str) -> String {
    hex::encode(Sha256::digest(v))[..16].to_string()
}

impl Sim {
    fn new(item: Output) -> Self {
        let sim = Sim::default();
        sim.world.borrow_mut().item = item.stdout.to_vec();
        sim
    }

    /// Forget the previous run's call count and writes: the next run is a new process.
    fn reset(&self) {
        self.calls.set(0);
        self.wrote.set(false);
    }

    fn exec(&self, program: &str, args: &[&str], stdin: Option<&[u8]>) -> Output {
        let mut w = self.world.borrow_mut();
        if program == "op" {
            return Output::success(w.item.clone());
        }
        match args {
            ["status", ..] => fly_app_ok(),
            ["releases", ..] => fly_releases("complete"),
            ["secrets", "list", ..] => {
                let v: Vec<Value> = w
                    .listed
                    .iter()
                    .map(|(n, (value, staged))| {
                        json!({
                            "name": n,
                            "digest": digest(value),
                            "status": if *staged { "Staged" } else { "Deployed" },
                        })
                    })
                    .collect();
                Output::success(serde_json::to_vec(&v).unwrap())
            }
            ["secrets", "import", ..] => {
                let text = String::from_utf8(stdin.unwrap().to_vec()).unwrap();
                for line in text.lines() {
                    let (name, quoted) = line.split_once('=').unwrap();
                    let value = quoted.trim_matches('"').to_string();
                    let same = w.listed.get(name).is_some_and(|(v, _)| *v == value);
                    if !same {
                        w.listed.insert(name.to_string(), (value, true));
                    }
                }
                ok()
            }
            ["secrets", "unset", rest @ ..] => {
                for name in rest.iter().take_while(|a| !a.starts_with("--")) {
                    w.listed.remove(*name);
                }
                ok()
            }
            ["secrets", "deploy", ..] => {
                w.live = w
                    .listed
                    .iter()
                    .map(|(n, (v, _))| (n.clone(), v.clone()))
                    .collect();
                for (_, staged) in w.listed.values_mut() {
                    *staged = false;
                }
                ok()
            }
            other => panic!("Sim: unexpected call {program} {other:?}"),
        }
    }

    /// Counts the call; on the failing index returns the lost outcome (a write takes
    /// effect first when the failure is `After`).
    fn step(&self, call: &Call<'_>, write: bool) -> Result<Output, Outcome> {
        let k = self.calls.get();
        self.calls.set(k + 1);
        let lost = Outcome::Unknown {
            reason: "lost",
            status: None,
        };
        match self.fail_at.get() {
            Some((at, Fail::After)) if at == k => {
                if write {
                    self.exec(call.program, call.args, call.stdin);
                }
                Err(lost)
            }
            Some((at, Fail::Before)) if at == k => Err(lost),
            _ => Ok(self.exec(call.program, call.args, call.stdin)),
        }
    }

    /// The store's list (names, values, pending) and the machines' env: values, never
    /// digests, so two runs compare equal when they converge.
    fn end_state(&self) -> (BTreeMap<String, (String, bool)>, BTreeMap<String, String>) {
        let w = self.world.borrow();
        // D0: a staged unset leaves the list at once, so a name unset by a run stopped
        // before its deploy stays on the machines, unseen by the next run, until any later
        // deploy. Only names the store still lists are compared on the machines.
        let live = w
            .live
            .iter()
            .filter(|(n, _)| w.listed.contains_key(*n))
            .map(|(n, v)| (n.clone(), v.clone()))
            .collect();
        (w.listed.clone(), live)
    }
}

impl CommandRunner for Sim {
    fn read(&self, call: &Call<'_>, _refused: &[i32]) -> io::Result<Outcome> {
        Ok(match self.step(call, false) {
            Err(o) => o,
            Ok(out) if out.status == 0 => Outcome::Done(out),
            Ok(out) => Outcome::Refused(out),
        })
    }

    fn write(&self, call: &Call<'_>) -> io::Result<Outcome> {
        if call.program != "op" {
            self.wrote.set(true);
        }
        Ok(match self.step(call, true) {
            Err(o) => o,
            Ok(out) if out.status == 0 => Outcome::Done(out),
            Ok(out) => Outcome::Unknown {
                reason: "failed-write",
                status: Some(out.status),
            },
        })
    }

    fn writes_started(&self) -> bool {
        self.wrote.get()
    }

    /// Diagnosis probes (sign-in checks) succeed.
    fn probe(&self, _call: &Call<'_>, _limit: Duration) -> io::Result<Output> {
        Ok(ok())
    }

    fn pause(&self, _: Duration, _: &str) {}

    fn note(&self, _: &str) {}

    fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> io::Result<i32> {
        unreachable!("sync never runs a child")
    }
}

fn deploy_prune() -> SyncOpts {
    SyncOpts {
        deploy: true,
        prune: true,
        ..Default::default()
    }
}

fn sync_on(sim: &Sim, fleet: &Fleet) -> Result<(), Error> {
    sim.reset();
    sync::run(fleet, "prod", sim, &mut Vec::new(), &deploy_prune())
}

/// An app with nothing on it yet.
fn first_sync() -> Sim {
    Sim::new(complete_item())
}

/// A deployed app holding a name the fleet no longer wants in prod, whose item now holds a
/// new OpenAI key.
fn change_and_prune() -> Sim {
    let sim = first_sync();
    sync_on(&sim, &fleet_old()).unwrap();
    {
        let mut w = sim.world.borrow_mut();
        w.listed
            .insert(OLD.into(), ("old-FIXTUREVALUE".into(), false));
        w.live.insert(OLD.into(), "old-FIXTUREVALUE".into());
    }
    sim.world.borrow_mut().item = complete_with(secret("allumata", "OPENAI_API_KEY", OPENAI_V2))
        .stdout
        .to_vec();
    sim
}

/// Decides one matrix cell from the interrupted run's result, the world after the
/// re-run, and the re-run's result.
type Judge<'a> = dyn Fn(&Result<(), Error>, &Sim, &Result<(), Error>) -> bool + 'a;

/// Every call of the reference run from `start`, failed both ways: the runs `judge`
/// rejects, given the interrupted run's result and the world after a clean re-run.
fn matrix(start: &dyn Fn() -> Sim, judge: &Judge) -> Vec<String> {
    let reference = start();
    sync_on(&reference, &fleet_old()).unwrap();
    let n = reference.calls.get();
    let mut bad = Vec::new();
    for k in 0..n {
        for mode in [Fail::After, Fail::Before] {
            let sim = start();
            sim.fail_at.set(Some((k, mode)));
            let interrupted = sync_on(&sim, &fleet_old());
            sim.fail_at.set(None);
            let rerun = sync_on(&sim, &fleet_old());
            if !judge(&interrupted, &sim, &rerun) {
                bad.push(format!("call {k} {mode:?}: {interrupted:?} then {rerun:?}"));
            }
        }
    }
    bad
}

/// The re-run succeeds and ends where an uninterrupted run ends (NR-1).
fn converges(start: &dyn Fn() -> Sim) -> Vec<String> {
    let reference = start();
    sync_on(&reference, &fleet_old()).unwrap();
    let want = reference.end_state();
    matrix(start, &|_, sim, rerun| {
        rerun.is_ok() && sim.end_state() == want
    })
}

/// The interrupted run either finished (its lost outcome reconciled) or exits 9: never
/// a "fix something" code for a call whose outcome is merely unknown (NR-2, NR-28).
fn exits_9_when_interrupted(start: &dyn Fn() -> Sim) -> Vec<String> {
    matrix(start, &|interrupted, _, _| match interrupted {
        Ok(()) => true,
        Err(e) => e.exit_code() == 9,
    })
}

#[test]
fn first_staged_sync_converges_after_interruption_at_every_call() {
    let bad = converges(&first_sync);
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn staged_change_and_prune_converge_after_interruption_at_every_call() {
    let bad = converges(&change_and_prune);
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn first_staged_sync_interrupted_at_any_call_exits_9() {
    let bad = exits_9_when_interrupted(&first_sync);
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn staged_change_and_prune_interrupted_at_any_call_exits_9() {
    let bad = exits_9_when_interrupted(&change_and_prune);
    assert!(bad.is_empty(), "{bad:#?}");
}

/// The reference run deploys what it staged: the machines run the new key.
#[test]
fn staged_change_reaches_the_machines() {
    let sim = change_and_prune();
    sync_on(&sim, &fleet_old()).unwrap();
    let w = sim.world.borrow();
    assert_eq!(w.live.get(OPENAI_FLY).map(String::as_str), Some(OPENAI_V2));
}
