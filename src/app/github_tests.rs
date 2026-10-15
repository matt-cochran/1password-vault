//! `status`, `plan` and `sync` on a GitHub Actions target, end to end through the real
//! adapters against a stateful fake of `op` and `gh`: the write scenarios and the
//! interruption matrix (NR-1, NR-2, NR-28).
//!
//! [`Gh`] serves the 1Password item read exactly as `staged_tests::Sim` does and keeps,
//! per repository and GitHub environment, secrets as name → (value, `updatedAt` counter)
//! and variables as name → value. Like GitHub, a secret is never read back: every ready
//! secret is written each sync, a variable is compared by value, and a `--prune` removes
//! the managed names of a product that this environment no longer wants while an
//! unmanaged name is never touched.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io;
use std::time::Duration;

use serde_json::{Value, json};

use super::sync::{self, SyncOpts};
use super::testutil::*;
use crate::domain::Fleet;
use crate::error::Error;
use crate::runner::{Call, CommandRunner, Outcome, Output};

const CI_SECRET: &str = "CI_SECRET";
const CI_POLICY: &str = "CI_POLICY";
const RETIRED_SECRET: &str = "RETIRED_SECRET";
const RETIRED_POLICY: &str = "RETIRED_POLICY";
const OTHER_TOOL: &str = "OTHER_TOOL_TOKEN";
const CI_SECRET_VALUE: &str = "sk-proj-FIXTUREVALUE-ci";
const POLICY_V1: &str = "open";
const POLICY_V2: &str = "invite_only";

/// The ci environment and the allumata keys declared for it, plus two keys declared for
/// staging only so `--prune` has managed names to remove in ci.
const CI_KEYS: &str = r#"
[environments.ci]
boundaries.allumata = { vault_id = "vci", item_id = "ici" }

[environments.ci.targets.app]
state_vault_id = "sci"
github.repo = "example-org/example-repo"

[products.allumata.keys.CI_SECRET]
kind = "secret"
environments = ["ci"]
guidance = "CI test secret"

[products.allumata.keys.CI_POLICY]
kind = "config"
environments = ["ci"]
rules = { enum = ["open", "invite_only"] }
guidance = "CI test config"

[products.allumata.keys.RETIRED_SECRET]
kind = "secret"
environments = ["staging"]

[products.allumata.keys.RETIRED_POLICY]
kind = "config"
environments = ["staging"]
"#;

/// The same keys on two repositories, under the GitHub environment `staging`.
const CI_KEYS_TWO: &str = r#"
[environments.ci]
boundaries.allumata = { vault_id = "vci", item_id = "ici" }

[environments.ci.targets.app]
state_vault_id = "sci"
github.repos = ["example-org/a", "example-org/b"]
github.environment = "staging"

[products.allumata.keys.CI_SECRET]
kind = "secret"
environments = ["ci"]

[products.allumata.keys.CI_POLICY]
kind = "config"
environments = ["ci"]
rules = { enum = ["open", "invite_only"] }

[products.allumata.keys.RETIRED_SECRET]
kind = "secret"
environments = ["staging"]

[products.allumata.keys.RETIRED_POLICY]
kind = "config"
environments = ["staging"]
"#;

fn fleet_ci() -> Fleet {
    fleet_with(CI_KEYS)
}

fn fleet_ci_two() -> Fleet {
    fleet_with(CI_KEYS_TWO)
}

/// The fixture item plus the two keys ready in ci.
fn ci_item(policy: &str) -> Output {
    let mut fs = complete_fields();
    fs.push(secret("allumata", CI_SECRET, CI_SECRET_VALUE));
    fs.push(text("allumata", CI_POLICY, policy));
    item(&fs)
}

/// The fixture item with `CI_POLICY` kept in a concealed field (never published as config).
fn ci_item_concealed() -> Output {
    let mut fs = complete_fields();
    fs.push(secret("allumata", CI_SECRET, CI_SECRET_VALUE));
    fs.push(secret("allumata", CI_POLICY, POLICY_V1));
    item(&fs)
}

/// A repository and GitHub environment (both owned) as the scope of one `gh` call.
type Scope = (String, Option<String>);

#[derive(Default)]
struct World {
    item: Vec<u8>,
    /// name → (value, `updatedAt` counter) per scope. GitHub never reads a value back.
    secrets: BTreeMap<Scope, BTreeMap<String, (String, i64)>>,
    /// name → value per scope.
    variables: BTreeMap<Scope, BTreeMap<String, String>>,
    /// repository → GitHub environments it has (an unknown repository lists `staging`).
    environments: BTreeMap<String, Vec<String>>,
    clock: i64,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Fail {
    /// The outcome is lost after the call took effect (a write) or was answered (a read).
    After,
    /// The call never reached GitHub.
    Before,
}

struct Rec {
    program: String,
    args: Vec<String>,
    stdin: Option<Vec<u8>>,
}

/// A stateful fake of `op` (the item read) and `gh` (GitHub Actions secrets, variables and
/// environments).
#[derive(Default)]
struct Gh {
    world: RefCell<World>,
    calls: RefCell<Vec<Rec>>,
    n: Cell<usize>,
    fail_at: Cell<Option<(usize, Fail)>>,
    wrote: Cell<bool>,
}

fn scope_of(args: &[&str]) -> Scope {
    let mut repo = String::new();
    let mut env = None;
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "-R" => {
                repo = args.get(i + 1).copied().unwrap_or_default().to_string();
                i += 2;
            }
            "-e" => {
                env = args.get(i + 1).map(|s| s.to_string());
                i += 2;
            }
            _ => i += 1,
        }
    }
    (repo, env)
}

/// A GitHub `updatedAt` in the fixture's shape, rising with the counter.
fn stamp(v: i64) -> String {
    format!(
        "2026-10-13T{:02}:{:02}:{:02}Z",
        v / 3600,
        (v / 60) % 60,
        v % 60
    )
}

impl Gh {
    fn new(item: Output) -> Self {
        let sim = Gh::default();
        sim.world.borrow_mut().item = item.stdout.to_vec();
        sim
    }

    /// Forget the previous run's calls and writes: the next run is a new process.
    fn reset(&self) {
        self.n.set(0);
        self.wrote.set(false);
        self.calls.borrow_mut().clear();
    }

    /// `program args...` of every call of the last run, for exact-sequence and SR-3 checks.
    fn argvs(&self) -> Vec<String> {
        self.calls
            .borrow()
            .iter()
            .map(|c| format!("{} {}", c.program, c.args.join(" ")))
            .collect()
    }

    /// True when any recorded argv word equals `needle` (SR-3: values never in argv).
    fn argv_contains(&self, needle: &str) -> bool {
        self.calls
            .borrow()
            .iter()
            .any(|c| c.program.contains(needle) || c.args.iter().any(|a| a.contains(needle)))
    }

    /// The `(repo, environment)` pairs of every `gh secret set` for `name`.
    fn secret_set_repos(&self, name: &str) -> Vec<String> {
        self.calls
            .borrow()
            .iter()
            .filter(|c| c.program == "gh" && c.args.first().is_some_and(|a| a == "secret"))
            .filter(|c| c.args.get(1).is_some_and(|a| a == "set"))
            .filter(|c| c.args.get(2).is_some_and(|a| a == name))
            .map(|c| scope_of(&c.args.iter().map(String::as_str).collect::<Vec<_>>()).0)
            .collect()
    }

    /// The stdin bytes of every `gh secret set` for `name` (the value never in argv).
    fn secret_set_stdin(&self, name: &str) -> Vec<Vec<u8>> {
        self.calls
            .borrow()
            .iter()
            .filter(|c| {
                c.program == "gh"
                    && c.args.first().is_some_and(|a| a == "secret")
                    && c.args.get(1).is_some_and(|a| a == "set")
                    && c.args.get(2).is_some_and(|a| a == name)
            })
            .filter_map(|c| c.stdin.clone())
            .collect()
    }

    fn wrote_gh(&self) -> bool {
        self.calls.borrow().iter().any(|c| {
            c.program == "gh" && matches!(c.args.get(1).map(String::as_str), Some("set" | "delete"))
        })
    }

    fn list_secrets(&self, repo: &str, env: Option<&str>) -> Output {
        let scope = (repo.to_string(), env.map(str::to_string));
        let w = self.world.borrow();
        let arr: Vec<Value> = w
            .secrets
            .get(&scope)
            .map(|m| {
                m.iter()
                    .map(|(n, (_, v))| json!({"name": n, "updatedAt": stamp(*v)}))
                    .collect()
            })
            .unwrap_or_default();
        Output::success(serde_json::to_vec(&arr).unwrap())
    }

    fn list_variables(&self, repo: &str, env: Option<&str>) -> Output {
        let scope = (repo.to_string(), env.map(str::to_string));
        let w = self.world.borrow();
        let arr: Vec<Value> = w
            .variables
            .get(&scope)
            .map(|m| {
                m.iter()
                    .map(|(n, v)| json!({"name": n, "value": v, "updatedAt": stamp(0)}))
                    .collect()
            })
            .unwrap_or_default();
        Output::success(serde_json::to_vec(&arr).unwrap())
    }
}

impl Gh {
    /// Answer one `gh` call against the world.
    fn exec(&self, program: &str, args: &[&str], stdin: Option<&[u8]>) -> Output {
        if program == "op" {
            return Output::success(self.world.borrow().item.clone());
        }
        match args {
            ["secret", "list", ..] | ["variable", "list", ..] => {
                let (repo, env) = scope_of(args);
                if args[0] == "secret" {
                    self.list_secrets(&repo, env.as_deref())
                } else {
                    self.list_variables(&repo, env.as_deref())
                }
            }
            ["secret", "set", name, ..] => {
                let (repo, env) = scope_of(args);
                let value = String::from_utf8(stdin.unwrap_or_default().to_vec()).unwrap();
                let mut w = self.world.borrow_mut();
                w.clock += 1;
                let v = w.clock;
                w.secrets
                    .entry((repo, env))
                    .or_default()
                    .insert((*name).to_string(), (value, v));
                ok()
            }
            ["variable", "set", name, ..] => {
                let (repo, env) = scope_of(args);
                let value = String::from_utf8(stdin.unwrap_or_default().to_vec()).unwrap();
                self.world
                    .borrow_mut()
                    .variables
                    .entry((repo, env))
                    .or_default()
                    .insert((*name).to_string(), value);
                ok()
            }
            ["secret", "delete", name, ..] => {
                let (repo, env) = scope_of(args);
                let gone = self
                    .world
                    .borrow_mut()
                    .secrets
                    .entry((repo, env))
                    .or_default()
                    .remove(*name);
                if gone.is_some() {
                    ok()
                } else {
                    Output::failure(1)
                }
            }
            ["variable", "delete", name, ..] => {
                let (repo, env) = scope_of(args);
                let gone = self
                    .world
                    .borrow_mut()
                    .variables
                    .entry((repo, env))
                    .or_default()
                    .remove(*name);
                if gone.is_some() {
                    ok()
                } else {
                    Output::failure(1)
                }
            }
            ["api", path, ..] => {
                let repo = path
                    .strip_prefix("repos/")
                    .and_then(|p| p.strip_suffix("/environments"))
                    .unwrap_or_default();
                let names = self
                    .world
                    .borrow()
                    .environments
                    .get(repo)
                    .cloned()
                    .unwrap_or_else(|| vec!["staging".to_string()]);
                let arr: Vec<Value> = names.iter().map(|n| json!({"name": n})).collect();
                Output::success(serde_json::to_vec(&json!({"environments": arr})).unwrap())
            }
            other => panic!("Gh: unexpected call {program} {other:?}"),
        }
    }

    /// Counts the call; on the failing index returns the lost outcome (a write takes effect
    /// first when the failure is `After`).
    fn step(&self, call: &Call<'_>, write: bool) -> Result<Output, Outcome> {
        let k = self.n.get();
        self.n.set(k + 1);
        self.calls.borrow_mut().push(Rec {
            program: call.program.to_string(),
            args: call.args.iter().map(|a| a.to_string()).collect(),
            stdin: call.stdin.map(<[u8]>::to_vec),
        });
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

    /// Secrets (name → value) and variables (name → value) of every scope: values and
    /// names only, never an `updatedAt`, so two runs converge when they store the same.
    fn end_state(&self) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
        let w = self.world.borrow();
        let secrets = w
            .secrets
            .values()
            .flat_map(|m| m.iter().map(|(n, (v, _))| (n.clone(), v.clone())))
            .collect();
        let variables = w
            .variables
            .values()
            .flat_map(|m| m.iter().map(|(n, v)| (n.clone(), v.clone())))
            .collect();
        (secrets, variables)
    }
}

impl CommandRunner for Gh {
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

    /// Diagnosis probes (the `gh auth status` after a failure, `op whoami`) succeed.
    fn probe(&self, _call: &Call<'_>, _limit: Duration) -> io::Result<Output> {
        Ok(ok())
    }

    fn pause(&self, _: Duration, _: &str) {}

    fn note(&self, _: &str) {}

    fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> io::Result<i32> {
        unreachable!("sync never runs a child")
    }
}

/// Run `sync` on the `ci` environment of `fleet`, returning its result and stdout.
fn sync_on(sim: &Gh, fleet: &Fleet, opts: &SyncOpts) -> (Result<(), Error>, String) {
    sim.reset();
    let mut out = Vec::new();
    let res = sync::run(fleet, "ci", sim, &mut out, opts);
    (res, text_of(&out))
}

/// A fresh, empty GitHub target holding the item with `POLICY_V1`.
fn first_sync() -> Gh {
    Gh::new(ci_item(POLICY_V1))
}

/// A converged app whose item now holds `POLICY_V2` and whose target still holds a managed
/// secret and variable that ci no longer declares.
fn change_and_prune() -> Gh {
    let sim = first_sync();
    sync_on(&sim, &fleet_ci(), &SyncOpts::default()).0.unwrap();
    {
        let mut w = sim.world.borrow_mut();
        let scope = ("example-org/example-repo".to_string(), None);
        w.secrets.entry(scope.clone()).or_default().insert(
            RETIRED_SECRET.to_string(),
            ("old-FIXTUREVALUE".to_string(), 900),
        );
        w.variables
            .entry(scope)
            .or_default()
            .insert(RETIRED_POLICY.to_string(), "old-FIXTUREVALUE".to_string());
    }
    sim.world.borrow_mut().item = ci_item(POLICY_V2).stdout.to_vec();
    sim
}

fn prune() -> SyncOpts {
    SyncOpts {
        prune: true,
        ..Default::default()
    }
}

/// Decides one matrix cell from the interrupted run's result, the world after the
/// re-run, and the re-run's result.
type Judge<'a> = dyn Fn(&Result<(), Error>, &Gh, &Result<(), Error>) -> bool + 'a;

/// Every call of the reference run from `start`, failed both ways: the runs `judge`
/// rejects, given the interrupted run's result and the world after a clean re-run.
fn matrix(start: &dyn Fn() -> Gh, opts: &SyncOpts, judge: &Judge) -> Vec<String> {
    let reference = start();
    sync_on(&reference, &fleet_ci(), opts).0.unwrap();
    let n = reference.n.get();
    let mut bad = Vec::new();
    for k in 0..n {
        for mode in [Fail::After, Fail::Before] {
            let sim = start();
            sim.fail_at.set(Some((k, mode)));
            let interrupted = sync_on(&sim, &fleet_ci(), opts).0;
            sim.fail_at.set(None);
            let rerun = sync_on(&sim, &fleet_ci(), opts).0;
            if !judge(&interrupted, &sim, &rerun) {
                bad.push(format!("call {k} {mode:?}: {interrupted:?} then {rerun:?}"));
            }
        }
    }
    bad
}

/// The re-run succeeds and ends where an uninterrupted run ends (NR-1).
fn converges(start: &dyn Fn() -> Gh, opts: &SyncOpts) -> Vec<String> {
    let reference = start();
    sync_on(&reference, &fleet_ci(), opts).0.unwrap();
    let want = reference.end_state();
    matrix(start, opts, &|_, sim, rerun| {
        rerun.is_ok() && sim.end_state() == want
    })
}

/// The interrupted run either finished (its lost outcome reconciled) or exits 9: never a
/// "fix something" code for a call whose outcome is merely unknown (NR-2, NR-28).
fn exits_9_when_interrupted(start: &dyn Fn() -> Gh, opts: &SyncOpts) -> Vec<String> {
    matrix(start, opts, &|interrupted, _, _| match interrupted {
        Ok(()) => true,
        Err(e) => e.exit_code() == 9,
    })
}

#[test]
fn first_sync_writes_the_ready_secret_and_config_variable() {
    let sim = first_sync();
    let (res, out) = sync_on(&sim, &fleet_ci(), &SyncOpts::default());
    res.unwrap();
    assert!(
        out.lines()
            .any(|l| l.contains("written:") && l.contains(CI_SECRET) && l.contains(CI_POLICY)),
        "{out}"
    );
}

#[test]
fn first_sync_prints_no_pending_deploy_line() {
    let sim = first_sync();
    let (_, out) = sync_on(&sim, &fleet_ci(), &SyncOpts::default());
    assert!(!out.contains("pending deploy"), "{out}");
}

#[test]
fn sync_deploy_says_github_applies_each_write_at_once() {
    let sim = first_sync();
    let (res, out) = sync_on(
        &sim,
        &fleet_ci(),
        &SyncOpts {
            deploy: true,
            ..Default::default()
        },
    );
    res.unwrap();
    assert!(
        out.lines()
            .any(|l| l == "ci/app: nothing to deploy: GitHub applies each write at once"),
        "{out}"
    );
}

#[test]
fn second_sync_reports_the_config_variable_unchanged() {
    let sim = first_sync();
    sync_on(&sim, &fleet_ci(), &SyncOpts::default()).0.unwrap();
    let (_, out) = sync_on(&sim, &fleet_ci(), &SyncOpts::default());
    assert!(
        out.lines()
            .any(|l| l.contains("unchanged:") && l.contains(CI_POLICY)),
        "{out}"
    );
}

#[test]
fn second_sync_writes_the_secret_again() {
    let sim = first_sync();
    sync_on(&sim, &fleet_ci(), &SyncOpts::default()).0.unwrap();
    let (_, out) = sync_on(&sim, &fleet_ci(), &SyncOpts::default());
    assert!(
        out.lines()
            .any(|l| l.contains("written:") && l.contains(CI_SECRET)),
        "{out}"
    );
}

#[test]
fn changed_config_value_replaces_the_stored_one() {
    let sim = change_and_prune();
    sync_on(&sim, &fleet_ci(), &prune()).0.unwrap();
    let scope = ("example-org/example-repo".to_string(), None);
    let w = sim.world.borrow();
    assert_eq!(
        w.variables
            .get(&scope)
            .and_then(|m| m.get(CI_POLICY))
            .map(String::as_str),
        Some(POLICY_V2)
    );
}

fn scope() -> Scope {
    ("example-org/example-repo".to_string(), None)
}

fn with_unmanaged(sim: Gh) -> Gh {
    sim.world
        .borrow_mut()
        .secrets
        .entry(scope())
        .or_default()
        .insert(OTHER_TOOL.to_string(), ("x-FIXTUREVALUE".to_string(), 950));
    sim
}

/// A two-repository target whose first repository has no `staging` environment.
fn missing_staging_on_a() -> Gh {
    let sim = Gh::new(ci_item(POLICY_V1));
    sim.world
        .borrow_mut()
        .environments
        .insert("example-org/a".to_string(), vec!["production".to_string()]);
    sim
}

#[test]
fn prune_removes_the_managed_secret_and_variable() {
    let sim = change_and_prune();
    sync_on(&sim, &fleet_ci(), &prune()).0.unwrap();
    let (secrets, variables) = sim.end_state();
    assert!(
        !secrets.contains_key(RETIRED_SECRET) && !variables.contains_key(RETIRED_POLICY),
        "secrets={secrets:?} variables={variables:?}"
    );
}

#[test]
fn prune_never_touches_an_unmanaged_name() {
    let sim = with_unmanaged(change_and_prune());
    sync_on(&sim, &fleet_ci(), &prune()).0.unwrap();
    assert!(sim.end_state().0.contains_key(OTHER_TOOL));
}

#[test]
fn without_prune_lists_the_retired_names_as_kept() {
    let sim = change_and_prune();
    let (_, out) = sync_on(&sim, &fleet_ci(), &SyncOpts::default());
    assert!(
        out.contains("extra, not pruned")
            && out.contains(RETIRED_SECRET)
            && out.contains(RETIRED_POLICY),
        "{out}"
    );
}

#[test]
fn plan_reports_a_new_config_row() {
    let sim = first_sync();
    let mut out = Vec::new();
    super::sync::plan(&fleet_ci(), "ci", &sim, &mut out).unwrap();
    let out = text_of(&out);
    assert!(
        out.lines()
            .any(|l| l.contains(CI_POLICY) && l.contains("new")),
        "{out}"
    );
}

#[test]
fn plan_reports_a_same_config_row_after_a_sync() {
    let sim = first_sync();
    sync_on(&sim, &fleet_ci(), &SyncOpts::default()).0.unwrap();
    let mut out = Vec::new();
    super::sync::plan(&fleet_ci(), "ci", &sim, &mut out).unwrap();
    let out = text_of(&out);
    assert!(
        out.lines()
            .any(|l| l.contains(CI_POLICY) && l.contains("same")),
        "{out}"
    );
}

#[test]
fn plan_reports_a_changed_config_row() {
    let sim = change_and_prune();
    let mut out = Vec::new();
    super::sync::plan(&fleet_ci(), "ci", &sim, &mut out).unwrap();
    let out = text_of(&out);
    assert!(
        out.lines()
            .any(|l| l.contains(CI_POLICY) && l.contains("changed")),
        "{out}"
    );
}

#[test]
fn plan_would_write_the_config_variable() {
    let sim = first_sync();
    let mut out = Vec::new();
    super::sync::plan(&fleet_ci(), "ci", &sim, &mut out).unwrap();
    let out = text_of(&out);
    assert!(
        out.lines()
            .any(|l| l.contains("would write") && l.contains(CI_POLICY)),
        "{out}"
    );
}

#[test]
fn concealed_config_blocks_sync_and_names_the_rule() {
    let sim = Gh::new(ci_item_concealed());
    let err = sync_on(&sim, &fleet_ci(), &SyncOpts::default())
        .0
        .unwrap_err();
    assert!(err.mentions("concealed-config"), "{err}");
}

#[test]
fn concealed_config_exits_with_a_blocking_code() {
    let sim = Gh::new(ci_item_concealed());
    let err = sync_on(&sim, &fleet_ci(), &SyncOpts::default())
        .0
        .unwrap_err();
    assert!([6, 8].contains(&err.exit_code()), "{}", err.exit_code());
}

#[test]
fn concealed_config_blocks_before_any_gh_write() {
    let sim = Gh::new(ci_item_concealed());
    let _ = sync_on(&sim, &fleet_ci(), &SyncOpts::default());
    assert!(!sim.wrote_gh(), "{:?}", sim.argvs());
}

#[test]
fn missing_environment_offers_the_create_command() {
    let sim = missing_staging_on_a();
    let err = sync_on(&sim, &fleet_ci_two(), &SyncOpts::default())
        .0
        .unwrap_err();
    assert!(
        err.mentions("gh api -X PUT repos/example-org/a/environments/staging"),
        "{err}"
    );
}

#[test]
fn missing_environment_refuses_before_any_gh_write() {
    let sim = missing_staging_on_a();
    let _ = sync_on(&sim, &fleet_ci_two(), &SyncOpts::default());
    assert!(!sim.wrote_gh(), "{:?}", sim.argvs());
}

#[test]
fn two_repos_receive_every_secret() {
    let sim = Gh::new(ci_item(POLICY_V1));
    sync_on(&sim, &fleet_ci_two(), &SyncOpts::default())
        .0
        .unwrap();
    let mut repos = sim.secret_set_repos(CI_SECRET);
    repos.sort();
    assert_eq!(repos, ["example-org/a", "example-org/b"]);
}

#[test]
fn secret_set_reads_the_value_from_stdin() {
    let sim = first_sync();
    sync_on(&sim, &fleet_ci(), &SyncOpts::default()).0.unwrap();
    assert!(
        sim.secret_set_stdin(CI_SECRET)
            .iter()
            .any(|v| v == CI_SECRET_VALUE.as_bytes())
    );
}

#[test]
fn first_sync_never_puts_a_value_in_argv() {
    let sim = first_sync();
    sync_on(&sim, &fleet_ci(), &SyncOpts::default()).0.unwrap();
    assert!(
        !sim.argv_contains(MARKER) && !sim.argv_contains(&enc()),
        "{:?}",
        sim.argvs()
    );
}

#[test]
fn status_reports_the_config_variable_as_same_after_a_sync() {
    let sim = first_sync();
    sync_on(&sim, &fleet_ci(), &SyncOpts::default()).0.unwrap();
    let mut out = Vec::new();
    super::status::run(&fleet_ci(), "ci", &sim, &mut out).unwrap();
    let out = text_of(&out);
    assert!(
        out.lines()
            .any(|l| l.contains(CI_POLICY) && l.contains("same")),
        "{out}"
    );
}

#[test]
fn first_sync_converges_after_interruption_at_every_call() {
    let bad = converges(&first_sync, &SyncOpts::default());
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn change_and_prune_converges_after_interruption_at_every_call() {
    let bad = converges(&change_and_prune, &prune());
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn first_sync_interrupted_at_any_call_exits_9() {
    let bad = exits_9_when_interrupted(&first_sync, &SyncOpts::default());
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn change_and_prune_interrupted_at_any_call_exits_9() {
    let bad = exits_9_when_interrupted(&change_and_prune, &prune());
    assert!(bad.is_empty(), "{bad:#?}");
}
