//! The application × environment consistency flow on opv-sim (#179, scope row B7): one chain
//! from a key added in development to that key's retirement, on the real `opv` binary.
//!
//! The project has three environments in tier order, `dev` (local, no target), `staging`
//! (shared) and `prod` (production), the last two delivered to GitHub environments of one
//! repository. Its keys declare no `environments` list, so each is present everywhere. The
//! chain's steps, in order (each test below asserts one outcome of it):
//!
//! 1. the person applies the structure and imports `API_KEY` and `OLD_KEY` in every
//!    environment; CI syncs `staging` and `prod`;
//! 2. a developer adds `NEW_KEY` to the contract and sets it in `dev` only: `ready` shows
//!    it missing in `staging` and `prod`, and CI's `opv ready staging --gate` refuses;
//! 3. the person proposes a new environment `qa` (`opv propose env qa --write`, which
//!    declares the boundary its inherited keys need): it inherits every key, with no list to
//!    edit (the person's apply gives `qa` a field for each, and the inventory lists each
//!    present);
//! 4. `PARTIAL_KEY` is declared with an explicit list that leaves `prod` and `qa` out:
//!    `ready` names each as a non-blocking `environment_gap`;
//! 5. the person fills the gaps the gate refused on, CI syncs, and the staging gate passes;
//! 6. `OLD_KEY` is retired (`opv propose retire`, the code at `HEAD` no longer reads it). An
//!    environment `perf` added now gets nothing of it: no field, no finding, no cell. CI's
//!    `opv sync prod --prune --retire` is refused while `staging` still holds it; CI prunes
//!    `staging` and then `prod` (each recording its delivery, the pruned key out of it); CI
//!    cannot run the person's archive (`opv apply rp-…`: `terminal_required`, handed to the
//!    person); the person does, the result naming CI's syncs of staging and prod; `ready`
//!    then shows the key `retired` with no `retirement_incomplete` finding;
//! 7. the archive edited every boundary item, so staging's and prod's gates refuse until CI
//!    delivers again (the gate names the archive as a cause); then they pass, and the
//!    retired key is delivered nowhere.
//!
//! **The person's terminal.** `opv apply` refuses a run without a terminal and the harness
//! gives opv none, so the person's applies run in-process through the library with a
//! `FakeEnv` that is a person at a TTY and a runner whose every call runs the simulator
//! installed in the scenario, as `scenarios/assistant.rs` does. CI's attempt at the same
//! retirement apply runs the real binary and is refused. Everything else is the real
//! binary; every CI step runs with `CI=true GITHUB_ACTIONS=true`.
//!
//! Every value is an `S7MARKER` marker and the transcript holds none (the canary). The chain
//! runs once per test binary; its transcript is the snapshot
//! `tests/e2e/snapshots/scenarios/consistency_chain.snap`.

use std::io;
use std::sync::OnceLock;
use std::time::Duration;

use serde_json::Value;

use crate::coverage::{DEV_ACCOUNT, MARK, Scenario, scenario_snapshots, updating};

/// The scenario snapshot this module writes (`tests/e2e/snapshots/scenarios/`).
pub(crate) const SNAPSHOTS: &[&str] = &["consistency_chain"];

/// The project the checkout's `origin` names (`github.com/e2e-org/e2e-app`).
const PROJECT: &str = "e2e-app";
const REPO: &str = "e2e-org/e2e-app";

/// The contract the chain starts from: three environments in tier order, two keys present
/// everywhere (no `environments` list).
const CONTRACT: &str = r#"[environments.dev]
tier = "local"
order = 1
boundaries.app = {}

[environments.staging]
tier = "shared"
order = 2
boundaries.app = {}

[environments.staging.targets.gh]
github.repo = "e2e-org/e2e-app"
github.environment = "staging"

[environments.prod]
tier = "production"
order = 3
boundaries.app = {}

[environments.prod.targets.gh]
github.repo = "e2e-org/e2e-app"
github.environment = "production"

[products.app.keys.API_KEY]
kind = "secret"

[products.app.keys.OLD_KEY]
kind = "secret"
"#;

/// Step 2: a key added in development, present everywhere by default.
const ADD_KEY: &str = r#"
[products.app.keys.NEW_KEY]
kind = "secret"
"#;

/// Step 4: a key whose explicit list leaves `prod` and `qa` out.
const ADD_PARTIAL: &str = r#"
[products.app.keys.PARTIAL_KEY]
kind = "config"
environments = ["dev", "staging"]
"#;

/// The code at `HEAD`: it reads every key but `OLD_KEY`.
const CODE: &str = "fn main() {\n    let _ = std::env::var(\"API_KEY\");\n    \
                    let _ = std::env::var(\"NEW_KEY\");\n    \
                    let _ = std::env::var(\"PARTIAL_KEY\");\n}\n";

const CI_VARS: [(&str, &str); 2] = [("CI", "true"), ("GITHUB_ACTIONS", "true")];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Actor {
    Developer,
    Person,
    Ci,
}

impl Actor {
    fn word(self) -> &'static str {
        match self {
            Actor::Developer => "developer",
            Actor::Person => "person",
            Actor::Ci => "ci",
        }
    }
}

/// One `opv` run: its exit code and its stdout's first JSON document (`Null` when none).
struct Ran {
    code: Option<i32>,
    doc: Value,
}

/// What the chain produced: its transcript and each step's outcome.
struct Chain {
    transcript: String,
    /// Step 2: the environments with a blocking finding on `app/NEW_KEY`.
    new_key_blocked_in: Vec<String>,
    /// Step 2 and 5: the staging gate's exit code before and after the gaps were filled.
    staging_gate: (Option<i32>, Option<i32>),
    /// Step 3: `qa`'s presence of every key, as the inventory lists it.
    qa_presence: Vec<(String, String)>,
    /// Step 4: every `environment_gap` finding as (environment, key, blocking).
    gaps: Vec<(String, String, bool)>,
    /// Step 6: CI's out-of-order prune of prod: its error code and the guard's subject.
    prod_first: (String, Value),
    /// Step 6: the prunes' exit codes in the order CI ran them (staging, then prod).
    prunes: Vec<(String, Option<i32>)>,
    /// Step 6: which GitHub environments still hold `OLD_KEY` after the prunes.
    old_key_held_after_prunes: Vec<String>,
    /// Step 6: in `perf`, added while `OLD_KEY` is retiring: `ready`'s findings on it, the
    /// inventory's cells of it, and the fields of perf's boundary item.
    old_key_in_perf: (usize, usize, Vec<String>),
    /// Step 6: CI's attempt at the person's archive: its error code and its next step.
    ci_archive: (String, Value),
    /// Step 6: the person's archive: the environments archived, whether it marked the key,
    /// and the CI syncs it names.
    archive: Result<(Vec<String>, bool, Vec<String>), String>,
    /// Step 6: `OLD_KEY`'s lifecycle in the inventory afterwards, and every
    /// `retirement_incomplete` finding left.
    after: (Value, Vec<Value>),
    /// After the archive: `opv ready <env> --gate` for staging and prod, before and after
    /// CI delivers again.
    gates_after: Vec<(String, Option<i32>)>,
    /// Which GitHub environments hold `OLD_KEY` after CI's last syncs.
    old_key_held_at_end: Vec<String>,
}

/// A `ProcessRunner` whose every call runs inside the scenario: the simulator first on
/// `PATH`, the scenario's `HOME` and world, and the project's account.
struct SimRunner {
    inner: opv::runner::ProcessRunner,
    env: Vec<(String, String)>,
}

impl SimRunner {
    fn new(s: &Scenario) -> Self {
        let inner = opv::runner::ProcessRunner::new(
            opv::runner::Budget::starting_now(Duration::from_secs(120)),
            false,
        );
        inner.use_account(Some(DEV_ACCOUNT.to_string()));
        let env = vec![
            (
                "PATH".to_string(),
                format!("{}:/usr/bin:/bin", s.path("bin").display()),
            ),
            ("HOME".to_string(), s.path("home").display().to_string()),
            (
                "OPV_SIM_WORLD".to_string(),
                s.path("world").display().to_string(),
            ),
            ("OP_ACCOUNT".to_string(), DEV_ACCOUNT.to_string()),
        ];
        Self { inner, env }
    }

    /// `call` with the scenario's variables under its own.
    fn scoped<T>(
        &self,
        call: &opv::runner::Call<'_>,
        f: impl FnOnce(&opv::runner::Call<'_>) -> T,
    ) -> T {
        let mut env: Vec<(&str, &str)> = self
            .env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        env.extend(call.env.iter().copied());
        f(&opv::runner::Call { env: &env, ..*call })
    }
}

impl opv::runner::CommandRunner for SimRunner {
    fn read(&self, call: &opv::runner::Call, refused: &[i32]) -> io::Result<opv::runner::Outcome> {
        self.scoped(call, |c| self.inner.read(c, refused))
    }
    fn write(&self, call: &opv::runner::Call) -> io::Result<opv::runner::Outcome> {
        self.scoped(call, |c| self.inner.write(c))
    }
    fn create(
        &self,
        call: &opv::runner::Call,
        kind: opv::cause::CreateKind,
    ) -> io::Result<opv::runner::CreateOutcome> {
        self.scoped(call, |c| self.inner.create(c, kind))
    }
    fn writes_started(&self) -> bool {
        self.inner.writes_started()
    }
    fn probe(&self, call: &opv::runner::Call, limit: Duration) -> io::Result<opv::runner::Output> {
        self.scoped(call, |c| self.inner.probe(c, limit))
    }
    fn pause(&self, d: Duration, note: &str) {
        self.inner.pause(d, note)
    }
    fn note(&self, line: &str) {
        self.inner.note(line)
    }
    fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> io::Result<i32> {
        // The person's steps here never start a child of their own (`opv run`).
        Err(io::ErrorKind::Unsupported.into())
    }
    fn spawns_processes(&self) -> bool {
        self.inner.spawns_processes()
    }
}

/// `git <args>` in the project, with nothing of the host's configuration.
fn git(s: &Scenario, args: &[&str]) {
    let ok = std::process::Command::new("git")
        .args(args)
        .current_dir(s.path("project"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", s.path("home"))
        .env("GIT_AUTHOR_NAME", "e2e")
        .env("GIT_AUTHOR_EMAIL", "e2e@example.test")
        .env("GIT_COMMITTER_NAME", "e2e")
        .env("GIT_COMMITTER_EMAIL", "e2e@example.test")
        .status()
        .expect("git")
        .success();
    assert!(ok, "git {args:?}");
}

/// The scenario: the app's accounts with every value marked, no vault and no item in
/// 1Password, a GitHub repository with a `staging` and a `production` environment, and a
/// git checkout whose `HEAD` holds the code and the starting contract.
fn scenario() -> Scenario {
    let s = Scenario::new()
        .marked()
        .world(|w| {
            w["op"]["vaults"] = serde_json::json!([]);
            w["op"]["items"] = serde_json::json!([]);
            w["github"]["repos"][REPO]["environments"]["staging"] =
                serde_json::json!({"secrets": {}, "variables": {}});
        })
        .git_checkout()
        .file("project/secrets.toml", CONTRACT)
        .tracked("src/main.rs", CODE);
    std::fs::remove_file(s.path("project/secrets.bindings.toml")).expect("bindings");
    git(&s, &["add", "secrets.toml"]);
    git(&s, &["commit", "-qm", "the app"]);
    // The simulator is installed on the first command; the person's in-process apply
    // comes first, so install it now.
    drop(s.command());
    s
}

/// The chain's transcript, one section per step.
struct Transcript<'a> {
    s: &'a Scenario,
    text: String,
    n: usize,
}

impl Transcript<'_> {
    fn step(&mut self, actor: Actor, what: &str, body: &str) {
        self.n += 1;
        let body = self.s.normalize(body);
        // A delivery revision is minted at random for each sync, and an archived section
        // is named by today's date.
        let body = regex::Regex::new(r"\bdrv-[a-z2-7]+")
            .expect("regex")
            .replace_all(&body, "drv-<id>");
        let body = regex::Regex::new(r"\b\d{4}-\d{2}-\d{2}\b")
            .expect("regex")
            .replace_all(&body, "<date>");
        self.text.push_str(&format!(
            "\n## {}. {}: {what}\n{}\n",
            self.n,
            actor.word(),
            body.trim_end()
        ));
    }

    /// One `opv` run by the person or CI.
    fn opv(&mut self, actor: Actor, args: &[&str]) -> Ran {
        let mut c = self.s.command();
        c.args(args);
        if actor == Actor::Ci {
            c.envs(CI_VARS);
        }
        let out = c.output().expect("run opv");
        let body = format!(
            "exit: {}\nstdout:\n{}stderr:\n{}",
            out.status
                .code()
                .map_or("killed".to_string(), |c| c.to_string()),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        self.step(actor, &format!("opv {}", args.join(" ")), &body);
        Ran {
            code: out.status.code(),
            doc: serde_json::Deserializer::from_slice(&out.stdout)
                .into_iter::<Value>()
                .next()
                .and_then(Result::ok)
                .unwrap_or_default(),
        }
    }

    /// The developer's change to the contract, in the pull request.
    fn edit_contract(&mut self, what: &str, added: &str) {
        let p = self.s.path("project/secrets.toml");
        let mut text = std::fs::read_to_string(&p).expect("contract");
        text.push_str(added);
        std::fs::write(&p, text).expect("contract");
        self.step(Actor::Developer, what, added.trim_start());
    }

    /// The person's import of `keys` into `env`, from a file of marked values.
    fn import(&mut self, env: &str, keys: &[&str]) {
        let rel = format!("{env}.env");
        let text: String = keys
            .iter()
            .map(|k| format!("{k}={MARK}VALUE-{env}-{}\n", k.to_ascii_lowercase()))
            .collect();
        let p = self.s.path(&format!("project/{rel}"));
        std::fs::write(&p, text).expect("values");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let ran = self.opv(
            Actor::Person,
            &["import", env, "--from", &rel, "--confirm", env],
        );
        assert_eq!(ran.code, Some(0), "import {env}:\n{}", self.text);
    }

    /// The person applies the structure the contract now needs (`opv apply` with no plan
    /// id: the plan is shown and confirmed), at their terminal (in-process: see the module
    /// doc).
    fn apply_structure(&mut self, r: &SimRunner) {
        let person = opv::host::FakeEnv::new("linux").tty();
        let mut out = Vec::new();
        let applied = opv::app::apply::apply(
            r,
            &person,
            &self.s.path("project/secrets.toml"),
            PROJECT,
            DEV_ACCOUNT,
            None,
            opv::app::apply::ApplyOpts::default(),
            &mut |_| true,
            &mut out,
        );
        let mut shown = String::from_utf8_lossy(&out).into_owned();
        shown.push_str("Apply this plan? [y/N] y\n");
        match &applied {
            Ok(a) => shown.push_str(&format!(
                "applied {}: {} step(s), {} created, {} field(s) added\n",
                a.plan_id,
                a.steps_run,
                a.created.len(),
                a.fields_added.len()
            )),
            Err(e) => shown.push_str(&format!("refused: {}\n", e.code_str())),
        }
        self.step(Actor::Person, "opv apply", &shown);
        assert!(applied.is_ok(), "apply:\n{}", self.text);
    }
}

/// The GitHub environments of the repository whose secrets hold `name`.
fn held_by(s: &Scenario, name: &str) -> Vec<String> {
    let w: Value =
        serde_json::from_str(&std::fs::read_to_string(s.path("world/world.json")).expect("world"))
            .expect("world");
    w["github"]["repos"][REPO]["environments"]
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, e)| e["secrets"].get(name).is_some())
        .map(|(n, _)| n.clone())
        .collect()
}

/// The labels of the fields of the 1Password item titled `title` in the simulated world.
fn fields_in(world: &Value, title: &str) -> Vec<String> {
    let mut labels: Vec<String> = world["op"]["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|i| i["title"] == title)
        .flat_map(|i| i["fields"].as_array().cloned().unwrap_or_default())
        .filter_map(|f| f["label"].as_str().map(str::to_string))
        // 1Password's own notes field of every item.
        .filter(|l| l != "notesPlain")
        .collect();
    labels.sort();
    labels
}

/// A `ready --json` document's findings with `code`.
fn findings<'a>(ready: &'a Value, code: &'a str) -> impl Iterator<Item = &'a Value> + 'a {
    ready["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(move |f| f["code"] == code)
}

fn run_chain() -> Chain {
    let s = scenario();
    let r = SimRunner::new(&s);
    let mut t = Transcript {
        s: &s,
        text: "# consistency_chain: application × environment consistency, from a new key to \
               its retirement (#179)\n"
            .to_string(),
        n: 0,
    };

    // 1. The starting point: every key set everywhere and delivered.
    t.apply_structure(&r);
    for env in ["dev", "staging", "prod"] {
        t.import(env, &["API_KEY", "OLD_KEY"]);
    }
    t.opv(Actor::Ci, &["sync", "staging"]);
    t.opv(Actor::Ci, &["sync", "prod", "--confirm", "prod"]);

    // 2. A key added in dev: missing in staging and prod, and the staging gate refuses.
    t.edit_contract("add app/NEW_KEY to secrets.toml", ADD_KEY);
    t.apply_structure(&r);
    t.import("dev", &["NEW_KEY"]);
    let ready = t.opv(Actor::Ci, &["ready", "--json"]);
    let mut new_key_blocked_in: Vec<String> = ready.doc["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| f["blocking"] == true && f["scope"]["key"] == "NEW_KEY")
        .filter_map(|f| f["scope"]["environment"].as_str().map(str::to_string))
        .collect();
    new_key_blocked_in.sort();
    new_key_blocked_in.dedup();
    let refused = t.opv(Actor::Ci, &["ready", "staging", "--gate"]).code;

    // 3. A new environment inherits every key: the person's apply gives it a field for
    // each, and the inventory lists each as present there.
    t.opv(
        Actor::Person,
        &["propose", "env", "qa", "--tier", "shared", "--write"],
    );
    t.apply_structure(&r);
    let inventory = t.opv(Actor::Ci, &["inventory", "--json"]);
    let qa_presence = inventory.doc["keys"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|k| {
            (
                k["key"].as_str().unwrap_or_default().to_string(),
                k["presence"]["qa"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();

    // 4. An explicit list that leaves environments out: environment_gap, non-blocking.
    t.edit_contract("add app/PARTIAL_KEY for dev and staging only", ADD_PARTIAL);
    let ready = t.opv(Actor::Ci, &["ready", "--json"]);
    let gaps = findings(&ready.doc, "environment_gap")
        .map(|f| {
            (
                f["scope"]["environment"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                f["scope"]["key"].as_str().unwrap_or_default().to_string(),
                f["blocking"] == true,
            )
        })
        .collect();

    // 5. The person fills what the gate refused on; CI delivers; the gate passes.
    t.apply_structure(&r);
    t.import("dev", &["PARTIAL_KEY"]);
    t.import("staging", &["NEW_KEY", "PARTIAL_KEY"]);
    t.import("prod", &["NEW_KEY"]);
    t.opv(Actor::Ci, &["sync", "staging"]);
    t.opv(Actor::Ci, &["sync", "prod", "--confirm", "prod"]);
    let passes = t.opv(Actor::Ci, &["ready", "staging", "--gate"]).code;

    // 6. Retiring OLD_KEY: CI prunes in tier order, then the person archives.
    t.opv(
        Actor::Person,
        &["propose", "retire", "app/OLD_KEY", "--write"],
    );
    // An environment added while OLD_KEY is retiring gets nothing of it: no field, no
    // finding, no cell.
    t.opv(
        Actor::Person,
        &["propose", "env", "perf", "--tier", "shared", "--write"],
    );
    t.apply_structure(&r);
    let ready = t.opv(Actor::Ci, &["ready", "perf", "--json"]);
    let inventory = t.opv(Actor::Ci, &["inventory", "--json"]);
    let old_key_in_perf = (
        ready.doc["findings"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|f| f["scope"]["key"] == "OLD_KEY")
            .count(),
        inventory.doc["cells"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|c| c["key"] == "OLD_KEY" && c["env"] == "perf")
            .count(),
        std::fs::read_to_string(s.path("world/world.json"))
            .ok()
            .and_then(|w| serde_json::from_str::<Value>(&w).ok())
            .map(|w| fields_in(&w, "e2e-app · app · perf values"))
            .unwrap_or_default(),
    );
    let out_of_order = t.opv(
        Actor::Ci,
        &[
            "sync",
            "prod",
            "--prune",
            "--retire",
            "--confirm",
            "prod",
            "--json",
        ],
    );
    let prod_first = (
        out_of_order.doc["error"]["code"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        out_of_order.doc["error"]["subject"].clone(),
    );
    let mut prunes = Vec::new();
    let code = t
        .opv(Actor::Ci, &["sync", "staging", "--prune", "--retire"])
        .code;
    prunes.push(("staging".to_string(), code));
    t.opv(Actor::Ci, &["ready", "--json"]);
    let code = t
        .opv(
            Actor::Ci,
            &["sync", "prod", "--prune", "--retire", "--confirm", "prod"],
        )
        .code;
    prunes.push(("prod".to_string(), code));
    let old_key_held_after_prunes = held_by(&s, "OLD_KEY");
    let ready = t.opv(Actor::Ci, &["ready", "--json"]);
    let archive_cmd = findings(&ready.doc, "retirement_incomplete")
        .find_map(|f| f["prerequisite"].as_str())
        .unwrap_or_default()
        .to_string();
    let plan_id = archive_cmd
        .strip_prefix("opv apply ")
        .unwrap_or_default()
        .to_string();
    let ci_try = t.opv(Actor::Ci, &["apply", &plan_id, "--json"]);
    let ci_archive = (
        ci_try.doc["error"]["code"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        ci_try.doc["next"].clone(),
    );

    // The person's archive at their terminal (in-process: see the module doc).
    let person = opv::host::FakeEnv::new("linux").tty();
    let at = opv::app::structure::ConfigAt::File(s.path("project/secrets.toml"));
    let mut out = Vec::new();
    let mut still_held = |fleet: &opv::domain::Fleet, product: &str, key: &str| {
        opv::app::retire::still_held(fleet, product, key, &r)
    };
    let archived = opv::app::apply::apply_retire(
        &r,
        &person,
        &at,
        &plan_id,
        &opv::app::retire::today(),
        &mut still_held,
        &mut |_| true,
        &mut out,
    );
    let mut shown = String::from_utf8_lossy(&out).into_owned();
    shown.push_str("Apply this plan? [y/N] y\n");
    match &archived {
        Ok(a) => shown.push_str(&format!(
            "applied {}: archived in {:?}, already archived in {:?}, retired: {}, resync: {:?}\n",
            a.plan_id, a.archived, a.already_archived, a.retired, a.resync
        )),
        Err(e) => shown.push_str(&format!("refused: {}\n", e.code_str())),
    }
    t.step(Actor::Person, &format!("opv apply {plan_id}"), &shown);
    let archive = archived
        .map(|a| (a.archived, a.retired, a.resync))
        .map_err(|e| e.code_str().to_string());

    let inventory = t.opv(Actor::Ci, &["inventory", "--json"]);
    let lifecycle = inventory.doc["keys"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|k| k["key"] == "OLD_KEY")
        .map(|k| k["lifecycle"].clone())
        .unwrap_or_default();
    let ready = t.opv(Actor::Ci, &["ready", "--json"]);
    let left: Vec<Value> = findings(&ready.doc, "retirement_incomplete")
        .cloned()
        .collect();
    // The archive edited every boundary item, so the delivery evidence is older than the
    // source: each delivered environment's gate refuses until CI delivers again, and then
    // passes (the retired key is wanted nowhere, so nothing adds it back).
    let mut gates_after = Vec::new();
    for env in ["staging", "prod"] {
        let code = t.opv(Actor::Ci, &["ready", env, "--gate"]).code;
        gates_after.push((env.to_string(), code));
    }
    t.opv(Actor::Ci, &["sync", "staging"]);
    t.opv(Actor::Ci, &["sync", "prod", "--confirm", "prod"]);
    for env in ["staging", "prod"] {
        let code = t.opv(Actor::Ci, &["ready", env, "--gate"]).code;
        gates_after.push((env.to_string(), code));
    }
    let old_key_held_at_end = held_by(&s, "OLD_KEY");

    Chain {
        transcript: t.text,
        new_key_blocked_in,
        staging_gate: (refused, passes),
        qa_presence,
        gaps,
        prod_first,
        prunes,
        old_key_held_after_prunes,
        old_key_in_perf,
        ci_archive,
        archive,
        after: (lifecycle, left),
        gates_after,
        old_key_held_at_end,
    }
}

/// The chain runs once; every test reads its outcome.
fn chain() -> &'static Chain {
    static CHAIN: OnceLock<Chain> = OnceLock::new();
    CHAIN.get_or_init(run_chain)
}

// --- the outcomes, one assertion each -------------------------------------------------------

#[test]
fn a_key_added_in_dev_shows_as_missing_in_staging_and_prod() {
    assert_eq!(
        chain().new_key_blocked_in,
        vec!["prod".to_string(), "staging".to_string()]
    );
}

/// The gate refuses while staging misses the key, and passes once the person fills it.
#[test]
fn the_staging_gate_refuses_until_the_key_is_filled() {
    assert_eq!(chain().staging_gate, (Some(GATE_FAILED), Some(0)));
}

#[test]
fn a_new_environment_inherits_every_key() {
    assert_eq!(
        chain().qa_presence,
        vec![
            ("API_KEY".to_string(), "present".to_string()),
            ("NEW_KEY".to_string(), "present".to_string()),
            ("OLD_KEY".to_string(), "present".to_string()),
        ]
    );
}

#[test]
fn an_explicit_list_leaving_environments_out_is_a_non_blocking_environment_gap() {
    assert_eq!(
        chain().gaps,
        vec![
            ("prod".to_string(), "PARTIAL_KEY".to_string(), false),
            ("qa".to_string(), "PARTIAL_KEY".to_string(), false),
        ]
    );
}

#[test]
fn ci_cannot_prune_prod_while_staging_still_holds_the_retiring_key() {
    let (code, subject) = &chain().prod_first;
    assert_eq!(
        (code.as_str(), &subject["guard"]["first"]),
        ("policy_refused", &Value::from("staging"))
    );
}

#[test]
fn ci_prunes_the_retiring_key_from_staging_then_prod() {
    let c = chain();
    assert_eq!(
        (&c.prunes, &c.old_key_held_after_prunes),
        (
            &vec![
                ("staging".to_string(), Some(0)),
                ("prod".to_string(), Some(0))
            ],
            &Vec::<String>::new()
        )
    );
}

/// CI is refused, and the next step it relays is the person's own `opv apply rp-…`.
#[test]
fn ci_cannot_run_the_persons_archive_and_hands_it_to_the_person() {
    let (code, next) = &chain().ci_archive;
    assert_eq!(
        (
            code.as_str(),
            &next["actor"],
            next["command"]
                .as_str()
                .unwrap_or_default()
                .starts_with("opv apply rp-")
        ),
        ("terminal_required", &Value::from("person"), true)
    );
}

#[test]
fn an_environment_added_while_a_key_is_retiring_gets_nothing_of_it() {
    assert_eq!(
        chain().old_key_in_perf,
        (0, 0, vec!["API_KEY".to_string(), "NEW_KEY".to_string()])
    );
}

#[test]
fn the_persons_archive_archives_every_field_marks_the_key_retired_and_names_ci_syncs() {
    assert_eq!(
        chain().archive,
        Ok((
            vec![
                "dev".to_string(),
                "qa".to_string(),
                "staging".to_string(),
                "prod".to_string()
            ],
            true,
            vec!["opv sync staging".to_string(), "opv sync prod".to_string()]
        ))
    );
}

#[test]
fn the_retired_key_leaves_no_retirement_incomplete_finding() {
    assert_eq!(chain().after, (Value::from("retired"), Vec::new()));
}

/// The archive edits each boundary item, so the delivered environments' gates refuse until
/// CI delivers again; then they pass.
#[test]
fn staging_and_prod_pass_the_gate_once_ci_delivers_after_the_archive() {
    assert_eq!(
        chain().gates_after,
        vec![
            ("staging".to_string(), Some(GATE_FAILED)),
            ("prod".to_string(), Some(GATE_FAILED)),
            ("staging".to_string(), Some(0)),
            ("prod".to_string(), Some(0)),
        ]
    );
}

/// A plain sync never delivers a retired key again.
#[test]
fn a_sync_after_the_retirement_does_not_deliver_the_retired_key() {
    assert_eq!(chain().old_key_held_at_end, Vec::<String>::new());
}

#[test]
fn no_value_reaches_the_chains_output() {
    assert!(!chain().transcript.contains(MARK));
}

#[test]
fn the_chain_matches_its_snapshot() {
    let got = &chain().transcript;
    let path = scenario_snapshots().join(format!("{}.snap", SNAPSHOTS[0]));
    if updating() {
        std::fs::write(&path, got).expect("write snapshot");
        return;
    }
    let want = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        got,
        &want,
        "{} differs from its snapshot; review and rerun with UPDATE_SNAPSHOTS=1",
        path.display()
    );
}

/// `opv ready --gate`'s exit code when a blocking finding remains (`gate_failed`).
const GATE_FAILED: i32 = 8;
