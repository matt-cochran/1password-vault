//! The assistant walkthrough on opv-sim (design §6.1, Part V row `e2e-walkthrough`): from a
//! repository with no configuration to `opv ready --gate` passing in every environment.
//!
//! The assistant acts only through the MCP tools of §25.2 (`opv_state`, `opv_propose`,
//! `opv_import_local`, `opv_explain`; `opv_next` is not on this tree yet, row mcp-propose,
//! so the assistant reads what is left with `opv_state`), plus the one thing §6.1 step 4
//! lets it do outside opv: write a proposal's contract diff into the repository (reviewed in
//! the pull request). The person runs `opv apply`, `opv import` and `opv set`; CI runs
//! `opv sync`. The walkthrough's steps, in order:
//!
//! 1. assistant `opv_state needs`: no configuration yet (`config_not_found`, next: setup);
//! 2. assistant `opv_propose setup` from the `.env`'s names, written as `secrets.toml`
//!    (environment `local`, tier `local`);
//! 3. assistant `opv_propose env prod` (tier production), then `opv_propose key` for each
//!    key in `local` and `prod`, then `opv_propose target prod gh` (GitHub), each written;
//! 4. assistant `opv_state needs` (the code reads every declared name) and
//!    `opv_propose structure`: the plan id it hands to the person;
//! 5. person `opv apply <plan_id>`: vaults, items, the state vault, the delivery item, the
//!    empty fields, the bindings and the apply record;
//! 6. assistant `opv_import_local local .env`;
//! 7. person `opv import prod --from prod.env` (two of the three production values);
//! 8. assistant `opv_state inventory` (prod): the one value only the person can provide
//!    (`empty`, capability `write`);
//! 9. person `opv set app/SESSION_SECRET --env prod`;
//! 10. CI `opv sync prod --confirm prod`;
//! 11. assistant `opv_explain app/API_KEY` (where the key is delivered);
//! 12. CI `opv ready <env> --gate` for each environment, and `opv ready --gate`.
//!
//! **The person's terminal.** `opv apply` and `opv set` refuse a run without a terminal,
//! and the binary has no non-interactive person path (the harness gives opv no TTY:
//! `scenarios/apply_needs_terminal.snap`). Those two steps therefore run in-process through
//! the library, as `src/app/flows_acceptance_tests.rs` does: `opv::app::apply::apply` and
//! `opv::app::set::set` with a `FakeEnv` that is a person at a TTY, the confirmation
//! answered yes, the masked prompt answered with a marker, and a `ProcessRunner` whose
//! every call runs the simulator installed in the scenario (`PATH`, `HOME`, `OPV_SIM_WORLD`
//! of the scenario). Everything else is the real `opv` binary.
//!
//! Every value is an `S7MARKER` marker and the whole transcript holds none (the canary).
//! Each test below is one milestone with one assertion; each runs the whole walkthrough.

use std::io;
use std::time::Duration;

use serde_json::{Value, json};

use crate::coverage::{DEV_ACCOUNT, MARK, Scenario, scenario_snapshots, updating};

/// The scenario snapshot this module writes (`tests/e2e/snapshots/scenarios/`).
pub(crate) const SNAPSHOTS: &[&str] = &["assistant_walkthrough"];

/// The project the checkout's `origin` names (`github.com/e2e-org/e2e-app`).
const PROJECT: &str = "e2e-app";
/// The keys the `.env` holds, with the kind the assistant declares for each.
const KEYS: [(&str, &str); 3] = [
    ("API_KEY", "secret"),
    ("LOG_LEVEL", "config"),
    ("SESSION_SECRET", "secret"),
];
/// The production values the person imports from a file; the third is typed (`opv set`).
const PROD_FILE_KEYS: [&str; 2] = ["API_KEY", "LOG_LEVEL"];
const TYPED_KEY: &str = "SESSION_SECRET";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Actor {
    Assistant,
    Person,
    Ci,
}

impl Actor {
    fn word(self) -> &'static str {
        match self {
            Actor::Assistant => "assistant",
            Actor::Person => "person",
            Actor::Ci => "ci",
        }
    }
}

/// What the walkthrough produced: the transcript and each milestone's outcome.
struct Walk {
    transcript: String,
    person_actions: usize,
    first_state: Value,
    setup: Value,
    applied: Result<opv::app::apply::Applied, String>,
    import_local: Value,
    set_out: Result<String, String>,
    sync_exit: Option<i32>,
    delivered: Vec<String>,
    gates: Vec<(String, Option<i32>)>,
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

/// The scenario: the app's accounts and targets with every value marked, no vault and no
/// item in 1Password, and a git checkout holding no configuration (no `secrets.toml`, no
/// bindings, no `.opv`; the account comes from `OP_ACCOUNT`), only a `.env` of the
/// developer's values, a file of production values and the code that reads the names.
fn scenario() -> Scenario {
    let names: Vec<&str> = KEYS.iter().map(|(k, _)| *k).collect();
    let prod: String = PROD_FILE_KEYS
        .iter()
        .map(|k| format!("{k}={MARK}VALUE-prod-{}\n", k.to_ascii_lowercase()))
        .collect();
    let code: String = names
        .iter()
        .map(|k| format!("    let _ = std::env::var(\"{k}\");\n"))
        .collect();
    let s = Scenario::new()
        .without_config()
        .dot_opv(None)
        .var("OP_ACCOUNT", DEV_ACCOUNT)
        .marked()
        .world(|w| {
            w["op"]["vaults"] = json!([]);
            w["op"]["items"] = json!([]);
        })
        .git_checkout()
        .tracked("src/main.rs", &format!("fn main() {{\n{code}}}\n"))
        .dotenv(".env", &names)
        .file("project/prod.env", &prod)
        .mode("project/prod.env", 0o600);
    std::fs::remove_file(s.path("project/secrets.bindings.toml")).expect("bindings");
    s
}

/// The walkthrough's transcript, one section per step.
struct Transcript<'a> {
    s: &'a Scenario,
    text: String,
    n: usize,
    person_actions: usize,
}

impl Transcript<'_> {
    fn step(&mut self, actor: Actor, what: &str, body: &str) {
        self.n += 1;
        if actor == Actor::Person {
            self.person_actions += 1;
        }
        // A delivery revision is minted at random for each sync.
        let body = regex::Regex::new(r"\bdrv-[a-z2-7]+")
            .expect("regex")
            .replace_all(&self.s.normalize(body), "drv-<id>")
            .into_owned();
        self.text.push_str(&format!(
            "\n## {}. {}: {what}\n{}",
            self.n,
            actor.word(),
            body.trim_end()
        ));
        self.text.push('\n');
    }

    /// One MCP tool call by the assistant: its answer.
    fn mcp(&mut self, tool: &str, arguments: Value) -> Value {
        let answer = self.s.mcp(tool, &arguments);
        self.step(
            Actor::Assistant,
            &format!("{tool} {arguments}"),
            &answer.to_string(),
        );
        answer
    }

    /// One `opv` run by the person or CI: its exit code.
    fn opv(&mut self, actor: Actor, args: &[&str]) -> Option<i32> {
        let mut c = self.s.command();
        c.args(args);
        if actor == Actor::Ci {
            c.env("CI", "true").env("GITHUB_ACTIONS", "true");
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
        out.status.code()
    }
}

/// The assistant writes a proposal's contract diff into the repository's `secrets.toml`
/// (design §6.1 step 4: reviewed in the pull request). The diff is the whole file.
fn write_diff(s: &Scenario, answer: &Value) {
    let diff = answer["proposal"]["diff"]
        .as_str()
        .or_else(|| answer["diff"].as_str())
        .expect("a proposal diff");
    let text: String = diff
        .lines()
        .filter(|l| !l.starts_with('-'))
        .map(|l| format!("{}\n", l.get(1..).unwrap_or_default()))
        .collect();
    std::fs::write(s.path("project/secrets.toml"), text).expect("contract");
}

/// The names delivered to the GitHub target's `production` environment (secrets and
/// variables), from the simulated world.
fn delivered(s: &Scenario) -> Vec<String> {
    let w: Value =
        serde_json::from_str(&std::fs::read_to_string(s.path("world/world.json")).expect("world"))
            .expect("world");
    let env = &w["github"]["repos"]["e2e-org/e2e-app"]["environments"]["production"];
    let mut names: Vec<String> = ["secrets", "variables"]
        .iter()
        .filter_map(|k| env[*k].as_object())
        .flat_map(|o| o.keys().cloned())
        .collect();
    names.sort();
    names
}

fn walk() -> Walk {
    let s = scenario();
    let mut t = Transcript {
        s: &s,
        text: "# assistant_walkthrough: from no configuration to opv ready --gate (design §6.1)\n"
            .to_string(),
        n: 0,
        person_actions: 0,
    };

    // 1. The assistant reads the repository: nothing is configured yet.
    let first_state = t.mcp("opv_state", json!({"section": "needs"}));

    // 2-3. The contract, proposed and written by the assistant.
    let setup = t.mcp(
        "opv_propose",
        json!({"kind": "setup", "names_from": ".env"}),
    );
    write_diff(&s, &setup);
    let env = t.mcp(
        "opv_propose",
        json!({"kind": "env", "env": "prod", "tier": "production"}),
    );
    write_diff(&s, &env);
    for (key, kind) in KEYS {
        let a = t.mcp(
            "opv_propose",
            json!({"kind": "key", "product": "app", "key": key, "field_kind": kind,
                   "environments": ["local", "prod"]}),
        );
        write_diff(&s, &a);
    }
    let target = t.mcp(
        "opv_propose",
        json!({"kind": "target", "env": "prod", "name": "gh",
               "options": {"github-repo": "e2e-org/e2e-app",
                           "github-environment": "production"}}),
    );
    write_diff(&s, &target);
    let contract = std::fs::read_to_string(s.path("project/secrets.toml")).expect("contract");
    t.step(
        Actor::Assistant,
        "the contract it wrote: secrets.toml",
        &contract,
    );

    // 4. What the code reads, then the structure the person applies.
    t.mcp("opv_state", json!({"section": "needs"}));
    let structure = t.mcp("opv_propose", json!({"kind": "structure"}));
    let plan_id = structure["plan_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    // 5. The person applies that plan at their terminal (in-process: see the module doc).
    let r = SimRunner::new(&s);
    let person = opv::host::FakeEnv::new("linux").tty();
    let mut out = Vec::new();
    let applied = opv::app::apply::apply(
        &r,
        &person,
        &s.path("project/secrets.toml"),
        PROJECT,
        DEV_ACCOUNT,
        Some(&plan_id),
        opv::app::apply::ApplyOpts::default(),
        &mut |_| true,
        &mut out,
    )
    .map_err(|e| e.code_str().to_string());
    let mut shown = String::from_utf8_lossy(&out).into_owned();
    shown.push_str("Apply this plan? [y/N] y\n");
    match &applied {
        Ok(a) => shown.push_str(&format!(
            "applied {}: {} step(s), {} created, {} field(s) added, {} generated\n",
            a.plan_id,
            a.steps_run,
            a.created.len(),
            a.fields_added.len(),
            a.generated.len()
        )),
        Err(code) => shown.push_str(&format!("refused: {code}\n")),
    }
    let bindings =
        std::fs::read_to_string(s.path("project/secrets.bindings.toml")).unwrap_or_default();
    shown.push_str(&format!("secrets.bindings.toml:\n{bindings}"));
    t.step(Actor::Person, &format!("opv apply {plan_id}"), &shown);

    // 6. The assistant's write-only import into the local tier.
    let import_local = t.mcp("opv_import_local", json!({"env": "local", "file": ".env"}));

    // 7. The person imports the production values they have in a file.
    t.opv(Actor::Person, &["import", "prod", "--from", "prod.env"]);

    // 8. What is left: one value only the person can provide.
    t.mcp("opv_state", json!({"section": "inventory", "env": "prod"}));

    // 9. The person types it (in-process: see the module doc).
    let key = format!("app/{TYPED_KEY}");
    let set_out = opv::config::load(s.path("project/secrets.toml"))
        .and_then(|fleet| {
            let mut out = Vec::new();
            let mut prompt = |_: &str| {
                Ok(Some(opv::domain::SecretValue::new(format!(
                    "{MARK}VALUE-typed-{}",
                    TYPED_KEY.to_ascii_lowercase()
                ))))
            };
            opv::app::set::set(&fleet, &person, &key, "prod", &mut prompt, &r, &mut out)?;
            Ok(String::from_utf8_lossy(&out).into_owned())
        })
        .map_err(|e| e.code_str().to_string());
    let shown = match &set_out {
        Ok(text) => format!("{key} (masked; Enter to skip): ********\n{text}"),
        Err(code) => format!("refused: {code}\n"),
    };
    t.step(Actor::Person, &format!("opv set {key} --env prod"), &shown);

    // 10. CI delivers.
    let sync_exit = t.opv(Actor::Ci, &["sync", "prod", "--confirm", "prod"]);
    let delivered = delivered(&s);

    // 11. Where the key now lives.
    t.mcp("opv_explain", json!({"key": "app/API_KEY", "env": "prod"}));

    // 12. The gate, per environment and for all of them.
    let mut gates = Vec::new();
    for env in ["local", "prod"] {
        let code = t.opv(Actor::Ci, &["ready", env, "--gate"]);
        gates.push((env.to_string(), code));
    }
    let code = t.opv(Actor::Ci, &["ready", "--gate"]);
    gates.push(("every environment".to_string(), code));

    let person_actions = t.person_actions;
    t.text
        .push_str(&format!("\nperson actions: {person_actions}\n"));
    Walk {
        transcript: t.text,
        person_actions,
        first_state,
        setup,
        applied,
        import_local,
        set_out,
        sync_exit,
        delivered,
        gates,
    }
}

// --- the milestones, one assertion each -----------------------------------------------------

#[test]
fn the_walkthrough_starts_from_no_configuration() {
    let w = walk();
    assert_eq!(w.first_state["error"]["code"], "config_not_found");
}

#[test]
fn the_assistant_proposes_the_setup_from_the_dotenvs_names() {
    let w = walk();
    assert_eq!(
        w.setup["structure_steps"],
        json!([
            "boundary app",
            "item app",
            "field app/API_KEY secret",
            "field app/LOG_LEVEL config",
            "field app/SESSION_SECRET secret"
        ])
    );
}

#[test]
fn the_persons_apply_creates_the_structure_of_both_environments() {
    let w = walk();
    let created: Result<Vec<(String, &str)>, String> = w.applied.map(|a| {
        a.created
            .iter()
            .map(|c| (c.environment.clone(), c.kind))
            .collect()
    });
    assert_eq!(
        created,
        Ok(vec![
            ("local".to_string(), "boundary"),
            ("prod".to_string(), "boundary"),
            ("prod".to_string(), "state_vault"),
            ("prod".to_string(), "delivery_item"),
        ])
    );
}

#[test]
fn the_assistants_local_import_sets_every_local_key() {
    let w = walk();
    let actions: Vec<Value> = w.import_local["rows"]
        .as_array()
        .map(|rows| rows.iter().map(|r| r["action"].clone()).collect())
        .unwrap_or_default();
    assert_eq!(actions, vec![json!("imported"); KEYS.len()]);
}

#[test]
fn the_persons_set_fills_the_typed_value() {
    let w = walk();
    assert_eq!(w.set_out, Ok("set\n".to_string()));
}

#[test]
fn cis_sync_delivers_every_key_to_the_target() {
    let w = walk();
    let mut want: Vec<String> = KEYS.iter().map(|(k, _)| k.to_string()).collect();
    want.sort();
    assert_eq!((w.sync_exit, w.delivered), (Some(0), want));
}

#[test]
fn ready_gate_passes_in_every_environment() {
    let w = walk();
    assert_eq!(
        w.gates,
        vec![
            ("local".to_string(), Some(0)),
            ("prod".to_string(), Some(0)),
            ("every environment".to_string(), Some(0)),
        ]
    );
}

/// The person's whole effort: one apply, one import of the values they hold in a file, and
/// the one value only they can type.
#[test]
fn the_person_takes_three_actions() {
    let w = walk();
    assert_eq!(w.person_actions, 3);
}

#[test]
fn no_value_reaches_the_walkthroughs_output() {
    let w = walk();
    assert!(!w.transcript.contains(MARK));
}

#[test]
fn the_walkthrough_matches_its_snapshot() {
    let got = walk().transcript;
    let path = scenario_snapshots().join(format!("{}.snap", SNAPSHOTS[0]));
    if updating() {
        std::fs::write(&path, &got).expect("write snapshot");
        return;
    }
    let want = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        got,
        want,
        "{} differs from its snapshot; review and rerun with UPDATE_SNAPSHOTS=1",
        path.display()
    );
}
