//! Agent sign-in and readiness, headless (`docs/design/agent-signin-readiness.md` §7.2): the
//! real `opv` binary against `opv-sim`, run as an agent's shell runs it: stdin `/dev/null`, a
//! new session with no controlling terminal, stdout a pipe and `OPV_NO_SKILL=1`.
//!
//! - **#265 (FR-64):** every `--json` command of the CLI surface, in a signed-in and in a
//!   signed-out world, prints exactly one JSON document or exits non-zero (E1, E2).
//! - **#257 (FR-65):** two accounts on `my.1password.com`, none selected: `ready --json`,
//!   `account list --json` and MCP `opv_state accounts` give the same `choose` with two
//!   choices (E6, E7, E8, E18); a selected signed-out account is `authorize` (E9), a selected
//!   signed-in one has no account finding (E10).
//! - **#266:** `opv run` with the selected account signed out stops before `op run` with the
//!   typed sign-in step (E11-E13); with two accounts and none selected it is
//!   `account_required` (E-R12). `tests/run_signin.rs` covers the terminal replay with a fake
//!   `op` (E14, E14b, E15): `opv-sim` models no `op run`.
//! - **#267 (FR-66):** a repository whose `.opv` names `config = "fleet/secrets.toml"` is
//!   found from `infra/shared-host` and a stray `secrets.toml` above the `.opv` never wins
//!   (E16); without `config =` the Next names the file it found (E17).
//!
//! Every world value carries a `test-marker-e2e-` canary, and no case prints one (E19). The
//! cases assert behaviour, so this module writes no snapshot.

use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use crate::coverage::{DEV_ACCOUNT, Run, Scenario};

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// Every account of the world, edited.
fn accounts(w: &mut Value, edit: impl Fn(&mut Value)) {
    for a in w["op"]["accounts"].as_array_mut().expect("accounts") {
        edit(a);
    }
}

/// #257: both accounts on `my.1password.com` and no `.opv`: nothing selects one. They are
/// signed in: `opv-sim` answers an unnamed call as op's default account, so signed out, every
/// command would stop at `op_not_signed_in` before it reads the accounts.
fn two_unselected() -> Scenario {
    Scenario::new()
        .dot_opv(None)
        .world(|w| accounts(w, |a| a["url"] = json!("https://my.1password.com")))
}

/// #266: `.opv` selects the dev account, which is signed out.
fn selected_signed_out() -> Scenario {
    Scenario::new().world(|w| accounts(w, |a| a["signed_in"] = json!(false)))
}

/// #267: the configuration under `fleet/` of a git checkout, the working directory
/// `infra/shared-host`; with `named`, `.opv` names it and a stray `secrets.toml` with an
/// environment of its own sits above the checkout.
fn config_one_folder_up(named: bool) -> Scenario {
    let app = Path::new(ROOT).join("tests/e2e/app");
    let read = |f: &str| std::fs::read_to_string(app.join(f)).expect("app file");
    let mut s = Scenario::new()
        .without_config()
        .file("project/fleet/secrets.toml", &read("secrets.toml"))
        .file(
            "project/fleet/secrets.bindings.toml",
            &read("secrets.bindings.toml"),
        )
        .file(
            "project/infra/shared-host/README",
            "a folder below the config\n",
        )
        .git_checkout();
    std::fs::remove_file(s.path("project/secrets.bindings.toml")).expect("bindings");
    if named {
        s = s
            .dot_opv(Some(&format!(
                "account = \"{DEV_ACCOUNT}\"\nconfig = \"fleet/secrets.toml\"\n"
            )))
            .file("secrets.toml", STRAY);
    }
    s
}

/// A configuration above the checkout: an environment the app's configuration does not have.
const STRAY: &str = "[environments.stray]\ntitle = \"Stray\"\n";

/// `opv <args>` headless (module docs) in `cwd` under the scenario root, not yet started.
fn headless_command(s: &Scenario, cwd: &str, args: &[&str]) -> Command {
    use std::os::unix::process::CommandExt as _;
    let mut c = s.command();
    c.current_dir(s.path(cwd))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: `setsid` is async-signal-safe and touches no memory of the parent.
    unsafe {
        c.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    c
}

fn finished(s: &Scenario, out: std::process::Output) -> Run {
    Run {
        code: out.status.code(),
        stdout: s.normalize(&String::from_utf8_lossy(&out.stdout)),
        stderr: s.normalize(&String::from_utf8_lossy(&out.stderr)),
    }
}

/// Run `opv <args>` headless in `cwd` under the scenario root.
fn headless(s: &Scenario, cwd: &str, args: &[&str]) -> Run {
    let out = headless_command(s, cwd, args).output().expect("run opv");
    finished(s, out)
}

/// The one JSON document on stdout, if stdout holds exactly one.
fn one_document(stdout: &str) -> Option<Value> {
    let mut docs = serde_json::Deserializer::from_str(stdout).into_iter::<Value>();
    let first = docs.next()?.ok()?;
    docs.next().is_none().then_some(first)
}

fn doc(s: &Scenario, cwd: &str, args: &[&str]) -> Value {
    let r = headless(s, cwd, args);
    one_document(&r.stdout)
        .unwrap_or_else(|| panic!("opv {args:?}: no document: {} {}", r.stdout, r.stderr))
}

/// A document's typed `next`: the error's, else the top level's.
fn next(d: &Value) -> Value {
    d.pointer("/error/next")
        .or_else(|| d.get("next"))
        .cloned()
        .unwrap_or(Value::Null)
}

fn ready(s: &Scenario) -> Value {
    doc(s, "project", &["ready", "dev", "--json"])
}

fn account_list(s: &Scenario) -> Value {
    doc(s, "project", &["account", "list", "--json"])
}

fn last_line(text: &str) -> &str {
    text.lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
}

// --- E1, E2: one document or a loud failure, for every `--json` command ----------------------

/// Every `--json` command of the CLI surface, with the arguments it runs with here: read-only
/// commands and dry runs on the test application, or a refusal before any write.
const JSON_COMMANDS: &[(&str, &[&str])] = &[
    ("access", &["access", "dev"]),
    ("account list", &["account", "list"]),
    ("account use", &["account", "use", DEV_ACCOUNT]),
    ("apply", &["apply", "plan-nonexistent"]),
    ("changed", &["changed", "dev"]),
    ("config export", &["config", "export", "dev"]),
    ("contract", &["contract"]),
    ("delivery verify", &["delivery", "verify", "dev"]),
    ("doctor", &["doctor", "--env", "dev"]),
    ("explain", &["explain", "web/API_KEY", "--env", "dev"]),
    ("history", &["history", "dev"]),
    ("import", &["import", "dev"]),
    ("inventory", &["inventory"]),
    ("mcp install", &["mcp", "install"]),
    ("needs", &["needs", "dev"]),
    ("next", &["next"]),
    ("open", &["open", "nonexistent"]),
    ("plan", &["plan", "dev"]),
    ("projects", &["projects"]),
    ("propose", &["propose"]),
    ("propose env", &["propose", "env", "staging"]),
    (
        "propose generate",
        &["propose", "generate", "dev", "web/API_KEY"],
    ),
    ("propose key", &["propose", "key", "web/NEW_KEY"]),
    ("propose retire", &["propose", "retire", "web/API_KEY"]),
    ("propose setup", &["propose", "setup"]),
    ("propose structure", &["propose", "structure"]),
    ("propose target", &["propose", "target", "dev", "extra"]),
    ("provision", &["provision", "nonexistent"]),
    ("ready", &["ready", "dev"]),
    (
        "run",
        &[
            "run",
            "--preview",
            "dev",
            "--product",
            "web",
            "--role",
            "serve",
        ],
    ),
    ("set", &["set", "web/API_KEY"]),
    ("skill install", &["skill", "install"]),
    ("skill status", &["skill", "status"]),
    ("status", &["status", "dev"]),
    ("sync", &["sync", "prod"]),
    ("target list", &["target", "list"]),
    ("target op", &["target", "op", "prod", "machines"]),
    // #271: no bundle here, so a refusal document (scenarios/sealed.rs runs a real one).
    (
        "unseal",
        &[
            "unseal",
            "absent.opv-sealed",
            "--env",
            "prod",
            "--product",
            "web",
            "--signers",
            "absent_signers",
            "--verify-only",
        ],
    ),
    (
        "vault locate",
        &["vault", "locate", "vE2ESHAREDDEV00000000000001"],
    ),
    ("version", &["version"]),
];

/// The `--json` commands `tests/e2e/expected/surface.json` lists.
fn surface_json_commands() -> Vec<String> {
    let text = std::fs::read_to_string(Path::new(ROOT).join("tests/e2e/expected/surface.json"))
        .expect("surface.json");
    let surface: Value = serde_json::from_str(&text).expect("surface.json");
    surface["cli"]
        .as_array()
        .expect("cli")
        .iter()
        .filter(|c| {
            c["flags"]
                .as_array()
                .is_some_and(|f| f.contains(&json!("json")))
        })
        .filter_map(|c| c["name"].as_str().map(str::to_string))
        .collect()
}

/// The commands that exit 0 without exactly one document on stdout, run four at a time.
fn silent_successes(s: &Scenario) -> Vec<String> {
    let mut silent = Vec::new();
    for chunk in JSON_COMMANDS.chunks(4) {
        let children: Vec<_> = chunk
            .iter()
            .map(|(name, args)| {
                let mut a = args.to_vec();
                a.push("--json");
                let child = headless_command(s, "project", &a).spawn().expect("run opv");
                (name, child)
            })
            .collect();
        for (name, child) in children {
            let r = finished(s, child.wait_with_output().expect("opv output"));
            if r.code == Some(0) && one_document(&r.stdout).is_none() {
                silent.push(format!("{name}: exit 0, stdout {:?}", r.stdout));
            }
        }
    }
    silent
}

#[test]
fn every_json_command_of_the_surface_is_exercised() {
    let listed: Vec<&str> = JSON_COMMANDS.iter().map(|(n, _)| *n).collect();
    let missing: Vec<String> = surface_json_commands()
        .into_iter()
        .filter(|c| !listed.contains(&c.as_str()))
        .collect();
    assert!(missing.is_empty(), "--json commands not run: {missing:?}");
}

#[test]
fn signed_in_json_commands_print_one_document_or_fail() {
    assert_eq!(silent_successes(&Scenario::new()), Vec::<String>::new());
}

#[test]
fn signed_out_json_commands_print_one_document_or_fail() {
    assert_eq!(
        silent_successes(&selected_signed_out()),
        Vec::<String>::new()
    );
}

// --- #257: two accounts on one address, none selected -----------------------------------------

#[test]
fn ready_with_two_unselected_accounts_asks_to_choose() {
    assert_eq!(next(&ready(&two_unselected()))["kind"], "choose");
}

#[test]
fn ready_with_two_unselected_accounts_offers_both() {
    let n = next(&ready(&two_unselected()));
    assert_eq!(n["choices"].as_array().map(Vec::len), Some(2));
}

#[test]
fn account_list_with_two_unselected_accounts_asks_to_choose() {
    assert_eq!(next(&account_list(&two_unselected()))["kind"], "choose");
}

#[test]
fn account_list_with_two_unselected_accounts_offers_both() {
    let n = next(&account_list(&two_unselected()));
    assert_eq!(n["choices"].as_array().map(Vec::len), Some(2));
}

#[test]
fn ready_and_account_list_give_the_same_choice() {
    let s = two_unselected();
    assert_eq!(
        next(&ready(&s))["choices"],
        next(&account_list(&s))["choices"]
    );
}

#[test]
fn mcp_accounts_gives_account_lists_next() {
    let s = two_unselected();
    let mcp = s.mcp("opv_state", &json!({"section": "accounts"}));
    assert_eq!(next(&mcp), next(&account_list(&s)));
}

#[test]
fn a_selected_signed_out_account_is_authorized() {
    assert_eq!(next(&ready(&selected_signed_out()))["kind"], "authorize");
}

#[test]
fn a_selected_signed_in_account_has_no_account_finding() {
    let d = account_list(&Scenario::new());
    let codes: Vec<&str> = d["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|f| f["code"].as_str())
        .filter(|c| c.starts_with("account_") || c.starts_with("selected_"))
        .collect();
    assert_eq!(codes, Vec::<&str>::new());
}

// --- #266: `opv run` signed out, headless -----------------------------------------------------

/// The app's `dev` products declare roles, so a run names one.
const RUN: &[&str] = &["run", "dev", "--role", "serve", "--", "true"];

fn run_signed_out() -> (Scenario, Run) {
    let s = selected_signed_out();
    let r = headless(&s, "project", RUN);
    (s, r)
}

#[test]
fn a_headless_run_signed_out_exits_7() {
    assert_eq!(run_signed_out().1.code, Some(7));
}

#[test]
fn a_headless_run_signed_out_never_shows_ops_message() {
    assert!(!run_signed_out().1.stderr.contains("op signin --help"));
}

#[test]
fn a_headless_run_signed_out_steps_to_login() {
    let (_, r) = run_signed_out();
    assert_eq!(
        last_line(&r.stderr),
        "Next: opv login -- opv run dev --role serve -- <command>"
    );
}

#[test]
fn a_headless_run_signed_out_never_calls_op_run() {
    let (s, _) = run_signed_out();
    let calls = std::fs::read_to_string(s.path("world/calls.log")).unwrap_or_default();
    assert!(!calls.lines().any(|l| l.starts_with("op run")), "{calls}");
}

#[test]
fn a_run_with_two_unselected_accounts_requires_an_account() {
    let r = headless(&two_unselected(), "project", RUN);
    assert_eq!(r.code, Some(2));
}

// --- #267: the configuration `.opv` names ------------------------------------------------------

#[test]
fn dot_opv_config_is_found_from_a_subfolder() {
    let d = doc(
        &config_one_folder_up(true),
        "project/infra/shared-host",
        &["contract", "--json"],
    );
    assert_ne!(d.pointer("/error/code"), Some(&json!("config_not_found")));
}

#[test]
fn a_stray_config_above_the_checkout_never_wins() {
    let r = headless(
        &config_one_folder_up(true),
        "project/infra/shared-host",
        &["contract", "--json"],
    );
    assert!(!r.stdout.contains("stray"), "{}", r.stdout);
}

#[test]
fn an_unnamed_config_below_the_checkout_is_the_next_step() {
    let d = doc(
        &config_one_folder_up(false),
        "project/infra/shared-host",
        &["contract", "--json"],
    );
    let command = next(&d)["command"].as_str().unwrap_or_default().to_string();
    assert!(command.contains("--config ../../fleet/secrets.toml"), "{d}");
}

// --- E19: no world value in any channel --------------------------------------------------------

/// The world's value canaries (`test-marker-e2e-…`).
fn canaries() -> Vec<String> {
    let world = std::fs::read_to_string(Path::new(ROOT).join("tests/e2e/app/world.json"))
        .expect("world.json");
    regex::Regex::new(r"test-marker-e2e-[a-z0-9-]+")
        .expect("regex")
        .find_iter(&world)
        .map(|m| m.as_str().to_string())
        .collect()
}

#[test]
fn no_signin_case_prints_a_world_value() {
    let cases: Vec<(Scenario, &str, Vec<&str>)> = vec![
        (two_unselected(), "project", vec!["ready", "dev", "--json"]),
        (
            two_unselected(),
            "project",
            vec!["account", "list", "--json"],
        ),
        (two_unselected(), "project", RUN.to_vec()),
        (
            selected_signed_out(),
            "project",
            vec!["ready", "dev", "--json"],
        ),
        (selected_signed_out(), "project", RUN.to_vec()),
        (
            Scenario::new(),
            "project",
            vec!["account", "list", "--json"],
        ),
        (
            config_one_folder_up(true),
            "project/infra/shared-host",
            vec!["contract", "--json"],
        ),
        (
            config_one_folder_up(false),
            "project/infra/shared-host",
            vec!["contract", "--json"],
        ),
    ];
    let canaries = canaries();
    let printed: Vec<String> = cases
        .iter()
        .flat_map(|(s, cwd, args)| {
            let r = headless(s, cwd, args);
            canaries
                .iter()
                .filter(|c| r.stdout.contains(c.as_str()) || r.stderr.contains(c.as_str()))
                .map(|c| format!("opv {}: {c}", args.join(" ")))
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(printed, Vec::<String>::new());
}
