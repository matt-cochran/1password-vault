//! opv-sim scenarios for the file-key guidance (0.15.0, #217): `opv next`, `opv inventory`
//! and `opv open` point a file key at `opv set --from-file`, not an app paste.
//!
//! The world is the e2e app's (`tests/e2e/app/world.json`) with the dev web vault writable,
//! `web/TLS_CERTIFICATE` (declared with `file = "tls/certificate"`) absent and
//! `web/API_KEY` (no `file`) absent. Every value stays the app's `test-marker-e2e-` marker,
//! so the coverage canary finds any value the snapshot holds.
//!
//! - `opv next --env dev --json`: the absent file key's action names
//!   `opv set web/TLS_CERTIFICATE --env dev --from-file <PATH>`.
//! - `opv inventory --env dev --json`: the file key's row `next.command` carries
//!   `--from-file <PATH>`.
//! - The plain key's row `next.command` has no `--from-file`.
//! - `opv open web/TLS_CERTIFICATE --env dev --print`: carries the app-paste warning.
//! - `opv open web/API_KEY --env dev --print`: carries none.

use serde_json::{Value, json};

use crate::coverage::{Run, Scenario, scenario_snapshots, updating};

/// The scenario snapshot this module writes (`tests/e2e/snapshots/scenarios/`).
pub(crate) const SNAPSHOTS: &[&str] = &["file_key_guidance"];

/// The dev account's user (`tests/e2e/app/world.json`).
const DEV_USER: &str = "UE2EDEVUSER000000000000001";
/// The dev web vault and its item (a writable boundary).
const WEB_DEV_VAULT: &str = "vE2EWEBDEV0000000000000001";
const WEB_DEV_ITEM: &str = "iE2EWEBDEV0000000000000001";
/// The file key the guidance names `--from-file` for.
const FILE_KEY: &str = "TLS_CERTIFICATE";
/// The plain key that must keep its plain `opv set` command.
const PLAIN_KEY: &str = "API_KEY";

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

fn document(run: &Run) -> Value {
    serde_json::Deserializer::from_str(&run.stdout)
        .into_iter::<Value>()
        .next()
        .and_then(Result::ok)
        .unwrap_or_else(|| panic!("no document: {}{}", run.stdout, run.stderr))
}

/// The app with the dev web vault writable and `web/TLS_CERTIFICATE` and `web/API_KEY`
/// absent, so both ask for a `set`.
fn guidance() -> Scenario {
    Scenario::new().world(|w| {
        for v in w["op"]["vaults"].as_array_mut().expect("vaults") {
            if v["id"] == WEB_DEV_VAULT {
                v["users"] = json!([{"id": DEV_USER, "name": "E2E Dev",
                                     "email": "dev@example.com"}]);
            }
        }
        for item in w["op"]["items"].as_array_mut().expect("items") {
            if item["id"] != WEB_DEV_ITEM {
                continue;
            }
            item["fields"]
                .as_array_mut()
                .expect("fields")
                .retain(|f| f["label"] != FILE_KEY && f["label"] != PLAIN_KEY);
        }
    })
}

const NEXT: &[&str] = &["next", "--env", "dev", "--json"];
const INVENTORY: &[&str] = &["inventory", "--env", "dev", "--json"];
const OPEN_FILE: &[&str] = &["open", "web/TLS_CERTIFICATE", "--env", "dev", "--print"];

/// The command `opv next --json` asks for `web/<key>`, in its one action or its queue.
fn next_command(run: &Run, key: &str) -> String {
    let doc = document(run);
    std::iter::once(&doc["next"])
        .chain(doc["queue"].as_array().into_iter().flatten())
        .find(|a| a["key"] == key)
        .and_then(|a| a["command"].as_str())
        .unwrap_or_else(|| panic!("no next action for {key}: {doc}"))
        .to_string()
}

/// The `web/<key>` row of `opv inventory --json`.
fn inventory_row(run: &Run, key: &str) -> Value {
    document(run)["keys"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| r["product"] == "web" && r["key"] == key)
        .cloned()
        .unwrap_or_else(|| panic!("no row for web/{key}: {}{}", run.stdout, run.stderr))
}

// --- the guidance ---------------------------------------------------------------------------

#[test]
fn next_names_the_absent_file_key_command_with_from_file() {
    let run = guidance().opv(&args(NEXT));
    assert_eq!(
        next_command(&run, FILE_KEY),
        "opv set web/TLS_CERTIFICATE --env dev --from-file <PATH>"
    );
}

#[test]
fn inventory_row_of_the_absent_file_key_carries_from_file() {
    let run = guidance().opv(&args(INVENTORY));
    assert_eq!(
        inventory_row(&run, FILE_KEY)["next"]["command"],
        "opv set web/TLS_CERTIFICATE --env dev --from-file <PATH>"
    );
}

#[test]
fn inventory_row_of_a_plain_absent_key_has_no_from_file() {
    let run = guidance().opv(&args(INVENTORY));
    assert_eq!(
        inventory_row(&run, PLAIN_KEY)["next"]["command"],
        "opv set web/API_KEY --env dev"
    );
}

#[test]
fn open_of_a_file_key_warns_that_the_app_paste_flattens_it() {
    let run = guidance().opv(&args(OPEN_FILE));
    assert!(
        run.stdout
            .contains("pasting into the 1Password app turns line breaks into spaces"),
        "{}{}",
        run.stdout,
        run.stderr
    );
}

#[test]
fn open_of_a_plain_key_carries_no_paste_warning() {
    let run = guidance().opv(&args(&["open", "web/API_KEY", "--env", "dev", "--print"]));
    assert!(
        !run.stdout.contains("--from-file"),
        "{}{}",
        run.stdout,
        run.stderr
    );
}

// --- the snapshot ---------------------------------------------------------------------------

/// One run as snapshot sections. The headings name the case, never `json stdout` or
/// `mcp …`, so the coverage gates read no document of this snapshot as a scenario's.
fn section(snap: &mut String, label: &str, run: &Run) {
    snap.push_str(&format!(
        "\n## {label} exit: {}\n## {label} stdout\n{}\n## {label} stderr\n{}",
        run.code.map_or("killed".into(), |c| c.to_string()),
        run.stdout,
        run.stderr,
    ));
}

/// Each guidance's telling runs, text and `--json`, each case on a fresh world.
fn transcript() -> String {
    let mut snap =
        String::from("# file_key_guidance: the file-key guidance through the real binary\n");
    let both = |snap: &mut String, label: &str, text: &[&str], json: &[&str]| {
        section(snap, &format!("{label} text"), &guidance().opv(&args(text)));
        section(
            snap,
            &format!("{label} --json"),
            &guidance().opv(&args(json)),
        );
    };
    both(&mut snap, "opv next dev", &["next", "--env", "dev"], NEXT);
    both(
        &mut snap,
        "opv inventory dev",
        &["inventory", "--env", "dev"],
        INVENTORY,
    );
    both(
        &mut snap,
        "opv open web/TLS_CERTIFICATE",
        OPEN_FILE,
        &["open", "web/TLS_CERTIFICATE", "--env", "dev", "--json"],
    );
    both(
        &mut snap,
        "opv open web/API_KEY",
        &["open", "web/API_KEY", "--env", "dev", "--print"],
        &["open", "web/API_KEY", "--env", "dev", "--json"],
    );
    snap
}

#[test]
fn the_guidance_matches_its_snapshot() {
    let got = transcript();
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
