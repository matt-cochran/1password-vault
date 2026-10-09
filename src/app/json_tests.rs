//! The `--json` contract (A1, A5, A6): one golden document per command for its success
//! and its failure shape, framed exactly as `main` frames stdout ([`crate::json::finish`]).
//! `UPDATE_GOLDEN=1` rewrites them in `tests/fixtures/json/`. Every fixture value carries
//! [`MARKER`]; no golden may contain it (SR-1).

use super::sync::{self, SyncOpts};
use super::testutil::*;
use super::{explain, local, skeleton, status};
use crate::error::Error;
use crate::runner::fake::FakeRunner;

/// stdout as `main` prints it for `--json`: the command's body, framed with its result.
/// `rerun` is the command line; the help command follows from its first word.
pub(crate) fn framed(body: &[u8], res: &Result<(), Error>, rerun: &str) -> String {
    let sub = rerun.split_whitespace().nth(1).unwrap_or_default();
    let help = format!("opv {sub} --help");
    let out = match res {
        Ok(()) => crate::json::finish(body, Ok(()), false),
        Err(e) => crate::json::finish(body, Err((e, &e.step(rerun, &help))), false),
    };
    String::from_utf8(out).unwrap()
}

/// `framed` with the temporary directory `dir` replaced by `<dir>` and the rest of each such
/// path written with `/`, so one golden serves every platform. The directory is replaced in
/// both its raw and its JSON-escaped spelling (`C:\\Users\\...` inside a JSON string).
pub(crate) fn without_dir(framed: &str, dir: &std::path::Path) -> String {
    let raw = dir.display().to_string();
    let quoted = serde_json::to_string(&raw).expect("a string");
    let escaped = &quoted[1..quoted.len() - 1];
    let s = framed.replace(escaped, "<dir>").replace(&raw, "<dir>");
    // The rest of the path, up to the end of its JSON string: separators become `/`.
    let mut out = String::with_capacity(s.len());
    let mut rest = s.as_str();
    while let Some(at) = rest.find("<dir>") {
        let (before, tail) = rest.split_at(at + "<dir>".len());
        out.push_str(before);
        let end = tail.find('"').unwrap_or(tail.len());
        out.push_str(&tail[..end].replace("\\\\", "/").replace('\\', "/"));
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// `framed` without the `checks` entry named `name`. `doctor` runs the `op local run` check
/// off Windows only (a Windows `op.exe` reached from WSL is what it detects, #54), so the
/// doctor goldens leave it out on every platform; its own tests cover it.
pub(crate) fn without_check(framed: &str, name: &str) -> String {
    let mut doc: serde_json::Value = serde_json::from_str(framed).expect("one JSON document");
    if let Some(checks) = doc["checks"].as_array_mut() {
        checks.retain(|c| c["name"] != name);
    }
    serde_json::to_string(&doc).unwrap()
}

/// Compare `actual` (one JSON line) with `tests/fixtures/json/<name>.json`, pretty-printed
/// so a diff shows the field that moved.
pub(crate) fn golden(name: &str, actual: &str) {
    let doc: serde_json::Value = serde_json::from_str(actual).expect("one JSON document");
    let pretty = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    assert_no_values(&pretty);
    let path = format!("tests/fixtures/json/{name}.json");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all("tests/fixtures/json").unwrap();
        std::fs::write(&path, &pretty).unwrap();
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(expected, pretty, "golden {path} differs");
}

#[test]
fn a_windows_temp_path_is_normalized_in_its_json_escaped_form() {
    let dir = std::path::Path::new(r"C:\Users\RUNNER~1\AppData\Local\Temp\.tmpAB12");
    let framed = serde_json::json!({ "path": dir.join("secrets.toml").display().to_string() })
        .to_string()
        .replace('/', "\\\\");
    assert_eq!(
        without_dir(&framed, dir),
        r#"{"path":"<dir>/secrets.toml"}"#
    );
}

fn status_json(item: crate::runner::Output) -> String {
    let r = FakeRunner::new([item, fly(&[(OPENAI_FLY, "d1")])]);
    let mut out = Vec::new();
    let res = status::run_with(&fleet(), "prod", &r, &mut out, true);
    framed(&out, &res, "opv status prod --json")
}

#[test]
fn status_success() {
    golden("status_success", &status_json(complete_item()));
}

#[test]
fn status_findings() {
    golden(
        "status_findings",
        &status_json(item_without("allumata", "OPENAI_API_KEY")),
    );
}

#[test]
fn status_unknown_environment() {
    let r = FakeRunner::new([]);
    let mut out = Vec::new();
    let res = status::run_with(&fleet(), "qa", &r, &mut out, true);
    golden(
        "status_unknown_env",
        &framed(&out, &res, "opv status qa --json"),
    );
}

#[test]
fn status_overview_run_only_environment() {
    let f = fleet_with("[environments.dev]\nvault_id = \"vdev\"\nitem_id = \"idev\"\n");
    // dev (run-only) is read too (H11): item only; then prod and staging, item and list.
    let r = FakeRunner::new([
        complete_item(),
        complete_item(),
        fly(&[(OPENAI_FLY, "d1")]),
        complete_item(),
        fly_empty(),
    ]);
    let mut out = Vec::new();
    let res = status::overview(&f, None, &r, &mut out, true);
    golden("status_overview", &framed(&out, &res, "opv status --json"));
}

fn plan_json(item: crate::runner::Output) -> String {
    let r = FakeRunner::new([item, fly(&[(OPENAI_FLY, "d1")])]);
    let mut out = Vec::new();
    let res = sync::plan_scoped(&fleet(), "prod", None, &r, &mut out, true);
    framed(&out, &res, "opv plan prod --json")
}

#[test]
fn plan_success() {
    golden("plan_success", &plan_json(complete_item()));
}

#[test]
fn plan_findings() {
    golden(
        "plan_findings",
        &plan_json(item_without("allumata", "OPENAI_API_KEY")),
    );
}

fn check_json(item: crate::runner::Output) -> String {
    let r = FakeRunner::new([item]);
    let mut out = Vec::new();
    let res = local::check(&fleet(), "prod", Some("allumata"), &r, &mut out, true);
    framed(&out, &res, "opv check prod --product allumata --json")
}

#[test]
fn check_success() {
    golden("check_success", &check_json(complete_item()));
}

#[test]
fn check_findings() {
    golden(
        "check_findings",
        &check_json(item_without("allumata", "OPENAI_API_KEY")),
    );
}

fn sync_json(r: &FakeRunner) -> String {
    let opts = SyncOpts {
        json: true,
        ..SyncOpts::default()
    };
    let mut out = Vec::new();
    let res = sync::run(&fleet(), "prod", r, &mut out, &opts);
    framed(&out, &res, "opv sync prod --json")
}

#[test]
fn sync_success() {
    let [st, rel] = fly_preflight_ok();
    let r = FakeRunner::new([
        complete_item(),
        fly_empty(),
        st,
        rel,
        ok(),
        fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2")]),
    ]);
    golden("sync_success", &sync_json(&r));
}

#[test]
fn sync_refused() {
    let r = FakeRunner::new([item_without("allumata", "OPENAI_API_KEY"), fly_empty()]);
    golden("sync_refused", &sync_json(&r));
}

#[test]
fn sync_confirm_required() {
    let mut f = fleet();
    f.environments.get_mut("prod").unwrap().confirm_env = true;
    let opts = SyncOpts {
        json: true,
        deploy: true,
        ..SyncOpts::default()
    };
    let mut out = Vec::new();
    // H12: the read-only part runs first; the guard refuses right before the first write.
    let r = FakeRunner::new([complete_item(), fly_empty()]);
    let res = sync::run(&f, "prod", &r, &mut out, &opts);
    golden(
        "sync_confirm_required",
        &framed(&out, &res, "opv sync prod --deploy --json"),
    );
}

fn explain_json(key: &str) -> String {
    let mut out = Vec::new();
    let res = explain::run_as(&fleet(), key, Some("prod"), &mut out, true);
    framed(&out, &res, "opv explain --json")
}

#[test]
fn explain_success() {
    golden("explain_success", &explain_json("allumata/OPENAI_API_KEY"));
}

#[test]
fn explain_undeclared_key() {
    golden("explain_undeclared", &explain_json("allumata/OPENAI_KEY"));
}

#[test]
fn skeleton_success() {
    let r = FakeRunner::new([item_without("allumata", "OPENAI_API_KEY"), ok()]);
    let mut out = Vec::new();
    let res = skeleton::run_as(&fleet(), "prod", &r, &mut out, true);
    golden(
        "skeleton_success",
        &framed(&out, &res, "opv item skeleton prod --json"),
    );
}

#[test]
fn skeleton_unknown_environment() {
    let mut out = Vec::new();
    let res = skeleton::run_as(&fleet(), "qa", &FakeRunner::new([]), &mut out, true);
    golden(
        "skeleton_unknown_env",
        &framed(&out, &res, "opv item skeleton qa --json"),
    );
}

// ---- The schema covers every field (A4): links (H1), changes (H8), shared keys (FR-45),
// tidy (FR-43) ----------------------------------------------------------------------------

/// The fields `opv schema` lists for document `doc`, without `?` (optional) or a
/// `: [...]` shape suffix, in order.
pub(crate) fn documented(doc: &str) -> Vec<String> {
    let schema = crate::schema::describe(&clap::Command::new("opv"), "0");
    schema["documents"][doc]
        .as_array()
        .unwrap_or_else(|| panic!("no document {doc:?} in the schema"))
        .iter()
        .map(|f| {
            let f = f.as_str().unwrap();
            let f = f.split(':').next().unwrap();
            let f = f.split(" (").next().unwrap();
            f.trim_end_matches('?').trim().to_string()
        })
        .collect()
}

/// The top-level fields of `doc` outside the frame (A1) that the schema does not list.
pub(crate) fn undocumented(doc: &serde_json::Value, name: &str) -> Vec<String> {
    let listed = documented(name);
    let frame = ["schema_version", "ok", "exit_code", "next", "do", "error"];
    doc.as_object()
        .unwrap()
        .keys()
        .filter(|k| !frame.contains(&k.as_str()) && !listed.contains(k))
        .cloned()
        .collect()
}

#[test]
fn the_schema_lists_every_row_field_in_order() {
    let row = crate::domain::Row {
        product: "allumata".into(),
        key: "OPENAI_API_KEY".into(),
        kind: crate::domain::Kind::Secret,
        state: crate::domain::KeyState::Ready,
        target: crate::domain::TargetState::Present,
        guidance: String::new(),
        source: Some(("api".into(), "OPENAI_API_KEY".into())),
        shared_by: Vec::new(),
    };
    let full = super::JsonRow {
        binding: Some("current"),
        pending_deploy: Some(false),
        drift: Some(false),
        chain: Some("a → b".into()),
        open_url: Some("https://start.1password.com/open/i".into()),
        ..super::JsonRow::new(&row, Some("NAME".into()), Some("present"), None)
    };
    let v = serde_json::to_value(&full).unwrap();
    let keys: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, documented("row"));
}

#[test]
fn the_schema_lists_every_field_of_every_golden_document() {
    let mut missing = Vec::new();
    for entry in std::fs::read_dir("tests/fixtures/json").unwrap() {
        let path = entry.unwrap().path();
        let file = path.file_stem().unwrap().to_str().unwrap().to_string();
        let name = match file.split('_').next().unwrap() {
            "status" if file == "status_overview" => "status_overview",
            "skeleton" => "item skeleton",
            other => other,
        };
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        for f in undocumented(&doc, name) {
            missing.push(format!("{file}: {f}"));
        }
    }
    assert!(missing.is_empty(), "{missing:?}");
}
