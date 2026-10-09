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
    let r = FakeRunner::new([
        complete_item(),
        fly(&[(OPENAI_FLY, "d1")]),
        complete_item(),
        fly_empty(),
    ]);
    let mut out = Vec::new();
    let res = status::overview_as(&f, &r, &mut out, true);
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
    let res = sync::run(&f, "prod", &FakeRunner::new([]), &mut out, &opts);
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
