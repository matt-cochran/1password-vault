use super::*;
use crate::runner::fake::FakeRunner;

fn fleet() -> Fleet {
    crate::config::load("tests/fixtures/secrets.toml").unwrap()
}

#[test]
fn replace_names_must_be_declared() {
    let e = pairs(&fleet(), &["allumata/NOPE".to_string()], "--replace").unwrap_err();
    assert!(e.mentions("not a declared key"), "{e}");
}

#[test]
fn a_fleet_replace_needs_a_product() {
    let e = pairs(&fleet(), &["OPENAI_API_KEY".to_string()], "--replace").unwrap_err();
    assert!(e.mentions("write product/KEY"), "{e}");
}

/// Fly cannot show a secret's value: adopting from it says so before any read.
#[test]
fn a_target_that_hides_values_is_refused_with_the_manual_way() {
    let r = FakeRunner::default();
    let e = read_source(&fleet(), "staging", &Source::Target, &r).unwrap_err();
    assert_eq!(e.next_step(), Some("opv adopt staging --from <file.env>"));
}

#[test]
fn the_refusal_names_no_value_and_reads_nothing() {
    let r = FakeRunner::default();
    let _ = read_source(&fleet(), "staging", &Source::Target, &r);
    assert!(r.calls.borrow().is_empty());
}

// End to end through the stateful fake op ------------------------------------------------

use crate::adapters::fake_op::FakeOp;

const MARK_NEW: &str = "sk-proj-ADOPTMARKER-new";
const MARK_OLD: &str = "sk-proj-ADOPTMARKER-old";

/// A dev environment on the fake's `myapp-dev` vault: api/OPENAI_API_KEY (secret, filled
/// with MARK_OLD unless `empty`) and api/LOG_LEVEL (config, empty).
fn world(empty: bool) -> (FakeOp, Fleet, tempfile::TempDir) {
    let op = FakeOp::default();
    let value = if empty { "" } else { MARK_OLD };
    let id = op.insert(
        "vdev0000000000000000000001",
        serde_json::json!({
            "title": "myapp · dev values", "category": "SECURE_NOTE",
            "sections": [{"id": "api", "label": "api"}],
            "fields": [
                {"id": "f1", "section": {"id": "api", "label": "api"}, "type": "CONCEALED", "label": "OPENAI_API_KEY", "value": value},
                {"id": "f2", "section": {"id": "api", "label": "api"}, "type": "STRING", "label": "LOG_LEVEL", "value": ""}
            ]
        }),
    );
    let fleet = crate::config::parse(&format!(
        "[profile]\nkind = \"fleet\"\n[environments.dev]\nvault_id = \"vdev0000000000000000000001\"\n\
         item_id = \"{id}\"\n[products.api.keys.OPENAI_API_KEY]\nkind = \"secret\"\n\
         environments = [\"dev\"]\nrules = {{ prefix = \"sk-\" }}\n\
         [products.api.keys.LOG_LEVEL]\nkind = \"config\"\nenvironments = [\"dev\"]\n"
    ))
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let env_file = dir.path().join("dev.env");
    std::fs::write(
        &env_file,
        format!("OPENAI_API_KEY={MARK_NEW}\nLOG_LEVEL=info\n"),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&env_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (op, fleet, dir)
}

fn opts(dir: &tempfile::TempDir, apply: bool, replace: &[&str]) -> Opts {
    Opts {
        source: Source::Dotenv(dir.path().join("dev.env")),
        replace: replace.iter().map(|s| s.to_string()).collect(),
        rotate: Vec::new(),
        skip: Vec::new(),
        apply,
        json: false,
    }
}

fn value_of(op: &FakeOp, fleet: &Fleet, label: &str) -> String {
    let item = op.item(
        &fleet.environments["dev"]
            .boundaries
            .values()
            .next()
            .unwrap()
            .item_id,
    );
    item["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == label && f["section"]["label"] == "api")
        .and_then(|f| f["value"].as_str())
        .unwrap_or_default()
        .to_string()
}

#[test]
fn without_apply_nothing_is_written() {
    let (op, fleet, dir) = world(true);
    run(&fleet, "dev", &opts(&dir, false, &[]), &op, &mut Vec::new()).unwrap();
    assert_eq!(value_of(&op, &fleet, "OPENAI_API_KEY"), "");
}

#[test]
fn apply_imports_into_an_empty_field() {
    let (op, fleet, dir) = world(true);
    run(&fleet, "dev", &opts(&dir, true, &[]), &op, &mut Vec::new()).unwrap();
    assert_eq!(value_of(&op, &fleet, "OPENAI_API_KEY"), MARK_NEW);
}

#[test]
fn apply_imports_config_too() {
    let (op, fleet, dir) = world(true);
    run(&fleet, "dev", &opts(&dir, true, &[]), &op, &mut Vec::new()).unwrap();
    assert_eq!(value_of(&op, &fleet, "LOG_LEVEL"), "info");
}

#[test]
fn a_filled_field_that_differs_is_kept_by_default() {
    let (op, fleet, dir) = world(false);
    run(&fleet, "dev", &opts(&dir, true, &[]), &op, &mut Vec::new()).unwrap();
    assert_eq!(value_of(&op, &fleet, "OPENAI_API_KEY"), MARK_OLD);
}

#[test]
fn replace_takes_the_found_value() {
    let (op, fleet, dir) = world(false);
    run(
        &fleet,
        "dev",
        &opts(&dir, true, &["api/OPENAI_API_KEY"]),
        &op,
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(value_of(&op, &fleet, "OPENAI_API_KEY"), MARK_NEW);
}

#[test]
fn replace_keeps_the_old_value_in_the_kept_section() {
    let (op, fleet, dir) = world(false);
    run(
        &fleet,
        "dev",
        &opts(&dir, true, &["api/OPENAI_API_KEY"]),
        &op,
        &mut Vec::new(),
    )
    .unwrap();
    let item = op.item(
        &fleet.environments["dev"]
            .boundaries
            .values()
            .next()
            .unwrap()
            .item_id,
    );
    assert!(
        item["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| { f["section"]["label"] == KEPT_SECTION && f["value"] == MARK_OLD })
    );
}

#[test]
fn the_output_never_holds_a_value() {
    let (op, fleet, dir) = world(false);
    let mut out = Vec::new();
    run(&fleet, "dev", &opts(&dir, false, &[]), &op, &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(
        !text.contains("ADOPTMARKER") && !text.contains("info"),
        "{text}"
    );
}

#[test]
fn a_differing_value_is_reported_with_the_replace_step() {
    let (op, fleet, dir) = world(false);
    let mut out = Vec::new();
    run(&fleet, "dev", &opts(&dir, false, &[]), &op, &mut out).unwrap();
    assert!(
        String::from_utf8(out)
            .unwrap()
            .contains("--replace api/OPENAI_API_KEY")
    );
}

#[test]
fn a_service_account_cannot_apply() {
    let (op, fleet, dir) = world(true);
    let e = crate::host::with_test_host(
        crate::host::Host::from_env(
            &crate::host::FakeEnv::new("linux").var("OP_SERVICE_ACCOUNT_TOKEN"),
        ),
        || run(&fleet, "dev", &opts(&dir, true, &[]), &op, &mut Vec::new()).unwrap_err(),
    );
    assert_eq!(e.exit_code(), 6);
}

// #94: --skip ---------------------------------------------------------------------------

#[test]
fn skip_leaves_an_import_unwritten() {
    let (op, fleet, dir) = world(true);
    let mut o = opts(&dir, true, &[]);
    o.skip = vec!["api/OPENAI_API_KEY".into()];
    run(&fleet, "dev", &o, &op, &mut Vec::new()).unwrap();
    assert_eq!(value_of(&op, &fleet, "OPENAI_API_KEY"), "");
}

#[test]
fn skip_still_imports_the_other_keys() {
    let (op, fleet, dir) = world(true);
    let mut o = opts(&dir, true, &[]);
    o.skip = vec!["api/OPENAI_API_KEY".into()];
    run(&fleet, "dev", &o, &op, &mut Vec::new()).unwrap();
    assert_eq!(value_of(&op, &fleet, "LOG_LEVEL"), "info");
}

#[test]
fn a_skipped_key_is_reported_as_skipped() {
    let (op, fleet, dir) = world(true);
    let mut o = opts(&dir, false, &[]);
    o.skip = vec!["api/OPENAI_API_KEY".into()];
    o.json = true;
    let mut out = Vec::new();
    run(&fleet, "dev", &o, &op, &mut out).unwrap();
    assert!(String::from_utf8(out).unwrap().contains("\"skipped\""));
}

#[test]
fn skip_names_must_be_declared() {
    let (op, fleet, dir) = world(true);
    let mut o = opts(&dir, false, &[]);
    o.skip = vec!["api/NOPE".into()];
    assert!(run(&fleet, "dev", &o, &op, &mut Vec::new()).is_err());
}
