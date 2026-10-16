use super::*;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

fn fleet() -> Fleet {
    crate::config::load("tests/fixtures/secrets.toml").unwrap()
}

/// The CLI invocation `opv <words>`, for rendering a cause's step.
fn cli(words: &[&str]) -> crate::cause::Invocation {
    let argv: Vec<String> = std::iter::once("opv")
        .chain(words.iter().copied())
        .map(str::to_string)
        .collect();
    crate::cause::Invocation::from_cli(&argv)
}

/// The Next an error renders against `inv`, as a command line.
fn next_of(e: &Error, inv: &crate::cause::Invocation) -> Option<String> {
    let (cause, _) = e.cause().expect("a catalog cause");
    crate::cause::render::next_text(&cause.step(inv).1, inv)
}

// Pinned wording changed with the catalog (05.39): an undeclared or malformed entry is a
// typed cause, not free text.
#[test]
fn replace_names_must_be_declared() {
    let e = pairs(&fleet(), &["allumata/NOPE".to_string()], "--replace").unwrap_err();
    assert_eq!(e.code_str(), "undeclared_key");
}

#[test]
fn a_fleet_replace_needs_a_product() {
    let e = pairs(&fleet(), &["OPENAI_API_KEY".to_string()], "--replace").unwrap_err();
    assert_eq!(e.code_str(), "usage");
}

/// Fly cannot show a secret's value: adopting from it is the provider-hides-values guard.
#[test]
fn a_target_that_hides_values_is_refused_by_its_guard() {
    let r = FakeRunner::default();
    let e = read_source(&fleet(), "staging", &Source::Target("portfolio".into()), &r).unwrap_err();
    assert!(matches!(
        e.cause(),
        Some((
            Cause::Guard {
                guard: Guard::ProviderHidesValues {
                    system: crate::cause::System::Fly
                }
            },
            _
        ))
    ));
}

/// 05.03 (S1): the refusal's Next never sends the person back to the adopt that refused.
#[test]
fn a_target_that_hides_values_never_names_the_same_adopt() {
    let r = FakeRunner::default();
    let e = read_source(&fleet(), "staging", &Source::Target("portfolio".into()), &r).unwrap_err();
    let inv = cli(&["adopt", "staging", "--from", "target:portfolio"]);
    // F2 (R46): its help, never the adopt itself.
    assert!(!next_of(&e, &inv).is_some_and(|n| n.contains("--from")));
}

#[test]
fn the_refusal_names_no_value_and_reads_nothing() {
    let r = FakeRunner::default();
    let _ = read_source(&fleet(), "staging", &Source::Target("portfolio".into()), &r);
    assert!(r.calls.borrow().is_empty());
}

// The `--from` value (FR-53, FR-60) -------------------------------------------------------

/// The bare `--from target` form was removed: it is a usage error.
#[test]
fn the_bare_target_form_is_a_usage_error() {
    let e = source_from(&fleet(), "staging", "target").unwrap_err();
    assert_eq!(e.code(), crate::error::Code::Usage);
}

/// With one target, the refusal's command is the named form.
#[test]
fn the_bare_target_error_names_the_named_form() {
    let e = source_from(&fleet(), "staging", "target").unwrap_err();
    let inv = cli(&["adopt", "staging", "--from", "target"]);
    assert!(next_of(&e, &inv).is_some_and(|n| n.contains("--from target:portfolio")));
}

#[test]
fn a_named_target_is_read_from_that_target() {
    let source = source_from(&fleet(), "staging", "target:portfolio").unwrap();
    assert_eq!(source, Source::Target("portfolio".into()));
}

#[test]
fn an_unknown_target_name_is_an_unknown_target() {
    let e = source_from(&fleet(), "staging", "target:nope").unwrap_err();
    assert_eq!(e.code_str(), "unknown_target");
}

/// A dotenv path (anything not the `target:` form) stays a file source.
#[test]
fn a_file_path_is_a_dotenv_source() {
    let source = source_from(&fleet(), "staging", ".env.staging").unwrap();
    assert_eq!(source, Source::Dotenv(PathBuf::from(".env.staging")));
}

/// A GitHub target reads back its config variables, so adopting from it lists that
/// target's store (FR-53, FR-46).
#[test]
fn a_named_target_reads_that_targets_store() {
    let fleet = crate::config::parse(
        "[environments.ci]\nboundaries.app = { vault_id = \"v\", item_id = \"i\" }\n\
         [environments.ci.targets.gh]\nstate_vault_id = \"s\"\n\
         github.repo = \"example-org/example-repo\"\n\
         [products.app.keys.LOG_LEVEL]\nkind = \"config\"\nenvironments = [\"ci\"]\n",
    )
    .unwrap();
    let r = FakeRunner::new([Output::success(
        br#"[{"name":"LOG_LEVEL","value":"info"}]"#.to_vec(),
    )]);
    let found = read_source(&fleet, "ci", &Source::Target("gh".into()), &r).unwrap();
    assert_eq!(found["LOG_LEVEL"].expose(), "info");
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
        "[environments.dev]\nboundaries.api = {{ vault_id = \"vdev0000000000000000000001\", \
         item_id = \"{id}\" }}\n[products.api.keys.OPENAI_API_KEY]\nkind = \"secret\"\n\
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

/// Two products, each in its own boundary item, on the fake's two vaults.
const MARK_API: &str = "sk-proj-ADOPTMARKER-api";
const MARK_WEB: &str = "sk-proj-ADOPTMARKER-web";

fn two_boundary_world() -> (FakeOp, Fleet, tempfile::TempDir) {
    let op = FakeOp::default();
    let id_a = op.insert(
        "vdev0000000000000000000001",
        serde_json::json!({
            "title": "myapp · dev api", "category": "SECURE_NOTE",
            "sections": [{"id": "api", "label": "api"}],
            "fields": [
                {"id": "fa", "section": {"id": "api", "label": "api"}, "type": "CONCEALED", "label": "API_TOKEN", "value": ""}
            ]
        }),
    );
    let id_b = op.insert(
        "vshr0000000000000000000002",
        serde_json::json!({
            "title": "myapp · dev web", "category": "SECURE_NOTE",
            "sections": [{"id": "web", "label": "web"}],
            "fields": [
                {"id": "fb", "section": {"id": "web", "label": "web"}, "type": "CONCEALED", "label": "WEB_TOKEN", "value": ""}
            ]
        }),
    );
    let fleet = crate::config::parse(&format!(
        "[environments.dev]\n\
         boundaries.api = {{ vault_id = \"vdev0000000000000000000001\", item_id = \"{id_a}\" }}\n\
         boundaries.web = {{ vault_id = \"vshr0000000000000000000002\", item_id = \"{id_b}\" }}\n\
         [products.api.keys.API_TOKEN]\nkind = \"secret\"\nenvironments = [\"dev\"]\n\
         [products.web.keys.WEB_TOKEN]\nkind = \"secret\"\nenvironments = [\"dev\"]\n"
    ))
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let env_file = dir.path().join("dev.env");
    std::fs::write(
        &env_file,
        format!("API_TOKEN={MARK_API}\nWEB_TOKEN={MARK_WEB}\n"),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&env_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (op, fleet, dir)
}

fn boundary_item(fleet: &Fleet, name: &str) -> String {
    fleet.environments["dev"].boundaries[name].item_id.clone()
}

fn field_in(op: &FakeOp, id: &str, label: &str) -> String {
    op.item(id)["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == label)
        .and_then(|f| f["value"].as_str())
        .unwrap_or_default()
        .to_string()
}

#[test]
fn apply_writes_a_value_to_its_own_boundary_item() {
    let (op, fleet, dir) = two_boundary_world();
    run(&fleet, "dev", &opts(&dir, true, &[]), &op, &mut Vec::new()).unwrap();
    let id = boundary_item(&fleet, "api");
    assert_eq!(field_in(&op, &id, "API_TOKEN"), MARK_API);
}

#[test]
fn apply_leaves_the_other_boundary_item_alone() {
    let (op, fleet, dir) = two_boundary_world();
    run(&fleet, "dev", &opts(&dir, true, &[]), &op, &mut Vec::new()).unwrap();
    let id = boundary_item(&fleet, "web");
    assert_eq!(field_in(&op, &id, "API_TOKEN"), "");
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

// 05.04 (S1): the plan's Next applies exactly what was reviewed --------------------------

fn narrowed() -> Opts {
    Opts {
        source: Source::Dotenv(PathBuf::from("my env/.env.staging")),
        replace: vec!["api/X".into()],
        rotate: vec!["api/X".into()],
        skip: vec!["api/LEGACY_TOKEN".into()],
        apply: false,
        json: false,
    }
}

#[test]
fn the_plans_next_keeps_skip() {
    let next = crate::cause::render::cmd_text(&next_step("staging", &narrowed(), 1));
    assert!(next.contains("--skip api/LEGACY_TOKEN"), "{next}");
}

#[test]
fn the_plans_next_keeps_rotate() {
    let next = crate::cause::render::cmd_text(&next_step("staging", &narrowed(), 1));
    assert!(next.contains("--rotate api/X"), "{next}");
}

#[test]
fn the_plans_next_quotes_a_path_with_a_space() {
    let next = crate::cause::render::cmd_text(&next_step("staging", &narrowed(), 1));
    assert!(next.contains("--from 'my env/.env.staging'"), "{next}");
}

// 05.10 (S2): a read-back failure names the command that wrote ---------------------------

#[test]
fn a_read_back_failure_of_adopt_names_its_plan() {
    let by = plan_command("dev", &Source::Target("web".into()));
    assert_eq!(
        crate::cause::render::cmd_text(&by),
        "opv adopt dev --from target:web"
    );
}
