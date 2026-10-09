//! Tests for `opv add` (H2): edits keep the file's comments, every edit is validated by the
//! loader before it is written, and the write is atomic.

use std::fs;
use std::path::PathBuf;

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::adapters::onepassword_manifest::template;
use crate::app::testutil::text_of;
use crate::config_store::{FileStore, Found, ManifestStore, Matched, Snapshot, manifest_title};
use crate::domain::Kind;

const COMMENTED: &str = "# Our services. Values live in 1Password.\n\n[profile]\nkind = \"fleet\"\n\n\
[environments.dev]   # local only\nvault_id = \"vdev\"\nitem_id = \"idev\"\n\n\
[environments.prod]\nvault_id = \"vprd\"\nitem_id = \"iprd\"\nfly.app = \"myapp\"\n\
fly.secret_name = \"FLEET__{PRODUCT}__{KEY}\"\n\n\
# The API\n[products.api.keys.DATABASE_URL]\nkind = \"secret\"\n\
environments = [\"dev\", \"prod\"]   # both\n";

struct Added {
    _dir: tempfile::TempDir,
    path: PathBuf,
    res: Result<(), Error>,
    out: String,
}

impl Added {
    fn text(&self) -> String {
        fs::read_to_string(&self.path).unwrap()
    }
    fn err(&self) -> String {
        self.res.as_ref().unwrap_err().to_string()
    }
    fn fleet(&self) -> crate::domain::Fleet {
        config::parse(&self.text()).unwrap()
    }
}

fn add_to(file: &str, a: AddArgs) -> Added {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    fs::write(&path, file).unwrap();
    let mut out = Vec::new();
    let store = FileStore { path: path.clone() };
    let res = run(&a, &store, &FakeOp::default(), &mut out);
    Added {
        _dir: dir,
        path,
        res,
        out: text_of(&out),
    }
}

fn new_key(name: &str) -> AddArgs {
    AddArgs {
        name: name.into(),
        kind: Some("secret".into()),
        ..AddArgs::default()
    }
}

fn simple() -> String {
    fs::read_to_string("tests/fixtures/simple.toml").unwrap()
}

#[test]
fn adding_a_key_keeps_every_comment_and_line() {
    let a = add_to(COMMENTED, new_key("api/STRIPE_KEY"));
    assert!(a.text().starts_with(COMMENTED), "{}", a.text());
}

#[test]
fn added_key_loads_with_its_kind() {
    let mut args = new_key("api/LOG_LEVEL");
    args.kind = Some("config".into());
    let a = add_to(COMMENTED, args);
    assert_eq!(
        a.fleet().products["api"].keys["LOG_LEVEL"].kind,
        Kind::Config
    );
}

#[test]
fn without_env_the_key_is_declared_for_every_environment() {
    let a = add_to(COMMENTED, new_key("api/STRIPE_KEY"));
    assert_eq!(
        a.fleet().products["api"].keys["STRIPE_KEY"].environments,
        vec!["dev", "prod"]
    );
}

#[test]
fn env_limits_the_environments() {
    let mut args = new_key("api/STRIPE_KEY");
    args.envs = vec!["prod".into()];
    let a = add_to(COMMENTED, args);
    assert_eq!(
        a.fleet().products["api"].keys["STRIPE_KEY"].environments,
        vec!["prod"]
    );
}

#[test]
fn a_name_colliding_on_a_target_is_refused() {
    let file = format!(
        "{COMMENTED}\n[products.my_app.keys.K]\nkind = \"secret\"\nenvironments = [\"prod\"]\n"
    );
    let a = add_to(&file, new_key("my-app/K"));
    assert_eq!(a.res.as_ref().unwrap_err().exit_code(), 2, "{:?}", a.res);
}

#[test]
fn a_refused_add_leaves_the_file_byte_for_byte() {
    let file = format!(
        "{COMMENTED}\n[products.my_app.keys.K]\nkind = \"secret\"\nenvironments = [\"prod\"]\n"
    );
    let a = add_to(&file, new_key("my-app/K"));
    assert_eq!(a.text(), file);
}

#[test]
fn the_write_leaves_no_temporary_file() {
    let a = add_to(COMMENTED, new_key("api/STRIPE_KEY"));
    let names: Vec<String> = fs::read_dir(a.path.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["secrets.toml"]);
}

#[test]
fn a_numeric_rule_is_written_as_a_number() {
    let mut args = new_key("api/JWT_KEY");
    args.rules = vec!["base64_bytes=32".into()];
    let a = add_to(COMMENTED, args);
    assert_eq!(
        a.fleet().products["api"].keys["JWT_KEY"].rules.base64_bytes,
        Some(32)
    );
}

#[test]
fn a_text_rule_is_written_as_text() {
    let mut args = new_key("api/STRIPE_KEY");
    args.rules = vec!["prefix=sk_".into()];
    let a = add_to(COMMENTED, args);
    assert_eq!(
        a.fleet().products["api"].keys["STRIPE_KEY"]
            .rules
            .prefix
            .as_deref(),
        Some("sk_")
    );
}

#[test]
fn a_comma_separated_enum_is_written_as_a_list() {
    let mut args = new_key("api/LOG_LEVEL");
    args.kind = Some("config".into());
    args.rules = vec!["enum=debug,info".into()];
    let a = add_to(COMMENTED, args);
    assert_eq!(
        a.fleet().products["api"].keys["LOG_LEVEL"].rules.r#enum,
        Some(vec!["debug".to_string(), "info".to_string()])
    );
}

#[test]
fn a_flag_rule_by_name_is_true() {
    let mut args = new_key("api/HOOK_URL");
    args.rules = vec!["https_url".into()];
    let a = add_to(COMMENTED, args);
    assert!(a.fleet().products["api"].keys["HOOK_URL"].rules.https_url);
}

#[test]
fn an_unknown_rule_is_refused_naming_it() {
    let mut args = new_key("api/STRIPE_KEY");
    args.rules = vec!["prefixx=sk_".into()];
    let a = add_to(COMMENTED, args);
    assert!(a.err().contains("--rule prefixx"), "{}", a.err());
}

#[test]
fn an_invalid_rule_value_is_refused_by_the_loader() {
    let mut args = new_key("api/STRIPE_KEY");
    args.rules = vec!["regex=([a-z".into()];
    let a = add_to(COMMENTED, args);
    assert!(a.err().contains("nothing written"), "{}", a.err());
}

#[test]
fn guidance_and_immutable_are_written() {
    let mut args = new_key("api/JWT_KEY");
    args.guidance = Some("32 random bytes".into());
    args.immutable = true;
    let a = add_to(COMMENTED, args);
    let k = &a.fleet().products["api"].keys["JWT_KEY"];
    assert_eq!(
        (k.guidance.as_str(), k.immutable),
        ("32 random bytes", true)
    );
}

#[test]
fn a_new_key_without_kind_is_refused() {
    let mut args = new_key("api/STRIPE_KEY");
    args.kind = None;
    let a = add_to(COMMENTED, args);
    assert!(a.err().contains("--kind"), "{}", a.err());
}

#[test]
fn an_unknown_environment_is_refused() {
    let mut args = new_key("api/STRIPE_KEY");
    args.envs = vec!["qa".into()];
    let a = add_to(COMMENTED, args);
    assert!(a.res.is_err());
}

#[test]
fn a_fleet_key_without_product_is_refused_naming_one() {
    let a = add_to(COMMENTED, new_key("STRIPE_KEY"));
    assert!(a.err().contains("opv add api/STRIPE_KEY"), "{}", a.err());
}

#[test]
fn a_simple_key_with_a_product_is_refused() {
    let a = add_to(&simple(), new_key("api/STRIPE_KEY"));
    assert!(a.err().contains("no products"), "{}", a.err());
}

#[test]
fn a_simple_key_is_declared_under_keys() {
    let a = add_to(&simple(), new_key("SENTRY_DSN"));
    assert!(
        a.text()
            .contains("\n[keys.SENTRY_DSN]\nkind = \"secret\"\n"),
        "{}",
        a.text()
    );
}

#[test]
fn a_declared_key_gains_the_new_environment_in_its_own_array() {
    let file = COMMENTED.replace("[\"dev\", \"prod\"]", "[\"prod\"]");
    let mut args = new_key("api/DATABASE_URL");
    args.kind = None;
    args.envs = vec!["dev".into()];
    let a = add_to(&file, args);
    assert!(
        a.text()
            .contains("environments = [\"prod\", \"dev\"]   # both\n"),
        "{}",
        a.text()
    );
}

#[test]
fn a_declared_key_with_new_rules_is_refused() {
    let mut args = new_key("api/DATABASE_URL");
    args.rules = vec!["prefix=postgres://".into()];
    let a = add_to(COMMENTED, args);
    assert!(a.err().contains("by hand"), "{}", a.err());
}

#[test]
fn a_declared_key_already_in_every_environment_changes_nothing() {
    let mut args = new_key("api/DATABASE_URL");
    args.kind = None;
    let a = add_to(COMMENTED, args);
    assert_eq!(a.text(), COMMENTED);
}

#[test]
fn the_next_step_adds_the_field_to_the_item() {
    let mut args = new_key("api/STRIPE_KEY");
    args.envs = vec!["prod".into()];
    let a = add_to(COMMENTED, args);
    assert!(
        a.out.ends_with("Next: opv item skeleton prod\n"),
        "{}",
        a.out
    );
}

#[test]
fn a_refusal_points_at_the_add_help() {
    let a = add_to(COMMENTED, new_key("api/bad"));
    assert_eq!(
        a.res.as_ref().unwrap_err().next_step(),
        Some("opv add --help")
    );
}

// --- a manifest in 1Password (FR-44): the same edit through ConfigStore ---

/// A manifest holding `body`, and its store as discovery returns it.
fn manifest(body: &str) -> (FakeOp, Found) {
    let op = FakeOp::default();
    let id = op.insert(
        "myapp-dev",
        template(&manifest_title("myapp"), "myapp", &[], body),
    );
    let row = crate::adapters::onepassword_manifest::Row {
        id,
        title: manifest_title("myapp"),
        tags: Vec::new(),
        version: 1,
        vault: crate::adapters::onepassword_manifest::VaultRef {
            id: "vdev0000000000000000000001".into(),
            name: "myapp-dev".into(),
        },
    };
    let found = Found::Manifest(ManifestStore::from_row(&row, None, Matched::Given));
    (op, found)
}

fn add_to_manifest(body: &str, a: AddArgs) -> (FakeOp, Found, Result<(), Error>, String) {
    let (op, found) = manifest(body);
    let mut out = Vec::new();
    let res = run(&a, found.store(), &op, &mut out);
    (op, found, res, text_of(&out))
}

#[test]
fn adding_to_a_manifest_saves_the_key_in_it() {
    let (op, found, res, _) = add_to_manifest(COMMENTED, new_key("api/STRIPE_KEY"));
    res.unwrap();
    let fleet = found.load(&op).unwrap();
    assert!(fleet.products["api"].keys.contains_key("STRIPE_KEY"));
}

#[test]
fn adding_to_a_manifest_keeps_its_comments() {
    let (op, found, res, _) = add_to_manifest(COMMENTED, new_key("api/STRIPE_KEY"));
    res.unwrap();
    let text = found.store().read(&op).unwrap().text;
    assert!(
        text.starts_with("# Our services. Values live in 1Password."),
        "{text}"
    );
}

#[test]
fn a_refused_add_to_a_manifest_edits_nothing() {
    let mut args = new_key("api/STRIPE_KEY");
    args.rules = vec!["regex=([a-z".into()];
    let (op, _, res, _) = add_to_manifest(COMMENTED, args);
    assert!(res.is_err() && op.count(&["op", "item", "edit"]) == 0);
}

#[test]
fn a_manifest_add_names_the_manifest_in_its_summary() {
    let (_, _, res, out) = add_to_manifest(COMMENTED, new_key("api/STRIPE_KEY"));
    res.unwrap();
    assert!(out.contains("manifest \"opv · myapp\""), "{out}");
}

#[test]
fn a_broken_manifest_names_the_manifest_and_points_at_config_edit() {
    let broken = COMMENTED.replace("kind = \"fleet\"", "kind = \"flet\"");
    let (_, _, res, _) = add_to_manifest(&broken, new_key("api/STRIPE_KEY"));
    let e = res.unwrap_err();
    assert!(
        e.text().starts_with("manifest \"opv · myapp\": ")
            && e.next_step() == Some("opv config edit"),
        "{e} / {:?}",
        e.next_step()
    );
}

#[test]
fn a_manifest_changed_since_it_was_read_is_refused() {
    let (op, found) = manifest(COMMENTED);
    let base: Snapshot = found.store().read(&op).unwrap();
    let Found::Manifest(m) = &found else {
        unreachable!()
    };
    op.bump(&m.item_id);
    let e = crate::config_store::save(found.store(), &op, &base, COMMENTED).unwrap_err();
    assert!(
        e.to_string().contains("changed while opv was editing it"),
        "{e}"
    );
}

#[test]
fn a_file_changed_since_it_was_read_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    fs::write(&path, COMMENTED).unwrap();
    let store = FileStore { path: path.clone() };
    let base = store.read(&FakeOp::default()).unwrap();
    fs::write(&path, format!("{COMMENTED}\n# someone else\n")).unwrap();
    let e = crate::config_store::save(&store, &FakeOp::default(), &base, COMMENTED).unwrap_err();
    assert!(
        e.to_string().contains("changed while opv was editing it"),
        "{e}"
    );
}
