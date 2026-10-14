//! `opv init <env> --from <file.env>` (#90): declare every key of a dotenv file and, with
//! `--apply`, create the item, write the configuration and import the values, verified.
//! Every value in the file holds [`MARK`]; none may reach the output or the configuration.

use std::path::{Path, PathBuf};

use super::*;
use crate::adapters::fake_op::FakeOp;

const MARK: &str = "INITFROMMARKER";

/// A private `dev.env` in a fresh directory: two secrets (one empty) and one config.
fn env_file(text: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dev.env");
    std::fs::write(&path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (dir, path)
}

fn standard() -> (tempfile::TempDir, PathBuf) {
    env_file(&format!(
        "OPENAI_API_KEY=sk-{MARK}\nSTRIPE_SECRET_KEY=\nSIGNUP_POLICY=open-{MARK}\n"
    ))
}

fn from(path: &Path, apply: bool) -> FromFile {
    FromFile {
        path: path.to_path_buf(),
        config: vec!["SIGNUP_POLICY".into()],
        secret: Vec::new(),
        apply,
    }
}

fn args(path: &Path, apply: bool) -> InitArgs {
    InitArgs {
        env: "dev".into(),
        vault: "myapp-dev".into(),
        item: "myapp · dev values".into(),
        target: None,
        fields: BTreeMap::new(),
        profile: None,
        force: false,
        from: Some(from(path, apply)),
    }
}

/// `init --from … --apply` into `dir` (the file profile) on a fresh fake.
fn apply(dir: &Path, path: &Path) -> (FakeOp, Result<(), Error>, String) {
    // A person signed in with their own account: init may create, adopt may write.
    let _person = crate::app::tidy::activate();
    let op = FakeOp::default();
    let mut out = Vec::new();
    let res = run_as(&args(path, true), dir, &op, &mut out, false);
    (op, res, String::from_utf8(out).unwrap())
}

fn written(dir: &Path) -> crate::domain::Fleet {
    crate::config::load(dir.join(FILE_NAME)).unwrap()
}

/// The value of the unsectioned field `label` in the item the configuration names.
fn value_of(op: &FakeOp, dir: &Path, label: &str) -> Option<String> {
    let fleet = written(dir);
    let item = op.item(
        &fleet.environments["dev"]
            .boundaries
            .values()
            .next()
            .unwrap()
            .item_id,
    );
    item["fields"]
        .as_array()?
        .iter()
        .find(|f| f["label"] == label)
        .and_then(|f| f["value"].as_str())
        .map(str::to_string)
}

// The plan (no --apply) ---------------------------------------------------------------

#[test]
fn every_key_in_the_file_is_declared() {
    let (_d, path) = standard();
    let imported = read_from(&from(&path, false)).unwrap();
    assert_eq!(imported.kinds.len(), 3);
}

#[test]
fn a_config_key_override_makes_the_key_config() {
    let (_d, path) = standard();
    let imported = read_from(&from(&path, false)).unwrap();
    assert_eq!(imported.kinds["SIGNUP_POLICY"], Kind::Config);
}

#[test]
fn a_secret_key_override_makes_the_key_secret() {
    let (_d, path) = env_file("APP_PORT=8080\n");
    let mut f = from(&path, false);
    f.config.clear();
    f.secret = vec!["APP_PORT".into()];
    assert_eq!(read_from(&f).unwrap().kinds["APP_PORT"], Kind::Secret);
}

#[test]
fn an_empty_value_is_listed_as_empty() {
    let (_d, path) = standard();
    let imported = read_from(&from(&path, false)).unwrap();
    assert_eq!(imported.empty, ["STRIPE_SECRET_KEY"]);
}

#[test]
fn an_override_for_a_key_not_in_the_file_is_refused() {
    let (_d, path) = standard();
    let mut f = from(&path, false);
    f.config.push("NOT_THERE".into());
    assert!(read_from(&f).is_err());
}

#[test]
fn the_same_key_as_config_and_secret_is_refused() {
    let (_d, path) = standard();
    let mut f = from(&path, false);
    f.secret.push("SIGNUP_POLICY".into());
    assert!(read_from(&f).is_err());
}

#[test]
fn a_file_without_keys_is_refused() {
    let (_d, path) = env_file("# nothing here\n");
    let mut f = from(&path, false);
    f.config.clear();
    assert!(read_from(&f).is_err());
}

#[cfg(unix)]
#[test]
fn a_file_others_can_read_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let (_d, path) = standard();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_from(&from(&path, false)).is_err());
}

#[test]
fn the_plan_never_shows_a_value() {
    let (_d, path) = standard();
    let a = args(&path, false);
    let imported = read_from(a.from.as_ref().unwrap()).unwrap();
    let mut out = Vec::new();
    plan_from(
        &a,
        &imported,
        "opv init dev --from dev.env --apply",
        &mut out,
        false,
    )
    .unwrap();
    assert!(!String::from_utf8(out).unwrap().contains(MARK));
}

#[test]
fn the_plan_ends_with_the_apply_command() {
    let (_d, path) = standard();
    let a = args(&path, false);
    let imported = read_from(a.from.as_ref().unwrap()).unwrap();
    let mut out = Vec::new();
    plan_from(
        &a,
        &imported,
        "opv init dev --from dev.env --apply",
        &mut out,
        false,
    )
    .unwrap();
    assert!(
        String::from_utf8(out)
            .unwrap()
            .ends_with("Next: opv init dev --from dev.env --apply\n")
    );
}

// --apply -----------------------------------------------------------------------------

#[test]
fn apply_succeeds_on_a_new_project() {
    let (d, path) = standard();
    let (_op, res, _) = apply(d.path(), &path);
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn apply_declares_the_keys_in_the_configuration() {
    let (d, path) = standard();
    let _ = apply(d.path(), &path);
    assert_eq!(written(d.path()).products[""].keys.len(), 3);
}

#[test]
fn apply_declares_the_override_kind() {
    let (d, path) = standard();
    let _ = apply(d.path(), &path);
    let fleet = written(d.path());
    assert_eq!(fleet.products[""].keys["SIGNUP_POLICY"].kind, Kind::Config);
}

#[test]
fn apply_imports_a_secret_value() {
    let (d, path) = standard();
    let (op, _, _) = apply(d.path(), &path);
    assert_eq!(
        value_of(&op, d.path(), "OPENAI_API_KEY").as_deref(),
        Some(&*format!("sk-{MARK}"))
    );
}

#[test]
fn apply_imports_a_config_value() {
    let (d, path) = standard();
    let (op, _, _) = apply(d.path(), &path);
    assert_eq!(
        value_of(&op, d.path(), "SIGNUP_POLICY").as_deref(),
        Some(&*format!("open-{MARK}"))
    );
}

#[test]
fn apply_leaves_an_empty_value_unfilled() {
    let (d, path) = standard();
    let (op, _, _) = apply(d.path(), &path);
    assert!(
        value_of(&op, d.path(), "STRIPE_SECRET_KEY")
            .unwrap_or_default()
            .is_empty()
    );
}

#[test]
fn apply_never_prints_a_value() {
    let (d, path) = standard();
    let (_, _, out) = apply(d.path(), &path);
    assert!(!out.contains(MARK), "{out}");
}

#[test]
fn the_configuration_holds_no_value() {
    let (d, path) = standard();
    let _ = apply(d.path(), &path);
    assert!(
        !std::fs::read_to_string(d.path().join(FILE_NAME))
            .unwrap()
            .contains(MARK)
    );
}

#[test]
fn apply_reports_the_imported_count() {
    let (d, path) = standard();
    let (_, _, out) = apply(d.path(), &path);
    assert!(out.contains("imported 2 values into 1Password"), "{out}");
}

#[test]
fn a_value_already_in_1password_is_kept() {
    let (d, path) = standard();
    let op = FakeOp::default();
    op.insert(
        "vdev0000000000000000000001",
        serde_json::json!({
            "title": "myapp · dev values", "category": "SECURE_NOTE",
            "fields": [{"id": "f1", "type": "CONCEALED", "label": "OPENAI_API_KEY", "value": "sk-kept"}]
        }),
    );
    let _person = crate::app::tidy::activate();
    run_as(&args(&path, true), d.path(), &op, &mut Vec::new(), false).unwrap();
    assert_eq!(
        value_of(&op, d.path(), "OPENAI_API_KEY").as_deref(),
        Some("sk-kept")
    );
}

#[test]
fn a_fleet_shaped_item_is_refused() {
    let (d, path) = standard();
    let op = FakeOp::default();
    op.insert(
        "vdev0000000000000000000001",
        serde_json::json!({
            "title": "myapp · dev values", "category": "SECURE_NOTE",
            "sections": [{"id": "api", "label": "api"}],
            "fields": [{"id": "f1", "section": {"id": "api", "label": "api"}, "type": "CONCEALED", "label": "X", "value": ""}]
        }),
    );
    let _person = crate::app::tidy::activate();
    assert!(run_as(&args(&path, true), d.path(), &op, &mut Vec::new(), false).is_err());
}

#[test]
fn a_bad_file_creates_nothing_in_1password() {
    let (d, path) = env_file("# nothing\n");
    let op = FakeOp::default();
    let mut a = args(&path, true);
    a.from.as_mut().unwrap().config.clear();
    let _person = crate::app::tidy::activate();
    let _ = run_as(&a, d.path(), &op, &mut Vec::new(), false);
    assert!(op.items.borrow().is_empty());
}
