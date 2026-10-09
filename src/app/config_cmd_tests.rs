use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::adapters::onepassword_manifest::template;
use crate::config_store::{Request, locate, manifest_tags, manifest_title};

const TOML: &str = "[profile]\nkind = \"simple\"\n\n[environments.dev]\nvault_id = \"vdev0000000000000000000001\"\nitem_id = \"app\"\n\n[keys.API_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\nguidance = \"from the dashboard\"\n";

const REMOTE: &str = "git@github.com:acme/myapp.git";

fn text(out: &[u8]) -> String {
    String::from_utf8(out.to_vec()).unwrap()
}

/// A checkout with `secrets.toml`, and a fake op with the checkout's remote.
fn checkout() -> (tempfile::TempDir, FakeOp) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("secrets.toml"), TOML).unwrap();
    (dir, FakeOp::with_remote(REMOTE))
}

fn import_args(dir: &Path) -> ImportArgs {
    ImportArgs {
        file: dir.join("secrets.toml"),
        vault: "myapp-dev".into(),
        project: None,
        paths: Vec::new(),
    }
}

/// The manifest found for the checkout's remote, skipping its secrets.toml.
fn manifest_of(dir: &Path, op: &FakeOp) -> Found {
    let req = Request {
        start: dir.to_path_buf(),
        manifest_only: true,
        ..Request::default()
    };
    locate(&req, op).unwrap()
}

fn put(op: &FakeOp, project: &str, body: &str) -> String {
    op.insert(
        "myapp-dev",
        template(
            &manifest_title(project),
            project,
            &manifest_tags(Some("github.com/acme/myapp"), &[]),
            body,
        ),
    )
}

// --- import / export ---

#[test]
fn import_then_export_is_byte_equivalent() {
    let (dir, op) = checkout();
    import(&import_args(dir.path()), dir.path(), &op, &mut Vec::new()).unwrap();
    let mut out = Vec::new();
    export(&manifest_of(dir.path(), &op), Format::Toml, &op, &mut out).unwrap();
    assert_eq!(text(&out), TOML);
}

#[test]
fn import_tags_the_manifest_with_the_git_remote() {
    let (dir, op) = checkout();
    import(&import_args(dir.path()), dir.path(), &op, &mut Vec::new()).unwrap();
    assert!(op.saw("opv-repo:github.com|acme|myapp"));
}

#[test]
fn import_tags_each_path() {
    let (dir, op) = checkout();
    let mut args = import_args(dir.path());
    args.paths = vec!["apps/api/".into()];
    import(&args, dir.path(), &op, &mut Vec::new()).unwrap();
    assert!(op.saw("opv-path:apps|api"));
}

#[test]
fn import_never_deletes_the_file() {
    let (dir, op) = checkout();
    import(&import_args(dir.path()), dir.path(), &op, &mut Vec::new()).unwrap();
    assert!(dir.path().join("secrets.toml").is_file());
}

#[test]
fn import_ends_with_a_next_step_to_delete_the_file() {
    let (dir, op) = checkout();
    let mut out = Vec::new();
    import(&import_args(dir.path()), dir.path(), &op, &mut out).unwrap();
    let last = text(&out).lines().last().unwrap().to_string();
    assert!(
        last.starts_with("Next: ") && last.contains("config check") && last.contains("git rm"),
        "{last}"
    );
}

#[test]
fn import_refuses_an_invalid_file_before_any_call() {
    let (dir, op) = checkout();
    std::fs::write(dir.path().join("secrets.toml"), "[profile\n").unwrap();
    let _ = import(&import_args(dir.path()), dir.path(), &op, &mut Vec::new());
    assert!(op.calls.borrow().is_empty());
}

#[test]
fn export_json_holds_the_environments() {
    let (dir, op) = checkout();
    import(&import_args(dir.path()), dir.path(), &op, &mut Vec::new()).unwrap();
    let mut out = Vec::new();
    export(&manifest_of(dir.path(), &op), Format::Json, &op, &mut out).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["environments"]["dev"]["item_id"], "app");
}

// --- check ---

#[test]
fn check_of_an_identical_copy_passes() {
    let (dir, op) = checkout();
    put(&op, "myapp", TOML);
    let found = manifest_of(dir.path(), &op);
    let res = check(
        &found,
        &dir.path().join("secrets.toml"),
        &op,
        &mut Vec::new(),
    );
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn check_of_a_different_copy_exits_8() {
    let (dir, op) = checkout();
    put(&op, "myapp", &TOML.replace("dashboard", "console"));
    let found = manifest_of(dir.path(), &op);
    let e = check(
        &found,
        &dir.path().join("secrets.toml"),
        &op,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(e.exit_code(), 8);
}

#[test]
fn check_of_a_different_copy_prints_the_diff() {
    let (dir, op) = checkout();
    put(&op, "myapp", &TOML.replace("dashboard", "console"));
    let found = manifest_of(dir.path(), &op);
    let mut out = Vec::new();
    let _ = check(&found, &dir.path().join("secrets.toml"), &op, &mut out);
    let t = text(&out);
    assert!(
        t.contains("-guidance = \"from the console\"")
            && t.contains("+guidance = \"from the dashboard\""),
        "{t}"
    );
}

// --- edit ---

/// Scripted editor: each `edit` returns the next text (or the input when none is left);
/// `confirm` answers yes and runs `on_confirm` first.
struct Script<'a> {
    edits: Vec<String>,
    on_confirm: Box<dyn FnMut() + 'a>,
}

impl EditUi for Script<'_> {
    fn edit(&mut self, text: &str) -> Result<String, Error> {
        Ok(if self.edits.is_empty() {
            text.to_string()
        } else {
            self.edits.remove(0)
        })
    }
    fn confirm(&mut self, _: &str) -> Result<bool, Error> {
        (self.on_confirm)();
        Ok(true)
    }
}

fn edited() -> String {
    TOML.replace("dashboard", "console")
}

#[test]
fn edit_saves_the_new_text_to_the_manifest() {
    let (dir, op) = checkout();
    let id = put(&op, "myapp", TOML);
    let found = manifest_of(dir.path(), &op);
    let mut ui = Script {
        edits: vec![edited()],
        on_confirm: Box::new(|| {}),
    };
    edit(&found, &op, &mut ui, &mut Vec::new()).unwrap();
    assert_eq!(op.item(&id)["fields"][0]["value"], edited().as_str());
}

#[test]
fn edit_refuses_when_the_manifest_changed_meanwhile() {
    let (dir, op) = checkout();
    let id = put(&op, "myapp", TOML);
    let found = manifest_of(dir.path(), &op);
    let mut ui = Script {
        edits: vec![edited()],
        on_confirm: Box::new(|| op.bump(&id)),
    };
    edit(&found, &op, &mut ui, &mut Vec::new()).unwrap();
    assert_eq!(op.count(&["op", "item", "edit"]), 0);
}

#[test]
fn edit_reopens_on_the_new_version_after_a_refusal() {
    let (dir, op) = checkout();
    let id = put(&op, "myapp", TOML);
    let found = manifest_of(dir.path(), &op);
    let mut ui = Script {
        edits: vec![edited()],
        on_confirm: Box::new(|| op.bump(&id)),
    };
    let mut out = Vec::new();
    edit(&found, &op, &mut ui, &mut out).unwrap();
    assert!(text(&out).contains("Re-opening on the new version"));
}

#[test]
fn edit_never_saves_an_invalid_configuration() {
    let (dir, op) = checkout();
    put(&op, "myapp", TOML);
    let found = manifest_of(dir.path(), &op);
    struct No;
    impl EditUi for No {
        fn edit(&mut self, _: &str) -> Result<String, Error> {
            Ok("[profile\n".into())
        }
        fn confirm(&mut self, _: &str) -> Result<bool, Error> {
            Ok(false)
        }
    }
    let _ = edit(&found, &op, &mut No, &mut Vec::new());
    assert_eq!(op.count(&["op", "item", "edit"]), 0);
}

#[test]
fn edit_works_on_a_file_too() {
    let (dir, op) = checkout();
    let found = Found::File {
        store: crate::config_store::FileStore {
            path: dir.path().join("secrets.toml"),
        },
        given: None,
    };
    let mut ui = Script {
        edits: vec![edited()],
        on_confirm: Box::new(|| {}),
    };
    edit(&found, &op, &mut ui, &mut Vec::new()).unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.path().join("secrets.toml")).unwrap(),
        edited()
    );
}

#[test]
fn diff_marks_removed_and_added_lines() {
    assert_eq!(diff("a\nb\nc\n", "a\nx\nc\n"), " a\n-b\n+x\n c\n");
}

// --- projects and status --all ---

#[test]
fn projects_lists_name_vault_and_repo() {
    let op = FakeOp::default();
    put(&op, "myapp", TOML);
    let mut out = Vec::new();
    projects(&op, false, false, &mut out).unwrap();
    assert_eq!(
        text(&out),
        "myapp: vault myapp-dev; repo github.com/acme/myapp\n"
    );
}

#[test]
fn projects_without_long_reads_no_manifest() {
    let op = FakeOp::default();
    put(&op, "myapp", TOML);
    projects(&op, false, false, &mut Vec::new()).unwrap();
    assert_eq!(op.count(&["op", "item", "get"]), 0);
}

#[test]
fn projects_long_names_the_environments() {
    let op = FakeOp::default();
    put(&op, "myapp", TOML);
    let mut out = Vec::new();
    projects(&op, true, false, &mut out).unwrap();
    assert!(text(&out).contains("environments dev"), "{}", text(&out));
}

#[test]
fn projects_json_has_the_paths() {
    let op = FakeOp::default();
    op.insert(
        "myapp-dev",
        template(
            "opv · api",
            "api",
            &manifest_tags(Some("github.com/acme/myapp"), &["apps/api".into()]),
            TOML,
        ),
    );
    let mut out = Vec::new();
    projects(&op, false, true, &mut out).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["projects"][0]["paths"][0], "apps/api");
}

#[test]
fn status_all_reports_an_unreadable_project_and_goes_on() {
    let op = FakeOp::default();
    put(&op, "broken", "[profile\n");
    put(&op, "myapp", TOML);
    let mut out = Vec::new();
    let _ = status_all(&op, None, false, &mut out);
    let t = text(&out);
    assert!(
        t.contains("broken (vault myapp-dev): not read")
            && t.contains("myapp (vault myapp-dev):\n  dev: "),
        "{t}"
    );
}

#[test]
fn status_all_fails_when_a_project_cannot_be_read() {
    let op = FakeOp::default();
    put(&op, "broken", "[profile\n");
    assert!(status_all(&op, None, false, &mut Vec::new()).is_err());
}

#[test]
fn status_all_json_has_one_entry_per_project() {
    let op = FakeOp::default();
    put(&op, "a", TOML);
    put(&op, "b", TOML);
    let mut out = Vec::new();
    // The environments' items are not in the fake: each project is still one entry.
    let _ = status_all(&op, None, true, &mut out);
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["projects"].as_array().unwrap().len(), 2);
}

const FLEET_TOML: &str = "[environments.dev]\nvault_id = \"vdev0000000000000000000001\"\nitem_id = \"app\"\n\n[products.api.keys.API_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n";

/// I7: `status --all` runs from anywhere, so its step names the project.
#[test]
fn status_all_next_names_the_project() {
    let e = super::in_project(Error::findings(1, "opv check dev".to_string()), "myapp");
    assert_eq!(e.next_step(), Some("env OPV_PROJECT=myapp opv check dev"));
}

/// I7: `--product` limits `status --all` to the projects that declare it.
#[test]
fn status_all_with_a_product_lists_only_projects_declaring_it() {
    let op = FakeOp::default();
    put(&op, "a", FLEET_TOML);
    put(&op, "b", TOML);
    let mut out = Vec::new();
    let _ = status_all(&op, Some("api"), true, &mut out);
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["projects"].as_array().unwrap().len(), 1);
}
