use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::adapters::onepassword_manifest::template;
use crate::config_store::{Request, locate, manifest_tags, manifest_title};

const TOML: &str = "[environments.dev]\nboundaries.app = { vault_id = \"vdev0000000000000000000001\", item_id = \"app\" }\n\n[products.app.keys.API_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\nguidance = \"from the dashboard\"\n";

const REMOTE: &str = "git@github.com:acme/myapp.git";

fn text(out: &[u8]) -> String {
    String::from_utf8(out.to_vec()).unwrap()
}

/// A checkout with `secrets.toml` (its ids in `secrets.bindings.toml` beside it, D-G), and
/// a fake op with the checkout's remote.
fn checkout() -> (tempfile::TempDir, FakeOp) {
    let dir = tempfile::tempdir().unwrap();
    crate::config::bindings::write_split(&dir.path().join("secrets.toml"), TOML).unwrap();
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
fn import_ends_with_a_typed_next_step_comparing_the_copy() {
    let (dir, op) = checkout();
    let mut out = Vec::new();
    import(&import_args(dir.path()), dir.path(), &op, &mut out).unwrap();
    let last = text(&out).lines().last().unwrap().to_string();
    let file = crate::error::shell_word(&dir.path().join("secrets.toml").display().to_string());
    assert_eq!(last, format!("Next: opv config check --file {file}"));
}

/// Without a git remote the checkout finds the manifest only through a pointer: the Do
/// says to write one before the typed Next.
#[test]
fn import_without_a_remote_says_to_write_the_pointer() {
    let dir = tempfile::tempdir().unwrap();
    crate::config::bindings::write_split(&dir.path().join("secrets.toml"), TOML).unwrap();
    let args = ImportArgs {
        project: Some("myapp".into()),
        ..import_args(dir.path())
    };
    let mut out = Vec::new();
    import(&args, dir.path(), &FakeOp::default(), &mut out).unwrap();
    assert!(
        text(&out).contains("Do: write project = \"myapp\" in .opv"),
        "{}",
        text(&out)
    );
}

/// 03.11: a manifest that already exists is named with the local copy, so the step compares
/// the two instead of editing the copy.
#[test]
fn import_beside_an_existing_manifest_names_the_local_copy() {
    let (dir, op) = checkout();
    put(&op, "myapp", TOML);
    let e = import(&import_args(dir.path()), dir.path(), &op, &mut Vec::new()).unwrap_err();
    assert!(
        matches!(
            e.cause(),
            Some((Cause::ManifestExists { local_file: Some(f), .. }, _))
                if *f == dir.path().join("secrets.toml")
        ),
        "{e:?}"
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
    assert_eq!(
        v["environments"]["dev"]["boundaries"]["app"]["item_id"],
        "app"
    );
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
fn check_of_a_different_copy_is_copies_differ() {
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
    assert_eq!(e.code_str(), "copies_differ");
}

/// D-G: a manifest whose inline ids differ from the file's bindings is a different copy.
#[test]
fn check_of_a_copy_with_other_ids_is_copies_differ() {
    let (dir, op) = checkout();
    put(
        &op,
        "myapp",
        &TOML.replace("item_id = \"app\"", "item_id = \"other\""),
    );
    let found = manifest_of(dir.path(), &op);
    let e = check(
        &found,
        &dir.path().join("secrets.toml"),
        &op,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "copies_differ");
}

/// 03.07: either copy may be the intended one; no step picks the direction for the person.
#[test]
fn check_of_a_different_copy_runs_nothing_next() {
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
    let inv = crate::cause::Invocation::from_cli(&["opv".into(), "config".into(), "check".into()]);
    assert!(
        matches!(
            e.cause().unwrap().0.step(&inv).1,
            crate::cause::Next::None(_)
        ),
        "{e:?}"
    );
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

/// Write the apply record at `<dir>/.opv/applied.json` with `bindings_digest`.
fn put_record(dir: &Path, bindings_digest: String) {
    let record = crate::config::bindings::ApplyRecord {
        plan_id: "01JPLAN".into(),
        contract_digest: crate::config::bindings::digest(b"contract"),
        bindings_digest,
    };
    crate::config::bindings::write_record(&dir.join(crate::config::bindings::APPLIED), &record)
        .unwrap();
}

/// The sha256 of the committed bindings file's bytes.
fn committed_bindings_digest(dir: &Path) -> String {
    let bytes = std::fs::read(dir.join(crate::config::bindings::FILE)).unwrap();
    crate::config::bindings::digest(&bytes)
}

#[test]
fn check_of_an_unapplied_bindings_digest_is_bindings_unapplied() {
    let (dir, op) = checkout();
    put(&op, "myapp", TOML);
    put_record(dir.path(), crate::config::bindings::digest(b"other"));
    let found = manifest_of(dir.path(), &op);
    let e = check(
        &found,
        &dir.path().join("secrets.toml"),
        &op,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "bindings_unapplied");
}

#[test]
fn check_of_an_unapplied_bindings_digest_names_the_environment() {
    let (dir, op) = checkout();
    put(&op, "myapp", TOML);
    put_record(dir.path(), crate::config::bindings::digest(b"other"));
    let found = manifest_of(dir.path(), &op);
    let e = check(
        &found,
        &dir.path().join("secrets.toml"),
        &op,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert!(e.to_string().contains("dev"), "{e}");
}

#[test]
fn check_of_a_matching_bindings_digest_passes() {
    let (dir, op) = checkout();
    put(&op, "myapp", TOML);
    put_record(dir.path(), committed_bindings_digest(dir.path()));
    let found = manifest_of(dir.path(), &op);
    let res = check(
        &found,
        &dir.path().join("secrets.toml"),
        &op,
        &mut Vec::new(),
    );
    assert!(res.is_ok(), "{res:?}");
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
    let notes = op.item(&id)["fields"][0]["value"]
        .as_str()
        .unwrap()
        .to_string();
    // D-G: the contract block holds the edit with its ids taken out.
    assert_eq!(
        crate::adapters::onepassword_manifest::config_text(&notes),
        crate::config::bindings::split(&edited()).0
    );
}

/// D-G: `config import` keeps the file's ids out of the manifest's contract block.
#[test]
fn import_keeps_the_ids_out_of_the_manifests_contract_block() {
    let (dir, op) = checkout();
    import(&import_args(dir.path()), dir.path(), &op, &mut Vec::new()).unwrap();
    let Found::Manifest(m) = manifest_of(dir.path(), &op) else {
        unreachable!("a manifest-only lookup")
    };
    let notes = op.item(&m.item_id)["fields"][0]["value"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        !crate::adapters::onepassword_manifest::config_text(&notes).contains("vault_id"),
        "{notes}"
    );
}

/// D-G: `config import` carries the file's `secrets.bindings.toml` into the manifest's
/// `opv-bindings` block, so the manifest loads with the same ids.
#[test]
fn import_carries_the_files_bindings_into_the_manifests_bindings_block() {
    let (dir, op) = checkout();
    import(&import_args(dir.path()), dir.path(), &op, &mut Vec::new()).unwrap();
    let Found::Manifest(m) = manifest_of(dir.path(), &op) else {
        unreachable!("a manifest-only lookup")
    };
    assert_eq!(
        m.read_bindings(&op).unwrap(),
        crate::config::bindings::read_sibling(&dir.path().join("secrets.toml")).unwrap()
    );
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

/// 03.05: the re-edit loop shows the fix where the person is editing, before "Edit again?".
#[test]
fn edit_shows_the_fix_of_an_invalid_edit_before_asking_again() {
    let (dir, op) = checkout();
    put(&op, "myapp", TOML);
    let found = manifest_of(dir.path(), &op);
    struct Typo;
    impl EditUi for Typo {
        fn edit(&mut self, _: &str) -> Result<String, Error> {
            Ok(TOML.replace(
                "[environments.dev]\n",
                "[environments.dev]\nconfrm_env = true\n",
            ))
        }
        fn confirm(&mut self, _: &str) -> Result<bool, Error> {
            Ok(false)
        }
    }
    let mut out = Vec::new();
    let _ = edit(&found, &op, &mut Typo, &mut out);
    assert!(text(&out).contains("\nDo: "), "{}", text(&out));
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
    // D-G: the edit lands in the contract; its ids stay in the bindings file.
    assert_eq!(
        std::fs::read_to_string(dir.path().join("secrets.toml")).unwrap(),
        crate::config::bindings::split(&edited()).0
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
    projects(&op, None, false, false, &mut out).unwrap();
    assert_eq!(
        text(&out),
        "myapp: vault myapp-dev; repo github.com/acme/myapp\n"
    );
}

#[test]
fn projects_without_long_reads_no_manifest() {
    let op = FakeOp::default();
    put(&op, "myapp", TOML);
    projects(&op, None, false, false, &mut Vec::new()).unwrap();
    assert_eq!(op.count(&["op", "item", "get"]), 0);
}

#[test]
fn projects_long_names_the_environments() {
    let op = FakeOp::default();
    put(&op, "myapp", TOML);
    let mut out = Vec::new();
    projects(&op, None, true, false, &mut out).unwrap();
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
    projects(&op, None, false, true, &mut out).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["projects"][0]["paths"][0], "apps/api");
}

#[test]
fn status_all_reports_an_unreadable_project_and_goes_on() {
    let op = FakeOp::default();
    put(&op, "broken", "[profile\n");
    put(&op, "myapp", TOML);
    let mut out = Vec::new();
    let _ = status_all(&op, None, None, false, &mut out);
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
    assert!(status_all(&op, None, None, false, &mut Vec::new()).is_err());
}

#[test]
fn status_all_json_has_one_entry_per_project() {
    let op = FakeOp::default();
    put(&op, "a", TOML);
    put(&op, "b", TOML);
    let mut out = Vec::new();
    // The environments' items are not in the fake: each project is still one entry.
    let _ = status_all(&op, None, None, true, &mut out);
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["projects"].as_array().unwrap().len(), 2);
}

// --- C1 (SR-1): a `.env` given by mistake never reaches the output ---

const ENV_FILE: &str =
    "OPENAI_API_KEY=\"sk-live-C1MARKERVALUE\"\nSTRIPE_KEY=sk_live_C1MARKERVALUE\n";

fn env_file(dir: &Path) -> PathBuf {
    let p = dir.join(".env");
    std::fs::write(&p, ENV_FILE).unwrap();
    p
}

#[test]
fn import_of_an_env_file_never_shows_a_value() {
    let (dir, op) = checkout();
    let mut args = import_args(dir.path());
    args.file = env_file(dir.path());
    let mut out = Vec::new();
    let e = import(&args, dir.path(), &op, &mut out).unwrap_err();
    assert!(!format!("{e}{}", text(&out)).contains("C1MARKER"), "{e}");
}

#[test]
fn check_of_an_env_file_never_shows_a_value() {
    let (dir, op) = checkout();
    put(&op, "myapp", TOML);
    let found = manifest_of(dir.path(), &op);
    let mut out = Vec::new();
    let e = check(&found, &env_file(dir.path()), &op, &mut out).unwrap_err();
    assert!(!format!("{e}{}", text(&out)).contains("C1MARKER"), "{e}");
}

#[test]
fn edit_to_an_env_file_never_shows_a_value() {
    let (dir, op) = checkout();
    put(&op, "myapp", TOML);
    let found = manifest_of(dir.path(), &op);
    struct EnvOnce;
    impl EditUi for EnvOnce {
        fn edit(&mut self, _: &str) -> Result<String, Error> {
            Ok(ENV_FILE.into())
        }
        fn confirm(&mut self, _: &str) -> Result<bool, Error> {
            Ok(false)
        }
    }
    let mut out = Vec::new();
    let res = edit(&found, &op, &mut EnvOnce, &mut out);
    let err = res.err().map(|e| e.to_string()).unwrap_or_default();
    let shown = format!("{err}{}", text(&out));
    assert!(!shown.contains("C1MARKER"), "{shown}");
}

const FLEET_TOML: &str = "[environments.dev]\nboundaries.api = { vault_id = \"vdev0000000000000000000001\", item_id = \"app\" }\n\n[products.api.keys.API_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n";

/// I7: `--product` limits `status --all` to the projects that declare it.
#[test]
fn status_all_with_a_product_lists_only_projects_declaring_it() {
    let op = FakeOp::default();
    put(&op, "a", FLEET_TOML);
    put(&op, "b", TOML);
    let mut out = Vec::new();
    let _ = status_all(&op, None, Some("api"), true, &mut out);
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["projects"].as_array().unwrap().len(), 1);
}

/// A command line with no placeholder for a person to fill in.
fn runs_as_typed(next: &str) -> bool {
    (next.starts_with("opv ") || next.starts_with("env OPV_PROJECT=")) && !next.contains(['<', '>'])
}

/// An environment `status --all` could not read: its `Next:` runs as typed.
#[test]
fn status_all_environment_error_next_is_runnable() {
    let op = FakeOp::default();
    put(&op, "myapp", TOML);
    let e = status_all(&op, None, None, false, &mut Vec::new()).unwrap_err();
    let next = e.next_text().unwrap_or_default();
    assert!(runs_as_typed(&next), "{:?}", next);
}

/// Each unread environment of `status --all --json` carries its runnable `next`.
#[test]
fn status_all_json_environment_error_carries_a_runnable_next() {
    let op = FakeOp::default();
    put(&op, "myapp", TOML);
    let mut out = Vec::new();
    let _ = status_all(&op, None, None, true, &mut out);
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let next = v["projects"][0]["environments"][0]["next"]
        .as_str()
        .unwrap_or_default();
    assert!(runs_as_typed(next), "{next}");
}

// --- #135: discovery reports every account, and never an incomplete list as empty ---

mod discovery {
    use super::super::*;
    use crate::runner::{Output, fake::FakeRunner, fake::failed_read};

    const A: &str = "ACCOUNTAAA000000000000AAAA";
    const B: &str = "ACCOUNTBBB000000000000BBBB";
    const EMAIL: &str = "person-c135@example.com";

    /// Two accounts on the same sign-in address (my.1password.com), as in the owner's
    /// report: a personal one (A) and a business one (B).
    fn two_accounts() -> Output {
        Output::success(format!(
            r#"[{{"url":"https://my.1password.com","email":"{EMAIL}","user_uuid":"USERAAA0000000000000000AAA","account_uuid":"{A}","shorthand":"my"}},{{"url":"https://my.1password.com","email":"{EMAIL}","user_uuid":"USERBBB0000000000000000BBB","account_uuid":"{B}","shorthand":"biz"}}]"#
        ))
    }

    fn one_manifest() -> Output {
        Output::success(
            r#"[{"id":"itemaaaaaaaaaaaaaaaaaaaaaa","title":"opv · app","tags":["opv-manifest"],"version":1,"vault":{"id":"vaultaaaaaaaaaaaaaaaaaaaaa","name":"app-dev"}}]"#,
        )
    }

    /// The responses for one account whose listing fails and whose `op whoami --account`
    /// says it is signed out.
    fn signed_out() -> Vec<Output> {
        failed_read(1).chain([Output::failure(1)]).collect()
    }

    fn runner(listings: Vec<Vec<Output>>) -> FakeRunner {
        let mut all = vec![two_accounts()];
        all.extend(listings.into_iter().flatten());
        FakeRunner::new(all)
    }

    fn projects_json(r: &FakeRunner, account: Option<&str>) -> (Result<(), Error>, Value) {
        let mut out = Vec::new();
        let res = projects(r, account, false, true, &mut out);
        let doc = serde_json::from_slice(&out).unwrap_or(Value::Null);
        (res, doc)
    }

    use serde_json::Value;

    #[test]
    fn a_selected_account_is_the_only_account_listed() {
        let r = runner(vec![vec![Output::success("[]")]]);
        let _ = projects_json(&r, Some(B));
        assert!(!r.argv_contains(A));
    }

    #[test]
    fn a_selected_account_is_listed_by_its_account_id() {
        let r = runner(vec![vec![Output::success("[]")]]);
        let _ = projects_json(&r, Some(B));
        assert!(r.argv_contains(B));
    }

    #[test]
    fn a_selected_account_listing_is_complete() {
        let r = runner(vec![vec![Output::success("[]")]]);
        let (_, doc) = projects_json(&r, Some(B));
        assert_eq!(doc["complete"], true);
    }

    #[test]
    fn a_selected_account_is_chosen_by_its_shorthand() {
        let r = runner(vec![vec![Output::success("[]")]]);
        let (_, doc) = projects_json(&r, Some("biz"));
        assert_eq!(doc["accounts"][0]["account_id"], B);
    }

    #[test]
    fn a_selected_signed_out_account_is_op_not_signed_in() {
        let r = runner(vec![signed_out()]);
        let (res, _) = projects_json(&r, Some(B));
        assert_eq!(res.unwrap_err().code_str(), "op_not_signed_in");
    }

    #[test]
    fn every_account_failing_is_inventory_incomplete() {
        let r = runner(vec![signed_out(), signed_out()]);
        let (res, _) = projects_json(&r, None);
        assert_eq!(res.unwrap_err().code_str(), "inventory_incomplete");
    }

    #[test]
    fn every_account_failing_is_not_complete() {
        let r = runner(vec![signed_out(), signed_out()]);
        let (_, doc) = projects_json(&r, None);
        assert_eq!(doc["complete"], false);
    }

    #[test]
    fn failed_accounts_are_told_apart_by_account_id() {
        let r = runner(vec![signed_out(), signed_out()]);
        let (_, doc) = projects_json(&r, None);
        let ids: Vec<&str> = doc["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|a| a["account_id"].as_str())
            .collect();
        assert_eq!(ids, [A, B]);
    }

    #[test]
    fn a_failed_account_is_reported_as_failed() {
        let r = runner(vec![signed_out(), signed_out()]);
        let (_, doc) = projects_json(&r, None);
        assert_eq!(doc["accounts"][1]["status"], "failed");
    }

    #[test]
    fn a_failed_account_report_names_why() {
        let r = runner(vec![signed_out(), signed_out()]);
        let (_, doc) = projects_json(&r, None);
        assert_eq!(doc["accounts"][1]["error_code"], "op_not_signed_in");
    }

    #[test]
    fn an_incomplete_inventory_names_the_failed_account() {
        let r = runner(vec![vec![Output::success("[]")], signed_out()]);
        let (res, _) = projects_json(&r, None);
        let e = res.unwrap_err();
        assert!(
            matches!(
                e.cause(),
                Some((Cause::InventoryIncomplete { unlisted }, _))
                    if unlisted.iter().map(|a| a.as_str()).collect::<Vec<_>>() == [B]
            ),
            "{e:?}"
        );
    }

    /// 03.08: following the sign-in step never re-points this checkout's .opv.
    #[test]
    fn an_incomplete_inventorys_sign_in_step_records_nothing() {
        let r = runner(vec![vec![Output::success("[]")], signed_out()]);
        let (res, _) = projects_json(&r, None);
        let e = res.unwrap_err();
        let inv = crate::cause::Invocation::from_cli(&["opv".into(), "projects".into()]);
        let next = crate::cause::render::next_text(&e.cause().unwrap().0.step(&inv).1, &inv);
        assert!(next.unwrap_or_default().contains("--no-record"), "{e:?}");
    }

    #[test]
    fn a_partial_inventory_keeps_the_projects_it_listed() {
        let r = runner(vec![vec![one_manifest()], signed_out()]);
        let (_, doc) = projects_json(&r, None);
        assert_eq!(doc["projects"][0]["account_id"], A);
    }

    #[test]
    fn a_partial_inventory_is_inventory_incomplete() {
        let r = runner(vec![vec![one_manifest()], signed_out()]);
        let (res, _) = projects_json(&r, None);
        assert_eq!(res.unwrap_err().code_str(), "inventory_incomplete");
    }

    #[test]
    fn a_listed_account_counts_its_manifests() {
        let r = runner(vec![vec![one_manifest()], signed_out()]);
        let (_, doc) = projects_json(&r, None);
        assert_eq!(doc["accounts"][0]["manifests"], 1);
    }

    #[test]
    fn every_account_listing_nothing_is_a_verified_empty_inventory() {
        let r = runner(vec![
            vec![Output::success("[]")],
            vec![Output::success("[]")],
        ]);
        let (res, _) = projects_json(&r, None);
        assert!(res.is_ok());
    }

    #[test]
    fn a_verified_empty_inventory_is_complete() {
        let r = runner(vec![
            vec![Output::success("[]")],
            vec![Output::success("[]")],
        ]);
        let (_, doc) = projects_json(&r, None);
        assert_eq!(doc["complete"], true);
    }

    #[test]
    fn a_failed_account_is_never_diagnosed_as_another_signed_in_identity() {
        let r = runner(vec![vec![Output::success("[]")], signed_out()]);
        let (res, doc) = projects_json(&r, None);
        let shown = format!("{doc}{}", res.unwrap_err());
        assert!(!shown.contains("signed in to 1Password as"), "{shown}");
    }

    #[test]
    fn account_reports_never_show_the_persons_email() {
        let r = runner(vec![signed_out(), signed_out()]);
        let (res, doc) = projects_json(&r, None);
        let shown = format!("{doc}{}", res.unwrap_err());
        assert!(!shown.contains(EMAIL), "{shown}");
    }

    #[test]
    fn an_incomplete_text_listing_never_claims_there_are_no_projects() {
        let r = runner(vec![signed_out(), signed_out()]);
        let mut out = Vec::new();
        let _ = projects(&r, None, false, false, &mut out);
        assert!(!String::from_utf8_lossy(&out).contains("no project manifests visible"));
    }

    #[test]
    fn status_all_with_an_incomplete_inventory_is_inventory_incomplete() {
        let r = runner(vec![vec![Output::success("[]")], signed_out()]);
        let res = status_all(&r, None, None, true, &mut Vec::new());
        assert_eq!(res.unwrap_err().code_str(), "inventory_incomplete");
    }
}
