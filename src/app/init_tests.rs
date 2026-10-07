//! Tests for `opv init` (FR-23). Every fake item value contains [`MARKER`]; no marker may
//! reach the written file, stdout, an error or argv (SR-1, SR-3, SR-4).

use std::path::Path;

use serde_json::json;

use super::*;
use crate::app::testutil::{
    Field, MARKER, assert_no_values, assert_no_values_in_argv, fly_empty, item, ok, secret, text,
    text_of,
};
use crate::app::{config_export, run as run_cmd, status, sync};
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

const VAULT_ID: &str = "vaultid01";
const ITEM_ID: &str = "itemid01";

fn vaults() -> Output {
    let v = json!([
        {"id": VAULT_ID, "name": "myapp-staging"},
        {"id": "othervault", "name": "Private"},
    ]);
    Output::success(serde_json::to_vec(&v).unwrap())
}

fn items() -> Output {
    let v = json!([
        {"id": ITEM_ID, "title": "myapp", "category": "SECURE_NOTE"},
        {"id": "otheritem", "title": "unrelated", "category": "LOGIN"},
    ]);
    Output::success(serde_json::to_vec(&v).unwrap())
}

fn args(profile: Option<Profile>, force: bool) -> InitArgs {
    InitArgs {
        env: "staging".into(),
        vault: "myapp-staging".into(),
        item: "myapp".into(),
        fly_app: "myapp-staging".into(),
        profile,
        force,
    }
}

fn v(s: &str) -> String {
    format!("{s}-{MARKER}")
}

fn simple_fields() -> Vec<Field> {
    vec![
        secret("", "DATABASE_URL", &v("postgres://u:p@h/db")),
        secret("", "JWT_KEY", &v("jwt")),
        text("", "LOG_LEVEL", &v("info")),
    ]
}

fn fleet_fields() -> Vec<Field> {
    vec![
        secret("api", "OPENAI_API_KEY", &v("sk-proj")),
        text("api", "SIGNUP_POLICY", &v("open")),
        secret("web-app", "SESSION_KEY", &v("sess")),
    ]
}

struct Run {
    res: Result<(), Error>,
    out: String,
    r: FakeRunner,
    file: Option<String>,
}

impl Run {
    fn err(&self) -> &Error {
        self.res.as_ref().unwrap_err()
    }
    fn file(&self) -> &str {
        self.file.as_deref().expect("no file written")
    }
    /// No value anywhere: file, stdout, error text, argv.
    fn assert_value_free(&self) {
        if let Some(f) = &self.file {
            assert_no_values(f);
        }
        assert_no_values(&self.out);
        if let Err(e) = &self.res {
            assert_no_values(&e.to_string());
            assert_no_values(&format!("{e:?}"));
        }
        assert_no_values_in_argv(&self.r);
    }
}

fn run_in(dir: &Path, a: &InitArgs, responses: Vec<Output>) -> Run {
    let r = FakeRunner::new(responses);
    let mut out = Vec::new();
    let res = run(a, dir, &r, &mut out);
    let file = fs::read_to_string(dir.join(FILE_NAME)).ok();
    let run = Run {
        res,
        out: text_of(&out),
        r,
        file,
    };
    run.assert_value_free();
    run
}

fn init_with(fields: &[Field], a: &InitArgs) -> (tempfile::TempDir, Run) {
    let dir = tempfile::tempdir().unwrap();
    let run = run_in(dir.path(), a, vec![vaults(), items(), item(fields)]);
    (dir, run)
}

fn argvs(r: &FakeRunner) -> Vec<String> {
    crate::app::testutil::argvs(r)
}

fn dir_entries(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn simple_item_writes_a_simple_file_with_ids_names_and_kinds() {
    let (dir, run) = init_with(&simple_fields(), &args(None, false));
    run.res.as_ref().unwrap();
    // Two lookups and one whole-item read by IDs; nothing else, nothing written to 1Password.
    assert_eq!(
        argvs(&run.r),
        vec![
            "op vault list --format json".to_string(),
            format!("op item list --vault {VAULT_ID} --format json"),
            format!("op item get {ITEM_ID} --vault {VAULT_ID} --format json"),
        ]
    );
    let f = run.file();
    assert!(f.contains("[profile]\nkind = \"simple\""), "{f}");
    assert!(f.contains("[environments.staging]"), "{f}");
    assert!(f.contains(&format!("vault_id = \"{VAULT_ID}\"")), "{f}");
    assert!(f.contains(&format!("item_id = \"{ITEM_ID}\"")), "{f}");
    assert!(f.contains("fly.app = \"myapp-staging\""), "{f}");
    assert!(!f.contains("secret_name"), "{f}");
    assert!(
        f.contains("[keys.DATABASE_URL]\nkind = \"secret\"\nenvironments = [\"staging\"]"),
        "{f}"
    );
    assert!(f.contains("[keys.LOG_LEVEL]\nkind = \"config\""), "{f}");
    assert!(
        !f.contains("notesPlain"),
        "built-in fields are not keys: {f}"
    );

    let fleet = config::load(dir.path().join(FILE_NAME)).unwrap();
    assert!(fleet.is_simple());
    assert_eq!(
        fleet.fly_name("staging", crate::domain::SIMPLE_PRODUCT, "JWT_KEY"),
        "JWT_KEY"
    );

    let out = &run.out;
    let path = dir.path().join(FILE_NAME);
    assert!(
        out.contains(&format!(
            "wrote {} (simple profile): 2 secret, 1 config, skipped 0",
            path.display()
        )),
        "{out}"
    );
    assert!(out.ends_with("Next step: opv fly plan staging\n"), "{out}");
    assert!(out.contains(VAULT_ID) && out.contains(ITEM_ID), "{out}");
}

#[test]
fn sectioned_item_writes_a_fleet_file_that_the_loader_accepts() {
    let (dir, run) = init_with(&fleet_fields(), &args(None, false));
    run.res.as_ref().unwrap();
    let f = run.file();
    assert!(f.contains("[profile]\nkind = \"fleet\""), "{f}");
    assert!(
        f.contains("fly.secret_name = \"FLEET__{PRODUCT}__{KEY}\""),
        "{f}"
    );
    assert!(
        f.contains("[products.api.keys.OPENAI_API_KEY]\nkind = \"secret\""),
        "{f}"
    );
    assert!(
        f.contains("[products.api.keys.SIGNUP_POLICY]\nkind = \"config\""),
        "{f}"
    );
    assert!(f.contains("[products.web-app.keys.SESSION_KEY]"), "{f}");

    let fleet = config::load(dir.path().join(FILE_NAME)).unwrap();
    assert!(!fleet.is_simple());
    assert_eq!(
        fleet.fly_name("staging", "web-app", "SESSION_KEY"),
        "FLEET__WEB_APP__SESSION_KEY"
    );
    assert_eq!(
        fleet.products["api"].keys["SIGNUP_POLICY"].kind,
        Kind::Config
    );
    assert!(
        run.out
            .contains("(fleet profile): 2 secret, 1 config, skipped 0"),
        "{}",
        run.out
    );
}

#[test]
fn mixed_item_fails_naming_both_shapes_and_writes_nothing() {
    let mut fs_ = simple_fields();
    fs_.extend(fleet_fields());
    let (dir, run) = init_with(&fs_, &args(None, false));
    let e = run.err();
    assert_eq!(e.exit_code(), 2, "{e}");
    let m = e.to_string();
    assert!(
        m.contains("3 unsectioned field(s) (the simple profile shape)"),
        "{m}"
    );
    assert!(
        m.contains("3 sectioned field(s) (the fleet profile shape)"),
        "{m}"
    );
    assert!(m.contains("--profile simple or --profile fleet"), "{m}");
    assert!(run.file.is_none());
    assert!(dir_entries(dir.path()).is_empty());
}

#[test]
fn mixed_item_with_profile_simple_keeps_unsectioned_and_notes_the_rest() {
    let mut fs_ = simple_fields();
    fs_.extend(fleet_fields());
    let (dir, run) = init_with(&fs_, &args(Some(Profile::Simple), false));
    run.res.as_ref().unwrap();
    let f = run.file();
    assert!(f.contains("kind = \"simple\""), "{f}");
    assert!(
        f.contains("[keys.DATABASE_URL]") && !f.contains("OPENAI_API_KEY"),
        "{f}"
    );
    let out = &run.out;
    assert!(
        out.contains(
            "note: ignored 3 sectioned field(s) under --profile simple: \"api\"/\"OPENAI_API_KEY\""
        ),
        "{out}"
    );
    assert!(out.contains("2 secret, 1 config, skipped 3"), "{out}");
    config::load(dir.path().join(FILE_NAME)).unwrap();
}

#[test]
fn mixed_item_with_profile_fleet_keeps_sections_and_notes_the_rest() {
    let mut fs_ = simple_fields();
    fs_.extend(fleet_fields());
    let (dir, run) = init_with(&fs_, &args(Some(Profile::Fleet), false));
    run.res.as_ref().unwrap();
    let f = run.file();
    assert!(
        f.contains("kind = \"fleet\"") && !f.contains("DATABASE_URL"),
        "{f}"
    );
    let out = &run.out;
    assert!(
        out.contains(
            "note: ignored 3 unsectioned field(s) under --profile fleet: \"DATABASE_URL\""
        ),
        "{out}"
    );
    assert!(out.contains("2 secret, 1 config, skipped 3"), "{out}");
    config::load(dir.path().join(FILE_NAME)).unwrap();
}

#[test]
fn no_matching_vault_lists_candidates_and_reads_nothing_more() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = args(None, false);
    a.vault = "myapp-prod".into();
    let run = run_in(dir.path(), &a, vec![vaults()]);
    let m = run.err().to_string();
    assert_eq!(run.err().exit_code(), 2);
    assert!(m.contains("no vault titled \"myapp-prod\""), "{m}");
    assert!(
        m.contains(&format!("\"myapp-staging\" ({VAULT_ID})")),
        "{m}"
    );
    assert!(m.contains("\"Private\" (othervault)"), "{m}");
    assert_eq!(argvs(&run.r).len(), 1);
    assert!(run.file.is_none());
}

#[test]
fn several_matching_items_list_them_and_write_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let dup = Output::success(
        serde_json::to_vec(&json!([
            {"id": "item_a", "title": "myapp"},
            {"id": "item_b", "title": "myapp"},
        ]))
        .unwrap(),
    );
    let run = run_in(dir.path(), &args(None, false), vec![vaults(), dup]);
    let m = run.err().to_string();
    assert_eq!(run.err().exit_code(), 2);
    assert!(m.contains("2 items are titled \"myapp\""), "{m}");
    assert!(m.contains("\"myapp\" (item_a), \"myapp\" (item_b)"), "{m}");
    assert_eq!(argvs(&run.r).len(), 2, "no item read");
    assert!(run.file.is_none());
}

#[test]
fn existing_file_without_force_is_refused_before_any_call_and_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(FILE_NAME);
    fs::write(&path, "# hand-written\n").unwrap();
    let run = run_in(dir.path(), &args(None, false), vec![]);
    let e = run.err();
    assert_eq!(e.exit_code(), 2);
    assert!(e.to_string().contains(&path.display().to_string()), "{e}");
    assert!(e.to_string().contains("--force"), "{e}");
    assert!(run.r.calls.borrow().is_empty());
    assert_eq!(fs::read_to_string(&path).unwrap(), "# hand-written\n");
}

#[test]
fn force_overwrites_atomically_and_leaves_no_temp_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(FILE_NAME);
    fs::write(&path, "# hand-written\n").unwrap();
    let run = run_in(
        dir.path(),
        &args(None, true),
        vec![vaults(), items(), item(&simple_fields())],
    );
    run.res.as_ref().unwrap();
    assert!(!run.file().contains("hand-written"));
    assert!(run.file().contains("[keys.JWT_KEY]"));
    assert_eq!(dir_entries(dir.path()), vec![FILE_NAME.to_string()]);
}

#[test]
fn failed_validation_leaves_an_existing_file_untouched_even_with_force() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(FILE_NAME);
    fs::write(&path, "# hand-written\n").unwrap();
    let mut fs_ = simple_fields();
    fs_.extend(fleet_fields());
    let run = run_in(
        dir.path(),
        &args(None, true),
        vec![vaults(), items(), item(&fs_)],
    );
    assert_eq!(run.err().exit_code(), 2);
    assert_eq!(fs::read_to_string(&path).unwrap(), "# hand-written\n");
    assert_eq!(dir_entries(dir.path()), vec![FILE_NAME.to_string()]);
}

#[test]
fn invalid_key_names_are_skipped_by_name_never_renamed() {
    let mut fs_ = simple_fields();
    fs_.push(secret("", "db-password", &v("pw")));
    fs_.push(text("", "Api_Url", &v("u")));
    let (dir, run) = init_with(&fs_, &args(None, false));
    run.res.as_ref().unwrap();
    let f = run.file();
    for bad in ["db-password", "DB_PASSWORD", "Api_Url", "API_URL"] {
        assert!(!f.contains(bad), "{bad}: {f}");
    }
    let out = &run.out;
    assert!(
        out.contains("note: skipped \"db-password\": not a valid key name (^[A-Z][A-Z0-9_]*$)"),
        "{out}"
    );
    assert!(out.contains("note: skipped \"Api_Url\""), "{out}");
    assert!(out.contains("2 secret, 1 config, skipped 2"), "{out}");
    config::load(dir.path().join(FILE_NAME)).unwrap();
}

#[test]
fn other_field_types_are_skipped_with_a_note() {
    let mut fs_ = fleet_fields();
    fs_.push(("api".into(), "HOMEPAGE".into(), "URL", Some(v("https://x"))));
    let (_dir, run) = init_with(&fs_, &args(None, false));
    run.res.as_ref().unwrap();
    assert!(!run.file().contains("HOMEPAGE"));
    assert!(
        run.out
            .contains("note: skipped \"api\"/\"HOMEPAGE\": field type \"URL\" is neither"),
        "{}",
        run.out
    );
    assert!(run.out.contains("skipped 1"), "{}", run.out);
}

#[test]
fn invalid_section_names_are_skipped_by_name() {
    let mut fs_ = fleet_fields();
    fs_.push(secret("My App", "TOKEN", &v("t")));
    let (_dir, run) = init_with(&fs_, &args(None, false));
    run.res.as_ref().unwrap();
    assert!(!run.file().contains("TOKEN") && !run.file().contains("[products.my"));
    assert!(
        run.out
            .contains("note: skipped section \"My App\" (1 field(s)): not a valid product name"),
        "{}",
        run.out
    );
}

#[test]
fn duplicate_field_is_an_error_and_nothing_is_written() {
    let mut fs_ = simple_fields();
    fs_.push(text("", "LOG_LEVEL", &v("debug")));
    let (dir, run) = init_with(&fs_, &args(None, false));
    assert_eq!(run.err().exit_code(), 4);
    assert!(
        run.err()
            .to_string()
            .contains("duplicate field \"LOG_LEVEL\"")
    );
    assert!(dir_entries(dir.path()).is_empty());
}

#[test]
fn bad_fly_app_or_env_name_fails_before_any_call() {
    let dir = tempfile::tempdir().unwrap();
    for (env, app) in [
        ("staging", "-flag"),
        ("staging", "my app"),
        ("a.b", "ok"),
        ("", "ok"),
    ] {
        let mut a = args(None, false);
        a.env = env.into();
        a.fly_app = app.into();
        let run = run_in(dir.path(), &a, vec![]);
        assert_eq!(run.err().exit_code(), 2, "{env} {app}");
        assert!(run.r.calls.borrow().is_empty());
    }
    assert!(dir_entries(dir.path()).is_empty());
}

#[test]
fn op_failure_goes_through_diagnosis() {
    let dir = tempfile::tempdir().unwrap();
    // vault list fails; op whoami fails; account list has one account → not signed in.
    let run = run_in(
        dir.path(),
        &args(None, false),
        vec![
            Output::failure(1),
            Output::failure(1),
            Output::success(b"[{}]".to_vec()),
        ],
    );
    assert_eq!(run.err().exit_code(), 7, "{}", run.err());
    assert!(run.err().to_string().contains("not signed in to 1Password"));
    assert!(run.file.is_none());
}

#[test]
fn init_never_writes_to_1password() {
    let (_dir, run) = init_with(&fleet_fields(), &args(None, false));
    run.res.as_ref().unwrap();
    for c in run.r.calls.borrow().iter() {
        assert_eq!(c.program, "op");
        assert!(c.stdin.is_none(), "{c:?}");
        assert!(
            matches!(c.args.get(1).map(String::as_str), Some("list" | "get")),
            "{c:?}"
        );
    }
}

/// The generated file loads with the normal loader and `opv status` passes (exit 0) against
/// the very item it was generated from, for both shapes.
#[test]
fn generated_file_passes_status_against_the_same_item() {
    for fields in [simple_fields(), fleet_fields()] {
        let (dir, run) = init_with(&fields, &args(None, false));
        run.res.as_ref().unwrap();
        let fleet = config::load(dir.path().join(FILE_NAME)).unwrap();
        let r = FakeRunner::new([item(&fields), fly_empty()]);
        let mut out = Vec::new();
        status::run(&fleet, "staging", &r, &mut out).unwrap();
        let out = text_of(&out);
        assert!(out.contains("3 saved"), "{out}");
        assert!(out.contains("0 findings"), "{out}");
        assert_no_values(&out);
        // status reads by IDs, written by init.
        assert!(
            crate::app::testutil::called(&r, "op", &["item", "get", ITEM_ID, "--vault", VAULT_ID]),
            "{:?}",
            argvs(&r)
        );
    }
}

// --- The title lookup is unreachable from every other command (FR-13, acceptance 20) ---

fn is_title_lookup(c: &crate::runner::fake::Call) -> bool {
    c.program == "op"
        && matches!(
            (
                c.args.first().map(String::as_str),
                c.args.get(1).map(String::as_str)
            ),
            (Some("vault" | "item"), Some("list"))
        )
}

/// Run sync, plan, status, run and config export (both profiles) against a recording runner
/// and assert none makes a title lookup; their one item read is by vault ID and item ID.
#[test]
fn other_commands_never_look_up_titles() {
    let fleet_cfg = crate::app::testutil::fleet();
    let simple_cfg = config::load("tests/fixtures/simple.toml").unwrap();
    let responses = || {
        let mut v = vec![crate::app::testutil::complete_item(), fly_empty()];
        v.extend((0..10).map(|_| ok()));
        v
    };
    for (cfg, product) in [(&fleet_cfg, Some("allumata")), (&simple_cfg, None)] {
        type Cmd<'a> = Box<dyn Fn(&FakeRunner) + 'a>;
        let cmds: Vec<(&str, Cmd)> = vec![
            (
                "status",
                Box::new(|r| {
                    let _ = status::run(cfg, "prod", r, &mut Vec::new());
                }),
            ),
            (
                "fly plan",
                Box::new(|r| {
                    let _ = sync::plan_with(cfg, "prod", r, &mut Vec::new(), true);
                }),
            ),
            (
                "fly sync",
                Box::new(|r| {
                    let opts = sync::SyncOpts {
                        deploy: true,
                        prune: true,
                        ..Default::default()
                    };
                    let _ = sync::run(cfg, "prod", r, &mut Vec::new(), &opts);
                }),
            ),
            (
                "config export",
                Box::new(|r| {
                    let _ = config_export::run(cfg, "prod", r, &mut Vec::new());
                }),
            ),
            (
                "run",
                Box::new(move |r| {
                    let _ = run_cmd::run_for(cfg, "prod", product, &["true".into()], r);
                }),
            ),
        ];
        for (name, cmd) in cmds {
            let r = FakeRunner::new(responses());
            cmd(&r);
            let calls = r.calls.borrow();
            assert!(!calls.is_empty(), "{name}: made no call");
            assert!(
                !calls.iter().any(is_title_lookup),
                "{name}: title lookup in {:?}",
                argvs(&r)
            );
            for c in calls
                .iter()
                .filter(|c| c.args.get(1).is_some_and(|a| a == "get"))
            {
                assert!(
                    c.args.contains(&"iprd".to_string()) && c.args.contains(&"vprd".to_string()),
                    "{name}: item read not by IDs: {c:?}"
                );
            }
        }
    }
}

/// Structural proof: only `init` (and its adapter) name the title-lookup module or issue a
/// `vault list` / `item list` call. Any new caller fails this test.
#[test]
fn title_lookup_is_referenced_only_by_init() {
    const ALLOWED: [&str; 4] = [
        "src/adapters/mod.rs",
        "src/adapters/onepassword_init.rs",
        "src/app/init.rs",
        "src/app/init_tests.rs",
    ];
    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    walk(&root.join("src"), &mut files);
    assert!(files.len() > 10, "source walk found {} files", files.len());
    let mut checked = 0;
    for p in files {
        let rel = p
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if ALLOWED.contains(&rel.as_str()) {
            continue;
        }
        let src = fs::read_to_string(&p).unwrap();
        for needle in [
            "onepassword_init",
            "resolve_vault",
            "resolve_item",
            "read_field_shapes",
            "\"vault\", \"list\"",
            "\"item\", \"list\"",
        ] {
            assert!(!src.contains(needle), "{rel} references {needle}");
        }
        // Only the binary's dispatch may call the init use case.
        if rel != "src/main.rs" {
            assert!(!src.contains("init::run"), "{rel} calls init::run");
        }
        checked += 1;
    }
    assert!(checked > 10);
}
