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
use crate::runner::fake::{FakeRunner, failed_read};

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
        target: None,
        fields: fly("myapp-staging"),
        profile,
        force,
    }
}

/// The Fly provider's `--fly-app` option.
fn fly(app: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("fly-app".to_string(), app.to_string())])
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
        fleet.target_name("staging", crate::domain::SIMPLE_PRODUCT, "JWT_KEY"),
        "JWT_KEY"
    );

    let out = &run.out;
    let path = dir.path().join(FILE_NAME);
    assert!(
        out.contains(&format!(
            "wrote {} (simple profile, fly target): 2 secret, 1 config, skipped 0",
            path.display()
        )),
        "{out}"
    );
    assert!(out.ends_with("Next: opv plan staging\n"), "{out}");
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
        fleet.target_name("staging", "web-app", "SESSION_KEY"),
        "FLEET__WEB_APP__SESSION_KEY"
    );
    assert_eq!(
        fleet.products["api"].keys["SIGNUP_POLICY"].kind,
        Kind::Config
    );
    assert!(
        run.out
            .contains("(fleet profile, fly target): 2 secret, 1 config, skipped 0"),
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
        a.fields = fly(app);
        let run = run_in(dir.path(), &a, vec![]);
        assert_eq!(run.err().exit_code(), 2, "{env} {app}");
        assert!(run.r.calls.borrow().is_empty());
    }
    assert!(dir_entries(dir.path()).is_empty());
}

#[test]
fn bad_fly_app_error_quotes_the_app_name() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = args(None, false);
    a.fields = fly("my app");
    let run = run_in(dir.path(), &a, vec![]);
    assert!(
        run.err()
            .to_string()
            .contains("fly.app \"my app\" must match"),
        "{}",
        run.err()
    );
}

#[test]
fn op_failure_goes_through_diagnosis() {
    let dir = tempfile::tempdir().unwrap();
    // vault list fails; op whoami fails; account list has one account → not signed in.
    let run = run_in(
        dir.path(),
        &args(None, false),
        failed_read(1)
            .chain([Output::failure(1), Output::success(b"[{}]".to_vec())])
            .collect(),
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

// --- Fix round 1: reader-rejected shapes, duplicates, ancestor note ---

const REJECT: &str = "status and sync will reject it until it is fixed in 1Password";

/// An `op item get` document from raw field objects (shapes `item_json` cannot build).
fn raw_item(fields: Vec<serde_json::Value>) -> Output {
    Output::success(serde_json::to_vec(&json!({"id": ITEM_ID, "fields": fields})).unwrap())
}

fn sf(section: serde_json::Value, ty: &str, label: &str) -> serde_json::Value {
    json!({"id": label.to_lowercase(), "section": section, "type": ty, "label": label,
           "value": v("x")})
}

fn init_raw(fields: Vec<serde_json::Value>, a: &InitArgs) -> (tempfile::TempDir, Run) {
    let dir = tempfile::tempdir().unwrap();
    let run = run_in(dir.path(), a, vec![vaults(), items(), raw_item(fields)]);
    (dir, run)
}

fn api() -> serde_json::Value {
    json!({"id": "api", "label": "api"})
}

#[test]
fn unlabelled_section_under_fleet_is_noted_as_rejected() {
    let fields = vec![
        sf(api(), "CONCEALED", "TOKEN"),
        sf(json!({"id": "nolabel"}), "STRING", "MODE"),
    ];
    let (_dir, run) = init_raw(fields, &args(Some(Profile::Fleet), false));
    run.res.as_ref().unwrap();
    assert!(
        run.out.contains(&format!(
            "note: skipped \"MODE\": it is in a section without a label; {REJECT}"
        )),
        "{}",
        run.out
    );
    assert!(!run.out.contains("ignored"), "{}", run.out);
    assert!(run.out.contains("skipped 1"), "{}", run.out);
}

/// Under simple the same field is an ordinary unsectioned key (the simple reader agrees).
#[test]
fn unlabelled_section_under_simple_is_a_key() {
    let fields = vec![sf(json!({"id": "nolabel"}), "STRING", "MODE")];
    let (_dir, run) = init_raw(fields, &args(None, false));
    run.res.as_ref().unwrap();
    assert!(run.file().contains("[keys.MODE]"), "{}", run.file());
    assert!(!run.out.contains(REJECT), "{}", run.out);
}

#[test]
fn empty_label_in_a_section_is_noted_as_rejected() {
    let fields = vec![sf(api(), "CONCEALED", "TOKEN"), sf(api(), "STRING", "")];
    let (_dir, run) = init_raw(fields, &args(None, false));
    run.res.as_ref().unwrap();
    assert!(
        run.out.contains(&format!(
            "note: skipped \"api\"/\"\": not a valid key name (^[A-Z][A-Z0-9_]*$); rename the \
             field in 1Password to manage it; it has no label; {REJECT}"
        )),
        "{}",
        run.out
    );
}

#[test]
fn wrong_type_in_a_skipped_section_is_noted_as_rejected() {
    let bad = json!({"id": "s", "label": "My App"});
    let fields = vec![
        sf(api(), "CONCEALED", "TOKEN"),
        sf(bad.clone(), "URL", "SITE"),
        sf(bad, "CONCEALED", "KEY"),
    ];
    let (_dir, run) = init_raw(fields, &args(None, false));
    run.res.as_ref().unwrap();
    let out = &run.out;
    assert!(
        out.contains(&format!(
            "note: skipped \"My App\"/\"SITE\": its section is skipped; field type \"URL\" is \
             neither concealed (secret) nor text (config); {REJECT}"
        )),
        "{out}"
    );
    // The valid field in the skipped section has no per-field note, only the section one.
    assert!(!out.contains("\"My App\"/\"KEY\""), "{out}");
    assert!(
        out.contains("skipped section \"My App\" (2 field(s))"),
        "{out}"
    );
}

#[test]
fn wrong_type_note_uses_the_rejection_wording() {
    let mut fs_ = simple_fields();
    fs_.push(("".into(), "HOMEPAGE".into(), "URL", Some(v("https://x"))));
    let (_dir, run) = init_with(&fs_, &args(None, false));
    run.res.as_ref().unwrap();
    assert!(
        run.out.contains(&format!(
            "note: skipped \"HOMEPAGE\": field type \"URL\" is neither concealed (secret) nor \
             text (config); {REJECT}"
        )),
        "{}",
        run.out
    );
}

/// The readers reject a label given twice whatever the field types, so init does too.
#[test]
fn duplicates_are_found_across_skipped_types_and_sections() {
    let bad = json!({"id": "s", "label": "My App"});
    let cases: Vec<(Vec<serde_json::Value>, &str)> = vec![
        (
            vec![sf(api(), "CONCEALED", "TOKEN"), sf(api(), "URL", "TOKEN")],
            "duplicate field \"api\"/\"TOKEN\"",
        ),
        (
            vec![
                sf(api(), "CONCEALED", "A"),
                sf(bad.clone(), "URL", "X"),
                sf(bad, "STRING", "X"),
            ],
            "duplicate field \"My App\"/\"X\"",
        ),
        (
            vec![
                json!({"id": "a", "type": "CONCEALED", "label": "TOKEN", "value": v("1")}),
                json!({"id": "b", "type": "URL", "label": "TOKEN", "value": v("2")}),
            ],
            "duplicate field \"TOKEN\"",
        ),
    ];
    for (fields, want) in cases {
        let (dir, run) = init_raw(fields, &args(None, false));
        let e = run.err();
        assert_eq!(e.exit_code(), 4, "{e}");
        assert!(e.to_string().contains(want), "{e}");
        assert!(dir_entries(dir.path()).is_empty());
    }
}

/// Not duplicates: the same label in two sections, or an invalid-name label twice under
/// simple (the simple reader ignores labels that cannot be keys).
#[test]
fn same_label_in_other_sections_is_not_a_duplicate() {
    let fields = vec![
        sf(api(), "CONCEALED", "TOKEN"),
        sf(json!({"id": "web", "label": "web"}), "CONCEALED", "TOKEN"),
    ];
    let (_dir, run) = init_raw(fields, &args(None, false));
    run.res.as_ref().unwrap();
    let fields = vec![
        json!({"id": "a", "type": "STRING", "label": "site url"}),
        json!({"id": "b", "type": "URL", "label": "site url"}),
        json!({"id": "c", "type": "STRING", "label": "MODE"}),
    ];
    let (_dir, run) = init_raw(fields, &args(None, false));
    run.res.as_ref().unwrap();
}

#[test]
fn ancestor_secrets_toml_is_noted_never_refused() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join(FILE_NAME), "# parent\n").unwrap();
    let nested = root.path().join("svc").join("api");
    fs::create_dir_all(&nested).unwrap();
    let run = run_in(
        &nested,
        &args(None, false),
        vec![vaults(), items(), item(&simple_fields())],
    );
    run.res.as_ref().unwrap();
    let want = format!(
        "note: {} also exists; the new secrets.toml takes precedence for commands run from {} \
         and below",
        root.path().join(FILE_NAME).display(),
        nested.display()
    );
    assert!(run.out.contains(&want), "{}", run.out);
    assert_eq!(run.out.matches("also exists").count(), 1);
    assert!(nested.join(FILE_NAME).exists());
    assert_eq!(
        fs::read_to_string(root.path().join(FILE_NAME)).unwrap(),
        "# parent\n"
    );
    // The file init wrote is the one discovery now finds from below.
    assert_eq!(config::discover(&nested), Some(nested.join(FILE_NAME)));
}

#[test]
fn no_ancestor_note_without_an_ancestor_file() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("x");
    fs::create_dir_all(&nested).unwrap();
    // Only meaningful when nothing above the temp dir holds a secrets.toml.
    if config::discover(dir.path()).is_none() {
        assert_eq!(ancestor_note(&nested), None);
    }
}

#[test]
fn targetless_init_writes_no_fly_section() {
    let mut a = args(None, false);
    a.fields.clear();
    let (_dir, run) = init_with(&simple_fields(), &a);
    assert!(!run.file().contains("fly."));
}

#[test]
fn targetless_fleet_init_points_to_product_check() {
    let mut a = args(None, false);
    a.fields.clear();
    let (_dir, run) = init_with(&fleet_fields(), &a);
    assert!(run.out.contains("opv check staging --product <product>"));
}

/// Review #16: with one product, the next step names it instead of a placeholder.
#[test]
fn targetless_single_product_init_names_the_product() {
    let mut a = args(None, false);
    a.fields.clear();
    let one: Vec<Field> = fleet_fields()
        .into_iter()
        .filter(|f| f.0 == "api")
        .collect();
    let (_dir, run) = init_with(&one, &a);
    assert!(
        run.out.contains("opv check staging --product api"),
        "{}",
        run.out
    );
}

/// Review #16, #17: the rules reference is a URL a binary install can open.
#[test]
fn init_points_to_the_rules_reference_url() {
    let (_dir, run) = init_with(&fleet_fields(), &args(None, false));
    assert!(
        run.out.contains("configuration.md#rules-reference"),
        "{}",
        run.out
    );
}

// H3: `init --target <provider>` with the provider's own options, through the plug-in
// contract.

const GUID: &str = "00000000-0000-0000-0000-0000000000ab";

fn with_target(target: Option<&str>, opts: &[(&str, &str)]) -> InitArgs {
    let mut a = args(None, false);
    a.target = target.map(String::from);
    a.fields = opts
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    a
}

fn azure_opts() -> Vec<(&'static str, &'static str)> {
    vec![
        ("azure-subscription", GUID),
        ("azure-key-vault", "kv-myapp"),
        ("azure-resource-group", "rg-myapp"),
        ("azure-container-app", "myapp"),
    ]
}

fn kubernetes_opts() -> Vec<(&'static str, &'static str)> {
    vec![
        ("kubernetes-context", "kind-dev"),
        ("kubernetes-namespace", "myapp"),
        ("kubernetes-deployment", "web"),
    ]
}

/// The provider section of the written file's environment, as loaded.
fn loaded_target(dir: &Path) -> &'static str {
    let fleet = config::load(dir.join(FILE_NAME)).unwrap();
    fleet.environments["staging"]
        .target
        .as_ref()
        .map_or("none", |t| t.provider().section())
}

#[test]
fn fly_target_by_option_writes_a_file_that_loads() {
    let (dir, _run) = init_with(
        &fleet_fields(),
        &with_target(Some("fly"), &[("fly-app", "a")]),
    );
    assert_eq!(loaded_target(dir.path()), "fly");
}

#[test]
fn azure_target_writes_a_fleet_file_that_loads() {
    let (dir, _run) = init_with(&fleet_fields(), &with_target(Some("azure"), &azure_opts()));
    assert_eq!(loaded_target(dir.path()), "azure");
}

#[test]
fn azure_target_writes_a_simple_file_that_loads() {
    let (dir, _run) = init_with(&simple_fields(), &with_target(Some("azure"), &azure_opts()));
    assert_eq!(loaded_target(dir.path()), "azure");
}

#[test]
fn kubernetes_target_writes_a_fleet_file_that_loads() {
    let (dir, _run) = init_with(
        &fleet_fields(),
        &with_target(Some("kubernetes"), &kubernetes_opts()),
    );
    assert_eq!(loaded_target(dir.path()), "kubernetes");
}

#[test]
fn kubernetes_target_writes_a_simple_file_that_loads() {
    let (dir, _run) = init_with(
        &simple_fields(),
        &with_target(Some("kubernetes"), &kubernetes_opts()),
    );
    assert_eq!(loaded_target(dir.path()), "kubernetes");
}

#[test]
fn the_target_is_inferred_from_its_options() {
    let (dir, _run) = init_with(&fleet_fields(), &with_target(None, &kubernetes_opts()));
    assert_eq!(loaded_target(dir.path()), "kubernetes");
}

#[test]
fn azure_identity_defaults_to_system() {
    let (_dir, run) = init_with(&fleet_fields(), &with_target(Some("azure"), &azure_opts()));
    assert!(
        run.file().contains("azure.identity = \"system\"\n"),
        "{}",
        run.file()
    );
}

#[test]
fn optional_options_are_written() {
    let mut opts = kubernetes_opts();
    opts.push(("kubernetes-container", "app"));
    let (_dir, run) = init_with(&fleet_fields(), &with_target(Some("kubernetes"), &opts));
    assert!(
        run.file().contains("kubernetes.container = \"app\"\n"),
        "{}",
        run.file()
    );
}

#[test]
fn a_missing_required_option_is_refused_before_any_call() {
    let dir = tempfile::tempdir().unwrap();
    let run = run_in(
        dir.path(),
        &with_target(Some("azure"), &azure_opts()[..3]),
        vec![],
    );
    assert!(
        run.err().to_string().contains("--azure-container-app"),
        "{}",
        run.err()
    );
}

#[test]
fn options_of_two_providers_without_target_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut opts = kubernetes_opts();
    opts.push(("fly-app", "a"));
    let run = run_in(dir.path(), &with_target(None, &opts), vec![]);
    assert!(
        run.err().to_string().contains("pass --target"),
        "{}",
        run.err()
    );
}

#[test]
fn an_option_of_another_provider_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut opts = kubernetes_opts();
    opts.push(("fly-app", "a"));
    let run = run_in(dir.path(), &with_target(Some("kubernetes"), &opts), vec![]);
    assert!(
        run.err()
            .to_string()
            .contains("--fly-app is an option of --target fly"),
        "{}",
        run.err()
    );
}

#[test]
fn an_invalid_option_value_is_refused_before_any_call() {
    let dir = tempfile::tempdir().unwrap();
    let mut opts = azure_opts();
    opts[0] = ("azure-subscription", "not-a-guid");
    let run = run_in(dir.path(), &with_target(Some("azure"), &opts), vec![]);
    assert!(run.r.calls.borrow().is_empty());
}

#[test]
fn an_unknown_target_is_refused_listing_the_providers() {
    let dir = tempfile::tempdir().unwrap();
    let run = run_in(dir.path(), &with_target(Some("heroku"), &[]), vec![]);
    assert!(run.err().to_string().contains("known: "), "{}", run.err());
}

#[test]
fn a_target_refusal_points_at_the_init_help() {
    let dir = tempfile::tempdir().unwrap();
    let run = run_in(dir.path(), &with_target(Some("azure"), &[]), vec![]);
    assert_eq!(run.err().next_step(), Some("opv init --help"));
}

// H2: `init <env> --add-env` adds one environment to an existing file.

const EXISTING: &str = "# Fleet config; values live in 1Password.\n[profile]\nkind = \"fleet\"\n\n\
[environments.prod]   # live\nvault_id = \"vprd\"\nitem_id = \"iprd\"\n\n\
# api\n[products.api.keys.OPENAI_API_KEY]\nkind = \"secret\"\nenvironments = [\"prod\"]\n\n\
[products.api.keys.LEGACY_TOKEN]\nkind = \"secret\"\nenvironments = [\"prod\"]  # going away\n";

struct AddEnv {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    res: Result<(), Error>,
    out: String,
    r: FakeRunner,
}

impl AddEnv {
    fn text(&self) -> String {
        fs::read_to_string(&self.path).unwrap()
    }
    fn fleet(&self) -> crate::domain::Fleet {
        config::parse(&self.text()).unwrap()
    }
}

fn add_env_with(file: &str, a: &InitArgs, fields: &[Field]) -> AddEnv {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(FILE_NAME);
    fs::write(&path, file).unwrap();
    let r = FakeRunner::new(vec![vaults(), items(), item(fields)]);
    let mut out = Vec::new();
    let res = add_env(a, &path, &r, &mut out);
    let run = AddEnv {
        _dir: dir,
        path,
        res,
        out: text_of(&out),
        r,
    };
    assert_no_values(&run.text());
    assert_no_values(&run.out);
    assert_no_values_in_argv(&run.r);
    run
}

fn staging() -> InitArgs {
    let mut a = args(None, false);
    a.fields.clear();
    a
}

#[test]
fn add_env_keeps_every_comment() {
    let run = add_env_with(EXISTING, &staging(), &fleet_fields());
    let text = run.text();
    let comments: Vec<&str> = EXISTING.lines().filter(|l| l.contains('#')).collect();
    assert!(comments.iter().all(|c| text.contains(c)), "{text}");
}

#[test]
fn add_env_writes_the_environment_with_its_ids() {
    let run = add_env_with(EXISTING, &staging(), &fleet_fields());
    let env = &run.fleet().environments["staging"];
    assert_eq!(
        (env.vault_id.as_str(), env.item_id.as_str()),
        (VAULT_ID, ITEM_ID)
    );
}

#[test]
fn add_env_includes_the_keys_the_item_has() {
    let run = add_env_with(EXISTING, &staging(), &fleet_fields());
    assert_eq!(
        run.fleet().products["api"].keys["OPENAI_API_KEY"].environments,
        vec!["prod", "staging"]
    );
}

#[test]
fn add_env_leaves_out_the_keys_the_item_lacks() {
    let run = add_env_with(EXISTING, &staging(), &fleet_fields());
    assert_eq!(
        run.fleet().products["api"].keys["LEGACY_TOKEN"].environments,
        vec!["prod"]
    );
}

#[test]
fn add_env_names_the_item_fields_not_declared() {
    let run = add_env_with(EXISTING, &staging(), &fleet_fields());
    assert!(
        run.out
            .contains("in the item but not declared: api/SIGNUP_POLICY, web-app/SESSION_KEY"),
        "{}",
        run.out
    );
}

#[test]
fn add_env_writes_the_target_options() {
    let mut a = staging();
    a.fields = fly("myapp-staging");
    let run = add_env_with(EXISTING, &a, &fleet_fields());
    assert!(run.fleet().environments["staging"].target.is_some());
}

#[test]
fn add_env_refuses_an_existing_environment_before_any_call() {
    let mut a = staging();
    a.env = "prod".into();
    let run = add_env_with(EXISTING, &a, &fleet_fields());
    assert!(run.r.calls.borrow().is_empty() && run.res.is_err());
}

#[test]
fn add_env_without_a_target_points_at_check() {
    let run = add_env_with(EXISTING, &staging(), &fleet_fields());
    assert!(
        run.out.ends_with("Next: opv check staging --product api\n"),
        "{}",
        run.out
    );
}
